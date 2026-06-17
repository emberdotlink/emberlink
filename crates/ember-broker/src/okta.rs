//! Okta `Broker` implementation — issues short-lived OAuth bearer
//! tokens via Okta's OAuth 2.0 service-app `private_key_jwt` grant,
//! returns the minted bearer paired with the requested Okta admin
//! scopes as a [`BrokeredCredential`] the daemon-side handler injects
//! into the child environment as `OKTA_API_TOKEN`.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`OktaServiceApp`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::okta_config`) and one entry per outstanding
//! materialization.
//!
//! ## Single-step mint (private_key_jwt)
//!
//! 1. Sign a self-issued RS256 JWT (5-min window) with the service
//!    app's private key. JWT claims:
//!    - `iss = client_id`
//!    - `sub = client_id`
//!    - `aud = "<org_url>/oauth2/v1/token"`
//!    - `exp = now + 300`
//!    - `iat = now`
//!    - `jti = <random hex>`
//!
//!    Header: `{ alg: "RS256", kid: <key_id> }`.
//! 2. POST `<org_url>/oauth2/v1/token` with form body:
//!    ```text
//!    grant_type=client_credentials
//!    scope=<space-separated scopes>
//!    client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//!    client_assertion=<signed JWT>
//!    ```
//!
//! Response is JSON: `{ access_token, expires_in, token_type, scope }`.
//!
//! ## Revocation
//!
//! Okta exposes `<org_url>/oauth2/v1/revoke` — POST with the bearer
//! token. Best-effort; the TTL bound (Okta caps at 3600s) is the real
//! safety net.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, IdentityRef, MintStamp,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Okta service-app configuration. Loaded once at daemon startup from
/// `~/.config/emberlink/okta.env` (see
/// `ember_daemon::broker::okta_config::load_okta_credentials`).
///
/// `private_key_pem` is held in a [`SecretString`] so it cannot be
/// accidentally `Debug`-printed or logged.
#[derive(Clone)]
pub struct OktaServiceApp {
    /// Base URL of the Okta org, e.g. `https://example.okta.com`.
    /// Embedded into both the JWT `aud` claim and the OAuth token URL.
    pub org_url: String,
    /// OAuth client ID of the service application (the `iss` and `sub`
    /// of the self-issued JWT).
    pub client_id: String,
    /// PEM-encoded RSA private key used to RS256-sign the JWT.
    pub private_key_pem: SecretString,
    /// JWK key id — emitted in the JWT header so Okta selects the
    /// correct public key from the service app's registered key set.
    pub key_id: String,
}

/// Provider-specific scope payload for the Okta broker.
///
/// Deserialized from the opaque `BrokerRequest::scope`
/// (`serde_json::Value`) inside `issue()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OktaScope {
    /// Okta admin scopes to attach to the minted bearer token.
    /// Example: `["okta.users.manage", "okta.groups.manage"]`.
    pub scopes: Vec<String>,

    /// Requested credential lifetime, in seconds. Okta caps
    /// `client_credentials` access tokens at 3600s — the value is
    /// passed through and the org-side cap takes effect server-side.
    pub ttl_seconds: u64,
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `<org>/oauth2/v1/...`.
///
/// Production callers use [`ReqwestOktaClient`]; tests use
/// [`MockOktaClient`].
#[async_trait::async_trait]
pub trait OktaHttpClient: Send + Sync {
    /// POST a `application/x-www-form-urlencoded` body to `url`. Used
    /// for both the OAuth token endpoint and the revoke endpoint.
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String>;
}

/// Production [`OktaHttpClient`] backed by `reqwest`.
pub struct ReqwestOktaClient {
    inner: reqwest::Client,
}

impl ReqwestOktaClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/okta")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestOktaClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl OktaHttpClient for ReqwestOktaClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by Okta's OAuth 2.0 `private_key_jwt`
/// service-app grant.
///
/// Construct with [`OktaBroker::new`] for production (uses
/// [`ReqwestOktaClient`]) or [`OktaBroker::with_client`] for tests
/// (any `dyn OktaHttpClient` implementation).
pub struct OktaBroker {
    app: OktaServiceApp,
    client: Arc<dyn OktaHttpClient>,
    /// `materialization_id` → `(expires_at, token_plaintext)`. The
    /// bearer token is captured so `revoke()` can call the OAuth revoke
    /// endpoint (which takes the token itself as a form param).
    state: Mutex<HashMap<String, OktaMaterializationState>>,
}

struct OktaMaterializationState {
    expires_at: SystemTime,
    token: SecretString,
}

impl OktaBroker {
    /// Production constructor — uses [`ReqwestOktaClient`].
    pub fn new(app: OktaServiceApp) -> Self {
        Self {
            app,
            client: Arc::new(
                ReqwestOktaClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`OktaHttpClient`] so
    /// unit tests can inject [`MockOktaClient`].
    pub fn with_client(app: OktaServiceApp, client: Arc<dyn OktaHttpClient>) -> Self {
        Self {
            app,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("okta broker state mutex").len()
    }
}

/// Self-issued JWT claims for the Okta `private_key_jwt`
/// client-assertion. Mirrors RFC 7523 client-assertion: `iss` and `sub`
/// are both the OAuth client_id; `aud` is the token endpoint URL;
/// `iat`/`exp` are 5 minutes apart; `jti` is a random unique id Okta
/// uses to detect replay.
#[derive(Debug, Serialize, Deserialize)]
struct OktaJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
}

/// Concatenate org URL + path, tolerating a trailing slash on the
/// configured org URL.
fn join_org(org_url: &str, path: &str) -> String {
    let trimmed = org_url.trim_end_matches('/');
    format!("{trimmed}{path}")
}

/// Build (but do not transmit) the RS256 JWT used as the `private_key_jwt`
/// client assertion. Extracted as a free function so unit tests can pin
/// the timestamp + jti without hitting the network.
pub fn build_okta_jwt(
    client_id: &str,
    private_key_pem: &str,
    key_id: &str,
    aud: &str,
    now_epoch_secs: i64,
    jti: &str,
) -> Result<String, BrokerError> {
    let exp = now_epoch_secs + 300; // 5-minute window per Okta docs.
    let claims = OktaJwtClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: aud.to_string(),
        iat: now_epoch_secs,
        exp,
        jti: jti.to_string(),
    };
    crate::install_jwt_crypto_provider();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_id.to_string());
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| BrokerError::Other(format!("jwt key parse: {e}")))?;
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| BrokerError::Other(format!("jwt encode: {e}")))
}

/// 16-byte random hex string used as the JWT `jti`. Avoids pulling in a
/// uuid dependency — Okta only requires uniqueness per service-app, and
/// 128 bits of entropy in lowercase hex is more than enough.
fn random_jti() -> String {
    let mut buf = [0u8; 16];
    // getrandom is already a workspace dep via the broker crate.
    if getrandom::fill(&mut buf).is_err() {
        // Fall back to a timestamp-derived string if the OS RNG fails —
        // jti only needs to be unique within the 5-min JWT window so a
        // monotonic-ish fallback is acceptable for the rare-edge case.
        let now = Utc::now().timestamp_micros();
        return format!("ember-okta-{now}");
    }
    let mut out = String::with_capacity(32);
    use std::fmt::Write as _;
    for b in buf {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// JSON shapes for the OAuth token response + error envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OktaTokenResponse {
    access_token: String,
    /// Lifetime of the bearer token in seconds (Okta caps at 3600).
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
}

/// Map an Okta non-2xx OAuth response (status + body) to the closest
/// [`BrokerError`] variant. Okta returns a JSON envelope of the form
/// `{ "error": "<code>", "error_description": "..." }`.
///
/// - `invalid_client` / 401 → `PolicyRejected` (bad client_id / wrong key)
/// - `invalid_scope` / 400 with scope-not-allowed → `Upstream`
///   (descriptive: "scope")
/// - `invalid_grant` / `invalid_request` mentioning expired key →
///   `Upstream` with "key expired" message
/// - everything else → `Upstream` with a descriptive message
fn map_okta_error(status: u16, body: &str) -> BrokerError {
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let error_code = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let error_desc = parsed
        .get("error_description")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let combined = format!("{error_code}: {error_desc}");
    let lower_desc = error_desc.to_ascii_lowercase();

    if status == 401 || error_code == "invalid_client" {
        return BrokerError::PolicyRejected(format!(
            "Okta invalid_client_credentials (status={status}): {combined}"
        ));
    }

    if error_code == "invalid_scope" {
        return BrokerError::Upstream(format!("Okta invalid scope (status={status}): {combined}"));
    }

    if (error_code == "invalid_grant" || error_code == "invalid_request")
        && (lower_desc.contains("expired")
            || lower_desc.contains("key")
            || lower_desc.contains("kid"))
    {
        return BrokerError::Upstream(format!(
            "Okta service-app key expired or unknown kid (status={status}): {combined}"
        ));
    }

    BrokerError::Upstream(format!(
        "Okta token endpoint error (status={status}): {combined}"
    ))
}

const TOKEN_PATH: &str = "/oauth2/v1/token";
const REVOKE_PATH: &str = "/oauth2/v1/revoke";

impl Broker for OktaBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Okta
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Okta {
            return Err(BrokerError::InvalidScope(format!(
                "OktaBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: OktaScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        if scope.scopes.is_empty() {
            return Err(BrokerError::InvalidScope(
                "OktaScope.scopes must be non-empty".to_string(),
            ));
        }
        if scope.ttl_seconds == 0 {
            return Err(BrokerError::InvalidScope(
                "OktaScope.ttl_seconds must be > 0".to_string(),
            ));
        }

        let token_url = join_org(&self.app.org_url, TOKEN_PATH);
        let now_secs = Utc::now().timestamp();
        let jti = random_jti();
        let jwt = build_okta_jwt(
            &self.app.client_id,
            self.app.private_key_pem.expose_secret(),
            &self.app.key_id,
            &token_url,
            now_secs,
            &jti,
        )?;

        let body = format!(
            "grant_type=client_credentials\
             &scope={}\
             &client_assertion_type={}\
             &client_assertion={}",
            urlencode(&scope.scopes.join(" ")),
            urlencode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            urlencode(&jwt),
        );

        let (status, resp_body) = self
            .client
            .post_form(&token_url, body)
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_okta_error(status, &resp_body);
            tracing::warn!(
                status = status,
                error = %err,
                "OktaBroker: token endpoint non-2xx"
            );
            return Err(err);
        }

        let parsed: OktaTokenResponse = serde_json::from_str(&resp_body).map_err(|e| {
            BrokerError::Upstream(format!(
                "Okta token response parse failed: {e}; body={resp_body}"
            ))
        })?;

        // Prefer the server-reported `expires_in` (Okta clamps to 3600s);
        // fall back to the requested ttl_seconds if absent.
        let lifetime_secs = if parsed.expires_in > 0 {
            parsed.expires_in as u64
        } else {
            scope.ttl_seconds
        };
        let expires_at = SystemTime::now() + std::time::Duration::from_secs(lifetime_secs);

        // Fold the per-mint `jti` into the id: `client_id` + expiry alone
        // collide for two mints of the same app within the same second,
        // which would overwrite the earlier entry in `state` and leave its
        // token untracked (revoke would target the wrong/forgotten token).
        let materialization_id = format!(
            "okta-{}-{}-{}",
            self.app.client_id,
            DateTime::<Utc>::from(expires_at).timestamp(),
            jti
        );

        let token_secret = SecretString::from(parsed.access_token);
        self.state.lock().expect("okta broker state mutex").insert(
            materialization_id.clone(),
            OktaMaterializationState {
                expires_at,
                token: token_secret.clone(),
            },
        );

        Ok(BrokeredCredential {
            token: token_secret,
            expires_at,
            materialization_id,
            mint_stamp: MintStamp::Identity {
                identity: IdentityRef {
                    provider: BrokerProvider::Okta,
                    identity: format!(
                        "{}:{}",
                        self.app.org_url.trim_end_matches('/'),
                        self.app.client_id
                    ),
                },
            },
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        let entry = self
            .state
            .lock()
            .expect("okta broker state mutex")
            .remove(materialization_id);
        let Some(state) = entry else {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        };

        // Best-effort upstream revoke. Okta's `/oauth2/v1/revoke`
        // expects the bearer token + token_type_hint in the form body
        // and uses the same `private_key_jwt` client authentication on
        // the revoke side. Failures are warned but do not surface as
        // `Err` — the TTL bound (cap 3600s) is the real safety net.
        let revoke_url = join_org(&self.app.org_url, REVOKE_PATH);
        let now_secs = Utc::now().timestamp();
        let jti = random_jti();
        let token_endpoint_url = join_org(&self.app.org_url, TOKEN_PATH);
        // The JWT `aud` for client-authenticated calls is the token URL
        // per RFC 7523; Okta accepts the same JWT shape on revoke.
        let assertion = match build_okta_jwt(
            &self.app.client_id,
            self.app.private_key_pem.expose_secret(),
            &self.app.key_id,
            &token_endpoint_url,
            now_secs,
            &jti,
        ) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "OktaBroker: failed to build revoke client_assertion (best-effort; TTL still bounds exposure)"
                );
                return Ok(());
            }
        };

        let body = format!(
            "token={}&token_type_hint=access_token\
             &client_assertion_type={}\
             &client_assertion={}",
            urlencode(state.token.expose_secret()),
            urlencode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            urlencode(&assertion),
        );

        match self.client.post_form(&revoke_url, body).await {
            Ok((status, _)) if (200..300).contains(&status) => {
                tracing::info!(
                    materialization_id = %materialization_id,
                    "OktaBroker: revoke succeeded"
                );
            }
            Ok((404, _)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    "OktaBroker: revoke returned 404 (token already expired/revoked; treating as success)"
                );
            }
            Ok((status, resp_body)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = status,
                    body = %resp_body,
                    "OktaBroker: upstream revoke non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "OktaBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        let _ = state.expires_at;
        Ok(())
    }
}

/// Minimal RFC3986 percent-encoder for form bodies. Encodes everything
/// outside the unreserved set `A-Za-z0-9-._~`. Avoids a full url crate
/// dep — same shape used by `gcp.rs::urlencode`.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

/// Scripted-response mock client for unit tests. Each call pops the
/// next `(status, body)` from `responses`. If the queue holds only one
/// entry it is reused for every subsequent call (terse setup); if the
/// queue is empty the mock errors so missing-fixture bugs surface
/// loudly.
pub struct MockOktaClient {
    pub responses: Mutex<Vec<(u16, String)>>,
    pub calls: Mutex<Vec<MockOktaCall>>,
}

#[derive(Debug, Clone)]
pub struct MockOktaCall {
    pub url: String,
    pub body: String,
}

impl MockOktaClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
        self.responses
            .lock()
            .expect("mock okta mutex")
            .push((status, body.into()));
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock okta mutex").len()
    }

    pub fn last_call(&self) -> Option<MockOktaCall> {
        self.calls.lock().expect("mock okta mutex").last().cloned()
    }
}

impl Default for MockOktaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl OktaHttpClient for MockOktaClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock okta mutex")
            .push(MockOktaCall {
                url: url.to_string(),
                body: body.clone(),
            });
        let mut q = self.responses.lock().expect("mock okta mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockOktaClient: no response queued for {url}; body={body}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // RSA private key fixture — same key the github_app/gcp tests use
    // so we share known-good PKCS#8 bytes. Not a real credential; safe
    // to embed.
    const FIXTURE_RSA_PEM: &str = include_str!("../tests/fixtures/rsa_pem.pem");

    fn fixture_app() -> OktaServiceApp {
        OktaServiceApp {
            org_url: "https://example.okta.com".to_string(),
            client_id: "0oa-test-service-app".to_string(),
            private_key_pem: SecretString::from(FIXTURE_RSA_PEM.to_string()),
            key_id: "test-kid-1".to_string(),
        }
    }

    fn okta_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Okta,
            scope,
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    fn token_ok_body() -> String {
        serde_json::json!({
            "access_token": "00okta_access_token_for_tests",
            "token_type": "Bearer",
            "expires_in": 3599,
            "scope": "okta.users.manage okta.groups.manage",
        })
        .to_string()
    }

    fn invalid_client_body() -> String {
        serde_json::json!({
            "error": "invalid_client",
            "error_description": "The client secret supplied for a confidential client is invalid.",
        })
        .to_string()
    }

    fn invalid_scope_body() -> String {
        serde_json::json!({
            "error": "invalid_scope",
            "error_description": "One or more scopes are not configured for the authorization server resource.",
        })
        .to_string()
    }

    fn expired_key_body() -> String {
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The client_assertion key has expired or kid is unknown.",
        })
        .to_string()
    }

    #[test]
    fn provider_returns_okta() {
        let broker = OktaBroker::with_client(fixture_app(), Arc::new(MockOktaClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::Okta);
    }

    #[test]
    fn build_okta_jwt_encodes_iss_sub_aud_iat_exp_jti_and_kid() {
        let now = 1_700_000_000i64;
        let token = build_okta_jwt(
            "0oa-client-id",
            FIXTURE_RSA_PEM,
            "test-kid-1",
            "https://example.okta.com/oauth2/v1/token",
            now,
            "deadbeef",
        )
        .expect("jwt must encode");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        use base64::Engine as _;
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header must be valid base64url");
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header must deserialize");
        assert_eq!(
            header_json.get("alg").and_then(|v| v.as_str()),
            Some("RS256"),
            "header alg must be RS256"
        );
        assert_eq!(
            header_json.get("kid").and_then(|v| v.as_str()),
            Some("test-kid-1"),
            "header must include the configured kid"
        );

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload must be valid base64url");
        let claims: OktaJwtClaims =
            serde_json::from_slice(&payload_bytes).expect("payload must deserialize");
        assert_eq!(claims.iss, "0oa-client-id");
        assert_eq!(claims.sub, "0oa-client-id");
        assert_eq!(claims.aud, "https://example.okta.com/oauth2/v1/token");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + 300);
        assert_eq!(claims.jti, "deadbeef");
    }

    #[test]
    fn build_okta_jwt_bad_pem_returns_other_error() {
        let err = build_okta_jwt("c", "not-a-pem", "kid", "aud", 0, "jti").unwrap_err();
        assert!(
            matches!(err, BrokerError::Other(_)),
            "expected Other for jwt key parse failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_happy_path_returns_bearer_and_records_state() {
        let mock = Arc::new(MockOktaClient::new().with_response(200, token_ok_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock.clone());
        let req = okta_request(
            serde_json::json!({
                "scopes": ["okta.users.manage", "okta.groups.manage"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "00okta_access_token_for_tests",
            "token must be the bearer Okta returned"
        );
        assert!(
            cred.materialization_id
                .starts_with("okta-0oa-test-service-app-"),
            "materialization_id includes client_id: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);

        let call = mock.last_call().expect("call recorded");
        assert_eq!(call.url, "https://example.okta.com/oauth2/v1/token");
        // Body must include grant_type, scope, client_assertion_type,
        // and client_assertion form params.
        assert!(
            call.body.contains("grant_type=client_credentials"),
            "body must include grant_type: {}",
            call.body
        );
        assert!(
            call.body
                .contains("scope=okta.users.manage%20okta.groups.manage"),
            "body must include space-separated scopes: {}",
            call.body
        );
        assert!(
            call.body.contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
            ),
            "body must include the URL-encoded client_assertion_type: {}",
            call.body
        );
        assert!(
            call.body.contains("client_assertion="),
            "body must include client_assertion: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_twice_same_second_keeps_distinct_materialization_ids() {
        // Two mints of the same service-app within the same second share
        // `client_id` and the expiry-second. If the id were only
        // `okta-{client_id}-{expiry}` they would collide, overwriting the
        // first entry in `state` and leaving its token untracked. The
        // per-mint `jti` keeps the ids distinct so both stay revocable.
        let mock = Arc::new(MockOktaClient::new().with_response(200, token_ok_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock.clone());
        let mk = || {
            okta_request(
                serde_json::json!({
                    "scopes": ["okta.users.manage"],
                    "ttl_seconds": 3600,
                }),
                3600,
            )
        };
        let c1 = Broker::issue(&broker, mk()).await.expect("first issue");
        let c2 = Broker::issue(&broker, mk()).await.expect("second issue");
        assert_ne!(
            c1.materialization_id, c2.materialization_id,
            "two same-second mints must produce distinct ids"
        );
        assert_eq!(
            broker.active_count(),
            2,
            "both materializations must be tracked, not overwritten"
        );
    }

    #[tokio::test]
    async fn issue_401_invalid_client_returns_policy_rejected() {
        let mock = Arc::new(MockOktaClient::new().with_response(401, invalid_client_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock);
        let req = okta_request(
            serde_json::json!({
                "scopes": ["okta.users.manage"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for 401 invalid_client, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_400_invalid_scope_returns_upstream_with_descriptive_message() {
        let mock = Arc::new(MockOktaClient::new().with_response(400, invalid_scope_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock);
        let req = okta_request(
            serde_json::json!({
                "scopes": ["okta.unknown.scope"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 400 invalid_scope, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("scope"),
            "error must mention 'scope': {msg}"
        );
    }

    #[tokio::test]
    async fn issue_400_expired_key_returns_upstream_with_key_expired_message() {
        let mock = Arc::new(MockOktaClient::new().with_response(400, expired_key_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock);
        let req = okta_request(
            serde_json::json!({
                "scopes": ["okta.users.manage"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 400 expired-key, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("key expired")
                || msg.to_ascii_lowercase().contains("kid"),
            "error must mention 'key expired' or 'kid': {msg}"
        );
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = OktaBroker::with_client(fixture_app(), Arc::new(MockOktaClient::new()));
        let mut req = okta_request(
            serde_json::json!({
                "scopes": ["okta.users.manage"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_empty_scopes_returns_invalid_scope() {
        let broker = OktaBroker::with_client(fixture_app(), Arc::new(MockOktaClient::new()));
        let req = okta_request(
            serde_json::json!({
                "scopes": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_zero_ttl_returns_invalid_scope() {
        let broker = OktaBroker::with_client(fixture_app(), Arc::new(MockOktaClient::new()));
        let req = okta_request(
            serde_json::json!({
                "scopes": ["okta.users.manage"],
                "ttl_seconds": 0,
            }),
            0,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_happy_path_calls_revoke_endpoint_and_drops_state() {
        let mock = Arc::new(
            MockOktaClient::new()
                .with_response(200, token_ok_body())
                .with_response(200, "".to_string()),
        );
        let broker = OktaBroker::with_client(fixture_app(), mock.clone());
        let cred = Broker::issue(
            &broker,
            okta_request(
                serde_json::json!({
                    "scopes": ["okta.users.manage"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        assert_eq!(broker.active_count(), 1);
        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed (best-effort)");
        assert_eq!(broker.active_count(), 0);
        // 1 form call for issue + 1 form call for revoke
        assert_eq!(mock.call_count(), 2);
        let last = mock.last_call().expect("revoke call recorded");
        assert_eq!(last.url, "https://example.okta.com/oauth2/v1/revoke");
        assert!(
            last.body.contains("token_type_hint=access_token"),
            "revoke body must include token_type_hint: {}",
            last.body
        );
        assert!(
            last.body.contains("token=00okta_access_token_for_tests"),
            "revoke body must include the bearer token: {}",
            last.body
        );
    }

    #[tokio::test]
    async fn revoke_404_already_revoked_treated_as_success() {
        let mock = Arc::new(
            MockOktaClient::new()
                .with_response(200, token_ok_body())
                .with_response(404, "{}".to_string()),
        );
        let broker = OktaBroker::with_client(fixture_app(), mock.clone());
        let cred = Broker::issue(
            &broker,
            okta_request(
                serde_json::json!({
                    "scopes": ["okta.users.manage"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed when token already gone");
        assert_eq!(broker.active_count(), 0);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = OktaBroker::with_client(fixture_app(), Arc::new(MockOktaClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn okta_scope_round_trips_through_json() {
        let scope = OktaScope {
            scopes: vec![
                "okta.users.manage".to_string(),
                "okta.groups.manage".to_string(),
            ],
            ttl_seconds: 1800,
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: OktaScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.scopes, scope.scopes);
        assert_eq!(parsed.ttl_seconds, scope.ttl_seconds);
    }

    #[test]
    fn map_okta_error_invalid_client_returns_policy_rejected() {
        let err = map_okta_error(401, &invalid_client_body());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected, got {err:?}"
        );
    }

    #[test]
    fn map_okta_error_invalid_scope_returns_upstream() {
        let err = map_okta_error(400, &invalid_scope_body());
        let msg = format!("{err}");
        assert!(matches!(err, BrokerError::Upstream(_)));
        assert!(
            msg.to_ascii_lowercase().contains("scope"),
            "must mention scope: {msg}"
        );
    }

    #[test]
    fn map_okta_error_expired_key_returns_upstream() {
        let err = map_okta_error(400, &expired_key_body());
        let msg = format!("{err}");
        assert!(matches!(err, BrokerError::Upstream(_)));
        assert!(
            msg.to_ascii_lowercase().contains("key expired")
                || msg.to_ascii_lowercase().contains("kid"),
            "must mention key expired or kid: {msg}"
        );
    }

    #[test]
    fn join_org_strips_single_trailing_slash() {
        assert_eq!(
            join_org("https://example.okta.com", "/oauth2/v1/token"),
            "https://example.okta.com/oauth2/v1/token"
        );
        assert_eq!(
            join_org("https://example.okta.com/", "/oauth2/v1/token"),
            "https://example.okta.com/oauth2/v1/token"
        );
    }

    #[test]
    fn random_jti_is_hex_and_unique_across_calls() {
        let a = random_jti();
        let b = random_jti();
        assert!(
            a.chars().all(|c| c.is_ascii_hexdigit()) || a.starts_with("ember-okta-"),
            "jti must be hex (or fallback prefixed): {a}"
        );
        assert_ne!(
            a, b,
            "two random_jti calls must (essentially always) produce different values"
        );
    }

    #[tokio::test]
    async fn issue_mint_stamp_records_okta_app_identity() {
        let mock = Arc::new(MockOktaClient::new().with_response(200, token_ok_body()));
        let broker = OktaBroker::with_client(fixture_app(), mock);
        let req = okta_request(
            serde_json::json!({ "scopes": ["api:access"], "ttl_seconds": 3600 }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        match &cred.mint_stamp {
            MintStamp::Identity { identity } => {
                assert_eq!(identity.provider, BrokerProvider::Okta);
                assert_eq!(
                    identity.identity,
                    "https://example.okta.com:0oa-test-service-app"
                );
            }
            other => panic!("expected MintStamp::Identity, got {other:?}"),
        }
    }
}
