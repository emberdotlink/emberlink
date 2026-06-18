//! Azure `Broker` implementation — issues short-lived OAuth bearer
//! tokens via the Azure AD service-principal client-credentials grant,
//! returns the bearer token as [`BrokeredCredential`] the consumer
//! (`broker_exec` / `apply_credential_to_env`) injects into the child
//! environment as `AZURE_ACCESS_TOKEN`.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`AzureServicePrincipal`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::azure_config`) and one entry per outstanding
//! materialization.
//!
//! ## Single-step mint
//!
//! POST `https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token`
//! with `application/x-www-form-urlencoded` body:
//!
//! ```text
//! grant_type=client_credentials
//! client_id=<client_id>
//! client_secret=<client_secret>
//! scope=<resource>/.default
//! ```
//!
//! Response is JSON: `{ "access_token": "...", "expires_in": 3600,
//! "token_type": "Bearer" }`.
//!
//! ## Workload Identity Federation (alternative auth)
//!
//! When [`AzureAuthMethod::FederatedIdentity`] is configured, the broker
//! reads a fresh OIDC token from `oidc_token_path` on every mint and
//! POSTs `client_assertion` instead of `client_secret`:
//!
//! ```text
//! grant_type=client_credentials
//! client_id=<client_id>
//! client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//! client_assertion=<oidc_token_read_from_disk>
//! scope=<resource>/.default
//! ```
//!
//! This is the Kubernetes / GitHub-Actions / generic-OIDC convention —
//! the workload's identity provider mounts a short-lived OIDC token at
//! a known filesystem path and Azure AD federates trust through the
//! IdP's issuer claim. No long-lived `client_secret` ever lives on the
//! broker host.
//!
//! ## Revocation
//!
//! Azure AD does NOT support programmatic OAuth-token revocation for
//! the client-credentials flow. `revoke()` therefore drops bookkeeping
//! and emits a `tracing::warn!` so the audit trail records the best-
//! effort semantics. The credential remains valid until its
//! `expires_at` (Azure caps OAuth bearer TTLs at one hour by default).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, IdentityRef, MintStamp,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// How the broker authenticates to Azure AD when minting tokens.
///
/// - [`AzureAuthMethod::ClientSecret`] — the historical default. The
///   service principal's long-lived client secret is held in a
///   [`SecretString`] and submitted as `client_secret` on the OAuth
///   token request.
/// - [`AzureAuthMethod::FederatedIdentity`] — Workload Identity
///   Federation. The broker reads a short-lived OIDC token from
///   `oidc_token_path` on every mint and submits it as
///   `client_assertion` (with `client_assertion_type` set to the
///   `jwt-bearer` URN). This is the Kubernetes / GitHub Actions / generic-
///   OIDC convention; no long-lived secret lives on the broker host.
///
/// `ClientSecret` remains the default for `AzureServicePrincipal::new`
/// callers and the daemon's dotenv loader — federation is opt-in.
#[derive(Clone, Debug)]
pub enum AzureAuthMethod {
    /// Long-lived service-principal client secret. Submitted as
    /// `client_secret` form parameter on the OAuth token request.
    ClientSecret { client_secret: SecretString },
    /// Workload Identity Federation — `oidc_token_path` is the
    /// filesystem path the broker reads on every mint to obtain a
    /// short-lived OIDC token. The contents are submitted as
    /// `client_assertion`. The token is NOT cached; it is re-read on
    /// every `issue()` so token-rotation by the OIDC issuer (kubelet
    /// projection refresh, Actions token rotation) is picked up
    /// without restart.
    FederatedIdentity { oidc_token_path: PathBuf },
}

/// Azure AD service-principal credentials backing the broker. Loaded
/// once at daemon startup from `~/.config/emberlink/azure.env` (see
/// `ember_daemon::broker::azure_config::load_azure_credentials`).
///
/// The broker uses these to mint short-lived OAuth bearer tokens. The
/// `auth_method` field selects between the historical
/// client-credentials path ([`AzureAuthMethod::ClientSecret`]) and the
/// Workload Identity Federation path
/// ([`AzureAuthMethod::FederatedIdentity`]). The default for new
/// configurations is `ClientSecret`.
#[derive(Clone)]
pub struct AzureServicePrincipal {
    /// Azure AD tenant id (UUID) — embedded in the OAuth token
    /// endpoint URL: `login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token`.
    pub tenant_id: String,
    /// Service-principal application (client) id.
    pub client_id: String,
    /// How the broker proves identity to Azure AD on each mint —
    /// either a long-lived client secret or a fresh OIDC token via
    /// Workload Identity Federation. See [`AzureAuthMethod`].
    pub auth_method: AzureAuthMethod,
}

/// Default OAuth resource URL when [`AzureScope::resource`] is empty.
/// Picked because Azure Resource Manager (ARM) covers the broadest
/// management-plane API surface; specialised callers (Graph, Key Vault)
/// override via the scope payload.
const DEFAULT_RESOURCE: &str = "https://management.azure.com/";

/// Provider-specific scope payload for the Azure broker.
///
/// Deserialized from the opaque `BrokerRequest::scope` (`serde_json::Value`)
/// inside `issue()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AzureScope {
    /// OAuth resource URL identifying the API the bearer token
    /// authenticates against. When empty, the broker falls back to
    /// [`DEFAULT_RESOURCE`] (Azure Resource Manager).
    #[serde(default)]
    pub resource: String,

    /// Optional fine-grained OAuth scopes
    /// (e.g. `["https://management.azure.com/.default"]`). When non-
    /// empty, the broker joins them with spaces and uses that as the
    /// `scope` form parameter — bypassing the default
    /// `<resource>/.default` shorthand. The two are mutually exclusive
    /// at request time; callers usually pick one or the other.
    #[serde(default)]
    pub scope: Vec<String>,

    /// Requested credential lifetime. Azure AD caps OAuth bearer TTLs
    /// at one hour by default; we pass through and let the upstream
    /// clamp.
    pub ttl_seconds: u64,
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `login.microsoftonline.com`.
///
/// Production callers use [`ReqwestAzureClient`]; tests use
/// [`MockAzureClient`].
#[async_trait::async_trait]
pub trait AzureHttpClient: Send + Sync {
    /// POST a `application/x-www-form-urlencoded` body to `url`. Used
    /// for the OAuth token endpoint.
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String>;
}

/// Production [`AzureHttpClient`] backed by `reqwest`.
pub struct ReqwestAzureClient {
    inner: reqwest::Client,
}

impl ReqwestAzureClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/azure")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestAzureClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl AzureHttpClient for ReqwestAzureClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by Azure AD service-principal client-credentials.
///
/// Construct with [`AzureCliBroker::new`] for production (uses
/// [`ReqwestAzureClient`]) or [`AzureCliBroker::with_client`] for tests
/// (any `dyn AzureHttpClient` implementation).
pub struct AzureCliBroker {
    sp: AzureServicePrincipal,
    client: Arc<dyn AzureHttpClient>,
    /// `materialization_id` → `expires_at`. Populated on `issue()`,
    /// drained on `revoke()`. The broker holds nothing else per
    /// outstanding token (Azure AD has no programmatic revoke for the
    /// client-credentials flow, so the plaintext is not retained).
    state: Mutex<HashMap<String, SystemTime>>,
}

impl AzureCliBroker {
    /// Production constructor — uses [`ReqwestAzureClient`].
    pub fn new(sp: AzureServicePrincipal) -> Self {
        Self {
            sp,
            client: Arc::new(
                ReqwestAzureClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`AzureHttpClient`] so
    /// unit tests can inject [`MockAzureClient`].
    pub fn with_client(sp: AzureServicePrincipal, client: Arc<dyn AzureHttpClient>) -> Self {
        Self {
            sp,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("azure broker state mutex").len()
    }

    fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.sp.tenant_id
        )
    }
}

/// Resolve the OAuth `scope` form-parameter from an [`AzureScope`].
/// Explicit fine-grained scopes win over the default
/// `<resource>/.default` shorthand. Both empty falls back to
/// `DEFAULT_RESOURCE/.default`.
fn resolve_scope_param(scope: &AzureScope) -> String {
    if !scope.scope.is_empty() {
        scope.scope.join(" ")
    } else {
        let resource = if scope.resource.is_empty() {
            DEFAULT_RESOURCE
        } else {
            scope.resource.as_str()
        };
        // The `.default` suffix is the Azure AD v2.0 convention for
        // requesting "all statically-configured permissions on this
        // resource" without per-request scope enumeration.
        let resource_trimmed = resource.trim_end_matches('/');
        format!("{resource_trimmed}/.default")
    }
}

/// Encode a slice of `(key, value)` pairs as a percent-encoded
/// `application/x-www-form-urlencoded` body.
fn encode_form(params: &[(&str, &str)]) -> String {
    let mut body = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            body.push('&');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut body, "{}={}", urlencode(k), urlencode(v));
    }
    body
}

/// Build the form-urlencoded body for an Azure AD client-credentials
/// token request signed with a long-lived client secret.
///
/// Extracted as a free function so tests can pin the exact body shape
/// without driving a full broker.
fn build_client_credentials_body(
    sp: &AzureServicePrincipal,
    client_secret: &SecretString,
    scope: &AzureScope,
) -> String {
    let scope_param = resolve_scope_param(scope);
    encode_form(&[
        ("grant_type", "client_credentials"),
        ("client_id", sp.client_id.as_str()),
        ("client_secret", client_secret.expose_secret()),
        ("scope", scope_param.as_str()),
    ])
}

/// Client-assertion type URN required by Azure AD when submitting an
/// OIDC token via Workload Identity Federation. Defined in RFC 7521
/// §4.2.
const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Build the form-urlencoded body for an Azure AD Workload Identity
/// Federation token request. Reads the OIDC token from
/// `oidc_token_path` on every call (no caching) so kubelet / GitHub-
/// Actions / generic-OIDC token rotation is picked up without
/// restarting the broker.
///
/// The OIDC token is submitted as `client_assertion` with
/// `client_assertion_type` set to the `jwt-bearer` URN. No long-lived
/// secret is included in the request body.
///
/// # Errors
///
/// Returns [`BrokerError::Upstream`] when the OIDC token file is
/// missing, unreadable, or empty after trimming whitespace. The token
/// must already be a JWT — Azure AD performs the federated-trust
/// validation by inspecting the `iss` claim and matching it against a
/// federated-credential trust policy on the service-principal app
/// registration.
fn azure_workload_identity_exchange(
    sp: &AzureServicePrincipal,
    oidc_token_path: &std::path::Path,
    scope: &AzureScope,
) -> Result<String, BrokerError> {
    let raw = std::fs::read_to_string(oidc_token_path).map_err(|e| {
        BrokerError::Upstream(format!(
            "Azure WIF: read OIDC token from {}: {e}",
            oidc_token_path.display()
        ))
    })?;
    let assertion = raw.trim();
    if assertion.is_empty() {
        return Err(BrokerError::Upstream(format!(
            "Azure WIF: OIDC token at {} is empty",
            oidc_token_path.display()
        )));
    }

    let scope_param = resolve_scope_param(scope);
    Ok(encode_form(&[
        ("grant_type", "client_credentials"),
        ("client_id", sp.client_id.as_str()),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
        ("client_assertion", assertion),
        ("scope", scope_param.as_str()),
    ]))
}

/// Minimal RFC3986 percent-encoder for form bodies. Encodes everything
/// outside the unreserved set `A-Za-z0-9-._~`. Avoids a full url crate
/// dep for one function (mirrors the GCP / AWS-STS broker shape).
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
// JSON shapes for the OAuth v2.0 token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    /// Lifetime of the bearer token, in seconds. Azure AD caps this at
    /// 3600s by default; we trust the upstream value over the
    /// caller-requested `ttl_seconds`.
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
}

/// Azure AD OAuth v2.0 error envelope. The token endpoint returns
/// `{ "error": "...", "error_description": "...", ... }` on failure
/// with a 4xx status.
#[derive(Debug, Deserialize)]
struct OauthErrorEnvelope {
    error: Option<String>,
    error_description: Option<String>,
}

/// Map an Azure AD OAuth error response to the closest [`BrokerError`]
/// variant. `invalid_client` (auth failure) → `PolicyRejected` (matches
/// the AWS/GCP broker convention for upstream auth failures);
/// `invalid_grant` / `invalid_scope` → `Upstream` with a descriptive
/// message; everything else falls through to `Upstream` with the raw
/// body.
fn map_azure_error(status: u16, body: &str) -> BrokerError {
    if let Ok(envelope) = serde_json::from_str::<OauthErrorEnvelope>(body) {
        let code = envelope.error.unwrap_or_default();
        let desc = envelope.error_description.unwrap_or_default();
        let lower = code.to_ascii_lowercase();
        // WIF-specific AADSTS codes Azure returns for federated-identity
        // failures. They typically arrive with error="invalid_client"
        // or "invalid_request"; routing on the AADSTS substring keeps
        // the mapping robust against shape drift.
        //
        // AADSTS50012 — invalid_client / "Invalid client secret" (also
        // emitted for malformed client_assertion).
        // AADSTS70021 — "No matching federated identity record found
        // for presented assertion." Indicates the OIDC issuer / subject
        // / audience does not match any federated-credential trust
        // record on the SP app registration — a policy decision by AAD.
        let desc_upper = desc.to_ascii_uppercase();
        let is_wif_assertion_failure =
            desc_upper.contains("AADSTS50012") || desc_upper.contains("AADSTS70021");
        if is_wif_assertion_failure {
            return BrokerError::PolicyRejected(format!(
                "Azure AD WIF assertion rejected ({code}): {desc} (status={status})"
            ));
        }
        if lower == "invalid_client" || lower == "unauthorized_client" || status == 401 {
            return BrokerError::PolicyRejected(format!(
                "Azure AD authentication failure ({code}): {desc} (status={status})"
            ));
        }
        if lower == "invalid_scope" {
            return BrokerError::Upstream(format!(
                "Azure AD invalid_scope: {desc} (status={status})"
            ));
        }
        if lower == "invalid_grant" {
            return BrokerError::Upstream(format!(
                "Azure AD client secret expired or invalid_grant: {desc} (status={status})"
            ));
        }
        if !code.is_empty() {
            return BrokerError::Upstream(format!(
                "Azure AD error ({code}): {desc} (status={status})"
            ));
        }
    }
    BrokerError::Upstream(format!("Azure AD error (status={status}): {body}"))
}

impl Broker for AzureCliBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::AzureCli
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::AzureCli {
            return Err(BrokerError::InvalidScope(format!(
                "AzureCliBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: AzureScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        if scope.ttl_seconds == 0 {
            return Err(BrokerError::InvalidScope(
                "ttl_seconds must be > 0".to_string(),
            ));
        }

        let url = self.token_url();
        let body = match &self.sp.auth_method {
            AzureAuthMethod::ClientSecret { client_secret } => {
                build_client_credentials_body(&self.sp, client_secret, &scope)
            }
            AzureAuthMethod::FederatedIdentity { oidc_token_path } => {
                azure_workload_identity_exchange(&self.sp, oidc_token_path, &scope)?
            }
        };

        let (status, resp_body) = self
            .client
            .post_form(&url, body)
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_azure_error(status, &resp_body);
            tracing::warn!(
                tenant_id = %self.sp.tenant_id,
                client_id = %self.sp.client_id,
                status = status,
                error = %err,
                "AzureCliBroker: OAuth token endpoint failed"
            );
            return Err(err);
        }

        let parsed: OauthTokenResponse = serde_json::from_str(&resp_body).map_err(|e| {
            BrokerError::Upstream(format!(
                "Azure AD token response parse failed: {e}; body={resp_body}"
            ))
        })?;

        // Azure returns `expires_in` (seconds-from-now). Convert to a
        // wall-clock SystemTime for the BrokeredCredential. Fall back
        // to the requested TTL if the upstream value is missing or
        // negative (defensive — well-formed responses always include
        // it, but we never want to surface a SystemTime in the past).
        let now = SystemTime::now();
        let lifetime = if parsed.expires_in > 0 {
            parsed.expires_in as u64
        } else {
            scope.ttl_seconds
        };
        let expires_at = now + std::time::Duration::from_secs(lifetime);

        let materialization_id = format!(
            "azure-{}-{}",
            self.sp.client_id,
            chrono_timestamp(expires_at),
        );

        self.state
            .lock()
            .expect("azure broker state mutex")
            .insert(materialization_id.clone(), expires_at);

        Ok(BrokeredCredential {
            token: SecretString::from(parsed.access_token),
            expires_at,
            materialization_id,
            mint_stamp: MintStamp::Identity {
                identity: IdentityRef {
                    provider: BrokerProvider::AzureCli,
                    identity: format!("{}/{}", self.sp.tenant_id, self.sp.client_id),
                },
            },
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        // Azure AD does not support programmatic OAuth-token revocation
        // for the client-credentials flow. Drop bookkeeping; the
        // credential remains valid until its expires_at. See module
        // docs.
        let mut st = self.state.lock().expect("azure broker state mutex");
        if st.remove(materialization_id).is_none() {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        }
        tracing::warn!(
            materialization_id = %materialization_id,
            "AzureCliBroker: revoke is best-effort — Azure AD has no programmatic OAuth revoke for client-credentials; the vended token remains valid until expiration"
        );
        Ok(())
    }
}

/// Convert a `SystemTime` to a Unix-epoch second count for embedding
/// into a `materialization_id`. Falls back to 0 on the (impossible)
/// pre-1970 path so the function is total.
fn chrono_timestamp(t: SystemTime) -> i64 {
    use chrono::{DateTime, Utc};
    DateTime::<Utc>::from(t).timestamp()
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

/// Scripted-response mock client for unit tests. Each call pops the
/// next `(status, body)` from `responses`. If the queue is empty the
/// mock returns the last entry forever, which keeps test setup terse
/// while still letting tests assert call ordering when they care.
pub struct MockAzureClient {
    pub responses: Mutex<Vec<(u16, String)>>,
    pub calls: Mutex<Vec<(String, String)>>,
}

impl MockAzureClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
        self.responses
            .lock()
            .expect("mock azure mutex")
            .push((status, body.into()));
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock azure mutex").len()
    }

    pub fn last_body(&self) -> Option<String> {
        self.calls
            .lock()
            .expect("mock azure mutex")
            .last()
            .map(|(_, body)| body.clone())
    }

    pub fn last_url(&self) -> Option<String> {
        self.calls
            .lock()
            .expect("mock azure mutex")
            .last()
            .map(|(url, _)| url.clone())
    }
}

impl Default for MockAzureClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AzureHttpClient for MockAzureClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock azure mutex")
            .push((url.to_string(), body.clone()));
        let mut q = self.responses.lock().expect("mock azure mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockAzureClient: no response queued for {url}; body={body}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_sp() -> AzureServicePrincipal {
        AzureServicePrincipal {
            tenant_id: "11111111-2222-3333-4444-555555555555".to_string(),
            client_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            auth_method: AzureAuthMethod::ClientSecret {
                client_secret: SecretString::from("fake-client-secret-for-tests".to_string()),
            },
        }
    }

    fn fixture_sp_wif(oidc_token_path: PathBuf) -> AzureServicePrincipal {
        AzureServicePrincipal {
            tenant_id: "11111111-2222-3333-4444-555555555555".to_string(),
            client_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            auth_method: AzureAuthMethod::FederatedIdentity { oidc_token_path },
        }
    }

    fn fake_oidc_jwt() -> &'static str {
        // Header.Payload.Signature shape — AAD parses without
        // validating signature locally; the federated-credential trust
        // policy on the SP app registration is what gates approval.
        "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMifQ.fake-sig"
    }

    fn azure_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::AzureCli,
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
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake-azure-token",
            "expires_in": 3599,
            "token_type": "Bearer",
        })
        .to_string()
    }

    fn invalid_client_body() -> String {
        serde_json::json!({
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.",
        })
        .to_string()
    }

    fn invalid_scope_body() -> String {
        serde_json::json!({
            "error": "invalid_scope",
            "error_description": "AADSTS70011: The provided value for the input parameter 'scope' is not valid.",
        })
        .to_string()
    }

    fn invalid_grant_body() -> String {
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "AADSTS7000222: The provided client secret has expired.",
        })
        .to_string()
    }

    #[test]
    fn provider_returns_azure_cli() {
        let broker = AzureCliBroker::with_client(fixture_sp(), Arc::new(MockAzureClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::AzureCli);
    }

    #[test]
    fn token_url_embeds_tenant_id() {
        let broker = AzureCliBroker::with_client(fixture_sp(), Arc::new(MockAzureClient::new()));
        assert_eq!(
            broker.token_url(),
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token"
        );
    }

    /// Helper — extract the secret out of an `AzureAuthMethod::ClientSecret`
    /// so the body-shape unit tests can drive the body-builder
    /// directly. Panics if the test fixture is misconfigured (a
    /// federated-identity SP feeds the WIF-exchange tests below).
    fn fixture_client_secret(sp: &AzureServicePrincipal) -> SecretString {
        match &sp.auth_method {
            AzureAuthMethod::ClientSecret { client_secret } => client_secret.clone(),
            _ => panic!("fixture is not a ClientSecret SP"),
        }
    }

    #[test]
    fn build_client_credentials_body_uses_default_resource_when_scope_empty() {
        let scope = AzureScope::default();
        let sp = fixture_sp();
        let secret = fixture_client_secret(&sp);
        let body = build_client_credentials_body(&sp, &secret, &scope);
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        // DEFAULT_RESOURCE = "https://management.azure.com/" → trimmed +
        // ".default" → "https://management.azure.com/.default" (URL-encoded).
        assert!(
            body.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"),
            "expected default-resource scope, got body={body}"
        );
    }

    #[test]
    fn build_client_credentials_body_uses_explicit_resource() {
        let scope = AzureScope {
            resource: "https://vault.azure.net/".to_string(),
            scope: vec![],
            ttl_seconds: 3600,
        };
        let sp = fixture_sp();
        let secret = fixture_client_secret(&sp);
        let body = build_client_credentials_body(&sp, &secret, &scope);
        assert!(
            body.contains("scope=https%3A%2F%2Fvault.azure.net%2F.default"),
            "expected vault.azure.net resource, got body={body}"
        );
    }

    #[test]
    fn build_client_credentials_body_uses_explicit_scope_list_over_resource() {
        let scope = AzureScope {
            resource: "https://management.azure.com/".to_string(),
            scope: vec![
                "https://graph.microsoft.com/.default".to_string(),
                "openid".to_string(),
            ],
            ttl_seconds: 3600,
        };
        let sp = fixture_sp();
        let secret = fixture_client_secret(&sp);
        let body = build_client_credentials_body(&sp, &secret, &scope);
        // Spaces between scopes percent-encode to %20.
        assert!(
            body.contains("scope=https%3A%2F%2Fgraph.microsoft.com%2F.default%20openid"),
            "expected explicit scope list, got body={body}"
        );
    }

    #[test]
    fn build_client_credentials_body_includes_client_secret() {
        let scope = AzureScope::default();
        let sp = fixture_sp();
        let secret = fixture_client_secret(&sp);
        let body = build_client_credentials_body(&sp, &secret, &scope);
        assert!(body.contains("client_secret=fake-client-secret-for-tests"));
    }

    #[tokio::test]
    async fn issue_success_returns_bearer_token() {
        let mock = Arc::new(MockAzureClient::new().with_response(200, token_ok_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock.clone());
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake-azure-token"
        );
        assert!(
            cred.materialization_id
                .starts_with("azure-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-"),
            "materialization_id includes client_id: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);
        assert_eq!(mock.call_count(), 1);
        assert!(
            mock.last_url().unwrap().contains(
                "login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token"
            ),
            "request URL must include tenant id: {}",
            mock.last_url().unwrap()
        );
    }

    #[tokio::test]
    async fn issue_with_empty_resource_uses_default() {
        let mock = Arc::new(MockAzureClient::new().with_response(200, token_ok_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock.clone());
        let req = azure_request(
            serde_json::json!({
                "resource": "",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        let body = mock.last_body().expect("call recorded");
        assert!(
            body.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"),
            "empty-resource scope must fall back to DEFAULT_RESOURCE: {body}"
        );
    }

    #[tokio::test]
    async fn issue_invalid_client_returns_policy_rejected() {
        let mock = Arc::new(MockAzureClient::new().with_response(401, invalid_client_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock);
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for invalid_client, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_invalid_scope_returns_upstream() {
        let mock = Arc::new(MockAzureClient::new().with_response(400, invalid_scope_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock);
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for invalid_scope, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("invalid_scope"),
            "error must mention invalid_scope: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_invalid_grant_on_expired_secret_returns_upstream() {
        let mock = Arc::new(MockAzureClient::new().with_response(400, invalid_grant_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock);
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for invalid_grant, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("invalid_grant")
                || msg.to_ascii_lowercase().contains("expired"),
            "error must mention invalid_grant / expired: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_with_zero_ttl_returns_invalid_scope_error() {
        let broker = AzureCliBroker::with_client(fixture_sp(), Arc::new(MockAzureClient::new()));
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 0,
            }),
            0,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = AzureCliBroker::with_client(fixture_sp(), Arc::new(MockAzureClient::new()));
        let mut req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_drops_state_returns_ok_with_warn() {
        let mock = Arc::new(MockAzureClient::new().with_response(200, token_ok_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock.clone());
        let cred = Broker::issue(
            &broker,
            azure_request(
                serde_json::json!({
                    "resource": "https://management.azure.com/",
                    "scope": [],
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
        // No HTTP call for revoke — Azure has no programmatic revoke
        // for client-credentials. The mock should have been called
        // exactly once (for the issue).
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = AzureCliBroker::with_client(fixture_sp(), Arc::new(MockAzureClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn azure_scope_round_trips_through_json() {
        let scope = AzureScope {
            resource: "https://vault.azure.net/".to_string(),
            scope: vec![
                "https://graph.microsoft.com/.default".to_string(),
                "offline_access".to_string(),
            ],
            ttl_seconds: 1800,
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: AzureScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.resource, scope.resource);
        assert_eq!(parsed.scope, scope.scope);
        assert_eq!(parsed.ttl_seconds, scope.ttl_seconds);
    }

    #[test]
    fn map_azure_error_invalid_client_returns_policy_rejected() {
        let err = map_azure_error(401, &invalid_client_body());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected, got {err:?}"
        );
    }

    #[test]
    fn map_azure_error_invalid_scope_returns_upstream() {
        let err = map_azure_error(400, &invalid_scope_body());
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
    }

    #[test]
    fn map_azure_error_invalid_grant_returns_upstream() {
        let err = map_azure_error(400, &invalid_grant_body());
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // Workload Identity Federation tests
    // ---------------------------------------------------------------

    fn aadsts50012_body() -> String {
        // Real-world AAD shape: error="invalid_client",
        // error_description carries the AADSTS50012 token.
        serde_json::json!({
            "error": "invalid_client",
            "error_description": "AADSTS50012: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '<id>'.",
        })
        .to_string()
    }

    fn aadsts70021_body() -> String {
        // AAD's federated-identity rejection. Often arrives with
        // error="invalid_request"; the AADSTS70021 substring is the
        // reliable router.
        serde_json::json!({
            "error": "invalid_request",
            "error_description": "AADSTS70021: No matching federated identity record found for presented assertion. Assertion Issuer: 'https://kubernetes.default.svc'. Assertion Subject: 'system:serviceaccount:ns:sa'. Assertion Audience: 'api://AzureADTokenExchange'.",
        })
        .to_string()
    }

    fn write_oidc_token(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("oidc-token");
        std::fs::write(&path, contents).expect("write OIDC token fixture");
        path
    }

    #[test]
    fn azure_workload_identity_exchange_builds_client_assertion_body() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let sp = fixture_sp_wif(token_path.clone());
        let scope = AzureScope {
            resource: "https://management.azure.com/".to_string(),
            scope: vec![],
            ttl_seconds: 3600,
        };
        let body = azure_workload_identity_exchange(&sp, &token_path, &scope).expect("build body");
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        // client_assertion_type is the jwt-bearer URN, percent-encoded.
        assert!(
            body.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"),
            "client_assertion_type must be the jwt-bearer URN: {body}"
        );
        // client_assertion is the OIDC token verbatim. Dots and dashes
        // are unreserved characters so they round-trip without
        // percent-encoding.
        assert!(
            body.contains(&format!("client_assertion={}", fake_oidc_jwt())),
            "client_assertion must carry the OIDC token verbatim: {body}"
        );
        // No client_secret leaked into the federation request.
        assert!(
            !body.contains("client_secret="),
            "WIF body must NOT include client_secret: {body}"
        );
    }

    #[test]
    fn azure_workload_identity_exchange_trims_oidc_token_whitespace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // kubelet's projected-token volume sometimes includes a
        // trailing newline; strip it so the JWT round-trips clean.
        let raw = format!("{}\n", fake_oidc_jwt());
        let token_path = write_oidc_token(tmp.path(), &raw);
        let sp = fixture_sp_wif(token_path.clone());
        let scope = AzureScope::default();
        let body = azure_workload_identity_exchange(&sp, &token_path, &scope).expect("build body");
        assert!(
            body.contains(&format!("client_assertion={}", fake_oidc_jwt())),
            "trailing newline must be trimmed before submission: {body}"
        );
        assert!(
            !body.contains("client_assertion=eyJ%0A"),
            "trimmed token must not carry encoded newline: {body}"
        );
    }

    #[test]
    fn azure_workload_identity_exchange_missing_token_returns_upstream() {
        let sp = fixture_sp_wif(PathBuf::from("/nonexistent/path/oidc-token"));
        let scope = AzureScope::default();
        let err = azure_workload_identity_exchange(
            &sp,
            std::path::Path::new("/nonexistent/path/oidc-token"),
            &scope,
        )
        .unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "missing token file must surface as Upstream, got {err:?}"
        );
    }

    #[test]
    fn azure_workload_identity_exchange_empty_token_returns_upstream() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), "   \n  \t");
        let sp = fixture_sp_wif(token_path.clone());
        let scope = AzureScope::default();
        let err = azure_workload_identity_exchange(&sp, &token_path, &scope).unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "whitespace-only token must surface as Upstream, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_federated_identity_succeeds_and_submits_client_assertion() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let mock = Arc::new(MockAzureClient::new().with_response(200, token_ok_body()));
        let broker = AzureCliBroker::with_client(fixture_sp_wif(token_path), mock.clone());
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("WIF issue must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake-azure-token"
        );
        let body = mock.last_body().expect("call recorded");
        assert!(
            body.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"),
            "submitted body must carry jwt-bearer client_assertion_type: {body}"
        );
        assert!(
            body.contains(&format!("client_assertion={}", fake_oidc_jwt())),
            "submitted body must carry OIDC client_assertion: {body}"
        );
        assert!(
            !body.contains("client_secret="),
            "submitted WIF body must NOT include client_secret: {body}"
        );
    }

    #[tokio::test]
    async fn issue_with_federated_identity_rereads_token_each_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), "first-token-value");
        let mock = Arc::new(
            MockAzureClient::new()
                .with_response(200, token_ok_body())
                .with_response(200, token_ok_body()),
        );
        let broker = AzureCliBroker::with_client(fixture_sp_wif(token_path.clone()), mock.clone());

        // First call uses "first-token-value".
        Broker::issue(
            &broker,
            azure_request(
                serde_json::json!({
                    "resource": "https://management.azure.com/",
                    "scope": [],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("first issue must succeed");

        // Rotate the on-disk token (kubelet projected-token refresh,
        // GH Actions step boundary, etc.).
        std::fs::write(&token_path, "second-token-value").expect("rotate OIDC token");

        Broker::issue(
            &broker,
            azure_request(
                serde_json::json!({
                    "resource": "https://management.azure.com/",
                    "scope": [],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("second issue must succeed");

        // The mock recorded two calls; the second must carry the
        // rotated token, proving the broker re-reads the file fresh
        // rather than caching from the first issue.
        let calls = mock.calls.lock().expect("mock azure mutex");
        assert_eq!(
            calls.len(),
            2,
            "two HTTP calls expected, got {}",
            calls.len()
        );
        assert!(
            calls[0].1.contains("client_assertion=first-token-value"),
            "first call must carry first-token: {}",
            calls[0].1
        );
        assert!(
            calls[1].1.contains("client_assertion=second-token-value"),
            "second call must carry rotated token: {}",
            calls[1].1
        );
    }

    #[tokio::test]
    async fn issue_with_federated_identity_missing_token_returns_upstream() {
        // No file ever written → mint must fail before the HTTP call.
        let mock = Arc::new(MockAzureClient::new());
        let broker = AzureCliBroker::with_client(
            fixture_sp_wif(PathBuf::from("/nonexistent/oidc-token")),
            mock.clone(),
        );
        let err = Broker::issue(
            &broker,
            azure_request(
                serde_json::json!({
                    "resource": "https://management.azure.com/",
                    "scope": [],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "missing OIDC token must surface as Upstream, got {err:?}"
        );
        assert_eq!(
            mock.call_count(),
            0,
            "broker must not POST to AAD when OIDC token unreadable"
        );
    }

    #[tokio::test]
    async fn issue_with_federated_identity_aadsts50012_returns_policy_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let mock = Arc::new(MockAzureClient::new().with_response(401, aadsts50012_body()));
        let broker = AzureCliBroker::with_client(fixture_sp_wif(token_path), mock);
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "AADSTS50012 must map to PolicyRejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_federated_identity_aadsts70021_returns_policy_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let mock = Arc::new(
            // AADSTS70021 typically arrives as 400 invalid_request.
            MockAzureClient::new().with_response(400, aadsts70021_body()),
        );
        let broker = AzureCliBroker::with_client(fixture_sp_wif(token_path), mock);
        let req = azure_request(
            serde_json::json!({
                "resource": "https://management.azure.com/",
                "scope": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "AADSTS70021 (no matching federated identity) must map to PolicyRejected, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.to_uppercase().contains("AADSTS70021"),
            "PolicyRejected message must surface the AADSTS code: {msg}"
        );
    }

    #[test]
    fn map_azure_error_aadsts50012_returns_policy_rejected() {
        let err = map_azure_error(401, &aadsts50012_body());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for AADSTS50012, got {err:?}"
        );
    }

    #[test]
    fn map_azure_error_aadsts70021_returns_policy_rejected() {
        let err = map_azure_error(400, &aadsts70021_body());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for AADSTS70021, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_mint_stamp_records_service_principal_identity() {
        let mock = Arc::new(MockAzureClient::new().with_response(200, token_ok_body()));
        let broker = AzureCliBroker::with_client(fixture_sp(), mock);
        let req = azure_request(
            serde_json::json!({ "resource": "https://management.azure.com/", "scope": [], "ttl_seconds": 3600 }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        match &cred.mint_stamp {
            MintStamp::Identity { identity } => {
                assert_eq!(identity.provider, BrokerProvider::AzureCli);
                assert_eq!(
                    identity.identity,
                    "11111111-2222-3333-4444-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                );
            }
            other => panic!("expected MintStamp::Identity, got {other:?}"),
        }
    }
}
