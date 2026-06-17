//! Vercel `Broker` implementation — issues short-lived scoped Vercel
//! API tokens via Vercel's `POST /v3/user/tokens` endpoint and returns
//! the minted token as [`BrokeredCredential`] the consumer
//! (`broker_exec` / `apply_credential_to_env`) injects into the child
//! environment as `VERCEL_TOKEN`.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`VercelParentToken`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::vercel_config`) and one entry per outstanding
//! materialization.
//!
//! ## Single-step mint
//!
//! POST `https://api.vercel.com/v3/user/tokens` with
//! `Authorization: Bearer <parent VERCEL_TOKEN>` and a JSON body:
//!
//! ```json
//! {
//!   "name": "<name>",
//!   "expiration": <unix_timestamp>,
//!   "teamId": "<team_id>"   // optional; omitted for personal-account scope
//! }
//! ```
//!
//! Response: `{ token: { id: "...", token: "...", name: "...",
//! expiration: ... } }`. The inner `token` field is the new access
//! token; the inner `id` is what `revoke()` uses.
//!
//! ## Revocation
//!
//! Vercel exposes `DELETE /v3/user/tokens/<token_id>` — best-effort;
//! 404 (already-revoked) treated as success. The TTL bound is the real
//! safety net.
//!
//! No canonical Vercel SDK exists in Rust; this module talks to the
//! REST surface directly with `reqwest`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, MintStamp,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Vercel parent API token + optional default team id. Loaded once at
/// daemon startup from `~/.config/emberlink/vercel.env` (see
/// `ember_daemon::broker::vercel_config::load_vercel_credentials`).
///
/// The broker uses the parent token to mint short-lived scoped tokens
/// via Vercel's `POST /v3/user/tokens` endpoint. The `token` is held in
/// a [`SecretString`] so it cannot be accidentally `Debug`-printed or
/// logged.
#[derive(Clone)]
pub struct VercelParentToken {
    /// Long-lived Vercel API token (a personal-account or team token
    /// with `tokens:create` scope) the broker exchanges for short-lived
    /// scoped tokens.
    pub token: SecretString,
    /// Optional default team id used when [`VercelScope::team_id`] is
    /// empty. When set, the broker scopes the minted token to this team
    /// by default. When unset, the minted token is personal-account-
    /// scoped.
    pub default_team_id: Option<String>,
}

/// Provider-specific scope payload for the Vercel broker.
///
/// Deserialized from the opaque `BrokerRequest::scope`
/// (`serde_json::Value`) inside `issue()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VercelScope {
    /// Team id to scope the token to. Falls back to
    /// [`VercelParentToken::default_team_id`] when empty. When neither
    /// is set, the broker mints a personal-account-scoped token (no
    /// `teamId` in the request body).
    #[serde(default)]
    pub team_id: Option<String>,

    /// Requested credential lifetime, in seconds. Vercel tokens default
    /// to no expiry — we always pass an explicit expiration so the
    /// minted credential is bounded.
    pub expiration_seconds: u64,

    /// Human-readable name Vercel stores alongside the token (visible
    /// in the Vercel dashboard + needed to identify the token for
    /// revoke).
    pub name: String,
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `api.vercel.com`.
///
/// Production callers use [`ReqwestVercelClient`]; tests use
/// [`MockVercelClient`].
#[async_trait::async_trait]
pub trait VercelHttpClient: Send + Sync {
    /// POST a JSON body to `url` with `Authorization: Bearer <bearer>`.
    /// Used for the `POST /v3/user/tokens` endpoint.
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String>;

    /// DELETE `url` with `Authorization: Bearer <bearer>`. Used for the
    /// `DELETE /v3/user/tokens/<token_id>` revoke endpoint.
    async fn delete_bearer(&self, url: &str, bearer: &str) -> Result<(u16, String), String>;
}

/// Production [`VercelHttpClient`] backed by `reqwest`.
pub struct ReqwestVercelClient {
    inner: reqwest::Client,
}

impl ReqwestVercelClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/vercel")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestVercelClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl VercelHttpClient for ReqwestVercelClient {
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    async fn delete_bearer(&self, url: &str, bearer: &str) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .delete(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by Vercel's `POST /v3/user/tokens` endpoint.
///
/// Construct with [`VercelBroker::new`] for production (uses
/// [`ReqwestVercelClient`]) or [`VercelBroker::with_client`] for tests
/// (any `dyn VercelHttpClient` implementation).
pub struct VercelBroker {
    parent: VercelParentToken,
    client: Arc<dyn VercelHttpClient>,
    /// `materialization_id` → `(expires_at, token_id)`. Token id is
    /// captured so `revoke()` can call `DELETE /v3/user/tokens/<id>`
    /// (which expects the Vercel token id, not the token plaintext).
    state: Mutex<HashMap<String, VercelMaterializationState>>,
}

struct VercelMaterializationState {
    expires_at: SystemTime,
    token_id: String,
}

impl VercelBroker {
    /// Production constructor — uses [`ReqwestVercelClient`].
    pub fn new(parent: VercelParentToken) -> Self {
        Self {
            parent,
            client: Arc::new(
                ReqwestVercelClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`VercelHttpClient`] so
    /// unit tests can inject [`MockVercelClient`].
    pub fn with_client(parent: VercelParentToken, client: Arc<dyn VercelHttpClient>) -> Self {
        Self {
            parent,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("vercel broker state mutex").len()
    }
}

const VERCEL_TOKENS_URL: &str = "https://api.vercel.com/v3/user/tokens";

/// Build the JSON request body for `POST /v3/user/tokens`. Resolves the
/// scope into either a personal-account variant (no `teamId`) or a
/// team-scoped variant. `team_id` falls back to `default_team_id` when
/// the scope's value is empty.
///
/// `now_epoch_secs` is taken as a parameter so unit tests can pin the
/// emitted `expiration` deterministically.
///
/// Extracted as a free function so tests can pin the exact body shape
/// without driving a full broker.
pub fn build_create_token_body(
    scope: &VercelScope,
    default_team_id: Option<&str>,
    now_epoch_secs: i64,
) -> Result<String, BrokerError> {
    if scope.name.trim().is_empty() {
        return Err(BrokerError::InvalidScope(
            "VercelScope.name must be non-empty".to_string(),
        ));
    }
    if scope.expiration_seconds == 0 {
        return Err(BrokerError::InvalidScope(
            "VercelScope.expiration_seconds must be > 0".to_string(),
        ));
    }

    let team_id_explicit = scope
        .team_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let team_id_default = default_team_id.map(str::trim).filter(|s| !s.is_empty());
    let team_id = team_id_explicit.or(team_id_default);

    // Vercel's `expiration` is a Unix timestamp in milliseconds (the
    // dashboard surfaces an absolute date). Pass an explicit absolute
    // expiration so the minted credential is always bounded.
    let expiration_ms = now_epoch_secs
        .saturating_add(scope.expiration_seconds as i64)
        .saturating_mul(1000);

    let body = if let Some(team) = team_id {
        serde_json::json!({
            "name": scope.name,
            "expiration": expiration_ms,
            "teamId": team,
        })
    } else {
        serde_json::json!({
            "name": scope.name,
            "expiration": expiration_ms,
        })
    };

    serde_json::to_string(&body)
        .map_err(|e| BrokerError::Other(format!("vercel create-token body encode: {e}")))
}

// ---------------------------------------------------------------------------
// JSON shapes for the create-token response envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateTokenResponse {
    token: CreatedToken,
}

#[derive(Debug, Deserialize)]
struct CreatedToken {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    token: String,
    #[serde(default)]
    #[allow(dead_code)]
    expiration: Option<i64>,
}

/// Map a Vercel non-2xx response (status + body) to the closest
/// [`BrokerError`] variant. Vercel returns a JSON envelope of the form
/// `{ "error": { "code": "...", "message": "..." } }`.
///
/// - 401 / `forbidden` (parent token unauthenticated) → `PolicyRejected`
/// - 403 (parent token missing `tokens:create` scope) → `PolicyRejected`
/// - everything else → `Upstream` with a descriptive message
fn map_vercel_error(status: u16, body: &str) -> BrokerError {
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let error_code = parsed
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let error_message = parsed
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let combined = format!("{error_code}: {error_message}");
    let lower_code = error_code.to_ascii_lowercase();

    if status == 401
        || status == 403
        || lower_code == "forbidden"
        || lower_code == "unauthorized"
        || lower_code == "not_authorized"
    {
        return BrokerError::PolicyRejected(format!(
            "Vercel unauthorized (status={status}): {combined}"
        ));
    }

    BrokerError::Upstream(format!(
        "Vercel /v3/user/tokens error (status={status}): {combined}"
    ))
}

impl Broker for VercelBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Vercel
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Vercel {
            return Err(BrokerError::InvalidScope(format!(
                "VercelBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: VercelScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        let now_secs = Utc::now().timestamp();
        let body =
            build_create_token_body(&scope, self.parent.default_team_id.as_deref(), now_secs)?;

        let (status, resp_body) = self
            .client
            .post_json_bearer(VERCEL_TOKENS_URL, self.parent.token.expose_secret(), body)
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_vercel_error(status, &resp_body);
            tracing::warn!(
                status = status,
                error = %err,
                "VercelBroker: POST /v3/user/tokens non-2xx"
            );
            return Err(err);
        }

        let parsed: CreateTokenResponse = serde_json::from_str(&resp_body).map_err(|e| {
            BrokerError::Upstream(format!(
                "Vercel create-token response parse failed: {e}; body={resp_body}"
            ))
        })?;

        let CreatedToken {
            id: token_id,
            name: _,
            token,
            expiration: _,
        } = parsed.token;

        let now = SystemTime::now();
        let expires_at = now + std::time::Duration::from_secs(scope.expiration_seconds);

        let materialization_id = format!(
            "vercel-{}-{}",
            token_id,
            DateTime::<Utc>::from(expires_at).timestamp()
        );

        self.state
            .lock()
            .expect("vercel broker state mutex")
            .insert(
                materialization_id.clone(),
                VercelMaterializationState {
                    expires_at,
                    token_id,
                },
            );

        Ok(BrokeredCredential {
            token: SecretString::from(token),
            expires_at,
            materialization_id,
            mint_stamp: MintStamp::Opaque,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        let entry = self
            .state
            .lock()
            .expect("vercel broker state mutex")
            .remove(materialization_id);
        let Some(state) = entry else {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        };

        // Best-effort upstream revoke. Vercel's
        // `DELETE /v3/user/tokens/<id>` accepts the token id; failures
        // are warned but do not surface as `Err` because the TTL bound
        // is the real safety net.
        let url = format!("{VERCEL_TOKENS_URL}/{}", state.token_id);
        match self
            .client
            .delete_bearer(&url, self.parent.token.expose_secret())
            .await
        {
            Ok((status, _)) if (200..300).contains(&status) => {
                tracing::info!(
                    materialization_id = %materialization_id,
                    "VercelBroker: revoke succeeded"
                );
            }
            Ok((404, _)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    "VercelBroker: revoke returned 404 (token already expired/revoked; treating as success)"
                );
            }
            Ok((status, resp_body)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = status,
                    body = %resp_body,
                    "VercelBroker: upstream revoke non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "VercelBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        let _ = state.expires_at;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

/// Recorded HTTP call for assertion in tests.
#[derive(Debug, Clone)]
pub struct MockVercelCall {
    pub method: &'static str,
    pub url: String,
    pub bearer: String,
    pub body: Option<String>,
}

/// Scripted-response mock client for unit tests. Each call pops the
/// next `(status, body)` from `responses`. If the queue is empty the
/// mock returns the last entry forever, which keeps test setup terse
/// while still letting tests assert call ordering when they care.
pub struct MockVercelClient {
    pub responses: Mutex<Vec<(u16, String)>>,
    pub calls: Mutex<Vec<MockVercelCall>>,
}

impl MockVercelClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
        self.responses
            .lock()
            .expect("mock vercel mutex")
            .push((status, body.into()));
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock vercel mutex").len()
    }

    pub fn last_call(&self) -> Option<MockVercelCall> {
        self.calls
            .lock()
            .expect("mock vercel mutex")
            .last()
            .cloned()
    }
}

impl Default for MockVercelClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl VercelHttpClient for MockVercelClient {
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock vercel mutex")
            .push(MockVercelCall {
                method: "POST",
                url: url.to_string(),
                bearer: bearer.to_string(),
                body: Some(body.clone()),
            });
        let mut q = self.responses.lock().expect("mock vercel mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockVercelClient: no response queued for POST {url}; body={body}"
            ))
        }
    }

    async fn delete_bearer(&self, url: &str, bearer: &str) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock vercel mutex")
            .push(MockVercelCall {
                method: "DELETE",
                url: url.to_string(),
                bearer: bearer.to_string(),
                body: None,
            });
        let mut q = self.responses.lock().expect("mock vercel mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockVercelClient: no response queued for DELETE {url}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_parent() -> VercelParentToken {
        VercelParentToken {
            token: SecretString::from("vc1_fake-parent-token-for-tests".to_string()),
            default_team_id: Some("team_default".to_string()),
        }
    }

    fn fixture_parent_no_default() -> VercelParentToken {
        VercelParentToken {
            token: SecretString::from("vc1_no_default".to_string()),
            default_team_id: None,
        }
    }

    fn vercel_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Vercel,
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

    fn create_ok_body(token_id: &str, name: &str, token: &str) -> String {
        serde_json::json!({
            "token": {
                "id": token_id,
                "name": name,
                "token": token,
                "expiration": 1_900_000_000_000_i64,
            }
        })
        .to_string()
    }

    fn unauthorized_body() -> String {
        serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "Not authorized",
            }
        })
        .to_string()
    }

    fn forbidden_scope_body() -> String {
        serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "Token is missing the tokens:create scope",
            }
        })
        .to_string()
    }

    fn bad_request_body() -> String {
        serde_json::json!({
            "error": {
                "code": "bad_request",
                "message": "Body is malformed",
            }
        })
        .to_string()
    }

    fn invalid_expiration_body() -> String {
        serde_json::json!({
            "error": {
                "code": "invalid_request",
                "message": "expiration must be in the future",
            }
        })
        .to_string()
    }

    #[test]
    fn provider_returns_vercel() {
        let broker = VercelBroker::with_client(fixture_parent(), Arc::new(MockVercelClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::Vercel);
    }

    #[test]
    fn build_create_token_body_personal_scope_omits_team_id() {
        let scope = VercelScope {
            team_id: None,
            expiration_seconds: 3600,
            name: "ember-personal".to_string(),
        };
        let body = build_create_token_body(&scope, None, 1_700_000_000).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed.get("name").and_then(|v| v.as_str()),
            Some("ember-personal")
        );
        assert!(
            parsed.get("teamId").is_none(),
            "personal-scope must omit teamId: {body}"
        );
        // Verify expiration is absolute Unix epoch in milliseconds
        let exp = parsed
            .get("expiration")
            .and_then(|v| v.as_i64())
            .expect("expiration must be set");
        assert_eq!(exp, (1_700_000_000_i64 + 3600) * 1000);
    }

    #[test]
    fn build_create_token_body_team_scope_includes_team_id() {
        let scope = VercelScope {
            team_id: Some("team_explicit".to_string()),
            expiration_seconds: 1800,
            name: "ember-team".to_string(),
        };
        let body = build_create_token_body(&scope, None, 1_700_000_000).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed.get("teamId").and_then(|v| v.as_str()),
            Some("team_explicit")
        );
    }

    #[test]
    fn build_create_token_body_falls_back_to_default_team_when_empty() {
        let scope = VercelScope {
            team_id: None,
            expiration_seconds: 3600,
            name: "ember-default".to_string(),
        };
        let body = build_create_token_body(&scope, Some("team_default"), 1_700_000_000)
            .expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed.get("teamId").and_then(|v| v.as_str()),
            Some("team_default"),
            "empty team_id must fall back to default_team_id: {body}"
        );
    }

    #[test]
    fn build_create_token_body_explicit_team_overrides_default() {
        let scope = VercelScope {
            team_id: Some("team_explicit".to_string()),
            expiration_seconds: 3600,
            name: "ember-explicit".to_string(),
        };
        let body = build_create_token_body(&scope, Some("team_default"), 1_700_000_000)
            .expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed.get("teamId").and_then(|v| v.as_str()),
            Some("team_explicit"),
            "explicit team_id must override default: {body}"
        );
    }

    #[test]
    fn build_create_token_body_errors_when_name_empty() {
        let scope = VercelScope {
            team_id: None,
            expiration_seconds: 3600,
            name: "  ".to_string(),
        };
        let err = build_create_token_body(&scope, None, 1_700_000_000).unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[test]
    fn build_create_token_body_errors_when_expiration_zero() {
        let scope = VercelScope {
            team_id: None,
            expiration_seconds: 0,
            name: "ember".to_string(),
        };
        let err = build_create_token_body(&scope, None, 1_700_000_000).unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_personal_scope_happy_path_returns_token_and_records_state() {
        let mock = Arc::new(MockVercelClient::new().with_response(
            200,
            create_ok_body("tk_personal", "ember-p", "vc1_minted_personal"),
        ));
        let broker = VercelBroker::with_client(fixture_parent_no_default(), mock.clone());
        let req = vercel_request(
            serde_json::json!({
                "team_id": null,
                "expiration_seconds": 3600,
                "name": "ember-p",
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(cred.token.expose_secret(), "vc1_minted_personal");
        assert!(
            cred.materialization_id.starts_with("vercel-tk_personal-"),
            "materialization_id includes token id: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);
        assert_eq!(mock.call_count(), 1);
        let call = mock.last_call().expect("call recorded");
        assert_eq!(call.method, "POST");
        assert_eq!(call.url, VERCEL_TOKENS_URL);
        assert_eq!(call.bearer, "vc1_no_default");
        let body = call.body.expect("post body recorded");
        assert!(
            !body.contains("teamId"),
            "personal-scope body must NOT include teamId: {body}"
        );
        assert!(
            body.contains("\"name\":\"ember-p\""),
            "body must include name: {body}"
        );
    }

    #[tokio::test]
    async fn issue_team_scope_happy_path_includes_team_id_in_body() {
        let mock = Arc::new(
            MockVercelClient::new()
                .with_response(200, create_ok_body("tk_team", "ember-t", "vc1_minted_team")),
        );
        let broker = VercelBroker::with_client(fixture_parent_no_default(), mock.clone());
        let req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 1800,
                "name": "ember-t",
            }),
            1800,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(cred.token.expose_secret(), "vc1_minted_team");
        let call = mock.last_call().expect("call recorded");
        let body = call.body.expect("post body recorded");
        assert!(
            body.contains("\"teamId\":\"team_explicit\""),
            "body must include teamId: {body}"
        );
    }

    #[tokio::test]
    async fn issue_default_team_fallback_when_scope_team_empty() {
        let mock = Arc::new(
            MockVercelClient::new()
                .with_response(200, create_ok_body("tk_default", "ember-d", "vc1_default")),
        );
        let broker = VercelBroker::with_client(fixture_parent(), mock.clone());
        let req = vercel_request(
            serde_json::json!({
                "expiration_seconds": 3600,
                "name": "ember-d",
            }),
            3600,
        );
        Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        let call = mock.last_call().expect("call recorded");
        let body = call.body.expect("post body recorded");
        assert!(
            body.contains("\"teamId\":\"team_default\""),
            "body must fall back to default_team_id: {body}"
        );
    }

    #[tokio::test]
    async fn issue_unauthorized_401_returns_policy_rejected() {
        let mock = Arc::new(MockVercelClient::new().with_response(401, unauthorized_body()));
        let broker = VercelBroker::with_client(fixture_parent(), mock);
        let req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for 401, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_forbidden_403_returns_policy_rejected() {
        let mock = Arc::new(MockVercelClient::new().with_response(403, forbidden_scope_body()));
        let broker = VercelBroker::with_client(fixture_parent(), mock);
        let req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for 403, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_bad_request_400_returns_upstream() {
        let mock = Arc::new(MockVercelClient::new().with_response(400, bad_request_body()));
        let broker = VercelBroker::with_client(fixture_parent(), mock);
        let req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 400, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.to_ascii_lowercase().contains("bad_request")
                || msg.to_ascii_lowercase().contains("malformed"),
            "error must mention the upstream reason: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_invalid_expiration_422_returns_upstream() {
        let mock = Arc::new(MockVercelClient::new().with_response(422, invalid_expiration_body()));
        let broker = VercelBroker::with_client(fixture_parent(), mock);
        let req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 422, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = VercelBroker::with_client(fixture_parent(), Arc::new(MockVercelClient::new()));
        let mut req = vercel_request(
            serde_json::json!({
                "team_id": "team_explicit",
                "expiration_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_happy_path_calls_delete_and_drops_state() {
        let mock = Arc::new(
            MockVercelClient::new()
                .with_response(
                    200,
                    create_ok_body("tk_rev_1", "ember-rev", "vc1_rev_token"),
                )
                .with_response(204, String::new()),
        );
        let broker = VercelBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            vercel_request(
                serde_json::json!({
                    "team_id": "team_explicit",
                    "expiration_seconds": 3600,
                    "name": "ember-rev",
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        assert_eq!(broker.active_count(), 1);
        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed");
        assert_eq!(broker.active_count(), 0);
        // 1 call for issue + 1 call for revoke
        assert_eq!(mock.call_count(), 2);
        let last = mock.last_call().expect("revoke call recorded");
        assert_eq!(last.method, "DELETE");
        assert!(
            last.url.ends_with("/v3/user/tokens/tk_rev_1"),
            "revoke URL must include the captured token id: {}",
            last.url
        );
    }

    #[tokio::test]
    async fn revoke_404_treated_as_success() {
        let mock = Arc::new(
            MockVercelClient::new()
                .with_response(200, create_ok_body("tk_404", "ember-404", "vc1_404"))
                .with_response(
                    404,
                    "{\"error\":{\"code\":\"not_found\",\"message\":\"Token not found\"}}"
                        .to_string(),
                ),
        );
        let broker = VercelBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            vercel_request(
                serde_json::json!({
                    "team_id": "team_explicit",
                    "expiration_seconds": 3600,
                    "name": "ember-404",
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must treat 404 as success");
        assert_eq!(broker.active_count(), 0);
    }

    #[tokio::test]
    async fn revoke_500_swallowed_after_dropping_state() {
        let mock = Arc::new(
            MockVercelClient::new()
                .with_response(200, create_ok_body("tk_500", "ember-500", "vc1_500"))
                .with_response(500, "<html>Internal Server Error</html>".to_string()),
        );
        let broker = VercelBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            vercel_request(
                serde_json::json!({
                    "team_id": "team_explicit",
                    "expiration_seconds": 3600,
                    "name": "ember-500",
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke is best-effort; upstream 500 must not surface");
        assert_eq!(broker.active_count(), 0);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = VercelBroker::with_client(fixture_parent(), Arc::new(MockVercelClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn vercel_scope_round_trips_through_json() {
        let scope = VercelScope {
            team_id: Some("team_x".to_string()),
            expiration_seconds: 1800,
            name: "ember-token".to_string(),
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: VercelScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.team_id, scope.team_id);
        assert_eq!(parsed.expiration_seconds, scope.expiration_seconds);
        assert_eq!(parsed.name, scope.name);
    }

    #[test]
    fn map_vercel_error_401_returns_policy_rejected() {
        let err = map_vercel_error(401, &unauthorized_body());
        assert!(matches!(err, BrokerError::PolicyRejected(_)));
    }

    #[test]
    fn map_vercel_error_403_returns_policy_rejected() {
        let err = map_vercel_error(403, &forbidden_scope_body());
        assert!(matches!(err, BrokerError::PolicyRejected(_)));
    }

    #[test]
    fn map_vercel_error_400_returns_upstream() {
        let err = map_vercel_error(400, &bad_request_body());
        assert!(matches!(err, BrokerError::Upstream(_)));
    }

    #[test]
    fn map_vercel_error_422_returns_upstream() {
        let err = map_vercel_error(422, &invalid_expiration_body());
        assert!(matches!(err, BrokerError::Upstream(_)));
    }

    #[tokio::test]
    async fn issue_mint_stamp_is_opaque() {
        let mock = Arc::new(MockVercelClient::new().with_response(
            200,
            create_ok_body("tok-1", "ember-test", "vercel-token-value"),
        ));
        let broker = VercelBroker::with_client(fixture_parent(), mock);
        let req = vercel_request(
            serde_json::json!({ "expiration_seconds": 3600, "name": "ember-test-token" }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert!(
            matches!(cred.mint_stamp, MintStamp::Opaque),
            "Vercel mint_stamp should be Opaque, got {:?}",
            cred.mint_stamp
        );
    }
}
