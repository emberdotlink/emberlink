//! Fly.io `Broker` implementation — issues short-lived scoped Fly API
//! tokens via Fly's GraphQL `createApiToken` mutation, returns the
//! minted token as [`BrokeredCredential`] the consumer
//! (`broker_exec` / `apply_credential_to_env`) injects into the child
//! environment as `FLY_API_TOKEN`.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`FlyParentToken`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::fly_config`) and one entry per outstanding
//! materialization.
//!
//! ## Single-step mint
//!
//! POST `https://api.fly.io/graphql` with `Authorization: Bearer
//! <parent FLY_API_TOKEN>` and a JSON body wrapping the
//! `createApiToken` mutation:
//!
//! ```graphql
//! mutation CreateApiToken($input: CreateApiTokenInput!) {
//!   createApiToken(input: $input) {
//!     token { id name token }
//!   }
//! }
//! ```
//!
//! `input` is `{ organizationId: <slug>, name: <name>, expirySeconds:
//! <ttl> }` for org-scoped tokens, or `{ appId: <app_name>, name:
//! <name>, expirySeconds: <ttl> }` for app-scoped tokens.
//!
//! ## Revocation
//!
//! Fly exposes a `revokeApiToken(input: RevokeApiTokenInput!)` mutation
//! that accepts the token's GraphQL ID. We POST it best-effort and warn
//! on failure — the TTL bound is the real safety net.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, MintStamp,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Fly.io parent API token + optional default org slug. Loaded once at
/// daemon startup from `~/.config/emberlink/fly.env` (see
/// `ember_daemon::broker::fly_config::load_fly_credentials`).
///
/// The broker uses the parent token to mint short-lived scoped tokens
/// via Fly's GraphQL `createApiToken` mutation. The `token` is held in
/// a [`SecretString`] so it cannot be accidentally `Debug`-printed or
/// logged.
#[derive(Clone)]
pub struct FlyParentToken {
    /// Long-lived Fly API token (e.g. a personal access token or org
    /// admin token) the broker exchanges for short-lived scoped tokens.
    pub token: SecretString,
    /// Optional default org slug used when [`FlyScope::org_slug`] is
    /// empty AND [`FlyScope::app_name`] is also empty. When set, the
    /// broker scopes the minted token to this org.
    pub default_org_slug: Option<String>,
}

/// Provider-specific scope payload for the Fly broker.
///
/// Deserialized from the opaque `BrokerRequest::scope`
/// (`serde_json::Value`) inside `issue()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlyScope {
    /// Org slug to scope the token to. Falls back to
    /// [`FlyParentToken::default_org_slug`] when empty AND `app_name` is
    /// also empty. Mutually exclusive with `app_name` at request time
    /// (when both present, `app_name` wins and an app-scoped token is
    /// minted).
    #[serde(default)]
    pub org_slug: Option<String>,

    /// App name to scope the token to. When set, the broker mints an
    /// app-scoped token; otherwise org-scoped.
    #[serde(default)]
    pub app_name: Option<String>,

    /// Requested credential lifetime, in seconds.
    pub expiry_seconds: u64,

    /// Human-readable name Fly stores alongside the token (visible in
    /// the Fly dashboard + needed to identify the token for revoke).
    pub name: String,
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `api.fly.io`.
///
/// Production callers use [`ReqwestFlyClient`]; tests use
/// [`MockFlyClient`].
#[async_trait::async_trait]
pub trait FlyHttpClient: Send + Sync {
    /// POST a JSON body to `url` with `Authorization: Bearer <bearer>`.
    /// Used for the GraphQL `createApiToken` and `revokeApiToken`
    /// mutations.
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String>;
}

/// Production [`FlyHttpClient`] backed by `reqwest`.
pub struct ReqwestFlyClient {
    inner: reqwest::Client,
}

impl ReqwestFlyClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/fly")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestFlyClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl FlyHttpClient for ReqwestFlyClient {
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
}

/// `Broker` impl backed by Fly.io's GraphQL `createApiToken` mutation.
///
/// Construct with [`FlyBroker::new`] for production (uses
/// [`ReqwestFlyClient`]) or [`FlyBroker::with_client`] for tests
/// (any `dyn FlyHttpClient` implementation).
pub struct FlyBroker {
    parent: FlyParentToken,
    client: Arc<dyn FlyHttpClient>,
    /// `materialization_id` → `(expires_at, token_id)`. Token id is
    /// captured so `revoke()` can call `revokeApiToken` (which expects
    /// the GraphQL token ID, not the token plaintext).
    state: Mutex<HashMap<String, FlyMaterializationState>>,
}

struct FlyMaterializationState {
    expires_at: SystemTime,
    token_id: String,
}

impl FlyBroker {
    /// Production constructor — uses [`ReqwestFlyClient`].
    pub fn new(parent: FlyParentToken) -> Self {
        Self {
            parent,
            client: Arc::new(
                ReqwestFlyClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`FlyHttpClient`] so
    /// unit tests can inject [`MockFlyClient`].
    pub fn with_client(parent: FlyParentToken, client: Arc<dyn FlyHttpClient>) -> Self {
        Self {
            parent,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("fly broker state mutex").len()
    }
}

const FLY_GRAPHQL_URL: &str = "https://api.fly.io/graphql";

const CREATE_TOKEN_MUTATION: &str = "mutation CreateApiToken($input: CreateApiTokenInput!) { \
createApiToken(input: $input) { token { id name token } } }";

const REVOKE_TOKEN_MUTATION: &str = "mutation RevokeApiToken($input: RevokeApiTokenInput!) { \
revokeApiToken(input: $input) { clientMutationId } }";

/// Build the GraphQL request body for `createApiToken`. Resolves the
/// scope into an org-scoped or app-scoped variant — `app_name` wins
/// when both are set; otherwise `org_slug` (with default-org fallback)
/// is used.
///
/// Extracted as a free function so tests can pin the exact body shape
/// without driving a full broker.
pub fn build_create_token_body(
    scope: &FlyScope,
    default_org_slug: Option<&str>,
) -> Result<String, BrokerError> {
    let app_name = scope
        .app_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let org_slug_explicit = scope
        .org_slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let input = if let Some(app) = app_name {
        // App-scope variant.
        serde_json::json!({
            "appId": app,
            "name": scope.name,
            "expirySeconds": scope.expiry_seconds,
        })
    } else {
        // Org-scope variant — fall back to default org when scope's
        // `org_slug` is empty.
        let org = match org_slug_explicit {
            Some(s) => s.to_string(),
            None => match default_org_slug {
                Some(s) if !s.trim().is_empty() => s.trim().to_string(),
                _ => {
                    return Err(BrokerError::InvalidScope(
                        "FlyScope: neither org_slug nor app_name provided and \
                         no default_org_slug configured"
                            .to_string(),
                    ));
                }
            },
        };
        serde_json::json!({
            "organizationId": org,
            "name": scope.name,
            "expirySeconds": scope.expiry_seconds,
        })
    };

    let envelope = serde_json::json!({
        "query": CREATE_TOKEN_MUTATION,
        "variables": { "input": input },
    });
    serde_json::to_string(&envelope)
        .map_err(|e| BrokerError::Other(format!("createApiToken body encode: {e}")))
}

/// Build the GraphQL request body for `revokeApiToken`.
fn build_revoke_token_body(token_id: &str) -> String {
    let envelope = serde_json::json!({
        "query": REVOKE_TOKEN_MUTATION,
        "variables": {
            "input": { "id": token_id },
        },
    });
    // `to_string` on a serde_json::Value is infallible.
    envelope.to_string()
}

// ---------------------------------------------------------------------------
// JSON shapes for the GraphQL response envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct GraphqlResponse<T> {
    #[serde(default = "Option::default")]
    data: Option<T>,
    #[serde(default = "Vec::new")]
    errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
struct GraphqlError {
    message: String,
    #[serde(default)]
    extensions: Option<GraphqlErrorExtensions>,
}

#[derive(Debug, Deserialize, Default)]
struct GraphqlErrorExtensions {
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateApiTokenData {
    #[serde(rename = "createApiToken")]
    create_api_token: CreateApiTokenPayload,
}

#[derive(Debug, Deserialize)]
struct CreateApiTokenPayload {
    token: CreatedToken,
}

#[derive(Debug, Deserialize)]
struct CreatedToken {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    token: String,
}

/// Map a GraphQL `errors[]` payload to the closest [`BrokerError`]
/// variant. Codes / messages mentioning unauthorized / forbidden /
/// permission map to `PolicyRejected`; everything else (`not_found`,
/// validation errors, transport-level non-2xx) maps to `Upstream` with
/// a descriptive message.
fn map_fly_graphql_errors(status: u16, body: &str, errors: &[GraphqlError]) -> BrokerError {
    let first = errors.first();
    let message = first.map(|e| e.message.clone()).unwrap_or_default();
    let code = first
        .and_then(|e| e.extensions.as_ref())
        .and_then(|ext| ext.code.clone())
        .unwrap_or_default();
    let lower_code = code.to_ascii_lowercase();
    let lower_msg = message.to_ascii_lowercase();

    if lower_code == "unauthorized"
        || lower_code == "forbidden"
        || lower_msg.contains("unauthorized")
        || lower_msg.contains("not authorized")
        || lower_msg.contains("permission")
        || status == 401
        || status == 403
    {
        return BrokerError::PolicyRejected(format!(
            "Fly.io GraphQL unauthorized ({code}): {message} (status={status})"
        ));
    }

    if lower_code == "not_found" || lower_msg.contains("not found") || status == 404 {
        return BrokerError::Upstream(format!(
            "Fly.io GraphQL not_found ({code}): {message} (status={status})"
        ));
    }

    BrokerError::Upstream(format!(
        "Fly.io GraphQL error ({code}): {message} (status={status}, body={body})"
    ))
}

impl Broker for FlyBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::FlyIo
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::FlyIo {
            return Err(BrokerError::InvalidScope(format!(
                "FlyBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: FlyScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        if scope.expiry_seconds == 0 {
            return Err(BrokerError::InvalidScope(
                "expiry_seconds must be > 0".to_string(),
            ));
        }

        if scope.name.trim().is_empty() {
            return Err(BrokerError::InvalidScope(
                "FlyScope.name must be non-empty".to_string(),
            ));
        }

        let body = build_create_token_body(&scope, self.parent.default_org_slug.as_deref())?;

        let (status, resp_body) = self
            .client
            .post_json_bearer(FLY_GRAPHQL_URL, self.parent.token.expose_secret(), body)
            .await
            .map_err(BrokerError::Upstream)?;

        // Fly's GraphQL endpoint returns 200 even on application errors,
        // surfacing the failure inside `errors[]`. We still treat a non-
        // 2xx transport status as fatal up front.
        if !(200..300).contains(&status) {
            // Try to parse the body for richer error mapping; fall back
            // to a raw upstream error.
            if let Ok(envelope) =
                serde_json::from_str::<GraphqlResponse<CreateApiTokenData>>(&resp_body)
                && !envelope.errors.is_empty()
            {
                let err = map_fly_graphql_errors(status, &resp_body, &envelope.errors);
                tracing::warn!(
                    status = status,
                    error = %err,
                    "FlyBroker: createApiToken upstream error"
                );
                return Err(err);
            }
            return Err(BrokerError::Upstream(format!(
                "Fly.io HTTP {status}: {resp_body}"
            )));
        }

        let envelope: GraphqlResponse<CreateApiTokenData> = serde_json::from_str(&resp_body)
            .map_err(|e| {
                BrokerError::Upstream(format!(
                    "Fly.io GraphQL response parse failed: {e}; body={resp_body}"
                ))
            })?;

        if !envelope.errors.is_empty() {
            let err = map_fly_graphql_errors(status, &resp_body, &envelope.errors);
            tracing::warn!(
                status = status,
                error = %err,
                "FlyBroker: createApiToken returned errors[]"
            );
            return Err(err);
        }

        let data = envelope.data.ok_or_else(|| {
            BrokerError::Upstream(format!(
                "Fly.io GraphQL response missing data: body={resp_body}"
            ))
        })?;
        let CreatedToken {
            id: token_id,
            name: _,
            token,
        } = data.create_api_token.token;

        let now = SystemTime::now();
        let expires_at = now + std::time::Duration::from_secs(scope.expiry_seconds);

        let materialization_id = format!("fly-{}-{}", token_id, chrono_timestamp(expires_at),);

        self.state.lock().expect("fly broker state mutex").insert(
            materialization_id.clone(),
            FlyMaterializationState {
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
            .expect("fly broker state mutex")
            .remove(materialization_id);
        let Some(state) = entry else {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        };

        // Best-effort upstream revoke. Fly's `revokeApiToken` mutation
        // accepts the GraphQL token ID; failures are warned but do not
        // surface as `Err` because the TTL bound is the real safety
        // net.
        let body = build_revoke_token_body(&state.token_id);
        match self
            .client
            .post_json_bearer(FLY_GRAPHQL_URL, self.parent.token.expose_secret(), body)
            .await
        {
            Ok((status, resp_body)) if (200..300).contains(&status) => {
                // 200 on the transport doesn't guarantee no GraphQL
                // errors[]; surface them at warn level so audit can pick
                // them up but still return Ok to the caller (TTL bound).
                if let Ok(envelope) =
                    serde_json::from_str::<GraphqlResponse<serde_json::Value>>(&resp_body)
                    && !envelope.errors.is_empty()
                {
                    tracing::warn!(
                        materialization_id = %materialization_id,
                        body = %resp_body,
                        "FlyBroker: revokeApiToken returned errors[] (best-effort; TTL still bounds exposure)"
                    );
                } else {
                    tracing::info!(
                        materialization_id = %materialization_id,
                        "FlyBroker: revoke succeeded"
                    );
                }
            }
            Ok((status, resp_body)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = status,
                    body = %resp_body,
                    "FlyBroker: upstream revoke returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "FlyBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        let _ = state.expires_at;
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
pub struct MockFlyClient {
    pub responses: Mutex<Vec<(u16, String)>>,
    pub calls: Mutex<Vec<MockFlyCall>>,
}

#[derive(Debug, Clone)]
pub struct MockFlyCall {
    pub url: String,
    pub bearer: String,
    pub body: String,
}

impl MockFlyClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
        self.responses
            .lock()
            .expect("mock fly mutex")
            .push((status, body.into()));
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock fly mutex").len()
    }

    pub fn last_call(&self) -> Option<MockFlyCall> {
        self.calls.lock().expect("mock fly mutex").last().cloned()
    }
}

impl Default for MockFlyClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FlyHttpClient for MockFlyClient {
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock fly mutex")
            .push(MockFlyCall {
                url: url.to_string(),
                bearer: bearer.to_string(),
                body: body.clone(),
            });
        let mut q = self.responses.lock().expect("mock fly mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockFlyClient: no response queued for {url}; body={body}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_parent() -> FlyParentToken {
        FlyParentToken {
            token: SecretString::from("fo1_fake-parent-token-for-tests".to_string()),
            default_org_slug: Some("default-org".to_string()),
        }
    }

    fn fly_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::FlyIo,
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
            "data": {
                "createApiToken": {
                    "token": {
                        "id": token_id,
                        "name": name,
                        "token": token,
                    }
                }
            }
        })
        .to_string()
    }

    fn unauthorized_errors_body() -> String {
        serde_json::json!({
            "data": null,
            "errors": [{
                "message": "You must be authenticated to access this resource",
                "extensions": { "code": "UNAUTHORIZED" }
            }]
        })
        .to_string()
    }

    fn not_found_errors_body() -> String {
        serde_json::json!({
            "data": null,
            "errors": [{
                "message": "Could not find Organization with slug=ghost-org",
                "extensions": { "code": "NOT_FOUND" }
            }]
        })
        .to_string()
    }

    fn revoke_ok_body() -> String {
        serde_json::json!({
            "data": {
                "revokeApiToken": { "clientMutationId": null }
            }
        })
        .to_string()
    }

    #[test]
    fn provider_returns_fly_io() {
        let broker = FlyBroker::with_client(fixture_parent(), Arc::new(MockFlyClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::FlyIo);
    }

    #[test]
    fn build_create_token_body_org_scope_uses_organization_id() {
        let scope = FlyScope {
            org_slug: Some("acme".to_string()),
            app_name: None,
            expiry_seconds: 3600,
            name: "ember-broker-acme".to_string(),
        };
        let body = build_create_token_body(&scope, None).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let input = parsed
            .get("variables")
            .and_then(|v| v.get("input"))
            .expect("variables.input must exist");
        assert_eq!(
            input.get("organizationId").and_then(|v| v.as_str()),
            Some("acme")
        );
        assert!(
            input.get("appId").is_none(),
            "org-scope must not include appId"
        );
        assert_eq!(
            input.get("name").and_then(|v| v.as_str()),
            Some("ember-broker-acme")
        );
        assert_eq!(
            input.get("expirySeconds").and_then(|v| v.as_u64()),
            Some(3600)
        );
        assert!(
            parsed
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("createApiToken")
        );
    }

    #[test]
    fn build_create_token_body_app_scope_uses_app_id() {
        let scope = FlyScope {
            org_slug: Some("ignored-when-app-set".to_string()),
            app_name: Some("my-app".to_string()),
            expiry_seconds: 1800,
            name: "ember-broker-my-app".to_string(),
        };
        let body = build_create_token_body(&scope, None).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let input = parsed
            .get("variables")
            .and_then(|v| v.get("input"))
            .expect("variables.input must exist");
        assert_eq!(input.get("appId").and_then(|v| v.as_str()), Some("my-app"));
        assert!(
            input.get("organizationId").is_none(),
            "app-scope must not include organizationId"
        );
    }

    #[test]
    fn build_create_token_body_falls_back_to_default_org_when_both_empty() {
        let scope = FlyScope {
            org_slug: None,
            app_name: None,
            expiry_seconds: 3600,
            name: "ember-default".to_string(),
        };
        let body = build_create_token_body(&scope, Some("default-org")).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let input = parsed
            .get("variables")
            .and_then(|v| v.get("input"))
            .expect("variables.input must exist");
        assert_eq!(
            input.get("organizationId").and_then(|v| v.as_str()),
            Some("default-org"),
            "empty org_slug + empty app_name must fall back to default_org_slug"
        );
    }

    #[test]
    fn build_create_token_body_errors_when_no_scope_and_no_default() {
        let scope = FlyScope {
            org_slug: None,
            app_name: None,
            expiry_seconds: 3600,
            name: "ember".to_string(),
        };
        let err = build_create_token_body(&scope, None).expect_err("must error");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_org_scope_happy_path_returns_token_and_records_state() {
        let mock = Arc::new(MockFlyClient::new().with_response(
            200,
            create_ok_body("tk_org_1", "ember-acme", "fo1_minted_org_token"),
        ));
        let broker = FlyBroker::with_client(fixture_parent(), mock.clone());
        let req = fly_request(
            serde_json::json!({
                "org_slug": "acme",
                "app_name": null,
                "expiry_seconds": 3600,
                "name": "ember-acme",
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(cred.token.expose_secret(), "fo1_minted_org_token");
        assert!(
            cred.materialization_id.starts_with("fly-tk_org_1-"),
            "materialization_id includes token id: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);
        assert_eq!(mock.call_count(), 1);
        let call = mock.last_call().expect("call recorded");
        assert_eq!(call.url, FLY_GRAPHQL_URL);
        assert_eq!(call.bearer, "fo1_fake-parent-token-for-tests");
        assert!(
            call.body.contains("\"organizationId\":\"acme\""),
            "body must include organizationId: {}",
            call.body
        );
        assert!(
            call.body.contains("createApiToken"),
            "body must include createApiToken mutation: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_app_scope_happy_path_uses_app_id_in_body() {
        let mock = Arc::new(MockFlyClient::new().with_response(
            200,
            create_ok_body("tk_app_1", "ember-app", "fo1_minted_app_token"),
        ));
        let broker = FlyBroker::with_client(fixture_parent(), mock.clone());
        let req = fly_request(
            serde_json::json!({
                "org_slug": null,
                "app_name": "my-app",
                "expiry_seconds": 1800,
                "name": "ember-app",
            }),
            1800,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(cred.token.expose_secret(), "fo1_minted_app_token");
        let call = mock.last_call().expect("call recorded");
        assert!(
            call.body.contains("\"appId\":\"my-app\""),
            "body must include appId: {}",
            call.body
        );
        assert!(
            !call.body.contains("organizationId"),
            "app-scope body must NOT include organizationId: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_default_org_fallback_when_both_empty() {
        let mock = Arc::new(MockFlyClient::new().with_response(
            200,
            create_ok_body("tk_default", "ember-default", "fo1_default_token"),
        ));
        let broker = FlyBroker::with_client(fixture_parent(), mock.clone());
        let req = fly_request(
            serde_json::json!({
                "expiry_seconds": 3600,
                "name": "ember-default",
            }),
            3600,
        );
        Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        let call = mock.last_call().expect("call recorded");
        assert!(
            call.body.contains("\"organizationId\":\"default-org\""),
            "body must fall back to default_org_slug: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_unauthorized_errors_returns_policy_rejected() {
        let mock = Arc::new(MockFlyClient::new().with_response(200, unauthorized_errors_body()));
        let broker = FlyBroker::with_client(fixture_parent(), mock);
        let req = fly_request(
            serde_json::json!({
                "org_slug": "acme",
                "expiry_seconds": 3600,
                "name": "ember-acme",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for unauthorized, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_not_found_errors_returns_upstream() {
        let mock = Arc::new(MockFlyClient::new().with_response(200, not_found_errors_body()));
        let broker = FlyBroker::with_client(fixture_parent(), mock);
        let req = fly_request(
            serde_json::json!({
                "org_slug": "ghost-org",
                "expiry_seconds": 3600,
                "name": "ember-ghost",
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for not_found, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("not_found")
                || msg.to_ascii_lowercase().contains("not found"),
            "error must mention not_found: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_with_zero_expiry_returns_invalid_scope() {
        let broker = FlyBroker::with_client(fixture_parent(), Arc::new(MockFlyClient::new()));
        let req = fly_request(
            serde_json::json!({
                "org_slug": "acme",
                "expiry_seconds": 0,
                "name": "ember",
            }),
            0,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = FlyBroker::with_client(fixture_parent(), Arc::new(MockFlyClient::new()));
        let mut req = fly_request(
            serde_json::json!({
                "org_slug": "acme",
                "expiry_seconds": 3600,
                "name": "ember",
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_happy_path_calls_revoke_mutation_and_drops_state() {
        let mock = Arc::new(
            MockFlyClient::new()
                .with_response(
                    200,
                    create_ok_body("tk_rev_1", "ember-rev", "fo1_rev_token"),
                )
                .with_response(200, revoke_ok_body()),
        );
        let broker = FlyBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            fly_request(
                serde_json::json!({
                    "org_slug": "acme",
                    "expiry_seconds": 3600,
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
            .expect("revoke must succeed (best-effort)");
        assert_eq!(broker.active_count(), 0);
        // 1 call for issue + 1 call for revoke
        assert_eq!(mock.call_count(), 2);
        let last = mock.last_call().expect("revoke call recorded");
        assert!(
            last.body.contains("revokeApiToken"),
            "revoke body must include mutation name: {}",
            last.body
        );
        assert!(
            last.body.contains("\"id\":\"tk_rev_1\""),
            "revoke body must include the captured token id: {}",
            last.body
        );
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = FlyBroker::with_client(fixture_parent(), Arc::new(MockFlyClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[tokio::test]
    async fn revoke_swallows_upstream_5xx_after_dropping_state() {
        let mock = Arc::new(
            MockFlyClient::new()
                .with_response(200, create_ok_body("tk_5xx", "ember-5xx", "fo1_5xx_token"))
                .with_response(503, "<html>Service Unavailable</html>".to_string()),
        );
        let broker = FlyBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            fly_request(
                serde_json::json!({
                    "org_slug": "acme",
                    "expiry_seconds": 3600,
                    "name": "ember-5xx",
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke is best-effort; upstream 503 must not surface");
        assert_eq!(broker.active_count(), 0);
    }

    #[test]
    fn fly_scope_round_trips_through_json() {
        let scope = FlyScope {
            org_slug: Some("acme".to_string()),
            app_name: Some("my-app".to_string()),
            expiry_seconds: 1800,
            name: "ember-token".to_string(),
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: FlyScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.org_slug, scope.org_slug);
        assert_eq!(parsed.app_name, scope.app_name);
        assert_eq!(parsed.expiry_seconds, scope.expiry_seconds);
        assert_eq!(parsed.name, scope.name);
    }

    #[test]
    fn map_fly_graphql_errors_unauthorized_returns_policy_rejected() {
        let envelope: GraphqlResponse<CreateApiTokenData> =
            serde_json::from_str(&unauthorized_errors_body()).expect("parse");
        let err = map_fly_graphql_errors(200, &unauthorized_errors_body(), &envelope.errors);
        assert!(matches!(err, BrokerError::PolicyRejected(_)));
    }

    #[test]
    fn map_fly_graphql_errors_not_found_returns_upstream() {
        let envelope: GraphqlResponse<CreateApiTokenData> =
            serde_json::from_str(&not_found_errors_body()).expect("parse");
        let err = map_fly_graphql_errors(200, &not_found_errors_body(), &envelope.errors);
        assert!(matches!(err, BrokerError::Upstream(_)));
    }

    #[tokio::test]
    async fn issue_mint_stamp_is_opaque() {
        let mock = Arc::new(MockFlyClient::new().with_response(
            200,
            create_ok_body("tok-1", "ember-test", "fly-token-value"),
        ));
        let broker = FlyBroker::with_client(fixture_parent(), mock);
        let req = fly_request(
            serde_json::json!({
                "org_slug": "acme",
                "expiry_seconds": 3600,
                "name": "ember-test-token",
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert!(
            matches!(cred.mint_stamp, MintStamp::Opaque),
            "Fly mint_stamp should be Opaque, got {:?}",
            cred.mint_stamp
        );
    }
}
