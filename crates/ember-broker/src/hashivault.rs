//! HashiCorp Vault `Broker` implementation — issues short-lived
//! "child" tokens via Vault's `/v1/auth/token/create` endpoint, returns
//! the minted token paired with `VAULT_ADDR` as a JSON bundle so the
//! consumer (`broker_exec` / `apply_credential_to_env`) can inject both
//! `VAULT_TOKEN` and `VAULT_ADDR` into the child environment.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`HashiVaultParentToken`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::hashivault_config`) and one entry per
//! outstanding materialization.
//!
//! ## Single-step mint
//!
//! POST `<vault_addr>/v1/auth/token/create` with header
//! `X-Vault-Token: <parent_token>` (and `X-Vault-Namespace: <namespace>`
//! when configured) and `application/json` body:
//!
//! ```json
//! {
//!   "policies": ["..."],
//!   "ttl": "<seconds>s",
//!   "renewable": true,
//!   "no_parent": true,
//!   "display_name": "..."
//! }
//! ```
//!
//! Response is JSON: `{ "auth": { "client_token": "hvs....",
//! "lease_duration": 3600, "renewable": true, "policies": [...] } }`.
//!
//! ## Revocation
//!
//! Vault exposes `/v1/auth/token/revoke-self` — POST to that endpoint
//! with the CHILD token as `X-Vault-Token`. Best-effort revoke; the TTL
//! bound is the real safety net.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, MintStamp,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// HashiCorp Vault parent token + endpoint configuration. Loaded once
/// at daemon startup from `~/.config/emberlink/hashivault.env` (see
/// `ember_daemon::broker::hashivault_config::load_hashivault_credentials`).
///
/// The broker uses the parent token to mint short-lived child tokens
/// via Vault's `/v1/auth/token/create` endpoint. The `token` is held in
/// a [`SecretString`] so it cannot be accidentally `Debug`-printed or
/// logged.
#[derive(Clone)]
pub struct HashiVaultParentToken {
    /// Long-lived Vault token (with the `auth/token/create` capability)
    /// the broker exchanges for short-lived child tokens.
    pub token: SecretString,
    /// Base URL of the Vault server, e.g. `https://vault.example.com:8200`.
    /// Embedded into both the request URL at issue time and the
    /// `VAULT_ADDR` env var the consumer injects alongside `VAULT_TOKEN`.
    pub address: String,
    /// Optional Vault Enterprise namespace — passed through as the
    /// `X-Vault-Namespace` header when set.
    pub namespace: Option<String>,
}

/// Provider-specific scope payload for the HashiCorp Vault broker.
///
/// Deserialized from the opaque `BrokerRequest::scope` (`serde_json::Value`)
/// inside `issue()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashiVaultScope {
    /// Vault policies attached to the minted child token. At least one
    /// policy is required — Vault rejects token creation with no
    /// policies when the parent token does not have `default`.
    pub policies: Vec<String>,
    /// Requested credential lifetime, in seconds. Mapped to Vault's
    /// `ttl: "<seconds>s"` body field; Vault may clamp downward.
    pub ttl_seconds: u64,
    /// Whether the child token can self-renew.
    pub renewable: bool,
    /// Detach the child token from the parent — recommended for
    /// delegation so revoking the parent does not cascade-revoke active
    /// child sessions. Defaults to true via [`default_no_parent`].
    #[serde(default = "default_no_parent")]
    pub no_parent: bool,
    /// Optional display name Vault stores alongside the token (visible
    /// in Vault audit logs + helpful for revoke targeting).
    #[serde(default)]
    pub display_name: Option<String>,
}

fn default_no_parent() -> bool {
    true
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting a Vault cluster.
///
/// Production callers use [`ReqwestHashiVaultClient`]; tests use
/// [`MockHttpClient`].
#[async_trait::async_trait]
pub trait HashiVaultHttpClient: Send + Sync {
    /// POST a JSON body to `url` with `X-Vault-Token: <vault_token>`
    /// and an optional `X-Vault-Namespace: <namespace>` header.
    async fn post_json_vault(
        &self,
        url: &str,
        vault_token: &str,
        namespace: Option<&str>,
        body: String,
    ) -> Result<(u16, String), String>;
}

/// Production [`HashiVaultHttpClient`] backed by `reqwest`.
pub struct ReqwestHashiVaultClient {
    inner: reqwest::Client,
}

impl ReqwestHashiVaultClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/hashivault")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestHashiVaultClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl HashiVaultHttpClient for ReqwestHashiVaultClient {
    async fn post_json_vault(
        &self,
        url: &str,
        vault_token: &str,
        namespace: Option<&str>,
        body: String,
    ) -> Result<(u16, String), String> {
        let mut req = self
            .inner
            .post(url)
            .header("X-Vault-Token", vault_token)
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(ns) = namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by HashiCorp Vault's `/v1/auth/token/create`
/// endpoint.
///
/// Construct with [`HashiVaultBroker::new`] for production (uses
/// [`ReqwestHashiVaultClient`]) or [`HashiVaultBroker::with_client`]
/// for tests (any `dyn HashiVaultHttpClient` implementation).
pub struct HashiVaultBroker {
    parent: HashiVaultParentToken,
    client: Arc<dyn HashiVaultHttpClient>,
    /// `materialization_id` → `(expires_at, child_token)`. The plaintext
    /// child token is retained so `revoke()` can call
    /// `/v1/auth/token/revoke-self` with it (the parent token is NOT
    /// the right credential to revoke a child via revoke-self).
    state: Mutex<HashMap<String, HashiVaultMaterializationState>>,
}

struct HashiVaultMaterializationState {
    expires_at: SystemTime,
    child_token: SecretString,
}

impl HashiVaultBroker {
    /// Production constructor — uses [`ReqwestHashiVaultClient`].
    pub fn new(parent: HashiVaultParentToken) -> Self {
        Self {
            parent,
            client: Arc::new(
                ReqwestHashiVaultClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`HashiVaultHttpClient`]
    /// so unit tests can inject [`MockHttpClient`].
    pub fn with_client(
        parent: HashiVaultParentToken,
        client: Arc<dyn HashiVaultHttpClient>,
    ) -> Self {
        Self {
            parent,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state
            .lock()
            .expect("hashivault broker state mutex")
            .len()
    }

    /// Address (`VAULT_ADDR`) the consumer must pair with the minted
    /// `VAULT_TOKEN` for the child token to be usable.
    pub fn address(&self) -> &str {
        &self.parent.address
    }
}

const TOKEN_CREATE_PATH: &str = "/v1/auth/token/create";
const TOKEN_REVOKE_SELF_PATH: &str = "/v1/auth/token/revoke-self";

/// Build the JSON body for `auth/token/create`.
///
/// Extracted as a free function so tests can pin the exact body shape
/// without driving a full broker.
pub fn build_create_token_body(scope: &HashiVaultScope) -> Result<String, BrokerError> {
    if scope.policies.is_empty() {
        return Err(BrokerError::InvalidScope(
            "HashiVaultScope.policies must be non-empty".to_string(),
        ));
    }
    if scope.ttl_seconds == 0 {
        return Err(BrokerError::InvalidScope(
            "HashiVaultScope.ttl_seconds must be > 0".to_string(),
        ));
    }
    let mut obj = serde_json::Map::new();
    obj.insert(
        "policies".to_string(),
        serde_json::Value::Array(
            scope
                .policies
                .iter()
                .map(|p| serde_json::Value::String(p.clone()))
                .collect(),
        ),
    );
    obj.insert(
        "ttl".to_string(),
        serde_json::Value::String(format!("{}s", scope.ttl_seconds)),
    );
    obj.insert(
        "renewable".to_string(),
        serde_json::Value::Bool(scope.renewable),
    );
    obj.insert(
        "no_parent".to_string(),
        serde_json::Value::Bool(scope.no_parent),
    );
    if let Some(name) = scope.display_name.as_deref()
        && !name.trim().is_empty()
    {
        obj.insert(
            "display_name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
    }
    serde_json::to_string(&serde_json::Value::Object(obj))
        .map_err(|e| BrokerError::Other(format!("auth/token/create body encode: {e}")))
}

/// Concatenate base address + path, tolerating a trailing slash on the
/// configured `VAULT_ADDR`. Vault rejects double slashes on some
/// endpoints so we strip exactly one trailing slash.
fn join_addr(base: &str, path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    format!("{trimmed}{path}")
}

// ---------------------------------------------------------------------------
// JSON shapes for the Vault response envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct VaultTokenCreateResponse {
    #[serde(default)]
    auth: Option<VaultAuthBlock>,
    /// Vault sometimes serializes the `errors` / `warnings` fields as
    /// `null` rather than `[]`. Wrap in `Option<Vec<_>>` and surface
    /// via the `*_vec` accessors so callers see an empty slice in
    /// either case.
    #[serde(default)]
    errors: Option<Vec<String>>,
    #[serde(default)]
    warnings: Option<Vec<String>>,
}

impl VaultTokenCreateResponse {
    fn errors_vec(&self) -> &[String] {
        self.errors.as_deref().unwrap_or(&[])
    }
    fn warnings_vec(&self) -> &[String] {
        self.warnings.as_deref().unwrap_or(&[])
    }
}

#[derive(Debug, Deserialize)]
struct VaultAuthBlock {
    client_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    lease_duration: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    renewable: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    policies: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct VaultErrorEnvelope {
    #[serde(default)]
    errors: Option<Vec<String>>,
}

impl VaultErrorEnvelope {
    fn errors_vec(&self) -> &[String] {
        self.errors.as_deref().unwrap_or(&[])
    }
}

/// Map a Vault HTTP non-2xx response (status + body) to the closest
/// [`BrokerError`] variant. 401/403 → `PolicyRejected` (parent token
/// lacks the `auth/token/create` capability); 503 / "sealed" → `Upstream`
/// with a "vault sealed" message; everything else → `Upstream` with a
/// descriptive message that includes the parsed Vault `errors[]` when
/// present.
fn map_vault_http_error(status: u16, body: &str) -> BrokerError {
    let parsed: VaultErrorEnvelope = serde_json::from_str(body).unwrap_or_default();
    let joined = parsed.errors_vec().join("; ");
    let msg_for_log = if joined.is_empty() {
        body.to_string()
    } else {
        joined.clone()
    };

    if status == 401 || status == 403 {
        return BrokerError::PolicyRejected(format!("Vault {status}: {msg_for_log}"));
    }

    let lower = msg_for_log.to_ascii_lowercase();
    if status == 503 || lower.contains("vault is sealed") || lower.contains("sealed") {
        return BrokerError::Upstream(format!("Vault sealed (status={status}): {msg_for_log}"));
    }

    BrokerError::Upstream(format!("Vault {status}: {msg_for_log}"))
}

impl Broker for HashiVaultBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::HashiVault
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::HashiVault {
            return Err(BrokerError::InvalidScope(format!(
                "HashiVaultBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: HashiVaultScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        let body = build_create_token_body(&scope)?;
        let url = join_addr(&self.parent.address, TOKEN_CREATE_PATH);

        let (status, resp_body) = self
            .client
            .post_json_vault(
                &url,
                self.parent.token.expose_secret(),
                self.parent.namespace.as_deref(),
                body,
            )
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_vault_http_error(status, &resp_body);
            tracing::warn!(
                status = status,
                error = %err,
                "HashiVaultBroker: auth/token/create non-2xx"
            );
            return Err(err);
        }

        let envelope: VaultTokenCreateResponse = serde_json::from_str(&resp_body).map_err(|e| {
            BrokerError::Upstream(format!(
                "Vault auth/token/create response parse failed: {e}; body={resp_body}"
            ))
        })?;

        if !envelope.errors_vec().is_empty() {
            return Err(BrokerError::Upstream(format!(
                "Vault auth/token/create returned errors[]: {}",
                envelope.errors_vec().join("; ")
            )));
        }

        // Capture warnings before partially moving `auth` out below.
        let warnings: Vec<String> = envelope.warnings_vec().to_vec();

        let auth = envelope.auth.ok_or_else(|| {
            BrokerError::Upstream(format!(
                "Vault auth/token/create response missing 'auth' block: body={resp_body}"
            ))
        })?;
        let client_token = auth.client_token;

        let now = SystemTime::now();
        let expires_at = now + std::time::Duration::from_secs(scope.ttl_seconds);

        let display = scope
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("ember-vault");
        let materialization_id = format!("vault-{}-{}", display, chrono_timestamp(expires_at));

        self.state
            .lock()
            .expect("hashivault broker state mutex")
            .insert(
                materialization_id.clone(),
                HashiVaultMaterializationState {
                    expires_at,
                    child_token: SecretString::from(client_token.clone()),
                },
            );

        if !warnings.is_empty() {
            tracing::info!(
                warnings = ?warnings,
                "HashiVaultBroker: auth/token/create returned warnings"
            );
        }

        // Return a JSON bundle pairing the child token with the
        // VAULT_ADDR the consumer needs to reach Vault. The
        // daemon-side handler (CredentialInjection::VaultToken match
        // arm) splits this into the VAULT_TOKEN + VAULT_ADDR env-var
        // pair when injecting into the child environment — a child
        // token alone is useless without the address.
        let bundle = serde_json::json!({
            "token": client_token,
            "address": self.parent.address,
        })
        .to_string();

        Ok(BrokeredCredential {
            token: SecretString::from(bundle),
            expires_at,
            materialization_id,
            mint_stamp: MintStamp::Opaque,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        let entry = self
            .state
            .lock()
            .expect("hashivault broker state mutex")
            .remove(materialization_id);
        let Some(state) = entry else {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        };

        // Best-effort upstream revoke. POST `/v1/auth/token/revoke-self`
        // with the CHILD token (not the parent). Vault returns 204 on
        // success; 404 if the token is already gone (treated as
        // best-effort success since the goal is "no longer valid").
        let url = join_addr(&self.parent.address, TOKEN_REVOKE_SELF_PATH);
        match self
            .client
            .post_json_vault(
                &url,
                state.child_token.expose_secret(),
                self.parent.namespace.as_deref(),
                String::new(),
            )
            .await
        {
            Ok((status, _)) if (200..300).contains(&status) => {
                tracing::info!(
                    materialization_id = %materialization_id,
                    "HashiVaultBroker: revoke-self succeeded"
                );
            }
            Ok((404, _)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    "HashiVaultBroker: revoke-self returned 404 (token already expired/revoked; treating as success)"
                );
            }
            Ok((status, resp_body)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = status,
                    body = %resp_body,
                    "HashiVaultBroker: upstream revoke-self returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "HashiVaultBroker: upstream revoke-self transport failure (best-effort; TTL still bounds exposure)"
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
/// next `(status, body)` from `responses`. If the queue holds only one
/// entry it is reused for every subsequent call (terse setup); if the
/// queue is empty the mock errors so missing-fixture bugs surface
/// loudly.
pub struct MockHttpClient {
    pub responses: Mutex<Vec<(u16, String)>>,
    pub calls: Mutex<Vec<MockHashiVaultCall>>,
}

#[derive(Debug, Clone)]
pub struct MockHashiVaultCall {
    pub url: String,
    pub vault_token: String,
    pub namespace: Option<String>,
    pub body: String,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
        self.responses
            .lock()
            .expect("mock hashivault mutex")
            .push((status, body.into()));
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock hashivault mutex").len()
    }

    pub fn last_call(&self) -> Option<MockHashiVaultCall> {
        self.calls
            .lock()
            .expect("mock hashivault mutex")
            .last()
            .cloned()
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HashiVaultHttpClient for MockHttpClient {
    async fn post_json_vault(
        &self,
        url: &str,
        vault_token: &str,
        namespace: Option<&str>,
        body: String,
    ) -> Result<(u16, String), String> {
        self.calls
            .lock()
            .expect("mock hashivault mutex")
            .push(MockHashiVaultCall {
                url: url.to_string(),
                vault_token: vault_token.to_string(),
                namespace: namespace.map(|s| s.to_string()),
                body: body.clone(),
            });
        let mut q = self.responses.lock().expect("mock hashivault mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockHttpClient: no response queued for {url}; body={body}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_parent() -> HashiVaultParentToken {
        HashiVaultParentToken {
            token: SecretString::from("hvs.parent-token-for-tests".to_string()),
            address: "https://vault.example.com:8200".to_string(),
            namespace: None,
        }
    }

    fn fixture_parent_with_namespace() -> HashiVaultParentToken {
        HashiVaultParentToken {
            token: SecretString::from("hvs.parent-token-for-tests".to_string()),
            address: "https://vault.example.com:8200".to_string(),
            namespace: Some("admin/team-zero".to_string()),
        }
    }

    fn vault_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::HashiVault,
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

    fn create_ok_body(client_token: &str, lease_duration: u64, policies: &[&str]) -> String {
        serde_json::json!({
            "request_id": "abc-123",
            "lease_id": "",
            "renewable": false,
            "lease_duration": 0,
            "data": null,
            "wrap_info": null,
            "warnings": null,
            "auth": {
                "client_token": client_token,
                "accessor": "acc-xyz",
                "policies": policies,
                "token_policies": policies,
                "metadata": null,
                "lease_duration": lease_duration,
                "renewable": true,
                "entity_id": "",
                "token_type": "service",
                "orphan": true,
            }
        })
        .to_string()
    }

    fn forbidden_body() -> String {
        serde_json::json!({
            "errors": ["1 error occurred:\n\t* permission denied\n\n"]
        })
        .to_string()
    }

    fn invalid_request_body() -> String {
        serde_json::json!({
            "errors": ["unknown policy: ghost-policy"]
        })
        .to_string()
    }

    fn sealed_body() -> String {
        serde_json::json!({
            "errors": ["Vault is sealed"]
        })
        .to_string()
    }

    #[test]
    fn provider_returns_hashi_vault() {
        let broker =
            HashiVaultBroker::with_client(fixture_parent(), Arc::new(MockHttpClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::HashiVault);
    }

    #[test]
    fn build_create_token_body_includes_policies_ttl_and_display_name() {
        let scope = HashiVaultScope {
            policies: vec!["read-only".to_string(), "deploy".to_string()],
            ttl_seconds: 3600,
            renewable: true,
            no_parent: true,
            display_name: Some("ember-broker-test".to_string()),
        };
        let body = build_create_token_body(&scope).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(
            parsed
                .get("policies")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(2)
        );
        assert_eq!(parsed.get("ttl").and_then(|v| v.as_str()), Some("3600s"));
        assert_eq!(
            parsed.get("renewable").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            parsed.get("no_parent").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            parsed.get("display_name").and_then(|v| v.as_str()),
            Some("ember-broker-test")
        );
    }

    #[test]
    fn build_create_token_body_omits_empty_display_name() {
        let scope = HashiVaultScope {
            policies: vec!["read-only".to_string()],
            ttl_seconds: 60,
            renewable: false,
            no_parent: true,
            display_name: None,
        };
        let body = build_create_token_body(&scope).expect("body must build");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert!(
            parsed.get("display_name").is_none(),
            "display_name must be omitted when None: {body}"
        );
    }

    #[test]
    fn build_create_token_body_rejects_empty_policies() {
        let scope = HashiVaultScope {
            policies: vec![],
            ttl_seconds: 60,
            renewable: false,
            no_parent: true,
            display_name: None,
        };
        let err = build_create_token_body(&scope).expect_err("must error");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[test]
    fn build_create_token_body_rejects_zero_ttl() {
        let scope = HashiVaultScope {
            policies: vec!["read-only".to_string()],
            ttl_seconds: 0,
            renewable: false,
            no_parent: true,
            display_name: None,
        };
        let err = build_create_token_body(&scope).expect_err("must error");
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_happy_path_returns_bundle_and_records_state() {
        let mock = Arc::new(MockHttpClient::new().with_response(
            200,
            create_ok_body("hvs.minted-child-token", 3600, &["read-only"]),
        ));
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock.clone());
        let req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 3600,
                "renewable": true,
                "no_parent": true,
                "display_name": "ember-test",
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        // The broker returns a JSON bundle pairing the child token
        // with VAULT_ADDR — the daemon-side handler splits it into
        // VAULT_TOKEN + VAULT_ADDR env vars at injection time.
        let bundle: serde_json::Value =
            serde_json::from_str(cred.token.expose_secret()).expect("bundle is JSON");
        assert_eq!(
            bundle.get("token").and_then(|v| v.as_str()),
            Some("hvs.minted-child-token")
        );
        assert_eq!(
            bundle.get("address").and_then(|v| v.as_str()),
            Some("https://vault.example.com:8200")
        );
        assert!(
            cred.materialization_id.starts_with("vault-ember-test-"),
            "materialization_id includes display_name: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);

        let call = mock.last_call().expect("call recorded");
        assert_eq!(
            call.url,
            "https://vault.example.com:8200/v1/auth/token/create"
        );
        assert_eq!(call.vault_token, "hvs.parent-token-for-tests");
        assert!(call.namespace.is_none());
        assert!(
            call.body.contains("\"policies\":[\"read-only\"]"),
            "body must include policies: {}",
            call.body
        );
        assert!(
            call.body.contains("\"ttl\":\"3600s\""),
            "body must include ttl: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_no_parent_default_is_true_when_absent_in_scope() {
        let mock = Arc::new(
            MockHttpClient::new()
                .with_response(200, create_ok_body("hvs.np-token", 60, &["read-only"])),
        );
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock.clone());
        // Scope omits `no_parent` — must default to true.
        let req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 60,
                "renewable": false,
            }),
            60,
        );
        Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        let call = mock.last_call().expect("call recorded");
        assert!(
            call.body.contains("\"no_parent\":true"),
            "no_parent must default to true: {}",
            call.body
        );
    }

    #[tokio::test]
    async fn issue_namespace_passthrough_sets_x_vault_namespace_header() {
        let mock = Arc::new(
            MockHttpClient::new()
                .with_response(200, create_ok_body("hvs.ns-token", 60, &["read-only"])),
        );
        let broker = HashiVaultBroker::with_client(fixture_parent_with_namespace(), mock.clone());
        let req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 60,
                "renewable": false,
                "no_parent": true,
            }),
            60,
        );
        Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        let call = mock.last_call().expect("call recorded");
        assert_eq!(call.namespace.as_deref(), Some("admin/team-zero"));
    }

    #[tokio::test]
    async fn issue_403_returns_policy_rejected() {
        let mock = Arc::new(MockHttpClient::new().with_response(403, forbidden_body()));
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock);
        let req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 60,
                "renewable": false,
                "no_parent": true,
            }),
            60,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for 403, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_400_returns_upstream_with_descriptive_message() {
        let mock = Arc::new(MockHttpClient::new().with_response(400, invalid_request_body()));
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock);
        let req = vault_request(
            serde_json::json!({
                "policies": ["ghost-policy"],
                "ttl_seconds": 60,
                "renewable": false,
                "no_parent": true,
            }),
            60,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 400, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("ghost-policy"),
            "error must mention the parsed Vault errors[]: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_500_sealed_returns_upstream_with_sealed_message() {
        let mock = Arc::new(MockHttpClient::new().with_response(503, sealed_body()));
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock);
        let req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 60,
                "renewable": false,
                "no_parent": true,
            }),
            60,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream for 503-sealed, got {err:?}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("sealed"),
            "error must mention vault sealed: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker =
            HashiVaultBroker::with_client(fixture_parent(), Arc::new(MockHttpClient::new()));
        let mut req = vault_request(
            serde_json::json!({
                "policies": ["read-only"],
                "ttl_seconds": 60,
                "renewable": false,
                "no_parent": true,
            }),
            60,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_happy_path_calls_revoke_self_with_child_token() {
        let mock = Arc::new(
            MockHttpClient::new()
                .with_response(200, create_ok_body("hvs.child-rev-1", 60, &["read-only"]))
                .with_response(204, "".to_string()),
        );
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            vault_request(
                serde_json::json!({
                    "policies": ["read-only"],
                    "ttl_seconds": 60,
                    "renewable": false,
                    "no_parent": true,
                    "display_name": "ember-rev",
                }),
                60,
            ),
        )
        .await
        .expect("issue must succeed");

        assert_eq!(broker.active_count(), 1);
        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed (best-effort)");
        assert_eq!(broker.active_count(), 0);
        // 1 call for issue + 1 call for revoke.
        assert_eq!(mock.call_count(), 2);
        let last = mock.last_call().expect("revoke call recorded");
        assert_eq!(
            last.url,
            "https://vault.example.com:8200/v1/auth/token/revoke-self"
        );
        // revoke-self uses the CHILD token, not the parent.
        assert_eq!(last.vault_token, "hvs.child-rev-1");
    }

    #[tokio::test]
    async fn revoke_already_expired_404_is_treated_as_success() {
        let mock = Arc::new(
            MockHttpClient::new()
                .with_response(200, create_ok_body("hvs.child-expired", 60, &["read-only"]))
                .with_response(404, r#"{"errors":[]}"#.to_string()),
        );
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock.clone());
        let cred = Broker::issue(
            &broker,
            vault_request(
                serde_json::json!({
                    "policies": ["read-only"],
                    "ttl_seconds": 60,
                    "renewable": false,
                    "no_parent": true,
                    "display_name": "ember-404",
                }),
                60,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed when child is already expired");
        assert_eq!(broker.active_count(), 0);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker =
            HashiVaultBroker::with_client(fixture_parent(), Arc::new(MockHttpClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn hashivault_scope_round_trips_through_json() {
        let scope = HashiVaultScope {
            policies: vec!["read-only".to_string(), "deploy".to_string()],
            ttl_seconds: 1800,
            renewable: true,
            no_parent: true,
            display_name: Some("ember-scope".to_string()),
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: HashiVaultScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.policies, scope.policies);
        assert_eq!(parsed.ttl_seconds, scope.ttl_seconds);
        assert_eq!(parsed.renewable, scope.renewable);
        assert_eq!(parsed.no_parent, scope.no_parent);
        assert_eq!(parsed.display_name, scope.display_name);
    }

    #[test]
    fn hashivault_scope_default_no_parent_is_true_when_absent() {
        let parsed: HashiVaultScope =
            serde_json::from_str(r#"{"policies":["x"],"ttl_seconds":60,"renewable":false}"#)
                .expect("deserialize");
        assert!(parsed.no_parent, "no_parent must default to true");
    }

    #[test]
    fn join_addr_strips_single_trailing_slash() {
        assert_eq!(
            join_addr("https://vault.example.com:8200", "/v1/auth/token/create"),
            "https://vault.example.com:8200/v1/auth/token/create"
        );
        assert_eq!(
            join_addr("https://vault.example.com:8200/", "/v1/auth/token/create"),
            "https://vault.example.com:8200/v1/auth/token/create"
        );
    }

    #[test]
    fn map_vault_http_error_403_returns_policy_rejected() {
        let err = map_vault_http_error(403, &forbidden_body());
        assert!(matches!(err, BrokerError::PolicyRejected(_)));
    }

    #[test]
    fn map_vault_http_error_400_returns_upstream() {
        let err = map_vault_http_error(400, &invalid_request_body());
        assert!(matches!(err, BrokerError::Upstream(_)));
    }

    #[test]
    fn map_vault_http_error_503_sealed_returns_upstream_with_sealed() {
        let err = map_vault_http_error(503, &sealed_body());
        let msg = format!("{err}");
        assert!(matches!(err, BrokerError::Upstream(_)));
        assert!(msg.to_ascii_lowercase().contains("sealed"));
    }

    #[tokio::test]
    async fn issue_mint_stamp_is_opaque() {
        let mock = Arc::new(MockHttpClient::new().with_response(
            200,
            create_ok_body("hvs.test-child-token", 3600, &["readonly"]),
        ));
        let broker = HashiVaultBroker::with_client(fixture_parent(), mock);
        let req = vault_request(
            serde_json::json!({
                "policies": ["readonly"],
                "ttl_seconds": 3600,
                "renewable": true,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert!(
            matches!(cred.mint_stamp, MintStamp::Opaque),
            "HashiVault mint_stamp should be Opaque, got {:?}",
            cred.mint_stamp
        );
    }
}
