//! CLASSIFICATION: PUBLIC
//!
//! PolicyBackend trait — decouples proxy IO from policy/credential/Receipt RPCs.
//!
//! The trait surface maps 1:1 to the direct `state.store.*` / `state.vault.*`
//! calls that today's `handle_request` makes in `ember-daemon`. Subtask -B
//! will do a mechanical `s/state.store.foo/backend.foo/` replacement once
//! `handle_request` is ported into this crate.

use async_trait::async_trait;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A grant resolved to a specific Statement for the incoming request.
///
/// Captures the grant identity, the matched Statement, and the metadata needed
/// for metering and audit in a single value that can be passed through the
/// proxy pipeline without re-querying the store.
#[derive(Debug, Clone)]
pub struct ResolvedGrant {
    pub grant_id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub statement_sid: String,
    pub statement: core_grant_types::Statement,
    /// Legacy flat grant-scope metadata from the stored grant row.
    ///
    /// Composite grants may carry richer signed statement chains than this
    /// single string can faithfully encode, so proxy request authorization
    /// must use `statement` rather than this field. Keep this for audit /
    /// display / compatibility surfaces that still expose the stored row.
    pub grant_scope: String,
    /// Optional comma-separated list of allowed upstream hosts/patterns.
    /// `None` means any target is permitted. Set from the grant's
    /// `allowed_targets` field; `None` in test fixtures.
    pub allowed_targets: Option<String>,
}

/// Errors returned by `PolicyBackend` operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("store error: {0}")]
    Store(String),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("other: {0}")]
    Other(String),
}

/// Outcome of a pre-flight budget check.
///
/// `Allowed` — proceed with the upstream request.
/// `Rejected` — return a 429 to the caller; names the exhausted axis so the
/// agent can back off intelligently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightDecision {
    Allowed,
    Rejected {
        axis: &'static str,
        limit: u64,
        used: u64,
    },
}

/// Per-upstream-call observation used to mint the visible `proxy_call`
/// receipt and event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCallReceiptRequest {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub outcome: String,
}

/// Trait that decouples proxy pipeline logic from its backing store and vault.
///
/// The co-located implementation (`ColocatedBackend`) delegates to the daemon's
/// in-process `ProxyState`. A remote implementation (subtask -C) will RPC over
/// a Unix-domain socket instead, allowing the proxy to run as a separate binary.
#[async_trait]
pub trait PolicyBackend: Send + Sync + 'static {
    async fn resolve_attachment_authority(
        &self,
        _attachment_id: &str,
        _endpoint_token: &str,
    ) -> Result<Option<ResolvedAttachmentAuthority>, PolicyError> {
        Ok(None)
    }

    /// Resolve the attachment authority bound to a per-session peercred-gated
    /// socket, keyed by `session_id` — **without** an endpoint-token bearer.
    ///
    /// P22-S2 (ADR 197 §2): on the per-session UDS lane the socket path *is*
    /// the attachment binding and the connection was already kernel-attested by
    /// the accept-time gate (peercred uid + liveness + launcher pid-tree +
    /// binary attestation). The replayable bearer is therefore superseded —
    /// `handle_request` resolves the credential identity from the socket's
    /// session binding instead of a caller-supplied token. The default returns
    /// `None` (no socket binding) so non-daemon backends and the transitional
    /// TCP lane are unaffected.
    async fn resolve_attachment_for_session(
        &self,
        _session_id: &str,
    ) -> Result<Option<ResolvedAttachmentAuthority>, PolicyError> {
        Ok(None)
    }

    /// Resolve the gateway authority for a session entirely server-side, keyed
    /// by the daemon-minted `session_id` rather than by client-supplied
    /// `X-Ember-*` headers.
    ///
    /// The codex loopback-TCP responses lane (P22-S2 / ADR 197 codex) cannot
    /// instruct codex to send `X-Ember-Credential` / `X-Ember-Target` /
    /// `X-Ember-Persona` headers — codex only POSTs a JSON body to
    /// `base_url/responses`. So the codex handler must synthesize the persona,
    /// grant, and credential name from the session binding the acceptor set.
    /// The daemon implementation reads the session metadata (persona + grant
    /// id) and resolves the grant's `credential_name`.
    ///
    /// Returns `None` when the session has no resolvable gateway authority
    /// (unknown / closed session). The codex handler treats `None` as
    /// fail-closed (403 — no credential is synthesized, nothing forwarded).
    async fn resolve_session_authority(
        &self,
        _session_id: &str,
    ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
        Ok(None)
    }

    /// Resolve the active grant for `(persona_id, credential_name)` and find
    /// the Statement that covers the incoming request's method + URI.
    ///
    /// When `resolved_grant_id` is `Some`, use the daemon-resolved current
    /// grant for an attachment rather than searching by persona/credential;
    /// the grant must still belong to `persona_id` and reference
    /// `credential_name`.
    ///
    /// `method` is the HTTP method string (e.g. `"GET"`, `"POST"`) used to
    /// resolve the applicable Statement in the grant's composite chain.
    async fn resolve_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        resolved_grant_id: Option<&str>,
        effective_uri: &http::Uri,
        method: &str,
    ) -> Result<ResolvedGrant, PolicyError>;

    /// Run the pre-flight budget check for an already-resolved grant.
    ///
    /// `body_bytes` is the collected request body, used for token estimation.
    async fn preflight_budget(
        &self,
        resolved: &ResolvedGrant,
        body_bytes: &[u8],
    ) -> Result<PreflightDecision, PolicyError>;

    /// Decrypt and return the named credential from the vault.
    ///
    /// The returned value is wrapped in `Zeroizing` so the secret bytes are
    /// wiped when the value is dropped.
    async fn get_credential(&self, credential_name: &str)
    -> Result<Zeroizing<String>, PolicyError>;

    /// Resolve the ChatGPT *plan/subscription* OAuth auth for the codex
    /// responses lane (P22-S2 GPT-plan rework).
    ///
    /// Unlike [`get_credential`] (which returns a single opaque secret string),
    /// the codex GPT-plan lane needs a *structured* credential: a short-window
    /// `Bearer` access token PLUS the `ChatGPT-Account-ID` the upstream
    /// (`chatgpt.com/backend-api/codex/responses`) requires. The vault stores
    /// the codex `auth.json` token blob (`{id_token, access_token,
    /// refresh_token, account_id}`); the daemon implementation parses it,
    /// refreshes the access token against `auth.openai.com/oauth/token` when it
    /// is near expiry (the daemon owns the `refresh_token` + rotation
    /// write-back — see ADR 197), and returns ONLY the fields the proxy injects.
    /// The `refresh_token` deliberately never crosses this boundary.
    ///
    /// Returns [`PolicyError::Forbidden`] with a re-auth signal when the
    /// `refresh_token` is expired/reused/revoked (the operator must re-run
    /// `codex login`). The default errors so non-codex backends need not
    /// implement it.
    async fn resolve_chatgpt_plan_auth(
        &self,
        _credential_name: &str,
    ) -> Result<ChatgptPlanAuth, PolicyError> {
        Err(PolicyError::Other(
            "chatgpt plan auth not supported by this backend".into(),
        ))
    }

    /// Resolve a short-window OAuth **Bearer** access token for the gemini Code
    /// Assist ("Sign in with Google") loopback lane (ADR 215 slice 2).
    ///
    /// Symmetric with [`resolve_chatgpt_plan_auth`], but the Code Assist lane
    /// needs only a single `Authorization: Bearer <access_token>` (no
    /// account-id). The vault stores the gemini `oauth_creds.json` blob
    /// (`{access_token, refresh_token, expiry_date, ...}`); the daemon
    /// implementation parses it, refreshes the access token against Google's
    /// OAuth token endpoint (`oauth2.googleapis.com/token`) with the gemini-cli
    /// public client id/secret + the stored `refresh_token` when it is near
    /// expiry, and returns ONLY the access token the proxy injects. The
    /// `refresh_token` deliberately never crosses this boundary (it stays
    /// daemon-only — the structural-absence root the loopback lane relies on).
    ///
    /// Returns [`PolicyError::Forbidden`] with a re-auth signal when the
    /// `refresh_token` is expired/reused/revoked (the operator must re-run the
    /// gemini "Sign in with Google" flow). The default errors so non-gemini
    /// backends need not implement it.
    async fn resolve_oauth_bearer(
        &self,
        _credential_name: &str,
    ) -> Result<Zeroizing<String>, PolicyError> {
        Err(PolicyError::Other(
            "oauth bearer auth not supported by this backend".into(),
        ))
    }

    /// Meter post-flight usage against the resolved grant/statement.
    ///
    /// `usage` is `None` when the upstream response did not include usage
    /// metadata (e.g. non-LLM credential grants).
    async fn post_flight(
        &self,
        resolved: &ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError>;

    /// Post-flight metering hook for credential grants that need explicit
    /// budget commit/decrement after the upstream call completes.
    ///
    /// Distinct from `post_flight` so the daemon-side implementation can
    /// route the two through different metering paths — Slice B will land
    /// the in-process implementation, Slice C the remote one.
    /// (ARCH-PROXY-TRAITS-EXPAND-A.)
    async fn post_flight_meter(
        &self,
        resolved: &ResolvedGrant,
        usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError>;

    /// Mint a signed receipt for the human-visible `proxy_call` event.
    ///
    /// Backends without a receipt subsystem return `Ok(None)`; the forwarding
    /// runtime then omits the event rather than emitting an unsigned demo id.
    async fn issue_proxy_call_receipt(
        &self,
        _resolved: &ResolvedGrant,
        _call: &ProxyCallReceiptRequest,
    ) -> Result<Option<String>, PolicyError> {
        Ok(None)
    }

    /// Append an audit event.
    ///
    /// Parameters mirror the `log_event` call shape used throughout
    /// `handle_request` today so subtask -B can replace direct store calls 1:1.
    async fn log_event(
        &self,
        persona_id: &str,
        event_kind: &str,
        credential_name: Option<&str>,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<(), PolicyError>;
}

/// Server-side gateway authority for a session, resolved from the
/// daemon-minted `session_id` by [`PolicyBackend::resolve_session_authority`].
///
/// Used by the codex responses lane, where no `X-Ember-*` headers exist: the
/// handler synthesizes the credential identity from this rather than trusting
/// any caller-supplied bearer/credential header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGatewayAuthority {
    pub session_id: String,
    pub persona_id: String,
    pub grant_id: String,
    pub credential_name: String,
}

/// Structured ChatGPT plan/subscription auth resolved for the codex responses
/// lane by [`PolicyBackend::resolve_chatgpt_plan_auth`].
///
/// Carries ONLY what the proxy injects on the outbound request: the current
/// (already-refreshed-if-needed) access token, the workspace/account id, and
/// the FedRAMP routing flag. The long-lived `refresh_token` stays daemon-side
/// (the daemon owns refresh + rotation per ADR 197) and never appears here.
#[derive(Clone)]
pub struct ChatgptPlanAuth {
    /// Short-window ChatGPT OAuth access token, injected as `Authorization:
    /// Bearer`. `Zeroizing` so the secret is wiped on drop.
    pub access_token: Zeroizing<String>,
    /// ChatGPT workspace/account id, injected as the `ChatGPT-Account-ID`
    /// header. `None` when the token blob carried neither an explicit
    /// `account_id` nor a `chatgpt_account_id` id-token claim.
    pub account_id: Option<String>,
    /// Whether the account must route through the FedRAMP edge
    /// (`X-OpenAI-Fedramp: true`).
    pub is_fedramp: bool,
}

impl std::fmt::Debug for ChatgptPlanAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the access token.
        f.debug_struct("ChatgptPlanAuth")
            .field("access_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("is_fedramp", &self.is_fedramp)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttachmentAuthority {
    pub session_id: String,
    pub attachment_id: String,
    pub runtime_persona_id: String,
    pub caller_binding_id: String,
    pub grant_id: String,
    pub state: String,
    /// ADR 190 §4 base posture for the session: `true` => strict (a lapsed
    /// authority denies until re-delegated), `false` => jit (re-approvable).
    /// Lets the LLM lane render a posture-aware recovery signal instead of a
    /// flat 403 when the grant goes non-active mid-session (ADR 197 §2).
    pub authority_strict: bool,
}

/// A grant record held in `ProxyState`'s in-process store.
///
/// Populated at grant-mint time and read by `ColocatedBackend::resolve_grant`.
#[derive(Debug, Clone)]
pub struct GrantRecord {
    pub grant_id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub statements: Vec<core_grant_types::Statement>,
}

/// In-process proxy state.
///
/// Holds the grant table and credential vault for use by `ColocatedBackend`.
/// This is the core-proxy-forward–native representation; the ember-daemon
/// integration layer (subtask -B) will wire `DaemonStore` + `Vault` into this
/// by adapting them to the same API surface.
#[derive(Default)]
pub struct ProxyState {
    /// Active grants keyed by `(persona_id, credential_name)`.
    /// Multiple grants may share a key; the first active one wins.
    pub grants: std::sync::RwLock<Vec<GrantRecord>>,
    /// Plaintext credentials keyed by `credential_name`. In the daemon the
    /// vault holds encrypted secrets; here we hold plaintext for unit tests.
    pub credentials: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl ProxyState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the in-memory state with a grant record (test helper).
    pub fn insert_grant(&self, record: GrantRecord) {
        self.grants.write().unwrap().push(record);
    }

    /// Seed the in-memory state with a plaintext credential (test helper).
    pub fn insert_credential(&self, name: impl Into<String>, value: impl Into<String>) {
        self.credentials
            .write()
            .unwrap()
            .insert(name.into(), value.into());
    }
}

/// Co-located `PolicyBackend` implementation.
///
/// Delegates every method to the `ProxyState` embedded in the same process.
/// Behavior-equivalent to the direct `state.store.*` / `state.vault.*` calls
/// that `handle_request` makes today — subtask -B will replace those call sites
/// with this trait surface.
pub struct ColocatedBackend {
    state: Arc<ProxyState>,
}

impl ColocatedBackend {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl PolicyBackend for ColocatedBackend {
    async fn resolve_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        resolved_grant_id: Option<&str>,
        _effective_uri: &http::Uri,
        _method: &str,
    ) -> Result<ResolvedGrant, PolicyError> {
        let grants = self.state.grants.read().unwrap();
        let record = if let Some(gid) = resolved_grant_id {
            grants.iter().find(|g| g.grant_id == gid)
        } else {
            grants
                .iter()
                .find(|g| g.persona_id == persona_id && g.credential_name == credential_name)
        };

        let record = record.ok_or_else(|| {
            PolicyError::NotFound(format!(
                "no active grant for persona={persona_id} credential={credential_name}"
            ))
        })?;

        if record.persona_id != persona_id {
            return Err(PolicyError::Forbidden(
                "grant belongs to a different persona".into(),
            ));
        }
        if record.credential_name != credential_name {
            return Err(PolicyError::Forbidden(
                "grant credential_name does not match".into(),
            ));
        }

        let stmt = record
            .statements
            .first()
            .cloned()
            .ok_or_else(|| PolicyError::Store("grant has no statements".into()))?;

        Ok(ResolvedGrant {
            grant_id: record.grant_id.clone(),
            persona_id: record.persona_id.clone(),
            credential_name: record.credential_name.clone(),
            statement_sid: stmt.sid.clone(),
            statement: stmt,
            grant_scope: "*".to_string(),
            allowed_targets: None,
        })
    }

    async fn preflight_budget(
        &self,
        resolved: &ResolvedGrant,
        _body_bytes: &[u8],
    ) -> Result<PreflightDecision, PolicyError> {
        let stmt = &resolved.statement;
        let Some(budget) = &stmt.budget else {
            return Ok(PreflightDecision::Allowed);
        };
        if let Some(cap) = budget.tokens
            && stmt.usage.tokens >= cap
        {
            return Ok(PreflightDecision::Rejected {
                axis: "tokens",
                limit: cap,
                used: stmt.usage.tokens,
            });
        }
        if let Some(cap) = budget.cents
            && stmt.usage.cents >= cap
        {
            return Ok(PreflightDecision::Rejected {
                axis: "cents",
                limit: cap,
                used: stmt.usage.cents,
            });
        }
        Ok(PreflightDecision::Allowed)
    }

    async fn get_credential(
        &self,
        credential_name: &str,
    ) -> Result<Zeroizing<String>, PolicyError> {
        let creds = self.state.credentials.read().unwrap();
        creds
            .get(credential_name)
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| {
                PolicyError::NotFound(format!("credential not found: {credential_name}"))
            })
    }

    /// Minimal test impl: treats the stored plaintext credential as the raw
    /// access token, with no account id. The structured `auth.json` blob
    /// parsing + refresh lives in the daemon implementation (which owns the
    /// vault); the colocated in-memory backend exists only for unit tests.
    async fn resolve_chatgpt_plan_auth(
        &self,
        credential_name: &str,
    ) -> Result<ChatgptPlanAuth, PolicyError> {
        let creds = self.state.credentials.read().unwrap();
        creds
            .get(credential_name)
            .map(|v| ChatgptPlanAuth {
                access_token: Zeroizing::new(v.clone()),
                account_id: None,
                is_fedramp: false,
            })
            .ok_or_else(|| {
                PolicyError::NotFound(format!("credential not found: {credential_name}"))
            })
    }

    async fn post_flight(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn post_flight_meter(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn log_event(
        &self,
        _persona_id: &str,
        _event_kind: &str,
        _credential_name: Option<&str>,
        _outcome: &str,
        _detail: Option<&str>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grant_types::{ResourceSelector, ResourceType, Statement, Usage};

    fn make_statement(sid: impl Into<String>) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: ResourceType::Session,
            actions: vec!["POST".into()],
            resource: ResourceSelector::Glob {
                pattern: "https://api.anthropic.com/*".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        }
    }

    #[tokio::test]
    async fn colocated_backend_delegates_resolve_grant() {
        let state = Arc::new(ProxyState::new());
        let stmt = make_statement("stmt-001");
        state.insert_grant(GrantRecord {
            grant_id: "grant-abc".into(),
            persona_id: "alice".into(),
            credential_name: "anthropic-key".into(),
            statements: vec![stmt.clone()],
        });

        let backend = ColocatedBackend::new(Arc::clone(&state));
        let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
        let resolved = backend
            .resolve_grant("alice", "anthropic-key", None, &uri, "POST")
            .await
            .expect("resolve_grant should succeed");

        assert_eq!(resolved.grant_id, "grant-abc");
        assert_eq!(resolved.persona_id, "alice");
        assert_eq!(resolved.credential_name, "anthropic-key");
        assert_eq!(resolved.statement_sid, "stmt-001");
        assert_eq!(resolved.statement.sid, stmt.sid);
    }

    #[tokio::test]
    async fn colocated_backend_resolve_grant_not_found() {
        let state = Arc::new(ProxyState::new());
        let backend = ColocatedBackend::new(Arc::clone(&state));
        let uri: http::Uri = "https://api.openai.com/v1/chat".parse().unwrap();
        let err = backend
            .resolve_grant("bob", "openai-key", None, &uri, "GET")
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::NotFound(_)));
    }

    #[tokio::test]
    async fn colocated_backend_get_credential() {
        let state = Arc::new(ProxyState::new());
        state.insert_credential("my-key", "sk-secret");
        let backend = ColocatedBackend::new(Arc::clone(&state));
        let cred = backend.get_credential("my-key").await.unwrap();
        assert_eq!(cred.as_str(), "sk-secret");
    }

    #[tokio::test]
    async fn colocated_backend_preflight_budget_no_budget_allowed() {
        let state = Arc::new(ProxyState::new());
        let stmt = make_statement("s1");
        state.insert_grant(GrantRecord {
            grant_id: "g1".into(),
            persona_id: "p".into(),
            credential_name: "c".into(),
            statements: vec![stmt],
        });
        let backend = ColocatedBackend::new(Arc::clone(&state));
        let uri: http::Uri = "https://example.com/".parse().unwrap();
        let resolved = backend
            .resolve_grant("p", "c", None, &uri, "GET")
            .await
            .unwrap();
        let decision = backend
            .preflight_budget(&resolved, b"test body")
            .await
            .unwrap();
        assert_eq!(decision, PreflightDecision::Allowed);
    }
}
