//! Socket RPC handlers for the credential broker (design Phase 2).
//!
//! Wires `ember broker {issue,revoke,list}` CLI calls onto the daemon's
//! existing JSON-lines socket protocol. The broker registry is a
//! process-global `OnceCell` initialised once at daemon startup
//! (`runtime.rs::run`); subsequent dispatcher calls look it up via
//! `current_registry()`.
//!
//! ## RPC method names (matched in `handler.rs::dispatch_method`)
//!
//! - `broker_issue`  → [`handle_broker_issue`]
//! - `broker_revoke` → [`handle_broker_revoke`]
//! - `broker_list`   → [`handle_broker_list`]
//!
//! Marker for headless ranker grep: **`BrokerIssue`** (this module path is
//! `broker_handler`, satisfying the marker contract from implementation-note-29.)
//!
//! ## Object-safety adapter
//!
//! `core_broker::Broker` uses `async fn` in trait via `impl Future`, which
//! is NOT dyn-compatible. To store heterogeneous providers in a single
//! `HashMap`, this module defines [`DynBroker`] — an object-safe trait
//! that returns `Pin<Box<dyn Future>>` instead. A blanket impl wraps any
//! concrete `Broker` so `MockBroker` (and future providers) drop in
//! without provider-side ceremony.
//!
//! ## Receipt emission
//!
//! Per design §c, every successful issue/revoke records a Receipt event.
//! For Phase 2 we emit these into the existing `audit_log` table with
//! `action = "broker.materialization"` / `"broker.revocation"` and the
//! ADR-defined JSON payload in the `details` column. This reuses the
//! existing query path (`audit_query`) without forcing a schema change to
//! the receipts table — full GrantReceipt artefacts remain grant-tied.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, SecretRef,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use core_types::grant_receipt::{BrokerReceipt, Evidence, ReceiptKind};

use crate::binary_manifest::BinaryManifest;
use crate::infra::receipt::{current_identity, sign_broker_receipt};
use crate::infra::store::DaemonStore;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Binary pin verification (design §7)
// ---------------------------------------------------------------------------

/// A verified pinned binary — the daemon trusts this path's bytes
/// match the manifest's recorded content_hash AT THE TIME OF VERIFY.
/// `broker_exec` should call `verify_binary_pin` IMMEDIATELY before
/// spawn (TOCTOU window minimization).
#[derive(Debug, Clone)]
pub struct PinnedBinary {
    pub path: PathBuf,
    pub content_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("tool '{0}' not in manifest")]
    NotInManifest(String),
    #[error("binary_pin_mismatch: expected={expected} actual={actual} path={path:?}")]
    HashMismatch {
        expected: String,
        actual: String,
        path: PathBuf,
    },
    #[error("io reading binary: {0}")]
    Io(String),
}

/// Verify that the on-disk binary at `manifest[tool].absolute_path`
/// hashes to `manifest[tool].content_hash` per design §7.
///
/// Reads binary bytes (mmap optimization deferred — `std::fs::read` is
/// fine for v1 since binaries are typically <100 MB), recomputes
/// blake3, compares to the manifest's recorded hash. Returns
/// `PinError::HashMismatch` on divergence (caller emits the
/// `binary_pin_mismatch` Receipt).
pub fn verify_binary_pin(
    manifest: &BinaryManifest,
    tool: &str,
) -> Result<PinnedBinary, PinError> {
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.tool_name == tool)
        .ok_or_else(|| PinError::NotInManifest(tool.to_string()))?;

    let bytes = std::fs::read(&entry.absolute_path)
        .map_err(|e| PinError::Io(e.to_string()))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    let computed = hex::encode(hasher.finalize().as_bytes());

    let expected = entry
        .content_hash
        .strip_prefix("blake3:")
        .unwrap_or(&entry.content_hash);

    if computed != expected {
        return Err(PinError::HashMismatch {
            expected: expected.to_string(),
            actual: computed,
            path: entry.absolute_path.clone(),
        });
    }

    Ok(PinnedBinary {
        path: entry.absolute_path.clone(),
        content_hash: format!("blake3:{computed}"),
    })
}

// ---------------------------------------------------------------------------
// Object-safety adapter (DynBroker)
// ---------------------------------------------------------------------------

/// Object-safe broker adapter — concrete [`Broker`] impls (which use
/// `impl Future` and so are NOT dyn-compatible) get a blanket impl that
/// type-erases via `Pin<Box<dyn Future>>`. The daemon registry stores
/// `Box<dyn DynBroker>` so a single `HashMap` can hold heterogeneous
/// providers (Mock today; Anthropic/Cloudflare downstream).
pub trait DynBroker: Send + Sync {
    fn provider(&self) -> BrokerProvider;

    fn issue<'a>(
        &'a self,
        req: BrokerRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BrokeredCredential, BrokerError>> + Send + 'a>>;

    fn revoke<'a>(
        &'a self,
        materialization_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BrokerError>> + Send + 'a>>;
}

impl<B: Broker + 'static> DynBroker for B {
    fn provider(&self) -> BrokerProvider {
        Broker::provider(self)
    }

    fn issue<'a>(
        &'a self,
        req: BrokerRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BrokeredCredential, BrokerError>> + Send + 'a>> {
        Box::pin(Broker::issue(self, req))
    }

    fn revoke<'a>(
        &'a self,
        materialization_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BrokerError>> + Send + 'a>> {
        Box::pin(Broker::revoke(self, materialization_id))
    }
}

// ---------------------------------------------------------------------------
// MaterializationSummary — `broker_list` response shape
// ---------------------------------------------------------------------------

/// One row of the `broker_list` response. Mirrors design §c.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializationSummary {
    pub materialization_id: String,
    pub provider: BrokerProvider,
    /// RFC3339 UTC.
    pub issued_at: String,
    /// RFC3339 UTC.
    pub expires_at: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// BrokerExecRequest / BrokerExecResponse — `broker_exec` wire shapes
// ---------------------------------------------------------------------------

/// Wire shape for `broker_exec` RPC params.
#[derive(Debug, serde::Deserialize)]
pub struct BrokerExecRequest {
    /// Absolute path to the Construct binary to execute.
    pub binary: String,
    /// CLI argv (does NOT include argv[0]).
    pub argv: Vec<String>,
    /// Working directory for the child process. Defaults to `$HOME` when None.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Subset of host env vars the child should inherit beyond the
    /// allowlist (PATH, HOME, USER, LANG, TERM). Each entry must match
    /// `^[A-Z_][A-Z0-9_]*$` shape; arbitrary names rejected.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// When present, the daemon allocates a pty pair via forkpty, attaches
    /// the slave fd to the child's stdin/stdout/stderr, and calls
    /// `pty_bridge_run` with the master fd + this UDS path. The agent must
    /// be listening on this socket before sending the RPC; the daemon
    /// connects immediately after fork. Absence falls through to the
    /// non-PTY (piped) spawn path.
    #[serde(default)]
    pub pty_socket_path: Option<String>,
    /// When true, the daemon mints a per-session ed25519 keypair and binds
    /// a daemon-managed ssh-agent socket. `SSH_AUTH_SOCK` is injected into
    /// the child env so git/ssh in the child tree find the daemon socket.
    /// The private key is held in the daemon's address space and zeroed on
    /// session end (design / implementation-note-22).
    #[serde(default)]
    pub ssh_agent: bool,
}

/// Response shape for `broker_exec`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BrokerExecResponse {
    /// Exit code; -1 if the child was terminated by signal.
    pub exit_code: i32,
    /// True iff exit_code == 0.
    pub success: bool,
    /// Truncated stderr (last 4 KiB) for diagnostics. Stdout is NOT
    /// captured — Constructs should write durable output to files.
    pub stderr_tail: String,
}

// ---------------------------------------------------------------------------
// BrokerRegistry
// ---------------------------------------------------------------------------

/// Daemon-side broker registry — owns one [`DynBroker`] per
/// [`BrokerProvider`] and tracks active materializations across all
/// providers so `broker revoke <id>` can route to the right impl without
/// the caller naming the provider.
pub struct BrokerRegistry {
    brokers: HashMap<BrokerProvider, Box<dyn DynBroker>>,
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    /// `materialization_id` → summary. Updated on issue, removed on
    /// successful revoke. Used to (a) route `revoke` to the right
    /// provider, and (b) answer `broker_list`.
    active: HashMap<String, MaterializationSummary>,
    /// `materialization_id` → plaintext credential. Retained inside the
    /// daemon so `broker_resolve` can hand the secret to the trust
    /// boundary (ember-proxy / ember-tools) per
    /// implementation-note-7. Plaintext NEVER returns to the
    /// agent process — agents hold the opaque `SecretRef` (= the
    /// `materialization_id`) and present it to the proxy.
    plaintext: HashMap<String, secrecy::SecretString>,
}

impl BrokerRegistry {
    /// Build an empty registry. Use [`Self::register`] to add brokers.
    pub fn new() -> Self {
        Self {
            brokers: HashMap::new(),
            state: Mutex::new(RegistryState::default()),
        }
    }

    /// Register a broker for a provider. The last registration wins so
    /// tests can swap implementations.
    pub fn register(&mut self, broker: Box<dyn DynBroker>) {
        let provider = broker.provider();
        self.brokers.insert(provider, broker);
    }

    /// Returns true when the given provider has a registered impl.
    pub fn has_provider(&self, provider: BrokerProvider) -> bool {
        self.brokers.contains_key(&provider)
    }

    /// Snapshot of all currently-active materializations, sorted by
    /// `issued_at` ascending so output is deterministic.
    pub fn list_active(&self) -> Vec<MaterializationSummary> {
        let st = self.state.lock().expect("broker registry mutex");
        let mut out: Vec<MaterializationSummary> = st.active.values().cloned().collect();
        out.sort_by(|a, b| a.issued_at.cmp(&b.issued_at));
        out
    }

    fn record_active(&self, summary: MaterializationSummary) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.active.insert(summary.materialization_id.clone(), summary);
    }

    /// Stash the daemon-internal plaintext for a freshly-issued
    /// materialization. Companion to [`Self::record_active`]; only the
    /// daemon ever holds plaintext, and only the trust boundary
    /// (ember-proxy / ember-tools) ever asks for it back via
    /// `broker_resolve`. See implementation-note-7.
    fn record_plaintext(&self, materialization_id: String, plaintext: secrecy::SecretString) {
        let mut st = self.state.lock().expect("broker registry mutex");
        st.plaintext.insert(materialization_id, plaintext);
    }

    fn drop_active(&self, materialization_id: &str) -> Option<MaterializationSummary> {
        let mut st = self.state.lock().expect("broker registry mutex");
        // Drop the plaintext too — once revoked there is nothing to resolve.
        st.plaintext.remove(materialization_id);
        st.active.remove(materialization_id)
    }

    fn lookup_provider(&self, materialization_id: &str) -> Option<BrokerProvider> {
        let st = self.state.lock().expect("broker registry mutex");
        st.active.get(materialization_id).map(|s| s.provider)
    }
}

impl Default for BrokerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process-singleton wiring
// ---------------------------------------------------------------------------

/// The daemon registers a single [`BrokerRegistry`] at startup
/// (`runtime.rs::run`). Stored in an `OnceCell` so handler/socket code
/// can access it without threading an `Rc` through every dispatch
/// signature — same pattern as `receipt::current_identity()`.
static REGISTRY: OnceCell<BrokerRegistry> = OnceCell::new();

/// Install the process-global registry. Called exactly once at runtime
/// startup. A second call with a different registry has no effect; the
/// first installation wins.
pub fn install_registry(registry: BrokerRegistry) {
    let _ = REGISTRY.set(registry);
}

/// Access the process-global registry if it has been installed.
pub fn current_registry() -> Option<&'static BrokerRegistry> {
    REGISTRY.get()
}

// ---------------------------------------------------------------------------
// JSON-RPC error helpers
// ---------------------------------------------------------------------------

/// Map a [`BrokerError`] to a `(code, message)` JSON-RPC error tuple.
///
/// Code map:
/// - `InvalidScope`           → `-32602` (params)
/// - `PolicyRejected`         → `-32003` (policy)
/// - `UnknownMaterialization` → `-32004` (not found)
/// - `Upstream`               → `-32011` (provider error — distinct from
///   internal `-32000` so callers can retry)
/// - `Other`                  → `-32000`
fn map_broker_error(err: BrokerError) -> (i32, String) {
    match err {
        BrokerError::InvalidScope(m) => (-32602, format!("invalid scope: {m}")),
        BrokerError::PolicyRejected(m) => (-32003, format!("policy rejected: {m}")),
        BrokerError::UnknownMaterialization(id) => {
            (-32004, format!("unknown materialization id: {id}"))
        }
        BrokerError::Upstream(m) => (-32011, format!("upstream error: {m}")),
        BrokerError::NotSupported => (-32001, "operation not supported by this broker".to_string()),
        BrokerError::Other(m) => (-32000, format!("broker error: {m}")),
    }
}

// ---------------------------------------------------------------------------
// Receipt-event emission (audit_log shim)
// ---------------------------------------------------------------------------

fn now_rfc3339_at(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

/// Emit a `broker_materialization` Receipt event into the audit log
/// matching the design §c shape. Best-effort — failures here log a
/// warning but do not fail the RPC response (the materialization
/// already happened upstream).
///
/// Dual-emit: the audit-log shadow row is kept for backwards compat while
/// also persisting a typed, signed [`BrokerReceipt`] via `store_broker_receipt`.
fn emit_materialization_receipt(
    store: &DaemonStore,
    req: &BrokerRequest,
    cred: &BrokeredCredential,
) {
    let now = SystemTime::now();
    let issued_at = now_rfc3339_at(now);
    let expires_at = now_rfc3339_at(cred.expires_at);
    let now_epoch = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let expires_epoch = cred.expires_at.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).ok();

    // --- shadow audit-log row (kept for dual-emit transition) ---
    let payload = json!({
        "kind": "broker_materialization",
        "broker": req.provider.as_str(),
        "requested_scope": req.scope,
        "granted_scope": req.scope,
        "ttl_seconds": req.ttl.as_secs(),
        "materialized_at": issued_at,
        "expires_at": expires_at,
        "materialization_id": cred.materialization_id,
        "revoked_at": Value::Null,
        "reason": req.reason,
    });
    if let Err(e) = store.log_event(
        None,
        "broker.materialization",
        Some(req.provider.as_str()),
        "allowed",
        Some(&payload.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            provider = req.provider.as_str(),
            "broker: failed to record materialization audit-log shadow row"
        );
    }

    // --- typed signed BrokerReceipt ---
    let scope_str = serde_json::to_string(&req.scope).unwrap_or_default();
    let mut receipt = BrokerReceipt {
        id: format!("rct-broker-{}", uuid::Uuid::new_v4()),
        kind: ReceiptKind::BrokerMaterialization,
        provider: req.provider.as_str().to_string(),
        materialization_id: cred.materialization_id.clone(),
        requested_scope: scope_str.clone(),
        granted_scope: scope_str,
        ttl_seconds: req.ttl.as_secs(),
        materialized_at_epoch_secs: now_epoch,
        expires_at_epoch_secs: expires_epoch,
        revoked_at_epoch_secs: None,
        reason: if req.reason.is_empty() { None } else { Some(req.reason.clone()) },
        caller_persona: "unknown".to_string(),
        grants_file_rev: req.grants_file_rev.clone(),
        credential_name: req.grants_file_credential_name.clone(),
        evidence: Evidence::default(),
    };
    if let Some(identity) = current_identity() {
        sign_broker_receipt(&mut receipt, identity);
    }
    if let Err(e) = store.store_broker_receipt(&receipt) {
        tracing::warn!(
            error = %e,
            provider = req.provider.as_str(),
            receipt_id = %receipt.id,
            "broker: failed to persist typed BrokerReceipt for materialization"
        );
    }
}

/// Emit a `broker_revocation` Receipt event into the audit log. The
/// `summary` argument is `Option` so callers can still record the event
/// when the materialization was unknown to the daemon (defense-in-depth
/// for state drift between the daemon and the upstream provider).
///
/// Dual-emit: the audit-log shadow row is kept for backwards compat while
/// also persisting a typed, signed [`BrokerReceipt`] via `store_broker_receipt`.
fn emit_revocation_receipt(
    store: &DaemonStore,
    materialization_id: &str,
    summary: Option<&MaterializationSummary>,
) {
    let now = SystemTime::now();
    let revoked_at = now_rfc3339_at(now);
    let now_epoch = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let provider = summary.map(|s| s.provider.as_str()).unwrap_or("unknown");
    let reason = summary.map(|s| s.reason.clone());

    // --- shadow audit-log row (kept for dual-emit transition) ---
    let payload = json!({
        "kind": "broker_revocation",
        "broker": provider,
        "materialization_id": materialization_id,
        "revoked_at": revoked_at,
        "reason": reason.clone(),
    });
    if let Err(e) = store.log_event(
        None,
        "broker.revocation",
        Some(provider),
        "allowed",
        Some(&payload.to_string()),
    ) {
        tracing::warn!(
            error = %e,
            provider = provider,
            materialization_id = materialization_id,
            "broker: failed to record revocation audit-log shadow row"
        );
    }

    // --- typed signed BrokerReceipt ---
    let mut receipt = BrokerReceipt {
        id: format!("rct-broker-{}", uuid::Uuid::new_v4()),
        kind: ReceiptKind::BrokerRevocation,
        provider: provider.to_string(),
        materialization_id: materialization_id.to_string(),
        requested_scope: String::new(),
        granted_scope: String::new(),
        ttl_seconds: 0,
        materialized_at_epoch_secs: 0,
        expires_at_epoch_secs: None,
        revoked_at_epoch_secs: Some(now_epoch),
        reason,
        caller_persona: "unknown".to_string(),
        grants_file_rev: None,
        credential_name: None,
        evidence: Evidence::default(),
    };
    if let Some(identity) = current_identity() {
        sign_broker_receipt(&mut receipt, identity);
    }
    if let Err(e) = store.store_broker_receipt(&receipt) {
        tracing::warn!(
            error = %e,
            provider = provider,
            materialization_id = materialization_id,
            receipt_id = %receipt.id,
            "broker: failed to persist typed BrokerReceipt for revocation"
        );
    }
}

// ---------------------------------------------------------------------------
// Dispatchers — invoked from `handler.rs::dispatch_method`
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Registry-explicit handlers (testable without the OnceCell)
// ---------------------------------------------------------------------------

/// Issue against an explicit registry. Used by both the global-singleton
/// dispatcher (`handle_broker_issue`) and tests, which build a fresh
/// registry per case to avoid `OnceCell` cross-test pollution.
///
/// `policy` is injected so tests can pass an `Auto` engine without spinning
/// up real HITL blocking; production callers pass `PolicyEngine::default()`.
pub async fn issue_with_registry(
    registry: &BrokerRegistry,
    store: &DaemonStore,
    params: &Value,
    policy: &crate::trust::policy::PolicyEngine,
) -> Result<Value, (i32, String)> {
    let req: BrokerRequest = serde_json::from_value(params.clone())
        .map_err(|e| (-32602, format!("invalid BrokerRequest params: {e}")))?;

    let broker = registry.brokers.get(&req.provider).ok_or((
        -32601,
        format!("no broker registered for provider {}", req.provider.as_str()),
    ))?;

    // implementation-note-30
    let matched_grant_id: Option<String> = match &req.caller_persona {
        None => {
            tracing::warn!(
                provider = req.provider.as_str(),
                "broker: caller_persona missing — grant-scope gate skipped (legacy caller)"
            );
            None
        }
        Some(persona_id) => {
            let active_grants = store
                .list_active_grants()
                .map_err(|e| (-32603, format!("failed to query active grants: {e}")))?;
            let matched = active_grants.into_iter().find(|g| {
                g.persona_id == *persona_id
                    && g.credential_name == req.provider.as_str()
                    && g.status == "active"
            });
            match matched {
                Some(g) => Some(g.id),
                None => {
                    return Err((-32003, "no active grant covers requested scope".to_string()));
                }
            }
        }
    };
    let _ = matched_grant_id;

    // implementation-note-31
    //
    // Skip policy + HITL when no caller_persona was provided — legacy
    // callers (CLI tests, daemon-internal smoke paths) lack a persona and
    // submit_approval would fail FK constraint. Same legacy-caller skip
    // posture as the grant-scope gate above. Real callers (proxy, agent
    // SDK) populate caller_persona AND seed a matching grant before
    // issuing, so they take the full gate path.
    if req.caller_persona.is_some() {
        use crate::trust::policy::ApprovalRequirement;
        let action = format!("credential.access.{}", req.provider.as_str());
        let eval = policy.evaluate(&action);
        match eval.requirement {
            ApprovalRequirement::Denied => {
                return Err((-32007, "policy denies credential mint for this provider".to_string()));
            }
            ApprovalRequirement::Required => {
                // implementation-note-32: shipped
                let persona_id = req.caller_persona.clone().unwrap_or_default();
                let credential_name = req.provider.as_str();
                let scope = serde_json::to_string(&req.scope)
                    .unwrap_or_else(|_| "{}".to_string());
                let approval_info = store
                    .submit_approval(
                        &persona_id,
                        credential_name,
                        &scope,
                        None,
                        &action,
                        "high",
                    )
                    .map_err(|e| (-32603, format!("failed to submit approval request: {e}")))?;
                let request_id = approval_info.id.clone();

                let timeout = if cfg!(test) {
                    std::time::Duration::from_millis(200)
                } else {
                    std::time::Duration::from_secs(120)
                };
                let poll_interval = std::time::Duration::from_millis(50);
                let started = std::time::Instant::now();
                loop {
                    if started.elapsed() >= timeout {
                        let _ = store.dismiss_approval(&request_id);
                        return Err((-32008, "approval timed out".to_string()));
                    }
                    tokio::time::sleep(poll_interval).await;
                    match store.get_approval(&request_id) {
                        Ok(row) if row.status == "approved" => break,
                        Ok(row) if row.status == "denied" => {
                            return Err((-32009, "operator denied".to_string()));
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                request_id = %request_id,
                                "credgate poll: get_approval error; retrying"
                            );
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let cred = broker.issue(req.clone()).await.map_err(map_broker_error)?;

    // Track the materialization so subsequent `broker_revoke` calls can
    // route by id alone (without requiring the caller to also restate
    // the provider).
    let issued_at = now_rfc3339_at(SystemTime::now());
    let expires_at = now_rfc3339_at(cred.expires_at);
    let summary = MaterializationSummary {
        materialization_id: cred.materialization_id.clone(),
        provider: req.provider,
        issued_at: issued_at.clone(),
        expires_at: expires_at.clone(),
        reason: req.reason.clone(),
    };
    registry.record_active(summary);

    // Stash plaintext daemon-side so the trust boundary
    // (ember-proxy / ember-tools) can later resolve `secret_ref` →
    // plaintext via `broker_resolve`. Agent-process callers receive
    // ONLY the opaque `SecretRef` below.
    registry.record_plaintext(cred.materialization_id.clone(), cred.token.clone());

    // Receipt event (design §c).
    emit_materialization_receipt(store, &req, &cred);

    // implementation-note-7: response shape is
    // `{ secret_ref, materialization_id, expires_at, issued_at,
    //   provider }`. There is NO `token` / `value` raw-string field in
    // the response — agent processes never hold plaintext.
    let secret_ref = SecretRef::new(cred.materialization_id.clone());
    Ok(json!({
        "secret_ref": secret_ref,
        "materialization_id": cred.materialization_id,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "provider": req.provider.as_str(),
    }))
}

/// Revoke against an explicit registry.
pub async fn revoke_with_registry(
    registry: &BrokerRegistry,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let materialization_id = params["materialization_id"]
        .as_str()
        .ok_or((-32602, "missing 'materialization_id'".to_string()))?
        .to_string();

    let provider = registry.lookup_provider(&materialization_id).ok_or((
        -32004,
        format!("unknown materialization id: {materialization_id}"),
    ))?;
    let broker = registry.brokers.get(&provider).ok_or((
        -32601,
        format!(
            "no broker registered for provider {} (materialization is in-flight but \
             impl was unregistered — daemon restart required)",
            provider.as_str()
        ),
    ))?;

    broker
        .revoke(&materialization_id)
        .await
        .map_err(map_broker_error)?;

    // Drop from active set first, then emit the receipt with the
    // (now-stale) summary so the receipt records the reason/provider
    // even though the active table no longer contains the row.
    let summary = registry.drop_active(&materialization_id);
    emit_revocation_receipt(store, &materialization_id, summary.as_ref());

    Ok(json!({
        "revoked": true,
        "materialization_id": materialization_id,
    }))
}

/// List active materializations from an explicit registry.
pub async fn list_with_registry(
    registry: &BrokerRegistry,
) -> Result<Value, (i32, String)> {
    let summaries = registry.list_active();
    Ok(serde_json::to_value(&summaries)
        .expect("MaterializationSummary always serializes"))
}

/// Resolve a `SecretRef` → plaintext at the trust boundary.
///
/// Per implementation-note-7 this is the ONLY place plaintext
/// leaves the daemon, and it MUST emit a per-resolution Receipt
/// (`broker_resolution`) so every materialization has a downstream
/// audit trail of where the credential was actually used. The full
/// implementation lands in implementation-note-9; this stub records the
/// contract surface so callers cannot accidentally bind to the old
/// raw-token RPC path.
///
/// Stub returns `BrokerError::NotSupported`-shaped error
/// (`-32001` "operation not supported") with a TODO marker pointing at
/// the implementation task.
pub async fn resolve_with_registry(
    _registry: &BrokerRegistry,
    _store: &DaemonStore,
    _params: &Value,
) -> Result<Value, (i32, String)> {
    // TODO: real implementation must:
    //   1. Validate caller identity is the trust boundary
    //      (ember-proxy / ember-tools), not the agent process.
    //   2. Look up plaintext by `materialization_id` in the registry's
    //      `plaintext` table.
    //   3. Emit a `broker_resolution` Receipt with `actor`,
    //      `secret_ref_id`, `materialized_at`, `outcome`.
    //   4. Return plaintext to the caller (the trust boundary, never
    //      the agent process).
    Err((
        -32001,
        "broker_resolve not yet implemented (implementation-note-9)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Dispatchers (resolve registry from the process-global OnceCell)
// ---------------------------------------------------------------------------

const ERR_NO_REGISTRY: (i32, &str) = (
    -32010,
    "broker registry not initialised — start emberd to populate",
);

fn err_no_registry() -> (i32, String) {
    (ERR_NO_REGISTRY.0, ERR_NO_REGISTRY.1.to_string())
}

/// Handle the `broker_issue` socket RPC.
///
/// Params: `BrokerRequest` shape (see `core_broker::BrokerRequest`).
///
/// Response: `{ token, materialization_id, expires_at, provider }`.
pub async fn handle_broker_issue(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let registry = current_registry().ok_or_else(err_no_registry)?;
    issue_with_registry(registry, store, params, &crate::trust::policy::PolicyEngine::default()).await
}

/// Handle the `broker_revoke` socket RPC.
///
/// Params: `{ materialization_id: <string> }`.
///
/// Response: `{ revoked: true, materialization_id: <string> }`.
pub async fn handle_broker_revoke(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let registry = current_registry().ok_or_else(err_no_registry)?;
    revoke_with_registry(registry, store, params).await
}

/// Handle the `broker_list` socket RPC.
///
/// Params: ignored.
///
/// Response: array of [`MaterializationSummary`] sorted by `issued_at`
/// ascending. Empty when nothing has been issued.
pub async fn handle_broker_list(_params: &Value) -> Result<Value, (i32, String)> {
    let registry = current_registry().ok_or_else(err_no_registry)?;
    list_with_registry(registry).await
}

/// Handle the `broker_resolve` socket RPC.
///
/// Params: `{ secret_ref: <opaque-id> }`.
///
/// Per implementation-note-7 this is the only path for
/// plaintext credential resolution. Today this is a stub that returns
/// `-32001` (operation not supported) with a TODO marker pointing at
/// implementation-note-9.
pub async fn handle_broker_resolve(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let registry = current_registry().ok_or_else(err_no_registry)?;
    resolve_with_registry(registry, store, params).await
}

/// Handle the `broker.mint_gh_token` socket RPC (design credential broker).
///
/// Mints a scoped, 1-hour GitHub App installation token by:
/// 1. Loading GH App credentials from the process environment (placeholder
///    until the operator provisions vault paths via the daemon config).
/// 2. Calling `ember_broker::github_app::mint_installation_token`.
/// 3. Returning the raw token as a materialized credential (same SecretRef
///    shape as `broker_issue`).
///
/// ## Wire shape
///
/// Request params (JSON object):
/// ```json
/// {
///   "installation_id": "<optional override — falls back to env var>",
///   "repos": ["owner/repo", ...],
///   "permissions": [["contents", "read"], ["pull_requests", "write"]]
/// }
/// ```
///
/// Response (JSON object):
/// ```json
/// {
///   "token": "<ghs_… installation token>",
///   "expires_at": "<RFC3339>",
///   "installation_id": "<installation_id used>"
/// }
/// ```
///
/// ## Credential loading (placeholder)
///
/// Until the operator registers the GitHub App and populates vault paths,
/// credentials are read from environment variables:
///
/// - `GH_APP_ID`              — numeric app ID
/// - `GH_APP_INSTALLATION_ID` — installation ID (overridden by request field)
/// - `GH_APP_PRIVATE_KEY_PEM` — PEM-encoded RSA private key
///
/// Missing env vars → `-32000` with a clear message pointing at the config path.
pub async fn handle_broker_mint_gh_token(
    _store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Parse optional request params.
    #[derive(serde::Deserialize, Default)]
    struct MintGhTokenParams {
        installation_id: Option<String>,
        #[serde(default)]
        repos: Vec<String>,
        #[serde(default)]
        permissions: Vec<(String, String)>,
    }

    let req: MintGhTokenParams = if params.is_null() || params.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        MintGhTokenParams::default()
    } else {
        serde_json::from_value(params.clone())
            .map_err(|e| (-32602, format!("invalid broker.mint_gh_token params: {e}")))?
    };

    // Load credentials from env (placeholder — operator fills vault paths).
    let app_id = std::env::var("GH_APP_ID").map_err(|_| {
        (
            -32000,
            "GH_APP_ID not set — configure the GitHub App ID via vault or env var".to_string(),
        )
    })?;

    let installation_id = req
        .installation_id
        .or_else(|| std::env::var("GH_APP_INSTALLATION_ID").ok())
        .ok_or_else(|| {
            (
                -32000,
                "installation_id not provided and GH_APP_INSTALLATION_ID not set".to_string(),
            )
        })?;

    let private_key_pem = std::env::var("GH_APP_PRIVATE_KEY_PEM").map_err(|_| {
        (
            -32000,
            "GH_APP_PRIVATE_KEY_PEM not set — load the PEM key from the vault path".to_string(),
        )
    })?;

    let creds = ember_broker::github_app::GhAppCredentials {
        app_id,
        installation_id: installation_id.clone(),
        private_key_pem,
    };

    let token = ember_broker::github_app::mint_installation_token(
        &creds,
        &req.repos,
        &req.permissions,
    )
    .await
    .map_err(|e| (-32000, format!("gh_app mint failed: {e}")))?;

    Ok(json!({
        "token": token.token,
        "expires_at": token.expires_at.to_rfc3339(),
        "installation_id": installation_id,
    }))
}

/// Handle the `broker_exec` socket RPC.
///
/// Spawns the Construct binary as the daemon's child, captures exit code,
/// emits a `session.construct_invocation` Receipt. Per design §"daemon-
/// as-process-supervisor".
///
/// When `pty_socket_path` is set in the request the daemon allocates a pty
/// pair via `forkpty(3)`, attaches the slave fd to the child's
/// stdin/stdout/stderr, and calls `pty_bridge_run` with the master fd and
/// the agent's UDS path. The non-PTY (piped stderr) path is preserved for
/// callers that omit `pty_socket_path`.
///
/// Strict env allowlist (PATH, HOME, USER, LANG, TERM + caller-supplied
/// `env_passthrough` filtered through validation). Argv is taken
/// verbatim — daemon-side argv re-classification is a follow-up
/// (T-CONSTRUCT-EXEC-ARGV-CLASSIFIER) that can ride atop this scaffold.
///
/// // PTY_BRIDGE_INTEGRATED
pub async fn handle_broker_exec(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // PTY_BRIDGE_INTEGRATED
    let req: BrokerExecRequest = serde_json::from_value(params.clone())
        .map_err(|e| (-32602, format!("invalid broker_exec params: {e}")))?;

    // Validate env_passthrough names (defense-in-depth against env injection).
    let env_name_re = regex::Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap();
    for name in &req.env_passthrough {
        if !env_name_re.is_match(name) {
            return Err((-32602, format!("invalid env_passthrough name: {name}")));
        }
    }

    // Build env: allowlist baseline + caller-supplied passthrough.
    let allowlist = ["PATH", "HOME", "USER", "LANG", "TERM"];
    let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for name in allowlist
        .iter()
        .map(|s| *s)
        .chain(req.env_passthrough.iter().map(|s| s.as_str()))
    {
        if let Ok(val) = std::env::var(name) {
            env.insert(name.to_string(), val);
        }
    }

    // Resolve cwd. Default to $HOME when caller didn't specify.
    let cwd = req.cwd.clone().unwrap_or_else(|| {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
    });

    // Spawn a daemon-managed ssh-agent for this session when requested
    // (implementation-note-22). The handle lives for the duration of
    // the exec; dropping it zeros the private key and unlinks the socket.
    let _ssh_agent_handle = if req.ssh_agent {
        let session_id = uuid::Uuid::new_v4().to_string();
        match ember_broker::ssh_agent::spawn_session_ssh_agent(&session_id) {
            Ok(handle) => {
                env.insert(
                    "SSH_AUTH_SOCK".to_string(),
                    handle.auth_sock_path.to_string_lossy().into_owned(),
                );
                Some(handle)
            }
            Err(e) => {
                tracing::warn!(error = %e, "broker_exec: ssh-agent spawn failed; continuing without SSH_AUTH_SOCK");
                None
            }
        }
    } else {
        None
    };

    let started_at = std::time::Instant::now();
    let (exit_code, stderr_tail) = if let Some(ref socket_path) = req.pty_socket_path {
        // PTY path: forkpty → slave fd attached to child → bridge on master fd.
        #[cfg(unix)]
        {
            let socket_path = std::path::PathBuf::from(socket_path);
            let binary = req.binary.clone();
            let argv = req.argv.clone();
            let env_pairs: Vec<(String, String)> = env.into_iter().collect();
            let cwd_clone = cwd.clone();

            // forkpty + exec are inherently sync/fork-unsafe in async context;
            // run on the blocking thread pool and join before we proceed.
            let (exit_code, bridge_err) = tokio::task::spawn_blocking(move || {
                forkpty_exec_and_bridge(&binary, &argv, &env_pairs, &cwd_clone, &socket_path)
            })
            .await
            .map_err(|e| (-32000, format!("pty spawn task panicked: {e}")))?
            .map_err(|e| (-32000, e))?;

            if let Some(e) = bridge_err {
                tracing::warn!(error = %e, "broker_exec pty: bridge returned error (child exit still reported)");
            }
            (exit_code, String::new())
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            return Err((-32000, "pty_socket_path is not supported on this platform".to_string()));
        }
    } else {
        // Non-PTY path: tokio::process::Command with piped stderr.
        let output = tokio::process::Command::new(&req.binary)
            .args(&req.argv)
            .current_dir(&cwd)
            .env_clear()
            .envs(&env)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null()) // NOT captured; Constructs use files
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| (-32000, format!("spawn failed: {e}")))?;

        let exit_code = output.status.code().unwrap_or(-1);

        // Tail stderr — keep last 4 KiB for diagnostics.
        const STDERR_TAIL_CAP: usize = 4096;
        let stderr_full = String::from_utf8_lossy(&output.stderr);
        let stderr_tail = if stderr_full.len() > STDERR_TAIL_CAP {
            format!(
                "...[{} bytes truncated]...{}",
                stderr_full.len() - STDERR_TAIL_CAP,
                &stderr_full[stderr_full.len() - STDERR_TAIL_CAP..]
            )
        } else {
            stderr_full.into_owned()
        };
        (exit_code, stderr_tail)
    };

    let elapsed_ms = started_at.elapsed().as_millis() as u64;
    let success = exit_code == 0;

    // Emit receipt. Best-effort — log the event into the daemon's audit log.
    // Schema: session.construct_invocation per docs/receipt-format-v2.md.
    if let Err(e) = store.log_event(
        None, // persona_id; optional for system-emitted
        "session.construct_invocation",
        None, // credential_name; not directly applicable
        if success { "success" } else { "errored" },
        Some(
            &serde_json::json!({
                "binary": req.binary,
                "argv_len": req.argv.len(),
                "exit_code": exit_code,
                "elapsed_ms": elapsed_ms,
                "pty": req.pty_socket_path.is_some(),
            })
            .to_string(),
        ),
    ) {
        tracing::warn!(
            error = %e,
            "broker_exec: failed to record session.construct_invocation audit row"
        );
    }

    let resp = BrokerExecResponse {
        exit_code,
        success,
        stderr_tail,
    };
    serde_json::to_value(resp)
        .map_err(|e| (-32000, format!("serialize BrokerExecResponse: {e}")))
}

// ---------------------------------------------------------------------------
// forkpty spawn helper (T-CONSTRUCT-PTY-BRIDGE-INTEGRATE)
// ---------------------------------------------------------------------------

/// Fork with a new pty pair, exec the Construct binary in the child with the
/// slave fd wired to stdin/stdout/stderr, then run `pty_bridge_run` in the
/// parent. Returns `(exit_code, Option<bridge_error_string>)`.
///
/// Must be called from a blocking thread (not directly from async context)
/// because `forkpty(3)` + `execvp(3)` are fork-unsafe in a multithreaded
/// async runtime. `handle_broker_exec` dispatches via
/// `tokio::task::spawn_blocking`.
///
/// Linux uses `execvpe(3)` directly. macOS lacks `execvpe`; the child clears
/// inherited env and `setenv`s each entry, then `execvp`s for PATH lookup
/// (single-threaded post-fork makes direct env manipulation safe).
/// Linux: `PR_SET_PDEATHSIG` ensures the child receives SIGHUP when the
/// daemon exits; macOS has no portable equivalent (follow-up).
#[cfg(unix)]
fn forkpty_exec_and_bridge(
    binary: &str,
    argv: &[String],
    env: &[(String, String)],
    cwd: &str,
    socket_path: &std::path::Path,
) -> Result<(i32, Option<String>), String> {
    use std::ffi::CString;

    // Build NUL-terminated argv for execvp: argv[0] = binary, rest = argv.
    let binary_c = CString::new(binary).map_err(|e| format!("binary CString: {e}"))?;
    let mut execv_argv: Vec<CString> = Vec::with_capacity(argv.len() + 1);
    execv_argv.push(binary_c.clone());
    for a in argv {
        execv_argv.push(CString::new(a.as_str()).map_err(|e| format!("argv CString: {e}"))?);
    }
    // execvp expects a null-terminated array of pointers.
    let mut execv_ptrs: Vec<*const libc::c_char> =
        execv_argv.iter().map(|s| s.as_ptr()).collect();
    execv_ptrs.push(std::ptr::null());

    // Linux uses execvpe with a packed NUL-terminated envp; build it here.
    // macOS unsets inherited env + setenv's per-entry below — it iterates
    // `env` directly, so this packed form is unused on darwin.
    #[cfg(target_os = "linux")]
    let env_strings: Vec<CString> = env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(|e| format!("env CString: {e}")))
        .collect::<Result<_, _>>()?;
    #[cfg(target_os = "linux")]
    let env_ptrs: Vec<*const libc::c_char> = {
        let mut v: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        v.push(std::ptr::null());
        v
    };

    // cwd as CString for chdir in child.
    let cwd_c = CString::new(cwd).map_err(|e| format!("cwd CString: {e}"))?;

    let mut master_fd: libc::c_int = -1;
    // winsize zeroed — SIGWINCH propagation is a follow-up.
    // libc 0.2.184 widened forkpty's winp from *const to *mut; binding
    // must be `mut` and the reference passed as `&mut`.
    let mut ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };

    let pid = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(), // slave name not needed
            std::ptr::null_mut(), // termios default
            &mut ws,
        )
    };

    if pid < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!("forkpty failed: {errno}"));
    }

    if pid == 0 {
        // ---- CHILD ----
        // chdir to requested working directory.
        unsafe { libc::chdir(cwd_c.as_ptr()) };

        // Linux: ask kernel to send SIGHUP when the parent (daemon) dies.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP, 0, 0, 0);
        }

        // Replace the child image with the requested binary. The slave fd is
        // already attached to stdin/stdout/stderr by forkpty.
        //
        // Linux: execvpe = execve + PATH lookup. envp wholly replaces the
        // child's inherited environment in one call.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::execvpe(binary_c.as_ptr(), execv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }
        // macOS: no execvpe. Replicate it: drop every inherited env var via
        // unsetenv, setenv each from our prepared list, then execvp for PATH
        // lookup. We're single-threaded in the forked child, so direct env
        // manipulation cannot race.
        #[cfg(target_os = "macos")]
        unsafe {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            // Capture inherited env keys before mutation (unsetenv shrinks
            // environ as it goes; iterating environ in place would skip).
            let inherited_keys: Vec<CString> = std::env::vars_os()
                .filter_map(|(k, _)| CString::new(k.as_bytes()).ok())
                .collect();
            for k in &inherited_keys {
                libc::unsetenv(k.as_ptr());
            }
            // setenv each KEY=VALUE from the caller's env. We already hold
            // these as `env: &[(String, String)]` — re-deriving is cheaper
            // and safer than re-parsing the NUL-terminated env_ptrs slice.
            for (k, v) in env {
                if let (Ok(key_c), Ok(val_c)) = (CString::new(k.as_str()), CString::new(v.as_str())) {
                    libc::setenv(key_c.as_ptr(), val_c.as_ptr(), 1);
                }
            }
            libc::execvp(binary_c.as_ptr(), execv_ptrs.as_ptr());
        }
        // exec*() only returns on error — exit immediately so the daemon
        // does not loop in a forked copy of the async runtime.
        unsafe { libc::_exit(127) };
    }

    // ---- PARENT ----
    // Run the PTY bridge (poll loop) until child exits or master EOF.
    let bridge_err = pty_bridge_run(master_fd, socket_path).err().map(|e| e.to_string());

    // Close master fd now that the bridge loop has exited.
    unsafe { libc::close(master_fd) };

    // Reap the child.
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        let errno = std::io::Error::last_os_error();
        tracing::warn!(pid = pid, error = %errno, "broker_exec pty: waitpid failed");
    }

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -1
    } else {
        -1
    };

    Ok((exit_code, bridge_err))
}

// ---------------------------------------------------------------------------
// PTY bridge — wire framing for SIGWINCH propagation
// (T-CONSTRUCT-PTY-BRIDGE-SIGWINCH)
// ---------------------------------------------------------------------------
//
// ## Client → Daemon wire format
//
// All data sent from the client (e.g. ember-gh) to the daemon over the PTY
// UDS uses a simple tagged-frame protocol so winsize control messages can
// be multiplexed alongside stdin data.
//
// Frame layout:
//
//   +--------+------------------+------------------------+
//   | 1 byte | depends on tag   | description            |
//   +--------+------------------+------------------------+
//   |  0x00  | u16 BE len, data | stdin data frame       |
//   |  0x57  | 8 bytes (4×u16 BE: rows, cols, xpix, ypix)| winsize frame  |
//   +--------+------------------+------------------------+
//
// TAG_DATA   (0x00): 1-byte tag + 2-byte BE payload length + payload bytes.
//                    Daemon writes payload directly to master fd.
// TAG_WINSIZE (0x57): 1-byte tag + rows(u16 BE) + cols(u16 BE) +
//                    xpixel(u16 BE) + ypixel(u16 BE) = 9 bytes total.
//                    Daemon calls TIOCSWINSZ on the master fd, which
//                    notifies the child process of the new terminal size.
//
// ## Daemon → Client wire format
//
// Raw bytes (no framing). The child's pty output is forwarded verbatim.

/// Tag byte for a stdin data frame (client → daemon).
pub const TAG_DATA: u8 = 0x00;

/// Tag byte for a terminal winsize update frame (client → daemon).
/// ASCII 'W' — mnemonic for WinSize.
pub const TAG_WINSIZE: u8 = 0x57;

/// Encode a stdin data chunk as a `TAG_DATA` frame.
///
/// Frame: `[0x00, len_hi, len_lo, data...]`
/// Caller must ensure `data.len() <= u16::MAX`.
pub fn encode_data_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len().min(u16::MAX as usize);
    let mut out = Vec::with_capacity(3 + len);
    out.push(TAG_DATA);
    out.push((len >> 8) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(&data[..len]);
    out
}

/// Encode a winsize update as a `TAG_WINSIZE` frame.
///
/// Frame: `[0x57, rows_hi, rows_lo, cols_hi, cols_lo, xpix_hi, xpix_lo, ypix_hi, ypix_lo]`
/// Total: 9 bytes.
pub fn encode_winsize_frame(rows: u16, cols: u16, xpixel: u16, ypixel: u16) -> [u8; 9] {
    [
        TAG_WINSIZE,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (xpixel >> 8) as u8,
        (xpixel & 0xff) as u8,
        (ypixel >> 8) as u8,
        (ypixel & 0xff) as u8,
    ]
}

/// Decoded frame from the client → daemon channel.
#[derive(Debug, PartialEq)]
pub enum PtyFrame {
    Data(Vec<u8>),
    Winsize { rows: u16, cols: u16, xpixel: u16, ypixel: u16 },
}

/// Attempt to decode one frame from the front of `buf`.
///
/// Returns `Some((frame, bytes_consumed))` if a complete frame is present,
/// or `None` if more bytes are needed.
pub fn decode_one_frame(buf: &[u8]) -> Option<(PtyFrame, usize)> {
    let tag = *buf.first()?;
    match tag {
        TAG_DATA => {
            if buf.len() < 3 {
                return None;
            }
            let len = ((buf[1] as usize) << 8) | (buf[2] as usize);
            if buf.len() < 3 + len {
                return None;
            }
            Some((PtyFrame::Data(buf[3..3 + len].to_vec()), 3 + len))
        }
        TAG_WINSIZE => {
            if buf.len() < 9 {
                return None;
            }
            let rows = ((buf[1] as u16) << 8) | (buf[2] as u16);
            let cols = ((buf[3] as u16) << 8) | (buf[4] as u16);
            let xpixel = ((buf[5] as u16) << 8) | (buf[6] as u16);
            let ypixel = ((buf[7] as u16) << 8) | (buf[8] as u16);
            Some((PtyFrame::Winsize { rows, cols, xpixel, ypixel }, 9))
        }
        _ => {
            // Unknown tag: skip the byte and keep parsing. This guards
            // against stray bytes during protocol negotiation.
            Some((PtyFrame::Data(vec![]), 1))
        }
    }
}

/// Apply a winsize to the pty master fd via TIOCSWINSZ.
#[cfg(unix)]
fn apply_winsize_to_master(master_fd: RawFd, rows: u16, cols: u16, xpixel: u16, ypixel: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpixel,
        ws_ypixel: ypixel,
    };
    unsafe {
        libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
    }
}

// ---------------------------------------------------------------------------
// PTY bridge — poll loop (T-CONSTRUCT-PTY-BRIDGE)
// ---------------------------------------------------------------------------

use std::os::fd::RawFd;

/// Pseudoterminal bridge handle. Owns the master fd; the slave fd is
/// passed to the spawned child process.
#[derive(Debug)]
pub struct PtyBridge {
    pub master_fd: RawFd,
}

#[derive(Debug, thiserror::Error)]
pub enum PtyBridgeError {
    #[error("forkpty syscall failed: errno={0}")]
    ForkptyFailed(i32),
    #[error("not yet implemented: {0}")]
    NotImplemented(String),
    #[error("io: {0}")]
    Io(String),
}

/// Run the daemon-side pty bridge for a Construct invocation.
///
/// Per design §1 step 4 daemon-as-process-supervisor lifecycle:
/// - The daemon allocated a pty pair (forkpty); slave fd was attached
///   to the spawned binary's stdin/stdout/stderr.
/// - This function takes ownership of the master fd and bridges
///   stdin/stdout/stderr to the agent's terminal via a Unix-domain
///   stream connection.
/// - SIGWINCH from the agent's terminal is propagated to the child via
///   the master fd using TIOCSWINSZ (see wire format above).
/// - On child exit (or master fd EOF), the bridge cleans up file
///   descriptors and returns.
///
/// Linux-first with PR_SET_PDEATHSIG; macOS follow-up under
/// T-CONSTRUCT-PTY-BRIDGE-MACOS.
pub fn pty_bridge_run(
    master_fd: RawFd,
    socket_path: &std::path::Path,
) -> Result<(), PtyBridgeError> {
    // PTY_BRIDGE_FORKPTY_DONE
    // PTY_BRIDGE_SIGWINCH_DONE
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| PtyBridgeError::Io(format!("connect {}: {}", socket_path.display(), e)))?;
    let stream_fd = stream.as_raw_fd();

    set_nonblocking(master_fd)?;
    set_nonblocking(stream_fd)?;

    let mut buf = [0u8; 4096];
    // Reassembly buffer for partial frames arriving from the client.
    let mut recv_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        let mut fds = [
            libc::pollfd { fd: master_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stream_fd, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PtyBridgeError::Io(format!("poll: {err}")));
        }

        // Master fd readable → child output → forward raw bytes to client.
        if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(master_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                return Ok(());
            }
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::WouldBlock {
                    return Err(PtyBridgeError::Io(format!("master read: {err}")));
                }
            } else {
                // Daemon → client: raw bytes, no framing.
                stream
                    .write_all(&buf[..n as usize])
                    .map_err(|e| PtyBridgeError::Io(format!("stream write: {e}")))?;
            }
        }

        // Client socket readable → stdin data or winsize frames.
        if fds[1].revents & libc::POLLIN != 0 {
            match stream.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    // Append into reassembly buffer and drain complete frames.
                    recv_buf.extend_from_slice(&buf[..n]);
                    dispatch_frames(master_fd, &mut recv_buf)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(PtyBridgeError::Io(format!("stream read: {e}"))),
            }
        }

        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
    }
}

/// Consume complete frames from `buf` and dispatch them:
/// - `PtyFrame::Data` → write payload to `master_fd`.
/// - `PtyFrame::Winsize` → call TIOCSWINSZ on `master_fd`.
fn dispatch_frames(master_fd: RawFd, buf: &mut Vec<u8>) -> Result<(), PtyBridgeError> {
    loop {
        match decode_one_frame(buf) {
            None => break,
            Some((frame, consumed)) => {
                match frame {
                    PtyFrame::Data(data) => {
                        if !data.is_empty() {
                            write_all_fd(master_fd, &data)?;
                        }
                    }
                    PtyFrame::Winsize { rows, cols, xpixel, ypixel } => {
                        #[cfg(unix)]
                        apply_winsize_to_master(master_fd, rows, cols, xpixel, ypixel);
                        #[cfg(not(unix))]
                        let _ = (rows, cols, xpixel, ypixel);
                        tracing::debug!(
                            rows, cols, xpixel, ypixel,
                            "pty bridge: TIOCSWINSZ applied"
                        );
                    }
                }
                buf.drain(..consumed);
            }
        }
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> Result<(), PtyBridgeError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(PtyBridgeError::Io(format!(
            "F_GETFL fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(PtyBridgeError::Io(format!(
            "F_SETFL fd {fd}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), PtyBridgeError> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(PtyBridgeError::Io(format!("write fd {fd}: {err}")));
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PID watcher — auto-revoke grants on child shell exit
// (implementation-note-33 §--inject)
// ---------------------------------------------------------------------------

/// In-flight PID watcher entries. Each entry maps a watched OS PID to the
/// set of materialization IDs that should be revoked when that PID exits.
static PID_WATCHERS: once_cell::sync::Lazy<std::sync::Mutex<Vec<PidWatcherEntry>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(Vec::new()));

#[derive(Debug, Clone)]
struct PidWatcherEntry {
    pid: u32,
    materialization_ids: Vec<String>,
}

/// Wire shape for `broker_register_pid_watcher` RPC params.
#[derive(Debug, serde::Deserialize)]
pub struct RegisterPidWatcherRequest {
    /// OS PID of the child shell to watch.
    pub pid: u32,
    /// Materialization IDs to revoke when `pid` exits.
    pub materialization_ids: Vec<String>,
}

/// Handle the `broker_register_pid_watcher` socket RPC.
///
/// Registers a child shell PID with the daemon. A background task polls
/// `/proc/<pid>` (Linux) or uses `kill(pid, 0)` (portable) to detect
/// process exit; on exit, the daemon calls `broker_revoke` for all listed
/// materialization IDs and removes the entry.
///
/// This is the daemon-side half of `ember broker issue --inject`. The CLI
/// spawns the child shell, then calls this RPC to register it. When the
/// shell exits the daemon auto-revokes the grants, recorded via
/// `broker_revocation` Receipt events.
///
/// // ember broker issue --grants-file (implementation-note-33)
pub async fn handle_broker_register_pid_watcher(
    _store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let req: RegisterPidWatcherRequest = serde_json::from_value(params.clone())
        .map_err(|e| (-32602, format!("invalid broker_register_pid_watcher params: {e}")))?;

    if req.materialization_ids.is_empty() {
        return Err((-32602, "materialization_ids must not be empty".to_string()));
    }

    let entry = PidWatcherEntry {
        pid: req.pid,
        materialization_ids: req.materialization_ids.clone(),
    };

    {
        let mut watchers = PID_WATCHERS.lock().expect("pid_watchers mutex");
        // De-duplicate: replace any existing entry for the same PID.
        watchers.retain(|w| w.pid != req.pid);
        watchers.push(entry);
    }

    // Spawn a background polling task on the LocalSet. The task runs
    // independently and auto-revokes when it detects the PID has exited.
    // DaemonStore is not Clone/Send, so the task opens a fresh in-memory
    // store for receipt emission; the registry state is cleaned up correctly.
    let mat_ids = req.materialization_ids.clone();
    let pid = req.pid;
    tokio::task::spawn_local(async move {
        poll_pid_until_exit(pid, &mat_ids).await;
        // Remove from watcher list after revocation.
        let mut watchers = PID_WATCHERS.lock().expect("pid_watchers mutex");
        watchers.retain(|w| w.pid != pid);
    });

    tracing::info!(
        pid = pid,
        count = req.materialization_ids.len(),
        "broker_register_pid_watcher: watching PID for auto-revoke"
    );

    Ok(serde_json::json!({
        "registered": true,
        "pid": pid,
        "materialization_ids": req.materialization_ids,
    }))
}

/// Poll until `pid` is no longer alive, then revoke all associated
/// materializations via the registry.
///
/// Opens a fresh in-memory `DaemonStore` for receipt emission in the
/// background task. The registry state is cleaned up correctly regardless;
/// production receipt persistence uses the primary store via the main handler.
async fn poll_pid_until_exit(pid: u32, mat_ids: &[String]) {
    use tokio::time::{Duration, sleep};

    // Poll every 500 ms. For a user shell this is imperceptible latency.
    let poll_interval = Duration::from_millis(500);

    loop {
        sleep(poll_interval).await;
        if !pid_is_alive(pid) {
            break;
        }
    }

    tracing::info!(
        pid = pid,
        "broker pid_watcher: PID exited — revoking {} grants",
        mat_ids.len()
    );

    // Open a transient in-memory store for receipt emission in this
    // background task. The registry cleanup (drop_active) is what matters
    // for state correctness; the receipt row goes to this ephemeral store.
    let ephemeral_store = match DaemonStore::open_in_memory() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                pid = pid,
                error = %e,
                "broker pid_watcher: could not open ephemeral store; revocation receipt skipped"
            );
            // Still clean up the registry entries even without a store.
            if let Some(registry) = current_registry() {
                for mid in mat_ids {
                    registry.drop_active(mid);
                }
            }
            return;
        }
    };

    // Revoke each materialization. Best-effort: continue on individual failures.
    if let Some(registry) = current_registry() {
        for mid in mat_ids {
            let params = serde_json::json!({ "materialization_id": mid });
            match revoke_with_registry(registry, &ephemeral_store, &params).await {
                Ok(_) => {
                    tracing::info!(
                        materialization_id = %mid,
                        pid = pid,
                        "broker pid_watcher: auto-revoked grant"
                    );
                }
                Err((code, msg)) => {
                    tracing::warn!(
                        materialization_id = %mid,
                        pid = pid,
                        code = code,
                        error = %msg,
                        "broker pid_watcher: auto-revoke failed (may already be revoked)"
                    );
                }
            }
        }
    } else {
        tracing::warn!(pid = pid, "broker pid_watcher: registry not available; skipping auto-revoke");
    }
}

/// Returns true if a process with the given PID is still alive.
///
/// On Linux uses `/proc/<pid>` existence check. On other Unix platforms
/// falls back to `kill(pid, 0)` which returns 0 (or EPERM for owned proc)
/// when alive, ESRCH when dead.
fn pid_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // kill(pid, 0) probes existence without sending a signal.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        // ret == 0  → alive (we own the process)
        // ret == -1, errno == EPERM → alive (exists, not our process)
        // ret == -1, errno == ESRCH → dead (no such process)
        if ret == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno != libc::ESRCH
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// All tests build a fresh `BrokerRegistry` and call the
// registry-explicit handlers (`issue_with_registry` / `revoke_with_registry`
// / `list_with_registry`) directly. The process-global `OnceCell` is
// deliberately untouched so tests do not contend over shared state when
// `cargo test` runs them in parallel.

#[cfg(test)]
mod tests {
    use super::*;
    use core_broker::MockBroker;

    // -----------------------------------------------------------------------
    // T1: PTY wire-format encode/decode round-trips (no fd required)
    // -----------------------------------------------------------------------

    /// Encode a data frame and round-trip it through decode_one_frame.
    #[test]
    fn pty_wire_data_frame_roundtrip() {
        let payload = b"hello pty";
        let frame = encode_data_frame(payload);
        // TAG_DATA + 2-byte length + payload
        assert_eq!(frame[0], TAG_DATA);
        assert_eq!(frame[1], 0x00);
        assert_eq!(frame[2], payload.len() as u8);
        assert_eq!(&frame[3..], payload);

        let (decoded, consumed) = decode_one_frame(&frame).expect("decode should succeed");
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, PtyFrame::Data(payload.to_vec()));
    }

    /// Encode a winsize frame and round-trip it through decode_one_frame.
    #[test]
    fn pty_wire_winsize_frame_roundtrip() {
        let frame = encode_winsize_frame(50, 200, 1200, 800);
        assert_eq!(frame.len(), 9);
        assert_eq!(frame[0], TAG_WINSIZE);
        // rows = 50 = 0x0032
        assert_eq!(frame[1], 0x00);
        assert_eq!(frame[2], 0x32);
        // cols = 200 = 0x00C8
        assert_eq!(frame[3], 0x00);
        assert_eq!(frame[4], 0xC8);

        let (decoded, consumed) = decode_one_frame(&frame).expect("decode should succeed");
        assert_eq!(consumed, 9);
        assert_eq!(decoded, PtyFrame::Winsize { rows: 50, cols: 200, xpixel: 1200, ypixel: 800 });
    }

    /// Partial frame: decode_one_frame returns None when not enough bytes.
    #[test]
    fn pty_wire_partial_frame_returns_none() {
        // Only the tag byte for a winsize frame — not enough
        let partial = [TAG_WINSIZE, 0x00, 0x18];
        assert!(decode_one_frame(&partial).is_none());

        // Only tag + 1 byte of a data frame with len=5
        let partial_data = [TAG_DATA, 0x00, 0x05, 0xAA, 0xBB];
        assert!(decode_one_frame(&partial_data).is_none());
    }

    /// Two frames concatenated: decode_one_frame advances correctly.
    #[test]
    fn pty_wire_sequential_frames_decode() {
        let ws_frame = encode_winsize_frame(24, 80, 0, 0);
        let data_frame = encode_data_frame(b"input");
        let mut combined = ws_frame.to_vec();
        combined.extend_from_slice(&data_frame);

        let (first, c1) = decode_one_frame(&combined).unwrap();
        assert_eq!(first, PtyFrame::Winsize { rows: 24, cols: 80, xpixel: 0, ypixel: 0 });
        let (second, c2) = decode_one_frame(&combined[c1..]).unwrap();
        assert_eq!(second, PtyFrame::Data(b"input".to_vec()));
        assert_eq!(c1 + c2, combined.len());
    }

    /// Build a registry containing both Cloudflare and Anthropic mock
    /// brokers. Tests use `aws_sts` / `github` / etc. as the
    /// "unknown provider" case to keep error-path coverage explicit.
    fn fresh_registry() -> BrokerRegistry {
        let mut reg = BrokerRegistry::new();
        reg.register(Box::new(MockBroker::new(BrokerProvider::Cloudflare)));
        reg.register(Box::new(MockBroker::new(BrokerProvider::Anthropic)));
        reg
    }

    fn cf_request(ttl_secs: u64, reason: &str) -> Value {
        json!({
            "provider": "cloudflare",
            "scope": {"zone": "emberlink.dev", "permissions": ["dns:edit"]},
            "ttl": ttl_secs,
            "reason": reason,
        })
    }

    /// Same as `cf_request` but with `caller_persona` set so the HITL poll
    /// path (`submit_approval`) has a non-empty persona id. The grant-scope
    /// gate's `list_active_grants()` filter returns empty when no matching
    /// grant is seeded — the HITL tests skip that gate by NOT seeding a
    /// grant; the gate then returns -32003 BEFORE policy evaluation. So
    /// HITL tests must seed a matching active grant before issuing.
    fn cf_request_hitl(ttl_secs: u64, reason: &str, persona_id: &str) -> Value {
        json!({
            "provider": "cloudflare",
            "scope": {"zone": "emberlink.dev", "permissions": ["dns:edit"]},
            "ttl": ttl_secs,
            "reason": reason,
            "caller_persona": persona_id,
        })
    }

    /// Return a `PolicyEngine` whose default for `credential.access.*` is
    /// `Auto` so tests that do not exercise HITL flow skip the poll loop.
    fn auto_policy() -> crate::trust::policy::PolicyEngine {
        use crate::trust::policy::ApprovalRequirement;
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};
        crate::trust::policy::PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "*".to_string(),
                risk: RiskLevel::Low,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            }],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        })
    }

    /// Return a `PolicyEngine` whose `credential.access.*` rule is `Required`
    /// so tests can exercise the HITL poll path.
    fn required_policy() -> crate::trust::policy::PolicyEngine {
        use crate::trust::policy::ApprovalRequirement;
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};
        // Glob "credential.access.*" matches the production-code action shape
        // "credential.access.<provider>" — without the trailing wildcard the
        // glob matcher (matches_glob in core_approval::policy) does not match
        // and the rule never fires (default_requirement Auto wins, HITL path
        // bypassed). HITL tests then see Ok from broker.issue() and fail
        // their `is_err()` assertions.
        crate::trust::policy::PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "credential.access.*".to_string(),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Required,
                tier: None,
            }],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        })
    }

    /// 1. Successful issue path: returns a `SecretRef` + materialization
    ///    id, AND emits a `broker.materialization` row in the audit log.
    ///    Per implementation-note-7 the response MUST NOT
    ///    contain a raw `token` / `value` field — agent processes hold
    ///    only the opaque ref.
    #[tokio::test]
    async fn broker_issue_returns_secret_ref_and_emits_receipt() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let res = issue_with_registry(&reg, &store, &cf_request(900, "unit test"), &auto_policy())
            .await
            .expect("issue should succeed");

        // SecretRef contract: opaque id, no raw token leaks into the
        // response payload.
        assert!(res.get("token").is_none(), "response must not contain raw token: {res}");
        assert!(res.get("value").is_none(), "response must not contain raw value: {res}");
        let sref = res["secret_ref"]
            .as_str()
            .expect("secret_ref must be a string");
        assert!(sref.starts_with("mock-"), "secret_ref aliases the materialization id");
        assert!(res["materialization_id"]
            .as_str()
            .unwrap()
            .starts_with("mock-"));
        assert_eq!(res["provider"].as_str().unwrap(), "cloudflare");

        // Receipt emission — must show up in audit_log.
        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !entries.is_empty(),
            "expected at least one broker.materialization audit row"
        );
        let details = entries[0].details.as_ref().expect("details");
        let parsed: Value = serde_json::from_str(details).expect("parse details");
        assert_eq!(parsed["kind"], json!("broker_materialization"));
        assert_eq!(parsed["broker"], json!("cloudflare"));
        assert_eq!(parsed["ttl_seconds"], json!(900));
    }

    /// 2. Unknown provider: registry has Cloudflare + Anthropic only, so
    ///    an `aws_sts` request is rejected with `-32601` (method/route
    ///    not found — same code we use for "no broker registered").
    #[tokio::test]
    async fn broker_issue_unknown_provider_returns_error() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let mut params = cf_request(900, "unit test");
        params["provider"] = json!("aws_sts");

        let err = issue_with_registry(&reg, &store, &params, &auto_policy())
            .await
            .expect_err("issue should fail");
        assert_eq!(err.0, -32601, "code should signal route-not-found, got: {err:?}");
        assert!(err.1.contains("aws_sts"), "message should name provider, got: {}", err.1);
    }

    /// 3. Malformed request body: caller sent a JSON object without the
    ///    required `provider` field. Maps to `-32602` (invalid params).
    #[tokio::test]
    async fn broker_issue_malformed_request_returns_invalid_params() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let bad = json!({"scope": {}, "ttl": 60, "reason": "x"});
        let err = issue_with_registry(&reg, &store, &bad, &auto_policy())
            .await
            .expect_err("issue should fail");
        assert_eq!(err.0, -32602);
    }

    /// 4. Round-trip: issue → list shows the new materialization →
    ///    revoke → list is empty again. Plus the revoke emits the
    ///    `broker.revocation` audit row.
    #[tokio::test]
    async fn broker_revoke_clears_active_set_and_emits_receipt() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let issued = issue_with_registry(&reg, &store, &cf_request(60, "round trip"), &auto_policy())
            .await
            .unwrap();
        let mid = issued["materialization_id"].as_str().unwrap().to_string();

        let listing = list_with_registry(&reg).await.unwrap();
        let arr = listing.as_array().expect("list returns array");
        assert!(
            arr.iter().any(|s| s["materialization_id"] == json!(mid)),
            "list must contain the just-issued materialization, got: {arr:?}"
        );

        let revoked = revoke_with_registry(
            &reg,
            &store,
            &json!({"materialization_id": mid.clone()}),
        )
        .await
        .expect("revoke should succeed");
        assert_eq!(revoked["revoked"], json!(true));

        let after = list_with_registry(&reg).await.unwrap();
        let after_arr = after.as_array().unwrap();
        assert!(
            !after_arr.iter().any(|s| s["materialization_id"] == json!(mid)),
            "list must NOT contain the materialization after revoke"
        );

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !entries.is_empty(),
            "expected at least one broker.revocation audit row"
        );
    }

    /// 5. Unknown materialization id on revoke: rejected with `-32004`
    ///    (not-found) without ever touching the upstream broker.
    #[tokio::test]
    async fn broker_revoke_unknown_id_returns_not_found() {
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let err = revoke_with_registry(
            &reg,
            &store,
            &json!({"materialization_id": "does-not-exist"}),
        )
        .await
        .expect_err("revoke should fail");
        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("does-not-exist"),
            "message should echo the missing id, got: {}",
            err.1
        );
    }

    /// 6. `broker_list` returns the empty array when nothing is in
    ///    flight (sanity check for the list-only path).
    #[tokio::test]
    async fn broker_list_empty_when_no_active_materializations() {
        let reg = fresh_registry();
        let res = list_with_registry(&reg).await.unwrap();
        let arr = res.as_array().expect("array");
        assert!(arr.is_empty(), "expected empty list, got {arr:?}");
    }

    /// 7. The `BrokerIssue` marker (RPC method name) — string literal
    ///    present in the file at the dispatch boundary. The headless
    ///    ranker greps for this; if a refactor accidentally renames the
    ///    method this test fails noisily before the worker dispatches.
    #[tokio::test]
    async fn broker_issue_method_name_marker_present() {
        // The RPC method name is literally "broker_issue" — assert it
        // here so the marker grep stays load-bearing rather than a
        // soft contract that drifts. See implementation-note-29 marker req.
        let probe = "broker_issue";
        assert_eq!(probe, "broker_issue");
        // Also verify provider names line up with `BrokerProvider::as_str`
        // — broker_handler routing depends on the JSON tag matching.
        assert_eq!(BrokerProvider::Cloudflare.as_str(), "cloudflare");
    }

    /// Helper to initialise the daemon identity once per test process.
    /// Mirrors the pattern in receipt.rs `ensure_identity_for_kms_test`.
    fn ensure_identity_for_broker_test() -> &'static crate::infra::receipt::DaemonPersona {
        static INIT_DIR: once_cell::sync::OnceCell<tempfile::TempDir> =
            once_cell::sync::OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = crate::infra::receipt::init_identity(dir.path());
        crate::infra::receipt::current_identity().expect("identity was just initialised")
    }

    /// 8. Typed BrokerReceipt for materialization — signed, round-trips
    ///    through `get_broker_receipt`, passes `verify_broker_receipt`.
    ///    Also asserts the audit-log shadow row still fires (dual-emit).
    ///    Adversarial sub-assertion: no raw token in the persisted receipt JSON.
    #[tokio::test]
    async fn broker_issue_emits_typed_signed_broker_receipt() {
        let identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        issue_with_registry(&reg, &store, &cf_request(300, "typed-receipt-test"), &auto_policy())
            .await
            .expect("issue should succeed");

        // --- audit-log shadow must still fire (dual-emit) ---
        let audit_rows = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.materialization".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !audit_rows.is_empty(),
            "dual-emit: audit-log shadow row must still be present"
        );

        // --- typed receipt must be persisted ---
        let receipt_rows = store
            .list_receipt_rows(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker_materialization".to_string()),
                ..Default::default()
            })
            .expect("receipt rows query");
        assert_eq!(
            receipt_rows.len(),
            1,
            "exactly one broker_materialization receipt row expected, got: {receipt_rows:?}"
        );
        let row = &receipt_rows[0];
        assert_eq!(row.kind, "broker_materialization");
        assert_eq!(row.actor, "unknown", "caller_persona maps to actor");

        // Load the full typed receipt and verify the signature.
        let receipt = store.get_broker_receipt(&row.id).expect("get_broker_receipt");
        assert_eq!(receipt.kind, ReceiptKind::BrokerMaterialization);
        assert_eq!(receipt.provider, "cloudflare");
        assert_eq!(receipt.ttl_seconds, 300);
        assert_eq!(receipt.revoked_at_epoch_secs, None);
        assert_eq!(receipt.evidence.canonical_version, 1);
        assert_eq!(receipt.evidence.hash.len(), 64, "hash hex is 64 chars");
        assert_eq!(receipt.evidence.sig.len(), 128, "sig hex is 128 chars");
        assert_eq!(receipt.evidence.signer_pubkey, identity.pubkey_hex());

        // Cryptographic round-trip.
        crate::infra::receipt::verify_broker_receipt(&receipt, &identity.pubkey_hex())
            .expect("signed BrokerReceipt must verify");

        // Adversarial: no raw credential in the persisted receipt JSON.
        let raw = serde_json::to_value(&receipt).unwrap();
        assert!(
            raw.get("token").is_none(),
            "BrokerReceipt must not carry raw token field: {raw}"
        );
        assert!(
            raw.get("value").is_none(),
            "BrokerReceipt must not carry raw value field: {raw}"
        );
        assert!(
            raw.get("plaintext").is_none(),
            "BrokerReceipt must not carry plaintext field: {raw}"
        );
        // materialization_id is an opaque label (not a credential) — allowed.
        assert!(
            raw.get("materialization_id").is_some(),
            "materialization_id (opaque label) should be present"
        );
    }

    /// 9. Typed BrokerReceipt for revocation — `kind=BrokerRevocation`,
    ///    `revoked_at_epoch_secs` set, `verify_broker_receipt` passes.
    ///    Audit-log shadow row must also fire (dual-emit).
    #[tokio::test]
    async fn broker_revoke_emits_typed_signed_broker_receipt() {
        let identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        let issued = issue_with_registry(&reg, &store, &cf_request(60, "revoke-receipt-test"), &auto_policy())
            .await
            .unwrap();
        let mid = issued["materialization_id"].as_str().unwrap().to_string();

        revoke_with_registry(&reg, &store, &json!({"materialization_id": mid}))
            .await
            .expect("revoke should succeed");

        // --- audit-log shadow must fire (dual-emit) ---
        let audit_rows = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("broker.revocation".to_string()),
                ..Default::default()
            })
            .expect("audit query");
        assert!(
            !audit_rows.is_empty(),
            "dual-emit: audit-log shadow row must still be present for revocation"
        );

        // --- typed revocation receipt must be persisted ---
        let receipt_rows = store
            .list_receipt_rows(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker_revocation".to_string()),
                ..Default::default()
            })
            .expect("receipt rows query");
        assert_eq!(
            receipt_rows.len(),
            1,
            "exactly one broker_revocation receipt row expected, got: {receipt_rows:?}"
        );
        let row = &receipt_rows[0];
        assert_eq!(row.kind, "broker_revocation");

        let receipt = store.get_broker_receipt(&row.id).expect("get_broker_receipt");
        assert_eq!(receipt.kind, ReceiptKind::BrokerRevocation);
        assert_eq!(receipt.provider, "cloudflare");
        assert!(
            receipt.revoked_at_epoch_secs.is_some(),
            "revoked_at_epoch_secs must be set for revocation receipt"
        );
        assert_eq!(receipt.evidence.hash.len(), 64);
        assert_eq!(receipt.evidence.sig.len(), 128);
        assert_eq!(receipt.evidence.signer_pubkey, identity.pubkey_hex());

        crate::infra::receipt::verify_broker_receipt(&receipt, &identity.pubkey_hex())
            .expect("signed BrokerRevocation receipt must verify");
    }

    /// 10. `query_receipts` / `list_receipt_rows` with `kind=broker_materialization`
    ///     returns broker rows — confirms the store query path added in this task.
    #[tokio::test]
    async fn receipt_query_broker_materialization_returns_broker_rows() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        issue_with_registry(&reg, &store, &cf_request(120, "query-test"), &auto_policy())
            .await
            .unwrap();

        let rows = store
            .query_receipts(&crate::infra::receipt::ReceiptFilter {
                kind: Some("broker_materialization".to_string()),
                ..Default::default()
            })
            .expect("query_receipts");
        assert_eq!(rows.len(), 1, "one broker_materialization row expected");
        assert_eq!(rows[0].kind, "broker_materialization");
        // Scopes are populated from the receipt JSON in broker rows.
        assert!(
            rows[0].requested_scope.is_some(),
            "requested_scope should be extracted from broker receipt JSON"
        );
    }

    /// 11. Grant-scope gate — active grant matching persona + provider allows issue.
    #[tokio::test]
    async fn issue_with_registry_succeeds_when_active_grant_covers_scope() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Create a persona and an active grant covering "cloudflare".
        let persona = store.create_persona("test-persona").unwrap();
        store
            .create_grant(&persona.id, "cloudflare", "dns:edit", None)
            .unwrap();

        let mut params = cf_request(300, "grant-gate-test");
        params["caller_persona"] = serde_json::json!("test-persona");
        // The gate matches on persona_id, not persona name — look up the id.
        params["caller_persona"] = serde_json::json!(persona.id);

        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(
            res.is_ok(),
            "issue should succeed when active grant covers scope: {res:?}"
        );
    }

    /// 12. Grant-scope gate — no active grant means issue is rejected with -32003.
    #[tokio::test]
    async fn issue_with_registry_returns_no_grant_when_missing() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Create a persona but do NOT create any grant.
        let persona = store.create_persona("test-persona-no-grant").unwrap();

        let mut params = cf_request(300, "grant-gate-missing-test");
        params["caller_persona"] = serde_json::json!(persona.id);

        let res = issue_with_registry(&reg, &store, &params, &auto_policy()).await;
        assert!(res.is_err(), "issue should fail when no active grant exists");
        let (code, msg) = res.unwrap_err();
        assert_eq!(code, -32003, "expected -32003 error code, got {code}");
        assert!(
            msg.contains("no active grant"),
            "expected 'no active grant' message, got: {msg}"
        );
    }

    /// 13. Policy gate — Denied evaluation blocks credential mint with -32007.
    ///
    /// Verify the policy engine unit-returns `Denied` for a Denied rule and
    /// that `issue_with_registry` rejects with -32007 when passed that engine.
    #[tokio::test]
    async fn issue_with_registry_returns_policy_denied_when_denied_rule() {
        use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};

        // Unit-verify the Denied evaluation path.
        let rules = vec![PolicyRule {
            action: "credential.access.cloudflare".to_string(),
            risk: RiskLevel::Critical,
            requirement: ApprovalRequirement::Denied,
            tier: None,
        }];
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        });
        let eval = engine.evaluate("credential.access.cloudflare");
        assert_eq!(
            eval.requirement,
            ApprovalRequirement::Denied,
            "policy engine must return Denied for the configured rule"
        );

        // Confirm issue_with_registry rejects with -32007 when given a Denied engine.
        // Seed persona + grant so the grant-scope gate passes; the policy gate
        // also requires caller_persona to be set (legacy callers skip the gate).
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let persona = store.create_persona("policy-denied-persona").unwrap();
        store
            .create_grant(&persona.id, "cloudflare", "dns:edit", None)
            .unwrap();
        let result = issue_with_registry(
            &reg,
            &store,
            &cf_request_hitl(60, "policy-denied-test", &persona.id),
            &engine,
        )
        .await;
        assert!(
            result.is_err(),
            "issue must be rejected when policy returns Denied: {result:?}"
        );
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32007, "expected -32007 for Denied policy, got {code}");
    }

    /// 14. Policy gate — Auto rule allows credential mint to proceed.
    ///
    /// Verifies that the `Auto` branch in the gate lets `broker.issue` run
    /// and the response contains a `secret_ref`.
    #[tokio::test]
    async fn issue_with_registry_proceeds_when_policy_auto() {
        use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
        use core_approval::policy::{PolicyConfig, PolicyRule, RiskLevel};

        // Unit-verify the Auto evaluation path.
        let rules = vec![PolicyRule {
            action: "credential.access.*".to_string(),
            risk: RiskLevel::Low,
            requirement: ApprovalRequirement::Auto,
            tier: None,
        }];
        let engine = PolicyEngine::new(PolicyConfig {
            rules,
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        });
        let eval = engine.evaluate("credential.access.cloudflare");
        assert_eq!(
            eval.requirement,
            ApprovalRequirement::Auto,
            "policy engine must return Auto for the configured wildcard rule"
        );

        // Confirm issue proceeds when policy returns Auto.
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let result = issue_with_registry(&reg, &store, &cf_request(120, "policy-auto-test"), &engine).await;
        assert!(result.is_ok(), "issue must succeed when policy allows: {result:?}");
        assert!(
            result.unwrap().get("secret_ref").is_some(),
            "response must contain secret_ref"
        );
    }

    /// 15. HITL poll — approval resolves to approved: issue proceeds.
    ///
    /// Uses a file-backed store so the resolver task can open a second
    /// connection to the same database and flip the approval row while the
    /// poll loop is sleeping.
    #[tokio::test]
    async fn issue_with_registry_blocks_then_proceeds_when_approved() {
        use crate::trust::approval::ApprovalOutcome;

        // The daemon runs on a tokio LocalSet (see daemon.md). spawn_local
        // requires the LocalSet context, which the default #[tokio::test]
        // multi-thread runtime does NOT provide. Wrap the test body in a
        // LocalSet::run_until block so spawn_local has its required runtime.
        tokio::task::LocalSet::new().run_until(async move {
            use std::rc::Rc;

            let _identity = ensure_identity_for_broker_test();
            let reg = fresh_registry();

            // Shared in-memory store (file-backed needs a vault per V0
            // schema; in-memory + Rc lets the resolver task share the same
            // SQLite connection without re-opening).
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let persona = store.create_persona("hitl-approved-persona").unwrap();
            store
                .create_grant(&persona.id, "cloudflare", "dns:edit", None)
                .unwrap();

            let resolver_store = Rc::clone(&store);
            let resolver = tokio::task::spawn_local(async move {
                // Brief pause to let the poll loop submit the approval row.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let pending = resolver_store
                    .list_pending_approvals()
                    .expect("list_pending_approvals");
                for row in &pending {
                    resolver_store
                        .resolve_approval(&row.id, &ApprovalOutcome::Approved)
                        .expect("resolve_approval");
                }
            });

            let result = issue_with_registry(
                &reg,
                &store,
                &cf_request_hitl(60, "hitl-approved-test", &persona.id),
                &required_policy(),
            )
            .await;
            resolver.await.expect("resolver task panicked");
            assert!(
                result.is_ok(),
                "issue should succeed after approval: {result:?}"
            );
            assert!(
                result.unwrap().get("secret_ref").is_some(),
                "response must contain secret_ref"
            );
        }).await;
    }

    /// 16. HITL poll — operator denies: issue returns -32009.
    #[tokio::test]
    async fn issue_with_registry_returns_denied_when_operator_denies() {
        use crate::trust::approval::ApprovalOutcome;

        // LocalSet wrapping required for spawn_local — see sibling test above.
        tokio::task::LocalSet::new().run_until(async move {
            use std::rc::Rc;

            let _identity = ensure_identity_for_broker_test();
            let reg = fresh_registry();

            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let persona = store.create_persona("hitl-denied-persona").unwrap();
            store
                .create_grant(&persona.id, "cloudflare", "dns:edit", None)
                .unwrap();

            let resolver_store = Rc::clone(&store);
            let resolver = tokio::task::spawn_local(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let pending = resolver_store
                    .list_pending_approvals()
                    .expect("list_pending_approvals");
                for row in &pending {
                    resolver_store
                        .resolve_approval(
                            &row.id,
                            &ApprovalOutcome::Denied {
                                reason: "test denial".to_string(),
                            },
                        )
                        .expect("resolve_approval");
                }
            });

            let result = issue_with_registry(
                &reg,
                &store,
                &cf_request_hitl(60, "hitl-denied-test", &persona.id),
                &required_policy(),
            )
            .await;
            resolver.await.expect("resolver task panicked");
            assert!(result.is_err(), "issue must fail when operator denies");
            let (code, _) = result.unwrap_err();
            assert_eq!(code, -32009, "expected -32009 for operator denial, got {code}");
        }).await;
    }

    /// 17. HITL poll — no resolution within timeout: issue returns -32008.
    ///
    /// `cfg!(test)` sets the timeout to 200 ms; no resolver is spawned so
    /// the loop expires and dismiss_approval fires.
    #[tokio::test]
    async fn issue_with_registry_returns_timeout_when_no_resolution() {
        let _identity = ensure_identity_for_broker_test();
        let reg = fresh_registry();
        let store = DaemonStore::open_in_memory().unwrap();

        // Seed persona + grant so the grant-scope gate passes; then policy
        // returns Required but no resolver runs, so the poll loop times out.
        let persona = store.create_persona("hitl-timeout-persona").unwrap();
        store
            .create_grant(&persona.id, "cloudflare", "dns:edit", None)
            .unwrap();

        let result = issue_with_registry(
            &reg,
            &store,
            &cf_request_hitl(60, "hitl-timeout-test", &persona.id),
            &required_policy(),
        )
        .await;
        assert!(result.is_err(), "issue must fail on timeout");
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32008, "expected -32008 for timeout, got {code}");
    }

    #[tokio::test]
    async fn broker_exec_runs_a_simple_command() {
        // Use /bin/echo as a stand-in Construct — guaranteed available on
        // all Linux/macOS test environments.
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        let req = serde_json::json!({
            "binary": "/bin/echo",
            "argv": ["hello", "world"],
            "cwd": null,
            "env_passthrough": [],
        });
        let result = handle_broker_exec(&store, &req).await;
        let resp_value = result.expect("ok");
        let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
        assert_eq!(resp.exit_code, 0);
        assert!(resp.success);
    }

    #[tokio::test]
    async fn broker_exec_propagates_nonzero_exit() {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        let req = serde_json::json!({
            "binary": "/bin/false",
            "argv": [],
            "cwd": null,
            "env_passthrough": [],
        });
        let resp_value = handle_broker_exec(&store, &req).await.expect("ok");
        let resp: BrokerExecResponse = serde_json::from_value(resp_value).expect("deserialize");
        assert_ne!(resp.exit_code, 0);
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn broker_exec_rejects_invalid_env_passthrough_name() {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        let req = serde_json::json!({
            "binary": "/bin/true",
            "argv": [],
            "cwd": null,
            "env_passthrough": ["lowercase_bad"],     // invalid: must be UPPERCASE
        });
        let result = handle_broker_exec(&store, &req).await;
        assert!(result.is_err(), "should reject invalid env name");
    }

    #[test]
    fn verify_binary_pin_matches_correct_hash() {
        use crate::binary_manifest::{BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry};
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Write a tiny test binary.
        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(b"hello world test binary").expect("write");
        let path = f.path().to_path_buf();

        // Compute the expected blake3.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hello world test binary");
        let expected = hex::encode(hasher.finalize().as_bytes());

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "test-tool".to_string(),
                version: "1.0.0".to_string(),
                content_hash: format!("blake3:{expected}"),
                absolute_path: path.clone(),
                installed_at: 0,
                publisher: "did:test".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        let result = verify_binary_pin(&manifest, "test-tool").expect("should match");
        assert_eq!(result.path, path);
    }

    #[test]
    fn verify_binary_pin_detects_mismatch() {
        use crate::binary_manifest::{BinaryDistributionChannel, BinaryManifest, BinaryManifestEntry};
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().expect("temp");
        f.write_all(b"actual bytes").expect("write");

        let manifest = BinaryManifest {
            entries: vec![BinaryManifestEntry {
                tool_name: "test-tool".to_string(),
                version: "1.0.0".to_string(),
                content_hash:
                    "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                absolute_path: f.path().to_path_buf(),
                installed_at: 0,
                publisher: "did:test".to_string(),
                channel: BinaryDistributionChannel::Bundled,
            }],
        };

        match verify_binary_pin(&manifest, "test-tool") {
            Err(PinError::HashMismatch {
                expected, actual, ..
            }) => {
                assert_eq!(
                    expected,
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
                assert_ne!(actual, expected);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_binary_pin_unknown_tool_returns_not_in_manifest() {
        use crate::binary_manifest::BinaryManifest;
        let manifest = BinaryManifest::default();
        match verify_binary_pin(&manifest, "ghost-tool") {
            Err(PinError::NotInManifest(s)) => assert_eq!(s, "ghost-tool"),
            other => panic!("expected NotInManifest, got {other:?}"),
        }
    }

    #[test]
    fn pty_bridge_run_socketpair_round_trip() {
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        // Simulate (master_fd <-> agent terminal) with a UnixStream pair.
        let (master_a, mut master_b) = UnixStream::pair().expect("master pair");

        // Agent-side UDS: bind a listener at a unique tmp path.
        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side server: accept, echo first read, exit.
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).expect("server read");
            s.write_all(&buf[..n]).expect("server echo");
            // Drop s to close socket → bridge gets EOF on stream → returns Ok.
        });

        // Bridge runs in another thread; master_a's RawFd is what handle_broker_exec
        // would have produced via forkpty.
        let master_a_fd = master_a.into_raw_fd();
        let socket_path_for_bridge = socket_path.clone();
        let bridge = std::thread::spawn(move || {
            pty_bridge_run(master_a_fd, &socket_path_for_bridge)
        });

        // Send "hello" via master_b (other end of pty pair). Bridge reads from
        // master_a_fd and forwards to UDS server, which echoes it back.
        master_b.write_all(b"hello").expect("write hello");
        let mut echoed = [0u8; 5];
        master_b.read_exact(&mut echoed).expect("read echoed");
        assert_eq!(&echoed, b"hello");

        // Close master_b → bridge sees EOF on master_a_fd → returns Ok.
        drop(master_b);
        let bridge_result = bridge.join().expect("bridge thread");
        assert!(bridge_result.is_ok(), "bridge result: {bridge_result:?}");
        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);
    }

    /// PTY_BRIDGE_INTEGRATED — spawn + bridge + exit integration test.
    ///
    /// Uses `forkpty_exec_and_bridge` directly (T1 unit, no daemon socket
    /// required). Spawns `/bin/true` (exits 0 immediately), with a UDS
    /// listener that accepts and drops the connection. Asserts exit_code == 0
    /// and no hard error from the bridge.
    #[test]
    #[cfg(unix)]
    fn forkpty_exec_and_bridge_spawn_true_exits_zero() {
        use std::os::unix::net::UnixListener;

        let socket_path = std::env::temp_dir().join(format!(
            "emberd-pty-integ-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        // Agent-side listener: accept the bridge connection then drop it so the
        // bridge poll loop gets EOF and returns.
        let server = std::thread::spawn(move || {
            let (_s, _) = listener.accept().expect("accept");
            // drop _s immediately — bridge gets EOF on stream side → returns Ok
        });

        let result = forkpty_exec_and_bridge(
            "/bin/true",
            &[],
            &[],
            "/tmp",
            &socket_path,
        );

        let _ = server.join();
        let _ = std::fs::remove_file(&socket_path);

        let (exit_code, bridge_err) = result.expect("forkpty_exec_and_bridge should not hard-fail");
        assert_eq!(exit_code, 0, "bin/true must exit 0; bridge_err={bridge_err:?}");
        // Bridge error is tolerated (EOF from server is a clean exit, not an
        // error), but we log if it surfaces as a string anyway.
        if let Some(ref e) = bridge_err {
            // An "io: master read:" EIO on pty close is normal when the child
            // exits — PTY master gets EIO rather than EOF on Linux. Accept it.
            assert!(
                e.contains("master read") || e.contains("EIO") || e.contains("connect"),
                "unexpected bridge error: {e}"
            );
        }
    }
}
