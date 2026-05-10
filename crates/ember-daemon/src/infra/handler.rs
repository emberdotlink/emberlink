// implementation-note-87

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::{json, Value};
use tokio::sync::broadcast;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
use core_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, ReceiptKind, ReceiptOutcome, VaultReceipt,
};

use crate::trust::approval::{ApprovalRequestInfo, DaemonApprovalStoreRef};
use crate::infra::audit::AuditFilter;
use crate::infra::events::GrantEvent;
use core_grants::GrantState as CoreGrantState;
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::{self, GateOutcome, HighRiskOp};
use crate::infra::rate_limit::RateLimiter;
use crate::infra::receipt::{
    current_identity,
    issue::{issue_cohort_a_receipt, TerminationMeta},
    sign_vault_receipt,
};
use core_events::receipt::{TerminationAuthority, TerminationReason};
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;

// development milestone: peer-credential-derived principal binding for
// `delegate_grant`. Mirrors the socket layer's `PeerIdentity` shape so
// `handler.rs` does not have to depend on socket-layer cfg gates. The
// fields are public because this is a kernel-derived identity carried
// by trusted code (the socket layer); there is no validation surface
// for callers to violate.
//
// `pid` is `Option<i32>` because BSD's `LOCAL_PEERCRED` does not always
// surface PID. On macOS in particular, when `pid` is `None`, the only
// safe behavior is to fail-closed — `peercred_principal()` returns
// `HandlerError::PrincipalUnavailable` rather than minting a delegation
// authorized by an unknown principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<i32>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<crate::infra::socket::PeerIdentity> for PeerCred {
    fn from(p: crate::infra::socket::PeerIdentity) -> Self {
        PeerCred { uid: p.uid, pid: p.pid }
    }
}

/// Errors returned by the principal-binding layer.
///
/// These are converted to JSON-RPC error tuples by the dispatch layer:
///   `PrincipalUnavailable` -> `-32401`, "principal binding unavailable"
///   `PrincipalMismatch    -> `-32401`, "principal mismatch"
///
/// `-32401` is reused from the JSON-RPC convention (Unauthorized) — same
/// code used elsewhere in the daemon for authorization rejections that
/// are NOT policy denials (`-32003`) or generic param errors (`-32602`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// The peer-credential structure did not contain enough information
    /// to derive a principal. On macOS this happens whenever
    /// `LOCAL_PEERCRED` did not return a PID. We fail-closed rather than
    /// fall back to UID-only binding (which would let any same-UID
    /// process claim any persona).
    PrincipalUnavailable,
    /// The kernel-derived principal does not match the persona the
    /// caller asserted in their request params. The caller is lying
    /// about which persona they are.
    PrincipalMismatch,
    /// The peer's PID is not enrolled in the daemon's PID->persona
    /// registry. The caller has not yet established an identity in
    /// this daemon (no `create_persona` call from this PID, or the
    /// enrollment expired/was cleared).
    PrincipalNotEnrolled,
}

impl HandlerError {
    pub fn to_jsonrpc(&self) -> (i32, String) {
        match self {
            HandlerError::PrincipalUnavailable => (
                -32401,
                "delegate_grant: principal binding unavailable on this \
                 platform (peer PID was not surfaced by the kernel)"
                    .to_string(),
            ),
            HandlerError::PrincipalMismatch => (
                -32401,
                "delegate_grant: caller's kernel-derived principal does \
                 not match the asserted caller_persona_id"
                    .to_string(),
            ),
            HandlerError::PrincipalNotEnrolled => (
                -32401,
                "delegate_grant: caller PID is not enrolled with any \
                 persona — call create_persona on this connection first"
                    .to_string(),
            ),
        }
    }
}

/// Per-connection request context carrying kernel-derived identity.
///
/// The `peer` field is populated by the socket layer at connection accept
/// time; the `principal` field is the persona id resolved from `peer.pid`
/// via `peercred_principal()`. For `Internal` callers, both are `None`.
///
/// The struct deliberately mirrors what we expect to extend to
/// session-ticket-based binding (Alternative B) so the handler call
/// site does not change between phases — only the population of
/// `principal` does.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub source: DispatchSource,
    pub peer: Option<PeerCred>,
    /// Pre-resolved persona id, when the dispatch layer has already
    /// looked it up (e.g. for tests that want to inject a principal
    /// directly without going through the PID registry).
    pub principal: Option<String>,
    /// Base directory for session sidecars (`~/.ember/sessions/`). Required
    /// by `register_session` and `close_session` RPC arms to read/write
    /// `SessionMeta` + `receipt.json`. `None` for internal callers and test
    /// contexts that don't exercise the session lifecycle.
    pub sessions_dir: Option<std::path::PathBuf>,
    /// implementation-note-88: bound LLM proxy
    /// URL plumbed from the runtime after the proxy listener binds. Populated
    /// by `SocketListener::with_llm_proxy_url` and consumed by
    /// `register_session` instead of reading `EMBER_PROXY_URL` from the
    /// environment, which is unreliable across tokio worker threads (Rust
    /// 2024 `set_var` cross-thread visibility hazard).
    pub llm_proxy_url: Option<String>,
    /// implementation-note-88: bound git proxy
    /// URL plumbed from the runtime after the git proxy listener binds.
    /// Matches the pattern of `llm_proxy_url` above.
    pub git_proxy_url: Option<String>,
}

impl RequestContext {
    /// Build an `Internal` context — bypasses peercred binding entirely.
    pub fn internal(reason: &'static str) -> Self {
        Self {
            source: DispatchSource::Internal { reason },
            peer: None,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        }
    }

    /// Build a `Socket` context with a peer credential. The principal
    /// will be lazily resolved by handlers that require it.
    pub fn socket(peer: Option<PeerCred>) -> Self {
        Self {
            source: DispatchSource::Socket,
            peer,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        }
    }

    /// Build a `Socket` context with a pre-resolved principal. Used by
    /// tests that want to assert handler behavior without populating
    /// the global PID registry.
    pub fn socket_with_principal(peer: Option<PeerCred>, principal: String) -> Self {
        Self {
            source: DispatchSource::Socket,
            peer,
            principal: Some(principal),
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        }
    }
}

// PID -> Persona enrollment registry. Populated when a Socket caller
// calls `create_persona` and inspected when the same caller (same PID)
// invokes `delegate_grant`.
//
// Why thread-local: the daemon is single-threaded LocalSet at runtime,
// so production correctness only needs a single map. We use a
// thread-local rather than a global static so that cargo's parallel
// test runner gets fresh registries per test thread — otherwise a
// `create_persona` enrollment from one test could leak into another
// test's `delegate_grant` lookup and produce a flaky principal-mismatch
// result. This is a pragmatic phase-1 fit; phase 2 (session ticket)
// will move enrollment into a more structured per-connection store.
std::thread_local! {
    static PID_PERSONA_REGISTRY: RefCell<HashMap<i32, String>> =
        RefCell::new(HashMap::new());
}

/// Enroll a (pid, persona_id) pair in the per-thread registry.
///
/// Called from the `create_persona` handler when the dispatch source is
/// `Socket` and the peer credential surfaced a PID.  Subsequent
/// `delegate_grant` calls from the same PID will resolve to this
/// persona id.
pub fn enroll_pid_persona(pid: i32, persona_id: &str) {
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow_mut().insert(pid, persona_id.to_string());
    });
}

/// Test-only helper: drop all enrollments. Cargo's per-test isolation
/// relies on a fresh registry, so individual tests that enroll PIDs
/// should call this in setup (or rely on thread-local isolation).
#[cfg(test)]
pub fn clear_pid_persona_registry() {
    PID_PERSONA_REGISTRY.with(|reg| reg.borrow_mut().clear());
}

/// Resolve the calling persona for a peer credential.
///
/// On Linux the registry is keyed by PID, populated at `create_persona`
/// dispatch time. On macOS where `peer.pid` may be `None`, we fail-closed
/// with `PrincipalUnavailable` rather than fall back to UID-only binding
/// (which would let any same-UID process claim any persona).
pub fn peercred_principal(peer: &PeerCred) -> Result<String, HandlerError> {
    let pid = peer.pid.ok_or(HandlerError::PrincipalUnavailable)?;
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow()
            .get(&pid)
            .cloned()
            .ok_or(HandlerError::PrincipalNotEnrolled)
    })
}

/// Origin of a dispatched RPC request.
///
/// Fix for development milestone (CRITICAL): the `force` flag on `create_grant`
/// used to be accepted from any wire caller, letting unauthenticated socket
/// clients mint grants that bypassed the policy engine. We now thread the
/// dispatch *source* through the handler so that only `Internal` callers
/// (admin CLI paths, test harness, recovery flows) can request policy
/// bypass. Socket callers that attempt `force: true` are rejected.
///
/// **Type-level barrier (development milestone):** The `Internal` variant
/// requires a mandatory `reason` string literal so that every in-process
/// privilege escalation is visible and attributable at the call site.  Code
/// review can grep for `DispatchSource::Internal` and see exactly *why* each
/// caller claims the internal trust lane.  Forgetting the `reason` is a
/// compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSource {
    /// Request arrived via the unix-domain socket RPC path. Callers on this
    /// path are NOT authenticated as admins, and MUST NOT be able to
    /// bypass policy gates. Any `force: true` is rejected.
    Socket,
    /// Request was synthesized by an in-process caller that has already
    /// established admin identity (test harness, internal admin CLI path,
    /// recovery flows). `force: true` is honored.
    ///
    /// `reason` is a mandatory static string that names the trust context
    /// at the call site (e.g. `"admin CLI"`, `"recovery flow"`,
    /// `"test harness"`).  It is purely a code-review / audit annotation
    /// and has no effect on runtime behaviour.
    Internal { reason: &'static str },
}

impl DispatchSource {
    /// Returns `true` when this source carries internal (admin) trust.
    #[inline]
    pub fn is_internal(self) -> bool {
        matches!(self, DispatchSource::Internal { .. })
    }
}

/// Test-only dispatcher — unconditionally runs as an `Internal` source so
/// existing tests can use `force: true` as a setup shortcut. Not reachable
/// from the socket path.
pub async fn dispatch_method(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_source(
        store,
        vault,
        policy,
        rate_limiter,
        None,
        DispatchSource::Internal { reason: "test harness" },
        method,
        params,
    )
    .await
}

pub struct Banner {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub click_url: String,
}

/// Build the notification banner strings for a pending approval request.
///
/// Kept short to fit macOS banner constraints (~60 chars title, ~50 chars
/// subtitle/body). The scope string is intentionally excluded — it was the
/// primary overflow culprit. The dashboard deep-link (`click_url`) is the
/// canonical control surface for full context.
pub fn build_banner(persona_name: &str, req: &ApprovalRequestInfo) -> Banner {
    let id_prefix: String = req
        .id
        .strip_prefix("approval-")
        .unwrap_or(&req.id)
        .chars()
        .take(8)
        .collect();

    // Title: prefer tool_name when present; fall back to the action string.
    // Cap the action at 40 chars to leave room for "Ember · <name> wants ".
    // Append agent_framework as a parenthesized badge when present.
    let framework_suffix = req
        .agent_framework
        .as_deref()
        .map(|f| {
            let f_short: String = f.chars().take(16).collect();
            format!(" ({f_short})")
        })
        .unwrap_or_default();
    let title = if let Some(ref tool) = req.tool_name {
        let tool_short: String = tool.chars().take(40).collect();
        format!("Ember · {persona_name} · {tool_short}{framework_suffix}")
    } else {
        let action_short: String = req.action.chars().take(40).collect();
        format!("Ember · {persona_name} wants {action_short}{framework_suffix}")
    };

    // Subtitle: credential · TTL · risk — decision-relevant, no scope/id.
    let ttl_part = req
        .ttl_secs
        .map(|s| format!(" · {s}s TTL"))
        .unwrap_or_default();
    let risk_part = if req.risk_level.is_empty() {
        String::new()
    } else {
        format!(" · risk {}", req.risk_level)
    };
    let subtitle_raw = format!("{}{ttl_part}{risk_part}", req.credential_name);
    // Hard-truncate at 50 chars to guard against long credential names.
    let subtitle: String = if subtitle_raw.chars().count() > 50 {
        let mut s: String = subtitle_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        subtitle_raw
    };

    // Body: prefer target_host + target_summary when either is present; then
    // fall back to target_url; otherwise use the click-to-review prompt.
    let body_raw = match (&req.target_host, &req.target_summary, &req.target_url) {
        (Some(host), Some(summary), _) => format!("{host}{summary}"),
        (Some(host), None, _) => host.clone(),
        (None, Some(summary), _) => summary.clone(),
        (None, None, Some(url)) => url.clone(),
        (None, None, None) => format!("Click to review · {id_prefix}"),
    };
    let body: String = if body_raw.chars().count() > 50 {
        let mut s: String = body_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        body_raw
    };

    let click_url = format!("http://localhost:3141/approvals/{}", req.id);

    Banner { title, subtitle, body, click_url }
}

/// Surface a pending approval to the user via the OS notification system.
///
/// Best-effort — errors are silently swallowed. The call is skipped when
/// `EMBER_NO_DESKTOP_NOTIFY=1` is set (useful in CI/tests).
fn notify_require_approval(store: &DaemonStore, req: &ApprovalRequestInfo) {
    #[cfg(test)]
    {
        let _ = (store, req);
        return;
    }
    #[cfg(not(test))]
    {
        if std::env::var("EMBER_NO_DESKTOP_NOTIFY").as_deref() == Ok("1") {
            return;
        }
        let persona_name = store
            .get_persona(&req.persona_id)
            .map(|p| p.name)
            .unwrap_or_else(|_| req.persona_id.chars().take(8).collect());
        let banner = build_banner(&persona_name, req);
        crate::infra::notify::send_notification_with_url(
            &banner.title,
            Some(&banner.subtitle),
            &banner.body,
            Some(&banner.click_url),
        );
    }
}

/// Dispatch a method with an optional event broadcast channel. When a handler
/// triggers a server-initiated event (e.g. `revoke_grant`), the event is
/// published on the channel for connected socket clients to forward.
///
/// This is the **socket entry point** — it always runs as
/// `DispatchSource::Socket`, which causes any caller-supplied `force: true`
/// on `create_grant` to be rejected. See `DispatchSource` for context.
///
/// Backward-compat entry point: no peer credential, so principal binding
/// (development milestone) cannot apply — `delegate_grant` falls back to the
/// param-asserted ownership check. Production callers should use
/// `dispatch_method_with_peer` instead.
pub async fn dispatch_method_with_events(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(None),
        method,
        params,
    )
    .await
}

/// Socket entry point with a peer credential — the production path.
///
/// The socket layer captures `SO_PEERCRED` / `LOCAL_PEERCRED` at accept
/// time and forwards the resulting `PeerIdentity` here. The handler
/// uses it to bind `delegate_grant` to a kernel-derived principal
/// instead of trusting an attacker-controlled `caller_persona_id` param.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_peer(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    peer: Option<crate::infra::socket::PeerIdentity>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let peer_cred: Option<PeerCred> = peer.map(Into::into);
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(peer_cred),
        method,
        params,
    )
    .await
}

/// Non-Linux/macOS fallback — never has a real PeerIdentity.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn dispatch_method_with_peer(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    _peer: Option<()>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(None),
        method,
        params,
    )
    .await
}

/// Per-op `require_user_presence` gate is applied to high-risk operations
/// dispatched here (`vault_add`,
/// `vault_remove`, `create_grant`). Read-class operations bump the
/// session's `last_activity` via `presence::record_activity()` so they
/// don't spam the user with biometric prompts but also keep the session
/// "warm" — the lock fires on idle silence, not on dashboard polling.
fn check_user_presence_gate(
    op: HighRiskOp,
    override_quiet_hours: bool,
) -> Result<(), (i32, String)> {
    match presence::require_user_presence(op, override_quiet_hours) {
        GateOutcome::Allowed => Ok(()),
        GateOutcome::Locked { reason } => Err((-32030, reason)),
    }
}

/// Backward-compatible shim: builds a `RequestContext` from a bare
/// `DispatchSource` and delegates to `dispatch_method_with_context`. Used
/// by tests that pre-date development milestone and by `Internal` callers
/// that have no peer credential to assert.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_source(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    source: DispatchSource,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let ctx = RequestContext {
        source,
        peer: None,
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
    };
    dispatch_method_with_context(
        store, vault, policy, rate_limiter, events_tx, ctx, method, params,
    )
    .await
}

/// Core dispatcher. Callers MUST set `ctx.source` correctly: `Socket` for
/// any request that arrived from the wire, `Internal` only for in-process
/// admin/test paths. Mis-attribution here would re-open development milestone.
///
/// `ctx.peer` carries the kernel-derived peer credential when available
/// (Linux + macOS sockets only). `delegate_grant` consults it via
/// `peercred_principal()` to bind requests to a real principal instead
/// of trusting an attacker-controlled param. See development milestone.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_context(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    ctx: RequestContext,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let source = ctx.source;
    match method {
        "ping" => Ok(json!({"pong": true})),

        // implementation-note-89: Claude Code PreToolUse hook entry point.
        // The proxy hook (`ember-proxy/src/claude_code_hook.rs`) calls
        // this with the parsed `tool_name` + `params` + `session_id`,
        // and the daemon performs grant lookup + audit emit + decision.
        // Real evaluator integration lands in implementation-note-90; this path is
        // a Permit-stub on grant-hit, Deny on grant-miss.
        "evaluate_tool_call" => {
            let persona = params["persona"]
                .as_str()
                .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
            let tool_name = params["tool_name"]
                .as_str()
                .ok_or((-32602, "missing 'tool_name' parameter".to_string()))?;
            let session_id = params["session_id"].as_str();
            let grant_id = params["grant_id"].as_str();
            let tool_params = &params["params"];
            let decision = store
                .evaluate_tool_call(persona, tool_name, tool_params, session_id, grant_id)
                .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(&decision)
                .map_err(|e| (-32000, format!("serialize ToolCallDecision: {e}")))
        }

        "create_persona" => {
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name' parameter".to_string()))?;
            let info = store
                .create_persona(name)
                .map_err(|e| (-32000, e.to_string()))?;
            // development milestone: enroll the (peer_pid, persona_id) so
            // subsequent `delegate_grant` calls from this PID resolve
            // back to the persona that just claimed it.  Only applies to
            // Socket callers; Internal callers don't have a real peer
            // identity and shouldn't pollute the registry.
            if !source.is_internal()
                && let Some(peer) = &ctx.peer
                && let Some(pid) = peer.pid
            {
                enroll_pid_persona(pid, &info.id);
            }
            Ok(json!({"id": info.id, "name": info.name, "public_key": info.public_key}))
        }

        "list_personas" => {
            let personas = store
                .list_personas()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = personas
                .iter()
                .map(|p| json!({"id": p.id, "name": p.name, "status": p.status}))
                .collect();
            Ok(json!(list))
        }

        "revoke_persona" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            store
                .revoke_persona(id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"revoked": true}))
        }

        "create_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let max_uses_per_hour = params["max_uses_per_hour"].as_u64();
            let allowed_hours_start = params["allowed_hours_start"].as_u64().map(|v| v as u32);
            let allowed_hours_end = params["allowed_hours_end"].as_u64().map(|v| v as u32);
            let allowed_targets = params["allowed_targets"].as_array().map(|arr| {
                serde_json::to_string(arr).unwrap_or_default()
            });
            let max_delegation_depth = params["max_delegation_depth"].as_u64().map(|v| v as u32);

            // Evaluate policy unless force=true (human/admin bypass).
            //
            // development milestone fix: `force` is ONLY honored for in-process
            // admin/test callers (`DispatchSource::Internal`). Socket
            // callers that supply `force: true` are rejected loudly so an
            // attacker can never silently bypass the policy gate.
            let force_requested = params["force"].as_bool().unwrap_or(false);
            if force_requested && !source.is_internal() {
                return Err((
                    -32602,
                    "the 'force' parameter is not permitted on the socket API"
                        .to_string(),
                ));
            }
            let force = force_requested && source.is_internal();

            // Per-op user-presence gate. Applied BEFORE policy evaluation
            // so a locked session is rejected with a
            // re-auth message instead of being silently routed into the
            // approval queue. Internal callers + force-allowed callers
            // bypass (test harness, admin CLI, recovery flow). Quiet
            // hours apply (grant create is NOT emergency-eligible).
            if !source.is_internal() && !force {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
            }

            if !force {
                let action = format!("credential.access.{}", credential_name);
                let eval = policy.evaluate(&action);

                match eval.requirement {
                    ApprovalRequirement::Denied => {
                        return Err((-32003, format!(
                            "policy denied: {}",
                            eval.matched_rule.unwrap_or_default()
                        )));
                    }
                    ApprovalRequirement::Required => {
                        let risk_str = format!("{:?}", eval.risk).to_lowercase();
                        // PHASE-C-1-MIGRATED: trait crossing per design §3
                        let adapter = DaemonApprovalStoreRef::new(store);
                        let metadata = SubmitMetadata {
                            action: "create_grant".to_string(),
                            ttl_secs,
                            risk_level: risk_str.clone(),
                            tool_name: None,
                            target_host: None,
                            target_url: None,
                            agent_framework: None,
                        };
                        let scope_obj = core_types::approval::RequestedScope {
                            capability: scope.to_string(),
                            resource_id: None,
                            constraints: vec![],
                        };
                        let request_id = adapter
                            .submit_request(persona_id, credential_name, scope_obj, metadata)
                            .await
                            .map_err(|e| (-32000, e.to_string()))?;
                        let req = store
                            .get_approval(&request_id.0)
                            .map_err(|e| (-32000, e.to_string()))?;
                        notify_require_approval(store, &req);
                        return Ok(json!({
                            "status": "pending_approval",
                            "approval_id": request_id.0,
                            "message": "Grant creation requires approval. Use list_pending_approvals to check status."
                        }));
                    }
                    ApprovalRequirement::Auto => {
                        // Fall through to create grant
                    }
                }
            }

            let grant = store
                .create_grant(persona_id, credential_name, scope, ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;

            if max_uses_per_hour.is_some()
                || allowed_hours_start.is_some()
                || allowed_targets.is_some()
                || max_delegation_depth.is_some()
            {
                store
                    .conn()
                    .execute(
                        "UPDATE grants SET max_uses_per_hour = ?1, allowed_hours_start = ?2, allowed_hours_end = ?3, allowed_targets = ?4, max_delegation_depth = ?5 WHERE id = ?6",
                        rusqlite::params![
                            max_uses_per_hour.map(|v| v as i64),
                            allowed_hours_start.map(|v| v as i64),
                            allowed_hours_end.map(|v| v as i64),
                            allowed_targets,
                            max_delegation_depth.map(|v| v as i64),
                            grant.id,
                        ],
                    )
                    .map_err(|e| (-32000, e.to_string()))?;
            }

            let _ = store.log_event(
                Some(persona_id),
                "grant.issued",
                Some(credential_name),
                "allowed",
                Some(&serde_json::json!({
                    "grant_id": grant.id,
                    "scope": scope,
                    "ttl_secs": ttl_secs,
                    "allowed_targets": params["allowed_targets"],
                }).to_string()),
            );

            Ok(json!({
                "id": grant.id,
                "expires_at": grant.expires_at,
                "conditions": {
                    "max_uses_per_hour": max_uses_per_hour,
                    "allowed_hours": if allowed_hours_start.is_some() {
                        Some(format!("{}:00-{}:00 UTC", allowed_hours_start.unwrap_or(0), allowed_hours_end.unwrap_or(0)))
                    } else { None },
                    "allowed_targets": params["allowed_targets"].as_array(),
                    "max_delegation_depth": max_delegation_depth,
                }
            }))
        }

        "delegate_grant" => {
            let parent_grant_id = params["parent_grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'parent_grant_id'".to_string()))?;
            let child_persona_id = params["child_persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'child_persona_id'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            // Optional child budget — when present, `delegate_grant_full`
            // enforces offline attenuation (child ≤ parent − usage on every
            // axis). When absent we fall back to the no-budget shape so
            // callers that don't set budgets keep working.
            let child_budget: Option<core_types::Budget> = if params["budget"].is_object() {
                Some(serde_json::from_value(params["budget"].clone())
                    .map_err(|e| (-32602, format!("invalid 'budget': {e}")))?)
            } else {
                None
            };
            // implementation-note-91: load via DaemonGrantStore to obtain
            // core_grants::Grant at the state-machine boundary. Ownership
            // checks below use `parent_grant.issuer.0` (persona_id) directly.
            // TODO: delegate_grant log_event credential_name
            // — not present in core_grants::Grant; requires a lookup helper.
            let parent_grant = store
                .grant_store()
                .load_grant(parent_grant_id)
                .map_err(|e| (-32000, e.to_string()))?;

            // development milestone — full principal binding.
            //
            // The defense-in-depth check from development milestone (prior change) was
            // a useful loud-fail for benign mis-use but did not prove the
            // caller WAS the claimed persona — `caller_persona_id` was
            // attacker-controlled. Full principal binding closes that gap
            // by deriving the caller's persona from the kernel-supplied
            // peer credential (`SO_PEERCRED` / `LOCAL_PEERCRED`) on the
            // Unix socket and rejecting any request whose params claim a
            // different persona.
            //
            // Resolution order for the calling principal:
            //   1. `ctx.principal` — pre-resolved by tests or future
            //      session-ticket binding (Phase 2).
            //   2. `peercred_principal(&ctx.peer)` — looks up the peer's
            //      PID in the daemon's enrollment registry. Populated by
            //      `create_persona` calls from the same PID. On macOS
            //      where pid is `None`, fail-closed with
            //      `PrincipalUnavailable`.
            //   3. Legacy fallback: when no peer credential is available
            //      (e.g. older callers using `dispatch_method_with_events`
            //      without a peer), fall back to the param-asserted
            //      ownership check from prior change.
            //
            // `Internal` source (admin CLI, test harness, recovery)
            // bypasses — mirrors development milestone pattern.
            if !source.is_internal() {
                // First try kernel-derived principal binding.
                let kernel_principal: Option<String> = match (&ctx.principal, &ctx.peer) {
                    (Some(p), _) => Some(p.clone()),
                    (None, Some(peer)) => match peercred_principal(peer) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::warn!(
                                error = ?e,
                                pid = ?peer.pid,
                                uid = peer.uid,
                                parent_grant_id = %parent_grant_id,
                                "rejecting delegate_grant: principal binding failed"
                            );
                            return Err(e.to_jsonrpc());
                        }
                    },
                    (None, None) => None,
                };

                match kernel_principal {
                    Some(principal) => {
                        // Optional `caller_persona_id` in params, when
                        // present, must match the kernel-derived principal.
                        // Attacker-supplied mismatch is rejected.
                        if let Some(asserted) = params["caller_persona_id"].as_str()
                            && asserted != principal
                        {
                            tracing::warn!(
                                asserted_persona_id = %asserted,
                                kernel_persona_id = %principal,
                                parent_grant_id = %parent_grant_id,
                                "rejecting delegate_grant: params.caller_persona_id \
                                 does not match kernel-derived principal"
                            );
                            return Err(HandlerError::PrincipalMismatch.to_jsonrpc());
                        }
                        // Kernel-derived principal must own the parent grant.
                        // implementation-note-91: compare against issuer.0 (core_grants::PrincipalId).
                        if principal != parent_grant.issuer.0 {
                            tracing::warn!(
                                kernel_persona_id = %principal,
                                parent_grant_id = %parent_grant_id,
                                parent_owner_persona_id = %parent_grant.issuer.0,
                                "rejecting delegate_grant: kernel-derived principal \
                                 does not own parent grant"
                            );
                            return Err((
                                -32002,
                                "delegate_grant: caller does not own parent grant"
                                    .to_string(),
                            ));
                        }
                    }
                    None => {
                        // Legacy fallback: no peer credential available
                        // (older socket entry points, missing kernel
                        // surface). Fall back to the param-asserted check
                        // — strictly weaker than principal binding but
                        // preserves backward compat for callers that
                        // haven't been migrated.
                        let caller_persona_id = params["caller_persona_id"]
                            .as_str()
                            .ok_or((
                                -32602,
                                "missing 'caller_persona_id': socket callers must \
                                 assert the persona delegating the parent grant"
                                    .to_string(),
                            ))?;
                        // implementation-note-91: compare against issuer.0.
                        if caller_persona_id != parent_grant.issuer.0 {
                            tracing::warn!(
                                caller_persona_id = %caller_persona_id,
                                parent_grant_id = %parent_grant_id,
                                parent_owner_persona_id = %parent_grant.issuer.0,
                                "rejecting delegate_grant: caller does not own parent grant"
                            );
                            return Err((
                                -32002,
                                "delegate_grant: caller does not own parent grant"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }

            let grant = store
                .delegate_grant_full(
                    parent_grant_id,
                    child_persona_id,
                    scope,
                    ttl_secs,
                    child_budget,
                )
                .map_err(|e| (-32000, e.to_string()))?;
            // TODO: delegate_grant credential_name not in core_grants::Grant;
            // audit logs emit None here until a lookup helper is added. The parent_grant_id
            // in the JSON body lets operators reconstruct the credential from the grant record.
            let _ = store.log_event(
                Some(child_persona_id),
                "grant.delegated",
                None,
                "allowed",
                Some(&serde_json::json!({
                    "parent_grant_id": parent_grant_id,
                    "child_grant_id": grant.id,
                    "child_persona_id": child_persona_id,
                    "scope": scope,
                }).to_string()),
            );
            Ok(json!({
                "id": grant.id,
                "scope": grant.scope,
                "parent": parent_grant_id,
                "expires_at": grant.expires_at,
                "budget": grant.budget,
            }))
        }

        "list_grants" => {
            // persona_id is required — the local socket is not yet authenticated,
            // so we refuse to enumerate grants across personas without an explicit
            // narrowing filter. Cross-persona enumeration would be a local info
            // disclosure. The agent runtime forwards its own persona_id, so the
            // MCP path stays functional; only bare socket callers are refused.
            //
            // Response shape per design: each entry also carries a
            // `statement_count` and a `statements` array with per-Statement
            // `sid`, `resource_type`, `actions`, `resource`, `budget`, and
            // `usage`. Clients can render per-Statement meters natively.
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let grants = store
                .list_active_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .filter(|g| g.persona_id == persona_id)
                .map(|g| {
                    let statements: Vec<Value> = match store.get_access_grant(&g.id) {
                        Ok(chain) => chain
                            .statements()
                            .map(|(bi, s)| {
                                json!({
                                    "sid": s.sid,
                                    "block_index": bi,
                                    "resource_type": s.resource_type.as_str(),
                                    "actions": s.actions,
                                    "resource": s.resource,
                                    "budget": s.budget,
                                    "usage": s.usage,
                                    "conditions": s.conditions,
                                })
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    json!({
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "expires_at": g.expires_at,
                        "status": g.status,
                        "statement_count": statements.len(),
                        "statements": statements,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "revoke_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            // implementation-note-91: load via DaemonGrantStore for issuer.
            // credential_name lives on GrantInfo (the SQL row projection),
            // not on core_grants::Grant — fetch both so the audit row carries
            // the credential identity.
            let core_grant = store.grant_store().load_grant(id).ok();
            let grant_info = store.get_grant(id).ok();
            let grant_persona = core_grant.as_ref().map(|g| g.issuer.0.clone());
            let grant_credential = grant_info.as_ref().map(|g| g.credential_name.clone());
            store
                .revoke_grant(id)
                .map_err(|e| (-32000, e.to_string()))?;

            // v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
            // Emit a signed v2 cohort-A Receipt with ExplicitRevoke for H1
            // coverage. Grant may have no live session; use a synthetic
            // session_id derived from the grant_id so the Receipt envelope is
            // well-formed (spec option (a)).
            let synthetic_session_id = format!("grant:{id}");
            if let Some(identity) = current_identity() {
                let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
                match issue_cohort_a_receipt(
                    &synthetic_session_id,
                    Vec::new(),
                    None,
                    TerminationAuthority::DaemonPersona,
                    &identity.pubkey_hex(),
                    Some(TerminationMeta {
                        reason: TerminationReason::ExplicitRevoke,
                        last_heartbeat_at: None,
                        pid_alive_at_check: None,
                    }),
                    &signer,
                ) {
                    Ok(envelope) => {
                        // Persist the Receipt sidecar if a sessions_dir is
                        // available. Best-effort: a write failure does not
                        // abort the revocation itself.
                        if let Some(sessions_dir) = &ctx.sessions_dir {
                            let receipt_dir = sessions_dir.join(&synthetic_session_id);
                            let _ = std::fs::create_dir_all(&receipt_dir);
                            let receipt_path = receipt_dir.join("receipt.json");
                            if let Ok(bytes) = serde_json::to_vec_pretty(&envelope) {
                                if let Err(e) = std::fs::write(&receipt_path, &bytes) {
                                    tracing::warn!(
                                        grant_id = %id,
                                        path = %receipt_path.display(),
                                        error = %e,
                                        "revoke_grant: failed to persist v2 Receipt sidecar"
                                    );
                                }
                            }
                        }
                        tracing::info!(
                            grant_id = %id,
                            receipt_id = %envelope.receipt_id,
                            "revoke_grant: signed v2 cohort-A Receipt emitted (ExplicitRevoke)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            grant_id = %id,
                            error = %e,
                            "revoke_grant: failed to issue v2 cohort-A Receipt — revocation still committed"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    grant_id = %id,
                    "revoke_grant: daemon identity not initialised — skipping v2 Receipt emission"
                );
            }

            // Push revocation notification (best-effort, queued for polling)
            if let Some(persona_id) = &grant_persona {
                let _ = store.push_notification(
                    persona_id,
                    "grant.revoked",
                    &json!({"grant_id": id}),
                );
            }
            // Log the revocation event.
            let _ = store.log_event(
                core_grant.as_ref().map(|g| g.issuer.0.as_str()),
                "grant.revoked",
                grant_credential.as_deref(),
                "allowed",
                Some(&serde_json::json!({"grant_id": id}).to_string()),
            );
            // Broadcast GRANT_REVOKED over the unix socket so connected agents
            // can zeroize cached credentials without waiting on polling.
            if let (Some(tx), Some(persona_id)) = (events_tx, grant_persona) {
                let event = GrantEvent::Revoked {
                    grant_id: id.to_string(),
                    persona_id: persona_id.clone(),
                };
                // send() returns Err only when there are no active subscribers,
                // which is expected at startup; ignore the result.
                let _ = tx.send(event);
                tracing::info!(grant_id = %id, "broadcasting grant revocation to connected agents");
            }
            Ok(json!({"revoked": true}))
        }

        // implementation-note-92 — revoke a single Statement
        // within a composite grant. The grant remains active; only requests
        // resolving to the named sid are denied at the proxy + use_credential
        // boundaries.
        "revoke_statement" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let sid = params["statement_sid"]
                .as_str()
                .ok_or((-32602, "missing 'statement_sid'".to_string()))?;
            store
                .revoke_grant_statement(grant_id, sid)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => (-32004, format!("grant {grant_id} not found")),
                    other => (-32000, other.to_string()),
                })?;
            Ok(json!({
                "status": "revoked",
                "grant_id": grant_id,
                "statement_sid": sid,
            }))
        }

        "evaluate_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let grant = store
                .evaluate_grant(persona_id, credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": grant.id, "scope": grant.scope, "expires_at": grant.expires_at}))
        }

        "use_credential" => {
            // Read-class — bump session activity so an active agent keeps
            // the vault unlocked, but do NOT prompt
            // for biometric (would spam the user every credential read).
            presence::record_activity();
            // Two calling conventions:
            //   1. `{persona_id, credential_name}` — classic vault lookup.
            //   2. `{grant_id, persona_id?}` — agent runtime flow. Looks up
            //      the grant by id and derives persona+credential from it.
            //      When the caller also supplies `persona_id`, it MUST match
            //      the grant's persona — this prevents grant-id guessing
            //      cross-persona reads via a leaked id.
            //
            // TODO: GrantInfo retained for use_credential resolved_grant
            // — grant.id (as "grant-{uuid}" string), grant.scope (as string), and
            // grant.credential_name are not present in core_grants::Grant.
            // State/issuer checks already use core_grants (migrated in PHASE-C-3A).
            // Full migration requires adding credential_name to core_grants::Grant
            // or a dedicated lookup helper.
            let (persona_id, credential_name, resolved_grant): (String, String, Option<crate::trust::grant::GrantInfo>) =
                if let Some(grant_id) = params["grant_id"].as_str() {
                    // Load core_grants::Grant for state-machine checks (implementation-note-91).
                    let core_grant = store
                        .grant_store()
                        .load_grant(grant_id)
                        .map_err(|e| match e {
                            crate::infra::store::StoreError::NotFound => {
                                (-32004, format!("grant {grant_id} not found"))
                            }
                            other => (-32000, other.to_string()),
                        })?;
                    if core_grant.state != CoreGrantState::Active {
                        return Err((
                            -32005,
                            format!("grant {grant_id} is not active and cannot be used"),
                        ));
                    }
                    if let Some(caller_persona) = params["persona_id"].as_str()
                        && caller_persona != core_grant.issuer.0
                    {
                        return Err((
                            -32002,
                            "grant belongs to a different persona".to_string(),
                        ));
                    }
                    // TODO: GrantInfo still needed for credential_name, id (string), scope (string).
                    let grant = store
                        .get_grant(grant_id)
                        .map_err(|e| match e {
                            crate::infra::store::StoreError::NotFound => {
                                (-32004, format!("grant {grant_id} not found"))
                            }
                            other => (-32000, other.to_string()),
                        })?;
                    // implementation-note-93: when the caller passes
                    // both grant_id AND credential_name, honor the caller's
                    // value if it's bound to a Credential Statement on the
                    // grant's chain. Composite grants carry multiple
                    // credential statements (e.g. anthropic-key + github-token);
                    // returning grant.credential_name unconditionally would
                    // hand back the grant's primary cred regardless of what
                    // the caller asked for, breaking per-statement isolation.
                    let resolved_cred_name = if let Some(caller_cred) =
                        params["credential_name"].as_str()
                    {
                        let chain = store
                            .get_access_grant(&grant.id)
                            .map_err(|e| (-32000, e.to_string()))?;
                        let bound = chain.statements().any(|(_idx, stmt)| {
                            stmt.resource_type == core_types::ResourceType::Credential
                                && match &stmt.resource {
                                    core_types::ResourceSelector::Exact { value } => {
                                        value == caller_cred
                                    }
                                    _ => false,
                                }
                        });
                        if !bound {
                            return Err((
                                -32007,
                                format!(
                                    "credential '{caller_cred}' is not bound to any statement on grant {}",
                                    grant.id
                                ),
                            ));
                        }
                        caller_cred.to_string()
                    } else {
                        grant.credential_name.clone()
                    };
                    (
                        grant.persona_id.clone(),
                        resolved_cred_name,
                        Some(grant),
                    )
                } else {
                    let persona_id = params["persona_id"]
                        .as_str()
                        .ok_or((-32602, "missing 'persona_id'".to_string()))?;
                    let credential_name = params["credential_name"]
                        .as_str()
                        .ok_or((-32602, "missing 'credential_name'".to_string()))?;
                    (persona_id.to_string(), credential_name.to_string(), None)
                };

            // Check grant exists and is active (redundant for the grant_id
            // branch but cheap — preserves single-path-through-evaluate
            // semantics for the classic branch).
            let grant = if let Some(g) = resolved_grant {
                g
            } else {
                store
                    .evaluate_grant(&persona_id, &credential_name)
                    .map_err(|e| (-32000, format!("no active grant: {e}")))?
            };

            // implementation-note-92 — block credential reads
            // when the Credential Statement that authorizes THIS specific
            // credential_name has been revoked. The previous shape blocked
            // ALL credential reads if ANY credential statement was revoked,
            // collapsing per-statement isolation; composite grants need
            // each credential statement to fail independently.
            let revoked_sids = store
                .get_revoked_sids(&grant.id)
                .map_err(|e| (-32000, e.to_string()))?;
            if !revoked_sids.is_empty()
                && let Ok(chain) = store.get_access_grant(&grant.id)
            {
                for (_idx, stmt) in chain.statements() {
                    let matches_this_credential = stmt.resource_type
                        == core_types::ResourceType::Credential
                        && match &stmt.resource {
                            core_types::ResourceSelector::Exact { value } => {
                                value == &credential_name
                            }
                            _ => false,
                        };
                    if matches_this_credential && revoked_sids.contains(&stmt.sid) {
                        let _ = store.log_event(
                            Some(&persona_id),
                            "credential.access",
                            Some(&credential_name),
                            "denied_statement_revoked",
                            Some(&format!(
                                "grant_id={} sid={}",
                                grant.id, stmt.sid
                            )),
                        );
                        return Err((-32006, "statement revoked".to_string()));
                    }
                }
            }

            // Record usage (enforces rate limits).
            store
                .record_grant_usage(&grant.id)
                .map_err(|e| (-32000, e.to_string()))?;
            // Retrieve the credential value.
            let value = vault
                .get(store, &credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            // Log the access.
            let _ = store.log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "allowed",
                None,
            );
            let text = String::from_utf8_lossy(&value);
            Ok(json!({
                "credential": text,
                "grant_id": grant.id,
                "credential_name": credential_name,
                "scope": grant.scope,
            }))
        }

        "vault_add" => {
            // Per-op user-presence gate. Internal callers (admin CLI /
            // test harness) bypass — same trust model as
            // development milestone force-flag handling.
            if !source.is_internal() {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultAdd, override_qh)?;
            }
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            let value = params["value"]
                .as_str()
                .ok_or((-32602, "missing 'value'".to_string()))?;
            let metadata = params["metadata"].as_str();
            let info = vault
                .add(store, name, value.as_bytes(), metadata)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": info.id, "name": info.name}))
        }

        "vault_remove" => {
            // High-risk write — gated. Emergency-eligible
            // (vault_remove revokes access; we'd rather let the user shut
            // down a leaked credential mid-quiet-hours than block them).
            if !source.is_internal() {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultRemove, override_qh)?;
            }
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            vault
                .remove(store, name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true, "name": name}))
        }

        "vault_lock" => {
            // Explicit re-lock. Always allowed (the user
            // is reducing privilege, not escalating). Internal/socket
            // both honored — `ember vault lock` may dispatch this.
            presence::lock();
            Ok(json!({"locked": true}))
        }

        "vault_status" => {
            // Lightweight diagnostic — read-class, never
            // prompts. Used by dashboards to show "session unlocked: 3m
            // idle" without forcing a biometric every refresh.
            presence::record_activity();
            let (unlocked, idle_secs) = presence::snapshot();
            let cfg = presence::current_config();
            Ok(json!({
                "unlocked": unlocked,
                "idle_secs": idle_secs,
                "idle_timeout_secs": cfg.idle_timeout.as_secs(),
                "quiet_hours_start": cfg.quiet_hours_start,
                "quiet_hours_end": cfg.quiet_hours_end,
            }))
        }

        "vault_migrate_acl" => {
            presence::record_activity();
            let service = params["service"]
                .as_str()
                .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_SERVICE);
            let account = params["account"]
                .as_str()
                .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_ACCOUNT);
            let result = crate::infra::vault::migrate_mek_acl(service, account)
                .map_err(|e| (-32000, e.to_string()))?;
            let _ = store.log_event(
                None,
                "vault.mek_acl_migrated",
                None,
                "ok",
                Some(&format!(
                    "before={} after={} service={} account={}",
                    result.before_acl_kind, result.after_acl_kind, result.service, result.account
                )),
            );
            Ok(json!({
                "before_acl_kind": result.before_acl_kind,
                "after_acl_kind": result.after_acl_kind,
                "service": result.service,
                "account": result.account,
            }))
        }

        "vault_list" => {
            // Read-class: bump activity, never prompt.
            presence::record_activity();
            let creds = vault.list(store).map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = creds
                .iter()
                .map(|c| json!({"id": c.id, "name": c.name, "metadata": c.metadata}))
                .collect();
            Ok(json!(list))
        }

        "vault_get" => {
            // Read-class: bump activity, never prompt. Returns the
            // plaintext credential value to the caller. Never log the
            // value — only the lookup name (security invariant —
            // see `feedback_never_print_vault_secrets` and the
            // 2026-04-27 CF token leak post-mortem).
            presence::record_activity();
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;

            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Attempt retrieval — emit a typed VaultReceipt on both success
            // and failure so the audit trail is never silent.
            let result = vault.get(store, name);
            let (outcome, error) = match &result {
                Ok(_) => (ReceiptOutcome::Success, None),
                Err(e) => (ReceiptOutcome::Failure, Some(e.to_string())),
            };

            let mut receipt = VaultReceipt {
                id: format!("rct-vault-{}", uuid::Uuid::new_v4()),
                kind: ReceiptKind::VaultRetrieval,
                key_name: name.to_string(),
                caller_persona: "unknown".to_string(),
                materialized_at_epoch_secs: now_epoch,
                grant_evaluation: GrantEvaluation {
                    outcome: GrantEvaluationOutcome::Denied,
                    grant_id: None,
                },
                outcome,
                evidence: Evidence::default(),
            };
            if let Some(identity) = current_identity() {
                sign_vault_receipt(&mut receipt, identity);
            }
            if let Err(e) = store.store_vault_receipt(&receipt) {
                tracing::warn!(
                    error = %e,
                    key_name = %name,
                    receipt_id = %receipt.id,
                    "vault_get: failed to persist typed VaultReceipt"
                );
            }

            match result {
                Ok(value) => {
                    tracing::info!(name = %name, "vault_get: credential fetched");
                    let text = String::from_utf8_lossy(&value).into_owned();
                    Ok(json!({"value": text}))
                }
                Err(e) => {
                    if let Some(reason) = error {
                        tracing::warn!(name = %name, error = %reason, "vault_get: retrieval failed");
                    }
                    Err((-32000, e.to_string()))
                }
            }
        }

        "audit_query" => {
            let agent_id = params["agent_id"].as_str().map(String::from);
            let limit = params["limit"].as_u64().map(|l| l as usize);
            let filter = AuditFilter {
                agent_id,
                limit,
                ..Default::default()
            };
            let entries = store
                .query_audit(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "agent_id": e.agent_id,
                        "action": e.action,
                        "credential": e.credential,
                        "outcome": e.outcome,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        // EMBER-implementation-note-94: unified receipt query — supports the full
        // `ReceiptFilter` shape (actor/kind/grant_id/since/resource/limit).
        // The `ember audit query` CLI path calls this via JSON-RPC socket.
        "receipt_query" => {
            let filter = crate::infra::receipt::ReceiptFilter {
                persona_id: params["actor"].as_str().map(String::from),
                kind: params["kind"].as_str().map(String::from),
                grant_id: params["grant_id"].as_str().map(String::from),
                resource: params["resource"].as_str().map(String::from),
                since_iso: params["since"].as_str().map(String::from),
                limit: params["limit"].as_u64(),
                ..Default::default()
            };
            let rows = store
                .query_receipts(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = rows
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "submit_approval" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let risk_level = params["risk_level"]
                .as_str()
                .ok_or((-32602, "missing 'risk_level'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs,
                risk_level: risk_level.to_string(),
                tool_name: params["tool_name"].as_str().map(str::to_owned),
                target_host: params["target_host"].as_str().map(str::to_owned),
                target_url: params["target_url"].as_str().map(str::to_owned),
                agent_framework: params["agent_framework"].as_str().map(str::to_owned),
            };
            let scope_obj = core_types::approval::RequestedScope {
                capability: scope.to_string(),
                resource_id: None,
                constraints: vec![],
            };
            let request_id = adapter
                .submit_request(persona_id, credential_name, scope_obj, metadata)
                .await
                .map_err(|e| (-32000, e.to_string()))?;
            let req = store
                .get_approval(&request_id.0)
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({"id": request_id.0, "status": req.status}))
        }

        // implementation-note-95 — submit a composite approval that bundles
        // an N-Statement envelope. On `Approved`, the resolver mints a single
        // composite grant whose `blocks_json` carries the full statement
        // chain. Wraps the already-shipped `DaemonStore::propose_grant`.
        "propose_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let risk_level = params["risk_level"]
                .as_str()
                .ok_or((-32602, "missing 'risk_level'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let stmts_value = params["statements"]
                .as_array()
                .ok_or((-32602, "missing 'statements' array".to_string()))?;
            let mut statements: Vec<core_types::Statement> =
                Vec::with_capacity(stmts_value.len());
            for v in stmts_value {
                let s: core_types::Statement = serde_json::from_value(v.clone())
                    .map_err(|e| (-32602, format!("invalid statement: {e}")))?;
                statements.push(s);
            }
            if statements.is_empty() {
                return Err((-32602, "statements must not be empty".to_string()));
            }
            // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — per ADR
            // 135 §4 every composite-grant action key must be DID-prefixed
            // (`did:<method>:<rest>`). Reject bare keys at the parse-time
            // gate so the RPC entry point is the migration enforcement point;
            // the error message includes the recommended `did:ember:<key>`
            // form so authors can migrate without consulting docs. Forward-
            // compat: arbitrary `did:<method>:` prefixes pass even though
            // v0.3.0's broker.resolve only routes `did:ember:`.
            crate::trust::grant::validate_action_keys_did_prefixed(&statements)
                .map_err(|e| (-32602, e.to_string()))?;
            // approval_notify_fields_persisted — use the with_notify variant so
            // tool_name / target_host / target_url / agent_framework land in the DB
            // (not just in the returned struct) for subsequent get_approval calls.
            let req = store
                .propose_grant_with_notify(
                    persona_id,
                    credential_name,
                    scope,
                    ttl_secs,
                    action,
                    risk_level,
                    statements,
                    params["tool_name"].as_str().map(str::to_owned),
                    params["target_host"].as_str().map(str::to_owned),
                    params["target_url"].as_str().map(str::to_owned),
                    params["agent_framework"].as_str().map(str::to_owned),
                )
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({
                "approval_id": req.id,
                "id": req.id,
                "status": req.status,
                "statement_count": req.composite_statements.as_ref().map(|v| v.len()).unwrap_or(0),
            }))
        }

        "list_pending_approvals" => {
            let requests = store
                .list_pending_approvals()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = requests
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "persona_id": r.persona_id,
                        "credential_name": r.credential_name,
                        "action": r.action,
                        "risk_level": r.risk_level,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "grant_status" => {
            // Look up by id. The agent protocol passes a single id that may
            // refer to either a live grant (`grant-*`) OR a pending approval
            // request (`approval-*`). Returning both shapes under one method
            // lets clients poll a `request_grant` response through to the
            // issued grant without having to switch RPC methods.
            //
            // The shape is kept wire-compatible with the agent runtime's
            // existing `GrantInfo` + `RequestGrantResponse`: callers parse
            // `kind == "grant"` for grant info or `kind == "approval"` for
            // an approval-request status.
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            // Optional: callers can pin the expected persona so a lost id
            // cannot be used to leak status for another agent's grant.
            let expected_persona = params["persona_id"].as_str();

            // implementation-note-96: if the caller is observing a
            // grant whose effective (wall-clock-projected) status is terminal
            // but whose stored status is still `active`, flip the row + emit
            // the signed receipt right now. Without this, the runner's
            // `grant_status` poll sees terminal via `effective_status` but
            // the receipt only lands on the next 60-second sweep tick — every
            // receipt-aware check (live receipts panel, dashboard SSE, offline
            // verify) would race the sweep. Best-effort: a failure here logs
            // but doesn't fail the read.
            if let Err(e) = store.expire_grant_if_terminal_now(id) {
                tracing::warn!(
                    grant_id = %id,
                    error = ?e,
                    "expire_grant_if_terminal_now failed; proceeding with stored status"
                );
            }

            // Try grant first.
            match store.get_grant(id) {
                Ok(g) => {
                    if let Some(pid) = expected_persona
                        && g.persona_id != pid
                    {
                        return Err((-32002, "grant belongs to a different persona".to_string()));
                    }
                    // Emit per-Statement array for composite callers
                    // (design). V0 schema: no envelope-level `budget` /
                    // `usage` projection — consumers read per-Statement
                    // fields from the `statements` array.
                    let statements: Vec<Value> = match store.get_access_grant(id) {
                        Ok(chain) => chain
                            .statements()
                            .map(|(bi, s)| {
                                json!({
                                    "sid": s.sid,
                                    "block_index": bi,
                                    "resource_type": s.resource_type.as_str(),
                                    "actions": s.actions,
                                    "resource": s.resource,
                                    "budget": s.budget,
                                    "usage": s.usage,
                                    "conditions": s.conditions,
                                })
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    // implementation-note-92 — surface the
                    // per-Statement revocation list so callers can render
                    // strikethrough on individual sids without polling a
                    // separate endpoint.
                    let revoked_sids = store
                        .get_revoked_sids(&g.id)
                        .unwrap_or_default();
                    return Ok(json!({
                        "kind": "grant",
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "status": g.status,
                        "expires_at": g.expires_at,
                        "created_at": g.created_at,
                        "statements": statements,
                        "statement_count": statements.len(),
                        "revoked_sids": revoked_sids,
                    }));
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    // Fall through to approval lookup.
                }
                Err(e) => return Err((-32000, e.to_string())),
            }

            match store.get_approval(id) {
                Ok(a) => {
                    if let Some(pid) = expected_persona
                        && a.persona_id != pid
                    {
                        return Err((-32002, "approval belongs to a different persona".to_string()));
                    }
                    Ok(json!({
                        "kind": "approval",
                        "id": a.id,
                        "persona_id": a.persona_id,
                        "credential_name": a.credential_name,
                        "scope": a.scope,
                        "status": a.status,
                        "action": a.action,
                        "risk_level": a.risk_level,
                    }))
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    Err((-32004, format!("grant or approval {id} not found")))
                }
                Err(e) => Err((-32000, e.to_string())),
            }
        }

        "extend_grant" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let add_tokens = params["add_tokens"].as_u64();
            let add_cents = params["add_cents"].as_u64();
            let add_ttl_secs = params["add_ttl_secs"].as_u64();
            let updated = store
                .extend_grant(grant_id, add_tokens, add_cents, add_ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "grant_id": updated.id,
                "expires_at": updated.expires_at,
                "budget": updated.budget,
            }))
        }

        "request_access" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();

            // Pre-evaluation rate limit check (#69C.4). Runs before standing
            // grant lookup and policy evaluation. On rejection the response
            // intentionally avoids disclosing which rule would have matched —
            // only the rate-limit fact is surfaced.
            if !rate_limiter.borrow_mut().check_action(persona_id, action) {
                return Ok(json!({
                    "status": "denied",
                    "decision": "deny",
                    "reason": "rate_spike",
                }));
            }

            // Check standing grants first
            if store.check_standing_grant(persona_id, action).map_err(|e| (-32000, e.to_string()))? {
                let grant = store
                    .create_grant(persona_id, credential_name, scope, ttl_secs)
                    .map_err(|e| (-32000, e.to_string()))?;
                let _ = store.log_event(
                    Some(persona_id),
                    "grant.issued",
                    Some(credential_name),
                    "allowed",
                    Some(&serde_json::json!({
                        "grant_id": grant.id,
                        "scope": scope,
                        "ttl_secs": ttl_secs,
                        "source": "standing_grant",
                    }).to_string()),
                );
                return Ok(json!({
                    "status": "approved",
                    "source": "standing_grant",
                    "grant_id": grant.id,
                }));
            }

            let eval = policy.evaluate(action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();

            match eval.requirement {
                ApprovalRequirement::Auto => {
                    let grant = store
                        .create_grant(persona_id, credential_name, scope, ttl_secs)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(credential_name),
                        "allowed",
                        Some(&serde_json::json!({
                            "grant_id": grant.id,
                            "scope": scope,
                            "ttl_secs": ttl_secs,
                            "source": "request_access",
                        }).to_string()),
                    );
                    Ok(json!({
                        "status": "approved",
                        "grant_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }))
                }
                ApprovalRequirement::Required => {
                    // PHASE-C-1-MIGRATED: trait crossing per design §3
                    let adapter = DaemonApprovalStoreRef::new(store);
                    let metadata = SubmitMetadata {
                        action: action.to_string(),
                        ttl_secs,
                        risk_level: risk_str.clone(),
                        tool_name: params["tool_name"].as_str().map(str::to_owned),
                        target_host: params["target_host"].as_str().map(str::to_owned),
                        target_url: params["target_url"].as_str().map(str::to_owned),
                        agent_framework: params["agent_framework"].as_str().map(str::to_owned),
                    };
                    let scope_obj = core_types::approval::RequestedScope {
                        capability: scope.to_string(),
                        resource_id: None,
                        constraints: vec![],
                    };
                    let request_id = adapter
                        .submit_request(persona_id, credential_name, scope_obj, metadata)
                        .await
                        .map_err(|e| (-32000, e.to_string()))?;
                    let req = store
                        .get_approval(&request_id.0)
                        .map_err(|e| (-32000, e.to_string()))?;
                    notify_require_approval(store, &req);
                    Ok(json!({
                        "status": "pending",
                        "approval_id": request_id.0,
                        "decision": "require_approval",
                        "risk": risk_str,
                    }))
                }
                ApprovalRequirement::Denied => Ok(json!({
                    "status": "denied",
                    "decision": "deny",
                    "risk": risk_str,
                    "reason": format!(
                        "policy denies action: {}",
                        eval.matched_rule.unwrap_or_default()
                    ),
                })),
            }
        }

        // implementation-note-18: block-and-poll RPC for the proxy hook approval round-trip.
        //
        // Polls `get_approval(request_id)` every 500ms up to `timeout_secs`. On
        // first non-pending state -> return the matching `ApprovalDecision`. On
        // deadline -> `TimedOut`. The approval row itself is created elsewhere
        // (`submit_approval` via `request_access` / `evaluate_tool_call`); this
        // arm only awaits resolution.
        //
        // Defaults: `timeout_secs = 300` (5 min) when omitted, matching the
        // proxy hook's `call_daemon_await_approval` default. A configurable
        // EmberConfig surface is out of scope for implementation-note-18 — file as
        // follow-up if operators need per-deployment tuning.
        //
        // TODO: T2 integration test with simulated dashboard
        // tap (separate process resolves the approval mid-poll). For this PR
        // the unit tests below cover the three resolution paths.
        "await_approval" => {
            let request_id = params["request_id"]
                .as_str()
                .ok_or((-32602, "missing 'request_id' parameter".to_string()))?
                .to_string();
            let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

            loop {
                let info = store
                    .get_approval(&request_id)
                    .map_err(|e| match e {
                        crate::infra::store::StoreError::NotFound => {
                            (-32004, format!("approval {request_id} not found"))
                        }
                        other => (-32000, other.to_string()),
                    })?;

                let decision_json: Option<Value> = match info.status.as_str() {
                    "pending" => None,
                    "approved" | "narrowed" | "narrowed_and_approved" => {
                        Some(json!({"decision": {"kind": "approved"}}))
                    }
                    "denied" | "dismissed" => Some(json!({
                        "decision": {
                            "kind": "denied",
                            "reason": info
                                .reason
                                .clone()
                                .unwrap_or_else(|| format!("approval {}", info.status)),
                        }
                    })),
                    "timed_out" | "expired" => {
                        Some(json!({"decision": {"kind": "timed_out"}}))
                    }
                    other => Some(json!({
                        "decision": {
                            "kind": "denied",
                            "reason": format!("unknown approval status: {other}"),
                        }
                    })),
                };

                if let Some(v) = decision_json {
                    return Ok(v);
                }

                if tokio::time::Instant::now() >= deadline {
                    return Ok(json!({"decision": {"kind": "timed_out"}}));
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        "request_access_blocking" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let resource = params["resource"].as_str().unwrap_or("");
            let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

            let eval = policy.evaluate(action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();

            match eval.requirement {
                ApprovalRequirement::Auto => {
                    let grant = store
                        .create_grant(persona_id, resource, "auto", None)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(resource),
                        "allowed",
                        Some(&serde_json::json!({
                            "grant_id": grant.id,
                            "scope": "auto",
                            "ttl_secs": null,
                            "source": "request_access_blocking",
                        }).to_string()),
                    );
                    return Ok(json!({
                        "status": "approved",
                        "approval_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }));
                }
                ApprovalRequirement::Denied => {
                    return Ok(json!({
                        "status": "denied",
                        "decision": "deny",
                        "risk": risk_str,
                        "reason": format!(
                            "policy denies action: {}",
                            eval.matched_rule.unwrap_or_default()
                        ),
                    }));
                }
                ApprovalRequirement::Required => {}
            }

            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs: None,
                risk_level: risk_str.clone(),
                tool_name: None,
                target_host: None,
                target_url: None,
                agent_framework: None,
            };
            let scope_obj = core_types::approval::RequestedScope {
                capability: String::new(),
                resource_id: None,
                constraints: vec![],
            };
            let request_id = adapter
                .submit_request(persona_id, resource, scope_obj, metadata)
                .await
                .map_err(|e| (-32000, e.to_string()))?;
            let approval = store
                .get_approval(&request_id.0)
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &approval);

            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
            loop {
                let pending = store
                    .list_pending_approvals()
                    .map_err(|e| (-32000, e.to_string()))?;
                let still_pending = pending.iter().any(|p| p.id == request_id.0);

                if !still_pending {
                    return Ok(json!({
                        "status": "resolved",
                        "approval_id": request_id.0,
                    }));
                }

                if std::time::Instant::now() > deadline {
                    return Ok(json!({
                        "status": "timeout",
                        "approval_id": request_id.0,
                    }));
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        "expire_grants" => {
            let count = store
                .expire_stale_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"expired_count": count}))
        }

        "grant_summary" => {
            let summary = store
                .grant_summary()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "active": summary.active,
                "expired": summary.expired,
                "revoked": summary.revoked,
            }))
        }

        "detect_anomalies" => {
            let anomalies = store.detect_anomalies()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(serde_json::to_value(&anomalies)
                .map_err(|e| (-32000, e.to_string()))?)
        }

        "create_standing_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action_pattern = params["action_pattern"]
                .as_str()
                .ok_or((-32602, "missing 'action_pattern'".to_string()))?;
            let scope = params["scope"].as_str().unwrap_or("*");
            let expires_at = params["expires_at"].as_str();
            store
                .create_standing_grant(persona_id, action_pattern, scope, expires_at)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"created": true, "action_pattern": action_pattern}))
        }

        "list_standing_grants" => {
            let grants = store.list_standing_grants().map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .map(|g| {
                    json!({"id": g.id, "persona_id": g.persona_id, "action_pattern": g.action_pattern, "scope": g.scope, "expires_at": g.expires_at})
                })
                .collect();
            Ok(Value::Array(list))
        }

        "remove_standing_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            store.remove_standing_grant(id).map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true}))
        }

        "poll_notifications" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let notifications = store
                .poll_notifications(persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(Value::Array(notifications))
        }

        "list_receipts" => {
            // Optional `persona_id` filter — returns all when omitted.
            let persona_id = params["persona_id"].as_str();
            let receipts = store
                .list_receipts(persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = receipts
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "get_receipt" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            let receipt = store
                .get_receipt(id)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("receipt {id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null))
        }

        "daemon_persona" => {
            // Expose the current Daemon Persona pubkey over the socket for
            // offline verification tools. Returns `null` when the Daemon
            // Persona was not initialised.
            match crate::infra::receipt::current_identity() {
                Some(id) => Ok(json!({
                    "pubkey": id.pubkey_hex(),
                    "canonical_version": crate::infra::receipt::CANONICAL_VERSION,
                })),
                None => Ok(Value::Null),
            }
        }

        "grant_budget_status" => {
            // Return per-Statement budget + usage + percent_used so MCP/SDK
            // clients can render a "runway" view without walking the
            // composite block chain themselves. This is a thin read-only
            // projection of `get_access_grant` + lifecycle status; the
            // proxy remains the sole writer of `usage`.
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let chain = match store.get_access_grant(grant_id) {
                Ok(c) => c,
                Err(crate::infra::store::StoreError::NotFound) => {
                    return Err((-32004, format!("grant {grant_id} not found")));
                }
                Err(e) => return Err((-32000, e.to_string())),
            };

            // Envelope status: load via DaemonGrantStore (implementation-note-91)
            // to get core_grants::Grant with a typed expires_at
            // (Option<DateTime<Utc>>) rather than an RFC3339 string from
            // GrantInfo. GrantStatus::derive is still used for the "Expired"
            // virtual status derived at query time.
            let envelope_status = match store.grant_store().load_grant(grant_id) {
                Ok(g) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let expires_epoch = g.expires_at
                        .map(|dt| dt.timestamp() as u64);
                    let status_str = match g.state {
                        CoreGrantState::Active => "active",
                        CoreGrantState::Paused => "paused",
                        CoreGrantState::Revoked => "revoked",
                    };
                    core_types::GrantStatus::derive(status_str, None, expires_epoch, now)
                        .as_str()
                        .to_string()
                }
                Err(_) => chain.status.as_str().to_string(),
            };

            let statements: Vec<Value> = chain
                .statements()
                .map(|(_bi, s)| build_statement_budget_entry(s))
                .collect();

            Ok(json!({
                "grant_id": grant_id,
                "status": envelope_status,
                "statements": statements,
            }))
        }

        // implementation-note-47 (design Phase 2): broker socket RPC arms.
        //
        // These are intentionally additive — the registry, materialization
        // tracking, Receipt-event emission, and provider-routing logic live
        // in `crate::broker_handler`. Adding them here is the minimum
        // dispatch surface so concurrent worktrees touching unrelated
        // arms don't conflict on a structural refactor of this fn.
        //
        // Marker (implementation-note-47): RPC method name "BrokerIssue" lives
        // alongside its sibling routes as the literal `broker_issue`. See
        // `broker_handler.rs` for handler bodies + tests.
        "broker_issue" => crate::broker::handler::handle_broker_issue(store, params).await,
        "broker_revoke" => crate::broker::handler::handle_broker_revoke(store, params).await,
        "broker_list" => crate::broker::handler::handle_broker_list(params).await,
        // implementation-note-9: agent processes hold an
        // opaque `SecretRef`; the trust boundary (ember-proxy /
        // ember-tools) calls `broker_resolve` to materialise the
        // plaintext credential. Stub today; full impl in
        // implementation-note-11.
        "broker_resolve" => crate::broker::handler::handle_broker_resolve(store, params).await,
        // design §"daemon-as-process-supervisor": spawn a Construct binary
        // as the daemon's child, capture exit code, emit
        // session.construct_invocation receipt. argv re-classifier deferred
        // (T-CONSTRUCT-EXEC-ARGV-CLASSIFIER).
        "broker_exec" => crate::broker::handler::handle_broker_exec(store, params).await,
        // implementation-note-97: mint a 1-hour GitHub App installation
        // token using a local-held RSA private key (design credential broker).
        // Credentials loaded from GH_APP_* env vars (placeholder until vault
        // path provisioning lands).
        "broker.mint_gh_token" => {
            crate::broker::handler::handle_broker_mint_gh_token(store, params).await
        }
        // implementation-note-53 §--inject: register a child shell PID for
        // auto-revoke when the shell exits. Spawns a background poll task that
        // watches /proc/<pid> (Linux) or kill(pid, 0) (other Unix) and calls
        // broker_revoke on all listed materialization IDs on exit.
        "broker_register_pid_watcher" => {
            crate::broker::handler::handle_broker_register_pid_watcher(store, params).await
        }

        // implementation-note-98 (design §"binding.delete"):
        // graceful delete of a SA→Persona binding. Revokes the workload
        // Persona's grants (cascade via `revoke_persona`) so in-flight
        // broker requests holding active grant references drain to
        // completion while new lookups fail. The audit log captures a
        // `binding.deleted` event keyed on `persona_id` +
        // `binding_request_id` for idempotent reconciler retries. The
        // canonical wire-form method is "binding.delete"; the
        // underscore alias mirrors the broker_* dispatch convention.
        "binding.delete" | "binding_delete" => binding_delete(store, params).await,

        // implementation-note-99 (design
        // §"binding.revoke_urgent"): compromise-response revocation.
        // Cascades the same SQL flip as `binding.delete` but tags the
        // audit row with `binding.revoke_urgent` so the operator can
        // distinguish the two lifecycle paths in the receipt + alerting
        // pipeline. Unlike `binding.delete`, the audit `outcome` is
        // `"urgent"` so downstream consumers (alerting, dashboards,
        // SOC2 evidence reports) can fire on the high-severity event
        // without re-parsing details JSON. The wire-form method
        // "binding.revoke_urgent" is canonical; the underscore alias
        // matches the broker_* convention.
        "binding.revoke_urgent" | "binding_revoke_urgent" => {
            binding_revoke_urgent(store, params).await
        }

        // implementation-note-100 (design §"binding.update"):
        // mutate metadata on an existing binding without revoking it.
        // Today the persona row only carries a mutable `name` column;
        // the broader binding-metadata fields the brief calls out
        // (`cred_class_allowlist`, `lease_duration_cap`, etc.) live in
        // the audit-log details JSON until the schema lands those
        // columns. The audit row carries a before/after snapshot so
        // the reconciler + receipt pipeline can correlate the mutation
        // with its originating `binding_request_id`. The wire-form
        // method "binding.update" is canonical; the underscore alias
        // mirrors the broker_* dispatch convention.
        "binding.update" | "binding_update" => binding_update(store, params).await,

        // implementation-note-101 (design §"binding.upsert"):
        // idempotent insert-or-update for the SA→Persona binding
        // surface used by `ember-kernel`'s EmberServiceAccount
        // reconciler. Replaces the placeholder "method not found"
        // fallback that today causes the reconciler to log a stub-
        // bind warning every reconcile pass. Semantics:
        //   * If the persona row identified by `persona_id` exists,
        //     update it in place (same surface as `binding.update`)
        //     and emit `binding.upserted` audit row with a
        //     before/after snapshot.
        //   * If the persona row does not exist, create a fresh
        //     persona using the requested `name` and emit
        //     `binding.upserted` with `before: null` and the freshly-
        //     created row in `after`. The daemon's canonical id
        //     (UUID-suffixed per `create_persona`) is returned to
        //     the reconciler in `persona_id`; the reconciler
        //     persists that into `status.bound_persona_id`.
        // The wire-form method "binding.upsert" is canonical; the
        // underscore alias matches the broker_* dispatch convention.
        "binding.upsert" | "binding_upsert" => binding_upsert(store, params).await,

        // implementation-note-102 Phase 2: SOPS DEK unwrap RPC.
        //
        // Authorisation flow:
        //   1. Caller supplies `persona_id`, `grant_id`, and the
        //      hex-encoded `encrypted_dek_blob`.
        //   2. The grant is looked up; it MUST be active and belong to
        //      `persona_id` (mirrors `use_credential`'s guard).
        //   3. The grant is rate-limited: one successful unwrap per
        //      grant_id per daemon-process lifetime. Second call with the
        //      same `grant_id` is rejected loudly. The check happens
        //      AFTER successful grant validation but BEFORE invoking
        //      the age library, so a stale duplicate request never even
        //      causes a decrypt attempt.
        //   4. The persona's age private key is fetched from the daemon
        //      vault at `age/persona/<persona_id>/private-key` (per
        //      `crate::age::vault_path_for_persona`). The key bytes
        //      live in a `Zeroizing` buffer; they never cross the IPC
        //      boundary.
        //   5. `sops::unwrap_dek_userspace` decrypts the blob in-process
        //      (the function takes `&[u8]` and returns
        //      `Zeroizing<Vec<u8>>` — the plaintext DEK). The age
        //      private key is dropped at the end of that function call.
        //   6. A `sops_dek_unwrapped` audit event is logged with
        //      `persona_id` + `dek_fingerprint` + `grant_id` so the
        //      operator can reconstruct the unwrap chain.
        //   7. The plaintext DEK is hex-encoded into the JSON response,
        //      then the `Zeroizing` buffer is dropped (which zeroes
        //      the underlying bytes). The hex string in the JSON is
        //      sent to the caller; whoever calls this RPC is implicitly
        //      trusted with the plaintext DEK by the grant flow.
        //
        // Phase 3 (implementation-note-42, orchestrator-only) ships
        // `.claude/scripts/sops-as-bot.sh` — the only blessed agent path
        // that calls this RPC. Direct callers from the agent harness are
        // out of scope for v0.
        #[cfg(feature = "age")]
        "sops_unwrap_dek" => {
            // Read-class on the user's view but high-trust on the daemon's
            // — bump activity so the vault stays unlocked, but do NOT
            // gate behind biometric (the wrapper script is expected to
            // run unattended in CI/dev loops).
            presence::record_activity();

            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let blob_hex = params["encrypted_dek_blob"]
                .as_str()
                .ok_or((-32602, "missing 'encrypted_dek_blob' (hex string)".to_string()))?;

            // Decode the hex-encoded ciphertext blob. Reject malformed
            // input loudly so a typo doesn't get smuggled into the age
            // decryptor where the error message is harder to map back.
            let encrypted_dek_blob = hex::decode(blob_hex).map_err(|e| {
                (-32602, format!("invalid 'encrypted_dek_blob' hex: {e}"))
            })?;

            // Grant gating: load via DaemonGrantStore to get core_grants::Grant
            // at the state-machine boundary (implementation-note-91). State and
            // issuer checks use the core type directly.
            let grant = store
                .grant_store()
                .load_grant(grant_id)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("grant {grant_id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            if grant.state != CoreGrantState::Active {
                return Err((
                    -32005,
                    format!("grant {grant_id} is not active and cannot be used"),
                ));
            }
            if grant.issuer.0 != persona_id {
                return Err((
                    -32002,
                    "grant belongs to a different persona".to_string(),
                ));
            }

            // Rate-limit: one **successful** unwrap per grant_id per
            // daemon lifetime. We check membership before doing any
            // crypto work so a known-consumed grant is rejected fast,
            // but we don't CLAIM the slot until after the unwrap
            // succeeds — failures along the vault / decrypt path leave
            // the slot open so the caller can retry once they fix the
            // setup. The daemon's single-threaded LocalSet means
            // there's no TOCTOU window between this check and the
            // claim below.
            if store.is_dek_grant_consumed(grant_id) {
                tracing::warn!(
                    grant_id = %grant_id,
                    persona_id = %persona_id,
                    "rejecting duplicate sops_unwrap_dek call for already-consumed grant"
                );
                return Err((
                    -32005,
                    format!(
                        "grant {grant_id} has already been used for a SOPS DEK unwrap; \
                         issue a fresh grant"
                    ),
                ));
            }

            // Load the persona's age private key from the daemon vault.
            // The key bytes live in a `Zeroizing` buffer so they zero on
            // drop — never log them, never serialize them.
            let vault_path = crate::age::vault_path_for_persona(persona_id);
            let raw_key = vault.get(store, &vault_path).map_err(|e| {
                tracing::warn!(
                    persona_id = %persona_id,
                    vault_path = %vault_path,
                    error = %e,
                    "sops_unwrap_dek: persona age key not in vault"
                );
                (
                    -32000,
                    format!(
                        "persona {persona_id} has no age private key in the vault \
                         (expected at {vault_path})"
                    ),
                )
            })?;
            let age_private_key: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(raw_key);

            // Compute the dek fingerprint BEFORE the unwrap call so the
            // audit row is emitted regardless of decrypt outcome — the
            // failure path also needs the fingerprint for forensics.
            let dek_fingerprint: String = {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(&encrypted_dek_blob);
                hex::encode(&digest[..16])
            };

            // Invoke the pure unwrap function. Plaintext lives in a
            // `Zeroizing<Vec<u8>>`; it will be zeroed when this scope
            // drops it after we serialize the response.
            let plaintext_dek: zeroize::Zeroizing<Vec<u8>> =
                match crate::sops::unwrap_dek_userspace(&age_private_key, &encrypted_dek_blob) {
                    Ok(dek) => dek,
                    Err(e) => {
                        // Audit the failure. The grant slot is NOT
                        // consumed on failure — the caller can retry
                        // once they fix the setup (e.g. wrong age key,
                        // truncated blob).
                        let _ = store.log_event(
                            Some(persona_id),
                            "sops_dek_unwrapped",
                            None,
                            "denied",
                            Some(&serde_json::json!({
                                "grant_id": grant_id,
                                "dek_fingerprint": dek_fingerprint,
                                "error": e.to_string(),
                            }).to_string()),
                        );
                        return Err((-32000, format!("dek unwrap failed: {e}")));
                    }
                };

            // Claim the rate-limit slot now that the unwrap succeeded.
            // The pre-check above already guaranteed the slot was open
            // when we entered the handler, and the daemon's
            // single-threaded LocalSet means no other dispatch can
            // have raced in between. `try_consume_dek_grant` returning
            // `false` here is therefore a programmer error.
            let claimed = store.try_consume_dek_grant(grant_id);
            debug_assert!(
                claimed,
                "try_consume_dek_grant returned false after a passing pre-check; \
                 this indicates a concurrency invariant violation"
            );

            // Receipt: log_event captures op + persona_id +
            // dek_fingerprint + grant_id + ts (the audit row's own
            // timestamp). Never log the plaintext DEK or the
            // ciphertext blob — only the fingerprint.
            let _ = store.log_event(
                Some(persona_id),
                "sops_dek_unwrapped",
                None,
                "allowed",
                Some(&serde_json::json!({
                    "grant_id": grant_id,
                    "dek_fingerprint": dek_fingerprint,
                }).to_string()),
            );

            // Serialize the plaintext DEK as hex. The `Zeroizing` buffer
            // is dropped immediately after — the hex string we return
            // is the only remaining copy outside the caller's process.
            let dek_hex = hex::encode(plaintext_dek.as_slice());
            drop(plaintext_dek);

            tracing::info!(
                persona_id = %persona_id,
                grant_id = %grant_id,
                dek_fingerprint = %dek_fingerprint,
                "sops_dek_unwrapped"
            );

            Ok(json!({
                "dek_hex": dek_hex,
                "dek_fingerprint": dek_fingerprint,
                "grant_id": grant_id,
                "persona_id": persona_id,
            }))
        }

        // Stub when the `age` feature is disabled at compile time. Mirror
        // the `crate::sops::unwrap_dek_userspace` cfg-not(age) error so
        // the wire surface fails loudly instead of silently returning
        // `Method not found` (which would be misleading — the method IS
        // configured, just not built).
        #[cfg(not(feature = "age"))]
        "sops_unwrap_dek" => {
            Err((
                -32000,
                "sops_unwrap_dek requires the 'age' feature; build with --features age"
                    .to_string(),
            ))
        }

        // SOPS-implementation-note-103 — implementation-note-104. Routes for the Path 2 native SOPS
        // recipient surface. Until implementation-note-105 lands, the underlying stubs
        // return NotImplementedError — wire is reserved so the SOPS Go-fork
        // (implementation-note-106) can develop against a real RPC shape.
        "sops.pubkey" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let pubkey = crate::sops::sops_pubkey(persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"persona_id": persona_id, "pubkey": pubkey}))
        }

        "sops.wrap" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let dek_hex = params["dek_hex"]
                .as_str()
                .ok_or((-32602, "missing 'dek_hex' parameter".to_string()))?;
            let dek = hex::decode(dek_hex)
                .map_err(|e| (-32602, format!("invalid 'dek_hex': {e}")))?;
            let encrypted = crate::sops::sops_wrap_dek(persona_id, &dek)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "persona_id": persona_id,
                "encrypted_dek_hex": hex::encode(&encrypted),
            }))
        }

        "sops.unwrap" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let encrypted_hex = params["encrypted_dek_hex"]
                .as_str()
                .ok_or((-32602, "missing 'encrypted_dek_hex' parameter".to_string()))?;
            let encrypted = hex::decode(encrypted_hex)
                .map_err(|e| (-32602, format!("invalid 'encrypted_dek_hex': {e}")))?;
            let dek = crate::sops::sops_unwrap_in_vault(persona_id, &encrypted)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "persona_id": persona_id,
                "dek_hex": hex::encode(&dek),
            }))
        }

        // implementation-note-107: register a new claude-code session.
        //
        // Called by the launcher immediately before spawning the `claude` child.
        // Creates a `SessionMeta` file in `sessions_dir` and returns the
        // `{session_id, grant_id, proxy_url}` triple the launcher injects as
        // env vars. The daemon's proxy URL is emitted so the launcher doesn't
        // need to hard-code a port.
        //
        // Params: `{ "persona": "<name_or_id>", "launcher_pid": <u32> }`
        // Result: `{ "session_id": "...", "grant_id": "...", "proxy_url": "..." }`
        "register_session" => {
            let persona_name = params["persona"]
                .as_str()
                .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
            let launcher_pid = params["launcher_pid"]
                .as_u64()
                .ok_or((-32602, "missing 'launcher_pid' parameter".to_string()))? as u32;

            let sessions_dir = ctx
                .sessions_dir
                .as_ref()
                .ok_or((-32000, "sessions_dir not configured on this connection".to_string()))?;

            // Resolve persona by name. We try get_persona_by_name; if not found,
            // treat the parameter as an id directly (for programmatic callers
            // that already have the id).
            let persona = store
                .list_personas()
                .map_err(|e| (-32000, e.to_string()))?
                .into_iter()
                .find(|p| p.name == persona_name || p.id == persona_name)
                .ok_or_else(|| (-32004, format!("persona '{persona_name}' not found")))?;

            // Look for an active grant for this persona.
            let grants = store
                .list_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let active_grant = grants
                .into_iter()
                .find(|g| g.persona_id == persona.id && g.status == "active")
                .ok_or_else(|| (-32004, format!("no active grant for persona '{persona_name}'")))?;

            // Build a unique session id.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let session_id = format!("sess_{:032x}", nanos);

            let meta = core_state::sessions::SessionMeta {
                session_id: session_id.clone(),
                persona: persona.id.clone(),
                grant_id: active_grant.id.clone(),
                started_at: chrono::Utc::now(),
                launcher_pid,
            };

            let session_store = core_state::SessionStore::new(sessions_dir.clone());
            session_store
                .create(&meta)
                .map_err(|e| (-32000, format!("create session: {e}")))?;

            let _ = store.log_event(
                Some(&persona.id),
                "session.opened",
                None,
                "ok",
                Some(&format!("session_id={session_id} grant_id={}", active_grant.id)),
            );

            // implementation-note-88: read the
            // LLM proxy URL from RequestContext, NOT from std::env::var.
            // The runtime populates ctx.llm_proxy_url via SocketListener
            // builder after the proxy binds. Using env::var here is
            // unreliable — std::env::set_var is unsafe in Rust 2024 precisely
            // because its cross-thread visibility is not guaranteed; tokio
            // worker threads may observe a stale Err(_) and fall back to 8484.
            let proxy_url = match &ctx.llm_proxy_url {
                Some(url) => url.clone(),
                None => {
                    tracing::warn!(
                        "register_session: llm_proxy_url absent from RequestContext \
                         (SocketListener.with_llm_proxy_url not called?) — \
                         falling back to hardcoded 8484; implementation-note-88"
                    );
                    "http://127.0.0.1:8484".to_string()
                }
            };
            // Include the git proxy URL when available so the launcher can
            // inject EMBER_GIT_PROXY_URL into the child env.
            let git_proxy_url = ctx.git_proxy_url.clone();

            let mut response = json!({
                "session_id": session_id,
                "grant_id": active_grant.id,
                "proxy_url": proxy_url,
            });
            if let Some(gpu) = git_proxy_url {
                response["git_proxy_url"] = json!(gpu);
            }
            Ok(response)
        }

        // implementation-note-107: close a claude-code session (clean exit).
        //
        // Called by the launcher after the `claude` child exits naturally. Emits
        // a signed v2 `session.claude_code` Receipt with
        // `termination_reason: clean_exit` into `<session_dir>/receipt.json`,
        // closes the `SessionMeta`, and logs a `session.closed` audit event.
        //
        // implementation-note-108: CleanExit MUST NOT
        // revoke the grant. A 24h grant supports many sessions; the previous
        // unconditional revoke_grant call here was the second-half regression
        // (the launcher goes through this RPC arm, not session_watcher, so
        // #2366's session_watcher fix did not reach the launcher path).
        //
        // Params: `{ "session_id": "..." }`
        // Result: `{ "closed": true, "receipt_id": "..." }`
        "close_session" => {
            let session_id = params["session_id"]
                .as_str()
                .ok_or((-32602, "missing 'session_id' parameter".to_string()))?;

            let sessions_dir = ctx
                .sessions_dir
                .as_ref()
                .ok_or((-32000, "sessions_dir not configured on this connection".to_string()))?;

            let session_store = core_state::SessionStore::new(sessions_dir.clone());

            // Load the session meta so we know the grant_id for logging.
            let meta = session_store
                .read(session_id)
                .map_err(|e| (-32000, format!("read session: {e}")))?
                .ok_or_else(|| (-32004, format!("session '{session_id}' not found or already closed")))?;

            // Emit a signed v2 Receipt with termination_reason = clean_exit
            // via the canonical atomic builder (design) — same path as the
            // dirty-exit termination in `session::lifecycle`.
            let identity = current_identity()
                .ok_or((-32000, "daemon identity not initialised — cannot sign Receipt".to_string()))?;
            let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);

            let envelope = crate::infra::receipt::issue::issue_cohort_a_receipt(
                session_id,
                Vec::new(),
                None,
                core_events::receipt::TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                Some(crate::infra::receipt::issue::TerminationMeta {
                    reason: core_events::receipt::TerminationReason::CleanExit,
                    last_heartbeat_at: None,
                    pid_alive_at_check: None,
                }),
                &signer,
            )
            .map_err(|e| (-32000, format!("issue Receipt: {e}")))?;

            let receipt_id = envelope.receipt_id.clone();

            let session_dir = sessions_dir.join(session_id);
            let receipt_path = session_dir.join("receipt.json");
            let receipt_json = serde_json::to_vec_pretty(&envelope)
                .map_err(|e| (-32000, format!("serialize Receipt JSON: {e}")))?;
            std::fs::write(&receipt_path, &receipt_json)
                .map_err(|e| (-32000, format!("persist Receipt: {e}")))?;

            session_store
                .close(session_id)
                .map_err(|e| (-32000, format!("close session: {e}")))?;

            let _ = store.log_event(
                Some(&meta.persona),
                "session.closed",
                None,
                "clean_exit",
                Some(&format!("session_id={session_id} grant_id={} grant_kept_active=true", meta.grant_id)),
            );

            Ok(json!({
                "closed": true,
                "session_id": session_id,
                "receipt_id": receipt_id,
            }))
        }

        _ => Err((-32601, "Method not found".to_string())),
    }
}

/// `binding.delete` JSON-RPC verb — graceful delete of a workload Persona binding.
///
/// Per design §"binding.delete":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Active grants flip to `revoked`; in-flight broker requests holding
///      a still-cached grant ref drain to completion. New `use_credential` /
///      broker lookups fail loudly because they hit the revoked-grant guard.
///   2. Emit a `binding.deleted` audit event so the reconciler + receipt
///      pipeline can correlate the lifecycle transition with the originating
///      `binding_request_id`. The receipt envelope (signed by the EIC Daemon
///      Persona) is layered on top of this audit event by the Receipt v2
///      pipeline (`crate::infra::receipt`); this handler's job is the
///      audit-log row + the state mutation.
///
/// Idempotency: re-deleting an already-revoked persona is a no-op success
/// path — the audit row still gets written so the reconciler sees a fresh
/// receipt for its retry. `revoke_persona` returns `NotFound` for a never-
/// registered persona; we surface that as `-32004`.
///
/// Drain semantics (graceful path): the cascade revoke flips the SQL row
/// state but does NOT actively cancel a tokio future already executing
/// inside `broker_issue` / `use_credential`. Those callers complete using
/// the locally-bound `core_grants::Grant` they captured at request entry.
/// New requests fail because lookup runs after the SQL flip.
///
/// `binding_revoke_urgent` (separate verb, T-EMBERD-BINDING-implementation-note-109)
/// will skip the in-flight drain by also poisoning the in-process
/// grant cache — that path is intentionally NOT reused here because it
/// inverts the contract callers rely on for the graceful path.
pub async fn binding_delete(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace a delete back to a specific reconcile pass.
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — graceful drain via cascade revoke. `revoke_persona` flips
    // the persona row to `revoked` and marks every active grant under it
    // as `revoked` in the same transaction. In-flight broker calls that
    // already loaded the grant complete with their cached copy; new
    // lookups hit the revoked guard.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {persona_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    }

    // Step 2 — audit-log emission. Action mirrors the receipt kind from
    // `core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED` so the
    // Receipt v2 pipeline can correlate audit rows with envelopes.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "deleted": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.revoke_urgent` JSON-RPC verb — compromise-response revocation
/// of a workload Persona binding.
///
/// Per design §"binding.revoke_urgent":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Same SQL transition as `binding.delete` — persona row flips to
///      `revoked` and every active grant under it flips to `revoked` in
///      the same statement.
///   2. Emit a `binding.revoke_urgent` audit row with outcome `"urgent"`
///      so alerting pipelines can fire on the high-severity event
///      without re-parsing the details JSON. Unlike the graceful
///      `binding.deleted` event, this row is the trigger for compromise-
///      response automation: rotate the credential, sweep the audit log
///      for the persona, page the on-call rotation.
///
/// Difference from `binding.delete`: this verb does NOT promise
/// graceful drain semantics. Today the SQL flip is synchronous and the
/// daemon does not maintain an in-process grant cache, so an in-flight
/// `use_credential` call holding a `core_grants::Grant` value at request
/// entry will still complete with that cached value. When the in-process
/// cache lands (planned with the broker materialization layer), this
/// verb is the one that will additionally poison the cache so urgent
/// revocations actually cancel in-flight callers.
///
/// Idempotency: re-revoking an already-revoked persona is a NotFound
/// (mirrors `binding.delete`). The compromise-response runbook is
/// expected to be idempotent at the orchestration layer — the reconciler
/// retries with the same `binding_request_id` and treats `-32004` as
/// "already revoked, no further action needed".
pub async fn binding_revoke_urgent(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace an urgent revocation back to a specific
    // compromise-response pass.
    let binding_request_id = params["binding_request_id"].as_str();
    // `reason` is optional but strongly recommended for compromise
    // response — it lands in the audit details JSON so the SOC2 evidence
    // export captures why the urgent revocation fired.
    let reason = params["reason"].as_str();

    // Step 1 — cascade revoke. Same SQL transition as `binding.delete`;
    // the wedge that distinguishes urgent from graceful is the audit
    // event row (action + outcome), NOT the storage layer.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {persona_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    }

    // Step 2 — audit-log emission. Action is the literal
    // `"binding.revoke_urgent"` (NOT the `RECEIPT_KIND_BINDING_REVOKED`
    // constant — that one is for the graceful-revoke pipeline, this
    // verb is the urgent-only path). Outcome `"urgent"` makes alerting
    // queries trivial: `WHERE outcome = 'urgent'`.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
        "reason": reason,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        "binding.revoke_urgent",
        None,
        "urgent",
        Some(&details),
    );

    Ok(json!({
        "revoked_urgent": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.update` JSON-RPC verb — mutate metadata on an existing
/// workload Persona binding without revoking it.
///
/// Per design §"binding.update":
///   1. Look up the existing binding (persona row). Return `-32004` if
///      the binding does not exist.
///   2. Apply each mutable field in turn — today only `name` is
///      surfaced as a SQL column, but the wire shape accepts the
///      broader binding-metadata fields (`cred_class_allowlist`,
///      `lease_duration_cap`, etc.) so callers can already speak the
///      design contract; those fields land in the audit details JSON
///      until the schema lands columns for them.
///   3. Emit a `binding.updated` audit row keyed on
///      `RECEIPT_KIND_BINDING_UPDATED` with a before/after snapshot
///      so the reconciler + receipt pipeline can correlate the
///      mutation with its originating `binding_request_id`.
///
/// JSON-RPC params shape (all fields after `binding_id` are optional;
/// at least one mutable field SHOULD be present):
/// ```json
/// {
///   "binding_id":          "persona-...",          // required
///   "binding_request_id":  "br-...",               // optional, recommended
///   "name":                "new-name",             // optional, SQL-mutated
///   "cred_class_allowlist": ["llm:*", ...],        // optional, audit-only
///   "lease_duration_cap":  3600,                   // optional, audit-only
///   "metadata":            { ... }                 // optional, audit-only
/// }
/// ```
///
/// Backwards-compat: `persona_id` is accepted as a synonym for
/// `binding_id` so the verb composes with the same callers that drive
/// `binding.delete` / `binding.revoke_urgent`.
///
/// Idempotency: replaying the same params is safe. The SQL UPDATE is
/// a write of the exact same value when nothing changed; the audit
/// row is appended each call so the reconciler always sees a fresh
/// receipt for its retry. The orchestration layer is expected to
/// dedupe via `binding_request_id` if it cares about exactly-once
/// audit emission.
pub async fn binding_update(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Accept either `binding_id` (canonical per design) or
    // `persona_id` (for symmetry with the delete/revoke verbs that
    // still speak persona_id). At least one must resolve to a string.
    let binding_id = params["binding_id"]
        .as_str()
        .or_else(|| params["persona_id"].as_str())
        .ok_or((
            -32602,
            "missing 'binding_id' parameter".to_string(),
        ))?;
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — load the existing binding so we can build a "before"
    // snapshot for the audit row AND surface NotFound as -32004.
    let before = match store.get_persona(binding_id) {
        Ok(p) => p,
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {binding_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    };

    // Step 2 — apply mutable fields. Today only `name` lives in SQL.
    // The remaining fields (cred_class_allowlist, lease_duration_cap,
    // metadata) are audit-only until the schema lands columns for
    // them; they still flow through the wire contract so callers can
    // forward-compatibly drive design today.
    let new_name = params["name"].as_str();
    if let Some(name) = new_name
        && name != before.name
    {
        // SQLite UNIQUE-constraint violations come back as
        // `Sqlite(SqliteFailure { code: ConstraintViolation, .. })`;
        // surface as -32005 to give callers an actionable signal
        // distinct from the generic -32000 "internal" bucket.
        match store.conn().execute(
            "UPDATE personas SET name = ?1 WHERE id = ?2",
            rusqlite::params![name, binding_id],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err((
                    -32005,
                    format!("name '{name}' already in use"),
                ));
            }
            Err(e) => return Err((-32000, e.to_string())),
        }
    }

    // Step 3 — capture the after-snapshot. We re-read so the audit
    // reflects whatever SQLite actually committed (in particular, if
    // a future migration adds defaulted columns, the audit row picks
    // them up automatically).
    let after = store
        .get_persona(binding_id)
        .map_err(|e| (-32000, e.to_string()))?;

    // Step 4 — audit-log emission. Action mirrors
    // `RECEIPT_KIND_BINDING_UPDATED` so the Receipt v2 pipeline can
    // correlate audit rows with envelopes. The details JSON carries
    // both the before/after persona snapshots AND the audit-only
    // metadata fields the caller passed (so the reconciler can apply
    // them to its in-memory model even before the schema lands).
    let details = serde_json::json!({
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "before": {
            "name": before.name,
            "status": before.status,
        },
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "name": new_name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(binding_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_UPDATED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "updated": true,
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "name": after.name,
    }))
}

/// `binding.upsert` JSON-RPC verb — idempotent insert-or-update for a
/// workload Persona binding.
///
/// Per design §"binding.upsert": this is the steady-state verb
/// `ember-kernel`'s EmberServiceAccount reconciler calls every pass.
/// Today it ships as a thin compose of `get_persona` + `create_persona`
/// + the SQL `UPDATE` from `binding.update`. The audit row records a
/// `binding.upserted` event keyed on the (final) persona id with a
/// before/after diff so the reconciler + receipt pipeline can tell
/// "first registration" apart from "no-op refresh" without re-parsing
/// the persona row.
///
/// JSON-RPC params shape (all fields optional except either `persona_id`
/// or `name` MUST be present so the verb has a binding to anchor on):
/// ```json
/// {
///   "namespace":            "ns-prod",                    // optional, audit-only
///   "name":                 "ml-eval",                    // required when creating
///   "persona_id":           "persona-...",                // optional, identifier when updating
///   "binding_request_id":   "br-...",                     // optional, recommended
///   "cred_class_allowlist": ["llm:*", ...],               // optional, audit-only
///   "lease_duration_cap":   3600,                         // optional, audit-only
///   "metadata":             { ... }                       // optional, audit-only
/// }
/// ```
///
/// Idempotency: replaying the same params is safe. If the persona
/// already exists with the requested name, the UPDATE is a no-op write
/// and the audit row records `before == after` (the reconciler still
/// gets a fresh receipt). If the row does not exist, a fresh persona
/// is created and the audit row carries `before: null`.
///
/// Returns `{ persona_id, created, updated }`. `persona_id` is always
/// the canonical id the daemon uses (which may differ from the caller's
/// `persona_id` if the caller asked for a fresh registration). Exactly
/// one of `created` / `updated` is `true`.
pub async fn binding_upsert(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Either `persona_id` (canonical, looks up an existing binding) or
    // `name` (required when creating fresh) MUST be present. Mirrors
    // the `binding.update` `binding_id`/`persona_id` synonym shape.
    let requested_persona_id = params["persona_id"]
        .as_str()
        .or_else(|| params["binding_id"].as_str());
    let name = params["name"].as_str();
    let binding_request_id = params["binding_request_id"].as_str();

    if requested_persona_id.is_none() && name.is_none() {
        return Err((
            -32602,
            "binding.upsert requires either 'persona_id' or 'name'".to_string(),
        ));
    }

    // Step 1 — try to load the existing binding so we can branch on
    // create-vs-update. NotFound on a caller-supplied `persona_id`
    // routes to the create path (idempotent insert); other errors
    // surface as -32000.
    let existing = match requested_persona_id {
        Some(pid) => match store.get_persona(pid) {
            Ok(p) => Some(p),
            Err(crate::infra::store::StoreError::NotFound) => None,
            Err(e) => return Err((-32000, e.to_string())),
        },
        None => None,
    };

    // Step 2 — branch.
    let (canonical_id, created, before_snapshot, after) = match existing {
        // ── Update path ──
        Some(before) => {
            // Apply the only mutable SQL column today (`name`). Deeper
            // metadata mutations land in audit-only details JSON until
            // the schema lands columns for them — same shape as
            // `binding.update`.
            if let Some(new_name) = name
                && new_name != before.name
            {
                match store.conn().execute(
                    "UPDATE personas SET name = ?1 WHERE id = ?2",
                    rusqlite::params![new_name, before.id],
                ) {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(err, _))
                        if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        return Err((
                            -32005,
                            format!("name '{new_name}' already in use"),
                        ));
                    }
                    Err(e) => return Err((-32000, e.to_string())),
                }
            }
            let after = store
                .get_persona(&before.id)
                .map_err(|e| (-32000, e.to_string()))?;
            let before_snapshot = json!({
                "name": before.name,
                "status": before.status,
            });
            (before.id.clone(), false, before_snapshot, after)
        }
        // ── Create path ──
        None => {
            // Creating a fresh persona requires a name — caller
            // either passed `persona_id` for a row that doesn't
            // exist (snapshot drift, fresh cluster) or passed `name`
            // for a never-registered SA.
            let create_name = name.ok_or((
                -32602,
                "binding.upsert create path requires 'name'".to_string(),
            ))?;
            let new_persona = match store.create_persona(create_name) {
                Ok(p) => p,
                Err(crate::infra::store::StoreError::Sqlite(
                    rusqlite::Error::SqliteFailure(err, _),
                )) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    return Err((
                        -32005,
                        format!("name '{create_name}' already in use"),
                    ));
                }
                Err(e) => return Err((-32000, e.to_string())),
            };
            (new_persona.id.clone(), true, Value::Null, new_persona)
        }
    };

    // Step 3 — audit-log emission. Action `"binding.upserted"` mirrors
    // the existing `binding.deleted` / `binding.updated` literals —
    // the kind constant for upsert is not yet locked in
    // `core_events::receipt::atomic`, so we emit the literal here and
    // tighten to a constant when design lands the discriminator.
    let details = serde_json::json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "before": before_snapshot,
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "namespace": params.get("namespace"),
            "name": name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(&canonical_id),
        "binding.upserted",
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "updated": !created,
        "name": after.name,
    }))
}

/// Shape a single `Statement` into the budget-status response entry used by
/// the `grant_budget_status` MCP tool. The `percent_used` map is populated
/// only for axes that have a ceiling set — TTL-only statements return an
/// empty map rather than a map full of nulls. `estimated_runway_seconds`
/// is today always `null` (reserved for a future burn-rate projection once
/// the metering history is durable).
fn build_statement_budget_entry(s: &core_types::Statement) -> Value {
    let mut percent_used = serde_json::Map::new();
    if let Some(budget) = &s.budget {
        if let Some(cap) = budget.tokens
            && cap > 0
        {
            let pct = ((s.usage.tokens as u128 * 100) / cap as u128) as u64;
            percent_used.insert("tokens".to_string(), json!(pct));
        }
        if let Some(cap) = budget.cents
            && cap > 0
        {
            let pct = ((s.usage.cents as u128 * 100) / cap as u128) as u64;
            percent_used.insert("cents".to_string(), json!(pct));
        }
        if let Some(cap) = budget.requests
            && cap > 0
        {
            let pct = ((s.usage.requests as u128 * 100) / cap as u128) as u64;
            percent_used.insert("requests".to_string(), json!(pct));
        }
    }

    json!({
        "sid": s.sid,
        "resource_type": s.resource_type.as_str(),
        "budget": s.budget,
        "usage": s.usage,
        "percent_used": Value::Object(percent_used),
        "estimated_runway_seconds": Value::Null,
        "has_budget_remaining": s.has_budget_remaining(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::build_banner;
    use crate::trust::approval::ApprovalRequestInfo;
    use crate::trust::policy::{ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel};
    use crate::infra::rate_limit::RateLimiter;
    use crate::infra::store::DaemonStore;
    use crate::infra::vault::Vault;
    use serde_json::json;
    use std::cell::RefCell;

    fn test_vault() -> Vault {
        Vault::new([42u8; 32])
    }

    fn test_policy() -> PolicyEngine {
        PolicyEngine::default()
    }

    fn test_rate_limiter() -> RefCell<RateLimiter> {
        RefCell::new(RateLimiter::default())
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "ping", &json!(null)).await.unwrap();
        assert_eq!(result["pong"], json!(true));
    }

    #[tokio::test]
    async fn unknown_method_returns_32601() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err =
            dispatch_method(&store, &vault, &policy, &rl, "no_such_method", &json!(null))
                .await.unwrap_err();
        assert_eq!(err.0, -32601);
    }

    #[tokio::test]
    async fn create_persona_then_list_shows_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-alpha"}),
        )
        .await.unwrap();
        assert!(result["id"].as_str().unwrap().starts_with("persona-"));
        assert_eq!(result["name"], json!("agent-alpha"));

        let list =
            dispatch_method(&store, &vault, &policy, &rl, "list_personas", &json!(null))
                .await.unwrap();
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], json!("agent-alpha"));
        assert_eq!(arr[0]["status"], json!("active"));
    }

    #[tokio::test]
    async fn create_persona_missing_name_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    // ---- implementation-note-89: evaluate_tool_call dispatch arm -----------------

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_returns_decision_for_active_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Mint persona + grant.
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "claude-code-host-x"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        store
            .create_grant(persona_id, "anthropic-api-key", "read", None)
            .unwrap();

        // Evaluate via dispatch.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({
                "persona": "claude-code-host-x",
                "tool_name": "Bash",
                "params": {"command": "ls"},
                "session_id": "sess-evt"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["permit"], json!(true), "got: {result}");
        assert!(result["grant_id"].is_string(), "got: {result}");
        assert!(result["emitted_event_id"].is_string());
    }

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_denies_unknown_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({
                "persona": "claude-code-nobody",
                "tool_name": "Read",
                "params": {}
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["permit"], json!(false), "got: {result}");
        assert!(result["reason"].as_str().unwrap().contains("no active grant"));
    }

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_missing_persona_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({"tool_name": "Bash", "params": {}}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn create_grant_then_evaluate_finds_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-beta"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "api-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();
        assert!(grant["id"].as_str().unwrap().starts_with("grant-"));

        let eval = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_grant",
            &json!({"persona_id": persona_id, "credential_name": "api-key"}),
        )
        .await.unwrap();
        assert_eq!(eval["scope"], json!("read"));
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!(null),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("persona_id"), "error should mention persona_id, got: {}", err.1);
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_in_empty_object_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn list_grants_with_persona_id_returns_only_that_personas_grants() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-a"}),
        )
        .await.unwrap();
        let persona_a_id = persona_a["id"].as_str().unwrap();

        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-b"}),
        )
        .await.unwrap();
        let persona_b_id = persona_b["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_a_id,
                "credential_name": "cred-a",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_b_id,
                "credential_name": "cred-b",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        let list_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_a_id}),
        )
        .await.unwrap();
        let arr_a = list_a.as_array().unwrap();
        assert_eq!(arr_a.len(), 1, "persona_a should see exactly 1 grant");
        assert_eq!(arr_a[0]["persona_id"], json!(persona_a_id));
        assert_eq!(arr_a[0]["credential_name"], json!("cred-a"));

        let list_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_b_id}),
        )
        .await.unwrap();
        let arr_b = list_b.as_array().unwrap();
        assert_eq!(arr_b.len(), 1, "persona_b should see exactly 1 grant");
        assert_eq!(arr_b[0]["persona_id"], json!(persona_b_id));
        assert_eq!(arr_b[0]["credential_name"], json!("cred-b"));
    }

    #[tokio::test]
    async fn use_credential_with_valid_grant_returns_value() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-gamma"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "my-token",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await.unwrap();
        assert_eq!(result["credential"], json!("supersecret"));
    }

    #[tokio::test]
    async fn revoke_statement_blocks_use_credential() {
        // implementation-note-92 — per-statement revoke MVP.
        // Revoking the Credential Statement's sid blocks use_credential
        // while the grant is otherwise still active.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-stmtrev"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "stmtrev-token", "value": "supersecret"}),
        )
        .await.unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "stmtrev-token",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();

        // Baseline: works.
        let ok = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
        )
        .await.unwrap();
        assert_eq!(ok["credential"], json!("supersecret"));

        // Revoke S0 (the credential statement built by create_grant).
        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_statement",
            &json!({"grant_id": grant_id, "statement_sid": "S0"}),
        )
        .await.unwrap();
        assert_eq!(resp["status"], json!("revoked"));

        // Now use_credential is blocked with -32006.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32006);
        assert!(err.1.contains("statement revoked"));

        // grant_status surfaces the revoked sid.
        let status = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": grant_id}),
        )
        .await.unwrap();
        let revoked = status["revoked_sids"].as_array().expect("revoked_sids array");
        assert!(revoked.iter().any(|v| v.as_str() == Some("S0")));
    }

    #[tokio::test]
    async fn propose_grant_rpc_persists_n_statements() {
        // implementation-note-95 — N-statement persistence + retrieval.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-agent"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // 3-Statement composite envelope (credential + session + time).
        // design §4 — composite-grant action keys must carry the
        // `did:<method>:<rest>` prefix; the RPC layer rejects bare keys
        // since T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES.
        let statements = json!([
            {
                "sid": "S0",
                "resource_type": "credential",
                "actions": ["did:ember:github.push", "did:ember:github.read"],
                "resource": {"kind": "any"},
                "budget": null,
                "usage": {},
                "conditions": [],
            },
            {
                "sid": "S1",
                "resource_type": "session",
                "actions": ["did:ember:generic.write"],
                "resource": {"kind": "any"},
                "budget": {"tokens": 10000},
                "usage": {},
                "conditions": [],
            },
            {
                "sid": "S2",
                "resource_type": "time",
                "actions": ["did:ember:generic.write"],
                "resource": {"kind": "any"},
                "budget": {"wall_clock_secs": 300},
                "usage": {},
                "conditions": [],
            },
        ]);

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "github.push",
                "risk_level": "high",
                "statements": statements,
            }),
        )
        .await.unwrap();

        let approval_id = resp["approval_id"].as_str().expect("approval_id present");
        assert!(approval_id.starts_with("approval-"));
        assert_eq!(resp["status"], json!("pending"));
        assert_eq!(resp["statement_count"], json!(3));

        // Retrieval round-trip via the store directly: the row should carry
        // all three statements exactly.
        let info = store.get_approval(approval_id).expect("approval row present");
        let stmts = info.composite_statements.expect("composite_statements present");
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[0].sid, "S0");
        assert_eq!(stmts[1].sid, "S1");
        assert_eq!(stmts[2].sid, "S2");
    }

    #[tokio::test]
    async fn propose_grant_rpc_rejects_empty_statements() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-empty"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "x",
                "risk_level": "high",
                "statements": [],
            }),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("statements"));
    }

    #[tokio::test]
    async fn propose_grant_rpc_rejects_bare_action_keys_with_migration_pointer() {
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — per ADR
        // 135 §4 the propose_grant RPC entry point is the parse-time
        // gate that refuses bare action keys (no `did:` prefix). The
        // error message must point operators at the new shape so they
        // can migrate without consulting docs.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-bare-key"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "credential.access",
                "risk_level": "high",
                "statements": [
                    {
                        "sid": "S0",
                        "resource_type": "credential",
                        "actions": ["gh.pr_create"],
                        "resource": {"kind": "any"},
                        "budget": null,
                        "usage": {},
                        "conditions": [],
                    }
                ],
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32602, "bare action key must surface as parse-time -32602");
        assert!(
            err.1.contains("did: prefix"),
            "error must name the missing prefix; got: {}",
            err.1
        );
        assert!(
            err.1.contains("did:ember:gh.pr_create"),
            "error must include the recommended did:ember: migration form; got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn propose_grant_rpc_accepts_did_web_for_forward_compat() {
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — arbitrary
        // `did:<method>:` prefixes pass the parse-time validator at the RPC
        // gate even though v0.3.0's broker.resolve only routes `did:ember:`.
        // This locks the forward-compat door so community publishers
        // (`did:web:hashicorp.com:terraform.apply`) submit cleanly today and
        // become resolvable when the per-publisher trust delegation UX lands.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-fwd-compat"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "tf-token",
                "scope": "*",
                "action": "credential.access",
                "risk_level": "high",
                "statements": [
                    {
                        "sid": "S0",
                        "resource_type": "credential",
                        "actions": ["did:web:hashicorp.com:terraform.apply"],
                        "resource": {"kind": "any"},
                        "budget": null,
                        "usage": {},
                        "conditions": [],
                    }
                ],
            }),
        )
        .await
        .expect("did:web: prefixed action key must pass the RPC parse-time gate");

        assert!(resp["approval_id"].as_str().unwrap_or("").starts_with("approval-"));
    }

    #[tokio::test]
    async fn use_credential_without_grant_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-delta"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await.unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32000);
        assert!(err.1.contains("no active grant"));
    }

    #[tokio::test]
    async fn audit_query_reflects_credential_access() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-epsilon"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "audit-token", "value": "v"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
        )
        .await.unwrap();

        let log =
            dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({})).await.unwrap();
        let arr = log.as_array().unwrap();
        // Three rows (timestamp DESC): credential.access, grant.issued, grant.minted.
        // grant.minted is emitted inside create_grant_with_budget before the handler
        // emits grant.issued, so it is the oldest.
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["action"], json!("credential.access"));
        assert_eq!(arr[0]["outcome"], json!("allowed"));
        assert_eq!(arr[1]["action"], json!("grant.issued"));
        assert_eq!(arr[1]["outcome"], json!("allowed"));
        assert_eq!(arr[2]["action"], json!("grant.minted"));
        assert_eq!(arr[2]["outcome"], json!("minted"));
    }

    #[tokio::test]
    async fn create_grant_with_rate_limit_stores_condition() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-ratelimit"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "rate-key",
                "scope": "read",
                "max_uses_per_hour": 5,
                "force": true,
            }),
        )
        .await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert!(grant_id.starts_with("grant-"));
        assert_eq!(grant["conditions"]["max_uses_per_hour"], json!(5));

        // Verify it was stored in the DB.
        let stored: Option<i64> = store
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, Some(5));
    }

    #[tokio::test]
    async fn delegate_grant_creates_child_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-parent"}),
        )
        .await.unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-child"}),
        )
        .await.unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap();

        let child_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "read",
            }),
        )
        .await.unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("read"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
    }

    /// Exercise the socket-level `delegate_grant` method with an
    /// explicit child `budget` param. Parent carries a tokens budget,
    /// child asks for a strict subset — attenuation must accept and the
    /// response envelope must surface the child budget + expiry.
    #[tokio::test]
    async fn delegate_grant_via_socket_accepts_child_budget() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "agent-parent-budget"}),
        ).await.unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "agent-child-budget"}),
        ).await.unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "github:push:acme/*",
                "max_delegation_depth": 2,
                "ttl_secs": 3_600,
                "force": true,
            }),
        ).await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        // `create_grant` socket path doesn't plumb budget yet, so stamp
        // the tokens budget directly on the row to set up the scenario.
        store.conn().execute(
            "UPDATE grants SET budget_json = ?1 WHERE id = ?2",
            rusqlite::params![
                r#"{"tokens":10000}"#,
                &parent_grant_id,
            ],
        ).unwrap();

        let child_grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "github:push:acme/widgets",
                "ttl_secs": 900,
                "budget": {"tokens": 2000},
            }),
        ).await.unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("github:push:acme/widgets"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
        assert_eq!(
            child_grant["budget"]["tokens"].as_u64(),
            Some(2000),
            "child budget echoed in response"
        );
        assert!(
            child_grant["expires_at"].is_string(),
            "expires_at present on delegated grant"
        );
    }

    #[tokio::test]
    async fn use_credential_records_usage_and_enforces_rate_limit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-usage"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "usage-token", "value": "secret"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "usage-token",
                "scope": "read",
                "max_uses_per_hour": 2,
                "force": true,
            }),
        )
        .await.unwrap();

        // First use: ok.
        let r1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r1.is_ok());

        // Second use: ok.
        let r2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r2.is_ok());

        // Third use: rate limit exceeded.
        let r3 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r3.is_err());
        assert_eq!(r3.unwrap_err().0, -32000);
    }

    #[tokio::test]
    async fn detect_anomalies_returns_empty_on_fresh_store() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
                .await.unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn request_access_blocking_timeout() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "blocker"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Request with 1 second timeout — nobody will approve.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access_blocking",
            &json!({
                "persona_id": persona_id,
                "action": "test.action",
                "timeout_secs": 1,
            }),
        )
        .await.unwrap();

        assert_eq!(result["status"], "timeout");
    }

    #[tokio::test]
    async fn detect_anomalies_finds_high_denial_rate() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Log enough denied events to trigger anomaly
        for _ in 0..4 {
            store.log_event(Some("agent-x"), "credential.access", None, "denied", None).unwrap();
        }
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
                .await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty());
    }

    #[tokio::test]
    async fn request_access_denies_when_rate_limit_exceeded() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        // Tight limiter: exactly 1 request per persona+action in a 60s window.
        let rl = RefCell::new(RateLimiter::new(1, 60));

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rate-limited"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // First request goes through (policy applies — "deploy.staging" is
        // auto-approve under the default policy, so a grant is created).
        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(first["status"], "approved");

        // Snapshot approvals count before the second (rate-limited) call.
        let pending_before = store.list_pending_approvals().unwrap();

        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(second["status"], "denied");
        assert_eq!(second["reason"], "rate_spike");
        // The response must not leak a matched rule — only the rate-limit fact.
        assert!(second.get("matched_rule").is_none());

        // Policy must NOT have been evaluated — no new approval submitted.
        let pending_after = store.list_pending_approvals().unwrap();
        assert_eq!(pending_before.len(), pending_after.len());
    }

    // --- build_banner unit tests ---

    fn fake_req(credential_name: &str, scope: &str, ttl_secs: Option<u64>, risk_level: &str, action: &str) -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-a54d6404-dead-beef-cafe-000000000000".to_string(),
            persona_id: "persona-1".to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            ttl_secs,
            action: action.to_string(),
            risk_level: risk_level.to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-04-20T00:00:00Z".to_string(),
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
            skill_ref: None,
        }
    }

    #[test]
    fn banner_title_fits_60_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.title.chars().count() <= 60,
            "title too long: {} chars — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    #[test]
    fn banner_subtitle_fits_50_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle too long: {} chars — {:?}",
            banner.subtitle.chars().count(),
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_fits_50_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.body.chars().count() <= 50,
            "body too long: {} chars — {:?}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_does_not_contain_scope() {
        let req = fake_req("github-token", "admin:repo:write:delete", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            !banner.subtitle.contains("admin:repo"),
            "subtitle must not contain scope — {:?}",
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_contains_id_prefix() {
        let req = fake_req("github-token", "read", None, "low", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.body.contains("a54d6404"),
            "body should contain 8-char id prefix — {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_hard_truncates_long_credential_name() {
        let long_cred = "a".repeat(60);
        let req = fake_req(&long_cred, "read", Some(3600), "high", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle should be hard-truncated: {} chars",
            banner.subtitle.chars().count()
        );
        assert!(banner.subtitle.ends_with("..."), "should end with ellipsis");
    }

    #[test]
    fn banner_title_long_action_truncates_at_40_chars() {
        let req = fake_req("key", "read", None, "low", &"x".repeat(80));
        let banner = build_banner("bot", &req);
        // The action portion is capped at 40 chars; title = "Ember · bot wants " + 40 = 58 chars max.
        assert!(
            banner.title.chars().count() <= 60,
            "title should fit in 60 chars: {} — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    // --- NOTIF-1: optional semantic fields ---

    #[test]
    fn banner_all_semantic_fields_none_uses_default_format() {
        // All new fields absent → legacy title/body behavior.
        let req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("wants"),
            "title should use action-based format when tool_name is None: {:?}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should use default format when target fields are None: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_tool_name_appears_in_title_instead_of_action() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.tool_name = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain tool_name: {:?}",
            banner.title
        );
        assert!(
            !banner.title.contains("wants"),
            "title should NOT use action-based 'wants' format when tool_name is set: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_target_fields_appear_in_body() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.tool_name = Some("claude-code".to_string());
        req.target_host = Some("api.github.com".to_string());
        req.target_summary = Some("POST /repos/x/y/pulls".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com"),
            "body should contain target_host: {:?}",
            banner.body
        );
        assert!(
            banner.body.contains("POST /repos"),
            "body should contain target_summary: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target fields are set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_target_url_appears_when_set() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.target_url = Some("api.github.com/repos/x/y".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com/repos/x/y"),
            "body should contain target_url: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target_url is set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_agent_framework_appears_when_set() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.agent_framework = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain agent_framework: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_omits_absent_optional_fields() {
        let req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        let banner = build_banner("demo-agent", &req);
        assert!(
            !banner.title.contains("None"),
            "title must not contain literal 'None': {:?}",
            banner.title
        );
        assert!(
            !banner.subtitle.contains("None"),
            "subtitle must not contain literal 'None': {:?}",
            banner.subtitle
        );
        assert!(
            !banner.body.contains("None"),
            "body must not contain literal 'None': {:?}",
            banner.body
        );
        // No stray separators from absent fields
        assert!(
            !banner.title.contains("()"),
            "title must not contain empty parens: {:?}",
            banner.title
        );
    }

    #[tokio::test]
    async fn dispatch_method_uses_provided_policy() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        // Custom policy: deny "test.action" explicitly.
        let custom = PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "test.action".to_string(),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            }],
            ..PolicyConfig::default()
        });
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "create_persona",
            &json!({"name": "custom-policy"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "test.action",
            }),
        )
        .await.unwrap();

        assert_eq!(result["status"], "denied");
        assert_eq!(result["decision"], "deny");
    }

    #[tokio::test]
    async fn grant_issuance_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-issuance"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // request_access with auto-approve policy creates a grant
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "audit-cred",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(result["status"], "approved");
        let grant_id = result["grant_id"].as_str().unwrap();

        let entries = store.query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.issued".to_string()),
            ..Default::default()
        }).unwrap();
        assert!(!entries.is_empty(), "expected at least one grant.issued audit row");
        let entry = entries.iter().find(|e| {
            e.details.as_ref().map(|d| d.contains(grant_id)).unwrap_or(false)
        });
        assert!(entry.is_some(), "audit row should reference the new grant_id");
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.issued");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("audit-cred"));
    }

    #[tokio::test]
    async fn grant_revocation_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-revocation"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "revoke-cred",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await.unwrap();

        let entries = store.query_audit(&crate::infra::audit::AuditFilter {
            action: Some("grant.revoked".to_string()),
            ..Default::default()
        }).unwrap();
        assert!(!entries.is_empty(), "expected at least one grant.revoked audit row");
        let entry = entries.iter().find(|e| {
            e.details.as_ref().map(|d| d.contains(grant_id)).unwrap_or(false)
        });
        assert!(entry.is_some(), "audit row should reference the revoked grant_id");
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.revoked");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("revoke-cred"));
    }

    // -----------------------------------------------------------------
    // `grant_status` + `list_grants` persona filter + `use_credential`
    // by grant_id — added for TODO 69I.1 so the agent runtime has a
    // daemon-side surface that matches its protocol shape.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn grant_status_finds_live_grant_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "gs-a"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": grant_id, "persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(result["kind"], "grant");
        assert_eq!(result["id"], json!(grant_id));
        assert_eq!(result["persona_id"], json!(persona_id));
        assert_eq!(result["scope"], "r");
    }

    #[tokio::test]
    async fn grant_status_rejects_mismatched_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "gs-owner"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller pinning a different persona must be rejected — this is
        // the cross-persona probe defense.
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": grant_id, "persona_id": "persona-other"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn grant_status_finds_pending_approval_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "appr-owner"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let req = store.submit_approval(persona_id, "cred", "read", None, "credential.access.cred", "medium").unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": req.id}),
        ).await.unwrap();
        assert_eq!(result["kind"], "approval");
        assert_eq!(result["id"], json!(req.id));
        assert_eq!(result["status"], "pending");
    }

    #[tokio::test]
    async fn grant_status_unknown_id_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": "nonexistent"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn list_grants_filters_by_persona_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let p1 = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "p1"})).await.unwrap();
        let p2 = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "p2"})).await.unwrap();
        let p1_id = p1["id"].as_str().unwrap();
        let p2_id = p2["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true})).await.unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true})).await.unwrap();

        // Bare call without persona_id is now refused — cross-persona
        // enumeration via the unauthenticated socket is an info disclosure.
        let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({})).await.unwrap_err();
        assert_eq!(err.0, -32602);

        let only_p1 = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({"persona_id": p1_id})).await.unwrap();
        let arr = only_p1.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_id"], json!(p1_id));
        assert_eq!(arr[0]["credential_name"], "k1");
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_succeeds() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "uc-grant"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "gk", "value": "secret-by-grant-id"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "gk", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(result["credential"], "secret-by-grant-id");
        assert_eq!(result["grant_id"], json!(grant_id));
        assert_eq!(result["credential_name"], "gk");
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_cross_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let owner = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "owner"})).await.unwrap();
        let owner_id = owner["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "ok", "value": "v"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": owner_id, "credential_name": "ok", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller supplying the owner's grant_id but a foreign persona
        // MUST be rejected — leaked id cannot be used to redeem.
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": "persona-other"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_inactive_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "inact"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "ik", "value": "v"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "ik", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": grant_id})).await.unwrap();

        let err = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32005);
    }

    // --- Grant Receipts (Stream D) socket surface -------------------------

    /// Init a process-singleton identity keyed off a temp dir so the test
    /// has real receipts to exercise. Called by each receipt test — the
    /// OnceCell silently no-ops on the second call, which is fine because
    /// the key file is stable.
    fn setup_receipt_identity() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let _ = crate::infra::receipt::init_identity(dir.path());
        dir
    }

    #[tokio::test]
    async fn get_receipt_and_list_receipts_round_trip() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl, "create_persona",
            &json!({"name": "rcpt-alpha"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl, "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();
        dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": grant_id})).await.unwrap();

        // list_receipts (no filter) returns our receipt.
        let list = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({})).await.unwrap();
        let arr = list.as_array().expect("array");
        assert!(!arr.is_empty(), "receipt should be emitted on revoke");
        let rid = arr[0]["id"].as_str().unwrap().to_string();
        assert_eq!(arr[0]["grant_id"].as_str().unwrap(), grant_id);

        // get_receipt returns the full signed body.
        let r = dispatch_method(&store, &vault, &policy, &rl, "get_receipt", &json!({"id": rid})).await.unwrap();
        assert_eq!(r["id"].as_str().unwrap(), rid);
        assert_eq!(r["evidence"]["canonical_version"].as_u64().unwrap(), 1);
        assert_eq!(r["evidence"]["sig"].as_str().unwrap().len(), 128);
    }

    #[tokio::test]
    async fn get_receipt_unknown_id_returns_32004() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "get_receipt",
            &json!({"id": "rct-nonexistent"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn list_receipts_persona_filter_narrows_results() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let a = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "lra"})).await.unwrap();
        let b = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "lrb"})).await.unwrap();
        let aid = a["id"].as_str().unwrap().to_string();
        let bid = b["id"].as_str().unwrap().to_string();
        for pid in [&aid, &bid] {
            let g = dispatch_method(
                &store, &vault, &policy, &rl, "create_grant",
                &json!({"persona_id": pid, "credential_name": "c", "scope": "r", "force": true}),
            ).await.unwrap();
            let gid = g["id"].as_str().unwrap().to_string();
            dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": gid})).await.unwrap();
        }
        let all = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({})).await.unwrap();
        let just_a = dispatch_method(
            &store, &vault, &policy, &rl, "list_receipts",
            &json!({"persona_id": aid}),
        ).await.unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2);
        assert_eq!(just_a.as_array().unwrap().len(), 1);
        assert_eq!(just_a[0]["summary"]["persona_id"].as_str().unwrap(), aid);
    }

    #[tokio::test]
    async fn daemon_persona_method_returns_pubkey_when_initialised() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "daemon_persona", &json!({})).await.unwrap();
        // Either a pubkey object or null (init raced on separate process) — but
        // since _guard held a tempdir that init_identity used for the OnceCell,
        // we expect a pubkey here.
        assert!(result.is_object(), "identity should be initialised in this test");
        let pubkey = result["pubkey"].as_str().unwrap();
        assert_eq!(pubkey.len(), 64);
    }

    // --- grant_budget_status (P69K-F1) -------------------------------------

    /// Helper: seed a 3-statement grant via the low-level composite-grant
    /// API so we can assert the MCP budget-status projection without
    /// relying on the proxy to mutate usage.
    fn seed_budget_grant(
        store: &DaemonStore,
        persona_id: &str,
        credential_name: &str,
    ) -> String {
        use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
        let grant = store
            .create_grant(persona_id, credential_name, "*", None)
            .unwrap();
        let root = store.persona_root_keypair(persona_id).unwrap();
        let statements = vec![
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["generic:write".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    tokens: Some(20_000),
                    cents: Some(100),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S2".into(),
                resource_type: ResourceType::Payment,
                actions: vec!["payment:charge".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    cents: Some(500),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S3".into(),
                resource_type: ResourceType::Time,
                actions: vec!["session:start".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    wall_clock_secs: Some(3_600),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
        ];
        let ag = crate::trust::grant::access_grant_from_statements(
            &grant.id,
            persona_id,
            credential_name,
            statements,
            0,
            None,
            &root,
        )
        .unwrap();
        store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
        grant.id
    }

    #[tokio::test]
    async fn grant_budget_status_returns_per_statement_shape() {
        // A 3-statement composite grant surfaces three entries in the
        // response, each carrying sid + resource_type + budget + usage +
        // percent_used. With a stubbed 50% usage on S1, percent_used
        // reflects it — the MCP client can render a runway view without
        // walking the block chain itself.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("budget-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-a");

        // Drive S1 to 10_000 tokens (50%) and 50 cents (50%).
        let delta = store
            .increment_statement_usage(
                &grant_id,
                "S1",
                core_types::Usage {
                    tokens: 10_000,
                    cents: 50,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta.current.tokens, 10_000);

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();

        assert_eq!(result["grant_id"].as_str().unwrap(), grant_id);
        assert_eq!(result["status"].as_str().unwrap(), "active");
        let statements = result["statements"].as_array().unwrap();
        assert_eq!(statements.len(), 3, "three-statement grant");

        let s1 = &statements[0];
        assert_eq!(s1["sid"], "S1");
        assert_eq!(s1["resource_type"], "session");
        assert_eq!(s1["usage"]["tokens"], 10_000);
        assert_eq!(s1["percent_used"]["tokens"], 50);
        assert_eq!(s1["percent_used"]["cents"], 50);
        // runway is reserved for a future burn-rate projection.
        assert!(s1["estimated_runway_seconds"].is_null());
        assert_eq!(s1["has_budget_remaining"], true);

        // S2 has no usage, should be 0% on its set axis.
        let s2 = &statements[1];
        assert_eq!(s2["sid"], "S2");
        assert_eq!(s2["percent_used"]["cents"], 0);
    }

    #[tokio::test]
    async fn grant_budget_status_unknown_grant_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": "grant-nonexistent"}),
        )
        .await
        .unwrap_err();
        // Consistent with `get_receipt` / `grant_status` not-found shape:
        // -32004 is the daemon's NotFound code for MCP.
        assert_eq!(err.0, -32004);
        assert!(err.1.contains("grant-nonexistent"));
    }

    #[tokio::test]
    async fn grant_budget_status_missing_grant_id_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("grant_id"));
    }

    #[tokio::test]
    async fn grant_budget_status_reflects_revoked_status() {
        // When the grant envelope is revoked, the budget-status projection
        // surfaces the terminal state to the caller instead of lying that
        // it's still active.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("revoked-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-r");
        store.revoke_grant(&grant_id).unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "revoked");
    }

    // --- development milestone regression tests ---------------------------------
    // These tests verify that the `force: true` policy-bypass flag on
    // `create_grant` is NOT honored when the request arrives via the socket
    // entry point (`DispatchSource::Socket`). Previously an unauthenticated
    // socket client could pass `force: true` and skip every policy gate.

    #[tokio::test]
    async fn create_grant_socket_rejects_force_true() {
        // A socket client sends `create_grant` with `force: true`. The
        // handler must reject with -32602 rather than minting the grant.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-victim"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // The default policy's `credential.access.*` rule is
        // `RequireApproval` — without `force`, a socket caller gets a
        // pending approval rather than a grant. With `force: true` the
        // handler MUST reject instead of bypassing policy.
        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602, "socket force must return -32602, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("force"),
            "error should mention force, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn create_grant_socket_without_force_runs_policy() {
        // Same request shape minus `force` — must be treated as an ordinary
        // policy-gated call. With default policy (RequireApproval for
        // credential.access), the response is a pending_approval envelope,
        // NOT a freshly minted grant.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-policy"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            result["status"], json!("pending_approval"),
            "default policy requires approval for credential.access.*"
        );
        assert!(result["approval_id"].is_string());
        // Crucially: no grant id was issued.
        assert!(result.get("id").is_none());
    }

    #[tokio::test]
    async fn create_grant_socket_with_force_false_is_allowed() {
        // Explicit `force: false` is indistinguishable from omitting it —
        // the socket path runs policy either way.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-force-false"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], json!("pending_approval"));
    }

    #[tokio::test]
    async fn create_grant_internal_honors_force() {
        // Internal callers (test harness / admin CLI path) retain the
        // ability to skip policy with `force: true`. This keeps the
        // legitimate bypass path working.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-internal"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal { reason: "test harness — create_grant force bypass" },
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal force should mint a grant, got: {result}"
        );
    }

    // --- development milestone regression tests ---------------------------------
    // A socket caller must assert `caller_persona_id` and it must match the
    // parent grant's owner (`persona_id`). Otherwise any socket process
    // could pick any leaked `parent_grant_id` and mint a child grant
    // pinned to an attacker-controlled persona, forging the audit trail
    // under the legitimate owner's name.

    /// Helper: create two personas (A, B) and a grant owned by A with
    /// delegation depth so it can be further attenuated. Returns the
    /// tuple (a_id, b_id, parent_grant_id). Uses the `Internal` dispatch
    /// path to set up — the `force: true` on `create_grant` requires it.
    async fn c3_setup_two_personas_and_grant(
        store: &DaemonStore,
        vault: &Vault,
        policy: &PolicyEngine,
        rl: &RefCell<RateLimiter>,
    ) -> (String, String, String) {
        let persona_a = dispatch_method(
            store, vault, policy, rl,
            "create_persona",
            &json!({"name": "c3-persona-a"}),
        ).await.unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        let persona_b = dispatch_method(
            store, vault, policy, rl,
            "create_persona",
            &json!({"name": "c3-persona-b"}),
        ).await.unwrap();
        let b_id = persona_b["id"].as_str().unwrap().to_string();

        let parent_grant = dispatch_method(
            store, vault, policy, rl,
            "create_grant",
            &json!({
                "persona_id": a_id,
                "credential_name": "c3-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        ).await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        (a_id, b_id, parent_grant_id)
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_non_owner() {
        // Parent grant is issued to persona A. Persona B tries to delegate
        // it via the socket path. The handler MUST reject before any state
        // mutation — no child grant may be minted, no `grant.delegated`
        // audit row may be written.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Snapshot grant count before the attack to prove nothing was
        // minted. `list_active_grants` returns every active grant in the
        // store; we expect the count to be identical after rejection.
        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Attacker asserts they are B, not A. B does not own
                // `parent_grant_id`.
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32002, "expected -32002, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("does not own"),
            "error should say caller does not own parent, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted when socket caller isn't parent owner"
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_accepts_owner() {
        // Same setup but the socket caller correctly asserts persona A
        // (the parent owner). Delegation must succeed.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "socket owner-delegation must mint a grant, got: {result}"
        );
        assert_eq!(result["parent"], json!(parent_grant_id));
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_missing_caller_persona_id() {
        // Even without a wrong persona id, the socket path must refuse to
        // proceed if the caller omits `caller_persona_id` — fail-closed.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // no caller_persona_id
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32602, "missing param must return -32602, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("caller_persona_id"),
            "error must name the missing parameter, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_internal_bypass() {
        // Internal callers (admin CLI / test harness) bypass the
        // ownership gate. Parent is owned by A; an `Internal` dispatch
        // without any `caller_persona_id` MUST still succeed — mirrors
        // the C2 `force` bypass semantics for Internal.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal { reason: "test harness — delegate_grant ownership bypass" },
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Deliberately omit caller_persona_id — Internal bypasses.
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal bypass must mint a grant, got: {result}"
        );
    }

    // --- development milestone regression tests ----------------------------
    //
    // Full principal binding via `SO_PEERCRED` / `LOCAL_PEERCRED` derived
    // peer credential. The new layer:
    //   1. Enrolls (peer.pid -> persona_id) in `create_persona` from a
    //      Socket caller carrying a real PeerCred.
    //   2. On `delegate_grant`, derives the kernel principal from the
    //      peer's PID and rejects any params.caller_persona_id that
    //      doesn't match the kernel principal (`PrincipalMismatch`).
    //   3. On macOS where pid is None, fails closed with
    //      `PrincipalUnavailable` rather than silently allowing.
    //
    // These tests exercise the handler dispatch surface directly with
    // synthetic `RequestContext` so we don't need a real Unix socket
    // pair or a second OS user — both impossible in CI.

    #[tokio::test]
    async fn forged_caller_persona_id_in_delegate_params_rejected() {
        // The threat model that motivated development milestone: an
        // attacker process running under the daemon's UID enumerates
        // personas, learns the victim's persona_id, and asserts it as
        // `caller_persona_id`.  Under development milestone alone the request
        // would succeed.  Under development milestone the kernel-derived
        // principal does not match, so the handler MUST reject with
        // `PrincipalMismatch`.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Attacker connection: the kernel says the peer is persona B
        // (the attacker's enrolled identity).  Attacker forges params
        // claiming to be A (the parent grant's owner).  The mismatch
        // between asserted A and kernel-derived B must trip the gate
        // BEFORE we even reach the ownership check.
        let attacker_pid: i32 = 70_001;
        enroll_pid_persona(attacker_pid, &b_id);

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred { uid: 1000, pid: Some(attacker_pid) }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        };

        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Attacker forges A as caller — but the kernel knows
                // they are running under PID enrolled to B.
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32401, "expected -32401 PrincipalMismatch, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("principal")
                || err.1.to_lowercase().contains("mismatch"),
            "error should reference principal mismatch, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted when params forge a different caller"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_peercred_resolves_persona_via_pid_lookup() {
        // Happy path on Linux: a Socket caller creates a persona and the
        // daemon enrolls (peer.pid -> persona_id).  A subsequent
        // `delegate_grant` from the same PID is bound to that persona
        // without the caller having to assert `caller_persona_id`.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Use a synthetic PID — never reused by a real process during
        // the test because the registry is thread-local and reset.
        let caller_pid: i32 = 80_002;
        let peer = PeerCred { uid: 1000, pid: Some(caller_pid) };

        // Step 1: create_persona via Socket with the peer credential.
        // Handler enrolls the (pid -> persona_id) pair.
        let create_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        };
        let persona = dispatch_method_with_context(
            &store, &vault, &policy, &rl, None, create_ctx,
            "create_persona",
            &json!({"name": "c3full-linux-caller"}),
        )
        .await
        .unwrap();
        let caller_persona_id = persona["id"].as_str().unwrap().to_string();

        // Verify the enrollment landed.
        let resolved = peercred_principal(&peer)
            .expect("PID must resolve to enrolled persona on Linux");
        assert_eq!(
            resolved, caller_persona_id,
            "peercred_principal must return the enrolled persona id"
        );

        // Step 2: build a parent grant owned by the enrolled persona
        // via Internal (force=true requires Internal).  Then delegate
        // via Socket from the same PID — must succeed without any
        // caller_persona_id forgery.
        let parent_grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": caller_persona_id,
                "credential_name": "c3full-linux-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        // child persona for the delegation target.
        let child = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "c3full-linux-child"}),
        )
        .await
        .unwrap();
        let child_id = child["id"].as_str().unwrap().to_string();

        let delegate_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        };
        let result = dispatch_method_with_context(
            &store, &vault, &policy, &rl, None, delegate_ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_id,
                "scope": "read",
                // Caller may also assert caller_persona_id; if so, it
                // must match the kernel principal.  Here we assert the
                // correct value to exercise the matching branch.
                "caller_persona_id": caller_persona_id,
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "Linux peercred-resolved owner must mint a grant, got: {result}"
        );
        assert_eq!(result["parent"], json!(parent_grant_id));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_peercred_pid_none_fails_closed() {
        // macOS LOCAL_PEERCRED does not always surface the peer PID.
        // When pid is `None` we cannot derive a principal — the only
        // safe move is to fail-closed with `PrincipalUnavailable`.
        // Falling back to UID-only binding would let any same-UID
        // process claim any persona, defeating the gate.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;
        // Suppress unused warning when the kernel-principal path runs
        // before the ownership check would have been hit.
        let _ = a_id;

        // Peer credential with no PID — the macOS edge case.
        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred { uid: 1000, pid: None }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
        };

        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_context(
            &store, &vault, &policy, &rl, None, ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Even with a "correct" caller_persona_id assertion,
                // the daemon must still reject — pid=None means the
                // principal is unverifiable, so we cannot trust ANY
                // attacker-supplied caller_persona_id.
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32401, "expected -32401 PrincipalUnavailable, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("unavailable")
                || err.1.to_lowercase().contains("principal"),
            "error should mention principal unavailable, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted on macOS when pid is None"
        );
    }

    #[test]
    fn peercred_principal_returns_unavailable_when_pid_is_none() {
        // Direct unit test of the peercred_principal helper — no
        // dispatch overhead.  This is the single-source-of-truth for
        // the macOS fail-closed semantics.
        let peer = PeerCred { uid: 1000, pid: None };
        match peercred_principal(&peer) {
            Err(HandlerError::PrincipalUnavailable) => {}
            other => panic!(
                "expected PrincipalUnavailable for pid=None, got: {other:?}"
            ),
        }
    }

    #[test]
    fn peercred_principal_returns_not_enrolled_for_unknown_pid() {
        // Direct unit test: a PID with no enrollment yields
        // `PrincipalNotEnrolled` — the caller has not yet established
        // an identity in this daemon.
        clear_pid_persona_registry();
        let peer = PeerCred { uid: 1000, pid: Some(99_999) };
        match peercred_principal(&peer) {
            Err(HandlerError::PrincipalNotEnrolled) => {}
            other => panic!(
                "expected PrincipalNotEnrolled for un-enrolled PID, got: {other:?}"
            ),
        }
    }

    fn minimal_req() -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-0bc51eff-0000-0000-0000-000000000000".to_string(),
            persona_id: "persona-abc".to_string(),
            credential_name: "github-token".to_string(),
            scope: "repo:read".to_string(),
            ttl_secs: Some(1800),
            action: "credential.access.github-token".to_string(),
            risk_level: "high".to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
            skill_ref: None,
        }
    }

    #[test]
    fn build_banner_includes_tool_and_target_when_present() {
        let mut req = minimal_req();
        req.tool_name = Some("claude-code".to_string());
        req.target_url = Some("api.github.com/repos/emberdotlink/emberlink".to_string());

        let banner = build_banner("claude-code", &req);

        assert!(
            banner.title.contains("claude-code"),
            "title should include tool_name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("api.github.com"),
            "body should include target_url, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn build_banner_falls_back_without_new_fields() {
        let req = minimal_req();
        let banner = build_banner("demo-agent", &req);

        assert!(
            banner.title.contains("demo-agent"),
            "title should include persona name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should fall back to click-to-review prompt, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    // --- per-op user-presence wiring ---
    //
    // These tests prove the new methods (`vault_remove`, `vault_lock`,
    // `vault_status`) dispatch correctly. The gate's lock/allow state
    // machine has its own coverage in `crate::trust::presence::tests`. Because
    // cargo-test binaries set `dev_mode_enabled() = true`, the gate
    // returns `Allowed` for every call here, exercising the wire shape
    // without forcing live keychain access.

    #[tokio::test]
    async fn vault_remove_round_trip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": "to-be-removed", "value": "secret"}),
        ).await.unwrap();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_remove",
            &json!({"name": "to-be-removed"}),
        ).await.unwrap();
        assert_eq!(result["removed"], json!(true));
        assert_eq!(result["name"], json!("to-be-removed"));
    }

    #[tokio::test]
    async fn vault_remove_missing_name_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_remove",
            &json!({}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn vault_lock_returns_locked_true() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_lock",
            &json!(null),
        ).await.unwrap();
        assert_eq!(result["locked"], json!(true));
    }

    #[tokio::test]
    async fn vault_status_exposes_session_shape() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_status",
            &json!(null),
        ).await.unwrap();
        // Shape contract: dashboard relies on these field names.
        assert!(result["unlocked"].is_boolean());
        assert!(result["idle_timeout_secs"].is_u64());
        // quiet_hours_* may be null, which is .is_null() (or .is_number() if set).
        assert!(result.get("quiet_hours_start").is_some());
        assert!(result.get("quiet_hours_end").is_some());
    }

    #[tokio::test]
    async fn vault_get_round_trip_returns_plaintext_value() {
        // implementation-note-110: pulumi-render.sh + similar headless
        // integrations call `ember vault get` -> daemon RPC `vault_get`.
        // This proves the RPC arm is wired and returns the decrypted
        // value under the canonical {"value": ...} shape.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": "rpc-fetch-target", "value": "passphrase-42"}),
        ).await.unwrap();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_get",
            &json!({"name": "rpc-fetch-target"}),
        ).await.unwrap();
        assert_eq!(result["value"], json!("passphrase-42"));
    }

    #[tokio::test]
    async fn vault_get_missing_name_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_get",
            &json!({}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn vault_get_unknown_name_returns_application_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_get",
            &json!({"name": "no-such-credential"}),
        ).await.unwrap_err();
        // Generic application error code (-32000) — vault.get returns
        // VaultError::NotFound, mapped uniformly with other vault errors.
        assert_eq!(err.0, -32000);
    }

    #[tokio::test]
    async fn vault_remove_via_socket_source_runs_under_dev_mode_gate() {
        // Even via Socket dispatch (where the gate WOULD run), the
        // cargo-test binary detection short-circuits the gate to Allowed
        // — so the call still succeeds and we can prove the wiring is
        // wired through dispatch_method_with_source, not just the
        // Internal-only convenience entry point.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Seed via Internal so add doesn't trip its own gate path.
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": "seed", "value": "v"}),
        ).await.unwrap();
        // Now exercise via Socket source.
        let result = dispatch_method_with_source(
            &store, &vault, &policy, &rl, None,
            DispatchSource::Socket,
            "vault_remove",
            &json!({"name": "seed"}),
        ).await.unwrap();
        assert_eq!(result["removed"], json!(true));
    }

    /// EMBER-implementation-note-94 integration test: emit synthetic kms_wrap receipts
    /// for two actors, then verify `receipt_query` filters by actor and kind.
    #[tokio::test]
    async fn receipt_query_filters_by_actor_and_kind() {
        use core_types::grant_receipt::{
            Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt,
            ReceiptKind, ReceiptOutcome,
        };
        use crate::infra::receipt::ReceiptFilter;

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Create two personas.
        let actor_a = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "audit-actor-a"}),
        ).await.unwrap();
        let actor_a_id = actor_a["id"].as_str().unwrap().to_string();

        let actor_b = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "audit-actor-b"}),
        ).await.unwrap();
        let actor_b_id = actor_b["id"].as_str().unwrap().to_string();

        let eval_denied = GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        };

        // Insert a synthetic kms_wrap receipt for actor_a.
        let kms_a = KmsReceipt {
            id: "kms-wrap-audit-a".to_string(),
            kind: ReceiptKind::KmsWrap,
            key_name: "test-key".to_string(),
            caller_persona: actor_a_id.clone(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 0,
            grant_evaluation: eval_denied.clone(),
            outcome: ReceiptOutcome::Success,
            evidence: Evidence::default(),
        };
        store.store_kms_receipt(&kms_a).unwrap();

        // Insert a synthetic kms_wrap receipt for actor_b.
        let kms_b = KmsReceipt {
            id: "kms-wrap-audit-b".to_string(),
            kind: ReceiptKind::KmsWrap,
            key_name: "test-key".to_string(),
            caller_persona: actor_b_id.clone(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 0,
            grant_evaluation: eval_denied,
            outcome: ReceiptOutcome::Success,
            evidence: Evidence::default(),
        };
        store.store_kms_receipt(&kms_b).unwrap();

        // receipt_query with no filter returns both.
        let all = dispatch_method(
            &store, &vault, &policy, &rl,
            "receipt_query", &json!({}),
        ).await.unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2, "no filter → both rows");

        // receipt_query filtered to actor_a returns exactly one row.
        let actor_a_rows = dispatch_method(
            &store, &vault, &policy, &rl,
            "receipt_query", &json!({"actor": actor_a_id}),
        ).await.unwrap();
        let arr = actor_a_rows.as_array().unwrap();
        assert_eq!(arr.len(), 1, "actor filter → one row for actor_a");
        assert_eq!(arr[0]["actor"].as_str().unwrap(), actor_a_id.as_str());

        // receipt_query filtered to kind=kms_wrap returns both (no actor filter).
        let kms_rows = dispatch_method(
            &store, &vault, &policy, &rl,
            "receipt_query", &json!({"kind": "kms_wrap"}),
        ).await.unwrap();
        assert_eq!(kms_rows.as_array().unwrap().len(), 2, "kind=kms_wrap → both rows");

        // Validate via store directly (acceptance: per-actor indexes confirmed).
        let direct = store.query_receipts(&ReceiptFilter {
            persona_id: Some(actor_b_id.clone()),
            ..Default::default()
        }).unwrap();
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].actor, actor_b_id);
        assert_eq!(direct[0].kind, "kms_wrap");
    }

    // -----------------------------------------------------------------
    // implementation-note-102 Phase 2: sops_unwrap_dek RPC tests
    // -----------------------------------------------------------------

    /// Build an age-encrypted DEK ciphertext for the given recipient
    /// public key. Used by the sops_unwrap_dek tests below.
    #[cfg(feature = "age")]
    fn encrypt_dek_for(public_key: &str, plaintext: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let recipient: age::x25519::Recipient = public_key.parse().unwrap();
        let encryptor = age::Encryptor::with_recipients(vec![
            Box::new(recipient) as Box<dyn age::Recipient + Send>,
        ])
        .unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        ciphertext
    }

    /// Happy path: a valid grant + a vault-stored age key + a
    /// well-formed ciphertext returns the plaintext DEK as hex.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_happy_path_returns_plaintext() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-happy"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Generate an age keypair, stash the private key in the vault
        // at the canonical path, and prepare a ciphertext recipient.
        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        ).await.unwrap();

        let plaintext_dek = b"deadbeef-this-is-the-data-encryption-key";
        let ciphertext = encrypt_dek_for(&keypair.public_key, plaintext_dek);
        let blob_hex = hex::encode(&ciphertext);

        // The brief defines the receipted credential as the SOPS DEK
        // unwrap, not a vault credential — but the grant gating still
        // requires a credential_name. Use the canonical vault_path so a
        // single grant covers both "read the age key" and "unwrap a
        // DEK" semantics from the operator's POV.
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap();

        let dek_hex = result["dek_hex"].as_str().unwrap();
        let unwrapped = hex::decode(dek_hex).unwrap();
        assert_eq!(unwrapped.as_slice(), plaintext_dek.as_slice());

        let fp = result["dek_fingerprint"].as_str().unwrap();
        assert_eq!(fp.len(), 32, "fingerprint should be 16 bytes -> 32 hex chars");
        assert_eq!(result["grant_id"], json!(grant_id));
        assert_eq!(result["persona_id"], json!(persona_id));

        // Audit: a sops_dek_unwrapped row should be present.
        assert!(store.is_dek_grant_consumed(grant_id));
    }

    /// Rate-limit: a second call with the same grant_id is rejected.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_duplicate_grant_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-dup"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        ).await.unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // First call: success.
        dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap();

        // Second call with the SAME grant_id: rejected with -32005
        // (the same code we use for revoked / inactive grants).
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32005);
        assert!(
            err.1.contains("already been used") || err.1.contains("already-consumed"),
            "expected duplicate-rejection message, got: {}",
            err.1
        );
    }

    /// Cross-persona attack: caller supplies a valid grant_id whose
    /// persona doesn't match the asserted persona_id. Rejected.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_cross_persona_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-owner"}),
        ).await.unwrap();
        let owner_id = owner["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(owner_id);
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        ).await.unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": owner_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": "persona-other",
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32002);
        // Slot must NOT be consumed when the caller is rejected.
        assert!(!store.is_dek_grant_consumed(grant_id));
    }

    /// Inactive grant: a revoked grant cannot unwrap a DEK.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_revoked_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-revoked"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        ).await.unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        dispatch_method(
            &store, &vault, &policy, &rl,
            "revoke_grant", &json!({"id": grant_id}),
        ).await.unwrap();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32005);
    }

    /// Missing persona age key: vault has no entry at the canonical
    /// path, so the unwrap fails with a clear -32000 error.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_errors_when_age_key_missing() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-no-key"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let vault_path = crate::age::vault_path_for_persona(persona_id);
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // Build a synthetic ciphertext (won't be reached — vault lookup fails).
        let dummy_keypair = crate::age::generate_age_keypair().unwrap();
        let ciphertext = encrypt_dek_for(&dummy_keypair.public_key, b"x");
        let blob_hex = hex::encode(&ciphertext);

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32000);
        assert!(err.1.contains("no age private key"), "got: {}", err.1);
        // Slot must NOT be consumed when the vault lookup fails — we
        // reject before claiming it.
        assert!(!store.is_dek_grant_consumed(grant_id));
    }

    /// Malformed hex blob: caller passes an unparseable hex string.
    /// Rejected with -32602 (invalid params).
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_malformed_hex() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "sops-bad-hex"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": "not-hex!@#",
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    // ---- implementation-note-18: await_approval block-and-poll RPC -----------------

    #[tokio::test]
    async fn await_approval_returns_approved_when_resolved_mid_poll() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Mint persona + pending approval row directly.
        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "ap4-approve"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-x", "read", None, "Bash", "low")
            .unwrap();
        let approval_id = approval.id.clone();

        // Resolve the approval before the poll fires (synchronous setup -
        // the dispatch call below will hit the resolved state on its first
        // get_approval lookup).
        store
            .resolve_approval(&approval_id, &crate::trust::approval::ApprovalOutcome::Approved)
            .unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 2}),
        ).await.unwrap();

        assert_eq!(result["decision"]["kind"], json!("approved"), "got: {result}");
    }

    #[tokio::test]
    async fn await_approval_returns_denied_when_resolved_denied() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "ap4-deny"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-y", "read", None, "Bash", "high")
            .unwrap();
        let approval_id = approval.id.clone();

        store
            .resolve_approval(
                &approval_id,
                &crate::trust::approval::ApprovalOutcome::Denied {
                    reason: "operator declined".to_string(),
                },
            )
            .unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 2}),
        ).await.unwrap();

        assert_eq!(result["decision"]["kind"], json!("denied"), "got: {result}");
        assert!(
            result["decision"]["reason"].as_str().unwrap_or("").contains("operator declined"),
            "got: {result}"
        );
    }

    #[tokio::test]
    async fn await_approval_returns_timed_out_after_deadline() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona", &json!({"name": "ap4-timeout"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-z", "read", None, "Bash", "med")
            .unwrap();
        let approval_id = approval.id.clone();

        // Don't resolve - let the deadline fire. timeout_secs=0 short-circuits
        // after the first poll cycle so the test doesn't spend wall-clock time.
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 0}),
        ).await.unwrap();

        assert_eq!(result["decision"]["kind"], json!("timed_out"), "got: {result}");
    }

    #[tokio::test]
    async fn await_approval_unknown_request_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "await_approval",
            &json!({"request_id": "approval-does-not-exist", "timeout_secs": 1}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004, "got: {err:?}");
    }

    #[tokio::test]
    async fn await_approval_missing_request_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "await_approval",
            &json!({"timeout_secs": 1}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602, "got: {err:?}");
    }

    // implementation-note-98 — graceful binding delete (design).
    #[tokio::test]
    async fn binding_delete_revokes_persona_and_cascades_grants() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Provision a workload Persona + a grant. The binding cascade
        // is the assertion target — after delete, the persona is
        // revoked AND the grant is drained (status=revoked).
        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "ml-eval-worker"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // `force: true` honored on Internal dispatch (test harness) — bypasses
        // the policy approval gate so the test exercises the cascade path,
        // not the approval queue.
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
                "scope": "llm:generate",
                "ttl_secs": 3600,
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"]
            .as_str()
            .unwrap_or_else(|| panic!("create_grant response missing id: {grant:?}"))
            .to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.delete",
            &json!({
                "persona_id": persona_id,
                "binding_request_id": "br-test-001",
            }),
        ).await.unwrap();
        assert_eq!(resp["deleted"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));

        // Grant should now be drained — i.e. evaluate_grant fails because
        // the cascade flipped its status to `revoked`.
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "evaluate_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32000);

        // Audit log must contain a `binding.deleted` row tied to the persona.
        let audit = dispatch_method(
            &store, &vault, &policy, &rl,
            "audit_query",
            &json!({"persona_id": persona_id}),
        ).await.unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries.iter().any(|e| e["action"] == json!("binding.deleted")),
            "expected binding.deleted audit row, got {entries:?}"
        );
        // The grant id is unused beyond the cascade assertion above; bind
        // it once so the compiler doesn't warn about an unused let.
        let _ = grant_id;
    }

    #[tokio::test]
    async fn binding_delete_missing_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.delete",
            &json!({}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_delete_unknown_persona_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.delete",
            &json!({"persona_id": "persona-does-not-exist"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_delete_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "alias-worker"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding_delete",
            &json!({"persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(resp["deleted"], json!(true));
    }

    // implementation-note-99 — compromise-response revocation
    // (design §"binding.revoke_urgent").
    #[tokio::test]
    async fn binding_revoke_urgent_cascades_grants_and_emits_urgent_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "compromised-worker"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // Provision a grant under the persona — it must be cascaded
        // to `revoked` by the urgent path, same as `binding.delete`.
        let _grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
                "scope": "llm:generate",
                "ttl_secs": 3600,
                "force": true,
            }),
        ).await.unwrap();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.revoke_urgent",
            &json!({
                "persona_id": persona_id,
                "binding_request_id": "br-urgent-001",
                "reason": "credential leaked in public repo",
            }),
        ).await.unwrap();
        assert_eq!(resp["revoked_urgent"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));

        // Cascade assertion: evaluate_grant fails because the urgent
        // path flipped the grant to `revoked` (same SQL as delete).
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "evaluate_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32000);

        // Audit assertion: action MUST be `binding.revoke_urgent` (NOT
        // `binding.deleted` — operators distinguish urgent revocations
        // from graceful deletes for compliance + alerting).
        let audit = dispatch_method(
            &store, &vault, &policy, &rl,
            "audit_query",
            &json!({"persona_id": persona_id}),
        ).await.unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries.iter().any(|e| {
                e["action"] == json!("binding.revoke_urgent")
                    && e["outcome"] == json!("urgent")
            }),
            "expected binding.revoke_urgent + outcome=urgent audit row, got {entries:?}"
        );
    }

    #[tokio::test]
    async fn binding_revoke_urgent_missing_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.revoke_urgent",
            &json!({}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_revoke_urgent_unknown_persona_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.revoke_urgent",
            &json!({"persona_id": "persona-does-not-exist"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_revoke_urgent_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "alias-urgent-worker"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding_revoke_urgent",
            &json!({"persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(resp["revoked_urgent"], json!(true));
    }

    // implementation-note-100 — mutate binding metadata
    // (design §"binding.update").
    #[tokio::test]
    async fn binding_update_mutates_name_and_emits_before_after_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "old-name"}),
        ).await.unwrap();
        let binding_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.update",
            &json!({
                "binding_id": binding_id,
                "binding_request_id": "br-update-001",
                "name": "new-name",
                "cred_class_allowlist": ["llm:generate", "fs:read"],
                "lease_duration_cap": 3600,
            }),
        ).await.unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["binding_id"], json!(binding_id));
        assert_eq!(resp["name"], json!("new-name"));

        // Persona row in SQL must reflect the new name.
        let fetched = store.get_persona(&binding_id).unwrap();
        assert_eq!(fetched.name, "new-name");

        // Audit row carries the before/after snapshot AND the
        // audit-only metadata fields the caller passed. The
        // `audit_query` JSON-RPC response strips `details` (operator
        // dashboards don't paginate details JSON), so read directly
        // via `query_audit` to assert the full payload landed.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(binding_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.updated")
            .unwrap_or_else(|| panic!("expected binding.updated audit row, got {entries:?}"));
        let details: serde_json::Value = serde_json::from_str(
            row.details.as_deref().expect("details JSON populated"),
        )
        .expect("details parses as JSON");
        assert_eq!(details["before"]["name"], json!("old-name"));
        assert_eq!(details["after"]["name"], json!("new-name"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate", "fs:read"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
        assert_eq!(details["binding_request_id"], json!("br-update-001"));
    }

    #[tokio::test]
    async fn binding_update_missing_binding_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.update",
            &json!({"name": "irrelevant"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_update_unknown_binding_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.update",
            &json!({
                "binding_id": "persona-does-not-exist",
                "name": "ghost",
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_update_duplicate_name_returns_32005() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Create two personas — renaming one to the other's name must
        // hit the UNIQUE constraint and surface as -32005.
        let _occupant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "occupied"}),
        ).await.unwrap();
        let other = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "free"}),
        ).await.unwrap();
        let other_id = other["id"].as_str().unwrap().to_string();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.update",
            &json!({
                "binding_id": other_id,
                "name": "occupied",
            }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32005);
    }

    #[tokio::test]
    async fn binding_update_underscore_alias_and_persona_id_synonym_dispatch() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "alias-update-worker"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // Underscore alias + `persona_id` synonym for `binding_id`.
        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding_update",
            &json!({
                "persona_id": persona_id,
                "name": "alias-update-renamed",
            }),
        ).await.unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["name"], json!("alias-update-renamed"));
    }

    #[tokio::test]
    async fn binding_update_no_mutation_still_emits_audit() {
        // Sanity: a no-op update (no `name` change requested) is
        // still a valid call — it serves as a "touch" for the
        // reconciler to record a binding-update receipt.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "touch-target"}),
        ).await.unwrap();
        let binding_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.update",
            &json!({
                "binding_id": binding_id,
                "binding_request_id": "br-touch-001",
                "metadata": {"reconciler_pass": "ts-2026-05-07"},
            }),
        ).await.unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["name"], json!("touch-target"));

        let audit = dispatch_method(
            &store, &vault, &policy, &rl,
            "audit_query",
            &json!({"persona_id": binding_id}),
        ).await.unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries.iter().any(|e| e["action"] == json!("binding.updated")),
            "expected binding.updated audit row, got {entries:?}"
        );
    }

    // implementation-note-101 — idempotent insert-or-update
    // (design §"binding.upsert").

    #[tokio::test]
    async fn binding_upsert_creates_when_persona_absent() {
        // First-pass reconcile: no persona row exists yet. The verb
        // creates one and emits a `binding.upserted` audit row with
        // `before: null` and a populated `after` snapshot.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({
                "namespace": "ns-prod",
                "name": "ml-eval-worker",
                "binding_request_id": "br-upsert-001",
                "cred_class_allowlist": ["llm:generate", "fs:read"],
                "lease_duration_cap": 3600,
                "metadata": {"sa_uid": "uid-abc"},
            }),
        ).await.unwrap();

        assert_eq!(resp["created"], json!(true));
        assert_eq!(resp["updated"], json!(false));
        assert_eq!(resp["name"], json!("ml-eval-worker"));
        let canonical_id = resp["persona_id"]
            .as_str()
            .expect("response carries persona_id");

        // Persona row exists in SQL with `active` status and the
        // requested name.
        let row = store.get_persona(canonical_id).unwrap();
        assert_eq!(row.name, "ml-eval-worker");
        assert_eq!(row.status, "active");

        // Audit row carries the create snapshot AND the audit-only
        // metadata fields the caller passed.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(canonical_id.to_string()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.upserted")
            .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
        let details: serde_json::Value = serde_json::from_str(
            row.details.as_deref().expect("details JSON populated"),
        )
        .expect("details parses as JSON");
        assert_eq!(details["created"], json!(true));
        assert_eq!(details["before"], serde_json::Value::Null);
        assert_eq!(details["after"]["name"], json!("ml-eval-worker"));
        assert_eq!(details["after"]["status"], json!("active"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate", "fs:read"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
        assert_eq!(details["requested"]["namespace"], json!("ns-prod"));
        assert_eq!(details["requested"]["metadata"], json!({"sa_uid": "uid-abc"}));
        assert_eq!(details["binding_request_id"], json!("br-upsert-001"));
    }

    #[tokio::test]
    async fn binding_upsert_updates_when_persona_present() {
        // Steady-state reconcile: persona row already exists. The
        // verb reuses its id, mutates `name` if the request asks for
        // a rename, and emits an audit row with a populated
        // before/after diff.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "old-name"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({
                "persona_id": persona_id,
                "name": "new-name",
                "binding_request_id": "br-upsert-002",
                "cred_class_allowlist": ["llm:generate"],
                "lease_duration_cap": 7200,
                "metadata": {"reconciler_pass": "ts-2026-05-07"},
            }),
        ).await.unwrap();

        assert_eq!(resp["created"], json!(false));
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));
        assert_eq!(resp["name"], json!("new-name"));

        // Persona row name updated in SQL.
        let row = store.get_persona(&persona_id).unwrap();
        assert_eq!(row.name, "new-name");

        // Audit row carries before/after diff.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(persona_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.upserted")
            .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
        let details: serde_json::Value = serde_json::from_str(
            row.details.as_deref().expect("details JSON populated"),
        )
        .expect("details parses as JSON");
        assert_eq!(details["created"], json!(false));
        assert_eq!(details["before"]["name"], json!("old-name"));
        assert_eq!(details["after"]["name"], json!("new-name"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(7200));
        assert_eq!(details["binding_request_id"], json!("br-upsert-002"));
    }

    #[tokio::test]
    async fn binding_upsert_idempotent_no_mutation_still_emits_audit() {
        // Replay-safety: calling upsert twice with the same params
        // updates nothing on the second call but still emits a
        // fresh `binding.upserted` audit row (the reconciler relies
        // on per-call receipts for retry idempotency).
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let first = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({
                "name": "stable-worker",
                "binding_request_id": "br-replay-001",
            }),
        ).await.unwrap();
        let persona_id = first["persona_id"].as_str().unwrap().to_string();

        let second = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({
                "persona_id": persona_id,
                "name": "stable-worker",
                "binding_request_id": "br-replay-001",
            }),
        ).await.unwrap();
        assert_eq!(second["created"], json!(false));
        assert_eq!(second["updated"], json!(true));
        assert_eq!(second["persona_id"], json!(persona_id));

        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(persona_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let upsert_count = entries
            .iter()
            .filter(|e| e.action == "binding.upserted")
            .count();
        assert_eq!(
            upsert_count, 2,
            "expected two binding.upserted audit rows, got {entries:?}"
        );
    }

    #[tokio::test]
    async fn binding_upsert_missing_both_id_and_name_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({"binding_request_id": "br-noop"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_upsert_unknown_persona_id_with_name_creates_fresh() {
        // Snapshot-drift path: caller supplies a `persona_id` that
        // does not exist on this daemon (e.g. cluster restored from
        // an older etcd snapshot pointing at a rotated id). With a
        // `name` available, the verb falls through to the create
        // path and returns the daemon's freshly-minted canonical id.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding.upsert",
            &json!({
                "persona_id": "persona-stale-id",
                "name": "drift-recovered-worker",
            }),
        ).await.unwrap();
        assert_eq!(resp["created"], json!(true));
        let canonical_id = resp["persona_id"].as_str().unwrap();
        assert_ne!(canonical_id, "persona-stale-id");
    }

    #[tokio::test]
    async fn binding_upsert_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store, &vault, &policy, &rl,
            "binding_upsert",
            &json!({"name": "alias-upsert-worker"}),
        ).await.unwrap();
        assert_eq!(resp["created"], json!(true));
        assert_eq!(resp["name"], json!("alias-upsert-worker"));
    }

    // -------------------------------------------------------------------------
    // implementation-note-107: register_session + close_session T2
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn register_session_and_close_session_emit_clean_exit_receipt() {
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "sess-test-persona"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert!(!grant_id.is_empty(), "grant must be created");

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());

        let reg = dispatch_method_with_context(
            &store, &vault, &policy, &rl,
            None, ctx.clone(),
            "register_session",
            &json!({
                "persona": "sess-test-persona",
                "launcher_pid": std::process::id(),
            }),
        ).await.unwrap();

        let session_id = reg["session_id"].as_str().unwrap().to_string();
        let reg_grant_id = reg["grant_id"].as_str().unwrap();
        assert_eq!(reg_grant_id, grant_id, "register_session must return the active grant id");
        assert!(!session_id.is_empty(), "session_id must be non-empty");

        let session_dir = sessions_dir.join(&session_id);
        assert!(session_dir.exists(), "session directory must be created");
        assert!(
            session_dir.join("meta.json").exists(),
            "meta.json must be written"
        );

        let close = dispatch_method_with_context(
            &store, &vault, &policy, &rl,
            None, ctx,
            "close_session",
            &json!({ "session_id": session_id }),
        ).await.unwrap();

        assert_eq!(close["closed"], json!(true), "close_session must return closed:true");

        let receipt_path = session_dir.join("receipt.json");
        let receipt_bytes = std::fs::read(&receipt_path)
            .expect("receipt.json must be written by close_session");
        assert!(!receipt_bytes.is_empty(), "receipt.json must be non-empty");

        let envelope: core_events::receipt::ReceiptEnvelope =
            serde_json::from_slice(&receipt_bytes).expect("receipt.json parses as v2 envelope");
        assert_eq!(envelope.kind, "session.claude_code");
        assert!(envelope.signature.is_some(), "receipt must be signed");

        let body: core_events::receipt::ClaudeCodeBody =
            serde_json::from_value(envelope.body).unwrap();
        assert_eq!(
            body.termination_reason,
            Some(core_events::receipt::TerminationReason::CleanExit),
            "termination_reason must be clean_exit"
        );

        assert!(
            !session_dir.join("meta.json").exists(),
            "meta.json must be renamed to meta.json.closed on close"
        );
        assert!(
            session_dir.join("meta.json.closed").exists(),
            "meta.json.closed must exist after close"
        );

        // implementation-note-108: grant must remain
        // Active after CleanExit — the handler no longer calls revoke_grant.
        let grant_after = store.get_grant(grant_id).expect("grant still queryable");
        assert_eq!(
            grant_after.status, "active",
            "CleanExit MUST NOT revoke the grant — multi-session per 24h grant invariant"
        );
    }

    #[tokio::test]
    async fn register_session_fails_without_sessions_dir() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let ctx = RequestContext::internal("test harness");

        let err = dispatch_method_with_context(
            &store, &vault, &policy, &rl,
            None, ctx,
            "register_session",
            &json!({ "persona": "x", "launcher_pid": 1u32 }),
        ).await.unwrap_err();
        assert_eq!(err.0, -32000, "should fail with -32000 when sessions_dir absent");
        assert!(err.1.contains("sessions_dir"), "error should mention sessions_dir");
    }

    // implementation-note-111: daemon-side T2 (updated for
    // implementation-note-88) — register_session
    // response must include the real LLM proxy URL from RequestContext.
    #[tokio::test]
    async fn register_session_response_includes_real_proxy_url() {
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        let expected_proxy_url = "http://127.0.0.1:61169";

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "proxy-url-test-persona"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        ).await.unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());
        // Wire the URL via RequestContext — the correct path after
        // implementation-note-88.
        ctx.llm_proxy_url = Some(expected_proxy_url.to_string());

        let reg = dispatch_method_with_context(
            &store, &vault, &policy, &rl,
            None, ctx,
            "register_session",
            &json!({
                "persona": "proxy-url-test-persona",
                "launcher_pid": std::process::id(),
            }),
        ).await.unwrap();

        let got_proxy_url = reg["proxy_url"].as_str().expect("proxy_url must be present in response");
        assert_eq!(
            got_proxy_url, expected_proxy_url,
            "register_session must return the real LLM proxy URL from RequestContext, not the 8484 fallback"
        );
        assert_ne!(
            got_proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be the hardcoded 8484 fallback when ctx.llm_proxy_url is set"
        );
    }

    // implementation-note-88: T2 test —
    // register_session must read the LLM proxy URL from RequestContext,
    // NOT from std::env::var. The env var may be absent or stale due to
    // Rust 2024 std::env::set_var cross-thread visibility hazard (tokio
    // worker threads may not observe a set_var from the startup thread).
    // The fix in #2389 relied on set_var; this test proves the correct fix.
    //
    // Key assertion: even if EMBER_PROXY_URL is set to a DIFFERENT (wrong)
    // value in the environment, the response uses the URL from RequestContext.
    #[tokio::test]
    async fn register_session_response_uses_request_context_proxy_url() {
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        // Deliberately set EMBER_PROXY_URL to a wrong value to prove the
        // handler does NOT read it. RequestContext plumbing should win.
        // SAFETY: test-only; value is removed after the test.
        unsafe {
            std::env::set_var("EMBER_PROXY_URL", "http://127.0.0.1:8484");
        }

        let persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "ctx-proxy-url-test-persona"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        ).await.unwrap();

        // Populate RequestContext with the real URL — this is what
        // SocketListener.with_llm_proxy_url wires in production.
        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());
        // implementation-note-88: this URL must
        // appear in the response; the env var ("8484") must be ignored.
        ctx.llm_proxy_url = Some("http://127.0.0.1:55555".to_string());

        let reg = dispatch_method_with_context(
            &store, &vault, &policy, &rl,
            None, ctx,
            "register_session",
            &json!({
                "persona": "ctx-proxy-url-test-persona",
                "launcher_pid": std::process::id(),
            }),
        ).await.unwrap();

        // Restore env so subsequent tests are not polluted.
        unsafe {
            std::env::remove_var("EMBER_PROXY_URL");
        }

        let got_proxy_url = reg["proxy_url"].as_str()
            .expect("proxy_url must be present in response");
        assert_eq!(
            got_proxy_url, "http://127.0.0.1:55555",
            "register_session must use ctx.llm_proxy_url from RequestContext, not env::var"
        );
        assert_ne!(
            got_proxy_url, "http://127.0.0.1:8484",
            "register_session must ignore EMBER_PROXY_URL env var; RequestContext wins"
        );
    }
}
