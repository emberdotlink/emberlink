//! Session lifecycle RPC helpers for the launcher-facing `register_session`
//! and `close_session` methods.
//! CLASSIFICATION: PUBLIC

use std::path::{Path, PathBuf};
use std::time::Duration;

use core_state::sessions::{SessionStore, SessionWorkspaceBinding};
use serde_json::{Value, json};

use crate::infra::{
    claim_journal::{
        close_session_scope_best_effort, close_summary_audit_fields,
        summarize_session_scope_best_effort,
    },
    endpoint_gate::{AdmissionPolicy, PeerIdentity, evaluate_admission},
    handler::RequestContext,
    handlers::principal::{
        ensure_connect_only_owner_matches_trusted_principal, trusted_request_persona,
    },
    handlers::session_authority_lane::{mint_runtime_lane, resolve_runtime_attach_target},
    receipt::current_identity,
    rpc_error::RpcError,
    store::DaemonStore,
};

const ISOLATED_BRIDGE_CLIENT_CERT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const ATTACHMENT_REBIND_WAIT_BUDGET: Duration = Duration::from_millis(1500);
const ATTACHMENT_REBIND_POLL_INTERVAL: Duration = Duration::from_millis(50);
const CLAUDE_CODE_DEFAULT_SCOPE: &str = "claude-code-default-v1";
const CODEX_DEFAULT_SCOPE: &str = "codex-default-v1";
const ANTHROPIC_PROVIDER_CREDENTIAL_PREFIX: &str = "anthropic/";
const ANTHROPIC_API_KEY_CREDENTIAL_PREFIX: &str = "anthropic/api/key/";
const ANTHROPIC_PLAN_OAUTH_CREDENTIAL_PREFIX: &str = "anthropic/plan/claude-oauth/";
const ANTHROPIC_RUNTIME_CREDENTIAL_HINT: &str =
    "anthropic/plan/claude-oauth/* or anthropic/api/key/*";
const OPENAI_PROVIDER_CREDENTIAL_PREFIX: &str = "openai/";
const OPENAI_CHATGPT_PLAN_CREDENTIAL_PREFIX: &str = "openai/plan/chatgpt-oauth/";
const OPENAI_RUNTIME_CREDENTIAL_HINT: &str = "openai/plan/chatgpt-oauth/<account>/<subject>";
// ADR 215 §2 — gemini Code Assist OAuth ("Sign in with Google") lane. The
// credential is the harvested `oauth_creds` blob stored under a single
// `google/code-assist-oauth` name (no `<account>/<subject>` sub-segments like
// the OpenAI plan credential), so the "prefix" is the full credential name.
const GOOGLE_PROVIDER_CREDENTIAL_PREFIX: &str = "google/";
const GOOGLE_CODE_ASSIST_OAUTH_CREDENTIAL: &str = "google/code-assist-oauth";
const GOOGLE_RUNTIME_CREDENTIAL_HINT: &str = "google/code-assist-oauth";
const GEMINI_DEFAULT_SCOPE: &str = "gemini-default-v1";
const ENDPOINT_GROUP_ROLLBACK_KEY: &str = "__endpoint_group_lifecycle";

/// target_state_anchor: SCION-everywhere — synthetic socket-path key for
/// host-mode `agent_socket_enrollments` rows written by
/// `handle_register_session` and revoked by `handle_close_session`.
/// The `host-mode/` prefix keeps these rows distinguishable from real
/// per-agent UDS enrollments produced by the SCION path.
pub(crate) fn host_mode_enrollment_socket_path(session_id: &str) -> String {
    format!("host-mode/{session_id}")
}

/// target_state_anchor: session_lookup_or_open_owned_by_session_handler —
/// `session.lookup_or_open` JSON-RPC verb — peercred-bound session
/// lookup/creation per the peercred principal-binding contract.
///
/// This helper is the kernel-attested identity barrier for session-open.
/// On launcher flows that also establish caller enrollment and attach
/// workflow authority, those steps must remain a compound atomic
/// transaction: callers must not observe a "session opened first,
/// authority attached later" gap. The richer launcher-facing path lives
/// in `infra::handlers::session::handle_register_session`; this helper
/// keeps the low-level peercred gate explicit so future refactors do not
/// weaken the invariant by treating `session.lookup_or_open` as a casual
/// lookup.
///
/// Returns the (session_id, persona, parent_pid) triple for the
/// caller's existing session, or opens a fresh session bound to the
/// kernel-attested principal. The persona identity is sourced from
/// the kernel-attested `PeerCredPrincipal` — a caller cannot lie
/// about which persona they are.
///
/// **Principal binding gates** (per ADR 094 §"Subprocess identity
/// spoofing (Phase 1)"):
///
/// - When `principal` is `None`, the call is refused with `-32401`
///   ("principal binding unavailable") — `session.lookup_or_open`
///   is wire-only and demands kernel attestation.
/// - When `params.persona` is supplied AND the persona's bound uid
///   does not match `principal.uid`, refuse with `-32004`.
/// - When `params.parent_pid` is supplied AND it disagrees with
///   `principal.pid`, refuse with `-32004` — the brief calls this
///   out: "refuses caller-supplied `parent_pid` that does not match
///   peer pid".
///
/// Params: `{ "persona"?: <string>, "parent_pid"?: <i32> }`
/// Result: `{ "session_id": <string>, "persona_id"?: <string>,
///            "parent_pid": <i32>, "socket_path": <string> }`
///
/// Implements the peercred principal-binding contract.
pub(crate) async fn handle_session_lookup_or_open(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let principal = principal.ok_or_else(|| {
        RpcError::OperatorAttestationFailed(
            "session.lookup_or_open requires kernel-attested principal — \
         wire-only RPC, refused on Internal source"
                .to_string(),
        )
    })?;

    // Refuse if the bound peer has been
    // reaped between connection-accept and this RPC dispatch. PID-reuse
    // could otherwise hand the freshly-recycled PID to a new process
    // that this session would then bind to.
    crate::broker::handler::check_principal_is_alive(Some(principal))?;

    // Persona-name → bound-uid check (when the caller asserts which
    // persona they're opening a session for, kernel attests it).
    // Gate
    // now consults `agent_socket_enrollments` (the new authority) via
    // the store, falling back to the legacy thread-local registry
    // during the transition.
    crate::broker::handler::check_principal_against_persona(
        Some(principal),
        store,
        params,
        "persona",
    )?;

    // parent_pid binding: brief calls this out — caller-supplied
    // parent_pid that does not match peer pid is refused.
    if let Some(claimed_pid) = params.get("parent_pid").and_then(|v| v.as_i64())
        && claimed_pid as i32 != principal.pid
    {
        tracing::warn!(
            claimed_parent_pid = claimed_pid,
            principal_pid = principal.pid,
            principal_uid = principal.uid,
            "session.lookup_or_open: rejecting — claimed parent_pid disagrees with kernel-attested peer pid"
        );
        return Err(RpcError::NotFound(
            format!(
                "principal binding mismatch: claimed parent_pid {} does not match kernel-attested peer pid {}",
                claimed_pid, principal.pid
            ),
        )
        .into());
    }

    // Mint a fresh session id. Production wiring (registry of open
    // sessions, persistence under `sessions_dir`, etc.) lives in the
    // sibling agent-persona-lifecycle task; this surface
    // establishes the peercred gate so the production wiring can
    // drop into a kernel-attested foundation.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let session_id = format!("sess_{:032x}", nanos);

    let mut response = json!({
        "session_id": session_id,
        "parent_pid": principal.pid,
        "socket_path": principal.socket_path.display().to_string(),
    });
    if let Some(persona) = params.get("persona").and_then(|v| v.as_str()) {
        response["persona_id"] = json!(persona);
    }
    Ok(response)
}

fn parse_register_session_workspace_binding(
    params: &Value,
) -> Result<Option<SessionWorkspaceBinding>, (i32, String)> {
    let workspace_ref = params["workspace_ref"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let worktree_path = params["worktree_path"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (workspace_ref, worktree_path) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(RpcError::InvalidParams(
            "register_session: workspace_ref and worktree_path must be provided together"
                .to_string(),
        )
        .into()),
        (Some(workspace_ref), Some(worktree_path)) => {
            let Some(runtime_id) = workspace_ref
                .strip_prefix("managed_worktree:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(RpcError::InvalidParams(format!(
                    "register_session: unsupported workspace_ref {workspace_ref:?}"
                ))
                .into());
            };
            let path = PathBuf::from(worktree_path);
            let canonical = path.canonicalize().map_err(|e| {
                RpcError::InvalidParams(format!(
                    "register_session: worktree_path {worktree_path:?} is not reachable: {e}"
                ))
            })?;
            if !canonical.join(".git").exists() {
                return Err(RpcError::InvalidParams(format!(
                    "register_session: worktree_path {} is not a git worktree",
                    canonical.display()
                ))
                .into());
            }
            Ok(Some(SessionWorkspaceBinding {
                workspace_ref: format!("managed_worktree:{runtime_id}"),
                worktree_path: canonical,
            }))
        }
    }
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct RegisterSessionBridgeClientBundle {
    pub(crate) port: u16,
    pub(crate) client_cert_pem: String,
    pub(crate) client_key_pem: String,
    pub(crate) ca_cert_pem: String,
}

// Manual Debug redacts `client_key_pem` (SCION-209 #2 review MED-3): the
// private key must never reach a log line via a stray `{:?}`. Serialize is
// derived (the key must cross the wire to the orchestrator), but Debug is not.
impl std::fmt::Debug for RegisterSessionBridgeClientBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterSessionBridgeClientBundle")
            .field("port", &self.port)
            .field("client_cert_pem", &self.client_cert_pem)
            .field("client_key_pem", &"<redacted>")
            .field("ca_cert_pem", &self.ca_cert_pem)
            .finish()
    }
}

struct EndpointGroup<'a> {
    store: &'a DaemonStore,
    session_id: String,
    armed: bool,
}

impl<'a> EndpointGroup<'a> {
    // endpoint_group_lifecycle: register_session and close_session route every
    // per-session endpoint teardown through this one owner.
    fn new(store: &'a DaemonStore, session_id: impl Into<String>) -> Self {
        Self {
            store,
            session_id: session_id.into(),
            armed: true,
        }
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn teardown_now(&mut self, reason: &str) {
        if self.armed {
            Self::teardown_all(self.store, &self.session_id, reason);
            self.armed = false;
        }
    }

    fn teardown_all(store: &DaemonStore, session_id: &str, reason: &str) {
        let ssh_grant_id = ssh_signing_grant_id(session_id);
        let _ = store.leases().drop_lease(&ssh_grant_id);
        teardown_ssh_agent_bridge(session_id);

        let host_mode_socket_path = host_mode_enrollment_socket_path(session_id);
        if let Err(e) = store.revoke_agent_socket_enrollment(&host_mode_socket_path) {
            tracing::warn!(
                session_id = %session_id,
                reason,
                error = %e,
                "endpoint_group: revoke host-mode agent_socket_enrollments row failed; session teardown continues"
            );
        }

        let _ = crate::infra::session_proxy::request_close(session_id);
        // Session-keyed; tears down whichever credential-projector loopback
        // lane (codex / gemini) this session opened (ADR 215 §2).
        let _ = crate::infra::loopback_proxy::request_close_loopback(session_id);
        // Cursor baseline is egress/audit only and intentionally separate from
        // the credential-injecting loopback projector registry.
        let _ = crate::infra::cursor_egress_proxy::request_close_cursor_egress(session_id);
    }

    fn open_session_proxy(
        &self,
        spec: crate::infra::session_proxy::SessionProxyOpenSpec,
    ) -> std::io::Result<Option<PathBuf>> {
        crate::infra::session_proxy::request_open(spec)
    }

    fn open_codex_proxy(&self, bound_uid: u32) -> Option<u16> {
        crate::infra::loopback_proxy::request_open_codex(&self.session_id, bound_uid)
    }

    fn open_gemini_proxy(&self, bound_uid: u32) -> Option<u16> {
        crate::infra::loopback_proxy::request_open_gemini(&self.session_id, bound_uid)
    }

    fn open_cursor_egress_proxy(&self, runtime_persona_id: &str, bound_uid: u32) -> Option<u16> {
        crate::infra::cursor_egress_proxy::request_open_cursor_egress(
            &self.session_id,
            runtime_persona_id,
            bound_uid,
        )
    }
}

impl Drop for EndpointGroup<'_> {
    fn drop(&mut self) {
        self.teardown_now("drop");
    }
}

struct RegisterSessionGuard<'a> {
    endpoint_group: EndpointGroup<'a>,
    session_store: &'a SessionStore,
    runtime_grant_id: Option<String>,
    pin_acquired: bool,
    active: bool,
}

impl<'a> RegisterSessionGuard<'a> {
    fn new(
        store: &'a DaemonStore,
        session_store: &'a SessionStore,
        session_id: impl Into<String>,
        runtime_grant_id: Option<String>,
    ) -> Self {
        Self {
            endpoint_group: EndpointGroup::new(store, session_id),
            session_store,
            runtime_grant_id,
            pin_acquired: false,
            active: true,
        }
    }

    fn session_id(&self) -> &str {
        self.endpoint_group.session_id()
    }

    fn note_pin_acquired(&mut self) {
        self.pin_acquired = true;
    }

    fn commit(mut self) {
        self.active = false;
        self.endpoint_group.disarm();
    }
}

impl Drop for RegisterSessionGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let session_id = self.endpoint_group.session_id().to_string();
        self.endpoint_group
            .teardown_now("register_session_rollback");
        if let Some(grant_id) = self.runtime_grant_id.as_deref()
            && let Err(e) = self.endpoint_group.store.revoke_grant(grant_id)
        {
            tracing::warn!(
                session_id = %session_id,
                grant_id,
                error = %e,
                "register_session rollback: revoke runtime grant failed"
            );
        }
        if let Err(e) = self.session_store.close(&session_id) {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "register_session rollback: close session store row failed"
            );
        }
        if self.pin_acquired {
            let _ = crate::infra::interactive_unlock::release_session_pin(&session_id);
        }
    }
}

struct CloseSessionGuard<'a> {
    endpoint_group: EndpointGroup<'a>,
    session_store: &'a SessionStore,
    active: bool,
}

impl<'a> CloseSessionGuard<'a> {
    fn new(store: &'a DaemonStore, session_store: &'a SessionStore, session_id: &str) -> Self {
        Self {
            endpoint_group: EndpointGroup::new(store, session_id),
            session_store,
            active: true,
        }
    }

    fn close_total(&mut self, reason: &str) -> std::io::Result<()> {
        let session_id = self.endpoint_group.session_id().to_string();
        self.endpoint_group.teardown_now(reason);
        let close_result = self.session_store.close(&session_id);
        let _ = crate::infra::interactive_unlock::release_session_pin(&session_id);
        close_result
    }

    fn commit(mut self) -> std::io::Result<()> {
        let result = self.close_total("close_session");
        if result.is_ok() {
            self.active = false;
        }
        result
    }
}

impl Drop for CloseSessionGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(e) = self.close_total("close_session_drop") {
            tracing::warn!(
                session_id = %self.endpoint_group.session_id(),
                error = %e,
                "close_session guard: close session store row failed"
            );
        }
    }
}

fn authority_posture_json(authority_strict: bool, has_delegated_grant: bool) -> Value {
    json!({
        "fallback": if authority_strict { "strict" } else { "jit" },
        "delegation": if has_delegated_grant { "delegated" } else { "ambient" },
    })
}

fn delegation_summary_json(
    _sessions_dir: &Path,
    meta: &core_state::sessions::SessionMeta,
    _context: &str,
) -> Result<Value, (i32, String)> {
    // BKR-4c (ADR 205 §6): the per-session authority lives in the runtime
    // persona's standing grant; the legacy delegation sidecar is retired. The
    // session summary reports the chosen template (stamped on the meta at
    // session-open); the authoritative TTL/scope is the runtime grant chain
    // (`meta.grant_id`).
    Ok(match (&meta.delegation_id, &meta.delegation_template) {
        (Some(delegation_id), Some(template)) => json!({
            "state": "active",
            "delegation_id": delegation_id,
            "template": template,
            "grant_id": meta.grant_id,
        }),
        _ => json!({
            "state": "ambient",
        }),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveAttachmentAuthority {
    pub attachment_id: String,
    pub runtime_persona_id: String,
    pub grant_id: String,
    pub durable_persona_id: Option<String>,
    pub caller_binding_id: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveAttachmentAuthorityError {
    NotFound(String),
    PersonaMismatch { expected: String, actual: String },
    Retryable(String),
    Store(String),
}

impl LiveAttachmentAuthorityError {
    pub fn into_rpc_error(self, rpc_method: &str) -> (i32, String) {
        match self {
            Self::NotFound(message) => {
                RpcError::NotFound(format!("{rpc_method}: {message}")).into()
            }
            Self::PersonaMismatch { expected, actual } => RpcError::PolicyDenied(format!(
                "{rpc_method}: attachment belongs to runtime persona '{actual}', not '{expected}'"
            ))
            .into(),
            Self::Retryable(message) => RpcError::Retryable {
                message: format!("{rpc_method}: {message}"),
            }
            .into(),
            Self::Store(message) => RpcError::Internal(format!("{rpc_method}: {message}")).into(),
        }
    }
}

async fn await_attachment_active(
    sessions_dir: &Path,
    attachment_id: &str,
    expected_persona_id: Option<&str>,
) -> Result<LiveAttachmentAuthority, LiveAttachmentAuthorityError> {
    let deadline = tokio::time::Instant::now() + ATTACHMENT_REBIND_WAIT_BUDGET;
    let session_store = SessionStore::new(sessions_dir.to_path_buf());
    loop {
        let meta = session_store
            .read(attachment_id)
            .map_err(|e| LiveAttachmentAuthorityError::Store(format!("read session: {e}")))?
            .ok_or_else(|| {
                LiveAttachmentAuthorityError::NotFound(format!(
                    "attachment '{attachment_id}' is not live"
                ))
            })?;
        if let Some(expected_persona_id) = expected_persona_id
            && meta.persona != expected_persona_id
        {
            return Err(LiveAttachmentAuthorityError::PersonaMismatch {
                expected: expected_persona_id.to_string(),
                actual: meta.persona,
            });
        }
        let endpoint = session_store
            .read_attachment_endpoint(attachment_id)
            .map_err(|e| {
                LiveAttachmentAuthorityError::Store(format!("read attachment state: {e}"))
            })?
            .ok_or_else(|| {
                LiveAttachmentAuthorityError::NotFound(format!(
                    "attachment '{attachment_id}' has no live authority endpoint"
                ))
            })?;
        if endpoint.is_active() {
            return Ok(LiveAttachmentAuthority {
                attachment_id: endpoint.attachment_id,
                runtime_persona_id: meta.persona,
                grant_id: meta.grant_id,
                durable_persona_id: meta.durable_persona,
                caller_binding_id: meta.caller_binding_id,
                state: endpoint.state,
            });
        }
        if endpoint.is_rebinding() {
            if tokio::time::Instant::now() >= deadline {
                return Err(LiveAttachmentAuthorityError::Retryable(format!(
                    "attachment '{attachment_id}' is rebinding; retry shortly"
                )));
            }
            tokio::time::sleep(ATTACHMENT_REBIND_POLL_INTERVAL).await;
            continue;
        }
        return Err(LiveAttachmentAuthorityError::Retryable(format!(
            "attachment '{attachment_id}' is not active for authority use: state={}",
            endpoint.state
        )));
    }
}

pub(crate) async fn resolve_live_attachment_authority(
    sessions_dir: &Path,
    attachment_id: &str,
    expected_persona_id: Option<&str>,
) -> Result<LiveAttachmentAuthority, LiveAttachmentAuthorityError> {
    await_attachment_active(sessions_dir, attachment_id, expected_persona_id).await
}
/// Resolve the bundled delegation templates directory (ADR 158 §Component 1).
///
/// Priority:
/// 1. `EMBER_DELEGATION_TEMPLATES_ROOT` env override.
/// 2. `/usr/local/lib/ember/delegation-templates/` (prod install).
///
/// This shape mirrors the CLI-side resolver in
/// `emberlink_cli::launcher::claude_code::delegation_template_install_root`,
/// minus the exe-walk fallback (the daemon binary is at a different layout).
fn bundled_delegation_templates_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_DELEGATION_TEMPLATES_ROOT")
        && !override_dir.is_empty()
    {
        return PathBuf::from(override_dir).join("delegation-templates");
    }
    PathBuf::from("/usr/local/lib/ember/delegation-templates")
}

/// Optional operator overlay directory:
/// `<config_dir>/emberlink/delegation-templates/`. Returns `None` when no
/// config dir is resolvable (rare).
fn overlay_delegation_templates_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|c| c.join("emberlink").join("delegation-templates"))
}

/// Launcher-facing session-open transaction.
///
/// This is intentionally compound and effectively atomic from the
/// caller's perspective: persona resolution, active-grant resolution,
/// optional workflow-template resolution, session-meta creation, and
/// optional delegation-grant attachment all happen on one open path. The
/// implementation must either expose a fully-opened session (with the
/// requested delegation grant attached when a template was selected) or
/// roll back to no session at all. Do not introduce an observable
/// half-open state where session ownership is visible before the
/// corresponding authority posture is settled.
/// ssh-agent-over-bridge S3 — canonical scope for a session's SSH-signing lease.
/// `github` is the dev0 deploy-key provider; the lease bounds TIME (this scope +
/// the TTL), the loaded deploy key bounds TARGET (resolved design, post-#5687).
/// Must satisfy [`crate::trust::lease::scope_authorizes_ssh_signing`].
const SSH_SIGNING_LEASE_SCOPE: &str = "github:ssh-agent:sign";

/// Deterministic grant id for a session's SSH-signing lease so `close_session`
/// (which holds only the session id) can drop it with no extra bookkeeping.
pub(crate) fn ssh_signing_grant_id(session_id: &str) -> String {
    format!("ssh-{session_id}")
}

/// ssh-agent-over-bridge S3/F — mint a session's SSH-signing authority: a
/// time-boxed, grant-scoped lease (ADR 211; no standing forever-key) via the
/// stable consumer API. Returns `(grant_id, granted_at_epoch_secs,
/// expires_at_epoch_secs)`.
///
/// The signed `session.ssh_lease_grant` Receipt is NOT emitted here — it is
/// emitted by [`finalize_register_session_endpoint_group`] once the per-session
/// bridge endpoint binds, because only then is the credential (the loaded key)
/// real and its fingerprint known. The S1 fail-closed gate
/// (`broker::handler::LeaseSshAuthority`) checks this lease; `finalize_*` drops it
/// fail-closed if the bridge cannot be brought up, and `close_session` drops it
/// at end-of-session (a subsequent sign is then refused).
fn provision_session_ssh_signing_lease(
    store: &DaemonStore,
    session_id: &str,
    persona_id: &str,
) -> (String, i64, i64) {
    let now = chrono::Utc::now();
    let expiry = now + chrono::Duration::hours(1);
    let grant_id = ssh_signing_grant_id(session_id);

    // Mint the time-boxed lease (stable consumer API — no lease.rs internal edits).
    store.leases().mint(
        &grant_id,
        persona_id,
        SSH_SIGNING_LEASE_SCOPE,
        Some(expiry),
        now,
    );
    (grant_id, now.timestamp().max(0), expiry.timestamp().max(0))
}

/// Emit the single signed `session.ssh_lease_grant` Receipt for a session's
/// SSH-signing lease, recording the **real** loaded-key fingerprint
/// (`sha256(pubkey blob)`). Called by
/// [`finalize_register_session_endpoint_group`] once the bridge has learned the
/// key: the authority decision (lease) and the credential binding (key) are both
/// real, so this is one honest artifact. It is NOT a second receipt — storage is
/// keyed by `receipt_id`, so a re-emit would
/// accumulate; the lease grant gets exactly this one Receipt.
fn sign_and_store_ssh_lease_grant_receipt(
    store: &DaemonStore,
    session_id: &str,
    persona_id: &str,
    grant_id: &str,
    key_fingerprint_sha256: &str,
    granted_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
) -> Result<(), (i32, String)> {
    let identity = current_identity().ok_or((
        -32000,
        "register_session: daemon identity unavailable — cannot emit ssh lease-grant receipt"
            .to_string(),
    ))?;
    let daemon_root_id = identity.pubkey_hex();
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let mut envelope = crate::infra::receipt::build_ssh_lease_grant_envelope(
        session_id,
        persona_id,
        grant_id,
        SSH_SIGNING_LEASE_SCOPE,
        key_fingerprint_sha256,
        granted_at_epoch_secs,
        expires_at_epoch_secs,
        &daemon_root_id,
    );
    core_events::receipt::sign::sign_receipt_v2(&mut envelope, &signer).map_err(|e| {
        (
            -32000,
            format!("register_session: sign ssh lease-grant receipt: {e}"),
        )
    })?;
    store
        .store_session_receipt_v2(&envelope, grant_id, persona_id)
        .map_err(|e| {
            (
                -32000,
                format!("register_session: persist ssh lease-grant receipt: {e}"),
            )
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ssh-agent-over-bridge F1 — per-session bridge endpoint (the bind deferred
// from S3) + the host/forwarder client wiring.
// ---------------------------------------------------------------------------

/// A bound per-session ssh-agent bridge, retained on the main socket `LocalSet`
/// for the session's lifetime. Dropping it (on `close_session`) aborts the bridge
/// accept loop + unlinks the bridge socket, and stops + cleans the host agent
/// (zeroes the key, unlinks the agent socket).
struct SessionSshBridge {
    _listener: ember_broker::ssh_agent_bridge::SshAgentBridgeListener,
    _agent: ember_broker::ssh_agent::SshAgentHandle,
}

thread_local! {
    /// `session_id` → its bound bridge. Lives on the single-threaded main socket
    /// `LocalSet` where `register_session` / `close_session` / `broker_exec` all
    /// dispatch, so a plain `RefCell<HashMap>` is sound — it never crosses a
    /// thread (same posture as `infra::session_proxy`'s per-session state).
    static SSH_AGENT_BRIDGES: std::cell::RefCell<
        std::collections::HashMap<String, SessionSshBridge>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

struct SshEndpointGateAdmission {
    policy: AdmissionPolicy,
}

impl ember_broker::ssh_agent_bridge::SshBridgeAdmission for SshEndpointGateAdmission {
    fn admit(
        &self,
        peer: ember_broker::ssh_agent_bridge::SshBridgePeerIdentity,
    ) -> Result<(), ember_broker::ssh_agent_bridge::SshBridgeAdmissionReject> {
        let framework_peer = PeerIdentity::host(peer.uid, peer.pid, peer.version);
        evaluate_admission(&self.policy, framework_peer)
            .map(|_| ())
            .map_err(|reject| {
                ember_broker::ssh_agent_bridge::SshBridgeAdmissionReject::new(
                    self.policy.to_string(),
                    format!("{reject:?}"),
                )
            })
    }
}

fn ssh_owner_uid_admission(
    bound_uid: u32,
) -> std::rc::Rc<dyn ember_broker::ssh_agent_bridge::SshBridgeAdmission> {
    std::rc::Rc::new(SshEndpointGateAdmission {
        policy: AdmissionPolicy::OwnerUid { bound_uid },
    })
}

/// The dedicated `0700` host-side bridge UDS path for a session — the value the
/// host client / in-container forwarder targets. The parent dir is forced to
/// `0700` by `ssh_agent_bridge::bind`; the socket itself is `0600` + peer-uid
/// gated.
fn ssh_bridge_socket_path(session_id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home)
        .join(".ember")
        .join("run")
        .join("ssh-bridge")
        .join(format!("{session_id}.sock"))
}

/// `sha256(pubkey blob)` hex — the bridge's advertised public key fingerprint,
/// recorded in the lease-grant Receipt. Public material only.
fn ssh_pubkey_fingerprint(pubkey_blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(pubkey_blob))
}

/// ssh-agent-over-bridge F1 — bind the session's per-session `SshAgentBridge`
/// (the endpoint deferred from S3) once `register_session` has minted the lease.
///
/// Invoked from the socket dispatch site, which holds the **main**
/// `Rc<DaemonStore>` the lease was minted into and runs on the main socket
/// `LocalSet` the bridge binds in — and which awaits this BEFORE sending the
/// response, so the contract is race-free. On success the bridge is serving, the
/// grant Receipt carries the real key fingerprint, and the response's
/// `ssh_agent_lease` gains `bridge_sock`. On ANY endpoint-bind failure the
/// whole just-opened session endpoint group is rolled back before the RPC
/// returns (fail closed — no SSH-signing authority without a working, audited
/// endpoint).
#[derive(Default)]
struct RegisterEndpointRollback {
    session_id: Option<String>,
    runtime_grant_id: Option<String>,
}

fn take_register_endpoint_rollback(result: &mut Value) -> RegisterEndpointRollback {
    let Some(meta) = result
        .as_object_mut()
        .and_then(|obj| obj.remove(ENDPOINT_GROUP_ROLLBACK_KEY))
    else {
        return RegisterEndpointRollback::default();
    };
    RegisterEndpointRollback {
        session_id: meta
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        runtime_grant_id: meta
            .get("runtime_grant_id")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

fn rollback_registered_session_after_endpoint_failure(
    store: &DaemonStore,
    sessions_dir: Option<&Path>,
    rollback: &RegisterEndpointRollback,
    session_id: &str,
) {
    EndpointGroup::teardown_all(store, session_id, "register_session_endpoint_failure");
    if let Some(grant_id) = rollback.runtime_grant_id.as_deref()
        && let Err(e) = store.revoke_grant(grant_id)
    {
        tracing::warn!(
            session_id = %session_id,
            grant_id,
            error = %e,
            "register_session endpoint rollback: revoke runtime grant failed"
        );
    }
    if let Some(sessions_dir) = sessions_dir {
        let session_store = SessionStore::new(sessions_dir.to_path_buf());
        if let Err(e) = session_store.close(session_id) {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "register_session endpoint rollback: close session store row failed"
            );
        }
    }
    let _ = crate::infra::interactive_unlock::release_session_pin(session_id);
}

fn register_session_still_open(
    sessions_dir: Option<&Path>,
    session_id: &str,
) -> Result<bool, (i32, String)> {
    let Some(sessions_dir) = sessions_dir else {
        return Ok(true);
    };
    SessionStore::new(sessions_dir.to_path_buf())
        .read(session_id)
        .map(|meta| meta.is_some())
        .map_err(|e| {
            RpcError::Internal(format!("read session during endpoint finalize: {e}")).into()
        })
}

pub(crate) async fn finalize_register_session_endpoint_group(
    store: std::rc::Rc<DaemonStore>,
    sessions_dir: Option<PathBuf>,
    result: &mut Value,
) -> Result<(), (i32, String)> {
    let rollback = take_register_endpoint_rollback(result);
    let Some(lease) = result.get("ssh_agent_lease").cloned() else {
        return Ok(());
    };
    let (Some(session_id), Some(persona_id), Some(grant_id)) = (
        lease.get("session_id").and_then(|v| v.as_str()),
        lease.get("persona_id").and_then(|v| v.as_str()),
        lease.get("grant_id").and_then(|v| v.as_str()),
    ) else {
        return Ok(());
    };
    let session_id = rollback
        .session_id
        .as_deref()
        .unwrap_or(session_id)
        .to_string();
    let persona_id = persona_id.to_string();
    let grant_id = grant_id.to_string();
    let granted_at = lease
        .get("granted_at_epoch_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let expires_at = lease
        .get("expires_at_epoch_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if !register_session_still_open(sessions_dir.as_deref(), &session_id)? {
        rollback_registered_session_after_endpoint_failure(
            &store,
            sessions_dir.as_deref(),
            &rollback,
            &session_id,
        );
        return Err((
            -32000,
            format!(
                "register_session: endpoint finalize raced with close_session for {session_id}"
            ),
        ));
    }

    match bind_session_ssh_bridge(
        &store,
        &session_id,
        &persona_id,
        &grant_id,
        granted_at,
        expires_at,
    )
    .await
    {
        Ok(bridge_sock) => {
            if !register_session_still_open(sessions_dir.as_deref(), &session_id)? {
                EndpointGroup::teardown_all(
                    &store,
                    &session_id,
                    "register_session_endpoint_finalize_raced_close",
                );
                return Err((
                    -32000,
                    format!(
                        "register_session: endpoint finalize raced with close_session for {session_id}"
                    ),
                ));
            }
            if let Some(obj) = result
                .get_mut("ssh_agent_lease")
                .and_then(|v| v.as_object_mut())
            {
                obj.insert(
                    "bridge_sock".to_string(),
                    json!(bridge_sock.to_string_lossy()),
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                session_id = %session_id,
                "ssh bridge: endpoint bind failed — rolling back register_session endpoint group (fail closed)"
            );
            if let Some(obj) = result.as_object_mut() {
                obj.remove("ssh_agent_lease");
            }
            rollback_registered_session_after_endpoint_failure(
                &store,
                sessions_dir.as_deref(),
                &rollback,
                &session_id,
            );
            return Err((
                -32000,
                format!("register_session: ssh bridge endpoint bind failed: {e}"),
            ));
        }
    }
    Ok(())
}

/// Spawn the session host agent, build the lease-gated + audited bridge in front
/// of it, emit the grant Receipt with the real key fingerprint, bind the
/// dedicated `0700` host-side UDS, and retain the listener (+ host agent) in the
/// per-session registry. Returns the bridge socket path on full success; on any
/// error NOTHING is registered (the just-built listener/agent drop-clean on the
/// early return) and the caller drops the lease.
async fn bind_session_ssh_bridge(
    store: &std::rc::Rc<DaemonStore>,
    session_id: &str,
    persona_id: &str,
    grant_id: &str,
    granted_at_epoch_secs: u64,
    expires_at_epoch_secs: u64,
) -> anyhow::Result<std::path::PathBuf> {
    // (1) The session's host ssh-agent (Tier-0/SE). The private key lives behind
    // this socket and never crosses the bridge.
    let agent = ember_broker::ssh_agent::spawn_session_ssh_agent(session_id)
        .map_err(|e| anyhow::anyhow!("spawn session ssh-agent: {e}"))?;

    // (2) The injected fail-closed gate (ADR 211 lease) + the per-sign audit sink.
    // Both bind `Rc<DaemonStore>` — the SAME main store the lease was minted into.
    let authority = std::rc::Rc::new(crate::broker::handler::LeaseSshAuthority::new(
        std::rc::Rc::clone(store),
        grant_id,
    ));
    let audit = std::rc::Rc::new(crate::broker::handler::DaemonSshSignAudit::new(
        std::rc::Rc::clone(store),
        session_id,
        persona_id,
    ));

    // (3) The bridge. endpoint_gate_ssh_f1_wired: the daemon constructs the
    // ADR 215 framework policy and injects a thin evaluator into ember-broker,
    // keeping the broker crate free of an ember-daemon dependency. Today's
    // fallback is `AdmissionPolicy::OwnerUid { bound_uid: daemon_euid }`, which
    // preserves the old uid-floor behavior. The graduation path is
    // `AdmissionPolicy::LeafSubtree` once the ADR 214 F1 descendant-walk
    // primitive is settled for the host/in-container forwarder topology.
    let admission = ssh_owner_uid_admission(crate::infra::runtime::daemon_euid_runtime());
    let bridge = ember_broker::ssh_agent_bridge::SshAgentBridge::connect(
        agent.auth_sock_path.clone(),
        authority,
        admission,
    )
    .await
    .map_err(|e| anyhow::anyhow!("bridge connect (host agent bootstrap): {e}"))?
    .with_audit(audit);

    // (4) The grant Receipt now carries the REAL loaded-key fingerprint (unknown
    // at provision time). Emitted once, here. Fail closed: a Receipt failure
    // aborts the bind, and the caller drops the lease (no unattested grant).
    let key_fingerprint = ssh_pubkey_fingerprint(bridge.session_pubkey_blob());
    sign_and_store_ssh_lease_grant_receipt(
        store,
        session_id,
        persona_id,
        grant_id,
        &key_fingerprint,
        granted_at_epoch_secs,
        expires_at_epoch_secs,
    )
    .map_err(|(code, msg)| anyhow::anyhow!("{code}: {msg}"))?;

    // (5) Bind the dedicated `0700` host-side UDS and serve the bridge on it.
    let bridge_sock = ssh_bridge_socket_path(session_id);
    let listener =
        ember_broker::ssh_agent_bridge::bind(bridge_sock.clone(), std::rc::Rc::new(bridge))
            .await
            .map_err(|e| anyhow::anyhow!("bind ssh bridge socket: {e}"))?;

    // (6) Retain listener + host agent for the session's lifetime. `close_session`
    // drops this entry (aborts the accept loop, unlinks both sockets, zeroes the
    // host key).
    SSH_AGENT_BRIDGES.with(|b| {
        b.borrow_mut().insert(
            session_id.to_string(),
            SessionSshBridge {
                _listener: listener,
                _agent: agent,
            },
        );
    });
    Ok(bridge_sock)
}

/// ssh-agent-over-bridge F1 — tear down a session's bound ssh-agent bridge.
/// Idempotent (a no-op when the session had no bridge). Dropping the retained
/// entry aborts the bridge accept loop + unlinks the bridge socket, and stops +
/// cleans the host agent. Called by `close_session` alongside the lease drop.
pub(crate) fn teardown_ssh_agent_bridge(session_id: &str) {
    SSH_AGENT_BRIDGES.with(|b| {
        b.borrow_mut().remove(session_id);
    });
}

pub(crate) fn handle_register_session(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_name = params["persona"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona' parameter".to_string()))?;
    let launcher_pid = params["launcher_pid"]
        .as_u64()
        .ok_or_else(|| RpcError::InvalidParams("missing 'launcher_pid' parameter".to_string()))?
        as u32;
    let authority_strict = params["authority_strict"].as_bool().unwrap_or(false);
    // ADR 158 §Component 3 — optional delegation template chosen by the
    // launcher at session-open. When `Some`, the daemon resolves the template
    // and lowers its authority into the runtime persona's `StandingGrant`
    // (per ADR 205 §6 — the legacy delegation sidecar lane is retired), and
    // stamps `delegation_id` / `delegation_template` onto the session meta.
    // When `None` (or empty), the legacy per-action / JIT chain governs
    // `broker.resolve`.
    let delegation_template_name = params["delegation_template"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let attach_runtime_persona_id = params["attach_runtime_persona_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let want_bridge_client_bundle = params["bridge_client_bundle"].as_bool().unwrap_or(false);
    // ssh-agent-over-bridge S3 — when the launcher requests SSH-agent support for
    // an isolated session, provision the session's SSH-signing authority: mint a
    // time-boxed grant-scoped lease (ADR 211) + emit the Receipt at grant. The
    // per-session bridge endpoint that consumes the lease binds with the
    // in-container forwarder slice; until then this grants the authority + Receipt
    // that the S1 fail-closed gate checks.
    let want_ssh_agent = params["ssh_agent"].as_bool().unwrap_or(false);
    // ADR 209 §2 / SCION-209 #2 — when the orchestrator spawns a SCION worker
    // container it passes the container id so the minted bridge client cert's
    // SPIFFE SAN binds the real container (`spiffe://emberd/container/<id>`,
    // cross-checked to persona) rather than defaulting to the session id. Other
    // register_session callers omit it and keep the session-id-as-container-ref
    // SAN shape unchanged.
    let bridge_bundle_container_id = params["container_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let workspace_binding = parse_register_session_workspace_binding(params)?;

    let sessions_dir = ctx.sessions_dir.as_ref().ok_or_else(|| {
        RpcError::Internal("sessions_dir not configured on this connection".to_string())
    })?;

    let durable_persona = resolve_register_session_persona(store, ctx, persona_name)?;
    let interactive_vault = crate::infra::interactive_unlock::ensure_vault_for_session_open(store)
        .map_err(RpcError::PresenceLocked)?;

    // Resolve the delegation template BEFORE generating the session id so a
    // template-resolution failure does not leave a half-opened session on
    // disk. NotFound / parse errors surface as -32602 (invalid params).
    let resolved_template = match delegation_template_name.as_deref() {
        Some(name) => Some(resolve_delegation_template(name)?),
        None => None,
    };
    if attach_runtime_persona_id.is_some() && resolved_template.is_some() {
        return Err(RpcError::InvalidParams(
            "register_session: `attach_runtime_persona_id` cannot be combined with delegated authority template selection in P9-S1".to_string(),
        )
        .into());
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let session_id = format!("sess_{:032x}", nanos);
    let caller_binding_id = format!("cb_{:032x}", nanos);
    let attachment_endpoint = core_state::sessions::AttachmentEndpoint::active(
        format!("att_{}", uuid::Uuid::new_v4()),
        format!("ep_{}", uuid::Uuid::new_v4()),
    );

    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    let (lane, rollback_runtime_grant_id) = match attach_runtime_persona_id.as_deref() {
        Some(runtime_persona_id) => (
            resolve_runtime_attach_target(&session_store, runtime_persona_id, &durable_persona.id)?,
            None,
        ),
        None => {
            let parent_grant = resolve_register_session_active_grant(
                store,
                &durable_persona,
                persona_name,
                gateway_lane_for_register_session(params),
                gateway_lane_requires_brokered_model_auth(params),
                resolved_template.is_some(),
            )?;
            // BKR-4c: when a delegation template was selected, lower its
            // action-ref scopes into the union of github capability needs and
            // mint the runtime grant carrying those enumerated github
            // statements (⊆ parent's github:* ceiling) instead of the broad
            // ceiling. The template's per-session pre-approval thus lives IN
            // the runtime persona's standing grant (resolved via need ⊆ grant
            // at use-time), not in the legacy delegation sidecar ADR 205 §6
            // retired.
            let github_needs = resolved_template
                .as_ref()
                .map(|t| ember_construct::template_github_needs(&t.scopes, &t.excludes));
            let lane = mint_runtime_lane(
                store,
                &durable_persona,
                &parent_grant,
                &caller_binding_id,
                authority_strict,
                github_needs.as_deref(),
            )?;
            let rollback_grant_id = Some(lane.runtime_grant_id.clone());
            (lane, rollback_grant_id)
        }
    };

    // Mint a delegation_id ULID-shape (nanos hex) only when the launcher is
    // attaching fresh delegated authority. Attach-to-runtime inherits the
    // binding's current delegation id and template.
    let delegation_id = match (&lane.delegation_id, resolved_template.as_ref()) {
        (Some(existing), _) => Some(existing.clone()),
        (None, Some(_)) => Some(format!("wfg_{}", uuid::Uuid::new_v4().simple())),
        (None, None) => None,
    };
    let delegation_template = lane
        .delegation_template
        .clone()
        .or_else(|| resolved_template.as_ref().map(|t| t.name.clone()));
    let has_delegated_authority = delegation_id.is_some() && delegation_template.is_some();

    let meta = core_state::sessions::SessionMeta {
        session_id: session_id.clone(),
        persona: lane.runtime_persona_id.clone(),
        grant_id: lane.runtime_grant_id.clone(),
        started_at: chrono::Utc::now(),
        launcher_pid,
        authority_strict: lane.authority_strict,
        // ADR 158 §Component 3 — delegation-grant attachment. Both fields are
        // populated together (Some/Some) when the launcher selected a
        // template, or together None (per the legacy path).
        delegation_id: delegation_id.clone(),
        delegation_template: delegation_template.clone(),
        durable_persona: Some(lane.durable_persona_id.clone()),
        caller_binding_id: Some(lane.caller_binding_id.clone()),
    };
    session_store
        .create(&meta)
        .map_err(|e| RpcError::Internal(format!("create session: {e}")))?;
    let mut register_guard = RegisterSessionGuard::new(
        store,
        &session_store,
        session_id.clone(),
        rollback_runtime_grant_id.clone(),
    );
    session_store
        .write_attachment_endpoint(&session_id, &attachment_endpoint)
        .map_err(|e| RpcError::Internal(format!("create attachment endpoint: {e}")))?;
    if let Some(binding) = workspace_binding.as_ref() {
        session_store
            .write_workspace_binding(&session_id, binding)
            .map_err(|e| RpcError::Internal(format!("create workspace binding: {e}")))?;
    }
    crate::infra::interactive_unlock::acquire_session_pin(&session_id);
    register_guard.note_pin_acquired();

    // BKR-4c (ADR 205 §6): no legacy delegation sidecar is issued. When a
    // delegation template was selected, the chosen scopes were lowered into the
    // runtime persona's standing grant above (`mint_runtime_lane` with
    // `github_needs`), so the per-session authority lives in the signed grant
    // chain — `need ⊆ standing grant` at use-time — not a side artifact.

    // target_state_anchor: SCION-everywhere
    //
    // Host-mode session-open writes an `agent_socket_enrollments` row
    // so the runtime persona passes broker_resolve's
    // `check_principal_enrollment_strict` (checkpoint
    // `fail_closed_broker_resolve`) and `check_principal_against_persona`
    // gates. Without this row a PATH-shadow construct shim that calls
    // broker_exec on behalf of this session is refused with
    // PrincipalNotEnrolled (-32401) — the authority_delegation scope check
    // never runs.
    //
    // The synthetic `host-mode/<session_id>` socket path keeps the row
    // distinguishable from real per-agent UDS enrollments and gives
    // `close_session` a deterministic key to revoke. The namespace tuple
    // is NULL — the namespace gate carve-out at
    // `check_principal_namespace_inodes` no-ops on all-NULL bindings,
    // which is the documented host-mode posture.
    //
    // Remove this host-mode shim once every session opens inside a
    // SCION container (ADR 140); the SCION path's
    // `enroll_container_persona` is the long-term writer.
    //
    // ARCH-BROKER-FAIL-CLOSED-PER-RPC-ROLLOUT Step E (option b): because
    // register_session is the enrollment WRITER for the row below, it is
    // deliberately the one broker entry point that does NOT call
    // `check_principal_enrollment_strict`. Gating the writer on prior
    // enrollment would deadlock bootstrap — the caller could never become
    // enrolled. This is the terminal state of the rollout; see
    // `broker::handler::FAIL_CLOSED_RPC_ROLLOUT_COMPLETE`
    // (checkpoint `fail_closed_rpc_rollout_complete`). Do NOT "fix" the
    // apparent asymmetry by adding the enrollment gate here.
    let host_mode_socket_path = host_mode_enrollment_socket_path(&session_id);
    let host_mode_peer_uid = ctx.peer.as_ref().map(|p| p.uid);
    store
        .record_host_mode_socket_enrollment(
            &host_mode_socket_path,
            &lane.runtime_persona_id,
            &lane.runtime_grant_id,
            host_mode_peer_uid,
        )
        .map_err(|e| {
            (
                -32000,
                format!("register_session: record host-mode enrollment: {e}"),
            )
        })?;

    // P22-S2 (ADR 197 §1/§2) — stand up the per-session peercred-gated LLM
    // gateway socket. Best-effort: requires a kernel-attested peer uid to bind
    // the gate against (host-mode sessions always have one; Internal/test
    // dispatch without peer creds is skipped). `attestation_caller` is the
    // binary-pin manifest key for the harness binary (`claude-code` /
    // `codex-network-proxy`), threaded in by the launcher; absent → attestation
    // runs unenforced (loud audited event) while the kernel-attested arms gate.
    let attestation_caller = params
        .get("attestation_caller")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // P22-S2 Door-1 leaf-pin (ADR 197 §2, adversarial FINDING-1): mint an
    // unguessable nonce the launcher must echo on `report_session_leaf` to pin
    // the harness leaf pid. Returned ONLY in this RPC response (to the launcher
    // over its own authenticated connection), never placed in the child env or
    // the socket path — so a same-uid attacker who knows the (predictable /
    // env-leaked) session_id cannot forge a leaf report. (Claude UDS lane only.)
    let leaf_report_nonce = format!("lrn_{}", uuid::Uuid::new_v4().simple());
    let use_anthropic_uds_lane = register_session_uses_anthropic_uds_lane(
        attestation_caller.as_deref(),
        want_bridge_client_bundle,
    );
    // P22-S2 (ADR 197 codex) — set to the per-session loopback-TCP responses
    // proxy URL when this is a codex session (see the codex branch below).
    let mut codex_responses_proxy_url: Option<String> = None;
    // ADR 215 §2 — set to the per-session loopback-TCP Code Assist proxy URL
    // (BARE base, no `/v1`) when this is a gemini Code Assist session.
    let mut gemini_proxy_url: Option<String> = None;
    // Cursor baseline is not a model-auth projector. Set only when the daemon
    // opens a per-session generic CONNECT egress proxy for allowlist/audit.
    let mut cursor_egress_proxy_url: Option<String> = None;
    let mut uds_socket_path: Option<PathBuf> = None;
    if let Some(bound_uid) = host_mode_peer_uid {
        // Seed the sticky manifest-enrolled latch while the vault is unlocked
        // (register_session is presence-gated). This closes the cold-boot
        // window where a locked vault would let the gate's attestation arm
        // downgrade to unenforced before any accept-time load succeeded
        // (adversarial FINDING-1, P22-S2 PR-B).
        crate::infra::session_proxy::probe_and_note_manifest(store);

        // P22-S2 (ADR 197 codex) — codex HOST lane. Codex can't dial a UDS or
        // send `X-Ember-*` headers, so when the launcher tags the session as
        // `codex-network-proxy` we stand up a per-session loopback-TCP
        // responses-API-proxy (named OwnerUid policy, no TCP peercred
        // enforcement; credential-safe by construction) and return its URL so
        // the launcher can point codex's config at it.
        // Other host harnesses (claude-code, etc.) take the UDS Door-1
        // capability path (peercred + LOCAL_PEERTOKEN + nonce-bound leaf-pin).
        // Bridge-bundle sessions are separate execution spaces (container /
        // Sandvault) and must not receive or depend on a host peercred UDS; they
        // use the TCP gateway bundle plus the ADR 154/215 mTLS bridge for
        // control/tool RPC.
        if attestation_caller.as_deref() == Some("codex-network-proxy") {
            let port = register_guard
                .endpoint_group
                .open_codex_proxy(bound_uid)
                .ok_or_else(|| {
                    RpcError::Internal(
                        "register_session: codex responses proxy failed to bind".to_string(),
                    )
            })?;
            codex_responses_proxy_url = Some(format!("http://127.0.0.1:{port}/v1"));
        } else if attestation_caller.as_deref() == Some("gemini-code-assist-network-proxy") {
            // ADR 215 §2 — gemini Code Assist HOST lane. Like codex, the
            // gemini-cli dials a `base_url` (its `CODE_ASSIST_ENDPOINT`) and
            // cannot send `X-Ember-*` headers, so we stand up a per-session
            // loopback-TCP listener dispatching the Code Assist OAuth projector
            // (server-side daemon-refreshed Bearer injection + `cloudcode-pa`
            // host pin). The URL is the BARE base (no `/v1`): the CLI builds
            // `${endpoint}/v1internal:<method>` itself.
            let port = register_guard
                .endpoint_group
                .open_gemini_proxy(bound_uid)
                .ok_or_else(|| {
                    RpcError::Internal(
                        "register_session: gemini code-assist proxy failed to bind".to_string(),
                    )
                })?;
            gemini_proxy_url = Some(format!("http://127.0.0.1:{port}"));
        } else if attestation_caller.as_deref() == Some("cursor-agent") {
            let port = register_guard
                .endpoint_group
                .open_cursor_egress_proxy(&lane.runtime_persona_id, bound_uid)
                .ok_or_else(|| {
                    RpcError::Internal(
                        "register_session: cursor egress proxy failed to bind".to_string(),
                    )
                })?;
            cursor_egress_proxy_url = Some(format!("http://127.0.0.1:{port}"));
        } else if use_anthropic_uds_lane {
            let opened_path = register_guard
                .endpoint_group
                .open_session_proxy(crate::infra::session_proxy::SessionProxyOpenSpec {
                    session_id: session_id.clone(),
                    bound_uid,
                    launcher_pid,
                    attestation_caller: attestation_caller.clone(),
                    leaf_report_nonce: leaf_report_nonce.clone(),
                })
                .map_err(|e| {
                    RpcError::Internal(format!(
                        "register_session: session proxy socket bind failed: {e}"
                    ))
                })?;
            uds_socket_path = opened_path;
        }
    }

    // P22-S2 PR-C — the Claude harness routes API traffic over the per-session
    // peercred-gated UDS (ADR 197 §2). We point it there iff (a) the per-session
    // registry is up (socket path resolvable) AND (b) the caller identified
    // itself as a UDS-capable Anthropic client. Other Anthropic clients that
    // cannot dial a UDS keep the transitional TCP bundle — no half-bridge, no
    // brick.
    //
    // UDS-capable Anthropic callers:
    //   - `claude-code`: the Claude Code harness (honors `ANTHROPIC_UNIX_SOCKET`).
    //   - `internal-automation`: the autopilot engine's own Anthropic client (reqwest
    //     blocking + `.unix_socket()`). It IS the connecting process (not a
    //     launched child), so it reports its OWN pid via `report_session_leaf`
    //     — the leaf-pin binds the forge pid directly. This replaces the
    //     transitional TCP gateway PR-E guarded off (META-AP-INTERNAL-AUTOMATION-UDS-LLM-CLIENT).
    let workflow_log_suffix = match (&delegation_id, &delegation_template) {
        (Some(wf_id), Some(template)) => {
            format!(" delegation_id={wf_id} delegation_template={template}")
        }
        _ => String::new(),
    };
    let _ = store.log_event(
        Some(&lane.runtime_persona_id),
        "session.opened",
        None,
        "ok",
        Some(&format!(
            "session_id={session_id} grant_id={} runtime_persona_id={} durable_persona_id={} caller_binding_id={} attach={}{}",
            lane.runtime_grant_id,
            lane.runtime_persona_id,
            lane.durable_persona_id,
            lane.caller_binding_id,
            attach_runtime_persona_id.is_some(),
            workflow_log_suffix
        )),
    );

    let active_grant = store.get_grant(&lane.runtime_grant_id).map_err(|e| {
        (
            -32000,
            format!("register_session: runtime grant lookup: {e}"),
        )
    })?;
    let tcp_anthropic_gateway_required = uds_socket_path.is_none()
        && active_grant_supports_anthropic_gateway(store, &active_grant, false);
    let proxy_url = match &ctx.llm_proxy_url {
        Some(url) => url.clone(),
        None => {
            if tcp_anthropic_gateway_required {
                return Err(RpcError::Internal(
                    "register_session: TCP LLM proxy listener is not configured; container Anthropic sessions cannot launch with the dead 8484 fallback"
                        .to_string(),
                )
                .into());
            }
            if gateway_lane_requires_brokered_model_auth(params) {
                crate::infra::session_proxy::SENTINEL_BASE_URL.to_string()
            } else {
                tracing::warn!(
                    "register_session: llm_proxy_url absent from RequestContext \
                 (SocketListener.with_llm_proxy_url not called?) — \
                 falling back to hardcoded 8484; COHORT-A-V03-T3-FIX-PROXY-URL-VIA-REQUEST-CONTEXT"
                );
                "http://127.0.0.1:8484".to_string()
            }
        }
    };
    let git_proxy_url = ctx.git_proxy_url.clone();
    let anthropic_gateway_bundle = anthropic_gateway_bundle_for_register_session(
        store,
        &active_grant,
        &attachment_endpoint,
        &proxy_url,
        uds_socket_path.as_deref(),
    );

    let mut response = json!({
        "session_id": session_id,
        "grant_id": lane.runtime_grant_id,
        "proxy_url": proxy_url,
        "persona_id": lane.runtime_persona_id,
        "runtime_persona_id": lane.runtime_persona_id,
        "durable_persona_id": lane.durable_persona_id,
        "caller_binding_id": lane.caller_binding_id,
        "attachment_id": attachment_endpoint.attachment_id,
        "attachment_endpoint_token": attachment_endpoint.endpoint_token,
        "attachment_state": attachment_endpoint.state,
        "authority_endpoint": {
            "kind": "attachment",
            "attachment_id": attachment_endpoint.attachment_id,
            "state": attachment_endpoint.state,
        },
        "authority_posture": authority_posture_json(
            lane.authority_strict,
            has_delegated_authority,
        ),
        "delegation": delegation_summary_json(sessions_dir, &meta, "register_session")?,
    });
    if let Some(token) =
        crate::infra::handler::mint_operator_presence_token(ctx.peer.as_ref(), "register_session")?
    {
        response["presence_token"] = serde_json::to_value(token).map_err(|e| {
            (
                -32000,
                format!("register_session: encode presence_token: {e}"),
            )
        })?;
    }
    if let Some((anthropic_base_url, anthropic_custom_headers)) = anthropic_gateway_bundle {
        response["anthropic_base_url"] = json!(anthropic_base_url);
        response["anthropic_custom_headers"] = json!(anthropic_custom_headers);
    }
    // P22-S2 PR-C — when the Claude harness is being routed over the
    // per-session UDS, hand it the socket path. The launcher sets
    // `ANTHROPIC_UNIX_SOCKET` to this and drops the bearer (the bundle above
    // already carries the checkpoint base URL + bearer-free headers). Absent →
    // the launcher uses the transitional TCP `proxy_url` (no brick).
    if let Some(path) = uds_socket_path.as_deref() {
        response["anthropic_unix_socket"] = json!(path.to_string_lossy());
        // The launcher echoes this on `report_session_leaf` to pin the harness
        // leaf pid (FINDING-1). Only returned on the UDS lane and only to the
        // launcher (this RPC response).
        response["leaf_report_nonce"] = json!(leaf_report_nonce);
    }
    if let Some(gpu) = git_proxy_url {
        response["git_proxy_url"] = json!(gpu);
    }
    if let Some(codex_url) = codex_responses_proxy_url {
        response["codex_responses_proxy_url"] = json!(codex_url);
    }
    if let Some(gemini_url) = gemini_proxy_url {
        response["gemini_proxy_url"] = json!(gemini_url);
    }
    if let Some(cursor_url) = cursor_egress_proxy_url {
        response["cursor_egress_proxy_url"] = json!(cursor_url);
    }
    if let Some(binding) = workspace_binding.as_ref() {
        response["workspace_ref"] = json!(binding.workspace_ref);
    }
    if want_bridge_client_bundle {
        let bridge_bundle = mint_register_session_bridge_client_bundle(
            &interactive_vault,
            &lane.runtime_persona_id,
            &session_id,
            bridge_bundle_container_id.as_deref(),
        )?;
        response["bridge_client_bundle"] = serde_json::to_value(bridge_bundle).map_err(|e| {
            (
                -32000,
                format!("register_session: encode bridge bundle: {e}"),
            )
        })?;
    }
    if want_ssh_agent {
        // Mint the lease here (synchronously, so the response reports it); the
        // per-session bridge endpoint is bound by
        // `finalize_register_session_endpoint_group` at the dispatch site (which
        // holds the main `Rc<DaemonStore>`), which adds `bridge_sock` on success
        // or strips this block + drops the lease on
        // failure. `session_id` / `persona_id` / the epoch times are carried so the
        // finalize step can bind + emit the real-fingerprint Receipt.
        let (grant_id, granted_at_epoch_secs, expires_at_epoch_secs) =
            provision_session_ssh_signing_lease(store, &session_id, &lane.runtime_persona_id);
        response["ssh_agent_lease"] = json!({
            "grant_id": grant_id,
            "scope": SSH_SIGNING_LEASE_SCOPE,
            "session_id": session_id,
            "persona_id": lane.runtime_persona_id,
            "granted_at_epoch_secs": granted_at_epoch_secs,
            "expires_at_epoch_secs": expires_at_epoch_secs,
        });
    }
    // ADR 158 §Component 3 — surface delegation grant identity to the launcher
    // so it can stamp `EMBER_DELEGATION_ID` / `EMBER_DELEGATION_TEMPLATE` into
    // the child env, and so `ember workflow show` / `ember workflow revoke`
    // can target the freshly-issued grant.
    if let Some(wf_id) = &delegation_id {
        response["delegation_id"] = json!(wf_id);
    }
    if let Some(template) = delegation_template.as_ref() {
        response["delegation_template"] = json!(template);
    }
    if want_ssh_agent {
        response[ENDPOINT_GROUP_ROLLBACK_KEY] = json!({
            "session_id": register_guard.session_id(),
            "runtime_grant_id": rollback_runtime_grant_id,
        });
    }
    register_guard.commit();
    Ok(response)
}

pub(crate) fn handle_describe_runtime_attach_target(
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let runtime_persona_id = params["runtime_persona_id"].as_str().ok_or_else(|| {
        RpcError::InvalidParams("missing 'runtime_persona_id' parameter".to_string())
    })?;
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or_else(|| {
        RpcError::Internal("sessions_dir not configured on this connection".to_string())
    })?;
    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    let meta = session_store
        .find_open_by_runtime_persona(runtime_persona_id)
        .map_err(|e| {
            RpcError::Internal(format!(
                "describe_runtime_attach_target: list open attachments: {e}"
            ))
        })?
        .ok_or_else(|| {
            RpcError::NotFound(format!(
                "describe_runtime_attach_target: runtime persona '{}' is not live",
                runtime_persona_id
            ))
        })?;
    let caller_binding_id = meta.caller_binding_id.clone().ok_or_else(|| {
        RpcError::Internal(
            "describe_runtime_attach_target: attach target missing caller_binding_id".to_string(),
        )
    })?;
    let durable_persona_id = meta.durable_persona.clone().ok_or_else(|| {
        RpcError::Internal(
            "describe_runtime_attach_target: attach target missing durable_persona".to_string(),
        )
    })?;
    ensure_connect_only_owner_matches_trusted_principal(
        ctx,
        "describe_runtime_attach_target",
        &durable_persona_id,
    )?;
    let attachment_count = session_store
        .count_other_open_attachments(&meta)
        .map_err(|e| {
            RpcError::Internal(format!(
                "describe_runtime_attach_target: count attachments: {e}"
            ))
        })?
        + 1;
    let endpoint_state = session_store
        .read_attachment_endpoint(&meta.session_id)
        .map_err(|e| {
            RpcError::Internal(format!(
                "describe_runtime_attach_target: read attachment endpoint: {e}"
            ))
        })?
        .map(|endpoint| endpoint.state)
        .unwrap_or_else(|| "unknown".to_string());
    let delegation =
        delegation_summary_json(sessions_dir, &meta, "describe_runtime_attach_target")?;

    Ok(json!({
        "runtime_persona_id": meta.persona,
        "durable_persona_id": durable_persona_id,
        "caller_binding_id": caller_binding_id,
        "attachment_count": attachment_count,
        "sample_attachment_id": meta.session_id,
        "sample_attachment_state": endpoint_state,
        "authority_posture": authority_posture_json(
            meta.authority_strict,
            meta.delegation_id.is_some() && meta.delegation_template.is_some(),
        ),
        "delegation": delegation,
        "started_at": meta.started_at.to_rfc3339(),
    }))
}

pub(crate) fn mint_register_session_bridge_client_bundle(
    vault: &crate::infra::vault::Vault,
    persona_id: &str,
    session_id: &str,
    container_id: Option<&str>,
) -> Result<RegisterSessionBridgeClientBundle, (i32, String)> {
    let config = crate::infra::interactive_unlock::current_config().ok_or_else(|| {
        RpcError::Internal("register_session: interactive unlock config not registered".to_string())
    })?;
    let bridge_bind = config.bridge_bind.ok_or_else(|| {
        RpcError::PresenceLocked(
            "register_session: daemon bridge listener is not configured".to_string(),
        )
    })?;
    if bridge_bind.port() == 0 {
        return Err(RpcError::PresenceLocked(
            "register_session: daemon bridge listener must bind a concrete port".to_string(),
        )
        .into());
    }

    let bridge_ca = crate::infra::runtime::load_or_mint_bridge_ca(&config.data_dir, vault)
        .map_err(|e| RpcError::Internal(format!("register_session: load bridge CA: {e}")))?;
    crate::infra::runtime::mint_or_rotate_ember_rpc_server_cert(
        &config.data_dir,
        Some(bridge_bind),
        &bridge_ca,
    )
    .map_err(|e| {
        RpcError::Internal(format!("register_session: mint ember-rpc server cert: {e}"))
    })?;
    // SPIFFE container SAN binds to the orchestrator-supplied container id when
    // present (SCION-209 #2 / ADR 209 §2); otherwise the session id is the
    // container ref, preserving the daemon-sandbox lane's existing SAN shape.
    let container_ref = container_id.unwrap_or(session_id);
    let (client_cert_pem, client_key_pem) = bridge_ca
        .sign_client_cert(
            persona_id,
            Some(container_ref),
            ISOLATED_BRIDGE_CLIENT_CERT_TTL,
        )
        .map_err(|e| {
            (
                -32000,
                format!("register_session: mint bridge client cert: {e}"),
            )
        })?;
    let ca_cert_pem = bridge_ca.trust_root_cert_pem().map_err(|e| {
        (
            -32000,
            format!("register_session: render bridge trust root: {e}"),
        )
    })?;

    Ok(RegisterSessionBridgeClientBundle {
        port: bridge_bind.port(),
        client_cert_pem: client_cert_pem.to_string(),
        client_key_pem: client_key_pem.to_string(),
        ca_cert_pem: ca_cert_pem.to_string(),
    })
}

/// Resolve a delegation template by name. Returns -32602 (invalid params) when
/// the name does not map to any bundled or overlay template; -32000 for I/O
/// or parse errors.
///
/// `pub(crate)` so the preflight coverage handler can resolve the same template
/// (via the same bundled/overlay search path) the launcher will mint a grant
/// from, keeping the lane-effective coverage answer and the issued grant in
/// agreement.
pub(crate) fn resolve_delegation_template(
    name: &str,
) -> Result<crate::infra::delegation_template::DelegationTemplate, (i32, String)> {
    let bundled = bundled_delegation_templates_dir();
    let overlay = overlay_delegation_templates_dir();
    crate::infra::delegation_template::load_template(name, &bundled, overlay.as_deref()).map_err(
        |e| match e {
            crate::infra::delegation_template::DelegationTemplateError::NotFound { .. } => (
                -32602,
                format!(
                    "register_session: delegated-authority template '{name}' not found; \
                     rerun without --delegated to stay ambient or pick a bundled/operator template"
                ),
            ),
            other => (
                -32000,
                format!("register_session: delegated-authority template error: {other}"),
            ),
        },
    )
}

/// Parse a JSON param expected to be an array of strings. A missing or `null`
/// key yields an empty vec; any non-string entry is rejected.
fn string_array_param(params: &Value, key: &str) -> Result<Vec<String>, (i32, String)> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().map(str::to_string).ok_or((
                    -32602,
                    format!("save_delegation_template: '{key}' entries must be strings"),
                ))
            })
            .collect(),
        Some(_) => Err((
            -32602,
            format!("save_delegation_template: '{key}' must be an array of strings"),
        )),
    }
}

/// Write a rendered template TOML atomically into `overlay_dir`, creating the
/// directory if needed. Factored from [`handle_save_delegation_template`] so
/// tests can target a tempdir instead of env-racing on the operator's real
/// config dir.
fn write_template_to_overlay(
    overlay_dir: &Path,
    name: &str,
    toml_str: &str,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(overlay_dir)?;
    let final_path = overlay_dir.join(format!("{name}.toml"));
    let tmp_path = overlay_dir.join(format!(".{name}.toml.tmp"));
    std::fs::write(&tmp_path, toml_str)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// `save_delegation_template` — persist a reusable delegated-authority artifact
/// from the planner (ADR 194 §5 output 3).
///
/// OperatorPresence-gated: a saved template overlay-overrides the bundled set
/// (`load_template` checks overlay first), so writing one is authority-shaping
/// and must ride the same presence gate as `register_session`. The artifact
/// lands in the daemon's OWN overlay dir — the dir it reads at launch — so a
/// separate-uid managed daemon (ADR 131) can resolve it later. A CLI-side write
/// to the operator's home would be unreadable to that daemon, so the write is
/// brokered here.
///
/// Saving a template is NOT an authority attachment: the runtime persona's
/// `StandingGrant` is still minted at launch via `register_session` under its
/// own presence gate.
///
/// Params: `{ "name", "ttl", "scopes": [..], "description"?, "excludes"?: [..] }`
/// Result: `{ "name", "path", "ttl", "scope_count" }`
pub(crate) fn handle_save_delegation_template(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "save_delegation_template: missing 'name'".to_string(),
        ))?;
    if !crate::infra::delegation_template::is_safe_template_name(name) {
        return Err((
            -32602,
            format!(
                "save_delegation_template: unsafe template name '{name}' — must be a single path \
                 component (no '/', '\\', or NUL) under 128 chars"
            ),
        ));
    }
    let ttl = params["ttl"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "save_delegation_template: missing 'ttl' (e.g. \"4h\")".to_string(),
        ))?;

    let scopes = string_array_param(params, "scopes")?;
    if scopes.is_empty() {
        return Err((
            -32602,
            "save_delegation_template: 'scopes' must be a non-empty array of action refs"
                .to_string(),
        ));
    }
    let excludes = string_array_param(params, "excludes")?;
    let description = params["description"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let toml_str = crate::infra::delegation_template::render_validated_template_toml(
        name,
        description,
        ttl,
        &scopes,
        &excludes,
    )
    .map_err(|e| match e {
        crate::infra::delegation_template::DelegationTemplateError::Ttl { .. } => {
            (-32602, format!("save_delegation_template: {e}"))
        }
        crate::infra::delegation_template::DelegationTemplateError::Parse { .. } => (
            -32602,
            format!("save_delegation_template: invalid scope/exclude action ref: {e}"),
        ),
        other => (-32000, format!("save_delegation_template: {other}")),
    })?;

    let overlay_dir = overlay_delegation_templates_dir().ok_or((
        -32000,
        "save_delegation_template: cannot resolve operator overlay directory".to_string(),
    ))?;
    let path = write_template_to_overlay(&overlay_dir, name, &toml_str).map_err(|e| {
        (
            -32000,
            format!(
                "save_delegation_template: write under {}: {e}",
                overlay_dir.display()
            ),
        )
    })?;

    let actor = ctx
        .peer
        .as_ref()
        .map(|p| format!("uid={}", p.uid))
        .unwrap_or_else(|| "uid=unknown".to_string());
    let _ = store.log_event(
        None,
        "delegation_template.saved",
        None,
        "ok",
        Some(&format!(
            "{actor} template={name} ttl={ttl} scope_count={}",
            scopes.len()
        )),
    );

    Ok(json!({
        "name": name,
        "path": path.display().to_string(),
        "ttl": ttl,
        "scope_count": scopes.len(),
    }))
}

/// P22-S2 Door-1 leaf-pin (ADR 197 §2). The launcher reports the pid of the
/// harness child it spawned for `session_id`; the per-session UDS accept gate
/// then admits a connection only from that exact pid (`evaluate_primary_gate`
/// leaf-pin arm), replacing the cross-uid-broken pid-tree walk.
///
/// Authentication (adversarial FINDING-1): the daemon socket is SO_PEERCRED-
/// gated to the operator uid, so a cross-uid process cannot reach this RPC. On
/// macOS the main socket's `LOCAL_PEERCRED` does not surface a usable pid, so we
/// cannot tie the report to the launcher pid kernel-side; instead the launcher
/// must echo the unguessable `leaf_report_nonce` the daemon minted at
/// `register_session` and returned ONLY in that RPC response (not in the child
/// env, not in the socket path). The registry refuses a `SetLeaf` whose nonce
/// does not match (`leaf_report_nonce_matches`, constant-time) and is otherwise
/// first-write-wins. So a same-uid attacker who knows the (predictable /
/// env-leaked) session_id but not the nonce cannot hijack the leaf-pin to its
/// own pid. The remaining residual — a compromised in-tree process that
/// ptrace-injects the actual pinned leaf — is the conceded host residual
/// (SCION/container is the structural answer; ADR 197 amendment).
pub(crate) fn handle_report_session_leaf(
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let session_id = params["session_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'session_id' parameter".to_string()))?;
    let leaf_pid_u64 = params["leaf_pid"].as_u64().ok_or((
        -32602,
        "missing or non-integer 'leaf_pid' parameter".to_string(),
    ))?;
    if leaf_pid_u64 == 0 || leaf_pid_u64 > u32::MAX as u64 {
        return Err((-32602, "'leaf_pid' out of range".to_string()));
    }
    let leaf_pid = leaf_pid_u64 as u32;
    // FINDING-1: the launcher-only nonce binds this report to the launcher. The
    // registry refuses a SetLeaf whose nonce does not match the one minted at
    // register_session, so a same-uid attacker who knows the session_id but not
    // the nonce cannot hijack the leaf-pin.
    let nonce = params["nonce"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or((-32602, "missing 'nonce' parameter".to_string()))?;

    // Confirm the session exists + is open so we never pin a leaf for an
    // arbitrary id. (The socket peer gate already constrains the caller to the
    // operator uid.)
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or_else(|| {
        RpcError::Internal("sessions_dir not configured on this connection".to_string())
    })?;
    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    let _meta = session_store
        .read(session_id)
        .map_err(|e| RpcError::Internal(format!("read session: {e}")))?
        .ok_or_else(|| {
            RpcError::NotFound(format!(
                "session '{session_id}' not found or already closed"
            ))
        })?;

    let accepted = crate::infra::session_proxy::request_set_leaf(session_id, leaf_pid, nonce);
    Ok(json!({ "leaf_pinned": accepted }))
}

pub(crate) fn handle_close_session(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let session_id = params["session_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'session_id' parameter".to_string()))?;

    let sessions_dir = ctx.sessions_dir.as_ref().ok_or_else(|| {
        RpcError::Internal("sessions_dir not configured on this connection".to_string())
    })?;

    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    let meta = session_store
        .read(session_id)
        .map_err(|e| RpcError::Internal(format!("read session: {e}")))?
        .ok_or_else(|| {
            RpcError::NotFound(format!(
                "session '{session_id}' not found or already closed"
            ))
        })?;

    let close_guard = CloseSessionGuard::new(store, &session_store, session_id);

    let identity = current_identity().ok_or_else(|| {
        RpcError::Internal("daemon identity not initialised — cannot sign Receipt".to_string())
    })?;
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let claim_summary =
        summarize_session_scope_best_effort(store, session_id, "handle_close_session");

    let envelope = if let Some(summary) = claim_summary.as_ref() {
        crate::infra::receipt::issue::issue_cohort_a_receipt_from_closed_scope(
            session_id,
            summary,
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
    } else {
        crate::infra::receipt::issue::issue_cohort_a_receipt(
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
    }
    .map_err(|e| RpcError::Internal(format!("issue Receipt: {e}")))?;

    let receipt_id = envelope.receipt_id.clone();

    let session_dir = sessions_dir.join(session_id);
    let receipt_path = session_dir.join("receipt.json");
    let receipt_json = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| RpcError::Internal(format!("serialize Receipt JSON: {e}")))?;
    std::fs::write(&receipt_path, &receipt_json)
        .map_err(|e| RpcError::Internal(format!("persist Receipt: {e}")))?;

    let attachment_endpoint = session_store
        .read_attachment_endpoint(session_id)
        .map_err(|e| RpcError::Internal(format!("read attachment endpoint: {e}")))?;
    if let Some(endpoint) = attachment_endpoint.as_ref() {
        let invalidated = store
            .invalidate_approval_bindings_for_attachment(
                &endpoint.attachment_id,
                "attachment_closed",
            )
            .map_err(|e| RpcError::Internal(format!("invalidate approval bindings: {e}")))?;
        if invalidated > 0 {
            tracing::info!(
                session_id = %session_id,
                attachment_id = %endpoint.attachment_id,
                invalidated,
                "close_session: invalidated unused attachment-local approval bindings"
            );
        }
    }

    let remaining_attachments = session_store
        .count_other_open_attachments(&meta)
        .map_err(|e| RpcError::Internal(format!("count attachment siblings: {e}")))?;

    // BKR-4c (ADR 205 §6): the per-session authority is the runtime persona's
    // standing grant, torn down below when the closing attachment is the last
    // live one on the caller binding (`terminate_runtime` → `revoke_persona`,
    // which revokes the persona's grants). There is no separate legacy
    // delegation sidecar to cascade-revoke; `workflow_cascade_revoked` now
    // reports that standing-grant teardown. Sibling attachments keep the
    // runtime persona — and thus its standing grant — live (ADR 190 liveness
    // unit = caller binding).
    let workflow_cascade_revoked = remaining_attachments == 0 && meta.is_runtime_attachment();
    if workflow_cascade_revoked
        && let (Some(wf_id), Some(template)) = (&meta.delegation_id, &meta.delegation_template)
    {
        let _ = store.log_event(
            Some(&meta.persona),
            "delegation.revoked",
            None,
            "session_close_cascade",
            Some(&format!(
                "delegation_id={wf_id} template={template} session_id={session_id} reason=session_close_cascade"
            )),
        );
    }

    let terminate_runtime = meta.is_runtime_attachment() && remaining_attachments == 0;
    let runtime_kept_alive = meta.is_runtime_attachment() && remaining_attachments > 0;

    close_guard
        .commit()
        .map_err(|e| RpcError::Internal(format!("close session: {e}")))?;
    let claim_summary = close_session_scope_best_effort(store, session_id, "handle_close_session")
        .or(claim_summary);
    let mut details = format!(
        "session_id={session_id} grant_id={} workflow_cascade_revoked={workflow_cascade_revoked} remaining_attachments={remaining_attachments} runtime_terminated={} runtime_kept_alive={runtime_kept_alive}",
        meta.grant_id, terminate_runtime
    );
    if terminate_runtime {
        store
            .revoke_persona(&meta.persona)
            .map_err(|e| RpcError::Internal(format!("terminate runtime persona: {e}")))?;
    } else if !meta.is_runtime_attachment() {
        details.push_str(" grant_kept_active=true");
    }
    if let Some(summary) = claim_summary.as_ref() {
        details.push(' ');
        details.push_str(&close_summary_audit_fields(summary));
    }

    let _ = store.log_event(
        Some(&meta.persona),
        "session.closed",
        None,
        "clean_exit",
        Some(&details),
    );

    Ok(json!({
        "closed": true,
        "session_id": session_id,
        "receipt_id": receipt_id,
        "workflow_cascade_revoked": workflow_cascade_revoked,
    }))
}

fn asserted_persona_matches(persona: &crate::infra::persona::PersonaInfo, asserted: &str) -> bool {
    persona.id == asserted || persona.name == asserted
}

fn resolve_persona_by_name_or_id(
    store: &DaemonStore,
    asserted: &str,
) -> Result<crate::infra::persona::PersonaInfo, (i32, String)> {
    if let Ok(persona) = store.get_persona(asserted) {
        return Ok(persona);
    }

    store
        .list_personas()
        .map_err(|e| RpcError::Internal(e.to_string()))?
        .into_iter()
        .find(|persona| persona.name == asserted)
        .ok_or_else(|| RpcError::NotFound(format!("persona '{asserted}' not found")).into())
}

fn resolve_register_session_persona(
    store: &DaemonStore,
    ctx: &RequestContext,
    asserted: &str,
) -> Result<crate::infra::persona::PersonaInfo, (i32, String)> {
    if let Some(trusted_principal) = trusted_request_persona(ctx).map_err(|e| e.to_jsonrpc())? {
        let persona = store.get_persona(&trusted_principal).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => RpcError::NotFound(format!(
                "register_session: trusted principal '{}' not found",
                trusted_principal
            )),
            other => RpcError::Internal(other.to_string()),
        })?;
        if !asserted_persona_matches(&persona, asserted) {
            tracing::warn!(
                trusted_persona_id = %persona.id,
                trusted_persona_name = %persona.name,
                asserted_persona = %asserted,
                "register_session refused: asserted persona does not match trusted principal"
            );
            return Err(RpcError::NotFound(
                "register_session: asserted persona does not match trusted principal".to_string(),
            )
            .into());
        }
        return Ok(persona);
    }

    resolve_persona_by_name_or_id(store, asserted)
}

/// Which LLM gateway lane a session is opening, used to disambiguate which
/// active gateway grant to bind when a persona holds more than one (e.g. an
/// operator who uses BOTH `ember claude` and `ember codex` has an
/// `anthropic/oauth-token` grant AND an `openai/chatgpt-oauth` grant on the
/// same persona). Derived from `attestation_caller`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayLane {
    Anthropic,
    OpenAi,
    /// The gemini Code Assist ("Sign in with Google") lane (ADR 215 §2). Binds a
    /// `google/`-prefixed OAuth grant so the loopback projector resolves the
    /// daemon-refreshed Bearer for the session.
    Google,
}

/// Map the launcher-asserted `attestation_caller` to the gateway lane.
/// `codex-network-proxy` → OpenAI (the codex GPT-plan lane, P22-S2);
/// `gemini-code-assist-network-proxy` → Google (ADR 215 §2). Cursor's
/// account/session remains Cursor-owned, so `cursor-agent` does not require a
/// brokered model-auth grant and falls through to the ambient-grant lane.
pub(crate) fn gateway_lane_for_register_session(params: &Value) -> GatewayLane {
    match params.get("attestation_caller").and_then(|v| v.as_str()) {
        Some("codex-network-proxy") => GatewayLane::OpenAi,
        Some("gemini-code-assist-network-proxy") => GatewayLane::Google,
        _ => GatewayLane::Anthropic,
    }
}

pub(crate) fn gateway_lane_requires_brokered_model_auth(params: &Value) -> bool {
    matches!(
        params.get("attestation_caller").and_then(|v| v.as_str()),
        Some(
            "claude-code"
                | "internal-automation"
                | "codex-network-proxy"
                | "gemini-code-assist-network-proxy"
        )
    )
}

fn register_session_uses_anthropic_uds_lane(
    attestation_caller: Option<&str>,
    want_bridge_client_bundle: bool,
) -> bool {
    matches!(
        attestation_caller,
        Some("claude-code") | Some("internal-automation")
    ) && !want_bridge_client_bundle
}

fn resolve_register_session_active_grant(
    store: &DaemonStore,
    persona: &crate::infra::persona::PersonaInfo,
    asserted: &str,
    lane: GatewayLane,
    require_brokered_model_auth: bool,
    require_github_operation_authority: bool,
) -> Result<crate::trust::grant::GrantInfo, (i32, String)> {
    let mut active_grants = store
        .list_active_grants()
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .filter(|grant| {
            grant.persona_id == persona.id
                && grant.status == "active"
                && grant.max_delegation_depth.unwrap_or(0) > 0
                && store.leases().has_live_lease(&grant.id, chrono::Utc::now())
        })
        .collect::<Vec<_>>();

    if let Some((preferred_idx, _rank)) = active_grants
        .iter()
        .enumerate()
        .filter_map(|(idx, grant)| {
            active_grant_gateway_preference_rank(
                store,
                grant,
                lane,
                require_github_operation_authority,
            )
            .map(|rank| (idx, rank))
        })
        .min_by_key(|(_, rank)| *rank)
    {
        return Ok(active_grants.swap_remove(preferred_idx));
    }

    if require_brokered_model_auth {
        let (provider, credential_hint, legacy_scope, init_target) = match lane {
            GatewayLane::Anthropic => (
                "Anthropic",
                ANTHROPIC_RUNTIME_CREDENTIAL_HINT,
                CLAUDE_CODE_DEFAULT_SCOPE,
                "claude",
            ),
            GatewayLane::OpenAi => (
                "OpenAI",
                OPENAI_RUNTIME_CREDENTIAL_HINT,
                CODEX_DEFAULT_SCOPE,
                "codex",
            ),
            GatewayLane::Google => (
                "Google",
                GOOGLE_RUNTIME_CREDENTIAL_HINT,
                GEMINI_DEFAULT_SCOPE,
                "gemini",
            ),
        };
        return Err((
            -32004,
            format!(
                "no active {provider} runtime-delegable grant for persona '{asserted}'; this launcher session requires brokered model auth via {credential_hint} and cannot fall back to legacy {legacy_scope} authority. Rerun `ember init --for {init_target}` after storing the missing vault credential"
            ),
        ));
    }

    active_grants
        .into_iter()
        .next()
        .ok_or_else(|| {
            (
                -32004,
                format!(
                    "no active runtime-delegable grant for persona '{asserted}'; rerun `ember init` to provision one"
                ),
            )
        })
}

fn is_anthropic_gateway_credential_name(credential_name: &str) -> bool {
    credential_name.starts_with(ANTHROPIC_PROVIDER_CREDENTIAL_PREFIX)
}

fn is_openai_gateway_credential_name(credential_name: &str) -> bool {
    credential_name.starts_with(OPENAI_PROVIDER_CREDENTIAL_PREFIX)
}

fn is_google_gateway_credential_name(credential_name: &str) -> bool {
    credential_name.starts_with(GOOGLE_PROVIDER_CREDENTIAL_PREFIX)
}

/// Lane-aware preference rank for an active grant. Lower = more preferred;
/// `None` = not a gateway grant for this lane (so it is never picked over a
/// matching one, but can still be the `.next()` fallback).
///
/// The codex GPT-plan lane (P22-S2) must NOT bind an `anthropic/*` grant and
/// vice-versa, so selection is keyed on the opening lane rather than a single
/// global anthropic preference.
fn active_grant_gateway_preference_rank(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    lane: GatewayLane,
    require_github_operation_authority: bool,
) -> Option<u8> {
    match lane {
        GatewayLane::Anthropic => {
            if !active_grant_supports_anthropic_gateway(
                store,
                active_grant,
                require_github_operation_authority,
            ) {
                return None;
            }
            Some(match active_grant.credential_name.as_str() {
                name if name.starts_with(ANTHROPIC_PLAN_OAUTH_CREDENTIAL_PREFIX) => 0,
                name if name.starts_with(ANTHROPIC_API_KEY_CREDENTIAL_PREFIX) => 1,
                name if is_anthropic_gateway_credential_name(name) => 2,
                _ => 3,
            })
        }
        GatewayLane::OpenAi => {
            if !active_grant_supports_openai_gateway(
                store,
                active_grant,
                require_github_operation_authority,
            ) {
                return None;
            }
            Some(match active_grant.credential_name.as_str() {
                name if name.starts_with(OPENAI_CHATGPT_PLAN_CREDENTIAL_PREFIX) => 0,
                name if is_openai_gateway_credential_name(name) => 1,
                _ => 2,
            })
        }
        GatewayLane::Google => {
            if !active_grant_supports_google_gateway(
                store,
                active_grant,
                require_github_operation_authority,
            ) {
                return None;
            }
            Some(match active_grant.credential_name.as_str() {
                name if name == GOOGLE_CODE_ASSIST_OAUTH_CREDENTIAL => 0,
                name if is_google_gateway_credential_name(name) => 1,
                _ => 2,
            })
        }
    }
}

/// Whether an active grant is shaped for the codex OpenAI gateway: its
/// credential is `openai/*`, its chain carries a Credential statement for that
/// credential, a Session statement allowing `llm:generate` against an
/// `openai/*` target, and, when the launcher selected a delegation template,
/// GitHub operation authority to narrow for `ember-gh` constructs (symmetric with
/// [`active_grant_supports_anthropic_gateway`]).
fn active_grant_supports_openai_gateway(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    require_github_operation_authority: bool,
) -> bool {
    let credential_name = active_grant.credential_name.as_str();
    if !is_openai_gateway_credential_name(credential_name) {
        return false;
    }

    let chain = match store.get_access_grant(&active_grant.id) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::warn!(
                grant_id = %active_grant.id,
                error = %e,
                "register_session: failed to load active grant chain for openai gateway shaping"
            );
            return false;
        }
    };

    let mut has_matching_credential_stmt = false;
    let mut has_openai_session_stmt = false;
    let mut has_github_operation_authority = false;
    for (_idx, stmt) in chain.statements() {
        match stmt.resource_type {
            core_grant_types::ResourceType::Credential => {
                has_matching_credential_stmt |= matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value == credential_name
                );
                has_github_operation_authority |= statement_has_github_operation_authority(&stmt);
            }
            core_grant_types::ResourceType::Session => {
                let allows_llm_generate =
                    stmt.actions.iter().any(|action| action == "llm:generate");
                let targets_openai = matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Glob { pattern } if pattern.starts_with("openai/")
                ) || matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value.starts_with("openai/")
                );
                has_openai_session_stmt |= allows_llm_generate && targets_openai;
            }
            _ => {}
        }
    }

    has_matching_credential_stmt
        && has_openai_session_stmt
        && (!require_github_operation_authority || has_github_operation_authority)
}

/// Whether an active grant is shaped for the gemini Code Assist Google gateway:
/// its credential is `google/*`, its chain carries a Credential statement for
/// that credential, a Session statement allowing `llm:generate` against a
/// `google/*` target, and, when the launcher selected a delegation template,
/// GitHub operation authority to narrow for `ember-gh` constructs (symmetric
/// with [`active_grant_supports_openai_gateway`]).
fn active_grant_supports_google_gateway(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    require_github_operation_authority: bool,
) -> bool {
    let credential_name = active_grant.credential_name.as_str();
    if !is_google_gateway_credential_name(credential_name) {
        return false;
    }

    let chain = match store.get_access_grant(&active_grant.id) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::warn!(
                grant_id = %active_grant.id,
                error = %e,
                "register_session: failed to load active grant chain for google gateway shaping"
            );
            return false;
        }
    };

    let mut has_matching_credential_stmt = false;
    let mut has_google_session_stmt = false;
    let mut has_github_operation_authority = false;
    for (_idx, stmt) in chain.statements() {
        match stmt.resource_type {
            core_grant_types::ResourceType::Credential => {
                has_matching_credential_stmt |= matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value == credential_name
                );
                has_github_operation_authority |= statement_has_github_operation_authority(&stmt);
            }
            core_grant_types::ResourceType::Session => {
                let allows_llm_generate =
                    stmt.actions.iter().any(|action| action == "llm:generate");
                let targets_google = matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Glob { pattern } if pattern.starts_with("google/")
                ) || matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value.starts_with("google/")
                );
                has_google_session_stmt |= allows_llm_generate && targets_google;
            }
            _ => {}
        }
    }

    has_matching_credential_stmt
        && has_google_session_stmt
        && (!require_github_operation_authority || has_github_operation_authority)
}

fn active_grant_supports_anthropic_gateway(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    require_github_operation_authority: bool,
) -> bool {
    let credential_name = active_grant.credential_name.as_str();
    if !is_anthropic_gateway_credential_name(credential_name) {
        return false;
    }

    let chain = match store.get_access_grant(&active_grant.id) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::warn!(
                grant_id = %active_grant.id,
                error = %e,
                "register_session: failed to load active grant chain for anthropic gateway shaping"
            );
            return false;
        }
    };

    let mut has_matching_credential_stmt = false;
    let mut has_anthropic_session_stmt = false;
    let mut has_github_operation_authority = false;
    for (_idx, stmt) in chain.statements() {
        match stmt.resource_type {
            core_grant_types::ResourceType::Credential => {
                has_matching_credential_stmt |= matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value == credential_name
                );
                has_github_operation_authority |= statement_has_github_operation_authority(&stmt);
            }
            core_grant_types::ResourceType::Session => {
                let allows_llm_generate =
                    stmt.actions.iter().any(|action| action == "llm:generate");
                let targets_anthropic = matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Glob { pattern } if pattern.starts_with("anthropic/")
                ) || matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value.starts_with("anthropic/")
                );
                has_anthropic_session_stmt |= allows_llm_generate && targets_anthropic;
            }
            _ => {}
        }
    }

    has_matching_credential_stmt
        && has_anthropic_session_stmt
        && (!require_github_operation_authority || has_github_operation_authority)
}

fn statement_has_github_operation_authority(stmt: &core_grant_types::Statement) -> bool {
    stmt.actions.iter().any(|action| {
        if action == "github:*" {
            matches!(
                &stmt.resource,
                core_grant_types::ResourceSelector::Glob { pattern } if pattern == "*"
            )
        } else {
            action.starts_with("github:")
        }
    })
}

fn anthropic_gateway_bundle_for_register_session(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    attachment_endpoint: &core_state::sessions::AttachmentEndpoint,
    proxy_url: &str,
    uds_socket_path: Option<&std::path::Path>,
) -> Option<(String, String)> {
    if !active_grant_supports_anthropic_gateway(store, active_grant, false) {
        return None;
    }

    Some(anthropic_gateway_lane_bundle(
        active_grant.credential_name.as_str(),
        &attachment_endpoint.attachment_id,
        &attachment_endpoint.endpoint_token,
        proxy_url,
        uds_socket_path.is_some(),
    ))
}

/// Build the `(base_url, custom_headers)` pair for the Anthropic gateway lane.
///
/// P22-S2 PR-C (ADR 197 §2):
/// - **UDS lane** (`uds == true`): base URL is the non-Anthropic CHECKPOINT so a
///   socket-bypass fails closed (the harness routes over
///   `ANTHROPIC_UNIX_SOCKET`); the attachment binding is the socket itself
///   (resolved daemon-side by session id), so the replayable bearer is DROPPED
///   entirely — only the credential selector + upstream target are sent.
/// - **TCP lane** (`uds == false`, non-Claude clients): loopback proxy URL +
///   attachment-endpoint bearer headers, resolved header-side.
///
/// Pure so the security-critical invariant — no `X-Ember-Endpoint-Token` on the
/// UDS lane — is unit-testable without a live store.
fn anthropic_gateway_lane_bundle(
    credential_name: &str,
    attachment_id: &str,
    endpoint_token: &str,
    proxy_url: &str,
    uds: bool,
) -> (String, String) {
    if uds {
        (
            crate::infra::session_proxy::SENTINEL_BASE_URL.to_string(),
            format!(
                "X-Ember-Credential: {credential_name}\nX-Ember-Target: https://api.anthropic.com"
            ),
        )
    } else {
        (
            proxy_url.to_string(),
            format!(
                "X-Ember-Credential: {credential_name}\nX-Ember-Target: https://api.anthropic.com\nX-Ember-Attachment-Id: {attachment_id}\nX-Ember-Endpoint-Token: {endpoint_token}"
            ),
        )
    }
}

/// Outcome of [`mint_sandbox_gateway_env`]: the internal session bound to the
/// sandbox plus the container env that carries its proxy LLM lane.
pub(crate) struct SandboxGatewayLane {
    /// Internal `register_session` id. The caller persists this on the sandbox
    /// so `sandbox_stop` / `sandbox_delete` can `close_session` it.
    pub session_id: String,
    /// Container `-e` vars carrying the proxy-injected LLM gateway bundle.
    pub env: Vec<(String, String)>,
    /// Per-spawn ADR 154 mTLS bridge client bundle for the container's emberd
    /// control plane (ADR 207 seam 6). `None` when the daemon bridge listener is
    /// not configured — the container still starts (fail-soft), just without a
    /// control plane; the dead daemon UDS is never mounted in (ADR 154).
    pub bridge: Option<RegisterSessionBridgeClientBundle>,
}

/// Mint the proxy-injected LLM gateway env for a daemon-spawned sandbox
/// container (ADR 207 §I2). Runs the canonical [`handle_register_session`]
/// minting core as an INTERNAL caller (`peer = None`), which:
/// - persists the `SessionMeta` + active `AttachmentEndpoint` the proxy resolves
///   server-side, so the container's `X-Ember-Attachment-Id` /
///   `X-Ember-Endpoint-Token` headers bind to the vault-backed credential;
/// - writes the persona-keyed host-mode enrollment row that lets the container's
///   `broker_exec` pass `check_principal_enrollment_strict`; and
/// - forces the TCP gateway lane (no UDS in a container — ADR 154) because
///   `peer = None` ⇒ no per-session peercred socket, so `uds_socket_path` is
///   `None`.
///
/// The caller (`sandbox_create` / `sandbox_run`) is itself classed
/// `OperatorPresence` — the SAME class as `register_session` — so the operator
/// presence that authorized the sandbox RPC already covers this internal session
/// mint; it is not a presence-gate bypass.
///
/// `owner_persona` is the persona the session registers under — it must hold
/// the active gateway grant. The daemon-sandbox lane funds the LLM lane off the
/// sandbox's OWNER (operator) persona, because the fresh per-sandbox persona
/// minted by `create_sandbox_with_opts` holds no grant; this mirrors the
/// isolated/`up` lane, which registers under the operator persona.
///
/// On success returns `Some(SandboxGatewayLane)` carrying the minted
/// `session_id` (the caller persists it on the sandbox so stop/delete can
/// `close_session` it) and the container `-e` vars: `ANTHROPIC_BASE_URL`
/// (loopback rewritten to `host.docker.internal`), `ANTHROPIC_CUSTOM_HEADERS`,
/// the inert `ANTHROPIC_AUTH_TOKEN` checkpoint, and `EMBER_WORKSPACE_REF` when the
/// session carries a workspace binding. The raw credential never leaves the
/// daemon.
///
/// Returns `Ok(None)` when the owner persona has no anthropic gateway grant: the
/// transient session `register_session` created is closed immediately so it
/// never strands a vault-lock pin.
pub(crate) fn mint_sandbox_gateway_env(
    store: &DaemonStore,
    ctx: &RequestContext,
    owner_persona: &str,
    launcher_pid: u32,
) -> Result<Option<SandboxGatewayLane>, (i32, String)> {
    // Internal caller: drop the operator peer so the per-session peercred UDS
    // gateway + presence-token mint are skipped and the TCP lane is selected,
    // but KEEP the connection's sessions_dir + proxy URLs —
    // `handle_register_session` hard-requires `sessions_dir` and reads
    // `llm_proxy_url` for the gateway bundle's base URL.
    let internal_ctx = RequestContext {
        sessions_dir: ctx.sessions_dir.clone(),
        llm_proxy_url: ctx.llm_proxy_url.clone(),
        git_proxy_url: ctx.git_proxy_url.clone(),
        ..RequestContext::internal("sandbox-register-session")
    };

    let params = json!({
        "persona": owner_persona,
        "launcher_pid": launcher_pid,
        "attestation_caller": "claude-code",
    });

    let mut response = handle_register_session(store, &internal_ctx, &params)?;
    if let Some(obj) = response.as_object_mut() {
        obj.remove(ENDPOINT_GROUP_ROLLBACK_KEY);
    }
    let session_id = response
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or((
            -32000,
            "register_session response missing session_id".to_string(),
        ))?
        .to_string();

    let mut env: Vec<(String, String)> = Vec::new();
    if let Some(base_url) = response.get("anthropic_base_url").and_then(Value::as_str) {
        env.push((
            "ANTHROPIC_BASE_URL".to_string(),
            crate::infra::sandbox::rewrite_loopback_url_for_container(base_url),
        ));
    }
    if let Some(headers) = response
        .get("anthropic_custom_headers")
        .and_then(Value::as_str)
    {
        env.push(("ANTHROPIC_CUSTOM_HEADERS".to_string(), headers.to_string()));
    }

    // No brokered base URL ⇒ the owner persona has no anthropic gateway grant.
    // Don't strand a useless session holding a vault-lock pin: close it now and
    // report no lane. Best-effort — a close failure only risks a stale pin
    // (cleared on daemon restart), never a leaked credential.
    if env.is_empty() {
        if let Err((code, msg)) =
            handle_close_session(store, &internal_ctx, &json!({ "session_id": session_id }))
        {
            tracing::warn!(code, error = %msg, %session_id, "failed to close empty-bundle sandbox session");
        }
        return Ok(None);
    }

    // Inert checkpoint — Claude needs a bearer present to start under a brokered
    // base URL; the proxy injects the real credential server-side.
    env.push((
        "ANTHROPIC_AUTH_TOKEN".to_string(),
        crate::infra::sandbox::CONTAINER_PROXY_AUTH_PLACEHOLDER.to_string(),
    ));
    if let Some(workspace_ref) = response.get("workspace_ref").and_then(Value::as_str) {
        env.push(("EMBER_WORKSPACE_REF".to_string(), workspace_ref.to_string()));
    }

    // ADR 207 seam 6 / ADR 154 — mint the per-spawn mTLS bridge client bundle so
    // the container has an emberd control plane (broker / grant resolution /
    // receipts), bound to this same session + runtime persona. This is the
    // contract-parity half of the daemon-sandbox lane: the CLI `--isolated` lane
    // already ships a bridge bundle, and the dead daemon-UDS mount is removed in
    // `start_container`.
    //
    // FAIL-SOFT and SEPARATE from the LLM `register_session` above: a bridge
    // failure (e.g. `[daemon].bridge_bind` unconfigured → -32030) must NOT kill
    // the working LLM lane. We therefore mint the bundle here rather than passing
    // `bridge_client_bundle: true` into `handle_register_session` (which would
    // `?`-propagate the failure and tear down the whole session). The bundle is
    // only minted when an LLM lane exists (env non-empty / session alive); a
    // bridge-only sandbox with no LLM grant is an unhandled follow-up.
    let bridge = match crate::infra::interactive_unlock::ensure_vault_for_session_open(store) {
        Ok(vault) => match response.get("runtime_persona_id").and_then(Value::as_str) {
            Some(runtime_persona_id) => {
                match mint_register_session_bridge_client_bundle(
                    &vault,
                    runtime_persona_id,
                    &session_id,
                    // Daemon-sandbox lane keeps the session-id-as-container-ref
                    // SAN; the orchestrator lane (SCION-209 #2) supplies its
                    // real container id via the register_session param instead.
                    None,
                ) {
                    Ok(bundle) => Some(bundle),
                    Err((code, msg)) => {
                        tracing::debug!(
                            code,
                            error = %msg,
                            %session_id,
                            "sandbox bridge bundle unavailable; container starts without an emberd control plane"
                        );
                        None
                    }
                }
            }
            None => {
                tracing::warn!(%session_id, "register_session response missing runtime_persona_id; skipping sandbox bridge bundle");
                None
            }
        },
        Err(msg) => {
            tracing::debug!(error = %msg, %session_id, "vault unavailable for sandbox bridge bundle mint; skipping");
            None
        }
    };

    Ok(Some(SandboxGatewayLane {
        session_id,
        env,
        bridge,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        GatewayLane, anthropic_gateway_lane_bundle, authority_posture_json,
        gateway_lane_for_register_session, gateway_lane_requires_brokered_model_auth,
        handle_describe_runtime_attach_target, register_session_uses_anthropic_uds_lane,
        statement_has_github_operation_authority, string_array_param, write_template_to_overlay,
    };

    // ssh-agent-over-bridge S3/F — register_session mints the session's
    // SSH-signing lease (time-boxed, grant-scoped, no standing forever-key) and
    // the S1 gate sees it live; close drops it so a subsequent sign is refused.
    // The signed Receipt is emitted at endpoint-bind (with the real key
    // fingerprint), covered by `ssh_lease_grant_receipt_records_real_fingerprint`.
    #[test]
    fn ssh_signing_lease_mint_then_drop_observed_by_gate() {
        use crate::trust::lease::scope_authorizes_ssh_signing;
        let store = super::DaemonStore::open_in_memory().expect("store");
        let now = chrono::Utc::now();

        let (grant_id, granted_at, expires) =
            super::provision_session_ssh_signing_lease(&store, "sess_ssh_s3", "persona-1");
        assert!(scope_authorizes_ssh_signing(super::SSH_SIGNING_LEASE_SCOPE));
        assert_eq!(grant_id, super::ssh_signing_grant_id("sess_ssh_s3"));
        assert!(
            store.leases().has_live_ssh_signing_lease(&grant_id, now),
            "the minted lease must authorize SSH signing — the S1 gate sees it live"
        );
        assert!(
            expires > granted_at && granted_at > 0,
            "lease must be time-boxed into the future (ADR 211: no standing forever-key)"
        );

        // close drops the lease → S1's gate refuses subsequent signs.
        assert!(
            store.leases().drop_lease(&grant_id),
            "close drops the lease"
        );
        assert!(
            !store.leases().has_live_ssh_signing_lease(&grant_id, now),
            "after close, no live lease — the bridge gate refuses (revocation propagates)"
        );
    }

    #[test]
    fn endpoint_group_teardown_drops_lease_and_host_enrollment_idempotently() {
        let store = super::DaemonStore::open_in_memory().expect("store");
        let session_id = "sess_endpoint_group";
        let persona_id = "persona-1";
        let (grant_id, _, _) =
            super::provision_session_ssh_signing_lease(&store, session_id, persona_id);
        let host_socket_path = super::host_mode_enrollment_socket_path(session_id);
        store
            .record_host_mode_socket_enrollment(
                &host_socket_path,
                persona_id,
                "runtime-grant-1",
                Some(501),
            )
            .expect("record host-mode enrollment");

        assert!(
            store
                .leases()
                .has_live_ssh_signing_lease(&grant_id, chrono::Utc::now()),
            "precondition: endpoint group owns a live SSH lease"
        );
        assert!(
            store
                .lookup_agent_socket_enrollment(&host_socket_path)
                .expect("lookup enrollment")
                .is_some(),
            "precondition: endpoint group owns a live host-mode enrollment"
        );

        super::EndpointGroup::teardown_all(&store, session_id, "test");
        super::EndpointGroup::teardown_all(&store, session_id, "test-idempotent");

        assert!(
            !store
                .leases()
                .has_live_ssh_signing_lease(&grant_id, chrono::Utc::now()),
            "endpoint group close drops the SSH-signing lease"
        );
        assert!(
            store
                .lookup_agent_socket_enrollment(&host_socket_path)
                .expect("lookup enrollment after close")
                .is_none(),
            "endpoint group close revokes the host-mode enrollment"
        );
    }

    #[tokio::test]
    async fn finalize_register_session_endpoint_group_strips_private_metadata_without_ssh() {
        let store = std::rc::Rc::new(super::DaemonStore::open_in_memory().expect("store"));
        let mut result = json!({
            "session_id": "sess_no_ssh",
            "grant_id": "runtime-grant-1",
        });
        result[super::ENDPOINT_GROUP_ROLLBACK_KEY] = json!({
            "session_id": "sess_no_ssh",
            "runtime_grant_id": "runtime-grant-1",
        });

        super::finalize_register_session_endpoint_group(store, None, &mut result)
            .await
            .expect("finalize without ssh lease");

        assert!(
            result.get(super::ENDPOINT_GROUP_ROLLBACK_KEY).is_none(),
            "private endpoint lifecycle metadata must not reach the RPC response"
        );
    }

    #[tokio::test]
    async fn finalize_ssh_endpoint_rolls_back_when_session_already_closed() {
        let sessions_dir = tempfile::tempdir().expect("sessions dir");
        let session_store = core_state::SessionStore::new(sessions_dir.path().to_path_buf());
        let session_id = "sess_finalize_closed";
        session_store
            .create(&core_state::sessions::SessionMeta {
                session_id: session_id.to_string(),
                persona: "persona-1".to_string(),
                grant_id: "runtime-grant-1".to_string(),
                started_at: chrono::Utc::now(),
                launcher_pid: std::process::id(),
                authority_strict: false,
                delegation_id: None,
                delegation_template: None,
                durable_persona: Some("durable-1".to_string()),
                caller_binding_id: Some("caller-binding-1".to_string()),
            })
            .expect("create session");
        session_store
            .close(session_id)
            .expect("close before finalize");

        let store = std::rc::Rc::new(super::DaemonStore::open_in_memory().expect("store"));
        let (grant_id, granted_at, expires_at) =
            super::provision_session_ssh_signing_lease(&store, session_id, "persona-1");
        let mut result = json!({
            "session_id": session_id,
            "grant_id": "runtime-grant-1",
            "ssh_agent_lease": {
                "grant_id": grant_id.clone(),
                "scope": super::SSH_SIGNING_LEASE_SCOPE,
                "session_id": session_id,
                "persona_id": "persona-1",
                "granted_at_epoch_secs": granted_at,
                "expires_at_epoch_secs": expires_at,
            },
        });
        result[super::ENDPOINT_GROUP_ROLLBACK_KEY] = json!({
            "session_id": session_id,
            "runtime_grant_id": null,
        });

        let err = super::finalize_register_session_endpoint_group(
            std::rc::Rc::clone(&store),
            Some(sessions_dir.path().to_path_buf()),
            &mut result,
        )
        .await
        .expect_err("closed session races fail closed");

        assert!(
            err.1.contains("raced with close_session"),
            "error explains the register/close race"
        );
        assert!(
            !store
                .leases()
                .has_live_ssh_signing_lease(&grant_id, chrono::Utc::now()),
            "rollback drops the SSH lease for the closed session"
        );
    }

    // ssh-agent-over-bridge F1 — the lease-grant Receipt is emitted at
    // endpoint-bind and carries the REAL loaded-key fingerprint (sha256 of the
    // pubkey blob), not the `pending_endpoint_bind` placeholder.
    #[test]
    fn ssh_lease_grant_receipt_records_real_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _ = crate::infra::receipt::init_identity(dir.path());
        let store = super::DaemonStore::open_in_memory().expect("store");

        let grant_id = super::ssh_signing_grant_id("sess_fp");
        let pubkey_blob = b"ssh-ed25519-pubkey-blob-bytes";
        let fp = super::ssh_pubkey_fingerprint(pubkey_blob);
        assert_eq!(fp.len(), 64, "sha256 hex is 64 chars");

        super::sign_and_store_ssh_lease_grant_receipt(
            &store,
            "sess_fp",
            "persona-1",
            &grant_id,
            &fp,
            1_000,
            4_600,
        )
        .expect("sign + store ssh lease-grant receipt");

        // The stored Receipt carries the real fingerprint (not the placeholder).
        let receipts = store
            .list_receipts_v2_envelopes(&[grant_id.clone()])
            .expect("query receipts");
        assert_eq!(receipts.len(), 1, "exactly one lease-grant Receipt");
        let body = &receipts[0].3.body;
        assert_eq!(
            body.get("key_fingerprint_sha256").and_then(|v| v.as_str()),
            Some(fp.as_str()),
            "Receipt records the real key fingerprint"
        );
        assert_ne!(
            body.get("key_fingerprint_sha256").and_then(|v| v.as_str()),
            Some("pending_endpoint_bind"),
            "no placeholder fingerprint survives to the Receipt"
        );
    }

    // ssh-agent-over-bridge F1 — the daemon-composition tracer: `register_session`
    // mints the lease; `finalize_register_session_endpoint_group` binds a
    // per-session bridge in front of the host agent, gated by the REAL
    // store-backed lease; a same-uid host client signs through it; dropping the
    // lease flips it to refused
    // (revocation propagates); and `close_session` teardown unlinks the socket.
    // (The crypto "key never crosses the wire" + per-session isolation invariants
    // are proven in ember-broker's S1 bridge tests; this proves the daemon wiring.)
    #[tokio::test]
    // The host-agent + bridge sockets live under a tempdir `HOME` (the real
    // `~/.ember/run` is owned by the daemon service user). `HOME` is process-
    // global, so `PROCESS_TEST_LOCK` serializes this with the suite's other
    // env-mutating tests; the lock is intentionally held across the test's
    // `.await`s to keep `HOME` exclusive for the whole run.
    #[allow(clippy::await_holding_lock)]
    async fn finalize_binds_lease_gated_bridge_then_teardown_revokes() {
        // OpenSSH agent protocol bytes (stable wire constants).
        const REQUEST_IDENTITIES: u8 = 11;
        const IDENTITIES_ANSWER: u8 = 12;
        const SIGN_REQUEST: u8 = 13;
        const SIGN_RESPONSE: u8 = 14;
        const FAILURE: u8 = 5;

        fn enc_str(s: &[u8]) -> Vec<u8> {
            let mut v = (s.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(s);
            v
        }
        fn build_sign_request(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
            let mut p = vec![SIGN_REQUEST];
            p.extend_from_slice(&enc_str(key_blob));
            p.extend_from_slice(&enc_str(data));
            p.extend_from_slice(&0u32.to_be_bytes());
            p
        }
        fn first_blob(answer: &[u8]) -> Option<Vec<u8>> {
            if answer.first().copied()? != IDENTITIES_ANSWER {
                return None;
            }
            let nkeys = u32::from_be_bytes(answer.get(1..5)?.try_into().ok()?);
            if nkeys == 0 {
                return None;
            }
            let blen = u32::from_be_bytes(answer.get(5..9)?.try_into().ok()?) as usize;
            Some(answer.get(9..9 + blen)?.to_vec())
        }
        async fn bridge_request(sock: &str, payload: &[u8]) -> Option<Vec<u8>> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = tokio::net::UnixStream::connect(sock).await.ok()?;
            s.write_all(&(payload.len() as u32).to_be_bytes())
                .await
                .ok()?;
            s.write_all(payload).await.ok()?;
            s.flush().await.ok()?;
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await.ok()?;
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > 256 * 1024 {
                return None;
            }
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).await.ok()?;
            Some(buf)
        }

        // Serialize the `HOME` mutation against the suite's other env-mutating
        // tests (the established `PROCESS_TEST_LOCK` convention). Held for the whole
        // test so `HOME` stays exclusive across the awaits below.
        let _env_lock = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Restore-on-drop `HOME` override so the host-agent + bridge sockets land
        // under a operator-owned tempdir (the real `~/.ember/run` is owned by the
        // daemon service user, so a same-user `bind` there would EACCES). Drop
        // runs on panic too, so a failing assert still restores `HOME`.
        struct HomeGuard(Option<String>);
        impl Drop for HomeGuard {
            fn drop(&mut self) {
                // SAFETY: test-only env mutation, serialized by PROCESS_TEST_LOCK.
                match &self.0 {
                    Some(v) => unsafe { std::env::set_var("HOME", v) },
                    None => unsafe { std::env::remove_var("HOME") },
                }
            }
        }
        let home = tempfile::tempdir().expect("home tempdir");
        let _home_guard = HomeGuard(std::env::var("HOME").ok());
        // SAFETY: test-only env mutation, serialized by PROCESS_TEST_LOCK.
        unsafe { std::env::set_var("HOME", home.path()) };

        let id_dir = tempfile::tempdir().expect("identity dir");
        let _ = crate::infra::receipt::init_identity(id_dir.path());
        let store = std::rc::Rc::new(super::DaemonStore::open_in_memory().expect("store"));

        tokio::task::LocalSet::new()
            .run_until(async move {
                let session_id = "sess_f1_wire";
                let persona_id = "persona-1";

                // register_session mints the lease...
                let (grant_id, granted_at, expires) =
                    super::provision_session_ssh_signing_lease(&store, session_id, persona_id);
                // ...and the dispatch site finalizes the bind off this response shape.
                let mut result = json!({
                    "ssh_agent_lease": {
                        "grant_id": grant_id,
                        "scope": super::SSH_SIGNING_LEASE_SCOPE,
                        "session_id": session_id,
                        "persona_id": persona_id,
                        "granted_at_epoch_secs": granted_at,
                        "expires_at_epoch_secs": expires,
                    }
                });
                super::finalize_register_session_endpoint_group(
                    std::rc::Rc::clone(&store),
                    None,
                    &mut result,
                )
                .await
                .expect("endpoint group finalizes");

                let bridge_sock = result["ssh_agent_lease"]["bridge_sock"]
                    .as_str()
                    .expect("bridge bound — response carries bridge_sock")
                    .to_string();

                // (The raw host-agent socket's 0600 owner-only perms + unlink-on-
                // drop are proven deterministically in ember-broker's
                // `host_agent_socket_is_owner_only_and_unlinked_on_drop`, which pins
                // the Tier-0 spawn path; the agent path here varies by Tier-0/SE.)

                // identities -> the session's pubkey blob.
                let answer = bridge_request(&bridge_sock, &[REQUEST_IDENTITIES])
                    .await
                    .expect("identities answer");
                assert_eq!(answer[0], IDENTITIES_ANSWER);
                let key_blob = first_blob(&answer).expect("session key advertised");

                // sign -> a real SIGN_RESPONSE (the REAL store-backed lease gate served it).
                let sign_req = build_sign_request(&key_blob, b"git-push-handshake");
                let resp = bridge_request(&bridge_sock, &sign_req)
                    .await
                    .expect("a response");
                assert_eq!(
                    resp[0], SIGN_RESPONSE,
                    "the live lease gate served the sign through the bound bridge"
                );

                // Revocation: drop the lease in the real store -> the next sign is refused.
                assert!(store.leases().drop_lease(&grant_id), "lease dropped");
                let refused = bridge_request(&bridge_sock, &sign_req)
                    .await
                    .expect("a response");
                assert_eq!(
                    refused,
                    vec![FAILURE],
                    "after the lease drops, the bridge refuses (SSH_AGENT_FAILURE)"
                );

                // close_session teardown unlinks the bridge socket + stops serving.
                super::teardown_ssh_agent_bridge(session_id);
                assert!(
                    !std::path::Path::new(&bridge_sock).exists(),
                    "teardown unlinks the bridge socket"
                );
                assert!(
                    tokio::net::UnixStream::connect(&bridge_sock).await.is_err(),
                    "no client can connect after teardown"
                );
            })
            .await;
    }

    // P22-S2 GPT-plan: the codex lane (attestation_caller=codex-network-proxy)
    // must select the OpenAI gateway grant, not the Anthropic one — otherwise a
    // persona holding both an anthropic and an openai grant would mis-bind codex
    // to the anthropic credential and fail the proxy's provider gate.
    #[test]
    fn gateway_lane_routes_codex_to_openai_claude_to_anthropic() {
        assert_eq!(
            gateway_lane_for_register_session(
                &json!({"attestation_caller": "codex-network-proxy"})
            ),
            GatewayLane::OpenAi
        );
        assert_eq!(
            gateway_lane_for_register_session(&json!({"attestation_caller": "claude-code"})),
            GatewayLane::Anthropic
        );
        // ADR 215 §2 — the gemini Code Assist caller routes to the Google lane.
        assert_eq!(
            gateway_lane_for_register_session(
                &json!({"attestation_caller": "gemini-code-assist-network-proxy"})
            ),
            GatewayLane::Google
        );
        assert_eq!(
            gateway_lane_for_register_session(&json!({"attestation_caller": "cursor-agent"})),
            GatewayLane::Anthropic
        );
        // Absent attestation_caller preserves prior behavior (Anthropic).
        assert_eq!(
            gateway_lane_for_register_session(&json!({})),
            GatewayLane::Anthropic
        );
        assert!(gateway_lane_requires_brokered_model_auth(
            &json!({"attestation_caller": "codex-network-proxy"})
        ));
        assert!(gateway_lane_requires_brokered_model_auth(
            &json!({"attestation_caller": "claude-code"})
        ));
        assert!(gateway_lane_requires_brokered_model_auth(
            &json!({"attestation_caller": "internal-automation"})
        ));
        assert!(
            gateway_lane_requires_brokered_model_auth(
                &json!({"attestation_caller": "gemini-code-assist-network-proxy"})
            ),
            "the gemini Code Assist lane is a governed brokered-model-auth lane"
        );
        assert!(
            !gateway_lane_requires_brokered_model_auth(
                &json!({"attestation_caller": "cursor-agent"})
            ),
            "Cursor egress proxying is not governed model-auth brokering"
        );
        assert!(
            !gateway_lane_requires_brokered_model_auth(&json!({})),
            "untagged register_session callers are not modeled as LLM sessions"
        );
    }

    #[test]
    fn bridge_requested_claude_registration_does_not_use_host_uds_lane() {
        assert!(
            register_session_uses_anthropic_uds_lane(Some("claude-code"), false),
            "host Claude keeps the peercred UDS Anthropic lane"
        );
        assert!(
            !register_session_uses_anthropic_uds_lane(Some("claude-code"), true),
            "Sandvault/container Claude requests a bridge bundle and must not receive a host UDS"
        );
        assert!(
            register_session_uses_anthropic_uds_lane(Some("internal-automation"), false),
            "host forge keeps the peercred UDS Anthropic lane"
        );
        assert!(
            !register_session_uses_anthropic_uds_lane(Some("codex-network-proxy"), false),
            "Codex uses its responses proxy lane, not the Anthropic UDS lane"
        );
        assert!(
            !register_session_uses_anthropic_uds_lane(Some("cursor-agent"), false),
            "Cursor uses its egress proxy lane, not the Anthropic UDS lane"
        );
    }

    #[test]
    fn gateway_grant_shape_accepts_narrowed_github_operation_authority() {
        fn github_statement(
            actions: Vec<&str>,
            wildcard_resource: bool,
        ) -> core_grant_types::Statement {
            core_grant_types::Statement {
                sid: "github".to_string(),
                resource_type: core_grant_types::ResourceType::Credential,
                actions: actions.into_iter().map(str::to_string).collect(),
                resource: if wildcard_resource {
                    core_grant_types::ResourceSelector::Glob {
                        pattern: "*".to_string(),
                    }
                } else {
                    core_grant_types::ResourceSelector::Exact {
                        value: "emberdotlink/emberlink-dev".to_string(),
                    }
                },
                budget: None,
                usage: core_grant_types::Usage::default(),
                conditions: Vec::new(),
                can_delegate: None,
            }
        }

        assert!(
            statement_has_github_operation_authority(&github_statement(vec!["github:*"], true)),
            "parent gateway grants carry the broad GitHub ceiling"
        );
        assert!(
            statement_has_github_operation_authority(&github_statement(
                vec!["github:pull_request:read"],
                true,
            )),
            "delegated runtime grants carry narrowed GitHub operation authority"
        );
        assert!(
            !statement_has_github_operation_authority(&github_statement(
                vec!["llm:generate"],
                true
            )),
            "non-GitHub model-auth statements are not GitHub operation authority"
        );
        assert!(
            statement_has_github_operation_authority(&github_statement(
                vec!["github:pull_request:read"],
                false,
            )),
            "exact-resource narrowed GitHub operation statements are still concrete authority"
        );
        assert!(
            !statement_has_github_operation_authority(&github_statement(vec!["github:*"], false,)),
            "broad GitHub authority still requires wildcard resource authority"
        );
    }

    // P22-S2 PR-C (ADR 197 §2): the UDS lane MUST drop the replayable bearer
    // and point the harness at the non-Anthropic checkpoint; the TCP lane keeps
    // the bearer for header-side resolution.
    #[test]
    fn uds_lane_bundle_drops_bearer_and_uses_sentinel() {
        let (base_url, headers) = anthropic_gateway_lane_bundle(
            "cred",
            "att_x",
            "ep_secret",
            "http://127.0.0.1:3142",
            true,
        );
        assert_eq!(base_url, crate::infra::session_proxy::SENTINEL_BASE_URL);
        assert!(headers.contains("X-Ember-Credential: cred"));
        assert!(headers.contains("X-Ember-Target: https://api.anthropic.com"));
        // The bearer and attachment-id selector are gone on the UDS lane.
        assert!(
            !headers.contains("X-Ember-Endpoint-Token"),
            "UDS lane must NOT carry the endpoint-token bearer; headers={headers:?}"
        );
        assert!(!headers.contains("ep_secret"));
        assert!(!headers.contains("X-Ember-Attachment-Id"));
    }

    #[test]
    fn tcp_lane_bundle_keeps_bearer_and_proxy_url() {
        let (base_url, headers) = anthropic_gateway_lane_bundle(
            "cred",
            "att_x",
            "ep_secret",
            "http://127.0.0.1:3142",
            false,
        );
        assert_eq!(base_url, "http://127.0.0.1:3142");
        assert!(headers.contains("X-Ember-Endpoint-Token: ep_secret"));
        assert!(headers.contains("X-Ember-Attachment-Id: att_x"));
    }

    use crate::infra::{
        config::DeploymentTier,
        handler::{
            PeerCred, RequestContext, current_dispatch_deployment_tier,
            set_dispatch_deployment_tier,
        },
    };
    use chrono::Utc;
    use core_state::sessions::{AttachmentEndpoint, SessionMeta, SessionStore};
    use serde_json::json;

    struct DeploymentTierGuard {
        previous: DeploymentTier,
    }

    impl DeploymentTierGuard {
        fn set(next: DeploymentTier) -> Self {
            let previous = current_dispatch_deployment_tier();
            set_dispatch_deployment_tier(next);
            Self { previous }
        }
    }

    impl Drop for DeploymentTierGuard {
        fn drop(&mut self) {
            set_dispatch_deployment_tier(self.previous);
        }
    }

    #[test]
    fn authority_posture_json_reports_jit_ambient_defaults() {
        assert_eq!(
            authority_posture_json(false, false),
            json!({"fallback": "jit", "delegation": "ambient"})
        );
    }

    #[test]
    fn authority_posture_json_reports_strict_delegated_when_enabled() {
        assert_eq!(
            authority_posture_json(true, true),
            json!({"fallback": "strict", "delegation": "delegated"})
        );
    }

    #[test]
    fn describe_runtime_attach_target_reports_read_only_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(dir.path().to_path_buf());
        let meta = SessionMeta {
            session_id: "sess-one".to_string(),
            persona: "runtime-one".to_string(),
            grant_id: "grant-runtime-one".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: true,
            delegation_id: None,
            delegation_template: None,
            durable_persona: Some("durable-one".to_string()),
            caller_binding_id: Some("binding-one".to_string()),
        };
        sessions.create(&meta).expect("create session");
        sessions
            .write_attachment_endpoint(
                &meta.session_id,
                &AttachmentEndpoint::active("att-one".to_string(), "ep-one".to_string()),
            )
            .expect("write endpoint");

        let mut ctx = RequestContext::internal("test");
        ctx.sessions_dir = Some(dir.path().to_path_buf());
        let summary = handle_describe_runtime_attach_target(
            &ctx,
            &json!({ "runtime_persona_id": "runtime-one" }),
        )
        .expect("summary");

        assert_eq!(summary["runtime_persona_id"], "runtime-one");
        assert_eq!(summary["durable_persona_id"], "durable-one");
        assert_eq!(summary["caller_binding_id"], "binding-one");
        assert_eq!(summary["attachment_count"], 1);
        assert_eq!(summary["delegation"]["state"], "ambient");
        assert_eq!(summary["authority_posture"]["fallback"], "strict");
    }

    #[test]
    fn team0_describe_runtime_attach_target_requires_matching_trusted_principal() {
        let _tier = DeploymentTierGuard::set(DeploymentTier::Team0);
        let dir = tempfile::tempdir().expect("tempdir");
        let sessions = SessionStore::new(dir.path().to_path_buf());
        let meta = SessionMeta {
            session_id: "sess-team0".to_string(),
            persona: "runtime-team0".to_string(),
            grant_id: "grant-runtime-team0".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: true,
            delegation_id: None,
            delegation_template: None,
            durable_persona: Some("durable-owner".to_string()),
            caller_binding_id: Some("binding-team0".to_string()),
        };
        sessions.create(&meta).expect("create session");

        let mut ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_008),
            }),
            "durable-other".to_string(),
        );
        ctx.sessions_dir = Some(dir.path().to_path_buf());
        let err = handle_describe_runtime_attach_target(
            &ctx,
            &json!({ "runtime_persona_id": "runtime-team0" }),
        )
        .expect_err("cross-principal describe must fail closed");

        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("trusted principal"),
            "mismatch should mention trusted principal: {}",
            err.1
        );
    }

    // --- save_delegation_template helpers (ADR 194 §5 output 3) ---

    #[test]
    fn string_array_param_parses_array_and_rejects_non_strings() {
        let params = json!({ "scopes": ["a", "b"], "bad": [1, 2], "scalar": "x" });
        assert_eq!(
            string_array_param(&params, "scopes").unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        // Missing key yields empty (excludes is optional).
        assert!(string_array_param(&params, "missing").unwrap().is_empty());
        // Non-string entries and non-array values are rejected.
        assert!(string_array_param(&params, "bad").is_err());
        assert!(string_array_param(&params, "scalar").is_err());
    }

    #[test]
    fn brokered_write_round_trips_to_the_loader() {
        // The whole point of brokering the write through the daemon is that the
        // artifact lands where the loader reads it. Render → write into an
        // overlay dir → load_template must resolve it.
        let toml_str = crate::infra::delegation_template::render_validated_template_toml(
            "release-proof",
            Some("Saved by ember catalog plan (bounded)"),
            "4h",
            &["registry.ember.systems/ember-systems/ember-gh/pr_create@v1".to_string()],
            &[],
        )
        .expect("render");

        let dir = tempfile::tempdir().expect("tempdir");
        let overlay = dir.path().join("overlay");
        let written =
            write_template_to_overlay(&overlay, "release-proof", &toml_str).expect("write");
        assert_eq!(written, overlay.join("release-proof.toml"));

        // bundled empty, overlay has our file — the loader (which checks overlay
        // first) must find the freshly-saved template with the saved ttl/scope.
        let bundled = dir.path().join("bundled");
        let loaded = crate::infra::delegation_template::load_template(
            "release-proof",
            &bundled,
            Some(&overlay),
        )
        .expect("load");
        assert_eq!(loaded.name, "release-proof");
        assert_eq!(loaded.ttl_secs, 4 * 3600);
        assert_eq!(loaded.scopes.len(), 1);
    }
}
