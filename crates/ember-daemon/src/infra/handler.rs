
use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use tokio::sync::broadcast;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
#[cfg(test)]
use core_personas::MtlsPrincipal;

use crate::infra::events::GrantEvent;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::receipt::{current_identity, issue::issue_atomic_receipt};
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;
use crate::trust::approval::DaemonApprovalStoreRef;
#[cfg(test)]
use crate::trust::approval::GrantShapeFields;
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::{self, GateOutcome, HighRiskOp};
use core_events::receipt::{
    RECEIPT_KIND_RECOVERY_ACTION, RecoveryActionBody, TerminationAuthority,
};

mod access_requests;
mod audit_receipts;
mod authority;
mod banner;
mod bindings;
mod context;
mod grant_lifecycle;
mod grant_use;
mod grants;
mod headless;
mod preflight;
mod presence_runtime;
mod recovery;
mod sandbox;
mod sops;
mod subprocess_audit;
#[cfg(test)]
mod test_support;

#[cfg(test)]
pub(crate) use authority::force_quarantine_latch_for_test;
pub use authority::{
    AuthorityClass, QuarantineAuthority, authority_class_for_method, clear_quarantine_after_repair,
    enter_quarantine, is_quarantined, quarantine_allowed_method, quarantine_authority,
    quarantine_reason,
};
use authority::{
    PRESENCE_SCOPE_CLASS_SESSION_RUNTIME, authority_error, operator_presence_token_optional_method,
    presence_scope_allows_method, presence_scope_for_unlock_target,
    session_runtime_scope_from_open_session,
};
#[cfg(test)]
use authority::{PRESENCE_SCOPE_CLASS_VAULT, enter_quarantine_into, is_read_class_method};
use banner::notify_require_approval;
pub use banner::{Banner, build_banner};
use context::broker_peercred_principal_for_handler;
pub(crate) use context::{
    DaemonIdentityPresenceSigner, current_dispatch_deployment_tier, mint_operator_presence_token,
};
#[cfg(test)]
pub(crate) use context::{
    DeploymentTierGuard, PRESENCE_CHOKEPOINT_TEST_ENFORCE, PresenceChokepointEnforceGuard,
    clear_pid_persona_registry, ensure_test_presence_identity,
};
pub use context::{
    DispatchSource, EnrolledPrincipal, HandlerError, PeerCred, RequestContext,
    enroll_container_persona, enroll_pid_persona, is_per_agent_socket_path, peercred_principal,
    set_dispatch_deployment_tier,
};
use presence_runtime::{
    TransientKekEvictionGuard, VerifiedPresenceProof, enforce_presence_chokepoint_with_audit,
    enforce_presence_proof, enforce_presence_proof_with_audit, handle_identity_device_enroll,
    handle_identity_device_enroll_backup, handle_identity_device_enroll_backup_plan,
    handle_identity_device_enroll_plan, handle_identity_device_revoke,
    handle_identity_recovery_enroll, handle_presence_request_nonce, parse_scope_kek_hex,
    presence_chokepoint_will_enforce, widening_transient_kek_applies,
};
#[cfg(test)]
use presence_runtime::{
    enforce_presence_chokepoint, parse_enroll_device_material, presence_chokepoint_applies,
};
pub use subprocess_audit::handle_subprocess_audit_log;
#[cfg(test)]
pub(crate) use test_support::*;

fn runtime_data_dir_from_context(
    ctx: &RequestContext,
) -> Result<std::path::PathBuf, (i32, String)> {
    headless::data_dir_from_context(ctx)
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
    // Per-method authority enforcement: the per-method
    // authority gate moved into `dispatch_method_with_context` (the
    // production choke point all socket-layer entry points converge
    // on). This test wrapper constructs a `DispatchSource::Internal`
    // context downstream, which is exempt from the gate by design —
    // Internal callers are the pre-existing in-process trust lane.
    dispatch_method_with_source(
        store,
        vault,
        policy,
        rate_limiter,
        None,
        DispatchSource::Internal {
            reason: "test harness",
        },
        method,
        params,
    )
    .await
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
/// dispatched here (`vault_add`, `vault_put`,
/// `vault_remove`, `create_grant`). Read-class operations bump the
/// session's `last_activity` via `presence::record_activity()` so they
/// don't spam the user with biometric prompts but also keep the session
/// "warm" — the lock fires on idle silence, not on dashboard polling.
pub(crate) fn check_user_presence_gate(
    op: HighRiskOp,
    override_quiet_hours: bool,
) -> Result<(), (i32, String)> {
    match presence::require_user_presence(op, override_quiet_hours) {
        GateOutcome::Allowed => Ok(()),
        GateOutcome::Locked { reason } => Err(RpcError::PresenceLocked(reason).into()),
    }
}

/// Allow-listed caller → vault namespace for the per-caller local-state
/// content key. Restricts `local_state_key_*` socket methods to the three
/// known ember binaries; a malicious caller cannot pollute the namespace
/// with arbitrary keys.
///
/// Per KEYCHAIN-CONSOLIDATE-CLI adversarial-review HIGH-1.
pub(crate) fn local_state_vault_name(caller: &str) -> Result<String, (i32, String)> {
    match caller {
        "cli" | "gui" | "native-host" => Ok(format!("local-state/{caller}")),
        other => Err(RpcError::InvalidParams(format!(
            "invalid 'caller' {other:?}: expected one of cli, gui, native-host"
        ))
        .into()),
    }
}

pub(crate) fn current_vault(
    store: &DaemonStore,
    op: &str,
) -> Result<std::rc::Rc<Vault>, (i32, String)> {
    crate::infra::interactive_unlock::current_live_vault(store)
        .map_err(|err| RpcError::PresenceLocked(err.with_context(op)).into())
}

pub(crate) fn enforce_fresh_presence_proof(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<(), (i32, String)> {
    enforce_presence_proof(store, method, params)
}

pub(crate) fn enforce_fresh_presence_proof_with_audit(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<VerifiedPresenceProof, (i32, String)> {
    enforce_presence_proof_with_audit(store, method, params)
}

/// Production socket dispatch consumes the widening proof before handlers run.
/// Handlers verify only for internal calls and test/mock lanes that bypass it.
pub(crate) fn handler_must_verify_fresh_presence_proof(source: &DispatchSource) -> bool {
    source.is_internal() || !presence_chokepoint_will_enforce()
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
    // Per-method authority enforcement: under `#[cfg(test)]`,
    // Synthesize a kernel-attested peer when the caller specified a
    // `Socket` source. Pre-existing test fixtures call this shim with
    // `peer: None` because they predate per-method authority gating;
    // the production socket layer always carries a peer credential
    // (`infra::socket::verify_peer_uid` rejects connections without
    // one). The synthetic peer here mirrors the pattern in
    // `enforce_local_state_gate` so the gate stays exercised end-to-end
    // without touching every legacy test.
    #[cfg(test)]
    let synthetic_peer: Option<PeerCred> = if matches!(source, DispatchSource::Socket) {
        ensure_test_authority_bridge_env();
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        })
    } else {
        None
    };
    #[cfg(not(test))]
    let synthetic_peer: Option<PeerCred> = None;

    // Per-method authority handler validation: under
    // `#[cfg(test)]`, also synthesize a valid presence_token bound to
    // the synthetic peer's uid so legacy tests that exercise
    // OperatorPresence-class methods through this shim continue to
    // pass the gate. Tests that want to assert the gate's negative
    // paths construct `RequestContext` directly and bypass this shim.
    #[cfg(test)]
    let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = {
        if matches!(source, DispatchSource::Socket) {
            use crate::auth::presence_token::{ScopeKey, mint};
            use std::time::Duration;
            ensure_test_presence_identity();
            let signer = DaemonIdentityPresenceSigner::current()
                .expect("test presence signer must be initialised");
            let uid = synthetic_peer.as_ref().map(|p| p.uid).unwrap_or(501);
            Some(mint(uid, ScopeKey::all(), Duration::from_secs(60), &signer))
        } else {
            None
        }
    };
    #[cfg(not(test))]
    let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = None;

    let ctx = RequestContext {
        source,
        peer: synthetic_peer,
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        presence_token: synthetic_presence_token,
        bypass_binary_pin_gate_for_test: false,
    };
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        ctx,
        method,
        params,
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
    _vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    mut ctx: RequestContext,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // `DispatchSource` is no longer `Copy` (the `Bridge` variant owns the
    // `MtlsPrincipal`), so take an owned clone for the many `is_internal()`
    // reads below while leaving `ctx.source` intact for the Bridge-lane
    // cross-check / denylist / audit that match on it directly.
    let source = ctx.source.clone();

    // Persona enrollment in container (design §"In-container
    // extension"): when the RPC arrived on a per-agent UDS socket
    // (`/run/emberd/agent-<uuid>.sock`), the calling principal is
    // resolved from the `agent_socket_enrollments` table rather than
    // from wire-claimed `caller_persona_id` / `caller_grant_id`. The
    // spawn-time enrollment IS the identity claim — the daemon
    // recorded `(socket_path, persona_id, grant_id,
    // brief_content_hash)` when it issued the per-agent socket, and
    // any RPC arriving on that socket is treated as coming from that
    // persona regardless of what the payload says.
    //
    // Defense: worker B with a forged grant_id (e.g. copy-paste of
    // the orchestrator's grant_id) cannot impersonate the
    // orchestrator just by sending the orchestrator's grant_id over
    // its own socket — the orchestrator's grant_id is bound to the
    // orchestrator's socket path, not B's.
    //
    // Shared-daemon socket entry points (the legacy `/var/run/
    // emberd.sock` shape) take the original peercred / PID-registry
    // path: `enrolled_principal` is `None` for them and the existing
    // handlers fall through to their established gates.
    let enrolled_principal: Option<EnrolledPrincipal> =
        match (source.is_internal(), ctx.peer_cred_principal.as_ref()) {
            (false, Some(p)) if is_per_agent_socket_path(&p.socket_path) => {
                match enroll_container_persona(store, &p.socket_path) {
                    Ok(enrolled) => Some(enrolled),
                    Err(e) => {
                        tracing::warn!(
                            socket_path = %p.socket_path.display(),
                            method = %method,
                            error = ?e,
                            "rejecting RPC on per-agent socket: principal not enrolled"
                        );
                        return Err(e.to_jsonrpc());
                    }
                }
            }
            _ => None,
        };

    // request_context_mtls_principal_overlay (design component 4) —
    // when the RPC arrived on the cross-uid bridge lane, the
    // bridge layer has already resolved the client cert's SPIFFE URI
    // SAN to a persona id, carried in `DispatchSource::Bridge` and read
    // via `ctx.mtls_principal()`. The
    // identity binding model is parallel to the per-agent UDS path:
    // the cert SAN IS the identity claim, NOT the wire-claimed
    // `caller_persona_id`. The container-id SAN is cross-checked against
    // the persona's `agent_personas.container_id` binding by the daemon
    // just below (the bridge listener itself has no store access), so a
    // container-bound persona presenting a mismatched container SAN is
    // refused before dispatch (design ESC-3).
    //
    // The two sources are mutually exclusive at the dispatch layer:
    // per-agent UDS sockets bind `peer_cred_principal.socket_path`
    // matching `/run/emberd/agent-*.sock`; the bridge listener uses a
    // TCP-or-TLS-UDS path with no per-agent socket shape. A future
    // attacker who could populate both fields concurrently would be
    // refused below — both populated is treated as a defense-in-depth
    // error and the request is rejected.
    if enrolled_principal.is_some() && ctx.mtls_principal().is_some() {
        tracing::warn!(
            method = %method,
            "rejecting RPC: both per-agent UDS enrollment AND mTLS \
             principal populated — exclusive sources, refusing"
        );
        return Err((
            -32004,
            "principal binding violation: enrolled + mtls both set".to_string(),
        ));
    }

    // F6 (design priv-sep SLICE 2a) — fail-closed when a Bridge cert claims a
    // persona that does not exist (or whose lookup errors). The container
    // cross-check BELOW short-circuits (PASSES) on `get_persona` returning
    // `NotFound`; without this arm, a cert minted for a non-existent persona
    // would skip the binding check and be stamped as the caller by the overlay.
    // This goes live the moment a production `DispatchSource::Bridge` is stamped
    // (SLICE 2a's `0700` accept loop). A persona that EXISTS with
    // `container_id = None` is host-mode and is intentionally NOT refused here
    // (the container SAN is then informational — the existing carve-out below).
    // The sibling's `extract_mtls_principal` hard-fails any cert lacking a
    // container SAN, so on the Bridge lane `container_id` is always non-empty;
    // the discriminator is persona existence, not the (always-present)
    // container_id. A `Sqlite` error fails closed (-32000) — never passed.
    if let Some(mtls) = ctx.mtls_principal() {
        match store.get_persona(&mtls.persona_id) {
            Ok(_) => {}
            Err(crate::infra::store::StoreError::NotFound) => {
                tracing::warn!(
                    method = %method,
                    mtls_persona = %mtls.persona_id,
                    "rejecting bridge RPC: cert persona SAN does not resolve to a known persona (design fail-closed)"
                );
                return Err((
                    -32004,
                    "principal binding violation: mTLS persona SAN does not resolve to a known persona"
                        .to_string(),
                ));
            }
            Err(e) => {
                tracing::warn!(
                    method = %method,
                    mtls_persona = %mtls.persona_id,
                    error = %e,
                    "rejecting bridge RPC: persona lookup failed (fail-closed)"
                );
                return Err(RpcError::Internal(format!("persona lookup failed: {e}")).into());
            }
        }
    }

    // design ESC-3 — enforce the persona↔container binding for
    // container-bound personas reaching the daemon over the mTLS bridge. The
    // cert's container SAN (`spiffe://emberd/container/<id>`) is the worker's
    // claimed container; `agent_personas.container_id` is the daemon's
    // authoritative binding, minted at spawn by `create_agent_persona`. A
    // container-bound persona whose cert container SAN does not match its
    // binding is refused here — the cross-check the `MtlsPrincipal` contract
    // promises but that was previously unwired on the non-session bridge lane
    // (the session-runtime path enforces container==session_id separately).
    // Personas with NO container binding (host-mode / daemon-sandbox runtime
    // personas) are unaffected — the cert SAN is then informational and other
    // gates apply. (The F6 arm above guarantees the persona EXISTS by here.)
    if let Some(mtls) = ctx.mtls_principal()
        && let Ok(persona_row) = store.get_persona(&mtls.persona_id)
        && let Some(bound_container) = persona_row.container_id.as_deref()
        && bound_container != mtls.container_id
    {
        tracing::warn!(
            method = %method,
            mtls_persona = %mtls.persona_id,
            mtls_container = %mtls.container_id,
            bound_container = %bound_container,
            "rejecting bridge RPC: mTLS container SAN does not match the persona's bound container (design ESC-3)"
        );
        return Err((
            -32004,
            "principal binding violation: mTLS container SAN does not match the persona's container binding"
                .to_string(),
        ));
    }

    // design audit-equivalence (SLICE 1, net-new) — every Bridge dispatch
    // writes one hash-chained audit row carrying the client cert fingerprint
    // + the resolved persona/container/method, so a later-revoked cert can be
    // retroactively correlated to the bridge-lane traffic it authenticated.
    // Recorded BEFORE the plaintext denylist below so even a *refused*
    // plaintext-bearing attempt leaves a forensic trail (a denylist hit on
    // the daemon side means a sibling forwarded a method it should have
    // gated — a high-signal event). Fail closed: if the chain cannot record
    // the call, the call does not proceed (matches `handle_subprocess_audit_log`).
    if let DispatchSource::Bridge(mtls) = &ctx.source {
        let mut details_map = serde_json::Map::new();
        details_map.insert("method".to_string(), Value::String(method.to_string()));
        details_map.insert(
            "persona_id".to_string(),
            Value::String(mtls.persona_id.clone()),
        );
        details_map.insert(
            "container_id".to_string(),
            Value::String(mtls.container_id.clone()),
        );
        details_map.insert(
            "cert_fingerprint".to_string(),
            Value::String(hex::encode(mtls.cert_fingerprint)),
        );
        let details = serde_json::to_string(&Value::Object(details_map))
            .map_err(|e| (-32000, format!("bridge audit: encode details: {e}")))?;
        crate::infra::audit::append_audit_event_with_chain(
            store,
            Some(&mtls.persona_id),
            "bridge.dispatch",
            None,
            "bridge_call",
            Some(&details),
        )
        .map_err(|e| (-32000, format!("bridge audit: chain append: {e}")))?;
    }

    // design priv-sep §1c (SLICE 1, net-new) — daemon-side refusal of the
    // nine credential-plaintext-bearing methods on the Bridge lane,
    // defense-in-depth over the untrusted sibling's own `gate_method`. The
    // sibling refuses these before forwarding, but a *compromised* sibling
    // must not be able to forward one: emberd refuses them here too, so no
    // credential-plaintext method can ever be served on a `Bridge` dispatch
    // regardless of what the sibling forwarded.
    if let DispatchSource::Bridge(_) = &ctx.source
        && ember_rpc::PLAINTEXT_BEARING_METHODS.contains(&method)
    {
        tracing::warn!(
            method = %method,
            "refusing plaintext-bearing method on the mTLS bridge lane (daemon-side denylist)"
        );
        return Err((
            ember_rpc::POLICY_DENIED_ERROR_CODE as i32,
            format!(
                "policy-denied: method {method:?} not available on the mTLS bridge lane (use the peercred UDS)"
            ),
        ));
    }

    // Overlay source — read from EITHER the per-agent UDS enrollment
    // (carries persona_id + grant_id) OR the mTLS principal (carries
    // persona_id only; caller's `caller_grant_id` param survives
    // through the overlay). Downstream handlers consult the overlaid
    // params uniformly.
    //
    // The mTLS principal does NOT carry a grant_id because spawn-time
    // grant attenuation happens via the existing `create_grant` flow,
    // not via cert claims. The caller is responsible for passing
    // `caller_grant_id` in the params; `check_principal_against_persona`
    // then binds (peercred-uid, claimed persona) on the UDS lane and
    // (cert-SAN persona, claimed persona) on the bridge lane.
    let overlay_source: Option<(String, Option<String>)> = enrolled_principal
        .as_ref()
        .map(|e| (e.persona_id.clone(), Some(e.grant_id.clone())))
        .or_else(|| ctx.mtls_principal().map(|m| (m.persona_id.clone(), None)));

    // When the RPC was dispatched from a per-agent socket and the
    // enrollment resolved, overlay the enrolled persona/grant onto
    // the params so downstream handlers consult the enrollment-derived
    // identity rather than whatever the wire payload claimed. The
    // overlay is a per-call clone — the original `params` reference
    // is untouched so concurrent callers in other branches see the
    // unaltered value.
    let overlaid_params: Option<Value> = overlay_source.as_ref().map(|(persona_id, grant_id)| {
        let mut p = params.clone();
        if let Value::Object(obj) = &mut p {
            // enrolled_principal_overlay_extends_persona_params:
            // the persona-param overlay closes the
            // cross-persona authz bypass where a persona-reading arm
            // (persona = other) read the wire param instead of the
            // kernel-attested (per-agent UDS) or cert-attested (mTLS)
            // identity. Insert ALL
            // common persona-claim aliases the dispatch arms read — both
            // legacy `caller_*` and modern `persona` / `persona_id` / `id` —
            // so no downstream arm can be tricked by a stale alias.
            for key in [
                "caller_persona",
                "caller_persona_id",
                "persona",
                "persona_id",
                "id",
            ] {
                obj.insert(key.to_string(), Value::String(persona_id.clone()));
            }
            if let Some(gid) = grant_id {
                obj.insert("caller_grant_id".to_string(), Value::String(gid.clone()));
            }
        }
        p
    });
    let params: &Value = match overlaid_params.as_ref() {
        Some(p) => p,
        None => params,
    };

    // enrolled_principal_overlay_propagates_to_ctx: also stamp the resolved persona_id onto
    // `ctx.principal` so `resolve_caller_principal` (handlers/support.rs) sees
    // the pre-resolved identity at step 1 and does NOT short-circuit on the
    // peercred PID-registry lookup at step 2. Without this, every per-agent
    // UDS RPC (and mTLS bridge RPC) that called into a handler-arm using
    // `resolve_caller_principal` would refuse with PrincipalNotEnrolled even
    // though enrollment had already resolved the identity — the overlay only
    // wrote to params, not to the principal field consulted by step 1.
    if let Some((persona_id, _)) = overlay_source.as_ref()
        && ctx.principal.is_none()
    {
        ctx.principal = Some(persona_id.clone());
    }

    // Audit-chain quarantine gate. When the daemon
    // has detected a tampered audit chain, refuse any non-read-class
    // socket method so the chain cannot be extended over the break and
    // state mutations cannot mask the tamper. Read-class methods (ping,
    // audit_verify, audit_query, …) still proceed so the operator can
    // diagnose. Internal callers (in-process test harness, recovery
    // CLIs) are NOT exempted — quarantine is a hard latch.
    //
    // audit_repair_chain_rpc_landed — `audit_repair_chain` is the
    // ONE write-class method allowed through this gate per design v2
    // §1 R1 D3. `quarantine_allowed_method` wraps
    // `is_read_class_method` with that single exception so the gate
    // logic remains "default-deny + named whitelist." The repair RPC
    // re-runs the operator-co-signature check internally; this gate
    // doesn't substitute for that authority check.
    if is_quarantined() && !quarantine_allowed_method(method) {
        // design v2 §1 + adversarial review HIGH-4: do NOT include the
        // free-text quarantine reason in the wire response. The reason
        // string is sourced from local SQLite (`expected_hash`,
        // `stored_hash`, `at_row_id`) and would leak chain-break
        // forensics to any peer-cred caller — the gate fires BEFORE the
        // OperatorPresence check at the authority gate below, so a
        // ConnectOnly caller would otherwise harvest the row id +
        // hashes. Keep the detail in the WARN log + the
        // `quarantine_reason()` accessor (which the future repair RPC
        // surfaces as an operator-presence-gated read-class method).
        tracing::warn!(
            method,
            authority = quarantine_authority()
                .map(|a| a.as_str())
                .unwrap_or("unrecorded"),
            reason = quarantine_reason().unwrap_or("reason unrecorded"),
            "daemon quarantined; refusing non-read-class dispatch"
        );
        return Err(RpcError::JsonRpcInternal(format!(
            "daemon quarantined; write-class method `{method}` refused"
        ))
        .into());
    }

    // Per-method authority gate. Cohort A's current local path uses the socket
    // listener's peer-cred gate for ConnectOnly and a daemon-signed
    // presence-token bound to that peer uid for OperatorPresence.
    // Internal callers (admin CLI, recovery flows, test harness) are
    // exempted — they ride the pre-existing in-process trust lane that
    // pre-dates peer-cred binding (see `DispatchSource::Internal`).
    //
    // The -32001 error body deliberately omits the method name to
    // avoid leaking the classification table to attackers probing
    // arms; the `tracing::warn!` carries the full context for
    // operator forensics.
    // authority_gate_unknown_method_returns_minus_32601 — unclassified
    // methods skip both gates so the dispatcher's `_ => Err(-32601)` arm
    // emits the standard JSON-RPC "Method not found" response. Classified
    // methods enforce the authority class against `ctx.satisfies(required)`.
    if !source.is_internal()
        && let Some(required) = authority_class_for_method(method)
        && !ctx.satisfies(required)
    {
        tracing::warn!(
            method = %method,
            required = ?required,
            peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
            "dispatch_method: authority class not met"
        );
        return Err(RpcError::AuthorityClassNotMet.into());
    }

    // design §1 — the fail-closed presence-authority chokepoint. For an
    // authority-widening method (per `presence_chokepoint_applies`), require +
    // verify a fresh, nonce-bound presence signature against an enrolled
    // presence-Device key the daemon does not hold (G1). This is **additive**: the
    // legacy OperatorPresence block below still runs (it also performs vault-MEK-
    // release / vault attachment). The chokepoint layers the unforgeable per-op
    // proof on top, closing the tap-once-opens-a-session forgery hole. Internal
    // callers retain the established carve-out (see fn doc / A2 note).
    //
    // `bypass_binary_pin_gate_for_test` doubles as the "synthetic in-memory test
    // socket" marker — it is set true ONLY by `RequestContext::socket_for_test`
    // (the constructor `SocketListener::with_test_mode_synthetic_presence_token`
    // uses) and is false in every production path. T3 socket integration tests run
    // against in-memory stores with no operator identity, so they cannot produce a
    // real proof; they are exempt here exactly as they are from the binary-pin
    // gate. The unit-level chokepoint coverage uses `PRESENCE_CHOKEPOINT_TEST_
    // ENFORCE` to opt back IN. Production builds (`cfg(not(test))`) always enforce.
    let verified_presence_proof = if !source.is_internal() && !ctx.bypass_binary_pin_gate_for_test {
        enforce_presence_chokepoint_with_audit(store, method, params)?
    } else {
        None
    };

    // design §1 (AC-2/AC-3) — transient-KEK widening install.
    //
    // The §1 proof for `method` has just been verified by the chokepoint above
    // (G1: a fresh, nonce-bound, presence-Device signature the daemon cannot
    // forge). If this is a minting widening op that seals under `KEK_s`
    // (`widening_transient_kek_applies`) AND the operator submitted a
    // `scope_kek` (their own `se_unwrap` output, batched with the §1 sig in this
    // SAME request), install `KEK_s` TRANSIENTLY so the handler can seal/decrypt
    // under it — with NO grace window and NO standing `mark_unlocked`. The
    // `TransientKekEvictionGuard` below evicts it the instant this dispatch
    // returns (success or failure), so the widening path holds no time-window
    // state (AC-2).
    //
    // Backward compatibility: absent `scope_kek`, NONE of this engages — the op
    // falls through to the unchanged §4 standing-window gate below, exactly as
    // before. Only the *presence* of `scope_kek` on a covered widening op
    // activates the transient path.
    //
    // If a standing §4 window is ALREADY open (the operator ran
    // `ember vault se-unlock` separately), we do NOT install or evict — the
    // window already authorizes the op, and tearing it down on eviction would
    // regress the existing flow. The transient path engages only when it is
    // genuinely supplying the KEK_s the op needs.
    let _transient_kek_guard;
    let mut transient_kek_authorized = false;
    if !source.is_internal()
        && !ctx.bypass_binary_pin_gate_for_test
        && presence_chokepoint_will_enforce()
        && widening_transient_kek_applies(method)
        && params.get("scope_kek").is_some()
    {
        let (already_unlocked, _) = presence::snapshot();
        if already_unlocked {
            // A standing window is already open; let the existing §4 gate
            // authorize on it. Do not install/evict a transient KEK_s.
            _transient_kek_guard = TransientKekEvictionGuard::inactive(store);
        } else {
            // Fail-closed parse of the operator-supplied scope KEK. A
            // missing/malformed KEK on a covered widening op is a hard error —
            // the op needs it to seal under `KEK_s`.
            let scope_kek = parse_scope_kek_hex(params, "scope_kek")?;
            crate::infra::interactive_unlock::install_presence_scope_kek_vault_leave_locked(
                store, *scope_kek,
            )
            .map_err(|e| {
                RpcError::PresenceLocked(format!(
                    "widening transient-KEK install for '{method}': {e}"
                ))
            })?;
            // Arm eviction for EVERY exit path of this dispatch.
            _transient_kek_guard = TransientKekEvictionGuard::active(store);
            transient_kek_authorized = true;
            tracing::info!(
                method = %method,
                "design §1: installed transient widening KEK_s (verified proof + op-supplied KEK_s); no standing window"
            );
        }
    } else {
        _transient_kek_guard = TransientKekEvictionGuard::inactive(store);
    }

    // Operator-presence validation.
    //
    // Methods on the OperatorPresence lane require:
    // 1. a daemon-signed presence-token bound to the peer uid, and
    // 2. a currently-unlocked interactive presence session.
    //
    // Token-optional OperatorPresence methods are only privilege-reduction
    // seams (`vault_lock`, `close_session`) that tear authority down. Proof
    // acquisition RPCs are ConnectOnly and validate request-specific proof in
    // their handlers; mutating callers such as `vault_unlock` and
    // `register_session` stay on this proof-required lane.
    if !source.is_internal()
        && matches!(
            authority_class_for_method(method),
            Some(AuthorityClass::OperatorPresence)
        )
        && !operator_presence_token_optional_method(method)
    {
        let authorized_scope = if let Some(token) = ctx.presence_token.as_ref() {
            let peer_uid = match ctx.peer.as_ref() {
                Some(p) => p.uid,
                None => {
                    tracing::warn!(
                        method = %method,
                        "dispatch_method: presence_token attached but no peer credential"
                    );
                    return Err(authority_error("missing"));
                }
            };

            let Some(identity) = crate::infra::receipt::current_identity() else {
                tracing::warn!(
                    method = %method,
                    "dispatch_method: daemon identity missing; cannot validate presence_token"
                );
                return Err(authority_error("identity-missing"));
            };
            let signer = DaemonIdentityPresenceSigner::new(identity);
            let cache = crate::auth::presence_token::PresenceTokenCache::new();

            if let Err(e) = crate::auth::presence_token::validate(&cache, token, peer_uid, &signer)
            {
                let reason = match e {
                    crate::auth::presence_token::AuthError::Expired => "expired",
                    crate::auth::presence_token::AuthError::UidMismatch => "uid-mismatch",
                    crate::auth::presence_token::AuthError::SignatureInvalid => "sig-invalid",
                    crate::auth::presence_token::AuthError::ScopeMismatch => "scope-mismatch",
                };
                tracing::warn!(
                    method = %method,
                    peer_uid = peer_uid,
                    reason = reason,
                    "dispatch_method: presence_token validation failed"
                );
                return Err(authority_error(reason));
            }

            token.scope.clone()
        } else if transient_kek_authorized {
            // design §1 (AC-2) — transient-KEK widening authorization.
            //
            // This op is a covered minting widening op whose §1 proof was
            // verified by the chokepoint above and whose `KEK_s` was just
            // installed transiently from the operator's own `se_unwrap` output.
            // It is authorized on `(verified proof + op-supplied KEK_s)`, NOT on
            // a standing §4 window — so we do NOT consult `presence::snapshot()`
            // (the transient path never calls `mark_unlocked`). The
            // `TransientKekEvictionGuard` evicts the KEK_s on return; no window
            // state outlives this op. The operator-supplied widen is unscoped
            // (operator-DIRECT), so the authority scope is `*`, identical to the
            // open-window operator-direct case below.
            crate::auth::presence_token::ScopeKey::new("*")
        } else if let Some(scope) = session_runtime_scope_from_open_session(method, params, &ctx) {
            scope
        } else {
            // design priv-sep (F7) — the Bridge lane (in-container agents) must
            // NEVER ride the operator's §4 presence window. `ctx.peer` on the
            // Bridge lane is the SIBLING's peercred (uid==`ember`), NOT an
            // operator; `satisfies(OperatorPresence)` is true here only because a
            // peer is present. A Bridge request that produced no session-runtime
            // scope from the open-session arm above is not a legitimate delegated
            // call, so it must fail closed here rather than fall through to the
            // operator-direct `*` scope (which `presence_scope_allows_method`
            // grants for ANY non-widening OperatorPresence method:
            // vault_get/revoke_grant/sandbox_delete/broker_revoke/…). Legitimate
            // bridge calls obtain `PRESENCE_SCOPE_CLASS_SESSION_RUNTIME` from the
            // open-session arm; the full positive in-container method allowlist is
            // a follow-on sub-slice — this closes the operator-authority escalation.
            if matches!(ctx.source, DispatchSource::Bridge(_)) {
                tracing::warn!(
                    method = %method,
                    "dispatch_method: Bridge lane denied the operator §4 window \
                     (in-container agents never obtain operator-direct authority)"
                );
                return Err(authority_error("missing"));
            }

            // design slice 4 C — fail-closed §4 fall-through.
            //
            // The forgeable native/managed/lazy auto-unlock-on-first-op path was
            // retired. An OperatorPresence method with NO presence token and NO
            // open-session-runtime scope is authorized ONLY when the §4
            // presence-as-decryption unlock window is OPEN (the operator ran
            // `ember vault se-unlock` — one Touch ID tap — which unwrapped the
            // scope KEK and marked the interactive presence session unlocked).
            //
            // Default-deny: a locked window MUST error here, never proceed. The
            // daemon cannot fabricate this state — the unlock window is opened
            // only by `vault.se_unlock_complete`, which installs the
            // operator-session-unwrapped KEK_s and calls `mark_unlocked()`.
            let (unlocked, _) = presence::snapshot();
            if !unlocked {
                tracing::warn!(
                    method = %method,
                    peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                    tier = current_dispatch_deployment_tier().as_str(),
                    "dispatch_method: OperatorPresence method denied — §4 unlock window locked"
                );
                return Err(authority_error("locked"));
            }
            // The session-runtime DELEGATED methods (`broker_resolve`,
            // `broker_exec`, `use_credential`, …) mint/route credentials on behalf
            // of an EXISTING agent session. They are authorized ONLY by a valid
            // open-session binding (`session_runtime_scope_from_open_session`,
            // checked above) or an explicit presence token — NOT by the operator's
            // bare §4 window. `register_session` is the session-creation edge: the
            // operator's §4 window may authorize creating the binding, and the
            // handler returns the scoped presence token that subsequent runtime
            // calls must carry.
            if method != "register_session"
                && presence_scope_allows_method(
                    &crate::auth::presence_token::ScopeKey::new(
                        PRESENCE_SCOPE_CLASS_SESSION_RUNTIME,
                    ),
                    method,
                )
            {
                tracing::warn!(
                    method = %method,
                    peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                    "dispatch_method: session-runtime delegated method denied — \
                     requires an open-session binding, not the operator §4 window"
                );
                return Err(authority_error("missing"));
            }
            // Otherwise the operator is present (the §4 window is open) and this is
            // an operator-DIRECT method: their authority is unscoped (they are the
            // operator themselves, not a delegated token).
            crate::auth::presence_token::ScopeKey::new("*")
        };

        if !presence_scope_allows_method(&authorized_scope, method) {
            tracing::warn!(
                method = %method,
                peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                scope = authorized_scope.as_str(),
                "dispatch_method: operator authority scope mismatch"
            );
            return Err(authority_error("scope-mismatch"));
        }
        // Re-assert the §4 unlock window is OPEN at execution time. The window
        // may have been evicted (idle / explicit lock / OS presence event)
        // between scope resolution and now; if so, deny. Default-deny: there is
        // no auto-reopen — the operator must run `ember vault se-unlock` again.
        //
        // EXCEPTION (design §1 AC-2): the transient-KEK widening path holds NO
        // standing window — its `KEK_s` is installed transiently and evicted on
        // return. It authorizes on `(verified proof + op-supplied KEK_s)`, so we
        // skip the standing-window re-assert here. The KEK_s is live (installed
        // above, not yet evicted) for the op that runs next.
        if !transient_kek_authorized {
            let (unlocked, _) = presence::snapshot();
            if !unlocked {
                tracing::warn!(
                    method = %method,
                    peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                    scope = authorized_scope.as_str(),
                    "dispatch_method: OperatorPresence method denied — §4 unlock window locked at exec"
                );
                return Err(authority_error("locked"));
            }

            presence::record_activity();
        }
    }

    match method {
        "ping" => Ok(json!({"pong": true})),

        "presence_token_mint" => Err((
            -32601,
            "presence_token_mint is not a shipped generic CLI authority surface".to_string(),
        )),

        // ADR191_PAYMENT_BUILD_AHEAD: payment reserve entry for the shipped
        // `ember grant evaluate` CLI command. This is the LIVE payment-lane
        // entry (resolve grant + parse PaymentAttempt + reserve/escalate +
        // emit payment.evaluated receipt). The retired PreToolUse
        // hook's stub-permit "false gate" path is GONE — this arm rejects any
        // call that does not carry a payment attempt, so it can only drive the
        // payment lane, never a generic tool-call permit.
        "evaluate_tool_call" => {
            let persona = params["persona"].as_str().ok_or_else(|| {
                RpcError::InvalidParams("missing 'persona' parameter".to_string())
            })?;
            let tool_name = params["tool_name"].as_str().ok_or_else(|| {
                RpcError::InvalidParams("missing 'tool_name' parameter".to_string())
            })?;
            let session_id = params["session_id"].as_str();
            let grant_id = params["grant_id"].as_str();
            let tool_params = &params["params"];
            let decision = store
                .reserve_payment_tool_call(persona, tool_name, tool_params, session_id, grant_id)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            serde_json::to_value(&decision)
                .map_err(|e| RpcError::Internal(format!("serialize ToolCallDecision: {e}")).into())
        }

        "create_persona" => {
            let name = params["name"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'name' parameter".to_string()))?;
            // Launcher onboarding creates an agent persona from an operator CLI
            // process; ordinary agent-created personas still bind the caller PID.
            let enroll_peer_pid = params["enroll_peer_pid"].as_bool().unwrap_or(true);
            let info = store
                .create_persona(name)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            // development milestone: enroll the (peer_pid, persona_id) so
            // subsequent `delegate_grant` calls from this PID resolve
            // back to the persona that just claimed it.  Only applies to
            // Socket callers; Internal callers don't have a real peer
            // identity and shouldn't pollute the registry.
            if !source.is_internal()
                && enroll_peer_pid
                && let Some(peer) = &ctx.peer
                && let Some(pid) = peer.pid
            {
                enroll_pid_persona(pid, &info.id);
            }
            Ok(json!({"id": info.id, "name": info.name, "public_key": info.public_key}))
        }

        "build_init_first_grant_receipt" => {
            let persona_id = params["persona_id"].as_str().ok_or_else(|| {
                RpcError::InvalidParams("missing 'persona_id' parameter".to_string())
            })?;
            let signer = store
                .persona_signer(persona_id)
                .map_err(|e| RpcError::Internal(format!("persona signer: {e}")))?;
            let file =
                crate::infra::init_first_grant::build_first_grant_receipt_file(persona_id, &signer)
                    .map_err(|e| {
                        RpcError::Internal(format!("build init first-grant receipt: {e}"))
                    })?;
            serde_json::to_value(file).map_err(|e| {
                RpcError::Internal(format!("serialize init first-grant receipt: {e}")).into()
            })
        }

        "persona_signer" => {
            // persona_signer_rpc_landed: daemon-held signer capability for
            // design init migration; returns signatures, never private keys.
            crate::broker::handler::handle_persona_signer(store, params)
        }

        "list_personas" => {
            let personas = store
                .list_personas()
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            let trusted_persona =
                crate::infra::handlers::principal::team0_connect_only_persona_scope(
                    &ctx,
                    "list_personas",
                )?;
            let name_prefix = params["name_prefix"].as_str();
            let list: Vec<Value> = personas
                .iter()
                .filter(|p| match trusted_persona.as_deref() {
                    Some(persona_id) => p.id == persona_id,
                    None => true,
                })
                .filter(|p| match name_prefix {
                    Some(prefix) => p.name.starts_with(prefix),
                    None => true,
                })
                .map(|p| json!({"id": p.id, "name": p.name, "status": p.status}))
                .collect();
            Ok(json!(list))
        }

        "revoke_persona" => {
            let id = params["id"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'id' parameter".to_string()))?;
            // revoke_persona_authority_check — Internal callers (admin CLI,
            // test harness, recovery) bypass; all socket callers must be
            // the revocation target (self-revoke). Operator-role extension
            // tracked separately.
            if !source.is_internal() {
                let principal =
                    crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
                if principal != id {
                    tracing::warn!(
                        caller_persona_id = %principal,
                        target_persona_id = %id,
                        "rejecting revoke_persona: caller is not the revocation target"
                    );
                    return Err(RpcError::PolicyDenied(
                        "revoke_persona: caller not authorized (must be operator or \
                         revocation target)"
                            .to_string(),
                    )
                    .into());
                }
                // Self-revoke: allowed.
            }
            store
                .revoke_persona(id)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            Ok(json!({"revoked": true}))
        }

        "retire_persona_for_reenroll" => {
            let id = params["id"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'id' parameter".to_string()))?;
            let expected_name = params["expected_name"].as_str().ok_or_else(|| {
                RpcError::InvalidParams("missing 'expected_name' parameter".to_string())
            })?;
            // Same authority posture as revoke_persona: this is a targeted
            // self-retire used by recovery/onboarding to free a default slot.
            if !source.is_internal() {
                let principal =
                    crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
                if principal != id {
                    tracing::warn!(
                        caller_persona_id = %principal,
                        target_persona_id = %id,
                        "rejecting retire_persona_for_reenroll: caller is not the target"
                    );
                    return Err(RpcError::PolicyDenied(
                        "retire_persona_for_reenroll: caller not authorized (must be \
                         revocation target)"
                            .to_string(),
                    )
                    .into());
                }
            }
            let retired_name = store
                .retire_persona_for_reenroll(id, expected_name)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            Ok(json!({
                "revoked": true,
                "id": id,
                "old_name": expected_name,
                "retired_name": retired_name
            }))
        }

        "create_grant" => {
            grant_lifecycle::handle_create(
                store,
                policy,
                &source,
                params,
                verified_presence_proof.as_ref(),
            )
            .await
        }

        "create_composite_grant" => grant_lifecycle::handle_create_composite(
            store,
            &source,
            params,
            verified_presence_proof.as_ref(),
        ),

        "delegate_grant" => grant_lifecycle::handle_delegate(store, &ctx, &source, params).await,

        "list_grants" => grants::handle_list_grants(store, &ctx, params),

        "list_operator_grants" => grants::handle_list_operator_grants(store, params),

        "list_all_grants" => {
            // grant_list_all_rpc_landed: daemon RPC projection for the
            // operator CLI migration; presence-gated because it exposes
            // cross-persona grant rows.
            crate::broker::handler::handle_list_all_grants(store, params)
        }

        // Sandbox launch/runtime RPCs live in handler::sandbox.
        "sandbox_create" => sandbox::handle_create(store, &ctx, params),

        "sandbox_list" => sandbox::handle_list(store),

        "sandbox_stop" => sandbox::handle_stop(store, &ctx, params),

        "sandbox_delete" => sandbox::handle_delete(store, &ctx, params),

        "sandbox_exec" => sandbox::handle_exec(store, &ctx, params).await,

        "sandbox_run" => sandbox::handle_run(store, policy, &ctx, params),

        "revoke_grant" => grant_lifecycle::handle_revoke(store, &ctx, events_tx, params),

        "revoke_statement" => grant_lifecycle::handle_revoke_statement(store, params),

        "evaluate_grant" => grant_lifecycle::handle_evaluate(store, &ctx, params),

        "use_credential" => grant_use::handle_use_credential(store, params),

        "vault_add" => crate::infra::handlers::vault::handle_add(store, &source, params),

        "vault_put" => crate::infra::handlers::vault::handle_put(store, &source, params),

        "vault_export_sealed" => crate::infra::handlers::vault::handle_export_sealed(store, params),

        "vault_import_sealed" => crate::infra::handlers::vault::handle_import_sealed(store, params),

        "vault_remove" => crate::infra::handlers::vault::handle_remove(store, &source, params),

        "vault_lock" => crate::infra::handlers::vault::handle_lock(),

        "vault_unlock" => crate::infra::handlers::vault::handle_unlock(store, &ctx, params),

        // design §4 presence-as-decryption — provisioning + unlock handoff.
        // The operator-session CLI performs all SE crypto (se_wrap/se_unwrap are
        // keychain-label ops the separate-uid daemon cannot do); the daemon stores
        // the opaque wrapped KEK blobs and installs the unwrapped scope KEK into
        // the live vault slot for the unlock window. The daemon NEVER holds the
        // unwrapped KEK_s at rest.
        "vault.se_provision" | "vault/se_provision" | "vault_se_provision" => {
            let device_id = params
                .get("device_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams("vault.se_provision: 'device_id' required".to_string())
                })?;
            let ecies_key_id = params
                .get("ecies_key_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.se_provision: 'ecies_key_id' required".to_string(),
                    )
                })?;
            let wrapped_kek = params
                .get("wrapped_kek")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.se_provision: 'wrapped_kek' (hex) required".to_string(),
                    )
                })
                .and_then(|h| {
                    hex::decode(h).map_err(|e| {
                        RpcError::InvalidParams(format!(
                            "vault.se_provision: 'wrapped_kek' bad hex: {e}"
                        ))
                    })
                })?;
            let scope_kek = parse_scope_kek_hex(params, "scope_kek")?;

            // design §4 — resolve BOTH the AC-7 recipient allowlist (§6 finding
            // M3) and the per-scope binding ("Never one global KEK") from a single
            // identity-substrate open, fail-closed BEFORE any mutation below.
            //  • AC-7: a scope-KEK wrap may be stored ONLY for an enrolled
            //    presence-Device ECIES recipient under the operator root (plus the
            //    off-host cold-recovery recipient once that exists), never a
            //    daemon-supplied arbitrary key — else a compromised daemon could
            //    persist a wrap to a recipient IT controls and unwrap KEK_s
            //    autonomously later (standing autonomous decrypt), violating the §4
            //    "no autonomous-key recipient" invariant (the set is device-rooted,
            //    never the MEK).
            //  • Per-scope: the wrap is stored under the operator-authority SCOPE so
            //    one tap opens exactly one scope, not the whole AuthorityBearing lane
            //    (F4). Crown-jewel resources earn their own scope in a later slice.
            // The set + scope live in the identity substrate (`identity-events.db`),
            // not the main store — reopen on demand (the audit_repair_chain idiom).
            // No data_dir / no operator root / no enrolled presence Device => refuse
            // (AC-4: never admit a recipient, never store with no scope).
            let (allowed_recipients, provision_scope) = match store.data_dir() {
                Some(data_dir) => {
                    match crate::infra::identity_substrate::open_identity_store(data_dir) {
                        Ok(identity_store) => {
                            let st = identity_store.materialized();
                            (
                                // AC-7 allowlist = enrolled ∪ recovery (presence
                                // Devices AND off-host Recovery recipients), per
                                // design §4/§6. The union admits a recovery
                                // recipient's wrap; a non-enrolled key is refused.
                                crate::infra::operator_identity::active_kek_recipient_ecies_key_ids_under_operator_root(st),
                                crate::infra::operator_identity::operator_authority_scope(st),
                            )
                        }
                        Err(e) => {
                            return Err(RpcError::Internal(format!(
                                "vault.se_provision: open identity store: {e}"
                            ))
                            .into());
                        }
                    }
                }
                None => (Vec::new(), None),
            };
            if !allowed_recipients.iter().any(|k| k == ecies_key_id) {
                return Err(RpcError::PresenceLocked(format!(
                    "vault.se_provision: ecies_key_id '{ecies_key_id}' is not an \
                         enrolled presence-Device or recovery recipient under the \
                         operator root (design §4/§6 AC-7 allowlist = enrolled ∪ \
                         recovery); refusing to store a scope-KEK wrap to a \
                         non-enrolled recipient"
                ))
                .into());
            }
            let (scope_kind, scope_id) = provision_scope.ok_or_else(|| {
                RpcError::PresenceLocked(
                    "vault.se_provision: no operator-authority scope (no unambiguous \
                 operator root); refusing to store a scope-KEK wrap with no scope \
                 (design §4: never one global KEK)"
                        .to_string(),
                )
            })?;

            store
                .write_presence_scope_kek_wrap(
                    &scope_kind,
                    &scope_id,
                    device_id,
                    ecies_key_id,
                    &wrapped_kek,
                )
                .map_err(|e| RpcError::Internal(format!("vault.se_provision: store wrap: {e}")))?;

            // design §4 CLEAN-BREAK (DESTRUCTIVE, deliberate): re-sourcing the
            // interactive vault key from the presence-unwrapped KEK_s makes any
            // headless blob wrapped under the PRIOR (Argon2id/keychain) MEK
            // un-unwrappable, and a canary sealed under that prior MEK would
            // false-alarm. NULL both in `vault_meta` and remove the on-disk
            // bootstrap sidecar BEFORE installing KEK_s, so the install's vault
            // open hits first-run headless generation under KEK_s. We do NOT
            // silently regenerate-on-mismatch anywhere else — a passphrase-lane
            // wrong-key must stay a loud error; this operator-initiated provision
            // is the one sanctioned break (operator pre-users; headless unused).
            store.clear_headless_and_canary_meta().map_err(|e| {
                RpcError::Internal(format!("vault.se_provision: clean-break meta: {e}"))
            })?;
            // bridge-CA is DaemonOperational (design §4): re-classified from the
            // old interactive MEK to the autonomous headless key (which §4
            // provisioning also regenerates). Its prior wrap is sealed under the
            // retired key, so NULL the wrap and remove the on-disk wrap + sealed-CA
            // files; the next load_or_mint re-mints the bridge CA under the new
            // headless custody (one-time CA re-issue, operator-accepted pre-users
            // clean break). NOTE: the DB NULL and file removals are not atomic with
            // each other or the KEK install; a crash mid-clean-break can leave a
            // half-removed bridge-CA state that load_or_mint rejects (unopenable
            // stale wrap). Recovery for this one-time operator-initiated break is to
            // delete `bridge_ca.*` and re-run `ember vault se-provision`.
            store.clear_bridge_ca_wrap().map_err(|e| {
                RpcError::Internal(format!("vault.se_provision: clean-break bridge-ca: {e}"))
            })?;
            if let Some(dir) = store.data_dir() {
                for stale in [
                    crate::infra::vault::HEADLESS_MEK_WRAP_FILE,
                    "bridge_ca.wrap",
                    "bridge_ca.sealed",
                ] {
                    let path = dir.join(stale);
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(RpcError::Internal(format!(
                                "vault.se_provision: clean-break remove {}: {e}",
                                path.display()
                            ))
                            .into());
                        }
                    }
                }
            }

            // Install KEK_s for the current window so persona creation can seal
            // immediately after provisioning (the operator is present — they just
            // generated + se_wrapped the KEK). The returned vault's interactive
            // key is the live authority key (KEK_s on the §4 lane).
            let vault = crate::infra::interactive_unlock::install_presence_scope_kek_vault(
                store, *scope_kek,
            )
            .map_err(|e| RpcError::PresenceLocked(format!("vault.se_provision: install: {e}")))?;

            // Re-seal the key-correctness canary under the now-live interactive
            // key (KEK_s) so the fail-loud `verify_canary` check returns on the
            // §4 lane too (it was NULLed by the clean break above). `seal_canary`
            // seals under `self.interactive_key`, so this is self-consistent with
            // whatever key the live authority vault is serving.
            let (canary_nonce, canary) = vault.seal_canary().map_err(|e| {
                RpcError::PresenceLocked(format!("vault.se_provision: re-seal canary: {e}"))
            })?;
            store
                .write_vault_canary(&canary, &canary_nonce)
                .map_err(|e| {
                    RpcError::Internal(format!("vault.se_provision: write canary: {e}"))
                })?;

            crate::infra::interactive_unlock::arm_non_session_grace_window();
            Ok(serde_json::json!({ "status": "provisioned", "device_id": device_id }))
        }
        "vault.se_add_recipient_wrap"
        | "vault/se_add_recipient_wrap"
        | "vault_se_add_recipient_wrap" => {
            // design §4/§6 — store ONE ADDITIONAL recipient's wrap of the SAME
            // scope `KEK_s` (multi-recipient: enrolled presence Device set ∪ the
            // off-host recovery recipient). Unlike `vault.se_provision`, this does
            // NOT clean-break or (re)install the live key — it only persists the
            // wrap, AC-7-gated. The wrap is produced in the operator session (the
            // trusted, present, peer-cred-gated zone): an SE `se_wrap` for a backup
            // presence Device, or a software `age` wrap to the recovery recipient's
            // public half. The daemon admits it ONLY if `ecies_key_id` is in the
            // event-sourced `enrolled ∪ recovery` allowlist — so a compromised
            // daemon cannot persist a wrap to a recipient it controls (§6 M3).
            // NOTE (availability-only, threat-model-accepted at dev0): we gate on
            // `ecies_key_id ∈ allowlist` but do NOT verify the opaque blob was
            // actually wrapped to that recipient's pubkey. A wrong/garbage blob
            // only makes recovery FAIL CLOSED (KEK_s cannot leak — unwrap needs the
            // off-host secret the daemon never holds, AC-4/C3). The wrap is produced
            // in the peer-cred-gated operator session (trusted zone); a fully
            // compromised daemon owns the store directly anyway.
            let device_id = params
                .get("device_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.se_add_recipient_wrap: 'device_id' required".to_string(),
                    )
                })?;
            let ecies_key_id = params
                .get("ecies_key_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.se_add_recipient_wrap: 'ecies_key_id' required".to_string(),
                    )
                })?;
            let wrapped_kek = params
                .get("wrapped_kek")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.se_add_recipient_wrap: 'wrapped_kek' (hex) required".to_string(),
                    )
                })
                .and_then(|h| {
                    hex::decode(h).map_err(|e| {
                        RpcError::InvalidParams(format!(
                            "vault.se_add_recipient_wrap: 'wrapped_kek' bad hex: {e}"
                        ))
                    })
                })?;

            let (allowed_recipients, add_scope) = match store.data_dir() {
                Some(data_dir) => {
                    match crate::infra::identity_substrate::open_identity_store(data_dir) {
                        Ok(identity_store) => {
                            let st = identity_store.materialized();
                            (
                                crate::infra::operator_identity::active_kek_recipient_ecies_key_ids_under_operator_root(st),
                                crate::infra::operator_identity::operator_authority_scope(st),
                            )
                        }
                        Err(e) => {
                            return Err(RpcError::Internal(format!(
                                "vault.se_add_recipient_wrap: open identity store: {e}"
                            ))
                            .into());
                        }
                    }
                }
                None => (Vec::new(), None),
            };
            if !allowed_recipients.iter().any(|k| k == ecies_key_id) {
                return Err(RpcError::PresenceLocked(format!(
                    "vault.se_add_recipient_wrap: ecies_key_id '{ecies_key_id}' is not an \
                         enrolled presence-Device or recovery recipient under the operator root \
                         (design §4/§6 AC-7 allowlist = enrolled ∪ recovery); refusing to store \
                         a scope-KEK wrap to a non-enrolled recipient"
                ))
                .into());
            }
            let (scope_kind, scope_id) = add_scope.ok_or_else(|| {
                RpcError::PresenceLocked(
                    "vault.se_add_recipient_wrap: no operator-authority scope (no unambiguous \
                 operator root); refusing to store a scope-KEK wrap with no scope"
                        .to_string(),
                )
            })?;
            store
                .write_presence_scope_kek_wrap(
                    &scope_kind,
                    &scope_id,
                    device_id,
                    ecies_key_id,
                    &wrapped_kek,
                )
                .map_err(|e| {
                    RpcError::Internal(format!("vault.se_add_recipient_wrap: store wrap: {e}"))
                })?;
            Ok(serde_json::json!({ "status": "recipient_added", "device_id": device_id }))
        }
        "vault.se_unlock_begin" | "vault/se_unlock_begin" | "vault_se_unlock_begin" => {
            // Pure read: return the opaque per-Device wrapped scope-KEK blobs for
            // the operator-authority SCOPE (design §4: a tap opens exactly one
            // scope, never the whole lane). The CLI picks the one for ITS Device
            // (whose SE key is in its keychain) and performs the `se_unwrap` tap.
            // The blobs reveal nothing without the presence-gated SE private key.
            // Scope is daemon-derived from the operator root (identity substrate,
            // reopened on demand); no operator scope => no wraps (empty), mirroring
            // the pre-§4 "nothing provisioned" contract the CLI already handles.
            let unlock_scope = match store.data_dir() {
                Some(data_dir) => {
                    match crate::infra::identity_substrate::open_identity_store(data_dir) {
                        Ok(identity_store) => {
                            crate::infra::operator_identity::operator_authority_scope(
                                identity_store.materialized(),
                            )
                        }
                        Err(e) => {
                            return Err(RpcError::Internal(format!(
                                "vault.se_unlock_begin: open identity store: {e}"
                            ))
                            .into());
                        }
                    }
                }
                None => None,
            };
            let wraps = match unlock_scope {
                Some((scope_kind, scope_id)) => store
                    .list_presence_scope_kek_wraps(&scope_kind, &scope_id)
                    .map_err(|e| {
                        RpcError::Internal(format!("vault.se_unlock_begin: list wraps: {e}"))
                    })?,
                None => Vec::new(),
            };
            let wraps_json: Vec<serde_json::Value> = wraps
                .into_iter()
                .map(|(device_id, ecies_key_id, wrapped)| {
                    serde_json::json!({
                        "device_id": device_id,
                        "ecies_key_id": ecies_key_id,
                        "wrapped_kek": hex::encode(&wrapped),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "wraps": wraps_json }))
        }
        "vault.se_unlock_complete" | "vault/se_unlock_complete" | "vault_se_unlock_complete" => {
            // The CLI submits the scope KEK it just `se_unwrap`ped (the tap). Install
            // it as the live interactive vault key for the unlock window. A wrong
            // KEK installs but fails every authority open closed (AEAD).
            let scope_kek = parse_scope_kek_hex(params, "scope_kek")?;
            crate::infra::interactive_unlock::install_presence_scope_kek_vault(store, *scope_kek)
                .map_err(|e| {
                RpcError::PresenceLocked(format!("vault.se_unlock_complete: install: {e}"))
            })?;
            crate::infra::interactive_unlock::arm_non_session_grace_window();
            // design slice 4 C — the §4 tap IS the operator-presence event. Mark
            // the interactive presence session UNLOCKED so the OperatorPresence
            // dispatch gate's fail-closed §4 fall-through (`presence::snapshot()`)
            // recognizes the open window. Eviction (idle / explicit lock / OS
            // presence event) re-locks it via the existing window machinery.
            crate::trust::presence::mark_unlocked();
            Ok(serde_json::json!({ "status": "unlocked" }))
        }

        // ── design — double-envelope SE custody RPCs ─────────────────────
        //
        // The double-envelope model: at rest, SE-custodied keys are
        //   SE_ECIES_encrypt( DWK_encrypt(raw_key) )
        // The CLI peels the outer SE layer (Aqua/501, Touch ID); the daemon
        // peels the inner DWK layer (uid=450). Raw key material exists only
        // in daemon memory. The CLI never holds it.
        "vault.de_provision_begin" | "vault/de_provision_begin" | "vault_de_provision_begin" => {
            use crate::infra::daemon_wrap_key::DwkPurpose;
            let purpose_str = params
                .get("purpose")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.de_provision_begin: 'purpose' required".to_string(),
                    )
                })?;
            let purpose = match purpose_str {
                "vault_mek" => DwkPurpose::VaultMek,
                "lease_kek" => DwkPurpose::LeaseKek,
                other => {
                    return Err(RpcError::InvalidParams(format!(
                        "vault.de_provision_begin: unknown purpose '{other}'"
                    ))
                    .into());
                }
            };

            let dwk = store.dwk().ok_or_else(|| {
                RpcError::Internal("vault.de_provision_begin: DWK not provisioned".to_string())
            })?;

            let mut raw_key = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::fill(raw_key.as_mut()).expect("OS entropy failure");

            let inner_blob = dwk.wrap(&*raw_key, purpose).map_err(|e| {
                RpcError::Internal(format!("vault.de_provision_begin: DWK wrap: {e}"))
            })?;

            match purpose {
                DwkPurpose::VaultMek => {
                    let vault = crate::infra::vault::finish_open_with_interactive_key_for_de(
                        *raw_key,
                        store
                            .data_dir()
                            .unwrap_or_else(|| std::path::Path::new(".")),
                    );
                    match vault {
                        Ok(vault) => {
                            store.set_vault(std::rc::Rc::new(vault));
                            tracing::info!("vault.de_provision_begin: MEK provisioned, vault open");
                        }
                        Err(e) => {
                            return Err(RpcError::Internal(format!(
                                "vault.de_provision_begin: vault open: {e}"
                            ))
                            .into());
                        }
                    }
                }
                DwkPurpose::LeaseKek => {
                    let lease_kek = crate::trust::lease::LeaseWrapKey::from_raw(*raw_key);
                    store.set_lease_kek(lease_kek);
                    // design §3 — blobs persisted by a prior session become
                    // live now, not at the next restart's de_unlock_complete.
                    // Blobs wrapped under a different (lost) KEK fail their
                    // AEAD open and are skipped per-blob inside rehydrate.
                    if let Err(e) = store.rehydrate_persisted_leases(chrono::Utc::now()) {
                        tracing::error!(
                            error = %e,
                            "vault.de_provision_begin: lease-KEK installed but \
                             rehydrating persisted leases failed"
                        );
                    }
                    tracing::info!("vault.de_provision_begin: lease-KEK installed (first boot)");
                }
            }

            Ok(serde_json::json!({
                "inner_blob": hex::encode(&inner_blob),
                "purpose": purpose_str,
            }))
        }

        "vault.de_provision_outer" | "vault/de_provision_outer" | "vault_de_provision_outer" => {
            let outer_blob = params
                .get("outer_blob")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.de_provision_outer: 'outer_blob' (hex) required".to_string(),
                    )
                })
                .and_then(|h| {
                    hex::decode(h).map_err(|e| {
                        RpcError::InvalidParams(format!("vault.de_provision_outer: bad hex: {e}"))
                    })
                })?;
            let purpose_str = params
                .get("purpose")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.de_provision_outer: 'purpose' required".to_string(),
                    )
                })?;

            match purpose_str {
                "vault_mek" => {
                    if store.vault().is_some()
                        && store.read_double_envelope_outer().ok().flatten().is_some()
                    {
                        return Err(RpcError::Internal(
                            "vault.de_provision_outer: refusing to overwrite \
                             existing outer blob while vault is open"
                                .to_string(),
                        )
                        .into());
                    }
                    store
                        .write_double_envelope_outer(&outer_blob)
                        .map_err(|e| {
                            RpcError::Internal(format!("vault.de_provision_outer: store: {e}"))
                        })?;
                }
                "lease_kek" => {
                    // Symmetric with the `vault_mek` arm above: refuse only when
                    // BOTH the in-memory key AND the on-disk outer blob are
                    // already present (i.e. a fully-provisioned, fully-loaded
                    // state). The prior strict `lease_kek().is_some()` check
                    // was correct against the pre-#5836 shape, but #5836
                    // changed `vault.de_provision_begin` to install the
                    // lease-KEK in memory BEFORE the outer round-trip — so the
                    // strict guard refused the very first-boot persistence the
                    // CLI relay is built to drive. Mirroring the conjunctive
                    // vault_mek shape lets the first-boot outer write land
                    // while still protecting an already-persisted blob.
                    let outer_present = store
                        .read_lease_kek_double_envelope_outer()
                        .ok()
                        .flatten()
                        .is_some();
                    if store.lease_kek().is_some() && outer_present {
                        return Err(RpcError::Internal(
                            "vault.de_provision_outer: refusing to overwrite \
                             existing lease-KEK outer blob while lease-KEK is active"
                                .to_string(),
                        )
                        .into());
                    }
                    store
                        .write_lease_kek_double_envelope_outer(&outer_blob)
                        .map_err(|e| {
                            RpcError::Internal(format!("vault.de_provision_outer: store: {e}"))
                        })?;
                }
                other => {
                    return Err(RpcError::InvalidParams(format!(
                        "vault.de_provision_outer: unknown purpose '{other}'"
                    ))
                    .into());
                }
            }

            tracing::info!(
                purpose = purpose_str,
                "vault.de_provision_outer: outer blob stored"
            );
            Ok(serde_json::json!({
                "status": "provisioned",
                "purpose": purpose_str,
            }))
        }

        "vault.de_unlock_begin" | "vault/de_unlock_begin" | "vault_de_unlock_begin" => {
            let purpose_str = params
                .get("purpose")
                .and_then(|v| v.as_str())
                .unwrap_or("vault_mek");

            let outer_blob = match purpose_str {
                "vault_mek" => store
                    .read_double_envelope_outer()
                    .map_err(|e| RpcError::Internal(format!("vault.de_unlock_begin: read: {e}")))?,
                "lease_kek" => store.read_lease_kek_double_envelope_outer().map_err(|e| {
                    RpcError::Internal(format!("vault.de_unlock_begin: read lease_kek: {e}"))
                })?,
                other => {
                    return Err(RpcError::InvalidParams(format!(
                        "vault.de_unlock_begin: unknown purpose '{other}'"
                    ))
                    .into());
                }
            };

            match outer_blob {
                Some(blob) => Ok(serde_json::json!({
                    "outer_blob": hex::encode(&blob),
                    "status": "locked",
                    "purpose": purpose_str,
                })),
                None => Ok(serde_json::json!({
                    "status": "unprovisioned",
                    "purpose": purpose_str,
                })),
            }
        }

        "vault.de_unlock_complete" | "vault/de_unlock_complete" | "vault_de_unlock_complete" => {
            use crate::infra::daemon_wrap_key::DwkPurpose;
            let inner_blob = params
                .get("inner_blob")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RpcError::InvalidParams(
                        "vault.de_unlock_complete: 'inner_blob' (hex) required".to_string(),
                    )
                })
                .and_then(|h| {
                    hex::decode(h).map_err(|e| {
                        RpcError::InvalidParams(format!("vault.de_unlock_complete: bad hex: {e}"))
                    })
                })?;

            let purpose_str = params
                .get("purpose")
                .and_then(|v| v.as_str())
                .unwrap_or("vault_mek");

            let dwk_purpose = match purpose_str {
                "vault_mek" => DwkPurpose::VaultMek,
                "lease_kek" => DwkPurpose::LeaseKek,
                other => {
                    return Err(RpcError::InvalidParams(format!(
                        "vault.de_unlock_complete: unknown purpose '{other}'"
                    ))
                    .into());
                }
            };

            let dwk = store.dwk().ok_or_else(|| {
                RpcError::Internal("vault.de_unlock_complete: DWK not provisioned".to_string())
            })?;

            let raw_key = dwk.unwrap(&inner_blob, dwk_purpose).map_err(|e| {
                RpcError::PresenceLocked(format!("vault.de_unlock_complete: DWK unwrap: {e}"))
            })?;
            if raw_key.len() != 32 {
                return Err(RpcError::PresenceLocked(format!(
                    "vault.de_unlock_complete: unwrapped key is {} bytes, expected 32",
                    raw_key.len()
                ))
                .into());
            }
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&raw_key);

            match dwk_purpose {
                DwkPurpose::VaultMek => {
                    let data_dir = store
                        .data_dir()
                        .unwrap_or_else(|| std::path::Path::new("."));
                    let vault = crate::infra::vault::finish_open_with_interactive_key_for_de(
                        *key, data_dir,
                    )
                    .map_err(|e| {
                        RpcError::PresenceLocked(format!(
                            "vault.de_unlock_complete: vault open: {e}"
                        ))
                    })?;

                    let vault = std::rc::Rc::new(vault);
                    vault.verify_canary(store).map_err(|e| {
                        RpcError::PresenceLocked(format!(
                            "vault.de_unlock_complete: canary verification failed \
                                 (wrong MEK / corrupt double-envelope): {e}"
                        ))
                    })?;
                    store.set_vault(vault);
                    crate::trust::presence::mark_unlocked();
                    tracing::info!("vault.de_unlock_complete: vault unlocked via double-envelope");

                    // Bridge CA loading: if lease-KEK is also available, load bridge CA.
                    // Both envelopes must be peeled before sandbox spawn can proceed.
                    if store.bridge_ca().is_none()
                        && store.lease_kek().is_some()
                        && let Some(vault_ref) = store.vault()
                    {
                        let data_dir = store
                            .data_dir()
                            .unwrap_or_else(|| std::path::Path::new("."));
                        match crate::infra::runtime::load_or_mint_bridge_ca(data_dir, &vault_ref) {
                            Ok(ca) => {
                                store.set_bridge_ca_fingerprint(ca.fingerprint());
                                store.set_bridge_ca(ca);
                                tracing::info!(
                                    "vault.de_unlock_complete: bridge CA loaded \
                                         after vault + lease-KEK unlock"
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "vault.de_unlock_complete: bridge CA load failed"
                                );
                            }
                        }
                    }
                }
                DwkPurpose::LeaseKek => {
                    let lease_kek = crate::trust::lease::LeaseWrapKey::from_raw(*key);
                    store.set_lease_kek(lease_kek);
                    if let Err(e) = store.rehydrate_persisted_leases(chrono::Utc::now()) {
                        tracing::error!(
                            error = %e,
                            "vault.de_unlock_complete: lease-KEK installed but \
                             rehydrating persisted leases failed"
                        );
                    }
                    tracing::info!(
                        "vault.de_unlock_complete: lease-KEK installed via double-envelope"
                    );

                    // Bridge CA loading: if vault is also available, load bridge CA.
                    // Both envelopes must be peeled before sandbox spawn can proceed.
                    if store.bridge_ca().is_none()
                        && let Some(vault_ref) = store.vault()
                    {
                        let data_dir = store
                            .data_dir()
                            .unwrap_or_else(|| std::path::Path::new("."));
                        match crate::infra::runtime::load_or_mint_bridge_ca(data_dir, &vault_ref) {
                            Ok(ca) => {
                                store.set_bridge_ca_fingerprint(ca.fingerprint());
                                store.set_bridge_ca(ca);
                                tracing::info!(
                                    "vault.de_unlock_complete: bridge CA loaded \
                                         after vault + lease-KEK unlock"
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "vault.de_unlock_complete: bridge CA load failed"
                                );
                            }
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "status": "unlocked",
                "purpose": purpose_str,
            }))
        }

        "recovery_action_receipt" => recovery::emit_recovery_action_receipt(store, params),
        "recover_grant_rebuild_chain_status" => {
            recovery::recover_grant_rebuild_chain_status(store, params)
        }
        "recover_persona_restore_status" => recovery::recover_persona_restore_status(store, params),
        "recover_grant_abandon" => recovery::execute_recover_grant_abandon(store, params),
        "recover_persona_abandon" => recovery::execute_recover_persona_abandon(store, params),

        "vault_status" => crate::infra::handlers::vault::handle_status(store),

        // design D3/D7 — vault MEK rotation (two-phase, daemon-authoritative).
        // Both arms delegate to the `vault_rotate` module; the OperatorPresence
        // gate on `vault_rotate_execute` is enforced upstream in
        // `dispatch_method_with_context` before this arm runs.
        "vault_rotate_plan" => {
            presence::record_activity();
            crate::infra::vault_rotate::handle_vault_rotate_plan(store, params, chrono::Utc::now())
        }
        "vault_rotate_execute" => {
            presence::record_activity();
            crate::infra::vault_rotate::handle_vault_rotate_execute(
                store,
                params,
                chrono::Utc::now(),
            )
        }

        "vault_migrate_acl" => crate::infra::handlers::vault::handle_migrate_acl(store, params),

        "vault_list" => crate::infra::handlers::vault::handle_list(store),

        "vault_get" => crate::infra::handlers::vault::handle_get(store, params),

        // KEYCHAIN-CONSOLIDATE-CLI-DAEMON-METHODS — per-caller local-state
        // content-key vending. Per design (separate-uid authorization
        // substrate) the daemon is the sole keychain client; CLI / GUI /
        // native-host callers route key acquisition through these three
        // arms over the SO_PEERCRED + group `ember` ACL-gated socket
        // instead of touching the OS keychain directly. The per-caller
        // vault namespace string is `local-state/<caller>` per the daemon-
        // sole-keychain-client proposal §"Three new daemon socket
        // methods". Per design, key resolve/rotation events are local
        // daemon/operator plumbing and emit immutable audit rows, not signed
        // v2 Receipts. `LocalStateKeyResolveBody` and
        // `LocalStateKeyRotationBody` are retained only as typed audit-detail
        // shapes for that lane.
        //
        // Key wire format: a `xchacha20-key:<64 hex>` content-key string
        // produced by `core_crypto::generate_content_key("local-state")`
        // (the canonical content-key shape consumed by
        // `core_crypto::encrypt_content` / `decrypt_content`). The vault
        // entry stores the UTF-8 bytes of that string; calling code reads
        // them back and treats them as the same content key.
        "local_state_key_get" => {
            crate::infra::handlers::local_state::handle_key_get(store, &ctx, &source, params)
        }

        "local_state_key_set" => {
            crate::infra::handlers::local_state::handle_key_set(store, &ctx, &source, params)
        }

        "local_state_key_rotate_and_reencrypt" => {
            crate::infra::handlers::local_state::handle_key_rotate_and_reencrypt(
                store, &ctx, &source, params,
            )
        }

        "binary_pin_generate" => {
            crate::infra::handlers::binary_pin::handle_generate(store, &source, params)
        }

        // Audit-chain verifier wiring: socket method that exposes
        // the audit-chain verifier primitive shipped in #2998. Walks the
        // last `tail` rows (or full chain when omitted) and returns a
        // shape callers (`ember audit verify` CLI) can render directly.
        "audit_verify" => audit_receipts::handle_verify(store, params),

        // audit_repair_chain_rpc_landed — design v2 §2 / B4 operator
        // -co-signed audit-chain repair RPC. Allowed while quarantined
        // (the ONLY write-class method on `quarantine_allowed_method`).
        // Wire shape:
        //   params: {
        //     "from_row_id": i64,
        //     "repair_kind": "truncate" | "tombstone_segment",
        //     "operator_signature_hex": "<128-hex>",
        //     "operator_pubkey":         "ed25519:<hex>",
        //     "current_chain_tip_hash":  "<hex>",
        //     "daemon_identity_root_fingerprint": "<hex>",
        //   }
        // returns: { "ok": true, "repair_id", "new_chain_tip_hash",
        //            "tombstone_row_id", "truncated_row_count" }
        "audit_repair_chain" => audit_receipts::handle_repair_chain(store, &ctx, params),

        // -S5 follow-up: read-only prepare half for audit repair. Derives
        // the row hash + daemon fingerprint and returns the canonical bytes the
        // operator signs off-host; commit still routes through audit_repair_chain.
        "audit_repair_chain_prepare" => {
            audit_receipts::handle_repair_chain_prepare(store, &ctx, params)
        }

        "audit_query" => audit_receipts::handle_audit_query(store, &ctx, params),

        // audit_query_rpc_landed — dotted daemon RPC exposure for the
        // sanitized audit-log projection; legacy `audit_query` stays above.
        "audit.query" => crate::broker::handler::handle_audit_query(store, &ctx, params),

        "audit_log_query" => audit_receipts::handle_audit_log_query(store, params),

        "audit_explain" => audit_receipts::handle_audit_explain(store, policy, params),

        "receipt_tree" => audit_receipts::handle_receipt_tree(store, params),

        // Unified receipt query — supports the full
        // `ReceiptFilter` shape (actor/kind/grant_id/since/resource/limit).
        // The `ember audit query` CLI path calls this via JSON-RPC socket.
        "receipt_query" => audit_receipts::handle_receipt_query(store, &ctx, params),

        // receipt_list_get_rpc_landed — dotted read RPCs return the persisted
        // receipt JSON envelopes/bodies, preserving each Receipt kind's
        // on-disk shape for callers that decode per design / design.
        "receipt.list" => crate::broker::handler::handle_receipt_list(store, &ctx, params),

        // receipt_list_get_rpc_landed
        "receipt.get" => crate::broker::handler::handle_receipt_get(store, &ctx, params),

        "submit_approval" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'action'".to_string()))?;
            // approval_socket_arm_operator_presence_required — Per
            // adversarial-review 2026-05-19 CRIT-3. The socket dispatch path
            // for `submit_approval` previously (a) skipped `policy.evaluate`
            // entirely, letting an agent submit approval requests for actions
            // the policy was configured to Deny, and (b) accepted the
            // caller-supplied `risk_level` verbatim, allowing the audit trail
            // to lie about how risky the request actually was.
            //
            // The fix matches the create_grant arm's pattern (handler.rs:2580+):
            //   1. Evaluate policy on the action. Denied → -32003 immediately.
            //   2. Use `eval.risk` for the audit row, ignore caller-supplied.
            //   3. Apply the per-op presence gate (same posture as create_grant)
            //      so submit-while-locked surfaces a re-auth prompt rather
            //      than silently filling the pending-approval queue.
            // Internal callers (test harness, daemon-internal flows like the
            // broker's HITL poll loop at broker/handler.rs:1356) bypass.
            let eval = policy.evaluate(action);
            if !source.is_internal() {
                if matches!(eval.requirement, ApprovalRequirement::Denied) {
                    return Err(RpcError::PolicyDenied(format!(
                        "submit_approval: policy denies action {action:?} ({})",
                        eval.matched_rule.unwrap_or_default()
                    ))
                    .into());
                }
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::ApprovalSubmit, override_qh)?;
            }
            // Risk level is policy-derived, not caller-supplied. This closes
            // the audit-truthfulness gap in CRIT-3 — an agent can no longer
            // mark a high-risk submission as "low" to slip past dashboard
            // filtering or operator-attention heuristics.
            let risk_level = format!("{:?}", eval.risk).to_lowercase();
            let ttl_secs = params["ttl_secs"].as_u64();
            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            // Approval flow delegation fields:
            // submit_approval is a generic tool-invoke approval entry; it
            // doesn't carry the grant-shaping fields directly. Defaults to
            // None so the resolver leaves the minted grant unshaped on the
            // delegation axes (legacy behaviour preserved).
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs,
                risk_level: risk_level.clone(),
                tool_name: params["tool_name"].as_str().map(str::to_owned),
                target_host: params["target_host"].as_str().map(str::to_owned),
                target_url: params["target_url"].as_str().map(str::to_owned),
                agent_framework: params["agent_framework"].as_str().map(str::to_owned),
                max_delegation_depth: None,
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            };
            let scope_obj = core_grant_types::approval::RequestedScope {
                capability: scope.to_string(),
                resource_id: None,
                constraints: vec![],
            };
            let request_id = adapter
                .submit_request(persona_id, credential_name, scope_obj, metadata)
                .await
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            let req = store
                .get_approval(&request_id.0)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({"id": request_id.0, "status": req.status}))
        }

        // Composite approval RPC — submit a composite approval that bundles
        // an N-Statement envelope. On `Approved`, the resolver mints a single
        // composite grant whose `blocks_json` carries the full statement
        // chain. Wraps the already-shipped `DaemonStore::propose_grant`.
        "propose_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'action'".to_string()))?;
            let risk_level = params["risk_level"]
                .as_str()
                .ok_or_else(|| RpcError::InvalidParams("missing 'risk_level'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let stmts_value = params["statements"]
                .as_array()
                .ok_or_else(|| RpcError::InvalidParams("missing 'statements' array".to_string()))?;
            let mut statements: Vec<core_grant_types::Statement> =
                Vec::with_capacity(stmts_value.len());
            for v in stmts_value {
                let s: core_grant_types::Statement = serde_json::from_value(v.clone())
                    .map_err(|e| RpcError::InvalidParams(format!("invalid statement: {e}")))?;
                statements.push(s);
            }
            if statements.is_empty() {
                return Err(
                    RpcError::InvalidParams("statements must not be empty".to_string()).into(),
                );
            }
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
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({
                "approval_id": req.id,
                "id": req.id,
                "status": req.status,
                "statement_count": req.composite_statements.as_ref().map(|v| v.len()).unwrap_or(0),
            }))
        }

        "list_pending_approvals" => {
            crate::infra::handlers::approval::handle_list_pending(store, &ctx)
        }

        "resolve_approval" => {
            crate::infra::handlers::approval::handle_resolve(store, &ctx, &source, params).await
        }

        "status" => {
            let persona_scope =
                crate::infra::handlers::principal::team0_connect_only_persona_scope(
                    &ctx, "status",
                )?;
            let personas = store.list_personas().map_err(|e| (-32000, e.to_string()))?;
            let grants = store
                .list_active_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let sandboxes = store
                .list_sandboxes()
                .map_err(|e| (-32000, e.to_string()))?;
            let approvals = store
                .list_pending_approvals()
                .map_err(|e| (-32000, e.to_string()))?;
            let recent_activity_filter = crate::infra::audit::AuditFilter {
                persona_id: persona_scope.clone(),
                limit: Some(5),
                ..Default::default()
            };
            let recent_activity = store
                .query_audit(&recent_activity_filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let standing_grants = store
                .list_standing_grants()
                .map_err(|e| (-32000, e.to_string()))?
                .into_iter()
                .filter(|grant| match persona_scope.as_deref() {
                    Some(persona_id) => grant.persona_id == persona_id,
                    None => true,
                })
                .count();
            let audit_events_total = if let Some(persona_id) = persona_scope.as_deref() {
                store
                    .query_audit(&crate::infra::audit::AuditFilter {
                        persona_id: Some(persona_id.to_string()),
                        ..Default::default()
                    })
                    .map_err(|e| (-32000, e.to_string()))?
                    .len() as u64
            } else {
                store.audit_count().map_err(|e| (-32000, e.to_string()))?
            };
            let grants = grants
                .into_iter()
                .filter(|grant| match persona_scope.as_deref() {
                    Some(persona_id) => grant.persona_id == persona_id,
                    None => true,
                })
                .collect::<Vec<_>>();
            let grant_live_leases = grants
                .iter()
                .filter(|grant| store.leases().has_live_lease(&grant.id, chrono::Utc::now()))
                .map(|grant| grant.id.clone())
                .collect();

            serde_json::to_value(crate::infra::status::StatusSummary {
                personas: personas
                    .into_iter()
                    .filter(|persona| match persona_scope.as_deref() {
                        Some(persona_id) => persona.id == persona_id,
                        None => true,
                    })
                    .collect(),
                grants,
                grant_live_leases,
                sandboxes: sandboxes
                    .into_iter()
                    .filter(|sandbox| match persona_scope.as_deref() {
                        Some(persona_id) => {
                            sandbox.persona_id == persona_id
                                || sandbox.owner_persona_id.as_deref() == Some(persona_id)
                        }
                        None => true,
                    })
                    .collect(),
                approvals: approvals
                    .into_iter()
                    .filter(|approval| match persona_scope.as_deref() {
                        Some(persona_id) => approval.persona_id == persona_id,
                        None => true,
                    })
                    .collect(),
                recent_activity,
                standing_grants,
                audit_events_total,
                quarantined: is_quarantined(),
                quarantine_authority: quarantine_authority()
                    .map(|authority| authority.as_str().to_string()),
            })
            .map_err(|e| (-32000, format!("serialize status summary: {e}")))
        }

        "grant_status" => grants::handle_status(store, &ctx, params),

        // grant_extend_rpc_landed: dotted namespaced spelling for the
        // daemon-owned grant extend. Authority gates mirror `create_grant`
        // (force-from-socket rejection, per-op presence gate under
        // `HighRiskOp::GrantCreate`, policy evaluation on
        // `credential.access`). `extend_grant` remains as the legacy
        // compatibility spelling used by current CLI releases.
        "grant.extend" | "extend_grant" => {
            grant_lifecycle::handle_extend(store, policy, &source, params)
        }

        "request_access" => {
            access_requests::handle_request(store, policy, rate_limiter, params).await
        }

        "await_approval" => access_requests::handle_await_approval(store, &ctx, params).await,

        "request_access_blocking" => {
            access_requests::handle_request_blocking(store, policy, params).await
        }

        // grant_expire_stale_rpc_landed: namespaced spelling for the
        // daemon-owned grant expiry sweep. Keep `expire_grants` as the legacy
        // compatibility spelling used by current CLI releases.
        "grant.expire_stale" | "expire_grants" => grant_lifecycle::handle_expire_stale(store),

        "grant_summary" => grants::handle_summary(store),

        "detect_anomalies" => grants::handle_detect_anomalies(store),

        "create_standing_grant" => {
            use core_event_types::ActionSelector;

            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action_selector: ActionSelector = serde_json::from_value(
                params
                    .get("action_selector")
                    .cloned()
                    .ok_or((-32602, "missing 'action_selector'".to_string()))?,
            )
            .map_err(|e| (-32602, format!("invalid 'action_selector': {e}")))?;
            let scope = params["scope"].as_str().unwrap_or("*");
            let expires_at = params["expires_at"].as_str();
            store
                .create_standing_grant(persona_id, &action_selector, scope, expires_at)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"created": true, "action_selector": action_selector}))
        }

        "list_standing_grants" => {
            let persona_scope =
                crate::infra::handlers::principal::team0_connect_only_persona_scope(
                    &ctx,
                    "list_standing_grants",
                )?;
            let grants = store
                .list_standing_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .filter(|g| match persona_scope.as_deref() {
                    Some(persona_id) => g.persona_id == persona_id,
                    None => true,
                })
                .map(|g| {
                    json!({"id": g.id, "persona_id": g.persona_id, "action_selector": g.action_selector, "scope": g.scope, "expires_at": g.expires_at})
                })
                .collect();
            Ok(Value::Array(list))
        }

        "remove_standing_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            store
                .remove_standing_grant(id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true}))
        }

        "poll_notifications" => {
            let persona_id =
                crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
                    &ctx,
                    params,
                    "poll_notifications",
                    "persona_id",
                    true,
                )?
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let notifications = store
                .poll_notifications(&persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(Value::Array(notifications))
        }

        "list_receipts" => audit_receipts::handle_list_receipts(store, &ctx, params),

        "get_receipt" => audit_receipts::handle_get_receipt(store, &ctx, params),

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

        "grant_budget_status" => grants::handle_budget_status(store, &ctx, params),

        // Broker daemon RPC (design Phase 2): broker socket RPC arms.
        //
        // These are intentionally additive — the registry, materialization
        // tracking, Receipt-event emission, and provider-routing logic live
        // in `crate::broker_handler`. Adding them here is the minimum
        // dispatch surface so concurrent worktrees touching unrelated
        // arms don't conflict on a structural refactor of this fn.
        //
        // Marker: RPC method name "BrokerIssue" lives
        // alongside its sibling routes as the literal `broker_issue`. See
        // `broker_handler.rs` for handler bodies + tests.
        //
        // Broker peercred principal binding: per-agent UDS callers
        // continue to thread a kernel-attested `PeerCredPrincipal` into
        // broker handlers. Bridge-authenticated callers instead ride the
        // `mtls_principal` lane stamped by ember-rpc, so the local sibling
        // peercred must be suppressed before entering the shared-socket
        // broker gates.
        "broker_issue" => {
            crate::broker::handler::handle_broker_issue(
                broker_peercred_principal_for_handler(&ctx),
                store,
                params,
            )
            .await
        }
        "broker_revoke" => {
            crate::broker::handler::handle_broker_revoke(
                broker_peercred_principal_for_handler(&ctx),
                store,
                params,
            )
            .await
        }
        "broker_list" => {
            crate::broker::handler::handle_broker_list(
                broker_peercred_principal_for_handler(&ctx),
                store,
                params,
            )
            .await
        }
        // Broker SecretRef contract: agent processes hold an
        // opaque `SecretRef`; the trust boundary (ember-proxy /
        // ember-tools) calls `broker_resolve` to materialise the
        // plaintext credential. Stub today; full impl in a
        // follow-up.
        "broker_resolve" => {
            crate::broker::handler::handle_broker_resolve(
                broker_peercred_principal_for_handler(&ctx),
                store,
                ctx.sessions_dir.as_deref(),
                params,
            )
            .await
        }
        // Bridge refresh-cert RPC: refresh_cert dispatch.
        // The handler consumes the mTLS principal stamped by the bridge
        // listener and performs design M3 identity proof + mint/update.
        // Anchor: refresh_cert_dispatch_landed
        "refresh_cert" => {
            crate::broker::handler::handle_refresh_cert(
                broker_peercred_principal_for_handler(&ctx),
                ctx.mtls_principal(),
                store,
                rate_limiter,
                params,
            )
            .await
        }
        // design §"daemon-as-process-supervisor": spawn a Construct binary
        // as the daemon's child, capture exit code, emit
        // session.construct_invocation receipt. argv re-classifier deferred.
        "broker_exec" => {
            crate::broker::handler::handle_broker_exec_with_sessions(
                broker_peercred_principal_for_handler(&ctx),
                store,
                ctx.sessions_dir.as_deref(),
                params,
            )
            .await
        }
        // Claude Code gradient warning (Tier 1) —
        // unsessioned subprocess audit observability. Fires from a
        // Construct shim's passthrough-exec branch BEFORE the shim
        // execs the wrapped binary, so the daemon's tamper-evident
        // chain records the invocation even though no broker mediation
        // occurred. ConnectOnly authority (peer-cred is sufficient);
        // schema validation in the handler prevents abuse. See
        // `handle_subprocess_audit_log` for the wire contract.
        "subprocess_audit_log" => {
            handle_subprocess_audit_log(store, params, ctx.peer_cred_principal.as_ref())
        }
        // Broker peercred principal binding: session.lookup_or_open
        // RPC — look up an existing session for the caller's persona or
        // open a fresh one. The persona identity is taken from the
        // kernel-attested `PeerCredPrincipal`, not from the request
        // payload, so a caller cannot pretend to be another persona's
        // session owner. On launcher paths this peercred gate is the
        // identity-binding barrier inside the larger session-open
        // transaction; do not split it from later caller enrollment or
        // authority attach semantics without preserving the same
        // gap-free invariant. Returns -32004 when the persona named by
        // `params.persona` does not match the kernel-attested uid
        // binding, OR -32401 when no principal is available.
        "session.lookup_or_open" | "session_lookup_or_open" => {
            bindings::handle_session_lookup_or_open(ctx.peer_cred_principal.as_ref(), store, params)
                .await
        }
        // Broker GitHub App local key: mint a 1-hour GitHub App installation
        // token using a local-held RSA private key (design credential broker).
        // Credentials loaded from GH_APP_* env vars (placeholder until vault
        // path provisioning lands).
        "broker.mint_gh_token" => {
            crate::broker::handler::handle_broker_mint_gh_token(store, params).await
        }
        // Mint sub-persona RPC: mint a child sub-persona scoped
        // under an existing parent persona. Params: { parent_persona_id, child_label,
        // scope }. Response: { persona_id }. Real two-phase commit + spawn wiring
        // is still a scaffold, but otherwise-valid calls fail closed instead of
        // panicking the daemon.
        "broker.mint_sub_persona" => {
            crate::broker::handler::handle_broker_mint_sub_persona(store, params).await
        }
        // Broker issue --inject: register a child shell PID for
        // auto-revoke when the shell exits. Spawns a background poll task that
        // watches /proc/<pid> (Linux) or kill(pid, 0) (other Unix) and calls
        // broker_revoke on all listed materialization IDs on exit.
        "broker_register_pid_watcher" => {
            crate::broker::handler::handle_broker_register_pid_watcher(store, params).await
        }

        // design slice 4 C: the forgeable WebAuthn-assertion → `DaemonSignedHandle`
        // presence-proof bridge (`issue_presence_proof` + `TabChannel` +
        // `AssertionVerifier` + `issue_daemon_signed_handle`) was deleted. The
        // dispatch arm is retained so the wire surface stays discoverable, but
        // `handle_request_presence_proof` now returns a clean `-32601
        // not_implemented`. Operator presence is sourced from the §4
        // presence-as-decryption unlock; widening verifies a real enrolled-device
        // signature via `presence_gate::verify_presence_signature`.
        "presence/request_proof" | "presence_request_proof" => {
            crate::broker::handler::handle_request_presence_proof(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }

        // design §3 — mint the single-use presence nonce a widening op's
        // presence-Device signature must cover (the G3 signing-driver's first
        // call). Returns the nonce, the daemon fingerprint, and the exact
        // canonical intent bytes to sign off-host. ConnectOnly proof-acquisition.
        "presence/request_nonce" | "presence_request_nonce" => {
            handle_presence_request_nonce(store, &ctx, params)
        }

        // V030-EMBER-DEVICE-LIST — ConnectOnly read of the full enrolled-device
        // inventory. No vault tap; no presence gate. Returns all devices in
        // `devices_current` from the identity event store. Exempt from the
        // revoke-coverage audit (EXEMPT: no persona/grant params).
        // Anchor: ember_device_list_surface_landed.
        "identity.device.list" | "identity_device_list" => {
            presence_runtime::handle_identity_device_list(store)
        }

        // design §5 device enrollment — operator-bootstrap ceremony. The
        // prepare→commit RPC that drives the merged
        // `operator_identity::{genesis_enroll_plan, commit_first_run_enrollment}`
        // primitives: PREPARE (no signatures) returns the exact bytes the
        // operator's presence device must sign off-host; COMMIT (signatures
        // present) appends + verifies the genesis/enroll events. The daemon never
        // holds the operator device key. This RETIRES the old
        // `presence/enroll` → `handle_first_run_enrollment` WebAuthn-passkey stub
        // (it minted non-attested passkeys structurally barred from the presence
        // class). The dashboard passkey ceremony / webauthn-rs machinery is kept
        // for the future `genuine_app` attested-passkey lane; only this
        // operator-enrollment entry point is retired.
        "identity.device.enroll" | "identity_device_enroll" => {
            handle_identity_device_enroll(store, params)
        }

        // design §5 — read-only PREPARE half (tap-reduction). ConnectOnly: no
        // key, no mutation, no vault; splitting it out of the OperatorPresence
        // commit RPC drops a redundant native-unlock Touch ID tap.
        "identity.device.enroll_plan" | "identity_device_enroll_plan" => {
            handle_identity_device_enroll_plan(store, params)
        }

        // design §5 / AC-2 — backup presence-device enrollment. PREPARE returns
        // the exact DeviceEnrolled bytes an existing operator presence Device
        // signs; COMMIT verifies that signature and appends the backup device.
        "identity.device.enroll_backup" | "identity_device_enroll_backup" => {
            handle_identity_device_enroll_backup(store, params)
        }
        "identity.device.enroll_backup_plan" | "identity_device_enroll_backup_plan" => {
            handle_identity_device_enroll_backup_plan(store, params)
        }

        // V030-EMBER-DEVICE-REVOKE — operator-driven device revocation. Same
        // two-call prepare/commit shape as `enroll_backup`: PREPARE returns the
        // DeviceRevoked event bytes the authority presence Device signs;
        // COMMIT verifies and appends. Daemon refuses to revoke the last
        // active presence Device (would brick the authority set). The OOB
        // signature on the event bytes IS the presence proof — this method is
        // deliberately NOT in `is_presence_widening` (the event-body
        // signature is structurally stronger than a chokepoint intent
        // signature; the operator does not sign twice). EXEMPT from the
        // revoke-coverage audit (no persona/grant params).
        // Anchor: ember_device_revoke_surface_landed.
        "identity.device.revoke" | "identity_device_revoke" => {
            // V030-EMBER-DEVICE-REVOKE F4.1 — handler is now async; it
            // acquires `DaemonStore::identity_mutation_lock` across the
            // open → guard → commit window so two concurrent COMMITs
            // cannot each pass an independent pre-flight against stale
            // per-instance materialized state. See the handler doc-comment
            // for the race rationale.
            handle_identity_device_revoke(store, params).await
        }

        // design §6 — off-host recovery-recipient enrollment (the printed `age`
        // code). Same two-call shape as backup-device enrollment: PREPARE returns
        // the `DeviceEnrolled(Recovery)` bytes an existing operator presence Device
        // signs; COMMIT verifies that signature and appends the Recovery Device.
        // The daemon holds neither the authority key nor the recovery secret.
        "identity.recovery.enroll" | "identity_recovery_enroll" => {
            handle_identity_recovery_enroll(store, params)
        }

        // Credential-binding admin verb: credential-binding admin
        // RPCs invoked by `ember bind {register, list, remove, move}`. The
        // admin path does NOT require biometric — the operator
        // authenticates to the daemon via PeerCred. Each handler enforces
        // caller_persona validation (non-nil parseable UUID) and emits an
        // audit row for register/remove/move. The dotted method names are
        // canonical; the underscore aliases mirror the broker_* dispatch
        // convention used by sibling routes.
        "broker.bindings.register" | "broker_bindings_register" => {
            crate::broker::handler::handle_broker_bindings_register(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.bindings.list" | "broker_bindings_list" => {
            crate::broker::handler::handle_broker_bindings_list(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.registry_status" | "broker_registry_status" => {
            // -S3 intentionally-global ConnectOnly diagnostic: registry
            // installation/authority posture is daemon-wide and carries no
            // persona-owned rows.
            let registry = crate::broker::handler::current_registry().ok_or_else(|| {
                (
                    -32000,
                    "broker registry not initialised — start emberd to populate".to_string(),
                )
            })?;
            crate::broker::handler::registry_status_with_registry(registry).await
        }
        "broker.github_status" | "broker_github_status" => {
            // -S3 intentionally-global ConnectOnly diagnostic: GitHub
            // broker resolver posture is daemon/operator posture, not a
            // persona inventory projection.
            let registry = crate::broker::handler::current_registry().ok_or_else(|| {
                (
                    -32000,
                    "broker registry not initialised — start emberd to populate".to_string(),
                )
            })?;
            let resolver = crate::broker::authority::BrokerAuthorityResolver::current()
                .ok_or_else(|| {
                    (
                        -32000,
                        "broker authority resolver not initialised — start emberd to populate"
                            .to_string(),
                    )
                })?;
            crate::broker::handler::github_status_with_registry_and_resolver(
                registry,
                resolver.as_ref(),
            )
            .await
        }
        "trust.list" | "trust_list" => {
            // design §Component 2 — operator-visible trust-set
            // introspection. Read-only; no peer-cred gating because the
            // snapshot answers a "what is this daemon's posture?" question
            // that any operator with socket access already learns by
            // probing the manifest path. -S3 keeps this intentionally
            // global because trust roots are daemon posture, not
            // persona-owned rows. See trust::introspect.
            crate::trust::introspect::handle_trust_list(params)
        }
        "trust.show" | "trust_show" => {
            // design §Component 2 Phase 2 — drill-down lookup by full
            // fingerprint or unique hex prefix. Same posture as
            // `trust.list` (read-only, intentionally-global ConnectOnly).
            crate::trust::introspect::handle_trust_show(params)
        }
        "trust.explain" | "trust_explain" => {
            // design §Component 2 Phase 3 — chain-walk a signed
            // artifact back to its trust root. v1 supports
            // `artifact_kind = "binary_manifest"`; Receipt + workflow
            // grant land in follow-up tasks. Same intentionally-global
            // daemon-posture read as `trust.list`.
            crate::trust::introspect::handle_trust_explain_with_store(Some(store), params)
        }
        "trust.rotate_dev_ir" | "trust_rotate_dev_ir" => {
            // design §Component 3 — dev IdentityRoot rotation.
            // The CLI side has already minted
            // the new keypair (Touch ID gated), stashed it in Keychain
            // at the `.v2` label, and is calling here to register the
            // rotation + schedule the grace-window timer. The mutation
            // is bookkeeping-only (registry entry); the trust-root
            // snapshot itself updates at the next daemon startup when
            // the operator-rewritten plist's `EMBER_TRUST_ROOTS`
            // carries both keys (additive rotation per Component 3
            // step 3). Anchor: `trust_rotate_dev_ir_landed`.
            crate::trust::rotation::handle_trust_rotate_dev_ir(params)
        }
        "trust.rotation_status" | "trust_rotation_status" => {
            // design §Component 3 — read-only "is anything rotating?"
            // query. Same intentionally-global posture as
            // `trust.list`; safe to expose to any ConnectOnly caller.
            crate::trust::rotation::handle_trust_rotation_status(params)
        }
        "broker.bindings.remove" | "broker_bindings_remove" => {
            crate::broker::handler::handle_broker_bindings_remove(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.bindings.move" | "broker_bindings_move" => {
            crate::broker::handler::handle_broker_bindings_move(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }

        // Binding delete RPC (design §"binding.delete"):
        // graceful delete of a SA→Persona binding. Revokes the workload
        // Persona's grants (cascade via `revoke_persona`) so in-flight
        // broker requests holding active grant references drain to
        // completion while new lookups fail. The audit log captures a
        // `binding.deleted` event keyed on `persona_id` +
        // `binding_request_id` for idempotent reconciler retries. The
        // canonical wire-form method is "binding.delete"; the
        // underscore alias mirrors the broker_* dispatch convention.
        "binding.delete" | "binding_delete" => bindings::binding_delete(store, params).await,

        // Binding revoke-urgent RPC (design
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
            bindings::binding_revoke_urgent(store, params).await
        }

        // Binding update RPC (design §"binding.update"):
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
        "binding.update" | "binding_update" => bindings::binding_update(store, params).await,

        // Binding upsert RPC (design §"binding.upsert"):
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
        "binding.upsert" | "binding_upsert" => bindings::binding_upsert(store, params).await,

        // Agent-persona RPC (design §9 + §6):
        // atomic create_agent_persona binding container identity →
        // Persona + attenuated child grant. Replaces the
        // create_persona + delegate_grant two-call sequence with a
        // single RPC whose state machine is the two-phase commit:
        //
        //   phase 1 — insert persona row with status='enrolling' +
        //             bind to container_id + parent_grant_id
        //             (CRIT-4: only one in-flight key per container)
        //   phase 2 — delegate the parent grant to the new persona
        //             with the requested narrowed scope
        //   phase 3 — flip persona status enrolling → active
        //
        // If the daemon crashes between phase 1 and phase 3, the
        // persona row stays in 'enrolling' and the reconciler refuses
        // to spawn into that container slot (see
        // DaemonStore::enrolling_persona_for_container). The
        // container_id binding is persisted in both the `personas`
        // table (via container_id column) AND the audit log (via
        // `agent_persona.created` event) so reconcilers can
        // reconstruct the binding from either source.
        "create_agent_persona" | "create_agent_persona_atomic" => {
            bindings::create_agent_persona(store, params).await
        }

        // SOPS RPCs live in handler::sops. `sops_unwrap_dek` carries the
        // grant validation, one-successful-unwrap consumption, vault key load,
        // age decrypt, and audit logging Interface for agent SOPS use.
        "sops_unwrap_dek" => sops::handle_unwrap_dek(store, params),

        "sops.pubkey" => sops::handle_pubkey(params),

        "sops.wrap" => sops::handle_wrap(params),

        "sops.unwrap" => sops::handle_unwrap(params),

        // Launcher session RPC: register a new claude-code session.
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
            crate::infra::handlers::session::handle_register_session(store, &ctx, params)
        }
        "describe_runtime_attach_target" => {
            crate::infra::handlers::session::handle_describe_runtime_attach_target(&ctx, params)
        }

        // Launcher session RPC: close a claude-code session (clean exit).
        //
        // Called by the launcher after the `claude` child exits naturally. Emits
        // a signed v2 `session.claude_code` Receipt with
        // `termination_reason: clean_exit` into `<session_dir>/receipt.json`,
        // closes the `SessionMeta`, and logs a `session.closed` audit event.
        //
        // Clean-exit revoke fix: CleanExit MUST NOT
        // revoke the grant. A 24h grant supports many sessions; the previous
        // unconditional revoke_grant call here was the second-half regression
        // (the launcher goes through this RPC arm, not session_watcher, so
        // #2366's session_watcher fix did not reach the launcher path).
        //
        // Params: `{ "session_id": "..." }`
        // Result: `{ "closed": true, "receipt_id": "..." }`
        "close_session" => {
            crate::infra::handlers::session::handle_close_session(store, &ctx, params)
        }

        // -S2 Door-1 leaf-pin (design §2). The launcher reports the pid of
        // the harness child it just spawned; the per-session UDS accept gate
        // admits a connection only from that exact pid (+ reuse-immune
        // pidversion). See `infra::session_proxy::evaluate_primary_gate`.
        //
        // Params: `{ "session_id": "...", "leaf_pid": <u32> }`
        // Result: `{ "leaf_pinned": <bool> }`
        "report_session_leaf" => {
            crate::infra::handlers::session::handle_report_session_leaf(&ctx, params)
        }

        // design §5 output 3 — persist a reusable delegated-authority artifact
        // from `ember catalog plan --save`. Writes the validated template TOML
        // into the daemon's own overlay dir so a separate-uid managed daemon
        // can resolve it at launch. OperatorPresence-gated (authority-shaping).
        "save_delegation_template" => {
            crate::infra::handlers::session::handle_save_delegation_template(store, &ctx, params)
        }

        // BKR-4c (design §6): the `delegation_{revoke,list,show}` RPCs were
        // retired with the legacy delegation sidecar (now `StandingGrant`). The
        // per-session authority lives in the runtime persona's standing grant;
        // operators inspect/revoke it via the unified `grant` surface (`ember
        // grant {ls,show,revoke}`). Unknown-method callers hit the default arm.

        // Headless enrollment/runtime surfaces live in handler::headless.
        "headless_enroll" => headless::handle_enroll(store, &ctx, params),

        "headless_revoke" => headless::handle_revoke(store, &ctx, params),

        "headless_status" => headless::handle_status(&ctx),

        "headless_preflight_gaps" => headless::handle_preflight_gaps(&ctx, params),

        // Headless pre-flight Layer 1 — Layer 1 predictive
        // pre-flight gate, wired over the daemon socket so the CLI can
        // surface manifest-declared Construct gaps before headless dispatches
        // a task that the enrolled persona's template cannot grant.
        //
        // Layer 1 pre-flight is wired into the socket surface.
        //
        // Per design §"Pre-flight scope check at enrollment" Layer 1: for
        // each queued task that declares `constructs = ["<construct>.<action>"]`,
        // resolve the union of action permissions through the bundled cohort-A
        // manifest registry, diff against the enrolled persona template, and
        // return the gap list. Slice B (prior change) shipped the resolver +
        // manifest parser; this arm wires them into the socket surface.
        //
        // Params:
        //   { "tasks": [ { "task_id": "<id>", "constructs": ["<c>.<a>", ...] }, ... ],
        //     "template"?: ["<construct>.<action>", ...] }
        //
        // Result: JSON array of `{ "task_id": <id>, "identifier": <perm>,
        //                          "scope": <string|null> }` — one entry per
        //         permission a task needs that is NOT in `template`.
        //
        // Authorization: read-only over caller-supplied data; SO_PEERCRED +
        // group `ember` ACL (design) is the only gate, matching
        // `headless_preflight_gaps`.
        "headless_preflight_layer1" => {
            presence::record_activity();
            preflight::handle_headless_preflight_layer1(params)
        }

        // -S3 — preflight authority coverage. Read-only, persona-scoped
        // ConnectOnly. The daemon owns the covered/prompt/deny/missing verdict
        // (authority root); the CLI only enumerates the catalog action set and
        // renders the result.
        "preflight_authority_coverage" => {
            presence::record_activity();
            preflight::handle_preflight_authority_coverage(&ctx, params, store).await
        }

        _ => Err((-32601, "Method not found".to_string())),
    }
}

#[cfg(test)]
mod tests;
