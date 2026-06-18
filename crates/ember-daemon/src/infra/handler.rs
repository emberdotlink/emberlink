// dispatch_method_revoke_coverage_audited
//
// dispatch_revoke_audit_relocated: the detailed revoke-coverage audit record
// lives outside this dispatcher module. Keep this checkpoint in handler.rs for
// the bridge-prerequisite proof breadcrumb; do not re-expand the audit table
// here.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use tokio::sync::broadcast;

#[cfg(test)]
use core_personas::MtlsPrincipal;

use crate::infra::events::GrantEvent;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::receipt::{current_identity, issue::issue_atomic_receipt};
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;
#[cfg(test)]
use crate::trust::approval::GrantShapeFields;
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::{self, GateOutcome, HighRiskOp};
use core_events::receipt::{
    RECEIPT_KIND_RECOVERY_ACTION, RecoveryActionBody, TerminationAuthority,
};

pub(crate) mod access_requests;
pub(crate) mod audit_receipts;
mod authority;
mod banner;
mod bindings;
mod context;
pub(crate) mod grant_lifecycle;
mod grant_use;
pub(crate) mod grants;
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
pub(crate) use banner::notify_require_approval;
pub use banner::{Banner, build_banner};
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
pub(crate) use presence_runtime::VerifiedPresenceProof;
pub(crate) use presence_runtime::parse_scope_kek_hex;
use presence_runtime::{
    TransientKekEvictionGuard, enforce_presence_chokepoint_with_audit, enforce_presence_proof,
    enforce_presence_proof_with_audit, handle_identity_device_enroll,
    handle_identity_device_enroll_backup, handle_identity_device_enroll_backup_plan,
    handle_identity_device_enroll_plan, handle_identity_device_revoke,
    handle_identity_recovery_enroll, handle_presence_request_nonce,
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
/// (C39-HANDLER-C3-FULL) cannot apply — `delegate_grant` falls back to the
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
/// by tests that pre-date C39-HANDLER-C3-FULL and by `Internal` callers
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
/// admin/test paths. Mis-attribution here would re-open C39-HANDLER-C2.
///
/// `ctx.peer` carries the kernel-derived peer credential when available
/// (Linux + macOS sockets only). `delegate_grant` consults it via
/// `peercred_principal()` to bind requests to a real principal instead
/// of trusting an attacker-controlled param. See C39-HANDLER-C3-FULL.
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

    // Persona enrollment in container (ADR 136 §"In-container
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

    // request_context_mtls_principal_overlay (ADR 154 component 4) —
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
    // refused before dispatch (ADR 154 ESC-3).
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

    // F6 (ADR 155 priv-sep SLICE 2a) — fail-closed when a Bridge cert claims a
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
                    "rejecting bridge RPC: cert persona SAN does not resolve to a known persona (ADR 155 fail-closed)"
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

    // ADR 154 ESC-3 — enforce the persona↔container binding for
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
            "rejecting bridge RPC: mTLS container SAN does not match the persona's bound container (ADR 154 ESC-3)"
        );
        return Err((
            -32004,
            "principal binding violation: mTLS container SAN does not match the persona's container binding"
                .to_string(),
        ));
    }

    // ADR 154 audit-equivalence (SLICE 1, net-new) — every Bridge dispatch
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

    // ADR 155 priv-sep §1c (SLICE 1, net-new) — daemon-side refusal of the
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
    // ONE write-class method allowed through this gate per ADR 174 v2
    // §1 R1 D3. `quarantine_allowed_method` wraps
    // `is_read_class_method` with that single exception so the gate
    // logic remains "default-deny + named whitelist." The repair RPC
    // re-runs the operator-co-signature check internally; this gate
    // doesn't substitute for that authority check.
    if is_quarantined() && !quarantine_allowed_method(method) {
        // ADR 174 v2 §1 + adversarial review HIGH-4: do NOT include the
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

    // ADR 206 §1 — the fail-closed presence-authority chokepoint. For an
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

    // ADR 206 §1 (AC-2/AC-3) — transient-KEK widening install.
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
                "ADR 206 §1: installed transient widening KEK_s (verified proof + op-supplied KEK_s); no standing window"
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
            // ADR 206 §1 (AC-2) — transient-KEK widening authorization.
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
            // ADR 155 priv-sep (F7) — the Bridge lane (in-container agents) must
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

            // ADR 206 slice 4 C — fail-closed §4 fall-through.
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
        // EXCEPTION (ADR 206 §1 AC-2): the transient-KEK widening path holds NO
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
        "ping" => crate::infra::handlers::system::handle_ping(),

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
            crate::infra::handlers::personas::handle_evaluate_tool_call(store, params).await
        }

        "create_persona" => {
            crate::infra::handlers::personas::handle_create_persona(store, &ctx, &source, params)
                .await
        }

        "build_init_first_grant_receipt" => {
            crate::infra::handlers::personas::handle_build_init_first_grant_receipt(store, params)
        }

        "persona_signer" => {
            // persona_signer_rpc_landed: daemon-held signer capability for
            // ADR-131 init migration; returns signatures, never private keys.
            crate::broker::handler::handle_persona_signer(store, params)
        }

        "list_personas" => {
            crate::infra::handlers::personas::handle_list_personas(store, &ctx, params).await
        }

        "revoke_persona" => {
            crate::infra::handlers::personas::handle_revoke_persona(store, &ctx, &source, params)
                .await
        }

        "retire_persona_for_reenroll" => {
            crate::infra::handlers::personas::handle_retire_for_reenroll(
                store, &ctx, &source, params,
            )
            .await
        }

        "create_grant" => {
            crate::infra::handlers::grants::handle_create_grant(
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

        "delegate_grant" => {
            crate::infra::handlers::grants::handle_delegate_grant(store, &ctx, &source, params)
                .await
        }

        "list_grants" => crate::infra::handlers::grants::handle_list_grants(store, &ctx, params),

        "list_operator_grants" => grants::handle_list_operator_grants(store, params),

        "list_all_grants" => {
            // grant_list_all_rpc_landed
            crate::broker::handler::handle_list_all_grants(store, params)
        }

        // Sandbox launch/runtime RPCs live in handler::sandbox.
        "sandbox_create" => sandbox::handle_create(store, &ctx, params),

        "sandbox_list" => sandbox::handle_list(store),

        "sandbox_stop" => sandbox::handle_stop(store, &ctx, params),

        "sandbox_delete" => sandbox::handle_delete(store, &ctx, params),

        "sandbox_exec" => sandbox::handle_exec(store, &ctx, params).await,

        "sandbox_run" => sandbox::handle_run(store, policy, &ctx, params),

        "revoke_grant" => {
            crate::infra::handlers::grants::handle_revoke_grant(store, &ctx, events_tx, params)
        }

        "revoke_statement" => {
            crate::infra::handlers::grants::handle_revoke_statement(store, params)
        }

        "evaluate_grant" => {
            crate::infra::handlers::grants::handle_evaluate_grant(store, &ctx, params)
        }

        "use_credential" => grant_use::handle_use_credential(store, params),

        "vault_add" => crate::infra::handlers::vault::handle_add(store, &source, params),

        "vault_put" => crate::infra::handlers::vault::handle_put(store, &source, params),

        "vault_export_sealed" => crate::infra::handlers::vault::handle_export_sealed(store, params),

        "vault_import_sealed" => crate::infra::handlers::vault::handle_import_sealed(store, params),

        "vault_remove" => crate::infra::handlers::vault::handle_remove(store, &source, params),

        "vault_lock" => crate::infra::handlers::vault::handle_lock(),

        "vault_unlock" => crate::infra::handlers::vault::handle_unlock(store, &ctx, params),

        "vault.se_provision" | "vault/se_provision" | "vault_se_provision" => {
            crate::infra::handlers::vault::handle_se_provision(store, params)
        }
        "vault.se_add_recipient_wrap"
        | "vault/se_add_recipient_wrap"
        | "vault_se_add_recipient_wrap" => {
            crate::infra::handlers::vault::handle_se_add_recipient_wrap(store, params)
        }
        "vault.se_unlock_begin" | "vault/se_unlock_begin" | "vault_se_unlock_begin" => {
            crate::infra::handlers::vault::handle_se_unlock_begin(store)
        }
        "vault.se_unlock_complete" | "vault/se_unlock_complete" | "vault_se_unlock_complete" => {
            crate::infra::handlers::vault::handle_se_unlock_complete(store, params)
        }

        "vault.de_provision_begin" | "vault/de_provision_begin" | "vault_de_provision_begin" => {
            crate::infra::handlers::vault::handle_de_provision_begin(store, params)
        }
        "vault.de_provision_outer" | "vault/de_provision_outer" | "vault_de_provision_outer" => {
            crate::infra::handlers::vault::handle_de_provision_outer(store, params)
        }
        "vault.de_unlock_begin" | "vault/de_unlock_begin" | "vault_de_unlock_begin" => {
            crate::infra::handlers::vault::handle_de_unlock_begin(store, params)
        }
        "vault.de_unlock_complete" | "vault/de_unlock_complete" | "vault_de_unlock_complete" => {
            crate::infra::handlers::vault::handle_de_unlock_complete(store, params)
        }

        "recovery_action_receipt" => recovery::emit_recovery_action_receipt(store, params),
        "recover_grant_rebuild_chain_status" => {
            recovery::recover_grant_rebuild_chain_status(store, params)
        }
        "recover_persona_restore_status" => recovery::recover_persona_restore_status(store, params),
        "recover_grant_abandon" => recovery::execute_recover_grant_abandon(store, params),
        "recover_persona_abandon" => recovery::execute_recover_persona_abandon(store, params),

        "vault_status" => crate::infra::handlers::vault::handle_status(store),

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

        "audit_verify" => crate::infra::handlers::system::handle_audit_verify_rpc(store, params),

        // audit_repair_chain_rpc_landed
        "audit_repair_chain" => audit_receipts::handle_repair_chain(store, &ctx, params),

        "audit_repair_chain_prepare" => {
            audit_receipts::handle_repair_chain_prepare(store, &ctx, params)
        }

        "audit_query" => {
            crate::infra::handlers::system::handle_audit_query_rpc(store, &ctx, params)
        }

        // audit_query_rpc_landed
        "audit.query" => crate::broker::handler::handle_audit_query(store, &ctx, params),

        "audit_log_query" => audit_receipts::handle_audit_log_query(store, params),

        "audit_explain" => audit_receipts::handle_audit_explain(store, policy, params),

        "receipt_tree" => audit_receipts::handle_receipt_tree(store, params),

        "receipt_query" => {
            crate::infra::handlers::system::handle_receipt_query_rpc(store, &ctx, params)
        }

        // receipt_list_get_rpc_landed
        "receipt.list" => crate::broker::handler::handle_receipt_list(store, &ctx, params),

        // receipt_list_get_rpc_landed
        "receipt.get" => crate::broker::handler::handle_receipt_get(store, &ctx, params),

        "submit_approval" => {
            crate::infra::handlers::approval::handle_submit(store, policy, &source, params).await
        }

        "propose_grant" => crate::infra::handlers::approval::handle_propose_grant(store, params),

        "list_pending_approvals" => {
            crate::infra::handlers::approval::handle_list_pending(store, &ctx)
        }

        "resolve_approval" => {
            crate::infra::handlers::approval::handle_resolve(store, &ctx, &source, params).await
        }

        // approval_resolve_rpc_landed
        "approval.resolve" | "approval_resolve" => {
            crate::broker::handler::handle_approval_resolve(store, &ctx, &source, params).await
        }
        "approval.narrow" | "approval_narrow" => {
            crate::broker::handler::handle_approval_narrow(store, &ctx, &source, params).await
        }

        // status_aggregated_rpc_landed
        "status" => crate::broker::handler::handle_status(store, &ctx),

        "grant_status" => crate::infra::handlers::grants::handle_grant_status(store, &ctx, params),

        // grant_extend_rpc_landed
        "grant.extend" | "extend_grant" => {
            crate::infra::handlers::grants::handle_extend_grant(store, policy, &source, params)
        }

        "request_access" => {
            crate::infra::handlers::approval::handle_request_access(
                store,
                policy,
                rate_limiter,
                params,
            )
            .await
        }

        "await_approval" => {
            crate::infra::handlers::approval::handle_await_approval(store, &ctx, params).await
        }

        // grant_expire_stale_rpc_landed
        "grant.expire_stale" | "expire_grants" => {
            crate::infra::handlers::system::handle_expire_grants(store)
        }

        "grant_summary" => crate::infra::handlers::grants::handle_grant_summary(store),

        "detect_anomalies" => crate::infra::handlers::system::handle_detect_anomalies(store),

        "create_standing_grant" => {
            crate::infra::handlers::grants::handle_create_standing_grant(store, params)
        }

        "list_standing_grants" => {
            crate::infra::handlers::grants::handle_list_standing_grants(store, &ctx)
        }

        "remove_standing_grant" => {
            crate::infra::handlers::grants::handle_remove_standing_grant(store, params)
        }

        "poll_notifications" => {
            crate::infra::handlers::system::handle_poll_notifications(store, &ctx, params)
        }

        "list_receipts" => {
            crate::infra::handlers::system::handle_list_receipts(store, &ctx, params)
        }

        "get_receipt" => crate::infra::handlers::system::handle_get_receipt(store, &ctx, params),

        "daemon_persona" => crate::infra::handlers::system::handle_daemon_persona(),

        "grant_budget_status" => {
            crate::infra::handlers::grants::handle_grant_budget_status(store, &ctx, params)
        }

        // Broker-facing RPC routing lives in handlers::broker.
        "broker_issue" => crate::infra::handlers::broker::handle_issue(store, &ctx, params).await,
        "broker_revoke" => crate::infra::handlers::broker::handle_revoke(store, &ctx, params).await,
        "broker_list" => crate::infra::handlers::broker::handle_list(store, &ctx, params).await,
        "broker_resolve" => {
            crate::infra::handlers::broker::handle_resolve(store, &ctx, params).await
        }
        "refresh_cert" => {
            crate::infra::handlers::broker::handle_refresh_cert(store, rate_limiter, &ctx, params)
                .await
        }
        "broker_exec" => crate::infra::handlers::broker::handle_exec(store, &ctx, params).await,
        "subprocess_audit_log" => {
            crate::infra::handlers::broker::handle_subprocess_audit_log(store, &ctx, params)
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
            crate::infra::handlers::session::handle_session_lookup_or_open(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.mint_gh_token" => {
            crate::infra::handlers::broker::handle_mint_gh_token(store, params).await
        }
        "broker.mint_sub_persona" => {
            crate::infra::handlers::broker::handle_mint_sub_persona(store, params).await
        }
        "broker_register_pid_watcher" => {
            crate::infra::handlers::broker::handle_register_pid_watcher(store, params).await
        }

        // handler_dispatch_prose_compacted: domain modules own detailed RPC contracts.
        "presence/request_proof" | "presence_request_proof" => {
            crate::infra::handlers::broker::handle_request_presence_proof(store, &ctx, params).await
        }

        "presence/request_nonce" | "presence_request_nonce" => {
            handle_presence_request_nonce(store, &ctx, params)
        }

        "identity.device.list" | "identity_device_list" => {
            presence_runtime::handle_identity_device_list(store)
        }

        "identity.device.enroll" | "identity_device_enroll" => {
            handle_identity_device_enroll(store, params)
        }

        "identity.device.enroll_plan" | "identity_device_enroll_plan" => {
            handle_identity_device_enroll_plan(store, params)
        }

        "identity.device.enroll_backup" | "identity_device_enroll_backup" => {
            handle_identity_device_enroll_backup(store, params)
        }
        "identity.device.enroll_backup_plan" | "identity_device_enroll_backup_plan" => {
            handle_identity_device_enroll_backup_plan(store, params)
        }

        "identity.device.revoke" | "identity_device_revoke" => {
            handle_identity_device_revoke(store, params).await
        }

        "identity.recovery.enroll" | "identity_recovery_enroll" => {
            handle_identity_recovery_enroll(store, params)
        }

        "broker.bindings.register" | "broker_bindings_register" => {
            crate::infra::handlers::broker::handle_bindings_register(store, &ctx, params).await
        }
        "broker.bindings.list" | "broker_bindings_list" => {
            crate::infra::handlers::broker::handle_bindings_list(store, &ctx, params).await
        }
        "broker.registry_status" | "broker_registry_status" => {
            crate::infra::handlers::broker::handle_registry_status().await
        }
        "broker.github_status" | "broker_github_status" => {
            crate::infra::handlers::broker::handle_github_status().await
        }
        "trust.list" | "trust_list" => crate::trust::introspect::handle_trust_list(params),
        "trust.show" | "trust_show" => crate::trust::introspect::handle_trust_show(params),
        "trust.explain" | "trust_explain" => {
            crate::trust::introspect::handle_trust_explain_with_store(Some(store), params)
        }
        "trust.rotate_dev_ir" | "trust_rotate_dev_ir" => {
            crate::trust::rotation::handle_trust_rotate_dev_ir(params)
        }
        "trust.rotation_status" | "trust_rotation_status" => {
            crate::trust::rotation::handle_trust_rotation_status(params)
        }
        "broker.bindings.remove" | "broker_bindings_remove" => {
            crate::infra::handlers::broker::handle_bindings_remove(store, &ctx, params).await
        }
        "broker.bindings.move" | "broker_bindings_move" => {
            crate::infra::handlers::broker::handle_bindings_move(store, &ctx, params).await
        }

        "binding.delete" | "binding_delete" => bindings::binding_delete(store, params).await,

        "binding.revoke_urgent" | "binding_revoke_urgent" => {
            bindings::binding_revoke_urgent(store, params).await
        }

        "binding.update" | "binding_update" => bindings::binding_update(store, params).await,

        "binding.upsert" | "binding_upsert" => bindings::binding_upsert(store, params).await,

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

        "register_session" => {
            crate::infra::handlers::session::handle_register_session(store, &ctx, params)
        }
        "describe_runtime_attach_target" => {
            crate::infra::handlers::session::handle_describe_runtime_attach_target(&ctx, params)
        }

        "close_session" => {
            crate::infra::handlers::session::handle_close_session(store, &ctx, params)
        }

        "report_session_leaf" => {
            crate::infra::handlers::session::handle_report_session_leaf(&ctx, params)
        }

        "save_delegation_template" => {
            crate::infra::handlers::session::handle_save_delegation_template(store, &ctx, params)
        }

        // Headless enrollment/runtime surfaces live in handler::headless.
        "headless_enroll" => headless::handle_enroll(store, &ctx, params),

        "headless_revoke" => headless::handle_revoke(store, &ctx, params),

        "headless_status" => headless::handle_status(&ctx),

        "headless_preflight_gaps" => headless::handle_preflight_gaps(&ctx, params),

        "headless_preflight_layer1" => {
            presence::record_activity();
            preflight::handle_headless_preflight_layer1(params)
        }

        "preflight_authority_coverage" => {
            presence::record_activity();
            preflight::handle_preflight_authority_coverage(&ctx, params, store).await
        }
        "catalog.search_actions" | "catalog_search_actions" => {
            presence::record_activity();
            preflight::handle_catalog_search_actions(params)
        }

        _ => Err((-32601, "Method not found".to_string())),
    }
}

#[cfg(test)]
mod tests;
