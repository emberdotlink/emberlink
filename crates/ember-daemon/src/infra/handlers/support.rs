//! fn resolve_caller_principal
//! CLASSIFICATION: PUBLIC

use core_events::receipt::TerminationAuthority;

use crate::infra::handler::{RequestContext, peercred_principal};
use crate::infra::receipt::current_identity;
use crate::infra::receipt::issue::{TerminationMeta, issue_cohort_a_receipt};
use crate::infra::rpc_error::RpcError;

/// Resolve the calling principal from the request context and params.
///
/// Resolution order:
///   1. `ctx.principal` — pre-resolved (tests / session-ticket binding).
///   2. `peercred_principal(&ctx.peer)` — kernel-attested PID registry.
///   3. `ctx.mtls_principal().persona_id` — mTLS-attested bridge lane
///      (the principal carried in `DispatchSource::Bridge`).
///   4. `params["caller_persona_id"]` — legacy param-asserted fallback.
///
/// Returns `Err` when peercred lookup fails in a way that makes the
/// principal unverifiable (for example pid-less peercred on macOS) or no
/// principal can be resolved at all. A merely *unenrolled* PID falls
/// through to the legacy operator fallback so the general local operator
/// socket can still assert `caller_persona_id`.
pub async fn resolve_caller_principal(
    ctx: &RequestContext,
    params: &serde_json::Value,
) -> Result<String, (i32, String)> {
    // 1. Pre-resolved (injected by tests or session-ticket path).
    if let Some(p) = &ctx.principal {
        return Ok(p.clone());
    }

    // 2. Kernel-attested via peercred PID registry.
    if let Some(peer) = &ctx.peer {
        match peercred_principal(peer) {
            Ok(p) => return Ok(p),
            Err(crate::infra::handler::HandlerError::PrincipalNotEnrolled) => {
                // General operator socket lane: the peer is real, but this
                // PID has not enrolled a persona in the daemon. Fall through
                // to the explicit caller_persona_id surface so operator CLI
                // flows can still act on existing personas.
            }
            Err(e) => {
                // peercred lookup failed hard (for example pid-less peercred
                // on macOS) — do not fall through to weaker mechanisms.
                return Err(e.to_jsonrpc());
            }
        }
    }

    // 3. mTLS-attested principal from the cross-uid bridge lane.
    if let Some(mtls) = ctx.mtls_principal() {
        return Ok(mtls.persona_id.clone());
    }

    // 4. Legacy param-asserted fallback.
    if let Some(id) = params["caller_persona_id"].as_str() {
        return Ok(id.to_string());
    }

    Err((
        -32602,
        "missing 'caller_persona_id': no kernel-attested principal available \
         and no caller_persona_id param supplied"
            .to_string(),
    ))
}

/// Allow-listed caller -> vault namespace for the per-caller local-state
/// content key. Restricts `local_state_key_*` and binary-pin socket methods to
/// the known Ember binaries; a malicious caller cannot pollute the namespace
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

// NB: `emit_local_state_v2_receipt` was removed here per ADR 133 §76-78 —
// local_state.key_resolve / key_rotation are withdrawn from the Receipt lane
// and now emit immutable audit rows (see crate::infra::handlers::local_state).
// Do NOT reintroduce a signed-receipt path for those kinds. (Sweep 3 D2.)

/// Emit a signed v2 cohort-A Receipt for a grant lifecycle event (revoke,
/// etc.) via `issue_cohort_a_receipt`. Best-effort: failures are logged but
/// do not abort the caller's committed operation.
///
/// `kind` is the Receipt kind string (e.g. `"grant.revoke"`).
/// `body` is the pre-built JSON body for the Receipt envelope.
///
/// Call sites currently inline this pattern with site-specific parameters;
/// migration is deferred until each site can be expressed in <10 lines.
///
/// TODO(handler-split-slice-1): migrate revoke_grant to support::emit_v2_receipt_for_grant_event
/// TODO(handler-split-slice-1): migrate vault_get to support::emit_v2_receipt_for_grant_event
pub async fn emit_v2_receipt_for_grant_event(
    _ctx: &RequestContext,
    kind: &str,
    body: serde_json::Value,
) -> Result<(), (i32, String)> {
    let Some(identity) = current_identity() else {
        tracing::warn!(
            kind = %kind,
            "emit_v2_receipt_for_grant_event: daemon identity not initialised — skipping"
        );
        return Ok(());
    };
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    match issue_cohort_a_receipt(
        "",
        Vec::new(),
        None,
        TerminationAuthority::DaemonPersona,
        &identity.pubkey_hex(),
        Some(TerminationMeta {
            reason: core_events::receipt::TerminationReason::ExplicitRevoke,
            last_heartbeat_at: None,
            pid_alive_at_check: None,
        }),
        &signer,
    ) {
        Ok(mut envelope) => {
            envelope.body = body;
            tracing::info!(
                kind = %kind,
                receipt_id = %envelope.receipt_id,
                "emit_v2_receipt_for_grant_event: signed v2 Receipt emitted"
            );
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                kind = %kind,
                error = %e,
                "emit_v2_receipt_for_grant_event: failed to issue v2 Receipt — operation still committed"
            );
            Ok(())
        }
    }
}
