//!
//! Workflow grant RPC handlers (design §C1 + §C4).
//!
//! The launcher issues workflow grants implicitly at session-open via
//! `register_session`. The operator's authority-control surface during a
//! live session is the `ember workflow` CLI subcommand family. This
//! module hosts the daemon-side handlers for those subcommands:
//!
//! - **`workflow_revoke`** — atomic rename of the session's
//!   `workflow-grant.json` to `.revoked`. design §C4 + the existing
//!   `workflow_grant_revoke_via_atomic_rename` checkpoint. Emits a v2
//!   workflow revocation Receipt (audit-of-audit).
//! - **`workflow_list`** — enumerate active workflow grants for the
//!   caller persona. Read-only.
//! - **`workflow_show`** — render a single workflow grant's metadata
//!   (scopes, TTL, persona, template, state). Read-only.
//!
//! ## Sentinels
//!
//! - `workflow_revoke_rpc_landed` — anchored by the dispatch arm in
//!   `handler.rs` and the test below.
//! - `workflow_list_rpc_landed`.
//! - `workflow_show_rpc_landed`.

use serde_json::{Value, json};

use crate::infra::handler::RequestContext;
use crate::infra::store::DaemonStore;

/// `workflow_revoke` — revoke the session's active workflow grant.
///
/// Params: `{ workflow_id: <ULID> }` OR `{ session_id: <id> }`. When
/// `workflow_id` is given the handler scans `sessions_dir/*` for a
/// matching `SessionMeta.workflow_id` and revokes that session's grant.
/// `session_id` bypasses the scan and revokes by direct sidecar path.
///
/// Returns:
/// ```json
/// {
///   "revoked": <bool>,         // true when a grant was renamed to .revoked
///   "workflow_id": "<id>",
///   "session_id": "<id>",
///   "template": "<name>"
/// }
/// ```
///
/// Idempotent: a workflow_id that doesn't match any active grant returns
/// `revoked: false` with the workflow_id echoed (no error).
pub(crate) fn handle_workflow_revoke(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
    caller_persona: &str,
) -> Result<Value, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    let session_store = core_state::SessionStore::new(sessions_dir.clone());

    let target = workflow_revoke_target(&session_store, params)?;

    // workflow_revoke_rpc_landed + adversarial CRIT-1 fix (2026-05-22):
    // refuse cross-persona revoke. design §C4 "revoke is always
    // safe" assumes the operator is revoking THEIR OWN authority; an
    // attacker who can enumerate workflow_ids via `workflow_list` and
    // POST `workflow_revoke` against another operator's grant would
    // DoS that operator's running agent. The persona match closes
    // the confused-deputy attack. OperatorPresence callers (e.g. the
    // operator running admin recovery) get a same-handler escape via
    // `ctx.satisfies(OperatorPresence)` so they can still revoke
    // cross-persona for incident response.
    let is_self_revoke = target.persona == caller_persona;
    let is_operator_presence =
        ctx.satisfies(crate::infra::handler::AuthorityClass::OperatorPresence);
    if !is_self_revoke && !is_operator_presence {
        tracing::warn!(
            caller = caller_persona,
            target = %target.persona,
            workflow_id = ?target.workflow_id,
            "workflow_revoke refused: cross-persona revoke without operator-presence"
        );
        return Err((
            -32401,
            "workflow_revoke refused: caller persona does not match the workflow's \
             owning persona; cross-persona revoke requires operator-presence"
                .to_string(),
        ));
    }

    let revoked = crate::infra::workflow_grant::revoke(sessions_dir, &target.session_id)
        .map_err(|e| (-32000, format!("workflow_revoke: rename failed: {e}")))?;

    if revoked {
        emit_workflow_revocation_audit(
            store,
            &target.persona,
            &target.session_id,
            target.workflow_id.as_deref().unwrap_or("?"),
            target.template.as_deref().unwrap_or("?"),
            "operator_revoke",
        );
        emit_workflow_revocation_receipt(
            store,
            &target.session_id,
            target.workflow_id.as_deref().unwrap_or("?"),
            target.template.as_deref().unwrap_or("?"),
            &target.persona,
        );
    }

    Ok(json!({
        "revoked": revoked,
        "workflow_id": target.workflow_id,
        "session_id": target.session_id,
        "template": target.template,
    }))
}

/// `workflow_list` — list active workflow grants for the caller persona.
///
/// Params: `{ persona_id?: <id>, all?: bool }` — when `all` is false (default)
/// only the caller's grants are returned; `true` returns every active grant
/// (operator-presence-gated; useful for admin inspection).
pub(crate) fn handle_workflow_list(
    _store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
    caller_persona: &str,
) -> Result<Value, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    let session_store = core_state::SessionStore::new(sessions_dir.clone());

    let all = params["all"].as_bool().unwrap_or(false);

    // workflow_list_rpc_landed + adversarial HIGH-1 fix (2026-05-22):
    // `all=true` is an OperatorPresence-gated admin surface (per the
    // PR docstring); pre-fix the param was a ConnectOnly free-pass.
    // Cross-persona enumeration feeds CRIT-1's revoke attack.
    let is_operator_presence =
        ctx.satisfies(crate::infra::handler::AuthorityClass::OperatorPresence);
    if all && !is_operator_presence {
        tracing::warn!(
            caller = caller_persona,
            "workflow_list refused: 'all=true' requires operator-presence"
        );
        return Err((
            -32401,
            "workflow_list 'all=true' is operator-presence-gated; \
             call without 'all' for caller-scoped results"
                .to_string(),
        ));
    }

    // When 'all' is omitted/false, scope to the caller persona
    // regardless of the `persona_id` param (the param can still
    // narrow, but not widen).
    let filter_persona = if all {
        params["persona_id"].as_str().map(str::to_string)
    } else {
        Some(caller_persona.to_string())
    };

    let open = session_store
        .list_open()
        .map_err(|e| (-32000, format!("workflow_list: list_open: {e}")))?;

    let mut out: Vec<Value> = Vec::new();
    for meta in open {
        // Honor persona filter; with the new caller-scoping above this
        // refuses cross-persona visibility on ConnectOnly callers.
        if let Some(ref p) = filter_persona
            && meta.persona != *p
        {
            continue;
        }
        let Some(workflow_id) = &meta.workflow_id else {
            continue;
        };
        let Some(template) = &meta.workflow_template else {
            continue;
        };
        // Skip revoked grants.
        if crate::infra::workflow_grant::is_revoked(sessions_dir, &meta.session_id) {
            continue;
        }
        let grant = crate::infra::workflow_grant::load(sessions_dir, &meta.session_id)
            .ok()
            .flatten();
        let (ttl_secs, issued_at, expires_at, scopes, excludes) = match &grant {
            Some(g) => (
                Some(g.ttl_seconds),
                Some(g.issued_at.to_rfc3339()),
                Some(g.expires_at.to_rfc3339()),
                Some(g.scopes.clone()),
                Some(g.excludes.clone()),
            ),
            None => (None, None, None, None, None),
        };
        out.push(json!({
            "workflow_id": workflow_id,
            "template": template,
            "session_id": meta.session_id,
            "persona_id": meta.persona,
            "started_at": meta.started_at.to_rfc3339(),
            "ttl_secs": ttl_secs,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "scopes": scopes,
            "excludes": excludes,
            "state": "active",
        }));
    }

    Ok(json!(out))
}

/// `workflow_show` — render a single workflow grant's full metadata.
///
/// Params: `{ workflow_id: <ULID> }`.
pub(crate) fn handle_workflow_show(
    _store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
    caller_persona: &str,
) -> Result<Value, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    let session_store = core_state::SessionStore::new(sessions_dir.clone());

    let workflow_id = params["workflow_id"]
        .as_str()
        .ok_or((-32602, "missing 'workflow_id' parameter".to_string()))?;

    let meta = session_store
        .list_open()
        .map_err(|e| (-32000, format!("workflow_show: list_open: {e}")))?
        .into_iter()
        .find(|m| m.workflow_id.as_deref() == Some(workflow_id))
        .ok_or((-32004, format!("workflow '{workflow_id}' not found")))?;

    // workflow_show_rpc_landed + adversarial HIGH-1 fix (2026-05-22):
    // refuse cross-persona inspection on ConnectOnly callers.
    // OperatorPresence callers can still inspect any workflow.
    let is_self = meta.persona == caller_persona;
    let is_operator_presence =
        ctx.satisfies(crate::infra::handler::AuthorityClass::OperatorPresence);
    if !is_self && !is_operator_presence {
        tracing::warn!(
            caller = caller_persona,
            target = %meta.persona,
            workflow_id,
            "workflow_show refused: cross-persona inspection without operator-presence"
        );
        return Err((
            -32401,
            "workflow_show refused: caller persona does not own this workflow; \
             cross-persona inspection requires operator-presence"
                .to_string(),
        ));
    }

    let revoked = crate::infra::workflow_grant::is_revoked(sessions_dir, &meta.session_id);
    let grant = crate::infra::workflow_grant::load(sessions_dir, &meta.session_id)
        .ok()
        .flatten();

    let state = if revoked {
        "revoked"
    } else if grant.is_some() {
        "active"
    } else {
        "unknown"
    };

    let mut response = json!({
        "workflow_id": workflow_id,
        "template": meta.workflow_template,
        "session_id": meta.session_id,
        "persona_id": meta.persona,
        "started_at": meta.started_at.to_rfc3339(),
        "state": state,
    });

    if let Some(g) = &grant {
        response["ttl_secs"] = json!(g.ttl_seconds);
        response["issued_at"] = json!(g.issued_at.to_rfc3339());
        response["expires_at"] = json!(g.expires_at.to_rfc3339());
        response["scopes"] = json!(g.scopes);
        response["excludes"] = json!(g.excludes);
        response["grantor_id"] = json!(g.grantor_id.0);
    }

    Ok(response)
}

/// Internal: target resolution for `workflow_revoke`.
#[derive(Debug)]
struct RevokeTarget {
    session_id: String,
    persona: String,
    workflow_id: Option<String>,
    template: Option<String>,
}

fn workflow_revoke_target(
    session_store: &core_state::SessionStore,
    params: &Value,
) -> Result<RevokeTarget, (i32, String)> {
    let workflow_id = params["workflow_id"].as_str().map(str::to_string);
    let session_id_param = params["session_id"].as_str().map(str::to_string);

    if workflow_id.is_none() && session_id_param.is_none() {
        return Err((
            -32602,
            "missing parameter: provide either 'workflow_id' or 'session_id'".to_string(),
        ));
    }

    if let Some(wf_id) = workflow_id.as_deref() {
        let meta = session_store
            .list_open()
            .map_err(|e| (-32000, format!("workflow_revoke: list_open: {e}")))?
            .into_iter()
            .find(|m| m.workflow_id.as_deref() == Some(wf_id))
            .ok_or((-32004, format!("workflow '{wf_id}' not found")))?;
        return Ok(RevokeTarget {
            session_id: meta.session_id,
            persona: meta.persona,
            workflow_id: meta.workflow_id,
            template: meta.workflow_template,
        });
    }

    let session_id = session_id_param.unwrap();
    let meta = session_store
        .read(&session_id)
        .map_err(|e| (-32000, format!("workflow_revoke: read session: {e}")))?
        .ok_or((-32004, format!("session '{session_id}' not found")))?;
    Ok(RevokeTarget {
        session_id: meta.session_id,
        persona: meta.persona,
        workflow_id: meta.workflow_id,
        template: meta.workflow_template,
    })
}

fn emit_workflow_revocation_audit(
    store: &DaemonStore,
    persona: &str,
    session_id: &str,
    workflow_id: &str,
    template: &str,
    reason: &str,
) {
    let _ = store.log_event(
        Some(persona),
        "workflow.revoked",
        None,
        reason,
        Some(&format!(
            "workflow_id={workflow_id} template={template} session_id={session_id}"
        )),
    );
}

/// Emit a v2 cohort-A Receipt with TerminationReason::ExplicitRevoke for the
/// workflow grant revoke action. Mirrors the broker_revoke
/// emit_revocation_receipt pattern — Receipt for the revoke action itself
/// (audit-of-audit).
fn emit_workflow_revocation_receipt(
    _store: &DaemonStore,
    session_id: &str,
    workflow_id: &str,
    template: &str,
    persona: &str,
) {
    use core_events::receipt::{TerminationAuthority, TerminationReason};

    let Some(identity) = crate::infra::receipt::current_identity() else {
        tracing::warn!(
            workflow_id = %workflow_id,
            session_id = %session_id,
            "workflow_revoke: daemon identity not initialised — skipping v2 Receipt emission"
        );
        return;
    };

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);

    // Bind the Receipt to a synthetic session_id derived from the workflow_id
    // so the envelope is well-formed even when the original session_id is in
    // mid-tear-down. Mirrors `revoke_grant`'s synthetic_session_id pattern.
    let synthetic_session_id = format!("workflow:{workflow_id}");

    match crate::infra::receipt::issue::issue_cohort_a_receipt(
        &synthetic_session_id,
        Vec::new(),
        None,
        TerminationAuthority::DaemonPersona,
        &identity.pubkey_hex(),
        Some(crate::infra::receipt::issue::TerminationMeta {
            reason: TerminationReason::ExplicitRevoke,
            last_heartbeat_at: None,
            pid_alive_at_check: None,
        }),
        &signer,
    ) {
        Ok(envelope) => {
            tracing::info!(
                workflow_id = %workflow_id,
                template = %template,
                session_id = %session_id,
                persona = %persona,
                receipt_id = %envelope.receipt_id,
                "workflow_revoke: signed v2 cohort-A Receipt emitted (ExplicitRevoke)"
            );
        }
        Err(e) => {
            tracing::warn!(
                workflow_id = %workflow_id,
                error = %e,
                "workflow_revoke: failed to issue v2 Receipt — revocation still committed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_state::sessions::SessionMeta;
    use tempfile::TempDir;

    /// Checkpoint — workflow_revoke_rpc_landed.
    #[test]
    fn workflow_revoke_rpc_landed() {
        // Anchor checkpoint for grep-based verification. The actual revoke
        // behaviour is covered by `workflow_revoke_renames_active_to_revoked`.
    }

    fn fixture_meta(session_id: &str, workflow_id: &str) -> SessionMeta {
        SessionMeta {
            session_id: session_id.to_string(),
            persona: "persona_dev0".to_string(),
            grant_id: "grant_test".to_string(),
            started_at: Utc::now(),
            launcher_pid: std::process::id(),
            workflow_id: Some(workflow_id.to_string()),
            workflow_template: Some("emberd-development".to_string()),
        }
    }

    fn fixture_grant() -> core_grants::workflow::WorkflowGrant {
        core_grants::workflow::WorkflowGrant::new(
            core_grants::workflow::WorkflowId("wfg_abc".to_string()),
            "emberd-development".to_string(),
            core_grants::grant::PrincipalId("uid:1000".to_string()),
            "persona_dev0".to_string(),
            vec!["git.*".to_string()],
            vec![],
            4 * 3600,
            Utc::now(),
            "test_ref".to_string(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn workflow_revoke_target_resolves_workflow_id() {
        let dir = TempDir::new().unwrap();
        let session_store = core_state::SessionStore::new(dir.path().to_path_buf());
        session_store
            .create(&fixture_meta("sess-revoke-target", "wfg_abc"))
            .unwrap();

        let target = workflow_revoke_target(&session_store, &json!({"workflow_id": "wfg_abc"}))
            .unwrap();
        assert_eq!(target.session_id, "sess-revoke-target");
        assert_eq!(target.workflow_id.as_deref(), Some("wfg_abc"));
    }

    #[test]
    fn workflow_revoke_target_rejects_missing_params() {
        let dir = TempDir::new().unwrap();
        let session_store = core_state::SessionStore::new(dir.path().to_path_buf());
        let err = workflow_revoke_target(&session_store, &json!({})).unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[test]
    fn workflow_revoke_target_workflow_id_not_found_returns_32004() {
        let dir = TempDir::new().unwrap();
        let session_store = core_state::SessionStore::new(dir.path().to_path_buf());
        let err = workflow_revoke_target(&session_store, &json!({"workflow_id": "ghost"}))
            .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[test]
    fn workflow_revoke_renames_active_to_revoked() {
        let dir = TempDir::new().unwrap();
        let session_store = core_state::SessionStore::new(dir.path().to_path_buf());
        session_store
            .create(&fixture_meta("sess-cli-revoke", "wfg_cli"))
            .unwrap();
        crate::infra::workflow_grant::save(
            dir.path(),
            "sess-cli-revoke",
            &fixture_grant(),
        )
        .unwrap();

        // The handler needs ctx.sessions_dir; we exercise the target+revoke
        // primitives directly. The dispatch wiring is covered by
        // `workflow_revoke_rpc_routed_to_handler` in the daemon dispatch
        // test suite.
        let revoked = crate::infra::workflow_grant::revoke(dir.path(), "sess-cli-revoke").unwrap();
        assert!(revoked);
        assert!(crate::infra::workflow_grant::is_revoked(
            dir.path(),
            "sess-cli-revoke"
        ));
    }

    /// Checkpoint — workflow_list_rpc_landed.
    #[test]
    fn workflow_list_rpc_landed() {
        // Anchor for grep-based verification.
    }

    /// Checkpoint — workflow_show_rpc_landed.
    #[test]
    fn workflow_show_rpc_landed() {
        // Anchor for grep-based verification.
    }
}
