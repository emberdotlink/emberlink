//! Session lifecycle RPC helpers for the launcher-facing `register_session`
//! and `close_session` methods.

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::infra::{
    claim_journal::{
        close_session_scope_best_effort, close_summary_audit_fields,
        summarize_session_scope_best_effort,
    },
    handler::{RequestContext, mint_operator_presence_token},
    handlers::principal::trusted_request_persona,
    receipt::current_identity,
    store::DaemonStore,
};

/// Resolve the bundled workflow templates directory (design §Component 1).
///
/// Priority:
/// 1. `EMBER_WORKFLOW_TEMPLATES_ROOT` env override.
/// 2. `/usr/local/lib/ember/workflow-templates/` (prod install).
///
/// This shape mirrors the CLI-side resolver in
/// `emberlink_cli::launcher::claude_code::workflow_template_install_root`,
/// minus the exe-walk fallback (the daemon binary is at a different layout).
fn bundled_workflow_templates_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_WORKFLOW_TEMPLATES_ROOT")
        && !override_dir.is_empty()
    {
        return PathBuf::from(override_dir).join("workflow-templates");
    }
    PathBuf::from("/usr/local/lib/ember/workflow-templates")
}

/// Optional operator overlay directory:
/// `<config_dir>/emberlink/workflow-templates/`. Returns `None` when no
/// config dir is resolvable (rare).
fn overlay_workflow_templates_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|c| c.join("emberlink").join("workflow-templates"))
}

pub(crate) fn handle_register_session(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_name = params["persona"]
        .as_str()
        .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
    let launcher_pid = params["launcher_pid"]
        .as_u64()
        .ok_or((-32602, "missing 'launcher_pid' parameter".to_string()))?
        as u32;
    // design §Component 3 — optional workflow template chosen by the
    // launcher at session-open. When `Some`, the daemon resolves the
    // template, issues a `WorkflowGrant` via
    // `workflow_grant::save_if_absent`, and stamps `workflow_id` /
    // `workflow_template` onto the session meta. When `None` (or empty),
    // the legacy per-action / JIT chain governs `broker.resolve`.
    let workflow_template_name = params["workflow_template"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;

    let persona = resolve_register_session_persona(store, ctx, persona_name)?;
    let active_grant = resolve_register_session_active_grant(store, &persona, persona_name)?;
    crate::infra::interactive_unlock::ensure_vault_for_session_open(store)
        .map_err(|msg| (-32030, msg))?;

    // Resolve the workflow template BEFORE generating the session id so a
    // template-resolution failure does not leave a half-opened session on
    // disk. NotFound / parse errors surface as -32602 (invalid params).
    let resolved_template = match workflow_template_name.as_deref() {
        Some(name) => Some(resolve_workflow_template(name)?),
        None => None,
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let session_id = format!("sess_{:032x}", nanos);

    // Mint a workflow_id ULID-shape (nanos hex) when a template was selected.
    let workflow_id = resolved_template
        .as_ref()
        .map(|_| format!("wfg_{:032x}", nanos));

    let meta = core_state::sessions::SessionMeta {
        session_id: session_id.clone(),
        persona: persona.id.clone(),
        grant_id: active_grant.id.clone(),
        started_at: chrono::Utc::now(),
        launcher_pid,
        // design §Component 3 — workflow-grant attachment. Both fields are
        // populated together (Some/Some) when the launcher selected a
        // template, or together None (per the legacy path).
        workflow_id: workflow_id.clone(),
        workflow_template: resolved_template.as_ref().map(|t| t.name.clone()),
    };

    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    session_store
        .create(&meta)
        .map_err(|e| (-32000, format!("create session: {e}")))?;
    crate::infra::interactive_unlock::acquire_session_pin(&session_id);

    // Issue the WorkflowGrant sidecar when a template was selected. The
    // grant's `presence_proof_ref` is anchored to the session-open
    // presence token's UID + scope class (the operator already Touch
    // ID'd to satisfy `register_session`'s OperatorPresence gate).
    if let (Some(template), Some(wf_id)) = (resolved_template.as_ref(), workflow_id.as_ref())
        && let Err(e) = issue_workflow_grant(
            store,
            sessions_dir,
            &session_id,
            wf_id,
            template,
            &persona.id,
            ctx,
        )
    {
        // Clean up the session meta on grant-issue failure so the operator
        // sees a structured error instead of a half-opened session.
        // Adversarial HIGH-2 fix (2026-05-22): also release the session
        // pin. Pre-fix the pin acquired at line 110 leaked on every
        // grant-issuance failure; pins gate `vault_lock` (last-pin
        // release fires the grace window), so leaked pins keep the
        // vault unlock-eligible longer than design §intends.
        let _ = session_store.close(&session_id);
        let _ = crate::infra::interactive_unlock::release_session_pin(&session_id);
        return Err(e);
    }

    let workflow_log_suffix = match &workflow_id {
        Some(wf_id) => format!(
            " workflow_id={wf_id} workflow_template={}",
            resolved_template
                .as_ref()
                .map(|t| t.name.as_str())
                .unwrap_or("?"),
        ),
        None => String::new(),
    };
    let _ = store.log_event(
        Some(&persona.id),
        "session.opened",
        None,
        "ok",
        Some(&format!(
            "session_id={session_id} grant_id={}{workflow_log_suffix}",
            active_grant.id
        )),
    );

    let proxy_url = match &ctx.llm_proxy_url {
        Some(url) => url.clone(),
        None => {
            tracing::warn!(
                "register_session: llm_proxy_url absent from RequestContext \
                 (SocketListener.with_llm_proxy_url not called?) — \
                 falling back to hardcoded 8484; implementation-note-266"
            );
            "http://127.0.0.1:8484".to_string()
        }
    };
    let git_proxy_url = ctx.git_proxy_url.clone();
    let anthropic_gateway_bundle = anthropic_gateway_bundle_for_register_session(
        store,
        &active_grant,
        &persona.id,
        &proxy_url,
    );

    let mut response = json!({
        "session_id": session_id,
        "grant_id": active_grant.id,
        "proxy_url": proxy_url,
    });
    if let Some((anthropic_base_url, anthropic_custom_headers)) = anthropic_gateway_bundle {
        response["anthropic_base_url"] = json!(anthropic_base_url);
        response["anthropic_custom_headers"] = json!(anthropic_custom_headers);
    }
    if let Some(gpu) = git_proxy_url {
        response["git_proxy_url"] = json!(gpu);
    }
    // design §Component 3 — surface workflow grant identity to the launcher
    // so it can stamp `EMBER_WORKFLOW_ID` / `EMBER_WORKFLOW_TEMPLATE` into
    // the child env, and so `ember workflow show` / `ember workflow revoke`
    // can target the freshly-issued grant.
    if let Some(wf_id) = &workflow_id {
        response["workflow_id"] = json!(wf_id);
    }
    if let Some(template) = resolved_template.as_ref() {
        response["workflow_template"] = json!(template.name);
    }
    if let Some(token) = mint_operator_presence_token(ctx.peer.as_ref(), "register_session")? {
        response["presence_token"] = serde_json::to_value(token).map_err(|e| {
            (
                -32000,
                format!("register_session: encode presence_token: {e}"),
            )
        })?;
    }
    Ok(response)
}

/// Resolve a workflow template by name. Returns -32602 (invalid params) when
/// the name does not map to any bundled or overlay template; -32000 for I/O
/// or parse errors.
fn resolve_workflow_template(
    name: &str,
) -> Result<crate::infra::workflow_template::WorkflowTemplate, (i32, String)> {
    let bundled = bundled_workflow_templates_dir();
    let overlay = overlay_workflow_templates_dir();
    crate::infra::workflow_template::load_template(name, &bundled, overlay.as_deref()).map_err(
        |e| match e {
            crate::infra::workflow_template::WorkflowTemplateError::NotFound { .. } => (
                -32602,
                format!(
                    "register_session: workflow template '{name}' not found; \
                     run `ember workflow list` to see available templates"
                ),
            ),
            other => (
                -32000,
                format!("register_session: workflow template error: {other}"),
            ),
        },
    )
}

/// Issue the session's WorkflowGrant sidecar via the atomic
/// save-if-absent primitive.
fn issue_workflow_grant(
    store: &DaemonStore,
    sessions_dir: &std::path::Path,
    session_id: &str,
    workflow_id: &str,
    template: &crate::infra::workflow_template::WorkflowTemplate,
    persona_id: &str,
    ctx: &RequestContext,
) -> Result<(), (i32, String)> {
    use core_grants::workflow::{WorkflowGrant, WorkflowId};

    let grantor_id = ctx
        .peer
        .as_ref()
        .map(|p| format!("uid:{}", p.uid))
        .unwrap_or_else(|| "uid:unknown".to_string());

    // presence_proof_ref anchors the audit trail to the operator-presence
    // gate that already passed for this register_session call. The exact
    // contents are advisory — a future enhancement may attach the full
    // PresenceToken envelope id; for now we record the scope+uid pair so
    // a later auditor can correlate against the daemon's presence log.
    let presence_proof_ref = format!(
        "register_session:{}",
        ctx.peer
            .as_ref()
            .map(|p| format!("uid={}", p.uid))
            .unwrap_or_else(|| "uid=unknown".to_string())
    );

    let now = chrono::Utc::now();
    let grant = WorkflowGrant::new(
        WorkflowId(workflow_id.to_string()),
        template.name.clone(),
        core_grants::grant::PrincipalId(grantor_id),
        persona_id.to_string(),
        template.scopes.clone(),
        template.excludes.clone(),
        template.ttl_secs,
        now,
        presence_proof_ref,
        None,
    )
    .map_err(|e| {
        (
            -32000,
            format!("register_session: construct WorkflowGrant: {e}"),
        )
    })?;

    crate::infra::workflow_grant::save_if_absent(sessions_dir, session_id, &grant).map_err(
        |e| match e {
            crate::infra::workflow_grant::SaveError::AlreadyActive { .. } => (
                -32003,
                format!("register_session: session '{session_id}' already has an active workflow grant"),
            ),
            crate::infra::workflow_grant::SaveError::AlreadyRevoked { .. } => (
                -32003,
                format!(
                    "register_session: session '{session_id}' had a revoked workflow grant; \
                     open a new session to issue a fresh one"
                ),
            ),
            crate::infra::workflow_grant::SaveError::Io(e) => (
                -32000,
                format!("register_session: persist workflow grant: {e}"),
            ),
        },
    )?;

    // Log the workflow grant issuance to the audit chain — auditors get
    // `workflow.granted` events with `workflow_id` / `template_name` so
    // the grant chain is reproducible without reading the sidecar.
    let _ = store.log_event(
        Some(persona_id),
        "workflow.granted",
        None,
        "ok",
        Some(&format!(
            "workflow_id={workflow_id} template={} session_id={session_id} ttl_secs={}",
            template.name, template.ttl_secs
        )),
    );

    Ok(())
}

pub(crate) fn handle_close_session(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let session_id = params["session_id"]
        .as_str()
        .ok_or((-32602, "missing 'session_id' parameter".to_string()))?;

    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;

    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    let meta = session_store
        .read(session_id)
        .map_err(|e| (-32000, format!("read session: {e}")))?
        .ok_or_else(|| {
            (
                -32004,
                format!("session '{session_id}' not found or already closed"),
            )
        })?;

    let identity = current_identity().ok_or((
        -32000,
        "daemon identity not initialised — cannot sign Receipt".to_string(),
    ))?;
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
    .map_err(|e| (-32000, format!("issue Receipt: {e}")))?;

    let receipt_id = envelope.receipt_id.clone();

    let session_dir = sessions_dir.join(session_id);
    let receipt_path = session_dir.join("receipt.json");
    let receipt_json = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| (-32000, format!("serialize Receipt JSON: {e}")))?;
    std::fs::write(&receipt_path, &receipt_json)
        .map_err(|e| (-32000, format!("persist Receipt: {e}")))?;

    // design §Component 3 / §C1 — cascade-revoke the session's workflow
    // grant when one was issued at session-open. The workflow grant lives
    // only as long as the session — keeping it active after `close_session`
    // would leak authority beyond the session boundary.
    let workflow_cascade_revoked = match crate::infra::workflow_grant::revoke(
        sessions_dir,
        session_id,
    ) {
        Ok(revoked) => revoked,
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "close_session: cascade-revoke workflow grant failed; \
                 session close continues but workflow grant may have leaked"
            );
            false
        }
    };
    if workflow_cascade_revoked
        && let (Some(wf_id), Some(template)) = (&meta.workflow_id, &meta.workflow_template)
    {
        let _ = store.log_event(
            Some(&meta.persona),
            "workflow.revoked",
            None,
            "session_close_cascade",
            Some(&format!(
                "workflow_id={wf_id} template={template} session_id={session_id} reason=session_close_cascade"
            )),
        );
    }

    session_store
        .close(session_id)
        .map_err(|e| (-32000, format!("close session: {e}")))?;
    let _ = crate::infra::interactive_unlock::release_session_pin(session_id);
    let claim_summary = close_session_scope_best_effort(store, session_id, "handle_close_session")
        .or(claim_summary);
    let mut details = format!(
        "session_id={session_id} grant_id={} grant_kept_active=true workflow_cascade_revoked={workflow_cascade_revoked}",
        meta.grant_id
    );
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
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .find(|persona| persona.name == asserted)
        .ok_or_else(|| (-32004, format!("persona '{asserted}' not found")))
}

fn resolve_register_session_persona(
    store: &DaemonStore,
    ctx: &RequestContext,
    asserted: &str,
) -> Result<crate::infra::persona::PersonaInfo, (i32, String)> {
    if let Some(trusted_principal) = trusted_request_persona(ctx).map_err(|e| e.to_jsonrpc())? {
        let persona = store.get_persona(&trusted_principal).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => (
                -32004,
                format!(
                    "register_session: trusted principal '{}' not found",
                    trusted_principal
                ),
            ),
            other => (-32000, other.to_string()),
        })?;
        if !asserted_persona_matches(&persona, asserted) {
            tracing::warn!(
                trusted_persona_id = %persona.id,
                trusted_persona_name = %persona.name,
                asserted_persona = %asserted,
                "register_session refused: asserted persona does not match trusted principal"
            );
            return Err((
                -32004,
                "register_session: asserted persona does not match trusted principal".to_string(),
            ));
        }
        return Ok(persona);
    }

    resolve_persona_by_name_or_id(store, asserted)
}

fn resolve_register_session_active_grant(
    store: &DaemonStore,
    persona: &crate::infra::persona::PersonaInfo,
    asserted: &str,
) -> Result<crate::trust::grant::GrantInfo, (i32, String)> {
    let mut active_grants = store
        .list_active_grants()
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .filter(|grant| grant.persona_id == persona.id && grant.status == "active")
        .collect::<Vec<_>>();

    if let Some(idx) = active_grants
        .iter()
        .position(|grant| active_grant_supports_anthropic_gateway(store, grant))
    {
        return Ok(active_grants.swap_remove(idx));
    }

    active_grants
        .into_iter()
        .next()
        .ok_or_else(|| (-32004, format!("no active grant for persona '{asserted}'")))
}

fn is_anthropic_gateway_credential_name(credential_name: &str) -> bool {
    credential_name == "anthropic-key" || credential_name.starts_with("anthropic/")
}

fn active_grant_supports_anthropic_gateway(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
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
    for (_idx, stmt) in chain.statements() {
        match stmt.resource_type {
            core_grant_types::ResourceType::Credential => {
                has_matching_credential_stmt |= matches!(
                    &stmt.resource,
                    core_grant_types::ResourceSelector::Exact { value } if value == credential_name
                );
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

    has_matching_credential_stmt && has_anthropic_session_stmt
}

fn anthropic_gateway_bundle_for_register_session(
    store: &DaemonStore,
    active_grant: &crate::trust::grant::GrantInfo,
    persona_id: &str,
    proxy_url: &str,
) -> Option<(String, String)> {
    if !active_grant_supports_anthropic_gateway(store, active_grant) {
        return None;
    }

    let credential_name = active_grant.credential_name.as_str();
    let headers = format!(
        "X-Ember-Persona: {persona_id}\nX-Ember-Credential: {credential_name}\nX-Ember-Target: https://api.anthropic.com\nX-Ember-Grant-Id: {}",
        active_grant.id
    );
    Some((proxy_url.to_string(), headers))
}
