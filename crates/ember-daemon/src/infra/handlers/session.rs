//! Session lifecycle RPC helpers for the launcher-facing `register_session`
//! and `close_session` methods.

use serde_json::{Value, json};

use crate::infra::{
    handler::{RequestContext, mint_operator_presence_token},
    handlers::principal::trusted_request_persona,
    receipt::current_identity,
    store::DaemonStore,
};

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

    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;

    let persona = resolve_register_session_persona(store, ctx, persona_name)?;
    let active_grant = resolve_register_session_active_grant(store, &persona, persona_name)?;
    crate::infra::interactive_unlock::ensure_vault_for_session_open(store)
        .map_err(|msg| (-32030, msg))?;

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
        // design §Component 3 — workflow-grant attachment lands when
        // the launcher implements the prompt UX
        // (implementation-note-159). Existing sessions open
        // without a workflow template selected.
        workflow_id: None,
        workflow_template: None,
    };

    let session_store = core_state::SessionStore::new(sessions_dir.clone());
    session_store
        .create(&meta)
        .map_err(|e| (-32000, format!("create session: {e}")))?;
    crate::infra::interactive_unlock::acquire_session_pin(&session_id);

    let _ = store.log_event(
        Some(&persona.id),
        "session.opened",
        None,
        "ok",
        Some(&format!(
            "session_id={session_id} grant_id={}",
            active_grant.id
        )),
    );

    let proxy_url = match &ctx.llm_proxy_url {
        Some(url) => url.clone(),
        None => {
            tracing::warn!(
                "register_session: llm_proxy_url absent from RequestContext \
                 (SocketListener.with_llm_proxy_url not called?) — \
                 falling back to hardcoded 8484; implementation-note-259"
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
    if let Some(token) = mint_operator_presence_token(ctx.peer.as_ref())? {
        response["presence_token"] = serde_json::to_value(token).map_err(|e| {
            (
                -32000,
                format!("register_session: encode presence_token: {e}"),
            )
        })?;
    }
    Ok(response)
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
    let _ = crate::infra::interactive_unlock::release_session_pin(session_id);

    let _ = store.log_event(
        Some(&meta.persona),
        "session.closed",
        None,
        "clean_exit",
        Some(&format!(
            "session_id={session_id} grant_id={} grant_kept_active=true",
            meta.grant_id
        )),
    );

    Ok(json!({
        "closed": true,
        "session_id": session_id,
        "receipt_id": receipt_id,
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
