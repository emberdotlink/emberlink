//! Runtime authority lane open/attach helpers.
//!
//! A runtime lane is the live authority coordinate for launcher sessions:
//! Runtime Persona + its current standing grant + the one Caller Binding that
//! attachments use. This Module keeps that product/runtime concept separate
//! from the `register_session` JSON-RPC adapter.

use crate::infra::{rpc_error::RpcError, store::DaemonStore};

#[derive(Debug, Clone)]
pub(super) struct RuntimeLaneOpen {
    pub(super) runtime_persona_id: String,
    pub(super) runtime_grant_id: String,
    pub(super) durable_persona_id: String,
    pub(super) caller_binding_id: String,
    pub(super) authority_strict: bool,
    pub(super) delegation_id: Option<String>,
    pub(super) delegation_template: Option<String>,
}

pub(super) fn resolve_runtime_attach_target(
    session_store: &core_state::SessionStore,
    runtime_persona_id: &str,
    durable_persona_id: &str,
) -> Result<RuntimeLaneOpen, (i32, String)> {
    let meta = session_store
        .find_open_by_runtime_persona(runtime_persona_id)
        .map_err(|e| {
            RpcError::Internal(format!("register_session: list open attachments: {e}"))
        })?
        .ok_or_else(|| {
            RpcError::NotFound(format!(
                "register_session: runtime persona '{}' is not live; launch a fresh runtime or attach to an active one",
                runtime_persona_id
            ))
        })?;

    if meta.durable_persona.as_deref() != Some(durable_persona_id) {
        return Err(RpcError::NotFound(
            "register_session: attach target belongs to a different durable persona".to_string(),
        )
        .into());
    }
    let caller_binding_id = meta.caller_binding_id.clone().ok_or_else(|| {
        RpcError::Internal("register_session: attach target missing caller_binding_id".to_string())
    })?;
    Ok(RuntimeLaneOpen {
        runtime_persona_id: meta.persona,
        runtime_grant_id: meta.grant_id,
        durable_persona_id: durable_persona_id.to_string(),
        caller_binding_id,
        authority_strict: meta.authority_strict,
        delegation_id: meta.delegation_id,
        delegation_template: meta.delegation_template,
    })
}

pub(super) fn mint_runtime_lane(
    store: &DaemonStore,
    durable_persona: &crate::infra::persona::PersonaInfo,
    parent_grant: &crate::trust::grant::GrantInfo,
    caller_binding_id: &str,
    authority_strict: bool,
    github_needs: Option<&[String]>,
) -> Result<RuntimeLaneOpen, (i32, String)> {
    let child_ttl_secs = derive_runtime_child_ttl_secs(parent_grant)?;
    let (runtime_persona, runtime_grant) = crate::infra::persona::runtime_persona_two_phase_commit(
        store,
        &durable_persona.name,
        &parent_grant.id,
        &parent_grant.scope,
        child_ttl_secs,
        github_needs,
    )
    .map_err(|e| RpcError::Internal(format!("register_session: mint runtime persona lane: {e}")))?;
    Ok(RuntimeLaneOpen {
        runtime_persona_id: runtime_persona.id,
        runtime_grant_id: runtime_grant.id,
        durable_persona_id: durable_persona.id.clone(),
        caller_binding_id: caller_binding_id.to_string(),
        authority_strict,
        delegation_id: None,
        delegation_template: None,
    })
}

fn derive_runtime_child_ttl_secs(
    parent_grant: &crate::trust::grant::GrantInfo,
) -> Result<u64, (i32, String)> {
    let expires_at = parent_grant.expires_at.as_deref().ok_or_else(|| {
        RpcError::PresenceLocked(format!(
            "register_session: active grant '{}' is not bounded; rerun `ember init` to provision a bounded, runtime-delegable grant",
            parent_grant.id
        ))
    })?;
    let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|e| RpcError::Internal(format!("register_session: parse grant expiry: {e}")))?
        .with_timezone(&chrono::Utc);
    let remaining = expiry
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    if remaining <= 0 {
        return Err(RpcError::PresenceLocked(format!(
            "register_session: active grant '{}' is already expired; mint a fresh durable grant before launching",
            parent_grant.id
        ))
        .into());
    }
    Ok(remaining as u64)
}
