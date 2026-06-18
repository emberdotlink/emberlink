//! Persona RPC helpers for persona lifecycle and init-first-grant methods.
//! CLASSIFICATION: PUBLIC

use serde_json::{Value, json};

use crate::infra::{
    handler::{DispatchSource, RequestContext, enroll_pid_persona},
    rpc_error::RpcError,
    store::DaemonStore,
};

pub(crate) async fn handle_evaluate_tool_call(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona = params["persona"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona' parameter".to_string()))?;
    let tool_name = params["tool_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'tool_name' parameter".to_string()))?;
    let session_id = params["session_id"].as_str();
    let grant_id = params["grant_id"].as_str();
    let tool_params = &params["params"];
    let decision = store
        .reserve_payment_tool_call(persona, tool_name, tool_params, session_id, grant_id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    serde_json::to_value(&decision)
        .map_err(|e| RpcError::Internal(format!("serialize ToolCallDecision: {e}")).into())
}

pub(crate) async fn handle_create_persona(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let name = params["name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'name' parameter".to_string()))?;
    // Launcher onboarding creates an agent persona from an operator CLI process;
    // ordinary agent-created personas still bind the caller PID.
    let enroll_peer_pid = params["enroll_peer_pid"].as_bool().unwrap_or(true);
    let info = store
        .create_persona(name)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    // C39-HANDLER-C3-FULL: enroll the (peer_pid, persona_id) so subsequent
    // `delegate_grant` calls from this PID resolve back to the persona that
    // just claimed it. Only applies to Socket callers; Internal callers don't
    // have a real peer identity and shouldn't pollute the registry.
    if !source.is_internal()
        && enroll_peer_pid
        && let Some(peer) = &ctx.peer
        && let Some(pid) = peer.pid
    {
        enroll_pid_persona(pid, &info.id);
    }
    Ok(json!({"id": info.id, "name": info.name, "public_key": info.public_key}))
}

pub(crate) fn handle_build_init_first_grant_receipt(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    let signer = store
        .persona_signer(persona_id)
        .map_err(|e| RpcError::Internal(format!("persona signer: {e}")))?;
    let file =
        crate::infra::init_first_grant::build_first_grant_receipt_file(persona_id, &signer)
            .map_err(|e| RpcError::Internal(format!("build init first-grant receipt: {e}")))?;
    serde_json::to_value(file).map_err(|e| {
        RpcError::Internal(format!("serialize init first-grant receipt: {e}")).into()
    })
}

pub(crate) async fn handle_list_personas(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let personas = store
        .list_personas()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let trusted_persona = crate::infra::handlers::principal::team0_connect_only_persona_scope(
        ctx,
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

/// target_state_anchor: handler_personas_split_moved
pub(crate) async fn handle_revoke_persona(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id' parameter".to_string()))?;
    // revoke_persona_authority_check — Internal callers (admin CLI, test
    // harness, recovery) bypass; all socket callers must be the revocation
    // target (self-revoke). Operator-role extension tracked separately.
    if !source.is_internal() {
        let principal =
            crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
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

pub(crate) async fn handle_retire_for_reenroll(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id' parameter".to_string()))?;
    let expected_name = params["expected_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'expected_name' parameter".to_string()))?;
    // Same authority posture as revoke_persona: this is a targeted self-retire
    // used by recovery/onboarding to free a default slot.
    if !source.is_internal() {
        let principal =
            crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
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
