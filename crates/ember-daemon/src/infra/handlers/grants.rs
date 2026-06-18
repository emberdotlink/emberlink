//! Dispatch-facing grant lifecycle and projection RPC helpers.
//! CLASSIFICATION: PUBLIC

use serde_json::{Value, json};
use tokio::sync::broadcast;

use core_event_types::ActionSelector;

use crate::infra::{
    events::GrantEvent,
    handler::{DispatchSource, RequestContext, VerifiedPresenceProof},
    store::DaemonStore,
};
use crate::trust::policy::PolicyEngine;

pub(crate) async fn handle_create_grant(
    store: &DaemonStore,
    policy: &PolicyEngine,
    source: &DispatchSource,
    params: &Value,
    verified_presence_proof: Option<&VerifiedPresenceProof>,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_create(
        store,
        policy,
        source,
        params,
        verified_presence_proof,
    )
    .await
}

/// target_state_anchor: handler_grants_split_moved
pub(crate) async fn handle_delegate_grant(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_delegate(store, ctx, source, params).await
}

pub(crate) fn handle_list_grants(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grants::handle_list_grants(store, ctx, params)
}

pub(crate) fn handle_revoke_grant(
    store: &DaemonStore,
    ctx: &RequestContext,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_revoke(store, ctx, events_tx, params)
}

pub(crate) fn handle_revoke_statement(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_revoke_statement(store, params)
}

pub(crate) fn handle_evaluate_grant(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_evaluate(store, ctx, params)
}

pub(crate) fn handle_extend_grant(
    store: &DaemonStore,
    policy: &PolicyEngine,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_extend(store, policy, source, params)
}

pub(crate) fn handle_grant_status(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grants::handle_status(store, ctx, params)
}

pub(crate) fn handle_grant_summary(store: &DaemonStore) -> Result<Value, (i32, String)> {
    crate::infra::handler::grants::handle_summary(store)
}

pub(crate) fn handle_grant_budget_status(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::grants::handle_budget_status(store, ctx, params)
}

pub(crate) fn handle_create_standing_grant(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
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

pub(crate) fn handle_list_standing_grants(
    store: &DaemonStore,
    ctx: &RequestContext,
) -> Result<Value, (i32, String)> {
    let persona_scope =
        crate::infra::handlers::principal::team0_connect_only_persona_scope(
            ctx,
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
            json!({
                "id": g.id,
                "persona_id": g.persona_id,
                "action_selector": g.action_selector,
                "scope": g.scope,
                "expires_at": g.expires_at,
            })
        })
        .collect();
    Ok(Value::Array(list))
}

pub(crate) fn handle_remove_standing_grant(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or((-32602, "missing 'id'".to_string()))?;
    store
        .remove_standing_grant(id)
        .map_err(|e| (-32000, e.to_string()))?;
    Ok(json!({"removed": true}))
}
