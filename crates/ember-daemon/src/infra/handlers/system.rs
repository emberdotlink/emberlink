//! Read-class system, audit, receipt, notification, and diagnostic RPC helpers.
//! CLASSIFICATION: PUBLIC

use serde_json::{Value, json};

use crate::infra::{handler::RequestContext, store::DaemonStore};

pub(crate) fn handle_ping() -> Result<Value, (i32, String)> {
    Ok(json!({"pong": true}))
}

pub(crate) fn handle_audit_verify_rpc(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::audit_receipts::handle_verify(store, params)
}

pub(crate) fn handle_audit_query_rpc(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::audit_receipts::handle_audit_query(store, ctx, params)
}

pub(crate) fn handle_receipt_query_rpc(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::audit_receipts::handle_receipt_query(store, ctx, params)
}

pub(crate) fn handle_list_receipts(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::audit_receipts::handle_list_receipts(store, ctx, params)
}

pub(crate) fn handle_get_receipt(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::audit_receipts::handle_get_receipt(store, ctx, params)
}

pub(crate) fn handle_expire_grants(store: &DaemonStore) -> Result<Value, (i32, String)> {
    crate::infra::handler::grant_lifecycle::handle_expire_stale(store)
}

pub(crate) fn handle_detect_anomalies(store: &DaemonStore) -> Result<Value, (i32, String)> {
    crate::infra::handler::grants::handle_detect_anomalies(store)
}

pub(crate) fn handle_poll_notifications(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
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

/// target_state_anchor: handler_system_split_moved
pub(crate) fn handle_daemon_persona() -> Result<Value, (i32, String)> {
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
