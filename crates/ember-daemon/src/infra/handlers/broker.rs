//! Broker-facing RPC routing helpers.
//! CLASSIFICATION: PUBLIC

use std::cell::RefCell;

use serde_json::Value;

use crate::infra::{
    handler::RequestContext, rate_limit::RateLimiter, store::DaemonStore,
};

fn broker_peercred_principal_for_handler(
    ctx: &RequestContext,
) -> Option<&crate::infra::runtime::PeerCredPrincipal> {
    // Bridge-authenticated callers reach the daemon over the local ember-rpc
    // sibling socket. On that lane, `peer_cred_principal` describes the
    // sibling service rather than the workload identity that was already
    // authenticated via mTLS and stamped into the `Bridge` source's principal.
    if ctx.mtls_principal().is_some() {
        None
    } else {
        ctx.peer_cred_principal.as_ref()
    }
}

/// target_state_anchor: handler_broker_split_moved
pub(crate) async fn handle_issue(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_issue(
        broker_peercred_principal_for_handler(ctx),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_revoke(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_revoke(
        broker_peercred_principal_for_handler(ctx),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_list(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_list(
        broker_peercred_principal_for_handler(ctx),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_resolve(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_resolve(
        broker_peercred_principal_for_handler(ctx),
        store,
        ctx.sessions_dir.as_deref(),
        params,
    )
    .await
}

pub(crate) async fn handle_refresh_cert(
    store: &DaemonStore,
    rate_limiter: &RefCell<RateLimiter>,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_refresh_cert(
        broker_peercred_principal_for_handler(ctx),
        ctx.mtls_principal(),
        store,
        rate_limiter,
        params,
    )
    .await
}

pub(crate) async fn handle_exec(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_exec_with_sessions(
        broker_peercred_principal_for_handler(ctx),
        store,
        ctx.sessions_dir.as_deref(),
        params,
    )
    .await
}

pub(crate) fn handle_subprocess_audit_log(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::handle_subprocess_audit_log(
        store,
        params,
        ctx.peer_cred_principal.as_ref(),
    )
}

pub(crate) async fn handle_mint_gh_token(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_mint_gh_token(store, params).await
}

pub(crate) async fn handle_mint_sub_persona(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_mint_sub_persona(store, params).await
}

pub(crate) async fn handle_register_pid_watcher(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_register_pid_watcher(store, params).await
}

pub(crate) async fn handle_request_presence_proof(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_request_presence_proof(
        ctx.peer_cred_principal.as_ref(),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_bindings_register(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_bindings_register(
        ctx.peer_cred_principal.as_ref(),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_bindings_list(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_bindings_list(
        ctx.peer_cred_principal.as_ref(),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_bindings_remove(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_bindings_remove(
        ctx.peer_cred_principal.as_ref(),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_bindings_move(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::broker::handler::handle_broker_bindings_move(
        ctx.peer_cred_principal.as_ref(),
        store,
        params,
    )
    .await
}

pub(crate) async fn handle_registry_status() -> Result<Value, (i32, String)> {
    let registry = crate::broker::handler::current_registry().ok_or_else(|| {
        (
            -32000,
            "broker registry not initialised — start emberd to populate".to_string(),
        )
    })?;
    crate::broker::handler::registry_status_with_registry(registry).await
}

pub(crate) async fn handle_github_status() -> Result<Value, (i32, String)> {
    let registry = crate::broker::handler::current_registry().ok_or_else(|| {
        (
            -32000,
            "broker registry not initialised — start emberd to populate".to_string(),
        )
    })?;
    let resolver = crate::broker::authority::BrokerAuthorityResolver::current().ok_or_else(|| {
        (
            -32000,
            "broker authority resolver not initialised — start emberd to populate".to_string(),
        )
    })?;
    crate::broker::handler::github_status_with_registry_and_resolver(registry, resolver.as_ref())
        .await
}
