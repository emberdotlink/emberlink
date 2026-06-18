//! Approval and access-request RPC helpers.
//! CLASSIFICATION: PUBLIC

use std::cell::RefCell;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
use serde_json::Value;
use serde_json::json;

use crate::infra::{
    handler::{DispatchSource, RequestContext, check_user_presence_gate, notify_require_approval},
    rate_limit::RateLimiter,
    rpc_error::RpcError,
    store::DaemonStore,
};
use crate::trust::approval::DaemonApprovalStoreRef;
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::HighRiskOp;

pub(crate) async fn handle_submit(
    store: &DaemonStore,
    policy: &PolicyEngine,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
    let action = params["action"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'action'".to_string()))?;
    // approval_socket_arm_operator_presence_required - Per
    // adversarial-review 2026-05-19 CRIT-3. The socket dispatch path
    // for `submit_approval` previously (a) skipped `policy.evaluate`
    // entirely, letting an agent submit approval requests for actions
    // the policy was configured to Deny, and (b) accepted the
    // caller-supplied `risk_level` verbatim, allowing the audit trail
    // to lie about how risky the request actually was.
    //
    // The fix matches the create_grant arm's pattern:
    //   1. Evaluate policy on the action. Denied -> -32003 immediately.
    //   2. Use `eval.risk` for the audit row, ignore caller-supplied.
    //   3. Apply the per-op presence gate (same posture as create_grant)
    //      so submit-while-locked surfaces a re-auth prompt rather
    //      than silently filling the pending-approval queue.
    // Internal callers bypass.
    let eval = policy.evaluate(action);
    if !source.is_internal() {
        if matches!(eval.requirement, ApprovalRequirement::Denied) {
            return Err(RpcError::PolicyDenied(format!(
                "submit_approval: policy denies action {action:?} ({})",
                eval.matched_rule.unwrap_or_default()
            ))
            .into());
        }
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::ApprovalSubmit, override_qh)?;
    }
    // Risk level is policy-derived, not caller-supplied. This closes the
    // audit-truthfulness gap in CRIT-3.
    let risk_level = format!("{:?}", eval.risk).to_lowercase();
    let ttl_secs = params["ttl_secs"].as_u64();
    // PHASE-C-1-MIGRATED: trait crossing per ADR 113 §3
    let adapter = DaemonApprovalStoreRef::new(store);
    let metadata = SubmitMetadata {
        action: action.to_string(),
        ttl_secs,
        risk_level,
        tool_name: params["tool_name"].as_str().map(str::to_owned),
        target_host: params["target_host"].as_str().map(str::to_owned),
        target_url: params["target_url"].as_str().map(str::to_owned),
        agent_framework: params["agent_framework"].as_str().map(str::to_owned),
        max_delegation_depth: None,
        max_uses_per_hour: None,
        allowed_hours_start: None,
        allowed_hours_end: None,
        allowed_targets: None,
        budget: None,
        max_children_per_day: None,
        auto_delegate_scope_template: None,
    };
    let scope_obj = core_grant_types::approval::RequestedScope {
        capability: scope.to_string(),
        resource_id: None,
        constraints: vec![],
    };
    let request_id = adapter
        .submit_request(persona_id, credential_name, scope_obj, metadata)
        .await
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let req = store
        .get_approval(&request_id.0)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    notify_require_approval(store, &req);
    Ok(json!({"id": request_id.0, "status": req.status}))
}

/// target_state_anchor: handler_approval_split_moved
pub(crate) fn handle_propose_grant(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'scope'".to_string()))?;
    let action = params["action"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'action'".to_string()))?;
    let risk_level = params["risk_level"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'risk_level'".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let stmts_value = params["statements"]
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("missing 'statements' array".to_string()))?;
    let mut statements: Vec<core_grant_types::Statement> =
        Vec::with_capacity(stmts_value.len());
    for v in stmts_value {
        let s: core_grant_types::Statement = serde_json::from_value(v.clone())
            .map_err(|e| RpcError::InvalidParams(format!("invalid statement: {e}")))?;
        statements.push(s);
    }
    if statements.is_empty() {
        return Err(RpcError::InvalidParams("statements must not be empty".to_string()).into());
    }
    // approval_notify_fields_persisted - use the with_notify variant so
    // tool_name / target_host / target_url / agent_framework land in the DB
    // (not just in the returned struct) for subsequent get_approval calls.
    let req = store
        .propose_grant_with_notify(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            action,
            risk_level,
            statements,
            params["tool_name"].as_str().map(str::to_owned),
            params["target_host"].as_str().map(str::to_owned),
            params["target_url"].as_str().map(str::to_owned),
            params["agent_framework"].as_str().map(str::to_owned),
        )
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    notify_require_approval(store, &req);
    Ok(json!({
        "approval_id": req.id,
        "id": req.id,
        "status": req.status,
        "statement_count": req.composite_statements.as_ref().map(|v| v.len()).unwrap_or(0),
    }))
}

pub(crate) fn handle_list_pending(
    store: &DaemonStore,
    ctx: &RequestContext,
) -> Result<Value, (i32, String)> {
    let persona_scope = crate::infra::handlers::principal::team0_connect_only_persona_scope(
        ctx,
        "list_pending_approvals",
    )?;
    let requests = store
        .list_pending_approvals()
        .map_err(|e| (-32000, e.to_string()))?;
    let list: Vec<Value> = requests
        .iter()
        .filter(|request| match persona_scope.as_deref() {
            Some(persona_id) => request.persona_id == persona_id,
            None => true,
        })
        .map(|request| serde_json::to_value(request).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(list))
}

pub(crate) async fn handle_resolve(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or((-32602, "missing 'id'".to_string()))?;
    let decision = params["decision"]
        .as_str()
        .ok_or((-32602, "missing 'decision'".to_string()))?;

    if !source.is_internal() {
        let pending = store.get_approval(id).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                (-32004, format!("approval {id} not found"))
            }
            other => (-32000, other.to_string()),
        })?;
        let caller_principal =
            crate::infra::handlers::support::resolve_caller_principal(ctx, params).await?;
        if caller_principal == pending.persona_id {
            tracing::warn!(
                caller_persona_id = %caller_principal,
                approval_id = %id,
                "rejecting resolve_approval: caller is the submitter (self-approval forbidden)"
            );
            return Err((
                -32003,
                "resolve_approval: caller cannot approve own request \
                 (two-party invariant; the dashboard path is the \
                 operator-attested route for self-submitted approvals)"
                    .to_string(),
            ));
        }
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::ApprovalResolve, override_qh)?;
    }

    let outcome = match decision {
        "approve" => crate::trust::approval::ApprovalOutcome::Approved,
        "deny" => crate::trust::approval::ApprovalOutcome::Denied {
            reason: params["reason"]
                .as_str()
                .ok_or((-32602, "missing 'reason'".to_string()))?
                .to_string(),
        },
        "narrow" => crate::trust::approval::ApprovalOutcome::Narrowed {
            new_scope: params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?
                .to_string(),
        },
        "always" => crate::trust::approval::ApprovalOutcome::Always {
            scope: params["scope"].as_str().map(str::to_owned),
            expires_at: params["expires_at"].as_str().map(str::to_owned),
        },
        other => {
            return Err((
                -32602,
                format!("invalid 'decision': expected approve|deny|narrow|always, got {other}"),
            ));
        }
    };
    store.resolve_approval(id, &outcome).map_err(|e| match e {
        crate::infra::store::StoreError::NotFound => (-32004, format!("approval {id} not found")),
        other => (-32000, other.to_string()),
    })?;
    let resolved = store.get_approval(id).map_err(|e| match e {
        crate::infra::store::StoreError::NotFound => {
            (-32004, format!("approval {id} not found after resolve"))
        }
        other => (-32000, other.to_string()),
    })?;
    serde_json::to_value(&resolved)
        .map_err(|e| (-32000, format!("serialize resolved approval: {e}")))
}

pub(crate) async fn handle_request_access(
    store: &DaemonStore,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::access_requests::handle_request(store, policy, rate_limiter, params)
        .await
}

pub(crate) async fn handle_await_approval(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    crate::infra::handler::access_requests::handle_await_approval(store, ctx, params).await
}
