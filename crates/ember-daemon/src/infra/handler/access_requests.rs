use std::cell::RefCell;
use std::time;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
use serde_json::{Value, json};

use crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::approval::DaemonApprovalStoreRef;
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};

use super::{RequestContext, notify_require_approval};

pub(super) async fn handle_request(
    store: &DaemonStore,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id'".to_string()))?;
    let credential_name = params["credential_name"]
        .as_str()
        .ok_or((-32602, "missing 'credential_name'".to_string()))?;
    let scope = params["scope"]
        .as_str()
        .ok_or((-32602, "missing 'scope'".to_string()))?;
    let action = params["action"]
        .as_str()
        .ok_or((-32602, "missing 'action'".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();

    // Pre-evaluation rate limit check (#69C.4). Runs before standing
    // grant lookup and policy evaluation. On rejection the response
    // intentionally avoids disclosing which rule would have matched:
    // only the rate-limit fact is surfaced.
    if !rate_limiter.borrow_mut().check_action(persona_id, action) {
        return Ok(json!({
            "status": "denied",
            "decision": "deny",
            "reason": "rate_spike",
        }));
    }

    // Check standing grants first.
    if store
        .check_standing_grant(persona_id, action)
        .map_err(|e| (-32000, e.to_string()))?
    {
        let grant = store
            .create_grant(persona_id, credential_name, scope, ttl_secs)
            .map_err(|e| (-32000, e.to_string()))?;
        let _ = store.log_event(
            Some(persona_id),
            "grant.issued",
            Some(credential_name),
            "allowed",
            Some(
                &serde_json::json!({
                    "grant_id": grant.id,
                    "scope": scope,
                    "ttl_secs": ttl_secs,
                    "source": "standing_grant",
                })
                .to_string(),
            ),
        );
        return Ok(json!({
            "status": "approved",
            "source": "standing_grant",
            "grant_id": grant.id,
        }));
    }

    let eval = policy.evaluate(action);
    let risk_str = format!("{:?}", eval.risk).to_lowercase();

    match eval.requirement {
        ApprovalRequirement::Auto => {
            let grant = store
                .create_grant(persona_id, credential_name, scope, ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;
            let _ = store.log_event(
                Some(persona_id),
                "grant.issued",
                Some(credential_name),
                "allowed",
                Some(
                    &serde_json::json!({
                        "grant_id": grant.id,
                        "scope": scope,
                        "ttl_secs": ttl_secs,
                        "source": "request_access",
                    })
                    .to_string(),
                ),
            );
            Ok(json!({
                "status": "approved",
                "grant_id": grant.id,
                "decision": "auto_approve",
                "risk": risk_str,
            }))
        }
        ApprovalRequirement::Required => {
            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            // implementation-note-13:
            // request_access does not surface grant-shaping fields on its
            // socket params, so default to None.
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs,
                risk_level: risk_str.clone(),
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
                .map_err(|e| (-32000, e.to_string()))?;
            let req = store
                .get_approval(&request_id.0)
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({
                "status": "pending",
                "approval_id": request_id.0,
                "decision": "require_approval",
                "risk": risk_str,
            }))
        }
        ApprovalRequirement::Denied => Ok(json!({
            "status": "denied",
            "decision": "deny",
            "risk": risk_str,
            "reason": format!(
                "policy denies action: {}",
                eval.matched_rule.unwrap_or_default()
            ),
        })),
    }
}

pub(super) async fn handle_await_approval(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let request_id = params["request_id"]
        .as_str()
        .ok_or((-32602, "missing 'request_id' parameter".to_string()))?
        .to_string();
    let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

    let deadline = tokio::time::Instant::now() + time::Duration::from_secs(timeout_secs);

    loop {
        let info = store.get_approval(&request_id).map_err(|e| match e {
            StoreError::NotFound => (-32004, format!("approval {request_id} not found")),
            other => (-32000, other.to_string()),
        })?;
        ensure_connect_only_owner_matches_trusted_principal(
            ctx,
            "await_approval",
            &info.persona_id,
        )?;

        let decision_json: Option<Value> = match info.status.as_str() {
            "pending" => None,
            "approved" | "narrowed" | "narrowed_and_approved" => {
                Some(json!({"decision": {"kind": "approved"}}))
            }
            "denied" | "dismissed" => Some(json!({
                "decision": {
                    "kind": "denied",
                    "reason": info
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("approval {}", info.status)),
                }
            })),
            "timed_out" | "expired" => Some(json!({"decision": {"kind": "timed_out"}})),
            other => Some(json!({
                "decision": {
                    "kind": "denied",
                    "reason": format!("unknown approval status: {other}"),
                }
            })),
        };

        if let Some(v) = decision_json {
            return Ok(v);
        }

        if tokio::time::Instant::now() >= deadline {
            return Ok(json!({"decision": {"kind": "timed_out"}}));
        }

        tokio::time::sleep(time::Duration::from_millis(500)).await;
    }
}

pub(super) async fn handle_request_blocking(
    store: &DaemonStore,
    policy: &PolicyEngine,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id'".to_string()))?;
    let action = params["action"]
        .as_str()
        .ok_or((-32602, "missing 'action'".to_string()))?;
    let resource = params["resource"].as_str().unwrap_or("");
    let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

    let eval = policy.evaluate(action);
    let risk_str = format!("{:?}", eval.risk).to_lowercase();

    match eval.requirement {
        ApprovalRequirement::Auto => {
            let grant = store
                .create_grant(persona_id, resource, "auto", None)
                .map_err(|e| (-32000, e.to_string()))?;
            let _ = store.log_event(
                Some(persona_id),
                "grant.issued",
                Some(resource),
                "allowed",
                Some(
                    &serde_json::json!({
                        "grant_id": grant.id,
                        "scope": "auto",
                        "ttl_secs": null,
                        "source": "request_access_blocking",
                    })
                    .to_string(),
                ),
            );
            return Ok(json!({
                "status": "approved",
                "approval_id": grant.id,
                "decision": "auto_approve",
                "risk": risk_str,
            }));
        }
        ApprovalRequirement::Denied => {
            return Ok(json!({
                "status": "denied",
                "decision": "deny",
                "risk": risk_str,
                "reason": format!(
                    "policy denies action: {}",
                    eval.matched_rule.unwrap_or_default()
                ),
            }));
        }
        ApprovalRequirement::Required => {}
    }

    // PHASE-C-1-MIGRATED: trait crossing per design §3
    let adapter = DaemonApprovalStoreRef::new(store);
    // implementation-note-13:
    // request_access_blocking is a coarse RPC that does not carry
    // grant-shaping fields; defaults to None.
    let metadata = SubmitMetadata {
        action: action.to_string(),
        ttl_secs: None,
        risk_level: risk_str.clone(),
        tool_name: None,
        target_host: None,
        target_url: None,
        agent_framework: None,
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
        capability: String::new(),
        resource_id: None,
        constraints: vec![],
    };
    let request_id = adapter
        .submit_request(persona_id, resource, scope_obj, metadata)
        .await
        .map_err(|e| (-32000, e.to_string()))?;
    let approval = store
        .get_approval(&request_id.0)
        .map_err(|e| (-32000, e.to_string()))?;
    notify_require_approval(store, &approval);

    let deadline = time::Instant::now() + time::Duration::from_secs(timeout_secs);
    loop {
        let pending = store
            .list_pending_approvals()
            .map_err(|e| (-32000, e.to_string()))?;
        let still_pending = pending.iter().any(|p| p.id == request_id.0);

        if !still_pending {
            return Ok(json!({
                "status": "resolved",
                "approval_id": request_id.0,
            }));
        }

        if time::Instant::now() > deadline {
            return Ok(json!({
                "status": "timeout",
                "approval_id": request_id.0,
            }));
        }

        tokio::time::sleep(time::Duration::from_millis(500)).await;
    }
}
