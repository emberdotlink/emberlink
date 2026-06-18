use serde_json::{Value, json};

use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;

use super::{RequestContext, current_dispatch_deployment_tier};

pub(crate) fn handle_list_grants(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Response shape per ADR 073: each entry also carries a
    // `statement_count` and a `statements` array with per-Statement
    // `sid`, `resource_type`, `actions`, `resource`, `budget`, and
    // `usage`. Clients can render per-Statement meters natively.
    let persona_id = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "list_grants",
        "persona_id",
        true,
    )?
    .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let grants = store
        .list_active_grants()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = grants
        .iter()
        .filter(|g| g.persona_id == persona_id)
        .map(|g| {
            let statements: Vec<Value> = match store.get_access_grant(&g.id) {
                Ok(chain) => chain
                    .statements()
                    .map(|(bi, s)| {
                        json!({
                            "sid": s.sid,
                            "block_index": bi,
                            "resource_type": s.resource_type.as_str(),
                            "actions": s.actions,
                            "resource": s.resource,
                            "budget": s.budget,
                            "usage": s.usage,
                            "conditions": s.conditions,
                        })
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            json!({
                "id": g.id,
                "persona_id": g.persona_id,
                "credential_name": g.credential_name,
                "scope": g.scope,
                "expires_at": g.expires_at,
                "status": g.status,
                "statement_count": statements.len(),
                "statements": statements,
            })
        })
        .collect();
    Ok(json!(list))
}

pub(super) fn handle_list_operator_grants(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Operator-facing enumeration surface for the installed local CLI.
    // Kept separate from `list_grants` so the MCP/runtime contract
    // stays persona-scoped + active-only while the operator can still
    // inspect the full grant table on the presence-gated lane.
    let active_only = params["active_only"].as_bool().unwrap_or(false);
    let grants = if active_only {
        store.list_active_grants()
    } else {
        store.list_grants()
    }
    .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = grants
        .iter()
        .map(|g| {
            json!({
                "id": g.id,
                "persona_id": g.persona_id,
                "credential_name": g.credential_name,
                "scope": g.scope,
                "status": g.status,
                "expires_at": g.expires_at,
            })
        })
        .collect();
    Ok(json!(list))
}

pub(crate) fn handle_status(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Look up by id. The agent protocol passes a single id that may
    // refer to either a live grant (`grant-*`) OR a pending approval
    // request (`approval-*`). Returning both shapes under one method
    // lets clients poll a `request_grant` response through to the
    // issued grant without having to switch RPC methods.
    //
    // The shape is kept wire-compatible with the agent runtime's
    // existing `GrantInfo` + `RequestGrantResponse`: callers parse
    // `kind == "grant"` for grant info or `kind == "approval"` for
    // an approval-request status.
    let id = params["id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id' parameter".to_string()))?;
    // Optional: callers can pin the expected persona so a lost id
    // cannot be used to leak status for another agent's grant.
    let expected_persona =
        crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
            ctx,
            params,
            "grant_status",
            "persona_id",
            false,
        )?;

    // DEMO-MAY3-RECEIPT-SYNCHRONOUS-EMIT: if the caller is observing a
    // grant whose effective (wall-clock-projected) status is terminal
    // but whose stored status is still `active`, flip the row + emit
    // the signed receipt right now. Without this, the runner's
    // `grant_status` poll sees terminal via `effective_status` but
    // the receipt only lands on the next 60-second sweep tick — every
    // receipt-aware check (live receipts panel, dashboard SSE, offline
    // verify) would race the sweep. Best-effort: a failure here logs
    // but doesn't fail the read.
    if let Err(e) = store.expire_grant_if_terminal_now(id) {
        tracing::warn!(
            grant_id = %id,
            error = ?e,
            "expire_grant_if_terminal_now failed; proceeding with stored status"
        );
    }

    // Try grant first.
    match store.get_grant(id) {
        Ok(g) => {
            if let Some(pid) = expected_persona.as_deref()
                && g.persona_id != pid
            {
                let error = if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                    RpcError::NotFound(
                        "grant_status: requested grant does not belong to trusted principal"
                            .to_string(),
                    )
                } else {
                    RpcError::GrantOwnershipMismatch(
                        "grant belongs to a different persona".to_string(),
                    )
                };
                return Err(error.into());
            }
            // Emit per-Statement array for composite callers
            // (ADR 073). V0 schema: no envelope-level `budget` /
            // `usage` projection — consumers read per-Statement
            // fields from the `statements` array.
            let reserved_by_statement = store
                .payment_reserved_cents_by_statement(&g.id)
                .unwrap_or_default();
            let statements: Vec<Value> = match store.get_access_grant(id) {
                Ok(chain) => chain
                    .statements()
                    .map(|(bi, s)| {
                        json!({
                            "sid": s.sid,
                            "block_index": bi,
                            "resource_type": s.resource_type.as_str(),
                            "actions": s.actions,
                            "resource": s.resource,
                            "budget": s.budget,
                            "usage": s.usage,
                            "conditions": s.conditions,
                            "reserved_cents": reserved_by_statement
                                .get(&s.sid)
                                .copied()
                                .unwrap_or(0),
                        })
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            // DEMO-MAY3-COMPOSITE-PER-STMT-REVOKE — surface the
            // per-Statement revocation list so callers can render
            // strikethrough on individual sids without polling a
            // separate endpoint.
            let revoked_sids = store.get_revoked_sids(&g.id).unwrap_or_default();
            let live_lease = store.leases().has_live_lease(&g.id, chrono::Utc::now());
            return Ok(json!({
                "kind": "grant",
                "id": g.id,
                "persona_id": g.persona_id,
                "credential_name": g.credential_name,
                "scope": g.scope,
                "status": g.status,
                "expires_at": g.expires_at,
                "created_at": g.created_at,
                "statements": statements,
                "statement_count": statements.len(),
                "revoked_sids": revoked_sids,
                "live_lease": live_lease,
            }));
        }
        Err(crate::infra::store::StoreError::NotFound) => {
            // Fall through to approval lookup.
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    }

    match store.get_approval(id) {
        Ok(a) => {
            if let Some(pid) = expected_persona.as_deref()
                && a.persona_id != pid
            {
                let error = if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                    RpcError::NotFound(
                        "grant_status: requested approval does not belong to trusted principal"
                            .to_string(),
                    )
                } else {
                    RpcError::GrantOwnershipMismatch(
                        "approval belongs to a different persona".to_string(),
                    )
                };
                return Err(error.into());
            }
            Ok(json!({
                "kind": "approval",
                "id": a.id,
                "persona_id": a.persona_id,
                "credential_name": a.credential_name,
                "scope": a.scope,
                "status": a.status,
                "action": a.action,
                "risk_level": a.risk_level,
            }))
        }
        Err(crate::infra::store::StoreError::NotFound) => {
            Err(RpcError::NotFound(format!("grant or approval {id} not found")).into())
        }
        Err(e) => Err(RpcError::Internal(e.to_string()).into()),
    }
}

pub(crate) fn handle_summary(store: &DaemonStore) -> Result<Value, (i32, String)> {
    let summary = store
        .grant_summary()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({
        "active": summary.active,
        "expired": summary.expired,
        "revoked": summary.revoked,
    }))
}

pub(crate) fn handle_detect_anomalies(store: &DaemonStore) -> Result<Value, (i32, String)> {
    let anomalies = store
        .detect_anomalies()
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    serde_json::to_value(&anomalies).map_err(|e| RpcError::Internal(e.to_string()).into())
}

pub(crate) fn handle_budget_status(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Return per-Statement budget + usage + percent_used so MCP/SDK
    // clients can render a "runway" view without walking the
    // composite block chain themselves. This is a thin read-only
    // projection of `get_access_grant` + lifecycle status; the
    // proxy remains the sole writer of `usage`.
    let grant_id = params["grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'grant_id'".to_string()))?;
    if let Some(trusted_persona) =
        crate::infra::handlers::principal::team0_connect_only_persona_scope(
            ctx,
            "grant_budget_status",
        )?
    {
        let owner = match store.get_grant(grant_id) {
            Ok(grant) => grant.persona_id,
            Err(crate::infra::store::StoreError::NotFound) => {
                return Err(RpcError::NotFound(format!("grant {grant_id} not found")).into());
            }
            Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
        };
        if owner != trusted_persona {
            tracing::warn!(
                method = "grant_budget_status",
                grant_id = %grant_id,
                owner_persona_id = %owner,
                trusted_persona_id = %trusted_persona,
                tier = current_dispatch_deployment_tier().as_str(),
                "connect-only persona-scoped lookup refused: grant owner does not match trusted principal"
            );
            return Err(RpcError::NotFound(
                "grant_budget_status: requested grant does not belong to trusted principal"
                    .to_string(),
            )
            .into());
        }
    }
    let chain = match store.get_access_grant(grant_id) {
        Ok(c) => c,
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err(RpcError::NotFound(format!("grant {grant_id} not found")).into());
        }
        Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
    };

    // Envelope status: load via DaemonGrantStore (GRANT-SM-PHASE-C-3A)
    // to get core_grants::Grant with a typed expires_at
    // (Option<DateTime<Utc>>) rather than an RFC3339 string from
    // GrantInfo. GrantStatus::derive is still used for the "Expired"
    // virtual status derived at query time.
    let envelope_status = match store.grant_store().load_grant(grant_id) {
        Ok(g) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let expires_epoch = g.expires_at.map(|dt| dt.timestamp() as u64);
            let status_str = match g.state {
                core_grants::GrantState::Active => "active",
                core_grants::GrantState::Paused => "paused",
                core_grants::GrantState::Revoked => "revoked",
            };
            core_grant_types::GrantStatus::derive(status_str, None, expires_epoch, now)
                .as_str()
                .to_string()
        }
        Err(_) => chain.status.as_str().to_string(),
    };

    let statements: Vec<Value> = chain
        .statements()
        .map(|(_bi, s)| build_statement_budget_entry(s))
        .collect();

    Ok(json!({
        "grant_id": grant_id,
        "status": envelope_status,
        "statements": statements,
    }))
}

/// Shape a single `Statement` into the budget-status response entry used by
/// the `grant_budget_status` MCP tool. The `percent_used` map is populated
/// only for axes that have a ceiling set — TTL-only statements return an
/// empty map rather than a map full of nulls. `estimated_runway_seconds`
/// is today always `null` (reserved for a future burn-rate projection once
/// the metering history is durable).
fn build_statement_budget_entry(s: &core_grant_types::Statement) -> Value {
    let mut percent_used = serde_json::Map::new();
    if let Some(budget) = &s.budget {
        if let Some(cap) = budget.tokens
            && cap > 0
        {
            let pct = ((s.usage.tokens as u128 * 100) / cap as u128) as u64;
            percent_used.insert("tokens".to_string(), json!(pct));
        }
        if let Some(cap) = budget.cents
            && cap > 0
        {
            let pct = ((s.usage.cents as u128 * 100) / cap as u128) as u64;
            percent_used.insert("cents".to_string(), json!(pct));
        }
        if let Some(cap) = budget.requests
            && cap > 0
        {
            let pct = ((s.usage.requests as u128 * 100) / cap as u128) as u64;
            percent_used.insert("requests".to_string(), json!(pct));
        }
    }

    json!({
        "sid": s.sid,
        "resource_type": s.resource_type.as_str(),
        "budget": s.budget,
        "usage": s.usage,
        "percent_used": Value::Object(percent_used),
        "estimated_runway_seconds": Value::Null,
        "has_budget_remaining": s.has_budget_remaining(),
    })
}
