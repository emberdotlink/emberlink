use std::cell::RefCell;

use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::approval::ApprovalRequestInfo;
use crate::audit::AuditFilter;
use crate::events::GrantEvent;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::rate_limit::RateLimiter;
use crate::store::DaemonStore;
use crate::vault::Vault;

pub async fn dispatch_method(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_events(store, vault, policy, rate_limiter, None, method, params).await
}

pub struct Banner {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub click_url: String,
}

/// Build the notification banner strings for a pending approval request.
///
/// Kept short to fit macOS banner constraints (~60 chars title, ~50 chars
/// subtitle/body). The scope string is intentionally excluded — it was the
/// primary overflow culprit. The dashboard deep-link (`click_url`) is the
/// canonical control surface for full context.
pub fn build_banner(persona_name: &str, req: &ApprovalRequestInfo) -> Banner {
    // Tighten action to 40 chars to leave room for "Ember · <name> wants ".
    let action_short: String = req.action.chars().take(40).collect();
    let id_prefix: String = req
        .id
        .strip_prefix("approval-")
        .unwrap_or(&req.id)
        .chars()
        .take(8)
        .collect();

    let title = format!("Ember · {persona_name} wants {action_short}");

    // Subtitle: credential · TTL · risk — decision-relevant, no scope/id.
    let ttl_part = req
        .ttl_secs
        .map(|s| format!(" · {s}s TTL"))
        .unwrap_or_default();
    let risk_part = if req.risk_level.is_empty() {
        String::new()
    } else {
        format!(" · risk {}", req.risk_level)
    };
    let subtitle_raw = format!("{}{ttl_part}{risk_part}", req.credential_name);
    // Hard-truncate at 50 chars to guard against long credential names.
    let subtitle: String = if subtitle_raw.chars().count() > 50 {
        let mut s: String = subtitle_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        subtitle_raw
    };

    let body_raw = format!("Click to review · {id_prefix}");
    let body: String = if body_raw.chars().count() > 50 {
        let mut s: String = body_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        body_raw
    };

    let click_url = format!("http://localhost:3141/approvals/{}", req.id);

    Banner { title, subtitle, body, click_url }
}

/// Surface a pending approval to the user via the OS notification system.
///
/// Best-effort — errors are silently swallowed. The call is skipped when
/// `EMBER_NO_DESKTOP_NOTIFY=1` is set (useful in CI/tests).
fn notify_require_approval(store: &DaemonStore, req: &ApprovalRequestInfo) {
    #[cfg(test)]
    {
        let _ = (store, req);
        return;
    }
    #[cfg(not(test))]
    {
        if std::env::var("EMBER_NO_DESKTOP_NOTIFY").as_deref() == Ok("1") {
            return;
        }
        let persona_name = store
            .get_persona(&req.persona_id)
            .map(|p| p.name)
            .unwrap_or_else(|_| req.persona_id.chars().take(8).collect());
        let banner = build_banner(&persona_name, req);
        crate::notify::send_notification_with_url(
            &banner.title,
            Some(&banner.subtitle),
            &banner.body,
            Some(&banner.click_url),
        );
    }
}

/// Dispatch a method with an optional event broadcast channel. When a handler
/// triggers a server-initiated event (e.g. `revoke_grant`), the event is
/// published on the channel for connected socket clients to forward.
pub async fn dispatch_method_with_events(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    match method {
        "ping" => Ok(json!({"pong": true})),

        "create_persona" => {
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name' parameter".to_string()))?;
            let info = store
                .create_persona(name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": info.id, "name": info.name, "public_key": info.public_key}))
        }

        "list_personas" => {
            let personas = store
                .list_personas()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = personas
                .iter()
                .map(|p| json!({"id": p.id, "name": p.name, "status": p.status}))
                .collect();
            Ok(json!(list))
        }

        "revoke_persona" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            store
                .revoke_persona(id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"revoked": true}))
        }

        "create_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let max_uses_per_hour = params["max_uses_per_hour"].as_u64();
            let allowed_hours_start = params["allowed_hours_start"].as_u64().map(|v| v as u32);
            let allowed_hours_end = params["allowed_hours_end"].as_u64().map(|v| v as u32);
            let allowed_targets = params["allowed_targets"].as_array().map(|arr| {
                serde_json::to_string(arr).unwrap_or_default()
            });
            let max_delegation_depth = params["max_delegation_depth"].as_u64().map(|v| v as u32);

            // Evaluate policy unless force=true (human/admin bypass)
            let force = params["force"].as_bool().unwrap_or(false);
            if !force {
                let action = format!("credential.access.{}", credential_name);
                let eval = policy.evaluate(&action);

                match eval.decision {
                    PolicyDecision::Deny => {
                        return Err((-32003, format!(
                            "policy denied: {}",
                            eval.matched_rule.unwrap_or_default()
                        )));
                    }
                    PolicyDecision::RequireApproval => {
                        let risk_str = format!("{:?}", eval.risk).to_lowercase();
                        let req = store
                            .submit_approval(
                                persona_id,
                                credential_name,
                                scope,
                                ttl_secs,
                                "create_grant",
                                &risk_str,
                            )
                            .map_err(|e| (-32000, e.to_string()))?;
                        notify_require_approval(store, &req);
                        return Ok(json!({
                            "status": "pending_approval",
                            "approval_id": req.id,
                            "message": "Grant creation requires approval. Use list_pending_approvals to check status."
                        }));
                    }
                    PolicyDecision::AutoApprove => {
                        // Fall through to create grant
                    }
                }
            }

            let grant = store
                .create_grant(persona_id, credential_name, scope, ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;

            if max_uses_per_hour.is_some()
                || allowed_hours_start.is_some()
                || allowed_targets.is_some()
                || max_delegation_depth.is_some()
            {
                store
                    .conn()
                    .execute(
                        "UPDATE grants SET max_uses_per_hour = ?1, allowed_hours_start = ?2, allowed_hours_end = ?3, allowed_targets = ?4, max_delegation_depth = ?5 WHERE id = ?6",
                        rusqlite::params![
                            max_uses_per_hour.map(|v| v as i64),
                            allowed_hours_start.map(|v| v as i64),
                            allowed_hours_end.map(|v| v as i64),
                            allowed_targets,
                            max_delegation_depth.map(|v| v as i64),
                            grant.id,
                        ],
                    )
                    .map_err(|e| (-32000, e.to_string()))?;
            }

            let _ = store.log_event(
                Some(persona_id),
                "grant.issued",
                Some(credential_name),
                "allowed",
                Some(&serde_json::json!({
                    "grant_id": grant.id,
                    "scope": scope,
                    "ttl_secs": ttl_secs,
                    "allowed_targets": params["allowed_targets"],
                }).to_string()),
            );

            Ok(json!({
                "id": grant.id,
                "expires_at": grant.expires_at,
                "conditions": {
                    "max_uses_per_hour": max_uses_per_hour,
                    "allowed_hours": if allowed_hours_start.is_some() {
                        Some(format!("{}:00-{}:00 UTC", allowed_hours_start.unwrap_or(0), allowed_hours_end.unwrap_or(0)))
                    } else { None },
                    "allowed_targets": params["allowed_targets"].as_array(),
                    "max_delegation_depth": max_delegation_depth,
                }
            }))
        }

        "delegate_grant" => {
            let parent_grant_id = params["parent_grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'parent_grant_id'".to_string()))?;
            let child_persona_id = params["child_persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'child_persona_id'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let parent_grant = store
                .get_grant(parent_grant_id)
                .map_err(|e| (-32000, e.to_string()))?;
            let grant = store
                .delegate_grant(parent_grant_id, child_persona_id, scope, ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;
            let _ = store.log_event(
                Some(child_persona_id),
                "grant.delegated",
                Some(&parent_grant.credential_name),
                "allowed",
                Some(&serde_json::json!({
                    "parent_grant_id": parent_grant_id,
                    "child_grant_id": grant.id,
                    "child_persona_id": child_persona_id,
                    "scope": scope,
                }).to_string()),
            );
            Ok(json!({"id": grant.id, "scope": grant.scope, "parent": parent_grant_id}))
        }

        "list_grants" => {
            // persona_id is required — the local socket is not yet authenticated,
            // so we refuse to enumerate grants across personas without an explicit
            // narrowing filter. Cross-persona enumeration would be a local info
            // disclosure. The agent runtime forwards its own persona_id, so the
            // MCP path stays functional; only bare socket callers are refused.
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let grants = store
                .list_active_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .filter(|g| g.persona_id == persona_id)
                .map(|g| {
                    json!({
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "expires_at": g.expires_at,
                        "status": g.status,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "revoke_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            // Look up full grant info before revoking (for notification, audit, and broadcast)
            let grant_info = store.get_grant(id).ok();
            let grant_persona = grant_info.as_ref().map(|g| g.persona_id.clone());
            store
                .revoke_grant(id)
                .map_err(|e| (-32000, e.to_string()))?;
            // Push revocation notification (best-effort, queued for polling)
            if let Some(persona_id) = &grant_persona {
                let _ = store.push_notification(
                    persona_id,
                    "grant.revoked",
                    &json!({"grant_id": id}),
                );
            }
            // Log the revocation event.
            let _ = store.log_event(
                grant_info.as_ref().map(|g| g.persona_id.as_str()),
                "grant.revoked",
                grant_info.as_ref().map(|g| g.credential_name.as_str()),
                "allowed",
                Some(&serde_json::json!({"grant_id": id}).to_string()),
            );
            // Broadcast GRANT_REVOKED over the unix socket so connected agents
            // can zeroize cached credentials without waiting on polling.
            if let (Some(tx), Some(persona_id)) = (events_tx, grant_persona) {
                let event = GrantEvent::Revoked {
                    grant_id: id.to_string(),
                    persona_id: persona_id.clone(),
                };
                // send() returns Err only when there are no active subscribers,
                // which is expected at startup; ignore the result.
                let _ = tx.send(event);
                tracing::info!(grant_id = %id, "broadcasting grant revocation to connected agents");
            }
            Ok(json!({"revoked": true}))
        }

        "evaluate_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let grant = store
                .evaluate_grant(persona_id, credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": grant.id, "scope": grant.scope, "expires_at": grant.expires_at}))
        }

        "use_credential" => {
            // Two calling conventions:
            //   1. `{persona_id, credential_name}` — classic vault lookup.
            //   2. `{grant_id, persona_id?}` — agent runtime flow. Looks up
            //      the grant by id and derives persona+credential from it.
            //      When the caller also supplies `persona_id`, it MUST match
            //      the grant's persona — this prevents grant-id guessing
            //      cross-persona reads via a leaked id.
            let (persona_id, credential_name, resolved_grant): (String, String, Option<crate::grant::GrantInfo>) =
                if let Some(grant_id) = params["grant_id"].as_str() {
                    let grant = store
                        .get_grant(grant_id)
                        .map_err(|e| match e {
                            crate::store::StoreError::NotFound => {
                                (-32004, format!("grant {grant_id} not found"))
                            }
                            other => (-32000, other.to_string()),
                        })?;
                    if grant.status != "active" {
                        return Err((
                            -32005,
                            format!("grant {grant_id} is {} and cannot be used", grant.status),
                        ));
                    }
                    if let Some(caller_persona) = params["persona_id"].as_str()
                        && caller_persona != grant.persona_id
                    {
                        return Err((
                            -32002,
                            "grant belongs to a different persona".to_string(),
                        ));
                    }
                    (
                        grant.persona_id.clone(),
                        grant.credential_name.clone(),
                        Some(grant),
                    )
                } else {
                    let persona_id = params["persona_id"]
                        .as_str()
                        .ok_or((-32602, "missing 'persona_id'".to_string()))?;
                    let credential_name = params["credential_name"]
                        .as_str()
                        .ok_or((-32602, "missing 'credential_name'".to_string()))?;
                    (persona_id.to_string(), credential_name.to_string(), None)
                };

            // Check grant exists and is active (redundant for the grant_id
            // branch but cheap — preserves single-path-through-evaluate
            // semantics for the classic branch).
            let grant = if let Some(g) = resolved_grant {
                g
            } else {
                store
                    .evaluate_grant(&persona_id, &credential_name)
                    .map_err(|e| (-32000, format!("no active grant: {e}")))?
            };
            // Record usage (enforces rate limits).
            store
                .record_grant_usage(&grant.id)
                .map_err(|e| (-32000, e.to_string()))?;
            // Retrieve the credential value.
            let value = vault
                .get(store, &credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            // Log the access.
            let _ = store.log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "allowed",
                None,
            );
            let text = String::from_utf8_lossy(&value);
            Ok(json!({
                "credential": text,
                "grant_id": grant.id,
                "credential_name": credential_name,
                "scope": grant.scope,
            }))
        }

        "vault_add" => {
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            let value = params["value"]
                .as_str()
                .ok_or((-32602, "missing 'value'".to_string()))?;
            let metadata = params["metadata"].as_str();
            let info = vault
                .add(store, name, value.as_bytes(), metadata)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": info.id, "name": info.name}))
        }

        "vault_list" => {
            let creds = vault.list(store).map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = creds
                .iter()
                .map(|c| json!({"id": c.id, "name": c.name, "metadata": c.metadata}))
                .collect();
            Ok(json!(list))
        }

        "audit_query" => {
            let agent_id = params["agent_id"].as_str().map(String::from);
            let limit = params["limit"].as_u64().map(|l| l as usize);
            let filter = AuditFilter {
                agent_id,
                limit,
                ..Default::default()
            };
            let entries = store
                .query_audit(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "agent_id": e.agent_id,
                        "action": e.action,
                        "credential": e.credential,
                        "outcome": e.outcome,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "submit_approval" => {
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
            let risk_level = params["risk_level"]
                .as_str()
                .ok_or((-32602, "missing 'risk_level'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let req = store
                .submit_approval(
                    persona_id,
                    credential_name,
                    scope,
                    ttl_secs,
                    action,
                    risk_level,
                )
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({"id": req.id, "status": req.status}))
        }

        "list_pending_approvals" => {
            let requests = store
                .list_pending_approvals()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = requests
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "persona_id": r.persona_id,
                        "credential_name": r.credential_name,
                        "action": r.action,
                        "risk_level": r.risk_level,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "grant_status" => {
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
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            // Optional: callers can pin the expected persona so a lost id
            // cannot be used to leak status for another agent's grant.
            let expected_persona = params["persona_id"].as_str();

            // Try grant first.
            match store.get_grant(id) {
                Ok(g) => {
                    if let Some(pid) = expected_persona
                        && g.persona_id != pid
                    {
                        return Err((-32002, "grant belongs to a different persona".to_string()));
                    }
                    return Ok(json!({
                        "kind": "grant",
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "status": g.status,
                        "expires_at": g.expires_at,
                        "created_at": g.created_at,
                        "budget": g.budget,
                        "usage": g.usage,
                    }));
                }
                Err(crate::store::StoreError::NotFound) => {
                    // Fall through to approval lookup.
                }
                Err(e) => return Err((-32000, e.to_string())),
            }

            match store.get_approval(id) {
                Ok(a) => {
                    if let Some(pid) = expected_persona
                        && a.persona_id != pid
                    {
                        return Err((-32002, "approval belongs to a different persona".to_string()));
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
                Err(crate::store::StoreError::NotFound) => {
                    Err((-32004, format!("grant or approval {id} not found")))
                }
                Err(e) => Err((-32000, e.to_string())),
            }
        }

        "extend_grant" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let add_tokens = params["add_tokens"].as_u64();
            let add_cents = params["add_cents"].as_u64();
            let add_ttl_secs = params["add_ttl_secs"].as_u64();
            let updated = store
                .extend_grant(grant_id, add_tokens, add_cents, add_ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "grant_id": updated.id,
                "expires_at": updated.expires_at,
                "budget": updated.budget,
            }))
        }

        "request_access" => {
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
            // intentionally avoids disclosing which rule would have matched —
            // only the rate-limit fact is surfaced.
            if !rate_limiter.borrow_mut().check_action(persona_id, action) {
                return Ok(json!({
                    "status": "denied",
                    "decision": "deny",
                    "reason": "rate_spike",
                }));
            }

            // Check standing grants first
            if store.check_standing_grant(persona_id, action).map_err(|e| (-32000, e.to_string()))? {
                let grant = store
                    .create_grant(persona_id, credential_name, scope, ttl_secs)
                    .map_err(|e| (-32000, e.to_string()))?;
                let _ = store.log_event(
                    Some(persona_id),
                    "grant.issued",
                    Some(credential_name),
                    "allowed",
                    Some(&serde_json::json!({
                        "grant_id": grant.id,
                        "scope": scope,
                        "ttl_secs": ttl_secs,
                        "source": "standing_grant",
                    }).to_string()),
                );
                return Ok(json!({
                    "status": "approved",
                    "source": "standing_grant",
                    "grant_id": grant.id,
                }));
            }

            let eval = policy.evaluate(action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();

            match eval.decision {
                PolicyDecision::AutoApprove => {
                    let grant = store
                        .create_grant(persona_id, credential_name, scope, ttl_secs)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(credential_name),
                        "allowed",
                        Some(&serde_json::json!({
                            "grant_id": grant.id,
                            "scope": scope,
                            "ttl_secs": ttl_secs,
                            "source": "request_access",
                        }).to_string()),
                    );
                    Ok(json!({
                        "status": "approved",
                        "grant_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }))
                }
                PolicyDecision::RequireApproval => {
                    let req = store
                        .submit_approval(
                            persona_id,
                            credential_name,
                            scope,
                            ttl_secs,
                            action,
                            &risk_str,
                        )
                        .map_err(|e| (-32000, e.to_string()))?;
                    notify_require_approval(store, &req);
                    Ok(json!({
                        "status": "pending",
                        "approval_id": req.id,
                        "decision": "require_approval",
                        "risk": risk_str,
                    }))
                }
                PolicyDecision::Deny => Ok(json!({
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

        "request_access_blocking" => {
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

            match eval.decision {
                PolicyDecision::AutoApprove => {
                    let grant = store
                        .create_grant(persona_id, resource, "auto", None)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(resource),
                        "allowed",
                        Some(&serde_json::json!({
                            "grant_id": grant.id,
                            "scope": "auto",
                            "ttl_secs": null,
                            "source": "request_access_blocking",
                        }).to_string()),
                    );
                    return Ok(json!({
                        "status": "approved",
                        "approval_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }));
                }
                PolicyDecision::Deny => {
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
                PolicyDecision::RequireApproval => {}
            }

            let approval = store
                .submit_approval(
                    persona_id,
                    resource,
                    "",
                    None,
                    action,
                    &risk_str,
                )
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &approval);

            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
            loop {
                let pending = store
                    .list_pending_approvals()
                    .map_err(|e| (-32000, e.to_string()))?;
                let still_pending = pending.iter().any(|p| p.id == approval.id);

                if !still_pending {
                    return Ok(json!({
                        "status": "resolved",
                        "approval_id": approval.id,
                    }));
                }

                if std::time::Instant::now() > deadline {
                    return Ok(json!({
                        "status": "timeout",
                        "approval_id": approval.id,
                    }));
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        "expire_grants" => {
            let count = store
                .expire_stale_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"expired_count": count}))
        }

        "grant_summary" => {
            let summary = store
                .grant_summary()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "active": summary.active,
                "expired": summary.expired,
                "revoked": summary.revoked,
            }))
        }

        "detect_anomalies" => {
            let anomalies = store.detect_anomalies()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(serde_json::to_value(&anomalies)
                .map_err(|e| (-32000, e.to_string()))?)
        }

        "create_standing_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action_pattern = params["action_pattern"]
                .as_str()
                .ok_or((-32602, "missing 'action_pattern'".to_string()))?;
            let scope = params["scope"].as_str().unwrap_or("*");
            let expires_at = params["expires_at"].as_str();
            store
                .create_standing_grant(persona_id, action_pattern, scope, expires_at)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"created": true, "action_pattern": action_pattern}))
        }

        "list_standing_grants" => {
            let grants = store.list_standing_grants().map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .map(|g| {
                    json!({"id": g.id, "persona_id": g.persona_id, "action_pattern": g.action_pattern, "scope": g.scope, "expires_at": g.expires_at})
                })
                .collect();
            Ok(Value::Array(list))
        }

        "remove_standing_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            store.remove_standing_grant(id).map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true}))
        }

        "poll_notifications" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let notifications = store
                .poll_notifications(persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(Value::Array(notifications))
        }

        _ => Err((-32601, "Method not found".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::build_banner;
    use crate::approval::ApprovalRequestInfo;
    use crate::policy::{PolicyConfig, PolicyDecision, PolicyEngine, PolicyRule, RiskLevel};
    use crate::rate_limit::RateLimiter;
    use crate::store::DaemonStore;
    use crate::vault::Vault;
    use serde_json::json;
    use std::cell::RefCell;

    fn test_vault() -> Vault {
        Vault::new([42u8; 32])
    }

    fn test_policy() -> PolicyEngine {
        PolicyEngine::default()
    }

    fn test_rate_limiter() -> RefCell<RateLimiter> {
        RefCell::new(RateLimiter::default())
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "ping", &json!(null)).await.unwrap();
        assert_eq!(result["pong"], json!(true));
    }

    #[tokio::test]
    async fn unknown_method_returns_32601() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err =
            dispatch_method(&store, &vault, &policy, &rl, "no_such_method", &json!(null))
                .await.unwrap_err();
        assert_eq!(err.0, -32601);
    }

    #[tokio::test]
    async fn create_persona_then_list_shows_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-alpha"}),
        )
        .await.unwrap();
        assert!(result["id"].as_str().unwrap().starts_with("persona-"));
        assert_eq!(result["name"], json!("agent-alpha"));

        let list =
            dispatch_method(&store, &vault, &policy, &rl, "list_personas", &json!(null))
                .await.unwrap();
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], json!("agent-alpha"));
        assert_eq!(arr[0]["status"], json!("active"));
    }

    #[tokio::test]
    async fn create_persona_missing_name_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn create_grant_then_evaluate_finds_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-beta"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "api-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();
        assert!(grant["id"].as_str().unwrap().starts_with("grant-"));

        let eval = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_grant",
            &json!({"persona_id": persona_id, "credential_name": "api-key"}),
        )
        .await.unwrap();
        assert_eq!(eval["scope"], json!("read"));
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!(null),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("persona_id"), "error should mention persona_id, got: {}", err.1);
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_in_empty_object_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn list_grants_with_persona_id_returns_only_that_personas_grants() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-a"}),
        )
        .await.unwrap();
        let persona_a_id = persona_a["id"].as_str().unwrap();

        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-b"}),
        )
        .await.unwrap();
        let persona_b_id = persona_b["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_a_id,
                "credential_name": "cred-a",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_b_id,
                "credential_name": "cred-b",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        let list_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_a_id}),
        )
        .await.unwrap();
        let arr_a = list_a.as_array().unwrap();
        assert_eq!(arr_a.len(), 1, "persona_a should see exactly 1 grant");
        assert_eq!(arr_a[0]["persona_id"], json!(persona_a_id));
        assert_eq!(arr_a[0]["credential_name"], json!("cred-a"));

        let list_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_b_id}),
        )
        .await.unwrap();
        let arr_b = list_b.as_array().unwrap();
        assert_eq!(arr_b.len(), 1, "persona_b should see exactly 1 grant");
        assert_eq!(arr_b[0]["persona_id"], json!(persona_b_id));
        assert_eq!(arr_b[0]["credential_name"], json!("cred-b"));
    }

    #[tokio::test]
    async fn use_credential_with_valid_grant_returns_value() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-gamma"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "my-token",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await.unwrap();
        assert_eq!(result["credential"], json!("supersecret"));
    }

    #[tokio::test]
    async fn use_credential_without_grant_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-delta"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await.unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await.unwrap_err();
        assert_eq!(err.0, -32000);
        assert!(err.1.contains("no active grant"));
    }

    #[tokio::test]
    async fn audit_query_reflects_credential_access() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-epsilon"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "audit-token", "value": "v"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
        )
        .await.unwrap();

        let log =
            dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({})).await.unwrap();
        let arr = log.as_array().unwrap();
        // Two rows: credential.access (most recent) and grant.issued.
        // query_audit orders by timestamp DESC, so arr[0] is the later use.
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["action"], json!("credential.access"));
        assert_eq!(arr[0]["outcome"], json!("allowed"));
        assert_eq!(arr[1]["action"], json!("grant.issued"));
        assert_eq!(arr[1]["outcome"], json!("allowed"));
    }

    #[tokio::test]
    async fn create_grant_with_rate_limit_stores_condition() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-ratelimit"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "rate-key",
                "scope": "read",
                "max_uses_per_hour": 5,
                "force": true,
            }),
        )
        .await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert!(grant_id.starts_with("grant-"));
        assert_eq!(grant["conditions"]["max_uses_per_hour"], json!(5));

        // Verify it was stored in the DB.
        let stored: Option<i64> = store
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, Some(5));
    }

    #[tokio::test]
    async fn delegate_grant_creates_child_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-parent"}),
        )
        .await.unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-child"}),
        )
        .await.unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap();

        let child_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "read",
            }),
        )
        .await.unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("read"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
    }

    #[tokio::test]
    async fn use_credential_records_usage_and_enforces_rate_limit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-usage"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "usage-token", "value": "secret"}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "usage-token",
                "scope": "read",
                "max_uses_per_hour": 2,
                "force": true,
            }),
        )
        .await.unwrap();

        // First use: ok.
        let r1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r1.is_ok());

        // Second use: ok.
        let r2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r2.is_ok());

        // Third use: rate limit exceeded.
        let r3 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        ).await;
        assert!(r3.is_err());
        assert_eq!(r3.unwrap_err().0, -32000);
    }

    #[tokio::test]
    async fn detect_anomalies_returns_empty_on_fresh_store() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
                .await.unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn request_access_blocking_timeout() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "blocker"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Request with 1 second timeout — nobody will approve.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access_blocking",
            &json!({
                "persona_id": persona_id,
                "action": "test.action",
                "timeout_secs": 1,
            }),
        )
        .await.unwrap();

        assert_eq!(result["status"], "timeout");
    }

    #[tokio::test]
    async fn detect_anomalies_finds_high_denial_rate() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Log enough denied events to trigger anomaly
        for _ in 0..4 {
            store.log_event(Some("agent-x"), "credential.access", None, "denied", None).unwrap();
        }
        let result =
            dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
                .await.unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty());
    }

    #[tokio::test]
    async fn request_access_denies_when_rate_limit_exceeded() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        // Tight limiter: exactly 1 request per persona+action in a 60s window.
        let rl = RefCell::new(RateLimiter::new(1, 60));

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rate-limited"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // First request goes through (policy applies — "deploy.staging" is
        // auto-approve under the default policy, so a grant is created).
        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(first["status"], "approved");

        // Snapshot approvals count before the second (rate-limited) call.
        let pending_before = store.list_pending_approvals().unwrap();

        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(second["status"], "denied");
        assert_eq!(second["reason"], "rate_spike");
        // The response must not leak a matched rule — only the rate-limit fact.
        assert!(second.get("matched_rule").is_none());

        // Policy must NOT have been evaluated — no new approval submitted.
        let pending_after = store.list_pending_approvals().unwrap();
        assert_eq!(pending_before.len(), pending_after.len());
    }

    // --- build_banner unit tests ---

    fn fake_req(credential_name: &str, scope: &str, ttl_secs: Option<u64>, risk_level: &str, action: &str) -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-a54d6404-dead-beef-cafe-000000000000".to_string(),
            persona_id: "persona-1".to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            ttl_secs,
            action: action.to_string(),
            risk_level: risk_level.to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-04-20T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn banner_title_fits_60_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.title.chars().count() <= 60,
            "title too long: {} chars — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    #[test]
    fn banner_subtitle_fits_50_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle too long: {} chars — {:?}",
            banner.subtitle.chars().count(),
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_fits_50_chars() {
        let req = fake_req("github-token", "admin:repo", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            banner.body.chars().count() <= 50,
            "body too long: {} chars — {:?}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_does_not_contain_scope() {
        let req = fake_req("github-token", "admin:repo:write:delete", Some(60), "critical", "deploy.production");
        let banner = build_banner("qa", &req);
        assert!(
            !banner.subtitle.contains("admin:repo"),
            "subtitle must not contain scope — {:?}",
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_contains_id_prefix() {
        let req = fake_req("github-token", "read", None, "low", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.body.contains("a54d6404"),
            "body should contain 8-char id prefix — {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_hard_truncates_long_credential_name() {
        let long_cred = "a".repeat(60);
        let req = fake_req(&long_cred, "read", Some(3600), "high", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle should be hard-truncated: {} chars",
            banner.subtitle.chars().count()
        );
        assert!(banner.subtitle.ends_with("..."), "should end with ellipsis");
    }

    #[test]
    fn banner_title_long_action_truncates_at_40_chars() {
        let req = fake_req("key", "read", None, "low", &"x".repeat(80));
        let banner = build_banner("bot", &req);
        // The action portion is capped at 40 chars; title = "Ember · bot wants " + 40 = 58 chars max.
        assert!(
            banner.title.chars().count() <= 60,
            "title should fit in 60 chars: {} — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    #[tokio::test]
    async fn dispatch_method_uses_provided_policy() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        // Custom policy: deny "test.action" explicitly.
        let custom = PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "test.action".to_string(),
                risk: RiskLevel::High,
                decision: PolicyDecision::Deny,
            }],
            ..PolicyConfig::default()
        });
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "create_persona",
            &json!({"name": "custom-policy"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "test.action",
            }),
        )
        .await.unwrap();

        assert_eq!(result["status"], "denied");
        assert_eq!(result["decision"], "deny");
    }

    #[tokio::test]
    async fn grant_issuance_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-issuance"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // request_access with auto-approve policy creates a grant
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "audit-cred",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await.unwrap();
        assert_eq!(result["status"], "approved");
        let grant_id = result["grant_id"].as_str().unwrap();

        let entries = store.query_audit(&crate::audit::AuditFilter {
            action: Some("grant.issued".to_string()),
            ..Default::default()
        }).unwrap();
        assert!(!entries.is_empty(), "expected at least one grant.issued audit row");
        let entry = entries.iter().find(|e| {
            e.details.as_ref().map(|d| d.contains(grant_id)).unwrap_or(false)
        });
        assert!(entry.is_some(), "audit row should reference the new grant_id");
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.issued");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("audit-cred"));
    }

    #[tokio::test]
    async fn grant_revocation_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-revocation"}),
        )
        .await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "revoke-cred",
                "scope": "read",
                "force": true,
            }),
        )
        .await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await.unwrap();

        let entries = store.query_audit(&crate::audit::AuditFilter {
            action: Some("grant.revoked".to_string()),
            ..Default::default()
        }).unwrap();
        assert!(!entries.is_empty(), "expected at least one grant.revoked audit row");
        let entry = entries.iter().find(|e| {
            e.details.as_ref().map(|d| d.contains(grant_id)).unwrap_or(false)
        });
        assert!(entry.is_some(), "audit row should reference the revoked grant_id");
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.revoked");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("revoke-cred"));
    }

    // -----------------------------------------------------------------
    // `grant_status` + `list_grants` persona filter + `use_credential`
    // by grant_id — added for TODO 69I.1 so the agent runtime has a
    // daemon-side surface that matches its protocol shape.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn grant_status_finds_live_grant_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "gs-a"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": grant_id, "persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(result["kind"], "grant");
        assert_eq!(result["id"], json!(grant_id));
        assert_eq!(result["persona_id"], json!(persona_id));
        assert_eq!(result["scope"], "r");
    }

    #[tokio::test]
    async fn grant_status_rejects_mismatched_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "gs-owner"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller pinning a different persona must be rejected — this is
        // the cross-persona probe defense.
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": grant_id, "persona_id": "persona-other"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn grant_status_finds_pending_approval_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "appr-owner"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let req = store.submit_approval(persona_id, "cred", "read", None, "credential.access.cred", "medium").unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": req.id}),
        ).await.unwrap();
        assert_eq!(result["kind"], "approval");
        assert_eq!(result["id"], json!(req.id));
        assert_eq!(result["status"], "pending");
    }

    #[tokio::test]
    async fn grant_status_unknown_id_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "grant_status",
            &json!({"id": "nonexistent"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn list_grants_filters_by_persona_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let p1 = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "p1"})).await.unwrap();
        let p2 = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "p2"})).await.unwrap();
        let p1_id = p1["id"].as_str().unwrap();
        let p2_id = p2["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true})).await.unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true})).await.unwrap();

        // Bare call without persona_id is now refused — cross-persona
        // enumeration via the unauthenticated socket is an info disclosure.
        let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({})).await.unwrap_err();
        assert_eq!(err.0, -32602);

        let only_p1 = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({"persona_id": p1_id})).await.unwrap();
        let arr = only_p1.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_id"], json!(p1_id));
        assert_eq!(arr[0]["credential_name"], "k1");
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_succeeds() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "uc-grant"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "gk", "value": "secret-by-grant-id"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "gk", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        ).await.unwrap();
        assert_eq!(result["credential"], "secret-by-grant-id");
        assert_eq!(result["grant_id"], json!(grant_id));
        assert_eq!(result["credential_name"], "gk");
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_cross_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let owner = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "owner"})).await.unwrap();
        let owner_id = owner["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "ok", "value": "v"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": owner_id, "credential_name": "ok", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller supplying the owner's grant_id but a foreign persona
        // MUST be rejected — leaked id cannot be used to redeem.
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": "persona-other"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_inactive_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "inact"})).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "vault_add", &json!({"name": "ik", "value": "v"})).await.unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "ik", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": grant_id})).await.unwrap();

        let err = dispatch_method(
            &store, &vault, &policy, &rl, "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32005);
    }
}
