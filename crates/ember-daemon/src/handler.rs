use std::cell::RefCell;

use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::approval::ApprovalRequestInfo;
use crate::audit::AuditFilter;
use crate::events::GrantEvent;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::presence::{self, GateOutcome, HighRiskOp};
use crate::rate_limit::RateLimiter;
use crate::store::DaemonStore;
use crate::vault::Vault;

/// Origin of a dispatched RPC request.
///
/// Fix for development milestone (CRITICAL): the `force` flag on `create_grant`
/// used to be accepted from any wire caller, letting unauthenticated socket
/// clients mint grants that bypassed the policy engine. We now thread the
/// dispatch *source* through the handler so that only `Internal` callers
/// (admin CLI paths, test harness, recovery flows) can request policy
/// bypass. Socket callers that attempt `force: true` are rejected.
///
/// **Type-level barrier (development milestone):** The `Internal` variant
/// requires a mandatory `reason` string literal so that every in-process
/// privilege escalation is visible and attributable at the call site.  Code
/// review can grep for `DispatchSource::Internal` and see exactly *why* each
/// caller claims the internal trust lane.  Forgetting the `reason` is a
/// compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSource {
    /// Request arrived via the unix-domain socket RPC path. Callers on this
    /// path are NOT authenticated as admins, and MUST NOT be able to
    /// bypass policy gates. Any `force: true` is rejected.
    Socket,
    /// Request was synthesized by an in-process caller that has already
    /// established admin identity (test harness, internal admin CLI path,
    /// recovery flows). `force: true` is honored.
    ///
    /// `reason` is a mandatory static string that names the trust context
    /// at the call site (e.g. `"admin CLI"`, `"recovery flow"`,
    /// `"test harness"`).  It is purely a code-review / audit annotation
    /// and has no effect on runtime behaviour.
    Internal { reason: &'static str },
}

impl DispatchSource {
    /// Returns `true` when this source carries internal (admin) trust.
    #[inline]
    pub fn is_internal(self) -> bool {
        matches!(self, DispatchSource::Internal { .. })
    }
}

/// Test-only dispatcher — unconditionally runs as an `Internal` source so
/// existing tests can use `force: true` as a setup shortcut. Not reachable
/// from the socket path.
pub async fn dispatch_method(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_source(
        store,
        vault,
        policy,
        rate_limiter,
        None,
        DispatchSource::Internal { reason: "test harness" },
        method,
        params,
    )
    .await
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
    let id_prefix: String = req
        .id
        .strip_prefix("approval-")
        .unwrap_or(&req.id)
        .chars()
        .take(8)
        .collect();

    // Title: prefer tool_name when present; fall back to the action string.
    // Cap the action at 40 chars to leave room for "Ember · <name> wants ".
    // Append agent_framework as a parenthesized badge when present.
    let framework_suffix = req
        .agent_framework
        .as_deref()
        .map(|f| {
            let f_short: String = f.chars().take(16).collect();
            format!(" ({f_short})")
        })
        .unwrap_or_default();
    let title = if let Some(ref tool) = req.tool_name {
        let tool_short: String = tool.chars().take(40).collect();
        format!("Ember · {persona_name} · {tool_short}{framework_suffix}")
    } else {
        let action_short: String = req.action.chars().take(40).collect();
        format!("Ember · {persona_name} wants {action_short}{framework_suffix}")
    };

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

    // Body: prefer target_host + target_summary when either is present; then
    // fall back to target_url; otherwise use the click-to-review prompt.
    let body_raw = match (&req.target_host, &req.target_summary, &req.target_url) {
        (Some(host), Some(summary), _) => format!("{host}{summary}"),
        (Some(host), None, _) => host.clone(),
        (None, Some(summary), _) => summary.clone(),
        (None, None, Some(url)) => url.clone(),
        (None, None, None) => format!("Click to review · {id_prefix}"),
    };
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
///
/// This is the **socket entry point** — it always runs as
/// `DispatchSource::Socket`, which causes any caller-supplied `force: true`
/// on `create_grant` to be rejected. See `DispatchSource` for context.
pub async fn dispatch_method_with_events(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_source(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        DispatchSource::Socket,
        method,
        params,
    )
    .await
}

/// security check marker: the per-op `require_user_presence` gate is
/// applied to high-risk operations dispatched here (`vault_add`,
/// `vault_remove`, `create_grant`). Read-class operations bump the
/// session's `last_activity` via `presence::record_activity()` so they
/// don't spam the user with biometric prompts but also keep the session
/// "warm" — the lock fires on idle silence, not on dashboard polling.
fn check_user_presence_gate(
    op: HighRiskOp,
    override_quiet_hours: bool,
) -> Result<(), (i32, String)> {
    match presence::require_user_presence(op, override_quiet_hours) {
        GateOutcome::Allowed => Ok(()),
        GateOutcome::Locked { reason } => Err((-32030, reason)),
    }
}

/// Core dispatcher. Callers MUST set `source` correctly: `Socket` for any
/// request that arrived from the wire, `Internal` only for in-process
/// admin/test paths. Mis-attribution here would re-open development milestone.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_source(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    source: DispatchSource,
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

            // Evaluate policy unless force=true (human/admin bypass).
            //
            // development milestone fix: `force` is ONLY honored for in-process
            // admin/test callers (`DispatchSource::Internal`). Socket
            // callers that supply `force: true` are rejected loudly so an
            // attacker can never silently bypass the policy gate.
            let force_requested = params["force"].as_bool().unwrap_or(false);
            if force_requested && !source.is_internal() {
                return Err((
                    -32602,
                    "the 'force' parameter is not permitted on the socket API"
                        .to_string(),
                ));
            }
            let force = force_requested && source.is_internal();

            // security check: per-op user-presence gate. Applied BEFORE
            // policy evaluation so a locked session is rejected with a
            // re-auth message instead of being silently routed into the
            // approval queue. Internal callers + force-allowed callers
            // bypass (test harness, admin CLI, recovery flow). Quiet
            // hours apply (grant create is NOT emergency-eligible).
            if !source.is_internal() && !force {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
            }

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
            // Optional child budget — when present, `delegate_grant_full`
            // enforces offline attenuation (child ≤ parent − usage on every
            // axis). When absent we fall back to the no-budget shape so
            // callers that don't set budgets keep working.
            let child_budget: Option<core_types::Budget> = if params["budget"].is_object() {
                Some(serde_json::from_value(params["budget"].clone())
                    .map_err(|e| (-32602, format!("invalid 'budget': {e}")))?)
            } else {
                None
            };
            let parent_grant = store
                .get_grant(parent_grant_id)
                .map_err(|e| (-32000, e.to_string()))?;

            // development milestone — defense-in-depth, NOT a full gate.
            //
            // What this check does: socket callers must assert
            // `caller_persona_id` in params; it must equal the parent
            // grant's owner. A caller who fails to lie — e.g. a benign
            // mis-use, a stale client, a local script that grabbed a
            // stranger's parent_grant_id from a log — is rejected before
            // any state change.
            //
            // What this check does NOT do: it does not prove the caller
            // IS the claimed persona. `caller_persona_id` is an
            // attacker-supplied string. An attacker who knows the victim
            // persona_id (readable via list_personas, audit log,
            // receipts) can set caller_persona_id == victim and the
            // check passes. Full principal binding requires SO_PEERCRED
            // + root-signed RPC or a persona session ticket — tracked
            // as development milestone (defer follow-up).
            //
            // The SO_PEERCRED gate (development milestone, prior change) already
            // ensures only processes running as the daemon's own uid
            // can connect, so the remaining attack surface is between
            // local processes of the same user — real but narrower.
            //
            // `Internal` source (admin CLI, test harness, recovery)
            // bypasses — mirrors development milestone pattern.
            if !source.is_internal() {
                let caller_persona_id = params["caller_persona_id"]
                    .as_str()
                    .ok_or((
                        -32602,
                        "missing 'caller_persona_id': socket callers must \
                         assert the persona delegating the parent grant"
                            .to_string(),
                    ))?;
                if caller_persona_id != parent_grant.persona_id {
                    tracing::warn!(
                        caller_persona_id = %caller_persona_id,
                        parent_grant_id = %parent_grant_id,
                        parent_owner_persona_id = %parent_grant.persona_id,
                        "rejecting delegate_grant: caller does not own parent grant"
                    );
                    return Err((
                        -32002,
                        "delegate_grant: caller does not own parent grant"
                            .to_string(),
                    ));
                }
            }

            let grant = store
                .delegate_grant_full(
                    parent_grant_id,
                    child_persona_id,
                    scope,
                    ttl_secs,
                    child_budget,
                )
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
            Ok(json!({
                "id": grant.id,
                "scope": grant.scope,
                "parent": parent_grant_id,
                "expires_at": grant.expires_at,
                "budget": grant.budget,
            }))
        }

        "list_grants" => {
            // persona_id is required — the local socket is not yet authenticated,
            // so we refuse to enumerate grants across personas without an explicit
            // narrowing filter. Cross-persona enumeration would be a local info
            // disclosure. The agent runtime forwards its own persona_id, so the
            // MCP path stays functional; only bare socket callers are refused.
            //
            // Response shape per design: each entry also carries a
            // `statement_count` and a `statements` array with per-Statement
            // `sid`, `resource_type`, `actions`, `resource`, `budget`, and
            // `usage`. Clients can render per-Statement meters natively.
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
            // security check: read-class — bump session activity so an
            // active agent keeps the vault unlocked, but do NOT prompt
            // for biometric (would spam the user every credential read).
            presence::record_activity();
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
            // security check: per-op user-presence gate. Internal callers
            // (admin CLI / test harness) bypass — same trust model as
            // development milestone force-flag handling.
            if !source.is_internal() {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultAdd, override_qh)?;
            }
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

        "vault_remove" => {
            // security check: high-risk write — gated. Emergency-eligible
            // (vault_remove revokes access; we'd rather let the user shut
            // down a leaked credential mid-quiet-hours than block them).
            if !source.is_internal() {
                let override_qh =
                    params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultRemove, override_qh)?;
            }
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            vault
                .remove(store, name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true, "name": name}))
        }

        "vault_lock" => {
            // security check: explicit re-lock. Always allowed (the user
            // is reducing privilege, not escalating). Internal/socket
            // both honored — `ember vault lock` may dispatch this.
            presence::lock();
            Ok(json!({"locked": true}))
        }

        "vault_status" => {
            // security check: lightweight diagnostic — read-class, never
            // prompts. Used by dashboards to show "session unlocked: 3m
            // idle" without forcing a biometric every refresh.
            presence::record_activity();
            let (unlocked, idle_secs) = presence::snapshot();
            let cfg = presence::current_config();
            Ok(json!({
                "unlocked": unlocked,
                "idle_secs": idle_secs,
                "idle_timeout_secs": cfg.idle_timeout.as_secs(),
                "quiet_hours_start": cfg.quiet_hours_start,
                "quiet_hours_end": cfg.quiet_hours_end,
            }))
        }

        "vault_list" => {
            // Read-class: bump activity, never prompt.
            presence::record_activity();
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

        // EMBER-implementation-note-18 — receipts-table audit view consumed by
        // `ember audit query`. Filters are AND-combined; `resource` is a
        // post-fetch substring match against the receipt body.
        "audit_receipts" => {
            let actor = params["actor"].as_str().map(String::from);
            let kind = params["kind"].as_str().map(String::from);
            let grant_id = params["grant_id"].as_str().map(String::from);
            let resource = params["resource"].as_str().map(String::from);
            let since_iso = params["since"].as_str().map(String::from);
            let limit = params["limit"].as_u64();
            let filter = crate::receipt::ReceiptFilter {
                persona_id: actor,
                kind,
                grant_id,
                resource,
                since_iso,
                limit,
                ..Default::default()
            };
            let rows = store
                .list_receipt_rows(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            // Serialize through serde so callers see the full ReceiptRow
            // shape (id, kind, actor, resource, grant_id, materialized_at,
            // terminal_reason, requested_scope, granted_scope).
            let value = serde_json::to_value(&rows)
                .map_err(|e| (-32000, format!("serialize receipt rows: {e}")))?;
            Ok(value)
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
            let mut req = store
                .submit_approval(
                    persona_id,
                    credential_name,
                    scope,
                    ttl_secs,
                    action,
                    risk_level,
                )
                .map_err(|e| (-32000, e.to_string()))?;
            req.tool_name = params["tool_name"].as_str().map(str::to_owned);
            req.target_host = params["target_host"].as_str().map(str::to_owned);
            req.target_url = params["target_url"].as_str().map(str::to_owned);
            req.agent_framework = params["agent_framework"].as_str().map(str::to_owned);
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
                    // Emit per-Statement array for composite callers
                    // (design). V0 schema: no envelope-level `budget` /
                    // `usage` projection — consumers read per-Statement
                    // fields from the `statements` array.
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
                                })
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
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
                    let mut req = store
                        .submit_approval(
                            persona_id,
                            credential_name,
                            scope,
                            ttl_secs,
                            action,
                            &risk_str,
                        )
                        .map_err(|e| (-32000, e.to_string()))?;
                    req.tool_name = params["tool_name"].as_str().map(str::to_owned);
                    req.target_host = params["target_host"].as_str().map(str::to_owned);
                    req.target_url = params["target_url"].as_str().map(str::to_owned);
                    req.agent_framework = params["agent_framework"].as_str().map(str::to_owned);
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

        "list_receipts" => {
            // Optional `persona_id` filter — returns all when omitted.
            let persona_id = params["persona_id"].as_str();
            let receipts = store
                .list_receipts(persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = receipts
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "get_receipt" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            let receipt = store
                .get_receipt(id)
                .map_err(|e| match e {
                    crate::store::StoreError::NotFound => {
                        (-32004, format!("receipt {id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null))
        }

        "daemon_identity" => {
            // Expose the current daemon identity pubkey over the socket for
            // offline verification tools. Returns `null` when the identity
            // was not initialised.
            match crate::receipt::current_identity() {
                Some(id) => Ok(json!({
                    "pubkey": id.pubkey_hex(),
                    "canonical_version": crate::receipt::CANONICAL_VERSION,
                })),
                None => Ok(Value::Null),
            }
        }

        "grant_budget_status" => {
            // Return per-Statement budget + usage + percent_used so MCP/SDK
            // clients can render a "runway" view without walking the
            // composite block chain themselves. This is a thin read-only
            // projection of `get_access_grant` + lifecycle status; the
            // proxy remains the sole writer of `usage`.
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let chain = match store.get_access_grant(grant_id) {
                Ok(c) => c,
                Err(crate::store::StoreError::NotFound) => {
                    return Err((-32004, format!("grant {grant_id} not found")));
                }
                Err(e) => return Err((-32000, e.to_string())),
            };

            // Envelope status: fold the stored Grant row's status through
            // `GrantStatus::derive` so Expired is reported alongside
            // Active/Revoked on the same snapshot. `expires_at` is stored
            // as an RFC3339 string — parse it defensively and fall back to
            // the chain-level status when the string is malformed.
            let envelope_status = match store.get_grant(grant_id) {
                Ok(g) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let expires_epoch = g.expires_at.as_deref().and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(s)
                            .ok()
                            .map(|dt| dt.timestamp() as u64)
                    });
                    core_types::GrantStatus::derive(&g.status, None, expires_epoch, now)
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

        // implementation-note-9 (design Phase 2): broker socket RPC arms.
        //
        // These are intentionally additive — the registry, materialization
        // tracking, Receipt-event emission, and provider-routing logic live
        // in `crate::broker_handler`. Adding them here is the minimum
        // dispatch surface so concurrent worktrees touching unrelated
        // arms don't conflict on a structural refactor of this fn.
        //
        // Marker (implementation-note-9): RPC method name "BrokerIssue" lives
        // alongside its sibling routes as the literal `broker_issue`. See
        // `broker_handler.rs` for handler bodies + tests.
        "broker_issue" => crate::broker_handler::handle_broker_issue(store, params).await,
        "broker_revoke" => crate::broker_handler::handle_broker_revoke(store, params).await,
        "broker_list" => crate::broker_handler::handle_broker_list(params).await,

        _ => Err((-32601, "Method not found".to_string())),
    }
}

/// Shape a single `Statement` into the budget-status response entry used by
/// the `grant_budget_status` MCP tool. The `percent_used` map is populated
/// only for axes that have a ceiling set — TTL-only statements return an
/// empty map rather than a map full of nulls. `estimated_runway_seconds`
/// is today always `null` (reserved for a future burn-rate projection once
/// the metering history is durable).
fn build_statement_budget_entry(s: &core_types::Statement) -> Value {
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
        // Three rows (timestamp DESC): credential.access, grant.issued, grant.minted.
        // grant.minted is emitted inside create_grant_with_budget before the handler
        // emits grant.issued, so it is the oldest.
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["action"], json!("credential.access"));
        assert_eq!(arr[0]["outcome"], json!("allowed"));
        assert_eq!(arr[1]["action"], json!("grant.issued"));
        assert_eq!(arr[1]["outcome"], json!("allowed"));
        assert_eq!(arr[2]["action"], json!("grant.minted"));
        assert_eq!(arr[2]["outcome"], json!("minted"));
    }

    /// EMBER-implementation-note-18 — round-trip: seed two kms receipts for the same
    /// persona, dispatch `audit_receipts` with `actor` set, verify both
    /// rows return with the expected shape.
    #[tokio::test]
    async fn audit_receipts_round_trips_kms_rows() {
        use core_types::grant_receipt::{
            GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind,
            ReceiptOutcome,
        };

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        for (kind, key, persona) in [
            (ReceiptKind::KmsWrap, "k1", "persona-audit"),
            (ReceiptKind::KmsUnwrap, "k1", "persona-audit"),
            (ReceiptKind::KmsWrap, "k2", "persona-other"),
        ] {
            let r = KmsReceipt {
                id: format!("rct-{}", uuid::Uuid::new_v4()),
                kind,
                key_name: key.into(),
                caller_persona: persona.into(),
                request_size_bytes: 8,
                materialized_at_epoch_secs: 1_700_000_000,
                grant_evaluation: GrantEvaluation {
                    outcome: GrantEvaluationOutcome::Allowed,
                    grant_id: None,
                },
                outcome: ReceiptOutcome::Success,
                evidence: core_types::grant_receipt::Evidence::default(),
            };
            store.store_kms_receipt(&r).unwrap();
        }

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_receipts",
            &json!({"actor": "persona-audit"}),
        )
        .await
        .unwrap();
        let arr = result.as_array().expect("array of rows");
        assert_eq!(arr.len(), 2);
        for row in arr {
            assert_eq!(row["actor"], json!("persona-audit"));
            assert!(
                row["kind"] == json!("kms_wrap") || row["kind"] == json!("kms_unwrap"),
                "kind must be kms_*; got {row:?}"
            );
            assert_eq!(row["resource"], json!("k1"));
        }
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

    /// Exercise the socket-level `delegate_grant` method with an
    /// explicit child `budget` param. Parent carries a tokens budget,
    /// child asks for a strict subset — attenuation must accept and the
    /// response envelope must surface the child budget + expiry.
    #[tokio::test]
    async fn delegate_grant_via_socket_accepts_child_budget() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "agent-parent-budget"}),
        ).await.unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_persona",
            &json!({"name": "agent-child-budget"}),
        ).await.unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "github:push:acme/*",
                "max_delegation_depth": 2,
                "ttl_secs": 3_600,
                "force": true,
            }),
        ).await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        // `create_grant` socket path doesn't plumb budget yet, so stamp
        // the tokens budget directly on the row to set up the scenario.
        store.conn().execute(
            "UPDATE grants SET budget_json = ?1 WHERE id = ?2",
            rusqlite::params![
                r#"{"tokens":10000}"#,
                &parent_grant_id,
            ],
        ).unwrap();

        let child_grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "github:push:acme/widgets",
                "ttl_secs": 900,
                "budget": {"tokens": 2000},
            }),
        ).await.unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("github:push:acme/widgets"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
        assert_eq!(
            child_grant["budget"]["tokens"].as_u64(),
            Some(2000),
            "child budget echoed in response"
        );
        assert!(
            child_grant["expires_at"].is_string(),
            "expires_at present on delegated grant"
        );
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
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
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

    // --- NOTIF-1: optional semantic fields ---

    #[test]
    fn banner_all_semantic_fields_none_uses_default_format() {
        // All new fields absent → legacy title/body behavior.
        let req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("wants"),
            "title should use action-based format when tool_name is None: {:?}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should use default format when target fields are None: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_tool_name_appears_in_title_instead_of_action() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.tool_name = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain tool_name: {:?}",
            banner.title
        );
        assert!(
            !banner.title.contains("wants"),
            "title should NOT use action-based 'wants' format when tool_name is set: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_target_fields_appear_in_body() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.tool_name = Some("claude-code".to_string());
        req.target_host = Some("api.github.com".to_string());
        req.target_summary = Some("POST /repos/x/y/pulls".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com"),
            "body should contain target_host: {:?}",
            banner.body
        );
        assert!(
            banner.body.contains("POST /repos"),
            "body should contain target_summary: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target fields are set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_target_url_appears_when_set() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.target_url = Some("api.github.com/repos/x/y".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com/repos/x/y"),
            "body should contain target_url: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target_url is set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_agent_framework_appears_when_set() {
        let mut req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        req.agent_framework = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain agent_framework: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_omits_absent_optional_fields() {
        let req = fake_req("github-token", "read", Some(1800), "high", "deploy.production");
        let banner = build_banner("demo-agent", &req);
        assert!(
            !banner.title.contains("None"),
            "title must not contain literal 'None': {:?}",
            banner.title
        );
        assert!(
            !banner.subtitle.contains("None"),
            "subtitle must not contain literal 'None': {:?}",
            banner.subtitle
        );
        assert!(
            !banner.body.contains("None"),
            "body must not contain literal 'None': {:?}",
            banner.body
        );
        // No stray separators from absent fields
        assert!(
            !banner.title.contains("()"),
            "title must not contain empty parens: {:?}",
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
                tier: None,
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

    // --- Grant Receipts (Stream D) socket surface -------------------------

    /// Init a process-singleton identity keyed off a temp dir so the test
    /// has real receipts to exercise. Called by each receipt test — the
    /// OnceCell silently no-ops on the second call, which is fine because
    /// the key file is stable.
    fn setup_receipt_identity() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let _ = crate::receipt::init_identity(dir.path());
        dir
    }

    #[tokio::test]
    async fn get_receipt_and_list_receipts_round_trip() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store, &vault, &policy, &rl, "create_persona",
            &json!({"name": "rcpt-alpha"}),
        ).await.unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl, "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();
        dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": grant_id})).await.unwrap();

        // list_receipts (no filter) returns our receipt.
        let list = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({})).await.unwrap();
        let arr = list.as_array().expect("array");
        assert!(!arr.is_empty(), "receipt should be emitted on revoke");
        let rid = arr[0]["id"].as_str().unwrap().to_string();
        assert_eq!(arr[0]["grant_id"].as_str().unwrap(), grant_id);

        // get_receipt returns the full signed body.
        let r = dispatch_method(&store, &vault, &policy, &rl, "get_receipt", &json!({"id": rid})).await.unwrap();
        assert_eq!(r["id"].as_str().unwrap(), rid);
        assert_eq!(r["evidence"]["canonical_version"].as_u64().unwrap(), 1);
        assert_eq!(r["evidence"]["sig"].as_str().unwrap().len(), 128);
    }

    #[tokio::test]
    async fn get_receipt_unknown_id_returns_32004() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl, "get_receipt",
            &json!({"id": "rct-nonexistent"}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn list_receipts_persona_filter_narrows_results() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let a = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "lra"})).await.unwrap();
        let b = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({"name": "lrb"})).await.unwrap();
        let aid = a["id"].as_str().unwrap().to_string();
        let bid = b["id"].as_str().unwrap().to_string();
        for pid in [&aid, &bid] {
            let g = dispatch_method(
                &store, &vault, &policy, &rl, "create_grant",
                &json!({"persona_id": pid, "credential_name": "c", "scope": "r", "force": true}),
            ).await.unwrap();
            let gid = g["id"].as_str().unwrap().to_string();
            dispatch_method(&store, &vault, &policy, &rl, "revoke_grant", &json!({"id": gid})).await.unwrap();
        }
        let all = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({})).await.unwrap();
        let just_a = dispatch_method(
            &store, &vault, &policy, &rl, "list_receipts",
            &json!({"persona_id": aid}),
        ).await.unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2);
        assert_eq!(just_a.as_array().unwrap().len(), 1);
        assert_eq!(just_a[0]["summary"]["persona_id"].as_str().unwrap(), aid);
    }

    #[tokio::test]
    async fn daemon_identity_method_returns_pubkey_when_initialised() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "daemon_identity", &json!({})).await.unwrap();
        // Either a pubkey object or null (init raced on separate process) — but
        // since _guard held a tempdir that init_identity used for the OnceCell,
        // we expect a pubkey here.
        assert!(result.is_object(), "identity should be initialised in this test");
        let pubkey = result["pubkey"].as_str().unwrap();
        assert_eq!(pubkey.len(), 64);
    }

    // --- grant_budget_status (P69K-F1) -------------------------------------

    /// Helper: seed a 3-statement grant via the low-level composite-grant
    /// API so we can assert the MCP budget-status projection without
    /// relying on the proxy to mutate usage.
    fn seed_budget_grant(
        store: &DaemonStore,
        persona_id: &str,
        credential_name: &str,
    ) -> String {
        use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
        let grant = store
            .create_grant(persona_id, credential_name, "*", None)
            .unwrap();
        let root = store.persona_root_keypair(persona_id).unwrap();
        let statements = vec![
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["generic:write".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    tokens: Some(20_000),
                    cents: Some(100),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S2".into(),
                resource_type: ResourceType::Payment,
                actions: vec!["payment:charge".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    cents: Some(500),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S3".into(),
                resource_type: ResourceType::Time,
                actions: vec!["session:start".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    wall_clock_secs: Some(3_600),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
        ];
        let ag = crate::grant::access_grant_from_statements(
            &grant.id,
            persona_id,
            credential_name,
            statements,
            0,
            None,
            &root,
        )
        .unwrap();
        store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
        grant.id
    }

    #[tokio::test]
    async fn grant_budget_status_returns_per_statement_shape() {
        // A 3-statement composite grant surfaces three entries in the
        // response, each carrying sid + resource_type + budget + usage +
        // percent_used. With a stubbed 50% usage on S1, percent_used
        // reflects it — the MCP client can render a runway view without
        // walking the block chain itself.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("budget-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-a");

        // Drive S1 to 10_000 tokens (50%) and 50 cents (50%).
        let delta = store
            .increment_statement_usage(
                &grant_id,
                "S1",
                core_types::Usage {
                    tokens: 10_000,
                    cents: 50,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta.current.tokens, 10_000);

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();

        assert_eq!(result["grant_id"].as_str().unwrap(), grant_id);
        assert_eq!(result["status"].as_str().unwrap(), "active");
        let statements = result["statements"].as_array().unwrap();
        assert_eq!(statements.len(), 3, "three-statement grant");

        let s1 = &statements[0];
        assert_eq!(s1["sid"], "S1");
        assert_eq!(s1["resource_type"], "session");
        assert_eq!(s1["usage"]["tokens"], 10_000);
        assert_eq!(s1["percent_used"]["tokens"], 50);
        assert_eq!(s1["percent_used"]["cents"], 50);
        // runway is reserved for a future burn-rate projection.
        assert!(s1["estimated_runway_seconds"].is_null());
        assert_eq!(s1["has_budget_remaining"], true);

        // S2 has no usage, should be 0% on its set axis.
        let s2 = &statements[1];
        assert_eq!(s2["sid"], "S2");
        assert_eq!(s2["percent_used"]["cents"], 0);
    }

    #[tokio::test]
    async fn grant_budget_status_unknown_grant_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": "grant-nonexistent"}),
        )
        .await
        .unwrap_err();
        // Consistent with `get_receipt` / `grant_status` not-found shape:
        // -32004 is the daemon's NotFound code for MCP.
        assert_eq!(err.0, -32004);
        assert!(err.1.contains("grant-nonexistent"));
    }

    #[tokio::test]
    async fn grant_budget_status_missing_grant_id_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("grant_id"));
    }

    #[tokio::test]
    async fn grant_budget_status_reflects_revoked_status() {
        // When the grant envelope is revoked, the budget-status projection
        // surfaces the terminal state to the caller instead of lying that
        // it's still active.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("revoked-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-r");
        store.revoke_grant(&grant_id).unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "revoked");
    }

    // --- development milestone regression tests ---------------------------------
    // These tests verify that the `force: true` policy-bypass flag on
    // `create_grant` is NOT honored when the request arrives via the socket
    // entry point (`DispatchSource::Socket`). Previously an unauthenticated
    // socket client could pass `force: true` and skip every policy gate.

    #[tokio::test]
    async fn create_grant_socket_rejects_force_true() {
        // A socket client sends `create_grant` with `force: true`. The
        // handler must reject with -32602 rather than minting the grant.
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
            &json!({"name": "c2-victim"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // The default policy's `credential.access.*` rule is
        // `RequireApproval` — without `force`, a socket caller gets a
        // pending approval rather than a grant. With `force: true` the
        // handler MUST reject instead of bypassing policy.
        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602, "socket force must return -32602, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("force"),
            "error should mention force, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn create_grant_socket_without_force_runs_policy() {
        // Same request shape minus `force` — must be treated as an ordinary
        // policy-gated call. With default policy (RequireApproval for
        // credential.access), the response is a pending_approval envelope,
        // NOT a freshly minted grant.
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
            &json!({"name": "c2-policy"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            result["status"], json!("pending_approval"),
            "default policy requires approval for credential.access.*"
        );
        assert!(result["approval_id"].is_string());
        // Crucially: no grant id was issued.
        assert!(result.get("id").is_none());
    }

    #[tokio::test]
    async fn create_grant_socket_with_force_false_is_allowed() {
        // Explicit `force: false` is indistinguishable from omitting it —
        // the socket path runs policy either way.
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
            &json!({"name": "c2-force-false"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], json!("pending_approval"));
    }

    #[tokio::test]
    async fn create_grant_internal_honors_force() {
        // Internal callers (test harness / admin CLI path) retain the
        // ability to skip policy with `force: true`. This keeps the
        // legitimate bypass path working.
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
            &json!({"name": "c2-internal"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal { reason: "test harness — create_grant force bypass" },
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal force should mint a grant, got: {result}"
        );
    }

    // --- development milestone regression tests ---------------------------------
    // A socket caller must assert `caller_persona_id` and it must match the
    // parent grant's owner (`persona_id`). Otherwise any socket process
    // could pick any leaked `parent_grant_id` and mint a child grant
    // pinned to an attacker-controlled persona, forging the audit trail
    // under the legitimate owner's name.

    /// Helper: create two personas (A, B) and a grant owned by A with
    /// delegation depth so it can be further attenuated. Returns the
    /// tuple (a_id, b_id, parent_grant_id). Uses the `Internal` dispatch
    /// path to set up — the `force: true` on `create_grant` requires it.
    async fn c3_setup_two_personas_and_grant(
        store: &DaemonStore,
        vault: &Vault,
        policy: &PolicyEngine,
        rl: &RefCell<RateLimiter>,
    ) -> (String, String, String) {
        let persona_a = dispatch_method(
            store, vault, policy, rl,
            "create_persona",
            &json!({"name": "c3-persona-a"}),
        ).await.unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        let persona_b = dispatch_method(
            store, vault, policy, rl,
            "create_persona",
            &json!({"name": "c3-persona-b"}),
        ).await.unwrap();
        let b_id = persona_b["id"].as_str().unwrap().to_string();

        let parent_grant = dispatch_method(
            store, vault, policy, rl,
            "create_grant",
            &json!({
                "persona_id": a_id,
                "credential_name": "c3-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        ).await.unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        (a_id, b_id, parent_grant_id)
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_non_owner() {
        // Parent grant is issued to persona A. Persona B tries to delegate
        // it via the socket path. The handler MUST reject before any state
        // mutation — no child grant may be minted, no `grant.delegated`
        // audit row may be written.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Snapshot grant count before the attack to prove nothing was
        // minted. `list_active_grants` returns every active grant in the
        // store; we expect the count to be identical after rejection.
        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Attacker asserts they are B, not A. B does not own
                // `parent_grant_id`.
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32002, "expected -32002, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("does not own"),
            "error should say caller does not own parent, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted when socket caller isn't parent owner"
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_accepts_owner() {
        // Same setup but the socket caller correctly asserts persona A
        // (the parent owner). Delegation must succeed.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "socket owner-delegation must mint a grant, got: {result}"
        );
        assert_eq!(result["parent"], json!(parent_grant_id));
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_missing_caller_persona_id() {
        // Even without a wrong persona id, the socket path must refuse to
        // proceed if the caller omits `caller_persona_id` — fail-closed.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // no caller_persona_id
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32602, "missing param must return -32602, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("caller_persona_id"),
            "error must name the missing parameter, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_internal_bypass() {
        // Internal callers (admin CLI / test harness) bypass the
        // ownership gate. Parent is owned by A; an `Internal` dispatch
        // without any `caller_persona_id` MUST still succeed — mirrors
        // the C2 `force` bypass semantics for Internal.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal { reason: "test harness — delegate_grant ownership bypass" },
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Deliberately omit caller_persona_id — Internal bypasses.
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal bypass must mint a grant, got: {result}"
        );
    }

    fn minimal_req() -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-0bc51eff-0000-0000-0000-000000000000".to_string(),
            persona_id: "persona-abc".to_string(),
            credential_name: "github-token".to_string(),
            scope: "repo:read".to_string(),
            ttl_secs: Some(1800),
            action: "credential.access.github-token".to_string(),
            risk_level: "high".to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
        }
    }

    #[test]
    fn build_banner_includes_tool_and_target_when_present() {
        let mut req = minimal_req();
        req.tool_name = Some("claude-code".to_string());
        req.target_url = Some("api.github.com/repos/emberdotlink/emberlink".to_string());

        let banner = build_banner("claude-code", &req);

        assert!(
            banner.title.contains("claude-code"),
            "title should include tool_name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("api.github.com"),
            "body should include target_url, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn build_banner_falls_back_without_new_fields() {
        let req = minimal_req();
        let banner = build_banner("demo-agent", &req);

        assert!(
            banner.title.contains("demo-agent"),
            "title should include persona name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should fall back to click-to-review prompt, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    // --- security check: per-op user-presence wiring ---
    //
    // These tests prove the new methods (`vault_remove`, `vault_lock`,
    // `vault_status`) dispatch correctly. The gate's lock/allow state
    // machine has its own coverage in `crate::presence::tests`. Because
    // cargo-test binaries set `dev_mode_enabled() = true`, the gate
    // returns `Allowed` for every call here, exercising the wire shape
    // without forcing live keychain access.

    #[tokio::test]
    async fn vault_remove_round_trip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": "to-be-removed", "value": "secret"}),
        ).await.unwrap();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_remove",
            &json!({"name": "to-be-removed"}),
        ).await.unwrap();
        assert_eq!(result["removed"], json!(true));
        assert_eq!(result["name"], json!("to-be-removed"));
    }

    #[tokio::test]
    async fn vault_remove_missing_name_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_remove",
            &json!({}),
        ).await.unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn vault_lock_returns_locked_true() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_lock",
            &json!(null),
        ).await.unwrap();
        assert_eq!(result["locked"], json!(true));
    }

    #[tokio::test]
    async fn vault_status_exposes_session_shape() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_status",
            &json!(null),
        ).await.unwrap();
        // Shape contract: dashboard relies on these field names.
        assert!(result["unlocked"].is_boolean());
        assert!(result["idle_timeout_secs"].is_u64());
        // quiet_hours_* may be null, which is .is_null() (or .is_number() if set).
        assert!(result.get("quiet_hours_start").is_some());
        assert!(result.get("quiet_hours_end").is_some());
    }

    #[tokio::test]
    async fn vault_remove_via_socket_source_runs_under_dev_mode_gate() {
        // Even via Socket dispatch (where the gate WOULD run), the
        // cargo-test binary detection short-circuits the gate to Allowed
        // — so the call still succeeds and we can prove the wiring is
        // wired through dispatch_method_with_source, not just the
        // Internal-only convenience entry point.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Seed via Internal so add doesn't trip its own gate path.
        dispatch_method(
            &store, &vault, &policy, &rl,
            "vault_add",
            &json!({"name": "seed", "value": "v"}),
        ).await.unwrap();
        // Now exercise via Socket source.
        let result = dispatch_method_with_source(
            &store, &vault, &policy, &rl, None,
            DispatchSource::Socket,
            "vault_remove",
            &json!({"name": "seed"}),
        ).await.unwrap();
        assert_eq!(result["removed"], json!(true));
    }
}
