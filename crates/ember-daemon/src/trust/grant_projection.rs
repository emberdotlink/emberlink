//! Daemon-local grant projection bridge.
//!
//! `GrantInfo` is still the compatibility row shape used by daemon handlers,
//! receipts, dashboards, and some legacy state-machine paths. This module
//! concentrates the lossy projections around that shape so the main grant
//! store can move toward AccessGrant/grant-set semantics without hiding row
//! hydration rules in every caller.

use chrono::{DateTime, Utc};
use core_grant_types::{Budget, GrantStatus, SignedBlock, Usage};

use super::grant::GrantInfo;

/// Bridge: convert a `GrantInfo` row projection into an in-memory
/// `core_grants::Grant` for legacy state-machine operations.
///
/// The mapping is intentionally lossy: scope is encoded as a capability-only
/// Scope, while resource_id and constraints are not round-tripped from the full
/// ADR 073 shape. Keep new authority logic on AccessGrant/Statement chains.
pub(crate) fn grant_info_to_core(g: &GrantInfo) -> core_grants::Grant {
    let state = match g.status.as_str() {
        "paused" => core_grants::GrantState::Paused,
        "revoked" | "expired" => core_grants::GrantState::Revoked,
        _ => core_grants::GrantState::Active,
    };
    let expires_at = g.expires_at.as_deref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });
    let parent_id = g
        .parent_grant_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    let raw_id = g.id.strip_prefix("grant-").unwrap_or(&g.id);
    let id = uuid::Uuid::parse_str(raw_id).unwrap_or_else(|_| uuid::Uuid::nil());
    core_grants::Grant {
        id,
        issuer: core_grants::PrincipalId(g.persona_id.clone()),
        scope: core_grants::Scope {
            capability: g.scope.clone(),
            resource_id: None,
            constraints: Vec::new(),
        },
        state,
        expires_at,
        parent_id,
        delegation_depth: g.max_delegation_depth.unwrap_or(0),
        usage: core_grants::Usage {
            used: g.usage.tokens,
        },
        schema_version: core_grants::GRANT_SCHEMA_VERSION_PIN,
    }
}

pub(super) fn parse_epoch(s: Option<&str>) -> Option<u64> {
    s.and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64)
}

/// Derive `usage.wall_clock_secs` at read time. Pure; no DB write.
pub(crate) fn derive_wall_clock_secs(
    now_secs: u64,
    created_at_secs: u64,
    expires_at_secs: Option<u64>,
    budget_cap: Option<u64>,
) -> u64 {
    let effective_end = expires_at_secs
        .map(|exp| exp.min(now_secs))
        .unwrap_or(now_secs);
    let elapsed = effective_end.saturating_sub(created_at_secs);
    match budget_cap {
        Some(cap) => elapsed.min(cap),
        None => elapsed,
    }
}

pub(super) fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantInfo> {
    let id: String = row.get(0)?;
    let persona_id: String = row.get(1)?;
    let credential_name: String = row.get(2)?;
    let scope: String = row.get(3)?;
    let created_at: String = row.get(4)?;
    let expires_at: Option<String> = row.get(5)?;
    let status: String = row.get(6)?;
    let max_uses: Option<i64> = row.get(7)?;
    let hours_start: Option<i64> = row.get(8)?;
    let hours_end: Option<i64> = row.get(9)?;
    let depth: Option<i64> = row.get(12)?;
    let spending: Option<i64> = row.get(13)?;
    let budget_json: Option<String> = row.get(14)?;
    let usage_json: Option<String> = row.get(15)?;
    let paused: i64 = row.get(16).unwrap_or(0);
    let receipt_id: Option<String> = row.get(17)?;
    let blocks_json: Option<String> = row.get(18)?;
    let is_standing: i64 = row.get(19).unwrap_or(0);
    let max_children_per_day: Option<i64> = row.get(20).unwrap_or(None);
    let auto_delegate_scope_template: Option<String> = row.get(21).unwrap_or(None);

    let flat_budget: Option<Budget> = budget_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let flat_usage: Usage = usage_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let chain_first_stmt_view: Option<(Option<Budget>, Usage)> = blocks_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<SignedBlock>>(raw).ok())
        .and_then(|blocks| {
            blocks
                .first()
                .and_then(|sb| sb.block.statements.first().cloned())
                .map(|s| (s.budget, s.usage))
        });

    let (projected_budget, mut projected_usage) = match chain_first_stmt_view {
        Some((b, u)) => (b, u),
        None => (flat_budget, flat_usage),
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let created_at_epoch = parse_epoch(Some(&created_at)).unwrap_or(0);
    let expires_at_epoch = parse_epoch(expires_at.as_deref());
    let budget_wall_cap = projected_budget.as_ref().and_then(|b| b.wall_clock_secs);
    projected_usage.wall_clock_secs = derive_wall_clock_secs(
        now_secs,
        created_at_epoch,
        expires_at_epoch,
        budget_wall_cap,
    );

    let effective_status = if matches!(
        status.as_str(),
        "revoked"
            | "abandoned"
            | "expired"
            | "exhausted_by_budget"
            | "expired_by_budget"
            | "parent_cascade_revoked"
    ) {
        status.clone()
    } else {
        GrantStatus::derive(&status, None, expires_at_epoch, now_secs)
            .as_str()
            .to_string()
    };

    Ok(GrantInfo {
        id,
        persona_id,
        credential_name,
        scope,
        created_at,
        expires_at,
        status: effective_status,
        max_uses_per_hour: max_uses.map(|v| v as u64),
        allowed_hours_start: hours_start.map(|v| v as u32),
        allowed_hours_end: hours_end.map(|v| v as u32),
        allowed_targets: row.get(10)?,
        parent_grant_id: row.get(11)?,
        max_delegation_depth: depth.map(|v| v as u32),
        spending_limit_cents: spending.map(|v| v as u64),
        budget: projected_budget,
        usage: projected_usage,
        paused: paused != 0,
        receipt_id,
        is_standing: is_standing != 0,
        max_children_per_day: max_children_per_day.map(|v| v as u64),
        auto_delegate_scope_template,
    })
}
