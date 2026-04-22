use chrono::{DateTime, Duration, Timelike, Utc};
use core_types::{Budget, Usage};
use rusqlite::OptionalExtension;
use serde::Serialize;
use uuid::Uuid;

use crate::attenuation::{
    check_budget_attenuation, check_expiry_attenuation, scope_subset,
};
use crate::store::{DaemonStore, StoreError};

/// Daemon-local grant record. Mirrors the protocol-level
/// [`core_types::AccessGrant`] shape for budget + usage per design so the
/// same struct flows end-to-end through the proxy meter, CLI, MCP surface,
/// and dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub max_uses_per_hour: Option<u64>,
    pub allowed_hours_start: Option<u32>,
    pub allowed_hours_end: Option<u32>,
    pub allowed_targets: Option<String>,
    pub parent_grant_id: Option<String>,
    pub max_delegation_depth: Option<u32>,
    pub spending_limit_cents: Option<u64>,
    /// Authority budget per design. `None` = TTL-only (today's default
    /// credential-grant behavior). `Some` populates tokens/cents/etc.
    pub budget: Option<Budget>,
    /// Running tally incremented by `ember-proxy` per grant use.
    #[serde(default)]
    pub usage: Usage,
    /// Operator-set advisory pause flag (69K.7). Advisory only — does not
    /// gate proxy traffic; emits a `budget.warning` with `paused: true` for
    /// well-behaved agents to self-moderate.
    pub paused: bool,
    /// Populated when the grant reached a terminal state and the Warden
    /// emitted a `GrantReceipt`.
    pub receipt_id: Option<String>,
}

const GRANT_COLUMNS: &str = "id, persona_id, credential_name, scope, created_at, expires_at, status, max_uses_per_hour, allowed_hours_start, allowed_hours_end, allowed_targets, parent_grant_id, max_delegation_depth, spending_limit_cents, budget_json, usage_json, paused, receipt_id";

fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantInfo> {
    let max_uses: Option<i64> = row.get(7)?;
    let hours_start: Option<i64> = row.get(8)?;
    let hours_end: Option<i64> = row.get(9)?;
    let depth: Option<i64> = row.get(12)?;
    let spending: Option<i64> = row.get(13)?;
    let budget_json: Option<String> = row.get(14)?;
    let usage_json: Option<String> = row.get(15)?;
    let paused: i64 = row.get(16).unwrap_or(0);
    let budget: Option<Budget> = budget_json.as_deref().and_then(|s| {
        serde_json::from_str(s)
            .inspect_err(|e| {
                tracing::warn!(error = %e, raw = %s, "grant.budget_json parse failed; treating as no budget");
            })
            .ok()
    });
    let usage: Usage = usage_json
        .as_deref()
        .and_then(|s| {
            serde_json::from_str(s)
                .inspect_err(|e| {
                    tracing::warn!(error = %e, raw = %s, "grant.usage_json parse failed; resetting to default");
                })
                .ok()
        })
        .unwrap_or_default();
    Ok(GrantInfo {
        id: row.get(0)?,
        persona_id: row.get(1)?,
        credential_name: row.get(2)?,
        scope: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        status: row.get(6)?,
        max_uses_per_hour: max_uses.map(|v| v as u64),
        allowed_hours_start: hours_start.map(|v| v as u32),
        allowed_hours_end: hours_end.map(|v| v as u32),
        allowed_targets: row.get(10)?,
        parent_grant_id: row.get(11)?,
        max_delegation_depth: depth.map(|v| v as u32),
        spending_limit_cents: spending.map(|v| v as u64),
        budget,
        usage,
        paused: paused != 0,
        receipt_id: row.get(17)?,
    })
}

impl DaemonStore {
    pub fn create_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        // Verify persona exists and is active.
        let persona_status: Option<String> = self
            .conn()
            .query_row(
                "SELECT status FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| row.get(0),
            )
            .optional()?;

        match persona_status.as_deref() {
            None => return Err(StoreError::NotFound),
            Some("active") => {}
            Some(other) => {
                return Err(StoreError::InvalidInput(format!(
                    "persona is not active: {other}"
                )))
            }
        }

        let id = format!("grant-{}", Uuid::new_v4());
        let now: DateTime<Utc> = Utc::now();
        let created_at = now.to_rfc3339();

        let expires_at: Option<String> = ttl_secs.map(|secs| {
            let expiry = now + Duration::seconds(secs as i64);
            expiry.to_rfc3339()
        });

        self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
            ],
        )?;

        Ok(GrantInfo {
            id,
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: None,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
        })
    }

    pub fn list_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn list_active_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?1)"
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![now], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn get_grant(&self, id: &str) -> Result<GrantInfo, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants WHERE id = ?1");
        self.conn()
            .query_row(&sql, rusqlite::params![id], row_to_grant)
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub fn evaluate_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
    ) -> Result<GrantInfo, StoreError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants \
             WHERE persona_id = ?1 AND credential_name = ?2 \
             AND status = 'active' AND (expires_at IS NULL OR expires_at > ?3) \
             LIMIT 1"
        );
        let grant = self
            .conn()
            .query_row(&sql, rusqlite::params![persona_id, credential_name, now], row_to_grant)
            .optional()?
            .ok_or(StoreError::NotFound)?;

        // Check time window
        if let (Some(start), Some(end)) = (grant.allowed_hours_start, grant.allowed_hours_end) {
            let current_hour = Utc::now().hour();
            let in_window = if start <= end {
                current_hour >= start && current_hour < end
            } else {
                current_hour >= start || current_hour < end
            };
            if !in_window {
                return Err(StoreError::InvalidInput(format!(
                    "outside allowed hours ({start}:00-{end}:00 UTC)"
                )));
            }
        }

        Ok(grant)
    }

    /// Record a usage of a grant. Returns error if rate limit exceeded.
    pub fn record_grant_usage(&self, grant_id: &str) -> Result<(), StoreError> {
        let max_uses: Option<i64> = self
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = max_uses {
            let one_hour_ago = (Utc::now() - Duration::hours(1)).to_rfc3339();
            let count: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, one_hour_ago],
                |row| row.get(0),
            )?;
            if count >= max {
                return Err(StoreError::InvalidInput(format!(
                    "rate limit exceeded: {count}/{max} uses per hour"
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at) VALUES (?1, ?2)",
            rusqlite::params![grant_id, now],
        )?;
        Ok(())
    }

    /// Create a delegated grant with narrowed scope (TTL + scope only).
    ///
    /// Thin wrapper over `delegate_grant_full` that passes `None` for the
    /// child budget. If the parent carries a budget this call will fail
    /// attenuation (child must also bound every parent-bounded axis). Kept
    /// as-is so existing socket + CLI callers keep working for grants
    /// without budgets.
    pub fn delegate_grant(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.delegate_grant_full(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
            None,
        )
    }

    /// Create a delegated grant with narrowed scope + optional child budget.
    ///
    /// Enforces offline attenuation per design § Offline attenuation:
    /// - child scope must be a subset of parent scope;
    /// - child budget must fit inside parent's remaining allowance
    ///   (parent.budget − parent.usage) on every axis the parent bounds;
    /// - child expires_at must be no later than the parent's (and must be
    ///   present if the parent has one).
    ///
    /// A failure on any axis returns `StoreError::DelegationViolation` with
    /// a reason that names the violating dimension only.
    pub fn delegate_grant_full(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
        child_budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        let parent = self.get_grant(parent_grant_id)?;
        if parent.status != "active" {
            return Err(StoreError::InvalidInput("parent grant not active".into()));
        }
        let max_depth = parent
            .max_delegation_depth
            .ok_or_else(|| StoreError::InvalidInput("parent does not allow delegation".into()))?;
        if max_depth == 0 {
            return Err(StoreError::InvalidInput("delegation depth exceeded".into()));
        }

        // --- Offline attenuation (design § Offline attenuation) ---
        // Scope subset check.
        scope_subset(narrowed_scope, &parent.scope)?;

        // Compute child expiry epoch seconds (if provided) and parent's (if present).
        let now: DateTime<Utc> = Utc::now();
        let child_expiry_epoch: Option<u64> = ttl_secs
            .map(|s| (now.timestamp() as i128 + s as i128).max(0) as u64);
        let parent_expiry_epoch: Option<u64> = parent
            .expires_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);

        check_expiry_attenuation(parent_expiry_epoch, child_expiry_epoch)?;
        check_budget_attenuation(&parent.budget, &parent.usage, &child_budget)?;

        let id = format!("grant-{}", Uuid::new_v4());
        let created_at = now.to_rfc3339();
        let expires_at = ttl_secs.map(|s| (now + Duration::seconds(s as i64)).to_rfc3339());
        let budget_json: Option<String> = child_budget
            .as_ref()
            .filter(|b| !b.is_none_set())
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status, parent_grant_id, max_delegation_depth, budget_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10)",
            rusqlite::params![
                id,
                child_persona_id,
                parent.credential_name,
                narrowed_scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
                parent_grant_id,
                max_depth.saturating_sub(1) as i64,
                budget_json,
            ],
        )?;

        Ok(GrantInfo {
            id,
            persona_id: child_persona_id.to_string(),
            credential_name: parent.credential_name,
            scope: narrowed_scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: Some(parent_grant_id.to_string()),
            max_delegation_depth: Some(max_depth.saturating_sub(1)),
            spending_limit_cents: None,
            budget: child_budget.filter(|b| !b.is_none_set()),
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
        })
    }

    pub fn revoke_grant(&self, id: &str) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        // Cascade to child delegated grants
        self.cascade_revoke_children(id)?;
        Ok(())
    }

    fn cascade_revoke_children(&self, parent_id: &str) -> Result<(), StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id FROM grants WHERE parent_grant_id = ?1 AND status = 'active'",
        )?;
        let children: Vec<String> = stmt
            .query_map(rusqlite::params![parent_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for child_id in children {
            self.conn().execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![child_id],
            )?;
            self.cascade_revoke_children(&child_id)?;
        }
        Ok(())
    }

    /// Mark grants whose expires_at has passed as 'expired'.
    pub fn expire_stale_grants(&self) -> Result<usize, StoreError> {
        let now = Utc::now().to_rfc3339();
        let count = self.conn().execute(
            "UPDATE grants SET status = 'expired' \
             WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
            rusqlite::params![now],
        )?;
        Ok(count)
    }

    /// List grants of any status — used for the receipt viewer and terminated-grant rows.
    pub fn list_all_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants ORDER BY created_at DESC");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    /// Set the `paused` flag on a grant (advisory signal to the agent).
    pub fn set_grant_paused(&self, id: &str, paused: bool) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET paused = ?1 WHERE id = ?2 AND status = 'active'",
            rusqlite::params![paused as i64, id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Extend a grant's budget and/or TTL.
    ///
    /// - `tokens_delta`: additional tokens to add to `budget_tokens` (and reset `tokens_used` floor
    ///   so the new budget is `old_budget + tokens_delta`).
    /// - `cents_delta`: additional cents to add to `budget_cents`.
    /// - `ttl_extension_secs`: seconds to add to `expires_at` (from now if currently unbounded).
    pub fn extend_grant(
        &self,
        id: &str,
        tokens_delta: Option<u64>,
        cents_delta: Option<u64>,
        ttl_extension_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        let grant = self.get_grant(id)?;
        if grant.status != "active" {
            return Err(StoreError::InvalidInput(format!(
                "cannot extend grant with status '{}'",
                grant.status
            )));
        }

        let now: DateTime<Utc> = Utc::now();

        // Compute new expires_at
        let new_expires_at: Option<String> = if let Some(ext) = ttl_extension_secs {
            let base = if let Some(ref exp) = grant.expires_at {
                DateTime::parse_from_rfc3339(exp)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or(now)
            } else {
                now
            };
            let new_exp = base + Duration::seconds(ext as i64);
            Some(new_exp.to_rfc3339())
        } else {
            grant.expires_at.clone()
        };

        // Compute new budget values per design (Budget struct, not flat columns)
        let existing_budget = grant.budget.clone().unwrap_or_default();
        let new_budget = Budget {
            tokens: match (existing_budget.tokens, tokens_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            cents: match (existing_budget.cents, cents_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            ..existing_budget
        };
        let new_budget_opt: Option<Budget> = if new_budget.is_none_set() { None } else { Some(new_budget) };
        let new_budget_json: Option<String> = new_budget_opt
            .as_ref()
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        self.conn().execute(
            "UPDATE grants SET budget_json = ?1, expires_at = ?2 WHERE id = ?3",
            rusqlite::params![new_budget_json, new_expires_at, id],
        )?;

        self.get_grant(id)
    }

    /// Set a receipt_id on a terminated grant.
    pub fn set_grant_receipt_id(&self, grant_id: &str, receipt_id: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE grants SET receipt_id = ?1 WHERE id = ?2",
            rusqlite::params![receipt_id, grant_id],
        )?;
        Ok(())
    }

    /// Get counts of grants by status.
    pub fn grant_summary(&self) -> Result<GrantSummary, StoreError> {
        let active: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        let expired: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'expired'",
            [],
            |row| row.get(0),
        )?;
        let revoked: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'revoked'",
            [],
            |row| row.get(0),
        )?;
        Ok(GrantSummary {
            active: active as u64,
            expired: expired as u64,
            revoked: revoked as u64,
        })
    }

    /// Record a spending event. Returns error if daily limit exceeded.
    pub fn record_grant_spending(&self, grant_id: &str, amount_cents: u64) -> Result<(), StoreError> {
        let limit: Option<i64> = self
            .conn()
            .query_row(
                "SELECT spending_limit_cents FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = limit {
            let today = Utc::now()
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .to_rfc3339();
            let spent: i64 = self.conn().query_row(
                "SELECT COALESCE(SUM(amount_cents), 0) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, today],
                |row| row.get(0),
            )?;
            if spent + amount_cents as i64 > max {
                return Err(StoreError::InvalidInput(format!(
                    "spending limit exceeded: ${:.2} + ${:.2} > ${:.2}/day",
                    spent as f64 / 100.0,
                    amount_cents as f64 / 100.0,
                    max as f64 / 100.0
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at, amount_cents) VALUES (?1, ?2, ?3)",
            rusqlite::params![grant_id, now, amount_cents as i64],
        )?;
        Ok(())
    }
}

pub struct GrantSummary {
    pub active: u64,
    pub expired: u64,
    pub revoked: u64,
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::store::DaemonStore;

    fn setup() -> DaemonStore {
        DaemonStore::open_in_memory().expect("in-memory store")
    }

    #[test]
    fn create_grant_list_shows_active() {
        let store = setup();
        let persona = store.create_persona("agent-alpha").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "read", None)
            .unwrap();
        assert_eq!(grant.status, "active");
        assert!(grant.expires_at.is_none());

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, grant.id);
        assert_eq!(grants[0].status, "active");
    }

    #[test]
    fn create_grant_with_ttl_expires_at_set() {
        let store = setup();
        let persona = store.create_persona("agent-beta").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "write", Some(3600))
            .unwrap();
        assert!(grant.expires_at.is_some());

        // Parse and verify it's in the future.
        let expires: DateTime<Utc> =
            DateTime::parse_from_rfc3339(grant.expires_at.as_ref().unwrap())
                .unwrap()
                .into();
        assert!(expires > Utc::now());
    }

    #[test]
    fn evaluate_grant_returns_active_grant() {
        let store = setup();
        let persona = store.create_persona("agent-gamma").unwrap();
        store
            .create_grant(&persona.id, "secret", "read", None)
            .unwrap();

        let found = store.evaluate_grant(&persona.id, "secret").unwrap();
        assert_eq!(found.persona_id, persona.id);
        assert_eq!(found.credential_name, "secret");
        assert_eq!(found.status, "active");
    }

    #[test]
    fn evaluate_grant_after_ttl_expires_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-delta").unwrap();

        // Insert a grant with expires_at in the past directly.
        let id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    id,
                    persona.id,
                    "expired-key",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let result = store.evaluate_grant(&persona.id, "expired-key");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn revoke_grant_evaluate_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-epsilon").unwrap();
        let grant = store
            .create_grant(&persona.id, "token", "full", None)
            .unwrap();

        store.revoke_grant(&grant.id).unwrap();

        let result = store.evaluate_grant(&persona.id, "token");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_nonexistent_persona_returns_error() {
        let store = setup();
        let result = store.create_grant("persona-does-not-exist", "key", "read", None);
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_revoked_persona_returns_error() {
        let store = setup();
        let persona = store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&persona.id).unwrap();

        let result = store.create_grant(&persona.id, "key", "read", None);
        assert!(matches!(result, Err(StoreError::InvalidInput(_))));
    }

    #[test]
    fn list_active_grants_excludes_expired_and_revoked() {
        let store = setup();
        let persona = store.create_persona("agent-eta").unwrap();

        // Active grant (no TTL).
        let active = store
            .create_grant(&persona.id, "active-key", "read", None)
            .unwrap();

        // Revoked grant.
        let revoked = store
            .create_grant(&persona.id, "revoked-key", "read", None)
            .unwrap();
        store.revoke_grant(&revoked.id).unwrap();

        // Expired grant: insert directly with past expires_at.
        let exp_id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    exp_id,
                    persona.id,
                    "expired-key2",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let active_grants = store.list_active_grants().unwrap();
        assert_eq!(active_grants.len(), 1);
        assert_eq!(active_grants[0].id, active.id);
    }

    // Keep the import used only in the sleep-based variant (unused without it).
    #[allow(dead_code)]
    fn _uses_thread_sleep() {
        let _ = thread::sleep(StdDuration::from_millis(0));
    }

    // --- Offline attenuation integration tests (design § 69K.6) ---

    /// Attach a budget + max_delegation_depth to a newly-created parent grant
    /// by patching the row directly. create_grant doesn't accept these yet
    /// (that's a separate task); the attenuation path does its own reads.
    fn attach_parent_constraints(
        store: &DaemonStore,
        grant_id: &str,
        budget: Option<Budget>,
        max_depth: u32,
    ) {
        let budget_json: Option<String> = budget
            .as_ref()
            .filter(|b| !b.is_none_set())
            .map(|b| serde_json::to_string(b).unwrap());
        store
            .conn()
            .execute(
                "UPDATE grants SET budget_json = ?1, max_delegation_depth = ?2 WHERE id = ?3",
                rusqlite::params![budget_json, max_depth as i64, grant_id],
            )
            .unwrap();
    }

    fn setup_parent_with_budget(
        store: &DaemonStore,
        tokens: u64,
        ttl_secs: u64,
    ) -> (String, String) {
        let parent_persona = store.create_persona("agent-parent").unwrap();
        let child_persona = store.create_persona("agent-child").unwrap();
        let parent_grant = store
            .create_grant(
                &parent_persona.id,
                "delegate-key",
                "github:push:acme/*",
                Some(ttl_secs),
            )
            .unwrap();
        attach_parent_constraints(
            store,
            &parent_grant.id,
            Some(Budget {
                tokens: Some(tokens),
                ..Default::default()
            }),
            3,
        );
        (parent_grant.id, child_persona.id)
    }

    #[test]
    fn delegate_different_target_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                // `other/*` is outside `acme/*`.
                "github:push:other/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("scope"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn delegate_child_budget_exceeds_parent_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(15_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("tokens"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn delegate_attenuated_child_approved() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .expect("attenuated delegate approved");
        assert_eq!(child.scope, "github:push:acme/widgets");
        assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
        assert_eq!(child.budget.and_then(|b| b.tokens), Some(3_000));
    }

    #[test]
    fn delegate_chained_grandchild_approved() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .expect("first delegate approved");

        // Grandchild further narrows budget.
        let grandchild_persona = store.create_persona("agent-grandchild").unwrap();
        let grandchild = store
            .delegate_grant_full(
                &child.id,
                &grandchild_persona.id,
                "github:push:acme/widgets",
                Some(60),
                Some(Budget {
                    tokens: Some(1_000),
                    ..Default::default()
                }),
            )
            .expect("grandchild delegate approved");
        assert_eq!(grandchild.parent_grant_id.as_deref(), Some(child.id.as_str()));
        assert_eq!(grandchild.budget.and_then(|b| b.tokens), Some(1_000));
    }

    #[test]
    fn delegate_parent_budget_child_no_budget_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        // No child budget — parent has one, so this must fail.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                None,
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("budget"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn delegate_child_expiry_later_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 600);

        // Parent TTL is 600s; child asks for 3600s.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(3600),
                Some(Budget {
                    tokens: Some(1_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("expiry"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }
}
