use chrono::{TimeZone, Utc};
use rusqlite::types::Value as SqlValue;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::infra::store::{DaemonStore, StoreError};

/// implementation-note-34 — convert unix-ms to an RFC3339 string so
/// the date-range filter compares lexicographically against the existing TEXT
/// `timestamp` column. Negative or out-of-range values clamp to the unix epoch.
fn ms_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let nsecs = (ms.rem_euclid(1000) as u32) * 1_000_000;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
        .to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub action: String,
    pub credential: Option<String>,
    pub outcome: String,
    pub details: Option<String>,
}

#[derive(Debug, Default)]
pub struct AuditFilter {
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<usize>,
    /// implementation-note-35 — filter to actions that start with this prefix,
    /// e.g. `"grant."` shows only grant-family events. Rendering-layer only;
    /// applied after the SQL fetch so the limit still governs the fetch window.
    pub action_prefix: Option<String>,
    /// implementation-note-34 — alias for `agent_id`. Both populate
    /// the `agent_id = ?` clause; if both are set, `persona_id` wins.
    pub persona_id: Option<String>,
    /// implementation-note-34 — narrow to rows whose `credential`
    /// column starts with this prefix. SQL `LIKE` with appended `%`.
    pub scope: Option<String>,
    /// implementation-note-34 — inclusive lower bound (unix ms).
    /// Converted to RFC3339 before binding so it compares against the
    /// existing TEXT timestamp column.
    pub since_ms: Option<i64>,
    /// implementation-note-34 — inclusive upper bound (unix ms).
    pub before_ms: Option<i64>,
}

impl DaemonStore {
    pub fn log_event(
        &self,
        agent_id: Option<&str>,
        action: &str,
        credential: Option<&str>,
        outcome: &str,
        details: Option<&str>,
    ) -> Result<i64, StoreError> {
        let timestamp = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO audit_log (timestamp, agent_id, action, credential, outcome, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![timestamp, agent_id, action, credential, outcome, details],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, StoreError> {
        // implementation-note-34 — dynamic positional binding so we
        // can compose any combination of {agent_id, action, persona_id, scope,
        // since_ms, before_ms} without the previous hand-numbered ladder.
        let mut query = String::from(
            "SELECT id, timestamp, agent_id, action, credential, outcome, details
             FROM audit_log WHERE 1=1",
        );

        let mut binds: Vec<SqlValue> = Vec::new();

        // persona_id and agent_id both target the agent_id column; persona_id wins.
        let agent_filter = filter
            .persona_id
            .as_deref()
            .or(filter.agent_id.as_deref());
        if let Some(aid) = agent_filter {
            binds.push(SqlValue::Text(aid.to_string()));
            query.push_str(&format!(" AND agent_id = ?{}", binds.len()));
        }

        if let Some(act) = filter.action.as_deref() {
            binds.push(SqlValue::Text(act.to_string()));
            query.push_str(&format!(" AND action = ?{}", binds.len()));
        }

        if let Some(scope) = filter.scope.as_deref() {
            // LIKE with a trailing % matches "scope/", "scope/path", etc.
            binds.push(SqlValue::Text(format!("{}%", scope)));
            query.push_str(&format!(" AND credential LIKE ?{}", binds.len()));
        }

        if let Some(since_ms) = filter.since_ms {
            binds.push(SqlValue::Text(ms_to_rfc3339(since_ms)));
            query.push_str(&format!(" AND timestamp >= ?{}", binds.len()));
        }

        if let Some(before_ms) = filter.before_ms {
            binds.push(SqlValue::Text(ms_to_rfc3339(before_ms)));
            query.push_str(&format!(" AND timestamp <= ?{}", binds.len()));
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let mut stmt = self.conn().prepare(&query)?;

        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                agent_id: row.get(2)?,
                action: row.get(3)?,
                credential: row.get(4)?,
                outcome: row.get(5)?,
                details: row.get(6)?,
            })
        };

        let mut entries: Vec<AuditEntry> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), map_row)?
            .collect::<Result<Vec<_>, _>>()?;

        // implementation-note-35 — action_prefix filter applied post-fetch so
        // the SQL limit governs the fetch window; the prefix narrows what
        // the dashboard displays. Empty/whitespace prefix is a no-op.
        if let Some(ref prefix) = filter.action_prefix {
            let p = prefix.trim();
            if !p.is_empty() {
                entries.retain(|e| e.action.starts_with(p));
            }
        }

        Ok(entries)
    }

    /// implementation-note-34 — test helper to insert an audit row
    /// with an explicit timestamp string (so date-range tests can pin
    /// timestamps without sleeping).
    #[cfg(test)]
    pub(crate) fn log_event_with_timestamp(
        &self,
        timestamp: &str,
        agent_id: Option<&str>,
        action: &str,
        credential: Option<&str>,
        outcome: &str,
    ) -> Result<i64, StoreError> {
        self.conn().execute(
            "INSERT INTO audit_log (timestamp, agent_id, action, credential, outcome, details)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![timestamp, agent_id, action, credential, outcome],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn audit_count(&self) -> Result<u64, StoreError> {
        let count: i64 =
            self.conn()
                .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::store::DaemonStore;

    #[test]
    fn log_event_and_query_returns_correct_fields() {
        let store = DaemonStore::open_in_memory().unwrap();
        let id = store
            .log_event(
                Some("agent-1"),
                "grant.create",
                Some("cred-abc"),
                "allowed",
                Some("test details"),
            )
            .unwrap();

        let entries = store.query_audit(&AuditFilter::default()).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.id, id);
        assert_eq!(e.agent_id.as_deref(), Some("agent-1"));
        assert_eq!(e.action, "grant.create");
        assert_eq!(e.credential.as_deref(), Some("cred-abc"));
        assert_eq!(e.outcome, "allowed");
        assert_eq!(e.details.as_deref(), Some("test details"));
    }

    #[test]
    fn agent_id_filter_returns_only_matching() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .log_event(Some("agent-1"), "grant.create", None, "allowed", None)
            .unwrap();
        store
            .log_event(Some("agent-2"), "grant.create", None, "allowed", None)
            .unwrap();
        store
            .log_event(Some("agent-1"), "credential.access", None, "allowed", None)
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                agent_id: Some("agent-1".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.agent_id.as_deref() == Some("agent-1")));
    }

    #[test]
    fn limit_caps_results() {
        let store = DaemonStore::open_in_memory().unwrap();
        for i in 0..5 {
            store
                .log_event(None, &format!("action-{}", i), None, "ok", None)
                .unwrap();
        }

        let entries = store
            .query_audit(&AuditFilter {
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn no_filter_returns_all_ordered_desc() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.log_event(None, "action-a", None, "ok", None).unwrap();
        store.log_event(None, "action-b", None, "ok", None).unwrap();
        store.log_event(None, "action-c", None, "ok", None).unwrap();

        let entries = store.query_audit(&AuditFilter::default()).unwrap();
        assert_eq!(entries.len(), 3);
        // Ordered DESC by timestamp — last inserted should be first
        assert_eq!(entries[0].action, "action-c");
        assert_eq!(entries[2].action, "action-a");
    }

    #[test]
    fn audit_count_returns_correct_total() {
        let store = DaemonStore::open_in_memory().unwrap();
        assert_eq!(store.audit_count().unwrap(), 0);
        store.log_event(None, "a", None, "ok", None).unwrap();
        store.log_event(None, "b", None, "ok", None).unwrap();
        assert_eq!(store.audit_count().unwrap(), 2);
    }

    #[test]
    fn empty_audit_log_returns_empty_vec_and_zero_count() {
        let store = DaemonStore::open_in_memory().unwrap();
        let entries = store.query_audit(&AuditFilter::default()).unwrap();
        assert!(entries.is_empty());
        assert_eq!(store.audit_count().unwrap(), 0);
    }

    #[test]
    fn action_prefix_filter_returns_only_matching() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.log_event(None, "grant.create", None, "ok", None).unwrap();
        store.log_event(None, "grant.revoke", None, "ok", None).unwrap();
        store.log_event(None, "approval.dismissed", None, "ok", None).unwrap();
        store.log_event(None, "broker.materialization", None, "ok", None).unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                action_prefix: Some("grant.".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 2, "only grant.* actions should be returned");
        assert!(entries.iter().all(|e| e.action.starts_with("grant.")));
    }

    #[test]
    fn persona_filter_isolates_rows() {
        // implementation-note-34 — persona_id targets the agent_id
        // column; a row tagged "persona-x" should not surface when querying
        // for "persona-y".
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .log_event(Some("persona-x"), "grant.create", None, "allowed", None)
            .unwrap();
        store
            .log_event(Some("persona-y"), "grant.create", None, "allowed", None)
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some("persona-x".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 1, "only persona-x rows should be returned");
        assert_eq!(entries[0].agent_id.as_deref(), Some("persona-x"));
    }

    #[test]
    fn since_before_bound_timestamps() {
        // implementation-note-34 — since_ms / before_ms inclusive
        // bounds. Insert three rows at t=100/200/300 ms; query [150, 250]
        // expects only the t=200 row.
        let store = DaemonStore::open_in_memory().unwrap();
        let t100 = ms_to_rfc3339(100);
        let t200 = ms_to_rfc3339(200);
        let t300 = ms_to_rfc3339(300);
        store
            .log_event_with_timestamp(&t100, None, "a", None, "ok")
            .unwrap();
        store
            .log_event_with_timestamp(&t200, None, "b", None, "ok")
            .unwrap();
        store
            .log_event_with_timestamp(&t300, None, "c", None, "ok")
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                since_ms: Some(150),
                before_ms: Some(250),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 1, "only the t=200 row should match [150,250]");
        assert_eq!(entries[0].action, "b");
    }

    #[test]
    fn action_prefix_filter_empty_string_is_noop() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.log_event(None, "grant.create", None, "ok", None).unwrap();
        store.log_event(None, "approval.dismissed", None, "ok", None).unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                action_prefix: Some("".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(entries.len(), 2, "empty prefix is a no-op — all events returned");
    }
}
