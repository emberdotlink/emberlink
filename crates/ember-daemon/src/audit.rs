use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::store::{DaemonStore, StoreError};

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
    /// implementation-note-8 — filter to actions that start with this prefix,
    /// e.g. `"grant."` shows only grant-family events. Rendering-layer only;
    /// applied after the SQL fetch so the limit still governs the fetch window.
    pub action_prefix: Option<String>,
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
        let mut query = String::from(
            "SELECT id, timestamp, agent_id, action, credential, outcome, details
             FROM audit_log WHERE 1=1",
        );

        if filter.agent_id.is_some() {
            query.push_str(" AND agent_id = ?1");
        }
        if filter.action.is_some() {
            query.push_str(if filter.agent_id.is_some() {
                " AND action = ?2"
            } else {
                " AND action = ?1"
            });
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

        let mut entries = match (&filter.agent_id, &filter.action) {
            (Some(aid), Some(act)) => stmt
                .query_map(params![aid, act], map_row)?
                .collect::<Result<Vec<_>, _>>()?,
            (Some(aid), None) => stmt
                .query_map(params![aid], map_row)?
                .collect::<Result<Vec<_>, _>>()?,
            (None, Some(act)) => stmt
                .query_map(params![act], map_row)?
                .collect::<Result<Vec<_>, _>>()?,
            (None, None) => stmt
                .query_map([], map_row)?
                .collect::<Result<Vec<_>, _>>()?,
        };

        // implementation-note-8 — action_prefix filter applied post-fetch so
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
    use crate::store::DaemonStore;

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
