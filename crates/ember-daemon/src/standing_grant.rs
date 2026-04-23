use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

/// Per-Statement standing grant match (design). Returned when an active
/// grant for the persona carries a Statement whose selector covers the
/// incoming (action, resource) pair. Used as a fast-path approval signal
/// during agent-facing authorize flows: a hit here means the human has
/// already delegated enough authority to bypass the HITL handoff for this
/// specific call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingStatementMatch {
    pub grant_id: String,
    pub block_index: usize,
    pub statement_sid: String,
}

pub struct StandingGrantInfo {
    pub id: String,
    pub persona_id: String,
    pub action_pattern: String,
    pub scope: String,
    pub expires_at: Option<String>,
}

impl DaemonStore {
    pub fn create_standing_grant(
        &self,
        persona_id: &str,
        action_pattern: &str,
        scope: &str,
        expires_at: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO standing_grants \
                 (id, persona_id, action_pattern, scope, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("sg-{}", Uuid::new_v4()),
                    persona_id,
                    action_pattern,
                    scope,
                    expires_at,
                ],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn check_standing_grant(&self, persona_id: &str, action: &str) -> Result<bool, StoreError> {
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM standing_grants \
                 WHERE persona_id = ?1 \
                   AND (?2 GLOB action_pattern OR action_pattern = '*') \
                   AND (expires_at IS NULL OR expires_at > datetime('now'))",
                rusqlite::params![persona_id, action],
                |row| row.get(0),
            )
            .map_err(StoreError::Sqlite)?;
        Ok(count > 0)
    }

    pub fn list_standing_grants(&self) -> Result<Vec<StandingGrantInfo>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, persona_id, action_pattern, scope, expires_at \
                 FROM standing_grants ORDER BY created_at DESC",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StandingGrantInfo {
                    id: row.get(0)?,
                    persona_id: row.get(1)?,
                    action_pattern: row.get(2)?,
                    scope: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })
            .map_err(StoreError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::Sqlite)
    }

    /// Walk every active grant for the persona and return the first that
    /// carries a Statement applicable to the request. Used by approval
    /// flows to short-circuit the HITL handoff when a prior grant already
    /// authorizes the call at the Statement level.
    ///
    /// Returns `Ok(None)` if no active grant has an applicable Statement —
    /// the caller falls back to the classical `check_standing_grant`
    /// persona-level action-pattern cache or to interactive approval.
    pub fn match_standing_statement(
        &self,
        persona_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<Option<StandingStatementMatch>, StoreError> {
        let grants = self.list_active_grants()?;
        for g in grants {
            if g.persona_id != persona_id {
                continue;
            }
            let ag = match self.get_access_grant(&g.id) {
                Ok(a) => a,
                Err(_) => continue,
            };
            for (block_idx, stmt) in ag.statements() {
                if stmt.applicable_to(action, resource) {
                    return Ok(Some(StandingStatementMatch {
                        grant_id: g.id.clone(),
                        block_index: block_idx,
                        statement_sid: stmt.sid.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn remove_standing_grant(&self, id: &str) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "DELETE FROM standing_grants WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("agent-test").expect("create persona");
        store
    }

    fn persona_id(store: &DaemonStore) -> String {
        store.list_personas().unwrap().into_iter().next().unwrap().id
    }

    #[test]
    fn create_and_list_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].persona_id, pid);
        assert_eq!(grants[0].action_pattern, "credential.access");
        assert_eq!(grants[0].scope, "*");
        assert!(grants[0].id.starts_with("sg-"));
        assert!(grants[0].expires_at.is_none());
    }

    #[test]
    fn check_standing_grant_exact_match() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
        assert!(!store.check_standing_grant(&pid, "credential.write").unwrap());
    }

    #[test]
    fn check_standing_grant_wildcard_pattern() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.*", "*", None)
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
        assert!(store.check_standing_grant(&pid, "credential.write").unwrap());
        assert!(!store.check_standing_grant(&pid, "sandbox.run").unwrap());
    }

    #[test]
    fn check_standing_grant_star_pattern_matches_all() {
        let store = setup();
        let pid = persona_id(&store);
        store.create_standing_grant(&pid, "*", "*", None).unwrap();
        assert!(store.check_standing_grant(&pid, "any.action").unwrap());
    }

    #[test]
    fn remove_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        store.remove_standing_grant(&grants[0].id).unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn upsert_replaces_on_duplicate_persona_pattern() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "read", None)
            .unwrap();
        store
            .create_standing_grant(&pid, "credential.access", "read:write", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "read:write");
    }

    #[test]
    fn check_standing_grant_wrong_persona() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        assert!(!store.check_standing_grant("other-persona", "credential.access").unwrap());
    }

    #[test]
    fn expired_standing_grant_not_matched() {
        let store = setup();
        let pid = persona_id(&store);
        // Insert a grant that expired in the past.
        store
            .create_standing_grant(&pid, "credential.access", "*", Some("2000-01-01T00:00:00"))
            .unwrap();
        // Must not match even though the action and persona are correct.
        assert!(!store.check_standing_grant(&pid, "credential.access").unwrap());
    }

    #[test]
    fn future_expiry_standing_grant_matches() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", Some("2099-01-01T00:00:00"))
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
    }

    #[test]
    fn match_standing_statement_returns_matching_grant() {
        let store = setup();
        let pid = persona_id(&store);
        // create_grant synthesizes a single-statement chain with scope
        // `github:read:emberdotlink/widgets`, action=github:read,
        // selector=Exact{"emberdotlink/widgets"}.
        store
            .create_grant(&pid, "gh-token", "github:read:emberdotlink/widgets", None)
            .unwrap();

        let hit = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(hit.is_some(), "should match on applicable Statement");

        // Request with a different resource — no match.
        let miss = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/other")
            .unwrap();
        assert!(miss.is_none(), "must not match a different resource");

        // Wrong persona — no match.
        let miss = store
            .match_standing_statement("other-persona", "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(miss.is_none(), "must not match a different persona");
    }
}
