use chrono::Utc;
use rusqlite::OptionalExtension;
use uuid::Uuid;

use crate::store::{DaemonStore, StoreError};

pub struct ApprovalRequestInfo {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub ttl_secs: Option<u64>,
    pub action: String,
    pub risk_level: String,
    pub status: String,
    pub reason: Option<String>,
    pub created_at: String,
}

pub enum ApprovalOutcome {
    Approved,
    Denied { reason: String },
    Narrowed { new_scope: String },
}

impl DaemonStore {
    pub fn submit_approval(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        action: &str,
        risk_level: &str,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        let id = format!("approval-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        self.conn().execute(
            "INSERT INTO approval_requests \
             (id, persona_id, credential_name, scope, ttl_secs, action, risk_level, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                action,
                risk_level,
                created_at,
            ],
        )?;

        Ok(ApprovalRequestInfo {
            id,
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            ttl_secs,
            action: action.to_string(),
            risk_level: risk_level.to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at,
        })
    }

    pub fn list_pending_approvals(&self) -> Result<Vec<ApprovalRequestInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, persona_id, credential_name, scope, ttl_secs, action, risk_level, \
             status, reason, created_at \
             FROM approval_requests WHERE status = 'pending' ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            let ttl: Option<i64> = row.get(4)?;
            Ok(ApprovalRequestInfo {
                id: row.get(0)?,
                persona_id: row.get(1)?,
                credential_name: row.get(2)?,
                scope: row.get(3)?,
                ttl_secs: ttl.map(|v| v as u64),
                action: row.get(5)?,
                risk_level: row.get(6)?,
                status: row.get(7)?,
                reason: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut requests = Vec::new();
        for row in rows {
            requests.push(row?);
        }
        Ok(requests)
    }

    pub fn resolve_approval(&self, id: &str, outcome: &ApprovalOutcome) -> Result<(), StoreError> {
        // Verify the request exists and is pending.
        let row: Option<(String, String, String, Option<i64>)> = self
            .conn()
            .query_row(
                "SELECT persona_id, credential_name, scope, ttl_secs \
                 FROM approval_requests WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let (persona_id, credential_name, scope, ttl_secs_raw) =
            row.ok_or(StoreError::NotFound)?;
        let ttl_secs: Option<u64> = ttl_secs_raw.map(|v| v as u64);

        let resolved_at = Utc::now().to_rfc3339();

        match outcome {
            ApprovalOutcome::Approved => {
                self.create_grant(&persona_id, &credential_name, &scope, ttl_secs)?;
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'approved', resolved_at = ?1 \
                     WHERE id = ?2",
                    rusqlite::params![resolved_at, id],
                )?;
            }
            ApprovalOutcome::Denied { reason } => {
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'denied', resolved_at = ?1, \
                     reason = ?2 WHERE id = ?3",
                    rusqlite::params![resolved_at, reason, id],
                )?;
            }
            ApprovalOutcome::Narrowed { new_scope } => {
                self.create_grant(&persona_id, &credential_name, new_scope, ttl_secs)?;
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'narrowed', resolved_at = ?1, \
                     scope = ?2 WHERE id = ?3",
                    rusqlite::params![resolved_at, new_scope, id],
                )?;
            }
        }

        Ok(())
    }

    pub fn get_approval(&self, id: &str) -> Result<ApprovalRequestInfo, StoreError> {
        self.conn()
            .query_row(
                "SELECT id, persona_id, credential_name, scope, ttl_secs, action, risk_level, \
                 status, reason, created_at \
                 FROM approval_requests WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    let ttl: Option<i64> = row.get(4)?;
                    Ok(ApprovalRequestInfo {
                        id: row.get(0)?,
                        persona_id: row.get(1)?,
                        credential_name: row.get(2)?,
                        scope: row.get(3)?,
                        ttl_secs: ttl.map(|v| v as u64),
                        action: row.get(5)?,
                        risk_level: row.get(6)?,
                        status: row.get(7)?,
                        reason: row.get(8)?,
                        created_at: row.get(9)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
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
        store
            .list_personas()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .id
    }

    #[test]
    fn submit_approval_appears_in_pending() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();
        assert_eq!(req.status, "pending");

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, req.id);
        assert_eq!(pending[0].status, "pending");
    }

    #[test]
    fn approve_creates_grant_and_updates_status() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        store.resolve_approval(&req.id, &ApprovalOutcome::Approved).unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].credential_name, "api-key");
        assert_eq!(grants[0].scope, "read");
        assert_eq!(grants[0].status, "active");
    }

    #[test]
    fn deny_no_grant_status_denied_with_reason() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "write", None, "credential.access", "high")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Denied {
                    reason: "too broad".to_string(),
                },
            )
            .unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "denied");
        assert_eq!(resolved.reason.as_deref(), Some("too broad"));

        let grants = store.list_grants().unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn narrow_creates_grant_with_narrowed_scope() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read:write:admin", None, "credential.access", "high")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Narrowed {
                    new_scope: "read".to_string(),
                },
            )
            .unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "narrowed");
        assert_eq!(resolved.scope, "read");

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "read");
    }

    #[test]
    fn resolve_nonexistent_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result = store.resolve_approval("approval-does-not-exist", &ApprovalOutcome::Approved);
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn list_pending_excludes_resolved() {
        let store = setup();
        let pid = persona_id(&store);

        let req1 = store
            .submit_approval(&pid, "key1", "read", None, "credential.access", "high")
            .unwrap();
        let _req2 = store
            .submit_approval(&pid, "key2", "write", None, "credential.access", "high")
            .unwrap();

        store.resolve_approval(&req1.id, &ApprovalOutcome::Approved).unwrap();

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].credential_name, "key2");
    }
}
