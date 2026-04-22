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
    /// Approve this request AND create a standing grant so future matching
    /// requests auto-approve without prompting.
    ///
    /// `scope` is `Some(narrowed_scope)` when the user wants the standing
    /// grant limited to a narrower scope than the original request.
    /// `expires_at` is an ISO-8601 string; `None` means indefinite.
    Always {
        scope: Option<String>,
        expires_at: Option<String>,
    },
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
        let row: Option<(String, String, String, Option<i64>, String)> = self
            .conn()
            .query_row(
                "SELECT persona_id, credential_name, scope, ttl_secs, action \
                 FROM approval_requests WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;

        let (persona_id, credential_name, scope, ttl_secs_raw, action) =
            row.ok_or(StoreError::NotFound)?;
        let ttl_secs: Option<u64> = ttl_secs_raw.map(|v| v as u64);

        let resolved_at = Utc::now().to_rfc3339();

        match outcome {
            ApprovalOutcome::Approved => {
                let grant = self.create_grant(&persona_id, &credential_name, &scope, ttl_secs)?;
                let _ = self.log_event(
                    Some(&persona_id),
                    "grant.issued",
                    Some(&credential_name),
                    "allowed",
                    Some(
                        &serde_json::json!({
                            "grant_id": grant.id,
                            "scope": scope,
                            "ttl_secs": ttl_secs,
                            "source": "approval",
                        })
                        .to_string(),
                    ),
                );
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
                let grant =
                    self.create_grant(&persona_id, &credential_name, new_scope, ttl_secs)?;
                let _ = self.log_event(
                    Some(&persona_id),
                    "grant.issued",
                    Some(&credential_name),
                    "allowed",
                    Some(
                        &serde_json::json!({
                            "grant_id": grant.id,
                            "scope": new_scope,
                            "ttl_secs": ttl_secs,
                            "source": "approval_narrowed",
                        })
                        .to_string(),
                    ),
                );
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'narrowed', resolved_at = ?1, \
                     scope = ?2 WHERE id = ?3",
                    rusqlite::params![resolved_at, new_scope, id],
                )?;
            }
            ApprovalOutcome::Always { scope: narrow_scope, expires_at } => {
                // Resolve the effective scope: narrowed if provided, original otherwise.
                let effective_scope = narrow_scope.as_deref().unwrap_or(&scope);
                let grant =
                    self.create_grant(&persona_id, &credential_name, effective_scope, ttl_secs)?;
                // Create the standing grant so future matching requests auto-approve.
                self.create_standing_grant(
                    &persona_id,
                    &action,
                    effective_scope,
                    expires_at.as_deref(),
                )?;
                let _ = self.log_event(
                    Some(&persona_id),
                    "grant.issued",
                    Some(&credential_name),
                    "allowed",
                    Some(
                        &serde_json::json!({
                            "grant_id": grant.id,
                            "scope": effective_scope,
                            "ttl_secs": ttl_secs,
                            "source": "approval_always",
                        })
                        .to_string(),
                    ),
                );
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'approved', resolved_at = ?1 \
                     WHERE id = ?2",
                    rusqlite::params![resolved_at, id],
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

    #[test]
    fn resolve_approval_approved_logs_grant_issued() {
        use crate::audit::AuditFilter;
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        store.resolve_approval(&req.id, &ApprovalOutcome::Approved).unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                action: Some("grant.issued".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(!entries.is_empty(), "expected grant.issued audit row");
        let entry = &entries[0];
        assert_eq!(entry.action, "grant.issued");
        assert_eq!(entry.agent_id.as_deref(), Some(&*pid));
        assert_eq!(entry.outcome, "allowed");
        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap()).unwrap();
        assert_eq!(details["source"], serde_json::json!("approval"));
        assert_eq!(details["scope"], serde_json::json!("read"));
    }

    #[test]
    fn resolve_approval_narrowed_logs_grant_issued() {
        use crate::audit::AuditFilter;
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(
                &pid,
                "api-key",
                "read:write:admin",
                None,
                "credential.access",
                "high",
            )
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Narrowed {
                    new_scope: "read".to_string(),
                },
            )
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                action: Some("grant.issued".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(!entries.is_empty(), "expected grant.issued audit row");
        let entry = &entries[0];
        assert_eq!(entry.action, "grant.issued");
        assert_eq!(entry.agent_id.as_deref(), Some(&*pid));
        assert_eq!(entry.outcome, "allowed");
        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap()).unwrap();
        assert_eq!(details["source"], serde_json::json!("approval_narrowed"));
        assert_eq!(details["scope"], serde_json::json!("read"));
    }

    #[test]
    fn resolve_approval_always_creates_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access.github-token", "low")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Always {
                    scope: None,
                    expires_at: Some("2099-01-01T00:00:00".to_string()),
                },
            )
            .unwrap();

        let standing = store.list_standing_grants().unwrap();
        assert_eq!(standing.len(), 1);
        assert_eq!(standing[0].persona_id, pid);
        assert_eq!(standing[0].action_pattern, "credential.access.github-token");
        assert_eq!(standing[0].scope, "read");
        assert_eq!(standing[0].expires_at.as_deref(), Some("2099-01-01T00:00:00"));
    }

    #[test]
    fn resolve_approval_always_issues_grant_and_logs_audit() {
        use crate::audit::AuditFilter;
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access.github-token", "low")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Always {
                    scope: None,
                    expires_at: None,
                },
            )
            .unwrap();

        // Approval status should be 'approved'
        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");

        // A credential grant should be created
        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "read");

        // Audit entry with source = "approval_always"
        let entries = store
            .query_audit(&AuditFilter {
                action: Some("grant.issued".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(!entries.is_empty(), "expected grant.issued audit row");
        let details: serde_json::Value =
            serde_json::from_str(entries[0].details.as_deref().unwrap()).unwrap();
        assert_eq!(details["source"], serde_json::json!("approval_always"));
        assert_eq!(details["scope"], serde_json::json!("read"));
    }

    #[test]
    fn resolve_approval_always_with_narrow_scope_creates_narrowed_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read:write:admin", None, "credential.access.github-token", "low")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Always {
                    scope: Some("read".to_string()),
                    expires_at: None,
                },
            )
            .unwrap();

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "read");

        let standing = store.list_standing_grants().unwrap();
        assert_eq!(standing.len(), 1);
        assert_eq!(standing[0].scope, "read");
        assert_eq!(standing[0].action_pattern, "credential.access.github-token");
    }

    #[test]
    fn check_standing_grant_matches_after_approve_always_without_prompt() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access.github-token", "low")
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Always {
                    scope: None,
                    expires_at: None,
                },
            )
            .unwrap();

        // A subsequent request for the same persona + action should match
        // the standing grant fast-path.
        assert!(
            store
                .check_standing_grant(&pid, "credential.access.github-token")
                .unwrap(),
            "standing grant should auto-approve future requests"
        );

        // Different action must not match
        assert!(
            !store.check_standing_grant(&pid, "credential.access.other-token").unwrap(),
            "exact-match pattern must not match unrelated actions"
        );
    }
}
