use chrono::Utc;
use core_types::Statement;
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
    // TODO: plumb these fields from MCP daemon_transport + SDK
    pub tool_name: Option<String>,
    pub target_host: Option<String>,
    pub target_summary: Option<String>,
    pub target_url: Option<String>,
    pub agent_framework: Option<String>,
    /// implementation-note-1 — composite envelope statements (3-statement
    /// credential+session+time bundle minted by `ember sandbox run`)
    /// serialized as JSON when set. Surfaces as a single approval entry
    /// (NOT three) so the dashboard can render all three statements as
    /// one card. `None` for legacy single-statement approvals.
    pub composite_statements: Option<Vec<Statement>>,
    /// Grant ID minted on `Approved` resolution. Populated only when the
    /// approval has `composite_statements` set; the caller (CLI sandbox
    /// run) polls `get_approval` to discover the resulting grant ID.
    pub result_grant_id: Option<String>,
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
        self.submit_approval_inner(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            action,
            risk_level,
            None,
        )
    }

    /// implementation-note-1 — submit ONE approval entry that bundles a 3-statement
    /// composite envelope (credential + session + time). On `Approved` the
    /// resolver mints a single composite grant whose `blocks_json` is
    /// overwritten with the supplied statement list (matching the shape
    /// `ember sandbox run` previously wrote directly).
    #[allow(clippy::too_many_arguments)]
    pub fn submit_composite_approval(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        action: &str,
        risk_level: &str,
        statements: Vec<Statement>,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        self.submit_approval_inner(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            action,
            risk_level,
            Some(statements),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_approval_inner(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        action: &str,
        risk_level: &str,
        composite_statements: Option<Vec<Statement>>,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        let id = format!("approval-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        let composite_json: Option<String> = match &composite_statements {
            Some(stmts) => Some(serde_json::to_string(stmts).map_err(|e| {
                StoreError::InvalidInput(format!("composite statements serialize: {e}"))
            })?),
            None => None,
        };

        self.conn().execute(
            "INSERT INTO approval_requests \
             (id, persona_id, credential_name, scope, ttl_secs, action, risk_level, status, created_at, composite_statements_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                action,
                risk_level,
                created_at,
                composite_json,
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
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements,
            result_grant_id: None,
        })
    }

    pub fn list_pending_approvals(&self) -> Result<Vec<ApprovalRequestInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, persona_id, credential_name, scope, ttl_secs, action, risk_level, \
             status, reason, created_at, composite_statements_json, result_grant_id \
             FROM approval_requests WHERE status = 'pending' ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            let ttl: Option<i64> = row.get(4)?;
            let composite_json: Option<String> = row.get(10)?;
            let composite_statements = composite_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<Vec<Statement>>(s).ok());
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
                tool_name: None,
                target_host: None,
                target_summary: None,
                target_url: None,
                agent_framework: None,
                composite_statements,
                result_grant_id: row.get(11)?,
            })
        })?;
        let mut requests = Vec::new();
        for row in rows {
            requests.push(row?);
        }
        Ok(requests)
    }

    pub fn resolve_approval(&self, id: &str, outcome: &ApprovalOutcome) -> Result<(), StoreError> {
        // implementation-note-1 — composite approvals stash their 3-statement envelope
        // alongside the legacy single-statement fields, so the SELECT row
        // shape grew by one column. Aliased to keep clippy happy.
        type ApprovalRow = (String, String, String, Option<i64>, String, Option<String>);

        // Verify the request exists and is pending.
        let row: Option<ApprovalRow> = self
            .conn()
            .query_row(
                "SELECT persona_id, credential_name, scope, ttl_secs, action, composite_statements_json \
                 FROM approval_requests WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;

        let (persona_id, credential_name, scope, ttl_secs_raw, action, composite_json) =
            row.ok_or(StoreError::NotFound)?;
        let ttl_secs: Option<u64> = ttl_secs_raw.map(|v| v as u64);
        let composite_statements: Option<Vec<Statement>> = composite_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<Statement>>(s).ok());

        let resolved_at = Utc::now().to_rfc3339();

        match outcome {
            ApprovalOutcome::Approved => {
                // implementation-note-1 — for composite approvals seed the parent grant
                // with scope "*" so the bipartite-dominance check in
                // `overwrite_grant_blocks` accepts the typed child
                // statements (Credential / Session / Time). Single-statement
                // approvals keep the original scope verbatim.
                let parent_scope: &str = if composite_statements.is_some() {
                    "*"
                } else {
                    &scope
                };
                let grant = self.create_grant(&persona_id, &credential_name, parent_scope, ttl_secs)?;

                // implementation-note-1 — when the approval bundles a composite envelope,
                // overwrite the freshly-minted single-statement grant's
                // blocks_json with the canonical 3-statement composite chain.
                // Mirrors the path the CLI sandbox-run handler used to take
                // before the policy gate moved minting into approval flow.
                if let Some(stmts) = composite_statements.as_ref() {
                    self.mint_composite_chain_for_grant(&grant.id, &persona_id, &credential_name, stmts.clone(), ttl_secs)?;
                }

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
                            "composite": composite_statements.is_some(),
                        })
                        .to_string(),
                    ),
                );
                self.conn().execute(
                    "UPDATE approval_requests SET status = 'approved', resolved_at = ?1, \
                     result_grant_id = ?2 WHERE id = ?3",
                    rusqlite::params![resolved_at, grant.id, id],
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
                 status, reason, created_at, composite_statements_json, result_grant_id \
                 FROM approval_requests WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    let ttl: Option<i64> = row.get(4)?;
                    let composite_json: Option<String> = row.get(10)?;
                    let composite_statements = composite_json
                        .as_deref()
                        .and_then(|s| serde_json::from_str::<Vec<Statement>>(s).ok());
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
                        tool_name: None,
                        target_host: None,
                        target_summary: None,
                        target_url: None,
                        agent_framework: None,
                        composite_statements,
                        result_grant_id: row.get(11)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// implementation-note-1 — overwrite a freshly-minted single-statement grant's
    /// `blocks_json` with the canonical 3-statement composite chain.
    ///
    /// Mirrors the path `ember sandbox run` previously took inline (signing
    /// block 0 under the persona's root keypair via
    /// `access_grant_from_statements`). Routed through the approval flow so
    /// the policy gate fires before mint, not after.
    ///
    /// The parent grant must be created with scope `"*"` upstream (see
    /// `submit_composite_approval` callers) so the bipartite-dominance
    /// check in `overwrite_grant_blocks` accepts the typed child statements
    /// (Credential / Session / Time) under the wildcard parent.
    fn mint_composite_chain_for_grant(
        &self,
        grant_id: &str,
        persona_id: &str,
        recipient_id: &str,
        statements: Vec<Statement>,
        ttl_secs: Option<u64>,
    ) -> Result<(), StoreError> {
        let created_at_epoch = chrono::Utc::now().timestamp().max(0) as u64;
        let expires_at_epoch = ttl_secs.map(|s| created_at_epoch.saturating_add(s));
        let composite = crate::grant::access_grant_from_statements_for_persona(
            self,
            grant_id,
            persona_id,
            recipient_id,
            statements,
            created_at_epoch,
            expires_at_epoch,
        )?;
        self.overwrite_grant_blocks(grant_id, &composite)
    }

    /// Startup sweep: mark `pending` approval_requests older than `threshold_secs` as
    /// `timed_out`. Returns the number of rows updated. Fires zero notifications.
    /// Logs a single `grant.request.stale_expired` audit event when any rows are expired.
    pub fn expire_stale_pending_approvals(&self, threshold_secs: u64) -> Result<usize, StoreError> {
        if threshold_secs == 0 {
            return Ok(0);
        }
        let cutoff = (Utc::now() - chrono::Duration::seconds(threshold_secs as i64)).to_rfc3339();
        let count = self.conn().execute(
            "UPDATE approval_requests SET status = 'timed_out' \
             WHERE status = 'pending' AND created_at <= ?1",
            rusqlite::params![cutoff],
        )?;
        if count > 0 {
            let _ = self.log_event(
                None,
                "grant.request.stale_expired",
                None,
                "expired",
                Some(&serde_json::json!({"count": count, "threshold_secs": threshold_secs}).to_string()),
            );
        }
        Ok(count)
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

    // --- NOTIF-2: stale pending approval sweep ---

    #[test]
    fn stale_sweep_marks_old_pending_as_timed_out() {
        let store = setup();
        let pid = persona_id(&store);

        // Insert a pending row backdated 2 hours by writing directly.
        let id = format!("approval-{}", uuid::Uuid::new_v4());
        let old_created_at = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        store.conn().execute(
            "INSERT INTO approval_requests \
             (id, persona_id, credential_name, scope, ttl_secs, action, risk_level, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            rusqlite::params![
                id, pid, "api-key", "read", rusqlite::types::Null,
                "credential.access", "high", old_created_at,
            ],
        ).unwrap();

        // Sweep with 1-hour threshold — the 2-hour-old row should be expired.
        let count = store.expire_stale_pending_approvals(3600).unwrap();
        assert_eq!(count, 1, "expected 1 row expired");

        let resolved = store.get_approval(&id).unwrap();
        assert_eq!(resolved.status, "timed_out", "row should be timed_out after sweep");

        // Verify no rows remain in pending.
        let pending = store.list_pending_approvals().unwrap();
        assert!(pending.is_empty(), "no rows should remain pending after sweep");
    }

    #[test]
    fn stale_sweep_does_not_expire_recent_pending() {
        let store = setup();
        let pid = persona_id(&store);

        // A fresh pending row — just submitted, well within the threshold.
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        let count = store.expire_stale_pending_approvals(3600).unwrap();
        assert_eq!(count, 0, "fresh row must not be expired");

        let still_pending = store.get_approval(&req.id).unwrap();
        assert_eq!(still_pending.status, "pending");
    }

    #[test]
    fn stale_sweep_threshold_zero_is_noop() {
        let store = setup();
        let pid = persona_id(&store);

        let id = format!("approval-{}", uuid::Uuid::new_v4());
        let old_created_at = (chrono::Utc::now() - chrono::Duration::hours(48)).to_rfc3339();
        store.conn().execute(
            "INSERT INTO approval_requests \
             (id, persona_id, credential_name, scope, ttl_secs, action, risk_level, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            rusqlite::params![
                id, pid, "api-key", "read", rusqlite::types::Null,
                "credential.access", "high", old_created_at,
            ],
        ).unwrap();

        let count = store.expire_stale_pending_approvals(0).unwrap();
        assert_eq!(count, 0, "threshold=0 must be a no-op");

        let still_pending = store.get_approval(&id).unwrap();
        assert_eq!(still_pending.status, "pending");
    }

    // --- implementation-note-1 — composite-grant approval flow ---

    fn demo_three_statements(credential: &str) -> Vec<Statement> {
        use core_types::{Budget, ResourceSelector, ResourceType, Usage};

        vec![
            Statement {
                sid: "s0-credential".to_string(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".to_string()],
                resource: ResourceSelector::Exact { value: credential.to_string() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
            Statement {
                sid: "s1-session".to_string(),
                resource_type: ResourceType::Session,
                actions: vec!["llm:generate".to_string()],
                resource: ResourceSelector::Glob {
                    pattern: "anthropic/*".to_string(),
                },
                budget: Some(Budget {
                    tokens: Some(20_000),
                    ..Budget::default()
                }),
                usage: Usage::default(),
                conditions: vec![],
            },
            Statement {
                sid: "s2-time".to_string(),
                resource_type: ResourceType::Time,
                actions: vec!["time:wall_clock".to_string()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    wall_clock_secs: Some(1800),
                    ..Budget::default()
                }),
                usage: Usage::default(),
                conditions: vec![],
            },
        ]
    }

    #[test]
    fn submit_composite_approval_appears_as_one_pending_entry_with_three_statements() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-github-token");

        let req = store
            .submit_composite_approval(
                &pid,
                "obj-github-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts.clone(),
            )
            .unwrap();
        assert_eq!(req.status, "pending");
        assert_eq!(req.composite_statements.as_ref().map(Vec::len), Some(3));

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "composite envelope must surface as ONE entry, not three"
        );
        let listed = &pending[0];
        assert_eq!(listed.id, req.id);
        let listed_stmts = listed
            .composite_statements
            .as_ref()
            .expect("composite statements must round-trip through SQL");
        assert_eq!(listed_stmts.len(), 3, "all 3 statements must be hydrated");
        assert_eq!(listed_stmts[0].sid, "s0-credential");
        assert_eq!(listed_stmts[1].sid, "s1-session");
        assert_eq!(listed_stmts[2].sid, "s2-time");
    }

    #[test]
    fn approve_composite_mints_three_statement_grant_and_records_grant_id() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-github-token");

        let req = store
            .submit_composite_approval(
                &pid,
                "obj-github-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        store
            .resolve_approval(&req.id, &ApprovalOutcome::Approved)
            .unwrap();

        // The approval row records the minted grant ID so the caller
        // (CLI sandbox-run) can poll for it.
        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");
        let grant_id = resolved
            .result_grant_id
            .as_deref()
            .expect("composite approval must record result_grant_id");
        assert!(grant_id.starts_with("grant-"));

        // Loading the grant returns the canonical 3-statement composite chain
        // (NOT the single-statement shim `create_grant` writes by default).
        let access_grant = store.get_access_grant(grant_id).unwrap();
        assert_eq!(access_grant.blocks.len(), 1, "one block envelope");
        let block = &access_grant.blocks[0].block;
        assert_eq!(
            block.statements.len(),
            3,
            "composite grant must carry all 3 statements"
        );
        assert_eq!(block.statements[0].sid, "s0-credential");
        assert_eq!(block.statements[1].sid, "s1-session");
        assert_eq!(block.statements[2].sid, "s2-time");
    }

    #[test]
    fn deny_composite_does_not_mint_any_grant() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-github-token");

        let req = store
            .submit_composite_approval(
                &pid,
                "obj-github-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        store
            .resolve_approval(
                &req.id,
                &ApprovalOutcome::Denied { reason: "demo deny".to_string() },
            )
            .unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "denied");
        assert!(
            resolved.result_grant_id.is_none(),
            "denied composite approval must not mint a grant"
        );
        assert!(
            store.list_grants().unwrap().is_empty(),
            "no grants must exist after composite deny"
        );
    }

    #[test]
    fn sandbox_run_composite_mint_policy_gate_under_require_approval_default() {
        // End-to-end gate: with the policy engine's default
        // (`default_decision = "require_approval"`) and the default
        // `credential.access` rule, the composite-mint flow MUST land in
        // submit_composite_approval, NOT in create_grant. This is the
        // demo's "agent asks → human approves" beat.
        use crate::policy::{PolicyDecision, PolicyEngine};

        let store = setup();
        let pid = persona_id(&store);
        let policy = PolicyEngine::default();
        let eval = policy.evaluate("credential.access");
        assert_eq!(
            eval.decision,
            PolicyDecision::RequireApproval,
            "default policy must require approval for credential.access"
        );

        // The CLI sandbox-run code path on RequireApproval calls
        // submit_composite_approval; mirror that here.
        let stmts = demo_three_statements("obj-github-token");
        let req = store
            .submit_composite_approval(
                &pid,
                "obj-github-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        // Exactly one pending entry surfaces, regardless of statement count.
        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "sandbox-run policy gate must yield ONE approval entry, not three"
        );
        assert_eq!(pending[0].id, req.id);
        assert_eq!(
            pending[0].composite_statements.as_ref().map(Vec::len),
            Some(3),
            "the single approval entry must carry all 3 statements"
        );
        // No grant exists until the operator approves.
        assert!(
            store.list_grants().unwrap().is_empty(),
            "no grant must be minted until the human approves"
        );
    }
}
