// implementation-note-6
use chrono::Utc;
use core_approval::{ApprovalLifecycle, LifecycleError, RequestId, SubmitMetadata};
use core_approval::ApprovalOutcome as CoreApprovalOutcome;
use core_grant_types::approval::RequestedScope;
use core_grant_types::{GrantProposal, Statement, Usage};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use std::rc::Rc;
use uuid::Uuid;

use crate::infra::store::{DaemonStore, StoreError};

// ---------------------------------------------------------------------------
// DaemonApprovalStore — Phase B adapter implementing ApprovalLifecycle
// ---------------------------------------------------------------------------

/// Adapter that bridges `ApprovalLifecycle` (from `core-approval`) to the
/// existing `DaemonStore` SQLite-backed persistence layer.
///
/// Phase B ships the seam; Phase C migrates callers away from the bare
/// `DaemonStore` approval methods.
///
/// # Safety note
///
/// `DaemonStore` wraps `rusqlite::Connection` which is `!Send`.  The daemon
/// runs exclusively on a single-threaded `tokio::task::LocalSet`, so
/// `DaemonApprovalStore` is never actually moved across threads at runtime.
/// The `unsafe impl Send + Sync` below satisfies the `ApprovalLifecycle`
/// supertrait bounds while preserving that invariant.  Do not move an
/// instance of this type across threads.
pub struct DaemonApprovalStore {
    store: Rc<DaemonStore>,
}

// SAFETY: The daemon is single-threaded (tokio LocalSet). `DaemonStore`
// contains `rusqlite::Connection` which is `!Send` by marker, but is never
// accessed from multiple threads in practice. This impl allows
// `DaemonApprovalStore` to satisfy `ApprovalLifecycle: Send + Sync`.
unsafe impl Send for DaemonApprovalStore {}
unsafe impl Sync for DaemonApprovalStore {}

impl DaemonApprovalStore {
    pub fn new(store: Rc<DaemonStore>) -> Self {
        Self { store }
    }
}

impl From<StoreError> for LifecycleError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => LifecycleError::UnknownRequest,
            StoreError::AlreadyResolved => LifecycleError::AlreadyDecided,
            other => LifecycleError::Storage(other.to_string()),
        }
    }
}

#[async_trait::async_trait]
impl ApprovalLifecycle for DaemonApprovalStore {
    async fn submit_request(
        &self,
        persona: &str,
        credential: &str,
        scope: RequestedScope,
        metadata: SubmitMetadata,
    ) -> Result<RequestId, LifecycleError> {
        // Convert RequestedScope to the flat string the existing store uses.
        let scope_str = scope.capability.clone();

        // PHASE-C-0-5-CODE: thread caller-supplied metadata into the
        // existing DaemonStore::submit_approval_inner signature instead of
        // hardcoding "credential.access" / "high". Tool/host/url/framework
        // are now persisted directly (approval_notify_fields_persisted) so
        // get_approval reads them back correctly.
        let action = if metadata.action.is_empty() {
            "credential.access"
        } else {
            metadata.action.as_str()
        };
        let risk = if metadata.risk_level.is_empty() {
            "high"
        } else {
            metadata.risk_level.as_str()
        };

        let info = self
            .store
            .submit_approval_inner(
                persona,
                credential,
                &scope_str,
                metadata.ttl_secs,
                action,
                risk,
                None,
                metadata.tool_name,
                metadata.target_host,
                metadata.target_url,
                metadata.agent_framework,
                None,
            )
            .map_err(LifecycleError::from)?;

        Ok(RequestId(info.id))
    }

    async fn decide(
        &self,
        request_id: &RequestId,
        outcome: CoreApprovalOutcome,
    ) -> Result<Option<core_grants::Grant>, LifecycleError> {
        // Validate the state transition using the pure-fn from core-approval.
        let info = self
            .store
            .get_approval(&request_id.0)
            .map_err(LifecycleError::from)?;

        let current_status: core_grant_types::approval::ApprovalStatus = match info.status.as_str() {
            "pending" => core_grant_types::approval::ApprovalStatus::Pending,
            "approved" => core_grant_types::approval::ApprovalStatus::Approved,
            "denied" => core_grant_types::approval::ApprovalStatus::Denied,
            "expired" | "timed_out" => core_grant_types::approval::ApprovalStatus::Expired,
            "narrowed" | "narrowed_and_approved" => {
                core_grant_types::approval::ApprovalStatus::NarrowedAndApproved
            }
            _other => {
                return Err(LifecycleError::AlreadyDecided);
            }
        };

        core_approval::transition(current_status, &outcome).map_err(|e| match e {
            core_approval::TransitionError::AlreadyDecided => LifecycleError::AlreadyDecided,
            core_approval::TransitionError::ScopeNotNarrowing => LifecycleError::ScopeNotNarrowing,
        })?;

        // Map CoreApprovalOutcome → daemon-internal ApprovalOutcome for
        // persistence.
        let daemon_outcome = match &outcome {
            CoreApprovalOutcome::Approved => ApprovalOutcome::Approved,
            CoreApprovalOutcome::Denied => ApprovalOutcome::Denied {
                reason: "denied".to_string(),
            },
            CoreApprovalOutcome::Narrowed(requested_scope) => ApprovalOutcome::Narrowed {
                new_scope: requested_scope.capability.clone(),
            },
            CoreApprovalOutcome::Always { ttl_seconds } => ApprovalOutcome::Always {
                scope: None,
                expires_at: Some(
                    (Utc::now() + chrono::Duration::seconds(*ttl_seconds as i64)).to_rfc3339(),
                ),
            },
        };

        self.store
            .resolve_approval(&request_id.0, &daemon_outcome)
            .map_err(LifecycleError::from)?;

        // For grant-issuing outcomes, fetch the resulting AccessGrant and
        // convert to core_grants::Grant at the approval → grant boundary.
        match outcome {
            CoreApprovalOutcome::Approved
            | CoreApprovalOutcome::Narrowed(_)
            | CoreApprovalOutcome::Always { .. } => {
                let resolved = self
                    .store
                    .get_approval(&request_id.0)
                    .map_err(LifecycleError::from)?;
                if let Some(grant_id) = resolved.result_grant_id {
                    let access_grant = self
                        .store
                        .get_access_grant(&grant_id)
                        .map_err(|e| LifecycleError::GrantMintFailed(e.to_string()))?;
                    Ok(Some(access_grant_to_core_grants(&access_grant)))
                } else {
                    Ok(None)
                }
            }
            CoreApprovalOutcome::Denied => Ok(None),
        }
    }

    async fn apply_standing(
        &self,
        _persona: &str,
        _pattern: RequestedScope,
        _ttl_seconds: u64,
    ) -> Result<core_grants::Grant, LifecycleError> {
        // Phase B stub — Phase C wires the full standing-grant path.
        // TODO: coordinate with C-3A — standing-grant
        // path will be implemented once handler.rs migration is complete.
        Err(LifecycleError::Storage("apply_standing: not yet implemented in Phase B".into()))
    }
}

// ---------------------------------------------------------------------------
// DaemonApprovalStoreRef — borrowed-store variant for handler.rs PHASE-C-1
// ---------------------------------------------------------------------------

/// Borrowed-store variant of `DaemonApprovalStore`.
///
/// PHASE-C-1 handler.rs production callers receive `&DaemonStore` from the
/// dispatch layer and have no path to upgrade the borrow into an
/// `Rc<DaemonStore>` without changing the dispatch function signatures
/// across multiple crates. This struct lets those callers cross the
/// `ApprovalLifecycle` seam without touching the dispatch chain.
///
/// Same single-threaded LocalSet safety invariant as `DaemonApprovalStore`
/// — see that type's safety note.
pub struct DaemonApprovalStoreRef<'a> {
    store: &'a DaemonStore,
}

// SAFETY: identical justification as `DaemonApprovalStore`. The daemon runs
// on a single-threaded tokio LocalSet; the contained reference is never
// touched from another thread. These markers satisfy
// `ApprovalLifecycle: Send + Sync`.
unsafe impl<'a> Send for DaemonApprovalStoreRef<'a> {}
unsafe impl<'a> Sync for DaemonApprovalStoreRef<'a> {}

impl<'a> DaemonApprovalStoreRef<'a> {
    pub fn new(store: &'a DaemonStore) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl<'a> ApprovalLifecycle for DaemonApprovalStoreRef<'a> {
    async fn submit_request(
        &self,
        persona: &str,
        credential: &str,
        scope: RequestedScope,
        metadata: SubmitMetadata,
    ) -> Result<RequestId, LifecycleError> {
        // Mirror DaemonApprovalStore::submit_request — see PHASE-C-0-5-CODE
        // in that impl for the metadata/action/risk fallback rationale.
        // approval_notify_fields_persisted: thread the four NOTIF-1 fields
        // through to submit_approval_inner so get_approval returns them.
        let scope_str = scope.capability.clone();
        let action = if metadata.action.is_empty() {
            "credential.access"
        } else {
            metadata.action.as_str()
        };
        let risk = if metadata.risk_level.is_empty() {
            "high"
        } else {
            metadata.risk_level.as_str()
        };

        let info = self
            .store
            .submit_approval_inner(
                persona,
                credential,
                &scope_str,
                metadata.ttl_secs,
                action,
                risk,
                None,
                metadata.tool_name,
                metadata.target_host,
                metadata.target_url,
                metadata.agent_framework,
                None,
            )
            .map_err(LifecycleError::from)?;

        Ok(RequestId(info.id))
    }

    async fn decide(
        &self,
        request_id: &RequestId,
        outcome: CoreApprovalOutcome,
    ) -> Result<Option<core_grants::Grant>, LifecycleError> {
        // Mirror DaemonApprovalStore::decide.
        let info = self
            .store
            .get_approval(&request_id.0)
            .map_err(LifecycleError::from)?;

        let current_status: core_grant_types::approval::ApprovalStatus = match info.status.as_str() {
            "pending" => core_grant_types::approval::ApprovalStatus::Pending,
            "approved" => core_grant_types::approval::ApprovalStatus::Approved,
            "denied" => core_grant_types::approval::ApprovalStatus::Denied,
            "expired" | "timed_out" => core_grant_types::approval::ApprovalStatus::Expired,
            "narrowed" | "narrowed_and_approved" => {
                core_grant_types::approval::ApprovalStatus::NarrowedAndApproved
            }
            _other => {
                return Err(LifecycleError::AlreadyDecided);
            }
        };

        core_approval::transition(current_status, &outcome).map_err(|e| match e {
            core_approval::TransitionError::AlreadyDecided => LifecycleError::AlreadyDecided,
            core_approval::TransitionError::ScopeNotNarrowing => LifecycleError::ScopeNotNarrowing,
        })?;

        let daemon_outcome = match &outcome {
            CoreApprovalOutcome::Approved => ApprovalOutcome::Approved,
            CoreApprovalOutcome::Denied => ApprovalOutcome::Denied {
                reason: "denied".to_string(),
            },
            CoreApprovalOutcome::Narrowed(requested_scope) => ApprovalOutcome::Narrowed {
                new_scope: requested_scope.capability.clone(),
            },
            CoreApprovalOutcome::Always { ttl_seconds } => ApprovalOutcome::Always {
                scope: None,
                expires_at: Some(
                    (Utc::now() + chrono::Duration::seconds(*ttl_seconds as i64)).to_rfc3339(),
                ),
            },
        };

        self.store
            .resolve_approval(&request_id.0, &daemon_outcome)
            .map_err(LifecycleError::from)?;

        match outcome {
            CoreApprovalOutcome::Approved
            | CoreApprovalOutcome::Narrowed(_)
            | CoreApprovalOutcome::Always { .. } => {
                let resolved = self
                    .store
                    .get_approval(&request_id.0)
                    .map_err(LifecycleError::from)?;
                if let Some(grant_id) = resolved.result_grant_id {
                    let access_grant = self
                        .store
                        .get_access_grant(&grant_id)
                        .map_err(|e| LifecycleError::GrantMintFailed(e.to_string()))?;
                    Ok(Some(access_grant_to_core_grants(&access_grant)))
                } else {
                    Ok(None)
                }
            }
            CoreApprovalOutcome::Denied => Ok(None),
        }
    }

    async fn apply_standing(
        &self,
        _persona: &str,
        _pattern: RequestedScope,
        _ttl_seconds: u64,
    ) -> Result<core_grants::Grant, LifecycleError> {
        // TODO: coordinate with C-3A — standing-grant
        // path will be implemented once handler.rs migration is complete.
        Err(LifecycleError::Storage("apply_standing: not yet implemented in Phase B".into()))
    }
}

/// Convert a `core_grant_types::AccessGrant` to a `core_grants::Grant` for the
/// approval → grant boundary (design + design phase C).
///
/// The mapping is intentionally minimal: `id` is parsed from the "grant-{uuid}"
/// string format; `scope` is derived from the first statement's actions (or
/// falls back to empty capability); `expires_at` is taken from the earliest
/// block expiry across the chain.
///
/// TODO: coordinate with C-3A — once handler.rs callers
/// are also migrated, richer scope round-tripping (resource_id, constraints)
/// can be added here without breaking the C-3A parallel branch.
fn access_grant_to_core_grants(ag: &core_grant_types::AccessGrant) -> core_grants::Grant {
    let state = match ag.status {
        core_grant_types::GrantStatus::Active | core_grant_types::GrantStatus::Pending => {
            core_grants::GrantState::Active
        }
        core_grant_types::GrantStatus::Paused => core_grants::GrantState::Paused,
        core_grant_types::GrantStatus::Revoked
        | core_grant_types::GrantStatus::Expired
        | core_grant_types::GrantStatus::ExhaustedByBudget => core_grants::GrantState::Revoked,
    };

    // Derive the scope capability from the first statement's first action, if present.
    let capability = ag
        .blocks
        .first()
        .and_then(|sb| sb.block.statements.first())
        .and_then(|s| s.actions.first())
        .cloned()
        .unwrap_or_default();

    // Derive expires_at from the earliest block expiry (epoch seconds → DateTime).
    let expires_at = ag.effective_expires_at().and_then(|epoch| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(epoch as i64, 0)
    });

    // Strip "grant-" prefix before parsing as UUID.
    let raw_id = ag.id.strip_prefix("grant-").unwrap_or(&ag.id);
    let id = uuid::Uuid::parse_str(raw_id).unwrap_or_else(|_| uuid::Uuid::nil());

    // Derive usage from the first statement's token usage, if present.
    let used = ag
        .blocks
        .first()
        .and_then(|sb| sb.block.statements.first())
        .map(|s| s.usage.tokens)
        .unwrap_or(0);

    core_grants::Grant {
        id,
        issuer: core_grants::PrincipalId(ag.issuing_persona_id.clone()),
        scope: core_grants::Scope {
            capability,
            resource_id: None,
            constraints: Vec::new(),
        },
        state,
        expires_at,
        parent_id: None,
        delegation_depth: 0,
        usage: core_grants::Usage { used },
        schema_version: core_grants::GRANT_SCHEMA_VERSION_PIN,
    }
}

/// Compute the SHA-256 of `json` and return it as a lowercase hex string.
fn sha256_hex(json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

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
    /// implementation-note-152 — composite envelope statements (3-statement
    /// credential+session+time bundle minted by `ember sandbox run`)
    /// serialized as JSON when set. Surfaces as a single approval entry
    /// (NOT three) so the dashboard can render all three statements as
    /// one card. `None` for legacy single-statement approvals.
    pub composite_statements: Option<Vec<Statement>>,
    /// Grant ID minted on `Approved` resolution. Populated only when the
    /// approval has `composite_statements` set; the caller (CLI sandbox
    /// run) polls `get_approval` to discover the resulting grant ID.
    pub result_grant_id: Option<String>,
    /// Advisory pointer to the originating Construct/skill. Persisted from
    /// the `GrantProposal.skill_ref` field; emberd does not enforce on it.
    /// Per design. `None` for approvals submitted without a skill_ref.
    pub skill_ref: Option<String>,
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
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// implementation-note-152 — submit ONE approval entry that bundles a 3-statement
    /// composite envelope (credential + session + time). On `Approved` the
    /// resolver mints a single composite grant whose `blocks_json` is
    /// overwritten with the supplied statement list (matching the shape
    /// `ember sandbox run` previously wrote directly).
    #[allow(clippy::too_many_arguments)]
    pub fn propose_grant(
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
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Typed variant of `propose_grant` that accepts a [`GrantProposal`]
    /// (per design / COMPOSITE Decision 2). Each [`StatementProposal`] is
    /// converted to a runtime [`Statement`] with auto-assigned `sid` and
    /// default [`Usage`]. The legacy `credential_name` and `scope` columns
    /// are populated from the first statement's `credential_name` and
    /// `"composite"` respectively for backward-compatible DB rows.
    pub fn propose_grant_typed(
        &self,
        proposal: &GrantProposal,
        action: &str,
        risk_level: &str,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        // COMPOSITE-prior change-TESTS-DASHBOARD — validate skill_ref before storing.
        // skill_ref is advisory but must not corrupt the DB: reject values that
        // are excessively long (> 256 chars) or contain null bytes.
        if let Some(sr) = proposal.skill_ref.as_deref() {
            if sr.len() > 256 {
                return Err(StoreError::InvalidInput(
                    "skill_ref must not exceed 256 characters".to_string(),
                ));
            }
            if sr.contains('\0') {
                return Err(StoreError::InvalidInput(
                    "skill_ref must not contain null bytes".to_string(),
                ));
            }
        }
        let statements: Vec<Statement> = proposal
            .statements
            .iter()
            .enumerate()
            .map(|(i, sp)| Statement {
                sid: format!("s{i}"),
                resource_type: sp.resource_type.clone(),
                actions: sp.actions.clone(),
                resource: sp.resource.clone(),
                budget: sp.budget.clone(),
                usage: Usage::default(),
                conditions: sp.conditions.clone(),
            })
            .collect();

        let legacy_credential_name = proposal
            .statements
            .first()
            .map(|s| s.credential_name.as_str())
            .unwrap_or("");

        self.submit_approval_inner(
            &proposal.persona_id,
            legacy_credential_name,
            "composite",
            proposal.expires_at,
            action,
            risk_level,
            Some(statements),
            None,
            None,
            None,
            None,
            proposal.skill_ref.clone(),
        )
    }

    /// Variant of `propose_grant` that also persists the four
    /// NOTIF-1 fields (`tool_name`, `target_host`, `target_url`,
    /// `agent_framework`) so `get_approval` and `list_pending_approvals` can
    /// return them for notification banner titles.
    ///
    /// approval_notify_fields_persisted — called by handler.rs
    /// `request_composite_approval` arm to replace the post-submit field
    /// mutations on the returned struct that were never written to DB.
    #[allow(clippy::too_many_arguments)]
    pub fn propose_grant_with_notify(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        action: &str,
        risk_level: &str,
        statements: Vec<Statement>,
        tool_name: Option<String>,
        target_host: Option<String>,
        target_url: Option<String>,
        agent_framework: Option<String>,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        self.submit_approval_inner(
            persona_id,
            credential_name,
            scope,
            ttl_secs,
            action,
            risk_level,
            Some(statements),
            tool_name,
            target_host,
            target_url,
            agent_framework,
            None,
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
        tool_name: Option<String>,
        target_host: Option<String>,
        target_url: Option<String>,
        agent_framework: Option<String>,
        skill_ref: Option<String>,
    ) -> Result<ApprovalRequestInfo, StoreError> {
        let id = format!("approval-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        let composite_json: Option<String> = match &composite_statements {
            Some(stmts) => Some(serde_json::to_string(stmts).map_err(|e| {
                StoreError::InvalidInput(format!("composite statements serialize: {e}"))
            })?),
            None => None,
        };

        // REVIEW2-F2 — compute SHA-256 of the JSON at submit time and store
        // it atomically in the same INSERT so the approve path can verify
        // the statement list was not mutated between submit and approve.
        let composite_hash: Option<String> = composite_json.as_deref().map(sha256_hex);

        // approval_notify_fields_persisted — INSERT includes the four NOTIF-1
        // fields so get_approval reads them back instead of returning None.
        self.conn().execute(
            "INSERT INTO approval_requests \
             (id, persona_id, credential_name, scope, ttl_secs, action, risk_level, status, created_at, \
              composite_statements_json, composite_statements_hash, \
              tool_name, target_host, target_url, agent_framework, skill_ref) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                composite_hash,
                tool_name,
                target_host,
                target_url,
                agent_framework,
                skill_ref,
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
            tool_name,
            target_host,
            target_summary: None,
            target_url,
            agent_framework,
            composite_statements,
            result_grant_id: None,
            skill_ref,
        })
    }

    pub fn list_pending_approvals(&self) -> Result<Vec<ApprovalRequestInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, persona_id, credential_name, scope, ttl_secs, action, risk_level, \
             status, reason, created_at, composite_statements_json, result_grant_id, \
             tool_name, target_host, target_url, agent_framework, skill_ref \
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
                tool_name: row.get(12)?,
                target_host: row.get(13)?,
                target_summary: None,
                target_url: row.get(14)?,
                agent_framework: row.get(15)?,
                composite_statements,
                result_grant_id: row.get(11)?,
                skill_ref: row.get(16)?,
            })
        })?;
        let mut requests = Vec::new();
        for row in rows {
            requests.push(row?);
        }
        Ok(requests)
    }

    /// Resolve an approval request with optional biometric attestation
    /// metadata (implementation-note-156).
    ///
    /// `biometric` records whether the approval was gated by a hardware
    /// biometric on the operator's device (Touch ID via LocalAuthentication
    /// on macOS CLI, or `navigator.credentials.get()` via WebAuthn in the
    /// dashboard). `credential_id` is an opaque, OS-supplied identifier
    /// for the credential that verified — surfaced into the audit log so a
    /// downstream auditor can correlate "this grant was approved by this
    /// passkey enrollment" without trusting the daemon process state.
    ///
    /// The default `resolve_approval` delegates to this with
    /// `biometric=false, credential_id=None`, preserving existing test
    /// coverage and call sites.
    pub fn resolve_approval_with_biometric(
        &self,
        id: &str,
        outcome: &ApprovalOutcome,
        biometric: bool,
        credential_id: Option<&str>,
    ) -> Result<(), StoreError> {
        self.resolve_approval_inner(id, outcome, biometric, credential_id)
    }

    pub fn resolve_approval(&self, id: &str, outcome: &ApprovalOutcome) -> Result<(), StoreError> {
        self.resolve_approval_inner(id, outcome, false, None)
    }

    fn resolve_approval_inner(
        &self,
        id: &str,
        outcome: &ApprovalOutcome,
        biometric: bool,
        credential_id: Option<&str>,
    ) -> Result<(), StoreError> {
        // REVIEW2-F3: Serialize concurrent resolve_approval calls via BEGIN
        // IMMEDIATE so two concurrent POST /approve requests cannot both pass
        // the "WHERE status = 'pending'" SELECT before either UPDATE commits,
        // which would mint two grants from one approval.
        //
        // Pattern mirrors extend_grant (P69K-H1): manual begin/commit with a
        // RAII TxGuard so any ?-propagated error path rolls back cleanly.
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        struct TxGuard<'c> {
            conn: &'c rusqlite::Connection,
            committed: bool,
        }
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                if !self.committed {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
            }
        }
        let mut tx_guard = TxGuard {
            conn: self.conn(),
            committed: false,
        };

        // implementation-note-152 — composite approvals stash their 3-statement envelope
        // alongside the legacy single-statement fields, so the SELECT row
        // shape grew by one column. Aliased to keep clippy happy.
        // REVIEW2-F2 — also fetch composite_statements_hash for integrity check.
        // Index 0..6 = data; index 7 = status.
        type ApprovalRow = (String, String, String, Option<i64>, String, Option<String>, Option<String>, String);

        // Fetch all columns we need (including status) in a single query.
        // Inside the IMMEDIATE transaction this read is stable — no concurrent
        // writer can flip the status between this SELECT and the UPDATE below.
        let row: Option<ApprovalRow> = self
            .conn()
            .query_row(
                "SELECT persona_id, credential_name, scope, ttl_secs, action, \
                 composite_statements_json, composite_statements_hash, status \
                 FROM approval_requests WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;

        let (persona_id, credential_name, scope, ttl_secs_raw, action, composite_json, composite_hash, current_status) =
            row.ok_or(StoreError::NotFound)?;

        // If a concurrent caller already committed the status transition,
        // reject this one — exactly one caller wins the write lock, mints
        // the grant, and commits.
        if current_status != "pending" {
            return Err(StoreError::AlreadyResolved);
        }

        let ttl_secs: Option<u64> = ttl_secs_raw.map(|v| v as u64);

        // REVIEW2-F2 — integrity check: if a hash was stored at submit time,
        // recompute SHA-256 of the current JSON and reject on mismatch.
        // NULL hash = legacy row without protection; allow through for backward compat.
        if let (Some(json), Some(stored_hash)) = (composite_json.as_deref(), composite_hash.as_deref()) {
            let current_hash = sha256_hex(json);
            if current_hash != stored_hash {
                let _ = self.log_event(
                    Some(&persona_id),
                    "approval.integrity_violation",
                    Some(&credential_name),
                    "blocked",
                    Some(
                        &serde_json::json!({
                            "approval_request_id": id,
                            "reason": "composite_statements_json hash mismatch",
                        })
                        .to_string(),
                    ),
                );
                // Commit to persist the integrity-violation audit event,
                // then return the tamper error. The grant is NOT minted.
                self.conn().execute_batch("COMMIT")?;
                tx_guard.committed = true;
                return Err(StoreError::CompositeStatementsTampered);
            }
        }

        let composite_statements: Option<Vec<Statement>> = composite_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<Statement>>(s).ok());

        let resolved_at = Utc::now().to_rfc3339();

        match outcome {
            ApprovalOutcome::Approved => {
                // implementation-note-152 — for composite approvals the row is created
                // with scope "*" because the typed child statements
                // (Credential / Session / Time) overwrite `blocks_json`
                // immediately below; the flat `scope` column is a
                // legacy projection that no longer maps cleanly when the
                // chain has multiple heterogeneous statements.
                //
                // REVIEW2-F4: the bipartite-dominance check at overwrite
                // time used to load the parent from `blocks_json` (this
                // wildcard projection), which trivially dominated any
                // child. `mint_composite_chain_for_grant` now bounds the
                // dominance check against the operator-approved statement
                // set explicitly; the `"*"` here is just the row's flat
                // marker, not a security-relevant authority decision.
                let parent_scope: &str = if composite_statements.is_some() {
                    "*"
                } else {
                    &scope
                };
                // REVIEW2-F8: for composite grants suppress the premature
                // grant.minted{statement_count:1} here; mint_composite_chain_for_grant
                // emits the canonical grant.minted after the multi-statement shape is
                // finalised so the audit log shows the accurate statement_count.
                let grant = if composite_statements.is_some() {
                    self.create_grant_suppress_minted_event(&persona_id, &credential_name, parent_scope, ttl_secs)?
                } else {
                    self.create_grant(&persona_id, &credential_name, parent_scope, ttl_secs)?
                };

                // implementation-note-152 — when the approval bundles a composite envelope,
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
                            // implementation-note-156 — `biometric=true` indicates the
                            // approval was attested by a hardware biometric on
                            // the operator's device (Touch ID via
                            // LocalAuthentication on the macOS CLI, or
                            // `navigator.credentials.get()` via WebAuthn in
                            // the dashboard). `credential_id` is an opaque,
                            // OS-supplied identifier for the credential that
                            // verified.
                            "biometric": biometric,
                            "credential_id": credential_id,
                        })
                        .to_string(),
                    ),
                );
                // implementation-note-156 — also emit a dedicated `approval.approved`
                // event so downstream auditors can filter on the approval
                // beat without parsing `grant.issued` semantics.
                let _ = self.log_event(
                    Some(&persona_id),
                    "approval.approved",
                    Some(&credential_name),
                    "approved",
                    Some(
                        &serde_json::json!({
                            "approval_id": id,
                            "grant_id": grant.id,
                            "biometric": biometric,
                            "credential_id": credential_id,
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
                // implementation-note-156 — record the biometric posture on denial too
                // so an auditor can distinguish "human rejected with TouchID"
                // from "untouched timeout".
                let _ = self.log_event(
                    Some(&persona_id),
                    "approval.denied",
                    Some(&credential_name),
                    "denied",
                    Some(
                        &serde_json::json!({
                            "approval_id": id,
                            "reason": reason,
                            "biometric": biometric,
                            "credential_id": credential_id,
                        })
                        .to_string(),
                    ),
                );
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
                            "biometric": biometric,
                            "credential_id": credential_id,
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
                            "biometric": biometric,
                            "credential_id": credential_id,
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

        self.conn().execute_batch("COMMIT")?;
        tx_guard.committed = true;

        Ok(())
    }

    pub fn get_approval(&self, id: &str) -> Result<ApprovalRequestInfo, StoreError> {
        self.conn()
            .query_row(
                "SELECT id, persona_id, credential_name, scope, ttl_secs, action, risk_level, \
                 status, reason, created_at, composite_statements_json, result_grant_id, \
                 tool_name, target_host, target_url, agent_framework, skill_ref \
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
                        tool_name: row.get(12)?,
                        target_host: row.get(13)?,
                        target_summary: None,
                        target_url: row.get(14)?,
                        agent_framework: row.get(15)?,
                        composite_statements,
                        result_grant_id: row.get(11)?,
                        skill_ref: row.get(16)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// implementation-note-152 — overwrite a freshly-minted single-statement grant's
    /// `blocks_json` with the canonical 3-statement composite chain.
    ///
    /// Mirrors the path `ember sandbox run` previously took inline (signing
    /// block 0 under the persona's root keypair via
    /// `access_grant_from_statements`). Routed through the approval flow so
    /// the policy gate fires before mint, not after.
    ///
    /// REVIEW2-F4: the bipartite-dominance check in `overwrite_grant_blocks`
    /// is rooted in the **operator-approved statement set** rather than the
    /// scope-`"*"` shim that `create_grant` wrote upstream. Without this
    /// fix the dominance check was trivially true (`*` dominates everything),
    /// and the composite-grant security claim was hollow.
    ///
    /// The parent bound is computed via
    /// [`crate::trust::attenuation::compute_statements_union_bound`] from the
    /// approved `statements`. For the minimal heterogeneous case this is
    /// the statements themselves (each dominates itself with usage zeroed),
    /// so the actual mint trivially passes — but any *future* overwrite
    /// of this row faces a real dominance gate against the approved bound.
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
        let statement_count: usize = statements.len();

        // REVIEW2-F4: build the union-bound parent from the operator-approved
        // statements BEFORE minting. This is what the bipartite-dominance
        // check is rooted against. We sign it under the same persona root
        // key so the override passes the envelope guard.
        let bound_statements =
            crate::trust::attenuation::compute_statements_union_bound(&statements);
        let parent_bound = crate::trust::grant::access_grant_from_statements_for_persona(
            self,
            grant_id,
            persona_id,
            recipient_id,
            bound_statements,
            created_at_epoch,
            expires_at_epoch,
        )?;

        let composite = crate::trust::grant::access_grant_from_statements_for_persona(
            self,
            grant_id,
            persona_id,
            recipient_id,
            statements,
            created_at_epoch,
            expires_at_epoch,
        )?;
        self.overwrite_grant_blocks_with_parent_bound(grant_id, &composite, &parent_bound)?;
        // REVIEW2-F8: emit grant.minted here, AFTER the composite shape is
        // finalised, so the audit log records the accurate statement_count.
        // The premature grant.minted{statement_count:1} from create_grant is
        // suppressed by the composite approval path (see resolve_approval).
        let _ = self.log_event(
            Some(persona_id),
            "grant.minted",
            Some(recipient_id),
            "minted",
            Some(
                &serde_json::json!({
                    "grant_id": grant_id,
                    "statement_count": statement_count,
                    "ttl_secs": ttl_secs,
                    "creation_mode": "composite",
                })
                .to_string(),
            ),
        );
        Ok(())
    }

    /// COMPOSITE-prior change — daemon-side "auto" lane for the single-mint code path.
    ///
    /// Per COMPOSITE Decision 2 (REVISED), the CLI no longer carries a
    /// separate "AutoApprove fast-path" that bypasses the approval queue with
    /// direct `create_grant` + `overwrite_grant_blocks` calls. Instead, every
    /// `ember sandbox run` (and any future caller) dispatches via
    /// `propose_grant`; the policy gate decides Auto vs Approval; and on the
    /// Auto path the daemon calls this method to immediately resolve the
    /// pending approval as `Approved`, mint the grant, and emit a dedicated
    /// `auto_resolved` audit event so downstream auditors can distinguish a
    /// silent policy-driven approval from a human-driven one.
    ///
    /// Behaviorally equivalent to `resolve_approval(id, Approved)` plus the
    /// extra audit event. The same composite-mint, integrity-check, and
    /// transaction-serialization invariants apply because the underlying
    /// resolver is the same code path.
    pub fn auto_resolve(&self, approval_id: &str) -> Result<(), StoreError> {
        // Look up the request first so the auto_resolved audit event can
        // record the persona / credential / scope context even if the
        // approval row gets resolved out from under us by a concurrent
        // caller (e.g. a human approving the same row in the dashboard
        // milliseconds before this call lands). The resolve_approval below
        // is the authoritative gate — it serializes via BEGIN IMMEDIATE
        // and rejects already-resolved rows.
        let info = self.get_approval(approval_id)?;

        self.resolve_approval(approval_id, &ApprovalOutcome::Approved)?;

        // Re-read to pick up the freshly-set `result_grant_id` so the
        // audit event correlates the auto-resolved approval with its
        // minted grant.
        let resolved = self.get_approval(approval_id)?;

        let _ = self.log_event(
            Some(&info.persona_id),
            "approval.auto_resolved",
            Some(&info.credential_name),
            "auto_approved",
            Some(
                &serde_json::json!({
                    "approval_id": approval_id,
                    "grant_id": resolved.result_grant_id,
                    "scope": info.scope,
                    "action": info.action,
                    "risk_level": info.risk_level,
                    "composite": info.composite_statements.is_some(),
                    "source": "policy.auto",
                })
                .to_string(),
            ),
        );

        Ok(())
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

    /// implementation-note-147 — operator-initiated dismiss of a pending
    /// approval card. Sets status to `dismissed`, records an `approval.dismissed`
    /// audit event, and returns. Does NOT fire a desktop notification (the operator
    /// is already looking at the dashboard). Only `pending` rows can be dismissed;
    /// already-resolved rows return `AlreadyResolved`.
    pub fn dismiss_approval(&self, id: &str) -> Result<(), StoreError> {
        let resolved_at = Utc::now().to_rfc3339();
        let count = self.conn().execute(
            "UPDATE approval_requests SET status = 'dismissed', resolved_at = ?1 \
             WHERE id = ?2 AND status = 'pending'",
            rusqlite::params![resolved_at, id],
        )?;
        if count == 0 {
            // Either not found or already resolved.
            let exists: i64 = self
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM approval_requests WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            return if exists == 0 {
                Err(StoreError::NotFound)
            } else {
                Err(StoreError::AlreadyResolved)
            };
        }
        let _ = self.log_event(
            None,
            "approval.dismissed",
            None,
            "dismissed",
            Some(&serde_json::json!({"approval_id": id}).to_string()),
        );
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
        use crate::infra::audit::AuditFilter;
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
        use crate::infra::audit::AuditFilter;
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
        use crate::infra::audit::AuditFilter;
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

    // --- implementation-note-152 — composite-grant approval flow ---

    fn demo_three_statements(credential: &str) -> Vec<Statement> {
        use core_grant_types::{Budget, ResourceSelector, ResourceType, Usage};

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
    fn propose_grant_appears_as_one_pending_entry_with_three_statements() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-github-token");

        let req = store
            .propose_grant(
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
            .propose_grant(
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

    /// COMPOSITE-prior change — `auto_resolve` mints a grant via the same code path
    /// the human-approval flow uses AND emits an `approval.auto_resolved`
    /// audit event so downstream auditors can distinguish silent
    /// policy-driven approvals from human-driven ones.
    #[test]
    fn auto_resolve_mints_composite_grant_and_emits_audit_event() {
        use crate::infra::audit::AuditFilter;

        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-auto-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-auto-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        store.auto_resolve(&req.id).expect("auto_resolve must succeed");

        // The approval row resolved as 'approved' and recorded the grant id —
        // same shape the human-approval path produces.
        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");
        let grant_id = resolved
            .result_grant_id
            .as_deref()
            .expect("auto_resolve must record result_grant_id");
        assert!(grant_id.starts_with("grant-"));

        // The minted grant carries the canonical 3-statement composite chain.
        let access_grant = store.get_access_grant(grant_id).unwrap();
        let block = &access_grant.blocks[0].block;
        assert_eq!(
            block.statements.len(),
            3,
            "auto_resolve must mint the composite chain via the shared resolver"
        );

        // An `approval.auto_resolved` audit row marks this as a policy-driven
        // (not human-driven) approval and links to the grant.
        let auto_entries = store
            .query_audit(&AuditFilter {
                action: Some("approval.auto_resolved".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            auto_entries.len(),
            1,
            "exactly one approval.auto_resolved audit event must be emitted"
        );
        let entry = &auto_entries[0];
        assert_eq!(entry.outcome, "auto_approved");
        assert_eq!(entry.agent_id.as_deref(), Some(pid.as_str()));

        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["approval_id"], req.id);
        assert_eq!(details["grant_id"], grant_id);
        assert_eq!(details["composite"], serde_json::json!(true));
        assert_eq!(details["source"], serde_json::json!("policy.auto"));
    }

    /// COMPOSITE-prior change — `auto_resolve` is idempotent in the sense that a
    /// second call against an already-resolved request returns
    /// `AlreadyResolved` instead of double-minting.
    #[test]
    fn auto_resolve_rejects_already_resolved_request() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        store.auto_resolve(&req.id).expect("first auto_resolve must succeed");
        let second = store.auto_resolve(&req.id);
        assert!(
            matches!(second, Err(StoreError::AlreadyResolved)),
            "expected AlreadyResolved, got {second:?}"
        );

        // Only one grant minted across both calls.
        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1, "auto_resolve must not double-mint");
    }

    #[test]
    fn approve_composite_emits_grant_minted_with_final_statement_count() {
        // REVIEW2-F8: grant.minted is now emitted AFTER the composite shape
        // is finalised; the audit log shows statement_count:3, not statement_count:1.
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-audit-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-audit-token",
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

        let resolved = store.get_approval(&req.id).unwrap();
        let grant_id = resolved.result_grant_id.as_deref().unwrap();

        // Exactly one grant.minted event must exist for this grant.
        let minted_entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("grant.minted".to_string()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            minted_entries.len(),
            1,
            "expected exactly one grant.minted audit entry for a composite grant"
        );
        let entry = &minted_entries[0];
        assert_eq!(entry.action, "grant.minted");
        assert_eq!(entry.agent_id.as_deref(), Some(pid.as_str()));
        assert_eq!(entry.outcome, "minted");

        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["grant_id"], grant_id);
        assert_eq!(
            details["statement_count"], 3,
            "grant.minted must reflect the final composite shape (statement_count:3)"
        );
        assert_eq!(details["creation_mode"], "composite");

        // No stale grant.composite_overwrite event — grant.minted is the
        // canonical emit for all grant shapes after REVIEW2-F8.
        let overwrite_entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("grant.composite_overwrite".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            overwrite_entries.is_empty(),
            "grant.composite_overwrite must not be emitted after REVIEW2-F8; \
             grant.minted is the single canonical event"
        );
    }

    /// REVIEW2-F8 — canonical acceptance test.
    /// Submit a composite approval, run mint, query audit log: exactly one
    /// `grant.minted` event with `statement_count: 3`.
    #[test]
    fn composite_grant_minted_event_has_final_statement_count() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-f8-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-f8-token",
                "composite",
                Some(600),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        store
            .resolve_approval(&req.id, &ApprovalOutcome::Approved)
            .unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        let grant_id = resolved.result_grant_id.as_deref().unwrap();

        let minted_entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("grant.minted".to_string()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(
            minted_entries.len(),
            1,
            "audit log must contain exactly one grant.minted event for a composite grant"
        );

        let details: serde_json::Value = serde_json::from_str(
            minted_entries[0].details.as_deref().unwrap_or("{}"),
        )
        .unwrap();
        assert_eq!(
            details["grant_id"], grant_id,
            "grant.minted must reference the minted grant_id"
        );
        assert_eq!(
            details["statement_count"], 3,
            "grant.minted must show statement_count:3 after composite shape is final (REVIEW2-F8)"
        );
        assert_eq!(details["creation_mode"], "composite");
    }

    #[test]
    fn deny_composite_does_not_mint_any_grant() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-github-token");

        let req = store
            .propose_grant(
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
        // propose_grant, NOT in create_grant. This is the
        // demo's "agent asks → human approves" beat.
        use crate::trust::policy::{ApprovalRequirement, PolicyEngine};

        let store = setup();
        let pid = persona_id(&store);
        let policy = PolicyEngine::default();
        let eval = policy.evaluate("credential.access");
        assert_eq!(
            eval.requirement,
            ApprovalRequirement::Required,
            "default policy must require approval for credential.access"
        );

        // The CLI sandbox-run code path on RequireApproval calls
        // propose_grant; mirror that here.
        let stmts = demo_three_statements("obj-github-token");
        let req = store
            .propose_grant(
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

    // --- REVIEW2-F2: SHA-256 integrity binding for composite_statements_json ---

    /// Happy path: submit + approve a composite approval without tampering.
    /// The grant must be minted cleanly and no integrity_violation event fired.
    #[test]
    fn composite_approval_no_tamper_mints_grant() {
        use crate::infra::audit::AuditFilter;

        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-integrity-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-integrity-token",
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

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");
        assert!(
            resolved.result_grant_id.is_some(),
            "grant must be minted on untampered composite approval"
        );

        // No integrity violation event must be logged.
        let violations = store
            .query_audit(&AuditFilter {
                action: Some("approval.integrity_violation".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            violations.is_empty(),
            "no integrity_violation event must be fired for untampered approval"
        );
    }

    /// Tamper detection: mutate `composite_statements_json` directly in the DB
    /// after submit but before approve. The resolve must return
    /// `CompositeStatementsTampered`, the grant must NOT be minted, and an
    /// `approval.integrity_violation` audit event must be present.
    #[test]
    fn composite_approval_tampered_json_blocks_mint_and_emits_audit() {
        use crate::infra::audit::AuditFilter;

        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-tamper-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-tamper-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        // Directly mutate composite_statements_json in the DB to simulate a
        // SQLite-level tamper (e.g. attacker with write access to the DB file).
        let tampered_json = r#"[{"sid":"evil","resource_type":"Credential","actions":["credential:admin"],"resource":{"type":"Any"},"budget":null,"usage":{"tokens":0,"wall_clock_secs":0,"calls":0,"cost_usd_millicents":0},"conditions":[]}]"#;
        store.conn().execute(
            "UPDATE approval_requests SET composite_statements_json = ?1 WHERE id = ?2",
            rusqlite::params![tampered_json, req.id],
        ).unwrap();

        // Approve must be blocked.
        let result = store.resolve_approval(&req.id, &ApprovalOutcome::Approved);
        assert!(
            matches!(result, Err(StoreError::CompositeStatementsTampered)),
            "expected CompositeStatementsTampered, got {result:?}"
        );

        // No grant must be minted.
        assert!(
            store.list_grants().unwrap().is_empty(),
            "grant must NOT be minted after tamper detection"
        );

        // The approval status must still be 'pending' (not approved).
        let still_pending = store.get_approval(&req.id).unwrap();
        assert_eq!(
            still_pending.status, "pending",
            "tampered approval must remain pending, not transition to approved"
        );

        // An integrity_violation audit event must be present.
        let violations = store
            .query_audit(&AuditFilter {
                action: Some("approval.integrity_violation".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            violations.len(),
            1,
            "exactly one integrity_violation audit event must be emitted"
        );
        let v = &violations[0];
        assert_eq!(v.action, "approval.integrity_violation");
        assert_eq!(v.outcome, "blocked");
        let details: serde_json::Value =
            serde_json::from_str(v.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["approval_request_id"], req.id);
    }

    /// Legacy row (no hash column populated) must approve without triggering
    /// the integrity check — backward compat for pre-REVIEW2-F2 rows.
    #[test]
    fn composite_approval_legacy_null_hash_allows_approve() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = demo_three_statements("obj-legacy-token");

        let req = store
            .propose_grant(
                &pid,
                "obj-legacy-token",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts,
            )
            .unwrap();

        // Simulate a legacy row by nulling the hash column after insert.
        store.conn().execute(
            "UPDATE approval_requests SET composite_statements_hash = NULL WHERE id = ?1",
            rusqlite::params![req.id],
        ).unwrap();

        // Approve must succeed — legacy rows have no binding and are allowed through.
        let result = store.resolve_approval(&req.id, &ApprovalOutcome::Approved);
        assert!(
            result.is_ok(),
            "legacy row with NULL hash must approve without error, got {result:?}"
        );

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");
        assert!(resolved.result_grant_id.is_some(), "legacy row must mint grant on approve");
    }

    // --- REVIEW2-F3: double-approve race prevention ---

    /// Two concurrent callers each with their own DaemonStore connection to
    /// the same file DB both call resolve_approval(Approved) simultaneously.
    /// BEGIN IMMEDIATE serializes them: exactly one wins and mints the grant;
    /// the other sees status != 'pending' and returns AlreadyResolved.
    #[test]
    fn concurrent_approve_mints_exactly_one_grant() {
        use std::rc::Rc;
        use std::sync::{Arc, Barrier};
        use tempfile::TempDir;

        // All stores share the same deterministic test vault key.
        const VAULT_KEY: [u8; 32] = [0xABu8; 32];

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        // Bootstrap: open store, create persona, submit approval.
        let request_id = {
            use crate::infra::vault::Vault;
            let store = DaemonStore::open(&db_path).unwrap();
            store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
            store.create_persona("race-agent").unwrap();
            let pid = store.list_personas().unwrap().into_iter().next().unwrap().id;
            let req = store
                .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
                .unwrap();
            req.id
        };

        // Both threads race to approve the same request.
        let barrier = Arc::new(Barrier::new(2));

        let db_path1 = db_path.clone();
        let req_id1 = request_id.clone();
        let barrier1 = Arc::clone(&barrier);
        let t1 = std::thread::spawn(move || {
            use crate::infra::vault::Vault;
            use std::rc::Rc;
            let store = DaemonStore::open(&db_path1).unwrap();
            store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
            // Both threads hit the barrier simultaneously to maximize overlap.
            barrier1.wait();
            store.resolve_approval(&req_id1, &ApprovalOutcome::Approved)
        });

        let db_path2 = db_path.clone();
        let req_id2 = request_id.clone();
        let barrier2 = Arc::clone(&barrier);
        let t2 = std::thread::spawn(move || {
            use crate::infra::vault::Vault;
            use std::rc::Rc;
            let store = DaemonStore::open(&db_path2).unwrap();
            store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
            barrier2.wait();
            store.resolve_approval(&req_id2, &ApprovalOutcome::Approved)
        });

        let r1 = t1.join().expect("thread 1 panicked");
        let r2 = t2.join().expect("thread 2 panicked");

        // Exactly one must succeed; the other must return AlreadyResolved.
        let (ok_count, err_count) = [&r1, &r2].iter().fold((0usize, 0usize), |(ok, err), r| {
            match r {
                Ok(()) => (ok + 1, err),
                Err(StoreError::AlreadyResolved) => (ok, err + 1),
                Err(e) => panic!("unexpected error: {e}"),
            }
        });
        assert_eq!(ok_count, 1, "exactly one approve call must succeed");
        assert_eq!(err_count, 1, "the other must return AlreadyResolved");

        // Verify exactly one grant was minted.
        use crate::infra::vault::Vault;
        let verify_store = DaemonStore::open(&db_path).unwrap();
        verify_store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
        let grants = verify_store.list_grants().unwrap();
        assert_eq!(grants.len(), 1, "exactly one grant must be minted, got {}", grants.len());
        assert_eq!(grants[0].credential_name, "api-key");

        // The approval row must record the winner's grant ID.
        let resolved = verify_store.get_approval(&request_id).unwrap();
        assert_eq!(resolved.status, "approved");
        assert!(resolved.result_grant_id.is_some());
    }

    #[test]
    fn resolve_already_approved_returns_already_resolved() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        // First approval succeeds.
        store.resolve_approval(&req.id, &ApprovalOutcome::Approved).unwrap();

        // Second approval on the same request must fail with AlreadyResolved.
        let result = store.resolve_approval(&req.id, &ApprovalOutcome::Approved);
        assert!(
            matches!(result, Err(StoreError::AlreadyResolved)),
            "expected AlreadyResolved, got {result:?}"
        );

        // Still exactly one grant.
        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1, "must not mint a second grant on double-approve");
    }

    // --- REVIEW2-F4: union-bound parent for composite mint ----------------
    //
    // The parent loaded for the bipartite-dominance check in
    // `overwrite_grant_blocks` used to be the scope-`*` projection
    // (`actions=["*"], resource=Any`) — trivially dominates everything,
    // hollowing out the security claim of composite-grant minting. The
    // fix bounds the dominance check against the operator-approved
    // statement set itself (the union bound). These tests exercise the
    // properties the bound must hold.

    fn three_disjoint_statements() -> Vec<Statement> {
        use core_grant_types::{ResourceSelector, ResourceType, Usage};
        vec![
            Statement {
                sid: "s0-push".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["github:push".into()],
                resource: ResourceSelector::Exact { value: "acme/widgets".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
            Statement {
                sid: "s1-read".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["github:read".into()],
                resource: ResourceSelector::Glob { pattern: "acme/*".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
            Statement {
                sid: "s2-time".into(),
                resource_type: ResourceType::Time,
                actions: vec!["time:wall_clock".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
        ]
    }

    /// Three disjoint child statements (push / read / time) — the union-bound
    /// parent must dominate every one of them. We exercise this by minting a
    /// composite from those statements and asserting the mint succeeds (the
    /// bipartite-dominance gate inside `overwrite_grant_blocks` ran against
    /// the bound, not against `*`, and accepted each child).
    #[test]
    fn parent_scope_is_union_of_approved_children() {
        let store = setup();
        let pid = persona_id(&store);
        let stmts = three_disjoint_statements();

        let req = store
            .propose_grant(
                &pid,
                "obj-cred",
                "composite",
                Some(300),
                "credential.access",
                "high",
                stmts.clone(),
            )
            .unwrap();
        store
            .resolve_approval(&req.id, &ApprovalOutcome::Approved)
            .unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        let grant_id = resolved
            .result_grant_id
            .as_deref()
            .expect("composite approval must record result_grant_id");

        // The minted chain carries all three operator-approved statements.
        let access_grant = store.get_access_grant(grant_id).unwrap();
        let block = &access_grant.blocks[0].block;
        assert_eq!(block.statements.len(), 3);
        assert_eq!(block.statements[0].sid, "s0-push");
        assert_eq!(block.statements[1].sid, "s1-read");
        assert_eq!(block.statements[2].sid, "s2-time");

        // And the bound dominates each one (sanity-check via the same
        // function `overwrite_grant_blocks` runs internally).
        let bound_stmts =
            crate::trust::attenuation::compute_statements_union_bound(&stmts);
        let bound_block = core_grant_types::Block {
            statements: bound_stmts,
            nbf: None,
            expires_at: None,
            issued_by: pid.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let root = store.persona_root_keypair(&pid).unwrap();
        let signed_bound =
            crate::trust::grant::sign_block_zero_with(&root, &bound_block).unwrap();
        let bound_grant = core_grant_types::AccessGrant {
            id: grant_id.to_string(),
            version: 1,
            issuing_persona_id: pid.clone(),
            recipient_kind: core_event_types::PresentationAudienceKind::Service,
            recipient_id: "obj-cred".into(),
            recipient_profile: core_grant_types::RecipientProfile::Agent,
            status: core_grant_types::GrantStatus::Active,
            mode: core_grant_types::GrantMode::OneShot,
            blocks: vec![signed_bound],
            attestation: core_grant_types::AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };
        crate::trust::attenuation::check_statement_attenuation(&bound_grant, &access_grant)
            .expect("bound dominates each approved child statement");
    }

    /// Children allow `github:push` and `github:read`; the union bound must
    /// NOT dominate a hypothetical child statement that asks for
    /// `github:admin`. The pre-fix behavior (parent scope `*`) WOULD have
    /// trivially accepted this child — this test guards the regression.
    #[test]
    fn parent_scope_does_not_contain_unapproved_action() {
        use core_grant_types::{ResourceSelector, ResourceType, Usage};

        let store = setup();
        let pid = persona_id(&store);
        let approved = vec![
            Statement {
                sid: "s0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["github:push".into()],
                resource: ResourceSelector::Exact { value: "acme/widgets".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
            Statement {
                sid: "s1".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["github:read".into()],
                resource: ResourceSelector::Exact { value: "acme/widgets".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
        ];

        // Build the bound and a hypothetical "admin" child grant.
        let bound_stmts =
            crate::trust::attenuation::compute_statements_union_bound(&approved);
        let bound_block = core_grant_types::Block {
            statements: bound_stmts,
            nbf: None,
            expires_at: None,
            issued_by: pid.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let root = store.persona_root_keypair(&pid).unwrap();
        let signed_bound =
            crate::trust::grant::sign_block_zero_with(&root, &bound_block).unwrap();
        let bound_grant = core_grant_types::AccessGrant {
            id: "grant-bound".into(),
            version: 1,
            issuing_persona_id: pid.clone(),
            recipient_kind: core_event_types::PresentationAudienceKind::Service,
            recipient_id: "obj-cred".into(),
            recipient_profile: core_grant_types::RecipientProfile::Agent,
            status: core_grant_types::GrantStatus::Active,
            mode: core_grant_types::GrantMode::OneShot,
            blocks: vec![signed_bound],
            attestation: core_grant_types::AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };

        let admin_child = vec![Statement {
            sid: "s-admin".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:admin".into()],
            resource: ResourceSelector::Exact { value: "acme/widgets".into() },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        }];
        let child_block = core_grant_types::Block {
            statements: admin_child,
            nbf: None,
            expires_at: None,
            issued_by: pid.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let signed_child =
            crate::trust::grant::sign_block_zero_with(&root, &child_block).unwrap();
        let child_grant = core_grant_types::AccessGrant {
            id: "grant-bound".into(),
            version: 1,
            issuing_persona_id: pid.clone(),
            recipient_kind: core_event_types::PresentationAudienceKind::Service,
            recipient_id: "obj-cred".into(),
            recipient_profile: core_grant_types::RecipientProfile::Agent,
            status: core_grant_types::GrantStatus::Active,
            mode: core_grant_types::GrantMode::OneShot,
            blocks: vec![signed_child],
            attestation: core_grant_types::AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };

        // The union bound must REJECT a child whose action is outside the
        // approved set.
        let err = crate::trust::attenuation::check_statement_attenuation(
            &bound_grant,
            &child_grant,
        )
        .expect_err("union bound must not subsume `github:admin`");
        assert!(
            err.reason.contains("no parent with matching selector/actions"),
            "expected matching-parent violation, got: {}",
            err.reason
        );

        // Counter-check: a wildcard parent (the pre-fix shape, scope `*`
        // projecting to actions=["*"], resource=Any) WOULD have falsely
        // accepted the same child.
        let wildcard_block = core_grant_types::Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["*".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: pid.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let signed_wild =
            crate::trust::grant::sign_block_zero_with(&root, &wildcard_block).unwrap();
        let wildcard_grant = core_grant_types::AccessGrant {
            blocks: vec![signed_wild],
            ..bound_grant.clone()
        };
        crate::trust::attenuation::check_statement_attenuation(
            &wildcard_grant,
            &child_grant,
        )
        .expect("wildcard parent (pre-fix) trivially accepts admin child");
    }

    /// Single-statement composite: the union bound's lone parent statement
    /// equals the approved child statement (with usage zeroed). The
    /// dominance check passes by definition.
    #[test]
    fn single_statement_composite_parent_matches_child() {
        use core_grant_types::{ResourceSelector, ResourceType, Usage};
        let only = vec![Statement {
            sid: "s0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:read".into()],
            resource: ResourceSelector::Exact { value: "acme/widgets".into() },
            budget: Some(core_grant_types::Budget {
                tokens: Some(100),
                ..Default::default()
            }),
            // Pre-fix usage on the approved input. `compute_statements_union_bound`
            // resets this to zero for the bound so dominance arithmetic
            // (child ≤ parent_remaining) works for a child whose budget
            // equals the approved budget.
            usage: Usage {
                tokens: 42,
                ..Default::default()
            },
            conditions: vec![],
        }];

        let bound = crate::trust::attenuation::compute_statements_union_bound(&only);
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].sid, "s0");
        assert_eq!(bound[0].actions, only[0].actions);
        assert_eq!(bound[0].resource, only[0].resource);
        assert_eq!(bound[0].budget, only[0].budget);
        assert_eq!(
            bound[0].usage,
            Usage::default(),
            "bound usage must reset so child budget=parent budget passes"
        );
    }

    // --- implementation-note-147: dismiss_approval ---

    #[test]
    fn dismiss_pending_approval_sets_status_dismissed() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "medium")
            .unwrap();

        store.dismiss_approval(&req.id).unwrap();

        let resolved = store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "dismissed");

        // Must not appear in pending list.
        let pending = store.list_pending_approvals().unwrap();
        assert!(pending.iter().all(|a| a.id != req.id));
    }

    #[test]
    fn dismiss_approval_records_audit_event() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "low")
            .unwrap();

        store.dismiss_approval(&req.id).unwrap();

        use crate::infra::audit::AuditFilter;
        let entries = store
            .query_audit(&AuditFilter { action: Some("approval.dismissed".to_string()), ..Default::default() })
            .unwrap();
        assert_eq!(entries.len(), 1, "expected one approval.dismissed audit entry");
        assert_eq!(entries[0].action, "approval.dismissed");
    }

    #[test]
    fn dismiss_approval_already_approved_returns_already_resolved() {
        let store = setup();
        let pid = persona_id(&store);
        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "low")
            .unwrap();
        store.resolve_approval(&req.id, &ApprovalOutcome::Approved).unwrap();

        let result = store.dismiss_approval(&req.id);
        assert!(
            matches!(result, Err(crate::infra::store::StoreError::AlreadyResolved)),
            "dismissing an already-approved request should return AlreadyResolved"
        );
    }

    #[test]
    fn dismiss_approval_nonexistent_returns_not_found() {
        let store = setup();
        let result = store.dismiss_approval("approval-does-not-exist");
        assert!(
            matches!(result, Err(crate::infra::store::StoreError::NotFound)),
            "dismissing a nonexistent approval should return NotFound"
        );
    }

    // --- Phase B: DaemonApprovalStore T2 integration test ---

    #[tokio::test(flavor = "current_thread")]
    async fn test_daemon_approval_store_roundtrip() {
        use core_approval::{ApprovalLifecycle, ApprovalOutcome as CoreApprovalOutcome, RequestId};
        use core_grant_types::approval::RequestedScope;
        use std::rc::Rc;

        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("roundtrip-test").expect("create persona");
        let pid = store
            .list_personas()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .id;

        let adapter = crate::trust::approval::DaemonApprovalStore::new(Rc::new(store));

        let scope = RequestedScope {
            capability: "read".to_string(),
            resource_id: None,
            constraints: vec![],
        };

        // Step 1: submit_request → RequestId returned + status=Pending
        let request_id: RequestId = adapter
            .submit_request(&pid, "api-key", scope, SubmitMetadata::default())
            .await
            .expect("submit_request must succeed");

        assert!(
            request_id.0.starts_with("approval-"),
            "RequestId must be backed by the approval row id"
        );

        // Verify the underlying store has the row in pending status.
        let info = adapter
            .store
            .get_approval(&request_id.0)
            .expect("approval row must exist");
        assert_eq!(info.status, "pending", "newly submitted request must be pending");

        // Step 2: decide(id, Approved) → core_grants::Grant returned
        let grant_opt = adapter
            .decide(&request_id, CoreApprovalOutcome::Approved)
            .await
            .expect("decide must succeed");

        let grant = grant_opt.expect("Approved outcome must produce a Grant");
        assert!(grant.id != uuid::Uuid::nil(), "Grant must have a non-nil UUID id");

        // Verify the approval row has transitioned to approved.
        let resolved = adapter
            .store
            .get_approval(&request_id.0)
            .expect("approval row must still be readable");
        assert_eq!(resolved.status, "approved", "request must be approved after decide");

        // Step 3: decide again on same id → AlreadyDecided error
        let second_result = adapter
            .decide(&request_id, CoreApprovalOutcome::Denied)
            .await;
        assert!(
            matches!(second_result, Err(core_approval::LifecycleError::AlreadyDecided)),
            "deciding an already-decided request must return AlreadyDecided"
        );
    }

    // --- implementation-note-248: T1 unit tests ---

    /// T1: submit_approval_inner persists tool_name, target_host, target_url,
    /// and agent_framework; get_approval reads them back (not None).
    #[test]
    fn notify_fields_persist_and_round_trip_via_get_approval() {
        // approval_notify_fields_persisted
        let store = setup();
        let pid = persona_id(&store);

        let req = store
            .submit_approval_inner(
                &pid,
                "api-key",
                "read",
                Some(120),
                "credential.access",
                "high",
                None,
                Some("Bash".to_string()),
                Some("api.example.com".to_string()),
                Some("https://api.example.com/v1/data".to_string()),
                Some("claude-code".to_string()),
                None,
            )
            .unwrap();

        // Returned struct has the fields set immediately.
        assert_eq!(req.tool_name.as_deref(), Some("Bash"));
        assert_eq!(req.target_host.as_deref(), Some("api.example.com"));
        assert_eq!(req.target_url.as_deref(), Some("https://api.example.com/v1/data"));
        assert_eq!(req.agent_framework.as_deref(), Some("claude-code"));

        // get_approval must read them back from the DB.
        let fetched = store.get_approval(&req.id).unwrap();
        assert_eq!(fetched.tool_name.as_deref(), Some("Bash"), "tool_name must survive DB round-trip");
        assert_eq!(fetched.target_host.as_deref(), Some("api.example.com"), "target_host must survive DB round-trip");
        assert_eq!(fetched.target_url.as_deref(), Some("https://api.example.com/v1/data"), "target_url must survive DB round-trip");
        assert_eq!(fetched.agent_framework.as_deref(), Some("claude-code"), "agent_framework must survive DB round-trip");
    }

    /// T1: list_pending_approvals returns notify fields from DB.
    #[test]
    fn notify_fields_appear_in_list_pending_approvals() {
        let store = setup();
        let pid = persona_id(&store);

        store
            .submit_approval_inner(
                &pid,
                "api-key",
                "write",
                None,
                "credential.access",
                "medium",
                None,
                Some("Read".to_string()),
                Some("storage.example.com".to_string()),
                Some("https://storage.example.com/bucket".to_string()),
                Some("aider".to_string()),
                None,
            )
            .unwrap();

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        let p = &pending[0];
        assert_eq!(p.tool_name.as_deref(), Some("Read"));
        assert_eq!(p.target_host.as_deref(), Some("storage.example.com"));
        assert_eq!(p.target_url.as_deref(), Some("https://storage.example.com/bucket"));
        assert_eq!(p.agent_framework.as_deref(), Some("aider"));
    }

    /// T1: notify fields default to None when not provided (submit_approval API).
    #[test]
    fn notify_fields_are_null_when_not_provided() {
        let store = setup();
        let pid = persona_id(&store);

        let req = store
            .submit_approval(&pid, "api-key", "read", None, "credential.access", "high")
            .unwrap();

        let fetched = store.get_approval(&req.id).unwrap();
        assert!(fetched.tool_name.is_none(), "tool_name must be None when not provided");
        assert!(fetched.target_host.is_none(), "target_host must be None when not provided");
        assert!(fetched.target_url.is_none(), "target_url must be None when not provided");
        assert!(fetched.agent_framework.is_none(), "agent_framework must be None when not provided");
    }

    // --- implementation-note-248: T2 round-trip via ApprovalLifecycle ---

    /// T2: SubmitMetadata carries notify fields → DaemonApprovalStoreRef persists them →
    /// get_approval returns them. This is the seam that was broken before this task.
    #[tokio::test(flavor = "current_thread")]
    async fn notify_fields_round_trip_via_daemon_approval_store_ref() {
        // approval_notify_fields_persisted
        use core_grant_types::approval::RequestedScope;

        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("notify-test").expect("create persona");
        let pid = store.list_personas().unwrap().into_iter().next().unwrap().id;

        let adapter = DaemonApprovalStoreRef::new(&store);

        let metadata = SubmitMetadata {
            action: "tool.invoke".to_string(),
            ttl_secs: Some(300),
            risk_level: "high".to_string(),
            tool_name: Some("WebFetch".to_string()),
            target_host: Some("docs.anthropic.com".to_string()),
            target_url: Some("https://docs.anthropic.com/api".to_string()),
            agent_framework: Some("claude-code".to_string()),
        };
        let scope = RequestedScope {
            capability: "read".to_string(),
            resource_id: None,
            constraints: vec![],
        };

        let request_id = adapter
            .submit_request(&pid, "api-key", scope, metadata)
            .await
            .expect("submit_request must succeed");

        // get_approval must return the persisted notify fields.
        let info = store.get_approval(&request_id.0).expect("approval row must exist");
        assert_eq!(info.status, "pending");
        assert_eq!(info.tool_name.as_deref(), Some("WebFetch"), "tool_name must round-trip via DaemonApprovalStoreRef");
        assert_eq!(info.target_host.as_deref(), Some("docs.anthropic.com"), "target_host must round-trip");
        assert_eq!(info.target_url.as_deref(), Some("https://docs.anthropic.com/api"), "target_url must round-trip");
        assert_eq!(info.agent_framework.as_deref(), Some("claude-code"), "agent_framework must round-trip");
    }

    /// T2: SubmitMetadata carries notify fields → DaemonApprovalStore persists them →
    /// get_approval returns them.
    #[tokio::test(flavor = "current_thread")]
    async fn notify_fields_round_trip_via_daemon_approval_store() {
        use core_grant_types::approval::RequestedScope;
        use std::rc::Rc;

        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("notify-rc-test").expect("create persona");
        let pid = store.list_personas().unwrap().into_iter().next().unwrap().id;
        let store_rc = Rc::new(store);

        let adapter = DaemonApprovalStore::new(Rc::clone(&store_rc));

        let metadata = SubmitMetadata {
            action: "credential.access".to_string(),
            ttl_secs: None,
            risk_level: "medium".to_string(),
            tool_name: Some("ListFiles".to_string()),
            target_host: Some("github.com".to_string()),
            target_url: Some("https://github.com/org/repo".to_string()),
            agent_framework: Some("cursor".to_string()),
        };
        let scope = RequestedScope {
            capability: "write".to_string(),
            resource_id: None,
            constraints: vec![],
        };

        let request_id = adapter
            .submit_request(&pid, "github-token", scope, metadata)
            .await
            .expect("submit_request must succeed");

        let info = store_rc.get_approval(&request_id.0).expect("approval row must exist");
        assert_eq!(info.tool_name.as_deref(), Some("ListFiles"));
        assert_eq!(info.target_host.as_deref(), Some("github.com"));
        assert_eq!(info.target_url.as_deref(), Some("https://github.com/org/repo"));
        assert_eq!(info.agent_framework.as_deref(), Some("cursor"));
    }
}
