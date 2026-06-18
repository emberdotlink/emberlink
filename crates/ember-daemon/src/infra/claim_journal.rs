use std::collections::HashMap;

use chrono::{DateTime, Utc};
use core_event_types::ActionRef;
use core_events::receipt::{ClaimEvent, ClaimKind};
use core_events::receipt::{merkle_leaf, merkle_root};
use core_events::rollup::RollupOutcome;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::infra::audit::append_audit_event_with_chain_in_tx;
use crate::infra::store::{DaemonStore, StoreError};

/// Claim rollup scope for authority-lane/composite receipt materialization.
///
/// `AuthorityLane` scopes model long-running interactive/runtime lanes such as
/// `session.claude_code`. `Grant` scopes model composite-grant lifetimes whose
/// eventual terminal receipt is keyed by grant rather than launcher session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimScopeKind {
    /// Rust name intentionally avoids bare `Session` per ADR 185 §3; the
    /// serialized/storage token stays `"session"` for compatibility with
    /// existing journal rows.
    #[serde(rename = "session")]
    AuthorityLane,
    #[serde(rename = "grant")]
    Grant,
}

/// Stable correlation key for a claim journal working set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRef {
    pub kind: ClaimScopeKind,
    pub id: String,
}

/// Immutable audit evidence that must be appended atomically with a successful
/// claim record. The claim-journal seam owns this transaction choreography so
/// callers do not manually write `audit_log` and claim-journal rows
/// separately.
///
/// Per ADR 186 §3, `action` remains the audit-row verb classifier while the
/// claim journal records canonical structured authority identity in
/// [`SuccessfulClaimInput::action_ref`] and the decomposed indexed columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvidenceInput {
    pub agent_id: Option<String>,
    pub action: String,
    pub credential: Option<String>,
    pub outcome: String,
    pub details: Option<String>,
}

/// Backend-normalized input for one successful authority exercise.
///
/// This is intentionally narrower than a generic "event" abstraction: the
/// journal stores only successful Claims that may contribute to a terminal
/// session/composite Grant Receipt. Attempts and refusals remain audit-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessfulClaimInput {
    /// Stable idempotency key for this successful Claim within its scope.
    ///
    /// The claim journal owns audit-row creation, so `audit_event_id` cannot
    /// be the pre-write dedupe anchor. Callers must supply a source key that
    /// survives retries (for example: a materialization/use invocation id).
    pub source_key: String,
    pub occurred_at: String,
    pub claim_kind: ClaimKind,
    pub tool: String,
    /// Structured action identity for construct-backed authority exercises.
    /// Legacy non-construct uses leave this unset and continue to project via
    /// the flat `tool` string.
    pub action_ref: Option<ActionRef>,
    /// Placement-truth runner class requested/selected for this authority
    /// exercise when the caller can surface it.
    pub runner_class: Option<String>,
    /// Placement-truth execution domain actually used when known.
    pub execution_domain: Option<String>,
    /// Placement-truth materialization class actually used when known.
    pub materialization_class: Option<String>,
    pub input_hash: String,
    pub input_redacted: serde_json::Value,
    pub resolved: serde_json::Value,
    pub audit: AuditEvidenceInput,
    pub persona_id: Option<String>,
    pub grant_id: Option<String>,
    pub device_id: Option<String>,
    pub delegation_id: Option<String>,
    pub materialization_id: Option<String>,
    pub credential_name: Option<String>,
}

/// Segment summary returned by the journal on snapshot/close operations.
///
/// Segment roots let the session/composite receipt materializer scale without
/// forcing one unbounded in-memory `Vec<ClaimEvent>` across long sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSegmentSummary {
    pub segment_no: i64,
    pub first_scope_seq: i64,
    pub last_scope_seq: i64,
    pub claim_count: usize,
    pub started_at: String,
    pub ended_at: String,
    pub merkle_root: String,
}

/// Bounded view of an open scope for dashboards/debugging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalSnapshot {
    pub scope: ScopeRef,
    pub claim_count: usize,
    pub segment_count: usize,
    pub open_segment_claims: usize,
    pub open_segment_no: i64,
}

/// Close-time handoff from the claim journal to the receipt materializer.
///
/// The journal returns segment summaries plus a bounded tail of recent
/// redacted claim events. Receipt materializers should not scan raw journal
/// rows directly; they consume this summary surface instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedScopeSummary {
    pub scope: ScopeRef,
    pub total_claims: usize,
    pub segments: Vec<ClaimSegmentSummary>,
    pub recent_claims: Vec<ClaimEvent>,
    pub recent_claims_truncated: bool,
}

/// Read-time service summary anchored to claim-journal segments.
///
/// Each `merkle_segment_ref` identifies one segment that contributed at least
/// one claim to the summary window. The reference format is
/// `<scope_kind>:<scope_id>:<segment_no>:<merkle_root>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRollupSummary {
    pub plugin_address: String,
    pub window_start: String,
    pub window_end: String,
    pub total_claims: usize,
    pub unique_personas: usize,
    pub unique_grants: usize,
    pub spend_total_cents: Option<i64>,
    pub by_outcome: HashMap<RollupOutcome, usize>,
    pub by_runner_class: HashMap<String, usize>,
    pub last_claim_at: Option<String>,
    pub merkle_segment_refs: Vec<String>,
}

/// Result of appending a successful claim to the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppendDisposition {
    Appended {
        source_key: String,
        audit_event_id: i64,
        scope_seq: i64,
        segment_no: i64,
        segment_seq: i64,
    },
    Duplicate {
        source_key: String,
        audit_event_id: i64,
        scope_seq: i64,
    },
}

/// Per-scope projection result returned from multi-scope claim appends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedAppendDisposition {
    pub scope: ScopeRef,
    pub disposition: AppendDisposition,
}

/// Scope-close options that affect close-time receipt materialization shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseScopeOpts {
    /// Maximum number of recent redacted claim events to surface inline in the
    /// close summary. Older history remains covered by segment summaries and
    /// immutable audit evidence.
    pub recent_claim_limit: usize,
}

impl Default for CloseScopeOpts {
    fn default() -> Self {
        Self {
            recent_claim_limit: 32,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimJournalError {
    #[error("scope id must not be empty")]
    EmptyScopeId,
    #[error("successful claim input is missing audit action")]
    MissingAuditAction,
    #[error("successful claim input is missing source_key")]
    MissingSourceKey,
    #[error("successful claim input is missing tool")]
    MissingTool,
    #[error("successful claim input is missing input_hash")]
    MissingInputHash,
    #[error("plugin_address must not be empty")]
    EmptyPluginAddress,
    #[error("scope not found")]
    ScopeNotFound,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Backend seam for session/composite claim accumulation.
///
/// Adapter contract:
/// - append immutable audit evidence and the normalized claim row in ONE
///   backend transaction
/// - assign `scope_seq` / `segment_seq` internally
/// - enforce idempotency without relying on caller-managed sequence state
/// - return segment-aware close summaries suitable for receipt materialization
///
/// Team Zero note: this seam is intentionally storage-backed. We expect at
/// least a SQLite adapter and a Postgres adapter.
pub trait ClaimJournal {
    fn record_successful_claim_for_scopes(
        &self,
        scopes: &[ScopeRef],
        input: &SuccessfulClaimInput,
    ) -> Result<Vec<ScopedAppendDisposition>, ClaimJournalError>;

    fn record_successful_claim(
        &self,
        scope: &ScopeRef,
        input: &SuccessfulClaimInput,
    ) -> Result<AppendDisposition, ClaimJournalError>;

    fn snapshot(&self, scope: &ScopeRef) -> Result<JournalSnapshot, ClaimJournalError>;

    fn summarize_scope(
        &self,
        scope: &ScopeRef,
        opts: CloseScopeOpts,
    ) -> Result<ClosedScopeSummary, ClaimJournalError>;

    fn close_scope(
        &self,
        scope: &ScopeRef,
        opts: CloseScopeOpts,
    ) -> Result<ClosedScopeSummary, ClaimJournalError>;
}

pub struct SqliteClaimJournal<'a> {
    store: &'a DaemonStore,
    segment_target: usize,
}

pub const DEFAULT_CLAIM_JOURNAL_SEGMENT_TARGET: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedActionRef {
    action_ref: Option<ActionRef>,
    /// `true` means this row only had a legacy flat tool/action string after
    /// deterministic ADR 186 parsing. Service-grouped rollups exclude it.
    legacy_flat: bool,
}

impl<'a> SqliteClaimJournal<'a> {
    pub fn new(store: &'a DaemonStore, segment_target: usize) -> Self {
        Self {
            store,
            segment_target: segment_target.max(1),
        }
    }

    fn validate_scope(scope: &ScopeRef) -> Result<(), ClaimJournalError> {
        if scope.id.trim().is_empty() {
            return Err(ClaimJournalError::EmptyScopeId);
        }
        Ok(())
    }

    fn validate_input(input: &SuccessfulClaimInput) -> Result<(), ClaimJournalError> {
        if input.source_key.trim().is_empty() {
            return Err(ClaimJournalError::MissingSourceKey);
        }
        if input.audit.action.trim().is_empty() {
            return Err(ClaimJournalError::MissingAuditAction);
        }
        if input.tool.trim().is_empty() {
            return Err(ClaimJournalError::MissingTool);
        }
        if input.input_hash.trim().is_empty() {
            return Err(ClaimJournalError::MissingInputHash);
        }
        Ok(())
    }

    fn validate_scope_set(scopes: &[ScopeRef]) -> Result<Vec<ScopeRef>, ClaimJournalError> {
        let mut normalized = Vec::with_capacity(scopes.len());
        for scope in scopes {
            Self::validate_scope(scope)?;
            if !normalized
                .iter()
                .any(|existing: &ScopeRef| existing == scope)
            {
                normalized.push(scope.clone());
            }
        }
        if normalized.is_empty() {
            return Err(ClaimJournalError::EmptyScopeId);
        }
        Ok(normalized)
    }

    fn validate_plugin_address(plugin_address: &str) -> Result<(), ClaimJournalError> {
        if plugin_address.trim().is_empty() {
            return Err(ClaimJournalError::EmptyPluginAddress);
        }
        Ok(())
    }

    /// Deterministic ADR 186 backfill parser.
    ///
    /// The only accepted legacy display form is the structured display form
    /// produced by [`ActionRef::to_string`]:
    /// `<plugin_address>/<action_key>@<action_version>`. Anything else is
    /// historical flat evidence and is tagged `legacy_flat=1`.
    pub(crate) fn backfill_action_ref_from_tool(tool: &str) -> Option<ActionRef> {
        ActionRef::parse(tool.trim()).ok()
    }

    fn resolve_action_ref(input: &SuccessfulClaimInput) -> ResolvedActionRef {
        if let Some(action_ref) = input.action_ref.clone() {
            return ResolvedActionRef {
                action_ref: Some(action_ref),
                legacy_flat: false,
            };
        }
        match Self::backfill_action_ref_from_tool(&input.tool) {
            Some(action_ref) => ResolvedActionRef {
                action_ref: Some(action_ref),
                legacy_flat: false,
            },
            None => ResolvedActionRef {
                action_ref: None,
                legacy_flat: true,
            },
        }
    }

    fn ensure_claim_journal_adr186_columns(
        conn: &rusqlite::Connection,
    ) -> Result<(), ClaimJournalError> {
        let _ = conn.execute(
            "ALTER TABLE claim_journal_claims ADD COLUMN legacy_flat INTEGER NOT NULL DEFAULT 0",
            [],
        );
        conn.prepare("SELECT legacy_flat FROM claim_journal_claims LIMIT 0")
            .map_err(Self::map_store)?;
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_plugin_time
             ON claim_journal_claims(action_plugin_address, ts)",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_claim_journal_claims_action_full
             ON claim_journal_claims(action_plugin_address, action_key, action_version)",
            [],
        );
        Ok(())
    }

    fn backfill_legacy_claim_action_refs(
        conn: &rusqlite::Connection,
    ) -> Result<(), ClaimJournalError> {
        Self::ensure_claim_journal_adr186_columns(conn)?;
        let mut stmt = conn
            .prepare(
                "SELECT rowid, tool
                   FROM claim_journal_claims
                  WHERE COALESCE(legacy_flat, 0) = 0
                    AND (action_plugin_address IS NULL
                         OR action_key IS NULL
                         OR action_version IS NULL)",
            )
            .map_err(Self::map_store)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?;
        drop(stmt);

        for (rowid, tool) in rows {
            match Self::backfill_action_ref_from_tool(&tool) {
                Some(action_ref) => {
                    conn.execute(
                        "UPDATE claim_journal_claims
                            SET action_plugin_address = ?2,
                                action_key = ?3,
                                action_version = ?4,
                                legacy_flat = 0
                          WHERE rowid = ?1",
                        params![
                            rowid,
                            action_ref.plugin_address,
                            action_ref.action_key,
                            action_ref.action_version
                        ],
                    )
                    .map_err(Self::map_store)?;
                }
                None => {
                    conn.execute(
                        "UPDATE claim_journal_claims
                            SET legacy_flat = 1
                          WHERE rowid = ?1",
                        params![rowid],
                    )
                    .map_err(Self::map_store)?;
                }
            }
        }
        Ok(())
    }

    fn scope_kind_str(kind: ClaimScopeKind) -> &'static str {
        match kind {
            ClaimScopeKind::AuthorityLane => "session",
            ClaimScopeKind::Grant => "grant",
        }
    }

    fn claim_kind_str(kind: ClaimKind) -> &'static str {
        match kind {
            ClaimKind::Approval => "approval",
            ClaimKind::Denial => "denial",
            ClaimKind::CredentialVended => "credential_vended",
            ClaimKind::ScopeCheck => "scope_check",
        }
    }

    fn claim_kind_from_str(kind: &str) -> Result<ClaimKind, ClaimJournalError> {
        match kind {
            "approval" => Ok(ClaimKind::Approval),
            "denial" => Ok(ClaimKind::Denial),
            "credential_vended" => Ok(ClaimKind::CredentialVended),
            "scope_check" => Ok(ClaimKind::ScopeCheck),
            other => Err(ClaimJournalError::Backend(format!(
                "unknown claim_kind in journal: {other}"
            ))),
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn compute_segment_merkle_root(
        conn: &rusqlite::Connection,
        scope: &ScopeRef,
        segment_no: i64,
    ) -> Result<String, ClaimJournalError> {
        let mut stmt = conn
            .prepare(
                "SELECT input_hash
                   FROM claim_journal_claims
                  WHERE scope_kind = ?1 AND scope_id = ?2 AND segment_no = ?3
               ORDER BY segment_seq ASC",
            )
            .map_err(Self::map_store)?;
        let hashes = stmt
            .query_map(
                params![Self::scope_kind_str(scope.kind), scope.id, segment_no],
                |row| row.get::<_, String>(0),
            )
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?;
        if hashes.is_empty() {
            return Ok(String::new());
        }
        let leaves: Vec<[u8; 32]> = hashes.iter().map(|h| merkle_leaf(h.as_bytes())).collect();
        Ok(Self::hex_lower(&merkle_root(&leaves)))
    }

    fn map_store(err: impl std::fmt::Display) -> ClaimJournalError {
        ClaimJournalError::Backend(err.to_string())
    }

    fn rollup_outcome_from_audit_outcome(outcome: &str) -> RollupOutcome {
        match outcome {
            "allowed" | "ok" | "success" | "minted" => RollupOutcome::Success,
            "in_flight" => RollupOutcome::InFlight,
            "incomplete" => RollupOutcome::Incomplete,
            other if other.starts_with("denied") => RollupOutcome::Denied {
                reason: other.to_string(),
            },
            other if other.starts_with("exit_code:") => {
                let exit_code = other
                    .trim_start_matches("exit_code:")
                    .parse::<i32>()
                    .unwrap_or(-1);
                RollupOutcome::Errored { exit_code }
            }
            other => RollupOutcome::Denied {
                reason: other.to_string(),
            },
        }
    }

    fn upsert_scope_and_segment_state(
        &self,
        conn: &rusqlite::Connection,
        scope: &ScopeRef,
        occurred_at: &str,
    ) -> Result<(i64, i64, i64), ClaimJournalError> {
        conn.execute(
            "INSERT OR IGNORE INTO claim_journal_scopes
             (scope_kind, scope_id, status, next_scope_seq, open_segment_no, created_at, closed_at)
             VALUES (?1, ?2, 'open', 1, 0, ?3, NULL)",
            params![Self::scope_kind_str(scope.kind), scope.id, occurred_at],
        )
        .map_err(Self::map_store)?;

        let (scope_seq, mut open_segment_no): (i64, i64) = conn
            .query_row(
                "SELECT next_scope_seq, open_segment_no
                   FROM claim_journal_scopes
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(Self::map_store)?;

        conn.execute(
            "INSERT OR IGNORE INTO claim_journal_segments
             (scope_kind, scope_id, segment_no, status, first_scope_seq, last_scope_seq, claim_count, started_at, ended_at, merkle_root)
             VALUES (?1, ?2, ?3, 'open', ?4, ?4, 0, ?5, ?5, '')",
            params![
                Self::scope_kind_str(scope.kind),
                scope.id,
                open_segment_no,
                scope_seq,
                occurred_at
            ],
        )
        .map_err(Self::map_store)?;

        let claim_count: i64 = conn
            .query_row(
                "SELECT claim_count
                   FROM claim_journal_segments
                  WHERE scope_kind = ?1 AND scope_id = ?2 AND segment_no = ?3",
                params![Self::scope_kind_str(scope.kind), scope.id, open_segment_no],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;

        if claim_count >= self.segment_target as i64 {
            open_segment_no += 1;
            conn.execute(
                "UPDATE claim_journal_scopes
                    SET open_segment_no = ?3
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id, open_segment_no],
            )
            .map_err(Self::map_store)?;
            conn.execute(
                "INSERT OR IGNORE INTO claim_journal_segments
                 (scope_kind, scope_id, segment_no, status, first_scope_seq, last_scope_seq, claim_count, started_at, ended_at, merkle_root)
                 VALUES (?1, ?2, ?3, 'open', ?4, ?4, 0, ?5, ?5, '')",
                params![
                    Self::scope_kind_str(scope.kind),
                    scope.id,
                    open_segment_no,
                    scope_seq,
                    occurred_at
                ],
            )
            .map_err(Self::map_store)?;
        }

        let segment_seq: i64 = conn
            .query_row(
                "SELECT claim_count + 1
                   FROM claim_journal_segments
                  WHERE scope_kind = ?1 AND scope_id = ?2 AND segment_no = ?3",
                params![Self::scope_kind_str(scope.kind), scope.id, open_segment_no],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;

        Ok((scope_seq, open_segment_no, segment_seq))
    }

    fn insert_claim_row_for_scope(
        conn: &rusqlite::Connection,
        scope: &ScopeRef,
        input: &SuccessfulClaimInput,
        audit_event_id: i64,
        scope_seq: i64,
        segment_no: i64,
        segment_seq: i64,
    ) -> Result<(), ClaimJournalError> {
        Self::ensure_claim_journal_adr186_columns(conn)?;
        let resolved = Self::resolve_action_ref(input);
        let legacy_flat = if resolved.legacy_flat { 1_i64 } else { 0_i64 };
        conn.execute(
            "INSERT INTO claim_journal_claims
             (scope_kind, scope_id, scope_seq, segment_no, segment_seq, source_key, audit_event_id, ts, claim_kind, tool, action_plugin_address, action_key, action_version, runner_class, execution_domain, materialization_class, legacy_flat, input_hash, input_redacted_json, resolved_json, persona_id, grant_id, device_id, delegation_id, materialization_id, credential_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
            params![
                Self::scope_kind_str(scope.kind),
                scope.id,
                scope_seq,
                segment_no,
                segment_seq,
                input.source_key,
                audit_event_id,
                input.occurred_at,
                Self::claim_kind_str(input.claim_kind),
                input.tool,
                resolved
                    .action_ref
                    .as_ref()
                    .map(|v| v.plugin_address.as_str()),
                resolved.action_ref.as_ref().map(|v| v.action_key.as_str()),
                resolved
                    .action_ref
                    .as_ref()
                    .map(|v| v.action_version.as_str()),
                input.runner_class.as_deref(),
                input.execution_domain.as_deref(),
                input.materialization_class.as_deref(),
                legacy_flat,
                input.input_hash,
                serde_json::to_string(&input.input_redacted).map_err(Self::map_store)?,
                serde_json::to_string(&input.resolved).map_err(Self::map_store)?,
                input.persona_id,
                input.grant_id,
                input.device_id,
                input.delegation_id,
                input.materialization_id,
                input.credential_name,
            ],
        )
        .map_err(Self::map_store)?;
        Ok(())
    }

    fn load_closed_scope_summary(
        conn: &rusqlite::Connection,
        scope: &ScopeRef,
        opts: CloseScopeOpts,
    ) -> Result<ClosedScopeSummary, ClaimJournalError> {
        Self::backfill_legacy_claim_action_refs(conn)?;
        let total_claims: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                   FROM claim_journal_claims
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;

        let mut seg_stmt = conn
            .prepare(
                "SELECT segment_no, first_scope_seq, last_scope_seq, claim_count, started_at, ended_at, merkle_root
                   FROM claim_journal_segments
                  WHERE scope_kind = ?1 AND scope_id = ?2
               ORDER BY segment_no ASC",
            )
            .map_err(Self::map_store)?;
        let segments = seg_stmt
            .query_map(params![Self::scope_kind_str(scope.kind), scope.id], |row| {
                Ok(ClaimSegmentSummary {
                    segment_no: row.get(0)?,
                    first_scope_seq: row.get(1)?,
                    last_scope_seq: row.get(2)?,
                    claim_count: row.get::<_, i64>(3)? as usize,
                    started_at: row.get(4)?,
                    ended_at: row.get(5)?,
                    merkle_root: row.get(6)?,
                })
            })
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?;

        let mut claim_stmt = conn
            .prepare(
                "SELECT ts, claim_kind, tool, action_plugin_address, action_key, action_version, input_hash, input_redacted_json, resolved_json
                   FROM claim_journal_claims
                  WHERE scope_kind = ?1 AND scope_id = ?2
               ORDER BY scope_seq DESC
                  LIMIT ?3",
            )
            .map_err(Self::map_store)?;
        let mut recent_claims = claim_stmt
            .query_map(
                params![
                    Self::scope_kind_str(scope.kind),
                    scope.id,
                    opts.recent_claim_limit as i64
                ],
                |row| {
                    let kind: String = row.get(1)?;
                    let plugin_address: Option<String> = row.get(3)?;
                    let action_key: Option<String> = row.get(4)?;
                    let action_version: Option<String> = row.get(5)?;
                    let input_redacted_json: String = row.get(7)?;
                    let resolved_json: String = row.get(8)?;
                    Ok(ClaimEvent {
                        ts: row.get(0)?,
                        kind: Self::claim_kind_from_str(&kind)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                        tool: row.get(2)?,
                        action_ref: match (plugin_address, action_key, action_version) {
                            (Some(plugin_address), Some(action_key), Some(action_version)) => {
                                Some(ActionRef::new(plugin_address, action_key, action_version))
                            }
                            _ => None,
                        },
                        input_hash: row.get(6)?,
                        input_redacted: serde_json::from_str(&input_redacted_json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                        resolved: serde_json::from_str(&resolved_json)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                    })
                },
            )
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?;
        recent_claims.reverse();

        Ok(ClosedScopeSummary {
            scope: scope.clone(),
            total_claims: total_claims as usize,
            segments,
            recent_claims_truncated: (total_claims as usize) > recent_claims.len(),
            recent_claims,
        })
    }

    /// Public ADR 187 §10d Layer 5 query entry point.
    ///
    /// Validates inputs + backfills any legacy flat rows, then delegates the
    /// actual aggregation to [`Self::compute_service_rollup`]. Splitting the
    /// helper out keeps the single indexed SELECT path explicit and gives
    /// callers (`ember catalog usage`, `ember spend by-service`, dashboard
    /// Layer 5) one named aggregation seam to reuse without re-running input
    /// validation on every call.
    pub fn summarize_by_service(
        &self,
        plugin_address: &str,
        window: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<ServiceRollupSummary, ClaimJournalError> {
        Self::validate_plugin_address(plugin_address)?;
        let conn = self.store.conn();
        Self::backfill_legacy_claim_action_refs(conn)?;
        Self::compute_service_rollup(conn, plugin_address, window)
    }

    /// ADR 187 §10d aggregation helper — the single indexed SELECT path that
    /// summarizes the `(action_plugin_address, ts)`-keyed claim rows over a
    /// window and anchors the resulting rollup to the existing tamper-evident
    /// segment chain via `merkle_segment_refs`.
    ///
    /// `legacy_flat=1` rows are excluded per ADR 187 §10d; rows without a
    /// structured `action_ref` are likewise excluded so service rollups only
    /// reflect canonical ADR 186 claims.
    ///
    /// The caller (`summarize_by_service`) is responsible for input validation
    /// and the legacy-action-ref backfill so this helper stays a pure
    /// aggregation step.
    fn compute_service_rollup(
        conn: &rusqlite::Connection,
        plugin_address: &str,
        window: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<ServiceRollupSummary, ClaimJournalError> {
        let window_start = window.0.to_rfc3339();
        let window_end = window.1.to_rfc3339();

        let (total_claims, unique_personas, unique_grants, last_claim_at): (
            i64,
            i64,
            i64,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT COUNT(*),
                        COUNT(DISTINCT persona_id),
                        COUNT(DISTINCT grant_id),
                        MAX(ts)
                   FROM claim_journal_claims
                  WHERE action_plugin_address = ?1
                    AND ts >= ?2
                    AND ts <= ?3
                    AND action_key IS NOT NULL
                    AND action_version IS NOT NULL
                    AND COALESCE(legacy_flat, 0) = 0",
                params![plugin_address, window_start, window_end],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(Self::map_store)?;

        let mut outcome_stmt = conn
            .prepare(
                "SELECT a.outcome, COUNT(*)
                   FROM claim_journal_claims c
                   JOIN audit_log a
                     ON a.id = c.audit_event_id
                  WHERE c.action_plugin_address = ?1
                    AND c.ts >= ?2
                    AND c.ts <= ?3
                    AND c.action_key IS NOT NULL
                    AND c.action_version IS NOT NULL
                    AND COALESCE(c.legacy_flat, 0) = 0
               GROUP BY a.outcome",
            )
            .map_err(Self::map_store)?;
        let by_outcome = outcome_stmt
            .query_map(params![plugin_address, window_start, window_end], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?
            .into_iter()
            .fold(HashMap::new(), |mut acc, (outcome, count)| {
                acc.insert(
                    Self::rollup_outcome_from_audit_outcome(&outcome),
                    count as usize,
                );
                acc
            });

        let mut runner_stmt = conn
            .prepare(
                "SELECT runner_class, COUNT(*)
                   FROM claim_journal_claims
                  WHERE action_plugin_address = ?1
                    AND ts >= ?2
                    AND ts <= ?3
                    AND action_key IS NOT NULL
                    AND action_version IS NOT NULL
                    AND COALESCE(legacy_flat, 0) = 0
                    AND runner_class IS NOT NULL
                    AND runner_class <> ''
               GROUP BY runner_class",
            )
            .map_err(Self::map_store)?;
        let by_runner_class = runner_stmt
            .query_map(params![plugin_address, window_start, window_end], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?
            .into_iter()
            .map(|(runner_class, count)| (runner_class, count as usize))
            .collect::<HashMap<_, _>>();

        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT c.scope_kind, c.scope_id, c.segment_no, s.merkle_root
                   FROM claim_journal_claims c
                   JOIN claim_journal_segments s
                     ON s.scope_kind = c.scope_kind
                    AND s.scope_id = c.scope_id
                    AND s.segment_no = c.segment_no
                  WHERE c.action_plugin_address = ?1
                    AND c.ts >= ?2
                    AND c.ts <= ?3
                    AND c.action_key IS NOT NULL
                    AND c.action_version IS NOT NULL
                    AND COALESCE(c.legacy_flat, 0) = 0
               ORDER BY c.scope_kind ASC, c.scope_id ASC, c.segment_no ASC",
            )
            .map_err(Self::map_store)?;
        let merkle_segment_refs = stmt
            .query_map(params![plugin_address, window_start, window_end], |row| {
                let scope_kind: String = row.get(0)?;
                let scope_id: String = row.get(1)?;
                let segment_no: i64 = row.get(2)?;
                let merkle_root: String = row.get(3)?;
                Ok(format!(
                    "{scope_kind}:{scope_id}:{segment_no}:{merkle_root}"
                ))
            })
            .map_err(Self::map_store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Self::map_store)?;

        Ok(ServiceRollupSummary {
            plugin_address: plugin_address.to_string(),
            window_start,
            window_end,
            total_claims: total_claims as usize,
            unique_personas: unique_personas as usize,
            unique_grants: unique_grants as usize,
            spend_total_cents: None,
            by_outcome,
            by_runner_class,
            last_claim_at,
            merkle_segment_refs,
        })
    }
}

fn close_scope_best_effort(
    store: &DaemonStore,
    scope: ScopeRef,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    let journal = SqliteClaimJournal::new(store, DEFAULT_CLAIM_JOURNAL_SEGMENT_TARGET);
    match journal.close_scope(&scope, CloseScopeOpts::default()) {
        Ok(summary) => Some(summary),
        Err(ClaimJournalError::ScopeNotFound) => {
            debug!(
                scope_kind = SqliteClaimJournal::scope_kind_str(scope.kind),
                scope_id = scope.id,
                context,
                "claim journal: no scope to close"
            );
            None
        }
        Err(err) => {
            warn!(
                scope_kind = SqliteClaimJournal::scope_kind_str(scope.kind),
                scope_id = scope.id,
                context,
                error = %err,
                "claim journal: failed to close scope"
            );
            None
        }
    }
}

fn summarize_scope_best_effort(
    store: &DaemonStore,
    scope: ScopeRef,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    let journal = SqliteClaimJournal::new(store, DEFAULT_CLAIM_JOURNAL_SEGMENT_TARGET);
    match journal.summarize_scope(&scope, CloseScopeOpts::default()) {
        Ok(summary) => Some(summary),
        Err(ClaimJournalError::ScopeNotFound) => {
            debug!(
                scope_kind = SqliteClaimJournal::scope_kind_str(scope.kind),
                scope_id = scope.id,
                context,
                "claim journal: no scope to summarize"
            );
            None
        }
        Err(err) => {
            warn!(
                scope_kind = SqliteClaimJournal::scope_kind_str(scope.kind),
                scope_id = scope.id,
                context,
                error = %err,
                "claim journal: failed to summarize scope"
            );
            None
        }
    }
}

/// Best-effort session-scope close helper used by session termination paths.
///
/// A session may legitimately have no journal scope at all if it never
/// exercised successful authority after opening. That case stays silent.
pub fn close_session_scope_best_effort(
    store: &DaemonStore,
    session_id: &str,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    close_scope_best_effort(
        store,
        ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: session_id.to_string(),
        },
        context,
    )
}

pub fn summarize_session_scope_best_effort(
    store: &DaemonStore,
    session_id: &str,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    summarize_scope_best_effort(
        store,
        ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: session_id.to_string(),
        },
        context,
    )
}

pub fn close_grant_scope_best_effort(
    store: &DaemonStore,
    grant_id: &str,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    close_scope_best_effort(
        store,
        ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: grant_id.to_string(),
        },
        context,
    )
}

pub fn summarize_grant_scope_best_effort(
    store: &DaemonStore,
    grant_id: &str,
    context: &'static str,
) -> Option<ClosedScopeSummary> {
    summarize_scope_best_effort(
        store,
        ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: grant_id.to_string(),
        },
        context,
    )
}

pub fn close_summary_audit_fields(summary: &ClosedScopeSummary) -> String {
    format!(
        "claim_count={} segment_count={} recent_claims_truncated={}",
        summary.total_claims,
        summary.segments.len(),
        summary.recent_claims_truncated
    )
}

impl<'a> ClaimJournal for SqliteClaimJournal<'a> {
    fn record_successful_claim_for_scopes(
        &self,
        scopes: &[ScopeRef],
        input: &SuccessfulClaimInput,
    ) -> Result<Vec<ScopedAppendDisposition>, ClaimJournalError> {
        let scopes = Self::validate_scope_set(scopes)?;
        Self::validate_input(input)?;

        let conn = self.store.conn();
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(Self::map_store)?;

        let result = (|| -> Result<Vec<ScopedAppendDisposition>, ClaimJournalError> {
            let mut results = Vec::with_capacity(scopes.len());
            let mut existing_audit_event_id: Option<i64> = None;
            let mut new_scope_count = 0usize;

            for scope in &scopes {
                let existing = conn
                    .query_row(
                        "SELECT audit_event_id, scope_seq
                           FROM claim_journal_claims
                          WHERE scope_kind = ?1 AND scope_id = ?2 AND source_key = ?3",
                        params![Self::scope_kind_str(scope.kind), scope.id, input.source_key],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .ok();

                if let Some((audit_event_id, scope_seq)) = existing {
                    if let Some(prior) = existing_audit_event_id {
                        if prior != audit_event_id {
                            return Err(ClaimJournalError::Backend(format!(
                                "inconsistent multi-scope journal state for source_key {}: audit_event_id {} != {}",
                                input.source_key, prior, audit_event_id
                            )));
                        }
                    } else {
                        existing_audit_event_id = Some(audit_event_id);
                    }
                    results.push(ScopedAppendDisposition {
                        scope: scope.clone(),
                        disposition: AppendDisposition::Duplicate {
                            source_key: input.source_key.clone(),
                            audit_event_id,
                            scope_seq,
                        },
                    });
                } else {
                    new_scope_count += 1;
                    results.push(ScopedAppendDisposition {
                        scope: scope.clone(),
                        disposition: AppendDisposition::Duplicate {
                            source_key: input.source_key.clone(),
                            audit_event_id: -1,
                            scope_seq: -1,
                        },
                    });
                }
            }

            if new_scope_count == 0 {
                return Ok(results);
            }

            let audit_event_id = if let Some(existing) = existing_audit_event_id {
                existing
            } else {
                append_audit_event_with_chain_in_tx(
                    conn,
                    input.audit.agent_id.as_deref(),
                    &input.audit.action,
                    input.audit.credential.as_deref(),
                    &input.audit.outcome,
                    input.audit.details.as_deref(),
                )
                .map_err(|e: StoreError| Self::map_store(e))?
            };

            for result in &mut results {
                let needs_append = matches!(
                    result.disposition,
                    AppendDisposition::Duplicate {
                        audit_event_id: -1,
                        scope_seq: -1,
                        ..
                    }
                );
                if !needs_append {
                    continue;
                }

                let (scope_seq, segment_no, segment_seq) =
                    self.upsert_scope_and_segment_state(conn, &result.scope, &input.occurred_at)?;
                Self::insert_claim_row_for_scope(
                    conn,
                    &result.scope,
                    input,
                    audit_event_id,
                    scope_seq,
                    segment_no,
                    segment_seq,
                )?;

                let merkle_root =
                    Self::compute_segment_merkle_root(conn, &result.scope, segment_no)?;
                conn.execute(
                    "UPDATE claim_journal_segments
                        SET claim_count = claim_count + 1,
                            last_scope_seq = ?4,
                            ended_at = ?5,
                            merkle_root = ?6
                      WHERE scope_kind = ?1 AND scope_id = ?2 AND segment_no = ?3",
                    params![
                        Self::scope_kind_str(result.scope.kind),
                        result.scope.id,
                        segment_no,
                        scope_seq,
                        input.occurred_at,
                        merkle_root
                    ],
                )
                .map_err(Self::map_store)?;

                conn.execute(
                    "UPDATE claim_journal_scopes
                        SET next_scope_seq = ?3
                      WHERE scope_kind = ?1 AND scope_id = ?2",
                    params![
                        Self::scope_kind_str(result.scope.kind),
                        result.scope.id,
                        scope_seq + 1
                    ],
                )
                .map_err(Self::map_store)?;

                result.disposition = AppendDisposition::Appended {
                    source_key: input.source_key.clone(),
                    audit_event_id,
                    scope_seq,
                    segment_no,
                    segment_seq,
                };
            }

            Ok(results)
        })();

        match result {
            Ok(value) => {
                conn.execute("COMMIT", []).map_err(Self::map_store)?;
                Ok(value)
            }
            Err(err) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(err)
            }
        }
    }

    fn record_successful_claim(
        &self,
        scope: &ScopeRef,
        input: &SuccessfulClaimInput,
    ) -> Result<AppendDisposition, ClaimJournalError> {
        let mut results =
            self.record_successful_claim_for_scopes(std::slice::from_ref(scope), input)?;
        match results.pop() {
            Some(result) => Ok(result.disposition),
            None => Err(ClaimJournalError::Backend(
                "single-scope append unexpectedly returned no result".to_string(),
            )),
        }
    }

    fn snapshot(&self, scope: &ScopeRef) -> Result<JournalSnapshot, ClaimJournalError> {
        Self::validate_scope(scope)?;
        let conn = self.store.conn();
        let (open_segment_no,): (i64,) = conn
            .query_row(
                "SELECT open_segment_no
                   FROM claim_journal_scopes
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
                |row| Ok((row.get(0)?,)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => ClaimJournalError::ScopeNotFound,
                other => Self::map_store(other),
            })?;
        let claim_count: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                   FROM claim_journal_claims
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;
        let segment_count: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                   FROM claim_journal_segments
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;
        let open_segment_claims: i64 = conn
            .query_row(
                "SELECT claim_count
                   FROM claim_journal_segments
                  WHERE scope_kind = ?1 AND scope_id = ?2 AND segment_no = ?3",
                params![Self::scope_kind_str(scope.kind), scope.id, open_segment_no],
                |row| row.get(0),
            )
            .map_err(Self::map_store)?;

        Ok(JournalSnapshot {
            scope: scope.clone(),
            claim_count: claim_count as usize,
            segment_count: segment_count as usize,
            open_segment_claims: open_segment_claims as usize,
            open_segment_no,
        })
    }

    fn summarize_scope(
        &self,
        scope: &ScopeRef,
        opts: CloseScopeOpts,
    ) -> Result<ClosedScopeSummary, ClaimJournalError> {
        Self::validate_scope(scope)?;
        let conn = self.store.conn();
        conn.query_row(
            "SELECT 1
               FROM claim_journal_scopes
              WHERE scope_kind = ?1 AND scope_id = ?2",
            params![Self::scope_kind_str(scope.kind), scope.id],
            |_| Ok(()),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ClaimJournalError::ScopeNotFound,
            other => Self::map_store(other),
        })?;
        Self::load_closed_scope_summary(conn, scope, opts)
    }

    fn close_scope(
        &self,
        scope: &ScopeRef,
        opts: CloseScopeOpts,
    ) -> Result<ClosedScopeSummary, ClaimJournalError> {
        Self::validate_scope(scope)?;
        let conn = self.store.conn();
        let closed_at = Utc::now().to_rfc3339();
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(Self::map_store)?;

        let result = (|| -> Result<ClosedScopeSummary, ClaimJournalError> {
            let updated = conn
                .execute(
                    "UPDATE claim_journal_scopes
                        SET status = 'closed',
                            closed_at = COALESCE(closed_at, ?3)
                      WHERE scope_kind = ?1 AND scope_id = ?2",
                    params![Self::scope_kind_str(scope.kind), scope.id, closed_at],
                )
                .map_err(Self::map_store)?;
            if updated == 0 {
                return Err(ClaimJournalError::ScopeNotFound);
            }

            conn.execute(
                "UPDATE claim_journal_segments
                    SET status = 'closed'
                  WHERE scope_kind = ?1 AND scope_id = ?2",
                params![Self::scope_kind_str(scope.kind), scope.id],
            )
            .map_err(Self::map_store)?;
            Self::load_closed_scope_summary(conn, scope, opts)
        })();

        match result {
            Ok(value) => {
                conn.execute("COMMIT", []).map_err(Self::map_store)?;
                Ok(value)
            }
            Err(err) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_quarantine_latch() {
        crate::infra::handler::force_quarantine_latch_for_test(false);
    }

    struct ClaimJournalTestGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for ClaimJournalTestGuard {
        fn drop(&mut self) {
            reset_quarantine_latch();
        }
    }

    fn claim_journal_test_guard() -> ClaimJournalTestGuard {
        let guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_quarantine_latch();
        ClaimJournalTestGuard { _guard: guard }
    }

    fn test_store() -> DaemonStore {
        reset_quarantine_latch();
        DaemonStore::open_in_memory().unwrap()
    }

    fn sample_input(source_key: &str, action: &str, hash: &str) -> SuccessfulClaimInput {
        SuccessfulClaimInput {
            source_key: source_key.to_string(),
            occurred_at: "2026-05-22T12:00:00Z".to_string(),
            claim_kind: ClaimKind::CredentialVended,
            tool: "Claude".to_string(),
            action_ref: None,
            runner_class: None,
            execution_domain: None,
            materialization_class: None,
            input_hash: hash.to_string(),
            input_redacted: serde_json::json!({"cmd": "deploy"}),
            resolved: serde_json::json!({"allowed": true}),
            audit: AuditEvidenceInput {
                agent_id: Some("persona-test".to_string()),
                action: action.to_string(),
                credential: Some("anthropic".to_string()),
                outcome: "ok".to_string(),
                details: Some("materialized".to_string()),
            },
            persona_id: Some("persona-test".to_string()),
            grant_id: Some("grant-test".to_string()),
            device_id: Some("device-test".to_string()),
            delegation_id: None,
            materialization_id: Some("mid-test".to_string()),
            credential_name: Some("anthropic".to_string()),
        }
    }

    #[test]
    fn sqlite_claim_journal_appends_and_dedupes_by_source_key() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-1".to_string(),
        };

        let first = journal
            .record_successful_claim(&scope, &sample_input("src-1", "broker.resolve", "h1"))
            .unwrap();
        let duplicate = journal
            .record_successful_claim(&scope, &sample_input("src-1", "broker.resolve", "h1"))
            .unwrap();
        let second = journal
            .record_successful_claim(&scope, &sample_input("src-2", "broker.resolve", "h2"))
            .unwrap();

        match first {
            AppendDisposition::Appended { scope_seq, .. } => assert_eq!(scope_seq, 1),
            other => panic!("expected append, got {other:?}"),
        }
        match duplicate {
            AppendDisposition::Duplicate { scope_seq, .. } => assert_eq!(scope_seq, 1),
            other => panic!("expected duplicate, got {other:?}"),
        }
        match second {
            AppendDisposition::Appended {
                scope_seq,
                segment_no,
                ..
            } => {
                assert_eq!(scope_seq, 2);
                assert_eq!(segment_no, 0);
            }
            other => panic!("expected append, got {other:?}"),
        }

        let snapshot = journal.snapshot(&scope).unwrap();
        assert_eq!(snapshot.claim_count, 2);
        assert_eq!(snapshot.segment_count, 1);
        assert_eq!(snapshot.open_segment_claims, 2);

        let closed = journal
            .close_scope(
                &scope,
                CloseScopeOpts {
                    recent_claim_limit: 8,
                },
            )
            .unwrap();
        assert_eq!(closed.total_claims, 2);
        assert_eq!(closed.segments.len(), 1);
        assert_eq!(closed.recent_claims.len(), 2);
    }

    #[test]
    fn sqlite_claim_journal_rolls_over_segments() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 1);
        let scope = ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: "grant-1".to_string(),
        };

        journal
            .record_successful_claim(&scope, &sample_input("src-1", "vault.read", "h1"))
            .unwrap();
        let second = journal
            .record_successful_claim(&scope, &sample_input("src-2", "vault.read", "h2"))
            .unwrap();

        match second {
            AppendDisposition::Appended { segment_no, .. } => assert_eq!(segment_no, 1),
            other => panic!("expected append, got {other:?}"),
        }

        let snapshot = journal.snapshot(&scope).unwrap();
        assert_eq!(snapshot.segment_count, 2);
        assert_eq!(snapshot.open_segment_no, 1);
    }

    #[test]
    fn sqlite_claim_journal_round_trips_structured_action_ref_on_recent_claims() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-action-ref".to_string(),
        };
        let action_ref = ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1",
        );
        let mut input = sample_input("src-1", "broker.resolve", "h1");
        input.tool = action_ref.to_string();
        input.action_ref = Some(action_ref.clone());

        journal.record_successful_claim(&scope, &input).unwrap();
        let summary = journal
            .summarize_scope(
                &scope,
                CloseScopeOpts {
                    recent_claim_limit: 4,
                },
            )
            .unwrap();

        assert_eq!(summary.recent_claims.len(), 1);
        assert_eq!(summary.recent_claims[0].action_ref, Some(action_ref));
    }

    #[test]
    fn sqlite_claim_journal_parses_structured_tool_when_action_ref_absent() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-action-ref-backfill".to_string(),
        };
        let action_ref = ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_create",
            "v1",
        );
        let mut input = sample_input("src-parse", "broker.resolve", "h-parse");
        input.tool = action_ref.to_string();
        input.action_ref = None;

        journal.record_successful_claim(&scope, &input).unwrap();

        let row: (Option<String>, Option<String>, Option<String>, i64) = store
            .conn()
            .query_row(
                "SELECT action_plugin_address, action_key, action_version, legacy_flat
                   FROM claim_journal_claims
                  WHERE scope_kind = 'session' AND scope_id = 'session-action-ref-backfill'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                Some(action_ref.plugin_address.clone()),
                Some(action_ref.action_key.clone()),
                Some(action_ref.action_version.clone()),
                0,
            )
        );

        let summary = journal
            .summarize_scope(&scope, CloseScopeOpts::default())
            .unwrap();
        assert_eq!(summary.recent_claims[0].action_ref, Some(action_ref));
    }

    #[test]
    fn sqlite_claim_journal_tags_unparseable_flat_tool_as_legacy_flat() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-legacy-flat".to_string(),
        };
        let input = sample_input("src-flat", "broker.resolve", "h-flat");

        journal.record_successful_claim(&scope, &input).unwrap();

        let row: (Option<String>, Option<String>, Option<String>, i64) = store
            .conn()
            .query_row(
                "SELECT action_plugin_address, action_key, action_version, legacy_flat
                   FROM claim_journal_claims
                  WHERE scope_kind = 'session' AND scope_id = 'session-legacy-flat'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (None, None, None, 1));
    }

    #[test]
    fn sqlite_claim_journal_projects_one_claim_into_multiple_scopes_with_shared_audit_evidence() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let session_scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-multi".to_string(),
        };
        let grant_scope = ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: "grant-multi".to_string(),
        };

        let results = journal
            .record_successful_claim_for_scopes(
                &[session_scope.clone(), grant_scope.clone()],
                &sample_input("src-shared", "broker.resolve", "h-shared"),
            )
            .unwrap();

        assert_eq!(results.len(), 2);
        let audit_event_ids: Vec<i64> = results
            .iter()
            .map(|result| match result.disposition {
                AppendDisposition::Appended { audit_event_id, .. } => audit_event_id,
                ref other => panic!("expected append, got {other:?}"),
            })
            .collect();
        assert_eq!(audit_event_ids[0], audit_event_ids[1]);

        let audit_row_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'broker.resolve'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            audit_row_count, 1,
            "one shared audit row must back both scope projections"
        );

        let session_claim_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM claim_journal_claims WHERE scope_kind = 'session' AND scope_id = 'session-multi'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let grant_claim_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM claim_journal_claims WHERE scope_kind = 'grant' AND scope_id = 'grant-multi'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_claim_count, 1);
        assert_eq!(grant_claim_count, 1);
    }

    #[test]
    fn close_session_scope_best_effort_marks_scope_closed() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-close-test".to_string(),
        };

        journal
            .record_successful_claim(&scope, &sample_input("src-1", "broker.resolve", "h1"))
            .unwrap();

        let summary =
            close_session_scope_best_effort(&store, &scope.id, "claim_journal_test").unwrap();
        assert_eq!(summary.total_claims, 1);

        let status: String = store
            .conn()
            .query_row(
                "SELECT status
                   FROM claim_journal_scopes
                  WHERE scope_kind = 'session' AND scope_id = ?1",
                params![scope.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "closed");
    }

    #[test]
    fn close_grant_scope_best_effort_marks_scope_closed() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let scope = ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: "grant-close-test".to_string(),
        };

        journal
            .record_successful_claim(&scope, &sample_input("src-1", "broker.resolve", "h1"))
            .unwrap();

        let summary =
            close_grant_scope_best_effort(&store, &scope.id, "claim_journal_test").unwrap();
        assert_eq!(summary.total_claims, 1);

        let status: String = store
            .conn()
            .query_row(
                "SELECT status
                   FROM claim_journal_scopes
                  WHERE scope_kind = 'grant' AND scope_id = ?1",
                params![scope.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "closed");
    }

    // FLAKE (2026-05-27, observed under host-mode session-enrollment work,
    // pre-existing on origin/main): fails non-deterministically under full
    // `cargo test -p ember-daemon --lib` ordering with
    // `Backend("daemon quarantined; audit-log write for action 'broker.resolve' refused")`.
    // Passes in isolation. Cause: a sibling test trips the quarantine latch
    // and exits before clearing it. `reset_quarantine_latch()` at test top
    // is necessary but not sufficient — the latch is process-global and
    // some sibling re-arms it after this test reads it. Follow-up: replace
    // the global latch with a per-store / per-test-context one, or have
    // every test that touches the latch call `reset_quarantine_latch()` in
    // a `Drop` guard rather than only at entry.
    #[test]
    fn summarize_by_service_counts_structured_claims_and_excludes_legacy_rows() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let service_ref = ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_create",
            "v1",
        );

        let scope_a = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-service-a".to_string(),
        };
        let scope_b = ScopeRef {
            kind: ClaimScopeKind::Grant,
            id: "grant-service-b".to_string(),
        };

        let mut input_a = sample_input("src-a", "broker.resolve", "h1");
        input_a.persona_id = Some("persona-a".to_string());
        input_a.grant_id = Some("grant-a".to_string());
        input_a.tool = service_ref.to_string();
        input_a.action_ref = Some(service_ref.clone());
        input_a.runner_class = Some("local_trusted".to_string());
        journal.record_successful_claim(&scope_a, &input_a).unwrap();

        let mut input_b = sample_input("src-b", "broker.resolve", "h2");
        input_b.persona_id = Some("persona-b".to_string());
        input_b.grant_id = Some("grant-b".to_string());
        input_b.tool = service_ref.to_string();
        input_b.action_ref = Some(service_ref.clone());
        input_b.runner_class = Some("isolated_local".to_string());
        journal.record_successful_claim(&scope_b, &input_b).unwrap();

        let legacy_scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-legacy".to_string(),
        };
        journal
            .record_successful_claim(
                &legacy_scope,
                &sample_input("src-legacy", "broker.resolve", "h3"),
            )
            .unwrap();

        let summary = journal
            .summarize_by_service(
                &service_ref.plugin_address,
                (
                    DateTime::parse_from_rfc3339("2026-05-22T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    DateTime::parse_from_rfc3339("2026-05-23T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
            )
            .unwrap();

        assert_eq!(summary.total_claims, 2);
        assert_eq!(summary.unique_personas, 2);
        assert_eq!(summary.unique_grants, 2);
        assert_eq!(summary.spend_total_cents, None);
        assert_eq!(summary.by_outcome.get(&RollupOutcome::Success), Some(&2));
        assert_eq!(summary.by_runner_class.get("local_trusted"), Some(&1));
        assert_eq!(summary.by_runner_class.get("isolated_local"), Some(&1));
        assert_eq!(
            summary.last_claim_at.as_deref(),
            Some("2026-05-22T12:00:00Z")
        );
        assert_eq!(summary.merkle_segment_refs.len(), 2);
        assert!(
            summary
                .merkle_segment_refs
                .iter()
                .any(|r| r.starts_with("session:session-service-a:0:"))
        );
        assert!(
            summary
                .merkle_segment_refs
                .iter()
                .any(|r| r.starts_with("grant:grant-service-b:0:"))
        );
    }

    // FLAKE (2026-05-27, see summarize_by_service_counts_structured_claims_and_excludes_legacy_rows):
    // same global-latch contamination. Both tests share the same fragility —
    // fixing one will likely fix both.
    #[test]
    fn summarize_by_service_empty_window_returns_zeroed_rollup() {
        let _guard = claim_journal_test_guard();
        let store = test_store();
        let journal = SqliteClaimJournal::new(&store, 2);
        let service_ref = ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_create",
            "v1",
        );
        let scope = ScopeRef {
            kind: ClaimScopeKind::AuthorityLane,
            id: "session-out-of-window".to_string(),
        };

        let mut input = sample_input("src-out-of-window", "broker.resolve", "h4");
        input.tool = service_ref.to_string();
        input.action_ref = Some(service_ref.clone());
        journal.record_successful_claim(&scope, &input).unwrap();

        let summary = journal
            .summarize_by_service(
                &service_ref.plugin_address,
                (
                    DateTime::parse_from_rfc3339("2026-05-23T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    DateTime::parse_from_rfc3339("2026-05-24T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
            )
            .unwrap();

        assert_eq!(summary.total_claims, 0);
        assert_eq!(summary.unique_personas, 0);
        assert_eq!(summary.unique_grants, 0);
        assert_eq!(summary.spend_total_cents, None);
        assert!(summary.by_outcome.is_empty());
        assert!(summary.by_runner_class.is_empty());
        assert_eq!(summary.last_claim_at, None);
        assert!(summary.merkle_segment_refs.is_empty());
    }

    #[test]
    fn summarize_by_service_query_plan_uses_plugin_time_index() {
        let store = test_store();
        SqliteClaimJournal::ensure_claim_journal_adr186_columns(store.conn()).unwrap();
        let mut stmt = store
            .conn()
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT COUNT(*)
                   FROM claim_journal_claims
                  WHERE action_plugin_address = ?1
                    AND ts >= ?2
                    AND ts <= ?3
                    AND action_key IS NOT NULL
                    AND action_version IS NOT NULL
                    AND COALESCE(legacy_flat, 0) = 0",
            )
            .unwrap();
        let plan = stmt
            .query_map(
                params![
                    "registry.ember.systems/ember-systems/ember-gh",
                    "2026-05-22T00:00:00Z",
                    "2026-05-23T00:00:00Z"
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(
            plan.contains("idx_claim_journal_claims_plugin_time"),
            "expected service rollup plan to use plugin_time index, got:\n{plan}"
        );
    }
}
