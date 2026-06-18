use std::path::Path;

use chrono::{TimeZone, Utc};
use rusqlite::params;
use rusqlite::types::Value as SqlValue;
use serde::{Deserialize, Serialize};

use crate::infra::store::{DaemonStore, StoreError};

/// Convert unix-ms to an RFC3339 string so
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
    pub id: Option<i64>,
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<usize>,
    /// Filter to actions that start with this prefix,
    /// e.g. `"grant."` shows only grant-family events. Rendering-layer only;
    /// applied after the SQL fetch so the limit still governs the fetch window.
    pub action_prefix: Option<String>,
    /// Alias for `agent_id`. Both populate
    /// the `agent_id = ?` clause; if both are set, `persona_id` wins.
    pub persona_id: Option<String>,
    /// Narrow to rows whose `credential`
    /// column starts with this prefix. SQL `LIKE` with appended `%`.
    pub scope: Option<String>,
    /// Inclusive lower bound (unix ms).
    /// Converted to RFC3339 before binding so it compares against the
    /// existing TEXT timestamp column.
    pub since_ms: Option<i64>,
    /// Inclusive upper bound (unix ms).
    pub before_ms: Option<i64>,
}

impl DaemonStore {
    /// Append an audit event to `audit_log`.
    ///
    /// # Audit-chain semantics
    ///
    /// Every audit write — including ones that historically used the
    /// NULL-hash legacy path — is now routed through the tamper-evident
    /// chain (`append_audit_event_with_chain` / `_in_tx`). The old
    /// behaviour (raw INSERT with NULL `row_hash` and `prev_hash`) is gone:
    /// it produced "pre-chain history" rows that the verifier ignored, and
    /// it polluted the next chained write's `prev_hash` lookup whenever a
    /// log_event row was the most recent in the table. That polluted
    /// lookup was the root cause of the 2026-05-19/20 quarantine cascade
    /// (rows 291 + 293, both `grant.revoked`, both inserted right after a
    /// `log_event` row and both ending up with NULL `prev_hash` despite
    /// valid `row_hash`).
    ///
    /// The structural fix per `[[feedback_root_cause_over_patch]]`: do the
    /// hard thing — every audit write joins the chain. NULL-hash rows
    /// become a migration artifact in existing DBs; new DBs never see one.
    /// Anchor: `audit_log_routes_through_chained_writer`.
    ///
    /// # Transaction context
    ///
    /// The two chained writers differ in whether they manage their own
    /// `BEGIN IMMEDIATE`:
    ///
    /// - `append_audit_event_with_chain` (free fn) opens its own write
    ///   transaction. Use when the caller is in SQLite autocommit mode.
    /// - `append_audit_event_with_chain_in_tx` (in-tx variant) assumes the
    ///   caller already holds a write lock. Use from inside
    ///   `revoke_grant_sql`-style envelopes that wrap several writes in one
    ///   transaction.
    ///
    /// `log_event` picks the right one by probing `conn.is_autocommit()`.
    /// Nesting `BEGIN IMMEDIATE` inside an open transaction would otherwise
    /// fail with "cannot start a transaction within a transaction"; calling
    /// the in-tx variant outside a transaction would race the prev_hash
    /// lookup against another writer. The probe keeps the API ergonomic
    /// while preserving the atomicity contract.
    ///
    /// # Quarantine
    ///
    /// Both downstream writers gate on
    /// `crate::infra::handler::is_quarantined()` and return
    /// `StoreError::Quarantined`. No separate gate is needed here.
    pub fn log_event(
        &self,
        agent_id: Option<&str>,
        action: &str,
        credential: Option<&str>,
        outcome: &str,
        details: Option<&str>,
    ) -> Result<i64, StoreError> {
        if self.conn().is_autocommit() {
            append_audit_event_with_chain(self, agent_id, action, credential, outcome, details)
        } else {
            append_audit_event_with_chain_in_tx(
                self.conn(),
                agent_id,
                action,
                credential,
                outcome,
                details,
            )
        }
    }

    pub fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, StoreError> {
        // Dynamic positional binding so we
        // can compose any combination of {agent_id, action, persona_id, scope,
        // since_ms, before_ms} without the previous hand-numbered ladder.
        // Audit-chain: filter out the chain-anchor checkpoint row.
        // It's an internal artifact of the tamper-evident chain (see
        // migrate() in store.rs); not a user-visible audit event. The
        // chain verifier (subtask C) reads the table directly and DOES see
        // the genesis row.
        let mut query = String::from(
            "SELECT id, timestamp, agent_id, action, credential, outcome, details
             FROM audit_log WHERE action != 'audit.chain_v1_genesis'",
        );

        let mut binds: Vec<SqlValue> = Vec::new();

        if let Some(id) = filter.id {
            binds.push(SqlValue::Integer(id));
            query.push_str(&format!(" AND id = ?{}", binds.len()));
        }

        // persona_id and agent_id both target the agent_id column; persona_id wins.
        let agent_filter = filter.persona_id.as_deref().or(filter.agent_id.as_deref());
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

        // Action_prefix filter applied post-fetch so
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

    /// Test helper to insert an audit row
    /// with an explicit timestamp string (so date-range tests can pin
    /// timestamps without sleeping).
    ///
    /// Inserts at `segment_id = 0` (the cordoned-legacy / pre-chain segment
    /// where NULL hashes are admitted by the CHECK constraint). Test helper
    /// rows are not chained.
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
            "INSERT INTO audit_log (timestamp, agent_id, action, credential, outcome, details, segment_id)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0)",
            params![timestamp, agent_id, action, credential, outcome],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    pub fn audit_count(&self) -> Result<u64, StoreError> {
        // Same internal-checkpoint exclusion as
        // query_audit so the user-facing count matches what query_audit
        // returns.
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action != 'audit.chain_v1_genesis'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Force-rotate the active audit-chain segment to free SQLite
    /// page space when the audit-store is full.
    ///
    /// Rotation inserts a `audit.forced_rotation` bridge row as the genesis of
    /// a new segment. The new segment's `prev_hash` chains from the most recent
    /// chained row in the current segment, preserving chain continuity. Rows in
    /// prior segments are **not deleted** — the operator must separately archive
    /// or vacuum old data from `~/.ember/audit/archive/` when disk is truly full.
    ///
    /// # Invariants preserved
    ///
    /// - Chain continuity: the bridge row's `prev_hash` == the last chained
    ///   row's `row_hash` in `MAX(segment_id)`.
    /// - No Receipts dropped: prior rows are retained (moved to a closed
    ///   segment, but still in the SQLite file).
    /// - Quarantine gate: if the daemon is quarantined, the rotation is refused
    ///   (same gate as `append_audit_event_with_chain`).
    ///
    /// # Returns
    ///
    /// `Ok(ForcedRotationOutcome)` on success, with the new segment id and the
    /// bridge row id so the caller can emit a receipt.
    ///
    /// # target_state_anchor
    ///
    /// `recover_f_audit_1_landed`
    pub fn force_rotate_audit_segment(&self) -> Result<ForcedRotationOutcome, StoreError> {
        // Quarantine gate — refuse while the chain is known-broken.
        if crate::infra::handler::is_quarantined() {
            tracing::warn!("daemon quarantined; refusing forced audit-chain rotation (F-AUDIT-1)");
            return Err(StoreError::Quarantined {
                action: "audit.forced_rotation".to_string(),
            });
        }

        let conn = self.conn();
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result = (|| -> Result<ForcedRotationOutcome, StoreError> {
            // Read the current max segment_id.
            let current_max_segment_id: u64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(segment_id), 0) FROM audit_log",
                    [],
                    |row| row.get::<_, i64>(0).map(|v| v as u64),
                )
                .unwrap_or(0);
            let new_segment_id = current_max_segment_id + 1;

            // Find the last chained row in the current segment to seed prev_hash.
            let prev_hash: Option<String> = conn
                .query_row(
                    "SELECT row_hash FROM audit_log \
                     WHERE row_hash IS NOT NULL AND segment_id = ?1 \
                     ORDER BY id DESC LIMIT 1",
                    rusqlite::params![current_max_segment_id as i64],
                    |row| row.get(0),
                )
                .ok()
                .flatten();

            let bridge_action = "audit.forced_rotation";
            let bridge_outcome = "ok";
            let bridge_timestamp = chrono::Utc::now().to_rfc3339();

            let canonical = canonical_audit_row_bytes(
                &bridge_timestamp,
                None,
                bridge_action,
                None,
                bridge_outcome,
                None,
            );
            let mut hasher = blake3::Hasher::new();
            if let Some(ref p) = prev_hash {
                hasher.update(p.as_bytes());
            }
            hasher.update(&canonical);
            let bridge_row_hash = hasher.finalize().to_hex().to_string();

            conn.execute(
                "INSERT INTO audit_log \
                 (timestamp, agent_id, action, credential, outcome, details, \
                  prev_hash, row_hash, segment_id, is_segment_genesis) \
                 VALUES (?1, NULL, ?2, NULL, ?3, NULL, ?4, ?5, ?6, 1)",
                rusqlite::params![
                    bridge_timestamp,
                    bridge_action,
                    bridge_outcome,
                    prev_hash,
                    bridge_row_hash,
                    new_segment_id as i64,
                ],
            )?;
            let bridge_row_id = conn.last_insert_rowid();

            Ok(ForcedRotationOutcome {
                new_segment_id,
                bridge_row_id,
                bridge_row_hash,
                prev_segment_id: current_max_segment_id,
            })
        })();

        match result {
            Ok(outcome) => {
                conn.execute("COMMIT", [])?;
                Ok(outcome)
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }
}

/// Outcome of a successful [`DaemonStore::force_rotate_audit_segment`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedRotationOutcome {
    /// The newly allocated segment ID.
    pub new_segment_id: u64,
    /// Row ID of the bridge row inserted as the genesis of the new segment.
    pub bridge_row_id: i64,
    /// `row_hash` of the bridge row (chain-tip for the new segment).
    pub bridge_row_hash: String,
    /// The segment ID that was active before rotation.
    pub prev_segment_id: u64,
}

// ---------------------------------------------------------------------------
// tamper-evident audit chain
// ---------------------------------------------------------------------------

/// Append an audit event to `audit_log` with a blake3 chain hash linking it
/// to the prior row. Writes inside `BEGIN IMMEDIATE` so two concurrent
/// writers can never race on the same `prev_hash`. The chain anchors at
/// the `audit.chain_v1_genesis` checkpoint row inserted by `migrate()`.
///
/// The hash input is `blake3(prev_hash || canonical_row_bytes)` where the
/// canonical body is a sorted-key JSON serialization of the row's logical
/// fields (timestamp, agent_id, action, credential, outcome, details). The
/// verifier (subtask C) recomputes this exact byte sequence from the stored
/// row contents and asserts it matches `row_hash`.
///
/// Use this instead of `log_event` for all NEW write paths — `log_event`
/// is retained for legacy callers and emits NULL hashes (treated as
/// pre-chain history by the verifier).
///
/// # target_state_anchor
///
/// `fn append_audit_event_with_chain`
pub fn append_audit_event_with_chain(
    store: &DaemonStore,
    agent_id: Option<&str>,
    action: &str,
    credential: Option<&str>,
    outcome: &str,
    details: Option<&str>,
) -> Result<i64, StoreError> {
    // quarantine_serve_mode_audit_writes_refused — gate the chained writer
    // BEFORE BEGIN IMMEDIATE so the daemon doesn't spuriously serialize
    // callers behind a write-lock that will immediately roll back. The
    // `_in_tx` variant has its own gate inside the lock for callers that
    // already hold one. Per ADR 174 v2 §1 + adversarial review CRIT-1.
    if crate::infra::handler::is_quarantined() {
        tracing::warn!(
            action,
            outcome,
            "daemon quarantined; refusing audit-chain extension"
        );
        return Err(StoreError::Quarantined {
            action: action.to_string(),
        });
    }
    let conn = store.conn();
    conn.execute("BEGIN IMMEDIATE", [])?;
    let result =
        append_audit_event_with_chain_in_tx(conn, agent_id, action, credential, outcome, details);
    match result {
        Ok(id) => {
            conn.execute("COMMIT", [])?;
            Ok(id)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// In-transaction variant of [`append_audit_event_with_chain`] for callers
/// that already hold a `BEGIN IMMEDIATE` write lock (e.g.
/// `revoke_grant_sql`'s atomic revoke+audit+receipt envelope). Skips the
/// outer transaction management; the caller is responsible for `COMMIT` /
/// `ROLLBACK`.
pub(crate) fn append_audit_event_with_chain_in_tx(
    conn: &rusqlite::Connection,
    agent_id: Option<&str>,
    action: &str,
    credential: Option<&str>,
    outcome: &str,
    details: Option<&str>,
) -> Result<i64, StoreError> {
    // quarantine_serve_mode_audit_writes_refused — also gate the in-tx path
    // so callers that already hold a write-lock (e.g. `resolve_approval` →
    // `dashboard.rs` POST handlers, `revoke_grant_sql`) cannot extend the
    // chain over a known-broken tail. The caller's surrounding transaction
    // will see `Err(Quarantined)` and roll back. Per ADR 174 v2 §1 +
    // adversarial review CRIT-1 (the dashboard write-path was the primary
    // bypass the v1 gate missed).
    if crate::infra::handler::is_quarantined() {
        tracing::warn!(
            action,
            outcome,
            "daemon quarantined; refusing audit-chain extension (in-tx)"
        );
        return Err(StoreError::Quarantined {
            action: action.to_string(),
        });
    }
    let started = std::time::Instant::now();

    // audit_writer_prevhash_seed_segment_scoped — the writer always extends
    // the latest segment. `MAX(segment_id)` is the operational segment; on a
    // fresh DB it's 0 (epoch-zero / pre-cordon), post-cordon it advances to
    // 1 (operator's host bridge) and incrementally past each repair tombstone.
    let current_segment_id: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(segment_id), 0) FROM audit_log",
            [],
            |row| row.get::<_, i64>(0).map(|v| v as u64),
        )
        .unwrap_or(0);

    // audit_writer_prevhash_seed_segment_scoped — seed the chain from the
    // latest CHAINED row in the current segment, skipping NULL-hash legacy
    // rows. This is THE bug-2 root-cause fix: under the old seed
    // (`ORDER BY id DESC LIMIT 1`), the latest row could be a NULL-hash
    // legacy log_event, producing `prev_hash = NULL`. The verifier expects
    // `prev_hash` to equal the prior CHAINED row's `row_hash` and surfaces a
    // ForwardLinkMismatch quarantine. Per locked decision #3 + migration D6.
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT row_hash FROM audit_log \
             WHERE row_hash IS NOT NULL AND segment_id = ?1 \
             ORDER BY id DESC LIMIT 1",
            rusqlite::params![current_segment_id as i64],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    let timestamp = Utc::now().to_rfc3339();
    let canonical =
        canonical_audit_row_bytes(&timestamp, agent_id, action, credential, outcome, details);

    let mut hasher = blake3::Hasher::new();
    if let Some(ref p) = prev_hash {
        hasher.update(p.as_bytes());
    }
    hasher.update(&canonical);
    let row_hash = hasher.finalize().to_hex().to_string();

    // Writer EXPLICITLY names `segment_id` in the INSERT (per pass-2 finding
    // #4 fix): segment_id is NOT NULL with no DEFAULT, so an older binary
    // that doesn't know about the column will fail loudly instead of
    // silently corrupting topology via DEFAULT 0. `is_segment_genesis` keeps
    // its DEFAULT 0 — chain extensions are never segment-genesis rows; the
    // only `is_segment_genesis = 1` rows are the chain-v1 genesis (migrate)
    // and the cordon bridge / repair tombstones.
    conn.execute(
        "INSERT INTO audit_log \
         (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            timestamp,
            agent_id,
            action,
            credential,
            outcome,
            details,
            prev_hash,
            row_hash,
            current_segment_id as i64,
        ],
    )?;
    let row_id = conn.last_insert_rowid();
    crate::telemetry::measurement::record_audit_write_batch(1, started.elapsed());
    Ok(row_id)
}

/// JCS-style canonical serialization of an audit row's logical fields. Keys
/// are sorted alphabetically; `null` is the absence checkpoint for
/// `Option<&str>` fields. The verifier (subtask C) reconstructs this exact
/// byte sequence from the stored row to recompute the row hash.
///
/// `pub(crate)` so the cordon-migration path in `store.rs` can canonicalize
/// the bridge row's body with the same byte sequence the verifier will
/// reconstruct when walking the chain post-migration.
pub(crate) fn canonical_audit_row_bytes_pub(
    timestamp: &str,
    agent_id: Option<&str>,
    action: &str,
    credential: Option<&str>,
    outcome: &str,
    details: Option<&str>,
) -> Vec<u8> {
    canonical_audit_row_bytes(timestamp, agent_id, action, credential, outcome, details)
}

fn canonical_audit_row_bytes(
    timestamp: &str,
    agent_id: Option<&str>,
    action: &str,
    credential: Option<&str>,
    outcome: &str,
    details: Option<&str>,
) -> Vec<u8> {
    use std::collections::BTreeMap;
    let opt = |v: Option<&str>| {
        v.map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null)
    };
    let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    map.insert("action", serde_json::Value::String(action.to_string()));
    map.insert("agent_id", opt(agent_id));
    map.insert("credential", opt(credential));
    map.insert("details", opt(details));
    map.insert("outcome", serde_json::Value::String(outcome.to_string()));
    map.insert(
        "timestamp",
        serde_json::Value::String(timestamp.to_string()),
    );
    serde_json::to_vec(&map).expect("BTreeMap<&str, Value> serialization is infallible")
}

// ---------------------------------------------------------------------------
// chain verifier
// ---------------------------------------------------------------------------

/// audit_verifier_outcome_v2 — outcome of a chain-verification walk.
///
/// Extended from the original 2-variant enum per ADR 174 v2 + autogrill
/// 20260521-134520 (DIGEST + adversarial-2 R3/R7). New variants distinguish
/// migration-artifact rows from real breaks, surface topology-invariant
/// violations distinct from chain breaks, and split the daemon-crashed-mid-
/// repair recovery surface into two symmetric variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every row in the walked range recomputes to its stored `row_hash`
    /// and links to the prior row via `prev_hash == prior.row_hash`. The
    /// `segments_walked` field counts how many distinct segment_id values
    /// the walker saw; `sample_mode` records which cadence the walker ran.
    Ok {
        rows_walked: u64,
        segments_walked: u32,
        sample_mode: SampleMode,
    },
    /// A row's chain invariant failed. The `kind` bifurcates the failure
    /// shape so the diagnostic surface can name "row_hash recomputed
    /// differently" vs "prev_hash didn't link to predecessor's row_hash"
    /// without text parsing.
    Break { kind: BreakKind },
    /// Pre-chain NULL-hash legacy rows are present in the DB. This is the
    /// post-cordon expected steady state on the operator's host (290 such
    /// rows in segment 0). NOT a quarantine condition — operator runs
    /// `ember audit migrate-chain --acknowledge` to mint the Phase 2
    /// attested receipt. Per autogrill verifier D2 + locked decision #13.
    LegacyRowsPresent {
        count: u64,
        max_legacy_id: i64,
        chain_resumes_at_id: i64,
    },
    /// A segment-topology invariant was violated (e.g. multiple segment-
    /// genesis rows for the same segment, post-migration NULL row_hash in
    /// segment > 0, non-monotonic segment_id). Quarantines under a distinct
    /// authority from `Break` so the repair flow can branch on the cause.
    ChainTopologyInvariantViolation {
        kind: TopologyViolation,
        at_row_id: i64,
        rows_walked_before: u64,
    },
    /// Daemon crashed mid-repair: the repair receipt was minted but the
    /// tombstone row never committed. Per ADR 174 v2 §6.
    IncompleteRepair { receipt_id_orphan: String },
    /// Symmetric to `IncompleteRepair`: the tombstone row committed but
    /// the repair receipt never minted. Recovered via the
    /// `ember audit chain-repair-finalize` CLI verb. Per locked decision
    /// #11 + repair D6.
    IncompleteRepairReceipt { tombstone_row_id: i64 },
}

/// audit_verifier_outcome_v2 — bifurcated break shape. Each variant is the
/// SAME quarantine class on dev0 (any break quarantines), but the
/// diagnostic + remediation surface differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// `blake3(prev_hash || canonical_row_bytes)` recomputed != stored
    /// `row_hash`. Classic in-row tamper.
    RowHashMismatch {
        at_row_id: i64,
        expected_hash: String,
        stored_hash: String,
        rows_walked_before: u64,
    },
    /// `prev_hash` did not equal the prior chained row's `row_hash`.
    /// Carries `predecessor_row_id` distinct from `at_row_id` (per R7 /
    /// pass-2 finding #7): `at_row_id` is the row whose `prev_hash`
    /// mismatched; `predecessor_row_id` is the prior chained row whose
    /// `row_hash` should have been the seed.
    ForwardLinkMismatch {
        at_row_id: i64,
        predecessor_row_id: i64,
        expected_prev_hash: String,
        stored_prev_hash: Option<String>,
        rows_walked_before: u64,
    },
}

/// audit_verifier_outcome_v2 — topology-invariant categories surfaced via
/// `ChainTopologyInvariantViolation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyViolation {
    /// More than one row in a single segment carries `is_segment_genesis =
    /// 1`. The partial unique index structurally prevents this at INSERT
    /// time, but a raw-SQL writer that bypassed the index (or a partial
    /// migration) can produce it.
    MultipleGenesis,
    /// A row in `segment_id > 0` carries `row_hash IS NULL`. Post-
    /// migration, only the original chain-v1 genesis + the cordoned legacy
    /// block (segment 0) are allowed to have NULL hashes; any further
    /// segment's rows must be fully chained. Caught by the CHECK
    /// constraint structurally, but the verifier surfaces it explicitly
    /// for diagnostic clarity if the constraint was bypassed.
    PostMigrationNullRowHash,
    /// Row id-order does not match segment_id non-decreasing order
    /// (e.g. an older binary wrote a `segment_id = 0` row AFTER a
    /// segment-1 row already existed). Surfaces the downgrade-write
    /// failure mode from pass-2 finding #4.
    SegmentIdNonMonotonic,
}

/// audit_verifier_outcome_v2 — how the verifier sampled the chain on the
/// current call. Surfaces in `Ok` so operators can see whether full-walk
/// or sampling fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleMode {
    /// Walked every row in `audit_log`. The dev0 default when N < 100k
    /// per ADR 174 v2 §6 (locked decision #17).
    FullWalk,
    /// Walked the last N rows. Used for tail-1000 cadence past the
    /// full-walk threshold.
    Tail { n: u32 },
    /// Walked one row per segment_id boundary only.
    PerSegmentGenesis,
}

/// audit_verifier_outcome_v2 — inter-segment seed query helper (R3 /
/// pass-2 finding #5). Returns the most-recent chained row's `row_hash`
/// strictly across PRIOR segments (i.e. `segment_id < ?1`), skipping NULL
/// rows.
///
/// Locked SQL (R3): `SELECT row_hash FROM audit_log WHERE segment_id <
/// ?1 AND row_hash IS NOT NULL ORDER BY id DESC LIMIT 1`.
///
/// Called when the walker crosses a segment-genesis boundary: a segment-1
/// bridge row's `prev_hash` chains to the v1 genesis row's `row_hash`
/// (the only chained row in segment 0 on the operator's host).
pub(crate) fn inter_segment_seed_row_hash(
    conn: &rusqlite::Connection,
    segment_id: u64,
) -> Result<Option<String>, rusqlite::Error> {
    let seed: Option<String> = conn
        .query_row(
            "SELECT row_hash FROM audit_log \
             WHERE segment_id < ?1 AND row_hash IS NOT NULL \
             ORDER BY id DESC LIMIT 1",
            rusqlite::params![segment_id as i64],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    Ok(seed)
}

/// Walk the audit chain forward from the genesis row, recomputing each
/// row's `blake3(prev_hash || canonical_row_bytes)` and asserting it
/// matches the stored `row_hash`. Pre-chain rows (NULL `row_hash`,
/// inserted before the audit-chain migration landed) are
/// skipped — the verifier walks only chained rows.
///
/// `tail` limits the walk to the most recent N rows (for sampling startup
/// verify, default 1000). `None` walks the full chain.
///
/// Returns `VerifyOutcome::Ok { rows_walked }` if the chain holds, or
/// `VerifyOutcome::Break { at_row_id, … }` at the first break.
///
/// The verifier reads the table directly (it bypasses the genesis-filter
/// in `query_audit` / `audit_count` because the chain anchor row is
/// load-bearing for the walk).
///
/// `data_dir` (when `Some`) points the verifier at `receipts.log` so it can
/// detect the `IncompleteRepair{Receipt}` crash-windows the repair primitive
/// (`truncate_after_row`) can produce — a tombstone row without its
/// `audit.chain_repair_finalize` receipt, or that receipt without its
/// tombstone. `None` (in-memory stores, tests) skips that pass.
///
/// # target_state_anchor
///
/// `fn run_audit_verify` / `incomplete_repair_detector_landed`
pub fn run_audit_verify(
    conn: &rusqlite::Connection,
    tail: Option<usize>,
    data_dir: Option<&Path>,
) -> Result<VerifyOutcome, StoreError> {
    let sample_mode = match tail {
        None => SampleMode::FullWalk,
        Some(n) => SampleMode::Tail { n: n as u32 },
    };
    // Collect (id, prev_hash, row_hash, segment_id, raw fields) in chronological
    // order. For sampling-mode we want the LAST N rows, so we ORDER BY id DESC
    // LIMIT N then reverse for forward iteration.
    let order_clause = match tail {
        Some(n) => format!("ORDER BY id DESC LIMIT {}", n),
        None => "ORDER BY id ASC".to_string(),
    };
    let sql = format!(
        "SELECT id, timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis \
         FROM audit_log {}",
        order_clause
    );
    let mut stmt = conn.prepare(&sql)?;

    type Row = (
        i64,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64, // segment_id
        i64, // is_segment_genesis (SQLite stores INTEGER for bool)
    );

    let mut rows: Vec<Row> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if tail.is_some() {
        rows.reverse(); // restore chronological order after DESC fetch
    }

    // audit_verifier_outcome_v2 — sampling-mode seed. When `tail` limits the
    // walk to the last N rows, the cross-row chain check on the first row of
    // the window has no in-walk predecessor; without seeding, every tail
    // walk would false-positive a Break. Seed from the immediate prior
    // CHAINED row in the same segment (or, if the window starts at a
    // segment-genesis boundary, use the inter-segment seed query — R3).
    let mut prior_row_hash: Option<String> = None;
    let mut last_predecessor_id: i64 = 0;
    let mut current_segment: Option<u64> = None;
    if let Some(first) = rows.first() {
        let first_id = first.0;
        let first_segment = first.9 as u64;
        // Look for the prior chained row in the SAME segment with id <
        // first_id. If none, fall back to the inter-segment seed (a
        // segment-genesis boundary case).
        let seed: Option<String> = conn
            .query_row(
                "SELECT row_hash FROM audit_log \
                 WHERE id < ?1 AND segment_id = ?2 AND row_hash IS NOT NULL \
                 ORDER BY id DESC LIMIT 1",
                rusqlite::params![first_id, first_segment as i64],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        prior_row_hash = match seed {
            Some(h) => Some(h),
            None => inter_segment_seed_row_hash(conn, first_segment)
                .ok()
                .flatten(),
        };
        if prior_row_hash.is_some() {
            // Walker has an in-DB predecessor whose id we don't track here;
            // ForwardLinkMismatch reporting falls back to id=0 in that
            // case — acceptable because sampling-mode seeds rarely fire.
            last_predecessor_id = 0;
        }
    }

    let mut walked: u64 = 0;
    let mut segments_walked: u32 = 0;
    let mut legacy_count: u64 = 0;
    let mut max_legacy_id: i64 = 0;
    let mut chain_resumes_at_id: i64 = 0;

    for (
        id,
        timestamp,
        agent_id,
        action,
        credential,
        outcome,
        details,
        prev_hash,
        row_hash,
        segment_id_raw,
        is_segment_genesis_raw,
    ) in rows
    {
        let row_segment = segment_id_raw as u64;
        let is_segment_genesis = is_segment_genesis_raw != 0;

        // Track segment crossings.
        match current_segment {
            None => {
                current_segment = Some(row_segment);
                segments_walked = 1;
            }
            Some(prev) if prev != row_segment => {
                // Segment boundary: re-seed from the inter-segment query.
                if let Ok(Some(new_seed)) = inter_segment_seed_row_hash(conn, row_segment) {
                    prior_row_hash = Some(new_seed);
                } else {
                    prior_row_hash = None;
                }
                current_segment = Some(row_segment);
                segments_walked += 1;
            }
            Some(_) => {}
        }

        // Pre-chain / legacy rows have NULL row_hash. Segment 0's NULL block
        // is the cordoned-legacy artifact (locked decision #19): walk-skipped
        // but COUNTED toward `LegacyRowsPresent`. A NULL row_hash in segment
        // > 0 is a topology violation (the CHECK constraint structurally
        // forbids it, but the verifier surfaces it explicitly).
        let stored_hash = match row_hash {
            Some(h) => h,
            None => {
                if row_segment == 0 && action != "audit.chain_v1_genesis" {
                    legacy_count += 1;
                    if id > max_legacy_id {
                        max_legacy_id = id;
                    }
                    continue;
                }
                if row_segment > 0 {
                    return Ok(VerifyOutcome::ChainTopologyInvariantViolation {
                        kind: TopologyViolation::PostMigrationNullRowHash,
                        at_row_id: id,
                        rows_walked_before: walked,
                    });
                }
                continue;
            }
        };

        // The chain forward starts at the genesis row. For the genesis row,
        // `prev_hash` is NULL by contract. For segment-genesis rows (bridge,
        // repair tombstones), `prev_hash` must equal the inter-segment seed
        // (the prior segment's last chained row's row_hash). For all other
        // rows, `prev_hash` must equal the prior chained row's `row_hash`.
        let is_chain_v1_genesis = action == "audit.chain_v1_genesis";
        if !is_chain_v1_genesis {
            let expected_prev = prior_row_hash.as_deref();
            let actual_prev = prev_hash.as_deref();
            if expected_prev != actual_prev {
                return Ok(VerifyOutcome::Break {
                    kind: BreakKind::ForwardLinkMismatch {
                        at_row_id: id,
                        predecessor_row_id: last_predecessor_id,
                        expected_prev_hash: expected_prev.unwrap_or("NULL").to_string(),
                        stored_prev_hash: actual_prev.map(str::to_string),
                        rows_walked_before: walked,
                    },
                });
            }
        }

        // Track first-non-null id past the legacy block (R-revisions).
        if legacy_count > 0 && chain_resumes_at_id == 0 && !is_chain_v1_genesis {
            chain_resumes_at_id = id;
        }

        // For the genesis row, the canonical body is "audit.chain_v1_genesis"
        // (the literal bytes used by `migrate()` to seed the anchor).
        // For all other rows, recompute blake3(prev_hash || canonical_body).
        let recomputed = if is_chain_v1_genesis {
            blake3::hash(b"audit.chain_v1_genesis").to_hex().to_string()
        } else {
            let canonical = canonical_audit_row_bytes(
                &timestamp,
                agent_id.as_deref(),
                &action,
                credential.as_deref(),
                &outcome,
                details.as_deref(),
            );
            let mut h = blake3::Hasher::new();
            if let Some(ref p) = prev_hash {
                h.update(p.as_bytes());
            }
            h.update(&canonical);
            h.finalize().to_hex().to_string()
        };

        if recomputed != stored_hash {
            return Ok(VerifyOutcome::Break {
                kind: BreakKind::RowHashMismatch {
                    at_row_id: id,
                    expected_hash: recomputed,
                    stored_hash,
                    rows_walked_before: walked,
                },
            });
        }

        // Mark `_` to acknowledge `is_segment_genesis` is read but its only
        // structural use is the partial unique index at the schema layer
        // (R6) — the walker doesn't need to gate on it once the chain
        // arithmetic passes.
        let _ = is_segment_genesis;
        prior_row_hash = Some(stored_hash);
        last_predecessor_id = id;
        walked += 1;
    }

    // incomplete_repair_detector_landed — the chain walked cleanly, but a
    // repair (truncate_after_row) crash-window can still leave the two-store
    // invariant half-fulfilled: the `audit.chain_repair_finalize` receipt is
    // appended to receipts.log INSIDE the repair's BEGIN IMMEDIATE but a
    // crash before COMMIT leaves a receipt-orphan (tombstone never committed),
    // and the symmetric tombstone-without-receipt is recovered via
    // chain-repair-finalize. These targeted queries are independent of the
    // walk's tail sampling. Gated on `data_dir` (the receipts.log location).
    if let Some(data_dir) = data_dir
        && let Some(outcome) = detect_incomplete_repair(conn, data_dir)?
    {
        return Ok(outcome);
    }

    // If the chain walked cleanly and there's a legacy block, surface it as
    // a distinct outcome so the operator knows Phase 2 attestation is still
    // pending (per locked decision #13 + verifier D2).
    if legacy_count > 0 {
        return Ok(VerifyOutcome::LegacyRowsPresent {
            count: legacy_count,
            max_legacy_id,
            chain_resumes_at_id,
        });
    }

    Ok(VerifyOutcome::Ok {
        rows_walked: walked,
        segments_walked,
        sample_mode,
    })
}

/// incomplete_repair_detector_landed — a finalize receipt's repair-binding
/// fields, projected from `receipts.log`. `repair_id` links to the tombstone
/// row's `details.repair_id`; `tombstone_row_id` is the receipt's claim about
/// which `audit_log` row the repair tombstoned.
struct FinalizeReceiptRef {
    receipt_id: String,
    repair_id: String,
    tombstone_row_id: i64,
}

/// incomplete_repair_detector_landed — read every `audit.chain_repair_finalize`
/// receipt from the `receipts.log` journal file. Missing file → empty vec.
/// Corrupt / non-finalize lines are skipped so a single bad line never
/// blocks the verifier.
fn read_repair_finalize_receipts(data_dir: &Path) -> Result<Vec<FinalizeReceiptRef>, StoreError> {
    use core_events::receipt::{
        AuditChainRepairFinalizeBody, RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE, ReceiptEnvelope,
    };
    let path = data_dir.join("receipts.log");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(StoreError::InvalidInput(format!(
                "incomplete_repair_detector_landed: read receipts.log: {e}"
            )));
        }
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(env) = serde_json::from_str::<ReceiptEnvelope>(line) else {
            continue;
        };
        if env.kind != RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE {
            continue;
        }
        let Ok(body) = serde_json::from_value::<AuditChainRepairFinalizeBody>(env.body.clone())
        else {
            continue;
        };
        out.push(FinalizeReceiptRef {
            receipt_id: env.receipt_id,
            repair_id: body.repair_id,
            tombstone_row_id: body.tombstone_row_id,
        });
    }
    Ok(out)
}

/// incomplete_repair_detector_landed — produce `VerifyOutcome::IncompleteRepair`
/// / `IncompleteRepairReceipt` when the `audit_log` repair tombstones and the
/// `receipts.log` finalize receipts disagree. Returns `None` when they are
/// consistent (or there are no repairs). Two passes over the SHIPPED repair
/// shapes (linkage is `repair_id` in the tombstone `details` + the receipt
/// body, and `tombstone_row_id` in the receipt body — NOT a `details.receipt_id`
/// as the pre-#4435 brief assumed):
///
///   1. tombstone-without-receipt → `IncompleteRepairReceipt { tombstone_row_id }`
///   2. receipt-without-tombstone → `IncompleteRepair { receipt_id_orphan }`
fn detect_incomplete_repair(
    conn: &rusqlite::Connection,
    data_dir: &Path,
) -> Result<Option<VerifyOutcome>, StoreError> {
    use std::collections::HashSet;

    let tombstone_action = core_events::receipt::RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE;
    // Orphan detection is an ADDITIVE check on top of the chain walk. If the
    // secondary store (receipts.log) is unreadable (perms drift, transient
    // I/O), do NOT error the whole verify — that would mask the chain-walk
    // result and could brick a daemon over a non-chain problem. Skip this
    // pass and let the next verify retry (self-healing).
    let finalize_receipts = match read_repair_finalize_receipts(data_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %e,
                "incomplete_repair_detector_landed: could not read receipts.log; skipping \
                 orphan detection for this verify (chain-walk result stands). Investigate \
                 receipts.log."
            );
            return Ok(None);
        }
    };
    let receipt_repair_ids: HashSet<&str> = finalize_receipts
        .iter()
        .map(|r| r.repair_id.as_str())
        .collect();

    // Pass 1: every repair tombstone must have a matching finalize receipt.
    let mut stmt =
        conn.prepare("SELECT id, details FROM audit_log WHERE action = ?1 ORDER BY id ASC")?;
    let tombstones: Vec<(i64, Option<String>)> = stmt
        .query_map(params![tombstone_action], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<_, _>>()?;
    for (tombstone_row_id, details) in tombstones {
        let repair_id = details
            .as_deref()
            .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .and_then(|v| {
                v.get("repair_id")
                    .and_then(|r| r.as_str())
                    .map(str::to_string)
            });
        let has_receipt = match repair_id {
            // Prefer the repair_id linkage; fall back to the receipt's
            // tombstone_row_id claim when details lack a repair_id.
            Some(rid) => receipt_repair_ids.contains(rid.as_str()),
            None => finalize_receipts
                .iter()
                .any(|r| r.tombstone_row_id == tombstone_row_id),
        };
        if !has_receipt {
            return Ok(Some(VerifyOutcome::IncompleteRepairReceipt {
                tombstone_row_id,
            }));
        }
    }

    // Pass 2: every finalize receipt must point at a real tombstone row.
    for r in &finalize_receipts {
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE id = ?1 AND action = ?2",
            params![r.tombstone_row_id, tombstone_action],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Ok(Some(VerifyOutcome::IncompleteRepair {
                receipt_id_orphan: r.receipt_id.clone(),
            }));
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// audit_repair_chain_rpc_landed — ADR 174 v2 §2 `audit.repair_chain`
// ---------------------------------------------------------------------------

/// audit_repair_chain_rpc_landed — repair strategy discriminator. v0.3
/// ships exactly `Truncate` (the `truncate_after_row` primitive named by
/// ADR 174 v2 §2). `TombstoneSegment` is reserved for a future
/// "preserve broken rows, mint a tombstone-only repair" flow;
/// dispatching it from v0.3
/// returns `-32602 unsupported repair_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairKind {
    Truncate,
    TombstoneSegment,
}

/// audit_repair_chain_rpc_landed / P23-S5 — operator-co-signed repair intent per
/// ADR 174 v2 §4, hardened to ADR 200 §6. The `operator_signature` is a
/// **presence-Device signature** (dev0: YubiKey-PIV ECDSA-P256) over the canonical
/// `(from_row_id, current_chain_tip_hash, daemon_identity_root_fingerprint)`
/// tuple. [`verify_repair_intent_signature`] verifies it against the enrolled
/// `presence`-class Device set under the operator root — NOT the caller-supplied
/// `operator_pubkey` and NOT any enrolled persona key — before any state mutation
/// runs. A `presence` Device's private key is hardware-held (G1), so the daemon
/// cannot forge this co-signature — the `cant > wont` gate per memory
/// `feedback_structural_cant_over_behavioral_wont`.
///
/// `current_chain_tip_hash` is the BLAKE3 hex `row_hash` of the audit_log
/// row at `from_row_id` BEFORE any truncate; the operator co-signs the
/// hash the daemon will preserve as the new chain tip's `prev_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairIntent {
    pub from_row_id: i64,
    pub repair_kind: RepairKind,
    /// Presence-Device signature over `canonical_repair_intent_bytes` (raw bytes;
    /// the `p256sig:`/`ed25519sig:` payload with the prefix stripped). Verified
    /// against the daemon-materialized presence-Device set, NOT this struct's
    /// `operator_pubkey` (ADR 200 §6).
    pub operator_signature: Vec<u8>,
    /// The presence Device's claimed signing public key (`p256:<hex>` for the
    /// dev0 YubiKey-PIV key; `ed25519:<hex>` only if so enrolled). Carried for
    /// diagnostics — the daemon verifies against its own materialized
    /// presence-Device set, never trusting this caller-supplied value.
    pub operator_pubkey: String,
    /// Operator-asserted current chain tip hash. The daemon re-derives
    /// the actual chain tip from `audit_log` post-quarantine and refuses
    /// the repair if they disagree (the confused-deputy guard per
    /// ADR 174 v2 §2 + §6 HIGH-2 reframing).
    pub current_chain_tip_hash: String,
    /// Daemon identity-root fingerprint at the time the operator
    /// co-signed. Bound into the canonical bytes so a stolen operator
    /// signature from one daemon can't be replayed against another.
    pub daemon_identity_root_fingerprint: String,
}

/// audit_repair_chain_rpc_landed — canonical encoding of the bytes the
/// operator co-signs. JCS-style, deterministic across SDKs.
///
/// **Domain separation (adversarial MED-1 fix 2026-05-22).** The signed
/// payload carries a leading `ctx` field with value
/// `"emberlink.v1.audit_repair_intent"` so a signature minted for this
/// envelope can NEVER be replayed against a different signed object
/// that happens to share the same three field names (e.g.,
/// `AuditChainRepairFinalizeBody` carries similar fields under similar
/// names; the `ctx` prefix structurally precludes cross-protocol
/// substitution). Defense-in-depth: structural `can't > won't` per the
/// `feedback_structural_cant_over_behavioral_wont` memory.
pub fn canonical_repair_intent_bytes(
    from_row_id: i64,
    current_chain_tip_hash: &str,
    daemon_identity_root_fingerprint: &str,
) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    map.insert(
        "ctx",
        serde_json::Value::String("emberlink.v1.audit_repair_intent".to_string()),
    );
    map.insert(
        "current_chain_tip_hash",
        serde_json::Value::String(current_chain_tip_hash.to_string()),
    );
    map.insert(
        "daemon_identity_root_fingerprint",
        serde_json::Value::String(daemon_identity_root_fingerprint.to_string()),
    );
    map.insert(
        "from_row_id",
        serde_json::Value::Number(serde_json::Number::from(from_row_id)),
    );
    serde_json::to_vec(&map).expect("BTreeMap<&str, Value> serialization is infallible")
}

/// audit_repair_chain_rpc_landed — repair outcome variants per ADR 174 v2
/// §6. `Ok` is the success path; `IncompleteRepair` and
/// `IncompleteRepairReceipt` mirror the verifier outcomes for the
/// daemon-crashed-mid-repair recovery surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairOutcome {
    Ok {
        repair_id: String,
        new_chain_tip_hash: String,
        tombstone_row_id: i64,
        truncated_row_count: u64,
    },
    IncompleteRepair {
        receipt_id_orphan: String,
    },
    IncompleteRepairReceipt {
        tombstone_row_id_orphan: i64,
    },
}

/// audit_repair_chain_rpc_landed — error variants distinct from the
/// generic StoreError so the dispatcher can map onto -32401-class
/// authority errors vs -32603 generic errors.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("operator signature verification failed")]
    OperatorSignatureInvalid,
    #[error("operator_pubkey is malformed: {0}")]
    OperatorPubkeyInvalid(String),
    #[error("daemon identity fingerprint mismatch: signed={signed} current={current}")]
    DaemonFingerprintMismatch { signed: String, current: String },
    #[error("current_chain_tip_hash mismatch: signed={signed} actual={actual}")]
    ChainTipMismatch { signed: String, actual: String },
    #[error("from_row_id {0} does not exist in audit_log")]
    FromRowIdMissing(i64),
    #[error("repair_kind {0:?} not supported in v0.3 (only Truncate)")]
    UnsupportedRepairKind(RepairKind),
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("receipt journal error: {0}")]
    Journal(String),
    #[error("daemon identity not initialised; cannot sign repair receipt")]
    IdentityMissing,
}

/// audit_repair_chain_rpc_landed — `truncate_after_row` primitive per
/// ADR 174 v2 §2. DELETEs every audit_log row with `id > from_row_id`,
/// inserts a `audit.chain_repair_tombstone` row at the new chain tip
/// chaining from the surviving row's `row_hash`, mints a
/// `audit.chain_repair_finalize` Receipt v2, appends it to receipts.log,
/// and clears the quarantine latch on success.
///
/// All SQLite mutations run inside a single `BEGIN IMMEDIATE`
/// transaction; the receipt mint happens inside the block so an I/O
/// error rolls back both the DELETE and the tombstone INSERT.
///
/// Authority gate: the caller MUST verify the co-signature against the enrolled
/// `presence`-Device set BEFORE calling this function — the `audit_repair_chain`
/// dispatcher does so via [`verify_repair_intent_signature`], which returns the
/// matched [`RepairCosigner`] threaded in here. This function re-checks the
/// chain-tip + daemon-fingerprint invariants but does NOT re-verify the signature
/// (it trusts the dispatcher's prior verify). The `cosigner`'s `signing_device_id`
/// is stamped onto the tombstone + finalize receipt (ADR 200 §4 attribution).
pub fn truncate_after_row(
    store: &DaemonStore,
    intent: &RepairIntent,
    cosigner: &RepairCosigner,
) -> Result<RepairOutcome, RepairError> {
    use core_events::receipt::{
        AuditChainRepairFinalizeBody, RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE, ReceiptEnvelope,
        ReceiptVersion, TerminationAuthority, sign_receipt_v2,
    };

    if intent.repair_kind != RepairKind::Truncate {
        return Err(RepairError::UnsupportedRepairKind(intent.repair_kind));
    }

    // Resolve current daemon identity + verify fingerprint matches what
    // the operator co-signed against. Refuses replay across daemon
    // identities.
    let identity = crate::infra::receipt::current_identity().ok_or(RepairError::IdentityMissing)?;
    let pubkey_hex = identity.pubkey_hex();
    // Single source of truth for the daemon identity-root fingerprint (shared with
    // the presence-intent nonce path) — see `DaemonPersona::identity_root_fingerprint`.
    let current_fingerprint = identity.identity_root_fingerprint();
    if current_fingerprint != intent.daemon_identity_root_fingerprint {
        return Err(RepairError::DaemonFingerprintMismatch {
            signed: intent.daemon_identity_root_fingerprint.clone(),
            current: current_fingerprint,
        });
    }

    // Resolve the row at `from_row_id` to establish the new chain tip's
    // `prev_hash`. Also re-derive the actual chain tip and refuse the
    // repair if it disagrees with the operator's signed assertion (the
    // confused-deputy guard).
    let from_row_hash: Option<String> = store
        .conn()
        .query_row(
            "SELECT row_hash FROM audit_log WHERE id = ?1",
            rusqlite::params![intent.from_row_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    let from_row_hash = from_row_hash.ok_or(RepairError::FromRowIdMissing(intent.from_row_id))?;

    if from_row_hash != intent.current_chain_tip_hash {
        return Err(RepairError::ChainTipMismatch {
            signed: intent.current_chain_tip_hash.clone(),
            actual: from_row_hash,
        });
    }

    // Resolve current_segment_id BEFORE the BEGIN IMMEDIATE for
    // bookkeeping. The tombstone opens a NEW segment per R7 / locked
    // decision #14.
    let current_max_segment_id: u64 = store
        .conn()
        .query_row(
            "SELECT COALESCE(MAX(segment_id), 0) FROM audit_log",
            [],
            |row| row.get::<_, i64>(0).map(|v| v as u64),
        )
        .unwrap_or(0);
    let new_segment_id = current_max_segment_id + 1;

    let repair_id = generate_repair_id();
    let repair_timestamp = chrono::Utc::now().to_rfc3339();

    let conn = store.conn();
    conn.execute("BEGIN IMMEDIATE", [])?;
    let result = (|| -> Result<RepairOutcome, RepairError> {
        // 1. Count and DELETE all rows after from_row_id.
        let truncated_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE id > ?1",
            rusqlite::params![intent.from_row_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "DELETE FROM audit_log WHERE id > ?1",
            rusqlite::params![intent.from_row_id],
        )?;

        // 2. INSERT the tombstone row at `from_row_id + 1` chaining from
        //    the surviving row's `row_hash`. The tombstone body carries
        //    the operator signature + repair_id + truncated_row_count.
        let tombstone_action = core_events::receipt::RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE;
        let tombstone_outcome = "ok";
        let tombstone_body_details = serde_json::json!({
            "repair_id": repair_id,
            "truncated_row_count": truncated_count,
            // The daemon-materialized presence-Device key that verified the
            // co-signature (ADR 200 §4/§6) — NOT the caller-claimed pubkey.
            "operator_pubkey": cosigner.signing_device_pubkey,
            "signing_device_id": cosigner.signing_device_id,
            "operator_signature_hex": hex::encode(&intent.operator_signature),
            "from_row_id": intent.from_row_id,
        });
        let tombstone_body_details_str = tombstone_body_details.to_string();
        let canonical = canonical_audit_row_bytes(
            &repair_timestamp,
            None,
            tombstone_action,
            None,
            tombstone_outcome,
            Some(&tombstone_body_details_str),
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(from_row_hash.as_bytes());
        hasher.update(&canonical);
        let tombstone_row_hash = hasher.finalize().to_hex().to_string();

        conn.execute(
            "INSERT INTO audit_log \
             (timestamp, agent_id, action, credential, outcome, details, prev_hash, row_hash, segment_id, is_segment_genesis) \
             VALUES (?1, NULL, ?2, NULL, ?3, ?4, ?5, ?6, ?7, 1)",
            rusqlite::params![
                repair_timestamp,
                tombstone_action,
                tombstone_outcome,
                tombstone_body_details_str,
                from_row_hash,
                tombstone_row_hash,
                new_segment_id as i64,
            ],
        )?;
        let tombstone_row_id = conn.last_insert_rowid();

        // 3. Mint the `audit.chain_repair_finalize` Receipt v2 and
        //    append to receipts.log INSIDE the transaction. A failure
        //    here propagates and ROLLBACK fires — neither the truncate
        //    nor the tombstone land.
        let data_dir = store.data_dir().ok_or_else(|| {
            RepairError::Journal(
                "audit.repair_chain requires a configured data_dir (file-backed store)".into(),
            )
        })?;

        let body = AuditChainRepairFinalizeBody {
            repair_id: repair_id.clone(),
            from_row_id: intent.from_row_id,
            truncated_row_count: truncated_count as u64,
            tombstone_row_id,
            new_chain_tip_hash: tombstone_row_hash.clone(),
            pre_repair_chain_tip_hash: from_row_hash.clone(),
            operator_signature: hex::encode(&intent.operator_signature),
            // ADR 200 §4 — attribute the co-signature to the enrolled presence
            // Device that verified it (the `(persona, device)` signature pair). A
            // verifier reads this to confirm a hardware presence Device co-signed,
            // not a daemon-forgeable persona key.
            signing_device_id: cosigner.signing_device_id.clone(),
            daemon_identity_root_fingerprint: current_fingerprint.clone(),
            repair_timestamp: repair_timestamp.clone(),
        };
        let body_value = serde_json::to_value(&body)
            .map_err(|e| RepairError::Journal(format!("serialize finalize body: {e}")))?;

        let mut envelope = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE.to_string(),
            receipt_id: String::new(),
            daemon_root_id: pubkey_hex.clone(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body: body_value,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };

        let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
        sign_receipt_v2(&mut envelope, &signer)
            .map_err(|e| RepairError::Journal(format!("sign finalize receipt: {e}")))?;

        crate::infra::receipt::append_receipts_journal(data_dir, &envelope)
            .map_err(|e| RepairError::Journal(format!("append finalize receipt: {e}")))?;

        Ok(RepairOutcome::Ok {
            repair_id: repair_id.clone(),
            new_chain_tip_hash: tombstone_row_hash,
            tombstone_row_id,
            truncated_row_count: truncated_count as u64,
        })
    })();

    match result {
        Ok(outcome) => {
            conn.execute("COMMIT", [])?;
            // audit_repair_chain_rpc_landed — clear the quarantine
            // latch on success per the brief's "Exits quarantine-serve
            // mode on success" acceptance. This narrows the ADR 174 v2
            // §1 Synthesis-1 "no in-process leave_quarantine"
            // contract: for v0.3-RC the operator-co-signed repair is
            // the ONLY path that clears the latch, and it does so
            // synchronously rather than requiring a daemon restart.
            // The next startup-verify walks the fresh chain cleanly.
            crate::infra::handler::clear_quarantine_after_repair();
            Ok(outcome)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

/// The verified audit-repair co-signer (P23-S5 / ADR 200 §4 + §6). Returned by
/// [`verify_repair_intent_signature`] when a co-signature verifies against an
/// enrolled `presence`-class Device under the operator root, so the consumer can
/// stamp `(signing_device_id, signing_device_pubkey)` onto the repair receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairCosigner {
    /// The `device_id` of the enrolled presence Device whose key verified the
    /// co-signature — the receipt's `signing_device_id` (ADR 200 §4).
    pub signing_device_id: String,
    /// The matched presence Device's signing public key (the daemon-materialized
    /// one, NOT the caller-supplied `operator_pubkey`).
    pub signing_device_pubkey: String,
}

/// audit_repair_chain_rpc_landed / P23-S5 — verify the operator co-signature on
/// a `RepairIntent` against the enrolled **`presence`-class Device set under the
/// operator root** (ADR 200 §6, the audit co-sign consumer that closes F1).
///
/// **The trust anchor is the daemon-materialized presence set (`presence_devices`,
/// from [`crate::infra::operator_identity::active_presence_devices_under_operator_root`]),
/// NEVER the caller-supplied `intent.operator_pubkey` and NEVER an arbitrary
/// enrolled persona key.** A `presence` Device's private key lives in hardware the
/// daemon does not hold (G1), so a verified signature here is one a compromised
/// daemon could not have produced — whereas the previous "any enrolled persona
/// pubkey" gate accepted a co-signature from a daemon-vault-sealed agent/runtime
/// persona key, which the daemon CAN forge (the original F1 hole). Fail closed on
/// an empty set (no enrolled presence Device → no key to verify against). Returns
/// the matched [`RepairCosigner`]; `RepairError::OperatorSignatureInvalid` if no
/// enrolled presence Device verifies. Called by the dispatcher BEFORE
/// [`truncate_after_row`].
pub fn verify_repair_intent_signature(
    intent: &RepairIntent,
    presence_devices: &[(String, String)],
) -> Result<RepairCosigner, RepairError> {
    use core_crypto::{PublicKey, Signature};
    let bytes = canonical_repair_intent_bytes(
        intent.from_row_id,
        &intent.current_chain_tip_hash,
        &intent.daemon_identity_root_fingerprint,
    );
    // G1: with no enrolled presence Device there is no operator-held key to verify
    // against, so the co-sign cannot be anything but daemon-forgeable — fail closed
    // rather than fall back to a persona-key gate.
    if presence_devices.is_empty() {
        return Err(RepairError::OperatorSignatureInvalid);
    }
    let sig_hex = hex::encode(&intent.operator_signature);
    // Model C, 1-of-N: any enrolled presence Device under the operator root may
    // co-sign. Try each; the matching Device is the attributed signer.
    for (device_id, device_pubkey) in presence_devices {
        // Build the signature wire form by the *enrolled* key's algorithm (fixed
        // at enrollment; an attacker cannot steer it independently of the key).
        // dev0 presence Devices are YubiKey-PIV ECDSA-P256; Ed25519 otherwise.
        let sig = if device_pubkey.starts_with("p256:") {
            Signature(format!("p256sig:{sig_hex}"))
        } else {
            Signature(format!("ed25519sig:{sig_hex}"))
        };
        // Prefix-dispatching device verifier (AC-4: P256 keys never route through
        // the Ed25519-only verifier).
        if core_crypto::verify_device_signature(&PublicKey(device_pubkey.clone()), &bytes, &sig) {
            return Ok(RepairCosigner {
                signing_device_id: device_id.clone(),
                signing_device_pubkey: device_pubkey.clone(),
            });
        }
    }
    Err(RepairError::OperatorSignatureInvalid)
}

/// audit_repair_chain_rpc_landed — UUID-shaped opaque repair id. Used
/// in the tombstone row's details + the finalize receipt body so the
/// operator can cross-reference them.
fn generate_repair_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    format!(
        "repair-{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:04x}{:04x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
        u16::from_be_bytes([bytes[12], bytes[13]]),
        u16::from_be_bytes([bytes[14], bytes[15]]),
    )
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
        assert!(
            entries
                .iter()
                .all(|e| e.agent_id.as_deref() == Some("agent-1"))
        );
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
        store
            .log_event(None, "grant.create", None, "ok", None)
            .unwrap();
        store
            .log_event(None, "grant.revoke", None, "ok", None)
            .unwrap();
        store
            .log_event(None, "approval.dismissed", None, "ok", None)
            .unwrap();
        store
            .log_event(None, "broker.materialization", None, "ok", None)
            .unwrap();

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
        // persona_id targets the agent_id
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
        // since_ms / before_ms inclusive
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
        assert_eq!(
            entries.len(),
            1,
            "only the t=200 row should match [150,250]"
        );
        assert_eq!(entries[0].action, "b");
    }

    #[test]
    fn action_prefix_filter_empty_string_is_noop() {
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .log_event(None, "grant.create", None, "ok", None)
            .unwrap();
        store
            .log_event(None, "approval.dismissed", None, "ok", None)
            .unwrap();

        let entries = store
            .query_audit(&AuditFilter {
                action_prefix: Some("".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            entries.len(),
            2,
            "empty prefix is a no-op — all events returned"
        );
    }

    #[test]
    fn chained_audit_append_records_telemetry_write_batch_when_enabled() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        struct ResetTelemetry;
        impl Drop for ResetTelemetry {
            fn drop(&mut self) {
                let _ = crate::telemetry::measurement::disable_collection_and_purge();
                crate::telemetry::measurement::set_output_dir(None);
            }
        }
        let _reset = ResetTelemetry;

        let dir = tempfile::tempdir().expect("tempdir");
        crate::telemetry::measurement::set_output_dir(Some(dir.path().to_path_buf()));
        crate::telemetry::measurement::enable_collection();

        let store = DaemonStore::open_in_memory().unwrap();
        append_audit_event_with_chain(&store, Some("a-1"), "grant.create", None, "ok", None)
            .expect("append audit event");

        let csv_path = std::fs::read_dir(dir.path())
            .expect("telemetry dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|e| e.to_str()) == Some("csv"))
            .expect("daily telemetry file written");
        let raw = std::fs::read_to_string(csv_path).expect("read telemetry");
        let saw_batch = raw.lines().any(|line| {
            matches!(
                serde_json::from_str::<crate::telemetry::measurement::SampleRow>(line),
                Ok(crate::telemetry::measurement::SampleRow::AuditWriteBatch { writes: 1, .. })
            )
        });
        assert!(
            saw_batch,
            "audit-chain append should emit an AuditWriteBatch telemetry row"
        );
    }

    /// Verifier walks a fresh chain and reports Ok.
    #[test]
    fn audit_verify_chain_passes_on_untampered_log() {
        let store = DaemonStore::open_in_memory().unwrap();
        // Genesis row already laid by migrate().
        append_audit_event_with_chain(&store, Some("a-1"), "grant.create", None, "ok", None)
            .unwrap();
        append_audit_event_with_chain(&store, Some("a-2"), "grant.revoked", None, "ok", None)
            .unwrap();
        append_audit_event_with_chain(&store, None, "broker.materialization", None, "ok", None)
            .unwrap();

        let outcome = run_audit_verify(store.conn(), None, None).expect("verify");
        match outcome {
            VerifyOutcome::Ok { rows_walked, .. } => {
                assert_eq!(
                    rows_walked, 4,
                    "expected 4 chain rows walked (genesis + 3 appends), got {}",
                    rows_walked
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// Verifier detects a tampered row.
    /// Seeds 3 chained events, hand-corrupts row 2's `details` column
    /// (bypassing the chain primitive's hash recompute), asserts the
    /// verifier emits `VerifyOutcome::Break` at the corrupted row.
    #[test]
    fn audit_verify_chain_detects_tampered_row() {
        let _guard = repair_test_lock();
        crate::infra::handler::force_quarantine_latch_for_test(false);
        let store = DaemonStore::open_in_memory().unwrap();
        let id1 = append_audit_event_with_chain(
            &store,
            Some("a-1"),
            "grant.create",
            None,
            "ok",
            Some("orig"),
        )
        .unwrap();
        append_audit_event_with_chain(&store, Some("a-2"), "grant.revoked", None, "ok", None)
            .unwrap();
        append_audit_event_with_chain(&store, None, "broker.materialization", None, "ok", None)
            .unwrap();

        // Bypass the chain primitive — mutate the row's `details` directly
        // so its stored `row_hash` no longer matches what the verifier
        // recomputes.
        let n = store
            .conn()
            .execute(
                "UPDATE audit_log SET details = 'TAMPERED' WHERE id = ?1",
                rusqlite::params![id1],
            )
            .unwrap();
        assert_eq!(n, 1);

        let outcome = run_audit_verify(store.conn(), None, None).expect("verify");
        match outcome {
            VerifyOutcome::Break {
                kind:
                    BreakKind::RowHashMismatch {
                        at_row_id,
                        rows_walked_before,
                        ..
                    },
            } => {
                assert_eq!(at_row_id, id1, "break must surface at the tampered row");
                // Genesis walked; tampered row is the next one — so 1 row walked before break.
                assert_eq!(rows_walked_before, 1);
            }
            other => panic!("expected Break::RowHashMismatch, got {:?}", other),
        }
        crate::infra::handler::force_quarantine_latch_for_test(false);
    }

    /// Sampling mode walks only the last N rows.
    #[test]
    fn audit_verify_chain_tail_walks_only_last_n() {
        let store = DaemonStore::open_in_memory().unwrap();
        for i in 0..10 {
            append_audit_event_with_chain(
                &store,
                Some(&format!("a-{i}")),
                "grant.create",
                None,
                "ok",
                None,
            )
            .unwrap();
        }

        let outcome = run_audit_verify(store.conn(), Some(3), None).expect("verify --tail 3");
        match outcome {
            VerifyOutcome::Ok { rows_walked, .. } => {
                assert_eq!(rows_walked, 3, "tail=3 should walk exactly 3 rows");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ---- incomplete_repair_detector_landed ----

    fn detector_conn_with_audit_log() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT,
                action TEXT NOT NULL,
                credential TEXT,
                outcome TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT,
                row_hash TEXT,
                segment_id INTEGER NOT NULL DEFAULT 0,
                is_segment_genesis INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn
    }

    fn insert_repair_tombstone(conn: &rusqlite::Connection, repair_id: &str) -> i64 {
        let details = serde_json::json!({ "repair_id": repair_id }).to_string();
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, outcome, details, segment_id, is_segment_genesis) \
             VALUES ('2026-05-29T00:00:00Z', ?1, 'ok', ?2, 1, 1)",
            params![
                core_events::receipt::RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE,
                details
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn write_finalize_receipt(
        data_dir: &Path,
        receipt_id: &str,
        repair_id: &str,
        tombstone_row_id: i64,
    ) {
        use core_events::receipt::{
            AuditChainRepairFinalizeBody, RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE,
            ReceiptEnvelope, ReceiptVersion, TerminationAuthority,
        };
        use std::io::Write as _;
        let body = AuditChainRepairFinalizeBody {
            repair_id: repair_id.to_string(),
            from_row_id: 1,
            truncated_row_count: 1,
            tombstone_row_id,
            new_chain_tip_hash: "tip".to_string(),
            pre_repair_chain_tip_hash: "pre".to_string(),
            operator_signature: "opsig".to_string(),
            signing_device_id: "device-operator-presence".to_string(),
            daemon_identity_root_fingerprint: "fp".to_string(),
            repair_timestamp: "2026-05-29T00:00:00Z".to_string(),
        };
        let env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE.to_string(),
            receipt_id: receipt_id.to_string(),
            daemon_root_id: "test-daemon".to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body: serde_json::to_value(&body).unwrap(),
            signature: Some("sig".to_string()),
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        let line = serde_json::to_string(&env).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_dir.join("receipts.log"))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// Tombstone committed but its `audit.chain_repair_finalize` receipt is
    /// absent from receipts.log → `IncompleteRepairReceipt`.
    #[test]
    fn incomplete_repair_detects_tombstone_orphan() {
        let dir = tempfile::TempDir::new().unwrap();
        let conn = detector_conn_with_audit_log();
        let tid = insert_repair_tombstone(&conn, "rid-1");
        // No receipts.log at all.
        let out = detect_incomplete_repair(&conn, dir.path()).unwrap();
        assert_eq!(
            out,
            Some(VerifyOutcome::IncompleteRepairReceipt {
                tombstone_row_id: tid
            })
        );
    }

    /// Finalize receipt minted but its tombstone row never committed (the
    /// repair crash-window: receipt appended before COMMIT, then rollback)
    /// → `IncompleteRepair` carrying the orphan receipt id.
    #[test]
    fn incomplete_repair_detects_receipt_orphan() {
        let dir = tempfile::TempDir::new().unwrap();
        let conn = detector_conn_with_audit_log();
        // Receipt claims tombstone_row_id=999, which does not exist.
        write_finalize_receipt(dir.path(), "rcpt-1", "rid-1", 999);
        let out = detect_incomplete_repair(&conn, dir.path()).unwrap();
        assert_eq!(
            out,
            Some(VerifyOutcome::IncompleteRepair {
                receipt_id_orphan: "rcpt-1".to_string()
            })
        );
    }

    /// A consistent post-repair state (tombstone + matching finalize
    /// receipt, linked by repair_id and tombstone_row_id) is clean.
    #[test]
    fn incomplete_repair_clean_when_consistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let conn = detector_conn_with_audit_log();
        let tid = insert_repair_tombstone(&conn, "rid-1");
        write_finalize_receipt(dir.path(), "rcpt-1", "rid-1", tid);
        let out = detect_incomplete_repair(&conn, dir.path()).unwrap();
        assert_eq!(out, None, "consistent tombstone+receipt must not flag");
    }

    /// Chain advances: every row's `prev_hash`
    /// equals the prior row's `row_hash`. Genesis row carries `prev_hash =
    /// NULL`. Two back-to-back appends must produce a row whose `prev_hash`
    /// matches the genesis row's `row_hash`, then another whose `prev_hash`
    /// matches the first append's `row_hash`.
    #[test]
    fn audit_chain_row_hash_advances_with_each_event() {
        let store = DaemonStore::open_in_memory().unwrap();

        // Genesis row was inserted by migrate(); confirm it.
        let (genesis_action, genesis_prev, genesis_hash): (String, Option<String>, Option<String>) =
            store
                .conn()
                .query_row(
                    "SELECT action, prev_hash, row_hash FROM audit_log ORDER BY id ASC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("genesis row must exist");
        assert_eq!(genesis_action, "audit.chain_v1_genesis");
        assert!(genesis_prev.is_none(), "genesis prev_hash must be NULL");
        let genesis_hash = genesis_hash.expect("genesis row_hash must be set");

        // First append after genesis.
        let id1 = append_audit_event_with_chain(
            &store,
            Some("agent-1"),
            "grant.create",
            Some("cred-x"),
            "ok",
            Some("first"),
        )
        .expect("first append");

        let (prev1, hash1): (Option<String>, Option<String>) = store
            .conn()
            .query_row(
                "SELECT prev_hash, row_hash FROM audit_log WHERE id = ?1",
                rusqlite::params![id1],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            prev1.as_deref(),
            Some(genesis_hash.as_str()),
            "first append's prev_hash must equal genesis's row_hash"
        );
        let hash1 = hash1.expect("first append's row_hash must be set");

        // Second append — chains forward from id1.
        let id2 = append_audit_event_with_chain(
            &store,
            Some("agent-2"),
            "grant.revoked",
            None,
            "ok",
            Some("second"),
        )
        .expect("second append");

        let (prev2, hash2): (Option<String>, Option<String>) = store
            .conn()
            .query_row(
                "SELECT prev_hash, row_hash FROM audit_log WHERE id = ?1",
                rusqlite::params![id2],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            prev2.as_deref(),
            Some(hash1.as_str()),
            "second append's prev_hash must equal first append's row_hash"
        );
        assert!(hash2.is_some(), "second append's row_hash must be set");
        assert_ne!(
            hash1,
            hash2.unwrap(),
            "consecutive rows with different content must have different row_hashes"
        );
    }

    // -----------------------------------------------------------------
    // audit_repair_chain_rpc_landed — B4 tests
    // -----------------------------------------------------------------

    /// Quarantine-touching tests share the global `QUARANTINED`
    /// `AtomicBool` in `infra::handler`; serialize them through the
    /// crate-wide process test lock so handler-side audit-repair tests
    /// that touch the same latch cannot race this module.
    ///
    /// We use `force_quarantine_latch_for_test` (an `#[cfg(test)]`
    /// helper in `infra::handler`) rather than the production
    /// `enter_quarantine` so the `QUARANTINE_REASON` /
    /// `QUARANTINE_AUTHORITY` `OnceLock`s remain unset across tests —
    /// otherwise sibling tests asserting `quarantine_authority() ==
    /// None` would fail once any B4 test ran first.
    fn repair_test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// audit_repair_chain_rpc_landed / P23-S5 — sign a synthetic operator
    /// `RepairIntent` with a P-256 **presence Device** key (as a dev0 YubiKey-PIV
    /// key would be), for the given `from_row_id` + actual chain tip. Returns the
    /// `(intent, presence_devices)` pair, where `presence_devices` is the
    /// daemon-materialized `(device_id, signing_pubkey)` set the verifier checks
    /// against (ADR 200 §6). Tests that want to assert "refuses unsigned" zero-out
    /// `intent.operator_signature` post-construction.
    fn build_signed_intent(
        from_row_id: i64,
        current_chain_tip_hash: &str,
        daemon_identity_root_fingerprint: &str,
    ) -> (RepairIntent, Vec<(String, String)>) {
        use core_crypto::{P256Signer, Signer as _};
        let signer = P256Signer::from_scalar_bytes(&[0x5B; 32]).unwrap();
        let device_pubkey = signer.public_key_material("dev-key-presence").public_key;

        let bytes = canonical_repair_intent_bytes(
            from_row_id,
            current_chain_tip_hash,
            daemon_identity_root_fingerprint,
        );
        let sig = signer.sign(&bytes);
        // `operator_signature` carries the raw signature bytes — the `p256sig:`
        // hex payload with the prefix stripped. The daemon reconstructs the wire
        // form by the matched device key's algorithm at verify time.
        let sig_hex = sig
            .0
            .strip_prefix("p256sig:")
            .expect("P256Signer yields a p256sig: wire form");
        let signature_bytes = hex::decode(sig_hex).unwrap();

        let intent = RepairIntent {
            from_row_id,
            repair_kind: RepairKind::Truncate,
            operator_signature: signature_bytes,
            operator_pubkey: device_pubkey.clone(),
            current_chain_tip_hash: current_chain_tip_hash.to_string(),
            daemon_identity_root_fingerprint: daemon_identity_root_fingerprint.to_string(),
        };

        let presence_devices = vec![("device-operator-presence".to_string(), device_pubkey)];
        (intent, presence_devices)
    }

    /// Test fixture: build a store at `<tempdir>/daemon.db`, ensure the
    /// daemon identity is initialised against the same data_dir, and
    /// append a few audit rows so the truncate has something to remove.
    /// Returns the store + tempdir + daemon fingerprint.
    fn build_store_with_chain_for_repair() -> (DaemonStore, tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("daemon.db");
        crate::infra::receipt::init_identity(dir.path()).expect("init daemon identity");
        let store = DaemonStore::open(&db).expect("open daemon store");
        // Append 3 chained rows so we have a tail to truncate.
        for i in 0..3 {
            append_audit_event_with_chain(
                &store,
                Some(&format!("agent-{i}")),
                &format!("test.repair.event-{i}"),
                None,
                "ok",
                None,
            )
            .expect("append chained event");
        }
        let identity = crate::infra::receipt::current_identity().expect("identity set");
        let fingerprint = blake3::hash(identity.pubkey_hex().as_bytes())
            .to_hex()
            .to_string();
        (store, dir, fingerprint)
    }

    /// audit_repair_chain_rpc_landed — `truncate_after_row` clears the
    /// quarantine latch on success per the v0.3-RC B4 acceptance.
    #[test]
    fn audit_repair_chain_truncate_exits_quarantine() {
        let _guard = repair_test_lock();
        // Reset latch from any prior test.
        crate::infra::handler::force_quarantine_latch_for_test(false);

        let (store, _dir, fingerprint) = build_store_with_chain_for_repair();
        // Choose the second chained row as the truncate boundary so
        // there's at least one row to delete (the third row).
        let (from_row_id, current_tip): (i64, String) = store
            .conn()
            .query_row(
                "SELECT id, row_hash FROM audit_log WHERE row_hash IS NOT NULL \
                 ORDER BY id DESC LIMIT 1 OFFSET 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        let (intent, presence_devices) =
            build_signed_intent(from_row_id, &current_tip, &fingerprint);
        // E2E: the co-signature verifies against the enrolled presence-Device set
        // and yields the attributed signer (ADR 200 §6).
        let cosigner = verify_repair_intent_signature(&intent, &presence_devices)
            .expect("presence-Device co-signature must verify");
        assert_eq!(cosigner.signing_device_id, "device-operator-presence");

        // Simulate startup-verify entering quarantine via the latch
        // only — leaves QUARANTINE_REASON/AUTHORITY OnceLocks unset so
        // sibling tests asserting on them are not contaminated.
        crate::infra::handler::force_quarantine_latch_for_test(true);
        assert!(crate::infra::handler::is_quarantined());

        let outcome = truncate_after_row(&store, &intent, &cosigner).expect("repair must succeed");
        match outcome {
            RepairOutcome::Ok {
                truncated_row_count,
                ..
            } => {
                assert!(truncated_row_count >= 1, "must truncate at least one row");
            }
            other => panic!("expected RepairOutcome::Ok, got {other:?}"),
        }

        // The repair must have cleared the quarantine latch.
        assert!(
            !crate::infra::handler::is_quarantined(),
            "quarantine must be cleared after operator-co-signed repair"
        );
    }

    /// audit_repair_chain_rpc_landed — an invalid operator signature
    /// causes `verify_repair_intent_signature` to return
    /// `OperatorSignatureInvalid`. The dispatcher maps this to -32401.
    #[test]
    fn audit_repair_chain_refuses_unsigned() {
        let _guard = repair_test_lock();
        crate::infra::handler::force_quarantine_latch_for_test(false);

        let (store, _dir, fingerprint) = build_store_with_chain_for_repair();
        let (from_row_id, current_tip): (i64, String) = store
            .conn()
            .query_row(
                "SELECT id, row_hash FROM audit_log WHERE row_hash IS NOT NULL \
                 ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (mut intent, presence_devices) =
            build_signed_intent(from_row_id, &current_tip, &fingerprint);

        // Zero out the signature — this is the wire-shape equivalent of
        // "no signature attached." The verifier MUST refuse.
        intent.operator_signature = vec![0u8; 64];

        let err = verify_repair_intent_signature(&intent, &presence_devices)
            .expect_err("zeroed signature must be refused");
        assert!(matches!(err, RepairError::OperatorSignatureInvalid));

        // Sanity: a structurally-malformed signature (wrong length) also
        // refuses.
        intent.operator_signature = vec![0u8; 32];
        let err2 = verify_repair_intent_signature(&intent, &presence_devices)
            .expect_err("32-byte signature must be refused");
        assert!(matches!(err2, RepairError::OperatorSignatureInvalid));
    }

    /// P23-S5 / ADR 200 §6 — **the F1 regression.** A co-signature produced by a
    /// key that is NOT an enrolled `presence`-class Device under the operator root
    /// (the shape of a daemon-vault-sealed agent/runtime persona key the daemon
    /// could forge) MUST be refused, even though the signature is cryptographically
    /// valid for that key. An empty presence set fails closed. This is exactly the
    /// gate the original audit-chain F1 finding required — "reject a co-signature
    /// from a daemon-vault-sealed key."
    #[test]
    fn audit_repair_chain_rejects_non_presence_cosigner() {
        use core_crypto::{P256Signer, Signer as _};

        let fingerprint = "fp-test".to_string();
        let tip = blake3::hash(b"tip").to_hex().to_string();

        // A rogue key (stands in for a daemon-vault-sealed persona key the daemon
        // could sign with). Its self-signature is cryptographically valid.
        let rogue = P256Signer::from_scalar_bytes(&[0x11; 32]).unwrap();
        let rogue_pubkey = rogue.public_key_material("rogue").public_key;
        let bytes = canonical_repair_intent_bytes(7, &tip, &fingerprint);
        let sig = rogue.sign(&bytes);
        let sig_hex = sig.0.strip_prefix("p256sig:").unwrap();
        let intent = RepairIntent {
            from_row_id: 7,
            repair_kind: RepairKind::Truncate,
            operator_signature: hex::decode(sig_hex).unwrap(),
            operator_pubkey: rogue_pubkey.clone(),
            current_chain_tip_hash: tip.clone(),
            daemon_identity_root_fingerprint: fingerprint.clone(),
        };

        // A DIFFERENT key is the only enrolled presence Device. The rogue's valid
        // self-signature must NOT verify against the enrolled set (F1 closed).
        let enrolled = P256Signer::from_scalar_bytes(&[0x22; 32]).unwrap();
        let enrolled_pubkey = enrolled.public_key_material("enrolled").public_key;
        let presence_devices = vec![("device-enrolled".to_string(), enrolled_pubkey)];
        let err = verify_repair_intent_signature(&intent, &presence_devices)
            .expect_err("a co-sign not from an enrolled presence Device must be refused (F1)");
        assert!(matches!(err, RepairError::OperatorSignatureInvalid));

        // Control: when the rogue's key IS the enrolled set, the same signature
        // verifies — proving the refusal above is set-membership (the F1 gate),
        // not a bad signature.
        let as_enrolled = vec![("device-rogue".to_string(), rogue_pubkey)];
        let signer = verify_repair_intent_signature(&intent, &as_enrolled)
            .expect("a co-sign from an enrolled presence Device verifies");
        assert_eq!(signer.signing_device_id, "device-rogue");

        // Empty set (no enrolled presence Device) fails closed.
        let err_empty = verify_repair_intent_signature(&intent, &[])
            .expect_err("empty presence set must fail closed");
        assert!(matches!(err_empty, RepairError::OperatorSignatureInvalid));
    }

    /// audit_repair_chain_rpc_landed — atomicity under a forced
    /// rollback. Simulated by passing an intent whose
    /// `current_chain_tip_hash` does NOT match the actual chain tip —
    /// the check fires AFTER `BEGIN IMMEDIATE` but BEFORE any DELETE,
    /// so the rollback handler runs and no rows are mutated.
    ///
    /// Stronger rollback shapes (mid-DELETE panic, mid-receipt-mint
    /// I/O failure) are exercised via the receipt-journal mode-drift
    /// path in `infra::receipt::tests` and the `BEGIN IMMEDIATE`
    /// wrapper's standard rollback semantics; this test pins the
    /// "auth check failure leaves the chain intact" contract.
    #[test]
    fn audit_repair_chain_atomic_under_rollback() {
        let _guard = repair_test_lock();
        crate::infra::handler::force_quarantine_latch_for_test(false);

        let (store, _dir, fingerprint) = build_store_with_chain_for_repair();
        let pre_count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        let (from_row_id, _current_tip): (i64, String) = store
            .conn()
            .query_row(
                "SELECT id, row_hash FROM audit_log WHERE row_hash IS NOT NULL \
                 ORDER BY id DESC LIMIT 1 OFFSET 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        // Quarantine the daemon BEFORE the repair attempt so we can
        // assert the latch remains set on rollback.
        crate::infra::handler::force_quarantine_latch_for_test(true);

        // Build the intent with a deliberately wrong current_chain_tip_hash
        // so the in-transaction chain-tip check fails. Sign the intent
        // properly so the signature gate passes; the failure must come
        // from the chain-tip mismatch check inside truncate_after_row.
        let wrong_tip = blake3::hash(b"wrong-tip-bytes").to_hex().to_string();
        let (intent, presence_devices) = build_signed_intent(from_row_id, &wrong_tip, &fingerprint);
        // The intent's signed payload uses `wrong_tip` so the signature
        // verifies. truncate_after_row's chain-tip refusal fires once
        // it consults the actual row.

        // Sanity: signature verifies (the gate that the dispatcher runs
        // first).
        let cosigner = verify_repair_intent_signature(&intent, &presence_devices)
            .expect("signature on wrong-tip intent must still verify cryptographically");

        let err = truncate_after_row(&store, &intent, &cosigner)
            .expect_err("chain-tip mismatch must refuse the repair");
        assert!(
            matches!(err, RepairError::ChainTipMismatch { .. }),
            "expected ChainTipMismatch, got {err:?}"
        );

        // Audit_log row count is unchanged — no rows deleted.
        let post_count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            pre_count, post_count,
            "rollback must leave audit_log unchanged"
        );
        // No tombstone row was inserted (the truncate's body INSERT is
        // inside the same BEGIN IMMEDIATE).
        let tombstones: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit_log \
                 WHERE action = 'audit.chain_repair_tombstone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tombstones, 0, "no tombstone may land on rollback");
        // Quarantine latch remains set — no implicit clear on refusal.
        assert!(
            crate::infra::handler::is_quarantined(),
            "quarantine must remain set when the repair refuses"
        );

        // Clean up: clear so subsequent tests don't observe the latch.
        crate::infra::handler::force_quarantine_latch_for_test(false);
    }

    /// audit_repair_chain_rpc_landed — the dispatcher's
    /// `quarantine_allowed_method` returns `true` for the
    /// `audit_repair_chain` method even though it is write-class.
    /// `is_read_class_method` MUST NOT include it (the gate is
    /// "default-deny + named whitelist", not "everything is read-class").
    #[test]
    fn audit_repair_chain_allowed_in_quarantine_dispatcher() {
        // No state mutation; safe to run without the REPAIR_TEST_LOCK.
        assert!(
            crate::infra::handler::quarantine_allowed_method("audit_repair_chain"),
            "audit_repair_chain must be allowed through the quarantine gate"
        );
        // Read-class methods stay allowed.
        assert!(crate::infra::handler::quarantine_allowed_method("ping"));
        assert!(crate::infra::handler::quarantine_allowed_method(
            "audit_verify"
        ));
        // Write-class methods stay refused.
        assert!(!crate::infra::handler::quarantine_allowed_method(
            "grant_create"
        ));
        assert!(!crate::infra::handler::quarantine_allowed_method(
            "vault_unlock"
        ));
    }
}
