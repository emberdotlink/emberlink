use chrono::{TimeZone, Utc};
use rusqlite::params;
use rusqlite::types::Value as SqlValue;
use serde::{Deserialize, Serialize};

use crate::infra::store::{DaemonStore, StoreError};

/// implementation-note-189 — convert unix-ms to an RFC3339 string so
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
    /// implementation-note-190 — filter to actions that start with this prefix,
    /// e.g. `"grant."` shows only grant-family events. Rendering-layer only;
    /// applied after the SQL fetch so the limit still governs the fetch window.
    pub action_prefix: Option<String>,
    /// implementation-note-189 — alias for `agent_id`. Both populate
    /// the `agent_id = ?` clause; if both are set, `persona_id` wins.
    pub persona_id: Option<String>,
    /// implementation-note-189 — narrow to rows whose `credential`
    /// column starts with this prefix. SQL `LIKE` with appended `%`.
    pub scope: Option<String>,
    /// implementation-note-189 — inclusive lower bound (unix ms).
    /// Converted to RFC3339 before binding so it compares against the
    /// existing TEXT timestamp column.
    pub since_ms: Option<i64>,
    /// implementation-note-189 — inclusive upper bound (unix ms).
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
        // implementation-note-189 — dynamic positional binding so we
        // can compose any combination of {agent_id, action, persona_id, scope,
        // since_ms, before_ms} without the previous hand-numbered ladder.
        // implementation-note-191: filter out the chain-anchor checkpoint row.
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

        // implementation-note-190 — action_prefix filter applied post-fetch so
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

    /// implementation-note-189 — test helper to insert an audit row
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
        // implementation-note-191: same internal-checkpoint exclusion as
        // query_audit so the user-facing count matches what query_audit
        // returns.
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action != 'audit.chain_v1_genesis'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }
}

// ---------------------------------------------------------------------------
// implementation-note-191 — tamper-evident audit chain
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
    // already hold one. Per design v2 §1 + adversarial review CRIT-1.
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
    // will see `Err(Quarantined)` and roll back. Per design v2 §1 +
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
    Ok(conn.last_insert_rowid())
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
// implementation-note-192 — chain verifier
// ---------------------------------------------------------------------------

/// audit_verifier_outcome_v2 — outcome of a chain-verification walk.
///
/// Extended from the original 2-variant enum per design v2 + design review
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
    Break {
        kind: BreakKind,
    },
    /// Pre-chain NULL-hash legacy rows are present in the DB. This is the
    /// post-cordon expected steady state on the operator's host (290 such
    /// rows in segment 0). NOT a quarantine condition — operator runs
    /// `ember audit migrate-chain --acknowledge` to mint the Phase 2
    /// attested receipt. Per design review verifier D2 + locked decision #13.
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
    /// tombstone row never committed. Per design v2 §6.
    IncompleteRepair {
        receipt_id_orphan: String,
    },
    /// Symmetric to `IncompleteRepair`: the tombstone row committed but
    /// the repair receipt never minted. Recovered via the
    /// `ember audit chain-repair-finalize` CLI verb. Per locked decision
    /// #11 + repair D6.
    IncompleteRepairReceipt {
        tombstone_row_id: i64,
    },
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
    /// per design v2 §6 (locked decision #17).
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
/// inserted before the implementation-note-191 migration landed) are
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
/// # target_state_anchor
///
/// `fn run_audit_verify`
pub fn run_audit_verify(
    conn: &rusqlite::Connection,
    tail: Option<usize>,
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
        // implementation-note-189 — persona_id targets the agent_id
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
        // implementation-note-189 — since_ms / before_ms inclusive
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

    /// implementation-note-192 — verifier walks a fresh chain and reports Ok.
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

        let outcome = run_audit_verify(store.conn(), None).expect("verify");
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

    /// implementation-note-192 — verifier detects a tampered row.
    /// Seeds 3 chained events, hand-corrupts row 2's `details` column
    /// (bypassing the chain primitive's hash recompute), asserts the
    /// verifier emits `VerifyOutcome::Break` at the corrupted row.
    #[test]
    fn audit_verify_chain_detects_tampered_row() {
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

        let outcome = run_audit_verify(store.conn(), None).expect("verify");
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
    }

    /// implementation-note-192 — sampling mode walks only the last N rows.
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

        let outcome = run_audit_verify(store.conn(), Some(3)).expect("verify --tail 3");
        match outcome {
            VerifyOutcome::Ok { rows_walked, .. } => {
                assert_eq!(rows_walked, 3, "tail=3 should walk exactly 3 rows");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    /// implementation-note-191 — chain advances: every row's `prev_hash`
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
}
