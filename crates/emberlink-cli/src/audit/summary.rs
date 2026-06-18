//! CLASSIFICATION: PUBLIC
//!
//! `ember audit summary` — direct-SQLite Receipt aggregation path.
//!
//! Anchor: `audit_summary_cli_landed`.
//!
//! Sister module to `audit::query`: where `query` returns a flat list of
//! per-Receipt rows, `summary` returns aggregate counts (total Receipts,
//! distinct sessions, calls-by-kind histogram, pregrant-path histogram)
//! for at-a-glance audit posture. Same direct-SQLite read-only contract as
//! `query` — opens
//! `daemon.db` via `SQLITE_OPEN_READ_ONLY` so the operator's primary
//! aggregation surface works even when the daemon is not running.
//!
//! The store schema is owned by `ember_daemon::infra::store`. This module
//! is a read-only consumer of the `receipts` table; column names and
//! types live there.
//!
//! ## MVP filter surface (this module)
//!
//! - `since_iso` — lower bound on `created_at` (caller pre-parses via
//!   `audit::query::parse_since`).
//! - `workflow` — match `delegation_id` OR `delegation_template` extracted
//!   from `receipt_json` via SQLite JSON1.
//! - `persona` — exact match on `persona_id`.
//!
//! JIT/mock-broker/deny-list breakdowns, chain-integrity rollups, and
//! the T2 perf test at 1000 Receipts are deferred to follow-up tasks
//! (see worker brief).

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params_from_iter, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MISSING_PREGRANT_PATH: &str = "missing";

/// Direct-SQLite aggregation filter for `ember audit summary`.
///
/// All fields are optional; omitting them aggregates over the entire
/// receipts table. Filters AND-combine. Mirrors `query::QueryFilter`'s
/// shape minus `limit` (summary aggregates all matching rows).
#[derive(Debug, Default, Clone)]
pub struct SummaryFilter {
    /// ISO-8601 lower bound on `created_at`. Caller is responsible for
    /// parsing user input via `audit::query::parse_since` and rendering
    /// to RFC3339.
    pub since_iso: Option<String>,
    /// Exact match on either `delegation_id` or `delegation_template`
    /// extracted from `receipt_json` via JSON1.
    pub delegation: Option<String>,
    /// Exact match on `persona_id`.
    pub persona: Option<String>,
}

/// Aggregate summary returned by [`run_audit_summary`].
///
/// `total_receipts` is the simple row count after filters apply.
/// `sessions_count` counts distinct `persona_id` values (the closest
/// proxy for "agent sessions" available in the MVP receipts schema —
/// session-level grouping is a follow-up). `calls_by_kind` is a
/// histogram keyed by `receipts.kind` (`grant`, `kms_wrap`,
/// `kms_unwrap`, `broker.materialization`, etc.). `pregrant_path_counts`
/// is keyed by the on-wire `pregrant_path` value carried in
/// `receipt_json` (`standing_grant`, `per_action`, etc.), with
/// `missing` used for rows that do not carry the field so serializer
/// regressions remain visible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditSummary {
    /// Total Receipt rows matching the filter.
    pub total_receipts: usize,
    /// Distinct `persona_id` values across matching rows. Used as a
    /// proxy for "sessions" until the schema carries an explicit
    /// session id.
    pub sessions_count: usize,
    /// Histogram of Receipt counts keyed by `kind`.
    pub calls_by_kind: HashMap<String, usize>,
    /// Histogram of Receipt counts keyed by `pregrant_path`.
    #[serde(default)]
    pub pregrant_path_counts: HashMap<String, usize>,
}

/// Errors returned by [`run_audit_summary`].
#[derive(Debug)]
pub enum SummaryError {
    /// Could not open the SQLite store (file missing, permission denied,
    /// corrupted header). The path is surfaced so the operator can
    /// investigate.
    OpenStore {
        path: std::path::PathBuf,
        source: rusqlite::Error,
    },
    /// Underlying SQLite error during the query itself.
    Sqlite(rusqlite::Error),
    /// `receipt_json` column held bytes that didn't deserialize as JSON.
    /// We surface this rather than silently dropping the row so a
    /// corrupted Receipt is visible to the operator (matches
    /// `query::QueryError::InvalidReceiptJson`).
    InvalidReceiptJson {
        id: String,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for SummaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenStore { path, source } => {
                write!(f, "open receipts store at {}: {source}", path.display())
            }
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::InvalidReceiptJson { id, source } => {
                write!(f, "receipt {id} has invalid receipt_json: {source}")
            }
        }
    }
}

impl std::error::Error for SummaryError {}

impl From<rusqlite::Error> for SummaryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// Run a direct-SQLite aggregation against the receipts table.
///
/// Opens the DB read-only (`SQLITE_OPEN_READ_ONLY`) so a concurrent
/// daemon write does not contend on the same connection's write lock,
/// and so the CLI cannot accidentally mutate the audit trail. The
/// WHERE-clause shape (persona / since / workflow with v1+v2 JSON1
/// extraction) mirrors `query::run_audit_query_direct` exactly so the
/// two surfaces stay consistent for the operator.
pub fn run_audit_summary(
    db_path: &Path,
    filter: &SummaryFilter,
) -> Result<AuditSummary, SummaryError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| SummaryError::OpenStore {
        path: db_path.to_path_buf(),
        source: e,
    })?;

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(persona) = filter.persona.as_deref() {
        clauses.push(format!("persona_id = ?{}", params.len() + 1));
        params.push(persona.to_string());
    }
    if let Some(since) = filter.since_iso.as_deref() {
        clauses.push(format!("created_at >= ?{}", params.len() + 1));
        params.push(since.to_string());
    }
    if let Some(delegation) = filter.delegation.as_deref() {
        let p1 = params.len() + 1;
        let p2 = params.len() + 2;
        clauses.push(format!(
            "(json_extract(receipt_json, '$.body.delegation_id') = ?{p1} \
              OR json_extract(receipt_json, '$.body.delegation_template') = ?{p1} \
              OR json_extract(receipt_json, '$.delegation_id') = ?{p2} \
              OR json_extract(receipt_json, '$.delegation_template') = ?{p2})"
        ));
        params.push(delegation.to_string());
        params.push(delegation.to_string());
    }

    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let sql = format!("SELECT id, kind, persona_id, receipt_json FROM receipts {where_clause}");

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    let mut total_receipts: usize = 0;
    let mut personas: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut calls_by_kind: HashMap<String, usize> = HashMap::new();
    let mut pregrant_path_counts: HashMap<String, usize> = HashMap::new();
    for r in rows {
        let (id, kind, persona_id, receipt_json) = r?;
        // Parse the receipt_json for early-detection of corruption,
        // matching the query path. Also extract pregrant_path from the
        // Receipt body so the summary command can prove standing-grant
        // routing without falling back to a raw query.
        let receipt = match serde_json::from_str::<Value>(&receipt_json) {
            Ok(v) => v,
            Err(e) => return Err(SummaryError::InvalidReceiptJson { id, source: e }),
        };
        let pregrant_path =
            extract_pregrant_path(&receipt).unwrap_or_else(|| MISSING_PREGRANT_PATH.to_string());
        total_receipts += 1;
        personas.insert(persona_id);
        *calls_by_kind.entry(kind).or_insert(0) += 1;
        *pregrant_path_counts.entry(pregrant_path).or_insert(0) += 1;
    }

    Ok(AuditSummary {
        total_receipts,
        sessions_count: personas.len(),
        calls_by_kind,
        pregrant_path_counts,
    })
}

/// Extract `pregrant_path` from a parsed Receipt JSON value. Tries the
/// v2 `body.pregrant_path` path first, then the v1 top-level path.
fn extract_pregrant_path(v: &Value) -> Option<String> {
    v.pointer("/body/pregrant_path")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("pregrant_path").and_then(|x| x.as_str()))
        .map(str::to_string)
}

/// Render a summary as a human-readable block. Mirrors the
/// header-then-rows shape of `query::format_summaries_pretty` but for an
/// aggregate (not per-row) projection. Kinds are sorted alphabetically
/// for stable operator output.
pub fn format_summary_pretty(s: &AuditSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!("total receipts: {}\n", s.total_receipts));
    out.push_str(&format!("sessions:       {}\n", s.sessions_count));
    if s.calls_by_kind.is_empty() {
        out.push_str("calls by kind:  (none)\n");
    } else {
        out.push_str("calls by kind:\n");
        let mut kinds: Vec<(&String, &usize)> = s.calls_by_kind.iter().collect();
        kinds.sort_by(|a, b| a.0.cmp(b.0));
        for (kind, count) in kinds {
            out.push_str(&format!("  {kind:<28}  {count}\n"));
        }
    }
    if s.pregrant_path_counts.is_empty() {
        out.push_str("pregrant paths: (none)\n");
    } else {
        out.push_str("pregrant paths:\n");
        let mut paths: Vec<(&String, &usize)> = s.pregrant_path_counts.iter().collect();
        paths.sort_by(|a, b| a.0.cmp(b.0));
        for (path, count) in paths {
            out.push_str(&format!("  {path:<28}  {count}\n"));
        }
    }
    out
}

/// Render a summary as JSON. `pretty=true` indents for human
/// consumption; `pretty=false` packs onto one line for downstream `jq`
/// pipelines.
pub fn format_summary_json(s: &AuditSummary, pretty: bool) -> Result<String, serde_json::Error> {
    if pretty {
        serde_json::to_string_pretty(s)
    } else {
        serde_json::to_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(path: &Path) -> Connection {
        let conn = Connection::open(path).expect("open");
        conn.execute_batch(
            "CREATE TABLE receipts (
                id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL,
                persona_id TEXT NOT NULL,
                terminal_reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                signer_pubkey TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'grant'
            );",
        )
        .expect("create");
        conn
    }

    fn insert(
        conn: &Connection,
        id: &str,
        persona: &str,
        kind: &str,
        created_at: &str,
        receipt_json: &str,
    ) {
        conn.execute(
            "INSERT INTO receipts (id, grant_id, persona_id, terminal_reason, \
             created_at, receipt_json, signer_pubkey, kind) \
             VALUES (?1, '', ?2, '\"expired\"', ?3, ?4, '', ?5)",
            rusqlite::params![id, persona, created_at, receipt_json, kind],
        )
        .expect("insert");
    }

    #[test]
    fn summary_empty_store_returns_zeroes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        drop(conn);
        let s = run_audit_summary(&db, &SummaryFilter::default()).expect("query");
        assert_eq!(s.total_receipts, 0);
        assert_eq!(s.sessions_count, 0);
        assert!(s.calls_by_kind.is_empty());
        assert!(s.pregrant_path_counts.is_empty());
    }

    #[test]
    fn summary_single_receipt_counts_one() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let s = run_audit_summary(&db, &SummaryFilter::default()).expect("query");
        assert_eq!(s.total_receipts, 1);
        assert_eq!(s.sessions_count, 1);
        assert_eq!(s.calls_by_kind.get("grant"), Some(&1));
        assert_eq!(s.pregrant_path_counts.get("missing"), Some(&1));
    }

    #[test]
    fn summary_multiple_receipts_aggregate_by_kind_and_persona() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-a",
            "kms_wrap",
            "2026-05-19T13:00:00Z",
            r#"{"body":{}}"#,
        );
        insert(
            &conn,
            "r3",
            "persona-b",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{}}"#,
        );
        insert(
            &conn,
            "r4",
            "persona-c",
            "grant",
            "2026-05-20T14:00:00Z",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let s = run_audit_summary(&db, &SummaryFilter::default()).expect("query");
        assert_eq!(s.total_receipts, 4);
        assert_eq!(s.sessions_count, 3);
        assert_eq!(s.calls_by_kind.get("grant"), Some(&3));
        assert_eq!(s.calls_by_kind.get("kms_wrap"), Some(&1));
        assert_eq!(s.pregrant_path_counts.get("missing"), Some(&4));
    }

    #[test]
    fn summary_aggregates_pregrant_path_from_body_and_top_level() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "broker.materialization",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"pregrant_path":"standing_grant"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-a",
            "broker.materialization",
            "2026-05-19T13:00:00Z",
            r#"{"pregrant_path":"per_action"}"#,
        );
        insert(
            &conn,
            "r3",
            "persona-b",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let s = run_audit_summary(&db, &SummaryFilter::default()).expect("query");
        assert_eq!(s.pregrant_path_counts.get("standing_grant"), Some(&1));
        assert_eq!(s.pregrant_path_counts.get("per_action"), Some(&1));
        assert_eq!(s.pregrant_path_counts.get("missing"), Some(&1));
    }

    #[test]
    fn summary_filters_by_persona() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-b",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let s = run_audit_summary(
            &db,
            &SummaryFilter {
                persona: Some("persona-a".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(s.total_receipts, 1);
        assert_eq!(s.sessions_count, 1);
        assert_eq!(s.calls_by_kind.get("grant"), Some(&1));
    }

    #[test]
    fn summary_filters_by_delegation_template() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"delegation_template":"emberd-development"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-a",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{"delegation_template":"emberd-staging"}}"#,
        );
        drop(conn);
        let s = run_audit_summary(
            &db,
            &SummaryFilter {
                delegation: Some("emberd-development".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(s.total_receipts, 1);
        assert_eq!(s.sessions_count, 1);
    }

    #[test]
    fn summary_missing_db_returns_open_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("nonexistent.db");
        let err = run_audit_summary(&db, &SummaryFilter::default()).expect_err("must error");
        assert!(matches!(err, SummaryError::OpenStore { .. }));
    }

    #[test]
    fn format_pretty_renders_kinds_sorted() {
        let mut calls_by_kind = HashMap::new();
        calls_by_kind.insert("grant".to_string(), 3);
        calls_by_kind.insert("kms_wrap".to_string(), 1);
        let s = AuditSummary {
            total_receipts: 4,
            sessions_count: 2,
            calls_by_kind,
            pregrant_path_counts: HashMap::new(),
        };
        let out = format_summary_pretty(&s);
        assert!(out.contains("total receipts: 4"));
        assert!(out.contains("sessions:       2"));
        // alphabetical: grant < kms_wrap
        let g_idx = out.find("grant").expect("grant");
        let k_idx = out.find("kms_wrap").expect("kms_wrap");
        assert!(g_idx < k_idx);
    }

    #[test]
    fn format_pretty_no_kinds_emits_none() {
        let s = AuditSummary::default();
        let out = format_summary_pretty(&s);
        assert!(out.contains("(none)"));
    }

    #[test]
    fn format_pretty_renders_pregrant_paths_sorted() {
        let mut pregrant_path_counts = HashMap::new();
        pregrant_path_counts.insert("standing_grant".to_string(), 3);
        pregrant_path_counts.insert("missing".to_string(), 1);
        let s = AuditSummary {
            total_receipts: 4,
            sessions_count: 2,
            calls_by_kind: HashMap::new(),
            pregrant_path_counts,
        };
        let out = format_summary_pretty(&s);
        assert!(out.contains("pregrant paths:"));
        assert!(out.contains("standing_grant"));
        assert!(out.contains("missing"));
        let m_idx = out.find("missing").expect("missing");
        let s_idx = out.find("standing_grant").expect("standing_grant");
        assert!(m_idx < s_idx);
    }

    #[test]
    fn format_json_round_trips() {
        let mut calls_by_kind = HashMap::new();
        calls_by_kind.insert("grant".to_string(), 2);
        let s = AuditSummary {
            total_receipts: 2,
            sessions_count: 1,
            calls_by_kind,
            pregrant_path_counts: HashMap::from([("standing_grant".to_string(), 2)]),
        };
        let encoded = format_summary_json(&s, false).expect("encode");
        let decoded: AuditSummary = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
        // pretty form is multi-line
        let pretty = format_summary_json(&s, true).expect("encode pretty");
        assert!(pretty.contains('\n'));
    }
}
