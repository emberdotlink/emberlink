//!
//! `ember audit query` — direct-SQLite Receipt query path.
//!
//! Anchor: `audit_query_cli_landed`.
//!
//! Per design §Component 3, the audit query CLI does its own aggregation
//! by opening the receipts SQLite store read-only — no daemon RPC round
//! trip. This keeps the operator's primary query surface available even
//! when the daemon is not running (post-mortem investigation, dev loops,
//! recovery scenarios), and avoids pushing aggregation logic into the
//! daemon's hot socket path.
//!
//! The store schema is owned by `ember_daemon::infra::store` (the
//! `receipts` table is created during daemon `init_db` and reused here as
//! a read-only contract — column names and types live there). The CLI
//! never writes to the DB.
//!
//! ## MVP filter surface (this module)
//!
//! - `--since DUR` / `--since ISO` — lower bound on `created_at`.
//! - `--workflow NAME` — match `workflow_id` OR `workflow_template`
//!   extracted from `receipt_json` via SQLite JSON1.
//! - `--persona ID` — exact match on `persona_id`.
//! - `--limit N` — cap rows returned (default 100; same default as the
//!   daemon's `ReceiptFilter`).
//!
//! Additional filters (`--action`, `--include-dev`, `--mock-only`,
//! `--denied-only`), `show <id>`, `chain <invocation_id>`, csv/cbor
//! output, the T2 perf test at 1000 Receipts, and the group-permission
//! setup are deferred to follow-up tasks.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Direct-SQLite query filter for `ember audit query`.
///
/// All fields are optional; omitting them returns all receipts up to
/// `limit`. Filters AND-combine.
#[derive(Debug, Default, Clone)]
pub struct QueryFilter {
    /// ISO-8601 lower bound on `created_at`. Caller is responsible for
    /// parsing user input via [`parse_since`] and rendering to RFC3339.
    pub since_iso: Option<String>,
    /// Exact match on either `workflow_id` or `workflow_template`
    /// extracted from `receipt_json` via JSON1. Operators typically pass
    /// a template name (e.g. `emberd-development`); falling back to the
    /// ULID `workflow_id` lets per-run drilldowns work too.
    pub workflow: Option<String>,
    /// Exact match on `persona_id`.
    pub persona: Option<String>,
    /// Maximum rows. Defaults to 100 when `None`.
    pub limit: Option<u64>,
}

/// Flat per-Receipt summary returned by [`run_audit_query_direct`].
///
/// Mirrors the operator-facing fields the audit CLI needs without
/// embedding the full v2 `ReceiptEnvelope` / v1 `GrantReceipt` body — a
/// 1-line-per-Receipt projection optimized for table and JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptSummary {
    /// Receipt id (`receipts.id`).
    pub id: String,
    /// `grant`, `kms_wrap`, `kms_unwrap`, or `broker.materialization` etc.
    pub kind: String,
    /// Persona id of the actor that triggered this Receipt.
    pub persona_id: String,
    /// Workflow grant id from the Receipt body (`None` for system-class
    /// Receipts and pre-rollout rows).
    pub workflow_id: Option<String>,
    /// Workflow template name from the Receipt body.
    pub workflow_template: Option<String>,
    /// ISO-8601 timestamp from `receipts.created_at`.
    pub created_at: String,
    /// Terminal reason (JSON-encoded — passed through verbatim).
    pub terminal_reason: String,
}

/// Errors returned by [`run_audit_query_direct`].
#[derive(Debug)]
pub enum QueryError {
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
    /// corrupted Receipt is visible to the operator.
    InvalidReceiptJson { id: String, source: serde_json::Error },
}

impl std::fmt::Display for QueryError {
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

impl std::error::Error for QueryError {}

impl From<rusqlite::Error> for QueryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// Run a direct-SQLite query against the receipts table.
///
/// Opens the DB read-only (`SQLITE_OPEN_READ_ONLY`) so a concurrent
/// daemon write does not contend on the same connection's write lock,
/// and so the CLI cannot accidentally mutate the audit trail.
///
/// The query AND-combines filters. Workflow filtering uses SQLite JSON1
/// to extract `workflow_id` / `workflow_template` from `receipt_json`
/// without requiring a schema migration. Rows whose `receipt_json` is
/// well-formed JSON but missing the workflow fields are excluded when
/// the workflow filter is set — operators expect zero hits when the
/// requested workflow has no Receipts.
pub fn run_audit_query_direct(
    db_path: &Path,
    filter: &QueryFilter,
) -> Result<Vec<ReceiptSummary>, QueryError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| QueryError::OpenStore {
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
    if let Some(workflow) = filter.workflow.as_deref() {
        // JSON1 extraction — match either the ULID workflow_id or the
        // human-readable workflow_template. AND-combined with the other
        // filters; OR-combined internally so operators can pass either
        // shape without knowing which one is populated for a given row.
        let p1 = params.len() + 1;
        let p2 = params.len() + 2;
        clauses.push(format!(
            "(json_extract(receipt_json, '$.body.workflow_id') = ?{p1} \
              OR json_extract(receipt_json, '$.body.workflow_template') = ?{p1} \
              OR json_extract(receipt_json, '$.workflow_id') = ?{p2} \
              OR json_extract(receipt_json, '$.workflow_template') = ?{p2})"
        ));
        params.push(workflow.to_string());
        params.push(workflow.to_string());
    }

    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    let limit = filter.limit.unwrap_or(100);
    let sql = format!(
        "SELECT id, kind, persona_id, terminal_reason, created_at, receipt_json \
         FROM receipts {where_clause} ORDER BY created_at DESC LIMIT {limit}"
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;

    let mut out: Vec<ReceiptSummary> = Vec::new();
    for r in rows {
        let (id, kind, persona_id, terminal_reason, created_at, receipt_json) = r?;
        // Parse just enough of receipt_json to surface the workflow
        // fields. We tolerate either v1 (top-level) or v2 (nested under
        // `body`) shapes — `extract_workflow_fields` returns `(None,
        // None)` if neither matches, which is fine for system-class
        // Receipts.
        let (workflow_id, workflow_template) = match serde_json::from_str::<Value>(&receipt_json) {
            Ok(v) => extract_workflow_fields(&v),
            Err(e) => {
                return Err(QueryError::InvalidReceiptJson { id, source: e });
            }
        };
        out.push(ReceiptSummary {
            id,
            kind,
            persona_id,
            workflow_id,
            workflow_template,
            created_at,
            terminal_reason,
        });
    }
    Ok(out)
}

/// Extract `(workflow_id, workflow_template)` from a parsed Receipt
/// JSON value. Tries the v2 `body.workflow_id` path first, then the
/// v1 top-level path. Returns `(None, None)` for rows that carry
/// neither (system-class Receipts, pre-rollout rows).
fn extract_workflow_fields(v: &Value) -> (Option<String>, Option<String>) {
    let body_wid = v
        .pointer("/body/workflow_id")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let body_tmpl = v
        .pointer("/body/workflow_template")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    if body_wid.is_some() || body_tmpl.is_some() {
        return (body_wid, body_tmpl);
    }
    let top_wid = v
        .get("workflow_id")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let top_tmpl = v
        .get("workflow_template")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    (top_wid, top_tmpl)
}

/// Parse a `--since` argument into an RFC3339 string.
///
/// Accepts either an ISO-8601 timestamp (`2026-04-01T00:00:00Z`) or a
/// relative duration (`1d`, `7d`, `24h`, `30m`, `45s`). Relative values
/// are resolved against `now` and returned as RFC3339 so the SQL `>=`
/// comparison uses canonical string-sort order against
/// `receipts.created_at` (which is stored as
/// `Utc::now().to_rfc3339()`).
///
/// Returns `None` for malformed input — callers surface a clean usage
/// error to the operator instead of silently passing an unparseable
/// string through to the SQL layer.
pub fn parse_since(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&chrono::Utc).to_rfc3339());
    }
    let secs = parse_duration(trimmed)?;
    let now = chrono::Utc::now();
    let cutoff = now.checked_sub_signed(chrono::Duration::seconds(secs))?;
    Some(cutoff.to_rfc3339())
}

/// Parse a short relative-duration string into seconds.
///
/// Recognises a non-negative integer immediately followed by one of
/// `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Returns
/// `None` for any other shape — callers translate that into a usage
/// error for the operator.
fn parse_duration(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let (num, unit) = bytes.split_at(bytes.len() - 1);
    let n: i64 = std::str::from_utf8(num).ok()?.parse().ok()?;
    if n < 0 {
        return None;
    }
    let mult = match unit[0] {
        b's' => 1,
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86_400,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Render a list of summaries as a one-line-per-Receipt pretty table,
/// closing with a `total: N` summary line. Mirrors `verify.rs`'s
/// per-Receipt verdict + aggregate header pattern.
pub fn format_summaries_pretty(rows: &[ReceiptSummary]) -> String {
    if rows.is_empty() {
        return "No receipts match the supplied filters.\n".to_string();
    }
    let mut out = String::new();
    let h_kind = "KIND";
    let h_persona = "PERSONA";
    let h_workflow = "WORKFLOW";
    let h_when = "CREATED_AT";
    let h_reason = "REASON";
    out.push_str(&format!(
        "{h_kind:<22}  {h_persona:<22}  {h_workflow:<32}  {h_when:<28}  {h_reason}\n"
    ));
    for r in rows {
        let workflow = r
            .workflow_template
            .as_deref()
            .or(r.workflow_id.as_deref())
            .unwrap_or("-");
        let reason_short: String = r.terminal_reason.chars().take(40).collect();
        out.push_str(&format!(
            "{:<22}  {:<22}  {:<32}  {:<28}  {}\n",
            truncate(&r.kind, 22),
            truncate(&r.persona_id, 22),
            truncate(workflow, 32),
            truncate(&r.created_at, 28),
            reason_short,
        ));
    }
    out.push_str(&format!("total: {}\n", rows.len()));
    out
}

/// Render summaries as compact JSON (one `Vec<ReceiptSummary>` blob).
/// `pretty=true` indents for human consumption; `pretty=false` packs
/// onto one line for downstream `jq` pipelines.
pub fn format_summaries_json(rows: &[ReceiptSummary], pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_string())
    } else {
        serde_json::to_string(rows).unwrap_or_else(|_| "[]".to_string())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
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
    fn extracts_workflow_from_v2_body() {
        let v: Value = serde_json::from_str(
            r#"{"body":{"workflow_id":"wfg_01HQ0EXAMPLE","workflow_template":"emberd-development"}}"#,
        )
        .unwrap();
        let (wid, tmpl) = extract_workflow_fields(&v);
        assert_eq!(wid.as_deref(), Some("wfg_01HQ0EXAMPLE"));
        assert_eq!(tmpl.as_deref(), Some("emberd-development"));
    }

    #[test]
    fn extracts_workflow_from_v1_top_level() {
        let v: Value =
            serde_json::from_str(r#"{"workflow_id":"wfg_top","workflow_template":"top-tmpl"}"#)
                .unwrap();
        let (wid, tmpl) = extract_workflow_fields(&v);
        assert_eq!(wid.as_deref(), Some("wfg_top"));
        assert_eq!(tmpl.as_deref(), Some("top-tmpl"));
    }

    #[test]
    fn extracts_workflow_returns_none_for_system_receipts() {
        let v: Value = serde_json::from_str(r#"{"body":{"claim_events":[]}}"#).unwrap();
        let (wid, tmpl) = extract_workflow_fields(&v);
        assert_eq!(wid, None);
        assert_eq!(tmpl, None);
    }

    #[test]
    fn parse_since_accepts_iso8601() {
        let got = parse_since("2026-04-01T00:00:00Z").expect("parse");
        // RFC3339 normalisation: parse + render to UTC → stable form.
        assert!(got.starts_with("2026-04-01T00:00:00"));
    }

    #[test]
    fn parse_since_accepts_relative_days() {
        let got = parse_since("7d").expect("parse 7d");
        let parsed = chrono::DateTime::parse_from_rfc3339(&got).expect("rfc3339");
        let delta = chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc));
        assert!(delta.num_seconds() >= (7 * 86_400) - 5);
        assert!(delta.num_seconds() <= (7 * 86_400) + 5);
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since("nonsense").is_none());
        assert!(parse_since("").is_none());
        assert!(parse_since("7x").is_none());
    }

    #[test]
    fn parse_duration_handles_units() {
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("1d"), Some(86_400));
        assert_eq!(parse_duration("0s"), Some(0));
        assert_eq!(parse_duration("-1d"), None);
        assert_eq!(parse_duration("abc"), None);
    }

    #[test]
    fn direct_query_returns_all_with_no_filters() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"workflow_id":"w1","workflow_template":"tmpl1"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-b",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{"workflow_id":"w2","workflow_template":"tmpl2"}}"#,
        );
        drop(conn);
        let rows =
            run_audit_query_direct(&db, &QueryFilter::default()).expect("query");
        assert_eq!(rows.len(), 2);
        // ORDER BY created_at DESC
        assert_eq!(rows[0].id, "r2");
        assert_eq!(rows[1].id, "r1");
        assert_eq!(rows[0].workflow_id.as_deref(), Some("w2"));
        assert_eq!(rows[0].workflow_template.as_deref(), Some("tmpl2"));
    }

    #[test]
    fn direct_query_filters_by_persona() {
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
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                persona: Some("persona-a".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "r1");
    }

    #[test]
    fn direct_query_filters_by_since() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r-old",
            "persona-a",
            "grant",
            "2026-04-01T00:00:00+00:00",
            r#"{"body":{}}"#,
        );
        insert(
            &conn,
            "r-new",
            "persona-a",
            "grant",
            "2026-05-20T00:00:00+00:00",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                since_iso: Some("2026-05-01T00:00:00+00:00".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "r-new");
    }

    #[test]
    fn direct_query_filters_by_workflow_template() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"workflow_id":"w1","workflow_template":"emberd-development"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-a",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{"workflow_id":"w2","workflow_template":"emberd-staging"}}"#,
        );
        insert(
            &conn,
            "r3",
            "persona-a",
            "grant",
            "2026-05-20T13:00:00Z",
            r#"{"body":{}}"#,
        );
        drop(conn);
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                workflow: Some("emberd-development".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "r1");
    }

    #[test]
    fn direct_query_filters_by_workflow_id() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"workflow_id":"wfg_01HQ0EXAMPLE","workflow_template":"tmpl"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-a",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{"workflow_id":"wfg_OTHER","workflow_template":"tmpl"}}"#,
        );
        drop(conn);
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                workflow: Some("wfg_01HQ0EXAMPLE".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "r1");
    }

    #[test]
    fn direct_query_filters_and_combine() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        insert(
            &conn,
            "r1",
            "persona-a",
            "grant",
            "2026-05-19T12:00:00Z",
            r#"{"body":{"workflow_template":"tmpl"}}"#,
        );
        insert(
            &conn,
            "r2",
            "persona-b",
            "grant",
            "2026-05-20T12:00:00Z",
            r#"{"body":{"workflow_template":"tmpl"}}"#,
        );
        drop(conn);
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                persona: Some("persona-a".to_string()),
                workflow: Some("tmpl".to_string()),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "r1");
    }

    #[test]
    fn direct_query_respects_limit() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("daemon.db");
        let conn = make_db(&db);
        for i in 0..5 {
            insert(
                &conn,
                &format!("r{i}"),
                "persona-a",
                "grant",
                &format!("2026-05-{:02}T12:00:00Z", 10 + i),
                r#"{"body":{}}"#,
            );
        }
        drop(conn);
        let rows = run_audit_query_direct(
            &db,
            &QueryFilter {
                limit: Some(2),
                ..Default::default()
            },
        )
        .expect("query");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn direct_query_missing_db_returns_open_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let db = dir.path().join("nonexistent.db");
        let err = run_audit_query_direct(&db, &QueryFilter::default())
            .expect_err("must error");
        assert!(matches!(err, QueryError::OpenStore { .. }));
    }

    #[test]
    fn format_pretty_empty_returns_no_match_line() {
        let s = format_summaries_pretty(&[]);
        assert!(s.contains("No receipts"));
    }

    #[test]
    fn format_pretty_includes_columns_and_total() {
        let rows = vec![ReceiptSummary {
            id: "r1".to_string(),
            kind: "grant".to_string(),
            persona_id: "persona-a".to_string(),
            workflow_id: Some("w1".to_string()),
            workflow_template: Some("tmpl1".to_string()),
            created_at: "2026-05-20T12:00:00Z".to_string(),
            terminal_reason: "\"expired\"".to_string(),
        }];
        let s = format_summaries_pretty(&rows);
        assert!(s.contains("KIND"));
        assert!(s.contains("PERSONA"));
        assert!(s.contains("WORKFLOW"));
        assert!(s.contains("tmpl1"));
        assert!(s.contains("total: 1"));
    }

    #[test]
    fn format_json_round_trips() {
        let rows = vec![ReceiptSummary {
            id: "r1".to_string(),
            kind: "grant".to_string(),
            persona_id: "persona-a".to_string(),
            workflow_id: None,
            workflow_template: None,
            created_at: "2026-05-20T12:00:00Z".to_string(),
            terminal_reason: "\"expired\"".to_string(),
        }];
        let s = format_summaries_json(&rows, false);
        let back: Vec<ReceiptSummary> = serde_json::from_str(&s).expect("round trip");
        assert_eq!(back, rows);
    }
}
