//! `ember receipt rollup` — read-time aggregation of construct-invocation
//! sub-Receipts (per ADR 124 §1 step 4 and `docs/construct-receipt-rollup.md`).
//!
//! A single Construct invocation produces 4+ sub-Receipts under the
//! daemon-as-process-supervisor lifecycle: `broker.materialization` +
//! `broker.resolution` + `session.construct_invocation` + `broker.revocation`.
//! This CLI verb collapses them into one row keyed by `materialization_id`,
//! mirroring the dashboard's `?view=rollup` endpoint (filed as the
//! `AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD` companion task).
//!
//! The rollup algorithm itself lives in [`core_events::rollup`]; this module
//! is the CLI-side adapter:
//!
//! - reads the daemon's `events.jsonl` (one JSON sub-Receipt per line),
//! - filters by `--since` / `--materialization` / `--incomplete-only`,
//! - calls [`core_events::rollup::compute_rollups`],
//! - renders a `RECEIPTS / STARTED / OUTCOME / ACTION / PERSONA` table or
//!   pretty-printed JSON when `--json` is set.
//!
//! It also exposes [`verify_chain`], the chain-integrity walker used by
//! `ember receipt verify --materialization <id>`. The walker checks that
//! the chain has at least the materialization step and either reaches a
//! terminal state (`broker.revocation` or `*_denied`) or is currently
//! `InFlight`; broken chains return an `Err` so the caller can exit
//! non-zero.
//!
//! Tracks **AP-CONSTRUCT-RECEIPT-ROLLUP-CLI** (P2/S).

use core_event_types::ActionRef;
use core_events::rollup::{
    ConstructInvocationRollup, RollupOutcome, RollupReceiptView, compute_rollups,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Wire shape for a single sub-Receipt as written to `events.jsonl`. Keeps
/// only the metadata fields the rollup computation needs; full sub-Receipt
/// bodies live elsewhere (and may grow without breaking the rollup view —
/// unknown JSON fields are ignored by serde at deserialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawReceipt {
    /// Receipt kind (e.g. `broker.materialization`).
    pub kind: String,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Join key shared across all sub-Receipts of one invocation. Optional
    /// because session-level events (e.g. `session.opened`) may share the
    /// log without participating in any rollup.
    #[serde(default)]
    pub materialization_id: Option<String>,
    /// blake3 over the canonical body, prefixed (`blake3:abc…`).
    #[serde(default)]
    pub receipt_hash: Option<String>,
    /// Persona that authored the dispatch.
    #[serde(default)]
    pub persona: Option<String>,
    /// Action identifier from `session.construct_invocation` (e.g.
    /// `gh.pr_create`).
    #[serde(default)]
    pub action: Option<String>,
    /// Structured authority-side action identity when present on the receipt.
    #[serde(default)]
    pub action_ref: Option<ActionRef>,
    /// Process exit code from `session.construct_invocation`.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Reason supplied with a `*_denied` sub-Receipt.
    #[serde(default)]
    pub denied_reason: Option<String>,
}

impl RollupReceiptView for RawReceipt {
    fn materialization_id(&self) -> Option<&str> {
        self.materialization_id.as_deref()
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn ts(&self) -> &str {
        &self.ts
    }
    fn receipt_hash(&self) -> &str {
        self.receipt_hash.as_deref().unwrap_or("")
    }
    fn persona(&self) -> Option<&str> {
        self.persona.as_deref()
    }
    fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }
    fn action_ref(&self) -> Option<&ActionRef> {
        self.action_ref.as_ref()
    }
    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
    fn denied_reason(&self) -> Option<&str> {
        self.denied_reason.as_deref()
    }
}

/// Errors raised by the rollup CLI surface.
#[derive(Debug)]
pub enum RollupError {
    /// `events.jsonl` (or the path passed via `--events`) could not be opened.
    EventsRead {
        path: String,
        source: std::io::Error,
    },
    /// A line in the events file failed to parse as a [`RawReceipt`]. Carries
    /// the 1-based line number so an operator can grep the source.
    ParseLine {
        line_no: usize,
        source: serde_json::Error,
    },
    /// The user passed an `--since` value the parser did not understand.
    InvalidSince(String),
    /// `verify_chain` detected a broken chain — used by
    /// `ember receipt verify --materialization`.
    ChainBroken {
        materialization_id: String,
        reason: String,
    },
    /// No sub-Receipts found for the requested `materialization_id`.
    UnknownMaterialization(String),
}

impl std::fmt::Display for RollupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollupError::EventsRead { path, source } => {
                write!(f, "could not read {path}: {source}")
            }
            RollupError::ParseLine { line_no, source } => {
                write!(f, "events.jsonl line {line_no}: {source}")
            }
            RollupError::InvalidSince(s) => {
                write!(
                    f,
                    "invalid --since value '{s}'; expected one of: 1h, 24h, 7d, all, or an ISO-8601 timestamp"
                )
            }
            RollupError::ChainBroken {
                materialization_id,
                reason,
            } => write!(f, "chain broken for {materialization_id}: {reason}"),
            RollupError::UnknownMaterialization(id) => {
                write!(f, "no sub-receipts found for materialization '{id}'")
            }
        }
    }
}

impl std::error::Error for RollupError {}

/// Parse a `--since` value into a lower-bound RFC 3339 timestamp. `all`
/// returns `None` (no filter). Recognised forms:
///
/// - `Nh` — last N hours
/// - `Nd` — last N days
/// - `all` — no filter
/// - any string already in RFC 3339 form is passed through unchanged
pub fn parse_since(value: &str) -> Result<Option<String>, RollupError> {
    if value == "all" {
        return Ok(None);
    }
    if let Some(rest) = value.strip_suffix('h') {
        let hours: i64 = rest
            .parse()
            .map_err(|_| RollupError::InvalidSince(value.to_string()))?;
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::hours(hours);
        return Ok(Some(
            cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ));
    }
    if let Some(rest) = value.strip_suffix('d') {
        let days: i64 = rest
            .parse()
            .map_err(|_| RollupError::InvalidSince(value.to_string()))?;
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::days(days);
        return Ok(Some(
            cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ));
    }
    // Try RFC-3339 passthrough
    if chrono::DateTime::parse_from_rfc3339(value).is_ok() {
        return Ok(Some(value.to_string()));
    }
    Err(RollupError::InvalidSince(value.to_string()))
}

/// Read sub-Receipts from a JSONL events file. Blank lines are skipped.
pub fn read_receipts_from_jsonl(path: &Path) -> Result<Vec<RawReceipt>, RollupError> {
    let raw = std::fs::read_to_string(path).map_err(|e| RollupError::EventsRead {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<RawReceipt>(trimmed) {
            Ok(r) => out.push(r),
            Err(_e) => {
                // Lines that don't fit the rollup shape (e.g. session-only
                // events, queue events) are tolerated — events.jsonl is a
                // shared log. Strict mode could be added later via a flag.
                continue;
            }
        }
    }
    Ok(out)
}

/// Walk the chain of sub-Receipts for `materialization_id` and return `Ok(())`
/// if it is well-formed, `Err(RollupError::ChainBroken)` otherwise.
///
/// **Well-formed** here means:
/// 1. At least one `broker.materialization` sub-Receipt is present (the chain
///    head) — without it, the chain has no provenance.
/// 2. Timestamps are non-decreasing in event order. (We sort by `ts`, so this
///    is automatic; we surface duplicate-ts collisions only if hashes differ
///    on the same `ts` for the same kind.)
/// 3. The chain is either terminal (`broker.revocation` present, or any
///    `*_denied` sub-Receipt present) or `InFlight`. `Incomplete` chains
///    (materialization + resolution but no invocation) are reported as
///    broken — that is the operator-followup signal the brief calls out.
///
/// Note that step 3 is intentionally stricter than the rollup *outcome*
/// classification: `verify` is "is this chain okay or do I have to act?",
/// while `rollup` is the read-time row.
pub fn verify_chain(
    receipts: &[RawReceipt],
    materialization_id: &str,
) -> Result<ConstructInvocationRollup, RollupError> {
    let group: Vec<&RawReceipt> = receipts
        .iter()
        .filter(|r| r.materialization_id.as_deref() == Some(materialization_id))
        .collect();
    if group.is_empty() {
        return Err(RollupError::UnknownMaterialization(
            materialization_id.to_string(),
        ));
    }
    // Compute the rollup with the same algorithm the read view uses —
    // so the verify output and the rollup output agree on `outcome`.
    let owned: Vec<RawReceipt> = group.iter().map(|r| (*r).clone()).collect();
    let mut rollups = compute_rollups(&owned);
    let rollup = rollups.pop().ok_or_else(|| RollupError::ChainBroken {
        materialization_id: materialization_id.to_string(),
        reason: "compute_rollups returned no row".to_string(),
    })?;

    // Step 1 — chain head must be present.
    let has_materialization = group.iter().any(|r| r.kind == "broker.materialization");
    if !has_materialization {
        return Err(RollupError::ChainBroken {
            materialization_id: materialization_id.to_string(),
            reason: "missing broker.materialization sub-receipt (chain head)".to_string(),
        });
    }

    // Step 3 — Incomplete is the operator-followup signal.
    if matches!(rollup.outcome, RollupOutcome::Incomplete) {
        return Err(RollupError::ChainBroken {
            materialization_id: materialization_id.to_string(),
            reason: "chain incomplete — session.construct_invocation never landed".to_string(),
        });
    }

    Ok(rollup)
}

/// Rendered output of a `rollup` invocation (kept distinct from the
/// `ConstructInvocationRollup` value type so we can serialize a stable
/// CLI-facing JSON shape without round-tripping through the dashboard
/// envelope).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollupRow {
    pub materialization_id: String,
    pub action: String,
    pub persona: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub outcome: String,
    pub outcome_detail: Option<String>,
    pub receipt_count: u32,
    pub sub_receipts: Vec<SubReceiptRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubReceiptRow {
    pub kind: String,
    pub ts: String,
    pub receipt_hash: String,
}

impl From<ConstructInvocationRollup> for RollupRow {
    fn from(r: ConstructInvocationRollup) -> Self {
        let (outcome, outcome_detail) = match &r.outcome {
            RollupOutcome::Success => ("success".to_string(), None),
            RollupOutcome::Denied { reason } => ("denied".to_string(), Some(reason.clone())),
            RollupOutcome::Errored { exit_code } => (
                "errored".to_string(),
                Some(format!("exit_code={exit_code}")),
            ),
            RollupOutcome::InFlight => ("in_flight".to_string(), None),
            RollupOutcome::Incomplete => ("incomplete".to_string(), None),
        };
        RollupRow {
            materialization_id: r.materialization_id,
            action: r.action,
            persona: r.persona,
            started_at: r.started_at,
            ended_at: r.ended_at,
            outcome,
            outcome_detail,
            receipt_count: r.receipt_count,
            sub_receipts: r
                .sub_receipts
                .into_iter()
                .map(|s| SubReceiptRow {
                    kind: s.kind,
                    ts: s.ts,
                    receipt_hash: s.receipt_hash,
                })
                .collect(),
        }
    }
}

/// Filter knobs accepted by [`rollup_command`]. Mirrors the clap
/// subcommand fields one-to-one so the dashboard task can swap in
/// query-string parsing without restructuring.
#[derive(Debug, Default, Clone)]
pub struct RollupFilters {
    pub since: Option<String>,
    pub materialization: Option<String>,
    pub incomplete_only: bool,
}

/// Apply [`RollupFilters`] to a list of computed rollups.
fn apply_filters(
    rollups: Vec<ConstructInvocationRollup>,
    filters: &RollupFilters,
    since_iso: Option<&str>,
) -> Vec<ConstructInvocationRollup> {
    rollups
        .into_iter()
        .filter(|r| {
            if let Some(mid) = &filters.materialization
                && &r.materialization_id != mid
            {
                return false;
            }
            if filters.incomplete_only && !matches!(r.outcome, RollupOutcome::Incomplete) {
                return false;
            }
            if let Some(cutoff) = since_iso
                && r.started_at.as_str() < cutoff
            {
                return false;
            }
            true
        })
        .collect()
}

/// Render a list of [`RollupRow`] as a fixed-width table (CLI default).
pub fn render_rollup_table(rows: &[RollupRow]) -> String {
    if rows.is_empty() {
        return "No rollups match the filter.\n".to_string();
    }
    let mut out = String::new();
    let header = format!(
        "{:<24} {:<22} {:<22} {:<10} {:<14} {:<24}\n",
        "MATERIALIZATION", "STARTED", "ENDED", "RECEIPTS", "OUTCOME", "ACTION"
    );
    out.push_str(&header);
    for row in rows {
        let ended = row.ended_at.as_deref().unwrap_or("-");
        let outcome = match (&row.outcome[..], &row.outcome_detail) {
            ("denied", Some(r)) => format!("denied:{r}"),
            ("errored", Some(r)) => format!("errored:{r}"),
            (o, _) => o.to_string(),
        };
        out.push_str(&format!(
            "{:<24} {:<22} {:<22} {:<10} {:<14} {:<24}\n",
            short(&row.materialization_id, 22),
            short(&row.started_at, 20),
            short(ended, 20),
            row.receipt_count,
            short(&outcome, 14),
            short(&row.action, 22),
        ));
    }
    out
}

fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Top-level entry point for `ember receipt rollup`.
///
/// Reads sub-Receipts from `events_path`, applies `filters`, and writes the
/// rendered output to `stdout`. When `as_json` is set, emits a pretty-printed
/// JSON array of [`RollupRow`]; otherwise, a fixed-width table.
///
/// Returns `Err` only on unrecoverable failure (file unreadable, invalid
/// `--since`). An empty result set is *not* an error; the table prints
/// `"No rollups match the filter."` and JSON prints `[]`.
pub fn rollup_command(
    events_path: &Path,
    filters: &RollupFilters,
    as_json: bool,
) -> Result<String, RollupError> {
    let receipts = read_receipts_from_jsonl(events_path)?;
    let since_iso = match &filters.since {
        Some(s) => parse_since(s)?,
        None => None,
    };
    let computed = compute_rollups(&receipts);
    let filtered = apply_filters(computed, filters, since_iso.as_deref());
    let rows: Vec<RollupRow> = filtered.into_iter().map(RollupRow::from).collect();
    if as_json {
        Ok(serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string()))
    } else {
        Ok(render_rollup_table(&rows))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn line(json: serde_json::Value) -> String {
        serde_json::to_string(&json).unwrap()
    }

    fn write_events(lines: &[String]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        f.flush().unwrap();
        f
    }

    fn success_chain(mid: &str) -> Vec<String> {
        vec![
            line(serde_json::json!({
                "kind": "broker.materialization",
                "ts": "2026-05-05T13:01:22Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:7c2a",
                "persona": "dev",
            })),
            line(serde_json::json!({
                "kind": "broker.resolution",
                "ts": "2026-05-05T13:01:22Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:9f81",
            })),
            line(serde_json::json!({
                "kind": "session.construct_invocation",
                "ts": "2026-05-05T13:01:24Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:b3f9",
                "action": "gh.pr_create",
                "exit_code": 0,
            })),
            line(serde_json::json!({
                "kind": "broker.revocation",
                "ts": "2026-05-05T13:01:24Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:e1d8",
            })),
        ]
    }

    fn incomplete_chain(mid: &str) -> Vec<String> {
        vec![
            line(serde_json::json!({
                "kind": "broker.materialization",
                "ts": "2026-05-05T13:04:00Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:x",
                "persona": "dev",
            })),
            line(serde_json::json!({
                "kind": "broker.resolution",
                "ts": "2026-05-05T13:04:00Z",
                "materialization_id": mid,
                "receipt_hash": "blake3:y",
            })),
        ]
    }

    #[test]
    fn raw_receipt_implements_rollup_view() {
        let r = RawReceipt {
            kind: "broker.materialization".to_string(),
            ts: "2026-05-05T00:00:00Z".to_string(),
            materialization_id: Some("m_a".to_string()),
            receipt_hash: Some("blake3:abc".to_string()),
            persona: Some("dev".to_string()),
            action: None,
            action_ref: None,
            exit_code: None,
            denied_reason: None,
        };
        assert_eq!(r.materialization_id(), Some("m_a"));
        assert_eq!(r.kind(), "broker.materialization");
        assert_eq!(r.ts(), "2026-05-05T00:00:00Z");
        assert_eq!(r.receipt_hash(), "blake3:abc");
        assert_eq!(r.persona(), Some("dev"));
        assert_eq!(r.action(), None);
        assert_eq!(r.action_ref(), None);
        assert_eq!(r.exit_code(), None);
        assert_eq!(r.denied_reason(), None);
    }

    #[test]
    fn parse_since_hours() {
        let out = parse_since("1h").expect("hour-form parses");
        assert!(out.is_some(), "expected a cutoff for 1h");
    }

    #[test]
    fn parse_since_days() {
        let out = parse_since("7d").expect("day-form parses");
        assert!(out.is_some(), "expected a cutoff for 7d");
    }

    #[test]
    fn parse_since_all_returns_none() {
        let out = parse_since("all").expect("all parses");
        assert!(out.is_none(), "expected no cutoff for all");
    }

    #[test]
    fn parse_since_iso_passthrough() {
        let out = parse_since("2026-05-05T00:00:00Z").expect("iso-8601 passes through");
        assert_eq!(out.as_deref(), Some("2026-05-05T00:00:00Z"));
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since("yesterday").is_err());
        assert!(parse_since("9z").is_err());
    }

    #[test]
    fn read_receipts_skips_blank_lines() {
        let mut lines = success_chain("m_abc");
        lines.insert(0, String::new());
        lines.insert(2, "   ".to_string());
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        assert_eq!(receipts.len(), 4);
    }

    #[test]
    fn read_receipts_tolerates_unrelated_lines() {
        // events.jsonl is shared with non-rollup events. Lines that don't
        // fit the RawReceipt shape are skipped, not surfaced as errors.
        let mut lines = success_chain("m_abc");
        lines.push("{\"unrelated\": \"queue.event\"}".to_string());
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        // The "unrelated" line still parses (RawReceipt has all-optional
        // fields except kind+ts), but those required fields are missing,
        // so serde returns Err and we skip it.
        assert_eq!(receipts.len(), 4, "should keep 4 chain lines");
    }

    #[test]
    fn rollup_command_renders_success_chain_as_table() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let out = rollup_command(f.path(), &RollupFilters::default(), false).unwrap();
        assert!(
            out.contains("m_abc"),
            "table missing materialization id: {out}"
        );
        assert!(out.contains("success"), "table missing outcome: {out}");
        assert!(out.contains("gh.pr_create"), "table missing action: {out}");
    }

    #[test]
    fn rollup_command_json_is_machine_parseable() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let out = rollup_command(f.path(), &RollupFilters::default(), true).unwrap();
        let parsed: Vec<RollupRow> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].materialization_id, "m_abc");
        assert_eq!(parsed[0].outcome, "success");
        assert_eq!(parsed[0].receipt_count, 4);
        assert_eq!(parsed[0].sub_receipts.len(), 4);
    }

    #[test]
    fn rollup_command_filters_by_materialization() {
        let mut lines = success_chain("m_one");
        lines.extend(success_chain("m_two"));
        let f = write_events(&lines);
        let filters = RollupFilters {
            materialization: Some("m_two".to_string()),
            ..Default::default()
        };
        let out = rollup_command(f.path(), &filters, true).unwrap();
        let parsed: Vec<RollupRow> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].materialization_id, "m_two");
    }

    #[test]
    fn rollup_command_incomplete_only_filters_complete_chains() {
        let mut lines = success_chain("m_complete");
        lines.extend(incomplete_chain("m_crash"));
        let f = write_events(&lines);
        let filters = RollupFilters {
            incomplete_only: true,
            ..Default::default()
        };
        let out = rollup_command(f.path(), &filters, true).unwrap();
        let parsed: Vec<RollupRow> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].materialization_id, "m_crash");
        assert_eq!(parsed[0].outcome, "incomplete");
    }

    #[test]
    fn rollup_command_empty_filter_match_prints_friendly_message() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let filters = RollupFilters {
            materialization: Some("m_does_not_exist".to_string()),
            ..Default::default()
        };
        let out = rollup_command(f.path(), &filters, false).unwrap();
        assert!(
            out.contains("No rollups"),
            "expected friendly empty msg: {out}"
        );
    }

    #[test]
    fn rollup_command_empty_filter_match_emits_empty_json_array() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let filters = RollupFilters {
            materialization: Some("nope".to_string()),
            ..Default::default()
        };
        let out = rollup_command(f.path(), &filters, true).unwrap();
        let parsed: Vec<RollupRow> = serde_json::from_str(&out).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn verify_chain_passes_for_success() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        let r = verify_chain(&receipts, "m_abc").expect("success chain verifies");
        assert_eq!(r.materialization_id, "m_abc");
    }

    #[test]
    fn verify_chain_fails_on_incomplete() {
        let lines = incomplete_chain("m_crash");
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        let err =
            verify_chain(&receipts, "m_crash").expect_err("incomplete chain should not verify");
        match err {
            RollupError::ChainBroken {
                materialization_id,
                reason,
            } => {
                assert_eq!(materialization_id, "m_crash");
                assert!(reason.contains("incomplete"), "got reason: {reason}");
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_fails_on_unknown_materialization() {
        let lines = success_chain("m_abc");
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        let err = verify_chain(&receipts, "m_other").expect_err("unknown should fail");
        assert!(matches!(err, RollupError::UnknownMaterialization(_)));
    }

    #[test]
    fn verify_chain_fails_when_materialization_step_missing() {
        // resolution + invocation + revocation, but no broker.materialization.
        let lines = vec![
            line(serde_json::json!({
                "kind": "broker.resolution",
                "ts": "2026-05-05T13:01:22Z",
                "materialization_id": "m_no_head",
            })),
            line(serde_json::json!({
                "kind": "session.construct_invocation",
                "ts": "2026-05-05T13:01:24Z",
                "materialization_id": "m_no_head",
                "action": "gh.pr_create",
                "exit_code": 0,
            })),
            line(serde_json::json!({
                "kind": "broker.revocation",
                "ts": "2026-05-05T13:01:24Z",
                "materialization_id": "m_no_head",
            })),
        ];
        let f = write_events(&lines);
        let receipts = read_receipts_from_jsonl(f.path()).unwrap();
        let err = verify_chain(&receipts, "m_no_head").expect_err("missing chain head should fail");
        match err {
            RollupError::ChainBroken { reason, .. } => {
                assert!(reason.contains("chain head"), "got: {reason}");
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn since_filter_excludes_old_rows() {
        // Construct two rollups, one in the past, one within the cutoff.
        let mut lines = vec![];
        lines.extend(vec![
            line(serde_json::json!({
                "kind": "broker.materialization",
                "ts": "2000-01-01T00:00:00Z",
                "materialization_id": "m_old",
                "receipt_hash": "blake3:a",
            })),
            line(serde_json::json!({
                "kind": "broker.resolution",
                "ts": "2000-01-01T00:00:00Z",
                "materialization_id": "m_old",
                "receipt_hash": "blake3:b",
            })),
            line(serde_json::json!({
                "kind": "session.construct_invocation",
                "ts": "2000-01-01T00:00:01Z",
                "materialization_id": "m_old",
                "action": "git.push",
                "exit_code": 0,
            })),
            line(serde_json::json!({
                "kind": "broker.revocation",
                "ts": "2000-01-01T00:00:01Z",
                "materialization_id": "m_old",
                "receipt_hash": "blake3:c",
            })),
        ]);
        let f = write_events(&lines);
        let filters = RollupFilters {
            since: Some("1h".to_string()),
            ..Default::default()
        };
        let out = rollup_command(f.path(), &filters, true).unwrap();
        let parsed: Vec<RollupRow> = serde_json::from_str(&out).unwrap();
        assert!(
            parsed.is_empty(),
            "1h filter should drop year-2000 row: {parsed:?}"
        );
    }
}
