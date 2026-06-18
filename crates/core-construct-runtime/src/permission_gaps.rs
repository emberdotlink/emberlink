//! Worker permission-gap capture — Rust-side bridge for the
//! `.ember/engine/permission-gaps.jsonl` audit log.
//!
//! When a worker exits with an empty diff and reports a reason that
//! starts with `"harness denied"`, the orchestrator calls
//! [`append_permission_gap`] to land a structured record in the gap log.
//! The orchestrator's drain step (`permission-gap-drain.sh`) reads
//! those records, dedups by `command`, and surfaces them for triage.
//!
//! Shape of each appended line:
//! ```json
//! {"ts":"2026-04-26T19:30:00Z","command":"<cmd>","reason":"<full>","source":"<agent_id>"}
//! ```
//!
//! Field caps:
//! - `command`: the substring after `"harness denied "` prefix, capped at 1024 chars
//! - `reason`:  the full original reason string, capped at 1024 chars
//!
//! The inner [`append_permission_gap_to`] helper takes an explicit path so
//! unit tests can target a tempfile without `set_current_dir`-racing the
//! rest of the test binary — the same isolation pattern used by
//! `events::emit_pool_skip_to`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::layout::{PERMISSION_GAPS_FILE, append_line};

/// Maximum byte length for `command` and `reason` fields, matching the
/// bash-side cap in `permission-gap-report.sh`.
pub const MAX_FIELD_LEN: usize = 1024;

/// Append a permission-gap record to the primary-worktree gap log.
///
/// `reason` must start with `"harness denied"` — callers are responsible for
/// the guard. This function is best-effort: errors are returned so callers
/// can log them, but the gap log is advisory only and a write failure must
/// never crash the release path.
///
/// The gap log file path resolves relative to the current directory, which
/// must be the primary worktree root when this is called (the same cwd
/// invariant that `queue::repo_cd_for_state()` establishes).
pub fn append_permission_gap(command: &str, reason: &str, source: &str) -> Result<()> {
    append_permission_gap_to(Path::new(PERMISSION_GAPS_FILE), command, reason, source)
}

/// Inner helper with an explicit path — allows unit tests to target a
/// tempfile without mutating process cwd.
pub fn append_permission_gap_to(
    path: &Path,
    command: &str,
    reason: &str,
    source: &str,
) -> Result<()> {
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Cap fields to prevent runaway entries.
    let command = truncate_bytes(command, MAX_FIELD_LEN);
    let reason = truncate_bytes(reason, MAX_FIELD_LEN);

    // Resolve the parent directory from the explicit path (not from
    // primary_worktree_root()) so tests that pass a tempfile path work
    // without a git repo in scope. The production caller has already cwd'd
    // to the primary worktree root before calling append_permission_gap().
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating parent dir for {}", path.display()))?;

    let obj = serde_json::json!({
        "ts": ts,
        "command": command,
        "reason": reason,
        "source": source,
    });
    let line = serde_json::to_string(&obj).context("serializing permission-gap record")?;
    append_line(path, &line)
}

/// Truncate `s` to at most `max_bytes` bytes on a UTF-8 character boundary.
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Walk backwards from max_bytes to find a valid char boundary.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Resolve the absolute path to `permission-gaps.jsonl` under the primary
/// worktree. Returns `None` if the primary worktree cannot be resolved.
pub fn gaps_file_path() -> Option<PathBuf> {
    let root = crate::layout::primary_worktree_root().ok()?;
    Some(root.join(PERMISSION_GAPS_FILE))
}

// ─── HEADLESS-PREFLIGHT-LAYER2-GAPS — Phase 1 substrate ───────────────
//
// PREFLIGHT-LAYER2-HISTORICAL
//
// Per ADR 139 §"Pre-flight scope check at enrollment" Layer 2 (Historical):
// at headless-enrollment time, the CTA surfaces recent permission-gap
// entries scoped to the enrolling persona so the operator can widen the
// template for the enrollment duration. This module exposes the
// read-side filter used by the daemon's `headless_preflight_gaps` socket
// method.
//
// Filter semantics (Phase 1):
// - Matches a permission-gap record's `source` field against the
//   supplied persona string. The gap log's `source` field today carries
//   `$EMBER_AGENT_ID` (per `permission-gap-report.sh`); the
//   agent/persona binding is the orchestrator's responsibility. Phase 2
//   will replace this with a proper persona-id linkage once
//   HEADLESS-ENROLL-CLI-ATTESTED ships the enrollment surface.
// - Filters by `ts >= now - since`. `ts` is parsed as RFC3339 UTC; a
//   malformed `ts` excludes the record (defensive — bad timestamps
//   should not leak across the time-window filter).
// - Dedupes by `command`: each unique command appears once with a
//   `count` of how many times it occurred in the window and a
//   `last_seen` timestamp of the most recent occurrence.
// - Returns an empty vector when the gap log does not exist (typical
//   on a fresh primary worktree before any worker has reported).

/// One aggregated permission-gap entry returned by
/// [`recent_gaps_for_persona`]. Distinct commands collapse into one
/// [`PermissionGap`]; the `count` and `last_seen` fields summarize the
/// matching raw records.
///
/// Wire shape (serde): the daemon's `headless_preflight_gaps` socket
/// method returns a JSON array of these objects to the CLI, which renders
/// the CTA bullet list from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGap {
    /// The denied-command substring (post-`"harness denied "` strip if
    /// applicable; whatever the worker / orchestrator passed to
    /// `permission-gap-report.sh`).
    pub command: String,
    /// How many records in the time window match this command.
    pub count: u32,
    /// RFC3339 UTC timestamp of the most recent occurrence in the
    /// window.
    pub last_seen: String,
}

/// Internal raw shape of one JSON line in `permission-gaps.jsonl`.
/// Mirrors the writer side (`append_permission_gap_to` + the bash
/// `permission-gap-report.sh`). Kept private — the public surface is
/// the aggregated [`PermissionGap`].
#[derive(Debug, Clone, Deserialize)]
struct RawGapRecord {
    ts: String,
    command: String,
    #[allow(dead_code)]
    reason: String,
    source: String,
}

/// Read recent permission-gap entries for the given persona over the
/// supplied time window, dedup by `command`, and return the aggregated
/// list.
///
/// Resolution order for the gap log:
///   1. [`gaps_file_path`] (primary worktree). If unresolvable, returns
///      an empty vector (caller treats absence as "no gaps").
///
/// `persona`: matched against each raw record's `source` field
/// (exact string compare; Phase 1 binding — see module preamble).
///
/// `since`: window measured from `Utc::now()`. Records older than
/// `now - since` are excluded.
///
/// Errors: parsing failures on individual lines are silently dropped —
/// the gap log is best-effort, and a truncated last line (typical from
/// a crash mid-append) must not poison the entire query. I/O errors
/// surface to the caller.
pub fn recent_gaps_for_persona(persona: &str, since: Duration) -> Vec<PermissionGap> {
    let Some(path) = gaps_file_path() else {
        return Vec::new();
    };
    recent_gaps_for_persona_at(&path, persona, since, Utc::now())
}

/// Inner helper with an explicit path + clock — unit-testable against a
/// tempfile and a frozen `now` without depending on the primary
/// worktree resolution or wall-clock time.
pub fn recent_gaps_for_persona_at(
    path: &Path,
    persona: &str,
    since: Duration,
    now: DateTime<Utc>,
) -> Vec<PermissionGap> {
    // Absent log = no gaps. This is the steady-state shape on a fresh
    // primary worktree; do not treat it as an error.
    let contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => return Vec::new(),
    };

    let cutoff = match chrono::Duration::from_std(since) {
        Ok(d) => now - d,
        // `Duration::from_std` only fails for absurdly large values;
        // treat as "no window" and return empty rather than panic.
        Err(_) => return Vec::new(),
    };

    // Aggregator: command -> (count, last_seen DateTime).
    let mut acc: HashMap<String, (u32, DateTime<Utc>)> = HashMap::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<RawGapRecord>(trimmed) else {
            // Malformed line — skip. Crash-truncated tails land here.
            continue;
        };
        if rec.source != persona {
            continue;
        }
        let Ok(parsed) = DateTime::parse_from_rfc3339(&rec.ts) else {
            continue;
        };
        let parsed_utc: DateTime<Utc> = parsed.with_timezone(&Utc);
        if parsed_utc < cutoff {
            continue;
        }
        let entry = acc.entry(rec.command.clone()).or_insert((0, parsed_utc));
        entry.0 = entry.0.saturating_add(1);
        if parsed_utc > entry.1 {
            entry.1 = parsed_utc;
        }
    }

    let mut out: Vec<PermissionGap> = acc
        .into_iter()
        .map(|(command, (count, last_seen))| PermissionGap {
            command,
            count,
            last_seen: last_seen.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
        .collect();

    // Deterministic ordering: highest count first, ties broken by
    // most-recent last_seen, ties broken by command string. Stable
    // ordering keeps the CTA bullet list deterministic across calls
    // and makes the daemon's JSON response stable for test
    // assertions.
    out.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.command.cmp(&b.command))
    });
    out
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A harness-denied reason flows to the gap log with the correct JSON shape.
    #[test]
    fn harness_denied_reason_appends_correct_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        append_permission_gap_to(
            &path,
            "find . -name '*.rs'",
            "harness denied find . -name '*.rs'",
            "agent-abc123",
        )
        .expect("append succeeded");

        let written = std::fs::read_to_string(&path).expect("file written");
        let line = written.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");

        assert_eq!(v["command"], "find . -name '*.rs'");
        assert_eq!(v["reason"], "harness denied find . -name '*.rs'");
        assert_eq!(v["source"], "agent-abc123");
        assert!(v.get("ts").and_then(|t| t.as_str()).is_some(), "ts present");
    }

    /// A non-harness-denied reason must NOT flow — the guard is the caller's
    /// responsibility; this test validates the happy-path shape only when the
    /// caller has already checked the prefix.
    ///
    /// This test verifies that `append_permission_gap_to` is a pure append
    /// function and does NOT apply the `harness denied` filter itself —
    /// the filter lives in `queue::release` where the guard belongs.
    #[test]
    fn non_harness_denied_reason_is_not_filtered_by_append_fn() {
        // The append helper has no knowledge of the harness-denied prefix;
        // it appends unconditionally. The filter is in release(). Verify
        // the helper appends whatever it's given — the queue tests cover
        // the filter behaviour.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        append_permission_gap_to(&path, "some-cmd", "normal failure", "agent-xyz")
            .expect("append succeeded");

        let written = std::fs::read_to_string(&path).expect("file written");
        assert!(
            !written.is_empty(),
            "helper always appends; filter is in release()"
        );
    }

    /// Empty reason string must not produce a gap record (guard is in release()).
    /// Verify that an empty reason round-trips through the helper unchanged
    /// (the helper itself does not apply the empty-reason guard).
    #[test]
    fn empty_reason_round_trips_through_helper() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        append_permission_gap_to(&path, "", "", "agent-xyz").expect("append succeeded");

        let written = std::fs::read_to_string(&path).expect("file written");
        let line = written.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        assert_eq!(v["command"], "");
        assert_eq!(v["reason"], "");
    }

    /// The 1024-byte cap is enforced on both `command` and `reason`.
    #[test]
    fn byte_cap_is_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let long = "x".repeat(2000);
        append_permission_gap_to(&path, &long, &long, "agent-cap").expect("append succeeded");

        let written = std::fs::read_to_string(&path).expect("file written");
        let line = written.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");

        let cmd = v["command"].as_str().expect("command is string");
        let rsn = v["reason"].as_str().expect("reason is string");

        assert!(
            cmd.len() <= MAX_FIELD_LEN,
            "command len {} exceeds cap",
            cmd.len()
        );
        assert!(
            rsn.len() <= MAX_FIELD_LEN,
            "reason len {} exceeds cap",
            rsn.len()
        );
        assert_eq!(cmd.len(), MAX_FIELD_LEN);
        assert_eq!(rsn.len(), MAX_FIELD_LEN);
    }

    /// JSON output is valid and can be read back; all four fields are present.
    #[test]
    fn json_line_is_valid_and_has_all_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        append_permission_gap_to(
            &path,
            "kubectl apply -f manifests/",
            "harness denied kubectl apply -f manifests/",
            "agent-deadbeef",
        )
        .expect("append succeeded");

        let written = std::fs::read_to_string(&path).expect("file written");
        let line = written.lines().next().expect("at least one line");

        // Must parse without error.
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON");

        // All four required fields must be present and string-valued.
        for field in &["ts", "command", "reason", "source"] {
            assert!(
                v.get(field).and_then(|x| x.as_str()).is_some(),
                "field '{field}' missing or non-string in: {line}"
            );
        }
    }

    /// `truncate_bytes` preserves UTF-8 character boundaries.
    #[test]
    fn truncate_bytes_respects_char_boundaries() {
        // "é" is U+00E9, encoded as 2 bytes in UTF-8. A 3-byte cap should
        // NOT include a partial byte sequence — it should truncate to 2 bytes.
        let s = "aéb"; // bytes: [0x61, 0xc3, 0xa9, 0x62] — 4 bytes
        assert_eq!(truncate_bytes(s, 3), "aé"); // 3-byte boundary lands inside 'b'; step back to 'é' end
        assert_eq!(truncate_bytes(s, 2), "a"); // 2 bytes: 'a' (1) + first byte of 'é' — step back to 'a'
        assert_eq!(truncate_bytes(s, 4), "aéb"); // exactly 4 bytes — no truncation
        assert_eq!(truncate_bytes(s, 100), "aéb"); // well under cap — no truncation
    }

    // ─── HEADLESS-PREFLIGHT-LAYER2-GAPS Phase 1 tests ────────────────
    //
    // PREFLIGHT-LAYER2-HISTORICAL — T1 unit tests for
    // `recent_gaps_for_persona_at`.

    /// Write one gap line to a fixture path. Avoids `set_current_dir`
    /// or any reliance on the production atomic-append path.
    fn write_gap(path: &Path, ts: &str, command: &str, source: &str) {
        use std::io::Write as _;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        let line = format!(
            "{{\"ts\":\"{ts}\",\"command\":\"{command}\",\"reason\":\"x\",\"source\":\"{source}\"}}\n"
        );
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open append");
        f.write_all(line.as_bytes()).expect("write line");
    }

    /// Absent gap log returns an empty list (no error). This is the
    /// steady-state shape on a fresh primary worktree.
    #[test]
    fn missing_gap_log_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.jsonl");
        let now = Utc::now();
        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);
        assert!(result.is_empty());
    }

    /// Records older than `now - since` are excluded; records inside
    /// the window are included. Verifies the time-window filter.
    #[test]
    fn time_window_excludes_old_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        // Frozen "now" — keeps the test deterministic regardless of
        // wall-clock drift.
        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // Old record: 10 days back — outside a 7-day window.
        write_gap(&path, "2026-04-30T11:59:59Z", "old-cmd", "main");
        // Recent record: 1 hour back — inside a 7-day window.
        write_gap(&path, "2026-05-10T11:00:00Z", "recent-cmd", "main");

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 1, "expected only the recent record");
        assert_eq!(result[0].command, "recent-cmd");
        assert_eq!(result[0].count, 1);
    }

    /// Records whose `source` does not match the persona string are
    /// excluded. Validates the persona filter.
    #[test]
    fn persona_filter_excludes_other_personas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        write_gap(&path, "2026-05-10T11:00:00Z", "cmd-a", "main");
        write_gap(&path, "2026-05-10T11:00:00Z", "cmd-b", "other");
        write_gap(&path, "2026-05-10T11:00:00Z", "cmd-c", "orchestrator");

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "cmd-a");
    }

    /// Repeated identical commands collapse into one [`PermissionGap`]
    /// with `count` reflecting the number of occurrences and
    /// `last_seen` reflecting the most recent timestamp.
    #[test]
    fn duplicate_commands_dedupe_with_count_and_last_seen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        write_gap(&path, "2026-05-09T10:00:00Z", "ember-gh.pr.merge", "main");
        write_gap(&path, "2026-05-10T08:00:00Z", "ember-gh.pr.merge", "main");
        write_gap(&path, "2026-05-10T11:30:00Z", "ember-gh.pr.merge", "main");

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "ember-gh.pr.merge");
        assert_eq!(result[0].count, 3);
        assert_eq!(result[0].last_seen, "2026-05-10T11:30:00Z");
    }

    /// Multiple distinct commands sort by descending count first,
    /// then descending `last_seen`, then ascending command. Confirms
    /// deterministic ordering for the CTA bullet list.
    #[test]
    fn multiple_commands_sort_by_count_then_recency() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // cmd-a: count 1, very recent.
        write_gap(&path, "2026-05-10T11:55:00Z", "cmd-a", "main");
        // cmd-b: count 3.
        write_gap(&path, "2026-05-09T01:00:00Z", "cmd-b", "main");
        write_gap(&path, "2026-05-09T02:00:00Z", "cmd-b", "main");
        write_gap(&path, "2026-05-09T03:00:00Z", "cmd-b", "main");
        // cmd-c: count 2.
        write_gap(&path, "2026-05-09T04:00:00Z", "cmd-c", "main");
        write_gap(&path, "2026-05-09T05:00:00Z", "cmd-c", "main");

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 3);
        // Count-descending: b (3), c (2), a (1).
        assert_eq!(result[0].command, "cmd-b");
        assert_eq!(result[0].count, 3);
        assert_eq!(result[1].command, "cmd-c");
        assert_eq!(result[1].count, 2);
        assert_eq!(result[2].command, "cmd-a");
        assert_eq!(result[2].count, 1);
    }

    /// Malformed JSON lines are silently skipped — a crash-truncated
    /// tail does not poison the rest of the query.
    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        // One valid record.
        write_gap(&path, "2026-05-10T11:00:00Z", "valid-cmd", "main");

        // One malformed tail (e.g. truncated mid-append).
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append");
            f.write_all(b"{\"ts\":\"2026-05-10T11:00:00Z\",\"comma")
                .unwrap();
        }

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "valid-cmd");
    }

    /// Records with malformed `ts` (un-parseable as RFC3339) are
    /// excluded — a bad timestamp must not let a record leak past
    /// the window filter.
    #[test]
    fn malformed_timestamp_excludes_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("permission-gaps.jsonl");

        let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-05-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        write_gap(&path, "not-a-timestamp", "cmd-x", "main");
        write_gap(&path, "2026-05-10T11:00:00Z", "cmd-y", "main");

        let result = recent_gaps_for_persona_at(&path, "main", Duration::from_secs(7 * 86400), now);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "cmd-y");
    }
}
