//! CLASSIFICATION: PUBLIC
//!
//! Empirical-sample telemetry collection for the v0.3.0 friendly-drop window.
//!
//! Anchor: `empirical_sample_pre_v031_retune_landed`
//!
//! Per `META-EMPIRICAL-SAMPLE-PRE-V031-RETUNE` (`tasks.toml`) and ADR 165:
//! emberd collects daemon-local, anonymized structural metrics during the
//! v0.3.0 friendly-drop window so v0.3.1 cohort retune decisions
//! (`META-V04-COHORT-RETUNE-BACKLOG`) ride on data, not guesses.
//!
//! ## Five measurement categories
//!
//! 1. **broker_exec inflight distribution** — per-session concurrent
//!    `broker_exec` count via [`record_inflight_sample`]; p50/p95/p99/max
//!    folded into the daily aggregate.
//! 2. **JIT approval-response latency** — time from decision-only approval
//!    request creation to operator approve/deny resolution via
//!    [`record_jit_latency`].
//! 3. **Audit-store write throughput** — sustained writes/sec, peak burst,
//!    SQLite WAL checkpoint latency via [`record_audit_write_batch`] and
//!    [`record_audit_checkpoint_latency`].
//! 4. **Delegated authority utilization** — scope-exercised vs scope-granted
//!    ratio via [`record_grant_utilization`].
//! 5. **Pool slot utilization** — execution-domain UID-pool occupancy via
//!    [`record_pool_slot_sample`].
//!
//! ## Opt-in + anonymization (privacy posture)
//!
//! - **Opt-in only.** Until [`enable_collection`] is called (set by the
//!    operator's `ember telemetry opt-in --anonymous` flow), every recording
//!    call is a no-op via the [`ENABLED`] atomic — the daemon's hot paths take
//!    a single relaxed load, never a heap allocation, when collection is off.
//! - **No PII.** The recording structs in this module deliberately omit any
//!    operator/persona/grant/session/PR identifier. Only structural metrics
//!    (counters, latencies, ratios, cohort tags) reach the writer.
//! - **Daily-rotating output.** Records land in
//!    `<daemon-data-dir>/telemetry/<yyyy-mm-dd>.csv` (configured at daemon
//!    startup; tests inject a tempdir via [`set_output_dir`]).
//! - **Opt-out wipes data.** [`disable_collection_and_purge`] flips the gate
//!    closed, removes the opt-in marker, and removes any existing daily files.
//!
//! ## Wiring
//!
//! The broker-exec dispatch path records inflight samples, the decision-only
//! approval resolver records JIT approval latency, and the audit-chain writer
//! records throughput when collection is enabled. The delegated-authority
//! standing-grant fast path records grant-utilization snapshots on approve;
//! the UID-pool allocator records slot occupancy after checkout and release.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Utc;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

const OPT_IN_MARKER_FILE: &str = "enabled-anonymous";

/// Process-wide opt-in gate. Default `false` — every recording call is a no-op
/// until the operator flips this via `ember telemetry opt-in --anonymous`.
///
/// Per ADR 165 §"opt-in posture": the daemon must never collect operator
/// metrics by default; the friendly-drop window opt-in is explicit and
/// reversible.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Optional output-directory override (tests + ops). When `None`, the writer
/// resolves the default `~/.ember/telemetry/` path via [`default_output_dir`].
/// Holding this in a `Mutex<OnceCell<...>>`-shaped slot keeps the hot path's
/// load lock-free (cleared/set only at startup / test setup).
static OUTPUT_DIR: OnceCell<Mutex<Option<PathBuf>>> = OnceCell::new();

/// Operator-visible status for the empirical-sample collector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryStatus {
    pub enabled: bool,
    pub anonymous: bool,
    pub output_dir: PathBuf,
    pub marker_path: PathBuf,
    pub active_daily_path: PathBuf,
}

fn output_dir_slot() -> &'static Mutex<Option<PathBuf>> {
    OUTPUT_DIR.get_or_init(|| Mutex::new(None))
}

/// Flip the opt-in gate to `true`. Invoked by `ember telemetry opt-in
/// --anonymous`. Idempotent.
pub fn enable_collection() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Persist anonymous opt-in and enable collection for this daemon process.
pub fn enable_collection_persistent() -> std::io::Result<TelemetryStatus> {
    let dir = resolved_output_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(marker_path_for_dir(&dir), b"anonymous\n")?;
    enable_collection();
    Ok(current_status())
}

/// Initialize the in-process gate from the persistent anonymous marker.
pub fn init_from_disk() -> std::io::Result<TelemetryStatus> {
    let marker = marker_path();
    match std::fs::read_to_string(&marker) {
        Ok(raw) => {
            ENABLED.store(raw.trim() == "anonymous", Ordering::Relaxed);
            Ok(current_status())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            ENABLED.store(false, Ordering::Relaxed);
            Ok(current_status())
        }
        Err(err) => {
            ENABLED.store(false, Ordering::Relaxed);
            Err(err)
        }
    }
}

/// Flip the opt-in gate to `false` AND purge any existing daily files under
/// the resolved output directory. Also removes the persistent anonymous marker.
/// Invoked by `ember telemetry opt-out`.
///
/// Returns the number of daily telemetry files removed (or any I/O error
/// encountered on the first failing entry). Removing the marker is not counted.
pub fn disable_collection_and_purge() -> std::io::Result<usize> {
    ENABLED.store(false, Ordering::Relaxed);
    let dir = resolved_output_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let marker = marker_path_for_dir(&dir);
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_csv = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("csv"))
            .unwrap_or(false);
        if is_csv && path.is_file() {
            std::fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Whether collection is currently enabled.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Snapshot the current collector status.
pub fn current_status() -> TelemetryStatus {
    let output_dir = resolved_output_dir();
    TelemetryStatus {
        enabled: is_enabled(),
        anonymous: is_enabled(),
        marker_path: marker_path_for_dir(&output_dir),
        active_daily_path: daily_path_for_dir(&output_dir),
        output_dir,
    }
}

/// Override the output directory (tests + non-default ops layouts). Use
/// `set_output_dir(None)` to revert to the default daemon system telemetry
/// resolution.
pub fn set_output_dir(dir: Option<PathBuf>) {
    let slot = output_dir_slot();
    let mut guard = slot.lock().expect("OUTPUT_DIR mutex poisoned");
    *guard = dir;
}

/// Compute the default output directory from the daemon-owned system state
/// root. Runtime startup overrides this with the loaded config's `data_dir`,
/// but this default keeps tests and pre-startup helper paths off user HOME.
fn default_output_dir() -> PathBuf {
    crate::paths::DaemonPaths::system()
        .data_dir
        .join("telemetry")
}

/// Resolve the active output directory — override if set, else
/// [`default_output_dir`].
fn resolved_output_dir() -> PathBuf {
    let slot = output_dir_slot();
    let guard = slot.lock().expect("OUTPUT_DIR mutex poisoned");
    guard.clone().unwrap_or_else(default_output_dir)
}

fn marker_path() -> PathBuf {
    marker_path_for_dir(&resolved_output_dir())
}

fn marker_path_for_dir(dir: &Path) -> PathBuf {
    dir.join(OPT_IN_MARKER_FILE)
}

/// Daily file name `<yyyy-mm-dd>.csv` resolved against the active output
/// directory.
fn daily_path() -> PathBuf {
    daily_path_for_dir(&resolved_output_dir())
}

fn daily_path_for_dir(dir: &Path) -> PathBuf {
    let date = Utc::now().format("%Y-%m-%d").to_string();
    dir.join(format!("{date}.csv"))
}

/// One row of the daily CSV. Tag-only enum on the wire so the daily file
/// stays self-describing across measurement categories without a separate
/// schema doc per row type. Anonymized: no operator/persona/grant identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[allow(dead_code)]
pub enum SampleRow {
    /// (1) broker_exec inflight distribution sample.
    InflightSample {
        ts_utc: String,
        cohort: String,
        /// Concurrent broker_exec count at sample time.
        concurrent: u32,
    },
    /// (2) JIT approval-response latency.
    JitLatency {
        ts_utc: String,
        cohort: String,
        latency_ms: u64,
        /// Approve / deny / timeout. Closed-set; no operator notes.
        outcome: JitOutcome,
    },
    /// (3a) Audit-store write batch.
    AuditWriteBatch {
        ts_utc: String,
        writes: u64,
        elapsed_ms: u64,
    },
    /// (3b) Audit-store WAL checkpoint latency.
    AuditCheckpointLatency { ts_utc: String, latency_ms: u64 },
    /// (4) Delegated authority grant utilization snapshot.
    GrantUtilization {
        ts_utc: String,
        cohort: String,
        /// Fraction of granted scope actually exercised (0.0–1.0).
        exercised_ratio: f32,
        /// Count of JIT escalations for out-of-scope actions in the window.
        /// Current standing-grant approve-path samples write zero because
        /// fallthrough is not necessarily a JIT.
        out_of_scope_jits: u32,
        /// Mean session length as fraction of grant TTL (0.0–1.0; can exceed
        /// 1.0 if sessions outlive grants via extend).
        session_ttl_ratio: f32,
    },
    /// (5) Pool slot utilization sample.
    PoolSlotSample {
        ts_utc: String,
        cohort: String,
        /// Pool capacity at sample time.
        capacity: u32,
        /// Occupied slots at sample time.
        occupied: u32,
        /// Whether the operator-reserve slot was occupied.
        operator_reserve_hit: bool,
    },
}

/// JIT approval outcome — closed set, no free-text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum JitOutcome {
    Approve,
    Deny,
    Timeout,
}

/// (1) Record one broker_exec inflight-count sample. Cohort is the closed-set
/// cohort tag (e.g. "dev0", "team0"). No-op when collection is disabled.
#[allow(dead_code)]
pub fn record_inflight_sample(cohort: &str, concurrent: u32) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::InflightSample {
        ts_utc: now_iso(),
        cohort: cohort.to_string(),
        concurrent,
    });
}

/// (2) Record a JIT approval-response latency. No-op when disabled.
#[allow(dead_code)]
pub fn record_jit_latency(cohort: &str, latency: Duration, outcome: JitOutcome) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::JitLatency {
        ts_utc: now_iso(),
        cohort: cohort.to_string(),
        latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
        outcome,
    });
}

/// (3a) Record an audit-store write batch. No-op when disabled.
#[allow(dead_code)]
pub fn record_audit_write_batch(writes: u64, elapsed: Duration) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::AuditWriteBatch {
        ts_utc: now_iso(),
        writes,
        elapsed_ms: elapsed.as_millis().min(u64::MAX as u128) as u64,
    });
}

/// (3b) Record an audit-store SQLite WAL checkpoint latency.
#[allow(dead_code)]
pub fn record_audit_checkpoint_latency(latency: Duration) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::AuditCheckpointLatency {
        ts_utc: now_iso(),
        latency_ms: latency.as_millis().min(u64::MAX as u128) as u64,
    });
}

/// (4) Record a delegated authority grant utilization snapshot.
#[allow(dead_code)]
pub fn record_grant_utilization(
    cohort: &str,
    exercised_ratio: f32,
    out_of_scope_jits: u32,
    session_ttl_ratio: f32,
) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::GrantUtilization {
        ts_utc: now_iso(),
        cohort: cohort.to_string(),
        exercised_ratio,
        out_of_scope_jits,
        session_ttl_ratio,
    });
}

/// (5) Record one pool-slot occupancy sample.
#[allow(dead_code)]
pub fn record_pool_slot_sample(
    cohort: &str,
    capacity: u32,
    occupied: u32,
    operator_reserve_hit: bool,
) {
    if !is_enabled() {
        return;
    }
    append(SampleRow::PoolSlotSample {
        ts_utc: now_iso(),
        cohort: cohort.to_string(),
        capacity,
        occupied,
        operator_reserve_hit,
    });
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Serialize one row to JSON and append it as a single line to the daily file
/// (JSON-lines on disk; `.csv` extension preserved per the task brief's
/// public path contract — the operator-facing surface treats this as "the
/// telemetry file" without making structural promises about CSV columns
/// because the row taxonomy is per-category).
///
/// Recording errors are logged at `warn!` and swallowed: a telemetry write
/// failure must never break the daemon's hot path or the operator's session.
fn append(row: SampleRow) {
    let line = match serde_json::to_string(&row) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(error = %err, "telemetry sample serialize failed; dropping");
            return;
        }
    };
    let path = daily_path();
    if let Err(err) = write_line(&path, &line) {
        tracing::warn!(error = %err, path = %path.display(), "telemetry sample write failed; dropping");
    }
}

fn write_line(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! T1 — pure-ish: every test injects a tempdir output via
    //! [`set_output_dir`] and toggles the [`ENABLED`] gate locally. No real
    //! `~/.ember/telemetry/` writes, no network, no SQLite.

    use super::*;

    fn fresh_tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Recording calls are no-ops when the opt-in gate is closed (default).
    #[test]
    fn no_op_when_disabled() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = fresh_tempdir();
        set_output_dir(Some(dir.path().to_path_buf()));
        ENABLED.store(false, Ordering::Relaxed);

        record_inflight_sample("dev0", 3);
        record_jit_latency("dev0", Duration::from_millis(120), JitOutcome::Approve);
        record_audit_write_batch(50, Duration::from_millis(10));
        record_audit_checkpoint_latency(Duration::from_millis(7));
        record_grant_utilization("dev0", 0.4, 1, 0.6);
        record_pool_slot_sample("dev0", 16, 8, false);

        // Daily file must NOT exist when collection is disabled.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let p = dir.path().join(format!("{date}.csv"));
        assert!(!p.exists(), "daily file should not exist while disabled");
        set_output_dir(None);
    }

    /// All five recording APIs append rows when enabled, and each row
    /// round-trips through serde as the expected `SampleRow` variant.
    #[test]
    fn round_trip_all_five_categories() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = fresh_tempdir();
        set_output_dir(Some(dir.path().to_path_buf()));
        enable_collection();

        record_inflight_sample("dev0", 4);
        record_jit_latency("dev0", Duration::from_millis(250), JitOutcome::Deny);
        record_audit_write_batch(100, Duration::from_millis(25));
        record_audit_checkpoint_latency(Duration::from_millis(12));
        record_grant_utilization("team0", 0.75, 2, 0.9);
        record_pool_slot_sample("team0", 32, 30, true);

        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let p = dir.path().join(format!("{date}.csv"));
        let raw = std::fs::read_to_string(&p).expect("daily file written");
        let mut variants: Vec<&'static str> = vec![];
        for line in raw.lines() {
            let row: SampleRow = serde_json::from_str(line).expect("row round-trips");
            variants.push(match row {
                SampleRow::InflightSample { .. } => "inflight",
                SampleRow::JitLatency { .. } => "jit",
                SampleRow::AuditWriteBatch { .. } => "audit_batch",
                SampleRow::AuditCheckpointLatency { .. } => "audit_ckpt",
                SampleRow::GrantUtilization { .. } => "grant",
                SampleRow::PoolSlotSample { .. } => "pool",
            });
        }
        assert_eq!(
            variants,
            vec![
                "inflight",
                "jit",
                "audit_batch",
                "audit_ckpt",
                "grant",
                "pool"
            ],
            "all six rows landed in insertion order"
        );

        // Clean up gate for other tests.
        ENABLED.store(false, Ordering::Relaxed);
        set_output_dir(None);
    }

    /// `disable_collection_and_purge` flips the gate closed AND wipes daily
    /// CSV files.
    #[test]
    fn opt_out_purges_daily_files() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = fresh_tempdir();
        set_output_dir(Some(dir.path().to_path_buf()));
        enable_collection();

        record_inflight_sample("dev0", 1);
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let p = dir.path().join(format!("{date}.csv"));
        assert!(p.exists(), "daily file written");

        let removed = disable_collection_and_purge().expect("purge ok");
        assert_eq!(removed, 1, "one daily file removed");
        assert!(!p.exists(), "daily file purged");
        assert!(!is_enabled(), "gate flipped closed");

        set_output_dir(None);
    }

    /// Persistent anonymous opt-in survives a daemon restart: startup reads
    /// the marker and reopens the in-process gate.
    #[test]
    fn persistent_opt_in_reopens_gate_from_marker() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = fresh_tempdir();
        set_output_dir(Some(dir.path().to_path_buf()));
        ENABLED.store(false, Ordering::Relaxed);

        let enabled = enable_collection_persistent().expect("persist opt-in");
        assert!(enabled.enabled);
        assert!(enabled.anonymous);
        assert!(enabled.marker_path.exists(), "marker written");

        // Simulated daemon restart: memory gate is cold, marker remains.
        ENABLED.store(false, Ordering::Relaxed);
        assert!(!is_enabled());
        let rehydrated = init_from_disk().expect("init from marker");
        assert!(rehydrated.enabled, "marker reopens collection");
        assert_eq!(rehydrated.output_dir, dir.path());

        let _ = disable_collection_and_purge();
        set_output_dir(None);
    }

    /// Opt-out removes both daily rows and the persistent marker so a restart
    /// does not silently re-enable collection.
    #[test]
    fn opt_out_removes_persistent_marker() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = fresh_tempdir();
        set_output_dir(Some(dir.path().to_path_buf()));
        enable_collection_persistent().expect("persist opt-in");
        record_inflight_sample("dev0", 1);

        let marker = dir.path().join(OPT_IN_MARKER_FILE);
        assert!(marker.exists(), "marker written");
        let removed = disable_collection_and_purge().expect("purge ok");
        assert_eq!(removed, 1, "one daily file removed");
        assert!(!marker.exists(), "marker removed");

        let rehydrated = init_from_disk().expect("init without marker");
        assert!(!rehydrated.enabled, "no marker means disabled");
        set_output_dir(None);
    }

    /// Anonymization invariant — the public recording API surface accepts no
    /// operator/persona/grant/session identifier (compile-time check). The
    /// only string parameter is `cohort`, a closed-set tag.
    #[test]
    fn anonymization_compile_time_surface() {
        // This is a documentation test: if a future change adds an
        // identifier-shaped param to any record_* fn, this assert will need
        // updating — and the reviewer will catch it.
        fn _signatures_pinned() {
            let _: fn(&str, u32) = record_inflight_sample;
            let _: fn(&str, Duration, JitOutcome) = record_jit_latency;
            let _: fn(u64, Duration) = record_audit_write_batch;
            let _: fn(Duration) = record_audit_checkpoint_latency;
            let _: fn(&str, f32, u32, f32) = record_grant_utilization;
            let _: fn(&str, u32, u32, bool) = record_pool_slot_sample;
        }
    }
}
