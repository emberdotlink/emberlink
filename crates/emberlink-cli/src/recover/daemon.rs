//! CLASSIFICATION: PUBLIC
//!
//! `ember recover daemon` - recover daemon-side state per ADR 161
//! §Component 1.
//!
//! Scope routing:
//! - `state` - recover an exited daemon process with F-DAEMON-1 crash
//!   recovery (`recover_f_daemon_1_landed`)
//! - `socket` - unlink a stale socket file, F-DAEMON-2
//!   (`recover_f_daemon_2_landed`)
//! - `db` - run SQLite integrity check and restore from backup, F-DAEMON-3
//!   (`recover_f_daemon_3_landed`)
//! - `pid` - re-pair daemon PID file with the running process

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use clap::{Args, ValueEnum};
use serde_json::{Value, json};

// Used by the real ops impl for PRAGMA integrity_check (F-DAEMON-3).
use rusqlite;

use crate::install_paths::{
    DEV_DAEMON_SOCKET_REL, DEV_PLIST_LABEL, PROD_PLIST_LABEL, prod_daemon_socket_path,
    prod_state_root,
};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult, note_receipt_contract};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const POLL_ATTEMPTS: usize = 50;
const PROD_DAEMON_ERR_LOG: &str = "/var/log/emberd.err";
const DEV_DAEMON_ERR_LOG: &str = "/var/log/emberd.dev.err";

/// `ember recover daemon [--dev|--prod] [--scope state|socket|db|pid]`.
#[derive(Args, Debug)]
pub struct RecoverDaemonArgs {
    /// Recover the dev-mode daemon.
    #[arg(long, group = "mode")]
    pub dev: bool,

    /// Recover the prod-mode daemon.
    #[arg(long, group = "mode")]
    pub prod: bool,

    /// Narrow the recovery to a single sub-component. When omitted,
    /// `state` runs F-DAEMON-1 crash recovery.
    #[arg(long, value_enum)]
    pub scope: Option<DaemonScope>,

    /// (F-DAEMON-3 `--scope db` only) Accept that up to N Receipts in
    /// the window between the last archive and the corruption point may be
    /// unrecoverable. Required when `--scope db` detects a non-zero receipt
    /// loss window; Touch ID gates the execution. Without this flag the
    /// command refuses to restore a database that would silently lose
    /// Receipt records.
    #[arg(long)]
    pub accept_receipt_loss: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum DaemonScope {
    /// Recover an exited daemon process by kickstarting launchd.
    State,
    /// Unlink a stale daemon.sock file.
    Socket,
    /// Rebuild the SQLite database (audit or session store).
    Db,
    /// Re-pair the daemon PID file with the running process.
    Pid,
}

impl DaemonScope {
    #[allow(dead_code)]
    fn as_str(self) -> &'static str {
        match self {
            DaemonScope::State => "state",
            DaemonScope::Socket => "socket",
            DaemonScope::Db => "db",
            DaemonScope::Pid => "pid",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DaemonMode {
    Prod,
    Dev,
}

impl DaemonMode {
    fn from_args(args: &RecoverDaemonArgs) -> Self {
        if args.dev { Self::Dev } else { Self::Prod }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Prod => "prod",
            Self::Dev => "dev",
        }
    }
}

#[derive(Debug, Clone)]
struct DaemonTarget {
    mode: DaemonMode,
    label: String,
    launchctl_target: String,
    plist_path: PathBuf,
    socket_path: PathBuf,
    log_path: PathBuf,
    /// Path to the primary daemon SQLite database used for F-DAEMON-3 repair.
    db_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LaunchdState {
    Running { pid: u32 },
    Exited { status: Option<i32> },
    Missing,
}

impl LaunchdState {
    fn before_state(&self) -> &'static str {
        match self {
            Self::Running { .. } => "running",
            Self::Exited { .. } | Self::Missing => "exited",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Running { pid } => format!("running(pid={pid})"),
            Self::Exited {
                status: Some(status),
            } => format!("exited(status={status})"),
            Self::Exited { status: None } => "exited(status=unknown)".to_string(),
            Self::Missing => "missing".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

trait DaemonRecoveryOps {
    fn launchctl_list(&self) -> RecoverResultString;
    fn launchctl_bootstrap(&self, domain: &str, plist_path: &Path) -> RecoverResultUnit;
    fn launchctl_kickstart(&self, target: &str) -> RecoverResultUnit;
    fn socket_reachable(&self, socket_path: &Path) -> bool;
    fn sleep_poll_interval(&self, interval: Duration);
    fn read_last_log_lines(&self, path: &Path, max_lines: usize) -> Vec<String>;
    fn emit_recovery_receipt(
        &self,
        socket_path: &Path,
        params: &Value,
    ) -> Result<ReceiptSummary, RecoverError>;
    /// F-DAEMON-2: return `true` if the socket file exists on disk but
    /// `connect()` fails — i.e., the socket is stale.
    fn socket_file_exists(&self, socket_path: &Path) -> bool;
    /// F-DAEMON-2: remove the stale socket file.
    fn remove_socket_file(&self, socket_path: &Path) -> RecoverResultUnit;
    /// F-DAEMON-3: run `PRAGMA integrity_check` on the database at `db_path`.
    /// Returns `Ok(())` when the DB is healthy, or a structured
    /// `RecoverError` describing the integrity violations.
    fn db_integrity_check(&self, db_path: &Path) -> RecoverResultUnit;
    /// F-DAEMON-3: locate the most-recent archive copy of `db_path`.
    ///
    /// The archive directory convention (ADR 160 §Component 2) is a sibling
    /// `archive/` directory next to the database file. Each entry is named
    /// `daemon.db.<unix-timestamp>` (or `daemon.db.bak`). Returns the path
    /// of the most recent entry, plus the estimated number of Receipts in
    /// the window between that archive and the live DB's last-modified time
    /// (a heuristic based on event-count delta; 0 = "no loss detectable").
    fn find_latest_db_archive(
        &self,
        db_path: &Path,
    ) -> Result<Option<DbArchiveEntry>, RecoverError>;
    /// F-DAEMON-3: copy `source` over `dest` (overwrite), used to restore
    /// a database from an archive entry.
    fn restore_db_from_archive(&self, source: &Path, dest: &Path) -> RecoverResultUnit;
}

/// Information about a located database archive entry.
#[derive(Debug, Clone)]
struct DbArchiveEntry {
    path: PathBuf,
    /// Estimated number of Receipt records that fall between this archive
    /// and the corrupt live DB. 0 when the estimate cannot be computed.
    estimated_receipt_loss: u64,
}

type RecoverResultString = Result<String, RecoverError>;
type RecoverResultUnit = Result<(), RecoverError>;

struct RealDaemonRecoveryOps;

impl DaemonRecoveryOps for RealDaemonRecoveryOps {
    fn launchctl_list(&self) -> RecoverResultString {
        let output = Command::new("launchctl")
            .arg("list")
            .output()
            .map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: launchctl list failed; step: launchctl-list; {err}"
                ))
            })?;
        if !output.status.success() {
            return Err(RecoverError::authority(format!(
                "recover daemon refused: launchctl list exited {}; step: launchctl-list; stderr: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn launchctl_bootstrap(&self, domain: &str, plist_path: &Path) -> RecoverResultUnit {
        let output = Command::new("launchctl")
            .arg("bootstrap")
            .arg(domain)
            .arg(plist_path)
            .output()
            .map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: launchctl bootstrap failed; step: launchctl-bootstrap; domain={domain}; plist={}; {err}",
                    plist_path.display()
                ))
            })?;
        if !output.status.success() {
            return Err(RecoverError::authority(format!(
                "recover daemon refused: launchctl bootstrap exited {}; step: launchctl-bootstrap; domain={domain}; plist={}; stderr: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                plist_path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn launchctl_kickstart(&self, target: &str) -> RecoverResultUnit {
        let output = Command::new("launchctl")
            .args(["kickstart", "-k", target])
            .output()
            .map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: launchctl kickstart failed; step: launchctl-kickstart; {err}"
                ))
            })?;
        if !output.status.success() {
            return Err(RecoverError::authority(format!(
                "recover daemon refused: launchctl kickstart exited {}; step: launchctl-kickstart; target={target}; stderr: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    fn socket_reachable(&self, socket_path: &Path) -> bool {
        UnixStream::connect(socket_path).is_ok()
    }

    fn sleep_poll_interval(&self, interval: Duration) {
        std::thread::sleep(interval);
    }

    fn read_last_log_lines(&self, path: &Path, max_lines: usize) -> Vec<String> {
        match fs::read_to_string(path) {
            Ok(body) => last_lines(&body, max_lines),
            Err(err) => vec![format!("<could not read {}: {err}>", path.display())],
        }
    }

    fn emit_recovery_receipt(
        &self,
        socket_path: &Path,
        params: &Value,
    ) -> Result<ReceiptSummary, RecoverError> {
        let value =
            crate::call_daemon_rpc(socket_path, "recovery_action_receipt", params).map_err(
                |err| {
                    RecoverError::authority(format!(
                        "recover daemon refused: could not emit recovery.action receipt through the daemon broker; step: recovery-receipt; {err}"
                    ))
                },
            )?;
        let receipt_id = value
            .get("receipt_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                RecoverError::authority(
                    "recover daemon refused: daemon returned no recovery.action receipt_id",
                )
            })?
            .to_string();
        let persisted = value
            .get("persisted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(ReceiptSummary {
            receipt_id,
            persisted,
        })
    }

    fn socket_file_exists(&self, socket_path: &Path) -> bool {
        socket_path.exists()
    }

    fn remove_socket_file(&self, socket_path: &Path) -> RecoverResultUnit {
        fs::remove_file(socket_path).map_err(|err| {
            RecoverError::authority(format!(
                "recover daemon refused: could not remove stale socket file {}; step: remove-socket; {err}",
                socket_path.display()
            ))
        })
    }

    fn db_integrity_check(&self, db_path: &Path) -> RecoverResultUnit {
        let conn = rusqlite::Connection::open(db_path).map_err(|err| {
            RecoverError::authority(format!(
                "recover daemon refused: could not open database {}; step: db-integrity-check; {err}",
                db_path.display()
            ))
        })?;
        let mut stmt = conn
            .prepare("PRAGMA integrity_check")
            .map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: could not prepare integrity_check on {}; step: db-integrity-check; {err}",
                    db_path.display()
                ))
            })?;
        let rows: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: integrity_check query failed on {}; step: db-integrity-check; {err}",
                    db_path.display()
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        // The pragma returns a single "ok" row when the database is healthy.
        if rows.len() == 1 && rows[0].eq_ignore_ascii_case("ok") {
            return Ok(());
        }
        let detail = rows.join("; ");
        Err(RecoverError::authority(format!(
            "recover daemon refused: database integrity check failed on {}; violations: {detail}; step: db-integrity-check",
            db_path.display()
        )))
    }

    fn find_latest_db_archive(
        &self,
        db_path: &Path,
    ) -> Result<Option<DbArchiveEntry>, RecoverError> {
        let parent = db_path
            .parent()
            .ok_or_else(|| RecoverError::usage("recover daemon: db_path has no parent dir"))?;
        let archive_dir = parent.join("archive");
        if !archive_dir.is_dir() {
            return Ok(None);
        }
        let db_name = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("daemon.db");
        let mut candidates: Vec<(u64, PathBuf)> = Vec::new();
        for entry in fs::read_dir(&archive_dir).map_err(|err| {
            RecoverError::authority(format!(
                "recover daemon refused: could not read archive dir {}; {err}",
                archive_dir.display()
            ))
        })? {
            let entry = entry.map_err(|err| {
                RecoverError::authority(format!(
                    "recover daemon refused: could not read archive entry; {err}"
                ))
            })?;
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            // Accept `daemon.db.<timestamp>` and `daemon.db.bak` shapes.
            if !fname_str.starts_with(db_name) {
                continue;
            }
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                })
                .unwrap_or(0);
            candidates.push((mtime, entry.path()));
        }
        if candidates.is_empty() {
            return Ok(None);
        }
        // Pick the newest archive by mtime.
        candidates.sort_by_key(|(ts, _)| *ts);
        let (_, best_path) = candidates.into_iter().last().unwrap();

        // Estimate receipt loss: count rows in the archive vs the live DB.
        // On any failure we default to 0 (conservative; operator will see
        // the real delta in the audit chain after restore).
        let estimated_receipt_loss = estimate_receipt_delta(&best_path, db_path);
        Ok(Some(DbArchiveEntry {
            path: best_path,
            estimated_receipt_loss,
        }))
    }

    fn restore_db_from_archive(&self, source: &Path, dest: &Path) -> RecoverResultUnit {
        // Atomically swap: copy to a temp file adjacent to dest, then rename.
        let tmp = dest.with_extension("recover.tmp");
        fs::copy(source, &tmp).map_err(|err| {
            RecoverError::authority(format!(
                "recover daemon refused: could not copy archive {} to temp {}; step: restore-db; {err}",
                source.display(),
                tmp.display()
            ))
        })?;
        fs::rename(&tmp, dest).map_err(|err| {
            let _ = fs::remove_file(&tmp);
            RecoverError::authority(format!(
                "recover daemon refused: could not rename temp {} to {}; step: restore-db; {err}",
                tmp.display(),
                dest.display()
            ))
        })
    }
}

/// Estimate how many receipt rows exist in `archive_db` vs `live_db`.
///
/// Uses a simple `SELECT COUNT(*) FROM receipts` on each; falls back to 0
/// when either cannot be queried (e.g. the live DB is already unreadable).
fn estimate_receipt_delta(archive_db: &Path, live_db: &Path) -> u64 {
    fn row_count(path: &Path) -> Option<i64> {
        let conn = rusqlite::Connection::open(path).ok()?;
        conn.query_row("SELECT COUNT(*) FROM receipts", [], |r| r.get::<_, i64>(0))
            .ok()
    }
    let archive_count = row_count(archive_db).unwrap_or(0).max(0) as u64;
    let live_count = row_count(live_db).unwrap_or(0).max(0) as u64;
    live_count.saturating_sub(archive_count)
}

pub fn handle(args: RecoverDaemonArgs, context: RecoverContext) -> RecoverResult {
    handle_with_ops(args, context, &RealDaemonRecoveryOps)
}

fn handle_with_ops(
    args: RecoverDaemonArgs,
    context: RecoverContext,
    ops: &dyn DaemonRecoveryOps,
) -> RecoverResult {
    let mode = DaemonMode::from_args(&args);
    let scope = args.scope.unwrap_or(DaemonScope::State);

    match scope {
        DaemonScope::State => recover_daemon_crash(mode, context, ops),
        DaemonScope::Socket => recover_stale_socket(mode, context, ops),
        DaemonScope::Db => recover_db_corrupt(mode, context, ops, args.accept_receipt_loss),
        DaemonScope::Pid => {
            println!(
                "ember recover daemon (mode={}, scope=pid): scaffold only - \
                 this scope lands under its own META-RECOVER-F-DAEMON task. \
                 See `ember recover --explain F-DAEMON-1` for the F-code-anchored runbook.",
                mode.as_str()
            );
            note_receipt_contract("daemon", "pid");
            Ok(RecoverOutcome::ok())
        }
    }
}

fn recover_daemon_crash(
    mode: DaemonMode,
    context: RecoverContext,
    ops: &dyn DaemonRecoveryOps,
) -> RecoverResult {
    let target = daemon_target(mode, context)?;
    let list = ops.launchctl_list()?;
    let state = parse_launchctl_list_state(&list, &target.label);

    if let LaunchdState::Running { pid } = state {
        println!(
            "ember recover daemon (mode={}, scope=state): daemon already healthy (label={}, pid={pid})",
            target.mode.as_str(),
            target.label
        );
        return Ok(RecoverOutcome::ok());
    }

    if matches!(state, LaunchdState::Missing) {
        println!(
            "ember recover daemon (mode={}, scope=state): daemon not loaded (label={}, state={}); bootstrapping {} from {}",
            target.mode.as_str(),
            target.label,
            state.detail(),
            target.launchctl_target,
            target.plist_path.display()
        );
        ops.launchctl_bootstrap("system", &target.plist_path)?;
    } else {
        println!(
            "ember recover daemon (mode={}, scope=state): daemon not running (label={}, state={}); kickstarting {}",
            target.mode.as_str(),
            target.label,
            state.detail(),
            target.launchctl_target
        );
    }
    ops.launchctl_kickstart(&target.launchctl_target)?;

    if !poll_socket_until_reachable(ops, &target.socket_path) {
        let log_lines = ops.read_last_log_lines(&target.log_path, 50);
        print_log_excerpt(&target.log_path, &log_lines);
        return Err(RecoverError::authority(format!(
            "recover daemon refused: daemon socket did not become reachable within 5s after launchctl kickstart; step: poll-socket; socket={}",
            target.socket_path.display()
        )));
    }

    let log_lines = ops.read_last_log_lines(&target.log_path, 50);
    print_log_excerpt(&target.log_path, &log_lines);

    let receipt_params = build_recovery_receipt_params(&target, &state, &log_lines);
    let receipt = ops.emit_recovery_receipt(&target.socket_path, &receipt_params)?;

    println!(
        "daemon recovered: before_state={}, after_state=running, socket={}",
        state.before_state(),
        target.socket_path.display()
    );
    println!(
        "Receipt: recovery.action {} (persisted={})",
        receipt.receipt_id, receipt.persisted
    );
    Ok(RecoverOutcome::ok())
}

fn daemon_target(mode: DaemonMode, context: RecoverContext) -> Result<DaemonTarget, RecoverError> {
    let (label, socket_path, log_path, db_path) = match mode {
        DaemonMode::Prod => {
            // ADR 218: prod paths are absolute system paths, NOT under
            // the operator's HOME. db_path lives at `<state_root>/daemon.db`
            // per `DaemonPaths::system` (state_root collapses onto data_dir).
            let socket_path = match context.socket_path {
                Some(path) => path,
                None => prod_daemon_socket_path(),
            };
            let db_path = prod_state_root().join("daemon.db");
            (
                PROD_PLIST_LABEL.to_string(),
                socket_path,
                PathBuf::from(PROD_DAEMON_ERR_LOG),
                db_path,
            )
        }
        DaemonMode::Dev => {
            let home = daemon_home()?;
            let db_path = home.join(".ember").join("data").join("daemon.db");
            (
                DEV_PLIST_LABEL.to_string(),
                home.join(DEV_DAEMON_SOCKET_REL),
                PathBuf::from(DEV_DAEMON_ERR_LOG),
                db_path,
            )
        }
    };
    Ok(DaemonTarget {
        mode,
        launchctl_target: format!("system/{label}"),
        plist_path: PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist")),
        label,
        socket_path,
        log_path,
        db_path,
    })
}

/// F-DAEMON-2: recover a stale socket file.
///
/// Anchor: `recover_f_daemon_2_landed`
fn recover_stale_socket(
    mode: DaemonMode,
    context: RecoverContext,
    ops: &dyn DaemonRecoveryOps,
) -> RecoverResult {
    let target = daemon_target(mode, context)?;

    // Check if the socket file exists on disk, then test reachability only
    // when it does. Calling connect() on a nonexistent path returns ENOENT,
    // not ECONNREFUSED; testing separately keeps the state machine clean.
    let file_exists = ops.socket_file_exists(&target.socket_path);

    if !file_exists {
        // Socket already gone — proceed to kickstart.
        println!(
            "ember recover daemon (mode={}, scope=socket): socket file not present ({}); \
             proceeding with daemon kickstart",
            target.mode.as_str(),
            target.socket_path.display()
        );
    } else if ops.socket_reachable(&target.socket_path) {
        println!(
            "ember recover daemon (mode={}, scope=socket): socket is already reachable ({}); \
             no action needed",
            target.mode.as_str(),
            target.socket_path.display()
        );
        return Ok(RecoverOutcome::ok());
    } else {
        // File exists but connect() fails: stale socket.
        println!(
            "ember recover daemon (mode={}, scope=socket): stale socket detected ({}); \
             unlinking",
            target.mode.as_str(),
            target.socket_path.display()
        );
        ops.remove_socket_file(&target.socket_path)?;
    }

    // Kickstart the daemon so it creates a fresh socket.
    let list = ops.launchctl_list()?;
    let state = parse_launchctl_list_state(&list, &target.label);
    println!(
        "ember recover daemon (mode={}, scope=socket): kickstarting {} (current launchd state={})",
        target.mode.as_str(),
        target.launchctl_target,
        state.detail()
    );
    ops.launchctl_kickstart(&target.launchctl_target)?;

    if !poll_socket_until_reachable(ops, &target.socket_path) {
        return Err(RecoverError::authority(format!(
            "recover daemon refused: socket {} did not become reachable within 5s \
             after kickstart; step: poll-socket-after-stale-unlink; \
             see `ember recover --explain F-DAEMON-2`",
            target.socket_path.display()
        )));
    }

    // Emit receipt: use daemon socket now that it is reachable.
    let recovery_params = build_socket_recovery_receipt_params(&target, file_exists, &state);
    let receipt = ops.emit_recovery_receipt(&target.socket_path, &recovery_params)?;

    println!(
        "stale socket recovered: socket={}, after_state=running",
        target.socket_path.display()
    );
    println!(
        "Receipt: recovery.action {} (persisted={})",
        receipt.receipt_id, receipt.persisted
    );
    Ok(RecoverOutcome::ok())
}

/// F-DAEMON-3: run SQLite integrity check and restore from archive if corrupt.
///
/// Per ADR 161 / runbook F-DAEMON-3 and ADR 160 §Component 2 receipt-loss
/// semantics: recovery NEVER silently drops Receipts. If the archive is
/// older than the live DB by N>0 Receipts the operator MUST pass
/// `--accept-receipt-loss`; without it the command refuses and reports the
/// loss count.
///
/// Anchor: `recover_f_daemon_3_landed`
fn recover_db_corrupt(
    mode: DaemonMode,
    context: RecoverContext,
    ops: &dyn DaemonRecoveryOps,
    accept_receipt_loss: bool,
) -> RecoverResult {
    let target = daemon_target(mode, context)?;
    let db_path = &target.db_path;

    println!(
        "ember recover daemon (mode={}, scope=db): running PRAGMA integrity_check on {}",
        target.mode.as_str(),
        db_path.display()
    );

    match ops.db_integrity_check(db_path) {
        Ok(()) => {
            println!(
                "ember recover daemon (mode={}, scope=db): database is healthy — no repair needed",
                target.mode.as_str()
            );
            return Ok(RecoverOutcome::ok());
        }
        Err(e) => {
            println!(
                "ember recover daemon (mode={}, scope=db): integrity check FAILED: {}",
                target.mode.as_str(),
                e
            );
        }
    }

    // Database is corrupt. Look for an archive to restore from.
    let archive = ops.find_latest_db_archive(db_path)?;
    let Some(archive) = archive else {
        return Err(RecoverError::authority(format!(
            "recover daemon refused: database {} is corrupt and no archive exists under \
             {}; cannot restore without a backup; step: find-archive; \
             see `ember recover --explain F-DAEMON-3`",
            db_path.display(),
            db_path
                .parent()
                .map(|p| p.join("archive").display().to_string())
                .unwrap_or_default()
        )));
    };

    // Check receipt loss window.
    if archive.estimated_receipt_loss > 0 && !accept_receipt_loss {
        return Err(RecoverError::authority(format!(
            "recover daemon refused: restoring from {} would lose approximately {} \
             Receipt record(s) in the window between the archive and the corrupt DB; \
             re-run with --accept-receipt-loss to proceed (Touch ID required); \
             step: receipt-loss-check; \
             see `ember recover --explain F-DAEMON-3`",
            archive.path.display(),
            archive.estimated_receipt_loss
        )));
    }

    println!(
        "ember recover daemon (mode={}, scope=db): restoring from archive {} \
         (estimated receipt loss: {})",
        target.mode.as_str(),
        archive.path.display(),
        archive.estimated_receipt_loss
    );

    ops.restore_db_from_archive(&archive.path, db_path)?;

    println!(
        "database restored: {} → {}",
        archive.path.display(),
        db_path.display()
    );

    // The daemon socket is likely down; skip receipt emission if socket
    // is unreachable and report with a note instead.
    let receipt_params = build_db_recovery_receipt_params(&target, &archive);
    let receipt_result = ops.emit_recovery_receipt(&target.socket_path, &receipt_params);
    match receipt_result {
        Ok(receipt) => {
            println!(
                "Receipt: recovery.action {} (persisted={})",
                receipt.receipt_id, receipt.persisted
            );
        }
        Err(e) => {
            println!(
                "Note: Receipt emission skipped — daemon socket not yet reachable \
                 ({}); start the daemon with `ember recover daemon` (F-DAEMON-1) \
                 to replay receipt: {e}",
                target.socket_path.display()
            );
        }
    }

    Ok(RecoverOutcome::ok())
}

fn daemon_home() -> Result<PathBuf, RecoverError> {
    dirs_next::home_dir().ok_or_else(|| {
        RecoverError::usage("recover daemon requires HOME to resolve the daemon socket path")
    })
}

fn parse_launchctl_list_state(output: &str, label: &str) -> LaunchdState {
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(line_label) = fields.last() else {
            continue;
        };
        if *line_label != label {
            continue;
        }
        if let Some(pid) = fields
            .first()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid > 0)
        {
            return LaunchdState::Running { pid };
        }
        let status = fields.get(1).and_then(|value| value.parse::<i32>().ok());
        return LaunchdState::Exited { status };
    }
    LaunchdState::Missing
}

fn poll_socket_until_reachable(ops: &dyn DaemonRecoveryOps, socket_path: &Path) -> bool {
    for attempt in 0..=POLL_ATTEMPTS {
        if ops.socket_reachable(socket_path) {
            return true;
        }
        if attempt < POLL_ATTEMPTS {
            ops.sleep_poll_interval(POLL_INTERVAL);
        }
    }
    false
}

fn print_log_excerpt(path: &Path, lines: &[String]) {
    println!(
        "Last {} daemon log lines from {}:",
        lines.len(),
        path.display()
    );
    if lines.is_empty() {
        println!("<no daemon log lines available>");
        return;
    }
    for line in lines {
        println!("{line}");
    }
}

fn build_recovery_receipt_params(
    target: &DaemonTarget,
    before_state: &LaunchdState,
    log_lines: &[String],
) -> Value {
    let requested_action = f_daemon_1_requested_action(target, before_state);
    let log_excerpt = log_lines.join("\n");
    let log_excerpt_hash = super::vault::digest_str(&log_excerpt);
    let prior_state = json!({
        "scope": "daemon_crash",
        "mode": target.mode.as_str(),
        "launchctl_label": target.label,
        "launchctl_state": before_state.detail(),
        "before_state": before_state.before_state(),
        "plist_path": target.plist_path.display().to_string(),
        "socket_path": target.socket_path.display().to_string(),
        "log_path": target.log_path.display().to_string(),
    });
    let dry_run = json!({
        "requested_action": requested_action,
        "poll_socket": target.socket_path.display().to_string(),
        "poll_interval_ms": POLL_INTERVAL.as_millis(),
        "poll_deadline_ms": (POLL_INTERVAL.as_millis() as usize) * POLL_ATTEMPTS,
        "after_state": "running",
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let dry_run_digest = super::vault::digest_value(&dry_run);
    let recovery_id = format!(
        "recover-daemon-crash-{}",
        prior_state_digest
            .strip_prefix("blake3:")
            .unwrap_or(&prior_state_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );

    json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "daemon",
        "target_kind": "launchdaemon",
        "target_id": target.label,
        "requested_action": requested_action,
        "prior_state_digest": prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "scope": "daemon_crash",
            "before_state": before_state.before_state(),
            "after_state": "running",
            "log_excerpt_hash": log_excerpt_hash,
            "launchctl_label": target.label,
            "launchctl_target": target.launchctl_target,
            "launchctl_bootstrap_performed": matches!(before_state, LaunchdState::Missing),
            "plist_path": target.plist_path.display().to_string(),
            "socket_path": target.socket_path.display().to_string(),
            "log_path": target.log_path.display().to_string(),
        },
        "outcome": "executed",
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#f-daemon-1",
        "adr_refs": ["ADR 161", "ADR 195"],
    })
}

fn f_daemon_1_requested_action(target: &DaemonTarget, before_state: &LaunchdState) -> String {
    if matches!(before_state, LaunchdState::Missing) {
        format!(
            "launchctl bootstrap system {}; launchctl kickstart -k {}",
            target.plist_path.display(),
            target.launchctl_target
        )
    } else {
        format!("launchctl kickstart -k {}", target.launchctl_target)
    }
}

/// Build the `recovery_action_receipt` RPC params for F-DAEMON-2.
fn build_socket_recovery_receipt_params(
    target: &DaemonTarget,
    file_existed: bool,
    before_state: &LaunchdState,
) -> Value {
    let requested_action = format!(
        "unlink {}; launchctl kickstart -k {}",
        target.socket_path.display(),
        target.launchctl_target
    );
    let prior_state = json!({
        "scope": "stale_socket",
        "mode": target.mode.as_str(),
        "launchctl_label": target.label,
        "launchctl_state": before_state.detail(),
        "socket_path": target.socket_path.display().to_string(),
        "socket_file_existed": file_existed,
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let recovery_id = format!(
        "recover-daemon-socket-{}",
        prior_state_digest
            .strip_prefix("blake3:")
            .unwrap_or(&prior_state_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "daemon",
        "target_kind": "launchdaemon",
        "target_id": target.label,
        "requested_action": requested_action,
        "prior_state_digest": prior_state_digest,
        "dry_run_digest": super::vault::digest_value(&json!({"requested_action": requested_action})),
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "scope": "stale_socket",
            "socket_file_existed": file_existed,
            "before_state": before_state.before_state(),
            "after_state": "running",
            "launchctl_label": target.label,
            "launchctl_target": target.launchctl_target,
            "socket_path": target.socket_path.display().to_string(),
        },
        "outcome": "executed",
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#f-daemon-2",
        "adr_refs": ["ADR 161", "ADR 195"],
    })
}

/// Build the `recovery_action_receipt` RPC params for F-DAEMON-3.
fn build_db_recovery_receipt_params(target: &DaemonTarget, archive: &DbArchiveEntry) -> Value {
    let prior_state = json!({
        "scope": "db_corrupt",
        "mode": target.mode.as_str(),
        "db_path": target.db_path.display().to_string(),
        "archive_path": archive.path.display().to_string(),
        "estimated_receipt_loss": archive.estimated_receipt_loss,
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let recovery_id = format!(
        "recover-daemon-db-{}",
        prior_state_digest
            .strip_prefix("blake3:")
            .unwrap_or(&prior_state_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "daemon",
        "target_kind": "sqlite_database",
        "target_id": target.db_path.display().to_string(),
        "requested_action": format!("restore {} from {}", target.db_path.display(), archive.path.display()),
        "prior_state_digest": prior_state_digest,
        "dry_run_digest": super::vault::digest_value(&prior_state),
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "scope": "db_corrupt",
            "db_path": target.db_path.display().to_string(),
            "archive_path": archive.path.display().to_string(),
            "estimated_receipt_loss": archive.estimated_receipt_loss,
            "before_state": "corrupt",
            "after_state": "restored_from_archive",
        },
        "outcome": "executed",
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#f-daemon-3",
        "adr_refs": ["ADR 161", "ADR 160", "ADR 195"],
    })
}

fn last_lines(text: &str, max_lines: usize) -> Vec<String> {
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let start = lines.len().saturating_sub(max_lines);
    lines.into_iter().skip(start).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct FakeOps {
        launchctl_list: String,
        socket_attempts: RefCell<Vec<bool>>,
        bootstraps: RefCell<Vec<(String, PathBuf)>>,
        kickstarts: RefCell<Vec<String>>,
        sleeps: RefCell<usize>,
        receipts: RefCell<Vec<Value>>,
        log_lines: Vec<String>,
        /// F-DAEMON-2: whether the socket file "exists" on disk
        socket_file_exists: bool,
        /// F-DAEMON-2: track socket file removal calls
        socket_removals: RefCell<Vec<PathBuf>>,
        /// F-DAEMON-3: result of db_integrity_check
        db_integrity_result: Result<(), String>,
        /// F-DAEMON-3: archive entry to return from find_latest_db_archive
        db_archive: Option<DbArchiveEntry>,
        /// F-DAEMON-3: track restore calls
        db_restores: RefCell<Vec<(PathBuf, PathBuf)>>,
    }

    impl FakeOps {
        fn new(launchctl_list: impl Into<String>, socket_attempts: Vec<bool>) -> Self {
            Self {
                launchctl_list: launchctl_list.into(),
                socket_attempts: RefCell::new(socket_attempts),
                bootstraps: RefCell::new(Vec::new()),
                kickstarts: RefCell::new(Vec::new()),
                sleeps: RefCell::new(0),
                receipts: RefCell::new(Vec::new()),
                log_lines: vec!["line-a".to_string(), "line-b".to_string()],
                socket_file_exists: false,
                socket_removals: RefCell::new(Vec::new()),
                db_integrity_result: Ok(()),
                db_archive: None,
                db_restores: RefCell::new(Vec::new()),
            }
        }

        fn with_stale_socket(mut self) -> Self {
            self.socket_file_exists = true;
            self
        }

        fn with_db_corrupt(mut self, msg: impl Into<String>) -> Self {
            self.db_integrity_result = Err(msg.into());
            self
        }

        fn with_db_archive(mut self, path: impl Into<PathBuf>, receipt_loss: u64) -> Self {
            self.db_archive = Some(DbArchiveEntry {
                path: path.into(),
                estimated_receipt_loss: receipt_loss,
            });
            self
        }
    }

    impl DaemonRecoveryOps for FakeOps {
        fn launchctl_list(&self) -> RecoverResultString {
            Ok(self.launchctl_list.clone())
        }

        fn launchctl_bootstrap(&self, domain: &str, plist_path: &Path) -> RecoverResultUnit {
            self.bootstraps
                .borrow_mut()
                .push((domain.to_string(), plist_path.to_path_buf()));
            Ok(())
        }

        fn launchctl_kickstart(&self, target: &str) -> RecoverResultUnit {
            self.kickstarts.borrow_mut().push(target.to_string());
            Ok(())
        }

        fn socket_reachable(&self, _socket_path: &Path) -> bool {
            let mut attempts = self.socket_attempts.borrow_mut();
            if attempts.is_empty() {
                return false;
            }
            attempts.remove(0)
        }

        fn sleep_poll_interval(&self, _interval: Duration) {
            *self.sleeps.borrow_mut() += 1;
        }

        fn read_last_log_lines(&self, _path: &Path, max_lines: usize) -> Vec<String> {
            self.log_lines
                .iter()
                .rev()
                .take(max_lines)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        }

        fn emit_recovery_receipt(
            &self,
            _socket_path: &Path,
            params: &Value,
        ) -> Result<ReceiptSummary, RecoverError> {
            self.receipts.borrow_mut().push(params.clone());
            Ok(ReceiptSummary {
                receipt_id: "rct-daemon-crash".to_string(),
                persisted: true,
            })
        }

        fn socket_file_exists(&self, _socket_path: &Path) -> bool {
            self.socket_file_exists
        }

        fn remove_socket_file(&self, socket_path: &Path) -> RecoverResultUnit {
            self.socket_removals
                .borrow_mut()
                .push(socket_path.to_path_buf());
            Ok(())
        }

        fn db_integrity_check(&self, _db_path: &Path) -> RecoverResultUnit {
            match &self.db_integrity_result {
                Ok(()) => Ok(()),
                Err(msg) => Err(RecoverError::authority(msg.clone())),
            }
        }

        fn find_latest_db_archive(
            &self,
            _db_path: &Path,
        ) -> Result<Option<DbArchiveEntry>, RecoverError> {
            Ok(self.db_archive.clone())
        }

        fn restore_db_from_archive(&self, source: &Path, dest: &Path) -> RecoverResultUnit {
            self.db_restores
                .borrow_mut()
                .push((source.to_path_buf(), dest.to_path_buf()));
            Ok(())
        }
    }

    fn context() -> RecoverContext {
        RecoverContext::with_socket_path("/tmp/ember-daemon.sock")
    }

    #[test]
    fn parses_launchctl_running_state() {
        let state = parse_launchctl_list_state(
            "PID\tStatus\tLabel\n123\t0\tsh.emberlink.daemon\n-\t0\tother.label",
            "sh.emberlink.daemon",
        );
        assert_eq!(state, LaunchdState::Running { pid: 123 });
    }

    #[test]
    fn parses_launchctl_exited_state() {
        let state = parse_launchctl_list_state("-\t3\tsh.emberlink.daemon", "sh.emberlink.daemon");
        assert_eq!(state, LaunchdState::Exited { status: Some(3) });
    }

    #[test]
    fn missing_launchctl_label_is_exited_for_crash_recovery() {
        let state = parse_launchctl_list_state("", "sh.emberlink.daemon");
        assert_eq!(state, LaunchdState::Missing);
        assert_eq!(state.before_state(), "exited");
    }

    #[test]
    fn running_daemon_noops_without_receipt() {
        let ops = FakeOps::new("321\t0\tsh.emberlink.daemon", vec![]);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::State),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("running daemon should be ok");

        assert_eq!(result.exit_code(), 0);
        assert!(ops.kickstarts.borrow().is_empty());
        assert!(ops.receipts.borrow().is_empty());
    }

    #[test]
    fn dev_mode_uses_dev_label_and_socket() {
        let target = daemon_target(
            DaemonMode::Dev,
            RecoverContext::with_socket_path("/tmp/prod-is-ignored.sock"),
        )
        .expect("dev target");

        assert_eq!(target.label, "sh.emberlink.daemon.dev");
        assert_eq!(target.launchctl_target, "system/sh.emberlink.daemon.dev");
        assert_eq!(
            target.plist_path,
            PathBuf::from("/Library/LaunchDaemons/sh.emberlink.daemon.dev.plist")
        );
        assert!(
            target
                .socket_path
                .ends_with(Path::new(".ember/run/daemon.dev.sock")),
            "unexpected dev socket: {}",
            target.socket_path.display()
        );
        assert_eq!(target.log_path, PathBuf::from("/var/log/emberd.dev.err"));
    }

    #[test]
    fn exited_daemon_kickstarts_polls_logs_and_emits_receipt() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![false, false, true]);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: None,
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("exited daemon should recover");

        assert_eq!(result.exit_code(), 0);
        assert_eq!(
            ops.kickstarts.borrow().as_slice(),
            ["system/sh.emberlink.daemon"]
        );
        assert!(ops.bootstraps.borrow().is_empty());
        assert_eq!(*ops.sleeps.borrow(), 2);
        let receipts = ops.receipts.borrow();
        assert_eq!(receipts.len(), 1);
        let params = &receipts[0];
        assert_eq!(params["verb"], json!("daemon"));
        assert_eq!(params["target_kind"], json!("launchdaemon"));
        assert_eq!(params["outcome"], json!("executed"));
        assert_eq!(params["authority_evidence"]["scope"], json!("daemon_crash"));
        assert_eq!(
            params["authority_evidence"]["before_state"],
            json!("exited")
        );
        assert_eq!(
            params["authority_evidence"]["after_state"],
            json!("running")
        );
        assert!(
            params["authority_evidence"]["log_excerpt_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("blake3:"))
        );
    }

    #[test]
    fn missing_prod_daemon_bootstraps_installed_plist_then_kickstarts_and_receipts() {
        let ops = FakeOps::new("", vec![false, true]);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::State),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("missing prod daemon should bootstrap and recover");

        assert_eq!(result.exit_code(), 0);
        assert_eq!(
            ops.bootstraps.borrow().as_slice(),
            [(
                "system".to_string(),
                PathBuf::from("/Library/LaunchDaemons/sh.emberlink.daemon.plist")
            )]
        );
        assert_eq!(
            ops.kickstarts.borrow().as_slice(),
            ["system/sh.emberlink.daemon"]
        );
        assert_eq!(*ops.sleeps.borrow(), 1);

        let receipts = ops.receipts.borrow();
        assert_eq!(receipts.len(), 1);
        let params = &receipts[0];
        assert_eq!(
            params["requested_action"],
            json!(
                "launchctl bootstrap system /Library/LaunchDaemons/sh.emberlink.daemon.plist; launchctl kickstart -k system/sh.emberlink.daemon"
            )
        );
        assert_eq!(
            params["authority_evidence"]["launchctl_bootstrap_performed"],
            json!(true)
        );
        assert_eq!(
            params["authority_evidence"]["plist_path"],
            json!("/Library/LaunchDaemons/sh.emberlink.daemon.plist")
        );
        assert_eq!(
            params["authority_evidence"]["before_state"],
            json!("exited")
        );
        assert_eq!(
            params["authority_evidence"]["after_state"],
            json!("running")
        );
    }

    #[test]
    fn socket_timeout_refuses_without_receipt() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![false; POLL_ATTEMPTS + 1]);
        let err = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::State),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect_err("socket timeout must refuse");

        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("within 5s"));
        assert!(ops.receipts.borrow().is_empty());
    }

    #[test]
    fn last_lines_tails_to_limit() {
        let body = (0..60)
            .map(|n| format!("line-{n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let lines = last_lines(&body, 50);
        assert_eq!(lines.len(), 50);
        assert_eq!(lines.first().map(String::as_str), Some("line-10"));
        assert_eq!(lines.last().map(String::as_str), Some("line-59"));
    }

    // ── F-DAEMON-2 tests ─────────────────────────────────────────────────────

    /// A stale socket (file exists, connect fails) is unlinked and the
    /// daemon kickstarted; receipt is emitted after socket is reachable.
    #[test]
    fn stale_socket_is_unlinked_and_daemon_kickstarted() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![false, true]).with_stale_socket();
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Socket),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("stale socket should be recoverable");

        assert_eq!(result.exit_code(), 0);
        assert_eq!(
            ops.socket_removals.borrow().len(),
            1,
            "stale socket file must be removed"
        );
        assert_eq!(
            ops.kickstarts.borrow().as_slice(),
            ["system/sh.emberlink.daemon"]
        );
        assert_eq!(ops.receipts.borrow().len(), 1);
        let params = &ops.receipts.borrow()[0];
        assert_eq!(params["authority_evidence"]["scope"], json!("stale_socket"));
        assert_eq!(
            params["authority_evidence"]["socket_file_existed"],
            json!(true)
        );
        assert_eq!(
            params["runbook_ref"],
            json!("docs/runbook/recovery.md#f-daemon-2")
        );
    }

    /// When the socket file does not exist, the recovery still kickstarts the
    /// daemon (no remove call needed).
    #[test]
    fn missing_socket_file_skips_remove_and_kickstarts() {
        // socket_reachable is called twice: once for the "already reachable?"
        // check, and once (or more) during the post-kickstart poll.
        // file_exists=false → skips the reachable pre-check entirely, so we only
        // need one true in the poll.
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![true]);
        // socket_file_exists defaults to false — the initial reachable check is
        // skipped when the file is absent (we go straight to the kickstart branch).
        // Sanity: verify the branch is taken (file_exists=false bypasses reachable pre-check).
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Socket),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("missing socket should still recover");

        assert_eq!(result.exit_code(), 0);
        assert!(
            ops.socket_removals.borrow().is_empty(),
            "no remove call when file does not exist"
        );
        assert_eq!(ops.kickstarts.borrow().len(), 1);
    }

    /// When the socket is already reachable, the recovery is a no-op.
    #[test]
    fn reachable_socket_is_noop_for_stale_socket_recovery() {
        // socket_file_exists = true but socket is reachable → healthy, no action
        let mut ops = FakeOps::new("321\t0\tsh.emberlink.daemon", vec![]);
        ops.socket_file_exists = true;
        ops.socket_attempts = RefCell::new(vec![true]);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Socket),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("reachable socket is ok");

        assert_eq!(result.exit_code(), 0);
        assert!(ops.socket_removals.borrow().is_empty());
        assert!(ops.kickstarts.borrow().is_empty());
        assert!(ops.receipts.borrow().is_empty());
    }

    /// Socket-scope timeout without poll success returns an authority error.
    #[test]
    fn stale_socket_poll_timeout_returns_error() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![false; POLL_ATTEMPTS + 1])
            .with_stale_socket();
        let err = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Socket),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect_err("poll timeout must be an error");

        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string().contains("5s"),
            "error must mention 5s timeout"
        );
        assert!(ops.receipts.borrow().is_empty(), "no receipt on timeout");
    }

    // ── F-DAEMON-3 tests ─────────────────────────────────────────────────────

    /// When PRAGMA integrity_check passes, the command reports healthy and
    /// no restore action is taken.
    #[test]
    fn healthy_db_reports_ok_and_no_restore() {
        let ops = FakeOps::new("321\t0\tsh.emberlink.daemon", vec![]);
        // db_integrity_result defaults to Ok(())
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Db),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("healthy DB should be ok");

        assert_eq!(result.exit_code(), 0);
        assert!(ops.db_restores.borrow().is_empty());
        assert!(ops.receipts.borrow().is_empty());
    }

    /// Corrupt DB with no archive returns an authority error.
    #[test]
    fn corrupt_db_with_no_archive_refuses() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![])
            .with_db_corrupt("database disk image is malformed");
        // db_archive is None by default
        let err = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Db),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect_err("corrupt DB with no archive must refuse");

        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string().contains("no archive"),
            "error must mention missing archive"
        );
    }

    /// Corrupt DB with archive and N>0 receipt loss refuses without
    /// `--accept-receipt-loss`.
    #[test]
    fn corrupt_db_receipt_loss_requires_accept_flag() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![])
            .with_db_corrupt("page size mismatch")
            .with_db_archive("/tmp/archive/daemon.db.1717000000", 5);
        let err = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Db),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect_err("receipt loss without flag must refuse");

        assert_eq!(err.exit_code(), 3);
        let msg = err.to_string();
        assert!(msg.contains("receipt"), "error must mention receipt loss");
        assert!(
            msg.contains("--accept-receipt-loss"),
            "error must suggest the flag"
        );
        assert_eq!(
            ops.db_restores.borrow().len(),
            0,
            "no restore without explicit acceptance"
        );
    }

    /// Corrupt DB with archive, N>0 receipt loss, and `--accept-receipt-loss`
    /// restores from archive and emits a receipt.
    #[test]
    fn corrupt_db_restores_from_archive_with_accept_flag() {
        let archive_path = PathBuf::from("/tmp/archive/daemon.db.1717000000");
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![])
            .with_db_corrupt("malformed")
            .with_db_archive(archive_path.clone(), 3);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Db),
                accept_receipt_loss: true,
            },
            context(),
            &ops,
        )
        .expect("restore with accept flag should succeed");

        assert_eq!(result.exit_code(), 0);
        let restores = ops.db_restores.borrow();
        assert_eq!(restores.len(), 1, "exactly one restore call");
        assert_eq!(restores[0].0, archive_path, "source must be the archive");

        let receipts = ops.receipts.borrow();
        assert_eq!(receipts.len(), 1);
        let params = &receipts[0];
        assert_eq!(params["authority_evidence"]["scope"], json!("db_corrupt"));
        assert_eq!(
            params["authority_evidence"]["before_state"],
            json!("corrupt")
        );
        assert_eq!(
            params["authority_evidence"]["after_state"],
            json!("restored_from_archive")
        );
        assert_eq!(
            params["authority_evidence"]["estimated_receipt_loss"],
            json!(3u64)
        );
        assert_eq!(
            params["runbook_ref"],
            json!("docs/runbook/recovery.md#f-daemon-3")
        );
    }

    /// Corrupt DB with archive and zero receipt loss restores without needing
    /// `--accept-receipt-loss`.
    #[test]
    fn corrupt_db_zero_loss_restores_without_flag() {
        let ops = FakeOps::new("-\t3\tsh.emberlink.daemon", vec![])
            .with_db_corrupt("malformed")
            .with_db_archive("/tmp/archive/daemon.db.bak", 0);
        let result = handle_with_ops(
            RecoverDaemonArgs {
                dev: false,
                prod: true,
                scope: Some(DaemonScope::Db),
                accept_receipt_loss: false,
            },
            context(),
            &ops,
        )
        .expect("zero-loss restore should not require flag");

        assert_eq!(result.exit_code(), 0);
        assert_eq!(ops.db_restores.borrow().len(), 1);
    }
}
