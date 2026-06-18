//! CLASSIFICATION: PUBLIC
//!
//! `ember recover audit` — recover audit-chain state per ADR 161.
//!
//! Scope routing:
//! - `rotate` — start a fresh audit segment with a cordon transition
//! - `verify` — run the audit verifier and report any chain failure
//! - `repair` — invoke `audit.repair_chain` to truncate-after-row a
//!   broken segment (ADR 174 v2)
//!
//! F-code surface:
//! - `F-AUDIT-1` — disk full; force-rotate the active audit-chain segment.
//!

use clap::{Args, ValueEnum};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverAuditArgs {
    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<AuditScope>,

    /// Target a specific F-code recovery action directly.
    /// `F-AUDIT-1` force-rotates the audit segment to free SQLite space.
    #[arg(long, value_name = "F_CODE", id = "audit_f_code")]
    pub f_code: Option<String>,

    /// Required for `--f-code F-AUDIT-1`: acknowledge that you understand
    /// rotation creates a new segment and old rows are NOT deleted (they
    /// remain in the SQLite file until you archive them). Prevents
    /// accidental invocation.
    #[arg(long)]
    pub force_rotate: bool,

    /// Path to the daemon SQLite database. Defaults to the standard
    /// daemon store path (`~/.ember/daemon.db` or equivalent). Override
    /// for testing or non-default installations.
    #[arg(long)]
    pub db_path: Option<std::path::PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuditScope {
    /// Start a fresh audit segment with a cordon transition.
    Rotate,
    /// Run the audit verifier and report any chain failure.
    Verify,
    /// Invoke `audit.repair_chain` to truncate-after-row a broken segment.
    Repair,
}

impl AuditScope {
    fn as_str(self) -> &'static str {
        match self {
            AuditScope::Rotate => "rotate",
            AuditScope::Verify => "verify",
            AuditScope::Repair => "repair",
        }
    }
}

pub fn handle(args: RecoverAuditArgs) -> RecoverResult {
    handle_with_context(args, &RecoverContext::default())
}

/// Internal dispatch with context — used by tests to inject a custom db path.
pub(crate) fn handle_with_context(args: RecoverAuditArgs, _ctx: &RecoverContext) -> RecoverResult {
    // F-code dispatch takes priority over scope routing.
    if let Some(ref f_code) = args.f_code {
        return match f_code.to_ascii_uppercase().as_str() {
            "F-AUDIT-1" => handle_f_audit_1(&args),
            other => Err(RecoverError::usage(format!(
                "unknown F-code `{other}` for `ember recover audit`; \
                 valid F-codes: F-AUDIT-1"
            ))),
        };
    }

    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "verify".to_string());

    println!(
        "ember recover audit (scope={scope}): scaffold only — per-F-code \
         implementations land as META-RECOVER-F-AUDIT-* tasks ship. See \
         `ember recover --explain F-AUDIT-1` (or 2) for the F-code-anchored runbook."
    );
    note_receipt_contract("audit", &scope);
    Ok(RecoverOutcome::ok())
}

// ---------------------------------------------------------------------------
// F-AUDIT-1 — Disk full; force-rotate the active audit-chain segment
// ---------------------------------------------------------------------------
//
// recover_f_audit_1_landed
//
// ADR 161 §F-AUDIT-1: daemon refuses any new broker_exec with "audit store
// full." Recovery: `ember recover audit --f-code F-AUDIT-1 --force-rotate`
// forces a new segment via `DaemonStore::force_rotate_audit_segment`.
//
// SECURITY NOTE: this is security-lane code. It writes directly to the
// daemon's audit chain (segment-start bridge row). The `--force-rotate` flag
// is required to prevent accidental invocation. The operator must also
// separately free disk space by deleting archive entries when the disk is
// genuinely full (not just the SQLite file growing).
//
// The `force_rotate_audit_segment` call creates a new segment with a
// `audit.forced_rotation` bridge row that chains from the last chained row
// in the previous segment — chain continuity is preserved. Prior rows are
// NOT deleted.
//
// Note: this surface writes directly to the daemon database on disk via
// `DaemonStore::open`. In a live daemon environment the operator should stop
// the daemon before running this command (or use the daemon-mediated RPC path
// once that is built). The CLI path is the recovery surface when the daemon
// cannot start at all because the audit store is full.

fn handle_f_audit_1(args: &RecoverAuditArgs) -> RecoverResult {
    if !args.force_rotate {
        return Err(RecoverError::usage(
            "F-AUDIT-1 requires --force-rotate to confirm you understand:\n\
             \n\
             - Rotation creates a new audit-chain segment.\n\
             - Rows in prior segments are NOT deleted; they remain in the SQLite file.\n\
             - To free disk space you must also delete archive entries from\n\
               ~/.ember/audit/archive/ (or the configured archive directory).\n\
             \n\
             Re-run with --force-rotate to proceed."
                .to_string(),
        ));
    }

    println!("ember recover audit F-AUDIT-1 — force-rotate audit segment");
    println!();

    // ADVERSARIAL-REVIEW-20260612 #1 — Quarantine gate is dead in the CLI
    // process (the daemon's is_quarantined() AtomicBool is a different process).
    // Mitigation: run the chain verifier on the open store BEFORE rotation and
    // refuse if the chain is broken (same class of break that triggers daemon
    // quarantine). This preserves the spirit of the quarantine gate for the
    // out-of-band recovery path. We also warn the operator explicitly.
    eprintln!(
        "  [warn] F-AUDIT-1 runs outside the daemon process. The daemon's quarantine \
         state cannot be read from here. A chain-integrity pre-check is performed \
         before rotation to detect known-broken chains."
    );

    let db_path = resolve_db_path(args.db_path.as_deref())?;
    println!("  db_path: {}", db_path.display());
    println!();

    // Open the store. If the daemon is running, this races with it — the
    // operator should stop the daemon first. SQLite's WAL mode can tolerate
    // concurrent readers but exclusive writes (BEGIN IMMEDIATE) will block.
    let store = open_store(&db_path)?;

    // ADVERSARIAL-REVIEW-20260612 #1 — Pre-rotation chain integrity check.
    // Refuse if the chain has a hard break (same class as daemon quarantine trigger).
    pre_rotation_chain_check(&store)?;

    let outcome = store
        .force_rotate_audit_segment()
        .map_err(|e| RecoverError::usage(format!("force_rotate_audit_segment failed: {e}")))?;

    println!("Audit segment rotation succeeded:");
    println!("  previous segment: {}", outcome.prev_segment_id,);
    println!(
        "  new segment:      {} (bridge row id={})",
        outcome.new_segment_id, outcome.bridge_row_id,
    );
    println!(
        "  bridge row hash:  {}",
        &outcome.bridge_row_hash[..std::cmp::min(16, outcome.bridge_row_hash.len())],
    );
    println!();
    println!(
        "Chain integrity is preserved. Prior rows remain in the SQLite file.\n\
         \n\
         To free disk space:\n\
         1. Verify the rotation succeeded: ember audit verify\n\
         2. Move archive entries from ~/.ember/audit/archive/ to cold storage.\n\
         3. VACUUM the database if needed: sqlite3 {} VACUUM",
        db_path.display(),
    );
    println!();
    println!("To restart the daemon after this rotation:\n  ember recover daemon --prod");

    note_receipt_contract("audit", "F-AUDIT-1");
    Ok(RecoverOutcome::ok())
}

/// Run a pre-rotation chain integrity check.
///
/// ADVERSARIAL-REVIEW-20260612 #1: since the daemon's quarantine AtomicBool
/// is not readable from the CLI process, we run the audit verifier directly on
/// the open store and refuse rotation if the chain has a hard break.
///
/// `LegacyRowsPresent`, `IncompleteRepair`, and `IncompleteRepairReceipt` are
/// NOT treated as blockers here — they are handled by `ember recover audit-chain`
/// and should not prevent a force-rotation that is freeing disk space. Only
/// `Break` and `ChainTopologyInvariantViolation` block rotation (same class as
/// daemon quarantine triggers).
fn pre_rotation_chain_check(store: &ember_daemon::infra::store::DaemonStore) -> RecoverResult {
    use ember_daemon::infra::audit::{BreakKind, VerifyOutcome, run_audit_verify};

    let outcome = run_audit_verify(store.conn(), None, None)
        .map_err(|e| RecoverError::usage(format!("pre-rotation chain verify failed: {e}")))?;

    match outcome {
        VerifyOutcome::Ok {
            rows_walked,
            segments_walked,
            ..
        } => {
            println!(
                "  pre-rotation chain verify: OK ({rows_walked} rows, {segments_walked} segments)"
            );
            Ok(RecoverOutcome::ok())
        }
        VerifyOutcome::Break { kind } => {
            let detail = match kind {
                BreakKind::RowHashMismatch { at_row_id, .. } => {
                    format!("RowHashMismatch at row {at_row_id}")
                }
                BreakKind::ForwardLinkMismatch { at_row_id, .. } => {
                    format!("ForwardLinkMismatch at row {at_row_id}")
                }
            };
            Err(RecoverError::usage(format!(
                "chain integrity check FAILED ({detail}); rotation refused.\n\
                 The chain is broken — force-rotating would hide the break in a closed segment.\n\
                 Fix the chain break first via `ember recover audit-chain --dry-run`,\n\
                 then retry F-AUDIT-1."
            )))
        }
        VerifyOutcome::ChainTopologyInvariantViolation {
            kind, at_row_id, ..
        } => Err(RecoverError::usage(format!(
            "chain topology invariant violated ({kind:?} at row {at_row_id}); rotation refused.\n\
                 Fix the topology issue first via `ember recover audit-chain --dry-run`."
        ))),
        // Non-blocking cases: proceed with a warning.
        VerifyOutcome::LegacyRowsPresent { count, .. } => {
            eprintln!(
                "  [warn] {count} legacy (pre-chain) rows present — not a blocker for rotation."
            );
            Ok(RecoverOutcome::ok())
        }
        VerifyOutcome::IncompleteRepair {
            ref receipt_id_orphan,
        } => {
            eprintln!(
                "  [warn] IncompleteRepair (orphan receipt {receipt_id_orphan}) — \
                 not a blocker for rotation; consider `ember recover audit-chain` after."
            );
            Ok(RecoverOutcome::ok())
        }
        VerifyOutcome::IncompleteRepairReceipt { tombstone_row_id } => {
            eprintln!(
                "  [warn] IncompleteRepairReceipt (tombstone row {tombstone_row_id}) — \
                 not a blocker for rotation; consider `ember recover audit-chain` after."
            );
            Ok(RecoverOutcome::ok())
        }
    }
}

/// Resolve the daemon database path with path-traversal protection.
///
/// ADVERSARIAL-REVIEW-20260612 #2: `--db-path` must not accept `..` components
/// (path traversal). When an override is supplied, we reject any path that
/// contains a `..` component. The default path (under `~/.ember/`) is always safe.
fn resolve_db_path(
    override_path: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, RecoverError> {
    if let Some(p) = override_path {
        // Reject path-traversal components.
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(RecoverError::usage(format!(
                "--db-path `{}` contains `..` path-traversal components — refusing",
                p.display()
            )));
        }
        return Ok(p.to_path_buf());
    }
    // Standard location: ~/.ember/daemon.db
    if let Some(home) = home_dir() {
        return Ok(home.join(".ember").join("daemon.db"));
    }
    // Fallback if home directory cannot be determined.
    Ok(std::path::PathBuf::from(".ember/daemon.db"))
}

/// Platform-agnostic home-directory resolution (no external deps required).
fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

/// Open the daemon store at the given path, mapping errors to `RecoverError`.
fn open_store(
    path: &std::path::Path,
) -> Result<ember_daemon::infra::store::DaemonStore, RecoverError> {
    ember_daemon::infra::store::DaemonStore::open(path).map_err(|e| {
        RecoverError::usage(format!(
            "could not open daemon store at {}: {}\n\n\
             If the daemon is running, stop it first:\n\
             launchctl stop sh.emberlink.daemon\n\
             Then retry this command.",
            path.display(),
            e
        ))
    })
}

// ---------------------------------------------------------------------------
// Unit tests (T1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // recover_f_audit_1_landed — force-rotate requires --force-rotate flag

    #[test]
    fn f_audit_1_requires_force_rotate_flag() {
        let args = RecoverAuditArgs {
            scope: None,
            f_code: Some("F-AUDIT-1".into()),
            force_rotate: false,
            db_path: None,
        };
        let result = handle(args);
        let err = result.expect_err("F-AUDIT-1 without --force-rotate should error");
        assert!(
            err.to_string().contains("--force-rotate"),
            "error should mention --force-rotate; got: {err}"
        );
    }

    #[test]
    fn f_audit_1_dispatch_case_insensitive() {
        // Use an in-memory DB so the test does not touch the real daemon store.
        let args = RecoverAuditArgs {
            scope: None,
            f_code: Some("f-audit-1".into()),
            force_rotate: false,
            db_path: None,
        };
        let result = handle(args);
        let err = result.expect_err("f-audit-1 without --force-rotate should error");
        assert!(
            err.to_string().contains("--force-rotate"),
            "case-insensitive dispatch reached F-AUDIT-1 handler; got: {err}"
        );
    }

    #[test]
    fn unknown_f_code_returns_usage_error() {
        let args = RecoverAuditArgs {
            scope: None,
            f_code: Some("F-AUDIT-99".into()),
            force_rotate: false,
            db_path: None,
        };
        let result = handle(args);
        let err = result.expect_err("unknown F-code should error");
        assert!(
            err.to_string().contains("unknown F-code"),
            "error should mention unknown F-code; got: {err}"
        );
    }

    #[test]
    fn no_f_code_falls_through_to_scaffold() {
        let args = RecoverAuditArgs {
            scope: None,
            f_code: None,
            force_rotate: false,
            db_path: None,
        };
        let result = handle(args);
        assert!(
            result.is_ok(),
            "scaffold path should return Ok; got {result:?}"
        );
    }

    /// F-AUDIT-1 with --force-rotate on an in-memory store completes successfully.
    /// Uses the daemon's `DaemonStore::open_in_memory` for isolation.
    #[test]
    fn f_audit_1_force_rotate_on_in_memory_store_succeeds() {
        let store = ember_daemon::infra::store::DaemonStore::open_in_memory()
            .expect("in-memory store open");

        // Seed one chained row so there is something to chain from.
        ember_daemon::infra::audit::append_audit_event_with_chain(
            &store,
            None,
            "test.action",
            None,
            "ok",
            None,
        )
        .expect("seed event");

        let segment_before: u64 = store
            .conn()
            .query_row(
                "SELECT COALESCE(MAX(segment_id), 0) FROM audit_log",
                [],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .unwrap_or(0);

        let outcome = store
            .force_rotate_audit_segment()
            .expect("force_rotate_audit_segment should succeed");

        assert_eq!(
            outcome.prev_segment_id, segment_before,
            "prev_segment_id should match the segment before rotation"
        );
        assert_eq!(
            outcome.new_segment_id,
            segment_before + 1,
            "new_segment_id should be prev + 1"
        );
        assert!(
            outcome.bridge_row_id > 0,
            "bridge_row_id should be a positive SQLite rowid"
        );
        assert!(
            !outcome.bridge_row_hash.is_empty(),
            "bridge_row_hash should not be empty"
        );

        // Verify the new segment genesis row is present.
        let genesis_count: i64 = store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM audit_log \
                 WHERE segment_id = ?1 AND is_segment_genesis = 1",
                rusqlite::params![outcome.new_segment_id as i64],
                |row| row.get(0),
            )
            .unwrap_or(0);
        assert_eq!(
            genesis_count, 1,
            "exactly one segment-genesis row for the new segment"
        );
    }

    /// F-AUDIT-1 twice produces two distinct new segments.
    #[test]
    fn f_audit_1_two_rotations_produce_distinct_segments() {
        let store = ember_daemon::infra::store::DaemonStore::open_in_memory()
            .expect("in-memory store open");

        let first = store.force_rotate_audit_segment().expect("first rotation");
        let second = store.force_rotate_audit_segment().expect("second rotation");

        assert_eq!(
            second.new_segment_id,
            first.new_segment_id + 1,
            "second rotation should increment segment by one"
        );
    }

    // ADVERSARIAL-REVIEW-20260612 #2 — path traversal protection

    #[test]
    fn resolve_db_path_rejects_parent_dir_components() {
        let p = std::path::Path::new("../../etc/passwd");
        let result = resolve_db_path(Some(p));
        let err = result.expect_err("path traversal should be rejected");
        assert!(
            err.to_string().contains(".."),
            "error should mention path traversal; got: {err}"
        );
    }

    #[test]
    fn resolve_db_path_accepts_normal_absolute_path() {
        let p = std::path::Path::new("/var/ember/daemon.db");
        let result = resolve_db_path(Some(p));
        assert!(
            result.is_ok(),
            "normal absolute path should be accepted; got {result:?}"
        );
    }

    #[test]
    fn resolve_db_path_default_is_under_home_ember() {
        let result = resolve_db_path(None).expect("default path should resolve");
        // Should end in .ember/daemon.db
        let s = result.to_string_lossy();
        assert!(
            s.contains(".ember") && s.ends_with("daemon.db"),
            "default path should be under .ember/; got: {s}"
        );
    }
}
