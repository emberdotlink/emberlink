//! Session heartbeat watcher — H1 dirty-exit detection.
//!
//! H1 invariant (cohort-A test plan): every grant terminates in a signed
//! Receipt across all four termination paths. This watcher implements the
//! dirty-exit path: when a launcher PID dies without sending `session.close`,
//! the daemon must still emit a Receipt.
//!
//! Heartbeat protocol:
//!   - Launcher writes the current ISO-8601 timestamp into
//!     `<session_dir>/heartbeat` every 30 s.
//!   - Watcher reads the file's contents (or its mtime as a fallback) on
//!     each tick.
//!   - When >`HEARTBEAT_TIMEOUT` (90 s) elapses since the last fresh
//!     heartbeat AND `kill(launcher_pid, 0)` returns `ESRCH`, the watcher
//!     calls into [`crate::session::lifecycle::transition_to_terminated_dirty`]
//!     to close the session, emit the Receipt, and revoke the grant.
//!
//! Why 90 s — three missed heartbeats at the 30 s cadence. One miss is
//! transient; three is "the launcher process is gone." Mirrors the
//! `liveness-fail-after-3-misses` convention used elsewhere in the codebase.
//!
//! Why `kill(pid, 0)` — POSIX-portable PID liveness check that does no harm
//! (signal 0 is the "validate target" signal). `ESRCH` means the PID is
//! gone; `EPERM` means the PID exists but we can't signal it (treat as
//! alive). Mirrors the existing [`crate::session_watcher::pid_alive`] helper.

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use core_state::sessions::{SessionMeta, SessionStore};
use tracing::{debug, info, warn};

use crate::infra::store::DaemonStore;
use crate::session::lifecycle;

/// Maximum time without a fresh heartbeat before the watcher considers a
/// session a dirty-exit candidate. 90 s = three missed 30 s heartbeats.
pub const HEARTBEAT_TIMEOUT: chrono::Duration = chrono::Duration::seconds(90);

/// Filename of the heartbeat sidecar inside `<session_dir>/`.
pub const HEARTBEAT_FILENAME: &str = "heartbeat";

/// Watcher tick cadence. Smaller than the 90 s timeout so the watcher
/// converges within ~1 tick of the timeout boundary.
pub const WATCHER_INTERVAL: StdDuration = StdDuration::from_secs(30);

/// Read the last heartbeat timestamp for `session_id` from the
/// `<session_dir>/heartbeat` file.
///
/// Returns:
/// - `Some(ts)` — file present and contains a parseable ISO-8601 timestamp.
/// - `None` — file absent, empty, or unparseable. Caller should fall back
///   to the session's `started_at` (i.e. treat the session start as the
///   first implicit heartbeat).
pub fn read_heartbeat(session_dir: &Path) -> Option<DateTime<Utc>> {
    let path = session_dir.join(HEARTBEAT_FILENAME);
    let contents = std::fs::read_to_string(&path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Write `now` as an ISO-8601 timestamp into `<session_dir>/heartbeat`.
///
/// Used by tests and (eventually) by the launcher's heartbeat tick. Atomic
/// via tempfile + rename so a crash mid-write leaves no partial bytes.
pub fn write_heartbeat(session_dir: &Path, now: DateTime<Utc>) -> std::io::Result<()> {
    let path = session_dir.join(HEARTBEAT_FILENAME);
    let tmp = session_dir.join(format!("{HEARTBEAT_FILENAME}.tmp"));
    std::fs::write(&tmp, now.to_rfc3339())?;
    std::fs::rename(&tmp, &path)
}

/// Check whether a process with the given PID is still alive.
///
/// Uses the shared daemon PID liveness helper so macOS separate-uid posture
/// does not misclassify live cross-uid launcher processes as gone.
pub fn pid_alive(pid: u32) -> bool {
    crate::infra::pid::process_exists(pid)
}

/// One pass of the heartbeat watcher. Visible for testing — production code
/// calls [`run`] which loops this every [`WATCHER_INTERVAL`].
///
/// For each open session:
/// 1. Compute `last_heartbeat_at` from the heartbeat sidecar (falling back
///    to `started_at`).
/// 2. If `now - last_heartbeat > HEARTBEAT_TIMEOUT` AND the launcher PID is
///    dead, call [`lifecycle::transition_to_terminated_dirty`].
///
/// Returns the count of sessions transitioned this pass.
pub fn tick(
    daemon_store: &DaemonStore,
    session_store: &SessionStore,
    sessions_dir: &Path,
    now: DateTime<Utc>,
) -> usize {
    let sessions = match session_store.list_open() {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "heartbeat watcher: failed to list open sessions");
            return 0;
        }
    };

    let mut transitioned = 0;
    for session in sessions {
        if check_one(daemon_store, session_store, sessions_dir, &session, now) {
            transitioned += 1;
        }
    }
    transitioned
}

/// Evaluate one session. Returns `true` when the session was transitioned
/// to `terminated_dirty`.
fn check_one(
    daemon_store: &DaemonStore,
    session_store: &SessionStore,
    sessions_dir: &Path,
    session: &SessionMeta,
    now: DateTime<Utc>,
) -> bool {
    let session_dir = sessions_dir.join(&session.session_id);
    let last_heartbeat_at = read_heartbeat(&session_dir).unwrap_or(session.started_at);
    let elapsed = now.signed_duration_since(last_heartbeat_at);

    if elapsed <= HEARTBEAT_TIMEOUT {
        debug!(
            session_id = %session.session_id,
            elapsed_secs = elapsed.num_seconds(),
            "heartbeat watcher: session within heartbeat window"
        );
        return false;
    }

    let alive = pid_alive(session.launcher_pid);
    if alive {
        // Heartbeat stale but launcher still alive — could be a paused
        // process or a stuck heartbeat writer. Don't terminate; log and
        // wait for the next tick. PID-liveness is the load-bearing gate.
        warn!(
            session_id = %session.session_id,
            launcher_pid = session.launcher_pid,
            elapsed_secs = elapsed.num_seconds(),
            "heartbeat watcher: heartbeat stale but launcher PID still alive — deferring"
        );
        return false;
    }

    info!(
        session_id = %session.session_id,
        launcher_pid = session.launcher_pid,
        last_heartbeat_at = %last_heartbeat_at.to_rfc3339(),
        elapsed_secs = elapsed.num_seconds(),
        "heartbeat watcher: launcher PID dead + heartbeat lost — terminating dirty"
    );

    if let Err(e) = lifecycle::transition_to_terminated_dirty_at(
        daemon_store,
        session_store,
        sessions_dir,
        session,
        last_heartbeat_at,
        /* pid_alive_at_check */ false,
    ) {
        warn!(
            session_id = %session.session_id,
            error = %e,
            "heartbeat watcher: terminated_dirty transition failed"
        );
        return false;
    }
    true
}

/// Background task: drives [`tick`] every [`WATCHER_INTERVAL`].
///
/// Spawned via `spawn_local` on the daemon's `LocalSet` so it shares the
/// single-threaded context as `DaemonStore` (which is `!Send`).
pub async fn run(store: Rc<DaemonStore>, sessions_dir: PathBuf) {
    let session_store = SessionStore::new(sessions_dir.clone());
    let mut interval = tokio::time::interval(WATCHER_INTERVAL);

    loop {
        interval.tick().await;
        tick(&store, &session_store, &sessions_dir, Utc::now());
    }
}

#[cfg(test)]
mod tests {
    //! T2: heartbeat unit tests use temporary session directories.

    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    #[test]
    fn read_heartbeat_returns_some_for_iso8601_contents() {
        let dir = TempDir::new().unwrap();
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap();
        write_heartbeat(dir.path(), now).unwrap();
        let read = read_heartbeat(dir.path()).expect("heartbeat parses");
        assert_eq!(read, now);
    }

    #[test]
    fn read_heartbeat_returns_none_when_file_missing() {
        let dir = TempDir::new().unwrap();
        assert!(read_heartbeat(dir.path()).is_none());
    }

    #[test]
    fn read_heartbeat_returns_none_when_file_empty() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(HEARTBEAT_FILENAME), b"").unwrap();
        assert!(read_heartbeat(dir.path()).is_none());
    }

    #[test]
    fn read_heartbeat_returns_none_when_contents_unparseable() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(HEARTBEAT_FILENAME), b"not a date").unwrap();
        assert!(read_heartbeat(dir.path()).is_none());
    }

    #[test]
    fn pid_alive_true_for_self() {
        // The current test process must report alive — sanity-check the
        // wrapper before T2 tests rely on it for "fake-dead" PIDs.
        assert!(pid_alive(std::process::id()));
    }

    #[test]
    fn pid_alive_false_for_unused_high_pid() {
        // PID 0x7FFF_FFFE is well above any plausible live PID on Linux
        // (PID_MAX_LIMIT is 4M by default). On macOS the kernel won't
        // assign anywhere near this. Treat ESRCH as the expected outcome.
        // We can't construct a guaranteed-dead PID without spawning + waitpid,
        // but a high checkpoint suffices for a smoke-test of the wrapper shape.
        // Skip the assertion if the platform happens to assign it (effectively
        // never on a real test runner).
        let alive = pid_alive(0x7FFF_FFFE);
        assert!(
            !alive,
            "PID 0x7FFF_FFFE should be dead on a real test runner"
        );
    }

    #[test]
    fn heartbeat_timeout_is_90_seconds() {
        // Locked at 90s — three missed 30s heartbeats. Test pins the
        // constant so a future drift is caught.
        assert_eq!(HEARTBEAT_TIMEOUT.num_seconds(), 90);
    }
}
