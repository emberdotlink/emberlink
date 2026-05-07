use std::path::PathBuf;
use std::rc::Rc;

use chrono::{DateTime, Duration, Utc};
use tracing::{info, warn};

use crate::infra::store::DaemonStore;
use core_state::sessions::SessionStore;

/// How long after a session's grant `created_at` before TTL backstop fires.
const GRANT_TTL: Duration = Duration::hours(24);

/// How long a launcher PID must be dead before the orphan sweep closes the session.
const ORPHAN_GRACE: Duration = Duration::minutes(5);

/// Check whether a process with the given PID is still alive.
///
/// Uses `kill(pid, 0)` — sends signal 0 which does no harm but returns an
/// error with `ESRCH` when the PID does not exist. Returns `true` when the
/// process is alive (or the caller lacks permission to signal it, which means
/// it exists).
fn pid_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is a read-only syscall: it never delivers a signal.
    // The only side effect is an errno value returned to us.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    // Read errno via std so this compiles on macOS and Linux without
    // platform-specific accessor function selection.
    let os_err = std::io::Error::last_os_error();
    let raw = os_err.raw_os_error().unwrap_or(0);
    // ESRCH — process does not exist.
    // EPERM — process exists but we can't signal it; treat as alive.
    raw != libc::ESRCH
}

/// Derive the sessions directory from the data directory.
///
/// Convention: `~/.ember/data/` → `~/.ember/sessions/`. We walk up one level
/// from `data_dir` and append `sessions/`. If the parent is unavailable we
/// fall back to `data_dir/../sessions` which is the same path on a standard
/// install.
pub fn sessions_dir_from_data(data_dir: &std::path::Path) -> PathBuf {
    data_dir
        .parent()
        .unwrap_or(data_dir)
        .join("sessions")
}

/// Background task: heartbeat + TTL session watcher.
///
/// Spawned via `spawn_local` on the daemon's `LocalSet` so it shares the same
/// single-threaded context as `DaemonStore` (which is `!Send`).
///
/// Loop cadence: 60 seconds. For each open session:
///
/// 1. **Orphan check** — if `launcher_pid` is dead AND the session has been
///    running for more than `ORPHAN_GRACE` (5 min), close it with reason
///    `"heartbeat-orphan"`.
/// 2. **TTL backstop** — if the session's grant `created_at + 24h` is in the
///    past, close it with reason `"ttl-expired"`.
///
/// Closing a session:
/// - calls `SessionStore::close` (renames `meta.json` → `meta.json.closed`)
/// - logs a `session.closed` event into the daemon audit log with the reason
///   as the `outcome` field.
pub async fn run(store: Rc<DaemonStore>, sessions_dir: PathBuf) {
    let session_store = SessionStore::new(sessions_dir);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let sessions = match session_store.list_open() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "session watcher: failed to list open sessions");
                continue;
            }
        };

        for session in sessions {
            let now = Utc::now();
            let session_id = &session.session_id;

            // --- Orphan check ---
            if !pid_alive(session.launcher_pid) {
                let age = now.signed_duration_since(session.started_at);
                if age > ORPHAN_GRACE {
                    info!(
                        session_id = %session_id,
                        launcher_pid = session.launcher_pid,
                        age_secs = age.num_seconds(),
                        "session watcher: orphaned session — closing"
                    );
                    close_session(&session_store, &store, session_id, "heartbeat-orphan");
                    continue;
                }
            }

            // --- TTL backstop ---
            let grant_expired = match store.get_grant(&session.grant_id) {
                Ok(grant_info) => {
                    match grant_info.created_at.parse::<DateTime<Utc>>() {
                        Ok(created_at) => {
                            let expiry = created_at + GRANT_TTL;
                            now > expiry
                        }
                        Err(e) => {
                            warn!(
                                session_id = %session_id,
                                grant_id = %session.grant_id,
                                error = %e,
                                "session watcher: could not parse grant created_at — skipping TTL check"
                            );
                            false
                        }
                    }
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    // Grant is gone — treat as TTL expired.
                    true
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        grant_id = %session.grant_id,
                        error = %e,
                        "session watcher: grant lookup failed — skipping TTL check"
                    );
                    false
                }
            };

            if grant_expired {
                info!(
                    session_id = %session_id,
                    grant_id = %session.grant_id,
                    "session watcher: grant TTL expired — closing session"
                );
                close_session(&session_store, &store, session_id, "ttl-expired");
            }
        }
    }
}

fn close_session(
    session_store: &SessionStore,
    daemon_store: &DaemonStore,
    session_id: &str,
    reason: &str,
) {
    if let Err(e) = session_store.close(session_id) {
        warn!(
            session_id = %session_id,
            error = %e,
            "session watcher: failed to close session"
        );
        return;
    }

    if let Err(e) = daemon_store.log_event(
        None,
        "session.closed",
        None,
        reason,
        Some(&format!("session_id={session_id}")),
    ) {
        warn!(
            session_id = %session_id,
            reason = %reason,
            error = %e,
            "session watcher: failed to log session.closed audit event"
        );
    }
}
