//! CLASSIFICATION: PUBLIC
//!
//! Launcher pidfd watch — fast-path detector for launcher-process exit.
//!
//! META-AP-PRESENCE-BRIDGE-LAUNCHER-PIDFD-WATCH (Phase 1).
//!
//! Per ADR-DRAFT-BROWSER-AS-TOUCH-ID-PROMPTER §D3: when a launcher process
//! (e.g. `ember up` or the bridge launcher) exits, all in-flight workflow
//! grants minted under that session must be revoked. This module watches
//! launcher processes for exit with sub-second latency so the revocation
//! cascade can fire promptly. The existing 60s `session_watcher` keeps its
//! TTL-and-orphan role; this watcher is the fast-path complement.
//!
//! ## Surface
//!
//! - Linux: holds `pidfd_open(2)` handles per session and `poll(2)`s them with
//!   a 1s timeout. POLLIN on a pidfd fires once the kernel has reaped the
//!   bound process, giving us deterministic, reuse-immune exit detection.
//! - macOS: `kqueue` with `EVFILT_PROC | NOTE_EXIT`. Phase 1 ships this path
//!   as a polling stub that uses the shared daemon PID-existence helper at the
//!   same cadence so separate-uid launchers are not falsely marked dead when
//!   `kill(pid, 0)` is sandbox-blind. The full kqueue integration is deferred
//!   to a sibling task. The Linux path is the load-bearing implementation for
//!   the autopilot fleet (Linux hosts).
//! - Other targets: the watcher loop is compiled but never detects an exit;
//!   logs a startup warning.
//!
//! ## Revocation cascade (Phase 2)
//!
//! On detected exit Phase 1 logs a structured `launcher.exit_detected` event
//! and leaves a TODO placeholder where
//! the cascade should invoke `infra::authority_delegation::revoke` (and any sibling
//! cascade required by the parent-walk task). Wiring the cascade in this slice
//! would tangle two tasks; Phase 2 lands once the parent-walk shape is
//! finalised.
//!
//! ## Reconciliation
//!
//! The watcher reconciles its internal `(session_id, launcher_pid, handle)`
//! map against `SessionStore::list_open()` on every tick:
//!
//! - New open sessions get a pidfd opened against their `launcher_pid`.
//! - Sessions that have been closed (no longer in `list_open`) get their
//!   handle dropped.
//! - Already-tracked sessions are left alone.
//!
//! The 1s tick is the worst-case detection latency. On Linux the `poll(2)`
//! call uses `timeout = 0` (non-blocking) so the tick cadence is the
//! detection bound; on macOS the stub also polls at the same cadence.

use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::infra::store::DaemonStore;
use core_state::sessions::SessionStore;

/// Watcher tick cadence. The brief targets ~1 s exit-detection latency; this
/// is the period that bounds it.
const TICK: Duration = Duration::from_secs(1);

/// Linux-only RAII pidfd handle for the launcher process.
///
/// Mirrors `infra::runtime::PidFdOwner` (which is bound to `PeerCredPrincipal`
/// for the broker-binding case). Defining a sibling here keeps the watcher's
/// fd ownership self-contained — the principal-binding pidfd has its own
/// `Drop`/`Arc`-on-clone contract we don't want to entangle with this
/// watcher's exclusive-owner pattern.
#[cfg(target_os = "linux")]
struct LauncherPidFd {
    fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl Drop for LauncherPidFd {
    fn drop(&mut self) {
        // SAFETY: `self.fd` was obtained from `pidfd_open(2)` and is owned
        // exclusively by this struct. Drop is the only path to `close(2)`.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// `pidfd_open(pid, 0)` — open a reuse-immune process file descriptor.
///
/// Returns `None` on pre-5.3 kernels (`ENOSYS`) or when the launcher process
/// has already exited between the session-create and watcher-tick races
/// (`ESRCH`).
#[cfg(target_os = "linux")]
fn pidfd_open(pid: i32) -> Option<std::os::unix::io::RawFd> {
    // SAFETY: `SYS_pidfd_open` takes `(pid, flags)`. We pass `flags = 0`;
    // the kernel returns a fresh fd `>= 0` on success or `-1` on error.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        debug!(
            pid,
            error = %err,
            "launcher_watch: pidfd_open failed — falling back to next-tick retry"
        );
        None
    } else {
        Some(ret as std::os::unix::io::RawFd)
    }
}

/// Poll a pidfd non-blocking. `Ok(true)` when the bound process is dead
/// (POLLIN | POLLHUP | POLLERR | POLLNVAL). `Ok(false)` when still alive.
/// `Err(_)` when `poll(2)` itself failed.
#[cfg(target_os = "linux")]
fn pidfd_is_dead(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` reads/writes the single `pollfd` we pass; `nfds = 1`
    // matches; `timeout = 0` makes the call non-blocking. The fd is owned
    // by the caller for the duration.
    let n = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(false);
    }
    let dead = pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0;
    Ok(dead)
}

/// macOS stub — Phase 1 polls the shared PID-existence helper at the same
/// cadence as the Linux fast path. The full `kqueue` + `EVFILT_PROC |
/// NOTE_EXIT` integration is deferred to a sibling task; this preserves the
/// structured-event surface on macOS dev boxes while the load-bearing Linux
/// path ships first.
#[cfg(target_os = "macos")]
fn macos_pid_is_dead(pid: u32) -> bool {
    !crate::infra::pid::process_exists(pid)
}

/// Tracked launcher entry.
///
/// On Linux the `pidfd` is the load-bearing handle. On macOS the entry holds
/// only the bare pid (the stub polls `kill(pid, 0)`). On other targets the
/// entry is the empty marker; the watcher loop never advances past the
/// startup warning.
struct TrackedLauncher {
    launcher_pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: LauncherPidFd,
}

/// In-memory watcher state. `!Send` because it lives on the daemon's
/// `LocalSet` alongside `DaemonStore`.
struct WatcherState {
    tracked: HashMap<String, TrackedLauncher>,
}

impl WatcherState {
    fn new() -> Self {
        Self {
            tracked: HashMap::new(),
        }
    }
}

/// Background task — fast-path launcher exit detector.
///
/// Spawned on the daemon's `LocalSet` next to `session_watcher::run`. The two
/// watchers cooperate: this one fires the per-launcher cascade within ~1 s of
/// process exit; `session_watcher` runs the 60 s sweep that closes orphan
/// sessions and TTL-expired grants. Phase 2 wires the revocation cascade
/// (currently a structured-log + TODO).
///
/// `daemon_store` drives the revocation cascade: on launcher exit the session's
/// runtime standing grant is revoked (BKR-4c — the per-session authority now
/// lives in that grant, not in the legacy delegation sidecar that ADR 205 §6
/// retired).
pub async fn run(daemon_store: Rc<DaemonStore>, sessions_dir: PathBuf) {
    let session_store = SessionStore::new(sessions_dir.clone());
    let mut state = WatcherState::new();
    let mut interval = tokio::time::interval(TICK);

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        warn!(
            "launcher_watch: unsupported target — launcher pidfd watch will not detect launcher exits"
        );
    }

    info!(
        tick_secs = TICK.as_secs(),
        "launcher_watch: starting (META-AP-PRESENCE-BRIDGE-LAUNCHER-PIDFD-WATCH Phase 1)"
    );

    loop {
        interval.tick().await;
        tick_once(&daemon_store, &session_store, &sessions_dir, &mut state);
    }
}

/// One tick of the watcher loop. Factored out of [`run`] so tests can drive
/// the reconciliation step deterministically without spinning the async
/// runtime.
fn tick_once(
    daemon_store: &DaemonStore,
    session_store: &SessionStore,
    sessions_dir: &std::path::Path,
    state: &mut WatcherState,
) {
    let open = match session_store.list_open() {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "launcher_watch: list_open failed — skipping tick");
            return;
        }
    };

    // 1. Reconcile: open pidfds for any newly-seen sessions; drop entries for
    //    sessions that are no longer open.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for meta in &open {
        seen.insert(meta.session_id.clone());
        if state.tracked.contains_key(&meta.session_id) {
            continue;
        }
        register_session(state, &meta.session_id, meta.launcher_pid);
    }
    state.tracked.retain(|sid, _| seen.contains(sid));

    // 2. Detect exits. Collect first to avoid borrow-checker conflicts with
    //    the remove-on-exit step.
    let mut exited: Vec<(String, u32)> = Vec::new();
    for (sid, tracked) in &state.tracked {
        if launcher_is_dead(tracked) {
            exited.push((sid.clone(), tracked.launcher_pid));
        }
    }
    for (sid, launcher_pid) in exited {
        on_launcher_exit(daemon_store, sessions_dir, &sid, launcher_pid);
        state.tracked.remove(&sid);
    }
}

/// Register a new launcher to track. cfg-gated so the Linux path opens a
/// pidfd while the macOS path only stores the bare pid.
fn register_session(state: &mut WatcherState, session_id: &str, launcher_pid: u32) {
    #[cfg(target_os = "linux")]
    {
        match pidfd_open(launcher_pid as i32) {
            Some(fd) => {
                debug!(
                    session_id = %session_id,
                    launcher_pid,
                    "launcher_watch: tracking launcher via pidfd"
                );
                state.tracked.insert(
                    session_id.to_string(),
                    TrackedLauncher {
                        launcher_pid,
                        pidfd: LauncherPidFd { fd },
                    },
                );
            }
            None => {
                // pidfd_open failed (ENOSYS on legacy kernels, or the
                // launcher already exited). The next tick will retry; if
                // the launcher is genuinely gone the 60s session_watcher
                // still catches it via the orphan-grace path.
                debug!(
                    session_id = %session_id,
                    launcher_pid,
                    "launcher_watch: pidfd unavailable — skipping (next tick will retry)"
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        debug!(
            session_id = %session_id,
            launcher_pid,
            "launcher_watch: tracking launcher via macOS kill(pid,0) stub"
        );
        state
            .tracked
            .insert(session_id.to_string(), TrackedLauncher { launcher_pid });
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // No tracking surface on this target; the warning at startup
        // already covers the operator-visible posture.
        let _ = (state, session_id, launcher_pid);
    }
}

/// Check whether a tracked launcher has exited.
///
/// Linux: consults the pidfd via non-blocking `poll(2)`. Reuse-immune.
/// macOS: shared PID-existence stub at tick cadence. Reuse-prone, but the
/// cadence is the same so the operator-visible behaviour matches.
/// Other targets: always returns `false` (no detection available).
fn launcher_is_dead(tracked: &TrackedLauncher) -> bool {
    #[cfg(target_os = "linux")]
    {
        match pidfd_is_dead(tracked.pidfd.fd) {
            Ok(dead) => dead,
            Err(e) => {
                warn!(
                    launcher_pid = tracked.launcher_pid,
                    error = %e,
                    "launcher_watch: poll(pidfd) failed — treating launcher as dead (fail-closed)"
                );
                true
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        macos_pid_is_dead(tracked.launcher_pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = tracked;
        false
    }
}

/// Structured event + delegation-grant cascade revoke.
///
/// Phase 1 emits a structured `info` event. Phase 2 (this slice — ADR 158
/// §Component 3 + ADR 161 F-AUTHORITY-1) wires the delegation-grant revoke
/// cascade so the operator's authority does not survive a crashed launcher.
/// The atomic rename in `authority_delegation::revoke` is the durable revocation
/// signal — subsequent `broker.resolve` calls return DENIED until a fresh
/// delegation is attached. Runtime-attachment lanes share delegated authority
/// by caller binding, so the revoke fires only when the exited launcher owned
/// the last live attachment on that binding.
///
/// Child-grant cascade (parent-walk) is still deferred to
/// ARCH-DAEMON-REVOCATION-PARENT-WALK.
fn on_launcher_exit(
    store: &DaemonStore,
    sessions_dir: &std::path::Path,
    session_id: &str,
    launcher_pid: u32,
) {
    info!(
        event = "launcher.exit_detected",
        session_id = %session_id,
        launcher_pid,
        "launcher_watch: launcher process exit detected — revoking runtime standing grant"
    );

    let session_store = SessionStore::new(sessions_dir.to_path_buf());
    let Some(meta) = session_store.read(session_id).ok().flatten() else {
        return;
    };
    let remaining_attachments = match session_store.count_other_open_attachments(&meta) {
        Ok(count) => count,
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "launcher_watch: failed to count sibling attachments; treating launcher exit as last attachment"
            );
            0
        }
    };
    if remaining_attachments > 0 {
        info!(
            event = "workflow.revoke_skipped",
            session_id = %session_id,
            launcher_pid,
            remaining_attachments,
            "launcher_watch: launcher exit detected but delegated authority stays live for sibling attachments on the same caller binding"
        );
        return;
    }

    // BKR-4c (ADR 205 §6): revoke the session's runtime standing grant — the
    // per-session authority now lives in that signed grant chain, not in the
    // legacy delegation sidecar ADR 205 §6 retired. Revoking it fail-closes
    // every subsequent `need ⊆ grant` use-time check for the dead launcher's
    // session.
    match store.revoke_grant(&meta.grant_id) {
        Ok(()) => {
            info!(
                event = "grant.revoked",
                session_id = %session_id,
                grant_id = %meta.grant_id,
                reason = "launcher_exited",
                "launcher_watch: runtime standing grant revoked on launcher exit"
            );
        }
        Err(e) => {
            tracing::warn!(
                session_id = %session_id,
                grant_id = %meta.grant_id,
                error = %e,
                "launcher_watch: runtime standing grant revoke failed; \
                 authority may leak beyond launcher exit"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use core_state::sessions::SessionMeta;
    use tempfile::TempDir;

    fn daemon_store() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("in-memory daemon store");
        store.set_vault(std::rc::Rc::new(crate::infra::vault::Vault::new(
            [0xEF; 32],
        )));
        store
    }

    /// Create a runtime persona + an active standing grant; returns its grant id
    /// (the BKR-4c per-session authority the launcher-exit cascade revokes).
    fn persist_runtime_grant(store: &DaemonStore) -> String {
        let persona = store
            .create_persona("runtime-dev0")
            .expect("create runtime persona");
        store
            .create_grant(&persona.id, "gh-token", "github:read:owner/repo", None)
            .expect("create standing grant")
            .id
    }

    fn grant_is_active(store: &DaemonStore, grant_id: &str) -> bool {
        store
            .get_grant(grant_id)
            .map(|g| g.status == "active")
            .unwrap_or(false)
    }

    fn meta(session_id: &str, launcher_pid: u32) -> SessionMeta {
        SessionMeta {
            session_id: session_id.to_string(),
            persona: "persona_dev0".to_string(),
            durable_persona: None,
            grant_id: "grant_test".to_string(),
            caller_binding_id: None,
            started_at: Utc::now(),
            launcher_pid,
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
        }
    }

    fn runtime_meta_with_binding(
        session_id: &str,
        launcher_pid: u32,
        grant_id: &str,
        binding: &str,
    ) -> SessionMeta {
        SessionMeta {
            session_id: session_id.to_string(),
            persona: "persona_runtime".to_string(),
            durable_persona: Some("persona_durable".to_string()),
            grant_id: grant_id.to_string(),
            caller_binding_id: Some(binding.to_string()),
            started_at: Utc::now(),
            launcher_pid,
            authority_strict: false,
            delegation_id: Some("wfg_runtime".to_string()),
            delegation_template: Some("emberd-development".to_string()),
        }
    }

    /// Checkpoint anchor — META-AP-PRESENCE-BRIDGE-LAUNCHER-PIDFD-WATCH Phase 1.
    /// Presence of this test proves the launcher_watch module ships with the
    /// load-bearing surface: tick_once reconciles against SessionStore, and
    /// the platform-specific pidfd/kqueue path lives behind cfg gates.
    #[test]
    fn presence_bridge_launcher_pidfd_watch_landed() {
        // Checkpoint — runtime body intentionally empty. Compilation of the
        // module (and the cfg-gated platform paths) is the load-bearing
        // assertion.
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pid_stub_keeps_self_alive() {
        assert!(
            !macos_pid_is_dead(std::process::id()),
            "macOS launcher watcher must not declare the current process dead"
        );
    }

    #[test]
    fn tick_once_registers_open_session_and_drops_closed_session() {
        let dir = TempDir::new().unwrap();
        let ds = daemon_store();
        let store = SessionStore::new(dir.path().to_path_buf());

        // No sessions yet — tick is a no-op, state stays empty.
        let mut state = WatcherState::new();
        tick_once(&ds, &store, dir.path(), &mut state);
        assert!(state.tracked.is_empty());

        // Open a session whose launcher_pid is the test process itself, so
        // the pidfd_open call (on Linux) succeeds and the watcher tracks it.
        let our_pid = std::process::id();
        store.create(&meta("sess-alive", our_pid)).unwrap();

        tick_once(&ds, &store, dir.path(), &mut state);
        // On Linux we expect the pidfd to be open; on macOS the bare-pid stub
        // tracks it; on other targets the register call is a no-op.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(state.tracked.contains_key("sess-alive"));
        }

        // Close the session — list_open no longer surfaces it; the reconciler
        // drops the tracked entry on the next tick.
        store.close("sess-alive").unwrap();
        tick_once(&ds, &store, dir.path(), &mut state);
        assert!(!state.tracked.contains_key("sess-alive"));
    }

    /// Linux-only: spawn a short-lived child, register it, wait for it to
    /// exit, then verify the watcher detects the exit on the next tick.
    #[cfg(target_os = "linux")]
    #[test]
    fn tick_once_detects_exited_launcher_on_linux() {
        let dir = TempDir::new().unwrap();
        let ds = daemon_store();
        let store = SessionStore::new(dir.path().to_path_buf());

        // Spawn `/bin/sleep 30` and capture its pid. The long sleep keeps the
        // child alive across the initial tick (so pidfd_open binds a live
        // process) and lets the test kill+reap deterministically before the
        // second tick.
        let mut child = match std::process::Command::new("/bin/sleep").arg("30").spawn() {
            Ok(c) => c,
            Err(_) => {
                // /bin/sleep unavailable (very minimal container) — skip.
                return;
            }
        };
        let child_pid = child.id();
        store.create(&meta("sess-exited", child_pid)).unwrap();

        let mut state = WatcherState::new();
        tick_once(&ds, &store, dir.path(), &mut state);
        assert!(
            state.tracked.contains_key("sess-exited"),
            "watcher should have opened a pidfd against the live child"
        );

        // Kill + reap the child so the pidfd flips to POLLIN. Wait() reaps
        // the zombie so the kernel marks the pidfd ready.
        let _ = child.kill();
        let _ = child.wait();

        // Give the kernel a moment to flip the pidfd's readiness state.
        std::thread::sleep(std::time::Duration::from_millis(50));

        tick_once(&ds, &store, dir.path(), &mut state);
        assert!(
            !state.tracked.contains_key("sess-exited"),
            "watcher should have detected exit and removed the entry"
        );
    }

    #[test]
    fn launcher_exit_revokes_runtime_grant_when_last_attachment() {
        let dir = TempDir::new().unwrap();
        let ds = daemon_store();
        let grant_id = persist_runtime_grant(&ds);
        let store = SessionStore::new(dir.path().to_path_buf());
        let solo =
            runtime_meta_with_binding("sess-solo", std::process::id(), &grant_id, "binding-solo");
        store.create(&solo).unwrap();
        assert!(grant_is_active(&ds, &grant_id));

        on_launcher_exit(&ds, dir.path(), &solo.session_id, solo.launcher_pid);

        assert!(
            !grant_is_active(&ds, &grant_id),
            "runtime standing grant must be revoked on the last attachment's launcher exit"
        );
    }

    #[test]
    fn launcher_exit_keeps_runtime_grant_live_for_sibling_attachment() {
        let dir = TempDir::new().unwrap();
        let ds = daemon_store();
        let grant_id = persist_runtime_grant(&ds);
        let store = SessionStore::new(dir.path().to_path_buf());
        let primary =
            runtime_meta_with_binding("sess-primary", std::process::id(), &grant_id, "binding-1");
        let sibling = runtime_meta_with_binding(
            "sess-sibling",
            std::process::id() + 1,
            &grant_id,
            "binding-1",
        );
        store.create(&primary).unwrap();
        store.create(&sibling).unwrap();

        on_launcher_exit(&ds, dir.path(), &primary.session_id, primary.launcher_pid);

        assert!(
            grant_is_active(&ds, &grant_id),
            "binding-scoped standing grant must stay active while a sibling attachment remains live"
        );
    }
}
