use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(target_os = "macos")]
use std::os::raw::{c_char, c_int};

#[derive(Debug, Error)]
pub enum PidError {
    #[error("I/O error during {op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("daemon already running with PID {0}")]
    AlreadyRunning(u32),
    #[error("invalid PID in file: {0}")]
    InvalidPid(String),
}

pub struct PidFile {
    path: PathBuf,
    // True only if this handle wrote the file. Read-only handles (CLI `daemon
    // status` / `daemon stop`) must not remove a running daemon's pid file on
    // drop — the daemon itself owns the file and will clean up via its own
    // PidFile::drop when it exits.
    owns_file: Cell<bool>,
}

impl PidFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            owns_file: Cell::new(false),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self) -> Result<(), PidError> {
        if let Some(existing) = self.read()? {
            if is_process_running(existing) {
                return Err(PidError::AlreadyRunning(existing));
            }
            // Stale PID file from a crashed process — remove it before overwriting.
            fs::remove_file(&self.path).map_err(|source| PidError::Io {
                op: "removing stale pid file",
                path: self.path.clone(),
                source,
            })?;
        }
        let pid = std::process::id();
        fs::write(&self.path, format!("{pid}\n")).map_err(|source| PidError::Io {
            op: "writing pid file",
            path: self.path.clone(),
            source,
        })?;
        self.owns_file.set(true);
        Ok(())
    }

    pub fn read(&self) -> Result<Option<u32>, PidError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                trimmed
                    .parse::<u32>()
                    .map(Some)
                    .map_err(|_| PidError::InvalidPid(trimmed.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(PidError::Io {
                op: "reading pid file",
                path: self.path.clone(),
                source,
            }),
        }
    }

    pub fn is_running(&self) -> bool {
        match self.read() {
            Ok(Some(pid)) => is_process_running(pid),
            _ => false,
        }
    }

    pub fn remove(&self) -> Result<(), PidError> {
        fs::remove_file(&self.path).map_err(|source| PidError::Io {
            op: "removing pid file",
            path: self.path.clone(),
            source,
        })?;
        self.owns_file.set(false);
        Ok(())
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if self.owns_file.get() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// `daemon_status_pid_liveness_check` — META-AP-EMBER-DAEMON-STATUS-STALE-PID-FALSE-NEGATIVE.
///
/// Discriminate `kill(0)` errno states so cross-uid daemons aren't
/// misclassified as gone under ADR 131 separate-uid posture:
///
/// - `kill(pid, 0)` returns 0 → process exists, callable from this uid → alive
/// - errno `EPERM` → process exists but owned by a different uid (we can't
///   signal it, but it's there) → alive
/// - errno `ESRCH` → process truly gone → stale
///
/// The previous implementation forked `kill -0 <pid>` and treated exit-1 as
/// "gone" — which conflated EPERM with ESRCH and made `ember daemon status`
/// report a healthy daemon as stale whenever the operator uid (e.g. operator)
/// differed from the daemon uid (e.g. ember). Per session_watcher::pid_alive
/// which has used this pattern for the heartbeat watcher.
fn is_process_running(pid: u32) -> bool {
    process_exists(pid)
}

/// Cross-platform process existence probe used by daemon status and the
/// session/launcher liveness watchers.
///
/// On macOS separate-uid posture the daemon runs as `ember` under a launchd
/// sandbox while the launcher runs as the operator uid. In that posture
/// `kill(pid, 0)` can return `ESRCH` for a live cross-uid process, which
/// falsely trips the session and launcher orphan logic. Prefer
/// `proc_pidpath(3)` there because it answers "does this pid still back a
/// real process image?" without relying on signal permission.
pub fn process_exists(pid: u32) -> bool {
    #[cfg(target_os = "macos")]
    {
        if process_exists_via_proc_pidpath(pid) {
            return true;
        }
    }

    // SAFETY: kill(pid, 0) is a read-only syscall — never delivers a signal.
    // The only effect is setting errno, which we inspect to discriminate.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    let os_err = std::io::Error::last_os_error();
    let raw = os_err.raw_os_error().unwrap_or(0);
    // ESRCH — no such process → stale.
    // EPERM (or anything else) — process exists but inaccessible → alive.
    raw != libc::ESRCH
}

const MAX_PROCESS_ANCESTRY_HOPS: usize = 128;

/// Best-effort process-lineage check for session-bound broker authority.
///
/// Returns true when `pid == ancestor_pid` or when repeatedly following the
/// process parent chain from `pid` reaches `ancestor_pid` within
/// `MAX_PROCESS_ANCESTRY_HOPS`. Missing process metadata, kernel refusals, or
/// looped / truncated parent chains fail closed as `false`.
pub fn process_is_same_or_descendant(pid: u32, ancestor_pid: u32) -> bool {
    if pid == 0 || ancestor_pid == 0 {
        return false;
    }
    if pid == ancestor_pid {
        return true;
    }

    let mut current = pid;
    for _ in 0..MAX_PROCESS_ANCESTRY_HOPS {
        let Some(parent_pid) = process_parent_pid(current) else {
            return false;
        };
        if parent_pid == ancestor_pid {
            return true;
        }
        if parent_pid <= 1 || parent_pid == current {
            return false;
        }
        current = parent_pid;
    }
    false
}

#[cfg(target_os = "macos")]
fn process_exists_via_proc_pidpath(pid: u32) -> bool {
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

    unsafe extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffersize: u32) -> c_int;
    }

    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let n = unsafe {
        proc_pidpath(
            pid as c_int,
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as u32,
        )
    };
    n > 0
}

#[cfg(target_os = "linux")]
fn process_parent_pid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix("PPid:")?.trim();
        value.parse::<u32>().ok()
    })
}

#[cfg(target_os = "macos")]
fn process_parent_pid(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let want = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;
    let got = unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            want,
        )
    };
    if got != want {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some(info.pbi_ppid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_parent_pid(_pid: u32) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use tempfile::tempdir;

    struct TestChild(Child);

    impl TestChild {
        fn spawn() -> Self {
            let child = Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep child");
            Self(child)
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn write_read_matches_current_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let pf = PidFile::new(path);
        pf.write().unwrap();
        let read_pid = pf.read().unwrap().expect("should have a PID");
        assert_eq!(read_pid, std::process::id());
    }

    #[test]
    fn is_running_true_for_current_process() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("running.pid");
        let pf = PidFile::new(path);
        pf.write().unwrap();
        assert!(pf.is_running());
    }

    #[test]
    fn process_exists_true_for_current_process() {
        assert!(process_exists(std::process::id()));
    }

    #[test]
    fn process_exists_false_for_unused_high_pid() {
        assert!(!process_exists(0x7FFF_FFFE));
    }

    #[test]
    fn process_is_same_or_descendant_accepts_self() {
        let pid = std::process::id();
        assert!(process_is_same_or_descendant(pid, pid));
    }

    #[test]
    fn process_is_same_or_descendant_accepts_child() {
        let child = TestChild::spawn();
        assert!(process_is_same_or_descendant(
            child.pid(),
            std::process::id()
        ));
    }

    #[test]
    fn process_is_same_or_descendant_rejects_sibling() {
        let launcher = TestChild::spawn();
        let sibling = TestChild::spawn();
        assert!(
            !process_is_same_or_descendant(sibling.pid(), launcher.pid()),
            "a sibling process must not be treated as part of the launcher's process family"
        );
    }

    #[test]
    fn remove_makes_read_return_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("remove.pid");
        {
            let pf = PidFile::new(path.clone());
            pf.write().unwrap();
            pf.remove().unwrap();
        }
        let pf2 = PidFile::new(path);
        assert!(pf2.read().unwrap().is_none());
    }

    #[test]
    fn stale_pid_file_is_overwritten() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("stale.pid");
        let stale_pid: u32 = 9_999_999;
        fs::write(&path, format!("{stale_pid}\n")).unwrap();
        let pf = PidFile::new(path);
        pf.write().unwrap();
        let read_pid = pf.read().unwrap().unwrap();
        assert_eq!(read_pid, std::process::id());
    }

    #[test]
    fn already_running_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("alive.pid");
        fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let pf = PidFile::new(path);
        match pf.write() {
            Err(PidError::AlreadyRunning(pid)) => assert_eq!(pid, std::process::id()),
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    #[test]
    fn invalid_content_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.pid");
        fs::write(&path, "not-a-number\n").unwrap();
        let pf = PidFile::new(path);
        match pf.read() {
            Err(PidError::InvalidPid(s)) => assert_eq!(s, "not-a-number"),
            other => panic!("expected InvalidPid, got {other:?}"),
        }
    }

    #[test]
    fn read_error_reports_operation_and_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pid-dir");
        fs::create_dir(&path).unwrap();
        let pf = PidFile::new(path.clone());
        match pf.read() {
            Err(PidError::Io {
                op, path: err_path, ..
            }) => {
                assert_eq!(op, "reading pid file");
                assert_eq!(err_path, path);
            }
            other => panic!("expected Io read error, got {other:?}"),
        }
    }

    // Regression: CLI `daemon status` / `daemon stop` construct a PidFile purely
    // to read the running daemon's PID. That transient handle dropping must NOT
    // remove the file — the daemon still owns it. (P69F.1)
    #[test]
    fn readonly_handle_does_not_remove_file_on_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("owned.pid");

        // Writer holds the file for the duration of the test.
        let writer = PidFile::new(path.clone());
        writer.write().unwrap();
        assert!(path.exists());

        // Simulate CLI-side read-only handle: construct, read, drop.
        {
            let reader = PidFile::new(path.clone());
            let pid = reader
                .read()
                .unwrap()
                .expect("reader should see writer's PID");
            assert_eq!(pid, std::process::id());
        }

        assert!(path.exists(), "reader's drop must not remove writer's file");
        assert_eq!(writer.read().unwrap(), Some(std::process::id()));
    }

    /// META-AP-EMBER-DAEMON-STATUS-STALE-PID-FALSE-NEGATIVE — regression test
    /// for the cross-uid case under ADR 131 separate-uid posture.
    ///
    /// PID 1 (init/launchd) always exists and is owned by root. When the
    /// test process runs as a non-root user, `kill(0)` against PID 1
    /// returns `EPERM`. The old `kill -0 <pid>` subprocess implementation
    /// misclassified this as "stale" (exit 1 → false). The new errno
    /// discriminator returns true for `EPERM` and only false for `ESRCH`.
    ///
    /// When the test happens to run as root (CI containers sometimes do),
    /// `kill(0)` against PID 1 returns 0 and the assertion still holds —
    /// the function is correct in both cases.
    #[test]
    fn pid_1_is_alive_even_when_caller_lacks_signal_permission() {
        // PID 1 always exists on every unix host this codebase supports.
        assert!(
            is_process_running(1),
            "PID 1 (init/launchd) must be classified as alive — the old \
             implementation incorrectly returned false when the caller's \
             uid couldn't signal it (kill -0 → exit 1 → EPERM)."
        );
    }

    #[test]
    fn impossibly_high_pid_is_stale() {
        // 999_999_999 should never be a valid PID; kill(0) → ESRCH → stale.
        assert!(!is_process_running(999_999_999));
    }

    #[test]
    fn failed_write_does_not_claim_ownership() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("contested.pid");
        // Simulate a live daemon by writing its PID manually.
        fs::write(&path, format!("{}\n", std::process::id())).unwrap();

        {
            let pf = PidFile::new(path.clone());
            // write() returns AlreadyRunning and must not set owns_file.
            assert!(matches!(pf.write(), Err(PidError::AlreadyRunning(_))));
        }

        // If owns_file had been set incorrectly, drop would have removed the file.
        assert!(path.exists(), "failed write must not take ownership");
    }
}
