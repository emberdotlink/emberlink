//! Reuse-immune process bindings for daemon spawn handles.
//!
//! spawn_handle_pidfd
//!
//! The current resolve -> exec protocol mints a `PendingSpawnHandle` before the
//! wrapped child process exists. The only kernel-attested process identity
//! available at mint time is therefore the Construct shim peer that called
//! `broker_resolve`. On Linux we duplicate that peer's accept-time pidfd and
//! bind it to the handle; on macOS we bind to the peer's kernel start time.

use std::fmt;

use crate::infra::runtime::PeerCredPrincipal;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

pub const ERR_SPAWN_HANDLE_PIDFD_INVALIDATED: i32 = -32034;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpawnHandlePidfdInvalidReason {
    MissingPrincipal,
    MissingBoundPidfd,
    MissingCurrentPidfd,
    PidMismatch { bound_pid: i32, current_pid: i32 },
    ClosedPidfd,
    NotAlive,
    Syscall(String),
    StartTimeUnavailable,
    StartTimeMismatch { expected: u64, actual: u64 },
    UnsupportedPlatform,
}

impl fmt::Display for SpawnHandlePidfdInvalidReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrincipal => write!(f, "missing_principal"),
            Self::MissingBoundPidfd => write!(f, "missing_bound_pidfd"),
            Self::MissingCurrentPidfd => write!(f, "missing_current_pidfd"),
            Self::PidMismatch {
                bound_pid,
                current_pid,
            } => write!(
                f,
                "pid_mismatch: bound_pid={bound_pid} current_pid={current_pid}"
            ),
            Self::ClosedPidfd => write!(f, "closed_pidfd"),
            Self::NotAlive => write!(f, "pidfd_not_alive"),
            Self::Syscall(err) => write!(f, "pidfd_syscall: {err}"),
            Self::StartTimeUnavailable => write!(f, "start_time_unavailable"),
            Self::StartTimeMismatch { expected, actual } => {
                write!(
                    f,
                    "start_time_mismatch: expected={expected} actual={actual}"
                )
            }
            Self::UnsupportedPlatform => write!(f, "unsupported_platform"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnHandlePidfdInvalidated {
    pub handle_id: String,
    pub reason: SpawnHandlePidfdInvalidReason,
}

impl SpawnHandlePidfdInvalidated {
    pub fn new(handle_id: impl Into<String>, reason: SpawnHandlePidfdInvalidReason) -> Self {
        Self {
            handle_id: handle_id.into(),
            reason,
        }
    }

    pub fn into_rpc_error(self) -> (i32, String) {
        (
            ERR_SPAWN_HANDLE_PIDFD_INVALIDATED,
            format!(
                "SpawnHandlePidfdInvalidated: handle_id={} reason={}",
                self.handle_id, self.reason
            ),
        )
    }
}

#[cfg(target_os = "linux")]
type SharedPidFd = std::sync::Arc<std::sync::Mutex<Option<std::os::fd::OwnedFd>>>;

/// Process identity bound to a minted spawn handle.
#[derive(Clone, Debug)]
pub struct SpawnHandlePidfd {
    pid: i32,
    #[cfg(target_os = "linux")]
    bound_pidfd: SharedPidFd,
    #[cfg(target_os = "macos")]
    start_time_usec: u64,
}

impl SpawnHandlePidfd {
    /// Bind a spawn handle to the socket principal that minted it.
    ///
    /// `None` is preserved as an internal/test-only legacy posture. Production
    /// socket dispatch passes a principal; when that principal cannot provide a
    /// reuse-immune process binding, resolve fails closed.
    pub fn bind_from_principal(
        principal: Option<&PeerCredPrincipal>,
    ) -> Result<Option<Self>, SpawnHandlePidfdInvalidReason> {
        let Some(principal) = principal else {
            return Ok(None);
        };
        Self::from_principal(principal).map(Some)
    }

    pub fn validate_for_principal(
        &self,
        handle_id: &str,
        principal: Option<&PeerCredPrincipal>,
    ) -> Result<(), SpawnHandlePidfdInvalidated> {
        self.validate_for_principal_inner(principal)
            .map_err(|reason| SpawnHandlePidfdInvalidated::new(handle_id, reason))
    }

    #[cfg(any(test, target_os = "linux"))]
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

#[cfg(target_os = "linux")]
impl SpawnHandlePidfd {
    fn from_principal(
        principal: &PeerCredPrincipal,
    ) -> Result<Self, SpawnHandlePidfdInvalidReason> {
        let Some(pidfd) = principal.pidfd.as_ref() else {
            return Err(SpawnHandlePidfdInvalidReason::MissingCurrentPidfd);
        };
        let duplicate = dup_pidfd(pidfd.as_raw_fd())
            .map_err(|e| SpawnHandlePidfdInvalidReason::Syscall(e.to_string()))?;
        Ok(Self {
            pid: principal.pid,
            bound_pidfd: std::sync::Arc::new(std::sync::Mutex::new(Some(duplicate))),
        })
    }

    fn validate_for_principal_inner(
        &self,
        principal: Option<&PeerCredPrincipal>,
    ) -> Result<(), SpawnHandlePidfdInvalidReason> {
        let principal = principal.ok_or(SpawnHandlePidfdInvalidReason::MissingPrincipal)?;
        if principal.pid != self.pid {
            return Err(SpawnHandlePidfdInvalidReason::PidMismatch {
                bound_pid: self.pid,
                current_pid: principal.pid,
            });
        }
        if principal.pidfd.is_none() {
            return Err(SpawnHandlePidfdInvalidReason::MissingCurrentPidfd);
        }

        let guard = self
            .bound_pidfd
            .lock()
            .map_err(|_| SpawnHandlePidfdInvalidReason::ClosedPidfd)?;
        let fd = guard
            .as_ref()
            .ok_or(SpawnHandlePidfdInvalidReason::ClosedPidfd)?;
        pidfd_send_signal_zero(fd.as_raw_fd())
    }

    #[cfg(test)]
    pub fn close_for_test(&self) {
        if let Ok(mut guard) = self.bound_pidfd.lock() {
            let _ = guard.take();
        }
    }
}

#[cfg(target_os = "linux")]
fn dup_pidfd(fd: std::os::fd::RawFd) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` duplicates a live fd owned elsewhere.
    // On success it returns a new fd owned by the caller; wrapping that fd in
    // `OwnedFd` gives it exactly one close-on-drop owner.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicated) })
    }
}

#[cfg(all(test, target_os = "linux"))]
fn pidfd_open_owned(pid: i32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: `SYS_pidfd_open` takes `(pid, flags)`. `flags = 0` requests a
    // process pidfd. On success the returned fd is newly owned by this process.
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(ret as std::os::fd::RawFd) })
    }
}

#[cfg(target_os = "linux")]
fn pidfd_send_signal_zero(fd: std::os::fd::RawFd) -> Result<(), SpawnHandlePidfdInvalidReason> {
    // SAFETY: `SYS_pidfd_send_signal` reads the pidfd integer and sends signal
    // 0, which is a permission/liveness probe and does not deliver a signal.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Err(SpawnHandlePidfdInvalidReason::NotAlive),
        Some(libc::EBADF) => Err(SpawnHandlePidfdInvalidReason::ClosedPidfd),
        Some(libc::EPERM) => Ok(()),
        _ => Err(SpawnHandlePidfdInvalidReason::Syscall(err.to_string())),
    }
}

#[cfg(target_os = "macos")]
impl SpawnHandlePidfd {
    fn from_principal(
        principal: &PeerCredPrincipal,
    ) -> Result<Self, SpawnHandlePidfdInvalidReason> {
        let start_time_usec = principal
            .start_time_usec
            .ok_or(SpawnHandlePidfdInvalidReason::StartTimeUnavailable)?;
        Ok(Self {
            pid: principal.pid,
            start_time_usec,
        })
    }

    fn validate_for_principal_inner(
        &self,
        principal: Option<&PeerCredPrincipal>,
    ) -> Result<(), SpawnHandlePidfdInvalidReason> {
        let principal = principal.ok_or(SpawnHandlePidfdInvalidReason::MissingPrincipal)?;
        if principal.pid != self.pid {
            return Err(SpawnHandlePidfdInvalidReason::PidMismatch {
                bound_pid: self.pid,
                current_pid: principal.pid,
            });
        }
        let actual = principal
            .start_time_usec
            .or_else(|| proc_pid_start_time_usec(principal.pid))
            .ok_or(SpawnHandlePidfdInvalidReason::StartTimeUnavailable)?;
        if actual != self.start_time_usec {
            return Err(SpawnHandlePidfdInvalidReason::StartTimeMismatch {
                expected: self.start_time_usec,
                actual,
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn proc_pid_start_time_usec(pid: i32) -> Option<u64> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `proc_pidinfo` writes at most `size` bytes into `info` for the
    // `PROC_PIDTBSDINFO` flavor. Short/failed reads are treated as unavailable.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            size,
        )
    };
    if n != size {
        return None;
    }
    Some(info.pbi_start_tvsec.wrapping_mul(1_000_000) + info.pbi_start_tvusec)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl SpawnHandlePidfd {
    fn from_principal(
        _principal: &PeerCredPrincipal,
    ) -> Result<Self, SpawnHandlePidfdInvalidReason> {
        Err(SpawnHandlePidfdInvalidReason::UnsupportedPlatform)
    }

    fn validate_for_principal_inner(
        &self,
        _principal: Option<&PeerCredPrincipal>,
    ) -> Result<(), SpawnHandlePidfdInvalidReason> {
        let _ = self;
        Err(SpawnHandlePidfdInvalidReason::UnsupportedPlatform)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn test_principal_for_pid(pid: i32) -> Option<PeerCredPrincipal> {
        let euid = unsafe { libc::geteuid() };
        PeerCredPrincipal::new_with_pidfd_for_test(
            euid,
            pid,
            PathBuf::from("/tmp/spawn-handle-pidfd-test.sock"),
        )
    }

    #[test]
    fn spawn_handle_pidfd_validates_live_principal() {
        let pid = std::process::id() as i32;
        let principal = test_principal_for_pid(pid).expect("pidfd_open current process");
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");

        binding
            .validate_for_principal("handle-live", Some(&principal))
            .expect("live principal must validate");
    }

    #[test]
    fn spawn_handle_pidfd_rejects_closed_pidfd() {
        let pid = std::process::id() as i32;
        let principal = test_principal_for_pid(pid).expect("pidfd_open current process");
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");

        binding.close_for_test();

        let err = binding
            .validate_for_principal("handle-closed", Some(&principal))
            .expect_err("closed pidfd must invalidate handle");
        assert_eq!(err.reason, SpawnHandlePidfdInvalidReason::ClosedPidfd);
    }

    #[test]
    fn spawn_handle_pidfd_rejects_dead_bound_process() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id() as i32;
        let principal = match test_principal_for_pid(pid) {
            Some(principal) => principal,
            None => return,
        };
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");

        let _ = child.wait();

        let err = binding
            .validate_for_principal("handle-dead", Some(&principal))
            .expect_err("dead process must invalidate handle");
        assert_eq!(err.reason, SpawnHandlePidfdInvalidReason::NotAlive);
    }

    #[test]
    fn spawn_handle_pidfd_open_after_reap_fails() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id() as i32;
        let _ = child.wait();

        let err = pidfd_open_owned(pid).expect_err("reaped pid must not yield pidfd");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn spawn_handle_pidfd_rejects_pid_mismatch() {
        let pid = std::process::id() as i32;
        let principal = test_principal_for_pid(pid).expect("pidfd_open current process");
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");
        let other = PeerCredPrincipal::new(
            unsafe { libc::geteuid() },
            pid.saturating_add(1),
            PathBuf::from("/tmp/spawn-handle-pidfd-test.sock"),
        );

        let err = binding
            .validate_for_principal("handle-pid-mismatch", Some(&other))
            .expect_err("pid mismatch must invalidate handle");
        assert!(matches!(
            err.reason,
            SpawnHandlePidfdInvalidReason::PidMismatch { .. }
        ));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn test_principal_with_start_time(pid: i32, start_time_usec: Option<u64>) -> PeerCredPrincipal {
        PeerCredPrincipal {
            uid: unsafe { libc::geteuid() },
            pid,
            socket_path: PathBuf::from("/tmp/spawn-handle-pidfd-test.sock"),
            start_time_usec,
        }
    }

    #[test]
    fn spawn_handle_pidfd_validates_macos_start_time_binding() {
        let pid = std::process::id() as i32;
        let start_time_usec =
            proc_pid_start_time_usec(pid).expect("current process start time should be available");
        let principal = test_principal_with_start_time(pid, Some(start_time_usec));
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");

        binding
            .validate_for_principal("handle-macos-live", Some(&principal))
            .expect("matching start time must validate");
    }

    #[test]
    fn spawn_handle_pidfd_rejects_macos_start_time_mismatch() {
        let pid = std::process::id() as i32;
        let start_time_usec =
            proc_pid_start_time_usec(pid).expect("current process start time should be available");
        let principal = test_principal_with_start_time(pid, Some(start_time_usec));
        let binding = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect("bind")
            .expect("bound");
        let reused_pid_principal =
            test_principal_with_start_time(pid, Some(start_time_usec.saturating_add(1)));

        let err = binding
            .validate_for_principal("handle-macos-reused", Some(&reused_pid_principal))
            .expect_err("changed start time must invalidate handle");
        assert!(matches!(
            err.reason,
            SpawnHandlePidfdInvalidReason::StartTimeMismatch { .. }
        ));
    }

    #[test]
    fn spawn_handle_pidfd_rejects_macos_missing_start_time_at_bind() {
        let pid = std::process::id() as i32;
        let principal = test_principal_with_start_time(pid, None);

        let err = SpawnHandlePidfd::bind_from_principal(Some(&principal))
            .expect_err("missing start time must fail closed");
        assert_eq!(err, SpawnHandlePidfdInvalidReason::StartTimeUnavailable);
    }
}
