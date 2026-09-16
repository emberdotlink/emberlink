//! Native macOS process-instance origin and exit observation.
//!
//! Process coordinates are derived only from a connected local socket's audit
//! token. Liveness uses one `EVFILT_PROC` registration and deliberately does
//! not combine kqueue with polling.

#![allow(unsafe_code)]

use std::{
    ffi::OsStr,
    io,
    mem::{MaybeUninit, align_of, offset_of, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt as _, net::UnixStream},
    },
    path::PathBuf,
    ptr,
};

use thiserror::Error;

const AUDIT_TOKEN_WORDS: usize = 8;
const PEER_TOKEN_OPERATION: &str = "read LOCAL_PEERTOKEN";
const KQUEUE_CREATE_OPERATION: &str = "create kqueue";
const KQUEUE_REGISTER_OPERATION: &str = "register process exit observation";
const KQUEUE_OBSERVE_OPERATION: &str = "observe process exit";
const REPORTED_PROCESS_OPERATION: &str = "observe reported process";
const PROC_PIDT_BSDINFOWITHUNIQID: libc::c_int = 18;

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    value: [u32; AUDIT_TOKEN_WORDS],
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_euid(token: AuditToken) -> libc::uid_t;
    fn audit_token_to_egid(token: AuditToken) -> libc::gid_t;
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
    fn audit_token_to_pidversion(token: AuditToken) -> libc::c_int;
}

#[repr(C)]
struct ProcUniqueIdentifierInfo {
    executable_uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    pid_version: i32,
    original_parent_pid_version: i32,
    reserved: [u64; 2],
}

#[repr(C)]
struct ProcBsdInfoWithUniqueId {
    bsd: libc::proc_bsdinfo,
    unique: ProcUniqueIdentifierInfo,
}

const _: () = {
    assert!(size_of::<ProcUniqueIdentifierInfo>() == 56);
    assert!(align_of::<ProcUniqueIdentifierInfo>() == 8);
    assert!(offset_of!(ProcUniqueIdentifierInfo, executable_uuid) == 0);
    assert!(offset_of!(ProcUniqueIdentifierInfo, unique_id) == 16);
    assert!(offset_of!(ProcUniqueIdentifierInfo, parent_unique_id) == 24);
    assert!(offset_of!(ProcUniqueIdentifierInfo, pid_version) == 32);
    assert!(offset_of!(ProcUniqueIdentifierInfo, original_parent_pid_version) == 36);
    assert!(offset_of!(ProcUniqueIdentifierInfo, reserved) == 40);
    assert!(offset_of!(ProcBsdInfoWithUniqueId, unique) == size_of::<libc::proc_bsdinfo>());
};

/// Kernel-issued coordinates for one exact process instance.
///
/// The fields are intentionally private: callers can obtain this value only by
/// asking the kernel about a connected Unix socket peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessInstance {
    pid: u32,
    pid_version: u64,
}

impl ProcessInstance {
    fn validated(pid: libc::pid_t, pid_version: libc::c_int) -> Result<Self, MacProcessError> {
        let pid = u32::try_from(pid).map_err(|_| MacProcessError::InvalidProcessCoordinates {
            reason: "kernel returned an invalid PID",
        })?;
        let pid_version =
            u32::try_from(pid_version).map_err(|_| MacProcessError::InvalidProcessCoordinates {
                reason: "kernel returned an invalid PID version",
            })?;
        if pid == 0 {
            return Err(MacProcessError::InvalidProcessCoordinates {
                reason: "kernel returned PID zero",
            });
        }
        if pid_version == 0 {
            return Err(MacProcessError::InvalidProcessCoordinates {
                reason: "kernel returned PID version zero",
            });
        }
        Ok(Self {
            pid,
            pid_version: u64::from(pid_version),
        })
    }

    pub fn pid(self) -> u32 {
        self.pid
    }

    pub fn pid_version(self) -> u64 {
        self.pid_version
    }
}

/// Failure to derive or observe a native macOS process instance.
#[derive(Debug, Error)]
pub enum MacProcessError {
    #[error("invalid kernel process coordinates: {reason}")]
    InvalidProcessCoordinates { reason: &'static str },
    #[error("invalid peer audit token: {reason}")]
    InvalidPeerToken { reason: &'static str },
    #[error("{operation} is unsupported: {source}")]
    Unsupported {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("permission denied while attempting to {operation}: {source}")]
    PermissionDenied {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("process was unavailable while attempting to {operation}: {source}")]
    ProcessUnavailable {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to {operation}: {source}")]
    System {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl MacProcessError {
    pub(crate) fn into_io_error(self) -> io::Error {
        let kind = match &self {
            Self::InvalidProcessCoordinates { .. } | Self::InvalidPeerToken { .. } => {
                io::ErrorKind::PermissionDenied
            }
            Self::Unsupported { .. } => io::ErrorKind::Unsupported,
            Self::PermissionDenied { .. } => io::ErrorKind::PermissionDenied,
            Self::ProcessUnavailable { .. } => io::ErrorKind::NotFound,
            Self::System { source, .. } => source.kind(),
        };
        io::Error::new(kind, self)
    }
}

/// The result of one nonblocking exit observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitObservation {
    Running,
    Exited,
}

/// RAII-owned native watcher for one exact process instance.
#[derive(Debug)]
pub struct ProcessExitWatcher {
    queue: OwnedFd,
    process: ProcessInstance,
    observed_exit: bool,
}

impl ProcessExitWatcher {
    /// Registers `EVFILT_PROC | NOTE_EXIT` for coordinates derived from a peer
    /// socket. No secondary liveness mechanism is active beside this kqueue.
    pub fn register(process: ProcessInstance) -> Result<Self, MacProcessError> {
        if process.pid == 0 || process.pid_version == 0 {
            return Err(MacProcessError::InvalidProcessCoordinates {
                reason: "invalid process coordinates",
            });
        }

        // SAFETY: kqueue has no pointer arguments and returns a newly owned
        // descriptor on success.
        let descriptor = unsafe { libc::kqueue() };
        if descriptor < 0 {
            return Err(classify_last_os_error(KQUEUE_CREATE_OPERATION));
        }
        // SAFETY: the successful kqueue call returned one newly owned fd.
        let queue = unsafe { OwnedFd::from_raw_fd(descriptor) };
        // SAFETY: queue owns a live descriptor and F_SETFD has no pointer
        // arguments. Failure leaves ownership with queue, which closes it.
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(classify_last_os_error(KQUEUE_CREATE_OPERATION));
        }

        let change = libc::kevent {
            ident: process.pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        // SAFETY: queue is live; change points to one initialized kevent; no
        // output or timeout pointer is supplied for this registration call.
        let result = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &change,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        };
        if result < 0 {
            return Err(classify_last_os_error(KQUEUE_REGISTER_OPERATION));
        }

        Ok(Self {
            queue,
            process,
            observed_exit: false,
        })
    }

    /// Registers one exact kernel-observed reported process.
    ///
    /// The watcher is installed between two libproc observations so a stale
    /// PID, PID reuse, or an exec during registration fails closed.
    #[cfg(test)]
    pub(crate) fn register_reported(
        pid: u32,
        expected_pid_version: u64,
    ) -> Result<Self, MacProcessError> {
        let before = reported_process_observation(pid, expected_pid_version)?;
        let watcher = Self::register(before.process)?;
        let after = reported_process_observation(pid, expected_pid_version)?;
        if before != after {
            return Err(MacProcessError::InvalidProcessCoordinates {
                reason: "reported process changed while registering exit observation",
            });
        }
        Ok(watcher)
    }

    pub fn process(&self) -> ProcessInstance {
        self.process
    }

    /// Observes process exit without blocking.
    pub fn observe_exit(&mut self) -> Result<ExitObservation, MacProcessError> {
        if self.observed_exit {
            return Ok(ExitObservation::Exited);
        }

        let mut event = MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = retry_on_interrupt(|| {
            // SAFETY: queue is live, event is writable for one kevent, and timeout
            // points to an initialized zero duration.
            let result = unsafe {
                libc::kevent(
                    self.queue.as_raw_fd(),
                    ptr::null(),
                    0,
                    event.as_mut_ptr(),
                    1,
                    &timeout,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result)
            }
        })
        .map_err(|error| classify_io_error(KQUEUE_OBSERVE_OPERATION, error))?;
        if result == 0 {
            return Ok(ExitObservation::Running);
        }
        if result != 1 {
            return Err(system_error(
                KQUEUE_OBSERVE_OPERATION,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kqueue returned an invalid event count",
                ),
            ));
        }

        // SAFETY: kevent reported that it initialized exactly one event.
        let event = unsafe { event.assume_init() };
        // kevent is packed on macOS; copy fields before inspecting them.
        let ident = event.ident;
        let filter = event.filter;
        let flags = event.flags;
        let fflags = event.fflags;
        let data = event.data;

        if flags & libc::EV_ERROR != 0 {
            let error = if data > 0 && data <= i32::MAX as libc::intptr_t {
                io::Error::from_raw_os_error(data as i32)
            } else {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kqueue returned an invalid error code",
                )
            };
            return Err(classify_io_error(KQUEUE_OBSERVE_OPERATION, error));
        }
        if ident != self.process.pid as libc::uintptr_t
            || filter != libc::EVFILT_PROC
            || fflags & libc::NOTE_EXIT == 0
        {
            return Err(system_error(
                KQUEUE_OBSERVE_OPERATION,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "kqueue returned an unexpected event",
                ),
            ));
        }

        self.observed_exit = true;
        Ok(ExitObservation::Exited)
    }
}

/// Derives exact PID and PID-version solely from `stream`'s kernel audit token.
pub fn peer_process_instance(stream: &UnixStream) -> Result<ProcessInstance, MacProcessError> {
    Ok(peer_audit_token(stream)?.process())
}

pub(crate) struct PeerAuditToken {
    token: AuditToken,
    process: ProcessInstance,
    euid: libc::uid_t,
    egid: libc::gid_t,
}

impl PeerAuditToken {
    pub(crate) fn process(&self) -> ProcessInstance {
        self.process
    }

    pub(crate) fn euid(&self) -> libc::uid_t {
        self.euid
    }

    pub(crate) fn egid(&self) -> libc::gid_t {
        self.egid
    }

    pub(crate) fn bytes(&self) -> [u8; AUDIT_TOKEN_WORDS * size_of::<u32>()] {
        let mut bytes = [0_u8; AUDIT_TOKEN_WORDS * size_of::<u32>()];
        for (index, word) in self.token.value.into_iter().enumerate() {
            let start = index * size_of::<u32>();
            bytes[start..start + size_of::<u32>()].copy_from_slice(&word.to_ne_bytes());
        }
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReportedProcessObservation {
    process: ProcessInstance,
    euid: u32,
    egid: u32,
    executable_path: PathBuf,
}

impl ReportedProcessObservation {
    pub(crate) fn process(&self) -> ProcessInstance {
        self.process
    }

    pub(crate) fn euid(&self) -> u32 {
        self.euid
    }

    pub(crate) fn egid(&self) -> u32 {
        self.egid
    }

    pub(crate) fn executable_path(&self) -> &std::path::Path {
        &self.executable_path
    }

    pub(crate) fn is_same_process_instance(&self, other: &Self, expected_pid_version: u64) -> bool {
        self == other && self.process.pid_version() == expected_pid_version
    }
}

pub(crate) fn reported_process_observation(
    pid: u32,
    expected_pid_version: u64,
) -> Result<ReportedProcessObservation, MacProcessError> {
    if pid == 0 {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "reported PID was zero",
        });
    }
    if expected_pid_version == 0 {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "reported PID version was zero",
        });
    }

    let before = process_coordinates(pid)?;
    if before.process.pid_version() != expected_pid_version {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "reported PID version mismatched the kernel",
        });
    }
    let executable_path = process_path(pid)?;
    let after = process_coordinates(pid)?;
    if before != after || after.process.pid_version() != expected_pid_version {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "reported process changed while reading its executable path",
        });
    }

    Ok(ReportedProcessObservation {
        process: before.process,
        euid: before.euid,
        egid: before.egid,
        executable_path,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessCoordinates {
    process: ProcessInstance,
    euid: u32,
    egid: u32,
}

pub(crate) fn process_instance(pid: u32) -> Result<ProcessInstance, MacProcessError> {
    Ok(process_coordinates(pid)?.process)
}

fn process_coordinates(pid: u32) -> Result<ProcessCoordinates, MacProcessError> {
    let native_pid =
        libc::c_int::try_from(pid).map_err(|_| MacProcessError::InvalidProcessCoordinates {
            reason: "reported PID exceeded the native range",
        })?;
    let mut information = MaybeUninit::<ProcBsdInfoWithUniqueId>::uninit();
    let size = size_of::<ProcBsdInfoWithUniqueId>();
    // SAFETY: information is writable for size bytes. Flavor 18 is
    // PROC_PIDT_BSDINFOWITHUNIQID and returns proc_bsdinfowithuniqid.
    let result = unsafe {
        libc::proc_pidinfo(
            native_pid,
            PROC_PIDT_BSDINFOWITHUNIQID,
            0,
            information.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if result != size as libc::c_int {
        if result <= 0 {
            return Err(classify_last_os_error(REPORTED_PROCESS_OPERATION));
        }
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned incomplete process coordinates",
        });
    }
    // SAFETY: proc_pidinfo reported that it initialized the complete value.
    let information = unsafe { information.assume_init() };
    if information.bsd.pbi_pid != pid {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned coordinates for a different PID",
        });
    }
    Ok(ProcessCoordinates {
        process: ProcessInstance::validated(
            information.bsd.pbi_pid as libc::pid_t,
            information.unique.pid_version,
        )?,
        euid: information.bsd.pbi_uid,
        egid: information.bsd.pbi_gid,
    })
}

fn process_path(pid: u32) -> Result<PathBuf, MacProcessError> {
    let native_pid =
        libc::c_int::try_from(pid).map_err(|_| MacProcessError::InvalidProcessCoordinates {
            reason: "reported PID exceeded the native range",
        })?;
    let mut buffer = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is writable for its reported size and proc_pidpath does
    // not retain the pointer.
    let result =
        unsafe { libc::proc_pidpath(native_pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if result <= 0 {
        return Err(classify_last_os_error(REPORTED_PROCESS_OPERATION));
    }
    let returned =
        usize::try_from(result).map_err(|_| MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned an invalid executable path length",
        })?;
    if returned > buffer.len() {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned an oversized executable path",
        });
    }
    let length = buffer[..returned]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(returned);
    if length == 0 {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned an empty executable path",
        });
    }
    let path = PathBuf::from(OsStr::from_bytes(&buffer[..length]));
    if !path.is_absolute() {
        return Err(MacProcessError::InvalidProcessCoordinates {
            reason: "libproc returned a non-absolute executable path",
        });
    }
    Ok(path)
}

pub(crate) fn peer_audit_token(stream: &UnixStream) -> Result<PeerAuditToken, MacProcessError> {
    let mut token = MaybeUninit::<AuditToken>::uninit();
    let mut length = size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: token is writable for length bytes and LOCAL_PEERTOKEN asks the
    // kernel for the immutable audit token of this connected local peer.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(classify_last_os_error(PEER_TOKEN_OPERATION));
    }
    if length as usize != size_of::<AuditToken>() {
        return Err(MacProcessError::InvalidPeerToken {
            reason: "LOCAL_PEERTOKEN returned an invalid length",
        });
    }
    // SAFETY: successful getsockopt initialized all audit-token bytes.
    let token = unsafe { token.assume_init() };
    // SAFETY: libbsm token accessors take the token by value and neither retain
    // nor dereference caller-owned pointers.
    let process = ProcessInstance::validated(unsafe { audit_token_to_pid(token) }, unsafe {
        audit_token_to_pidversion(token)
    })?;
    // SAFETY: same by-value libbsm accessor contract as above.
    let euid = unsafe { audit_token_to_euid(token) };
    // SAFETY: same by-value libbsm accessor contract as above.
    let egid = unsafe { audit_token_to_egid(token) };

    Ok(PeerAuditToken {
        token,
        process,
        euid,
        egid,
    })
}

fn classify_last_os_error(operation: &'static str) -> MacProcessError {
    classify_io_error(operation, io::Error::last_os_error())
}

fn classify_io_error(operation: &'static str, source: io::Error) -> MacProcessError {
    match source.raw_os_error() {
        Some(libc::ENOSYS | libc::ENOTSUP) => MacProcessError::Unsupported { operation, source },
        Some(libc::EACCES | libc::EPERM) => MacProcessError::PermissionDenied { operation, source },
        Some(libc::ESRCH) => MacProcessError::ProcessUnavailable { operation, source },
        _ => MacProcessError::System { operation, source },
    }
}

fn system_error(operation: &'static str, source: io::Error) -> MacProcessError {
    MacProcessError::System { operation, source }
}

fn retry_on_interrupt<T>(
    mut operation: impl FnMut() -> Result<T, io::Error>,
) -> Result<T, io::Error> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn process_coordinates_reject_pid_zero() {
        assert!(matches!(
            ProcessInstance::validated(0, 1),
            Err(MacProcessError::InvalidProcessCoordinates { .. })
        ));
    }

    #[test]
    fn process_coordinates_reject_pid_version_zero() {
        assert!(matches!(
            ProcessInstance::validated(1, 0),
            Err(MacProcessError::InvalidProcessCoordinates { .. })
        ));
    }

    #[test]
    fn process_coordinates_widen_native_pid_version() {
        let process = ProcessInstance::validated(42, 7).unwrap();
        assert_eq!(process.pid(), 42);
        assert_eq!(process.pid_version(), 7);
    }

    #[test]
    fn reported_process_rejects_mismatched_pid_version() {
        let process = process_coordinates(std::process::id()).unwrap();
        let mismatched = process.process.pid_version().wrapping_add(1);
        assert!(matches!(
            reported_process_observation(std::process::id(), mismatched),
            Err(MacProcessError::InvalidProcessCoordinates { .. })
        ));
    }

    #[test]
    fn reported_process_bracket_rejects_any_process_instance_change() {
        let observed = reported_process_observation(
            std::process::id(),
            process_coordinates(std::process::id())
                .unwrap()
                .process
                .pid_version(),
        )
        .unwrap();
        let changed = ReportedProcessObservation {
            process: ProcessInstance {
                pid: observed.process().pid(),
                pid_version: observed.process().pid_version().wrapping_add(1),
            },
            ..observed.clone()
        };

        assert!(!observed.is_same_process_instance(&changed, observed.process().pid_version()));
    }

    #[test]
    fn kqueue_observes_registered_process_exit() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let expected_pid_version = process_coordinates(child.id())
            .unwrap()
            .process
            .pid_version();
        let mut watcher =
            ProcessExitWatcher::register_reported(child.id(), expected_pid_version).unwrap();
        assert_eq!(watcher.observe_exit().unwrap(), ExitObservation::Running);

        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(watcher.observe_exit().unwrap(), ExitObservation::Exited);
    }

    #[test]
    fn syscall_errors_are_typed_for_integration_fallback() {
        assert!(matches!(
            classify_io_error("probe", io::Error::from_raw_os_error(libc::EPERM)),
            MacProcessError::PermissionDenied { .. }
        ));
        assert!(matches!(
            classify_io_error("probe", io::Error::from_raw_os_error(libc::ENOTSUP)),
            MacProcessError::Unsupported { .. }
        ));
        assert!(matches!(
            classify_io_error("probe", io::Error::from_raw_os_error(libc::ESRCH)),
            MacProcessError::ProcessUnavailable { .. }
        ));
        assert!(matches!(
            classify_io_error("probe", io::Error::from_raw_os_error(libc::EIO)),
            MacProcessError::System { .. }
        ));
    }

    #[test]
    fn interrupted_operations_are_retried() {
        let mut attempts = 0;
        let result = retry_on_interrupt(|| {
            attempts += 1;
            if attempts == 1 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(ExitObservation::Running)
            }
        });

        assert_eq!(result.unwrap(), ExitObservation::Running);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn non_interrupted_errors_are_not_retried() {
        let mut attempts = 0;
        let result = retry_on_interrupt(|| {
            attempts += 1;
            Err::<(), _>(io::Error::from(io::ErrorKind::WouldBlock))
        });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(attempts, 1);
    }
}
