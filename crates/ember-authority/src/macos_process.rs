//! Native macOS observation for a caller-reported process instance.

#![allow(unsafe_code)]

use std::{
    ffi::OsStr,
    io,
    mem::{MaybeUninit, align_of, offset_of, size_of},
    os::unix::ffi::OsStrExt as _,
    path::PathBuf,
};

use thiserror::Error;

const REPORTED_PROCESS_OPERATION: &str = "observe reported process";
const PROC_PIDT_BSDINFOWITHUNIQID: libc::c_int = 18;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInstance {
    pid: u32,
    pid_version: u64,
}

impl ProcessInstance {
    fn validated(pid: libc::pid_t, pid_version: libc::c_int) -> Result<Self, MacProcessError> {
        let pid = u32::try_from(pid).map_err(|_| invalid("kernel returned an invalid PID"))?;
        let pid_version = u32::try_from(pid_version)
            .map_err(|_| invalid("kernel returned an invalid PID version"))?;
        if pid == 0 {
            return Err(invalid("kernel returned PID zero"));
        }
        if pid_version == 0 {
            return Err(invalid("kernel returned PID version zero"));
        }
        Ok(Self {
            pid,
            pid_version: u64::from(pid_version),
        })
    }

    pub(crate) fn pid_version(self) -> u64 {
        self.pid_version
    }
}

#[derive(Debug, Error)]
pub(crate) enum MacProcessError {
    #[error("invalid kernel process coordinates: {reason}")]
    InvalidProcessCoordinates { reason: &'static str },
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
            Self::InvalidProcessCoordinates { .. } | Self::PermissionDenied { .. } => {
                io::ErrorKind::PermissionDenied
            }
            Self::Unsupported { .. } => io::ErrorKind::Unsupported,
            Self::ProcessUnavailable { .. } => io::ErrorKind::NotFound,
            Self::System { source, .. } => source.kind(),
        };
        io::Error::new(kind, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReportedProcessObservation {
    process: ProcessInstance,
    executable_path: PathBuf,
}

impl ReportedProcessObservation {
    pub(crate) fn executable_path(&self) -> &std::path::Path {
        &self.executable_path
    }

    pub(crate) fn is_same_process_instance(&self, other: &Self, expected_pid_version: u64) -> bool {
        self == other && self.process.pid_version() == expected_pid_version
    }
}

pub(crate) fn process_instance(pid: u32) -> Result<ProcessInstance, MacProcessError> {
    process_coordinates(pid)
}

pub(crate) fn reported_process_observation(
    pid: u32,
    expected_pid_version: u64,
) -> Result<ReportedProcessObservation, MacProcessError> {
    if pid == 0 {
        return Err(invalid("reported PID was zero"));
    }
    if expected_pid_version == 0 {
        return Err(invalid("reported PID version was zero"));
    }

    let before = process_coordinates(pid)?;
    if before.pid_version() != expected_pid_version {
        return Err(invalid("reported PID version mismatched the kernel"));
    }
    let executable_path = process_path(pid)?;
    let after = process_coordinates(pid)?;
    if before != after || after.pid_version() != expected_pid_version {
        return Err(invalid(
            "reported process changed while reading its executable path",
        ));
    }

    Ok(ReportedProcessObservation {
        process: before,
        executable_path,
    })
}

fn process_coordinates(pid: u32) -> Result<ProcessInstance, MacProcessError> {
    let native_pid = libc::c_int::try_from(pid)
        .map_err(|_| invalid("reported PID exceeded the native range"))?;
    let mut information = MaybeUninit::<ProcBsdInfoWithUniqueId>::uninit();
    let size = size_of::<ProcBsdInfoWithUniqueId>();
    // SAFETY: `information` is writable for `size` bytes. Flavor 18 returns
    // `proc_bsdinfowithuniqid` and does not retain the pointer.
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
            return Err(classify_last_os_error());
        }
        return Err(invalid("libproc returned incomplete process coordinates"));
    }
    // SAFETY: `proc_pidinfo` reported complete initialization.
    let information = unsafe { information.assume_init() };
    if information.bsd.pbi_pid != pid {
        return Err(invalid("libproc returned coordinates for a different PID"));
    }
    ProcessInstance::validated(
        information.bsd.pbi_pid as libc::pid_t,
        information.unique.pid_version,
    )
}

fn process_path(pid: u32) -> Result<PathBuf, MacProcessError> {
    let native_pid = libc::c_int::try_from(pid)
        .map_err(|_| invalid("reported PID exceeded the native range"))?;
    let mut buffer = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buffer` is writable for its reported size and `proc_pidpath`
    // does not retain the pointer.
    let result =
        unsafe { libc::proc_pidpath(native_pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if result <= 0 {
        return Err(classify_last_os_error());
    }
    let returned = usize::try_from(result)
        .map_err(|_| invalid("libproc returned an invalid executable path length"))?;
    if returned > buffer.len() {
        return Err(invalid("libproc returned an oversized executable path"));
    }
    let length = buffer[..returned]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(returned);
    if length == 0 {
        return Err(invalid("libproc returned an empty executable path"));
    }
    let path = PathBuf::from(OsStr::from_bytes(&buffer[..length]));
    if !path.is_absolute() {
        return Err(invalid("libproc returned a non-absolute executable path"));
    }
    Ok(path)
}

fn invalid(reason: &'static str) -> MacProcessError {
    MacProcessError::InvalidProcessCoordinates { reason }
}

fn classify_last_os_error() -> MacProcessError {
    let source = io::Error::last_os_error();
    match source.raw_os_error() {
        Some(libc::ENOSYS | libc::ENOTSUP) => MacProcessError::Unsupported {
            operation: REPORTED_PROCESS_OPERATION,
            source,
        },
        Some(libc::EACCES | libc::EPERM) => MacProcessError::PermissionDenied {
            operation: REPORTED_PROCESS_OPERATION,
            source,
        },
        Some(libc::ESRCH) => MacProcessError::ProcessUnavailable {
            operation: REPORTED_PROCESS_OPERATION,
            source,
        },
        _ => MacProcessError::System {
            operation: REPORTED_PROCESS_OPERATION,
            source,
        },
    }
}
