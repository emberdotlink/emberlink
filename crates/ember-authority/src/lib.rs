#![deny(unsafe_code)]

pub mod artifact;
pub mod audit;
pub mod catalog;
pub mod control;
pub mod custody;
pub mod daemon;
pub mod git;
pub mod host;
pub mod host_client;
pub mod identity;
pub mod install;
pub mod install_transport;
pub(crate) mod installed_state;
pub mod kernel;
#[allow(unsafe_code)]
pub(crate) mod macos_console_session;
#[cfg(target_os = "macos")]
pub mod macos_process;
pub mod model;
pub mod pack;
pub mod presence;
pub mod principal;
pub mod provider;
pub mod recovery;
pub mod runner;
pub mod runtime_presence;
pub(crate) mod session_supervisor;

// Compile-time-only references keep dormant constructors type-checked until
// permanent custody and daemon control restore their production callers.
#[cfg(not(test))]
const _: () = {
    let _ = control::ControlRuntime::new;
    let _ = control::LockableGithubProvider::locked;
    let _ = macos_console_session::ConsoleSessionMonitor::new;
    let _ = || session_supervisor::SessionSupervisor::new(std::path::Path::new("/"), 0, 0);
};

/// Owner-private state root relative to the effective user's home directory.
pub const AUTHORITY_STATE_DIRECTORY: &str = ".local/state/ember-authority";

/// Returns the effective user ID for the current process.
///
/// Keeping this libc boundary here gives every library and binary caller the
/// same audited implementation.
#[allow(unsafe_code)]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments or memory preconditions.
    unsafe { libc::geteuid() }
}

/// Returns the effective group ID for the current process.
#[allow(unsafe_code)]
pub fn effective_gid() -> u32 {
    // SAFETY: `getegid` has no arguments or memory preconditions.
    unsafe { libc::getegid() }
}

/// Resolves an account home from the passwd database, rejecting ambiguous or
/// unsafe roots. Environment variables are intentionally ignored.
#[allow(unsafe_code)]
pub fn effective_home(uid: u32) -> std::io::Result<std::path::PathBuf> {
    use std::{
        ffi::{CStr, OsStr},
        mem::MaybeUninit,
        os::unix::ffi::OsStrExt as _,
        path::Path,
    };

    let mut capacity = 16 * 1024;
    loop {
        let mut record = MaybeUninit::<libc::passwd>::uninit();
        let mut resolved = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        // SAFETY: the record, result pointer, and writable buffer remain live
        // and uniquely borrowed for the duration of the libc call.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut resolved,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status));
        }
        if resolved.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "effective uid has no passwd entry",
            ));
        }
        // SAFETY: a successful lookup with a non-null result initialized the
        // record, whose string pointers refer into the still-live buffer.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "effective uid has no home directory",
            ));
        }
        // SAFETY: passwd string fields are NUL-terminated.
        let home = std::path::PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes(),
        ));
        if !home.is_absolute() || home == Path::new("/") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "effective uid home directory is unsafe",
            ));
        }
        let canonical = std::fs::canonicalize(home)?;
        if !canonical.is_absolute() || canonical == Path::new("/") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "canonical effective uid home directory is unsafe",
            ));
        }
        return Ok(canonical);
    }
}

/// Returns the sole supported authority-state root for an account.
pub fn authority_state_directory(uid: u32) -> std::io::Result<std::path::PathBuf> {
    effective_home(uid).map(|home| home.join(AUTHORITY_STATE_DIRECTORY))
}

/// Returns whether two metadata observations describe the same unchanged file
/// version.
///
/// Callers must still validate the file type and the policy-specific owner and
/// mode requirements. This comparison only pins every mutable version and
/// identity field exposed by Unix metadata across a review boundary.
pub(crate) fn same_file_version(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    hex::encode(sha2::Sha256::digest(bytes))
}

pub use kernel::{AuthorityKernel, SubmitError};
pub use model::{ActionRequest, OperationResult};
