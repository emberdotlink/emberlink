//! Kernel-bound local peer identity and reviewed-executable fingerprints.
//!
//! Linux fingerprints the executable inode exposed by `/proc/<pid>/exe`.
//! macOS asks the kernel for the socket peer's audit token, including its PID
//! version, resolves that token to a dynamic `SecCode`, strictly validates it,
//! and hashes its CDHash into the existing fixed-width 32-byte executable-digest
//! field. The installer uses the same CDHash-based algorithm for reviewed paths.

use std::{
    ffi::CString,
    io,
    os::unix::{ffi::OsStrExt as _, net::UnixStream},
    path::{Path, PathBuf},
};

#[cfg(not(target_os = "macos"))]
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
};

use sha2::{Digest, Sha256};

use thiserror::Error;

use crate::host::PeerIdentity;
#[cfg(not(target_os = "macos"))]
use crate::same_file_version;

/// Measures a reviewed executable using the platform identity algorithm used
/// for accepted peers.
pub fn reviewed_executable_fingerprint(path: &Path) -> io::Result<[u8; 32]> {
    platform::reviewed_executable_fingerprint(path)
}
/// Returns the kernel's process-instance generation for a live PID.
///
/// Launchers report this coordinate with a child PID so the daemon can reject
/// stale reports after PID reuse.
pub fn process_pid_version(pid: u32) -> io::Result<u64> {
    platform::process_pid_version(pid)
}

/// Derives every authorization coordinate from the accepted local socket.
pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    platform::peer_identity(stream)
}

/// Assigns a daemon-created socket to its installer-provisioned client group
/// without following a substituted symlink.
#[allow(unsafe_code)]
pub(crate) fn set_socket_owner(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::lchown(path.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Derives every authorization coordinate for one reported process directly
/// from the kernel and rejects a stale or reused PID.
///
/// This is the socketless admission boundary: macOS provides no connected
/// socket audit token for a launcher-reported child. The PID version is
/// therefore a required process-instance coordinate, and the implementation
/// must observe identical PID-version, credentials, and executable path both
/// before and after all dynamic-code validation and fingerprinting. No
/// authorization identity may escape a failed final comparison.
///
/// The report contributes only the PID and the PID-version that the launcher
/// observed. Effective credentials, executable identity, and executable
/// fingerprint are measured here rather than accepted from the report.
pub fn observed_process(pid: u32, expected_pid_version: u64) -> io::Result<PeerIdentity> {
    platform::observed_process(pid, expected_pid_version)
}

/// Confirms that `child` is still in the live process tree rooted at `ancestor`.
pub fn process_descends_from(mut child: u32, ancestor: u32) -> io::Result<bool> {
    if child == 0 || ancestor == 0 {
        return Ok(false);
    }
    for _ in 0..64 {
        if child == ancestor {
            return Ok(true);
        }
        let parent = platform::parent_process_id(child)?;
        if parent == 0 || parent == child {
            return Ok(false);
        }
        child = parent;
    }
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
fn digest_reader(mut reader: impl Read) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

#[cfg(not(target_os = "macos"))]
fn digest_path_bytes(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    let digest = digest_reader(&mut file)?;
    let after = file.metadata()?;
    if !same_file_version(&before, &after) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "reviewed executable changed while fingerprinting",
        ));
    }
    Ok(digest)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use std::os::fd::AsRawFd as _;

    pub fn reviewed_executable_fingerprint(path: &Path) -> io::Result<[u8; 32]> {
        digest_path_bytes(path)
    }

    pub fn process_pid_version(pid: u32) -> io::Result<u64> {
        Ok(process_coordinates(pid)?.pid_version)
    }
    pub fn observed_process(pid: u32, expected_pid_version: u64) -> io::Result<PeerIdentity> {
        validate_expected_process(pid, expected_pid_version)?;

        let before = process_coordinates(pid)?;
        if before.pid_version != expected_pid_version {
            return Err(permission_denied("reported process PID version mismatched"));
        }

        let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
        let mut executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&proc_executable)?;
        let executable_path = descriptor_path(&executable)?;
        let executable_before = executable.metadata()?;
        let digest = digest_reader(&mut executable)?;
        let executable_after = executable.metadata()?;
        if !same_file_version(&executable_before, &executable_after) {
            return Err(permission_denied(
                "reported process executable changed while fingerprinting",
            ));
        }

        // Reopen the live procfs executable after hashing. Comparing only the
        // first descriptor to itself would miss an intervening exec because
        // that descriptor continues to reference the old executable.
        let current_executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&proc_executable)?;
        let current_path = descriptor_path(&current_executable)?;
        let current_version = current_executable.metadata()?;
        if executable_path != current_path
            || !same_file_version(&executable_before, &current_version)
        {
            return Err(permission_denied(
                "reported process executable changed while fingerprinting",
            ));
        }

        let after = process_coordinates(pid)?;
        if after != before || after.pid_version != expected_pid_version {
            return Err(permission_denied(
                "reported process changed while fingerprinting",
            ));
        }

        observed(
            pid,
            before.pid_version,
            before.euid,
            before.egid,
            executable_path,
            digest,
        )
    }

    pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: credentials is writable for `length` bytes and `stream` owns
        // a live local-socket descriptor.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful getsockopt initialized the complete ucred value.
        let credentials = unsafe { credentials.assume_init() };
        let pid =
            u32::try_from(credentials.pid).map_err(|_| permission_denied("invalid peer pid"))?;
        if pid == 0 {
            return Err(permission_denied("invalid peer pid"));
        }
        let pid_version = process_start_time(pid)?;

        let proc_executable = PathBuf::from(format!("/proc/{pid}/exe"));
        let mut executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&proc_executable)?;
        let executable_path = descriptor_path(&executable)?;
        let before = executable.metadata()?;
        let digest = digest_reader(&mut executable)?;
        let after = executable.metadata()?;
        if !same_file_version(&before, &after) {
            return Err(permission_denied(
                "peer executable changed while fingerprinting",
            ));
        }
        let current_executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&proc_executable)?;
        let current_path = descriptor_path(&current_executable)?;
        let current_version = current_executable.metadata()?;
        if executable_path != current_path || !same_file_version(&before, &current_version) {
            return Err(permission_denied(
                "peer process executable changed while fingerprinting",
            ));
        }
        if process_start_time(pid)? != pid_version {
            return Err(permission_denied(
                "peer process changed while fingerprinting",
            ));
        }

        observed(
            pid,
            pid_version,
            credentials.uid,
            credentials.gid,
            executable_path,
            digest,
        )
    }

    fn permission_denied(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProcessCoordinates {
        pid_version: u64,
        euid: u32,
        egid: u32,
    }

    fn validate_expected_process(pid: u32, expected_pid_version: u64) -> io::Result<()> {
        if pid == 0 {
            return Err(permission_denied("reported process PID was zero"));
        }
        if expected_pid_version == 0 {
            return Err(permission_denied("reported process PID version was zero"));
        }
        Ok(())
    }

    fn process_coordinates(pid: u32) -> io::Result<ProcessCoordinates> {
        let pid_version = process_start_time(pid)?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        Ok(ProcessCoordinates {
            pid_version,
            euid: parse_effective_id(&status, "Uid:")?,
            egid: parse_effective_id(&status, "Gid:")?,
        })
    }

    fn parse_effective_id(status: &str, label: &'static str) -> io::Result<u32> {
        let line = status
            .lines()
            .find(|line| line.starts_with(label))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process status omitted identity",
                )
            })?;
        line[label.len()..]
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process status omitted effective identity",
                )
            })?
            .parse()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process status contained invalid effective identity",
                )
            })
    }

    fn descriptor_path(file: &std::fs::File) -> io::Result<PathBuf> {
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let path = std::fs::read_link(descriptor_path)?;
        if !path.is_absolute() {
            return Err(permission_denied(
                "reported process executable path is not absolute",
            ));
        }
        std::fs::canonicalize(path)
    }

    fn process_start_time(pid: u32) -> io::Result<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let command_end = stat.rfind(')').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "process stat omitted command")
        })?;
        let start_time = stat[command_end + 1..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process stat omitted start time",
                )
            })?
            .parse()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid process start time")
            })?;
        if start_time == 0 {
            return Err(permission_denied("invalid process start time"));
        }
        Ok(start_time)
    }

    pub fn parent_process_id(pid: u32) -> io::Result<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let command_end = stat.rfind(')').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "process stat omitted command")
        })?;
        let mut fields = stat[command_end + 1..].split_whitespace();
        let _state = fields.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "process stat omitted state")
        })?;
        fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process stat omitted parent pid",
                )
            })?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid parent pid"))
    }

    fn observed(
        pid: u32,
        pid_version: u64,
        uid: u32,
        gid: u32,
        path: PathBuf,
        digest: [u8; 32],
    ) -> io::Result<PeerIdentity> {
        PeerIdentity::observed(pid, pid_version, uid, gid, path, digest)
            .map_err(|_| permission_denied("invalid peer identity"))
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use crate::macos_process::{peer_audit_token, process_instance, reported_process_observation};
    use core_foundation::{
        base::{CFGetTypeID, TCFType as _},
        data::{CFData, CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID},
        dictionary::{CFDictionary, CFDictionaryGetValue, CFDictionaryRef},
        string::CFStringRef,
        url::CFURL,
    };
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
    };
    use security_framework_sys::code_signing::SecStaticCodeRef;

    const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

    struct PeerObservation {
        pid: u32,
        pid_version: u64,

        uid: u32,
        gid: u32,
        executable_path: PathBuf,
        digest: [u8; 32],
    }

    unsafe extern "C" {
        static kSecCodeInfoUnique: CFStringRef;

        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
    }

    pub fn reviewed_executable_fingerprint(path: &Path) -> io::Result<[u8; 32]> {
        let url = CFURL::from_path(path, false)
            .ok_or_else(|| invalid_data("reviewed executable path is not representable"))?;
        let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(security_error)?;
        check_static_validity(&code)?;
        code_fingerprint(code.as_concrete_TypeRef())
    }

    pub fn process_pid_version(pid: u32) -> io::Result<u64> {
        process_instance(pid)
            .map(|process| process.pid_version())
            .map_err(|error| error.into_io_error())
    }
    pub fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
        let observation = peer_observation(stream)?;
        PeerIdentity::observed(
            observation.pid,
            observation.pid_version,
            observation.uid,
            observation.gid,
            observation.executable_path,
            observation.digest,
        )
        .map_err(|_| permission_denied("invalid peer identity"))
    }

    pub fn observed_process(pid: u32, expected_pid_version: u64) -> io::Result<PeerIdentity> {
        let before = reported_process_observation(pid, expected_pid_version)
            .map_err(|error| error.into_io_error())?;
        let native_pid = libc::pid_t::try_from(pid)
            .map_err(|_| permission_denied("reported PID exceeded the native range"))?;
        let mut attributes = GuestAttributes::new();
        attributes.set_pid(native_pid);
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(security_error)?;
        check_dynamic_validity(&code)?;

        // Security.framework documents this API as accepting a dynamic SecCode
        // despite its C signature using SecStaticCodeRef.
        let digest = code_fingerprint(code.as_concrete_TypeRef().cast())?;
        let security_path = code
            .path(Flags::NONE)
            .map_err(security_error)?
            .to_path()
            .ok_or_else(|| invalid_data("Security.framework returned no process path"))?;
        if !security_path.is_absolute() {
            return Err(permission_denied(
                "reported process executable path is not absolute",
            ));
        }
        if !security_path_matches_executable(&security_path, before.executable_path()) {
            return Err(permission_denied(
                "Security.framework and libproc executable paths mismatched",
            ));
        }

        let after = reported_process_observation(pid, expected_pid_version)
            .map_err(|error| error.into_io_error())?;
        if !before.is_same_process_instance(&after, expected_pid_version) {
            return Err(permission_denied(
                "reported process changed while fingerprinting",
            ));
        }

        PeerIdentity::observed(
            before.process().pid(),
            before.process().pid_version(),
            before.euid(),
            before.egid(),
            before.executable_path().to_path_buf(),
            digest,
        )
        .map_err(|_| permission_denied("invalid reported process identity"))
    }

    fn security_path_matches_executable(security_path: &Path, executable_path: &Path) -> bool {
        if security_path == executable_path {
            return true;
        }
        let Some(macos_directory) = executable_path.parent() else {
            return false;
        };
        let Some(contents_directory) = macos_directory.parent() else {
            return false;
        };
        macos_directory
            .file_name()
            .is_some_and(|name| name == "MacOS")
            && contents_directory
                .file_name()
                .is_some_and(|name| name == "Contents")
            && contents_directory.parent() == Some(security_path)
    }

    fn peer_observation(stream: &UnixStream) -> io::Result<PeerObservation> {
        let token = peer_audit_token(stream).map_err(|error| error.into_io_error())?;
        let process = token.process();
        let token_bytes = token.bytes();
        let token_data = CFData::from_buffer(&token_bytes);
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(token_data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(security_error)?;
        check_dynamic_validity(&code)?;

        // Security.framework documents this API as accepting a dynamic SecCode
        // despite its C signature using SecStaticCodeRef.
        let digest = code_fingerprint(code.as_concrete_TypeRef().cast())?;

        let security_path = code
            .path(Flags::NONE)
            .map_err(security_error)?
            .to_path()
            .ok_or_else(|| invalid_data("Security.framework returned no peer path"))?;
        if !security_path.is_absolute() {
            return Err(permission_denied("peer executable path is not absolute"));
        }
        // HostRuntime compares this Security-resolved path as an additional
        // exact constraint. The pathname is not reopened or hashed.

        Ok(PeerObservation {
            pid: process.pid(),
            pid_version: process.pid_version(),
            uid: token.euid(),
            gid: token.egid(),
            executable_path: security_path,
            digest,
        })
    }

    fn check_dynamic_validity(code: &SecCode) -> io::Result<()> {
        let requirement: SecRequirement = "always".parse().map_err(security_error)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(security_error)
    }

    fn check_static_validity(code: &SecStaticCode) -> io::Result<()> {
        let requirement: SecRequirement = "always".parse().map_err(security_error)?;
        code.check_validity(
            Flags::STRICT_VALIDATE | Flags::CHECK_ALL_ARCHITECTURES | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(security_error)
    }

    fn code_fingerprint(code: SecStaticCodeRef) -> io::Result<[u8; 32]> {
        let mut information = std::mem::MaybeUninit::<CFDictionaryRef>::uninit();
        let status = unsafe {
            SecCodeCopySigningInformation(
                code,
                SEC_CS_SIGNING_INFORMATION,
                information.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(security_status(status));
        }
        // SAFETY: a successful create-rule call initialized a retained object.
        let information: CFDictionary =
            unsafe { CFDictionary::wrap_under_create_rule(information.assume_init()) };
        let cdhash = unsafe {
            CFDictionaryGetValue(information.as_concrete_TypeRef(), kSecCodeInfoUnique.cast())
        };
        if cdhash.is_null() || unsafe { CFGetTypeID(cdhash) } != unsafe { CFDataGetTypeID() } {
            return Err(permission_denied("validated code has no CDHash"));
        }
        let length = unsafe { CFDataGetLength(cdhash.cast()) };
        let bytes = unsafe { CFDataGetBytePtr(cdhash.cast()) };
        if length <= 0 || bytes.is_null() {
            return Err(permission_denied("validated code has an invalid CDHash"));
        }
        let cdhash = unsafe { std::slice::from_raw_parts(bytes, length as usize) };
        // CDHashes vary in length with the code-directory hash algorithm. Hash
        // the complete CDHash to preserve the established 32-byte wire field.
        Ok(Sha256::digest(cdhash).into())
    }

    fn security_error(error: security_framework::base::Error) -> io::Error {
        permission_denied_owned(format!(
            "Security.framework rejected executable code: {error}"
        ))
    }

    fn security_status(status: i32) -> io::Error {
        security_error(security_framework::base::Error::from_code(status))
    }

    fn permission_denied(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }

    fn permission_denied_owned(message: String) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    pub fn parent_process_id(pid: u32) -> io::Result<u32> {
        let mut information = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>();
        let result = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                information.as_mut_ptr().cast(),
                size as libc::c_int,
            )
        };
        if result != size as libc::c_int {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { information.assume_init() }.pbi_ppid)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn socket_pair_identity_uses_self_audit_token_and_installer_cdhash() {
            let (peer, _other) = UnixStream::pair().unwrap();
            let observation = peer_observation(&peer).unwrap();
            let current = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();

            assert_eq!(observation.pid, std::process::id());
            assert_ne!(observation.pid_version, 0);
            assert_eq!(observation.uid, crate::effective_uid());
            // SAFETY: `getegid` has no arguments or memory preconditions.
            let effective_gid = unsafe { libc::getegid() };
            assert_eq!(observation.gid, effective_gid);
            assert_eq!(observation.executable_path, current);
            assert_eq!(
                observation.digest,
                reviewed_executable_fingerprint(&observation.executable_path).unwrap()
            );
            assert!(peer_identity(&peer).is_ok());
        }

        #[test]
        fn security_path_accepts_exact_executable_or_bundle_root() {
            assert!(security_path_matches_executable(
                Path::new("/opt/ember"),
                Path::new("/opt/ember")
            ));
            assert!(security_path_matches_executable(
                Path::new("/opt/ember.app"),
                Path::new("/opt/ember.app/Contents/MacOS/ember")
            ));
        }

        #[test]
        fn security_path_rejects_unrelated_or_nonstandard_ancestors() {
            assert!(!security_path_matches_executable(
                Path::new("/opt/other.app"),
                Path::new("/opt/ember.app/Contents/MacOS/ember")
            ));
            assert!(!security_path_matches_executable(
                Path::new("/opt/ember.app"),
                Path::new("/opt/ember.app/MacOS/ember")
            ));
            assert!(!security_path_matches_executable(
                Path::new("/opt/ember.app"),
                Path::new("/opt/ember.app/Contents/MacOS/nested/ember")
            ));
        }

        #[test]
        fn socket_peer_identity_mismatches_another_reviewed_executable() {
            let (peer, _other) = UnixStream::pair().unwrap();
            let observation = peer_observation(&peer).unwrap();
            let other_path = std::fs::canonicalize("/bin/ls").unwrap();
            let other_digest = reviewed_executable_fingerprint(&other_path).unwrap();

            assert_ne!(observation.executable_path, other_path);
            assert_ne!(observation.digest, other_digest);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;

    pub fn reviewed_executable_fingerprint(path: &Path) -> io::Result<[u8; 32]> {
        digest_path_bytes(path)
    }

    pub fn process_pid_version(_pid: u32) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process identity is unsupported on this platform",
        ))
    }
    pub fn peer_identity(_stream: &UnixStream) -> io::Result<PeerIdentity> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer identity is unsupported on this platform",
        ))
    }

    pub fn observed_process(_pid: u32, _expected_pid_version: u64) -> io::Result<PeerIdentity> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reported process identity is unsupported on this platform",
        ))
    }

    pub fn parent_process_id(_pid: u32) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process ancestry is unsupported on this platform",
        ))
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod observed_process_tests {
    use super::*;

    #[test]
    fn observed_process_rejects_zero_coordinates() {
        assert_eq!(
            observed_process(0, 1)
                .err()
                .expect("PID zero must be rejected")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            observed_process(std::process::id(), 0)
                .err()
                .expect("PID-version zero must be rejected")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn observed_process_rejects_pid_version_mismatch() {
        assert_eq!(
            observed_process(std::process::id(), u64::MAX)
                .err()
                .expect("a mismatched PID version must be rejected")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

macro_rules! evidence_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);
        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
evidence_id!(InstallationRootId);
evidence_id!(OperatorId);
evidence_id!(DeviceId);
evidence_id!(SignerGenerationId);
evidence_id!(VaultId);
evidence_id!(SignerKeyId);
evidence_id!(OperatorCertificateId);
evidence_id!(DeviceCertificateId);

/// Algorithms accepted for certificate and evidence signatures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SigningAlgorithm {
    Ed25519 = 0,
    EcdsaP256Sha256 = 1,
}

/// Certificate-bound signer roles and their permitted signature domains.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SignerPurpose {
    AuthorityTransition = 0,
    OperationalEvidence = 1,
}

impl SignerPurpose {
    pub const fn required_algorithm(self) -> SigningAlgorithm {
        match self {
            Self::AuthorityTransition => SigningAlgorithm::EcdsaP256Sha256,
            Self::OperationalEvidence => SigningAlgorithm::Ed25519,
        }
    }
    pub const fn permits(self, domain: SignatureDomain) -> bool {
        matches!(
            (self, domain),
            (
                Self::AuthorityTransition,
                SignatureDomain::AuthorityTransition
            ) | (
                Self::OperationalEvidence,
                SignatureDomain::OperationalDeescalation
            )
        )
    }
}

/// Closed signature-domain vocabulary. `audit` owns every encoded separator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SignatureDomain {
    OperatorCertificate,
    DeviceCertificate,
    SignerGeneration,
    AuthorityTransition,
    OperationalDeescalation,
}

/// Algorithm-tagged public key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidencePublicKey {
    Ed25519([u8; 32]),
    /// SEC1 encoded P-256 point (compressed or uncompressed).
    P256(Vec<u8>),
}
impl EvidencePublicKey {
    pub const fn algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Ed25519(_) => SigningAlgorithm::Ed25519,
            Self::P256(_) => SigningAlgorithm::EcdsaP256Sha256,
        }
    }
}

/// Algorithm-tagged signature bytes accepted by E1 verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceSignatureBytes {
    Ed25519([u8; 64]),
    /// Canonical low-S ASN.1 DER ECDSA signature.
    P256Der(Vec<u8>),
}
impl EvidenceSignatureBytes {
    pub const fn algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Ed25519(_) => SigningAlgorithm::Ed25519,
            Self::P256Der(_) => SigningAlgorithm::EcdsaP256Sha256,
        }
    }
}

/// Inclusive journal-sequence validity interval.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ValidityInterval {
    pub first: crate::model::JournalSequence,
    pub last: crate::model::JournalSequence,
}
impl ValidityInterval {
    pub fn new(
        first: crate::model::JournalSequence,
        last: crate::model::JournalSequence,
    ) -> Result<Self, IdentityError> {
        if first > last {
            Err(IdentityError::InvalidValidity)
        } else {
            Ok(Self { first, last })
        }
    }
    pub const fn contains(self, sequence: crate::model::JournalSequence) -> bool {
        sequence.get() >= self.first.get() && sequence.get() <= self.last.get()
    }
}

/// Enrolled installation trust root. Trust is explicit, never inferred from a
/// self-signature or ambient host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationRoot {
    pub id: InstallationRootId,
    pub key_id: SignerKeyId,
    pub algorithm: SigningAlgorithm,
    pub public_key: EvidencePublicKey,
    pub validity: ValidityInterval,
}

/// Issuer-bound signature over a canonical certificate body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSignature {
    pub issuer_key_id: SignerKeyId,
    pub signature: EvidenceSignatureBytes,
}

/// Installation-root-certified Operator identity and key fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorCertificateBody {
    pub certificate_id: OperatorCertificateId,
    pub root_id: InstallationRootId,
    pub operator_id: OperatorId,
    pub key_id: SignerKeyId,
    pub algorithm: SigningAlgorithm,
    pub public_key: EvidencePublicKey,
    pub validity: ValidityInterval,
}
/// Installation-root signature binding an Operator certificate body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorCertificate {
    pub body: OperatorCertificateBody,
    pub signature: CertificateSignature,
}

/// Operator-certified device identity and key fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificateBody {
    pub certificate_id: DeviceCertificateId,
    pub operator_certificate_id: OperatorCertificateId,
    pub device_id: DeviceId,
    pub key_id: SignerKeyId,
    pub algorithm: SigningAlgorithm,
    pub public_key: EvidencePublicKey,
    pub validity: ValidityInterval,
}
/// Operator signature binding a device certificate body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificate {
    pub body: DeviceCertificateBody,
    pub signature: CertificateSignature,
}

/// Device-certified signer generation, role, key, validity, and predecessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerGenerationBody {
    pub generation_id: SignerGenerationId,
    pub vault_id: VaultId,
    pub device_certificate_id: DeviceCertificateId,
    pub key_id: SignerKeyId,
    pub generation: std::num::NonZeroU32,
    pub purpose: SignerPurpose,
    pub algorithm: SigningAlgorithm,
    pub public_key: EvidencePublicKey,
    pub validity: ValidityInterval,
    pub predecessor: Option<SignerGenerationId>,
}
/// Device signature binding a signer generation body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerGeneration {
    pub body: SignerGenerationBody,
    pub signature: CertificateSignature,
}

/// Evidence signature bound to one signer generation, sequence, and domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSignature {
    pub generation_id: SignerGenerationId,
    pub sequence: crate::model::JournalSequence,
    pub domain: SignatureDomain,
    pub signature: EvidenceSignatureBytes,
}

/// Capability produced only after authenticating the complete root chain.
#[derive(Clone, Copy, Debug)]
pub struct TrustedSignerGeneration<'a> {
    installation_root_id: InstallationRootId,
    generation: &'a SignerGeneration,
}
impl<'a> TrustedSignerGeneration<'a> {
    pub const fn installation_root_id(&self) -> InstallationRootId {
        self.installation_root_id
    }
    pub fn generation(&self) -> &'a SignerGeneration {
        self.generation
    }
}

/// Capability proving that a signature was accepted under a root-authenticated
/// signer generation, its bounded validity, and its exact signature domain.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedEvidence<'a> {
    signature: &'a EvidenceSignature,
    signer: TrustedSignerGeneration<'a>,
    evidence_digest: [u8; 32],
}
impl<'a> VerifiedEvidence<'a> {
    pub(crate) const fn new(
        signature: &'a EvidenceSignature,
        signer: TrustedSignerGeneration<'a>,
        evidence_digest: [u8; 32],
    ) -> Self {
        Self {
            signature,
            signer,
            evidence_digest,
        }
    }
    pub const fn signature(&self) -> &'a EvidenceSignature {
        self.signature
    }
    pub const fn signer(&self) -> TrustedSignerGeneration<'a> {
        self.signer
    }
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
}

/// Authenticate the complete root, Operator, device, and signer-generation chain.
pub fn verify_identity_chain<'a>(
    root: &InstallationRoot,
    operator: &OperatorCertificate,
    device: &DeviceCertificate,
    predecessor: Option<TrustedSignerGeneration<'_>>,
    generation: &'a SignerGeneration,
    at: crate::model::JournalSequence,
) -> Result<TrustedSignerGeneration<'a>, IdentityError> {
    if root.validity.first > root.validity.last {
        return Err(IdentityError::InvalidValidity);
    }
    if operator.body.root_id != root.id
        || device.body.operator_certificate_id != operator.body.certificate_id
        || generation.body.device_certificate_id != device.body.certificate_id
        || !root.validity.contains(at)
        || !operator.body.validity.contains(at)
        || !device.body.validity.contains(at)
        || !generation.body.validity.contains(at)
        || operator.body.validity.first < root.validity.first
        || operator.body.validity.last > root.validity.last
        || device.body.validity.first < operator.body.validity.first
        || device.body.validity.last > operator.body.validity.last
        || generation.body.validity.first < device.body.validity.first
        || generation.body.validity.last > device.body.validity.last
        || root.algorithm != root.public_key.algorithm()
        || operator.body.algorithm != operator.body.public_key.algorithm()
        || device.body.algorithm != device.body.public_key.algorithm()
        || generation.body.algorithm != generation.body.public_key.algorithm()
        || generation.body.algorithm != generation.body.purpose.required_algorithm()
    {
        return Err(IdentityError::BrokenChain);
    }
    crate::audit::validate_public_key(&generation.body.public_key)?;
    match predecessor {
        None if generation.body.generation.get() == 1 && generation.body.predecessor.is_none() => {}
        Some(predecessor)
            if predecessor.installation_root_id == root.id
                && validate_successor_generation(
                    &predecessor.generation.body,
                    &generation.body,
                )
                .is_ok() => {}
        _ => return Err(IdentityError::InvalidSuccessor),
    }
    crate::audit::verify_certificate_signature(
        SignatureDomain::OperatorCertificate,
        root.key_id,
        &root.public_key,
        &crate::audit::encode_operator_certificate(&operator.body),
        &operator.signature,
    )?;
    crate::audit::verify_certificate_signature(
        SignatureDomain::DeviceCertificate,
        operator.body.key_id,
        &operator.body.public_key,
        &crate::audit::encode_device_certificate(&device.body),
        &device.signature,
    )?;
    crate::audit::verify_certificate_signature(
        SignatureDomain::SignerGeneration,
        device.body.key_id,
        &device.body.public_key,
        &crate::audit::encode_signer_generation(&generation.body),
        &generation.signature,
    )?;
    Ok(TrustedSignerGeneration {
        installation_root_id: root.id,
        generation,
    })
}

/// Exact-predecessor rotation. A successor may move to another certified
/// device and overlap its predecessor, but it cannot reuse the generation or
/// key identity, change scope or algorithm, backdate, or skip a generation.
pub fn validate_successor_generation(
    predecessor: &SignerGenerationBody,
    successor: &SignerGenerationBody,
) -> Result<(), IdentityError> {
    let Some(expected_generation) = predecessor.generation.get().checked_add(1) else {
        return Err(IdentityError::InvalidSuccessor);
    };
    if successor.predecessor != Some(predecessor.generation_id)
        || successor.generation_id == predecessor.generation_id
        || successor.key_id == predecessor.key_id
        || successor.generation.get() != expected_generation
        || successor.vault_id != predecessor.vault_id
        || successor.purpose != predecessor.purpose
        || successor.algorithm != predecessor.algorithm
        || successor.public_key == predecessor.public_key
        || successor.public_key.algorithm() != successor.algorithm
        || successor.algorithm != successor.purpose.required_algorithm()
        || successor.validity.first < predecessor.validity.first
    {
        return Err(IdentityError::InvalidSuccessor);
    }
    Ok(())
}

/// First journal position at which a compromised generation is untrusted.
/// Evaluation accepts only [`VerifiedEvidence`], so a caller cannot apply a
/// cutoff to unauthenticated signature metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompromiseCutoff {
    pub generation_id: SignerGenerationId,
    pub first_untrusted: crate::model::JournalSequence,
}
impl CompromiseCutoff {
    pub const fn new(
        generation_id: SignerGenerationId,
        first_untrusted: crate::model::JournalSequence,
    ) -> Self {
        Self {
            generation_id,
            first_untrusted,
        }
    }
    pub fn permits(&self, evidence: VerifiedEvidence<'_>) -> bool {
        let signature = evidence.signature();
        signature.generation_id != self.generation_id || signature.sequence < self.first_untrusted
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid certificate or signer validity interval")]
    InvalidValidity,
    #[error("certificate chain is not rooted in the selected installation root")]
    BrokenChain,
    #[error("signer generation is not an exact valid successor")]
    InvalidSuccessor,
    #[error("signature algorithm, domain, issuer, or bytes are invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod e1_tests {
    use super::*;

    fn sequence(value: u64) -> crate::model::JournalSequence {
        crate::model::JournalSequence::new(value).unwrap()
    }

    fn predecessor() -> SignerGenerationBody {
        let key = p256::ecdsa::SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        SignerGenerationBody {
            generation_id: SignerGenerationId::from_bytes([1; 32]),
            vault_id: VaultId::from_bytes([2; 32]),
            device_certificate_id: DeviceCertificateId::from_bytes([3; 32]),
            key_id: SignerKeyId::from_bytes([4; 32]),
            generation: std::num::NonZeroU32::new(1).unwrap(),
            purpose: SignerPurpose::AuthorityTransition,
            algorithm: SigningAlgorithm::EcdsaP256Sha256,
            public_key: EvidencePublicKey::P256(
                key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
            ),
            validity: ValidityInterval::new(sequence(2), sequence(10)).unwrap(),
            predecessor: None,
        }
    }

    #[test]
    fn successor_rotation_requires_exact_predecessor_fresh_key_and_no_backdating() {
        let predecessor = predecessor();
        let successor_key = p256::ecdsa::SigningKey::from_bytes((&[0x32; 32]).into()).unwrap();
        let successor = SignerGenerationBody {
            generation_id: SignerGenerationId::from_bytes([5; 32]),
            device_certificate_id: DeviceCertificateId::from_bytes([6; 32]),
            key_id: SignerKeyId::from_bytes([7; 32]),
            generation: std::num::NonZeroU32::new(2).unwrap(),
            public_key: EvidencePublicKey::P256(
                successor_key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .to_vec(),
            ),
            validity: ValidityInterval::new(sequence(5), sequence(20)).unwrap(),
            predecessor: Some(predecessor.generation_id),
            ..predecessor.clone()
        };
        validate_successor_generation(&predecessor, &successor).unwrap();
        for invalid in [
            SignerGenerationBody {
                predecessor: None,
                ..successor.clone()
            },
            SignerGenerationBody {
                generation_id: predecessor.generation_id,
                ..successor.clone()
            },
            SignerGenerationBody {
                key_id: predecessor.key_id,
                ..successor.clone()
            },
            SignerGenerationBody {
                generation: std::num::NonZeroU32::new(3).unwrap(),
                ..successor.clone()
            },
            SignerGenerationBody {
                public_key: predecessor.public_key.clone(),
                ..successor.clone()
            },
            SignerGenerationBody {
                validity: ValidityInterval::new(sequence(1), sequence(20)).unwrap(),
                ..successor.clone()
            },
            SignerGenerationBody {
                vault_id: VaultId::from_bytes([8; 32]),
                ..successor.clone()
            },
            SignerGenerationBody {
                purpose: SignerPurpose::OperationalEvidence,
                ..successor.clone()
            },
        ] {
            assert!(validate_successor_generation(&predecessor, &invalid).is_err());
        }
    }
}
