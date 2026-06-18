// CLASSIFICATION: PUBLIC

//! `SO_PEERCRED` / `LOCAL_PEERCRED` extraction for the helper's UDS
//! accept loop.
//!
//! The peercred uid is the load-bearing auth primitive: any caller
//! whose kernel-attested uid != the helper's `--daemon-uid` is refused
//! before the helper reads any frame. This is the same shape the main
//! daemon's `broker.handler` uses to gate `broker_exec` against the
//! operator's uid.
//!
//! ## Platform mapping
//!
//! - **macOS / *BSD**: `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` returns
//!   `struct xucred { cr_version: u32, cr_uid: uid_t, ... }`. The
//!   advertised version is `XUCRED_VERSION` (1) — we accept any
//!   version and read `cr_uid`. Reference: `<sys/ucred.h>` on Darwin.
//! - **Linux**: `getsockopt(SOL_SOCKET, SO_PEERCRED)` returns `struct
//!   ucred { pid: pid_t, uid: uid_t, gid: gid_t }`. Reference:
//!   `unix(7)`.
//!
//! Other platforms surface `-32010 caller_identity_unavailable` per
//! ADR 155 Component 7. The helper doesn't run on those platforms in
//! production.

use std::io;
use std::os::fd::AsRawFd;

#[cfg(target_os = "macos")]
mod sys {
    pub const SOL_LOCAL: libc::c_int = 0;
    pub const LOCAL_PEERCRED: libc::c_int = 0x001;

    /// `struct xucred` as defined in `<sys/ucred.h>` on Darwin. Layout
    /// is stable across macOS releases (xucred is part of the kernel
    /// ABI for SCM_CREDS and LOCAL_PEERCRED).
    #[repr(C)]
    pub struct Xucred {
        pub cr_version: libc::c_uint,
        pub cr_uid: libc::uid_t,
        pub cr_ngroups: libc::c_short,
        pub cr_groups: [libc::gid_t; 16],
    }
}

#[cfg(target_os = "linux")]
mod sys {
    pub const SO_PEERCRED: libc::c_int = libc::SO_PEERCRED;
    pub const SOL_SOCKET: libc::c_int = libc::SOL_SOCKET;

    #[repr(C)]
    pub struct Ucred {
        pub pid: libc::pid_t,
        pub uid: libc::uid_t,
        pub gid: libc::gid_t,
    }
}

/// Extract the peer uid from a connected Unix-domain stream. Returns
/// `Err(io::ErrorKind::Unsupported)` on non-macOS/non-Linux targets so
/// callers can surface a clear "this platform isn't supported" error
/// rather than silently accepting unauthenticated connections.
#[cfg(target_os = "macos")]
pub fn peer_uid<S: AsRawFd>(stream: &S) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    // SAFETY: zero-initialised xucred is a valid initial state for
    // getsockopt to fill; we pass the actual struct size so the kernel
    // writes exactly the fields we expect.
    let mut cred: sys::Xucred = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<sys::Xucred>() as libc::socklen_t;
    // SAFETY: `cred` is exclusively borrowed for the duration; `len`
    // is a writable in-out parameter pointing to a stack u32.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            sys::SOL_LOCAL,
            sys::LOCAL_PEERCRED,
            (&mut cred as *mut sys::Xucred) as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if (len as usize) < std::mem::size_of::<u32>() * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("LOCAL_PEERCRED returned undersized result: {len} bytes"),
        ));
    }
    Ok(cred.cr_uid)
}

#[cfg(target_os = "linux")]
pub fn peer_uid<S: AsRawFd>(stream: &S) -> io::Result<u32> {
    let fd = stream.as_raw_fd();
    // SAFETY: zero-initialised ucred is a valid initial state for
    // getsockopt to fill.
    let mut cred: sys::Ucred = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<sys::Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            sys::SOL_SOCKET,
            sys::SO_PEERCRED,
            (&mut cred as *mut sys::Ucred) as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_uid<S: AsRawFd>(_stream: &S) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer_uid: spawn-helper is only supported on macOS and Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// Smoke test: a self-connected UnixStream returns the current uid
    /// for both halves of the pair. Doesn't exercise the cross-uid
    /// refusal path (that requires a non-root cooperating second uid,
    /// covered by integration tests in `tests/`).
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn peer_uid_returns_self_uid_for_socketpair() {
        let (a, b) = UnixStream::pair().expect("UnixStream::pair");
        // SAFETY: getuid is async-signal-safe and always succeeds.
        let cur = unsafe { libc::getuid() };
        let ua = peer_uid(&a).expect("peer_uid(a)");
        let ub = peer_uid(&b).expect("peer_uid(b)");
        assert_eq!(ua, cur);
        assert_eq!(ub, cur);
    }
}
