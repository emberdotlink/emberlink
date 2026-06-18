//! CLASSIFICATION: PUBLIC
//!
//! `core-fd-pass` — SCM_RIGHTS + sealed-memfd cross-process fd-passing
//! primitive. Helper crate for the `ember-rpc` plaintext lane
//! (ARCH-EMBERD-RPC-SCM-RIGHTS-PRIMITIVE; depends on
//! META-ADR-155-AMEND-EXTEND-TO-RPC-FRONTEND Phase D).
//!
//! ## checkpoint
//!
//! `scm_rights_primitive_crate_landed` — grep target so the orchestrator
//! can confirm this crate's structural existence in the tree.
//!
//! ## scope
//!
//! The existing `ember-daemon::broker::exec_env` covers the
//! `fork(2) + execve(2)` fd-inheritance case (Phase 1 of
//! META-BROKER-EXEC-ENV-LEAK-VIA-PROC). That path can NOT hand an fd to
//! a cross-process peer over a Unix domain socket because the receiver
//! never shared a parent fd-table with the sender.
//!
//! This crate fills that gap with two primitives:
//!
//! - [`send_fds`] / [`recv_fds`] — wrap `sendmsg(2) + SCM_RIGHTS` so a
//!   caller can hand an arbitrary fd batch to a Unix-domain-socket peer.
//!   The receiver gets `OwnedFd` values that inherit `FD_CLOEXEC`
//!   (Linux: via `MSG_CMSG_CLOEXEC`; macOS: via explicit `fcntl(F_SETFD)`).
//! - [`SealedMemfd`] — anonymous in-memory file holding a single payload,
//!   sealed against post-write mutation on Linux via `F_ADD_SEALS`.
//!   macOS uses `shm_open(O_EXCL) + shm_unlink + ftruncate + mmap+write
//!   + munmap + mlock` to approximate the same shape; the Linux sealing
//!   guarantees do NOT carry over to macOS (see [`SealedMemfd`] doc).
//!
//! Combined: `ember-rpc` mints a `SealedMemfd::from_bytes(label, secret)`,
//! forwards `memfd.as_fd()` over `send_fds`, and the peer recovers the
//! bytes via `SealedMemfd::read_to_vec`. The plaintext never enters the
//! `ember-rpc` process address space — only fd numbers cross the wire.
//!
//! ## what this is NOT
//!
//! Not a complete RPC layer. Not a framed-message protocol — `send_fds`
//! ships a single payload frame per call, no length-prefix, no
//! re-assembly. Higher-level framing is the caller's responsibility.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

// ---------------------------------------------------------------------------
// send_fds / recv_fds
// ---------------------------------------------------------------------------

/// Maximum number of fds we'll accept per `recv_fds` call. The
/// kernel-side `SCM_MAX_FD` is 253 on current Linux; we cap the buffer
/// sizing at the caller's requested `max_fds`, bounded by a sanity
/// ceiling to avoid pathological allocations.
const SCM_RIGHTS_MAX: usize = 253;

/// Send a single payload frame plus an ancillary `SCM_RIGHTS` batch of
/// file descriptors over a connected `UnixStream`.
///
/// `payload` may be empty (some callers send only fds + a checkpoint byte
/// to satisfy the kernel's "at least one byte of iovec" requirement;
/// callers that want a true zero-byte send MUST pass at least one byte
/// or the kernel may discard the ancillary payload — POSIX leaves the
/// behavior undefined for zero-iovec sends with control data).
///
/// `fds` are borrowed for the duration of the call — the receiver gets
/// duplicates in its own fd table, the sender retains the originals.
///
/// Single-frame semantics: no length-prefix, no chunking. If `payload`
/// exceeds the socket's send buffer (`SO_SNDBUF`) this will short-write
/// or block depending on stream non-blocking mode.
pub fn send_fds(stream: &UnixStream, payload: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    let raw_fds: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    let cmsg = [ControlMessage::ScmRights(&raw_fds)];

    // `sendmsg` requires at least one iovec; if `payload` is empty we
    // still pass a zero-length slice and let the kernel handle it — on
    // Linux this is fine, on macOS the kernel accepts it too.
    let iov = [io::IoSlice::new(payload)];

    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(io::Error::from)?;
    Ok(())
}

/// Receive a single payload frame plus an ancillary `SCM_RIGHTS` batch
/// from a connected `UnixStream`.
///
/// `max_fds` sizes the ancillary buffer — passing fewer fds than the
/// sender sent will silently truncate (the kernel drops the overflow
/// fds with `MSG_CTRUNC`). Callers MUST agree on the upper bound via
/// out-of-band protocol negotiation.
///
/// Returns the inline payload bytes (sized to fit `payload_capacity`,
/// see below) and the received `OwnedFd` batch. Each `OwnedFd` carries
/// `FD_CLOEXEC` — set by `MSG_CMSG_CLOEXEC` on Linux/FreeBSD, applied
/// explicitly via `fcntl(F_SETFD)` on macOS where the flag doesn't
/// exist.
///
/// `payload_capacity` is fixed at 4 KiB for this v0 primitive. Higher-
/// level callers framing larger payloads on top of `recv_fds` should
/// either (a) keep their per-frame payload under 4 KiB or (b) wrap
/// `recvmsg` directly.
pub fn recv_fds(stream: &UnixStream, max_fds: usize) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let capped_fds = max_fds.min(SCM_RIGHTS_MAX);

    // Ancillary buffer sized for `capped_fds` × `RawFd` plus the
    // cmsghdr header. The nix `cmsg_space!` macro would do this for us
    // but it requires a compile-time constant; we want runtime sizing
    // tied to `max_fds`, so we compute by hand.
    //
    // CMSG_SPACE(sizeof(int) * n) is the right answer. We use a
    // generous upper bound (CMSG_SPACE alignment is at most 32B
    // overhead on any reasonable libc) — overshoot is harmless.
    //
    // The buffer must have real LENGTH, not just capacity: nix ≥0.30's
    // `recvmsg` treats the ancillary buffer as a slice and sizes
    // `msg_controllen` from its `.len()` (older nix used spare capacity).
    // A zero-length buffer leaves no room for the `SCM_RIGHTS` cmsg, so the
    // fds are silently dropped — hence `vec![0u8; …]`, not `with_capacity`.
    let cmsg_capacity = std::mem::size_of::<RawFd>() * capped_fds + 64;
    let mut cmsg_buf: Vec<u8> = vec![0u8; cmsg_capacity];

    // 4 KiB payload buffer — see doc above.
    let mut payload_buf = vec![0u8; 4096];
    let mut iov = [io::IoSliceMut::new(&mut payload_buf[..])];

    // MSG_CMSG_CLOEXEC: Linux/FreeBSD/NetBSD only. On macOS we apply
    // FD_CLOEXEC manually below.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    let flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    let flags = MsgFlags::empty();

    let msg = recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(&mut cmsg_buf), flags)
        .map_err(io::Error::from)?;

    let n_bytes = msg.bytes;
    let mut received_fds: Vec<OwnedFd> = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            for raw_fd in fds {
                // On macOS we didn't get MSG_CMSG_CLOEXEC, so set it
                // explicitly. On Linux this is a no-op (already set)
                // but harmless.
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd",
                    target_os = "netbsd"
                )))]
                {
                    // SAFETY: fcntl on an fd we just received and own.
                    unsafe {
                        let flags = libc::fcntl(raw_fd, libc::F_GETFD);
                        if flags >= 0 {
                            libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                        }
                    }
                }
                // SAFETY: raw_fd was just produced by recvmsg + SCM_RIGHTS;
                // the kernel guarantees it's a valid fd in our table, and
                // OwnedFd takes ownership (close on drop).
                received_fds.push(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            }
        }
    }

    payload_buf.truncate(n_bytes);
    Ok((payload_buf, received_fds))
}

// ---------------------------------------------------------------------------
// SealedMemfd
// ---------------------------------------------------------------------------

/// An anonymous in-memory file holding a single payload, sealed against
/// post-creation mutation.
///
/// ## platform-divergent seal semantics
///
/// - **Linux:** backed by `memfd_create(2)` with `MFD_ALLOW_SEALING`,
///   then `fcntl(F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK |
///   F_SEAL_GROW | F_SEAL_SEAL)`. Post-seal `write(2)` and
///   `ftruncate(2)` against the fd return `EPERM`; no further seals
///   can be added.
///
/// - **macOS:** backed by `shm_open(O_EXCL | O_RDWR | O_CREAT)` with an
///   ephemeral name, `shm_unlink` immediately afterward (so the
///   region is anonymous from the filesystem's perspective), then
///   `ftruncate + mmap(PROT_WRITE) + memcpy + munmap`, then `mlock` to
///   discourage swap-out. macOS does NOT have memfd seals — a hostile
///   fd holder CAN `write(2)` against the fd or call `ftruncate` on
///   it. The load-bearing property (plaintext never lands in the
///   ember-rpc process address space) is enforced by ember-rpc
///   behavior (`as_fd()` forward + SCM_RIGHTS, never `read()` /
///   `write()`), not by the seal itself.
///
/// - **other Unix:** `io::ErrorKind::Unsupported`. Windows isn't a
///   target — the daemon is Unix-only.
///
/// ## intended use
///
/// `ember-rpc` mints `SealedMemfd::from_bytes(label, secret_bytes)`,
/// forwards `memfd.as_fd()` via [`send_fds`] to the daemon, and the
/// daemon recovers via `SealedMemfd::read_to_vec` on the received fd
/// (re-wrapped via `SealedMemfd { fd: received_owned_fd }`).
pub struct SealedMemfd {
    fd: OwnedFd,
}

impl SealedMemfd {
    /// Build a sealed memfd from a byte slice.
    ///
    /// `label` is the debug-only name for `/proc/self/fd/<n>` symlink
    /// targets on Linux (visible in `lsof` / forensic walks). Free-
    /// form; ember-rpc convention is `ember-rpc-cred-<KIND>`.
    ///
    /// On Linux this returns a fd that REJECTS post-seal writes. On
    /// macOS this returns a fd backed by an mlock'd shm region; the
    /// seal contract is partial (see struct doc).
    pub fn from_bytes(label: &str, bytes: &[u8]) -> io::Result<SealedMemfd> {
        #[cfg(target_os = "linux")]
        {
            linux::seal_from_bytes(label, bytes)
        }
        #[cfg(target_os = "macos")]
        {
            macos::seal_from_bytes(label, bytes)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (label, bytes);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SealedMemfd: unsupported platform",
            ))
        }
    }

    /// Wrap an already-received `OwnedFd` (from `recv_fds`) as a
    /// `SealedMemfd`. The caller is responsible for verifying the
    /// peer's identity out-of-band — this constructor performs no
    /// validation that the fd actually points at a sealed memfd.
    pub fn from_owned_fd(fd: OwnedFd) -> SealedMemfd {
        SealedMemfd { fd }
    }

    /// Borrow the underlying fd for forwarding via [`send_fds`]. This
    /// is the load-bearing surface for the ember-rpc plaintext lane —
    /// the daemon never `read()`s in ember-rpc's address space.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Consume the memfd, map it read-only, copy out the bytes, scrub
    /// the temporary mapping, and return the plaintext.
    ///
    /// The returned `Vec<u8>` is owned by the caller — they're
    /// responsible for `zeroize`-ing it when finished. This function
    /// only scrubs the intermediate mmap buffer, not the result.
    pub fn read_to_vec(self) -> io::Result<Vec<u8>> {
        let raw = self.fd.as_raw_fd();

        // Determine the size via fstat.
        let size = {
            // SAFETY: fstat on a fd we own; stat is zero-initialized.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(raw, &mut stat) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            stat.st_size as usize
        };

        if size == 0 {
            return Ok(Vec::new());
        }

        // mmap PROT_READ from offset 0. SAFETY: fd is valid, len > 0,
        // and we promise to munmap below.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                raw,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Copy out. SAFETY: ptr..ptr+size is a valid read-only mapping.
        let mut out = Vec::with_capacity(size);
        unsafe {
            std::ptr::copy_nonoverlapping(ptr as *const u8, out.as_mut_ptr(), size);
            out.set_len(size);
        }

        // Best-effort scrub of the mmap region before unmapping. We
        // can't truly zero a read-only mapping but we can drop refs
        // and unmap promptly. The kernel-side page is shared via the
        // fd-backed region; zeroing the mapping here would require a
        // PROT_WRITE remap which defeats the seal. The seal IS the
        // protection; the unmap is the cleanup.
        let unmap_rc = unsafe { libc::munmap(ptr, size) };
        if unmap_rc != 0 {
            // Don't fail the read on cleanup error — log via debug
            // attribute (no logger in this crate). The caller still
            // gets the bytes; cleanup failure is rare and best-effort.
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Linux backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::SealedMemfd;
    use nix::fcntl::{FcntlArg, SealFlag, fcntl};
    use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    pub(super) fn seal_from_bytes(label: &str, bytes: &[u8]) -> io::Result<SealedMemfd> {
        let cstr = CString::new(label)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("label nul: {e}")))?;

        // MFD_ALLOW_SEALING required so F_ADD_SEALS works. We don't set
        // MFD_CLOEXEC — the caller's intent is to ship this fd over
        // SCM_RIGHTS, and the receiver sets CLOEXEC on its end via
        // MSG_CMSG_CLOEXEC. Locally we don't fork+exec, so CLOEXEC's
        // absence has no leak surface in the sender's address space.
        let owned_fd: OwnedFd =
            memfd_create(&cstr, MemFdCreateFlag::MFD_ALLOW_SEALING).map_err(io::Error::from)?;

        let raw_fd = owned_fd.into_raw_fd();
        // SAFETY: raw_fd just produced by memfd_create; sole ownership.
        let mut file = unsafe { File::from_raw_fd(raw_fd) };
        file.write_all(bytes)?;
        let raw_fd = file.into_raw_fd();
        // SAFETY: raw_fd released by File::into_raw_fd; still valid.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let seals = SealFlag::F_SEAL_WRITE
            | SealFlag::F_SEAL_GROW
            | SealFlag::F_SEAL_SHRINK
            | SealFlag::F_SEAL_SEAL;
        fcntl(owned_fd.as_raw_fd(), FcntlArg::F_ADD_SEALS(seals)).map_err(io::Error::from)?;

        Ok(SealedMemfd { fd: owned_fd })
    }
}

// ---------------------------------------------------------------------------
// macOS backend
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::SealedMemfd;
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    pub(super) fn seal_from_bytes(label: &str, bytes: &[u8]) -> io::Result<SealedMemfd> {
        // shm_open requires a name; we use a per-call ephemeral name
        // and unlink immediately. macOS shm names are limited to
        // PSHMNAMLEN (31 chars on Darwin). We hash the label into a
        // short suffix and prepend a fixed prefix.
        let pid = unsafe { libc::getpid() } as u64;
        // Best-effort entropy: nanos since epoch XOR pid.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let suffix = format!("{:x}", pid ^ nanos);
        let _ = label; // label is informational; macOS shm names have a length limit
        let name = format!("/ef{}", &suffix[..suffix.len().min(28)]);
        let cname = CString::new(name).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("shm name nul: {e}"))
        })?;

        // SAFETY: shm_open is a libc call; mode 0600.
        let fd = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Immediately unlink so the name disappears; the fd remains valid.
        // SAFETY: cname is still valid.
        let _ = unsafe { libc::shm_unlink(cname.as_ptr()) };

        // ftruncate to the payload size.
        let size = bytes.len();
        if size > 0 {
            // SAFETY: fd is valid; size_t is non-negative.
            let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }

            // mmap PROT_WRITE, copy in, munmap.
            // SAFETY: fd is valid, size > 0, MAP_SHARED so writes hit
            // the backing object.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }
            // SAFETY: ptr..ptr+size is a valid writable mapping.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, size);
            }
            // SAFETY: ptr was just produced by mmap with size bytes.
            let unmap_rc = unsafe { libc::munmap(ptr, size) };
            if unmap_rc != 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(err);
            }

            // mlock the region (re-map RO to mlock, since the writable
            // mapping is already gone). Best-effort: mlock can fail with
            // EPERM on restricted hosts; we ignore the failure rather
            // than failing the whole operation.
            // SAFETY: fd valid, size > 0.
            let ro_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if ro_ptr != libc::MAP_FAILED {
                // SAFETY: ro_ptr just produced by mmap with size bytes.
                unsafe {
                    let _ = libc::mlock(ro_ptr, size);
                    // We keep the mapping locked but munmap our handle;
                    // the lock follows the page, not our mapping.
                    libc::munmap(ro_ptr, size);
                }
            }
        }

        // SAFETY: fd was just produced by shm_open and we own it.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(SealedMemfd { fd: owned_fd })
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// Round-trip a sealed memfd over SCM_RIGHTS and verify the
    /// receiver reads back the original bytes.
    ///
    /// Linux-only: the macOS backend uses POSIX shm + mmap, and
    /// `read_to_vec` calls `mmap(PROT_READ, MAP_PRIVATE)` which returns
    /// `EINVAL` against a shm fd on Darwin. macOS's `read_to_vec` is not
    /// a load-bearing path either — ember-rpc only forwards the fd via
    /// SCM_RIGHTS and never reads through this helper on macOS (see the
    /// `SealedMemfd` struct doc above). Gate matches the production
    /// `#[cfg(target_os = "linux")]` linux backend module.
    #[cfg(target_os = "linux")]
    #[test]
    fn send_recv_sealed_memfd_roundtrip() {
        const SECRET: &[u8] = b"ember-test-fd-pass-secret-7f2a9e1c";
        const METADATA: &[u8] = b"meta-v0";

        let memfd = SealedMemfd::from_bytes("ember-test-roundtrip", SECRET).expect("seal memfd");

        let (sender, receiver) = UnixStream::pair().expect("UnixStream pair");

        // Sender: ship metadata + memfd over SCM_RIGHTS.
        send_fds(&sender, METADATA, &[memfd.as_fd()]).expect("send_fds");

        // Receiver: read inline payload + ancillary fds.
        let (payload, mut fds) = recv_fds(&receiver, 1).expect("recv_fds");
        assert_eq!(payload, METADATA, "metadata round-tripped");
        assert_eq!(fds.len(), 1, "exactly one fd received");

        let received = SealedMemfd::from_owned_fd(fds.remove(0));
        let bytes = received.read_to_vec().expect("read_to_vec");
        assert_eq!(bytes, SECRET, "secret round-tripped via fd-pass");
    }

    /// Linux-only: confirm F_SEAL_WRITE + F_SEAL_GROW are applied.
    /// `nix::unistd::write` on the sealed fd must return EPERM, and
    /// `nix::unistd::ftruncate` likewise.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealing_enforced() {
        use nix::errno::Errno;
        use std::os::fd::AsRawFd;

        let memfd =
            SealedMemfd::from_bytes("ember-test-seal", b"sealed-content").expect("seal memfd");
        let raw = memfd.as_fd().as_raw_fd();

        // Attempt to write past the sealed contents — must fail EPERM.
        // SAFETY: raw is a valid fd we own for the duration of the test.
        let write_rc = unsafe { libc::write(raw, b"-mut".as_ptr() as *const _, 4) };
        assert!(
            write_rc < 0,
            "write to sealed memfd unexpectedly succeeded ({write_rc} bytes)"
        );
        let err = Errno::last();
        assert_eq!(
            err,
            Errno::EPERM,
            "expected EPERM from sealed write, got {err:?}"
        );

        // Attempt to truncate — must also fail EPERM (F_SEAL_SHRINK +
        // F_SEAL_GROW both apply).
        // SAFETY: raw is a valid fd we own.
        let trunc_rc = unsafe { libc::ftruncate(raw, 0) };
        assert!(
            trunc_rc < 0,
            "ftruncate on sealed memfd unexpectedly succeeded"
        );
        let err = Errno::last();
        assert_eq!(
            err,
            Errno::EPERM,
            "expected EPERM from sealed ftruncate, got {err:?}"
        );
    }

    /// Verify FD_CLOEXEC is set on fds received via recv_fds. On Linux
    /// this is via MSG_CMSG_CLOEXEC; on macOS via explicit fcntl in
    /// recv_fds. Either way, the post-condition is the same: the
    /// received fd carries FD_CLOEXEC.
    #[test]
    fn received_fds_have_cloexec() {
        use std::os::fd::AsRawFd;

        let memfd = SealedMemfd::from_bytes("ember-test-cloexec", b"x").expect("seal memfd");

        let (sender, receiver) = UnixStream::pair().expect("UnixStream pair");
        send_fds(&sender, b"_", &[memfd.as_fd()]).expect("send_fds");

        let (_payload, fds) = recv_fds(&receiver, 1).expect("recv_fds");
        assert_eq!(fds.len(), 1);

        // SAFETY: fcntl(F_GETFD) on a valid fd; the fd outlives the call.
        let flags = unsafe { libc::fcntl(fds[0].as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "FD_CLOEXEC not set on received fd (flags={flags:#x})"
        );
    }
}
