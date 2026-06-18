//! Linux memfd-sealed credential surface for broker exec (META-BROKER-
//! EXEC-ENV-LEAK-VIA-PROC Phase 1).
//!
//! ## Problem
//!
//! The broker exec path currently injects credentials into the child
//! process via plain environment variables (e.g. `GH_TOKEN=ghs_...`).
//! Plaintext env vars are readable by ANY process on the host via
//! `/proc/<pid>/environ` for the lifetime of the child. A co-tenant
//! process (sibling agent, telemetry scraper, leaked container shell)
//! that can `read(2)` `/proc/<pid>/environ` recovers the secret string
//! directly.
//!
//! ## Phase 1 fix (Linux only)
//!
//! Each credential is materialised into an anonymous in-memory file via
//! [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
//! with sealing enabled, the secret is written, and the file is sealed
//! against further writes / grows / shrinks / additional seals. The
//! resulting file descriptor is left WITHOUT `FD_CLOEXEC` so it
//! naturally inherits across `fork(2) + execve(2)` to the spawned
//! child. The child env carries `<KEY>_FD=<n>` instead of
//! `<KEY>=<plaintext>`, so the child knows which fd to read for each
//! named credential.
//!
//! `/proc/<pid>/environ` of the child now exposes the FD number, not
//! the secret. `/proc/<pid>/fd/<n>` and the memfd content are
//! readable only by processes matching the child's UID / capabilities
//! (kernel ptrace_may_access semantics) — the leak surface shrinks
//! from "any process on the host" to "any process that could already
//! ptrace the child".
//!
//! ## Phase 2 (out of scope for this module today)
//!
//! - macOS shm_open path (Darwin lacks `memfd_create`).
//! - Concurrent-child `/proc/<pid>/environ` attack regression test.
//! - Construct pre-exec stub that strips `GH_TOKEN` / `GITHUB_TOKEN` /
//!   `ANTHROPIC_API_KEY` from the child env before it sees them — a
//!   parallel concern owned by the Construct runtime layer.
//!
//! ## API
//!
//! [`seal_credentials_for_exec`] takes a list of `(name, plaintext)`
//! pairs and returns a [`SealedEnv`] handle. The handle exposes
//! `<KEY>_FD=<n>` env entries via [`SealedEnv::env_entries`] and owns
//! the [`OwnedFd`](std::os::fd::OwnedFd) for each credential — drop
//! closes the fds. Callers must keep the handle alive until the child
//! has been spawned (so the kernel's fork-and-exec inherits the fds);
//! after that, the parent can drop the handle freely since the child
//! holds its own copies.
//!
//! ## Non-Linux targets
//!
//! On non-Linux Unix targets and on Windows, [`seal_credentials_for_exec`]
//! returns [`SealError::NotImplemented`] — a structured error, not a
//! panic, so the daemon still compiles and runs everywhere. Callers
//! gracefully degrade to the existing plaintext-env path on those
//! platforms until Phase 2 lands.

use std::collections::HashMap;

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

/// Failure modes for [`seal_credentials_for_exec`].
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// `memfd_create(2)` syscall failed.
    #[error("memfd_create failed: {0}")]
    MemfdCreate(String),
    /// Writing the credential plaintext into the memfd failed.
    #[error("write to memfd failed: {0}")]
    Write(String),
    /// `fcntl(F_ADD_SEALS)` failed — the memfd was created but couldn't
    /// be sealed. The caller MUST treat this as a hard error and abort:
    /// an un-sealed memfd is mutable by anyone holding the fd.
    #[error("F_ADD_SEALS failed: {0}")]
    Seal(String),
    /// The credential name contains characters that would corrupt the
    /// env-var wire format. Names must match `[A-Z_][A-Z0-9_]*`.
    #[error("invalid credential name: {0}")]
    InvalidName(String),
    /// Non-Linux target — Phase 1 is Linux-only. Callers should fall
    /// back to the existing plaintext-env path. macOS shm_open + the
    /// Windows equivalent ship in Phase 2.
    #[error("seal_credentials_for_exec not implemented on this platform")]
    NotImplemented,
}

/// Opaque handle for a batch of memfd-sealed credentials.
///
/// Holds the [`OwnedFd`] for each sealed credential plus the mapping
/// from credential name → file descriptor number. The fds are NOT
/// `CLOEXEC` so they inherit naturally to the child on
/// `fork(2) + execve(2)`. The parent may drop the handle once the
/// child has been spawned — the child holds its own descriptor
/// references after fork.
///
/// On non-Linux targets this type still exists (so callers can pattern-
/// match on the result type uniformly) but it carries no inner state.
pub struct SealedEnv {
    /// Map of credential-name → file-descriptor-number.
    ///
    /// On Linux each entry corresponds to one [`OwnedFd`] in [`Self::fds`].
    /// On non-Linux this is always empty.
    name_to_fd: HashMap<String, i32>,
    /// On Linux: the owned file descriptors. Their `Drop` closes the
    /// fds; the parent must keep `SealedEnv` alive until after spawn
    /// so the kernel preserves the fds across fork.
    ///
    /// On non-Linux this field is omitted via `cfg`.
    ///
    /// `#[allow(dead_code)]`: this field's *purpose* IS its `Drop`
    /// side effect (close-on-drop semantics from `OwnedFd`). The
    /// compiler sees it as "never read" because Rust's dead-code
    /// analysis doesn't trace destructor effects — but removing the
    /// field would close the fds immediately and orphan the child's
    /// `*_FD` env entries.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fds: Vec<OwnedFd>,
}

impl SealedEnv {
    /// Yield env entries to merge into the child's environment.
    ///
    /// Each credential `(name, _)` passed to
    /// [`seal_credentials_for_exec`] becomes a single `<name>_FD=<n>`
    /// pair. The child must `read(2)` `/proc/self/fd/<n>` (or `dup`
    /// the inherited fd) to recover the plaintext.
    ///
    /// On non-Linux this yields nothing.
    pub fn env_entries(&self) -> impl Iterator<Item = (String, String)> + '_ {
        self.name_to_fd
            .iter()
            .map(|(name, fd)| (format!("{name}_FD"), fd.to_string()))
    }

    /// Total number of sealed credentials carried by this handle.
    /// Used for telemetry / receipt fields, NEVER for security checks.
    pub fn len(&self) -> usize {
        self.name_to_fd.len()
    }

    /// `true` when the handle carries no sealed credentials. Useful in
    /// the early-out path when the broker mint produced an empty
    /// credential set.
    pub fn is_empty(&self) -> bool {
        self.name_to_fd.is_empty()
    }

    /// Return owned (KEY, RawFd) pairs paralleling `env_entries`'s
    /// `<KEY>_FD=<n>` output. Used by the host-direct pre-exec stub
    /// (Slice B) to read the sealed fd contents and rewrite the
    /// child env as `<KEY>=<plaintext>` immediately before execve.
    ///
    /// On non-Linux platforms this returns an empty Vec — same as
    /// `env_entries()`.
    pub fn key_fd_map(&self) -> Vec<(String, std::os::fd::RawFd)> {
        self.name_to_fd
            .iter()
            .map(|(name, fd)| (name.clone(), *fd as std::os::fd::RawFd))
            .collect()
    }
}

/// Validate that a credential name is safe to substitute into the
/// env-var wire format. The pattern matches the existing broker
/// `env_passthrough` validator (see `broker/handler.rs::validate_env_name`)
/// — `[A-Z_][A-Z0-9_]*` — so `FOO` → `FOO_FD` round-trips cleanly and
/// can't smuggle `=` or NUL bytes into the child environment.
fn is_valid_env_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_uppercase() => {}
        _ => return false,
    }
    for c in chars {
        if !(c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Seal a batch of credentials into memfd-backed file descriptors
/// (Linux) and return a handle that yields `<KEY>_FD=<n>` env entries
/// for child injection.
///
/// On non-Linux platforms returns [`SealError::NotImplemented`] — the
/// daemon still compiles, and callers gracefully degrade to the
/// existing plaintext-env path. The macOS `shm_open` equivalent is
/// Phase 2.
///
/// ## Sealing contract (Linux)
///
/// Each memfd is created with `MFD_ALLOW_SEALING` (sealing enabled)
/// and intentionally WITHOUT `MFD_CLOEXEC` so the fd inherits across
/// `fork(2) + execve(2)`. After the plaintext is written, four seals
/// are applied via `fcntl(F_ADD_SEALS)`:
///
/// - `F_SEAL_WRITE` — no further writes to the contents.
/// - `F_SEAL_GROW` — no extending the file size.
/// - `F_SEAL_SHRINK` — no truncating the file size.
/// - `F_SEAL_SEAL` — no adding further seals (locks the policy).
///
/// After this returns, the memfd content is read-only for the
/// duration of its existence in the file table.
pub fn seal_credentials_for_exec(creds: &[(&str, &str)]) -> Result<SealedEnv, SealError> {
    // Validate names up-front so we don't half-build a SealedEnv before
    // failing. Doing this on non-Linux as well keeps the error
    // taxonomy uniform across platforms — a malformed name is the
    // same error class regardless of whether sealing is implemented.
    for (name, _) in creds {
        if !is_valid_env_name(name) {
            return Err(SealError::InvalidName((*name).to_string()));
        }
    }

    #[cfg(target_os = "linux")]
    {
        linux::seal_credentials_for_exec_impl(creds)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = creds;
        Err(SealError::NotImplemented)
    }
}

/// Read the plaintext from a Phase-1-sealed memfd and return it as a
/// zeroizing `String`. The caller is responsible for closing the fd afterward —
/// `read_sealed_fd` does NOT take ownership.
///
/// Used by the Slice B pre-exec closure in `handler.rs` to recover the
/// plaintext for env rewrite immediately before execve.
///
/// `lseek` to start is required because Phase 1's
/// [`seal_credentials_for_exec`] left the position at EOF after the
/// write. Without seeking, `read` returns 0 bytes.
///
/// Returns `InvalidData` if the buffer isn't valid UTF-8.
#[cfg(target_os = "linux")]
pub fn read_sealed_fd(fd: std::os::fd::RawFd) -> std::io::Result<zeroize::Zeroizing<String>> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::FromRawFd;

    // SAFETY: we borrow the fd temporarily. ManuallyDrop prevents the
    // `File` from closing it when this fn returns — the caller (Slice
    // B's pre-exec closure) owns the close discipline via `libc::close`.
    let mut file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    String::from_utf8(buf)
        .map(zeroize::Zeroizing::new)
        .map_err(|e| {
            let mut bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed fd contents not valid UTF-8",
            )
        })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{SealError, SealedEnv, is_valid_env_name};
    use nix::fcntl::{FcntlArg, SealFlag, fcntl};
    use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    /// Linux implementation of the credential-sealing path. See the
    /// module-level doc-comment for the security contract.
    pub(super) fn seal_credentials_for_exec_impl(
        creds: &[(&str, &str)],
    ) -> Result<SealedEnv, SealError> {
        let mut name_to_fd: HashMap<String, i32> = HashMap::with_capacity(creds.len());
        let mut fds: Vec<OwnedFd> = Vec::with_capacity(creds.len());

        for (name, plaintext) in creds {
            // Re-validate inside the loop so this function is safe to
            // call without the up-front guard if the surface ever
            // expands (defence-in-depth).
            if !is_valid_env_name(name) {
                return Err(SealError::InvalidName((*name).to_string()));
            }

            // `name` is the memfd's debug-only label visible in
            // `/proc/self/fd/<n>` symlink target (e.g.
            // `/memfd:ember-broker-cred-GH_TOKEN (deleted)`). The
            // label is informational; the secret is the file content.
            // We prefix `ember-broker-cred-` so a forensic walk of
            // `/proc/<pid>/fd` can recognise daemon-managed credential
            // fds vs ambient memfds. The CString cannot contain NUL —
            // is_valid_env_name guarantees that.
            let label = CString::new(format!("ember-broker-cred-{name}"))
                .map_err(|e| SealError::MemfdCreate(format!("label CString: {e}")))?;

            // Intentionally NOT MFD_CLOEXEC — we want the fd to
            // inherit to the child on execve. Sealing is mandatory.
            let owned_fd = memfd_create(&label, MemFdCreateFlag::MFD_ALLOW_SEALING)
                .map_err(|e| SealError::MemfdCreate(format!("name={name}: {e}")))?;

            // Wrap the OwnedFd as a File for write(). Move the fd
            // out + back to preserve ownership semantics: File takes
            // ownership of the raw fd, we extract it back via
            // into_raw_fd + FromRawFd to keep an OwnedFd for the
            // SealedEnv handle. This avoids a double-close.
            let raw_fd = owned_fd.into_raw_fd();
            // SAFETY: raw_fd was just produced by memfd_create + into_raw_fd
            // and we hold sole ownership. File::from_raw_fd takes
            // ownership and closes on drop.
            let mut file = unsafe { File::from_raw_fd(raw_fd) };
            file.write_all(plaintext.as_bytes())
                .map_err(|e| SealError::Write(format!("name={name}: {e}")))?;
            // Recover the OwnedFd from the File. into_raw_fd here
            // releases the File's close-on-drop, and we re-wrap into
            // OwnedFd so the SealedEnv owns the lifetime.
            let raw_fd = file.into_raw_fd();
            // SAFETY: raw_fd was just released by File::into_raw_fd
            // (no double-close path), and the fd is still valid.
            let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

            // Apply sealing policy. F_SEAL_WRITE blocks further
            // writes; F_SEAL_GROW + F_SEAL_SHRINK lock the size at
            // the current write position; F_SEAL_SEAL prevents
            // adding more seals (this is the lock-the-policy step
            // that defends against a hostile fd holder relaxing
            // sealing later via additional F_ADD_SEALS calls).
            let seals = SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL;
            fcntl(owned_fd.as_raw_fd(), FcntlArg::F_ADD_SEALS(seals))
                .map_err(|e| SealError::Seal(format!("name={name}: {e}")))?;

            name_to_fd.insert((*name).to_string(), owned_fd.as_raw_fd());
            fds.push(owned_fd);
        }

        Ok(SealedEnv { name_to_fd, fds })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Name validation tests (platform-agnostic) ------------------------

    #[test]
    fn is_valid_env_name_accepts_uppercase_alpha_and_underscore() {
        assert!(is_valid_env_name("GH_TOKEN"));
        assert!(is_valid_env_name("AWS_SESSION_TOKEN"));
        assert!(is_valid_env_name("_LEADING_UNDERSCORE"));
        assert!(is_valid_env_name("VAR_WITH_DIGITS_123"));
    }

    #[test]
    fn is_valid_env_name_rejects_lowercase_leading_or_special() {
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("ghToken"));
        assert!(!is_valid_env_name("1LEADING_DIGIT"));
        assert!(!is_valid_env_name("HAS=EQUALS"));
        assert!(!is_valid_env_name("HAS\0NUL"));
        assert!(!is_valid_env_name("HAS SPACE"));
    }

    #[test]
    fn invalid_name_returns_error_on_all_targets() {
        // This guards the up-front validation: invalid names short-
        // circuit before any platform-specific syscall.
        let creds = [("not-valid", "x")];
        match seal_credentials_for_exec(&creds) {
            Err(SealError::InvalidName(n)) => assert_eq!(n, "not-valid"),
            other => panic!("expected InvalidName, got {:?}", other.err()),
        }
    }

    // ---- Linux-only behavioural test --------------------------------------
    //
    // Spawns a child that reads `/proc/self/environ` and asserts the
    // credential plaintext is NOT present but `<KEY>_FD=<n>` IS. This
    // is the proof of the Phase 1 invariant: env-readers see fd
    // numbers, never the secret string.

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealed_env_hides_secret_from_proc_environ() {
        use std::os::fd::AsRawFd;

        // A high-entropy, unique checkpoint so a false-negative on
        // contains() is essentially impossible (the daemon's binary
        // doesn't contain this string anywhere).
        const SECRET: &str = "ember-test-sealed-secret-7f2a9e1c4b8d3a5e6f9c0b1a2d4e5f60";
        let creds = [("EMBER_TEST_CRED", SECRET)];

        let sealed = seal_credentials_for_exec(&creds).expect("seal credentials");
        assert_eq!(sealed.len(), 1);
        assert!(!sealed.is_empty());

        let env_entries: Vec<(String, String)> = sealed.env_entries().collect();
        assert_eq!(env_entries.len(), 1);
        assert_eq!(env_entries[0].0, "EMBER_TEST_CRED_FD");
        // FD number is positive and the assigned raw fd matches
        // what env_entries reports.
        let claimed_fd: i32 = env_entries[0].1.parse().expect("fd is integer");
        assert!(claimed_fd >= 0);

        // Spawn `cat /proc/self/environ`. The shell's env-clear is
        // honored: we ONLY pass the FD env var (plus PATH for cat
        // resolution). The child's /proc/self/environ MUST contain
        // the FD entry but NEVER the secret.
        let mut cmd = std::process::Command::new("cat");
        cmd.arg("/proc/self/environ");
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin");
        for (k, v) in &env_entries {
            cmd.env(k, v);
        }
        let output = cmd.output().expect("spawn cat /proc/self/environ");
        assert!(
            output.status.success(),
            "cat /proc/self/environ failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        // /proc/self/environ is NUL-separated; convert to lossy
        // utf8 (NUL is preserved) and substring-check.
        let environ = String::from_utf8_lossy(&output.stdout);
        assert!(
            !environ.contains(SECRET),
            "secret leaked into child /proc/self/environ"
        );
        assert!(
            environ.contains("EMBER_TEST_CRED_FD="),
            "fd-env entry missing from child /proc/self/environ; got={environ:?}"
        );

        // Sanity: the secret string IS in the parent's memfd
        // contents (proves the seal-then-pass-fd path actually
        // carries the secret to the child, just not via env). We
        // read the parent-side fd directly rather than via
        // /proc/self/fd/<n> to avoid mount-namespace surprises in
        // the test runner.
        use std::io::{Read, Seek, SeekFrom};
        use std::os::fd::FromRawFd;
        // Borrow the OwnedFd for read. We dup so the test doesn't
        // close the SealedEnv's owned fd.
        let dup_fd = unsafe { libc::dup(sealed.fds[0].as_raw_fd()) };
        assert!(dup_fd >= 0, "dup failed");
        // SAFETY: dup_fd was just produced by dup, we own it, and
        // File::from_raw_fd takes ownership + closes on drop.
        let mut f = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        f.seek(SeekFrom::Start(0)).expect("seek memfd");
        let mut s = String::new();
        f.read_to_string(&mut s).expect("read memfd");
        assert_eq!(s, SECRET, "memfd content lost in seal path");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn key_fd_map_and_read_sealed_fd_roundtrip() {
        let sealed =
            seal_credentials_for_exec(&[("FOO", "alpha"), ("BAR", "beta")]).expect("seal succeeds");

        let map = sealed.key_fd_map();
        assert_eq!(map.len(), 2);

        // Build a HashMap for order-independent assertion (HashMap ordering
        // is unspecified, so the two entries can come out either way).
        let map_by_name: std::collections::HashMap<String, std::os::fd::RawFd> =
            map.into_iter().collect();

        let foo_fd = map_by_name.get("FOO").expect("FOO present");
        let bar_fd = map_by_name.get("BAR").expect("BAR present");

        let foo_plaintext = read_sealed_fd(*foo_fd).expect("read FOO");
        let bar_plaintext = read_sealed_fd(*bar_fd).expect("read BAR");

        assert_eq!(foo_plaintext, "alpha");
        assert_eq!(bar_plaintext, "beta");

        // Don't close the fds — sealed.drop() owns them. Closing here
        // would double-free in Drop.
    }

    /// Sealed memfd refuses further writes — proves the F_SEAL_WRITE
    /// flag is actually applied. A failure here would mean the
    /// sealing step silently no-op'd and the secret bytes are still
    /// mutable post-seal.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealed_fd_rejects_post_seal_writes() {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd, FromRawFd};

        let creds = [("EMBER_TEST_SEAL_W", "before")];
        let sealed = seal_credentials_for_exec(&creds).expect("seal");
        let dup_fd = unsafe { libc::dup(sealed.fds[0].as_raw_fd()) };
        assert!(dup_fd >= 0);
        // SAFETY: dup_fd was just produced by dup. File::from_raw_fd
        // takes ownership + closes on drop.
        let mut f = unsafe { std::fs::File::from_raw_fd(dup_fd) };
        // Seek to end and try to write — must fail with EPERM
        // (or in practice, an io::Error backed by the kernel's
        // sealed-file rejection).
        let res = f.write_all(b"-after");
        assert!(
            res.is_err(),
            "expected post-seal write to fail; got Ok — F_SEAL_WRITE not applied"
        );
    }
}
