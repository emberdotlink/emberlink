// CLASSIFICATION: PUBLIC

//! Daemon-side client for the root-privileged spawn-helper sibling daemon.
//!
//! ## Architecture
//!
//! The main daemon (`ember` uid per ADR 131) does NOT have privilege
//! to `setresuid` arbitrary target uids — that capability lives in
//! the root-privileged spawn-helper sibling (LaunchDaemon on macOS,
//! systemd unit on hardened Linux). When `handle_broker_exec` needs
//! to spawn a Construct under a leased pool uid, it sends a
//! [`SpawnDirective`] frame over the helper's UDS at
//! `/var/run/emberd-spawn-helper.sock` and waits for the helper to
//! reply with the child's exit code.
//!
//! ## Platform routing
//!
//! - **Modern Linux** (`unprivileged_userns_clone=1`): in-daemon
//!   clone3 path runs directly; this module is unused.
//! - **Hardened Linux** (`unprivileged_userns_clone=0`): routes
//!   through `/var/run/emberd-spawn-helper.sock`.
//! - **macOS**: routes through `/var/run/emberd-spawn-helper.sock`.
//!   The helper itself `posix_spawn`s `emberd-spawn-shim` so sandbox setup
//!   happens after a clean exec boundary.
//!
//! [`should_use_spawn_helper`] reads the kernel sysctl on Linux at
//! process start, caches the answer, and returns true only on
//! hardened-Linux + macOS.
//!
//! ## Wire transport
//!
//! [`send_spawn_directive`] connects to the helper's UDS, writes one
//! `HelperFrame::Spawn(directive)` frame, reads one reply frame
//! (`Exit { code, .. }`, `HashMismatch`, or `Refused`), and closes the
//! connection. The helper enforces `SO_PEERCRED` — the daemon's
//! `ember` uid is the only caller it accepts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ember_spawn_helper::{
    DEFAULT_SOCKET_PATH, FrameError, HelperFrame, SpawnDirective, read_frame, write_frame,
};
use tokio::net::UnixStream;

/// Errors from [`send_spawn_directive`]. `Connect` covers the helper
/// being offline (daemon dev runs without the LaunchDaemon installed,
/// helper crashed and is mid-restart). `Refused` carries the helper's
/// stable reason string so callers can map to JSON-RPC error codes
/// per ADR 155 Component 7.
#[derive(Debug, thiserror::Error)]
pub enum SpawnHelperError {
    #[error("connect {socket}: {source}")]
    Connect {
        socket: PathBuf,
        source: std::io::Error,
    },
    #[error("frame io: {0}")]
    Frame(#[from] FrameError),
    #[error("helper refused: {reason} (detail={detail:?})")]
    Refused {
        reason: String,
        detail: Option<String>,
    },
    /// The helper's on-disk shim hash did not match `EXPECTED_SHIM_HASH`.
    /// Surfaced as a typed variant so the daemon's RPC layer can map it to a
    /// distinct error code vs a generic refusal.
    #[error("shim hash mismatch (helper refused to invoke shim): {detail:?}")]
    ShimHashMismatch { detail: Option<String> },
    #[error("hash mismatch: expected {expected} actual {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("unexpected frame from helper: {0:?}")]
    UnexpectedFrame(HelperFrame),
    #[error("connection closed before reply")]
    NoReply,
    #[error("timeout waiting for reply after {ms}ms")]
    Timeout { ms: u128 },
    #[error("platform does not support spawn-helper routing")]
    UnsupportedPlatform,
}

/// Default per-spawn timeout. The helper's accept loop is sequential
/// (one spawn at a time) so a hung child could block subsequent
/// directives; this wall-clock backstop is the daemon-side fallback
/// when the helper's own `construct_runtime_exceeded` watchdog doesn't
/// fire (per ADR 155 §"Hung-construct detection").
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1800);

/// Returns the default socket path the helper binds on this platform.
/// Both Linux and macOS converge on `/var/run/emberd-spawn-helper.sock`.
pub fn default_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

/// Returns true when this host's platform requires the spawn-helper
/// path.
///
/// **Modern Linux** is the only "self-spawn" case — `clone3` with
/// `CLONE_NEWUSER` does the privilege drop in-process. Everything
/// else (hardened Linux, macOS) needs the helper.
///
/// Cached on first call to avoid re-reading the sysctl per
/// `broker_exec` request. (Linux-worker lineage.)
#[cfg(target_os = "linux")]
pub fn should_use_spawn_helper() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
            Ok(raw) => raw.trim() == "0",
            Err(_) => {
                // Sysctl not present (pre-3.18 kernels never had this
                // knob, or restricted /proc). Fail-closed: assume
                // hardened, route through the helper. The helper's
                // absence is a separate failure mode (connect
                // ECONNREFUSED) that surfaces clearly.
                true
            }
        }
    })
}

/// macOS always uses the helper — there is no in-daemon equivalent of
/// `clone3+CLONE_NEWUSER` on Darwin (`sandbox_init` requires a
/// separate privileged process for setuid).
#[cfg(target_os = "macos")]
pub fn should_use_spawn_helper() -> bool {
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn should_use_spawn_helper() -> bool {
    false
}

/// Returns true if the spawn-helper UDS exists at the canonical path
/// — a cheap "is the helper installed?" probe. Callers gate the
/// route-through-helper dispatch on this:
///
/// ```ignore
/// if spawn_helper_client::helper_available() {
///     spawn_helper_client::send_spawn_directive(...).await
/// } else {
///     // fall back to daemon-internal setresuid path
/// }
/// ```
///
/// The check is path-existence only; an actually-broken helper
/// (socket stale, helper crashed but socket inode lingers) surfaces
/// as a `Connect` error from [`send_spawn_directive`] and the caller
/// can fall back at that point.
pub fn helper_available() -> bool {
    Path::new(DEFAULT_SOCKET_PATH).exists()
}

/// Canonical socket path. Re-export so callers don't reach across
/// crates.
pub use ember_spawn_helper::DEFAULT_SOCKET_PATH as SOCKET_PATH;

/// Connect to the spawn-helper UDS, send one directive, and await the
/// terminal reply.
///
/// On success returns `(exit_code, stdout_tail, stderr_tail)` — the
/// helper drains the child's output and carries the (capped) tails in
/// the `Exit` frame so headless brokered commands surface their output
/// even with no PTY bridge. A pre-capture helper omits the tail fields
/// and they decode as empty strings (serde default). On `HashMismatch`,
/// `Refused`, or transport error, returns the corresponding typed
/// [`SpawnHelperError`] so the caller can map to the right JSON-RPC
/// error code:
///
/// - `Refused { reason: "peercred_mismatch", .. }` →
///   `-32010 caller_identity_unavailable`
/// - `Refused { reason: "protocol_version_mismatch", .. }` →
///   `-32024 construct_runtime_exceeded`
/// - `ShimHashMismatch { .. }` → `-32032
///   spawn_helper_shim_tampered` (Component 7 reserves this code;
///   -32031 already taken by PTY+subuid refusal in handler.rs per
///   the Path A hotfix in PR #3389)
/// - `HashMismatch { .. }` → `-32030 construct_hash_mismatch`
/// - All other refusals → `-32000` (generic; refine as Component 7
///   grows)
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn send_spawn_directive(
    socket: &Path,
    directive: SpawnDirective,
    timeout: Option<Duration>,
) -> Result<(i32, String, String), SpawnHelperError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| SpawnHelperError::Connect {
            socket: socket.to_path_buf(),
            source: e,
        })?;

    write_frame(&mut stream, &HelperFrame::Spawn(directive)).await?;

    let to = timeout.unwrap_or(DEFAULT_TIMEOUT);
    let read = tokio::time::timeout(to, read_frame(&mut stream)).await;
    let frame = match read {
        Ok(Ok(Some(f))) => f,
        Ok(Ok(None)) => return Err(SpawnHelperError::NoReply),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(SpawnHelperError::Timeout { ms: to.as_millis() }),
    };

    match frame {
        HelperFrame::Exit {
            code,
            stdout_tail,
            stderr_tail,
            ..
        } => Ok((code, stdout_tail, stderr_tail)),
        HelperFrame::HashMismatch { expected, actual } => {
            Err(SpawnHelperError::HashMismatch { expected, actual })
        }
        HelperFrame::Refused { reason, detail } => {
            // The shim-hash refusal is its own typed variant.
            if reason == "shim_hash_mismatch" {
                Err(SpawnHelperError::ShimHashMismatch { detail })
            } else {
                Err(SpawnHelperError::Refused { reason, detail })
            }
        }
        other => Err(SpawnHelperError::UnexpectedFrame(other)),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn send_spawn_directive(
    _socket: &Path,
    _directive: SpawnDirective,
    _timeout: Option<Duration>,
) -> Result<(i32, String, String), SpawnHelperError> {
    Err(SpawnHelperError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_spawn_helper::{HelperFrame, WIRE_VERSION};
    use tokio::net::UnixListener;

    /// T1 — default socket path is `/var/run/emberd-spawn-helper.sock`
    /// on both supported platforms.
    #[test]
    fn default_socket_path_is_expected() {
        let p = default_socket_path();
        assert_eq!(p.to_string_lossy(), "/var/run/emberd-spawn-helper.sock");
    }

    /// T1 — on macOS the helper is always required (no in-daemon
    /// path).
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_always_uses_helper() {
        assert!(should_use_spawn_helper());
    }

    /// T1 — `helper_available()` is path-based and reflects what the
    /// dispatch gate would see in production.
    #[test]
    fn helper_available_reflects_canonical_path() {
        let canonical = Path::new(DEFAULT_SOCKET_PATH);
        assert_eq!(helper_available(), canonical.exists());
    }

    fn sample_directive() -> SpawnDirective {
        SpawnDirective {
            protocol_version: WIRE_VERSION,
            binary_path: PathBuf::from("/bin/sh"),
            argv: vec!["sh".to_string()],
            env: vec![],
            cwd: PathBuf::from("/"),
            target_uid: 1000,
            target_gid: 1000,
            content_hash_blake3: "00".to_string(),
            chroot_dir: None,
            sandbox_profile: None,
            seccomp_filter: None,
            invocation_id: None,
        }
    }

    /// T1 — happy reply path roundtrips through the client.
    #[tokio::test]
    async fn send_spawn_directive_happy_path() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-helper-client-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("h.sock");

        let listener = UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut s).await.unwrap().unwrap();
            write_frame(
                &mut s,
                &HelperFrame::Exit {
                    code: 0,
                    invocation_id: None,
                    stdout_tail: String::new(),
                    stderr_tail: String::new(),
                },
            )
            .await
            .unwrap();
        });

        let (exit, _out, _err) =
            send_spawn_directive(&socket, sample_directive(), Some(Duration::from_secs(5)))
                .await
                .expect("happy path");
        assert_eq!(exit, 0);
        mock.await.unwrap();
    }

    /// T1 — the helper's captured output tails are threaded back to the
    /// caller so headless brokered commands surface their stdout/stderr.
    #[tokio::test]
    async fn send_spawn_directive_returns_output_tails() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-helper-client-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("h.sock");

        let listener = UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut s).await.unwrap().unwrap();
            write_frame(
                &mut s,
                &HelperFrame::Exit {
                    code: 0,
                    invocation_id: Some("01HXAMPLE".to_string()),
                    stdout_tail: "#1\topen\tfix: thing\n".to_string(),
                    stderr_tail: "warning: rate limited\n".to_string(),
                },
            )
            .await
            .unwrap();
        });

        let (exit, out, err) =
            send_spawn_directive(&socket, sample_directive(), Some(Duration::from_secs(5)))
                .await
                .expect("happy path");
        assert_eq!(exit, 0);
        assert_eq!(out, "#1\topen\tfix: thing\n");
        assert_eq!(err, "warning: rate limited\n");
        mock.await.unwrap();
    }

    /// T1 — `HashMismatch` reply surfaces as typed error so caller
    /// can map to `-32030 construct_hash_mismatch`.
    #[tokio::test]
    async fn send_spawn_directive_surfaces_hash_mismatch() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-helper-client-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("h.sock");

        let listener = UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut s).await.unwrap().unwrap();
            write_frame(
                &mut s,
                &HelperFrame::HashMismatch {
                    expected: "00".to_string(),
                    actual: "ff".to_string(),
                },
            )
            .await
            .unwrap();
        });

        let err = send_spawn_directive(&socket, sample_directive(), Some(Duration::from_secs(5)))
            .await
            .expect_err("expected error");
        match err {
            SpawnHelperError::HashMismatch { expected, actual } => {
                assert_eq!(expected, "00");
                assert_eq!(actual, "ff");
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        mock.await.unwrap();
    }

    /// T1 — `Refused { peercred_mismatch }` surfaces as typed
    /// `Refused` error.
    #[tokio::test]
    async fn send_spawn_directive_surfaces_peercred_refusal() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-helper-client-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("h.sock");

        let listener = UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut s).await.unwrap().unwrap();
            write_frame(
                &mut s,
                &HelperFrame::Refused {
                    reason: "peercred_mismatch".to_string(),
                    detail: Some("uid=501 expected=302".to_string()),
                },
            )
            .await
            .unwrap();
        });

        let err = send_spawn_directive(&socket, sample_directive(), Some(Duration::from_secs(5)))
            .await
            .expect_err("expected error");
        match err {
            SpawnHelperError::Refused { reason, .. } => {
                assert_eq!(reason, "peercred_mismatch");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        mock.await.unwrap();
    }

    /// T1 — `Refused { shim_hash_mismatch }` surfaces as the typed
    /// `ShimHashMismatch` variant — distinct from generic refusals
    /// so the RPC layer can return a dedicated error code.
    #[tokio::test]
    async fn send_spawn_directive_surfaces_shim_hash_mismatch() {
        let dir = tempfile::Builder::new()
            .prefix("spawn-helper-client-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("h.sock");

        let listener = UnixListener::bind(&socket).unwrap();
        let mock = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_frame(&mut s).await.unwrap().unwrap();
            write_frame(
                &mut s,
                &HelperFrame::Refused {
                    reason: "shim_hash_mismatch".to_string(),
                    detail: Some(
                        "shim=/usr/local/libexec/emberd-spawn-shim expected=aaaa actual=bbbb"
                            .to_string(),
                    ),
                },
            )
            .await
            .unwrap();
        });

        let err = send_spawn_directive(&socket, sample_directive(), Some(Duration::from_secs(5)))
            .await
            .expect_err("expected error");
        match err {
            SpawnHelperError::ShimHashMismatch { detail } => {
                assert!(detail.unwrap_or_default().contains("expected=aaaa"));
            }
            other => panic!("expected ShimHashMismatch, got {other:?}"),
        }
        mock.await.unwrap();
    }
}
