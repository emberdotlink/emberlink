// CLASSIFICATION: PUBLIC

//! Shared protocol + helpers for the spawn-helper sibling daemon.
//!
//! ## Architecture
//!
//! This crate defines the shared frame protocol, validation helpers, content
//! hash checks, and peer-credential extraction used by the platform helpers.
//! The Linux helper performs the setuid/chroot/seccomp/exec chain directly in
//! its child process. The macOS helper uses `posix_spawn` to invoke a small
//! shim binary (see `src/bin/emberd_spawn_shim.rs`); the shim runs as the target
//! uid, applies the SBPL sandbox + chroot, and `execve`s the real construct
//! binary.
//!
//! ## Trust boundary
//!
//! The spawn-helper is a root-privileged sibling daemon (LaunchDaemon
//! on macOS, systemd unit on hardened Linux). It accepts
//! [`SpawnDirective`] frames over a Unix domain socket from the
//! unprivileged main daemon (`ember` uid per ADR 131) and performs the
//! `setuid → chroot → sandbox/seccomp → exec` chain. Per ADR 155
//! Component 4, the privileged surface is intentionally a systemd-
//! style sibling (no setuid binary anywhere) so MDM scanners see a
//! known service instance and the security review boundary stays
//! well-defined.
//!
//! ## Wire shape
//!
//! Each connection is **one directive, one reply** — single-shot RPC.
//!
//! Framing: 4-byte **little-endian** `u32` length prefix followed by a
//! UTF-8 JSON body (no nesting, no streaming, hard size cap
//! [`MAX_FRAME_BYTES`]). A frame whose length exceeds the cap drops
//! the connection without reply.
//!
//! Direction A (daemon → helper): exactly one [`HelperFrame::Spawn`]
//! carrying a [`SpawnDirective`].
//!
//! Direction B (helper → daemon): exactly one reply chosen from
//! [`HelperFrame::Exit`], [`HelperFrame::HashMismatch`], or
//! [`HelperFrame::Refused`]. After the reply, both sides close their
//! halves.
//!
//! ## Versioning
//!
//! [`WIRE_VERSION`] is the stable compile-time constant. Producers
//! stamp [`SpawnDirective::protocol_version`] on every frame; the
//! helper refuses with [`HelperFrame::Refused`] (`reason =
//! "protocol_version_mismatch"`) when the frame's value disagrees.
//! Bumps to the wire format require a coordinated daemon + helper
//! roll-out.
//!
//! ## Auth
//!
//! `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) validation via
//! [`peercred::peer_uid`] on the helper side refuses any caller whose
//! kernel-attested uid != the helper's configured `--daemon-uid`. This
//! is the load-bearing primitive that prevents any other local user
//! (or compromised local process) from issuing root-privileged spawns
//! through the helper socket.

#![deny(unsafe_op_in_unsafe_fn)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod hash;
pub mod peercred;

/// Wire-protocol version. Bumped lock-step with the daemon and the
/// helper. Frames whose [`SpawnDirective::protocol_version`] disagrees
/// are refused via [`HelperFrame::Refused`] (`reason =
/// "protocol_version_mismatch"`).
///
/// Sourced from the Linux worker's `WIRE_VERSION = 1` invariant; the
/// macOS worker also picked `1` for `PROTOCOL_VERSION`, so the two
/// streams converge here.
pub const WIRE_VERSION: u32 = 1;

/// Back-compat alias. Earlier macOS-side code referred to this constant
/// as `PROTOCOL_VERSION`. Kept as a re-export so existing daemon-side
/// references compile unchanged.
pub const PROTOCOL_VERSION: u32 = WIRE_VERSION;

/// Maximum allowed frame payload size in bytes. Defends against a
/// malicious or buggy peer that sends a giant length prefix and
/// against memory exhaustion on the root-side accept loop.
///
/// 16 MiB is generous for the legitimate payload shape (argv + env +
/// optional seccomp BPF program + sandbox profile) while still
/// bounding the helper's read buffer hard.
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Per-stream caps for the child-output tails carried in
/// [`HelperFrame::Exit`]. The helper drains the child's stdout/stderr
/// to EOF (so the child never blocks on a full pipe) but retains only
/// the last N bytes — enough for a headless caller to see command
/// output or a failure message without unbounded frame growth. The
/// values match the daemon's inline-`Command` path so a brokered
/// command's surfaced output is identical regardless of exec route.
pub const STDOUT_TAIL_CAP: usize = 64 * 1024;
pub const STDERR_TAIL_CAP: usize = 4 * 1024;

/// Format a captured output tail for the wire. `retained` is the last
/// (up to a cap) bytes of the stream; `total_seen` is the full byte
/// count the helper observed before trimming. When the stream was
/// trimmed, the daemon-side inline-path truncation marker is prepended
/// so headless callers see consistent formatting across exec routes.
pub fn format_tail(retained: &[u8], total_seen: usize) -> String {
    let s = String::from_utf8_lossy(retained);
    if total_seen > retained.len() {
        format!(
            "...[{} bytes truncated]...{}",
            total_seen - retained.len(),
            s
        )
    } else {
        s.into_owned()
    }
}

/// Default socket path the helper binds. Production mode is `0660 root:
/// ember-clients` on both platforms — the daemon's `ember` uid joins
/// `ember-clients` and connects through the group bit. Tests override
/// via `--socket <tempdir>/sock`.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/emberd-spawn-helper.sock";

/// Back-compat aliases for the per-platform names the macOS / Linux
/// drops introduced. Both point at the canonical socket path above.
pub const DEFAULT_LINUX_SOCKET_PATH: &str = DEFAULT_SOCKET_PATH;
pub const DEFAULT_MACOS_SOCKET_PATH: &str = DEFAULT_SOCKET_PATH;

/// The shared connect-group both the daemon and the spawn-helper's
/// socket use. Daemon's `ember` uid is a member of this group at
/// install time (see `ember_daemon::install::provision_ember_user`).
/// The helper chowns its socket to `root:ember-clients 0660` after
/// bind so the daemon can `connect(2)` through the group bit.
pub const DAEMON_CONNECT_GROUP: &str = "ember-clients";

/// Canonical install path for the macOS spawn shim. The macOS helper bin
/// invokes this path via `posix_spawn(2)`; the install-time hash check verifies
/// the on-disk shim matches the daemon-rendered `EXPECTED_SHIM_HASH` env var
/// before any invocation.
pub const DEFAULT_SHIM_PATH: &str = "/usr/local/libexec/emberd-spawn-shim";

/// A `SpawnDirective` instructs the helper to verify, privilege-drop,
/// chroot, sandbox/seccomp, and exec a target binary. Sent once at the
/// start of a connection inside a [`HelperFrame::Spawn`].
///
/// Field semantics:
/// - `protocol_version`: producer's [`WIRE_VERSION`] at build time. The
///   helper rejects mismatches via [`HelperFrame::Refused`].
/// - `binary_path`: absolute path on the helper's filesystem to exec.
///   The helper opens it, blake3-hashes the contents, compares to
///   `content_hash_blake3`, then `posix_spawn`s (macOS, via the shim)
///   or `execve`s (Linux) the same path.
/// - `content_hash_blake3`: lowercase or uppercase hex blake3 of
///   `binary_path`. The helper streams the file through
///   [`blake3::Hasher`] and refuses with [`HelperFrame::HashMismatch`]
///   when the on-disk content does not match. Per ADR 155 Component 2
///   this is CRIT-B's mitigation: hash divergence is `-32030
///   construct_hash_mismatch`.
/// - `argv`: argv vector for the spawned child. By convention `argv[0]`
///   is the binary name as the child sees it (basename, NOT the path).
/// - `env`: full environment vector for the child. The helper does NOT
///   inherit its own env; the directive specifies the full set. Names
///   MUST match `^[A-Z_][A-Z0-9_]*$` — see [`validate_directive`].
/// - `cwd`: working directory the child starts in. MUST be inside
///   `chroot_dir` if `chroot_dir` is `Some`.
/// - `target_uid` / `target_gid`: pool uid/gid the child runs as. The
///   helper sets gid first, then uid (lose-group-before-user order).
/// - `chroot_dir`: optional chroot root (per ADR 155 Component 3).
/// - `sandbox_profile`: optional SBPL text passed to
///   `sandbox_init_with_parameters(3)` on macOS via the shim; ignored
///   on Linux. `None` means "no SBPL sandbox" — the daemon is
///   responsible for always sending a profile in production; `None`
///   exists for test paths.
/// - `seccomp_filter`: optional raw seccomp-bpf filter bytes (the
///   wire-encoded `sock_filter` array, 8 bytes per instruction).
///   Ignored on macOS; on Linux the helper installs the filter via
///   `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` AFTER setuid
///   and BEFORE execve. The daemon owns the compilation; the helper
///   is a pure carrier.
/// - `invocation_id`: optional ULID the daemon minted for the Receipt
///   chain. The helper does NOT persist this — it's relayed back in
///   the `Exit` reply so the daemon can correlate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnDirective {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    pub binary_path: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub target_uid: u32,
    pub target_gid: u32,
    pub content_hash_blake3: String,
    #[serde(default)]
    pub chroot_dir: Option<PathBuf>,
    #[serde(default)]
    pub sandbox_profile: Option<String>,
    /// Linux-only: optional seccomp-bpf filter. Sourced from the Linux
    /// worker's directive shape. macOS ignores this field.
    #[serde(default)]
    pub seccomp_filter: Option<Vec<u8>>,
    /// Optional Receipt-chain correlation id. Sourced from the Linux
    /// worker; macOS does not yet emit it but the field is accepted on
    /// both platforms for forward-compat.
    #[serde(default)]
    pub invocation_id: Option<String>,
}

fn default_protocol_version() -> u32 {
    WIRE_VERSION
}

/// Reasons the helper can refuse a directive without spawning. Surfaced
/// in [`HelperFrame::Refused`]'s `reason` field as a stable string so
/// the daemon can map to JSON-RPC error codes (ADR 155 Component 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseReason {
    /// `SO_PEERCRED` reported a uid other than the configured daemon
    /// uid.
    PeerCredMismatch,
    /// Frame parse / length / utf-8 / json error.
    BadFrame,
    /// `protocol_version` on directive didn't match helper's build.
    ProtocolVersionMismatch,
    /// `binary_path` was not absolute or didn't exist.
    BadBinaryPath,
    /// `chroot_dir` was set but path invalid / not a directory.
    BadChrootDir,
    /// `target_uid` outside the helper's configured pool range.
    UidOutOfPool,
    /// Env name failed the `^[A-Z_][A-Z0-9_]*$` shape gate.
    InvalidEnvName,
    /// `setgid` / `setuid` / `chroot` / `chdir` returned errno.
    PrivilegeDropFailed,
    /// `sandbox_init_with_parameters(3)` returned non-zero (macOS
    /// only; surfaced via shim → helper).
    SandboxInitFailed,
    /// `prctl(PR_SET_SECCOMP)` failed (Linux only).
    SeccompInstallFailed,
    /// `posix_spawn(2)` / `Command::spawn()` / `execve(2)` failed.
    SpawnFailed,
    /// The on-disk `emberd-spawn-shim` blake3 hash didn't match the helper's
    /// installed `EXPECTED_SHIM_HASH` env var. Refused with no spawn.
    ShimHashMismatch,
}

impl RefuseReason {
    /// Stable wire string for the reason. Daemon-side maps these to
    /// JSON-RPC error codes (Component 7 allocation table).
    pub fn as_str(&self) -> &'static str {
        match self {
            RefuseReason::PeerCredMismatch => "peercred_mismatch",
            RefuseReason::BadFrame => "bad_frame",
            RefuseReason::ProtocolVersionMismatch => "protocol_version_mismatch",
            RefuseReason::BadBinaryPath => "bad_binary_path",
            RefuseReason::BadChrootDir => "bad_chroot_dir",
            RefuseReason::UidOutOfPool => "uid_out_of_pool",
            RefuseReason::InvalidEnvName => "invalid_env_name",
            RefuseReason::PrivilegeDropFailed => "privilege_drop_failed",
            RefuseReason::SandboxInitFailed => "sandbox_init_failed",
            RefuseReason::SeccompInstallFailed => "seccomp_install_failed",
            RefuseReason::SpawnFailed => "spawn_failed",
            RefuseReason::ShimHashMismatch => "shim_hash_mismatch",
        }
    }
}

/// Helper-side wire frames. `serde(tag = "type")` keeps JSON self-
/// describing for offline log analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperFrame {
    /// Daemon → helper: spawn this directive.
    Spawn(SpawnDirective),
    /// Helper → daemon: child exited (or was killed by signal). On
    /// success, `code` is the process exit code; on signal death the
    /// helper sets `code = 128 + signum` to match shell convention.
    /// `invocation_id` echoes the directive's correlation id when
    /// set.
    ///
    /// `stdout_tail` / `stderr_tail` carry the child's captured output
    /// (last [`STDOUT_TAIL_CAP`] / [`STDERR_TAIL_CAP`] bytes, UTF-8
    /// lossy, with a truncation marker via [`format_tail`]). Both are
    /// `#[serde(default)]` so a pre-capture helper (which omits them)
    /// still decodes against this struct and a pre-capture daemon
    /// ignores them — the change is additive on the wire in both
    /// directions. Carrying terminal output back to the authority root
    /// is the spawn-helper's slice of the execution-result contract
    /// (ADR 184 §"Receipts must capture placement truth" — terminal
    /// outcome), closing the gap to the higher-level `ExecOutcome`
    /// shape `core-construct-runtime` already owns.
    Exit {
        code: i32,
        #[serde(default)]
        invocation_id: Option<String>,
        #[serde(default)]
        stdout_tail: String,
        #[serde(default)]
        stderr_tail: String,
    },
    /// Helper → daemon: content_hash_blake3 didn't match. No spawn
    /// happened.
    HashMismatch { expected: String, actual: String },
    /// Helper → daemon: directive refused before spawn. No process
    /// started.
    Refused {
        reason: String,
        detail: Option<String>,
    },
}

/// Frame-level wire errors. Distinguished from spawn-side errors so
/// the helper can drop the connection (frame error) vs reply with a
/// typed [`HelperFrame::Refused`] (validation error).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame length {0} exceeds MAX_FRAME_BYTES ({MAX_FRAME_BYTES})")]
    LengthExceeded(u32),
    #[error("frame payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("frame payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Read one length-prefixed JSON frame. Length is 4-byte little-
/// endian. Returns `Ok(None)` on clean EOF before any bytes;
/// otherwise either a parsed frame or a typed error.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<HelperFrame>, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let length = u32::from_le_bytes(len_buf);
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::LengthExceeded(length));
    }
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    let json = String::from_utf8(payload)?;
    let frame: HelperFrame = serde_json::from_str(&json)?;
    Ok(Some(frame))
}

/// Write one length-prefixed JSON frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &HelperFrame,
) -> Result<(), FrameError> {
    let json = serde_json::to_vec(frame)?;
    let length = u32::try_from(json.len()).map_err(|_| FrameError::LengthExceeded(u32::MAX))?;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::LengthExceeded(length));
    }
    writer.write_all(&length.to_le_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

/// Synchronous frame I/O. The Linux bin's accept loop is async
/// (tokio), but the post-fork child branch is async-signal-safe-only
/// and cannot use tokio. The sync paths are used inside the parent's
/// `tokio::task::spawn_blocking` for the raw-fork harness, and also
/// by the daemon-side `spawn_helper_client::dispatch_spawn` blocking
/// fallback.
pub mod sync_io {
    use super::{FrameError, HelperFrame, MAX_FRAME_BYTES};
    use std::io::{Read, Write};

    /// Sync analogue of [`super::read_frame`]. Same wire shape (4-byte
    /// little-endian length + JSON body).
    pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<HelperFrame>, FrameError> {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_le_bytes(len_buf);
        if length > MAX_FRAME_BYTES {
            return Err(FrameError::LengthExceeded(length));
        }
        let mut payload = vec![0u8; length as usize];
        reader.read_exact(&mut payload)?;
        let json = String::from_utf8(payload)?;
        let frame: HelperFrame = serde_json::from_str(&json)?;
        Ok(Some(frame))
    }

    /// Sync analogue of [`super::write_frame`].
    pub fn write_frame<W: Write>(writer: &mut W, frame: &HelperFrame) -> Result<(), FrameError> {
        let json = serde_json::to_vec(frame)?;
        let length = u32::try_from(json.len()).map_err(|_| FrameError::LengthExceeded(u32::MAX))?;
        if length > MAX_FRAME_BYTES {
            return Err(FrameError::LengthExceeded(length));
        }
        writer.write_all(&length.to_le_bytes())?;
        writer.write_all(&json)?;
        writer.flush()?;
        Ok(())
    }
}

/// Construct a [`HelperFrame::Refused`] with the given reason +
/// optional detail. Convenience helper so call-sites don't keep
/// stringifying.
pub fn refuse(reason: RefuseReason, detail: Option<String>) -> HelperFrame {
    HelperFrame::Refused {
        reason: reason.as_str().to_string(),
        detail,
    }
}

/// Validate a directive's invariants before acting on it. Returns
/// `Ok(())` on success; the [`RefuseReason`] otherwise. Pool range is
/// `[pool_uid_base, pool_uid_base + pool_size)`.
///
/// The hash check is NOT part of this gate — that requires reading
/// the on-disk binary and is performed by the helper's spawn path (see
/// [`hash::verify_content_hash`]).
///
/// Sourced from the Linux worker's `validate_directive` — the env-name
/// shape gate is defense-in-depth against env-injection from a daemon
/// path that didn't pre-filter.
pub fn validate_directive(
    d: &SpawnDirective,
    pool_uid_base: u32,
    pool_size: u32,
) -> Result<(), RefuseReason> {
    if d.protocol_version != WIRE_VERSION {
        return Err(RefuseReason::ProtocolVersionMismatch);
    }
    if !d.binary_path.is_absolute() {
        return Err(RefuseReason::BadBinaryPath);
    }
    if d.target_uid < pool_uid_base || d.target_uid >= pool_uid_base.saturating_add(pool_size) {
        return Err(RefuseReason::UidOutOfPool);
    }
    if let Some(chroot) = &d.chroot_dir
        && !chroot.is_absolute()
    {
        return Err(RefuseReason::BadChrootDir);
    }
    for (name, _) in &d.env {
        if !is_valid_env_name(name) {
            return Err(RefuseReason::InvalidEnvName);
        }
    }
    Ok(())
}

/// `^[A-Z_][A-Z0-9_]*$` — the shape gate for env names. Refuses empty
/// strings, lowercase, leading digits, and embedded `=` / `\n` /
/// control chars. Sourced from the Linux worker's env-injection
/// defense.
pub fn is_valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first_ok = bytes[0].is_ascii_uppercase() || bytes[0] == b'_';
    if !first_ok {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn directive() -> SpawnDirective {
        SpawnDirective {
            protocol_version: WIRE_VERSION,
            binary_path: PathBuf::from("/usr/bin/id"),
            argv: vec!["id".to_string(), "-u".to_string()],
            env: vec![("PATH".to_string(), "/usr/bin".to_string())],
            cwd: PathBuf::from("/"),
            target_uid: 10010,
            target_gid: 10010,
            content_hash_blake3: "0".repeat(64),
            chroot_dir: None,
            sandbox_profile: None,
            seccomp_filter: None,
            invocation_id: Some("01HXAMPLE0000000000000".to_string()),
        }
    }

    #[tokio::test]
    async fn spawn_directive_protocol_roundtrips() {
        // Roundtrip every HelperFrame variant through the wire
        // encoding.
        let cases = vec![
            HelperFrame::Spawn(directive()),
            HelperFrame::Exit {
                code: 0,
                invocation_id: None,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            },
            HelperFrame::Exit {
                code: 137,
                invocation_id: Some("01HXAMPLE".to_string()),
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            },
            HelperFrame::Exit {
                code: 0,
                invocation_id: Some("01HXAMPLE".to_string()),
                stdout_tail: "#1\topen\tfix: thing\n".to_string(),
                stderr_tail: "warning: rate limited\n".to_string(),
            },
            HelperFrame::HashMismatch {
                expected: "aa".to_string(),
                actual: "bb".to_string(),
            },
            HelperFrame::Refused {
                reason: "peercred_mismatch".to_string(),
                detail: Some("uid=501 expected=302".to_string()),
            },
            HelperFrame::Refused {
                reason: "shim_hash_mismatch".to_string(),
                detail: Some("on-disk=aaaa expected=bbbb".to_string()),
            },
        ];
        for frame in cases {
            let (mut a, mut b) = duplex(64 * 1024);
            write_frame(&mut a, &frame).await.unwrap();
            let read = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(read, frame);
        }
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        let bad_len = (MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(bad_len);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(FrameError::LengthExceeded(_))));
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let empty: Vec<u8> = vec![];
        let mut cursor = std::io::Cursor::new(empty);
        let result = read_frame(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn refuse_reason_strings_are_stable() {
        // Daemon-side maps these to JSON-RPC error codes; renaming
        // would break the cross-component contract.
        assert_eq!(RefuseReason::PeerCredMismatch.as_str(), "peercred_mismatch");
        assert_eq!(RefuseReason::BadFrame.as_str(), "bad_frame");
        assert_eq!(
            RefuseReason::ProtocolVersionMismatch.as_str(),
            "protocol_version_mismatch"
        );
        assert_eq!(RefuseReason::BadBinaryPath.as_str(), "bad_binary_path");
        assert_eq!(RefuseReason::BadChrootDir.as_str(), "bad_chroot_dir");
        assert_eq!(RefuseReason::UidOutOfPool.as_str(), "uid_out_of_pool");
        assert_eq!(RefuseReason::InvalidEnvName.as_str(), "invalid_env_name");
        assert_eq!(
            RefuseReason::PrivilegeDropFailed.as_str(),
            "privilege_drop_failed"
        );
        assert_eq!(
            RefuseReason::SandboxInitFailed.as_str(),
            "sandbox_init_failed"
        );
        assert_eq!(
            RefuseReason::SeccompInstallFailed.as_str(),
            "seccomp_install_failed"
        );
        assert_eq!(RefuseReason::SpawnFailed.as_str(), "spawn_failed");
        assert_eq!(
            RefuseReason::ShimHashMismatch.as_str(),
            "shim_hash_mismatch"
        );
    }

    #[test]
    fn directive_defaults_protocol_version_on_deserialize() {
        let json = r#"{
            "binary_path": "/usr/bin/id",
            "argv": ["id"],
            "env": [],
            "cwd": "/",
            "target_uid": 10010,
            "target_gid": 10010,
            "content_hash_blake3": "00"
        }"#;
        let d: SpawnDirective = serde_json::from_str(json).unwrap();
        assert_eq!(d.protocol_version, WIRE_VERSION);
        // seccomp_filter + invocation_id default to None.
        assert!(d.seccomp_filter.is_none());
        assert!(d.invocation_id.is_none());
    }

    #[test]
    fn wire_version_back_compat_alias() {
        // PROTOCOL_VERSION is the macOS-worker name; both names point
        // at the same constant so existing call-sites compile
        // unchanged.
        assert_eq!(PROTOCOL_VERSION, WIRE_VERSION);
    }

    fn pool_directive_at_uid(uid: u32) -> SpawnDirective {
        let mut d = directive();
        d.target_uid = uid;
        d.target_gid = uid;
        d
    }

    #[test]
    fn validate_rejects_uid_below_pool() {
        let d = pool_directive_at_uid(10009);
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::UidOutOfPool));
    }

    #[test]
    fn validate_rejects_uid_above_pool() {
        let d = pool_directive_at_uid(10010 + 8);
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::UidOutOfPool));
    }

    #[test]
    fn validate_accepts_uid_at_pool_base() {
        let d = pool_directive_at_uid(10010);
        validate_directive(&d, 10010, 8).expect("should accept");
    }

    #[test]
    fn validate_accepts_uid_at_pool_max_inclusive() {
        let d = pool_directive_at_uid(10010 + 7);
        validate_directive(&d, 10010, 8).expect("should accept");
    }

    #[test]
    fn validate_rejects_wire_version_mismatch() {
        let mut d = pool_directive_at_uid(10010);
        d.protocol_version = WIRE_VERSION + 1;
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::ProtocolVersionMismatch));
    }

    #[test]
    fn validate_rejects_lowercase_env_name() {
        let mut d = pool_directive_at_uid(10010);
        d.env = vec![("path".to_string(), "/usr/bin".to_string())];
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::InvalidEnvName));
    }

    #[test]
    fn validate_rejects_env_name_starting_with_digit() {
        let mut d = pool_directive_at_uid(10010);
        d.env = vec![("1FOO".to_string(), "x".to_string())];
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::InvalidEnvName));
    }

    #[test]
    fn validate_rejects_env_name_with_equals() {
        let mut d = pool_directive_at_uid(10010);
        d.env = vec![("FOO=BAR".to_string(), "x".to_string())];
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::InvalidEnvName));
    }

    #[test]
    fn validate_rejects_env_name_with_newline() {
        let mut d = pool_directive_at_uid(10010);
        d.env = vec![("FOO\nBAR".to_string(), "x".to_string())];
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::InvalidEnvName));
    }

    #[test]
    fn validate_rejects_empty_env_name() {
        let mut d = pool_directive_at_uid(10010);
        d.env = vec![("".to_string(), "x".to_string())];
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::InvalidEnvName));
    }

    #[test]
    fn validate_rejects_relative_binary_path() {
        let mut d = pool_directive_at_uid(10010);
        d.binary_path = PathBuf::from("usr/bin/id");
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::BadBinaryPath));
    }

    #[test]
    fn validate_rejects_relative_chroot_dir() {
        let mut d = pool_directive_at_uid(10010);
        d.chroot_dir = Some(PathBuf::from("tmp/quarantine"));
        let err = validate_directive(&d, 10010, 8).expect_err("should reject");
        assert!(matches!(err, RefuseReason::BadChrootDir));
    }

    #[test]
    fn sync_io_roundtrip() {
        let frame = HelperFrame::Exit {
            code: 42,
            invocation_id: None,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
        };
        let mut buf = Vec::new();
        sync_io::write_frame(&mut buf, &frame).expect("encode");
        let mut cursor = std::io::Cursor::new(&buf);
        let decoded = sync_io::read_frame(&mut cursor)
            .expect("decode")
            .expect("Some");
        assert_eq!(decoded, frame);
    }

    /// A pre-capture helper omits `stdout_tail` / `stderr_tail` on the
    /// wire. The `#[serde(default)]` attrs must decode that legacy
    /// frame into empty tails rather than failing — the additive
    /// fields are backward-compatible in the helper→daemon direction.
    #[test]
    fn exit_frame_decodes_legacy_without_tails() {
        let legacy = r#"{"type":"exit","code":7,"invocation_id":"01HXAMPLE"}"#;
        let frame: HelperFrame = serde_json::from_str(legacy).expect("legacy decode");
        assert_eq!(
            frame,
            HelperFrame::Exit {
                code: 7,
                invocation_id: Some("01HXAMPLE".to_string()),
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            }
        );
    }

    #[test]
    fn format_tail_marks_truncation() {
        // Untruncated: total_seen == retained.len() → no marker.
        assert_eq!(format_tail(b"hello", 5), "hello");
        // Truncated: marker reports how many bytes were dropped.
        let out = format_tail(b"tail-bytes", 100);
        assert!(out.starts_with("...[90 bytes truncated]..."), "{out}");
        assert!(out.ends_with("tail-bytes"), "{out}");
    }
}
