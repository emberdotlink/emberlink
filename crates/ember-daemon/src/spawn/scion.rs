//! Container mount-table helpers.
//!
//! Bind-mount strategy (one socket per agent, parent dir read-only):
//!
//! 1. emberd creates `/run/emberd/agent-<uuid>.sock` via
//!    [`crate::infra::socket::create_per_agent_socket`] (O_EXCL + flock
//!    on the parent dir, refuses any pre-existing inode).
//! 2. The container's mount table grants the agent uid RW on **only that
//!    single socket inode**, and RO on the parent dir `/run/emberd/`.
//! 3. Because the parent dir is RO from inside the container, the agent
//!    uid cannot `unlink` the socket, cannot `rename` it, cannot plant a
//!    symlink at a sibling path, and cannot list other agents' sockets.
//! 4. On agent termination emberd calls
//!    [`crate::infra::socket::tombstone_socket`] so the UUID is never
//!    reused, defending against agent-id replay across spawn cycles.
//!
//! This module returns a description of the mount table — the actual
//! runtime that constructs the container (containerd / runc / Docker /
//! Apple's `container` toolchain) consumes [`MountSpec`] and applies the
//! mounts in its native vocabulary. Keeping the description abstract
//! lets us swap runtimes without rewriting the security-critical
//! mount-table logic.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use core_crypto::Signer;
use core_events::receipt::{
    ExecCompletionBody, RECEIPT_KIND_EXEC_COMPLETION, RECEIPT_KIND_SPAWN_WITNESS, ReceiptEnvelope,
    ReceiptVersion, SignError, TerminationAuthority, sign_receipt_v2,
    sign_spawn_witness_parent_signature,
};
use core_receipts::SpawnWitness;
use ember_exec::uds::{ExecFrame, FrameError, SpawnDirective, write_frame};
use sha2::{Digest, Sha256};
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::spawn::runtime::{
    ContainerRuntime, RuntimeSpawnError, RuntimeState, SpawnSpec, SpawnedContainer, UdsBindMount,
};

/// Errors raised by the SCION agent-spawn path.
///
/// The two variants relevant to binary hash pinning are:
///
/// - [`SpawnError::BinaryHashMismatch`] — the on-disk binary's SHA-256
///   does not match the operator-pinned hash from [`crate::infra::config::DaemonConfig::scion_binary_sha256`].
///   The spawn path MUST refuse to fork-exec on this error: a mismatch
///   means an attacker has swapped the binary on disk between install
///   and exec (TOCTOU).
/// - [`SpawnError::BinaryIo`] — `open`/`read` of the binary failed.
///   Conservative posture: also refuse the spawn so a missing/unreadable
///   binary cannot be silently substituted by symlink-redirect.
///
/// New variants must be additive: each represents a refuse-spawn
/// condition. Bundling unrelated errors into this enum widens the trust
/// surface and should require security review.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// The on-disk binary's computed SHA-256 differs from the operator-
    /// pinned hash in `DaemonConfig`. Both fields are lower-hex
    /// SHA-256 (64 chars). Refuse the spawn unconditionally; do not
    /// retry, do not log the mismatch as a warn — this is the CRIT-B
    /// signal that the binary has been replaced.
    #[error("scion binary hash mismatch: expected {expected}, got {actual}")]
    BinaryHashMismatch {
        /// Operator-pinned SHA-256 from `DaemonConfig::scion_binary_sha256`.
        expected: String,
        /// Computed SHA-256 of the binary bytes at the configured path.
        actual: String,
    },
    /// I/O failure while opening or reading the binary for hashing.
    /// Treat as refuse-spawn — see the variant docstring on
    /// [`SpawnError`] for the rationale.
    #[error("scion binary io error: {0}")]
    BinaryIo(#[from] std::io::Error),
    /// The configured
    /// in-container UDS path does not exist, is not a socket, or
    /// could not be `stat`-ed. Validated BEFORE `connect()` so a
    /// dangling path produces a clean error instead of a vague
    /// `ECONNREFUSED`. Refuse the spawn — sending a directive to a
    /// non-socket inode (regular file, symlink to a hostile target)
    /// re-opens CRIT-C-shaped redirect attacks against the per-agent
    /// socket trust surface.
    #[error("scion exec socket invalid: {path} ({reason})")]
    ExecSocketInvalid {
        /// The configured socket path that failed validation.
        path: String,
        /// Human-readable reason (`not found`, `not a socket`, etc.).
        reason: String,
    },
    /// `tokio::net::UnixStream::connect`
    /// failed against an already-validated path. Carries the underlying
    /// I/O error (`ECONNREFUSED` when the receiver crashed between
    /// validation and connect, `EACCES` when the agent uid doesn't
    /// hold 0660 on the socket, etc.).
    #[error("scion exec connect failed: {0}")]
    ExecConnect(std::io::Error),
    /// Encoding or writing
    /// the SpawnDirective frame failed mid-handshake. The connection
    /// is owned by the caller at the point of return; this variant
    /// is reached only on the pre-return write path inside
    /// [`send_spawn_directive`] itself.
    #[error("scion exec directive write failed: {0}")]
    ExecDirectiveWrite(FrameError),
    /// Failed to capture the
    /// (cgroup_v2_id, userns_inode, mnt_ns_inode) tuple for a freshly
    /// spawned container PID. Refuse-spawn: a missing binding tuple
    /// breaks the agent_socket_enrollments → container identity
    /// invariant and would let a future kernel exploit re-bind the
    /// per-agent UDS to a different namespace without detection. See
    /// [`capture_container_ns_inodes`] for the read paths and the
    /// error semantics.
    #[error("namespace inode capture failed: {reason}")]
    NamespaceInodeCaptureFailed {
        /// Human-readable description naming the specific read that
        /// failed (e.g. `read /proc/12345/cgroup: No such file or
        /// directory`).
        reason: String,
    },
}

/// Hash the file at `path` with SHA-256 and compare against `expected`
/// (lower-hex, no `sha256:` prefix). Returns `Ok(())` on byte-for-byte
/// match.
///
/// Reads the file in 64 KiB chunks rather than slurping it into RAM,
/// so a multi-hundred-MB binary does not balloon the daemon's RSS at
/// spawn time. The comparison is case-insensitive on the `expected`
/// side (operators paste hashes from different sources — `shasum -a 256`
/// lowercase, GitHub release pages uppercase) but the **computed** side
/// is always lowercase, so the equality test normalises `expected` once.
///
/// # CRIT-B (TOCTOU between install and exec)
///
/// The pin is meaningful only when this function runs **immediately
/// before** fork-exec — any window between hashing and `execve` is a
/// TOCTOU vector. Callers that need to derive multiple values from the
/// binary (size, mtime, etc.) must hash last, not first.
///
/// # Errors
///
/// - [`SpawnError::BinaryHashMismatch`] when the computed hash differs.
/// - [`SpawnError::BinaryIo`] when opening or reading the file fails
///   (missing file, permission denied, mid-read I/O error).
pub fn verify_scion_binary_hash(path: &Path, expected: &str) -> Result<(), SpawnError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    let expected_lower = expected.to_ascii_lowercase();
    if actual != expected_lower {
        return Err(SpawnError::BinaryHashMismatch {
            expected: expected_lower,
            actual,
        });
    }
    Ok(())
}

/// One entry in the container mount table.
///
/// Each entry binds a host filesystem path into the container at a
/// fixed target path. The kind dictates whether the mount is the parent
/// directory (always RO — protects against socket-swap attacks from
/// inside the container) or the per-agent socket inode itself (RW so
/// the agent can speak to emberd over JSON-RPC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    /// Path on the daemon-host filesystem.
    pub source: PathBuf,
    /// Path inside the agent container.
    pub target: PathBuf,
    /// Mount kind — selects the read/write posture.
    pub kind: MountKind,
}

/// Mount kinds emitted by [`scion_mount_table_for_socket`] and
/// [`scion_mount_table_with_persona_key`].
///
/// The first two variants form the load-bearing trust-surface universe
/// of [`scion_mount_table_for_socket`]: the parent dir is *always* RO
/// and the socket inode is *always* RW. Adding new kinds to the socket
/// mount table would widen the trust surface — extend only with
/// security review.
///
/// [`MountKind::MlockedPersonaKey`] is a virtual entry — it describes
/// the in-process mlocked memory region for the agent's persona key, not
/// a filesystem mount. It is emitted only by
/// [`scion_mount_table_with_persona_key`]
/// so the lifecycle of the locked region is observable in the same
/// table that the container runtime consumes for the socket bind-mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// Read-only bind-mount. Used for the parent directory so the agent
    /// uid cannot unlink, rename, or replace any sibling inode. From
    /// inside the container the directory listing is visible but every
    /// mutation (unlink, mkdir, symlink, rename) fails with `EROFS`.
    ReadOnlyDir,
    /// Read-write bind-mount of a single socket inode. The agent uid
    /// (assigned by the container runtime) holds 0660 on the socket so
    /// it can `connect()` and send/receive bytes, but the parent-dir
    /// RO mount prevents `unlink`/`rename` of the inode itself.
    ReadWriteSocket,
    /// Virtual entry describing the
    /// in-process mlocked memory region holding the persona's Ed25519
    /// secret. The `source` path is a checkpoint (`/proc/self/mem`) and
    /// the `target` carries the persona id so reconcilers can correlate
    /// "which agent's key is currently pinned" with the personas table
    /// `container_id` column. The entry is informational — container
    /// runtimes ignore it (the underlying memory is per-daemon, not
    /// per-container), but it surfaces the lifecycle in the same table
    /// that the spawn-path tests assert against.
    MlockedPersonaKey,
}

/// Build the container mount-table contribution for a per-agent UDS
/// socket created by
/// [`crate::infra::socket::create_per_agent_socket`].
///
/// `socket_path` is the absolute path on the daemon host (typically
/// `/run/emberd/agent-<uuid>.sock`). The returned vector has two
/// entries — the parent dir RO, the socket inode RW — and the order is
/// stable for diffing: parent first, socket second. Callers must apply
/// both: dropping the parent-dir RO mount lets the agent uid unlink
/// the socket and replace it with a symlink to a different victim
/// inode, re-opening CRIT-C.
///
/// # Panics
///
/// Panics if `socket_path` has no parent directory (i.e. is the
/// filesystem root). In practice the per-agent socket always lives
/// under `/run/emberd/` so this is unreachable; the panic is a
/// defensive assertion rather than a recoverable error.
pub fn scion_mount_table_for_socket(socket_path: &Path) -> Vec<MountSpec> {
    let parent = socket_path
        .parent()
        .expect("per-agent socket path must have a parent directory")
        .to_path_buf();
    let file_name = socket_path
        .file_name()
        .expect("per-agent socket path must have a file name");

    // Mount target paths are fixed: the agent container always sees the
    // parent dir at `/run/emberd/` and its own socket at the same
    // basename under that dir. This makes the agent's connect()
    // target stable (`/run/emberd/agent-<uuid>.sock`) regardless of
    // where emberd stages the socket on the host.
    let target_parent = PathBuf::from(crate::infra::socket::PER_AGENT_SOCKET_PARENT);
    let target_socket = target_parent.join(file_name);

    vec![
        MountSpec {
            source: parent,
            target: target_parent,
            kind: MountKind::ReadOnlyDir,
        },
        MountSpec {
            source: socket_path.to_path_buf(),
            target: target_socket,
            kind: MountKind::ReadWriteSocket,
        },
    ]
}

/// Build the mount-table contribution
/// for a per-agent UDS socket AND surface the persona's mlocked
/// memory region as an additional informational entry.
///
/// The returned vector extends [`scion_mount_table_for_socket`] with a
/// third [`MountKind::MlockedPersonaKey`] entry whose `target` carries
/// the persona id (e.g. `/run/emberd/mlocked/<persona_id>`) so the
/// spawn-path tests can assert "a persona key is currently pinned"
/// without reaching into daemon private state.
///
/// The MlockedPersonaKey entry is informational only — container
/// runtimes that consume the mount table for actual filesystem mounts
/// MUST filter on [`MountKind`] and ignore non-filesystem kinds. The
/// first two entries (parent dir RO, socket inode RW) carry the same
/// load-bearing trust-surface invariants as the bare socket-only
/// table, so callers can swap to this variant without changing the
/// runtime's mount-application logic.
pub fn scion_mount_table_with_persona_key(socket_path: &Path, persona_id: &str) -> Vec<MountSpec> {
    let mut mounts = scion_mount_table_for_socket(socket_path);
    // The persona-key entry carries the persona id in its `target`
    // path so the lifecycle is correlatable across audit log + mount
    // table without an extra column. The `source` is a checkpoint that
    // never resolves to a real bind-mount source — runtimes ignore
    // entries with non-filesystem kinds.
    let target = PathBuf::from(crate::infra::socket::PER_AGENT_SOCKET_PARENT)
        .join("mlocked")
        .join(persona_id);
    mounts.push(MountSpec {
        source: PathBuf::from("/proc/self/mem"),
        target,
        kind: MountKind::MlockedPersonaKey,
    });
    mounts
}

fn uds_bind_mounts_from_mount_table(mounts: &[MountSpec]) -> Vec<UdsBindMount> {
    mounts
        .iter()
        .filter_map(|mount| match mount.kind {
            MountKind::ReadOnlyDir => Some(UdsBindMount {
                host_path: mount.source.clone(),
                container_path: mount.target.clone(),
                read_only: true,
            }),
            MountKind::ReadWriteSocket => Some(UdsBindMount {
                host_path: mount.source.clone(),
                container_path: mount.target.clone(),
                read_only: false,
            }),
            // Informational only: runtimes must not try to materialize
            // the in-process mlocked key region as a filesystem mount.
            MountKind::MlockedPersonaKey => None,
        })
        .collect()
}

/// Apply a SCION mount table to a canonical spawn spec, then dispatch
/// through any [`ContainerRuntime`] implementation.
///
/// This is the caller-side narrow waist for SCION spawn: SCION owns the
/// mount-table translation, while the selected runtime owns container
/// lifecycle. Tests can pass a noop/recording runtime here without
/// changing SCION-specific caller code.
pub async fn spawn_with_scion_mount_table<R>(
    runtime: &R,
    mut spec: SpawnSpec,
    mounts: &[MountSpec],
) -> Result<SpawnedContainer, RuntimeSpawnError>
where
    R: ContainerRuntime + ?Sized,
{
    spec.uds_mounts
        .extend(uds_bind_mounts_from_mount_table(mounts));
    runtime.spawn(spec).await
}

/// SCION-facing adapter over a generic [`ContainerRuntime`].
///
/// SCION owns the security-critical mount-table logic; the underlying
/// runtime owns the backend-specific container lifecycle. This adapter
/// keeps those responsibilities separate by translating SCION's
/// [`MountSpec`] table into canonical runtime [`UdsBindMount`]s and
/// delegating the actual spawn/drain/state-report calls through the
/// shared runtime trait.
pub struct ScionRuntime {
    inner: Box<dyn ContainerRuntime>,
}

impl ScionRuntime {
    pub fn new<R>(inner: R) -> Self
    where
        R: ContainerRuntime + 'static,
    {
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn from_boxed(inner: Box<dyn ContainerRuntime>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &dyn ContainerRuntime {
        self.inner.as_ref()
    }

    /// Apply a SCION mount table to the canonical spawn spec, then
    /// delegate the launch to the wrapped runtime through trait
    /// dispatch.
    pub async fn spawn_with_mount_table(
        &self,
        spec: SpawnSpec,
        mounts: &[MountSpec],
    ) -> Result<SpawnedContainer, RuntimeSpawnError> {
        spawn_with_scion_mount_table(self.inner.as_ref(), spec, mounts).await
    }
}

#[async_trait]
impl ContainerRuntime for ScionRuntime {
    async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
        self.inner.spawn(spec).await
    }

    async fn bind_mount_uds(
        &self,
        container_id: &str,
        host_path: &Path,
        in_container_path: &Path,
    ) -> Result<(), RuntimeSpawnError> {
        self.inner
            .bind_mount_uds(container_id, host_path, in_container_path)
            .await
    }

    async fn drain(
        &self,
        container_id: &str,
        grace: std::time::Duration,
    ) -> Result<(), RuntimeSpawnError> {
        self.inner.drain(container_id, grace).await
    }

    async fn state_report(&self, container_id: &str) -> Result<RuntimeState, RuntimeSpawnError> {
        self.inner.state_report(container_id).await
    }
}

impl fmt::Debug for ScionRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScionRuntime").finish_non_exhaustive()
    }
}

/// emberd-side wire-protocol
/// counterpart to `ember_exec::spawn::handle_spawn_directive` (subtask C).
///
/// Opens a `tokio::net::UnixStream` to the in-container `ember-exec`
/// listener at `socket_path`, encodes `directive` as
/// `ExecFrame::SpawnDirective`, writes the frame, flushes, and returns the
/// open stream so the caller can drive the bidirectional pty-frame proxy
/// (`StdinBytes` / `OutputBytes` / `Resize` / `Exit`) until the child
/// exits. The connection lifecycle from here is the caller's
/// responsibility — `send_spawn_directive` performs handshake only.
///
/// # Security
///
/// - `socket_path` is validated BEFORE `connect()` via `tokio::fs::metadata`
///   plus `FileTypeExt::is_socket`. A dangling path or non-socket inode is
///   refused with [`SpawnError::ExecSocketInvalid`]; the daemon never sends
///   credentials to a hostile inode.
/// - `directive.credential_env` carries broker-resolved scoped credentials
///   destined for the child's `execve` env. The error paths in this
///   function log the binary path and target uid by name only — `credential_env`
///   is NEVER logged or surfaced in error messages.
///
/// # Errors
///
/// - [`SpawnError::ExecSocketInvalid`] — path missing, not a socket, or
///   metadata read failed.
/// - [`SpawnError::ExecConnect`] — `UnixStream::connect` failed
///   (ECONNREFUSED, EACCES, etc.).
/// - [`SpawnError::ExecDirectiveWrite`] — encoding or writing the
///   SpawnDirective frame failed.
pub async fn send_spawn_directive(
    socket_path: &Path,
    directive: SpawnDirective,
) -> Result<UnixStream, SpawnError> {
    // Validate the socket path BEFORE connect so a missing / non-socket
    // path produces a typed error instead of a vague ECONNREFUSED from
    // the connect syscall.
    let meta = match tokio::fs::metadata(socket_path).await {
        Ok(m) => m,
        Err(e) => {
            return Err(SpawnError::ExecSocketInvalid {
                path: socket_path.display().to_string(),
                reason: format!("metadata: {e}"),
            });
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;
        if !meta.file_type().is_socket() {
            return Err(SpawnError::ExecSocketInvalid {
                path: socket_path.display().to_string(),
                reason: "not a unix-domain socket".to_string(),
            });
        }
    }
    // Connect. `tokio::net::UnixStream::connect` is async-safe and
    // returns the open stream on success.
    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) => {
            // Log fields by name only — credential_env is NEVER logged.
            tracing::warn!(
                socket = %socket_path.display(),
                binary_path = %directive.binary_path,
                target_uid = directive.target_uid,
                error = %e,
                "send_spawn_directive: UDS connect failed"
            );
            return Err(SpawnError::ExecConnect(e));
        }
    };
    // Encode + flush the SpawnDirective frame. The receiver (subtask C's
    // `handle_spawn_directive`) reads exactly one SpawnDirective at
    // connection open.
    let frame = ExecFrame::SpawnDirective(directive.clone());
    if let Err(e) = write_frame(&mut stream, &frame).await {
        tracing::warn!(
            socket = %socket_path.display(),
            binary_path = %directive.binary_path,
            target_uid = directive.target_uid,
            error = %e,
            "send_spawn_directive: SpawnDirective frame write failed"
        );
        return Err(SpawnError::ExecDirectiveWrite(e));
    }
    Ok(stream)
}

/// Build + sign a Receipt v2 envelope
/// of kind `exec.completion` for the just-completed in-container exec.
///
/// Called by [`crate::broker::handler::handle_broker_exec`]'s in-container
/// branch on every `ExecFrame::Exit` arriving from the in-container
/// `ember-exec` sidecar. The receipt is the audit-trail anchor for the
/// parent service-acceptance — emberd (not ember-exec)
/// is the receipt signer; ember-exec only reports the child's exit code,
/// and emberd composes + signs the v2 envelope from the inputs the daemon
/// already trusts (the directive's `binary_path` + the blake3 hash the
/// daemon verified BEFORE sending the directive, etc.).
///
/// # Cryptographic discipline
///
/// Receipt signing goes through `sign_receipt_v2` (per ADR 118 + the
/// canonical-builder rule in `.claude/rules/daemon.md`). No inline
/// blake3, no inline JCS — `sign_receipt_v2` carries both. This function
/// composes the envelope + body and dispatches to the canonical signer.
///
/// # Field provenance
///
/// - `persona_id` / `grant_id` — the persona under which `broker.resolve`
///   issued the spawn handle, and the standing parent grant that
///   authorised the exec.
/// - `binary_path` — absolute container path of the executed binary.
/// - `binary_blake3` — the blake3 hex hash the daemon verified BEFORE
///   sending the SpawnDirective. **NOT** recomputed here — emberd trusts
///   the verify step that already ran, and recording the
///   already-verified hash preserves "the bytes the daemon actually
///   approved" in the audit chain.
/// - `target_uid` — the unprivileged uid the in-container sidecar
///   dropped to before `execve`.
/// - `exit_code` — the child's exit status from `ExecFrame::Exit { code }`.
/// - `materialized_at` — wall-clock at which emberd composed this
///   receipt (i.e. when the Exit frame arrived), NOT the in-container
///   child's own clock — ember-exec is not a trust root for time.
///
/// # Returns
///
/// The signed [`ReceiptEnvelope`] on success. Callers persist via the
/// daemon's existing event-log path (matching the `broker_materialization`
/// pattern in `broker/handler.rs`).
///
/// # Errors
///
/// Propagates [`SignError`] from `sign_receipt_v2` — canonicalization
/// failure, serialization failure (impossible for the kind+body shape
/// here, kept for the trait shape).
///
/// # Security notes
///
/// Credential bytes never appear in the receipt body — the directive's
/// `credential_env` is the sensitive carrier and is excluded from
/// `ExecCompletionBody` by construction. The seven fields recorded are
/// metadata only; tampering with any of them invalidates the signature.
#[allow(clippy::too_many_arguments)]
pub fn emit_exec_completion_receipt<S: Signer>(
    persona_id: Uuid,
    grant_id: Uuid,
    binary_path: PathBuf,
    binary_blake3: String,
    target_uid: u32,
    exit_code: i32,
    materialized_at: DateTime<Utc>,
    signer: &S,
) -> Result<ReceiptEnvelope, SignError> {
    let body = ExecCompletionBody {
        persona_id: persona_id.to_string(),
        grant_id: grant_id.to_string(),
        binary_path: binary_path.display().to_string(),
        binary_blake3,
        target_uid,
        exit_code,
        materialized_at: materialized_at.to_rfc3339(),
    };
    let body_value = serde_json::to_value(&body)?;
    let daemon_root_id = signer.public_key().0;
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_EXEC_COMPLETION.to_string(),
        receipt_id: String::new(),
        daemon_root_id,
        traceparent: None,
        // emberd (daemon persona) is
        // the receipt signer per the parent service-acceptance,
        // matching the `broker.revocation` envelope's
        // DaemonPersona posture in
        // `crate::infra::receipt::build_broker_revocation_envelope`.
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: body_value,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut envelope, signer)?;
    Ok(envelope)
}

/// Build + dual-sign a Receipt v2
/// envelope of kind `spawn.witness` for a parent→child grant edge.
///
/// Called from the spawn path (`crate::trust::grant::delegate_grant_full_sql`)
/// at the moment a child grant is minted from a parent grant. The witness
/// binds a spawned persona to its parent's authorization via two independent
/// signatures (CRIT-7 mitigation per ADR 118 / core-receipts):
///
/// 1. The parent persona signs `JCS(spawn.witness body \ parent_signature)`.
///    Without this signature, an `emberd` impersonator could fabricate a
///    fresh `spawned_persona_id` and present it as legitimate; the parent
///    signature requires the parent to have authorized the spawn.
/// 2. The daemon signs the outer envelope (`receipt_id` + payload), matching
///    the `broker.materialization` and `exec.completion` envelope posture.
///
/// # Field provenance
///
/// - `spawned_persona_id` — the child persona id created by `emberd` for the
///   spawn (matches the child grant's `persona_id`).
/// - `parent_persona_id` — the parent's persona id (matches the parent grant's
///   `persona_id`).
/// - `container_id` — opaque label identifying the container slot the spawn
///   is bound to. Pass an empty string when no container slot is associated
///   (classical pre-SCION delegation paths).
/// - `spawn_grant_id` — the parent grant authorizing the spawn (the grant
///   the child is delegated from).
///
/// # Returns
///
/// The signed [`ReceiptEnvelope`] on success — the envelope's body carries
/// the populated `parent_signature` field. Callers persist via
/// `DaemonStore::store_spawn_witness_receipt`.
///
/// # Errors
///
/// Propagates [`SignError`] from `sign_spawn_witness_parent_signature` (parent
/// signing) and `sign_receipt_v2` (envelope signing).
pub fn emit_spawn_witness_receipt<P: Signer, D: Signer>(
    spawned_persona_id: &str,
    parent_persona_id: &str,
    container_id: &str,
    spawn_grant_id: &str,
    ca_fingerprint: [u8; 32],
    parent_signer: &P,
    daemon_signer: &D,
) -> Result<ReceiptEnvelope, SignError> {
    // 1. Build the unsigned body and have the parent persona sign it.
    //    The
    //    `ca_fingerprint` binds the spawn to the daemon's SE-sealed Bridge CA
    //    (Slice B's `runtime.bridge_ca.lock().unwrap().as_ref().map(|ca|
    //    ca.fingerprint())`). Callers without a fingerprint to bind (legacy
    //    test paths, pre-startup) pass `[0u8; 32]` which Slice D treats as
    //    "not asserted" (bridge_ca_fingerprint_in_spawn_receipt).
    let witness = SpawnWitness::new(
        spawned_persona_id,
        parent_persona_id,
        container_id,
        spawn_grant_id,
    )
    .with_ca_fingerprint(ca_fingerprint);
    let mut body_value = witness.body_for_parent_signature();
    sign_spawn_witness_parent_signature(&mut body_value, parent_signer)?;

    // 2. Wrap the now-parent-signed body in a v2 envelope. The
    //    `parent_signature` field is now embedded inside `body_value`; the
    //    daemon's envelope signature covers the full body (including
    //    parent_signature) plus the receipt_id and envelope metadata.
    let daemon_root_id = daemon_signer.public_key().0;
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_SPAWN_WITNESS.to_string(),
        receipt_id: String::new(),
        daemon_root_id,
        traceparent: None,
        // The daemon issues spawn.witness — matches broker.materialization
        // and exec.completion posture for daemon-emitted v2 receipts.
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: body_value,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut envelope, daemon_signer)?;
    Ok(envelope)
}

/// Mint a per-agent X.509 CA for the
/// ember-proxy TLS interceptor.
///
/// Each SCION worker runs its own ember-proxy instance (ADR 140 §7). The
/// proxy performs TLS interception: it terminates agent HTTPS, injects the
/// workspace API key, and forwards upstream. This CA's cert is installed in
/// the container trust store (via the `update-ca-certificates` entrypoint
/// hook); its private key is written to a host-side tmpfs at mode 0o600
/// and bind-mounted into the ember-proxy service uid only.
///
/// The `nameConstraints` extension (RFC 5280 §4.2.1.10) scopes the CA to
/// exactly the permitted DNS names. A compromised proxy cannot issue a
/// valid cert for any host outside that set — blast radius is bounded by
/// X.509 math, not operator discipline.
///
/// # Parameters
///
/// - `agent_id` — embedded in the CA Subject CN for audit correlation.
/// - `permitted_dns_names` — the exhaustive set of DNS names this CA may
///   sign for. Defaults to Anthropic API + GitHub if the caller supplies
///   `None`.
/// - `validity_hours` — CA cert validity window (1–168 hours). Defaults to
///   24 if `None`.
///
/// # Returns
///
/// `(ca_cert_pem, ca_key_pem)` — both are `Zeroizing<String>` so key
/// material is wiped on drop. The caller is responsible for:
///
/// 1. Writing `ca_key_pem` to the host-side tmpfs path at mode 0o600.
/// 2. Writing `ca_cert_pem` to the container trust store path.
/// 3. Adding `ca_key_pem`'s mount path to the container mount table
///    (read-only for ember-proxy uid, invisible to agent uid).
///
/// # Errors
///
/// Propagates [`core_crypto::X509Error`] from the mint helper.
///
/// # TODO
///
/// Wire the returned PEM pair into the container mount table and trust store
/// installation path once the SCION spawn path graduates from UDS-socket
/// staging to full container launch (follow-up task).
pub fn mint_per_agent_proxy_ca(
    agent_id: &str,
    permitted_dns_names: Option<&[&str]>,
    validity_hours: Option<u32>,
) -> Result<(zeroize::Zeroizing<String>, zeroize::Zeroizing<String>), core_crypto::X509Error> {
    const DEFAULT_PERMITTED: &[&str] = &["api.anthropic.com", "*.anthropic.com", "github.com"];
    let names = permitted_dns_names.unwrap_or(DEFAULT_PERMITTED);
    let hours = validity_hours.unwrap_or(24);
    core_crypto::mint_per_agent_ca_with_name_constraints(agent_id, names, hours)
}

/// Mint a per-agent mTLS client cert for the
/// ember-proxy SCION listener.
///
/// The proxy at `https://localhost:8443` inside the worker container requires
/// mTLS client authentication. emberd mints this cert at spawn time using a
/// daemon-held client-auth signer CA (kept in mlock'd memory, never on disk).
/// The cert is written to host tmpfs at mode 0o600, owned by emberd uid, and
/// bind-mounted read-only into the container at a path readable only by the
/// agent uid (mode 0o600).
///
/// # Parameters
///
/// - `agent_id` — embedded in the cert Subject CN and SAN URI for post-
///   handshake identity extraction by `ember_proxy::mtls::extract_agent_id_from_cert`.
/// - `signer_key` — the client-auth CA signing key (mlock'd in emberd; caller
///   holds the `KeyPair`).
/// - `signer_cert` — the client-auth CA certificate.
/// - `validity_hours` — client cert validity window (1–168 hours). Defaults to
///   24 if `None`.
///
/// # Returns
///
/// `(client_cert_pem, client_key_pem)` — both `Zeroizing<String>` so key
/// material is wiped on drop. The caller is responsible for:
///
/// 1. Writing `client_key_pem` to the host-side tmpfs path at mode 0o600.
/// 2. Bind-mounting that path into the container read-only at a path
///    readable only by the agent uid (mode 0o600).
///
/// # Errors
///
/// Propagates [`core_crypto::X509Error`] from the mint helper.
///
/// # TODO
///
/// Wire the returned PEM pair into the container mount table once the SCION
/// spawn path graduates from UDS-socket staging to full container launch
/// (follow-up task, same pattern as `mint_per_agent_proxy_ca`).
pub fn mint_per_agent_mtls_client_cert(
    agent_id: &str,
    container_id: Option<&str>,
    signer_key: &rcgen::KeyPair,
    signer_cert: &rcgen::Certificate,
    validity_hours: Option<u32>,
) -> Result<(zeroize::Zeroizing<String>, zeroize::Zeroizing<String>), core_crypto::X509Error> {
    let hours = validity_hours.unwrap_or(24);
    core_crypto::mint_per_agent_client_cert(agent_id, container_id, signer_key, signer_cert, hours)
}

/// The three-tuple captured at
/// spawn-completion that binds an `agent_socket_enrollments` row to a
/// kernel-observable namespace identity.
///
/// Each field is the canonical Linux identifier for the corresponding
/// namespace, stored as `i64` to match the SQLite column types in
/// `agent_socket_enrollments` (cgroup_v2_id / userns_inode / mnt_ns_inode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceInodes {
    /// Inode of the cgroup-v2 cgroup the container PID is a member of.
    /// Resolved from `/proc/<pid>/cgroup` line `0::/<path>` then
    /// `stat`-ed under the cgroup-v2 root (`/sys/fs/cgroup` in
    /// production).
    pub cgroup_v2_id: i64,
    /// Inode of the user namespace the container PID is in. Resolved
    /// from `stat("/proc/<pid>/ns/user").st_ino`.
    pub userns_inode: i64,
    /// Inode of the mount namespace the container PID is in. Resolved
    /// from `stat("/proc/<pid>/ns/mnt").st_ino`.
    pub mnt_ns_inode: i64,
}

/// Production capture path. Reads under `/proc` and `/sys/fs/cgroup`.
///
/// Wrapper around [`capture_container_ns_inodes_at`] that pins the
/// proc and cgroup roots to the canonical Linux paths. Tests use the
/// `_at` variant with a fixture root.
///
/// # Errors
///
/// [`SpawnError::NamespaceInodeCaptureFailed`] on any read or stat
/// failure. The spawn path treats this as refuse-spawn — the binding
/// tuple is load-bearing on the identity invariant for the per-agent
/// UDS, and a missing tuple lets a future kernel-side namespace swap
/// go undetected. On non-Linux platforms this returns the same error
/// with a platform-not-supported reason — namespace inodes are a Linux
/// kernel primitive and have no equivalent in `/proc` on macOS / BSDs.
pub fn capture_container_ns_inodes(pid: u32) -> Result<NamespaceInodes, SpawnError> {
    capture_container_ns_inodes_at(pid, Path::new("/proc"), Path::new("/sys/fs/cgroup"))
}

/// Fixture-injectable capture path. `proc_root` and `cgroup_root`
/// stand in for `/proc` and `/sys/fs/cgroup` respectively so T2
/// integration tests can exercise the read paths against a tempdir
/// without root privileges or a real container.
///
/// Reads in order:
///
/// 1. `<proc_root>/<pid>/cgroup` → parsed for the cgroup-v2 line
///    (`0::/<path>`); `cgroup_root.join(path)` is stat-ed for the
///    cgroup inode.
/// 2. `<proc_root>/<pid>/ns/user` → `stat().st_ino`.
/// 3. `<proc_root>/<pid>/ns/mnt` → `stat().st_ino`.
///
/// All three reads MUST succeed; any failure short-circuits with
/// [`SpawnError::NamespaceInodeCaptureFailed`] and the partial state
/// is discarded.
///
/// Linux-only: `std::os::linux::fs::MetadataExt::st_ino` is the
/// canonical accessor for the inode field of `struct stat`, and
/// `/proc/<pid>/ns/{user,mnt}` are Linux-kernel-only paths. On
/// non-Linux platforms a stub returns
/// `SpawnError::NamespaceInodeCaptureFailed` so callers fail-closed
/// the same way they would on a Linux box without the relevant
/// `/proc` entries.
#[cfg(target_os = "linux")]
pub fn capture_container_ns_inodes_at(
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<NamespaceInodes, SpawnError> {
    use std::os::unix::fs::MetadataExt;

    let pid_dir = proc_root.join(pid.to_string());

    let cgroup_content = std::fs::read_to_string(pid_dir.join("cgroup")).map_err(|e| {
        SpawnError::NamespaceInodeCaptureFailed {
            reason: format!("read {}/cgroup: {}", pid_dir.display(), e),
        }
    })?;
    let cgroup_rel = cgroup_content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| SpawnError::NamespaceInodeCaptureFailed {
            reason: format!("no cgroup-v2 line (0::) in {}/cgroup", pid_dir.display()),
        })?;
    let cgroup_path = cgroup_root.join(cgroup_rel.trim_start_matches('/'));
    let cgroup_meta =
        std::fs::metadata(&cgroup_path).map_err(|e| SpawnError::NamespaceInodeCaptureFailed {
            reason: format!("stat {}: {}", cgroup_path.display(), e),
        })?;
    let cgroup_v2_id = cgroup_meta.ino() as i64;

    let userns_meta = std::fs::metadata(pid_dir.join("ns/user")).map_err(|e| {
        SpawnError::NamespaceInodeCaptureFailed {
            reason: format!("stat {}/ns/user: {}", pid_dir.display(), e),
        }
    })?;
    let userns_inode = userns_meta.ino() as i64;

    let mntns_meta = std::fs::metadata(pid_dir.join("ns/mnt")).map_err(|e| {
        SpawnError::NamespaceInodeCaptureFailed {
            reason: format!("stat {}/ns/mnt: {}", pid_dir.display(), e),
        }
    })?;
    let mnt_ns_inode = mntns_meta.ino() as i64;

    Ok(NamespaceInodes {
        cgroup_v2_id,
        userns_inode,
        mnt_ns_inode,
    })
}

/// Non-Linux stub. Namespace inodes are a Linux kernel primitive; the
/// `/proc/<pid>/ns/{user,mnt}` symlinks and `/sys/fs/cgroup` v2 layout
/// do not exist on macOS / BSDs. Returning the same
/// [`SpawnError::NamespaceInodeCaptureFailed`] shape as the Linux path
/// lets callers fail-closed uniformly — the spawn path refuses-spawn,
/// which is the correct behavior for an attempted container spawn on
/// a host without Linux namespace primitives.
#[cfg(not(target_os = "linux"))]
pub fn capture_container_ns_inodes_at(
    _pid: u32,
    _proc_root: &Path,
    _cgroup_root: &Path,
) -> Result<NamespaceInodes, SpawnError> {
    Err(SpawnError::NamespaceInodeCaptureFailed {
        reason: "namespace inode capture requires Linux (no /proc/<pid>/ns on this platform)"
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingRuntime {
        specs: Arc<Mutex<Vec<SpawnSpec>>>,
    }

    #[async_trait::async_trait]
    impl ContainerRuntime for RecordingRuntime {
        async fn spawn(&self, spec: SpawnSpec) -> Result<SpawnedContainer, RuntimeSpawnError> {
            self.specs.lock().expect("record spawn spec").push(spec);
            Ok(SpawnedContainer {
                container_id: "container-test-001".to_string(),
                name: Some("scion-runtime-test".to_string()),
            })
        }

        async fn drain(
            &self,
            _container_id: &str,
            _grace: std::time::Duration,
        ) -> Result<(), RuntimeSpawnError> {
            Ok(())
        }

        async fn state_report(
            &self,
            _container_id: &str,
        ) -> Result<RuntimeState, RuntimeSpawnError> {
            Ok(RuntimeState::Running)
        }
    }

    #[test]
    fn scion_runtime_coerces_to_dyn_container_runtime() {
        fn assert_dyn_runtime(_r: &dyn ContainerRuntime) {}

        let runtime = ScionRuntime::new(RecordingRuntime::default());
        assert_dyn_runtime(&runtime);
    }

    #[tokio::test]
    async fn scion_runtime_spawn_with_mount_table_extends_spec_and_skips_mlock_entry() {
        let recorder = RecordingRuntime::default();
        let runtime =
            ScionRuntime::from_boxed(Box::new(recorder.clone()) as Box<dyn ContainerRuntime>);
        let path = Path::new("/run/emberd/agent-abc.sock");
        let mounts = scion_mount_table_with_persona_key(path, "persona-12345");
        let seed_mount = UdsBindMount {
            host_path: PathBuf::from("/already/present.sock"),
            container_path: PathBuf::from("/run/emberd/already-present.sock"),
            read_only: false,
        };

        let spawned = runtime
            .spawn_with_mount_table(
                SpawnSpec {
                    image: "ubuntu:24.04".to_string(),
                    uds_mounts: vec![seed_mount.clone()],
                    ..Default::default()
                },
                &mounts,
            )
            .await
            .expect("spawn_with_mount_table succeeds");

        assert_eq!(spawned.container_id, "container-test-001");

        let recorded = recorder.specs.lock().expect("inspect recorded spec");
        let captured = recorded
            .last()
            .expect("spawn_with_mount_table records one spec");
        assert_eq!(
            captured.uds_mounts.len(),
            3,
            "seed mount + [parent dir, socket inode] expected",
        );
        assert_eq!(captured.uds_mounts[0], seed_mount);
        assert!(
            captured
                .uds_mounts
                .iter()
                .any(|m| m.container_path == PathBuf::from("/run/emberd") && m.read_only),
            "parent dir mount must remain read-only",
        );
        assert!(
            captured.uds_mounts.iter().any(|m| m.container_path
                == PathBuf::from("/run/emberd/agent-abc.sock")
                && !m.read_only),
            "socket inode mount must remain read-write",
        );
        assert!(
            captured
                .uds_mounts
                .iter()
                .all(|m| !m.container_path.to_string_lossy().contains("/mlocked/")),
            "informational mlocked entry must not become a filesystem bind mount",
        );
    }

    #[tokio::test]
    async fn scion_mount_table_spawn_accepts_dyn_container_runtime() {
        let recorder = RecordingRuntime::default();
        let runtime: Box<dyn ContainerRuntime> = Box::new(recorder.clone());
        let path = Path::new("/run/emberd/agent-dyn.sock");
        let mounts = scion_mount_table_for_socket(path);

        spawn_with_scion_mount_table(
            runtime.as_ref(),
            SpawnSpec {
                image: "ubuntu:24.04".to_string(),
                ..Default::default()
            },
            &mounts,
        )
        .await
        .expect("generic dyn runtime spawn succeeds");

        let recorded = recorder.specs.lock().expect("inspect recorded spec");
        let captured = recorded.last().expect("dyn path records one spec");
        assert_eq!(captured.uds_mounts.len(), 2);
        assert!(
            captured.uds_mounts.iter().any(|m| m.container_path
                == PathBuf::from("/run/emberd/agent-dyn.sock")
                && !m.read_only),
            "dyn caller path must preserve the SCION socket bind",
        );
    }

    #[test]
    fn mount_table_parent_dir_is_read_only() {
        // CRIT-C invariant: the parent dir mount is ALWAYS read-only.
        // If this entry flips to RW the agent uid can unlink the
        // socket and plant a symlink to a different victim inode.
        let path = Path::new("/run/emberd/agent-abc.sock");
        let mounts = scion_mount_table_for_socket(path);
        let parent = mounts
            .iter()
            .find(|m| m.target == Path::new("/run/emberd"))
            .expect("parent dir mount must be present");
        assert_eq!(parent.kind, MountKind::ReadOnlyDir);
    }

    #[test]
    fn mount_table_socket_inode_is_read_write() {
        // The socket itself must be RW so the agent can connect()/
        // send/recv. The RO parent dir is what stops unlink/replace.
        let path = Path::new("/run/emberd/agent-abc.sock");
        let mounts = scion_mount_table_for_socket(path);
        let socket = mounts
            .iter()
            .find(|m| m.target == Path::new("/run/emberd/agent-abc.sock"))
            .expect("socket inode mount must be present");
        assert_eq!(socket.kind, MountKind::ReadWriteSocket);
    }

    #[test]
    fn mount_table_targets_use_canonical_per_agent_dir() {
        // The agent's view of the socket path must match the
        // production parent dir regardless of where emberd staged the
        // socket on the host — otherwise the agent's connect target
        // becomes host-dependent.
        let path = Path::new("/var/tmp/emberd-test/agent-xyz.sock");
        let mounts = scion_mount_table_for_socket(path);
        assert_eq!(
            mounts[0].target,
            PathBuf::from(crate::infra::socket::PER_AGENT_SOCKET_PARENT),
        );
        assert_eq!(
            mounts[1].target,
            PathBuf::from(crate::infra::socket::PER_AGENT_SOCKET_PARENT).join("agent-xyz.sock"),
        );
    }

    #[test]
    fn verify_scion_binary_hash_refuses_mismatched_binary() {
        // CRIT-B regression gate: if the on-disk binary's SHA-256 does
        // not match the operator-pinned hash, `verify_scion_binary_hash`
        // must return `BinaryHashMismatch`. The spawn path treats this
        // as refuse-spawn — silently allowing the mismatched binary
        // re-opens the TOCTOU vector this pin was added to close.
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"wrong").unwrap();
        // A SHA-256 hash that is NOT the hash of "wrong". 64 hex chars
        // of zero is guaranteed to mismatch any real content.
        let expected = "0000000000000000000000000000000000000000000000000000000000000000";
        let err =
            verify_scion_binary_hash(f.path(), expected).expect_err("mismatched hash must refuse");
        match err {
            SpawnError::BinaryHashMismatch {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected);
                assert_ne!(a, expected, "actual hash must differ from expected");
            }
            other => panic!("expected BinaryHashMismatch, got {:?}", other),
        }
    }

    #[test]
    fn verify_scion_binary_hash_accepts_matched_binary() {
        // The positive path: when the operator-pinned hash matches the
        // bytes on disk, `verify_scion_binary_hash` returns `Ok(())`
        // and the caller proceeds to fork-exec.
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"wrong").unwrap();
        // Compute the real SHA-256 of "wrong" and use it as `expected`.
        let mut hasher = Sha256::new();
        hasher.update(b"wrong");
        let expected = hex::encode(hasher.finalize());
        verify_scion_binary_hash(f.path(), &expected).expect("matching hash must accept");
    }

    #[test]
    fn verify_scion_binary_hash_accepts_uppercase_expected() {
        // Operators paste hashes from heterogeneous sources — some
        // tools emit uppercase hex. Normalise on the `expected` side
        // so a case mismatch is not a denial-of-service against valid
        // operator-pinned configs.
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"wrong").unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"wrong");
        let expected = hex::encode(hasher.finalize()).to_ascii_uppercase();
        verify_scion_binary_hash(f.path(), &expected).expect("uppercase expected hash must accept");
    }

    #[test]
    fn verify_scion_binary_hash_missing_file_returns_io_error() {
        // Missing binary is refuse-spawn: an attacker who can delete
        // the binary out from under the daemon must not get a silent
        // pass. The variant is `BinaryIo` so callers can distinguish
        // operator misconfiguration from active tamper.
        let err = verify_scion_binary_hash(
            Path::new("/no/such/scion/binary/for/test"),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("missing file must error");
        assert!(
            matches!(err, SpawnError::BinaryIo(_)),
            "expected BinaryIo, got {:?}",
            err
        );
    }

    #[test]
    fn mount_table_emits_exactly_two_entries() {
        // Two-entry universe by contract. Adding new mounts here would
        // widen the trust surface and should require security review,
        // not a silent test-update.
        let path = Path::new("/run/emberd/agent-abc.sock");
        let mounts = scion_mount_table_for_socket(path);
        assert_eq!(
            mounts.len(),
            2,
            "expected exactly [parent-dir RO, socket RW]; got {mounts:#?}",
        );
    }

    #[test]
    fn emit_spawn_witness_receipt_dual_signature_verifies() {
        // The emit function
        // must produce an envelope where BOTH signatures verify under
        // the supplied trust anchors:
        //
        //   1. body.parent_signature verifies under parent_signer's pubkey
        //      (the CRIT-7 dual-signature binding — the parent persona
        //      attests "I authorised this spawn").
        //   2. envelope.signature verifies under daemon_signer's pubkey
        //      (the issuing daemon attests "I composed this envelope").
        //
        // A regression that swaps the signers (e.g. signs the body with
        // the daemon by mistake) is caught by the parent-side verify
        // failing — exactly the regression the CRIT-7 mitigation exists
        // to detect.
        use core_crypto::{Ed25519Verifier, FixtureSigner};
        use core_events::receipt::sign::{
            verify_receipt_v2, verify_spawn_witness_parent_signature,
        };

        let parent_signer = FixtureSigner::new("META-AP-spawn-witness-parent-key");
        let daemon_signer = FixtureSigner::new("META-AP-spawn-witness-daemon-key");
        let parent_pk = parent_signer.public_key();
        let daemon_pk = daemon_signer.public_key();

        // Slice C: a non-zero fingerprint so a zero-fill regression would
        // fail the round-trip assertion below.
        let test_ca_fp: [u8; 32] = [0x7eu8; 32];
        let envelope = emit_spawn_witness_receipt(
            "persona-child-abc",
            "persona-parent-xyz",
            "container-test-001",
            "grant-spawn-parent-001",
            test_ca_fp,
            &parent_signer,
            &daemon_signer,
        )
        .expect("emit_spawn_witness_receipt succeeds");

        assert_eq!(envelope.kind, "spawn.witness");
        assert!(
            !envelope.receipt_id.is_empty(),
            "envelope receipt_id must be populated by sign_receipt_v2",
        );
        assert!(
            envelope.signature.is_some(),
            "envelope signature must be populated by sign_receipt_v2",
        );

        // 1. Daemon's envelope signature must verify under the daemon's
        //    trust anchor — proves the daemon issued this envelope.
        verify_receipt_v2(&envelope, &daemon_pk, &Ed25519Verifier)
            .expect("envelope signature must verify under daemon pubkey");

        // 2. Parent's body signature must verify under the parent's
        //    trust anchor — proves the parent authorised the spawn.
        verify_spawn_witness_parent_signature(&envelope.body, &parent_pk, &Ed25519Verifier)
            .expect("body parent_signature must verify under parent pubkey");

        // CRIT-7 regression guard: swapping the trust anchors must fail.
        // Verifying the parent_signature under the daemon pubkey, or the
        // envelope under the parent pubkey, would mean an emberd
        // impersonator could fabricate witnesses — exactly the attack the
        // dual-signature design closes off.
        assert!(
            verify_spawn_witness_parent_signature(&envelope.body, &daemon_pk, &Ed25519Verifier)
                .is_err(),
            "parent_signature must NOT verify under the daemon pubkey",
        );
        assert!(
            verify_receipt_v2(&envelope, &parent_pk, &Ed25519Verifier).is_err(),
            "envelope signature must NOT verify under the parent pubkey",
        );

        // Body shape: the four payload fields are populated as supplied
        // and `parent_signature` is the ed25519sig wire form.
        let body = envelope.body.as_object().expect("body is object");
        assert_eq!(body["spawned_persona_id"], "persona-child-abc");
        assert_eq!(body["parent_persona_id"], "persona-parent-xyz");
        assert_eq!(body["container_id"], "container-test-001");
        assert_eq!(body["spawn_grant_id"], "grant-spawn-parent-001");
        let sig = body["parent_signature"]
            .as_str()
            .expect("parent_signature is string");
        assert!(
            sig.starts_with("ed25519sig:"),
            "parent_signature must use canonical wire form, got {sig:?}",
        );

        // Slice C — bridge_ca_fingerprint_in_spawn_receipt. The fingerprint
        // supplied to `emit_spawn_witness_receipt` must appear verbatim on
        // the wire body (serde serializes `[u8; 32]` as a JSON array of 32
        // numbers — no base64/hex conversion).
        let fp_arr = body["ca_fingerprint"]
            .as_array()
            .expect("ca_fingerprint serializes as JSON array");
        assert_eq!(fp_arr.len(), 32);
        for (i, byte_val) in fp_arr.iter().enumerate() {
            let n = byte_val.as_u64().expect("byte serializes as integer");
            assert_eq!(n as u8, test_ca_fp[i], "ca_fingerprint byte {i}");
        }
    }

    #[test]
    fn mount_table_with_persona_key_appends_mlock_entry() {
        // The companion table extends
        // the bare socket-only table with a third MlockedPersonaKey
        // entry. The first two entries match the bare table byte-for-
        // byte so callers can swap variants without losing the
        // socket-mount trust-surface invariants.
        let path = Path::new("/run/emberd/agent-abc.sock");
        let bare = scion_mount_table_for_socket(path);
        let with_key = scion_mount_table_with_persona_key(path, "persona-12345");
        assert_eq!(
            with_key.len(),
            bare.len() + 1,
            "with_persona_key adds exactly one entry to the bare table",
        );
        assert_eq!(&with_key[..bare.len()], bare.as_slice());
        let key_entry = with_key
            .iter()
            .find(|m| m.kind == MountKind::MlockedPersonaKey)
            .expect("MlockedPersonaKey entry must be present");
        assert!(
            key_entry.target.to_string_lossy().contains("persona-12345"),
            "MlockedPersonaKey target must encode the persona id; got {:?}",
            key_entry.target,
        );
    }

    /// T2 fixture — happy path.
    ///
    /// Build a fake `/proc/<pid>/` tree and a fake cgroup root in a
    /// tempdir, run the capture helper against them, assert the three
    /// fields decode to the expected fixture inodes.
    #[test]
    #[cfg(target_os = "linux")]
    fn capture_container_ns_inodes_reads_three_fixture_inodes() {
        use std::os::linux::fs::MetadataExt;
        let proc_root = tempfile::tempdir().expect("proc tempdir");
        let cgroup_root = tempfile::tempdir().expect("cgroup tempdir");
        let pid: u32 = 4242;

        let pid_dir = proc_root.path().join(pid.to_string());
        std::fs::create_dir_all(pid_dir.join("ns")).expect("mkdir proc/<pid>/ns");
        std::fs::write(pid_dir.join("cgroup"), "0::/scion-fixture\n")
            .expect("write proc/<pid>/cgroup");
        std::fs::write(pid_dir.join("ns/user"), b"userns-fixture")
            .expect("write proc/<pid>/ns/user");
        std::fs::write(pid_dir.join("ns/mnt"), b"mntns-fixture").expect("write proc/<pid>/ns/mnt");

        let cgroup_dir = cgroup_root.path().join("scion-fixture");
        std::fs::create_dir(&cgroup_dir).expect("mkdir cgroup/scion-fixture");

        let expected_cgroup = std::fs::metadata(&cgroup_dir)
            .expect("stat cgroup-fixture")
            .st_ino() as i64;
        let expected_userns = std::fs::metadata(pid_dir.join("ns/user"))
            .expect("stat user")
            .st_ino() as i64;
        let expected_mntns = std::fs::metadata(pid_dir.join("ns/mnt"))
            .expect("stat mnt")
            .st_ino() as i64;

        let captured = capture_container_ns_inodes_at(pid, proc_root.path(), cgroup_root.path())
            .expect("capture must succeed against well-formed fixture");

        assert_eq!(captured.cgroup_v2_id, expected_cgroup);
        assert_eq!(captured.userns_inode, expected_userns);
        assert_eq!(captured.mnt_ns_inode, expected_mntns);
    }

    /// T2 fixture — failure path.
    ///
    /// Missing `/proc/<pid>/cgroup` must produce
    /// [`SpawnError::NamespaceInodeCaptureFailed`]. The spawn flow
    /// treats this as refuse-spawn — the binding tuple is load-bearing
    /// on the identity invariant.
    #[test]
    #[cfg(target_os = "linux")]
    fn capture_container_ns_inodes_refuses_missing_cgroup_file() {
        let proc_root = tempfile::tempdir().expect("proc tempdir");
        let cgroup_root = tempfile::tempdir().expect("cgroup tempdir");
        let pid: u32 = 4243;
        // No /proc/<pid>/cgroup file: capture must refuse.
        let err = capture_container_ns_inodes_at(pid, proc_root.path(), cgroup_root.path())
            .expect_err("missing cgroup file must refuse-spawn");
        assert!(
            matches!(err, SpawnError::NamespaceInodeCaptureFailed { .. }),
            "expected NamespaceInodeCaptureFailed, got: {err:?}"
        );
    }

    /// T2 fixture — malformed cgroup
    /// file (no `0::` line) refuses.
    #[test]
    #[cfg(target_os = "linux")]
    fn capture_container_ns_inodes_refuses_malformed_cgroup_v1_only() {
        let proc_root = tempfile::tempdir().expect("proc tempdir");
        let cgroup_root = tempfile::tempdir().expect("cgroup tempdir");
        let pid: u32 = 4244;
        let pid_dir = proc_root.path().join(pid.to_string());
        std::fs::create_dir_all(pid_dir.join("ns")).expect("mkdir proc/<pid>/ns");
        // Pure cgroup v1 (no 0:: line). Refuse.
        std::fs::write(
            pid_dir.join("cgroup"),
            "12:devices:/scion\n11:pids:/scion\n",
        )
        .expect("write proc/<pid>/cgroup");
        let err = capture_container_ns_inodes_at(pid, proc_root.path(), cgroup_root.path())
            .expect_err("v1-only cgroup file must refuse-spawn");
        assert!(
            matches!(err, SpawnError::NamespaceInodeCaptureFailed { .. }),
            "expected NamespaceInodeCaptureFailed, got: {err:?}"
        );
    }
}
