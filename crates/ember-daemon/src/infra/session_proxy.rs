//! CLASSIFICATION: PUBLIC
//!
//! Per-session peercred-gated LLM-gateway Unix sockets (P22-S2, ADR 197 §1/§2).
//!
//! # What this provides
//!
//! The pre-P22-S2 LLM credential-injection gateway listens on a single
//! loopback `127.0.0.1:3142` `TcpListener` (`infra::proxy::run_proxy`). TCP
//! loopback exposes **no kernel peer identity**, is port-squattable, and is
//! reachable by any process on the host — so the only thing standing between an
//! arbitrary operator-uid process and credential injection was a replayable
//! bearer token in the child env (CRIT-1).
//!
//! This module stands up the *capability* that replaces that: **one
//! Unix socket per session**, spawned when a session registers and torn down
//! when it closes (the SCION-PER-AGENT-UDS-SOCKET pattern — the socket path
//! *is* the attachment binding). Every accepted connection runs a **fail-closed
//! authorization gate** before a single byte is forwarded:
//!
//! 1. **Kernel-attested uid match** — the connecting peer's uid (macOS
//!    `LOCAL_PEERTOKEN` audit token / Linux `SO_PEERCRED`) must equal the uid
//!    bound to the session at register time.
//! 2. **Door-1 leaf-pin** — the connecting pid must equal the launcher-reported
//!    harness *leaf* pid (the exact `claude`/`codex` process the launcher
//!    spawned, reported over its authenticated daemon channel right after
//!    spawn), NOT merely a descendant of the launcher. This is the only host
//!    instance-binding with real teeth: it rejects a same-uid sibling or a
//!    compromised in-tree subagent that spins up its own harness pointed at the
//!    socket. Before the leaf is reported the gate fail-closes (nothing to pin).
//! 3. **Reuse-immunity** — the peer's `(pid, version)` is captured on the
//!    session's first admitted connection (`version` = macOS pidversion from
//!    the audit token / Linux `/proc/<pid>/stat` start-time, both
//!    cross-uid-readable and reuse-immune). A later connection whose pid was
//!    recycled by a different process carries a different `version` → rejected.
//! 4. **Binary attestation** — when a signed binary-pin manifest is enrolled,
//!    the peer binary's blake3 must match the pinned hash
//!    (`binary_pin::verify_peer_against_manifest`, which uses cross-uid-readable
//!    `proc_pidpath`). HARD-FAIL on mismatch. When **no** manifest is enrolled
//!    the connection is NOT silently honored: a loud audited
//!    `attestation-unenforced` event is emitted (and surfaced to the launcher
//!    via the session-open response so it can banner every launch) — but the
//!    kernel-attested arms above still hard-close, so the connection is gated,
//!    just not binary-pinned.
//!
//! Arms 1–3 are **always hard-closed** — a rejected connection is dropped
//! (`Ok(None)` from `ProxyAcceptor::accept_authorized`), never fail-open. This
//! is independent of the rollout-gated per-RPC fail-open arm at
//! `broker/handler.rs` (`ARCH-BROKER-FAIL-CLOSED-PER-RPC-ROLLOUT`), which this
//! module does not touch.
//!
//! ## Why not `proc_pidinfo` (the superseded PR-B/PR-C gate)
//!
//! The original gate used `proc_pidinfo(PROC_PIDTBSDINFO)` for the macOS
//! start-time liveness anchor and `process_is_same_or_descendant` for the
//! pid-tree walk. Both are `CHECK_SAME_USER`-gated on macOS: a **non-root**
//! daemon (`ember`/`_ember_dev` uid) reading an **operator-uid** peer gets
//! `EPERM`, so those arms silently degraded cross-uid (never exercised live
//! while the lane was still on transitional TCP). `LOCAL_PEERTOKEN` is a
//! socket-layer read that works cross-uid for a non-root daemon, and the
//! launcher-reported leaf-pin replaces the (also cross-uid-broken, and
//! over-broad) descendant walk. See the ADR 197 amendment.
//!
//! # Lifecycle (no live-behavior change in this seam)
//!
//! P22-S2 PR-B builds the capability but does **not** yet point any harness at
//! it — live `ember claude` sessions stay on the transitional `TcpListener`
//! path. The per-session sockets exist and the gate runs, exercised by the
//! integration tests here and (in PR-C/PR-D) by the Claude / Codex adapters.
//!
//! The sync session handlers (`handle_register_session` /
//! `handle_close_session`) reach the proxy's `!Send` `LocalSet` — which owns the
//! `DaemonStore`/vault — through a process-global command channel
//! ([`request_open`] / [`request_close`]). `request_open` binds the socket on
//! the register path before advertising it; the registry loop
//! ([`run_session_proxy_registry`]) adopts the listener and owns the
//! per-session shutdown handles. The daemon sweeps stale sockets at boot
//! ([`sweep_stale_session_sockets`]).

use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};

use proxy_forward_runtime::forward::{
    AuthorizedConnection, ProxyAcceptor, run_forward_accept_loop,
};

use crate::infra::binary_pin;
use crate::infra::endpoint_gate::{
    AdmissionAdmit, AdmissionPolicy, AdmissionReject, PeerIdentity, evaluate_admission,
};
use crate::infra::proxy::{DaemonPolicyBackend, ProxyState};

/// Short subdirectory under the daemon socket dir that holds per-session
/// LLM-gateway sockets. macOS caps Unix socket paths at 104 bytes; the installed
/// daemon run dir already consumes most of that budget, so this name must stay
/// compact. Kept separate from the daemon's own `daemon.sock` and per-agent RPC
/// sockets so the boot sweep can safely remove every entry.
pub const SESSION_PROXY_SUBDIR: &str = "p";

/// Command sent from the sync session handlers to the proxy registry loop.
///
/// Carries only plain data — never the `!Send` `DaemonStore`/vault — so it can
/// cross the channel from the daemon's main socket `LocalSet` to the proxy's
/// `LocalSet`.
#[derive(Debug)]
pub enum SessionProxyCommand {
    /// Stand up a per-session Unix socket + gated accept loop.
    Open(PreparedSessionProxyOpen),
    /// Report the launcher-spawned harness leaf pid for `session_id` (P22-S2
    /// Door-1 leaf-pin). The accept gate admits a connection only when the
    /// connecting pid equals this reported leaf (see [`evaluate_primary_gate`]).
    /// Sent by the launcher over its authenticated daemon socket *after* it has
    /// spawned the harness child, before that child makes its first API call.
    ///
    /// `nonce` is the unguessable `leaf_report_nonce` the daemon minted at
    /// `register_session` and returned **only** to the launcher (over its own
    /// RPC response — not in the child env, not in the socket path). The
    /// registry sets the leaf only when `nonce` matches the session's stored
    /// nonce. This binds the report to the launcher: a same-uid attacker who
    /// learns the (predictable / env-leaked) session_id still cannot forge a
    /// SetLeaf to pin the gate to its own pid (adversarial FINDING-1, P22-S2
    /// PR-C rework).
    SetLeaf {
        session_id: String,
        leaf_pid: u32,
        nonce: String,
    },
    /// Tear down the session's socket + accept loop (idempotent).
    Close { session_id: String },
}

/// Everything the registry needs to bind + gate a per-session socket. All
/// fields are `Send` plain data resolved at `register_session` time.
#[derive(Debug, Clone)]
pub struct SessionProxyOpenSpec {
    pub session_id: String,
    /// Kernel-attested uid bound to the session (captured from the
    /// `register_session` caller's `SO_PEERCRED`). The accept gate requires the
    /// connecting peer's uid to equal this.
    pub bound_uid: u32,
    /// The launcher pid recorded in `SessionMeta`. Diagnostics only since the
    /// Door-1 rework — instance-binding is now the launcher-*reported* leaf pid
    /// ([`SessionProxyCommand::SetLeaf`]), not a descendant-of-launcher walk
    /// (which EPERM'd cross-uid for a non-root daemon and admitted any
    /// descendant). Retained for logging + the orphan-session watcher.
    pub launcher_pid: u32,
    /// Binary-pin manifest caller key for this session's harness
    /// (`claude-code`, `codex-network-proxy`, …), or `None` when the harness
    /// type is not yet known. `None` disables the attestation arm (loud
    /// `attestation-unenforced` event); the kernel-attested arms still gate.
    pub attestation_caller: Option<String>,
    /// Unguessable token the daemon minted at `register_session` and returned
    /// **only** to the launcher. A [`SessionProxyCommand::SetLeaf`] sets the
    /// Door-1 leaf-pin only when its `nonce` matches this — binding the leaf
    /// report to the launcher so a same-uid attacker who knows the session_id
    /// cannot pin the gate to its own pid (adversarial FINDING-1).
    pub leaf_report_nonce: String,
}

/// A per-session UDS already bound by the register path.
#[derive(Debug)]
pub struct PreparedSessionProxyOpen {
    pub spec: SessionProxyOpenSpec,
    listener: StdUnixListener,
    socket_path: PathBuf,
}

/// Process-global sender into the proxy registry loop. Set once, when the
/// registry starts at daemon boot. The sync session handlers publish
/// `Open`/`Close` here.
static COMMAND_TX: OnceLock<mpsc::UnboundedSender<SessionProxyCommand>> = OnceLock::new();

/// Process-global per-session socket directory, set when the registry starts.
/// Lets the sync `register_session` handler compute a session's socket path for
/// the launch response without threading the daemon socket dir through every
/// `RequestContext`.
static SOCKET_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Base-URL host the launcher hands the harness for the per-session UDS lane.
///
/// P22-S2 (ADR 197 §2, locked): a **non-Anthropic checkpoint** host. The harness
/// routes API traffic over `ANTHROPIC_UNIX_SOCKET` (undici `socketPath`
/// short-circuits the connect), so the host is never actually resolved on the
/// happy path. If a socket-bypass is ever attempted, the connection targets
/// this checkpoint (which does not resolve / is not a real upstream) and **fails
/// closed** — it never leaks a plaintext API key to the real
/// `api.anthropic.com`. The proxy→upstream hop is always real WebPKI TLS.
pub const SENTINEL_BASE_URL: &str = "http://ember-proxy.local/";

/// Compute the per-session socket path for `session_id` if the registry is up
/// (proxy enabled). Used by `register_session` to populate the launch
/// response's `anthropic_unix_socket`. Returns `None` when the proxy/registry
/// was not started, so the launcher transparently falls back to the
/// transitional TCP proxy URL.
pub fn session_socket_path_for(session_id: &str) -> Option<PathBuf> {
    SOCKET_DIR
        .get()
        .map(|dir| session_socket_path(dir, session_id))
}

/// Install the global command sender. Idempotent-safe: returns `false` if a
/// sender was already installed (a second daemon incarnation inside one process
/// — only happens in tests).
pub fn install_command_sender(tx: mpsc::UnboundedSender<SessionProxyCommand>) -> bool {
    COMMAND_TX.set(tx).is_ok()
}

/// Request a per-session socket be stood up.
///
/// Returns `Ok(None)` when the registry is not installed (proxy disabled in
/// this process), `Ok(Some(path))` after the socket has been bound and handed to
/// the registry, and `Err` when a configured registry could not accept a live
/// socket. The bind happens on the register path so callers never advertise a
/// UDS path that was never bound.
pub fn request_open(spec: SessionProxyOpenSpec) -> io::Result<Option<PathBuf>> {
    let Some(socket_dir) = SOCKET_DIR.get() else {
        tracing::warn!("session_proxy: socket dir not installed (proxy disabled?) — open skipped");
        return Ok(None);
    };
    let prepared = prepare_session_socket(socket_dir, spec)?;
    let socket_path = prepared.socket_path.clone();
    if send_command(SessionProxyCommand::Open(prepared)) {
        Ok(Some(socket_path))
    } else {
        if let Err(e) = std::fs::remove_file(&socket_path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %socket_path.display(), error = %e, "session_proxy: unlink after command send failure failed");
        }
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "session_proxy registry receiver unavailable",
        ))
    }
}

/// Report the launcher-spawned harness leaf pid for a session (Door-1
/// leaf-pin), authenticated by the launcher-only `nonce`. Best-effort (see
/// [`request_open`]). Until a valid report lands, the session's accept gate
/// fail-closes every connection (no leaf to pin against).
pub fn request_set_leaf(session_id: &str, leaf_pid: u32, nonce: &str) -> bool {
    send_command(SessionProxyCommand::SetLeaf {
        session_id: session_id.to_string(),
        leaf_pid,
        nonce: nonce.to_string(),
    })
}

/// Request a per-session socket be torn down. Best-effort (see [`request_open`]).
pub fn request_close(session_id: &str) -> bool {
    send_command(SessionProxyCommand::Close {
        session_id: session_id.to_string(),
    })
}

/// Process-global sticky flag: set the first time *any* successful binary-pin
/// manifest load is observed (an accept-time attestation, or the presence-gated
/// register-time probe). Once a manifest is known to be enrolled, a later
/// accept that CANNOT read the manifest — vault grace-locked, load error,
/// daemon identity not yet initialised — must **fail closed** rather than
/// silently downgrade to "attestation unenforced".
///
/// Adversarial FINDING-1 (P22-S2 PR-B): the registry's `ProxyState` shares the
/// daemon's live-vault slot, which `grace_lock_if_due` clears on idle — the
/// routine steady state. Without this latch, an attacker who swaps the pinned
/// harness binary (same uid, in launcher tree) connects during a locked-vault
/// window, the manifest is unreadable, and the gate downgrades to loud-but-open
/// — bypassing the pin entirely. The latch turns "manifest enrolled but
/// unreadable" into a hard close, which costs nothing legitimate: a locked
/// vault cannot materialize a credential to inject anyway.
static MANIFEST_ENROLLED_SEEN: AtomicBool = AtomicBool::new(false);

fn note_manifest_enrolled() {
    MANIFEST_ENROLLED_SEEN.store(true, Ordering::Relaxed);
}

fn manifest_known_enrolled() -> bool {
    MANIFEST_ENROLLED_SEEN.load(Ordering::Relaxed)
}

/// Seed [`MANIFEST_ENROLLED_SEEN`] from a context where the vault is known to
/// be unlocked — the presence-gated `register_session` path. Best-effort: a
/// read failure just leaves the latch for an accept-time load to set. This
/// closes the cold-boot window where the very first accept on a freshly-booted
/// daemon races a locked vault before any successful manifest load.
pub fn probe_and_note_manifest(store: &crate::infra::store::DaemonStore) {
    let Some(identity) = crate::infra::receipt::current_identity() else {
        return;
    };
    let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());
    let Ok(vault) = crate::infra::interactive_unlock::current_live_vault(store) else {
        return;
    };
    if let Ok(Some(_)) = binary_pin::load_manifest(&vault, store, &pubkey_str) {
        note_manifest_enrolled();
        tracing::debug!("session_proxy: register-time probe latched manifest-enrolled");
    }
}

fn send_command(cmd: SessionProxyCommand) -> bool {
    match COMMAND_TX.get() {
        Some(tx) => match tx.send(cmd) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "session_proxy: registry receiver gone — command dropped");
                false
            }
        },
        None => {
            tracing::debug!(
                "session_proxy: command channel not installed (proxy disabled?) — command dropped"
            );
            false
        }
    }
}

/// Directory that holds per-session sockets, under the daemon socket dir.
pub fn session_proxy_dir(socket_dir: &Path) -> PathBuf {
    socket_dir.join(SESSION_PROXY_SUBDIR)
}

/// Per-session socket path. Session ids are daemon-minted `sess_<hex>` tokens
/// (no path separators), so the join is safe; we additionally sanitize to a
/// conservative charset as defense-in-depth against a future id scheme.
pub fn session_socket_path(socket_dir: &Path, session_id: &str) -> PathBuf {
    let safe: String = session_id
        .strip_prefix("sess_")
        .unwrap_or(session_id)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    session_proxy_dir(socket_dir).join(format!("s-{safe}.sock"))
}

/// Create the per-session socket directory, group-traversable by
/// `ember-clients` so an operator-uid harness can reach its socket cross-uid.
///
/// Mirrors the `daemon.sock` model (`0750 ember:ember-clients`): a **non-root**
/// daemon cannot chown the per-session socket to the operator, so the operator
/// reaches it via the `ember-clients` group (of which it is a member), and the
/// accept gate (uid-match + Door-1 leaf-pin) — strictly stronger than the FS
/// perm — is the real authorization. The `0700`-owner-only mode PR-B used was
/// unreachable cross-uid (the lane was never exercised live). chgrp is
/// best-effort: in dev (no `ember-clients` group, daemon == operator uid) the
/// owner bits already grant access.
fn ensure_session_proxy_dir(socket_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = session_proxy_dir(socket_dir);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0750: ember (owner) + ember-clients (group) traverse/list; world none.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;
        if let Err(e) = crate::infra::runtime::chown_ember_clients(&dir) {
            tracing::debug!(dir = %dir.display(), error = %e, "session_proxy: chgrp ember-clients on dir failed (dev/no-group) — owner bits apply");
        }
    }
    Ok(dir)
}

/// Remove every stale per-session socket left behind by a previous daemon
/// incarnation. Run once at daemon boot, before the registry accepts commands:
/// the sockets are dead (their owning sessions died with the old daemon), and a
/// leftover inode would make `UnixListener::bind` fail with `EADDRINUSE`.
///
/// Returns the number of inodes removed. Best-effort — individual removal
/// failures are logged and skipped, never fatal.
pub fn sweep_stale_session_sockets(socket_dir: &Path) -> usize {
    let dir = session_proxy_dir(socket_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "session_proxy: boot sweep read_dir failed");
            return 0;
        }
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_sock = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| e == "sock")
            .unwrap_or(false);
        if !is_sock {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
                tracing::info!(path = %path.display(), "session_proxy: swept stale session socket");
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "session_proxy: failed to sweep stale socket");
            }
        }
    }
    removed
}

// ---------------------------------------------------------------------------
// Fail-closed gate
// ---------------------------------------------------------------------------

/// Kernel-attested identity of the peer on a per-session UDS, read *without*
/// any cross-uid `proc_pidinfo` call (which a non-root daemon cannot make
/// against an operator-uid peer — `CHECK_SAME_USER` returns `EPERM`; see ADR
/// 197 amendment + memory `adr-197-p22-transport-resilient-proxy`).
///
/// - **macOS:** `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` returns the peer's
///   `audit_token_t`, from which we read `(euid, pid, pidversion)`. This is a
///   socket-layer read (not `proc_security_policy`-gated), so it works
///   cross-uid for a non-root daemon. `pidversion` is **reuse-immune**: the
///   kernel bumps `p_idversion` when a pid is recycled, so a recycled pid
///   carries a different version.
/// - **Linux:** `SO_PEERCRED` gives `(uid, pid)`; the reuse-immunity anchor is
///   the process **start time** from `/proc/<pid>/stat` field 22, which is
///   world-readable cross-uid on Linux and never mutates for a live process.
///
/// `version` is `None` only when the reuse-immunity anchor could not be read;
/// the gate then falls back to a pid-only binding (degraded — a recycled pid is
/// no longer distinguishable — but uid-match + leaf-pin still hold).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPeerIdentity {
    pub uid: u32,
    pub pid: i32,
    pub version: Option<u64>,
}

/// Read the peer identity of an accepted per-session UDS connection.
///
/// The caller MUST first await the peer's first bytes (the socket is
/// `readable`) so that on macOS `LOCAL_PEERTOKEN` resolves the audit token
/// against the connecting peer (it resolves at `getsockopt` time against the
/// socket's last-active pid). [`SessionUdsAcceptor::accept_authorized`] does
/// this with [`PEER_FIRST_BYTE_TIMEOUT`].
#[cfg(target_os = "macos")]
fn read_proxy_peer_identity(stream: &UnixStream) -> std::io::Result<ProxyPeerIdentity> {
    use std::os::unix::io::AsRawFd;
    // SOL_LOCAL / LOCAL_PEERTOKEN are not exposed by `libc` on macOS; the
    // numeric values are stable kernel ABI (`sys/un.h` / `sys/socket.h`).
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    // `audit_token_t` is `struct { unsigned int val[8]; }`. The canonical
    // accessors (`bsm/audit_token.h`) map: val[1]=euid, val[5]=pid,
    // val[7]=pidversion. We read it directly to avoid linking `libbsm`.
    let mut token = [0u32; 8];
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `token`; we pass the
    // exact size of the `[u32; 8]` we allocated and a valid mutable pointer.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of_val(&token) {
        return Err(std::io::Error::other(
            "LOCAL_PEERTOKEN returned an unexpected audit-token size",
        ));
    }
    Ok(ProxyPeerIdentity {
        uid: token[1],
        pid: token[5] as i32,
        version: Some(token[7] as u64),
    })
}

/// Linux peer identity: `SO_PEERCRED` `(uid, pid)` + `/proc/<pid>/stat`
/// start-time as the reuse-immunity anchor (cross-uid-readable on Linux).
#[cfg(target_os = "linux")]
fn read_proxy_peer_identity(stream: &UnixStream) -> std::io::Result<ProxyPeerIdentity> {
    let cred = stream.peer_cred()?;
    let pid = cred.pid().ok_or_else(|| {
        std::io::Error::other("peer pid unavailable — fail-closed (no kernel-attested principal)")
    })?;
    let version = proc_starttime_ticks(pid);
    Ok(ProxyPeerIdentity {
        uid: cred.uid(),
        pid,
        version,
    })
}

/// Linux process start time (clock ticks since boot) from `/proc/<pid>/stat`
/// field 22. Parsed after the final `)` of the (possibly paren-containing)
/// comm field so a process named `a) b 0 0 ...` cannot spoof the column.
#[cfg(target_os = "linux")]
fn proc_starttime_ticks(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    // After comm: " S ppid pgrp session tty_nr tpgid flags minflt cminflt
    // majflt cmajflt utime stime cutime cstime priority nice num_threads
    // itrealvalue starttime ...". starttime is field 22 overall = index 20
    // here (0-based, counting the leading state char as index 0).
    after_comm.split_whitespace().nth(20)?.parse::<u64>().ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_proxy_peer_identity(_stream: &UnixStream) -> std::io::Result<ProxyPeerIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "per-session UDS peer identity is only supported on macOS and Linux",
    ))
}

/// Constant-time equality for the launcher-only leaf-report nonce. An empty
/// expected nonce never matches (defensive — every UDS-lane session is minted
/// with a non-empty nonce). Length is fixed (uuid simple, 32 hex chars), so the
/// length short-circuit leaks nothing useful.
fn leaf_report_nonce_matches(expected: &str, presented: &str) -> bool {
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    if a.is_empty() || a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Why a connection was rejected by the primary (kernel-attested) gate arms.
/// Returned by [`evaluate_primary_gate`] so the reason is both logged and
/// unit-testable without a real socket or a second uid on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateReject {
    /// Connecting peer's uid did not match the session-bound uid.
    UidMismatch { expected: u32, actual: u32 },
    /// Non-positive / invalid peer pid.
    InvalidPid { pid: i32 },
    /// The launcher has not yet reported the harness leaf pid for this session,
    /// so there is nothing to pin against — fail closed (the launcher reports
    /// it right after spawn; an early connection is dropped and the client
    /// retries).
    LeafUnreported { pid: i32 },
    /// The connecting pid is not the launcher-reported harness leaf (Door-1
    /// leaf-pin — the only host instance-binding with real teeth; a descendant
    /// of the launcher is NOT admitted, unlike the superseded pid-tree arm).
    LeafPidMismatch { pid: i32, expected_leaf: u32 },
    /// The connecting pid matches the bound leaf but its reuse-immunity anchor
    /// (macOS pidversion / Linux start-time) differs from the value captured on
    /// the session's first connection — the pid was recycled by a different
    /// process. The macOS analogue of the Linux pidfd reaped-process signal.
    Recycled {
        pid: i32,
        bound_version: u64,
        actual_version: u64,
    },
}

/// What [`evaluate_primary_gate`] decided for an admitted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAdmit {
    /// First connection from the bound leaf — the caller captures
    /// `peer.version` as the session's reuse-immunity anchor for the rest of
    /// the session.
    CapturePidVersion(Option<u64>),
    /// A subsequent connection whose `(pid, version)` matched the captured
    /// binding.
    BoundMatch,
}

/// Pure decision for the kernel-attested gate arms — uid match + Door-1
/// leaf-pin + reuse-immunity. No syscalls: every input is read by the caller
/// (`peer` from [`read_proxy_peer_identity`], `expected_leaf` from the
/// launcher-reported leaf pid, `bound_version` from the first-connection
/// capture) so this is directly unit-testable without a real socket or a
/// second uid on the host.
///
/// - `bound_uid` — uid captured at `register_session`.
/// - `expected_leaf` — launcher-reported harness leaf pid (`0` = not reported
///   yet → fail closed).
/// - `bound_version` — reuse-immunity anchor captured on the session's first
///   admitted connection, or `None` if this is the first connection.
///
/// # ADR 215 slice 3 — `endpoint_gate_framework`
///
/// Since the slice-3 gate-framework drop, this function is a thin wrapper
/// over [`crate::infra::endpoint_gate::evaluate_admission`] with the
/// [`AdmissionPolicy::LeafExact`] policy — the LLM lane rides the framework
/// like every other ADR-215 §3 lane will, instead of carrying its own
/// duplicate arms. The legacy `ProxyPeerIdentity` / `GateReject` / `GateAdmit`
/// types are preserved for callers (and for the existing test surface), and
/// only the inner uid/leaf/reuse-immunity logic is delegated.
pub fn evaluate_primary_gate(
    bound_uid: u32,
    peer: ProxyPeerIdentity,
    expected_leaf: u32,
    bound_version: Option<u64>,
) -> Result<GateAdmit, GateReject> {
    let policy = AdmissionPolicy::LeafExact {
        bound_uid,
        expected_leaf,
        bound_version,
    };
    let framework_peer = PeerIdentity::host(peer.uid, peer.pid, peer.version);
    match evaluate_admission(&policy, framework_peer) {
        Ok(AdmissionAdmit::CapturePidVersion(v)) => Ok(GateAdmit::CapturePidVersion(v)),
        Ok(AdmissionAdmit::BoundMatch) => Ok(GateAdmit::BoundMatch),
        Err(AdmissionReject::UidMismatch { expected, actual }) => {
            Err(GateReject::UidMismatch { expected, actual })
        }
        Err(AdmissionReject::InvalidPid { pid }) => Err(GateReject::InvalidPid { pid }),
        Err(AdmissionReject::LeafUnreported { pid }) => Err(GateReject::LeafUnreported { pid }),
        Err(AdmissionReject::LeafPidMismatch { pid, expected_leaf }) => {
            Err(GateReject::LeafPidMismatch { pid, expected_leaf })
        }
        Err(AdmissionReject::Recycled {
            pid,
            bound_version,
            actual_version,
        }) => Err(GateReject::Recycled {
            pid,
            bound_version,
            actual_version,
        }),
        // The other framework reject variants don't apply to the LeafExact
        // policy — but pattern-completeness keeps the compiler honest if the
        // framework grows new variants. Each maps to a defensive fail-closed
        // shape that surfaces as a LeafUnreported in the legacy enum (the
        // closest "fail because we couldn't decide" variant). This branch
        // should be statically unreachable today.
        Err(AdmissionReject::NotInLeafSubtree { .. })
        | Err(AdmissionReject::CertSanExpectedMalformed { .. })
        | Err(AdmissionReject::CertSanExtractFailed { .. })
        | Err(AdmissionReject::CertSanPersonaMismatch { .. })
        | Err(AdmissionReject::CertSanContainerMismatch { .. }) => {
            Err(GateReject::LeafUnreported { pid: peer.pid })
        }
    }
}

/// `ProxyAcceptor` over a per-session `0700` `UnixListener`. Runs the full
/// fail-closed gate inside `accept_authorized`; an authorized connection is
/// handed to the generic forwarding loop, a rejected one is dropped.
pub struct SessionUdsAcceptor {
    listener: UnixListener,
    spec: SessionProxyOpenSpec,
    /// Shared proxy state — used at accept time to resolve the live vault (for
    /// the binary-pin manifest) and to route the loud `attestation-unenforced`
    /// audit event. The same `ProxyState` backs the forwarding `PolicyBackend`.
    state: Arc<ProxyState>,
    /// Launcher-reported harness leaf pid (Door-1 leaf-pin). `0` until the
    /// launcher reports it via [`SessionProxyCommand::SetLeaf`]. Shared with the
    /// registry (`SessionEntry::expected_leaf_pid`) on the proxy `LocalSet`, so
    /// `Rc<Cell<_>>` rather than an atomic — never crosses a thread boundary.
    expected_leaf_pid: Rc<Cell<u32>>,
    /// Reuse-immunity anchor captured from the session's first admitted
    /// connection (macOS pidversion / Linux start-time). Every subsequent
    /// connection must match it. Acceptor-private interior mutability — the
    /// accept loop owns this acceptor on the single-threaded `LocalSet`.
    bound_version: Cell<Option<u64>>,
}

impl SessionUdsAcceptor {
    pub fn new(
        listener: UnixListener,
        spec: SessionProxyOpenSpec,
        state: Arc<ProxyState>,
        expected_leaf_pid: Rc<Cell<u32>>,
    ) -> Self {
        Self {
            listener,
            spec,
            state,
            expected_leaf_pid,
            bound_version: Cell::new(None),
        }
    }

    /// Run the binary-attestation arm. Returns `true` to ADMIT, `false` to
    /// REJECT. A `None` manifest (or `None` caller) admits but emits the loud
    /// `attestation-unenforced` audit event; a present manifest HARD-FAILS on
    /// hash mismatch / missing pin.
    fn attest_peer_binary(&self, pid: i32) -> bool {
        let Some(caller) = self.spec.attestation_caller.as_deref() else {
            self.emit_attestation_unenforced("no-harness-caller");
            return true;
        };

        let identity = match crate::infra::receipt::current_identity() {
            Some(id) => id,
            None => {
                // Daemon identity not initialised — cannot verify the manifest
                // signature. Indeterminate: fail closed iff a manifest is known
                // to be enrolled (see `attestation_indeterminate`).
                return self.attestation_indeterminate(pid, "daemon-identity-uninitialised");
            }
        };
        let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());

        let vault = match crate::infra::interactive_unlock::current_live_vault(&self.state.store) {
            Ok(v) => v,
            Err(_) => {
                // Vault grace-locked / unavailable — cannot read the manifest.
                // Indeterminate: fail closed iff a manifest is known enrolled.
                return self.attestation_indeterminate(pid, "vault-unavailable");
            }
        };

        match binary_pin::load_manifest(&vault, &self.state.store, &pubkey_str) {
            Ok(Some(manifest)) => {
                // Latch: a manifest IS enrolled. From now on an unreadable
                // manifest fails closed rather than downgrading to unenforced.
                note_manifest_enrolled();
                match binary_pin::verify_peer_against_manifest(Some(pid), caller, &manifest) {
                    Ok(()) => true,
                    Err(e) => {
                        // HARD-FAIL: a manifest IS enrolled and the peer binary
                        // does not match (or no pin for this caller). Reject.
                        tracing::warn!(
                            session_id = %self.spec.session_id,
                            caller,
                            pid,
                            error = %e,
                            "session_proxy gate: binary attestation FAILED — rejecting connection"
                        );
                        let _ = self.state.sink_log_event(
                            None,
                            "attestation-rejected",
                            None,
                            "denied",
                            Some(&format!(
                                "session={} caller={} pid={} err={}",
                                self.spec.session_id, caller, pid, e
                            )),
                        );
                        false
                    }
                }
            }
            Ok(None) => {
                // Vault was READABLE and reports no manifest — authoritative
                // "not pinned" posture. Loud-but-open is correct here (the
                // operator never opted into pinning); this is NOT the
                // indeterminate case.
                self.emit_attestation_unenforced("no-manifest-enrolled");
                true
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %self.spec.session_id,
                    error = %e,
                    "session_proxy gate: manifest load failed"
                );
                // Indeterminate: a corrupt/unreadable manifest entry is
                // attacker-adjacent — fail closed iff a manifest is known
                // enrolled.
                self.attestation_indeterminate(pid, "manifest-load-error")
            }
        }
    }

    /// Resolve an attestation arm where the manifest could not be read or
    /// verified (vault locked, load error, identity not ready). Returns `true`
    /// (ADMIT, loud-unenforced) only when NO manifest is known to be enrolled;
    /// returns `false` (REJECT, fail-closed) when one IS — so a routine
    /// locked-vault window can never silently disable an enrolled pin
    /// (adversarial FINDING-1). `pid` is logged for incident correlation.
    fn attestation_indeterminate(&self, pid: i32, reason: &str) -> bool {
        if manifest_known_enrolled() {
            tracing::warn!(
                session_id = %self.spec.session_id,
                pid,
                reason,
                "session_proxy gate: binary-pin manifest is ENROLLED but currently unreadable — FAILING CLOSED (no silent downgrade to unenforced)"
            );
            let _ = self.state.sink_log_event(
                None,
                "attestation-enforced-fail-closed",
                None,
                "denied",
                Some(&format!(
                    "session={} pid={} reason={}",
                    self.spec.session_id, pid, reason
                )),
            );
            false
        } else {
            self.emit_attestation_unenforced(reason);
            true
        }
    }

    /// Emit the loud, audited `attestation-unenforced` event. The session-open
    /// response separately reports manifest presence so the launcher can banner
    /// every launch (PR-C).
    fn emit_attestation_unenforced(&self, reason: &str) {
        tracing::warn!(
            session_id = %self.spec.session_id,
            reason,
            "session_proxy gate: BINARY ATTESTATION UNENFORCED — connection admitted on kernel-attested arms only (peercred uid + liveness + launcher pid-tree). Enrol a signed binary-pin manifest to pin the harness binary."
        );
        let _ = self.state.sink_log_event(
            None,
            "attestation-unenforced",
            None,
            "warn",
            Some(&format!(
                "session={} reason={}",
                self.spec.session_id, reason
            )),
        );
    }
}

#[async_trait::async_trait(?Send)]
impl ProxyAcceptor for SessionUdsAcceptor {
    type Conn = UnixStream;

    async fn accept_authorized(&self) -> std::io::Result<Option<AuthorizedConnection<Self::Conn>>> {
        let (stream, _addr) = self.listener.accept().await?;

        // Kernel-attested peer identity via LOCAL_PEERTOKEN (macOS) /
        // SO_PEERCRED + start-time (Linux) — read IMMEDIATELY after accept, with
        // no wait for peer bytes. The macOS audit token is bound to the
        // connection's peer at connect time (empirically: a peer that has sent
        // nothing still yields its correct pid+pidversion), so there is no
        // last-pid timing dependency and nothing to wait for — which also means
        // a connector that opens the socket and never sends cannot stall the
        // accept loop. No cross-uid proc_pidinfo call. A failure here means we
        // could not attest the peer — fail closed.
        let peer = match read_proxy_peer_identity(&stream) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    session_id = %self.spec.session_id,
                    error = %e,
                    "session_proxy gate: peer-identity read failed — rejecting connection"
                );
                return Ok(None);
            }
        };

        // Primary arms — uid match + Door-1 leaf-pin + reuse-immunity. ALWAYS
        // hard-closed.
        let expected_leaf = self.expected_leaf_pid.get();
        let bound_version = self.bound_version.get();
        match evaluate_primary_gate(self.spec.bound_uid, peer, expected_leaf, bound_version) {
            Ok(GateAdmit::CapturePidVersion(version)) => {
                // First admitted connection: pin the reuse-immunity anchor for
                // the rest of the session.
                self.bound_version.set(version);
                if version.is_none() {
                    tracing::warn!(
                        session_id = %self.spec.session_id,
                        peer_pid = peer.pid,
                        "session_proxy gate: no reuse-immunity anchor for leaf — proceeding on uid + leaf-pin only (degraded)"
                    );
                }
            }
            Ok(GateAdmit::BoundMatch) => {}
            Err(reject) => {
                tracing::warn!(
                    session_id = %self.spec.session_id,
                    bound_uid = self.spec.bound_uid,
                    peer_uid = peer.uid,
                    peer_pid = peer.pid,
                    expected_leaf,
                    ?reject,
                    "session_proxy gate: PRIMARY arm rejected connection (fail-closed)"
                );
                return Ok(None);
            }
        }

        // Binary attestation arm (hard-fail on mismatch; loud-but-proceed when
        // no manifest is enrolled). proc_pidpath is cross-uid-readable, so this
        // arm works for a non-root daemon (unlike the superseded proc_pidinfo
        // arms).
        if !self.attest_peer_binary(peer.pid) {
            return Ok(None);
        }

        tracing::debug!(
            session_id = %self.spec.session_id,
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            "session_proxy gate: connection AUTHORIZED"
        );
        // The socket path IS the attachment binding — carry the session id into
        // forwarding so `handle_request` resolves the credential identity from
        // the session (no caller-supplied bearer).
        Ok(Some(AuthorizedConnection {
            conn: stream,
            session_binding: Some(self.spec.session_id.clone()),
        }))
    }
}

// ---------------------------------------------------------------------------
// Registry loop + lifecycle
// ---------------------------------------------------------------------------

struct SessionEntry {
    socket_path: PathBuf,
    /// Per-session shutdown — flipping to `true` breaks the accept loop.
    shutdown_tx: watch::Sender<bool>,
    /// Door-1 leaf-pin cell shared with the session's `SessionUdsAcceptor`. The
    /// registry writes the launcher-reported leaf pid here on
    /// [`SessionProxyCommand::SetLeaf`]; the accept gate reads it. Both run on
    /// the proxy `LocalSet`, so `Rc<Cell<_>>` is safe (never crosses a thread).
    expected_leaf_pid: Rc<Cell<u32>>,
    /// Launcher-only nonce a `SetLeaf` must present to pin the leaf (FINDING-1).
    leaf_report_nonce: String,
}

impl SessionEntry {
    fn tear_down(self) {
        let _ = self.shutdown_tx.send(true);
        // Best-effort unlink — the accept loop is breaking out; remove the
        // inode so the path is reusable and the boot sweep stays small.
        if let Err(e) = std::fs::remove_file(&self.socket_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.socket_path.display(), error = %e, "session_proxy: unlink on close failed");
        }
    }
}

/// Bind a per-session socket (unlink-before-bind) on the register path.
fn prepare_session_socket(
    socket_dir: &Path,
    spec: SessionProxyOpenSpec,
) -> io::Result<PreparedSessionProxyOpen> {
    ensure_session_proxy_dir(socket_dir)?;
    let socket_path = session_socket_path(socket_dir, &spec.session_id);

    // Unlink-before-bind: a stale inode (boot sweep missed it, or a rapid
    // re-register) would make bind fail with EADDRINUSE.
    if let Err(e) = std::fs::remove_file(&socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(path = %socket_path.display(), error = %e, "session_proxy: unlink-before-bind failed");
    }

    let listener = StdUnixListener::bind(&socket_path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", socket_path.display())))?;
    listener.set_nonblocking(true)?;
    // 0660 ember:ember-clients — mirrors `daemon.sock`. A non-root daemon cannot
    // chown the socket to the operator, so the operator (an ember-clients
    // member) reaches it via the group; the accept gate (uid-match + Door-1
    // leaf-pin) is the real authorization. chgrp best-effort: in dev (daemon ==
    // operator uid, no group) the owner bits already grant access. (PR-B's
    // 0700-owner-only was unreachable by an operator-uid client cross-uid.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;
        if let Err(e) = crate::infra::runtime::chown_ember_clients(&socket_path) {
            tracing::debug!(path = %socket_path.display(), error = %e, "session_proxy: chgrp ember-clients on socket failed (dev/no-group) — owner bits apply");
        }
    }

    Ok(PreparedSessionProxyOpen {
        spec,
        listener,
        socket_path,
    })
}

/// Convert a synchronously-bound per-session socket and spawn its gated accept
/// loop. Returns the `SessionEntry` to track, or an error if the listener could
/// not be adopted by tokio.
fn open_session_socket(
    prepared: PreparedSessionProxyOpen,
    state: Arc<ProxyState>,
    backend: Arc<DaemonPolicyBackend>,
) -> io::Result<SessionEntry> {
    let PreparedSessionProxyOpen {
        spec,
        listener,
        socket_path,
    } = prepared;
    let listener = UnixListener::from_std(listener)?;
    let session_id = spec.session_id.clone();
    let bound_uid = spec.bound_uid;
    let launcher_pid = spec.launcher_pid;
    let leaf_report_nonce = spec.leaf_report_nonce.clone();

    // Door-1 leaf-pin cell, shared between the registry (writes the
    // launcher-reported leaf pid) and the acceptor (reads it). `0` = not yet
    // reported → the gate fail-closes until the launcher reports.
    let expected_leaf_pid = Rc::new(Cell::new(0u32));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let acceptor = SessionUdsAcceptor::new(listener, spec, state, Rc::clone(&expected_leaf_pid));

    let loop_session_id = session_id.clone();
    tokio::task::spawn_local(async move {
        run_forward_accept_loop(acceptor, backend, shutdown_rx).await;
        tracing::debug!(session_id = %loop_session_id, "session_proxy: accept loop exited");
    });

    tracing::info!(
        session_id = %session_id,
        path = %socket_path.display(),
        bound_uid,
        launcher_pid,
        "session_proxy: per-session gated socket up (leaf-pin pending launcher report)"
    );

    Ok(SessionEntry {
        socket_path,
        shutdown_tx,
        expected_leaf_pid,
        leaf_report_nonce,
    })
}

/// The registry control loop. Owns the `!Send` `ProxyState`/backend and the
/// live per-session listeners; processes `Open`/`Close` commands until the
/// global daemon shutdown fires. Runs on the proxy's `LocalSet` via
/// `spawn_local`.
pub async fn run_session_proxy_registry(
    socket_dir: PathBuf,
    state: Arc<ProxyState>,
    backend: Arc<DaemonPolicyBackend>,
    mut commands: mpsc::UnboundedReceiver<SessionProxyCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Publish the socket dir so `register_session` can compute per-session
    // socket paths for the launch response. Idempotent (set-once).
    let _ = SOCKET_DIR.set(socket_dir.clone());

    // Eagerly create the per-session socket dir at boot — before any
    // path is handed to a launcher — so the owner-only directory exists ahead
    // of first open (defense-in-depth against a socket-path squat in the
    // register→bind window; adversarial PR-C hardening).
    if let Err(e) = ensure_session_proxy_dir(&socket_dir) {
        tracing::warn!(error = %e, "session_proxy: failed to pre-create 0700 session dir at boot");
    }

    // Boot sweep: clear stale sockets from any previous incarnation before we
    // start binding.
    let swept = sweep_stale_session_sockets(&socket_dir);
    if swept > 0 {
        tracing::info!(
            count = swept,
            "session_proxy: boot sweep removed stale sockets"
        );
    }

    let mut sessions: HashMap<String, SessionEntry> = HashMap::new();

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(SessionProxyCommand::Open(prepared)) => {
                        let session_id = prepared.spec.session_id.clone();
                        // Re-register: tear the old one down first (idempotent).
                        if let Some(prev) = sessions.remove(&session_id) {
                            prev.tear_down();
                        }
                        match open_session_socket(prepared, state.clone(), backend.clone()) {
                            Ok(entry) => {
                                sessions.insert(session_id, entry);
                            }
                            Err(e) => {
                                tracing::warn!(session_id = %session_id, error = %e, "session_proxy: failed to open per-session socket");
                            }
                        }
                    }
                    Some(SessionProxyCommand::SetLeaf { session_id, leaf_pid, nonce }) => {
                        match sessions.get(&session_id) {
                            Some(entry) => {
                                // Bind the report to the launcher: a SetLeaf
                                // must present the unguessable nonce the daemon
                                // returned only to the launcher at register time
                                // (FINDING-1). Constant-time compare. A
                                // mismatch — a same-uid attacker who knows the
                                // session_id but not the nonce — is refused.
                                if !leaf_report_nonce_matches(&entry.leaf_report_nonce, &nonce) {
                                    tracing::warn!(
                                        session_id = %session_id,
                                        leaf_pid,
                                        "session_proxy: SetLeaf nonce mismatch — REFUSED (possible leaf-pin hijack attempt)"
                                    );
                                    continue;
                                }
                                let current = entry.expected_leaf_pid.get();
                                // First-write-wins: never let a later report
                                // overwrite an already-pinned leaf with a
                                // different pid (anti-hijack — see
                                // `handle_report_session_leaf`). Re-reporting the
                                // same pid is idempotent.
                                if current == 0 || current == leaf_pid {
                                    entry.expected_leaf_pid.set(leaf_pid);
                                    tracing::info!(
                                        session_id = %session_id,
                                        leaf_pid,
                                        "session_proxy: Door-1 leaf-pin set from launcher report"
                                    );
                                } else {
                                    tracing::warn!(
                                        session_id = %session_id,
                                        current_leaf = current,
                                        rejected_leaf = leaf_pid,
                                        "session_proxy: SetLeaf would overwrite an already-pinned leaf — IGNORED (first-write-wins)"
                                    );
                                }
                            }
                            None => {
                                tracing::warn!(
                                    session_id = %session_id,
                                    leaf_pid,
                                    "session_proxy: SetLeaf for unknown session — ignored"
                                );
                            }
                        }
                    }
                    Some(SessionProxyCommand::Close { session_id }) => {
                        if let Some(entry) = sessions.remove(&session_id) {
                            entry.tear_down();
                            tracing::info!(session_id = %session_id, "session_proxy: per-session socket torn down");
                        }
                    }
                    None => {
                        tracing::debug!("session_proxy: command channel closed — registry exiting");
                        break;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    // Daemon shutting down — tear down every live session socket.
    for (_id, entry) in sessions.drain() {
        entry.tear_down();
    }
    tracing::debug!("session_proxy: registry loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, pid: i32, version: Option<u64>) -> ProxyPeerIdentity {
        ProxyPeerIdentity { uid, pid, version }
    }

    #[test]
    fn leaf_report_nonce_match_semantics() {
        // FINDING-1: the leaf report is authenticated by the launcher-only
        // nonce. Exact match admits; any mismatch / empty expected refuses.
        assert!(leaf_report_nonce_matches("lrn_abc123", "lrn_abc123"));
        assert!(!leaf_report_nonce_matches("lrn_abc123", "lrn_abc124"));
        assert!(!leaf_report_nonce_matches("lrn_abc123", "lrn_abc12")); // length
        assert!(!leaf_report_nonce_matches("lrn_abc123", "")); // attacker has no nonce
        assert!(!leaf_report_nonce_matches("", "")); // empty expected never matches
        assert!(!leaf_report_nonce_matches("", "anything"));
    }

    #[test]
    fn primary_gate_rejects_uid_mismatch() {
        let r = evaluate_primary_gate(1000, peer(1001, 4242, Some(7)), 4242, None);
        assert_eq!(
            r,
            Err(GateReject::UidMismatch {
                expected: 1000,
                actual: 1001
            })
        );
    }

    #[test]
    fn primary_gate_rejects_nonpositive_pid() {
        let r = evaluate_primary_gate(1000, peer(1000, 0, Some(7)), 0, None);
        assert_eq!(r, Err(GateReject::InvalidPid { pid: 0 }));
    }

    #[test]
    fn primary_gate_fails_closed_when_leaf_unreported() {
        // uid matches but the launcher has not reported the harness leaf yet
        // (expected_leaf == 0) → nothing to pin against → fail closed.
        let r = evaluate_primary_gate(1000, peer(1000, 4242, Some(7)), 0, None);
        assert_eq!(r, Err(GateReject::LeafUnreported { pid: 4242 }));
    }

    #[test]
    fn primary_gate_rejects_non_leaf_pid() {
        // uid matches, leaf reported as 4242, but the connecting pid is 5555 —
        // a same-uid process that is NOT the launched leaf (e.g. a compromised
        // sibling/descendant). Door-1 leaf-pin rejects it.
        let r = evaluate_primary_gate(1000, peer(1000, 5555, Some(7)), 4242, None);
        assert_eq!(
            r,
            Err(GateReject::LeafPidMismatch {
                pid: 5555,
                expected_leaf: 4242
            })
        );
    }

    #[test]
    fn primary_gate_admits_leaf_first_connection_and_captures_version() {
        // First connection from the bound leaf → admit + capture the anchor.
        let r = evaluate_primary_gate(1000, peer(1000, 4242, Some(99)), 4242, None);
        assert_eq!(r, Ok(GateAdmit::CapturePidVersion(Some(99))));
    }

    #[test]
    fn primary_gate_admits_subsequent_matching_version() {
        let r = evaluate_primary_gate(1000, peer(1000, 4242, Some(99)), 4242, Some(99));
        assert_eq!(r, Ok(GateAdmit::BoundMatch));
    }

    #[test]
    fn primary_gate_rejects_recycled_pid() {
        // Same pid + uid as the bound leaf, but a different reuse-immunity
        // anchor → the pid was recycled by a different process → reject.
        let r = evaluate_primary_gate(1000, peer(1000, 4242, Some(100)), 4242, Some(99));
        assert_eq!(
            r,
            Err(GateReject::Recycled {
                pid: 4242,
                bound_version: 99,
                actual_version: 100
            })
        );
    }

    #[test]
    fn primary_gate_rejects_when_anchor_missing_but_bound() {
        // We bound an anchor on the first connection; a later connection with
        // no anchor cannot prove non-recycle → fail closed.
        let r = evaluate_primary_gate(1000, peer(1000, 4242, None), 4242, Some(99));
        assert_eq!(
            r,
            Err(GateReject::Recycled {
                pid: 4242,
                bound_version: 99,
                actual_version: 0
            })
        );
    }

    #[test]
    fn socket_path_sanitizes_and_is_under_subdir() {
        let dir = Path::new("/run/ember");
        let p = session_socket_path(dir, "sess_00ff");
        assert_eq!(p, Path::new("/run/ember/p/s-00ff.sock"));
        // Path-separator-bearing id is sanitized — cannot escape the subdir.
        let evil = session_socket_path(dir, "../../etc/x");
        assert_eq!(evil, Path::new("/run/ember/p/s-______etc_x.sock"));
    }

    #[test]
    fn socket_path_fits_macos_sun_len_under_installed_run_dir() {
        let installed_run_dir = Path::new("/Library/Application Support/Emberlink/run");
        let p = session_socket_path(installed_run_dir, "sess_0123456789abcdef0123456789abcdef");
        assert!(
            p.display().to_string().len() < 104,
            "{} should fit in macOS sun_path",
            p.display()
        );
    }

    #[test]
    fn sweep_removes_only_sock_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = session_proxy_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("agent-a.sock"), b"").unwrap();
        std::fs::write(dir.join("agent-b.sock"), b"").unwrap();
        std::fs::write(dir.join("keep.txt"), b"").unwrap();
        let removed = sweep_stale_session_sockets(tmp.path());
        assert_eq!(removed, 2);
        assert!(dir.join("keep.txt").exists());
        assert!(!dir.join("agent-a.sock").exists());
    }

    #[test]
    fn sweep_missing_dir_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(sweep_stale_session_sockets(tmp.path()), 0);
    }

    /// Adversarial FINDING-1 regression: the sticky manifest-enrolled latch is
    /// monotonic (write-once-true). Once latched, `manifest_known_enrolled()`
    /// stays true so the `attestation_indeterminate` arms fail closed instead
    /// of downgrading to unenforced during a locked-vault window. (Monotone +
    /// only consulted on the `Some`-caller path, so this cannot perturb the
    /// `None`-caller integration gate tests above.)
    #[test]
    fn sticky_manifest_latch_is_monotonic() {
        note_manifest_enrolled();
        assert!(manifest_known_enrolled());
        // Idempotent: a second note does not clear it.
        note_manifest_enrolled();
        assert!(manifest_known_enrolled());
    }

    // ----- integration: real UnixStream through the full gate -----

    fn own_uid() -> u32 {
        // SAFETY: getuid has no preconditions and never fails.
        unsafe { libc::getuid() }
    }

    fn test_state() -> Arc<ProxyState> {
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        #[allow(clippy::arc_with_non_send_sync)]
        let state = Arc::new(ProxyState::new(store, None));
        #[allow(clippy::arc_with_non_send_sync)]
        let sink = Arc::new(crate::infra::proxy::DaemonEventSink::new(
            state.clone(),
            None,
        ));
        let _ = state.event_sink.set(sink);
        state
    }

    fn spec_for(session_id: &str, launcher_pid: u32) -> SessionProxyOpenSpec {
        SessionProxyOpenSpec {
            session_id: session_id.to_string(),
            bound_uid: own_uid(),
            launcher_pid,
            attestation_caller: None,
            leaf_report_nonce: "test-nonce".to_string(),
        }
    }

    /// Build an acceptor with the Door-1 leaf-pin pre-set to `leaf_pid` (the
    /// production registry sets this on the launcher's `SetLeaf` report).
    fn acceptor_with_leaf(
        listener: UnixListener,
        spec: SessionProxyOpenSpec,
        leaf_pid: u32,
    ) -> SessionUdsAcceptor {
        SessionUdsAcceptor::new(listener, spec, test_state(), Rc::new(Cell::new(leaf_pid)))
    }

    /// Connect to `sock` WITHOUT sending any bytes. The gate reads
    /// `LOCAL_PEERTOKEN` immediately after accept (connection-bound, no wait for
    /// peer data), so a silent connection is still attested + admitted/rejected
    /// without stalling — this helper proves that.
    async fn connect_peer(sock: &Path) -> UnixStream {
        UnixStream::connect(sock).await.unwrap()
    }

    /// The leaf-pinned peer (here: the test process is its own leaf) is
    /// ADMITTED — even with no binary-pin manifest enrolled, because the
    /// attestation arm proceeds loud-but-open while the kernel-attested arms
    /// (uid + leaf-pin + reuse-immunity capture) all pass.
    #[tokio::test]
    async fn gate_admits_leaf_pinned_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("agent-admit.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = std::process::id();
        let acceptor = acceptor_with_leaf(listener, spec_for("sess_admit", me), me);

        let _client = connect_peer(&sock).await;
        let res = acceptor.accept_authorized().await.unwrap();
        assert!(res.is_some(), "leaf-pinned same-uid peer must be admitted");
    }

    /// Before the launcher reports the leaf pid (cell == 0) the gate
    /// FAIL-CLOSES every connection — there is nothing to pin against.
    #[tokio::test]
    async fn gate_rejects_before_leaf_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("agent-noleaf.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = std::process::id();
        // leaf_pid == 0 → unreported.
        let acceptor = acceptor_with_leaf(listener, spec_for("sess_noleaf", me), 0);

        let _client = connect_peer(&sock).await;
        let res = acceptor.accept_authorized().await.unwrap();
        assert!(
            res.is_none(),
            "connection before leaf-pin report must be rejected (fail-closed)"
        );
    }

    /// A same-uid peer whose pid is NOT the launcher-reported leaf is REJECTED
    /// by the Door-1 leaf-pin — this is the "attacker runs their own
    /// claude/codex copy under the same uid" / compromised-sibling defense. We
    /// pin the leaf to pid 2 (not us); our connecting pid mismatches → reject.
    #[tokio::test]
    async fn gate_rejects_non_leaf_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("agent-reject.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = std::process::id();
        let acceptor = acceptor_with_leaf(listener, spec_for("sess_reject", me), 2);

        let _client = connect_peer(&sock).await;
        let res = acceptor.accept_authorized().await.unwrap();
        assert!(
            res.is_none(),
            "non-leaf same-uid peer must be rejected (fail-closed)"
        );
    }

    /// A peer whose uid does not match the session-bound uid is REJECTED by the
    /// peercred arm. We cannot forge a different connecting uid in-process, so
    /// we bind the gate to a uid that is NOT ours (own_uid + 1) and connect as
    /// ourselves; the kernel-attested uid then mismatches.
    #[tokio::test]
    async fn gate_rejects_uid_mismatch_over_real_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("agent-uid.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = std::process::id();
        let mut spec = spec_for("sess_uid", me);
        spec.bound_uid = own_uid().wrapping_add(1); // bind to a different uid
        let acceptor = acceptor_with_leaf(listener, spec, me);

        let _client = connect_peer(&sock).await;
        let res = acceptor.accept_authorized().await.unwrap();
        assert!(res.is_none(), "uid mismatch must be rejected (fail-closed)");
    }

    /// `open_session_socket` binds a `0700` socket; `tear_down` unlinks it.
    /// Drives the lifecycle on a `LocalSet` because the accept loop is
    /// `spawn_local`'d.
    #[tokio::test]
    async fn open_socket_is_group_accessible_and_close_unlinks() {
        use std::os::unix::fs::PermissionsExt;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let tmp = tempfile::tempdir().unwrap();
                let me = std::process::id();
                let state = test_state();
                #[allow(clippy::arc_with_non_send_sync)]
                let backend = Arc::new(DaemonPolicyBackend::new(state.clone()));
                // ADR 215 slice 4 split `open_session_socket` into
                // `prepare_session_socket` (sync bind) + `open_session_socket`
                // (LocalSet adoption + accept-loop spawn). The test was not
                // updated when the split landed in PR #5995.
                let prepared = prepare_session_socket(tmp.path(), spec_for("sess_life", me))
                    .expect("prepare per-session socket");
                let entry = open_session_socket(prepared, state.clone(), backend)
                    .expect("bind per-session socket");

                let path = session_socket_path(tmp.path(), "sess_life");
                assert!(path.exists(), "socket should be bound");
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                // 0660 ember:ember-clients (mirrors daemon.sock) so an
                // operator-uid harness can reach it cross-uid; the leaf-pin gate
                // is the real authorization.
                assert_eq!(
                    mode, 0o660,
                    "per-session socket must be 0660 (group-accessible)"
                );
                // Leaf-pin starts unreported (0) until the launcher reports.
                assert_eq!(entry.expected_leaf_pid.get(), 0);

                entry.tear_down();
                // tear_down unlinks synchronously.
                assert!(!path.exists(), "socket should be unlinked on close");
            })
            .await;
    }
}
