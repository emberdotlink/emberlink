//! Dedicated `0700` rpc-forward UDS listener — the daemon-side receiver for the
//! OS-supervised `ember-rpc` sibling (ADR 155 priv-sep, SLICE 2a).
//!
//! The sibling terminates mTLS in a cap-dropped, no-vault process and forwards a
//! hand-rolled typed bridge frame ([`ember_rpc::frame`]) over this socket. The
//! daemon **attests the peer is the real `emberd-rpc` binary** before acting on
//! anything it sent:
//!
//! 1. `SO_PEERCRED` → refuse `uid != ember` (the daemon's own euid). The
//!    `0700 ember:ember` socket mode is the *structural* barrier (only the
//!    `ember` uid can dial it); this is the defense-in-depth peercred check.
//! 2. **Content-hash** the peer binary and require it to equal the pinned
//!    `emberd-rpc` entry in the signed binary manifest (NOT any manifest entry —
//!    `ember-gh` must not pass). Fail-closed when no manifest is installed.
//! 3. **Linux:** refuse a non-zero `TracerPid` (anti-`ptrace`-mid-flight). macOS
//!    has no in-tree `TracerPid`-equivalent (`csops`) yet — documented residual.
//! 4. **PID-reuse recheck** after the hash (`PeerCredPrincipal::is_alive` —
//!    Linux pidfd / macOS start-time) so a pid reused during the hash is caught.
//!
//! Only a process that *is* the daemon-signed `emberd-rpc` binary (same uid,
//! untraced on Linux, live) passes. This is a *behavioral* attestation
//! (signed-binary + untraced + live), bounded by the `0700` structural barrier,
//! the daemon-side `(persona,container)` cross-check, and Plane-3 authority — it
//! is NOT a structural "cannot." After attestation the typed frame is decoded by
//! the hardened [`crate::infra::bridge_frame`] decoder and dispatched as
//! `DispatchSource::Bridge`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

use crate::infra::events::GrantEvent;
use crate::infra::handler::{PeerCred, RequestContext};
use crate::infra::rate_limit::RateLimiter;
use crate::infra::runtime::PeerCredPrincipal;
use crate::infra::socket::{
    ErrorPayload, Request, Response, SharedPolicyEngine, snapshot_policy_engine,
};
use crate::infra::store::DaemonStore;
use ember_rpc::frame::MAX_FRAME_BYTES;

/// Wallclock deadline for reading one typed frame off an accepted rpc
/// connection. Mirrors the listener's `FRAME_READ_TIMEOUT` — a peer that
/// connects then dribbles bytes must not pin the accept task forever.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an rpc-forward peer was refused before any frame was acted on. Every
/// variant is fail-closed; the connection is dropped.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestError {
    /// Peer uid is not the daemon's euid (`ember`).
    WrongUid { peer_uid: u32, expected_uid: u32 },
    /// A debugger is attached to the peer (Linux `TracerPid != 0`).
    Traced,
    /// Could not resolve/hash the peer binary.
    HashUnavailable(String),
    /// No signed binary manifest is installed — fail-closed (a fresh install
    /// must not accept an unattested sibling).
    NoManifest,
    /// The peer binary's hash does not match the pinned `emberd-rpc` manifest
    /// entry (a different binary, or an `emberd-rpc` not in the manifest).
    NotEmberRpc,
    /// The peer pid was reused between accept and hash (pidfd/start-time recheck).
    PidReused,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::WrongUid {
                peer_uid,
                expected_uid,
            } => {
                write!(f, "peer uid {peer_uid} != daemon euid {expected_uid}")
            }
            AttestError::Traced => write!(f, "peer is being traced (TracerPid != 0)"),
            AttestError::HashUnavailable(e) => write!(f, "peer binary hash unavailable: {e}"),
            AttestError::NoManifest => {
                write!(f, "no signed binary manifest installed (fail-closed)")
            }
            AttestError::NotEmberRpc => {
                write!(
                    f,
                    "peer binary hash does not match the pinned emberd-rpc manifest entry"
                )
            }
            AttestError::PidReused => write!(f, "peer pid reused between accept and hash"),
        }
    }
}

/// The daemon's effective uid — the sibling must run as the same uid.
fn daemon_euid() -> u32 {
    // SAFETY: `geteuid` is an infallible syscall wrapper with no preconditions.
    unsafe { libc::geteuid() }
}

/// Returns `true` when `computed_hex` (a bare blake3 hex) matches the pinned
/// `emberd-rpc` entry in `manifest`. Pure — the testable core of the content-hash
/// gate. Pins SPECIFICALLY to the `emberd-rpc` tool family: a different
/// manifest-listed binary (e.g. `ember-gh`) whose hash happens to be present is
/// NOT accepted, because the match is keyed on BOTH the `emberd-rpc` tool name
/// AND the hash.
/// The canonical `emberd-rpc` tool names. The provenance gate pins SPECIFICALLY
/// to this family (exact membership, NOT a prefix) so a future/mistaken signed
/// entry like `emberd-rpc-debug` or `emberd-rpcx` cannot be admitted.
const EMBERD_RPC_TOOL_NAMES: &[&str] = &["emberd-rpc", "emberd-rpc-linux", "emberd-rpc-macos"];

fn manifest_pins_emberd_rpc(
    manifest: &crate::binary_manifest::BinaryManifest,
    computed_hex: &str,
    exe_path: Option<&std::path::Path>,
) -> bool {
    manifest.entries.iter().any(|e| {
        EMBERD_RPC_TOOL_NAMES.contains(&e.tool_name.as_str())
            && e.content_hash
                .strip_prefix("blake3:")
                .unwrap_or(&e.content_hash)
                == computed_hex
            // Defense-in-depth absolute_path cross-check (Linux only — macOS does
            // not resolve a path here). Mirrors `verify_peer_binary`'s path pin.
            && exe_path.is_none_or(|p| e.absolute_path == p)
    })
}

/// Hash the peer's exec'd binary, inode-pinned on Linux. Returns
/// `(blake3-hex, resolved-path-for-the-cross-check)`.
///
/// **Linux:** opens `/proc/<pid>/exe` DIRECTLY so the kernel resolves the open
/// to the actually-exec'd inode — immune to a path rename/swap. (The
/// `read_link` + open-by-path path in `peer_binary_blake3` leaves a TOCTOU
/// window where an `ember`-uid attacker swaps the file at the resolved path
/// between resolve and read; opening the magic symlink closes it.) The resolved
/// path is returned separately, only for the defense-in-depth cross-check.
/// **macOS:** no `/proc` magic symlink; `proc_pidpath` resolves a path and the
/// path-swap TOCTOU is an acknowledged residual (the real fix, `csops`/inode
/// pinning, is deferred). No path is returned → the cross-check is skipped.
#[cfg(target_os = "linux")]
fn hash_peer_exe(pid: i32) -> Result<(String, Option<std::path::PathBuf>), String> {
    let mut file = std::fs::File::open(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| e.to_string())?;
    let hash = hasher.finalize().to_hex().to_string();
    let exe_path = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    Ok((hash, exe_path))
}

#[cfg(target_os = "macos")]
fn hash_peer_exe(pid: i32) -> Result<(String, Option<std::path::PathBuf>), String> {
    let hash = crate::infra::binary_pin::peer_binary_blake3(pid).map_err(|e| e.to_string())?;
    Ok((hash, None))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn hash_peer_exe(_pid: i32) -> Result<(String, Option<std::path::PathBuf>), String> {
    Err("peer binary hashing unsupported on this target".to_string())
}

/// Attest that the peer behind `principal` is the daemon-signed `emberd-rpc`
/// binary. Fail-closed on every uncertainty. See the module doc for the gate
/// ordering + the macOS `TracerPid` residual.
fn attest_emberd_rpc_peer(principal: &PeerCredPrincipal) -> Result<(), AttestError> {
    // (1) uid == ember.
    let expected = daemon_euid();
    if principal.uid != expected {
        return Err(AttestError::WrongUid {
            peer_uid: principal.uid,
            expected_uid: expected,
        });
    }

    // (2) Linux TracerPid refusal (macOS: no csops equivalent in-tree — residual).
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{}/status", principal.pid))
            .map_err(|e| AttestError::HashUnavailable(format!("read /proc/status: {e}")))?;
        match crate::binary_manifest::parse_tracer_pid(&status) {
            Some(0) => {}
            Some(_) => return Err(AttestError::Traced),
            None => {
                return Err(AttestError::HashUnavailable(
                    "TracerPid line missing".to_string(),
                ));
            }
        }
    }

    // (3) content-hash the peer binary == the pinned emberd-rpc manifest entry.
    // Inode-pinned on Linux (immune to a path-swap TOCTOU); fail-closed on no
    // manifest. The path cross-check is defense-in-depth on top of the hash.
    let (computed, exe_path) =
        hash_peer_exe(principal.pid).map_err(AttestError::HashUnavailable)?;
    let manifest = crate::broker::handler::current_manifest().ok_or(AttestError::NoManifest)?;
    if !manifest_pins_emberd_rpc(&manifest, &computed, exe_path.as_deref()) {
        return Err(AttestError::NotEmberRpc);
    }

    // (4) PID-reuse recheck AFTER the hash (Linux pidfd / macOS start-time). A
    // pid reused during the hash read is detected here and refused.
    if !principal.is_alive() {
        return Err(AttestError::PidReused);
    }

    Ok(())
}

/// The daemon-side receiver for the OS-supervised `ember-rpc` sibling. Binds a
/// dedicated `0700 ember:ember` UDS and dispatches attested, decoded bridge
/// frames as `DispatchSource::Bridge`. MUST run on the daemon's `LocalSet`
/// (`spawn_local`) — it dispatches into `dispatch_method_with_context`, which
/// borrows the `!Send` `Rc<DaemonStore>` (unlike the old in-process mTLS
/// listener, which only forwarded over UDS and never touched the store).
pub struct RpcListener {
    path: PathBuf,
    shutdown: watch::Receiver<bool>,
    store: Rc<DaemonStore>,
    policy: SharedPolicyEngine,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
    sessions_dir: Option<PathBuf>,
}

impl RpcListener {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        shutdown: watch::Receiver<bool>,
        store: Rc<DaemonStore>,
        policy: SharedPolicyEngine,
        rate_limiter: Rc<RefCell<RateLimiter>>,
        events_tx: broadcast::Sender<GrantEvent>,
        sessions_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            path,
            shutdown,
            store,
            policy,
            rate_limiter,
            events_tx,
            sessions_dir,
        }
    }

    fn bind(&self) -> std::io::Result<UnixListener> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        let listener = UnixListener::bind(&self.path)?;
        ensure_rpc_socket_perms(&self.path);
        Ok(listener)
    }

    /// Accept loop. Run via `local.spawn_local(rpc_listener.accept_loop())`.
    pub async fn accept_loop(self) {
        let listener = match self.bind() {
            Ok(l) => l,
            Err(e) => {
                warn!(
                    path = %self.path.display(),
                    error = %e,
                    "rpc-forward listener failed to bind — bridge lane unavailable (fail-soft)"
                );
                return;
            }
        };
        info!(path = %self.path.display(), "rpc-forward (bridge) listener started (0700)");
        let mut shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let stream = match accept {
                        Ok((stream, _addr)) => stream,
                        Err(e) => {
                            warn!(error = %e, "rpc-forward accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };

                    // Capture the kernel-attested peer triple (uid, pid, +
                    // reuse-immune binding) BEFORE the content hash so the
                    // post-hash liveness recheck has a baseline.
                    let principal = match PeerCredPrincipal::from_stream(&stream, self.path.clone()) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "rpc-forward: peer credentials unavailable — refusing");
                            drop(stream);
                            continue;
                        }
                    };

                    // Provenance gate. A refusal drops the connection silently
                    // (the sibling is the only legitimate peer; a refusal means
                    // either a misconfig or an attacker on the 0700 socket).
                    if let Err(reason) = attest_emberd_rpc_peer(&principal) {
                        warn!(
                            peer_uid = principal.uid,
                            peer_pid = principal.pid,
                            reason = %reason,
                            "rpc-forward: peer failed provenance attestation — refusing"
                        );
                        drop(stream);
                        continue;
                    }

                    let store = Rc::clone(&self.store);
                    let policy = Rc::clone(&self.policy);
                    let rate_limiter = Rc::clone(&self.rate_limiter);
                    let events_tx = self.events_tx.clone();
                    let sessions_dir = self.sessions_dir.clone();
                    let peer = PeerCred { uid: principal.uid, pid: Some(principal.pid) };
                    tokio::task::spawn_local(async move {
                        handle_rpc_connection(
                            stream, store, policy, rate_limiter, events_tx, sessions_dir, peer,
                        )
                        .await;
                    });
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("rpc-forward listener shutdown");
                        break;
                    }
                }
            }
        }
    }
}

/// Serve ONE attested bridge connection: read the typed frame, decode +
/// re-validate (hardened, daemon-side), stamp `DispatchSource::Bridge`, dispatch,
/// and write back a newline-delimited JSON-RPC response.
#[allow(clippy::too_many_arguments)]
async fn handle_rpc_connection(
    stream: UnixStream,
    store: Rc<DaemonStore>,
    policy: SharedPolicyEngine,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
    sessions_dir: Option<PathBuf>,
    peer: PeerCred,
) {
    let (read_half, mut write_half) = stream.into_split();

    // Read exactly one typed frame, bounded + timed out. The sibling writes the
    // frame then half-closes its write half, so read-to-EOF terminates the read.
    let mut buf = Vec::with_capacity(4096);
    let read = tokio::time::timeout(
        FRAME_READ_TIMEOUT,
        read_half.take(MAX_FRAME_BYTES as u64).read_to_end(&mut buf),
    )
    .await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(error = %e, "rpc-forward: frame read failed");
            return;
        }
        Err(_) => {
            warn!("rpc-forward: frame read timed out");
            return;
        }
    }

    let (principal, request) = match crate::infra::bridge_frame::decode_and_validate(&buf) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(error = %e, "rpc-forward: frame decode/validate failed — refusing");
            return;
        }
    };

    let Request { id, method, params } = request;
    debug!(id = %id, method = %method, "rpc-forward: dispatching bridge request");

    let mut ctx = RequestContext::bridge(Some(peer), principal);
    ctx.sessions_dir = sessions_dir;

    // Panic-isolate the dispatch (mirrors the UDS lane's AssertUnwindSafe wrap).
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;
    let fallback_dispatch_vault = crate::infra::vault::Vault::new([0u8; 32]);
    let policy_snapshot = snapshot_policy_engine(&policy);
    let outcome = AssertUnwindSafe(crate::infra::handler::dispatch_method_with_context(
        &store,
        &fallback_dispatch_vault,
        policy_snapshot.as_ref(),
        &rate_limiter,
        Some(&events_tx),
        ctx,
        &method,
        &params,
    ))
    .catch_unwind()
    .await;

    let response = match outcome {
        Ok(Ok(result)) => Response {
            id,
            result: Some(result),
            error: None,
        },
        Ok(Err((code, message))) => Response {
            id,
            result: None,
            error: Some(ErrorPayload::new(code, message)),
        },
        Err(_) => Response {
            id,
            result: None,
            error: Some(ErrorPayload {
                code: -32603,
                message: "internal_panic_recovered".to_string(),
                data: None,
            }),
        },
    };

    match serde_json::to_vec(&response) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            if let Err(e) = write_half.write_all(&bytes).await {
                warn!(error = %e, "rpc-forward: response write failed");
            }
            let _ = write_half.shutdown().await;
        }
        Err(e) => warn!(error = %e, "rpc-forward: response serialize failed"),
    }
}

/// chmod `0700` + best-effort chown `ember:ember` on the rpc-forward socket.
/// Distinct from `socket::ensure_socket_perms` (0660 `ember:ember-clients`):
/// `0700 ember:ember` means the operator-CLI uid in `ember-clients` CANNOT dial
/// this socket — only the `ember`-uid sibling can. Best-effort/dev-mode fallback
/// (warn + continue) mirrors the shared-socket helper.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_rpc_socket_perms(path: &Path) {
    use std::ffi::CString;
    let Some(c_path) = path.to_str().and_then(|s| CString::new(s).ok()) else {
        warn!(path = %path.display(), "ensure_rpc_socket_perms: path not a valid C string");
        return;
    };
    // SAFETY: standard POSIX chmod; pointer valid for the call, mode well-formed.
    if unsafe { libc::chmod(c_path.as_ptr(), 0o700) } != 0 {
        warn!(path = %path.display(), error = %std::io::Error::last_os_error(), "ensure_rpc_socket_perms: chmod 0700 failed");
        return;
    }
    // Resolve ember uid + GID (best-effort). The rpc socket is ember:ember, NOT
    // ember:ember-clients — the operator lane must not reach it.
    let ember = CString::new("ember").unwrap();
    // SAFETY: getpwnam is read immediately; pointer not retained.
    let pw = unsafe { libc::getpwnam(ember.as_ptr()) };
    if pw.is_null() {
        warn!(path = %path.display(), "ensure_rpc_socket_perms: ember user not found (dev mode) — socket is 0700 with current owner");
        return;
    }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    // SAFETY: lchown acts on the socket inode (not a symlink target).
    if unsafe { libc::lchown(c_path.as_ptr(), uid, gid) } != 0 {
        warn!(path = %path.display(), error = %std::io::Error::last_os_error(), "ensure_rpc_socket_perms: lchown ember:ember failed (continuing)");
    } else {
        info!(path = %path.display(), uid, gid, "rpc-forward socket permissions set to 0700 ember:ember");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_rpc_socket_perms(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_manifest::{BinaryManifest, BinaryManifestEntry};

    fn entry(tool: &str, hash_hex: &str) -> BinaryManifestEntry {
        BinaryManifestEntry {
            tool_name: tool.to_string(),
            version: "0.3.0".to_string(),
            content_hash: format!("blake3:{hash_hex}"),
            absolute_path: PathBuf::from("/usr/local/bin").join(tool),
            installed_at: 0,
            publisher: "did:emberlink".to_string(),
            channel: Default::default(),
        }
    }

    #[test]
    fn manifest_pins_only_the_emberd_rpc_entry() {
        let m = BinaryManifest {
            entries: vec![entry("emberd-rpc-linux", "aaaa"), entry("ember-gh", "bbbb")],
        };
        // The emberd-rpc entry's hash passes (no path-pin requested).
        assert!(manifest_pins_emberd_rpc(&m, "aaaa", None));
        // A DIFFERENT manifest-listed binary (ember-gh) whose hash is present is
        // NOT accepted — the match is keyed on the emberd-rpc tool name AND hash.
        assert!(!manifest_pins_emberd_rpc(&m, "bbbb", None));
        // An unknown hash is refused.
        assert!(!manifest_pins_emberd_rpc(&m, "cccc", None));
    }

    #[test]
    fn manifest_pins_macos_variant_too() {
        let m = BinaryManifest {
            entries: vec![entry("emberd-rpc-macos", "dddd")],
        };
        assert!(manifest_pins_emberd_rpc(&m, "dddd", None));
    }

    #[test]
    fn empty_manifest_pins_nothing() {
        let m = BinaryManifest { entries: vec![] };
        assert!(!manifest_pins_emberd_rpc(&m, "aaaa", None));
    }

    #[test]
    fn exact_tool_name_match_rejects_lookalike_prefix() {
        // A future/mistaken signed entry that merely starts with "emberd-rpc"
        // (e.g. "emberd-rpc-debug") must NOT be admitted — the gate is exact
        // tool-family membership, not a prefix.
        let m = BinaryManifest {
            entries: vec![entry("emberd-rpc-debug", "aaaa")],
        };
        assert!(!manifest_pins_emberd_rpc(&m, "aaaa", None));
    }

    #[test]
    fn path_cross_check_refuses_hash_match_at_wrong_path() {
        // Hash matches the emberd-rpc entry, but the resolved exe path does not
        // match the manifest's absolute_path → refused (defense-in-depth).
        let m = BinaryManifest {
            entries: vec![entry("emberd-rpc-linux", "aaaa")],
        };
        // entry's absolute_path is /usr/local/bin/emberd-rpc-linux.
        assert!(manifest_pins_emberd_rpc(
            &m,
            "aaaa",
            Some(std::path::Path::new("/usr/local/bin/emberd-rpc-linux"))
        ));
        assert!(!manifest_pins_emberd_rpc(
            &m,
            "aaaa",
            Some(std::path::Path::new("/tmp/evil"))
        ));
    }
}
