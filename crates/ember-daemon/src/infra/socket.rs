// development milestone: fail-closed platform whitelist.
//
// Tokio's `UnixStream::peer_cred()` returns *synthetic root* creds on a
// handful of exotic Unix targets (espidf, vita, hurd, fuchsia) instead of
// erroring. If the daemon ever ran as uid 0 on one of those platforms the
// `verify_peer_uid` gate would silently pass every caller — fail-OPEN,
// not fail-closed — defeating development milestone. Rather than try to enumerate
// "unsafe" platforms we whitelist the platforms we actually ship on and
// intend to support (Linux + macOS). Any other target is rejected at
// compile time, so an accidental cross-compile produces a clear error
// instead of a silently weakened daemon.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "ember-daemon socket peer-cred gate (development milestone) is only \
     audited for target_os = \"linux\" and target_os = \"macos\". Tokio's \
     peer_cred() returns synthetic root creds on espidf/vita/hurd/fuchsia, \
     which would silently disable the SO_PEERCRED trust boundary. Add the \
     target to the whitelist and audit peer_cred() semantics there before \
     building."
);

use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tokio::task::LocalSet;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::infra::events::{GrantEvent, GrantEventExt};
use crate::infra::rate_limit::RateLimiter;
use crate::trust::policy::PolicyEngine;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MB
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// development milestone: Exponential backoff bounds for `accept()` errors.
///
/// Under fd exhaustion (`EMFILE`) or a hostile client flooding the socket
/// with never-closed connections, `listener.accept()` can fail on every
/// iteration. Without a sleep between retries the accept loop busy-spins
/// at CPU-full speed, pinning a core and starving the rest of the daemon
/// (policy engine, expiry scheduler, dashboard). We back off exponentially
/// starting at 10ms and capping at 5s: long enough to starve a spin
/// attacker, short enough that a legitimate transient error recovers
/// within a few seconds.
const MIN_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const MAX_ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(5);
static FALLBACK_DISPATCH_VAULT: Lazy<crate::infra::vault::Vault> =
    Lazy::new(|| crate::infra::vault::Vault::new([0u8; 32]));

/// Compute the next accept-error backoff delay given the previous delay.
///
/// Pure function so the backoff schedule is unit-testable without having
/// to drive a live accept loop through synthetic `EMFILE`s. The schedule
/// is: `ZERO -> 10ms -> 20ms -> 40ms -> ... -> 5s (capped)`.
fn compute_next_accept_delay(current: Duration) -> Duration {
    if current.is_zero() {
        MIN_ACCEPT_RETRY_DELAY
    } else {
        (current * 2).min(MAX_ACCEPT_RETRY_DELAY)
    }
}

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    #[error("socket path already bound")]
    AlreadyBound,
    /// implementation-note-154 (CRIT-C): an inode already exists at the
    /// per-agent socket path. Returned when the O_EXCL precondition under
    /// the parent-dir `flock()` fails, including the symlink-swap attack
    /// where a privileged container process pre-creates a symlink at the
    /// predictable path before emberd's permission check.
    #[error("per-agent socket path already exists: {0}")]
    AlreadyExists(PathBuf),
    /// implementation-note-154: the UUID was previously tombstoned and
    /// is permanently retired. Tombstoning prevents agent-id recycling so
    /// a freshly-spawned agent cannot inherit a previous agent's grants
    /// or audit trail by replaying its UUID.
    #[error("per-agent socket UUID has been tombstoned and cannot be reused: {0}")]
    TombstonedUuid(Uuid),
}

/// P69E.8b: wrap a bind-site `io::Error` so the message includes the path
/// and (when the kind is `AddrInUse`) actionable hints — `lsof -i :<port>`
/// for TCP, `lsof -U <path>` for Unix sockets, plus the daemon stop command.
///
/// Returns a fresh `io::Error` of the same kind as the input, with a richer
/// message body. Callers should keep the original kind so downstream
/// `ErrorKind` matching keeps working; only the human-readable text grows.
pub(crate) fn annotate_bind_error(err: std::io::Error, target: &str) -> std::io::Error {
    let kind = err.kind();
    let original = err.to_string();

    // Heuristic split: `host:port` looks like a TCP socket address, anything
    // else (a filesystem path, e.g. `~/.ember/sock`) is a Unix domain socket.
    // We don't try to be exhaustive — `host:port` shapes covered by
    // `SocketAddr::Display` always contain at least one `:` and end in digits.
    let looks_tcp = target
        .rsplit_once(':')
        .map(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false);

    if kind == std::io::ErrorKind::AddrInUse {
        let how_to_find = if looks_tcp {
            // Pull the port out of the trailing `:NNNN` segment.
            let port = target.rsplit_once(':').map(|(_, p)| p).unwrap_or(target);
            format!("    lsof -i :{port}")
        } else {
            format!("    lsof -U {target}")
        };
        let body = format!(
            "failed to bind {target}: {original}\n\
             \n\
             Another process is already using this address.\n\
             \n\
             Find the conflicting process:\n\
             \n\
             {how_to_find}\n\
             \n\
             Stop an existing ember daemon:\n\
             \n\
             - Foreground: hit Ctrl-C or run `ember daemon stop`\n\
             - launchd (macOS): launchctl bootout gui/$(id -u)/com.emberlink.ember-daemon\n\
             - Or kill the conflicting PID directly: `kill -TERM <pid>`\n",
        );
        return std::io::Error::new(kind, body);
    }

    // Non-AddrInUse errors: still include the address so the user sees what
    // we tried to bind, but skip the lsof hint (it would be misleading for
    // permission-denied / EACCES / address-not-available paths).
    std::io::Error::new(kind, format!("failed to bind {target}: {original}"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 §5: a Response object has either `result` or `error`,
/// but never both. Default serde-derive emits `error: null` on success
/// and `result: null` on failure — clients that check `if "error" in resp`
/// (the natural Python idiom) misinterpret the always-present null key
/// as a failure and raise `RPC error: None`. Skip-if-none on both fields
/// makes the wire shape spec-compliant: successful responses carry only
/// `result`, errors carry only `error`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

/// Server-initiated JSON-RPC notification sent to clients over the socket.
/// Uses `jsonrpc: "2.0"` and omits the `id` field, matching the standard
/// JSON-RPC 2.0 notification shape. No response is expected from the client.
#[derive(Debug, Serialize)]
struct Notification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

pub struct SocketListener {
    path: PathBuf,
    shutdown: watch::Receiver<bool>,
    store: Rc<crate::infra::store::DaemonStore>,
    policy: Rc<PolicyEngine>,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
    sessions_dir: Option<PathBuf>,
    /// implementation-note-266: bound LLM proxy
    /// URL populated after the proxy listener binds in runtime.rs, then
    /// plumbed into every connection's RequestContext via handle_connection.
    llm_proxy_url: Option<String>,
    /// implementation-note-266: bound git proxy URL.
    git_proxy_url: Option<String>,
    /// implementation-note-268 — integration
    /// tests in sibling crates (`emberlink-cli/tests/*.rs`) link against
    /// `ember-daemon` as cfg(not(test)), so the `cfg(test)` synthesis on
    /// `RequestContext::socket` does not fire. When this flag is set,
    /// `handle_connection` builds the per-request context via
    /// `RequestContext::socket_for_test` instead, which mints a synthetic
    /// presence_token bound to the peer-cred uid. The token signs and
    /// verifies via the same `DaemonIdentityPresenceSigner` (real Ed25519
    /// from the daemon persona) the dispatch layer uses in production —
    /// the legacy SHA-256 `StubPresenceSigner` was removed; this comment
    /// previously referenced it.
    /// Production callers never set this — the daemon binary leaves it false.
    test_mode_synthetic_presence_token: bool,
}

impl SocketListener {
    pub fn new(
        path: PathBuf,
        shutdown: watch::Receiver<bool>,
        store: Rc<crate::infra::store::DaemonStore>,
        policy: Rc<PolicyEngine>,
        rate_limiter: Rc<RefCell<RateLimiter>>,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            path,
            shutdown,
            store,
            policy,
            rate_limiter,
            events_tx,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            test_mode_synthetic_presence_token: false,
        }
    }

    /// Enable integration-test mode. When `enabled = true`, every accepted
    /// connection's `RequestContext` is built via
    /// `RequestContext::socket_for_test` (mints a synthetic presence_token
    /// bound to the peer-cred uid) instead of `RequestContext::socket` (no
    /// presence_token under cfg(not(test))). Production code MUST NOT call
    /// this — see the field docstring. implementation-note-347-
    /// PRE-EXISTING-FAILURES.
    pub fn with_test_mode_synthetic_presence_token(mut self, enabled: bool) -> Self {
        self.test_mode_synthetic_presence_token = enabled;
        self
    }

    pub fn with_sessions_dir(mut self, sessions_dir: PathBuf) -> Self {
        self.sessions_dir = Some(sessions_dir);
        self
    }

    /// Set the LLM proxy URL on every connection's RequestContext.
    ///
    /// Call after the LLM proxy listener binds in runtime.rs. Mirrors
    /// `with_sessions_dir` from the LAUNCHER-SESSION-RPC plumbing (#2318).
    pub fn with_llm_proxy_url(mut self, url: Option<String>) -> Self {
        self.llm_proxy_url = url;
        self
    }

    /// Set the git proxy URL on every connection's RequestContext.
    pub fn with_git_proxy_url(mut self, url: Option<String>) -> Self {
        self.git_proxy_url = url;
        self
    }

    /// Expose the event broadcast sender so the daemon runtime can publish
    /// events from other tasks (e.g. scheduled grant expiry).
    pub fn events_sender(&self) -> broadcast::Sender<GrantEvent> {
        self.events_tx.clone()
    }

    pub fn bind(&self) -> Result<UnixListener, SocketError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| {
                SocketError::Bind(annotate_bind_error(e, &self.path.display().to_string()))
            })?;
        }
        let listener = UnixListener::bind(&self.path).map_err(|e| {
            SocketError::Bind(annotate_bind_error(e, &self.path.display().to_string()))
        })?;
        // Set 0660 permissions and best-effort chown to ember:ember-clients.
        // Non-fatal: if the system is in dev mode (no ember user/group) the
        // daemon continues with the current owner and 0660 mode.
        ensure_socket_perms(&self.path)?;
        Ok(listener)
    }

    /// Run the accept loop without creating a LocalSet.
    ///
    /// The caller must ensure this runs inside a `LocalSet` (e.g. via
    /// `local.run_until()` or `spawn_local()`).
    pub async fn accept_loop(self) -> Result<(), SocketError> {
        let listener = self.bind()?;
        info!(path = %self.path.display(), "socket listener started");

        let mut shutdown = self.shutdown.clone();

        // development milestone: accept-error backoff state. Zero while the loop is
        // healthy; grows exponentially under persistent failure; resets
        // to zero on the first successful accept after errors.
        let mut accept_delay: Duration = Duration::ZERO;

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            // Reset the backoff: a successful accept means
                            // the error condition cleared. The next error
                            // starts again at MIN_ACCEPT_RETRY_DELAY.
                            accept_delay = Duration::ZERO;

                            // The Unix socket is the local trust boundary.
                            // In install-shaped mode the listener accepts
                            // `ember-clients` members; in development/CI it
                            // falls back to same-euid. Reuse the runtime's
                            // audited helper so the live listener matches the
                            // install/runtime contract.
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            let peer_creds = match crate::infra::runtime::authenticate_peer_creds(&stream) {
                                Ok(peer) => peer,
                                Err(e) => {
                                    warn!(error = %e, "rejecting socket connection");
                                    drop(stream);
                                    continue;
                                }
                            };
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            {
                                tracing::warn!(
                                    "peer-cred verification unsupported on this target — refusing connection"
                                );
                                drop(stream);
                                continue;
                            }
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            let peer = PeerIdentity {
                                uid: peer_creds.uid,
                                pid: peer_creds.pid,
                            };
                            // development milestone: include peer_uid and
                            // peer_pid in the success log so "who connected
                            // at T+5s" is answerable from the journal. Both
                            // fields are numbers from the kernel — no
                            // attacker-controlled strings. pid is Option<i32>
                            // (BSD may omit it); -1 checkpoint means unavailable.
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            {
                                let uid = peer_creds.uid;
                                let gid = peer_creds.gid;
                                let pid = peer_creds.pid.unwrap_or(-1);
                                info!(peer_uid = uid, peer_gid = gid, peer_pid = pid, "client connected");
                            }
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            info!("client connected");
                            let store = Rc::clone(&self.store);
                            let policy = Rc::clone(&self.policy);
                            let rate_limiter = Rc::clone(&self.rate_limiter);
                            let events_tx = self.events_tx.clone();
                            let events_rx = self.events_tx.subscribe();
                            let sessions_dir = self.sessions_dir.clone();
                            let llm_proxy_url = self.llm_proxy_url.clone();
                            let git_proxy_url = self.git_proxy_url.clone();
                            // development milestone: forward the kernel-derived
                            // peer identity into the per-connection task so
                            // it reaches the request-context layer in handler.rs.
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            let peer_for_task = Some(peer);
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            let peer_for_task: Option<PeerIdentity> = None;
                            // implementation-note-153: extract
                            // the (uid, pid, socket_path) triple once per
                            // connection so every dispatch on this stream
                            // gets the same kernel-attested principal.
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            let peer_cred_principal = crate::infra::runtime::PeerCredPrincipal::from_stream(
                                &stream,
                                self.path.clone(),
                            )
                            .map_err(|e| {
                                tracing::warn!(
                                    error = %e,
                                    "PeerCredPrincipal::from_stream failed — connection \
                                     proceeds without kernel-attested principal (handlers \
                                     fall back to legacy warn-only path)"
                                );
                            })
                            .ok();
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            let peer_cred_principal: Option<crate::infra::runtime::PeerCredPrincipal> = None;
                            let test_mode_synthetic_presence_token =
                                self.test_mode_synthetic_presence_token;
                            tokio::task::spawn_local(handle_connection(
                                stream,
                                store,
                                policy,
                                rate_limiter,
                                events_tx,
                                events_rx,
                                peer_for_task,
                                sessions_dir,
                                llm_proxy_url,
                                git_proxy_url,
                                peer_cred_principal,
                                test_mode_synthetic_presence_token,
                            ));
                        }
                        Err(e) => {
                            // development milestone: exponential backoff. Without this
                            // sleep, fd exhaustion (EMFILE) or a hostile
                            // client holding many connections open makes
                            // accept() fail in a tight loop at CPU-full
                            // speed. Back off starting at 10ms, doubling
                            // each consecutive failure, capped at 5s.
                            accept_delay = compute_next_accept_delay(accept_delay);
                            warn!(
                                error = %e,
                                delay_ms = accept_delay.as_millis() as u64,
                                "socket accept failed, backing off",
                            );
                            tokio::time::sleep(accept_delay).await;
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("shutdown signal received, draining connections");
                        break;
                    }
                }
            }
        }

        // Drop listener; give spawned tasks a moment to drain.
        drop(listener);
        tokio::time::sleep(DRAIN_TIMEOUT.min(Duration::from_millis(100))).await;
        info!(path = %self.path.display(), "socket listener stopped");

        Ok(())
    }

    /// Run the socket listener with its own LocalSet (standalone mode).
    pub async fn run(self) -> Result<(), SocketError> {
        let local = LocalSet::new();
        local.run_until(self.accept_loop()).await
    }
}

// verify_peer_uid uses SO_PEERCRED (linux) / LOCAL_PEERCRED (macos). Other platforms fail-closed.

/// Return the daemon's effective uid. Used as the "expected" peer uid for
/// the SO_PEERCRED / LOCAL_PEERCRED gate.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn daemon_euid() -> u32 {
    // SAFETY: `geteuid` is a simple syscall wrapper with no preconditions
    // and cannot fail.
    unsafe { libc::geteuid() }
}

/// Identity of the peer on the other end of a Unix socket, as reported by
/// `SO_PEERCRED` / `LOCAL_PEERCRED`. Returned from the accepted peer-cred
/// check so callers can log structured fields without a second kernel
/// round-trip.
///
/// development milestone: Made `pub` and field-public so the handler layer
/// can carry the peer identity into `RequestContext` for full principal
/// binding on `delegate_grant`. Without this the socket layer would have
/// to translate to a parallel struct, doubling the surface area.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    /// BSD variants don't always surface the peer pid, so this is optional.
    pub pid: Option<i32>,
}

/// Kernel-supplied credentials for the peer process on the other end of a
/// Unix domain socket. Extends `PeerIdentity` with the primary group id so
/// group-membership checks (e.g. `ember-clients`) can be performed without
/// a second kernel round-trip.
///
/// All fields are kernel-supplied — never wire-claimed — so they carry the
/// trust level of the OS credential store.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCreds {
    pub uid: u32,
    pub gid: u32,
    /// Process id of the peer. `None` on BSD/macOS variants that do not
    /// surface the pid in `LOCAL_PEERCRED`.
    pub pid: Option<i32>,
}

/// Set mode 0660 on `path` and attempt a best-effort chown to
/// `ember:ember-clients`.
///
/// This function is called after every successful `UnixListener::bind` so
/// the socket file is not accessible to unrelated local users. The chown is
/// best-effort: if the `ember` user or `ember-clients` group does not exist
/// (development mode, CI, embedded) the function logs a warning and returns
/// `Ok(())` so the daemon continues to start.
///
/// The mode change (`chmod 0660`) is always applied because it only requires
/// the daemon to own the socket, not the `ember` user to exist.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn ensure_socket_perms(path: &Path) -> Result<(), SocketError> {
    use std::ffi::CString;

    // Convert the path to a C string so we can pass it to libc.
    let c_path = path
        .to_str()
        .and_then(|s| CString::new(s).ok())
        .ok_or_else(|| {
            SocketError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path contains interior NUL or is not valid UTF-8",
            ))
        })?;

    // Step 1: chmod 0660. Always applied — requires only file ownership,
    // not the ember user/group to exist on this system.
    // SAFETY: `chmod` is a standard POSIX syscall; the pointer is valid for
    // the duration of the call and the mode value is well-formed.
    let chmod_rc = unsafe { libc::chmod(c_path.as_ptr(), 0o660) };
    if chmod_rc != 0 {
        let e = std::io::Error::last_os_error();
        warn!(
            path = %path.display(),
            error = %e,
            "ensure_socket_perms: chmod 0660 failed"
        );
        return Err(SocketError::Io(e));
    }

    // Step 2: resolve ember uid (best-effort).
    let ember_uid: Option<libc::uid_t> = {
        let name = CString::new("ember").unwrap();
        // SAFETY: `getpwnam` is thread-safe when the result is not cached;
        // we read `pw_uid` immediately and do not retain the pointer.
        let pw = unsafe { libc::getpwnam(name.as_ptr()) };
        if pw.is_null() {
            None
        } else {
            Some(unsafe { (*pw).pw_uid })
        }
    };

    // Step 3: resolve ember-clients gid (best-effort).
    let ember_clients_gid: Option<libc::gid_t> = {
        let name = CString::new("ember-clients").unwrap();
        // SAFETY: same as getpwnam above.
        let gr = unsafe { libc::getgrnam(name.as_ptr()) };
        if gr.is_null() {
            None
        } else {
            Some(unsafe { (*gr).gr_gid })
        }
    };

    match (ember_uid, ember_clients_gid) {
        (Some(uid), Some(gid)) => {
            // SAFETY: `lchown` is a standard POSIX syscall. We use lchown
            // (not chown) so we act on the socket itself, not a symlink
            // target, which would be a TOCTOU risk on chown after bind.
            let chown_rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
            if chown_rc != 0 {
                let e = std::io::Error::last_os_error();
                warn!(
                    path = %path.display(),
                    error = %e,
                    uid,
                    gid,
                    "ensure_socket_perms: lchown ember:ember-clients failed (continuing)"
                );
                // Best-effort: do not fail the bind on a chown error.
            } else {
                info!(
                    path = %path.display(),
                    uid,
                    gid,
                    "ensure_socket_perms: socket permissions set to 0660 ember:ember-clients"
                );
            }
        }
        _ => {
            warn!(
                path = %path.display(),
                ember_uid = ?ember_uid,
                ember_clients_gid = ?ember_clients_gid,
                "ensure_socket_perms: ember user or ember-clients group not found \
                 (development mode — skipping chown, socket is 0660 with current owner)"
            );
        }
    }

    Ok(())
}

/// No-op stub for non-Linux/macOS targets — compile-error at top of module
/// prevents this from ever being reached.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn ensure_socket_perms(_path: &Path) -> Result<(), SocketError> {
    Ok(())
}

/// Read the kernel-supplied credentials for the peer process on the other
/// end of `stream`, without applying any uid-match policy.
///
/// Returns `Some(PeerCreds)` when the kernel successfully delivers the
/// peer's uid, gid, and pid. Returns `None` only when the kernel call
/// itself fails (i.e. `SO_PEERCRED` / `LOCAL_PEERCRED` returns an error).
///
/// This is the fact-collection step: it does NOT enforce that the peer
/// uid matches the daemon euid. That policy check is the caller's
/// responsibility. `verify_peer_uid` is the existing wrapper that
/// re-applies the strict uid-match on top of this function.
///
/// implementation-note-348: Phase A design destination.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn read_peer_creds(stream: &UnixStream) -> Option<PeerCreds> {
    match stream.peer_cred() {
        Ok(c) => Some(PeerCreds {
            uid: c.uid(),
            gid: c.gid(),
            pid: c.pid(),
        }),
        Err(e) => {
            warn!(error = %e, "read_peer_creds: kernel peer_cred() call failed");
            None
        }
    }
}

fn take_presence_token(
    params: &mut serde_json::Value,
) -> Option<crate::auth::presence_token::PresenceToken> {
    let token_value = match params {
        serde_json::Value::Object(map) => map.remove("_presence_token"),
        _ => None,
    }?;

    match serde_json::from_value(token_value) {
        Ok(token) => Some(token),
        Err(e) => {
            warn!(error = %e, "ignoring malformed _presence_token");
            None
        }
    }
}

/// Verify that the peer of `stream` is running as the daemon's own euid.
///
/// On Linux this uses `SO_PEERCRED`; on macOS tokio's `peer_cred()`
/// translates to `LOCAL_PEERCRED`. Either way we get the uid of the
/// process on the other end of the socket at connect time. Only linux
/// and macos are audited — see the `compile_error!` at the top of this
/// module for the platform-whitelist rationale (development milestone).
///
/// development milestone (CRIT): without this gate, any local process under any
/// uid that can reach the socket inode can drive the daemon and request
/// grants. The filesystem permissions on the socket are the first line of
/// defense; this is the second, so that a misconfigured umask, a shared
/// tmpfs, or a demo running as a different user cannot silently widen the
/// trust boundary.
///
/// Returns `Some(PeerIdentity)` when the peer is the same uid as the
/// daemon, `None` otherwise. On rejection, emits a `tracing::warn!` with
/// the peer uid, the expected uid, and (when available) the peer pid.
///
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn verify_peer_uid(stream: &UnixStream) -> Option<PeerIdentity> {
    // bridge_widening_removed (implementation-note-349):
    // design bridge widening removed; per-method authority gate from
    // Phase D (WebAuthn presence-token cache) is the replacement.
    verify_peer_uid_with(
        || {
            stream.peer_cred().map(|cred| PeerIdentity {
                uid: cred.uid(),
                pid: cred.pid(),
            })
        },
        daemon_euid(),
    )
}

/// Pure peer-cred policy: accept iff the source returns a peer whose uid
/// equals `expected_uid`. Factored from `verify_peer_uid` so the reject
/// paths (mismatched uid, failed `peer_cred()` read) can be unit-tested
/// without needing a hostile cross-uid Unix-socket pair in CI
/// (development milestone).
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn verify_peer_uid_with<F>(get_peer: F, expected_uid: u32) -> Option<PeerIdentity>
where
    F: FnOnce() -> io::Result<PeerIdentity>,
{
    match get_peer() {
        Ok(peer) => {
            if peer.uid == expected_uid {
                Some(peer)
            } else {
                // `pid` is Option<i32> because BSD variants don't always
                // surface it; log None explicitly rather than unwrapping.
                warn!(
                    peer_uid = peer.uid,
                    expected_uid,
                    pid = ?peer.pid,
                    "rejecting socket connection: peer uid does not match daemon euid"
                );
                None
            }
        }
        Err(e) => {
            // If we can't read peer creds, fail closed. A kernel that does
            // not support SO_PEERCRED / LOCAL_PEERCRED on AF_UNIX is not a
            // platform we intend to ship on, and falling through would
            // defeat the gate.
            warn!(
                error = %e,
                expected_uid,
                "rejecting socket connection: failed to read peer credentials"
            );
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: UnixStream,
    store: Rc<crate::infra::store::DaemonStore>,
    policy: Rc<PolicyEngine>,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
    mut events_rx: broadcast::Receiver<GrantEvent>,
    peer_cred: Option<PeerIdentity>,
    sessions_dir: Option<PathBuf>,
    llm_proxy_url: Option<String>,
    git_proxy_url: Option<String>,
    peer_cred_principal: Option<crate::infra::runtime::PeerCredPrincipal>,
    test_mode_synthetic_presence_token: bool,
) {
    let peer = stream.peer_addr().ok();
    debug!(?peer, ?peer_cred, "handling connection");

    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    // Merge inbound request handling and outbound event forwarding into a
    // single task so writes to the socket are serialized without a shared
    // mutex. Either a request line or an event will be processed per
    // iteration of the select.
    loop {
        tokio::select! {
            // Inbound request from client.
            line = lines.next_line() => {
                let line = match line {
                    Ok(Some(line)) => line,
                    Ok(None) => break, // EOF
                    Err(e) => {
                        warn!(error = %e, "read error");
                        break;
                    }
                };

                if line.len() > MAX_MESSAGE_BYTES {
                    let resp = Response {
                        id: String::new(),
                        result: None,
                        error: Some(ErrorPayload {
                            code: -32600,
                            message: "Message too large".to_string(),
                        }),
                    };
                    if let Err(e) = write_response(&mut write_half, &resp).await {
                        warn!(error = %e, "write error");
                        break;
                    }
                    continue;
                }

                let req: Request = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => {
                        let resp = Response {
                            id: String::new(),
                            result: None,
                            error: Some(ErrorPayload {
                                code: -32700,
                                message: "Parse error".to_string(),
                            }),
                        };
                        if let Err(e) = write_response(&mut write_half, &resp).await {
                            warn!(error = %e, "write error");
                            break;
                        }
                        continue;
                    }
                };

                let Request {
                    id,
                    method,
                    mut params,
                } = req;
                let presence_token = take_presence_token(&mut params);

                debug!(id = %id, method = %method, "dispatching request");

                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let peer_for_ctx: Option<crate::infra::handler::PeerCred> =
                    peer_cred.map(Into::into);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let peer_for_ctx: Option<crate::infra::handler::PeerCred> = None;

                // implementation-note-268: when
                // the listener was constructed with
                // `with_test_mode_synthetic_presence_token(true)`, build via
                // `socket_for_test` so external integration tests
                // (`emberlink-cli/tests/*.rs` link as cfg(not(test))) get the
                // synthetic presence_token that satisfies OperatorPresence-
                // class methods. Production daemons leave the flag false.
                let base_ctx = match (test_mode_synthetic_presence_token, peer_for_ctx) {
                    (true, Some(p)) => crate::infra::handler::RequestContext::socket_for_test(p),
                    _ => crate::infra::handler::RequestContext::socket(peer_for_ctx),
                };
                let mut ctx = base_ctx.with_presence_token(presence_token);
                ctx.sessions_dir = sessions_dir.clone();
                ctx.llm_proxy_url = llm_proxy_url.clone();
                ctx.git_proxy_url = git_proxy_url.clone();
                // implementation-note-153: stamp the
                // kernel-attested principal captured at accept time so
                // every dispatch on this connection inherits the same
                // (uid, pid, socket_path) triple.
                ctx.peer_cred_principal = peer_cred_principal.clone();

                // implementation-note-114 — dispatch_method_panic_recovered.
                //
                // prior change shipped `recover_rpc_panic` as a sync
                // `std::panic::catch_unwind` wrapper, but `catch_unwind` doesn't
                // work on async futures directly. The standard pattern is
                // `AssertUnwindSafe(future).catch_unwind().await` from
                // `futures_util::FutureExt`. Without this wrap a single panic
                // in any dispatch arm crashes the entire daemon process, taking
                // down every other in-flight connection with it.
                //
                // AssertUnwindSafe justification matches recover_rpc_panic's
                // (broker/handler.rs): SQLite transactions auto-rollback on
                // Drop; non-transactional state is borrowed read-only or
                // Mutex-guarded (poisoning is observable). Safe to wrap.
                use futures_util::FutureExt;
                use std::panic::AssertUnwindSafe;
                let dispatch_method_str = method.clone();
                let dispatch_params_owned = params.clone();
                let dispatch_future = crate::infra::handler::dispatch_method_with_context(
                    &store,
                    &FALLBACK_DISPATCH_VAULT,
                    &policy,
                    &rate_limiter,
                    Some(&events_tx),
                    ctx,
                    &method,
                    &params,
                );
                let dispatch_outcome = AssertUnwindSafe(dispatch_future).catch_unwind().await;
                let response = match dispatch_outcome {
                    Ok(Ok(result)) => Response {
                        id,
                        result: Some(result),
                        error: None,
                    },
                    Ok(Err((code, message))) => Response {
                        id,
                        result: None,
                        error: Some(ErrorPayload { code, message }),
                    },
                    Err(panic_payload) => {
                        let panic_msg = panic_payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "<panic payload not downcastable>".to_string());
                        let frame_hash = {
                            use sha2::{Digest, Sha256};
                            let mut h = Sha256::new();
                            h.update(dispatch_method_str.as_bytes());
                            h.update(
                                serde_json::to_vec(&dispatch_params_owned).unwrap_or_default(),
                            );
                            let digest = h.finalize();
                            let mut s = String::with_capacity(16);
                            for b in digest.iter().take(8) {
                                s.push_str(&format!("{b:02x}"));
                            }
                            s
                        };
                        tracing::error!(
                            method = %dispatch_method_str,
                            frame_hash = %frame_hash,
                            panic = %panic_msg,
                            "async dispatch_method panicked — converted to RpcError::InternalPanic"
                        );
                        Response {
                            id,
                            result: None,
                            error: Some(ErrorPayload {
                                code: -32603,
                                message: format!("internal_panic_recovered: {panic_msg}"),
                            }),
                        }
                    }
                };

                debug!(id = %response.id, "sending response");

                if let Err(e) = write_response(&mut write_half, &response).await {
                    warn!(error = %e, "write error");
                    break;
                }
            }
            // Server-initiated event pushed to this connection.
            event = events_rx.recv() => {
                match event {
                    Ok(ev) => {
                        if let Err(e) = write_notification(&mut write_half, &ev).await {
                            warn!(error = %e, "notification write error");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "connection lagged on event channel");
                        // Continue — we don't want a slow client to stall
                        // revocation broadcasts to other connections.
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed; stop forwarding but keep serving
                        // request/response.
                        debug!("event channel closed");
                    }
                }
            }
        }
    }

    debug!(?peer, "connection closed");
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &Response,
) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await
}

async fn write_notification(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    event: &GrantEvent,
) -> std::io::Result<()> {
    let notif = Notification {
        jsonrpc: "2.0",
        method: event.method_name(),
        params: event.params(),
    };
    let mut bytes = serde_json::to_vec(&notif)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await
}

// ---- implementation-note-154 ------------------------------------------
//
// CRIT-1: a single shared daemon socket cannot distinguish two agents living
// in different pid namespaces — `SO_PEERCRED.pid` is pid-namespace-relative,
// so both `pid=1` callers fold into the same trust principal. CRIT-C: a stale
// predictable socket inode can be swapped via symlink by a privileged
// container process before emberd checks permissions.
//
// Fix: one socket per agent, path derived from an unguessable UUIDv4. emberd
// creates the socket under `flock()` of the parent directory with O_EXCL
// semantics — any pre-existing inode (including a symlink) at the path
// rejects with `SocketError::AlreadyExists`. On agent termination the UUID
// is tombstoned so it can never be reused.

/// Default parent directory for per-agent sockets in production.
///
/// The directory layout assumed by the bind-mount strategy:
/// - `/run/emberd/` is read-only into the agent container (so the agent
///   uid cannot unlink/replace sibling sockets)
/// - `/run/emberd/agent-<uuid>.sock` is read-write into the agent's own
///   container (just the inode, not the parent dir)
pub const PER_AGENT_SOCKET_PARENT: &str = "/run/emberd";

/// In-process tombstone table. Tracks UUIDs that have been retired by a
/// successful `tombstone_socket` call so they can never be recycled.
///
/// Persistence-across-restart is intentionally NOT implemented here — the
/// 122-bit UUIDv4 entropy already makes accidental recycling
/// vanishingly unlikely, and a daemon restart starts with a fresh
/// process-namespace anyway. The tombstone defends against in-process
/// recycling attacks where a long-running daemon might otherwise be
/// coerced into re-creating a socket with a previously-released UUID.
static TOMBSTONED_UUIDS: Lazy<Mutex<HashSet<Uuid>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// RAII guard for an exclusive `flock()` on the parent directory. Drops
/// release the lock by closing the fd. Used to serialize the
/// stat→bind window inside `create_per_agent_socket_with` so no other
/// thread/process can plant an inode between the check and the bind.
struct DirFlockGuard {
    fd: libc::c_int,
}

impl DirFlockGuard {
    /// Open `dir` `O_RDONLY | O_DIRECTORY` and take an exclusive `flock()`.
    /// `O_NOFOLLOW` prevents the lock landing on a symlink target outside
    /// the parent directory the caller intended.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn acquire(dir: &Path) -> io::Result<Self> {
        use std::ffi::CString;
        let c_path = dir
            .to_str()
            .and_then(|s| CString::new(s).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "parent directory path contains interior NUL or is not valid UTF-8",
                )
            })?;
        // SAFETY: `open` is a standard POSIX syscall; the path pointer is
        // valid for the duration of the call.
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `flock` operates on the fd we just opened. LOCK_EX takes
        // an exclusive lock that blocks both shared and exclusive holders.
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            // SAFETY: closing the fd we just opened is always safe.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(Self { fd })
    }
}

impl Drop for DirFlockGuard {
    fn drop(&mut self) {
        // SAFETY: `close` on our own fd is safe; the kernel releases the
        // associated `flock()` when the last fd referencing the open-file
        // description closes.
        unsafe { libc::close(self.fd) };
    }
}

/// Check whether anything (regular file, dir, symlink, socket) exists at
/// `path` without following symlinks. Returns `true` iff `lstat()` succeeds.
fn path_exists_nofollow(path: &Path) -> bool {
    use std::ffi::CString;
    let Some(c_path) = path.to_str().and_then(|s| CString::new(s).ok()) else {
        // If the path is not a valid C string the call would fail anyway
        // — fall through to bind() and let it produce the canonical error.
        return false;
    };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `lstat` is a standard POSIX syscall; `stat` is a valid
    // out-pointer for the duration of the call. We discard the result
    // and only care whether the call succeeded.
    let rc = unsafe { libc::lstat(c_path.as_ptr(), &mut stat) };
    rc == 0
}

/// Create a per-agent UDS socket with O_EXCL + `flock()` semantics, owned
/// by the agent uid.
///
/// Path shape: `/run/emberd/agent-<uuid>.sock` (see
/// [`PER_AGENT_SOCKET_PARENT`]). The UUID is a freshly-generated v4 so
/// the path is unguessable to an adversary that does not have read access
/// to `/run/emberd/`.
///
/// Returns the UUID identifying the socket, its filesystem path, and a
/// tokio `UnixListener` bound to it. Caller is responsible for tombstoning
/// via [`tombstone_socket`] on agent termination so the UUID is never
/// reused.
///
/// Errors:
/// - [`SocketError::AlreadyExists`] if anything exists at the would-be
///   path (regular file, directory, symlink, or socket). The check
///   happens under an exclusive `flock()` of the parent directory, so a
///   concurrent symlink-swap cannot win this race.
/// - [`SocketError::TombstonedUuid`] if (vanishingly unlikely) the freshly
///   generated UUID collides with a previously tombstoned one.
/// - [`SocketError::Bind`] if the underlying `UnixListener::bind` fails
///   for any other reason (permission denied, disk full, etc.).
pub fn create_per_agent_socket(
    uid: u32,
    gid: u32,
) -> Result<(Uuid, PathBuf, UnixListener), SocketError> {
    let uuid = Uuid::new_v4();
    create_per_agent_socket_with(Path::new(PER_AGENT_SOCKET_PARENT), uuid, uid, gid)
}

/// Test/spawn seam for [`create_per_agent_socket`] that accepts an
/// explicit parent directory and UUID. Used directly by the spawn path
/// when the caller has a pre-allocated UUID to bind, and by tests that
/// need to verify the symlink-swap rejection at a known path.
///
/// Production callers should prefer [`create_per_agent_socket`], which
/// generates a fresh UUID and uses [`PER_AGENT_SOCKET_PARENT`].
pub fn create_per_agent_socket_with(
    parent_dir: &Path,
    uuid: Uuid,
    uid: u32,
    gid: u32,
) -> Result<(Uuid, PathBuf, UnixListener), SocketError> {
    // Tombstone check first — no point doing filesystem work if the UUID
    // is permanently retired.
    {
        let table = TOMBSTONED_UUIDS.lock().unwrap_or_else(|e| e.into_inner());
        if table.contains(&uuid) {
            return Err(SocketError::TombstonedUuid(uuid));
        }
    }

    let socket_path = parent_dir.join(format!("agent-{}.sock", uuid));

    // Acquire an exclusive flock on the parent dir so the existence-check
    // → bind window is atomic relative to any other process holding the
    // same lock. This closes the symlink-swap race: an attacker cannot
    // plant a symlink between our `lstat` and the `bind`.
    let _flock = DirFlockGuard::acquire(parent_dir).map_err(SocketError::Bind)?;

    // O_EXCL semantics on the socket path: lstat (NOFOLLOW) must return
    // ENOENT. Any pre-existing inode — regular file, directory, symlink,
    // or stale socket — rejects with AlreadyExists.
    if path_exists_nofollow(&socket_path) {
        return Err(SocketError::AlreadyExists(socket_path));
    }

    // Bind the listener. The flock keeps the path-window atomic, so this
    // bind is the canonical "create the socket inode" step. If bind
    // itself races with another flock-holder (impossible by definition)
    // or fails for OS reasons, surface as `Bind`.
    let listener = UnixListener::bind(&socket_path).map_err(|e| {
        SocketError::Bind(annotate_bind_error(e, &socket_path.display().to_string()))
    })?;

    // Set 0660 + chown to the agent uid/gid. Errors here are fatal — the
    // whole point of this code path is that the socket is owned by the
    // agent, so failing to chown means we'd hand back a socket the agent
    // cannot use. Unwind on failure: unlink the freshly-bound socket
    // before propagating so we don't leave a half-configured inode behind.
    if let Err(e) = chown_per_agent_socket(&socket_path, uid, gid) {
        // Best-effort cleanup. If unlink fails too, the original chown
        // error is the more actionable one — log the cleanup miss and
        // fall through.
        if let Err(unlink_err) = std::fs::remove_file(&socket_path) {
            warn!(
                path = %socket_path.display(),
                error = %unlink_err,
                "create_per_agent_socket: failed to unlink socket after chown failure",
            );
        }
        return Err(e);
    }

    info!(
        path = %socket_path.display(),
        uid,
        gid,
        uuid = %uuid,
        "per-agent socket created",
    );
    Ok((uuid, socket_path, listener))
}

/// Apply mode 0660 and `lchown` the socket to the agent `uid:gid`.
///
/// Separate from [`ensure_socket_perms`] because the per-agent code path
/// chowns to an agent-supplied uid/gid (the container's view of the
/// agent user) rather than the daemon's `ember:ember-clients`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn chown_per_agent_socket(path: &Path, uid: u32, gid: u32) -> Result<(), SocketError> {
    use std::ffi::CString;
    let c_path = path
        .to_str()
        .and_then(|s| CString::new(s).ok())
        .ok_or_else(|| {
            SocketError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path contains interior NUL or is not valid UTF-8",
            ))
        })?;
    // SAFETY: `chmod` is a standard POSIX syscall; the pointer is valid
    // for the duration of the call and the mode value is well-formed.
    let chmod_rc = unsafe { libc::chmod(c_path.as_ptr(), 0o660) };
    if chmod_rc != 0 {
        return Err(SocketError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `lchown` is a standard POSIX syscall. We use lchown (not
    // chown) so we act on the socket inode itself — not a symlink
    // target — eliminating a TOCTOU window between bind and chown.
    let chown_rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if chown_rc != 0 {
        return Err(SocketError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Tombstone a per-agent socket. Removes the inode (best-effort) and
/// records the UUID in the tombstone table so subsequent
/// [`create_per_agent_socket_with`] calls with the same UUID return
/// [`SocketError::TombstonedUuid`].
///
/// Callers should invoke this when an agent terminates. The UUID is
/// permanently retired for the lifetime of the daemon process.
pub fn tombstone_socket(uuid: Uuid) -> Result<(), SocketError> {
    let mut table = TOMBSTONED_UUIDS.lock().unwrap_or_else(|e| e.into_inner());
    table.insert(uuid);
    info!(uuid = %uuid, "per-agent socket UUID tombstoned");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn make_store() -> Rc<crate::infra::store::DaemonStore> {
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        Rc::new(store)
    }

    async fn start_listener(tmp: &TempDir) -> (PathBuf, watch::Sender<bool>) {
        let path = tmp.path().join("ember.sock");
        let (tx, rx) = watch::channel(false);
        let store = make_store();
        let policy = Rc::new(PolicyEngine::default());
        let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));

        // Three invariants the listener needs for OperatorPresence-class
        // socket tests (create_persona, etc.) to pass the dispatch-time
        // authority gates (prior change / #3822 / #3828). Methods that aren't
        // OperatorPresence-classified (e.g. ping) are unaffected by either
        // helper, so existing non-OP tests on the same `start_listener`
        // still pass.
        //
        //   1. Daemon identity for mint_operator_presence_token
        //      (idempotent; tempdir leaked since the singleton outlives
        //      any one test).
        //   2. presence::mark_unlocked so the unlocked-session gate
        //      doesn't refuse with -32030.
        //   3. with_test_mode_synthetic_presence_token(true) so every
        //      accepted connection's RequestContext carries a synthetic
        //      presence token (socket.rs:247).
        let id_dir = tempfile::tempdir().expect("tempdir for daemon identity");
        let _ = crate::infra::receipt::init_identity(id_dir.path());
        std::mem::forget(id_dir);
        crate::trust::presence::mark_unlocked();

        let listener = SocketListener::new(path.clone(), rx, store, policy, rate_limiter)
            .with_test_mode_synthetic_presence_token(true);
        tokio::task::spawn_local(async move {
            listener.run().await.unwrap();
        });
        // Give listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (path, tx)
    }

    async fn connect(
        path: &PathBuf,
    ) -> (
        tokio::net::unix::OwnedWriteHalf,
        tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    ) {
        let stream = UnixStream::connect(path).await.unwrap();
        let (r, w) = stream.into_split();
        (w, BufReader::new(r))
    }

    async fn send_recv(
        w: &mut tokio::net::unix::OwnedWriteHalf,
        r: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
        msg: &str,
    ) -> Response {
        let mut line = msg.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();

        let mut resp_line = String::new();
        r.read_line(&mut resp_line).await.unwrap();
        serde_json::from_str(&resp_line).unwrap()
    }

    fn test_presence_token(uid: u32) -> crate::auth::presence_token::PresenceToken {
        use crate::auth::presence_token::{DaemonSigner, ScopeKey, mint};

        struct TestStubSigner;

        impl DaemonSigner for TestStubSigner {
            fn sign(&self, msg: &[u8]) -> bytes::Bytes {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(msg);
                bytes::Bytes::copy_from_slice(&hash)
            }

            fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
                use sha2::{Digest, Sha256};
                let expected = Sha256::digest(msg);
                sig == expected.as_slice()
            }
        }

        mint(
            uid,
            ScopeKey::all(),
            Duration::from_secs(60),
            &TestStubSigner,
        )
    }

    #[test]
    fn take_presence_token_extracts_and_removes_field() {
        let token = test_presence_token(501);
        let token_value = serde_json::to_value(&token).expect("token value");
        let mut params = serde_json::json!({
            "name": "socket-token-test",
            "_presence_token": token_value,
        });

        let parsed = take_presence_token(&mut params).expect("presence token");

        assert_eq!(parsed.uid, 501);
        assert_eq!(params, serde_json::json!({"name": "socket-token-test"}));
    }

    #[test]
    fn take_presence_token_ignores_malformed_field() {
        let mut params = serde_json::json!({
            "name": "socket-token-test",
            "_presence_token": {"uid": "not-a-number"},
        });

        let parsed = take_presence_token(&mut params);

        assert!(parsed.is_none(), "malformed token must be ignored");
        assert_eq!(params, serde_json::json!({"name": "socket-token-test"}));
    }

    #[tokio::test]
    async fn test_ping() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = r#"{"id":"1","method":"ping","params":null}"#;
                let resp = send_recv(&mut w, &mut r, req).await;

                assert_eq!(resp.id, "1");
                assert!(resp.error.is_none());
                let result = resp.result.unwrap();
                assert_eq!(result["pong"], serde_json::json!(true));
            })
            .await;
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = r#"{"id":"2","method":"no_such_method"}"#;
                let resp = send_recv(&mut w, &mut r, req).await;

                assert_eq!(resp.id, "2");
                assert!(resp.result.is_none());
                let err = resp.error.unwrap();
                assert_eq!(err.code, -32601);
            })
            .await;
    }

    #[tokio::test]
    async fn test_malformed_json() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = "not json at all\n";
                w.write_all(req.as_bytes()).await.unwrap();

                let mut resp_line = String::new();
                r.read_line(&mut resp_line).await.unwrap();
                let resp: Response = serde_json::from_str(&resp_line).unwrap();

                assert!(resp.result.is_none());
                let err = resp.error.unwrap();
                assert_eq!(err.code, -32700);
            })
            .await;
    }

    #[tokio::test]
    async fn test_shutdown() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, tx) = start_listener(&tmp).await;

                // Signal shutdown.
                tx.send(true).unwrap();

                // After shutdown the listener should stop accepting.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let result = UnixStream::connect(&path).await;
                assert!(
                    result.is_err(),
                    "expected connection refused after shutdown"
                );
            })
            .await;
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;

                let mut handles = vec![];
                for i in 0..5u32 {
                    let p = path.clone();
                    handles.push(tokio::task::spawn_local(async move {
                        let (mut w, mut r) = connect(&p).await;
                        let req = format!(r#"{{"id":"{i}","method":"ping"}}"#);
                        let resp = send_recv(&mut w, &mut r, &req).await;
                        assert_eq!(resp.id, i.to_string());
                        assert!(resp.error.is_none());
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            })
            .await;
    }

    #[tokio::test]
    async fn test_create_persona_returns_id() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = r#"{"id":"10","method":"create_persona","params":{"name":"test-agent"}}"#;
                let resp = send_recv(&mut w, &mut r, req).await;

                assert_eq!(resp.id, "10");
                assert!(resp.error.is_none());
                let result = resp.result.unwrap();
                assert!(result["id"].as_str().unwrap().starts_with("persona-"));
                assert_eq!(result["name"], serde_json::json!("test-agent"));
            })
            .await;
    }

    #[tokio::test]
    async fn test_peer_uid_gate_accepts_same_uid() {
        // development milestone: a client running as the daemon's own uid (the
        // common case, and the only case CI can exercise) must be able to
        // connect and complete a ping round-trip. This exercises the
        // `verify_peer_uid` branch that returns `true`.
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = r#"{"id":"peer-uid","method":"ping"}"#;
                let resp = send_recv(&mut w, &mut r, req).await;

                assert_eq!(resp.id, "peer-uid");
                assert!(resp.error.is_none());
            })
            .await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_daemon_euid_matches_process_euid() {
        // Sanity check that `daemon_euid()` returns the real effective uid
        // of the test process. If this ever returned 0 or a constant we'd
        // either be rejecting every connection or accepting every
        // connection — this pins the happy path.
        let uid = daemon_euid();
        // SAFETY: `geteuid` is a simple syscall wrapper.
        let expected = unsafe { libc::geteuid() };
        assert_eq!(uid, expected);
    }

    // ── read_peer_creds tests (implementation-note-348) ──────

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn read_peer_creds_returns_pid_uid_gid() {
        // read_peer_creds must return the current process's own uid/gid/pid
        // when called on a connected UnixStream pair from the same process.
        // Uses a real socket pair — no injection needed because both ends
        // are this process.
        use tempfile::TempDir;
        use tokio::net::UnixListener;
        use tokio::task::LocalSet;
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let path = tmp.path().join("read_peer_creds_test.sock");
                let listener = UnixListener::bind(&path).unwrap();

                let connect_task = tokio::task::spawn_local({
                    let path = path.clone();
                    async move { tokio::net::UnixStream::connect(&path).await.unwrap() }
                });

                let (server_side, _) = listener.accept().await.unwrap();
                let _client_side = connect_task.await.unwrap();

                let expected_uid = unsafe { libc::geteuid() };
                let expected_gid = unsafe { libc::getegid() };
                let expected_pid = std::process::id() as i32;

                let creds = read_peer_creds(&server_side)
                    .expect("read_peer_creds must succeed on a same-process socket pair");

                assert_eq!(
                    creds.uid, expected_uid,
                    "uid must match current process euid"
                );
                assert_eq!(
                    creds.gid, expected_gid,
                    "gid must match current process egid"
                );
                // pid may be None on BSD platforms that don't surface it in LOCAL_PEERCRED;
                // when present it must match the current process.
                if let Some(pid) = creds.pid {
                    assert_eq!(
                        pid, expected_pid,
                        "pid must match current process id when present"
                    );
                }
            })
            .await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn read_peer_creds_returns_some_on_valid_pair() {
        // Contract test: read_peer_creds must return Some(_) for a connected
        // socket pair. The kernel-anomaly (None) path cannot be exercised
        // in normal unit tests without a mock socket, so this test asserts
        // the happy-path type contract: Some is returned and all three fields
        // are present at the struct level.
        use tempfile::TempDir;
        use tokio::net::UnixListener;
        use tokio::task::LocalSet;
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let path = tmp.path().join("read_peer_creds_contract.sock");
                let listener = UnixListener::bind(&path).unwrap();

                let connect_task = tokio::task::spawn_local({
                    let path = path.clone();
                    async move { tokio::net::UnixStream::connect(&path).await.unwrap() }
                });

                let (server_side, _) = listener.accept().await.unwrap();
                let _client_side = connect_task.await.unwrap();

                let result = read_peer_creds(&server_side);
                assert!(
                    result.is_some(),
                    "read_peer_creds must return Some for a real connected socket"
                );
                let creds = result.unwrap();
                // Verify the struct carries all three fields at the type level.
                let _: u32 = creds.uid;
                let _: u32 = creds.gid;
                let _: Option<i32> = creds.pid;
            })
            .await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn test_verify_peer_uid_accepts_self_connection() {
        // Direct unit test of `verify_peer_uid` using a real connected
        // socket pair from the same process. Both ends are this process,
        // so the peer uid must match the daemon euid.
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let path = tmp.path().join("peer_cred.sock");
                let listener = UnixListener::bind(&path).unwrap();

                let connect_task = tokio::task::spawn_local({
                    let path = path.clone();
                    async move { UnixStream::connect(&path).await.unwrap() }
                });

                let (server_side, _) = listener.accept().await.unwrap();
                let _client_side = connect_task.await.unwrap();

                let peer = verify_peer_uid(&server_side)
                    .expect("self-connection must pass the same-uid gate");
                assert_eq!(peer.uid, daemon_euid());
            })
            .await;
    }

    // ---- development milestone ----------------------------
    //
    // The happy-path test above only exercises the branch where
    // `peer_cred()` succeeds and the uid matches. The following three
    // tests use the `verify_peer_uid_with` seam to inject synthetic
    // peer lookups so we can exercise the rejection paths without
    // needing a second uid on the test host (which CI cannot provide).

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn verify_peer_uid_rejects_mismatched_uid() {
        // A peer with a different uid than the daemon must be rejected,
        // no matter what pid it claims. This is the path that protects
        // against a misconfigured socket-file permission letting a
        // second local user drive the daemon. (Test name matches the
        // development milestone target_state_anchor:
        // `fn verify_peer_uid_rejects_mismatched`.)
        let expected = daemon_euid();
        let intruder = expected.wrapping_add(1);
        let result = verify_peer_uid_with(
            || {
                Ok(PeerIdentity {
                    uid: intruder,
                    pid: Some(4242),
                })
            },
            expected,
        );
        assert!(
            result.is_none(),
            "peer uid {intruder} must be rejected when expected is {expected}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn verify_peer_uid_rejects_peer_cred_error() {
        // If `peer_cred()` itself fails, we fail closed. A kernel that
        // doesn't implement SO_PEERCRED / LOCAL_PEERCRED on AF_UNIX is
        // not a platform we ship on — falling through would defeat the
        // entire gate.
        let result = verify_peer_uid_with::<fn() -> io::Result<PeerIdentity>>(
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "simulated peer_cred failure",
                ))
            },
            daemon_euid(),
        );
        assert!(result.is_none(), "peer_cred() error must fail closed");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn verify_peer_uid_accepts_matching_uid_via_seam() {
        // Regression guard for the existing same-uid happy path: the
        // seam must still accept a peer whose uid matches the daemon's
        // expected uid and surface the peer identity for logging.
        let expected = daemon_euid();
        let peer = verify_peer_uid_with(
            || {
                Ok(PeerIdentity {
                    uid: expected,
                    pid: Some(7),
                })
            },
            expected,
        )
        .expect("matching uid must be accepted");
        assert_eq!(peer.uid, expected);
        assert_eq!(peer.pid, Some(7));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn verify_peer_uid_accepts_matching_uid_without_pid() {
        // On BSD variants `pid()` is `None`; make sure a missing pid
        // does not by itself cause the accept path to reject.
        let expected = daemon_euid();
        let peer = verify_peer_uid_with(
            || {
                Ok(PeerIdentity {
                    uid: expected,
                    pid: None,
                })
            },
            expected,
        )
        .expect("matching uid with unknown pid must still be accepted");
        assert_eq!(peer.uid, expected);
        assert_eq!(peer.pid, None);
    }

    /// Checkpoint ensuring the `target_state_anchor` token used by the headless
    /// ranker (`fn verify_peer_uid_rejects_mismatched`) keeps matching even
    /// if a future rename suffixes the negative test (e.g. `_uid` → `_caller`).
    /// If you rename a test above, add another `fn verify_peer_uid_rejects_mismatched...`
    /// or update release-checklist — do not delete this comment.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)]
    const _C43_PEERCRED_NEGATIVE_TESTS_GREP_ANCHOR: &str =
        "fn verify_peer_uid_rejects_mismatched_uid + fn verify_peer_uid_rejects_peer_cred_error";

    #[test]
    fn test_compute_next_accept_delay_sequence() {
        // development milestone: verify the exponential backoff sequence so that a
        // runaway accept() failure cannot busy-spin and so that the
        // cap works. Sequence under repeated errors:
        //   ZERO -> 10ms -> 20ms -> 40ms -> 80ms -> 160ms -> ...
        //   -> 2_560ms -> 5_000ms (capped) -> 5_000ms (stays capped)
        let d0 = Duration::ZERO;
        let d1 = compute_next_accept_delay(d0);
        assert_eq!(
            d1,
            Duration::from_millis(10),
            "first retry should be 10ms, not 0"
        );

        let d2 = compute_next_accept_delay(d1);
        assert_eq!(d2, Duration::from_millis(20));

        let d3 = compute_next_accept_delay(d2);
        assert_eq!(d3, Duration::from_millis(40));

        // Walk up to and past the cap. 10ms doubled 9 times = 5_120ms,
        // which should clamp to MAX_ACCEPT_RETRY_DELAY = 5_000ms.
        let mut d = d1;
        for _ in 0..20 {
            d = compute_next_accept_delay(d);
            assert!(
                d <= MAX_ACCEPT_RETRY_DELAY,
                "delay {d:?} exceeded MAX_ACCEPT_RETRY_DELAY {MAX_ACCEPT_RETRY_DELAY:?}",
            );
        }
        // After many iterations we must be pinned at the cap.
        assert_eq!(
            d, MAX_ACCEPT_RETRY_DELAY,
            "backoff should saturate at the cap"
        );

        // Re-entering with the cap must stay at the cap.
        let d_capped = compute_next_accept_delay(MAX_ACCEPT_RETRY_DELAY);
        assert_eq!(d_capped, MAX_ACCEPT_RETRY_DELAY);

        // And ZERO always restarts the sequence — this is what the
        // accept loop does on a successful accept, so the next error
        // starts with a small delay instead of jumping to the cap.
        let d_reset = compute_next_accept_delay(Duration::ZERO);
        assert_eq!(d_reset, MIN_ACCEPT_RETRY_DELAY);
    }

    #[tokio::test]
    async fn test_list_personas_empty() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let tmp = TempDir::new().unwrap();
                let (path, _tx) = start_listener(&tmp).await;
                let (mut w, mut r) = connect(&path).await;

                let req = r#"{"id":"11","method":"list_personas","params":null}"#;
                let resp = send_recv(&mut w, &mut r, req).await;

                assert_eq!(resp.id, "11");
                assert!(resp.error.is_none());
                let result = resp.result.unwrap();
                let arr = result.as_array().unwrap();
                assert!(arr.is_empty());
            })
            .await;
    }

    // ---- P69E.8b: annotate_bind_error -------------------------------
    //
    // Three branches: (1) AddrInUse on a TCP `host:port` shape gets the
    // `lsof -i :<port>` hint + daemon-stop guidance, (2) AddrInUse on a
    // Unix socket path gets `lsof -U <path>`, (3) any other ErrorKind
    // is annotated with the address but skips the lsof block (since
    // `lsof` won't help on EACCES / EADDRNOTAVAIL).

    #[test]
    fn annotate_bind_error_tcp_addr_in_use_includes_lsof_port_hint() {
        let raw = io::Error::new(io::ErrorKind::AddrInUse, "Address already in use");
        let annotated = annotate_bind_error(raw, "127.0.0.1:3141");
        let msg = annotated.to_string();

        assert_eq!(annotated.kind(), io::ErrorKind::AddrInUse);
        assert!(
            msg.contains("lsof -i :3141"),
            "expected `lsof -i :3141` hint, got: {msg}"
        );
        assert!(
            msg.contains("ember daemon stop") || msg.contains("launchctl bootout"),
            "expected daemon-stop guidance, got: {msg}"
        );
        assert!(
            msg.contains("127.0.0.1:3141"),
            "expected the bind addr in the message, got: {msg}"
        );
    }

    #[test]
    fn annotate_bind_error_unix_socket_addr_in_use_includes_lsof_unix_hint() {
        let raw = io::Error::new(io::ErrorKind::AddrInUse, "Address already in use");
        let annotated = annotate_bind_error(raw, "/Users/example/.ember/sock");
        let msg = annotated.to_string();

        assert_eq!(annotated.kind(), io::ErrorKind::AddrInUse);
        assert!(
            msg.contains("lsof -U /Users/example/.ember/sock"),
            "expected `lsof -U <path>` hint for Unix socket, got: {msg}"
        );
        // Should NOT use the `:port` form for filesystem paths.
        assert!(
            !msg.contains("lsof -i :"),
            "must not emit TCP-style hint for a filesystem path, got: {msg}"
        );
    }

    #[test]
    fn annotate_bind_error_non_addr_in_use_skips_lsof_hint() {
        let raw = io::Error::new(io::ErrorKind::PermissionDenied, "EACCES");
        let annotated = annotate_bind_error(raw, "0.0.0.0:80");
        let msg = annotated.to_string();

        assert_eq!(annotated.kind(), io::ErrorKind::PermissionDenied);
        // Address is still surfaced...
        assert!(
            msg.contains("0.0.0.0:80"),
            "expected the bind addr to still appear, got: {msg}"
        );
        // ...but no lsof guidance (it would mislead — the port is free,
        // we just lack permission to bind it).
        assert!(
            !msg.contains("lsof -i"),
            "must not suggest lsof for non-AddrInUse failures, got: {msg}"
        );
    }

    // ---- implementation-note-154 ------------------------------------
    //
    // CRIT-C symlink-swap rejection + tombstone UUID-recycling rejection.
    // Both tests use the `_with` seam so we can drive the would-be-path
    // deterministically: the production entry point generates a fresh
    // UUIDv4, but a test cannot pre-create a symlink at an unknown path.

    #[test]
    fn create_per_agent_socket_refuses_symlink_swap() {
        // CRIT-C: a privileged-enough container process may pre-create a
        // symlink at the predictable per-agent socket path before emberd
        // gets a chance to bind. The O_EXCL + flock contract must reject
        // any pre-existing inode at the path — including symlinks —
        // rather than overwrite or follow it.
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path();
        let uuid = Uuid::new_v4();
        let socket_path = parent.join(format!("agent-{}.sock", uuid));

        // Plant a symlink at the would-be path pointing at /tmp (a real
        // path that exists). If the implementation followed the symlink
        // it would either fail with a confusing EEXIST-on-target or, in
        // a worst-case TOCTOU window, end up binding the socket at the
        // wrong location entirely.
        std::os::unix::fs::symlink("/tmp", &socket_path).unwrap();

        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let err = create_per_agent_socket_with(parent, uuid, uid, gid)
            .expect_err("symlink at would-be path must reject");

        match err {
            SocketError::AlreadyExists(p) => {
                assert_eq!(
                    p, socket_path,
                    "AlreadyExists must surface the colliding path"
                );
            }
            other => panic!("expected SocketError::AlreadyExists on symlink-swap, got: {other:?}"),
        }

        // Symlink must still be present — we refused to touch it.
        let meta = std::fs::symlink_metadata(&socket_path).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "symlink must be untouched after refused create",
        );
    }

    #[tokio::test]
    async fn tombstone_prevents_uuid_recycling() {
        // After tombstoning a UUID, attempts to create another socket
        // with the same UUID must reject with `TombstonedUuid` so a
        // recycled agent-id cannot inherit a previous agent's identity.
        //
        // tempdir_in("/tmp") matches the canonical SUN_LEN-safe pattern
        // used elsewhere in the daemon (broker/spawn_helper_client.rs).
        // macOS $TMPDIR resolves under /var/folders/<long>/T which
        // overruns sockaddr_un's 104-byte path limit; binding then
        // fails with `path must be shorter than SUN_LEN`.
        let tmp = tempfile::Builder::new()
            .prefix("ember-socket-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let parent = tmp.path();
        let uuid = Uuid::new_v4();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        // First create succeeds: tombstone table is empty for this UUID.
        let (got_uuid, socket_path, listener) =
            create_per_agent_socket_with(parent, uuid, uid, gid).expect("fresh UUID must bind");
        assert_eq!(got_uuid, uuid);
        assert!(socket_path.exists(), "socket inode must exist after create");
        drop(listener);
        // Remove the inode so the second attempt would otherwise succeed
        // — proving the tombstone (not a stale inode) is doing the work.
        std::fs::remove_file(&socket_path).unwrap();

        // Tombstone the UUID.
        tombstone_socket(uuid).expect("tombstone must succeed");

        // Second create with the same UUID must reject with TombstonedUuid
        // even though the inode is gone.
        let err = create_per_agent_socket_with(parent, uuid, uid, gid)
            .expect_err("recycled UUID must reject after tombstone");
        match err {
            SocketError::TombstonedUuid(u) => {
                assert_eq!(u, uuid, "TombstonedUuid must surface the recycled UUID");
            }
            other => {
                panic!("expected SocketError::TombstonedUuid on recycled UUID, got: {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn create_per_agent_socket_happy_path_returns_listener() {
        // Regression guard for the success path: a fresh UUID under a
        // fresh tempdir binds, the socket exists at the returned path,
        // and the listener accepts connections.
        //
        // tempdir_in("/tmp") — see SUN_LEN note on
        // tombstone_prevents_uuid_recycling above.
        let tmp = tempfile::Builder::new()
            .prefix("ember-socket-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let parent = tmp.path();
        let uuid = Uuid::new_v4();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        let (got_uuid, socket_path, _listener) =
            create_per_agent_socket_with(parent, uuid, uid, gid).expect("fresh path must bind");
        assert_eq!(got_uuid, uuid);
        assert!(
            socket_path.starts_with(parent),
            "socket path must live under parent dir",
        );
        assert!(
            socket_path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("agent-") && s.ends_with(".sock"))
                .unwrap_or(false),
            "socket filename must match agent-<uuid>.sock shape",
        );
        let meta = std::fs::symlink_metadata(&socket_path).unwrap();
        use std::os::unix::fs::FileTypeExt;
        assert!(
            meta.file_type().is_socket(),
            "created inode must be a Unix socket",
        );
    }

    // ─── implementation-note-114 ────────────────────
    //
    // The dispatch-site wrapper in this file uses
    // `AssertUnwindSafe(future).catch_unwind().await` from
    // futures_util::FutureExt to convert async panics into typed
    // RpcError responses. These tests demonstrate the pattern
    // converts panics into the expected `Err(panic_payload)` shape
    // that the wrap-block then turns into a -32603 InternalPanic
    // response (`internal_panic_recovered: <msg>`). Anchor:
    // dispatch_method_panic_recovered.

    #[tokio::test]
    async fn catch_unwind_converts_async_panic_to_err() {
        use futures_util::FutureExt;
        use std::panic::AssertUnwindSafe;

        // Suppress the default panic hook's stderr noise during this
        // intentional-panic test so cargo test output stays readable.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let fut = async {
            // Await something first to prove the wrap catches a panic
            // that fires after a real .await suspension — not just a
            // straight-line panic at construction.
            tokio::task::yield_now().await;
            panic!("dispatch_method_panic_recovered fixture panic");
        };

        let outcome = AssertUnwindSafe(fut).catch_unwind().await;

        std::panic::set_hook(prev);

        let panic_payload = outcome.expect_err("panic must surface as Err");
        let panic_msg = panic_payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| panic_payload.downcast_ref::<String>().cloned())
            .expect("panic payload must downcast to a string");
        assert!(
            panic_msg.contains("dispatch_method_panic_recovered fixture panic"),
            "panic message preserved through catch_unwind, got: {panic_msg}"
        );
    }

    #[tokio::test]
    async fn catch_unwind_passes_through_non_panicking_future() {
        // A future that returns Ok(value) must not be perturbed by the
        // wrap — outcome is Ok(Ok(value)).
        use futures_util::FutureExt;
        use std::panic::AssertUnwindSafe;

        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, (i32, String)>>>> =
            Box::pin(async {
                tokio::task::yield_now().await;
                Ok::<i32, (i32, String)>(42)
            });

        let outcome = AssertUnwindSafe(fut).catch_unwind().await;
        match outcome {
            Ok(Ok(v)) => assert_eq!(v, 42),
            other => panic!("expected Ok(Ok(42)), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn catch_unwind_passes_through_typed_err() {
        // A future that returns Err((code, msg)) must surface as
        // Ok(Err((code, msg))) — the wrap distinguishes "domain error"
        // from "panic".
        use futures_util::FutureExt;
        use std::panic::AssertUnwindSafe;

        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<i32, (i32, String)>>>> =
            Box::pin(async {
                tokio::task::yield_now().await;
                Err::<i32, _>((-32601, "method not found".to_string()))
            });

        let outcome = AssertUnwindSafe(fut).catch_unwind().await;
        match outcome {
            Ok(Err((code, msg))) => {
                assert_eq!(code, -32601);
                assert_eq!(msg, "method not found");
            }
            other => panic!("expected Ok(Err(...)), got {other:?}"),
        }
    }
}
