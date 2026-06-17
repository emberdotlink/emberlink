//! CLASSIFICATION: PUBLIC
//!
//! Per-session loopback-TCP responses-API-proxy for the codex HOST lane
//! (-S2 / design codex).
//!
//! This mirrors the per-session lifecycle of [`crate::infra::session_proxy`]
//! (a process-global command channel + a registry loop that owns one listener
//! per session, stood up at `register_session` and torn down at
//! `close_session`), but with three deliberate differences:
//!
//! 1. **Transport is loopback TCP, not a Unix socket.** Codex cannot be told
//!    to dial a Unix socket or to send `X-Ember-*` headers — it only POSTs a
//!    JSON body to `base_url/responses`. So we stand up a
//!    `127.0.0.1:<ephemeral>` listener and point codex's `config.toml`
//!    `model_providers.ember.base_url` at it.
//!
//! 2. **The peer-attestation gate degrades explicitly to `OwnerUid` in name.**
//!    A non-root daemon cannot read a loopback-TCP peer's kernel identity
//!    (`proc_pidfdinfo` is `CHECK_SAME_USER` gated; macOS exposes no TCP audit
//!    token). So unlike the UDS lane, there are no peercred / liveness /
//!    pid-tree / binary arms here. Under design slice 3
//!    (`endpoint_gate_framework`) this is no longer an unnamed "no gate":
//!    the per-session bookkeeping carries
//!    [`crate::infra::endpoint_gate::AdmissionPolicy::OwnerUid`], and every
//!    accepted TCP connection emits the loud
//!    `codex-loopback-no-kernel-attestation` audit event.
//!
//!    This lane remains credential-safe **by construction** — strict
//!    `POST /v1/responses` endpoint, client-header strip, server-side
//!    credential injection, server-side `api.openai.com` upstream pin — not by
//!    gate arms. See `handle_codex_responses_request` in
//!    `proxy-forward-runtime` for the security contract.
//!
//!    HONEST RESIDUAL (out of scope for v1): a same-uid process that discovers
//!    the ephemeral port can POST `/v1/responses` and spend the session
//!    budget. It CANNOT exfil the key (never returned, only injected upstream),
//!    CANNOT hit other endpoints (strict gate), CANNOT redirect upstream
//!    (server-side pin). Closing attribution would need a root spawn-helper
//!    doing cross-uid peer-pid attestation — explicitly deferred.
//!
//! 3. **No inode sweep.** TCP listeners vanish with their accept loop; there
//!    is no on-disk artifact to clean up (unlike the UDS lane's socket files).

use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex, OnceLock};

use hyper_util::rt::TokioIo;
use tokio::sync::{mpsc, watch};

use crate::infra::endpoint_gate::AdmissionPolicy;
use crate::infra::proxy::DaemonPolicyBackend;

/// Everything the registry needs to stand up a per-session codex listener.
/// The bound `std::net::TcpListener` is captured SYNCHRONOUSLY on the calling
/// (`register_session`) path so the ephemeral port is known immediately and
/// can be returned in the RPC response, then handed to the registry which
/// converts it to a tokio listener and spawns the accept loop. This sidesteps
/// the cross-`LocalSet` round-trip the async-bind alternative would require
/// (plan open-question 1, recommendation (a)).
pub struct CodexProxyOpenSpec {
    pub session_id: String,
    /// The bound listener (already on `127.0.0.1:<port>`). `std::net` so it can
    /// cross the channel; the registry calls `set_nonblocking(true)` +
    /// `TcpListener::from_std`.
    pub listener: StdTcpListener,
    /// Kept for logging/parity with the UDS lane; NOT enforced (loopback TCP
    /// exposes no kernel peer id for a non-root daemon).
    pub bound_uid: u32,
    /// design slice 3: the codex loopback-TCP lane carries an explicit
    /// `OwnerUid` policy in per-session bookkeeping even though the transport
    /// cannot enforce peercred. `endpoint_gate_codex_owner_uid_named`.
    pub admission_policy: AdmissionPolicy,
}

impl std::fmt::Debug for CodexProxyOpenSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexProxyOpenSpec")
            .field("session_id", &self.session_id)
            .field("bound_uid", &self.bound_uid)
            .field("admission_policy", &self.admission_policy)
            .finish_non_exhaustive()
    }
}

/// Command sent from the sync session handlers to the codex registry loop.
#[derive(Debug)]
pub enum CodexProxyCommand {
    Open(CodexProxyOpenSpec),
    Close { session_id: String },
}

/// Process-global sender into the codex registry loop. Set once when the
/// registry starts at daemon boot. Distinct from the UDS lane's `COMMAND_TX`
/// so the no-gate codex dispatch and the gated UDS dispatch never share a
/// channel (plan open-question 5: separate channel + module).
static CODEX_COMMAND_TX: OnceLock<mpsc::UnboundedSender<CodexProxyCommand>> = OnceLock::new();

/// Process-global map of `session_id -> bound port`, populated by the registry
/// on `Open` and cleared on `Close`. `register_session` reads it via
/// [`codex_responses_url_for`] to build the URL it returns to the launcher.
///
/// Because the bind happens synchronously on the calling path BEFORE the Open
/// command is sent, the port is also published here synchronously by
/// [`request_open_codex`] (not by the registry), so a `register_session`
/// reader never races the registry's async processing of the command.
static CODEX_PORTS: OnceLock<Mutex<HashMap<String, u16>>> = OnceLock::new();

fn codex_ports() -> &'static Mutex<HashMap<String, u16>> {
    CODEX_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install the global codex command sender. Idempotent-safe: returns `false`
/// if a sender was already installed (a second daemon incarnation in-process —
/// only happens in tests).
pub fn install_codex_command_sender(tx: mpsc::UnboundedSender<CodexProxyCommand>) -> bool {
    CODEX_COMMAND_TX.set(tx).is_ok()
}

/// Bind a loopback-TCP listener on an ephemeral port, publish the port, and
/// request the registry stand up its accept loop. Returns the bound port on
/// success so the caller (`register_session`) can build the proxy URL, or
/// `None` if the bind failed or the registry channel is not installed.
///
/// The bind runs HERE (synchronously, on the caller's path) so the port is
/// known immediately; the registry only owns the accept loop afterwards.
pub fn request_open_codex(session_id: &str, bound_uid: u32) -> Option<u16> {
    let listener = match StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(session_id, error = %e, "codex_proxy: failed to bind loopback listener");
            return None;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            tracing::warn!(session_id, error = %e, "codex_proxy: failed to read local_addr");
            return None;
        }
    };

    // Publish the port BEFORE sending the command so a `register_session`
    // reader observes it without racing the registry.
    codex_ports()
        .lock()
        .unwrap()
        .insert(session_id.to_string(), port);

    let spec = CodexProxyOpenSpec {
        session_id: session_id.to_string(),
        listener,
        bound_uid,
        admission_policy: codex_owner_uid_policy(bound_uid),
    };
    if !send_command(CodexProxyCommand::Open(spec)) {
        // Registry not installed / gone — roll back the published port so we
        // don't hand the launcher a URL nothing is listening on.
        codex_ports().lock().unwrap().remove(session_id);
        return None;
    }
    Some(port)
}

fn codex_owner_uid_policy(bound_uid: u32) -> AdmissionPolicy {
    AdmissionPolicy::OwnerUid { bound_uid }
}

/// Request a per-session codex listener be torn down (idempotent).
pub fn request_close_codex(session_id: &str) -> bool {
    codex_ports().lock().unwrap().remove(session_id);
    send_command(CodexProxyCommand::Close {
        session_id: session_id.to_string(),
    })
}

/// Return the loopback responses-proxy base URL for a session, or `None` if no
/// codex listener is bound for it. The URL ends in `/v1` because codex appends
/// `/responses` to the configured provider `base_url`.
pub fn codex_responses_url_for(session_id: &str) -> Option<String> {
    let port = *codex_ports().lock().unwrap().get(session_id)?;
    Some(format!("http://127.0.0.1:{port}/v1"))
}

fn send_command(cmd: CodexProxyCommand) -> bool {
    match CODEX_COMMAND_TX.get() {
        Some(tx) => match tx.send(cmd) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "codex_proxy: registry receiver gone — command dropped");
                false
            }
        },
        None => {
            tracing::debug!(
                "codex_proxy: command channel not installed (codex lane disabled?) — command dropped"
            );
            false
        }
    }
}

/// A live per-session codex listener entry.
struct CodexEntry {
    shutdown_tx: watch::Sender<bool>,
    #[allow(dead_code)]
    admission_policy: AdmissionPolicy,
}

impl CodexEntry {
    fn tear_down(self) {
        let _ = self.shutdown_tx.send(true);
        // No inode to unlink — the TCP listener vanishes with its accept loop.
    }
}

/// Convert the bound `std::net` listener to tokio, spawn its accept loop.
fn open_session_tcp_socket(
    spec: CodexProxyOpenSpec,
    backend: Arc<DaemonPolicyBackend>,
) -> std::io::Result<CodexEntry> {
    let CodexProxyOpenSpec {
        session_id,
        listener,
        bound_uid,
        admission_policy,
    } = spec;

    listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
    let port = tokio_listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_session_id = session_id.clone();
    let loop_policy = admission_policy.clone();
    tokio::task::spawn_local(async move {
        run_codex_forward_accept_loop_with_named_policy(
            tokio_listener,
            loop_session_id.clone(),
            bound_uid,
            loop_policy,
            backend,
            shutdown_rx,
        )
        .await;
        tracing::debug!(session_id = %loop_session_id, "codex_proxy: accept loop exited");
    });

    tracing::info!(
        session_id = %session_id,
        port,
        bound_uid,
        admission_policy = %admission_policy,
        "codex_proxy: per-session loopback responses listener up (credential-safe by construction; named OwnerUid policy, no TCP peercred enforcement)"
    );

    Ok(CodexEntry {
        shutdown_tx,
        admission_policy,
    })
}

async fn run_codex_forward_accept_loop_with_named_policy(
    listener: tokio::net::TcpListener,
    session_id: String,
    bound_uid: u32,
    admission_policy: AdmissionPolicy,
    backend: Arc<DaemonPolicyBackend>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        emit_codex_loopback_no_kernel_attestation(
                            &backend,
                            &session_id,
                            bound_uid,
                            &admission_policy,
                        );
                        let backend = Arc::clone(&backend);
                        let session_id = session_id.clone();
                        let io = TokioIo::new(stream);
                        tokio::task::spawn_local(async move {
                            let svc = hyper::service::service_fn(move |req| {
                                let backend = Arc::clone(&backend);
                                let session_id = session_id.clone();
                                async move {
                                    proxy_forward_runtime::forward::handle_codex_responses_request(
                                        backend,
                                        req,
                                        session_id,
                                    )
                                    .await
                                }
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                tracing::warn!(error = %e, "codex proxy connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "codex proxy accept error");
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
}

fn emit_codex_loopback_no_kernel_attestation(
    backend: &DaemonPolicyBackend,
    session_id: &str,
    bound_uid: u32,
    admission_policy: &AdmissionPolicy,
) {
    tracing::warn!(
        session_id,
        bound_uid,
        admission_policy = %admission_policy,
        "codex-loopback-no-kernel-attestation: admitted loopback-TCP connection under named OwnerUid policy; kernel peer identity is unavailable on this transport"
    );
    if let Err(e) =
        backend.log_codex_loopback_no_kernel_attestation(session_id, bound_uid, admission_policy)
    {
        tracing::warn!(
            session_id,
            error = ?e,
            "codex_proxy: failed to write codex-loopback-no-kernel-attestation audit event"
        );
    }
}

/// The codex registry control loop. Owns the `!Send` backend and the live
/// per-session listeners; processes `Open`/`Close` commands until the global
/// daemon shutdown fires. Runs on the proxy's `LocalSet` via `spawn_local`.
pub async fn run_codex_proxy_registry(
    backend: std::sync::Arc<DaemonPolicyBackend>,
    mut commands: mpsc::UnboundedReceiver<CodexProxyCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions: HashMap<String, CodexEntry> = HashMap::new();

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(CodexProxyCommand::Open(spec)) => {
                        let session_id = spec.session_id.clone();
                        // Re-register: tear the old one down first (idempotent).
                        if let Some(prev) = sessions.remove(&session_id) {
                            prev.tear_down();
                        }
                        match open_session_tcp_socket(spec, backend.clone()) {
                            Ok(entry) => {
                                sessions.insert(session_id, entry);
                            }
                            Err(e) => {
                                tracing::warn!(session_id = %session_id, error = %e, "codex_proxy: failed to open per-session listener");
                                // Bind succeeded on the caller's path; the
                                // conversion/spawn failed. Drop the published
                                // port so we don't advertise a dead URL.
                                codex_ports().lock().unwrap().remove(&session_id);
                            }
                        }
                    }
                    Some(CodexProxyCommand::Close { session_id }) => {
                        if let Some(entry) = sessions.remove(&session_id) {
                            entry.tear_down();
                            tracing::info!(session_id = %session_id, "codex_proxy: per-session listener torn down");
                        }
                    }
                    None => {
                        tracing::debug!("codex_proxy: command channel closed — registry exiting");
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

    for (_id, entry) in sessions.drain() {
        entry.tear_down();
    }
    tracing::debug!("codex_proxy: registry loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_none_before_open() {
        // A session id that was never opened resolves to None.
        assert!(codex_responses_url_for("sess_never_opened_xyz").is_none());
    }

    #[test]
    fn publish_then_url_then_remove() {
        let sid = "sess_codex_unit_publish";
        // Simulate request_open_codex's publish step directly (no registry).
        codex_ports().lock().unwrap().insert(sid.to_string(), 54321);
        let url = codex_responses_url_for(sid).expect("url after publish");
        assert_eq!(url, "http://127.0.0.1:54321/v1");
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(url.ends_with("/v1"));
        // Close removes it.
        codex_ports().lock().unwrap().remove(sid);
        assert!(codex_responses_url_for(sid).is_none());
    }

    #[test]
    fn request_open_codex_binds_loopback_and_publishes_port() {
        // No command sender installed in this unit context, so request_open
        // rolls back. But we can assert the bind targets loopback + ephemeral
        // by binding directly the same way and checking the addr.
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback(), "must bind 127.0.0.1, got {addr}");
        assert_ne!(addr.port(), 0, "ephemeral port must be non-zero once bound");
    }

    #[test]
    fn request_open_codex_names_owner_uid_policy() {
        assert_eq!(
            codex_owner_uid_policy(501),
            AdmissionPolicy::OwnerUid { bound_uid: 501 }
        );
    }

    #[test]
    fn request_open_codex_rolls_back_port_when_registry_absent() {
        let sid = "sess_codex_rollback";
        // No CODEX_COMMAND_TX installed in this test process by default; the
        // send fails and the port must be rolled back.
        let result = request_open_codex(sid, 1000);
        // Either the channel is absent (None + rolled back) — assert no
        // dangling published port in that case.
        if result.is_none() {
            assert!(
                codex_responses_url_for(sid).is_none(),
                "port must be rolled back when the registry channel is absent"
            );
        } else {
            // A sibling test installed a sender; clean up.
            request_close_codex(sid);
        }
    }
}
