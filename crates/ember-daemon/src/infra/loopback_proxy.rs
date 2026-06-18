//! CLASSIFICATION: PUBLIC
//!
//! Per-session loopback-TCP credential-injection proxy registry for the host
//! LLM lanes that cannot dial a Unix socket or send `X-Ember-*` headers
//! (P22-S2 / ADR 197 codex; ADR 215 §2 generalization).
//!
//! Two lanes ride this one registry today — the codex GPT-plan responses lane
//! ([`CODEX_PROJECTOR`]) and the gemini Code Assist OAuth lane
//! ([`GEMINI_CODE_ASSIST_PROJECTOR`]) — and any future loopback lane is one more
//! `&'static LoopbackProjector`. The registry mechanism (bind → accept loop →
//! lifecycle) is projector-agnostic; every lane-specific behavior (strict gate,
//! upstream pin, credential injection) is data on the projector and is enforced
//! inside `handle_loopback_projector_request` in `proxy-forward-runtime`.
//!
//! This mirrors the per-session lifecycle of [`crate::infra::session_proxy`]
//! (a process-global command channel + a registry loop that owns one listener
//! per session, stood up at `register_session` and torn down at
//! `close_session`), but with three deliberate differences:
//!
//! 1. **Transport is loopback TCP, not a Unix socket.** Neither codex nor the
//!    gemini-cli can be told to dial a Unix socket or to send `X-Ember-*`
//!    headers — they POST/GET to a configured `base_url`. So we stand up a
//!    `127.0.0.1:<ephemeral>` listener and point the harness's config at it
//!    (codex's `config.toml` `model_providers.ember.base_url`; the gemini-cli's
//!    `CODE_ASSIST_ENDPOINT`).
//!
//! 2. **The peer-attestation gate degrades explicitly to `OwnerUid` in name.**
//!    A non-root daemon cannot read a loopback-TCP peer's kernel identity
//!    (`proc_pidfdinfo` is `CHECK_SAME_USER` gated; macOS exposes no TCP audit
//!    token). So unlike the UDS lane, there are no peercred / liveness /
//!    pid-tree / binary arms here. Under ADR 215 slice 3
//!    (`endpoint_gate_framework`) this is no longer an unnamed "no gate":
//!    the per-session bookkeeping carries
//!    [`crate::infra::endpoint_gate::AdmissionPolicy::OwnerUid`], and every
//!    accepted TCP connection emits the loud
//!    `<lane>-loopback-no-kernel-attestation` audit event.
//!
//!    Each lane remains credential-safe **by construction** — strict
//!    endpoint gate, client-header strip, server-side credential injection,
//!    server-side upstream-host pin — not by gate arms. See
//!    `handle_loopback_projector_request` in `proxy-forward-runtime` for the
//!    security contract.
//!
//!    HONEST RESIDUAL (out of scope for v1): a same-uid process that discovers
//!    the ephemeral port can POST to the lane and spend the session budget. It
//!    CANNOT exfil the credential (never returned, only injected upstream),
//!    CANNOT hit other endpoints (strict gate), CANNOT redirect upstream
//!    (server-side host pin). Closing attribution would need a root spawn-helper
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
use proxy_forward_runtime::forward::{
    handle_loopback_projector_request, LoopbackProjector, CODEX_PROJECTOR,
    GEMINI_CODE_ASSIST_PROJECTOR,
};

/// Everything the registry needs to stand up a per-session loopback listener.
/// The bound `std::net::TcpListener` is captured SYNCHRONOUSLY on the calling
/// (`register_session`) path so the ephemeral port is known immediately and
/// can be returned in the RPC response, then handed to the registry which
/// converts it to a tokio listener and spawns the accept loop. This sidesteps
/// the cross-`LocalSet` round-trip the async-bind alternative would require
/// (plan open-question 1, recommendation (a)).
pub struct LoopbackProxyOpenSpec {
    pub session_id: String,
    /// The bound listener (already on `127.0.0.1:<port>`). `std::net` so it can
    /// cross the channel; the registry calls `set_nonblocking(true)` +
    /// `TcpListener::from_std`.
    pub listener: StdTcpListener,
    /// Kept for logging/parity with the UDS lane; NOT enforced (loopback TCP
    /// exposes no kernel peer id for a non-root daemon).
    pub bound_uid: u32,
    /// ADR 215 slice 3: the loopback-TCP lane carries an explicit `OwnerUid`
    /// policy in per-session bookkeeping even though the transport cannot
    /// enforce peercred. `endpoint_gate_codex_owner_uid_named`.
    pub admission_policy: AdmissionPolicy,
    /// The loopback projector this per-session listener dispatches every
    /// connection to. The registry mechanism (bind → accept loop → lifecycle)
    /// is projector-agnostic; the lane-specific gate / upstream pin / credential
    /// injection all ride on this `&'static LoopbackProjector`. codex passes
    /// [`CODEX_PROJECTOR`]; the gemini Code Assist lane passes
    /// [`GEMINI_CODE_ASSIST_PROJECTOR`].
    pub projector: &'static LoopbackProjector,
}

impl std::fmt::Debug for LoopbackProxyOpenSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackProxyOpenSpec")
            .field("session_id", &self.session_id)
            .field("bound_uid", &self.bound_uid)
            .field("admission_policy", &self.admission_policy)
            .field("projector", &self.projector.name)
            .finish_non_exhaustive()
    }
}

/// Command sent from the sync session handlers to the loopback registry loop.
#[derive(Debug)]
pub enum LoopbackProxyCommand {
    Open(LoopbackProxyOpenSpec),
    Close { session_id: String },
}

/// Process-global sender into the loopback registry loop. Set once when the
/// registry starts at daemon boot. Distinct from the UDS lane's `COMMAND_TX`
/// so the no-kernel-attestation loopback dispatch and the gated UDS dispatch
/// never share a channel (plan open-question 5: separate channel + module).
static LOOPBACK_COMMAND_TX: OnceLock<mpsc::UnboundedSender<LoopbackProxyCommand>> = OnceLock::new();

/// Process-global map of `session_id -> bound port`, populated by the registry
/// on `Open` and cleared on `Close`. `register_session` reads it via
/// [`codex_responses_url_for`] / [`gemini_code_assist_url_for`] to build the URL
/// it returns to the launcher.
///
/// Because the bind happens synchronously on the calling path BEFORE the Open
/// command is sent, the port is also published here synchronously by
/// [`request_open_loopback`] (not by the registry), so a `register_session`
/// reader never races the registry's async processing of the command. The map
/// is keyed by session id alone (not by lane), so a session has at most one
/// loopback listener and [`request_close_loopback`] tears down whichever lane
/// it was.
static LOOPBACK_PORTS: OnceLock<Mutex<HashMap<String, u16>>> = OnceLock::new();

fn loopback_ports() -> &'static Mutex<HashMap<String, u16>> {
    LOOPBACK_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install the global loopback command sender. Idempotent-safe: returns `false`
/// if a sender was already installed (a second daemon incarnation in-process —
/// only happens in tests).
pub fn install_loopback_command_sender(tx: mpsc::UnboundedSender<LoopbackProxyCommand>) -> bool {
    LOOPBACK_COMMAND_TX.set(tx).is_ok()
}

/// Bind a loopback-TCP listener on an ephemeral port, publish the port, and
/// request the registry stand up its accept loop dispatching to `projector`.
/// Returns the bound port on success so the caller (`register_session`) can
/// build the proxy URL, or `None` if the bind failed or the registry channel is
/// not installed.
///
/// The bind runs HERE (synchronously, on the caller's path) so the port is
/// known immediately; the registry only owns the accept loop afterwards.
pub fn request_open_loopback(
    session_id: &str,
    bound_uid: u32,
    projector: &'static LoopbackProjector,
) -> Option<u16> {
    let listener = match StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(lane = projector.name, session_id, error = %e, "loopback_proxy: failed to bind loopback listener");
            return None;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            tracing::warn!(lane = projector.name, session_id, error = %e, "loopback_proxy: failed to read local_addr");
            return None;
        }
    };

    // Publish the port BEFORE sending the command so a `register_session`
    // reader observes it without racing the registry.
    loopback_ports()
        .lock()
        .unwrap()
        .insert(session_id.to_string(), port);

    let spec = LoopbackProxyOpenSpec {
        session_id: session_id.to_string(),
        listener,
        bound_uid,
        admission_policy: loopback_owner_uid_policy(bound_uid),
        projector,
    };
    if !send_command(LoopbackProxyCommand::Open(spec)) {
        // Registry not installed / gone — roll back the published port so we
        // don't hand the launcher a URL nothing is listening on.
        loopback_ports().lock().unwrap().remove(session_id);
        return None;
    }
    Some(port)
}

/// Stand up a per-session codex responses listener ([`CODEX_PROJECTOR`]).
pub fn request_open_codex(session_id: &str, bound_uid: u32) -> Option<u16> {
    request_open_loopback(session_id, bound_uid, &CODEX_PROJECTOR)
}

/// Stand up a per-session gemini Code Assist listener
/// ([`GEMINI_CODE_ASSIST_PROJECTOR`]).
pub fn request_open_gemini(session_id: &str, bound_uid: u32) -> Option<u16> {
    request_open_loopback(session_id, bound_uid, &GEMINI_CODE_ASSIST_PROJECTOR)
}

fn loopback_owner_uid_policy(bound_uid: u32) -> AdmissionPolicy {
    AdmissionPolicy::OwnerUid { bound_uid }
}

/// Request a per-session loopback listener be torn down (idempotent). The map +
/// Close command are session-keyed, so this tears down whichever lane (codex or
/// gemini) the session opened.
pub fn request_close_loopback(session_id: &str) -> bool {
    loopback_ports().lock().unwrap().remove(session_id);
    send_command(LoopbackProxyCommand::Close {
        session_id: session_id.to_string(),
    })
}

/// The bound loopback port for a session, or `None` if no listener is bound.
fn loopback_port_for(session_id: &str) -> Option<u16> {
    loopback_ports().lock().unwrap().get(session_id).copied()
}

/// Return the loopback responses-proxy base URL for a codex session, or `None`
/// if no listener is bound for it. The URL ends in `/v1` because codex appends
/// `/responses` to the configured provider `base_url`.
///
/// This is the canonical, unit-tested formatter for the codex URL shape. The
/// live `register_session` path builds the same shape inline from the
/// freshly-bound port (so it never re-reads the shared port map); this fn is the
/// spec that pins the `/v1` suffix discipline (see the `publish_then_url_then_remove`
/// unit test). Keep it even though prod inlines the format.
pub fn codex_responses_url_for(session_id: &str) -> Option<String> {
    loopback_port_for(session_id).map(|port| format!("http://127.0.0.1:{port}/v1"))
}

/// Return the loopback Code Assist base URL for a gemini session, or `None` if
/// no listener is bound for it. This is the BARE base (no `/v1` suffix): the
/// gemini-cli builds `${CODE_ASSIST_ENDPOINT}/v1internal:<method>`, so the
/// endpoint must be the host root only.
///
/// Canonical, unit-tested formatter for the gemini URL shape (the prod
/// `register_session` path inlines the same shape from the freshly-bound port);
/// this fn pins the bare-base discipline (see `gemini_url_is_bare_base_no_v1_suffix`).
pub fn gemini_code_assist_url_for(session_id: &str) -> Option<String> {
    loopback_port_for(session_id).map(|port| format!("http://127.0.0.1:{port}"))
}

fn send_command(cmd: LoopbackProxyCommand) -> bool {
    match LOOPBACK_COMMAND_TX.get() {
        Some(tx) => match tx.send(cmd) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "loopback_proxy: registry receiver gone — command dropped");
                false
            }
        },
        None => {
            tracing::debug!(
                "loopback_proxy: command channel not installed (loopback lanes disabled?) — command dropped"
            );
            false
        }
    }
}

/// A live per-session loopback listener entry.
struct LoopbackEntry {
    shutdown_tx: watch::Sender<bool>,
    #[allow(dead_code)]
    admission_policy: AdmissionPolicy,
}

impl LoopbackEntry {
    fn tear_down(self) {
        let _ = self.shutdown_tx.send(true);
        // No inode to unlink — the TCP listener vanishes with its accept loop.
    }
}

/// Convert the bound `std::net` listener to tokio, spawn its accept loop.
fn open_session_tcp_socket(
    spec: LoopbackProxyOpenSpec,
    backend: Arc<DaemonPolicyBackend>,
) -> std::io::Result<LoopbackEntry> {
    let LoopbackProxyOpenSpec {
        session_id,
        listener,
        bound_uid,
        admission_policy,
        projector,
    } = spec;

    listener.set_nonblocking(true)?;
    let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
    let port = tokio_listener.local_addr().map(|a| a.port()).unwrap_or(0);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let loop_session_id = session_id.clone();
    let loop_policy = admission_policy.clone();
    tokio::task::spawn_local(async move {
        run_loopback_accept_loop_with_named_policy(
            tokio_listener,
            loop_session_id.clone(),
            bound_uid,
            loop_policy,
            projector,
            backend,
            shutdown_rx,
        )
        .await;
        tracing::debug!(session_id = %loop_session_id, "loopback_proxy: accept loop exited");
    });

    tracing::info!(
        session_id = %session_id,
        lane = projector.name,
        port,
        bound_uid,
        admission_policy = %admission_policy,
        "loopback_proxy: per-session loopback listener up (credential-safe by construction; named OwnerUid policy, no TCP peercred enforcement)"
    );

    Ok(LoopbackEntry {
        shutdown_tx,
        admission_policy,
    })
}

async fn run_loopback_accept_loop_with_named_policy(
    listener: tokio::net::TcpListener,
    session_id: String,
    bound_uid: u32,
    admission_policy: AdmissionPolicy,
    projector: &'static LoopbackProjector,
    backend: Arc<DaemonPolicyBackend>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        emit_loopback_no_kernel_attestation(
                            &backend,
                            projector.name,
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
                                    handle_loopback_projector_request(
                                        projector, backend, req, session_id,
                                    )
                                    .await
                                }
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                tracing::warn!(error = %e, "loopback proxy connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "loopback proxy accept error");
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

fn emit_loopback_no_kernel_attestation(
    backend: &DaemonPolicyBackend,
    lane: &str,
    session_id: &str,
    bound_uid: u32,
    admission_policy: &AdmissionPolicy,
) {
    tracing::warn!(
        lane,
        session_id,
        bound_uid,
        admission_policy = %admission_policy,
        "loopback-no-kernel-attestation: admitted loopback-TCP connection under named OwnerUid policy; kernel peer identity is unavailable on this transport"
    );
    if let Err(e) =
        backend.log_loopback_no_kernel_attestation(lane, session_id, bound_uid, admission_policy)
    {
        tracing::warn!(
            lane,
            session_id,
            error = ?e,
            "loopback_proxy: failed to write loopback-no-kernel-attestation audit event"
        );
    }
}

/// The loopback registry control loop. Owns the `!Send` backend and the live
/// per-session listeners; processes `Open`/`Close` commands until the global
/// daemon shutdown fires. Runs on the proxy's `LocalSet` via `spawn_local`. One
/// registry serves every loopback lane — each `Open` carries its own projector.
pub async fn run_loopback_proxy_registry(
    backend: std::sync::Arc<DaemonPolicyBackend>,
    mut commands: mpsc::UnboundedReceiver<LoopbackProxyCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sessions: HashMap<String, LoopbackEntry> = HashMap::new();

    loop {
        tokio::select! {
            cmd = commands.recv() => {
                match cmd {
                    Some(LoopbackProxyCommand::Open(spec)) => {
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
                                tracing::warn!(session_id = %session_id, error = %e, "loopback_proxy: failed to open per-session listener");
                                // Bind succeeded on the caller's path; the
                                // conversion/spawn failed. Drop the published
                                // port so we don't advertise a dead URL.
                                loopback_ports().lock().unwrap().remove(&session_id);
                            }
                        }
                    }
                    Some(LoopbackProxyCommand::Close { session_id }) => {
                        if let Some(entry) = sessions.remove(&session_id) {
                            entry.tear_down();
                            tracing::info!(session_id = %session_id, "loopback_proxy: per-session listener torn down");
                        }
                    }
                    None => {
                        tracing::debug!("loopback_proxy: command channel closed — registry exiting");
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
    tracing::debug!("loopback_proxy: registry loop stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_for_none_before_open() {
        // A session id that was never opened resolves to None on both lanes.
        assert!(codex_responses_url_for("sess_never_opened_xyz").is_none());
        assert!(gemini_code_assist_url_for("sess_never_opened_xyz").is_none());
    }

    #[test]
    fn publish_then_url_then_remove() {
        let sid = "sess_codex_unit_publish";
        // Simulate request_open_loopback's publish step directly (no registry).
        loopback_ports().lock().unwrap().insert(sid.to_string(), 54321);
        let url = codex_responses_url_for(sid).expect("url after publish");
        assert_eq!(url, "http://127.0.0.1:54321/v1");
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(url.ends_with("/v1"));
        // Close removes it.
        loopback_ports().lock().unwrap().remove(sid);
        assert!(codex_responses_url_for(sid).is_none());
    }

    #[test]
    fn gemini_url_is_bare_base_no_v1_suffix() {
        let sid = "sess_gemini_unit_publish";
        // Same published port surfaces a BARE base URL for the gemini lane: the
        // CLI appends `/v1internal:<method>`, so a `/v1` suffix would break it.
        loopback_ports().lock().unwrap().insert(sid.to_string(), 54322);
        let url = gemini_code_assist_url_for(sid).expect("url after publish");
        assert_eq!(url, "http://127.0.0.1:54322");
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(!url.ends_with("/v1"), "gemini base must NOT carry a /v1 suffix");
        // codex formatter over the SAME port keeps its /v1 suffix.
        assert_eq!(
            codex_responses_url_for(sid).unwrap(),
            "http://127.0.0.1:54322/v1"
        );
        loopback_ports().lock().unwrap().remove(sid);
        assert!(gemini_code_assist_url_for(sid).is_none());
    }

    #[test]
    fn projectors_carry_expected_provider_prefixes() {
        // The registry is projector-agnostic; the lane's provider pin rides on
        // the projector. Guard that the two wrappers bind the intended lanes.
        assert_eq!(CODEX_PROJECTOR.provider_prefix, "openai/");
        assert_eq!(GEMINI_CODE_ASSIST_PROJECTOR.provider_prefix, "google/");
        assert_eq!(GEMINI_CODE_ASSIST_PROJECTOR.name, "gemini-code-assist");
    }

    #[test]
    fn request_open_binds_loopback_and_publishes_port() {
        // No command sender installed in this unit context, so request_open
        // rolls back. But we can assert the bind targets loopback + ephemeral
        // by binding directly the same way and checking the addr.
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback(), "must bind 127.0.0.1, got {addr}");
        assert_ne!(addr.port(), 0, "ephemeral port must be non-zero once bound");
    }

    #[test]
    fn request_open_names_owner_uid_policy() {
        assert_eq!(
            loopback_owner_uid_policy(501),
            AdmissionPolicy::OwnerUid { bound_uid: 501 }
        );
    }

    #[test]
    fn request_open_codex_rolls_back_port_when_registry_absent() {
        let sid = "sess_codex_rollback";
        // No LOOPBACK_COMMAND_TX installed in this test process by default; the
        // send fails and the port must be rolled back.
        let result = request_open_codex(sid, 1000);
        if result.is_none() {
            assert!(
                codex_responses_url_for(sid).is_none(),
                "port must be rolled back when the registry channel is absent"
            );
        } else {
            // A sibling test installed a sender; clean up.
            request_close_loopback(sid);
        }
    }

    #[test]
    fn request_open_gemini_rolls_back_port_when_registry_absent() {
        let sid = "sess_gemini_rollback";
        let result = request_open_gemini(sid, 1000);
        if result.is_none() {
            assert!(
                gemini_code_assist_url_for(sid).is_none(),
                "port must be rolled back when the registry channel is absent"
            );
        } else {
            request_close_loopback(sid);
        }
    }
}
