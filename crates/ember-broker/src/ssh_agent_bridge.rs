//! ssh-agent-over-bridge, Slice 1 — the lease-gated, per-session SSH-agent
//! bridge (`ssh_agent_sign_over_bridge`).
//!
//! ## What this is
//!
//! A fail-closed front door to the session's host ssh-agent
//! ([`crate::ssh_agent::SshAgentHandle`]). A client — in S1 a test stand-in, in
//! S2 the in-container forwarder — connects to the bridge's **dedicated `0700`
//! host-side UDS** and speaks the OpenSSH agent protocol. The bridge:
//!
//!   1. **attests the peer** — the connecting peer identity is delegated to the
//!      injected endpoint admission gate. Today the daemon wires this as
//!      `AdmissionPolicy::OwnerUid` (the ADR 214 F1 fallback); the `0700` socket
//!      dir is still the primary control, with the admission gate as
//!      defense-in-depth;
//!   2. **refuses every sign/identities unless authorized** — a request is
//!      served only when [`SshSignAuthority::ssh_signing_authorized`] returns
//!      `true`, i.e. the session holds a valid, unexpired, grant-scoped
//!      SSH-signing **lease** (ADR 211). There is no code path that produces a
//!      sign response without this check;
//!   3. **enforces per-session key isolation** — a sign request naming any
//!      `key_blob` other than the session's own is refused, and `identities`
//!      returns only the session's own key;
//!   4. **forwards** the authorized request to the host agent's UDS and relays
//!      the response. The private key **never leaves the host agent** — only
//!      OpenSSH sign requests (the *public* key blob + data) and signatures
//!      cross the bridge.
//!
//! ## Why the authority gate is injected (crate-boundary note)
//!
//! `ember-broker` cannot depend on `ember-daemon` — the dependency runs the
//! other way. So the ADR 211 lease check is injected as the [`SshSignAuthority`]
//! trait: the daemon implements it against its `LeaseRegistry`
//! (`store.leases()`), binding a concrete `grant_id`. This keeps the bridge's
//! wire/protocol logic in the broker and the authority decision in the daemon,
//! with the trait as the seam.
//!
//! ## Transport (resolved design, post-#5687)
//!
//! A **dedicated** `0700` host-side rpc-forward UDS — NOT a frame multiplexed
//! onto the authority control channel (the SSH stream is agent-controlled,
//! bursty, and arbitrary-length; coupling it to the authority plane enlarges the
//! parser attack surface and risks DoS of `register_session`). Still
//! ADR-207-compliant: the socket is host-side, never a UDS *in* the container.
//!
//! ## Scope of S1
//!
//! Host-only tracer bullet — no container yet. The lease *enforcement* lives
//! here; `register_session` *provisioning* of the lease + audit fidelity is
//! Slice 3, and the in-container forwarder + retiring the raw host-socket mount
//! is Slice 2.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::ssh_agent::{
    SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, decode_sign_request, decode_string,
    decode_u32,
};

/// Max OpenSSH agent message read off the bridge wire before refusing. Mirrors
/// the host agent's own ceiling in `ssh_agent::handle_agent_connection`, so a
/// hostile client cannot make the bridge buffer more than the agent would.
const MAX_AGENT_MSG_BYTES: usize = 256 * 1024;

/// Per-message read timeout. A client that sends a length prefix then stalls
/// (slowloris) is dropped rather than pinning a task + its (≤256 KiB) buffer.
/// Generous for a burst of agent requests during a git operation; an idle
/// connection past this is dropped and the client reconnects.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Cap on concurrently-served connections per bridge. Bounds the
/// pre-authentication memory/task footprint a hostile client can pin by opening
/// many connections (the DoS needs no lease). Backpressure: the accept loop
/// waits for a free slot rather than unboundedly spawning.
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// The fail-closed authority gate the bridge consults before **every** sign and
/// identities op.
///
/// `ember-broker` cannot depend on `ember-daemon`, so the ADR 211 lease check is
/// injected: the daemon implements this against its `LeaseRegistry`, binding a
/// concrete `grant_id`. Returning `false` (no live, unexpired, grant-scoped
/// SSH-signing lease) makes the bridge refuse — there is no path that signs
/// without a `true` here.
///
/// Not `Send + Sync`: the daemon's `LeaseRegistry` is `!Sync` (single-threaded
/// `LocalSet`, like `infra::session_proxy`/`infra::proxy`), so the whole bridge
/// stays on one thread (`Rc`, `spawn_local`) and the gate borrows the registry
/// directly — no cross-thread sharing, no `unsafe impl Send`.
pub trait SshSignAuthority {
    /// True iff the bridge's session holds a valid, unexpired, grant-scoped
    /// SSH-signing lease at this instant (ADR 211). Evaluated fresh per request
    /// so an expiry/revoke mid-session flips subsequent ops to refused.
    fn ssh_signing_authorized(&self) -> bool;
}

/// Audit sink for completed signs (ssh-agent-over-bridge S3 audit fidelity).
///
/// The daemon implements this to append **one hash-chained audit-log row per
/// authorized sign** — this is an **audit-log** entry, NOT a receipt (the Receipt
/// is emitted once at lease grant, the authority decision; per-access logging is
/// the audit log, per the `receipt_vs_audit_log` distinction). Injected like
/// [`SshSignAuthority`] because `ember-broker` cannot depend on `ember-daemon`;
/// keeping it `!Send + !Sync` for the same single-`LocalSet` reason.
pub trait SshSignAudit {
    /// Record one authorized sign that passed the lease gate + per-session key
    /// isolation. `key_blob` is the session's public-key blob, `data` the opaque
    /// OpenSSH blob being signed, `flags` the agent flags. The daemon hashes
    /// `data`, parses the userauth fields
    /// ([`crate::ssh_agent::parse_sign_userauth`]), and appends the row. Emission
    /// is best-effort and must never block or fail the sign response.
    fn record_sign(&self, key_blob: &[u8], data: &[u8], flags: u32);
}

/// Kernel-attested peer identity as seen by the SSH bridge's host UDS.
///
/// `ember-broker` owns this transport and cannot depend on `ember-daemon`'s
/// `endpoint_gate` module, so the daemon maps this thin carrier into
/// `endpoint_gate::PeerIdentity` before evaluating the concrete
/// `AdmissionPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshBridgePeerIdentity {
    pub uid: u32,
    pub pid: i32,
    pub version: Option<u64>,
}

/// Rejection returned by the injected endpoint admission gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBridgeAdmissionReject {
    pub policy: String,
    pub reason: String,
}

impl SshBridgeAdmissionReject {
    pub fn new(policy: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
            reason: reason.into(),
        }
    }
}

/// Endpoint admission seam for the SSH bridge.
///
/// The broker deliberately receives a thin evaluator instead of a bare
/// `expected_peer_uid`, so ADR 215's shared endpoint-gate framework remains the
/// source of admission truth without creating an `ember-broker` ->
/// `ember-daemon` dependency cycle.
pub trait SshBridgeAdmission {
    /// Admit or reject one newly accepted bridge connection before any
    /// OpenSSH-agent protocol bytes are read.
    fn admit(&self, peer: SshBridgePeerIdentity) -> Result<(), SshBridgeAdmissionReject>;
}

/// A lease-gated, per-session OpenSSH agent endpoint. Sits in front of the
/// session's host [`crate::ssh_agent::SshAgentHandle`].
pub struct SshAgentBridge {
    /// The session's own OpenSSH public-key blob, learned from the host agent's
    /// identities answer at [`SshAgentBridge::connect`] time. The per-session
    /// isolation anchor: a sign request naming any other blob is refused.
    session_pubkey_blob: Vec<u8>,
    /// The host agent's UDS. Authorized requests are forwarded here; the private
    /// key lives behind it and never crosses the bridge.
    upstream_sock: PathBuf,
    /// The injected fail-closed ADR 211 lease gate.
    authority: Rc<dyn SshSignAuthority>,
    /// Optional audit sink — one hash-chained audit-log row per authorized sign
    /// (ssh-agent-over-bridge S3). `None` in S1's host-only tracer (no daemon
    /// audit wired); `Some` once `register_session` provisions the bridge.
    audit: Option<Rc<dyn SshSignAudit>>,
    /// Injected endpoint gate. The daemon wires this to ADR 215
    /// `AdmissionPolicy::OwnerUid` today; `LeafSubtree` graduation stays in the
    /// daemon-side evaluator once the descendant-walk primitive is settled.
    admission: Rc<dyn SshBridgeAdmission>,
}

impl SshAgentBridge {
    /// Build a bridge in front of the host agent at `upstream_sock`.
    ///
    /// Learns the session's advertised public-key blob by issuing one
    /// `identities` request to the host agent. This is **SE-safe**: it reads the
    /// key the agent actually advertises (Tier-0 ed25519 or the Secure-Enclave
    /// key), never a Tier-0 placeholder. This bootstrap is daemon-internal, not
    /// a client request, so it is deliberately **not** lease-gated.
    pub async fn connect(
        upstream_sock: impl Into<PathBuf>,
        authority: Rc<dyn SshSignAuthority>,
        admission: Rc<dyn SshBridgeAdmission>,
    ) -> Result<Self> {
        let upstream_sock = upstream_sock.into();
        let answer = upstream_roundtrip(&upstream_sock, &[SSH_AGENTC_REQUEST_IDENTITIES])
            .await
            .context("host ssh-agent identities bootstrap")?;
        let session_pubkey_blob = first_identity_blob(&answer)
            .context("host ssh-agent advertised no identity to bind the bridge to")?;
        Ok(Self {
            session_pubkey_blob,
            upstream_sock,
            authority,
            audit: None,
            admission,
        })
    }

    /// Attach an audit sink (ssh-agent-over-bridge S3): one hash-chained
    /// audit-log row per authorized sign. `register_session` provisioning calls
    /// this with the daemon's [`SshSignAudit`] impl; S1's host-only tracer leaves
    /// it unset.
    pub fn with_audit(mut self, audit: Rc<dyn SshSignAudit>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// The session's advertised OpenSSH public-key blob (public material only).
    pub fn session_pubkey_blob(&self) -> &[u8] {
        &self.session_pubkey_blob
    }

    /// Serve one accepted connection: attest the peer, then loop one OpenSSH
    /// agent request → gated response at a time until the peer closes.
    pub async fn handle_connection(&self, mut stream: UnixStream) {
        // (1) Peer attestation — fail-closed. endpoint_gate_ssh_f1_wired: the
        // bridge delegates to the shared endpoint-gate policy instead of
        // carrying a bespoke uid comparison.
        let peer = match stream.peer_cred() {
            Ok(cred) => SshBridgePeerIdentity {
                uid: cred.uid(),
                pid: cred.pid().unwrap_or(0),
                version: None,
            },
            Err(e) => {
                tracing::warn!(error = %e, "ssh bridge: peer_cred unavailable — fail closed");
                return;
            }
        };
        match self.admission.admit(peer) {
            Ok(()) => {}
            Err(reject) => {
                tracing::warn!(
                    peer_uid = peer.uid,
                    peer_pid = peer.pid,
                    policy = %reject.policy,
                    reason = %reject.reason,
                    "ssh bridge: endpoint admission refused"
                );
                return;
            }
        }

        loop {
            // Bound each read so a client that sends a length prefix then stalls
            // (slowloris) is dropped instead of pinning the task + its buffer.
            let payload =
                match tokio::time::timeout(READ_TIMEOUT, read_framed_message(&mut stream)).await {
                    Ok(Some(payload)) => payload,
                    Ok(None) => return, // EOF / error / over-cap — done.
                    Err(_elapsed) => {
                        tracing::warn!("ssh bridge: read timed out — dropping connection");
                        return;
                    }
                };
            let response = self.process_message(&payload).await;
            if write_framed_message(&mut stream, &response).await.is_err() {
                return;
            }
        }
    }

    /// Apply the gate + per-session isolation to one OpenSSH agent payload
    /// (`[type][body]`), forwarding to the host agent only when authorized.
    /// Returns the OpenSSH response payload (a signature/identities answer, or
    /// `SSH_AGENT_FAILURE` on any refusal/error). Never panics, never leaks.
    async fn process_message(&self, payload: &[u8]) -> Vec<u8> {
        // (2) Fail-closed lease gate FIRST — gates BOTH sign and identities.
        // No branch below is reachable without a live SSH-signing lease.
        if !self.authority.ssh_signing_authorized() {
            tracing::warn!("ssh bridge: refused — no valid grant-scoped SSH-signing lease");
            return vec![SSH_AGENT_FAILURE];
        }

        let Some(&msg_type) = payload.first() else {
            return vec![SSH_AGENT_FAILURE];
        };

        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                // The host agent advertises only this session's key, so relaying
                // is already per-session isolated.
                self.forward(payload)
                    .await
                    .unwrap_or_else(|_| vec![SSH_AGENT_FAILURE])
            }
            SSH_AGENTC_SIGN_REQUEST => {
                // (3) Per-session key isolation: `decode_sign_request` accepts
                // the body only when its `key_blob` equals THIS session's blob,
                // so a request naming another session's key is refused here —
                // before the host agent is ever reached.
                let Some((data, flags)) =
                    decode_sign_request(&payload[1..], &self.session_pubkey_blob)
                else {
                    tracing::warn!(
                        "ssh bridge: sign refused — key_blob is not this session's (cross-session isolation)"
                    );
                    return vec![SSH_AGENT_FAILURE];
                };
                let response = self
                    .forward(payload)
                    .await
                    .unwrap_or_else(|_| vec![SSH_AGENT_FAILURE]);
                // (4) Audit fidelity (S3): one hash-chained audit-log row per
                // signature ACTUALLY ISSUED — emitted only when the host agent
                // returned a real `SIGN_RESPONSE` (the lease gate + key isolation
                // already passed above). A host-agent failure issued no signature,
                // so there is nothing to attribute. Best-effort: the daemon hashes
                // `data` + parses userauth fields, and a failed append is logged,
                // never propagated — the signature is already cryptographically
                // issued and an audit-DB hiccup must not un-issue it.
                //
                // The forwarder slice (F) wires real signs, so the emission is
                // moved OFF the response path: `record_sign` runs a synchronous
                // SQLite write on the shared `LocalSet`, and the caller writes
                // `response` to the wire as soon as `process_message` returns. We
                // detach the write into `spawn_local` (the signed-data bytes cloned
                // in) so the response flushes first and a blocking audit-DB write
                // never delays signature delivery on the shared loop. Ordering is
                // preserved per connection because the detached task is enqueued in
                // request order and the loop is single-threaded.
                if response.first() == Some(&SSH_AGENT_SIGN_RESPONSE)
                    && let Some(audit) = &self.audit
                {
                    let audit = Rc::clone(audit);
                    let key_blob = self.session_pubkey_blob.clone();
                    let data = data.to_vec();
                    tokio::task::spawn_local(async move {
                        audit.record_sign(&key_blob, &data, flags);
                    });
                }
                response
            }
            other => {
                tracing::debug!(msg_type = other, "ssh bridge: unhandled message type");
                vec![SSH_AGENT_FAILURE]
            }
        }
    }

    /// Forward one authorized OpenSSH payload to the host agent and return its
    /// response payload. The host agent holds the key; only the sign
    /// request/response cross this hop.
    async fn forward(&self, payload: &[u8]) -> Result<Vec<u8>> {
        upstream_roundtrip(&self.upstream_sock, payload).await
    }
}

/// A running bridge: owns the dedicated `0700` UDS and the accept task. Dropping
/// it **aborts** the accept loop and unlinks the socket — so a `close_session`
/// teardown actually stops serving (unlinking the path alone would not: an
/// already-bound `UnixListener` keeps accepting on its held fd after the path is
/// gone, so the abort is what makes revocation real).
pub struct SshAgentBridgeListener {
    /// The dedicated host-side UDS path (the value the forwarder targets).
    pub socket_path: PathBuf,
    task: tokio::task::JoinHandle<()>,
    _guard: SocketGuard,
}

impl Drop for SshAgentBridgeListener {
    fn drop(&mut self) {
        // Stop the accept loop. The `SocketGuard` field unlinks the socket path
        // immediately after (field drops run after this `Drop::drop`).
        self.task.abort();
    }
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the dedicated `0700` host-side UDS at `socket_path` and serve `bridge`
/// on it. The parent dir is forced to `0700` and the socket to `0600`
/// (owner-only); the per-connection uid check is the second gate.
///
/// The accept loop is `spawn_local`'d, so this must be called from within a
/// `LocalSet` (the daemon's single-threaded socket runtime — the same context
/// `infra::session_proxy` binds its per-session sockets in).
pub async fn bind(
    socket_path: impl Into<PathBuf>,
    bridge: Rc<SshAgentBridge>,
) -> Result<SshAgentBridgeListener> {
    let socket_path = socket_path.into();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("create ssh bridge socket dir")?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .context("chmod 0700 ssh bridge socket dir")?;
    }
    // Clear a stale inode from a previous daemon incarnation (else EADDRINUSE).
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind ssh bridge socket {}", socket_path.display()))?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("chmod 0600 ssh bridge socket")?;

    let guard = SocketGuard {
        path: socket_path.clone(),
    };
    let accept_bridge = Rc::clone(&bridge);
    // Backpressure cap on concurrently-served connections (DoS bound — needs no
    // lease). `acquire_owned` requires an `Arc`; the semaphore is the only
    // cross-`spawn_local` shared state, the rest of the bridge stays `Rc`.
    let conn_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let task = tokio::task::spawn_local(async move {
        loop {
            // Wait for a free slot before accepting, so a hostile client cannot
            // make us spawn unbounded handler tasks / pin unbounded buffers.
            let Ok(permit) = std::sync::Arc::clone(&conn_slots).acquire_owned().await else {
                break; // semaphore closed — stop accepting (fail-closed).
            };
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let b = Rc::clone(&accept_bridge);
                    tokio::task::spawn_local(async move {
                        let _permit = permit; // released when the connection ends.
                        b.handle_connection(stream).await
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ssh bridge: accept error");
                    break;
                }
            }
        }
    });

    Ok(SshAgentBridgeListener {
        socket_path,
        task,
        _guard: guard,
    })
}

// ---------------------------------------------------------------------------
// Wire helpers (OpenSSH agent length-prefixed framing)
// ---------------------------------------------------------------------------

/// Read one length-prefixed OpenSSH agent message, returning the payload
/// (`[type][body]`, no length prefix). `None` on EOF/error/over-cap.
async fn read_framed_message(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_MSG_BYTES {
        return None;
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

/// Write one length-prefixed OpenSSH agent message (`payload` is `[type][body]`).
async fn write_framed_message(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Connect to a host ssh-agent UDS, send one framed payload, and return its one
/// framed response payload. A fresh connection per round-trip: the host agent's
/// read loop sees EOF and exits when we drop it.
async fn upstream_roundtrip(sock: &PathBuf, payload: &[u8]) -> Result<Vec<u8>> {
    let mut up = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect host ssh-agent {}", sock.display()))?;
    write_framed_message(&mut up, payload)
        .await
        .context("write to host ssh-agent")?;
    read_framed_message(&mut up)
        .await
        .context("host ssh-agent closed without a response")
}

/// Parse the first key blob out of an `SSH_AGENT_IDENTITIES_ANSWER` payload
/// (`[type=12][u32 nkeys][string blob][string comment]...`). Bounds-checked via
/// the shared `decode_*` helpers; `None` on any malformed/empty answer.
fn first_identity_blob(answer_payload: &[u8]) -> Option<Vec<u8>> {
    if answer_payload.first().copied() != Some(SSH_AGENT_IDENTITIES_ANSWER) {
        return None;
    }
    let (nkeys, off) = decode_u32(answer_payload, 1)?;
    if nkeys == 0 {
        return None;
    }
    let (blob, _off) = decode_string(answer_payload, off)?;
    Some(blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ed25519_dalek::{Signature, SigningKey, Verifier};

    use crate::ssh_agent::{encode_string, spawn_tier0_ssh_agent_with_seed};

    // --- Test authorities (the injected lease gate) ---

    struct AlwaysAuthorized;
    impl SshSignAuthority for AlwaysAuthorized {
        fn ssh_signing_authorized(&self) -> bool {
            true
        }
    }

    struct NeverAuthorized;
    impl SshSignAuthority for NeverAuthorized {
        fn ssh_signing_authorized(&self) -> bool {
            false
        }
    }

    /// A gate the test can flip — proves the gate is re-read per request (an
    /// expiry/revoke mid-session flips later ops to refused).
    struct ToggleAuthority(AtomicBool);
    impl SshSignAuthority for ToggleAuthority {
        fn ssh_signing_authorized(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    // --- Test audit sink (records each authorized sign) ---

    /// Captures every `record_sign` call. `RefCell` (not a mutex) because the
    /// bridge — like the daemon's real audit sink — runs on one `LocalSet`.
    #[derive(Default)]
    struct RecordingAudit {
        signs: std::cell::RefCell<Vec<(Vec<u8>, Vec<u8>, u32)>>,
    }
    impl SshSignAudit for RecordingAudit {
        fn record_sign(&self, key_blob: &[u8], data: &[u8], flags: u32) {
            self.signs
                .borrow_mut()
                .push((key_blob.to_vec(), data.to_vec(), flags));
        }
    }

    // --- Test admission gate (mirrors endpoint_gate::AdmissionPolicy::OwnerUid) ---

    struct TestOwnerUidAdmission {
        bound_uid: u32,
    }

    impl SshBridgeAdmission for TestOwnerUidAdmission {
        fn admit(&self, peer: SshBridgePeerIdentity) -> Result<(), SshBridgeAdmissionReject> {
            if peer.uid == self.bound_uid {
                Ok(())
            } else {
                Err(SshBridgeAdmissionReject::new(
                    "owner-uid",
                    format!(
                        "uid mismatch: expected {}, actual {}",
                        self.bound_uid, peer.uid
                    ),
                ))
            }
        }
    }

    fn test_owner_uid_admission(bound_uid: u32) -> Rc<dyn SshBridgeAdmission> {
        Rc::new(TestOwnerUidAdmission { bound_uid })
    }

    // --- Helpers ---

    /// Run `fut` on a fresh single-threaded `LocalSet` — the context `bind`'s
    /// `spawn_local` accept loop needs (the daemon binds its per-session sockets
    /// the same way; see `infra::session_proxy`).
    async fn run_local<F: std::future::Future<Output = ()>>(fut: F) {
        tokio::task::LocalSet::new().run_until(fut).await
    }

    /// Discover this test process's uid without libc/nix: a `UnixStream::pair`
    /// is two connected ends in the same process, so the peer's uid is ours.
    async fn current_uid() -> u32 {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        a.peer_cred().expect("peer_cred").uid()
    }

    /// The OpenSSH public-key blob for an ed25519 seed (`string "ssh-ed25519"`,
    /// `string <32-byte pubkey>`).
    fn pubkey_blob_for_seed(seed: [u8; 32]) -> Vec<u8> {
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let mut blob = Vec::new();
        blob.extend_from_slice(&encode_string(b"ssh-ed25519"));
        blob.extend_from_slice(&encode_string(vk.as_bytes()));
        blob
    }

    /// Build a `SSH_AGENTC_SIGN_REQUEST` payload (`[type][string key_blob]
    /// [string data][u32 flags]`).
    fn sign_request_payload(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut p = vec![SSH_AGENTC_SIGN_REQUEST];
        p.extend_from_slice(&encode_string(key_blob));
        p.extend_from_slice(&encode_string(data));
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    }

    /// Send one OpenSSH payload to a UDS, return the response payload + every
    /// byte that crossed the socket in both directions (for the wire assertion).
    async fn request_capture(sock: &PathBuf, payload: &[u8]) -> (Option<Vec<u8>>, Vec<u8>) {
        let mut s = UnixStream::connect(sock).await.expect("connect bridge");
        // Outbound framed bytes (what we put on the wire).
        let mut wire = Vec::new();
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        write_framed_message(&mut s, payload).await.expect("write");
        let resp = read_framed_message(&mut s).await;
        if let Some(ref r) = resp {
            wire.extend_from_slice(&(r.len() as u32).to_be_bytes());
            wire.extend_from_slice(r);
        }
        (resp, wire)
    }

    /// Extract the 64-byte ed25519 signature from a `SSH_AGENT_SIGN_RESPONSE`
    /// payload (`[type=14][string sig_blob]`; `sig_blob = string "ssh-ed25519"
    /// string <64-byte sig>`).
    fn signature_from_response(payload: &[u8]) -> Option<[u8; 64]> {
        if payload.first().copied() != Some(crate::ssh_agent::SSH_AGENT_SIGN_RESPONSE) {
            return None;
        }
        let (sig_blob, _) = decode_string(payload, 1)?;
        let (_alg, off) = decode_string(sig_blob, 0)?;
        let (sig, _) = decode_string(sig_blob, off)?;
        sig.try_into().ok()
    }

    /// Spin up: a host agent (known seed) + a bridge bound to a `0700` dir, with
    /// `authority`. Returns (bridge listener, the bridge socket path, the host
    /// agent handle kept alive, the temp dir kept alive).
    async fn bridge_fixture(
        seed: [u8; 32],
        authority: Rc<dyn SshSignAuthority>,
    ) -> (
        SshAgentBridgeListener,
        PathBuf,
        crate::ssh_agent::SshAgentHandle,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let agent =
            spawn_tier0_ssh_agent_with_seed("bridge-test", seed, &tmp.path().join("agent-run"))
                .expect("host agent");
        let uid = current_uid().await;
        let bridge = Rc::new(
            SshAgentBridge::connect(
                agent.auth_sock_path.clone(),
                authority,
                test_owner_uid_admission(uid),
            )
            .await
            .expect("bridge connect"),
        );
        let sock = tmp.path().join("bridge").join("ssh-bridge.sock");
        let listener = bind(sock.clone(), bridge).await.expect("bind bridge");
        (listener, sock, agent, tmp)
    }

    /// Like [`bridge_fixture`] but attaches an audit sink (S3). Returns the same
    /// tuple plus the shared `RecordingAudit` so the test can inspect it.
    async fn bridge_fixture_with_audit(
        seed: [u8; 32],
        authority: Rc<dyn SshSignAuthority>,
        audit: Rc<RecordingAudit>,
    ) -> (
        SshAgentBridgeListener,
        PathBuf,
        crate::ssh_agent::SshAgentHandle,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let agent = spawn_tier0_ssh_agent_with_seed(
            "bridge-audit-test",
            seed,
            &tmp.path().join("agent-run"),
        )
        .expect("host agent");
        let uid = current_uid().await;
        let bridge = Rc::new(
            SshAgentBridge::connect(
                agent.auth_sock_path.clone(),
                authority,
                test_owner_uid_admission(uid),
            )
            .await
            .expect("bridge connect")
            .with_audit(audit),
        );
        let sock = tmp.path().join("bridge").join("ssh-bridge.sock");
        let listener = bind(sock.clone(), bridge).await.expect("bind bridge");
        (listener, sock, agent, tmp)
    }

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];

    // -----------------------------------------------------------------------
    // Acceptance 1 + 5 — valid-lease sign round-trips and verifies; identities.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn valid_lease_sign_round_trips_and_verifies() {
        run_local(async {
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(AlwaysAuthorized)).await;

            let blob = pubkey_blob_for_seed(SEED_A);
            let data = b"git-push-handshake-bytes";
            let (resp, _wire) = request_capture(&sock, &sign_request_payload(&blob, data)).await;

            let sig = signature_from_response(&resp.expect("a response")).expect("a signature");
            let vk = SigningKey::from_bytes(&SEED_A).verifying_key();
            vk.verify(data, &Signature::from_bytes(&sig))
                .expect("signature must verify against the advertised pubkey");
        })
        .await;
    }

    // -----------------------------------------------------------------------
    // Acceptance (S3) — one audit-log row per AUTHORIZED sign; none on refusal.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn authorized_sign_emits_one_audit_record() {
        run_local(async {
            let audit = Rc::new(RecordingAudit::default());
            let (_l, sock, _agent, _tmp) =
                bridge_fixture_with_audit(SEED_A, Rc::new(AlwaysAuthorized), Rc::clone(&audit))
                    .await;

            let blob = pubkey_blob_for_seed(SEED_A);
            let data = b"git-push-handshake-bytes";
            let (resp, _wire) = request_capture(&sock, &sign_request_payload(&blob, data)).await;
            // The sign succeeded...
            signature_from_response(&resp.expect("a response")).expect("a signature");

            // ...and produced exactly one audit record with this session's key +
            // the signed data (the daemon hashes/parses it; the bridge passes the
            // raw bytes). The row is emitted in a detached `spawn_local` task off
            // the response path (F1), so yield until it lands (bounded).
            for _ in 0..1000 {
                if audit.signs.borrow().len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let signs = audit.signs.borrow();
            assert_eq!(signs.len(), 1, "exactly one audit row per authorized sign");
            assert_eq!(signs[0].0, blob, "audit records the session's key blob");
            assert_eq!(
                signs[0].1, data,
                "audit records the signed data for hashing"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn refused_sign_emits_no_audit_record() {
        run_local(async {
            // No-lease refusal: nothing is signed, so nothing is audited.
            let audit = Rc::new(RecordingAudit::default());
            let (_l, sock, _agent, _tmp) =
                bridge_fixture_with_audit(SEED_A, Rc::new(NeverAuthorized), Rc::clone(&audit))
                    .await;
            let blob = pubkey_blob_for_seed(SEED_A);
            let (resp, _wire) = request_capture(&sock, &sign_request_payload(&blob, b"x")).await;
            assert_eq!(resp.expect("a response"), vec![SSH_AGENT_FAILURE]);
            assert!(
                audit.signs.borrow().is_empty(),
                "a refused sign must emit no audit row (gate runs before audit)"
            );

            // Cross-session key refusal: also no audit (isolation runs before audit).
            let audit2 = Rc::new(RecordingAudit::default());
            let (_l2, sock2, _agent2, _tmp2) =
                bridge_fixture_with_audit(SEED_A, Rc::new(AlwaysAuthorized), Rc::clone(&audit2))
                    .await;
            let other_blob = pubkey_blob_for_seed(SEED_B);
            let (resp2, _w) =
                request_capture(&sock2, &sign_request_payload(&other_blob, b"x")).await;
            assert_eq!(resp2.expect("a response"), vec![SSH_AGENT_FAILURE]);
            assert!(
                audit2.signs.borrow().is_empty(),
                "a cross-session-key sign must emit no audit row"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn valid_lease_identities_returns_only_the_session_key() {
        run_local(async {
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(AlwaysAuthorized)).await;

            let (resp, _wire) = request_capture(&sock, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
            let answer = resp.expect("identities answer");
            let blob = first_identity_blob(&answer).expect("one identity");
            assert_eq!(
                blob,
                pubkey_blob_for_seed(SEED_A),
                "identities must list exactly the session's own key"
            );
        })
        .await;
    }

    // -----------------------------------------------------------------------
    // Acceptance 2 — fail-closed: no path signs without an authorizing lease.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_lease_refuses_sign() {
        run_local(async {
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(NeverAuthorized)).await;

            let blob = pubkey_blob_for_seed(SEED_A);
            let (resp, _wire) = request_capture(&sock, &sign_request_payload(&blob, b"data")).await;

            let resp = resp.expect("a response");
            assert_eq!(
                resp,
                vec![SSH_AGENT_FAILURE],
                "sign with no SSH-signing lease must be refused (SSH_AGENT_FAILURE), never signed"
            );
            assert!(
                signature_from_response(&resp).is_none(),
                "a refused sign must carry no signature"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn no_lease_refuses_identities() {
        run_local(async {
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(NeverAuthorized)).await;

            let (resp, _wire) = request_capture(&sock, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
            assert_eq!(
                resp.expect("a response"),
                vec![SSH_AGENT_FAILURE],
                "identities with no SSH-signing lease must be refused — no key disclosure"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn lease_revoked_mid_session_flips_to_refused() {
        run_local(async {
            // The gate is re-read per request: a sign that succeeds under a live
            // lease is refused once that lease is gone (revoke/expiry).
            let toggle = Rc::new(ToggleAuthority(AtomicBool::new(true)));
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, toggle.clone()).await;
            let blob = pubkey_blob_for_seed(SEED_A);

            let (ok, _) = request_capture(&sock, &sign_request_payload(&blob, b"d")).await;
            assert!(
                signature_from_response(&ok.expect("resp")).is_some(),
                "sign must succeed while the lease is live"
            );

            toggle.0.store(false, Ordering::SeqCst); // lease revoked / expired
            let (refused, _) = request_capture(&sock, &sign_request_payload(&blob, b"d")).await;
            assert_eq!(
                refused.expect("resp"),
                vec![SSH_AGENT_FAILURE],
                "once the lease is gone, the next sign must be refused"
            );
        })
        .await;
    }

    // -----------------------------------------------------------------------
    // Acceptance 3 — per-session key isolation.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cross_session_key_blob_is_refused() {
        run_local(async {
            // Bridge bound to session A; a sign request naming session B's key
            // must be refused even though the lease gate is open.
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(AlwaysAuthorized)).await;

            let other_blob = pubkey_blob_for_seed(SEED_B);
            let (resp, _wire) =
                request_capture(&sock, &sign_request_payload(&other_blob, b"data")).await;
            assert_eq!(
                resp.expect("a response"),
                vec![SSH_AGENT_FAILURE],
                "a sign naming another session's key_blob must be refused"
            );

            // Control: the session's own key still signs.
            let own_blob = pubkey_blob_for_seed(SEED_A);
            let (ok, _) = request_capture(&sock, &sign_request_payload(&own_blob, b"data")).await;
            assert!(
                signature_from_response(&ok.expect("resp")).is_some(),
                "the session's own key must still sign"
            );
        })
        .await;
    }

    // -----------------------------------------------------------------------
    // Acceptance 1 (assert on bytes) — private key never crosses the channel.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn private_key_never_crosses_the_wire() {
        run_local(async {
            let (_l, sock, _agent, _tmp) = bridge_fixture(SEED_A, Rc::new(AlwaysAuthorized)).await;

            let blob = pubkey_blob_for_seed(SEED_A);
            let (resp, wire) =
                request_capture(&sock, &sign_request_payload(&blob, b"payload")).await;
            // It really signed (so the wire carried a real operation, not a no-op)…
            assert!(signature_from_response(&resp.expect("resp")).is_some());
            // …yet the 32-byte private seed never appears anywhere on the wire.
            assert!(
                !contains_subsequence(&wire, &SEED_A),
                "the private key seed must never be serialized across the bridge"
            );
            // Defense-in-depth: no 32-byte window on the wire is the signing seed.
            let vk = SigningKey::from_bytes(&SEED_A).verifying_key();
            assert!(
                !wire
                    .windows(32)
                    .any(|w| SigningKey::from_bytes(w.try_into().unwrap()).verifying_key() == vk),
                "no window on the wire reconstructs the signing key"
            );
        })
        .await;
    }

    // -----------------------------------------------------------------------
    // Peer attestation — uid mismatch is refused before any protocol exchange.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn wrong_peer_uid_is_refused() {
        run_local(async {
            let tmp = tempfile::tempdir().unwrap();
            let agent =
                spawn_tier0_ssh_agent_with_seed("uid-test", SEED_A, &tmp.path().join("agent-run"))
                    .unwrap();
            let wrong_uid = current_uid().await.wrapping_add(1);
            let bridge = Rc::new(
                SshAgentBridge::connect(
                    agent.auth_sock_path.clone(),
                    Rc::new(AlwaysAuthorized),
                    test_owner_uid_admission(wrong_uid),
                )
                .await
                .unwrap(),
            );
            let sock = tmp.path().join("bridge").join("s.sock");
            let _l = bind(sock.clone(), bridge).await.unwrap();

            let blob = pubkey_blob_for_seed(SEED_A);
            let (resp, _wire) = request_capture(&sock, &sign_request_payload(&blob, b"d")).await;
            assert!(
                resp.is_none(),
                "a peer whose uid does not match must be dropped with no response"
            );
        })
        .await;
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // -----------------------------------------------------------------------
    // Raw host-agent socket hardening — the bridge's gate is only meaningful if
    // the ungated signer it fronts is NOT independently reachable, and is torn
    // down on drop (no leaked signer).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn host_agent_socket_is_owner_only_and_unlinked_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let agent = spawn_tier0_ssh_agent_with_seed("perm-test", SEED_A, &tmp.path().join("run"))
            .expect("host agent");
        let sock = agent.auth_sock_path.clone();

        // 0600 owner-only: no group/other principal can reach the ungated raw
        // signer, so the lease-gated bridge is the only sign path a different-uid
        // client can reach.
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "raw agent socket must be 0600, got {mode:o}");

        // Dropping the handle aborts the accept loop; the task held the only other
        // `AgentGuard` Arc, so the abort is what lets the socket unlink (without it
        // a live, ungated signer would leak past teardown).
        drop(agent);
        for _ in 0..1000 {
            if !sock.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !sock.exists(),
            "dropping the handle must unlink the raw agent socket (no leaked signer)"
        );
    }
}
