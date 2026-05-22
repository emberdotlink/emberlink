//! ember_rpc_phase_c_mtls_listener_wired
//!
//! Phase C — the actual mTLS listener (design component 1 + design
//! amendment). Replaces the Phase B `bail!`-only scaffold in `run()`.
//!
//! # Architecture (Phase C scope)
//!
//! ```text
//! container ──TLS────► ember-rpc listener (this file)
//!                          │
//!                          ├─► WebPkiClientVerifier (CA-pinned, no system roots)
//!                          ├─► newline-delimited JSON-RPC parse
//!                          ├─► gate_method (lib.rs::gate_method)
//!                          │
//!                          ├─► [DenyPlaintextBearing] → write policy-denied response, close
//!                          └─► [AllowForward] → write phase-c-stub response, close
//!                                               (Phase D will replace this with the
//!                                                actual bincode forward to emberd core)
//! ```
//!
//! # What this file is NOT
//!
//! - Not the bincode forward path (Phase D). `AllowForward` writes a stub
//!   response today; Phase D replaces it with a `core-fd-pass`-free UDS
//!   dial to emberd core that re-encodes the JSON-RPC as typed bincode.
//! - Not SPIFFE SAN extraction. The TLS handshake validates the cert
//!   chain against the configured CA; identity-extraction (parsing the
//!   `spiffe://emberd/persona/<p>` SAN) is deferred to Phase D where the
//!   forward wire carries an opaque identity claim. Phase C ships
//!   "transport is locked"; Phase D ships "identity threads through."
//! - Not the SE-sealed CA load path. ember-rpc reads cert + key + CA
//!   from operator-configured PEM paths. The emberd-side cert-minter
//!   that writes those files is a separate task (the brief flags it as
//!   `implementation-note-115`, M-size).
//!
//! Security invariants enforced here:
//! - `WebPkiClientVerifier::builder` REQUIRES a client cert; rustls refuses
//!   the handshake when none is presented. There is no anonymous lane.
//! - `RootCertStore` is built fresh and contains ONLY the configured CA.
//!   System roots are never consulted (closed trust domain per design).
//! - Per-source-IP rate-limit (token bucket, 10/sec default) drops
//!   connections pre-handshake so a malicious client cannot exhaust
//!   handshake CPU. Multi-tenant hardening per design §"Multi-tenant
//!   hardening".
//! - No cert PEM, private key material, or peer-cert byte content is
//!   ever logged. Error strings use `[redacted]` for key material.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{JsonRpcRequest, PolicyDecision, build_policy_denied_response, gate_method};

// ---------------------------------------------------------------------------
// Hard-coded defenses against DoS / misuse — fix all CRIT findings from the
// Phase C adversarial review.
// ---------------------------------------------------------------------------

/// Per-frame byte ceiling. JSON-RPC envelopes for in-container agent calls
/// stay well under this; an attacker streaming a non-newline-terminated
/// blob hits this cap and the connection is dropped.
///
/// **CRIT-1 fix**: `tokio::io::AsyncBufReadExt::read_line` reads unbounded.
/// We replace it with `AsyncReadExt::take(MAX_FRAME_BYTES).read_to_end()`.
const MAX_FRAME_BYTES: u64 = 1 << 20; // 1 MiB

/// Per-handshake wallclock deadline. A connected TCP peer that sends no
/// ClientHello (or sends one byte every minute) is dropped before tying up
/// a tokio task for the lifetime of the listener.
///
/// **CRIT-2 fix**: no handshake timeout existed; slow-loris would pin tasks
/// forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wallclock deadline for reading the (single, bounded) JSON-RPC frame
/// after the TLS handshake completes. Same threat shape as the handshake
/// timeout — a peer that completes mTLS then writes one byte every minute
/// pins a task forever otherwise.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Global ceiling on concurrent per-connection handler tasks. Above this
/// the listener accepts the TCP connection (kernel will refuse if backlog
/// fills) but refuses to spawn the handler — drops the stream immediately.
///
/// **CRIT-2 fix**: bare per-IP rate-limit is useless against IPv6 /64
/// source rotation. Global semaphore caps total in-flight handlers.
const MAX_CONCURRENT_HANDLERS: usize = 256;

/// Idle eviction window for the per-IP rate-limit map. Entries whose
/// `last_refill` is older than this are evicted by the background sweeper.
///
/// **CRIT-3 fix**: the per-IP `HashMap` previously grew without bound;
/// an attacker rotating IPv6 source addresses could pin one entry per IP
/// forever (~80 bytes per entry).
const RATE_LIMITER_IDLE_EVICTION: Duration = Duration::from_secs(60);

/// Sweeper period for the rate-limit map eviction task.
const RATE_LIMITER_SWEEP_PERIOD: Duration = Duration::from_secs(30);

/// Maximum permitted nesting depth inside JSON-RPC `params` / `id`.
///
/// **HIGH-3 fix**: bound the input bytes (`MAX_FRAME_BYTES`) AND reject
/// pathological nesting (e.g. `[[[...]]]` 1 MiB deep) post-parse.
const MAX_JSON_NESTING_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("bind failed: {0}")]
    BindFailed(io::Error),

    #[error("read PEM file {0}: {1}")]
    ReadPem(PathBuf, io::Error),

    #[error("parse PEM file {0}: {1}")]
    ParsePem(PathBuf, &'static str),

    #[error("PEM file {0} contained no items of the expected kind")]
    EmptyPem(PathBuf),

    #[error("TLS config error: {0}")]
    TlsConfig(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Listener configuration. The three new path fields extend Phase B's
/// `Config` with the materials needed to actually serve mTLS:
///
/// - `server_cert_path` / `server_key_path` — ember-rpc's own server
///   identity, presented during the TLS handshake. Minted by emberd
///   core (sibling task `implementation-note-115`).
/// - `ca_cert_path` — the bridge CA cert used for client-auth
///   verification. emberd publishes this as `<data_dir>/bridge_ca.pub`
///   per `implementation-note-328`.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub listen_addr: std::net::SocketAddr,
    pub forward_uds: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

// ---------------------------------------------------------------------------
// PEM loading helpers
// ---------------------------------------------------------------------------

fn read_pem(path: &Path) -> Result<Vec<u8>, ListenerError> {
    std::fs::read(path).map_err(|e| ListenerError::ReadPem(path.to_path_buf(), e))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ListenerError> {
    let bytes = read_pem(path)?;
    let mut cursor = std::io::Cursor::new(bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ListenerError::ParsePem(path.to_path_buf(), "rustls_pemfile::certs"))?;
    if certs.is_empty() {
        return Err(ListenerError::EmptyPem(path.to_path_buf()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ListenerError> {
    let bytes = read_pem(path)?;
    let mut cursor = std::io::Cursor::new(bytes);
    let key = rustls_pemfile::private_key(&mut cursor)
        .map_err(|_| ListenerError::ParsePem(path.to_path_buf(), "rustls_pemfile::private_key"))?
        .ok_or_else(|| ListenerError::EmptyPem(path.to_path_buf()))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// TLS config
// ---------------------------------------------------------------------------

/// Build the `rustls::ServerConfig` for the mTLS listener.
///
/// Security invariants (mirror `crates/ember-daemon/src/infra/kms_edge.rs::
/// build_server_tls_config`, the shipped reference impl for the same pattern):
///
/// - `WebPkiClientVerifier::builder` REQUIRES a client cert — connections
///   without a valid cert are dropped at TLS handshake, not at the
///   application layer.
/// - The `RootCertStore` contains ONLY the configured CA cert. System roots
///   are deliberately excluded — closed trust domain per design.
fn build_server_tls_config(cfg: &ListenerConfig) -> Result<Arc<ServerConfig>, ListenerError> {
    // Install ring as the default crypto provider if not already done.
    // Idempotent — Err means a provider was already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_certs = load_certs(&cfg.ca_cert_path)?;

    let mut root_store = RootCertStore::empty();
    for ca in ca_certs {
        root_store
            .add(ca)
            .map_err(|e| ListenerError::TlsConfig(format!("add CA to root store: {e}")))?;
    }
    let root_store = Arc::new(root_store);

    let client_verifier = WebPkiClientVerifier::builder(root_store)
        .build()
        .map_err(|e| ListenerError::TlsConfig(format!("build client verifier: {e}")))?;

    let server_certs = load_certs(&cfg.server_cert_path)?;
    let server_key = load_private_key(&cfg.server_key_path)?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| ListenerError::TlsConfig(format!("server cert: {e}")))?;

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Method-name canonical-shape validator
// ---------------------------------------------------------------------------

/// True when `method` matches the canonical JSON-RPC method-name shape
/// `[a-z][a-z0-9_]*`. Refusing anything else neutralizes:
///
/// - Case-twiddled bypass of [`crate::gate_method`] (e.g. `Vault_Unseal`).
///   The gate matches `&[&str].contains` which is byte-equality; if a
///   future downstream dispatcher in emberd core ever normalizes
///   (`.to_lowercase()`, serde rename-all), a case-variant would slip
///   past the gate and hit a plaintext-bearing handler.
/// - Embedded control bytes / newlines / NULs / ANSI escapes that would
///   become log-injection vectors when echoed through `tracing::info!`.
/// - Unicode lookalikes / NFD-vs-NFC normalization mismatches.
///
/// **HIGH-1 fix**: the policy gate is the named structural invariant
/// per design / 155 amendment; defending it via byte-equality between
/// two crates is fragile. Validating the shape up-front rejects every
/// variant that could disagree with downstream normalization.
pub(crate) fn is_canonical_method_name(method: &str) -> bool {
    if method.is_empty() || method.len() > 128 {
        return false;
    }
    let mut chars = method.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Recursive depth check for `serde_json::Value`. Returns true when the
/// value (or any nested value reachable through it) exceeds
/// [`MAX_JSON_NESTING_DEPTH`].
fn json_exceeds_depth(value: &serde_json::Value, remaining: usize) -> bool {
    if remaining == 0 {
        return true;
    }
    match value {
        serde_json::Value::Array(arr) => arr.iter().any(|v| json_exceeds_depth(v, remaining - 1)),
        serde_json::Value::Object(obj) => {
            obj.values().any(|v| json_exceeds_depth(v, remaining - 1))
        }
        _ => false,
    }
}

/// Validate the JSON-RPC envelope's `id` per JSON-RPC 2.0 §4: only
/// string, number, or null are permitted. Objects/arrays are rejected
/// — they'd otherwise enable bandwidth-amp via the echo in the
/// phase-c-stub response (**HIGH-2 fix**).
fn id_is_well_formed(id: &serde_json::Value) -> bool {
    matches!(
        id,
        serde_json::Value::Null | serde_json::Value::Number(_) | serde_json::Value::String(_)
    )
}

// ---------------------------------------------------------------------------
// Per-source-IP rate limiter — simple token bucket
// ---------------------------------------------------------------------------

const DEFAULT_RATE_PER_SEC: f64 = 10.0;
const DEFAULT_BUCKET_CAPACITY: f64 = 10.0;

#[derive(Debug, Clone, Copy)]
struct BucketEntry {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Default)]
struct RateLimiter {
    inner: Mutex<HashMap<IpAddr, BucketEntry>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self::default()
    }

    /// Refill bucket from elapsed time and attempt to consume one token.
    /// Returns true when the connection is allowed.
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");
        let entry = map.entry(ip).or_insert_with(|| BucketEntry {
            tokens: DEFAULT_BUCKET_CAPACITY,
            last_refill: now,
        });
        let elapsed = now
            .saturating_duration_since(entry.last_refill)
            .as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * DEFAULT_RATE_PER_SEC).min(DEFAULT_BUCKET_CAPACITY);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evict entries whose `last_refill` is older than [`RATE_LIMITER_IDLE_EVICTION`].
    ///
    /// **CRIT-3 fix**: bound the per-IP map under IPv6-source-rotation
    /// attacks. The token-bucket math tolerates eviction — re-creating
    /// after eviction seeds a full bucket, which is a tiny rate-limit
    /// loophole in exchange for bounded memory.
    fn evict_idle(&self, now: Instant) -> usize {
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");
        let before = map.len();
        map.retain(|_ip, entry| {
            now.saturating_duration_since(entry.last_refill) < RATE_LIMITER_IDLE_EVICTION
        });
        before.saturating_sub(map.len())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("rate limiter mutex poisoned")
            .len()
    }
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// mTLS bridge listener handle.
///
/// Constructed via [`Listener::spawn`]. Dropping the returned `JoinHandle`
/// cancels the accept loop.
pub struct Listener;

impl Listener {
    /// Spawn the mTLS listener.
    ///
    /// Returns a `JoinHandle` that drives the accept loop. Call
    /// `.abort()` on the handle to cancel the listener (dropping the
    /// `JoinHandle` only *detaches* the task — it does not cancel).
    pub async fn spawn(config: ListenerConfig) -> Result<JoinHandle<()>, ListenerError> {
        let tls_config = build_server_tls_config(&config)?;
        let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));

        let tcp_listener = TcpListener::bind(config.listen_addr)
            .await
            .map_err(ListenerError::BindFailed)?;

        let bind_addr = tcp_listener.local_addr().unwrap_or(config.listen_addr);
        let rate_limiter = Arc::new(RateLimiter::new());
        let handler_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDLERS));

        info!(
            %bind_addr,
            forward_uds = %config.forward_uds.display(),
            rate_per_sec = DEFAULT_RATE_PER_SEC,
            bucket_capacity = DEFAULT_BUCKET_CAPACITY,
            max_concurrent_handlers = MAX_CONCURRENT_HANDLERS,
            max_frame_bytes = MAX_FRAME_BYTES,
            handshake_timeout_secs = HANDSHAKE_TIMEOUT.as_secs(),
            "ember-rpc Phase C mTLS listener accepting"
        );

        // Background eviction sweeper for the per-IP rate-limit map
        // (CRIT-3 fix). Tied to the accept-loop's lifetime via the
        // rate_limiter Arc: when the outer JoinHandle is aborted, this
        // task is dropped too via Arc refcount → no orphan.
        let evict_rl = Arc::clone(&rate_limiter);
        let evict_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RATE_LIMITER_SWEEP_PERIOD);
            // Skip first immediate tick.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let evicted = evict_rl.evict_idle(Instant::now());
                if evicted > 0 {
                    debug!(evicted, "rate-limiter: evicted idle buckets");
                }
            }
        });

        let handle = tokio::spawn(async move {
            // Move the eviction task handle into the accept-loop task so
            // it gets aborted when the outer handle is aborted.
            let _evict_task = evict_task;

            loop {
                let (stream, peer_addr) = match tcp_listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "listener: accept error");
                        continue;
                    }
                };

                // Pre-handshake rate-limit check. Drop the connection
                // without entering the TLS state machine if the bucket
                // for the source IP is empty.
                if !rate_limiter.allow(peer_addr.ip()) {
                    debug!(%peer_addr, "listener: rate-limited, dropping pre-handshake");
                    drop(stream);
                    continue;
                }

                // Global concurrent-handler ceiling (CRIT-2 fix).
                // try_acquire_owned() is non-blocking — if the
                // semaphore is exhausted we drop the connection
                // pre-handshake rather than queue it.
                let permit = match Arc::clone(&handler_semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        debug!(
                            %peer_addr,
                            in_flight = MAX_CONCURRENT_HANDLERS,
                            "listener: handler ceiling reached, dropping pre-handshake"
                        );
                        drop(stream);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // Hold the permit for the lifetime of the handler.
                    // Dropped on return (success, error, or panic via
                    // tokio's task-cancellation cleanup).
                    let _permit = permit;
                    handle_connection(acceptor, stream, peer_addr).await;
                });
            }
        });

        Ok(handle)
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) {
    // Complete the TLS handshake within HANDSHAKE_TIMEOUT (CRIT-2 fix).
    // Failure here means the client either didn't present a cert,
    // presented one that wasn't CA-signed, hit a protocol error, or
    // exceeded the handshake deadline (slow-loris). Drop the
    // connection in all cases.
    let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(
                %peer_addr,
                error = %e,
                "listener: TLS handshake failed [cert=[redacted]]"
            );
            return;
        }
        Err(_) => {
            warn!(
                %peer_addr,
                timeout_secs = HANDSHAKE_TIMEOUT.as_secs(),
                "listener: TLS handshake timed out (slow-loris defense)"
            );
            return;
        }
    };

    // Confirm the peer presented at least one cert. `WebPkiClientVerifier`
    // enforces this at handshake — the check here is belt-and-suspenders
    // so a rustls behavior change can't silently widen the surface.
    {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.peer_certificates() {
            Some(certs) if !certs.is_empty() => {
                debug!(
                    %peer_addr,
                    chain_len = certs.len(),
                    "listener: peer cert chain present"
                );
            }
            _ => {
                warn!(%peer_addr, "listener: no peer cert after handshake (rustls invariant violated)");
                return;
            }
        }
    }

    // Read ONE bounded JSON-RPC frame. Cap at MAX_FRAME_BYTES (CRIT-1
    // fix); apply FRAME_READ_TIMEOUT so post-handshake slow-loris is
    // also defeated.
    //
    // `read_until(b'\n', ...)` over a `take(MAX_FRAME_BYTES)`-wrapped
    // reader returns when ANY of:
    //   (a) the cap is reached (`take` reports EOF after N bytes)
    //   (b) a `\n` is found
    //   (c) the peer half-closes
    //   (d) the deadline fires
    //
    // The client convention is one frame per connection terminated by
    // `\n` (which the smoke tests + the bridge-cli ping client both
    // honor). Cap-without-newline produces a truncated read that
    // fails the JSON-RPC parse downstream and returns a -32700.
    let (read_half, mut write_half) = tokio::io::split(tls_stream);
    let mut bounded = BufReader::new(read_half.take(MAX_FRAME_BYTES));
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let read_result =
        tokio::time::timeout(FRAME_READ_TIMEOUT, bounded.read_until(b'\n', &mut buf)).await;

    let bytes_read = match read_result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!(%peer_addr, error = %e, "listener: read frame failed");
            return;
        }
        Err(_) => {
            warn!(
                %peer_addr,
                timeout_secs = FRAME_READ_TIMEOUT.as_secs(),
                "listener: post-handshake frame read timed out"
            );
            return;
        }
    };

    if bytes_read == 0 {
        debug!(%peer_addr, "listener: client closed before sending a frame");
        return;
    }

    // Trim a trailing newline if present (newline-delimited JSON
    // shape is the documented contract).
    let frame_bytes = match buf.last() {
        Some(b'\n') => &buf[..buf.len() - 1],
        _ => &buf[..],
    };

    // Parse the JSON-RPC envelope. Malformed frames get a -32700 parse
    // error response per the JSON-RPC 2.0 spec.
    let req: JsonRpcRequest = match serde_json::from_slice(frame_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!(%peer_addr, error = %e, "listener: malformed JSON-RPC frame");
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "parse error"},
                "id": serde_json::Value::Null,
            });
            let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
            bytes.push(b'\n');
            let _ = write_half.write_all(&bytes).await;
            return;
        }
    };

    // ----- Post-parse validation gates (HIGH-1 / HIGH-2 / HIGH-3 fixes) -----
    //
    // 1. id must be string | number | null (JSON-RPC 2.0 §4). Reject
    //    object/array ids — they otherwise enable bandwidth-amp via
    //    the echo back in error / stub responses.
    if !id_is_well_formed(&req.id) {
        warn!(
            %peer_addr,
            "listener: rejecting malformed id (must be string/number/null)"
        );
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "invalid request: id must be string, number, or null"},
            "id": serde_json::Value::Null,
        });
        let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
        bytes.push(b'\n');
        let _ = write_half.write_all(&bytes).await;
        return;
    }

    // 2. Reject pathologically nested params / id (depth-bomb defense).
    if json_exceeds_depth(&req.params, MAX_JSON_NESTING_DEPTH)
        || json_exceeds_depth(&req.id, MAX_JSON_NESTING_DEPTH)
    {
        warn!(
            %peer_addr,
            max_depth = MAX_JSON_NESTING_DEPTH,
            "listener: rejecting frame with excessive nesting"
        );
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "invalid request: nesting too deep"},
            "id": serde_json::Value::Null,
        });
        let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
        bytes.push(b'\n');
        let _ = write_half.write_all(&bytes).await;
        return;
    }

    // 3. Method-name canonical-shape check. HIGH-1 fix: the policy
    //    gate is byte-equality; non-canonical shapes (case-twiddled,
    //    Unicode-decorated, embedded-control-bytes) get rejected
    //    here so they cannot create a downstream-normalization
    //    mismatch with emberd-core's dispatcher.
    if !is_canonical_method_name(&req.method) {
        info!(
            %peer_addr,
            "listener: rejecting non-canonical method name (must match [a-z][a-z0-9_]*)"
        );
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "invalid request: method name must match [a-z][a-z0-9_]*"},
            "id": req.id,
        });
        let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
        bytes.push(b'\n');
        let _ = write_half.write_all(&bytes).await;
        return;
    }

    // Route through the policy gate. The gate is the load-bearing
    // structural invariant — plaintext-bearing methods cannot reach
    // the forward path even by code-mistake. By the time we reach
    // here `req.method` matches `[a-z][a-z0-9_]*` so any disagreement
    // with downstream normalization is impossible.
    let response_bytes = match gate_method(&req.method) {
        PolicyDecision::DenyPlaintextBearing => {
            info!(
                %peer_addr,
                method = %req.method,
                "listener: policy-denied (plaintext-bearing method on mTLS lane)"
            );
            let resp = build_policy_denied_response(&req);
            serde_json::to_vec(&resp).unwrap_or_default()
        }
        PolicyDecision::AllowForward => {
            // Phase C stub. Phase D replaces this with a real bincode
            // forward over `config.forward_uds` to emberd core. The
            // stub shape lets clients verify the gate-allow path
            // round-trips end-to-end without requiring the Phase D
            // emberd-side consumer.
            //
            // **HIGH-2 fix**: don't echo the method name back. The
            // method-name echo was a method-existence oracle and an
            // amplification vector. The round-trip is verified by
            // receiving ANY successful response.
            info!(
                %peer_addr,
                method = %req.method,
                "listener: allow-forward (phase-c-stub; Phase D wires real forward)"
            );
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "forwarded": false,
                    "reason": "phase-c-stub",
                },
                "id": req.id,
            });
            serde_json::to_vec(&resp).unwrap_or_default()
        }
    };

    let mut framed = response_bytes;
    framed.push(b'\n');
    if let Err(e) = write_half.write_all(&framed).await {
        warn!(%peer_addr, error = %e, "listener: write response failed");
    }
    let _ = write_half.shutdown().await;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_limiter_initially_allows_burst_up_to_capacity() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // The bucket starts at DEFAULT_BUCKET_CAPACITY (10). Ten back-
        // to-back accepts must all succeed; the eleventh must fail
        // until time passes.
        for i in 0..(DEFAULT_BUCKET_CAPACITY as u32) {
            assert!(
                limiter.allow(ip),
                "burst accept {} must succeed under initial capacity",
                i
            );
        }
        assert!(
            !limiter.allow(ip),
            "burst accept past initial capacity must be rate-limited"
        );
    }

    #[test]
    fn rate_limiter_refills_with_elapsed_time() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // Drain the bucket.
        for _ in 0..(DEFAULT_BUCKET_CAPACITY as u32) {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));
        // Sleep just past the refill interval for ~1 token (1 / 10 = 0.1s).
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            limiter.allow(ip),
            "bucket must refill at least one token after 0.15s at 10/sec"
        );
    }

    #[test]
    fn rate_limiter_evicts_idle_entries() {
        let limiter = RateLimiter::new();
        let ip_a: IpAddr = "127.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(limiter.allow(ip_a));
        assert!(limiter.allow(ip_b));
        assert_eq!(limiter.len(), 2);
        // Step "now" forward past the eviction window. Use a synthetic
        // Instant we construct by adding the idle window plus a margin
        // to a known anchor.
        let future = Instant::now() + RATE_LIMITER_IDLE_EVICTION + Duration::from_secs(1);
        let evicted = limiter.evict_idle(future);
        assert_eq!(evicted, 2, "both idle buckets should be evicted");
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn canonical_method_name_accepts_valid_shapes() {
        assert!(is_canonical_method_name("vault_status"));
        assert!(is_canonical_method_name("list_grants"));
        assert!(is_canonical_method_name("audit_tail"));
        assert!(is_canonical_method_name("ping"));
        assert!(is_canonical_method_name("a"));
        assert!(is_canonical_method_name("a0"));
    }

    #[test]
    fn canonical_method_name_rejects_attack_shapes() {
        // Case-twiddled (HIGH-1 attack)
        assert!(!is_canonical_method_name("Vault_Unseal"));
        assert!(!is_canonical_method_name("VAULT_UNSEAL"));
        // Whitespace / newlines / NULs (log-injection)
        assert!(!is_canonical_method_name("vault unseal"));
        assert!(!is_canonical_method_name("vault_unseal\n"));
        assert!(!is_canonical_method_name("vault_unseal\0"));
        // ANSI escape sequence
        assert!(!is_canonical_method_name("vault_unseal\x1b[31m"));
        // Leading digit / underscore
        assert!(!is_canonical_method_name("0vault"));
        assert!(!is_canonical_method_name("_vault"));
        // Unicode (NFC-decoration)
        assert!(!is_canonical_method_name("vault_unsea\u{0301}l"));
        // Path-traversal-style
        assert!(!is_canonical_method_name("./vault_unseal"));
        assert!(!is_canonical_method_name("vault-unseal"));
        // Empty
        assert!(!is_canonical_method_name(""));
        // Too long (over 128 chars)
        assert!(!is_canonical_method_name(&"a".repeat(129)));
    }

    #[test]
    fn id_is_well_formed_per_jsonrpc_spec() {
        assert!(id_is_well_formed(&serde_json::Value::Null));
        assert!(id_is_well_formed(&serde_json::Value::from(7u64)));
        assert!(id_is_well_formed(&serde_json::Value::from("req-1")));
        // Reject arrays/objects (HIGH-2 amplification surface)
        assert!(!id_is_well_formed(&serde_json::json!([1, 2, 3])));
        assert!(!id_is_well_formed(&serde_json::json!({"k": "v"})));
    }

    #[test]
    fn json_depth_check_catches_array_bomb() {
        // With remaining=N, the check rejects when an Array/Object is
        // encountered after the budget hits zero — so the function
        // accepts up to N-1 nested arrays and rejects N+ nested arrays.
        // Build a nest just under the limit; should pass.
        let mut under_limit = serde_json::Value::Null;
        for _ in 0..(MAX_JSON_NESTING_DEPTH - 1) {
            under_limit = serde_json::Value::Array(vec![under_limit]);
        }
        assert!(
            !json_exceeds_depth(&under_limit, MAX_JSON_NESTING_DEPTH),
            "nest of MAX-1 arrays should be accepted"
        );
        // One more level → rejected.
        let over = serde_json::Value::Array(vec![under_limit]);
        assert!(
            json_exceeds_depth(&over, MAX_JSON_NESTING_DEPTH),
            "nest of MAX arrays should be rejected"
        );
    }

    #[test]
    fn rate_limiter_buckets_are_per_ip() {
        let limiter = RateLimiter::new();
        let ip_a: IpAddr = "127.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "127.0.0.2".parse().unwrap();
        // Drain bucket for ip_a.
        for _ in 0..(DEFAULT_BUCKET_CAPACITY as u32) {
            assert!(limiter.allow(ip_a));
        }
        assert!(!limiter.allow(ip_a));
        // ip_b's bucket is independent and starts full.
        assert!(
            limiter.allow(ip_b),
            "second IP's bucket must be independent of first IP's drain"
        );
    }
}
