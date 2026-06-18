pub mod admission;
pub mod tls;

pub use admission::{AdmissionError, AdmittedRequest};

/// Domain-separation prefix bound into every `RESPOND_GRANT_REQUEST`
/// signature so a signed payload for this wire cannot be replayed into a
/// different protocol that happens to share the responder's signing key
/// (ADR 200 §4 algorithm-confusion / cross-protocol guard).
pub const RESPOND_GRANT_REQUEST_DOMAIN_SEP: &[u8] = b"emberlink-relay/respond-grant-request/v1\0";

/// Nonce size required on `RESPOND_GRANT_REQUEST` frames (32 raw bytes,
/// 64 hex chars). Matches ADR 200's per-use nonce tombstone convention.
pub const RESPOND_GRANT_REQUEST_NONCE_BYTES: usize = 32;

/// Soft cap on the consumed-nonce dedup set. The relay only ever needs
/// nonces that are still in their replay window — once a grant request
/// has been resolved the responder cannot reissue, so the set can shed
/// pressure under sustained abuse without losing security. Far above
/// the legitimate `100`-per-target REQUEST_GRANT rate limit so it never
/// kicks in under normal operation.
const MAX_CONSUMED_NONCES: usize = 100_000;

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use core_crypto::{Ed25519Verifier, PublicKey, Signature, Verifier, parse_did, resolve_did_jwks};
use core_principals::{RelayAdmission, RelayMode, TrustThreshold};
use core_sync::{PortableRelaySubmission, check_relay_submission_admission};

use crate::tls::{RelayStream, TlsMode};

/// Configuration for the relay daemon.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_address: String,
    pub mode: RelayMode,
    pub threshold: Option<TrustThreshold>,
    pub allowlist: Vec<String>,
    pub trusted_issuer_keys: HashMap<String, String>,
    pub tls_mode: TlsMode,
    /// Maximum envelopes queued per peer mailbox (0 = unlimited).
    pub max_per_peer: usize,
    /// Maximum total envelopes across all mailboxes (0 = unlimited).
    pub max_total: usize,
    /// Optional shared secret that gates authority-bearing admin commands
    /// (STATS, SHUTDOWN, SHUTDOWN-NOTICE, DRAIN). Every admin command must
    /// include the token as its first space-delimited argument; requests that
    /// omit or mis-state the token are rejected with `AUTH-REQUIRED`.
    /// When `None` the relay rejects admin commands rather than accepting
    /// them from arbitrary clients.
    pub admin_token: Option<String>,
    /// Maximum simultaneous TCP connections (0 = unlimited).
    /// Connections beyond this limit are immediately closed.
    pub max_connections: usize,
    /// Read/write timeout per connection in seconds (0 = no timeout).
    pub read_timeout_secs: u64,
    /// Maximum offers stored per depositor source (0 = unlimited).
    /// Default: 100.
    pub max_offers_per_peer: usize,
    /// Maximum total bytes across all stored offer payloads (0 = unlimited).
    /// Default: 50 MB.
    pub max_offer_bytes_total: usize,
    /// Maximum offer TTL in seconds. Deposits requesting a longer TTL are
    /// capped to this value.  Default: 72 hours (259200).
    pub max_offer_ttl_secs: u64,
    /// TCP port for the HTTP /health endpoint (None = disabled).
    /// Default: 9101.
    pub health_port: Option<u16>,
    /// TCP port for the WebSocket listener (None = disabled).
    ///
    /// v0.3.0 release containment disables this listener from CLI config
    /// because the legacy WS protocol carries the full command surface without
    /// TLS/client auth. `--ws-port` is accepted as a compatibility no-op.
    pub ws_port: Option<u16>,
}

impl RelayConfig {
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut bind_address = "127.0.0.1:9100".to_string();
        let mut mode = RelayMode::Open;
        let mut threshold: Option<TrustThreshold> = None;
        let mut allowlist: Vec<String> = Vec::new();
        let mut trusted_issuer_keys = HashMap::new();
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;
        let mut tls_self_signed = false;
        // `no_tls` is only mutated when the `insecure-no-tls` feature is on.
        // Suppress `unused_mut` (and `unused_variables` in the negative gate)
        // so the production build stays warning-clean without splitting the
        // surrounding `match` block.
        #[allow(unused_mut, unused_assignments)]
        let mut no_tls = false;
        let mut max_per_peer: usize = 10_000;
        let mut max_total: usize = 1_000_000;
        let mut admin_token: Option<String> = None;
        let mut max_connections: usize = 1_000;
        let mut read_timeout_secs: u64 = 30;
        let mut max_offers_per_peer: usize = 100;
        let mut max_offer_bytes_total: usize = 50 * 1024 * 1024; // 50 MB
        let mut max_offer_ttl_secs: u64 = 72 * 3600; // 72 hours
        let mut health_port: Option<u16> = Some(9101);
        let mut ws_port: Option<u16> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--bind" => {
                    i += 1;
                    bind_address = args.get(i).ok_or("--bind requires an address")?.clone();
                }
                "--mode" => {
                    i += 1;
                    let value = args.get(i).ok_or("--mode requires a value")?;
                    mode = RelayMode::parse(value)
                        .ok_or_else(|| format!("unknown relay mode: {value}"))?;
                }
                "--threshold" => {
                    i += 1;
                    let value: f32 = args
                        .get(i)
                        .ok_or("--threshold requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid threshold: {e}"))?;
                    threshold = Some(
                        TrustThreshold::new(value)
                            .map_err(|e| format!("invalid threshold: {e}"))?,
                    );
                }
                "--allow" => {
                    i += 1;
                    let persona = args.get(i).ok_or("--allow requires a persona ID")?.clone();
                    allowlist.push(persona);
                }
                "--trusted-issuer" => {
                    i += 1;
                    let value = args
                        .get(i)
                        .ok_or("--trusted-issuer requires persona-id=public-key")?;
                    let Some((persona_id, public_key)) = value.split_once('=') else {
                        return Err(
                            "--trusted-issuer must be formatted as persona-id=public-key"
                                .to_string(),
                        );
                    };
                    if persona_id.is_empty() || public_key.is_empty() {
                        return Err(
                            "--trusted-issuer must include both persona ID and public key"
                                .to_string(),
                        );
                    }
                    trusted_issuer_keys.insert(persona_id.to_string(), public_key.to_string());
                }
                "--tls-cert" => {
                    i += 1;
                    tls_cert = Some(
                        args.get(i)
                            .ok_or("--tls-cert requires a file path")?
                            .clone(),
                    );
                }
                "--tls-key" => {
                    i += 1;
                    tls_key = Some(args.get(i).ok_or("--tls-key requires a file path")?.clone());
                }
                "--tls-self-signed" => {
                    tls_self_signed = true;
                }
                "--no-tls" => {
                    // Tier A §A4:
                    // mandatory TLS in production. The `insecure-no-tls` feature
                    // is OFF by default; production builds reject this flag as
                    // unknown rather than silently downgrading to plain TCP.
                    // Anchor: `respond_grant_request_signed_no_tls_test_only_feature`.
                    #[cfg(feature = "insecure-no-tls")]
                    {
                        no_tls = true;
                    }
                    #[cfg(not(feature = "insecure-no-tls"))]
                    {
                        return Err("--no-tls is rejected in production builds; \
                             rebuild with --features insecure-no-tls only for test \
                             loopback rigs (AUDIT-V030-RELAY-TLS-AND-RESPOND-GRANT-SIGNATURE)"
                            .to_string());
                    }
                }
                "--max-per-peer" => {
                    i += 1;
                    max_per_peer = args
                        .get(i)
                        .ok_or("--max-per-peer requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid max-per-peer: {e}"))?;
                }
                "--max-total" => {
                    i += 1;
                    max_total = args
                        .get(i)
                        .ok_or("--max-total requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid max-total: {e}"))?;
                }
                "--admin-token" => {
                    i += 1;
                    let token = args.get(i).ok_or("--admin-token requires a value")?.clone();
                    if token.is_empty() {
                        return Err("--admin-token must not be empty".to_string());
                    }
                    admin_token = Some(token);
                }
                "--max-connections" => {
                    i += 1;
                    max_connections = args
                        .get(i)
                        .ok_or("--max-connections requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid max-connections: {e}"))?;
                }
                "--read-timeout" => {
                    i += 1;
                    read_timeout_secs = args
                        .get(i)
                        .ok_or("--read-timeout requires a value in seconds")?
                        .parse()
                        .map_err(|e| format!("invalid read-timeout: {e}"))?;
                }
                "--max-offers-per-peer" => {
                    i += 1;
                    max_offers_per_peer = args
                        .get(i)
                        .ok_or("--max-offers-per-peer requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid max-offers-per-peer: {e}"))?;
                }
                "--max-offer-bytes" => {
                    i += 1;
                    max_offer_bytes_total = args
                        .get(i)
                        .ok_or("--max-offer-bytes requires a value")?
                        .parse()
                        .map_err(|e| format!("invalid max-offer-bytes: {e}"))?;
                }
                "--max-offer-ttl" => {
                    i += 1;
                    max_offer_ttl_secs = args
                        .get(i)
                        .ok_or("--max-offer-ttl requires a value in seconds")?
                        .parse()
                        .map_err(|e| format!("invalid max-offer-ttl: {e}"))?;
                }
                "--health-port" => {
                    i += 1;
                    let port: u16 = args
                        .get(i)
                        .ok_or("--health-port requires a port number")?
                        .parse()
                        .map_err(|e| format!("invalid health-port: {e}"))?;
                    health_port = Some(port);
                }
                "--no-health" => {
                    health_port = None;
                }
                "--ws-port" => {
                    i += 1;
                    let _port: u16 = args
                        .get(i)
                        .ok_or("--ws-port requires a port number")?
                        .parse()
                        .map_err(|e| format!("invalid ws-port: {e}"))?;
                    ws_port = None;
                }
                "--no-ws" => {
                    ws_port = None;
                }
                other => return Err(format!("unknown flag: {other}")),
            }
            i += 1;
        }

        if mode == RelayMode::TrustGated && threshold.is_none() {
            return Err("trust-gated mode requires --threshold".to_string());
        }
        if mode == RelayMode::TrustGated && trusted_issuer_keys.is_empty() {
            return Err(
                "trust-gated mode requires at least one --trusted-issuer persona-id=public-key"
                    .to_string(),
            );
        }

        let tls_mode = if no_tls {
            TlsMode::Plain
        } else if tls_self_signed {
            TlsMode::SelfSigned
        } else {
            match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => TlsMode::FromFiles {
                    cert_path: cert,
                    key_path: key,
                },
                (Some(_), None) | (None, Some(_)) => {
                    return Err("--tls-cert and --tls-key must both be provided".to_string());
                }
                (None, None) => TlsMode::SelfSigned,
            }
        };

        Ok(Self {
            bind_address,
            mode,
            threshold,
            allowlist,
            trusted_issuer_keys,
            tls_mode,
            max_per_peer,
            max_total,
            admin_token,
            max_connections,
            read_timeout_secs,
            max_offers_per_peer,
            max_offer_bytes_total,
            max_offer_ttl_secs,
            health_port,
            ws_port,
        })
    }
}

/// Graceful shutdown notice state.
#[derive(Debug, Clone)]
pub struct ShutdownNotice {
    pub reason: String,
    pub deadline_epoch: u64,
}

/// A stored grant offer envelope.
///
/// The relay stores offers as opaque encrypted blobs indexed by offer ID.
/// It never sees plaintext — the `payload` is the sealed envelope bytes
/// provided by the issuer.
#[derive(Debug)]
pub struct StoredOffer {
    /// Opaque encrypted offer payload (bytes as hex or raw, issuer-defined).
    pub payload: Vec<u8>,
    /// Epoch seconds after which this offer is expired and may be purged.
    pub expires_at: u64,
    /// Whether this offer has been claimed (consumed).
    pub claimed: bool,
    /// Source identifier (peer address) for per-peer quota tracking.
    pub source: String,
}

/// A stored credential envelope.
///
/// The relay stores credentials as opaque encrypted blobs indexed by grant ID.
/// Unlike offers, credentials are not consumed on fetch — they persist until
/// explicitly revoked or the 30-day TTL expires.
#[derive(Debug)]
pub struct StoredCredential {
    /// Opaque encrypted credential payload (bytes).
    pub payload: Vec<u8>,
    /// Unix timestamp when this credential was deposited.
    pub deposit_time: u64,
}

/// Status of a grant request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRequestStatus {
    Pending,
    Approved,
    Denied,
}

/// A grant request from an agent to a human identity.
///
/// **At-rest sealing.** The relay used
/// to store the requester id, scope, and justification as plaintext
/// `String` fields. The relay contract mandates that relays see only opaque
/// encrypted envelopes — "relays never hold plaintext content" — and the
/// free-relay tier's compelled-disclosure resistance depends on it. After this
/// change the relay stores a single
/// `sealed_payload: Vec<u8>` opaque blob; the responder unseals it
/// outside the relay's address space.
///
/// `target_id` stays cleartext because the relay must route fetch
/// queries by it — the minimum metadata ADR 007 allows the relay to see
/// for routing.
///
/// `target_signing_pubkey` is the responder's persona signing key,
/// posted in cleartext by the requester at REQUEST time so the relay can
/// verify the signature attached to the matching `RESPOND_GRANT_REQUEST`.
/// The signing-pubkey itself is public material; carrying it on the
/// wire does not leak anything ADR 007 protects.
#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub request_id: String,
    pub target_id: String,
    pub target_signing_pubkey: PublicKey,
    pub sealed_payload: Vec<u8>,
    pub created_at: u64,
    pub status: GrantRequestStatus,
}

/// Shared relay state: queued envelopes waiting for pickup by downstream peers.
#[derive(Debug, Default)]
pub struct RelayState {
    pub mailboxes: HashMap<String, Vec<PortableRelaySubmission>>,
    /// Grant offer store: offer_id → StoredOffer.
    pub offers: HashMap<String, StoredOffer>,
    /// Per-source offer count tracking for quota enforcement.
    pub offer_counts_by_source: HashMap<String, usize>,
    /// Running total of offer payload bytes (updated on insert/purge).
    pub offer_bytes_total: usize,
    /// Credential store: grant_id → StoredCredential.
    pub credential_store: HashMap<String, StoredCredential>,
    /// Grant request store: target_id → pending requests from agents.
    pub grant_requests: HashMap<String, Vec<GrantRequest>>,
    /// Monotonically increasing counter for grant request IDs.
    pub next_grant_request_id: u64,
    /// Nonces consumed by
    /// accepted `RESPOND_GRANT_REQUEST` frames. Each successful response
    /// inserts its 32-byte nonce here; replays are rejected with
    /// `REJECTED nonce replay`. Bounded by `MAX_CONSUMED_NONCES` to cap
    /// memory growth.
    pub consumed_response_nonces: HashSet<String>,
    pub stats: RelayStats,
    pub shutdown_notice: Option<ShutdownNotice>,
}

#[derive(Debug)]
pub struct RelayStats {
    pub accepted: u64,
    pub rejected: u64,
    pub delivered: u64,
    pub started_at: u64,
    pub peers_seen: std::collections::HashSet<String>,
}

impl Default for RelayStats {
    fn default() -> Self {
        Self {
            accepted: 0,
            rejected: 0,
            delivered: 0,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            peers_seen: std::collections::HashSet::new(),
        }
    }
}

impl RelayState {
    pub fn queued_count(&self) -> usize {
        self.mailboxes.values().map(Vec::len).sum()
    }

    /// Remove all offers whose `expires_at` is at or before `now`.
    /// Also updates byte totals and per-source counts.
    pub fn purge_expired_offers(&mut self, now: u64) {
        self.offers.retain(|_, o| {
            if o.expires_at > now {
                return true;
            }
            // Decrement counters for purged offers.
            self.offer_bytes_total = self.offer_bytes_total.saturating_sub(o.payload.len());
            if let Some(count) = self.offer_counts_by_source.get_mut(&o.source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    // Mark for removal — will clean up empty entries below.
                }
            }
            false
        });
        self.offer_counts_by_source.retain(|_, c| *c > 0);
    }

    /// Remove credentials older than `ttl_secs` (default: 30 days).
    pub fn purge_expired_credentials(&mut self, now: u64, ttl_secs: u64) {
        self.credential_store
            .retain(|_, c| now.saturating_sub(c.deposit_time) < ttl_secs);
    }
}

/// Entry point: run the relay with the given config. Blocks until the process exits.
pub fn run(config: RelayConfig) {
    let tls_label = match &config.tls_mode {
        TlsMode::Plain => "plain (no TLS)",
        TlsMode::SelfSigned => "self-signed TLS",
        TlsMode::FromFiles { cert_path, .. } => cert_path.as_str(),
    };
    eprintln!(
        "emberlink-relay starting on {} mode={} tls={}",
        config.bind_address,
        config.mode.as_str(),
        tls_label,
    );
    if let Some(t) = config.threshold {
        eprintln!("  threshold: {:.2}", t.value());
    }
    if !config.allowlist.is_empty() {
        eprintln!("  allowlist: {:?}", config.allowlist);
    }
    if !config.trusted_issuer_keys.is_empty() {
        eprintln!(
            "  trusted issuers: {:?}",
            config.trusted_issuer_keys.keys().collect::<Vec<_>>()
        );
    }
    if config.admin_token.is_some() {
        eprintln!("  admin commands: token-protected");
    } else {
        eprintln!("  admin commands: disabled (set --admin-token to enable)");
    }
    if config.max_connections > 0 {
        eprintln!("  max connections: {}", config.max_connections);
    }
    if config.read_timeout_secs > 0 {
        eprintln!("  read/write timeout: {}s", config.read_timeout_secs);
    }
    if config.ws_port.is_none() {
        eprintln!("  ws listener: disabled for v0.3.0 release containment");
    }

    let tls_config = match tls::build_server_config(&config.tls_mode) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("TLS setup failed: {e}");
            std::process::exit(1);
        }
    };

    let start_time = Instant::now();

    let state = Arc::new(Mutex::new(RelayState::default()));
    let config = Arc::new(config);
    let active_connections = Arc::new(AtomicUsize::new(0));

    if let Some(port) = config.health_port {
        let mode = config.mode;
        let ws_port = config.ws_port;
        let bind_host = auxiliary_bind_host(&config.bind_address);
        thread::spawn(move || run_health_server_bound(bind_host, port, mode, start_time, ws_port));
    }

    if let Some(ws_port) = config.ws_port {
        let ws_config = Arc::clone(&config);
        let ws_state = Arc::clone(&state);
        let ws_active = Arc::clone(&active_connections);
        let ws_bind_host = auxiliary_bind_host(&config.bind_address);
        thread::spawn(move || {
            run_ws_listener_bound(ws_bind_host, ws_port, ws_config, ws_state, ws_active)
        });
        eprintln!("  ws port: {ws_port}");
    }

    let listener = match TcpListener::bind(&config.bind_address) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {}: {e}", config.bind_address);
            std::process::exit(1);
        }
    };

    let tls_config = Arc::new(tls_config);

    for stream in listener.incoming() {
        match stream {
            Ok(tcp_stream) => {
                // Enforce connection limit before spawning a thread.
                if config.max_connections > 0 {
                    let current = active_connections.load(Ordering::Relaxed);
                    if current >= config.max_connections {
                        eprintln!(
                            "connection limit reached ({current}/{}) — dropping new connection",
                            config.max_connections
                        );
                        continue;
                    }
                }

                // Apply read/write timeouts to bound how long a slow client holds a thread.
                if config.read_timeout_secs > 0 {
                    let timeout = Duration::from_secs(config.read_timeout_secs);
                    if let Err(e) = tcp_stream
                        .set_read_timeout(Some(timeout))
                        .and(tcp_stream.set_write_timeout(Some(timeout)))
                    {
                        eprintln!("warning: could not set socket timeout: {e}");
                    }
                }

                let config = Arc::clone(&config);
                let state = Arc::clone(&state);
                let tls_config = Arc::clone(&tls_config);
                let active_connections = Arc::clone(&active_connections);
                thread::spawn(move || {
                    active_connections.fetch_add(1, Ordering::Relaxed);
                    match RelayStream::accept(tcp_stream, tls_config.as_ref().as_ref()) {
                        Ok(stream) => handle_connection(stream, &config, &state),
                        Err(e) => eprintln!("TLS handshake error: {e}"),
                    }
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }
}

/// Wire protocol (minimal, v0.5):
///
/// Client sends: 4-byte big-endian length prefix, then payload bytes.
/// Payload is one of:
///   - A PortableRelaySubmission (submit for forwarding)
///   - `DRAIN <peer-id> <admin-token>` — receive queued envelopes
///   - `STATS <admin-token>` — relay statistics
///   - `SHUTDOWN <admin-token>` — immediate shutdown (flushes all mailboxes)
///   - `SHUTDOWN-NOTICE <admin-token> <reason> <deadline-epoch>` — graceful shutdown
///   - `DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>` — store a grant offer envelope
///   - `FETCH_OFFER <offer-id>` — retrieve a grant offer envelope by ID
///   - `CLAIM_OFFER <offer-id>` — mark a grant offer as consumed
///   - `FETCH_AND_CLAIM <offer-id>` — atomically fetch and claim an offer (recommended)
///
/// Admin commands without the correct configured token receive an
/// `AUTH-REQUIRED` response and are otherwise ignored.
/// Grant offer commands (DEPOSIT_OFFER, FETCH_OFFER, CLAIM_OFFER, FETCH_AND_CLAIM) are open to any
/// connected client — same policy as envelope submission.
/// Legacy credential/grant-request commands are parsed for compatibility but
/// dispatch rejects them for v0.3.0 release containment.
///
/// Server responds with the same length-prefixed format.
fn handle_connection(
    mut stream: RelayStream,
    config: &RelayConfig,
    state: &Arc<Mutex<RelayState>>,
) {
    let payload = match read_frame(&mut stream) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("read error: {e}");
            return;
        }
    };

    dispatch_command(&mut stream, &payload, config, state);
}

/// Core command dispatch: parse the payload, execute the appropriate handler,
/// and write the response to the provided writer.  Shared by both the TCP and
/// WebSocket code paths.
pub fn dispatch_command(
    stream: &mut impl io::Write,
    payload: &[u8],
    config: &RelayConfig,
    state: &Arc<Mutex<RelayState>>,
) {
    match parse_command(payload, config.admin_token.as_deref()) {
        Command::Stats => handle_stats(stream, state),
        Command::Shutdown => handle_shutdown(stream, state),
        Command::ShutdownNotice(notice) => handle_shutdown_notice(stream, state, notice),
        Command::Drain(peer_id) => handle_drain(stream, state, &peer_id),
        Command::Submission => handle_envelope_submission(stream, payload, config, state),
        Command::DepositOffer {
            offer_id,
            expires_at,
            payload: offer_payload,
        } => {
            // R-H1: Gate offer commands behind relay admission policy.
            if !offer_admission_ok(config) {
                respond(
                    stream,
                    b"REJECTED relay admission policy requires authenticated submission",
                );
                return;
            }
            handle_deposit_offer(
                stream,
                state,
                config,
                offer_id,
                expires_at,
                offer_payload,
                "anon",
            );
        }
        Command::FetchOffer(offer_id) => {
            // DRY-8-MIGRATE: representative migration to typed admission token.
            // The gate produces an `AdmittedRequest` that `handle_fetch_offer`
            // requires — skipping the gate is now a compile error rather than
            // a runtime check the next handler might forget. Other handlers
            // are still on the inline `offer_admission_ok` path; see
            // DRY-8-MIGRATE follow-ups (one per remaining handler).
            if !offer_admission_ok(config) {
                respond(
                    stream,
                    b"REJECTED relay admission policy requires authenticated submission",
                );
                return;
            }
            // The legacy frame protocol does not carry persona/scope headers,
            // so we synthesise a minimal admitted-request for the
            // open-mode/anonymous path. Once the wire format gains those
            // fields the call becomes `admission::gate(auth, persona, scope)`
            // and the synthesis disappears.
            let admitted = match admission::gate(None, Some("anon"), Some(&offer_id)) {
                Ok(a) => a,
                Err(e) => {
                    respond(stream, format!("REJECTED {e}").as_bytes());
                    return;
                }
            };
            handle_fetch_offer(stream, state, &offer_id, &admitted);
        }
        Command::ClaimOffer(offer_id) => {
            if !offer_admission_ok(config) {
                respond(
                    stream,
                    b"REJECTED relay admission policy requires authenticated submission",
                );
                return;
            }
            handle_claim_offer(stream, state, &offer_id);
        }
        Command::FetchAndClaimOffer(offer_id) => {
            if !offer_admission_ok(config) {
                respond(
                    stream,
                    b"REJECTED relay admission policy requires authenticated submission",
                );
                return;
            }
            handle_fetch_and_claim_offer(stream, state, &offer_id);
        }
        Command::DepositCredential { .. } => reject_release_disabled(stream, "DEPOSIT_CREDENTIAL"),
        Command::FetchCredential(_) => reject_release_disabled(stream, "FETCH_CREDENTIAL"),
        Command::RequestGrant { .. } => reject_release_disabled(stream, "REQUEST_GRANT"),
        Command::FetchGrantRequests(_) => reject_release_disabled(stream, "FETCH_GRANT_REQUESTS"),
        Command::RespondGrantRequest { .. } => {
            reject_release_disabled(stream, "RESPOND_GRANT_REQUEST")
        }
        Command::AdminRequired => respond(
            stream,
            b"AUTH-REQUIRED admin token required for this command",
        ),
    }
}

fn reject_release_disabled(stream: &mut impl io::Write, command: &str) {
    respond(
        stream,
        format!(
            "REJECTED {command} disabled for v0.3.0 release containment; use opaque relay envelopes"
        )
        .as_bytes(),
    );
}

/// Parsed command derived from an incoming payload frame.
pub enum Command {
    Stats,
    Shutdown,
    ShutdownNotice(ShutdownNotice),
    Drain(String),
    Submission,
    /// Deposit a grant offer envelope: `DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>`
    DepositOffer {
        offer_id: String,
        expires_at: u64,
        payload: Vec<u8>,
    },
    /// Fetch a grant offer envelope by ID: `FETCH_OFFER <offer-id>`
    FetchOffer(String),
    /// Claim (consume) a grant offer: `CLAIM_OFFER <offer-id>`
    ClaimOffer(String),
    /// Atomically fetch and claim a grant offer: `FETCH_AND_CLAIM <offer-id>`
    FetchAndClaimOffer(String),
    /// Deposit an encrypted credential: `DEPOSIT_CREDENTIAL <grant-id> <hex-payload>`
    DepositCredential {
        grant_id: String,
        payload: Vec<u8>,
    },
    /// Fetch a stored credential: `FETCH_CREDENTIAL <grant-id>`
    FetchCredential(String),
    /// Request a grant from a human identity. The plaintext requester /
    /// scope / justification fields are sealed off-relay; only the
    /// routing-required `target_id` and the responder's expected signing
    /// pubkey ride in cleartext.
    ///
    /// Wire format:
    /// `REQUEST_GRANT <target-id> <target-signing-pubkey-hex> <sealed-payload-hex>`
    RequestGrant {
        target_id: String,
        target_signing_pubkey: PublicKey,
        sealed_payload: Vec<u8>,
    },
    /// Fetch pending grant requests for a target identity: `FETCH_GRANT_REQUESTS <target-id>`
    FetchGrantRequests(String),
    /// Respond to a grant request with a nonce + signature so the relay
    /// can authenticate the responder rather than trusting an unauth'd
    /// admission token.
    ///
    /// Wire format:
    /// `RESPOND_GRANT_REQUEST <request-id> <approved|denied> <nonce-hex> <signature-hex>`
    ///
    /// The signature is over
    /// `RESPOND_GRANT_REQUEST_DOMAIN_SEP || request_id_bytes || verdict_byte || nonce_raw`
    /// by the responder persona signing key bound at REQUEST time.
    RespondGrantRequest {
        request_id: String,
        approved: bool,
        nonce_hex: String,
        signature: Signature,
    },
    /// Admin command detected but token missing or wrong.
    AdminRequired,
}

/// Parse an incoming payload into a `Command`.
///
/// When `admin_token` is `Some(t)`, admin commands (STATS, SHUTDOWN,
/// SHUTDOWN-NOTICE, DRAIN) must include the token as their first
/// space-delimited argument.  The wire format for authenticated commands is:
///
/// - `STATS <token>`
/// - `SHUTDOWN <token>`
/// - `SHUTDOWN-NOTICE <token> <reason> <deadline-epoch>`
/// - `DRAIN <peer-id> <token>`  (token is the *last* space-delimited field)
///
/// When `admin_token` is `None`, admin commands fail closed with
/// `Command::AdminRequired`.
pub fn parse_command(payload: &[u8], admin_token: Option<&str>) -> Command {
    let Ok(text) = std::str::from_utf8(payload) else {
        return Command::Submission;
    };

    // STATS
    if text == "STATS" {
        return Command::AdminRequired;
    }
    if let Some(rest) = text.strip_prefix("STATS ") {
        return if admin_auth_ok(rest.trim(), admin_token) {
            Command::Stats
        } else {
            Command::AdminRequired
        };
    }

    // SHUTDOWN (exact, no args)
    if text == "SHUTDOWN" {
        return Command::AdminRequired;
    }
    if let Some(rest) = text.strip_prefix("SHUTDOWN ") {
        // Must not be a SHUTDOWN-NOTICE prefix handled below
        if !text.starts_with("SHUTDOWN-NOTICE") {
            return if admin_auth_ok(rest.trim(), admin_token) {
                Command::Shutdown
            } else {
                Command::AdminRequired
            };
        }
    }

    // SHUTDOWN-NOTICE
    if let Some(remainder) = text.strip_prefix("SHUTDOWN-NOTICE ") {
        return match admin_token {
            None => Command::AdminRequired,
            Some(tok) => {
                // Authenticated format: SHUTDOWN-NOTICE <token> <reason> <deadline-epoch>
                if let Some((provided_tok, rest)) = remainder.split_once(' ') {
                    if provided_tok == tok {
                        parse_notice_args(rest)
                    } else {
                        Command::AdminRequired
                    }
                } else {
                    Command::AdminRequired
                }
            }
        };
    }

    // DRAIN
    if let Some(rest) = text.strip_prefix("DRAIN ") {
        return match admin_token {
            None => Command::AdminRequired,
            Some(tok) => {
                // Authenticated format: DRAIN <peer-id> <token>
                // token is the last space-delimited field
                if let Some((peer_id, provided_tok)) = rest.trim().rsplit_once(' ') {
                    if provided_tok == tok && !peer_id.is_empty() {
                        Command::Drain(peer_id.to_string())
                    } else {
                        Command::AdminRequired
                    }
                } else {
                    // No space → no token provided
                    Command::AdminRequired
                }
            }
        };
    }

    // DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>
    // No admin auth required — open to any client (same as envelope submission).
    if let Some(rest) = text.strip_prefix("DEPOSIT_OFFER ") {
        return parse_deposit_offer(rest);
    }

    // FETCH_OFFER <offer-id>
    if let Some(rest) = text.strip_prefix("FETCH_OFFER ") {
        let offer_id = rest.trim();
        if offer_id.is_empty() {
            return Command::Submission;
        }
        return Command::FetchOffer(offer_id.to_string());
    }

    // CLAIM_OFFER <offer-id>
    if let Some(rest) = text.strip_prefix("CLAIM_OFFER ") {
        let offer_id = rest.trim();
        if offer_id.is_empty() {
            return Command::Submission;
        }
        return Command::ClaimOffer(offer_id.to_string());
    }

    // FETCH_AND_CLAIM <offer-id> — atomic fetch + claim in one step
    if let Some(rest) = text.strip_prefix("FETCH_AND_CLAIM ") {
        let offer_id = rest.trim();
        if offer_id.is_empty() {
            return Command::Submission;
        }
        return Command::FetchAndClaimOffer(offer_id.to_string());
    }

    // DEPOSIT_CREDENTIAL <grant-id> <hex-payload>
    if let Some(rest) = text.strip_prefix("DEPOSIT_CREDENTIAL ") {
        return parse_deposit_credential(rest);
    }

    // FETCH_CREDENTIAL <grant-id>
    if let Some(rest) = text.strip_prefix("FETCH_CREDENTIAL ") {
        let grant_id = rest.trim();
        if grant_id.is_empty() {
            return Command::Submission;
        }
        return Command::FetchCredential(grant_id.to_string());
    }

    // REQUEST_GRANT <target-id> <requester-id> <scope> <justification>
    if let Some(rest) = text.strip_prefix("REQUEST_GRANT ") {
        return parse_request_grant(rest);
    }

    // FETCH_GRANT_REQUESTS <target-id>
    if let Some(rest) = text.strip_prefix("FETCH_GRANT_REQUESTS ") {
        let target_id = rest.trim();
        if target_id.is_empty() {
            return Command::Submission;
        }
        return Command::FetchGrantRequests(target_id.to_string());
    }

    // RESPOND_GRANT_REQUEST <request-id> <approved|denied>
    if let Some(rest) = text.strip_prefix("RESPOND_GRANT_REQUEST ") {
        return parse_respond_grant_request(rest);
    }

    Command::Submission
}

/// Check whether unauthenticated offer commands are permitted under the
/// current relay admission mode.  Only `Open` mode allows offer operations
/// without an admission token — `TrustGated` and `NetworkScoped` require
/// the full envelope-level admission flow which offer commands do not carry.
pub fn offer_admission_ok(config: &RelayConfig) -> bool {
    config.mode == RelayMode::Open
}

pub fn admin_auth_ok(provided: &str, configured: Option<&str>) -> bool {
    match configured {
        None => false,
        Some(tok) => provided == tok,
    }
}

fn parse_notice_args(remainder: &str) -> Command {
    // Format: <reason> <deadline-epoch>  (deadline is the last space-separated token)
    if let Some((reason, deadline_str)) = remainder.rsplit_once(' ') {
        let reason = reason.trim();
        if !reason.is_empty()
            && let Ok(deadline_epoch) = deadline_str.trim().parse::<u64>()
        {
            return Command::ShutdownNotice(ShutdownNotice {
                reason: reason.to_string(),
                deadline_epoch,
            });
        }
    }
    Command::Submission // malformed
}

/// Parse the remainder of a `DEPOSIT_OFFER` command.
///
/// Expected format: `<offer-id> <expires-at-epoch> <hex-payload>`
fn parse_deposit_offer(remainder: &str) -> Command {
    // Split into at most 3 parts: offer-id, expires-at, and hex-payload (which may contain no spaces)
    let mut parts = remainder.splitn(3, ' ');
    let offer_id = match parts.next() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Command::Submission,
    };
    let expires_str = match parts.next() {
        Some(s) if !s.is_empty() => s,
        _ => return Command::Submission,
    };
    let expires_at = match expires_str.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return Command::Submission,
    };
    let hex_payload = match parts.next() {
        Some(s) if !s.is_empty() => s.trim(),
        _ => return Command::Submission,
    };
    let payload = match hex::decode(hex_payload) {
        Ok(b) => b,
        Err(_) => return Command::Submission,
    };
    Command::DepositOffer {
        offer_id,
        expires_at,
        payload,
    }
}

/// Parse the remainder of a `DEPOSIT_CREDENTIAL` command.
///
/// Expected format: `<grant-id> <hex-payload>`
fn parse_deposit_credential(remainder: &str) -> Command {
    let mut parts = remainder.splitn(2, ' ');
    let grant_id = match parts.next() {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Command::Submission,
    };
    let hex_payload = match parts.next() {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return Command::Submission,
    };
    let payload = match hex::decode(hex_payload) {
        Ok(b) => b,
        Err(_) => return Command::Submission,
    };
    Command::DepositCredential { grant_id, payload }
}

/// Store an encrypted credential envelope indexed by `grant_id`.
///
/// Wire response:
/// - `OK credential deposited\n` on success.
/// - `ERR payload too large\n` if payload exceeds 1 MB.
/// - `ERR invalid grant-id\n` if grant-id is empty or whitespace.
pub fn handle_deposit_credential(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    grant_id: String,
    payload: Vec<u8>,
) {
    const MAX_CREDENTIAL_BYTES: usize = 1024 * 1024; // 1 MB

    if grant_id.trim().is_empty() {
        respond(stream, b"ERR invalid grant-id");
        return;
    }
    if payload.len() > MAX_CREDENTIAL_BYTES {
        respond(stream, b"ERR payload too large");
        return;
    }

    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Purge stale credentials (30-day TTL) before inserting.
    const CREDENTIAL_TTL_SECS: u64 = 30 * 24 * 3600;
    s.purge_expired_credentials(now, CREDENTIAL_TTL_SECS);

    s.credential_store.insert(
        grant_id,
        StoredCredential {
            payload,
            deposit_time: now,
        },
    );

    respond(stream, b"OK credential deposited");
}

/// Fetch a stored credential envelope by `grant_id`.
///
/// Wire response:
/// - `OK <hex-payload>` on success.
/// - `ERR not found` if no credential is stored for this grant-id.
///
/// Credentials are NOT deleted on fetch — they persist until TTL expiry.
pub fn handle_fetch_credential(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    grant_id: &str,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Purge stale credentials before lookup.
    const CREDENTIAL_TTL_SECS: u64 = 30 * 24 * 3600;
    s.purge_expired_credentials(now, CREDENTIAL_TTL_SECS);

    match s.credential_store.get(grant_id) {
        None => respond(stream, b"ERR not found"),
        Some(cred) => {
            let hex_payload = hex::encode(&cred.payload);
            respond(stream, format!("OK {hex_payload}").as_bytes());
        }
    }
}

/// Parse the remainder of a `REQUEST_GRANT` command.
///
/// Expected format: `<target-id> <target-signing-pubkey-hex> <sealed-payload-hex>`
///
/// The requester id, scope, and
/// justification all ride inside `sealed-payload-hex` — the relay sees
/// only opaque sealed bytes for those fields. `target_id` stays
/// cleartext because the relay routes fetch queries by it (the minimum
/// metadata ADR 007 §3 allows the relay to see).
///
/// The pubkey is captured here so the responder's signed
/// `RESPOND_GRANT_REQUEST` can be verified later
/// (`respond_grant_request_signed`).
fn parse_request_grant(remainder: &str) -> Command {
    let mut parts = remainder.splitn(3, ' ');
    let target_id = match parts.next() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Command::Submission,
    };
    let pubkey_hex = match parts.next() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Command::Submission,
    };
    let sealed_hex = match parts.next() {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Command::Submission,
    };
    // Decode the sealed payload eagerly — invalid hex is a malformed
    // command, falling through to `Submission` mirrors how
    // `parse_deposit_offer` handles bad-hex payloads.
    let sealed_payload = match hex::decode(&sealed_hex) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return Command::Submission,
    };
    Command::RequestGrant {
        target_id,
        target_signing_pubkey: PublicKey(pubkey_hex),
        sealed_payload,
    }
}

/// Parse the remainder of a `RESPOND_GRANT_REQUEST` command.
///
/// Expected format: `<request-id> <approved|denied> <nonce-hex> <signature-hex>`
///
/// The nonce is the operator's per-response replay-defeating tombstone
/// (`RESPOND_GRANT_REQUEST_NONCE_BYTES` raw bytes); the signature is the
/// responder's persona-key signature over the payload built in
/// `respond_grant_request_signing_payload`. We accept the wire shape
/// here and defer cryptographic verification to
/// `handle_respond_grant_request` so a parse-time refusal does not leak
/// "request id exists" vs "signature is wrong" through different
/// rejection paths.
fn parse_respond_grant_request(remainder: &str) -> Command {
    let mut parts = remainder.splitn(4, ' ');
    let request_id = match parts.next() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Command::Submission,
    };
    let verdict = match parts.next() {
        Some(s) => s.trim(),
        None => return Command::Submission,
    };
    let approved = match verdict {
        "approved" => true,
        "denied" => false,
        _ => return Command::Submission,
    };
    let nonce_hex = match parts.next() {
        Some(s) if s.len() == RESPOND_GRANT_REQUEST_NONCE_BYTES * 2 => s.to_string(),
        _ => return Command::Submission,
    };
    // Refuse non-hex nonces at parse time — handles the case where the
    // nonce slot is the right length but not valid hex.
    if hex::decode(&nonce_hex).is_err() {
        return Command::Submission;
    }
    let signature_hex = match parts.next() {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Command::Submission,
    };
    Command::RespondGrantRequest {
        request_id,
        approved,
        nonce_hex,
        signature: Signature(signature_hex),
    }
}

/// Build the canonical signed payload bound to a `RESPOND_GRANT_REQUEST`.
///
/// The payload is `DOMAIN_SEP || request_id_bytes || verdict_byte ||
/// nonce_raw`. Including the verdict byte means a "denied" signature
/// cannot be replayed against the same request id to flip the verdict
/// to "approved", and including the request id binds the signature to
/// the specific grant request rather than the responder's broader
/// authority.
pub fn respond_grant_request_signing_payload(
    request_id: &str,
    approved: bool,
    nonce_raw: &[u8],
) -> Vec<u8> {
    let verdict_byte: u8 = if approved { 1 } else { 0 };
    let mut payload = Vec::with_capacity(
        RESPOND_GRANT_REQUEST_DOMAIN_SEP.len() + request_id.len() + 1 + nonce_raw.len(),
    );
    payload.extend_from_slice(RESPOND_GRANT_REQUEST_DOMAIN_SEP);
    payload.extend_from_slice(request_id.as_bytes());
    payload.push(verdict_byte);
    payload.extend_from_slice(nonce_raw);
    payload
}

/// Store a grant request from an agent targeting a human identity.
///
/// The requester id, scope, and
/// justification have been sealed off-relay; only the routing-required
/// `target_id` and the responder's signing pubkey (used later to verify
/// the matching `RESPOND_GRANT_REQUEST` signature) ride in cleartext.
///
/// Wire response: `OK <request-id>` on success.
pub fn handle_request_grant(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    target_id: String,
    target_signing_pubkey: PublicKey,
    sealed_payload: Vec<u8>,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Rate limit: cap at 100 pending requests per target to prevent memory exhaustion.
    {
        let existing = s.grant_requests.entry(target_id.clone()).or_default();
        let pending_count = existing
            .iter()
            .filter(|r| matches!(r.status, GrantRequestStatus::Pending))
            .count();
        if pending_count >= 100 {
            respond(stream, b"RATE_LIMITED");
            return;
        }
    }

    // Use hex-encoded random ID to prevent enumeration attacks.
    s.next_grant_request_id += 1;
    let n = s.next_grant_request_id;
    let mixed = n
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let request_id = format!("gr-{:016x}", mixed);

    let request = GrantRequest {
        request_id: request_id.clone(),
        target_id: target_id.clone(),
        target_signing_pubkey,
        sealed_payload,
        created_at: now,
        status: GrantRequestStatus::Pending,
    };

    s.grant_requests.entry(target_id).or_default().push(request);

    respond(stream, format!("OK {request_id}").as_bytes());
}

/// Fetch all pending grant requests for a target identity.
///
/// Wire response:
/// - `NONE` if no requests exist for this target.
/// - Newline-separated JSON objects for each request, followed by `END`.
///
/// The requester id / scope /
/// justification fields are emitted as a single hex-encoded
/// `sealed_payload`; the responder unseals them outside the relay's
/// address space. The relay never reconstructs plaintext for any of
/// these fields, so the JSON shape changed accordingly.
pub fn handle_fetch_grant_requests(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    target_id: &str,
) {
    let s = acquire_state(state);

    let requests = match s.grant_requests.get(target_id) {
        Some(reqs) if !reqs.is_empty() => reqs,
        _ => {
            respond(stream, b"NONE");
            return;
        }
    };

    let mut lines = Vec::new();
    for r in requests {
        let status = match r.status {
            GrantRequestStatus::Pending => "pending",
            GrantRequestStatus::Approved => "approved",
            GrantRequestStatus::Denied => "denied",
        };
        // Escape JSON-sensitive characters in operator-controlled fields.
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let sealed_hex = hex::encode(&r.sealed_payload);
        lines.push(format!(
            r#"{{"request_id":"{}","target_id":"{}","target_signing_pubkey":"{}","sealed_payload":"{}","created_at":{},"status":"{}"}}"#,
            esc(&r.request_id),
            esc(&r.target_id),
            esc(&r.target_signing_pubkey.0),
            sealed_hex,
            r.created_at,
            status,
        ));
    }
    lines.push("END".to_string());

    respond(stream, lines.join("\n").as_bytes());
}

// respond_grant_request_signed
/// Respond to a grant request (approve or deny).
///
/// The caller MUST supply a fresh `nonce_raw` and a signature over
/// `respond_grant_request_signing_payload(request_id, approved, nonce_raw)`
/// produced by the responder persona signing key bound at REQUEST time.
/// The relay verifies the signature against that bound pubkey using
/// `Ed25519Verifier` (ADR 200 §3 algorithm-bound), then tombstones the
/// nonce in `consumed_response_nonces` so a captured frame cannot be
/// replayed.
///
/// Wire response:
/// - `OK` on accepted, signed response.
/// - `NOT_FOUND` if no request with the given ID exists.
/// - `ALREADY_RESOLVED` if the request has already been answered.
/// - `REJECTED nonce replay` if the nonce has been seen before.
/// - `REJECTED signature verification failed` if the signature does not
///   verify under the bound responder pubkey.
///
/// Signature failure and nonce-replay BOTH refuse without mutating the
/// grant-request state — only an `OK` response transitions the request
/// from `Pending` to `Approved`/`Denied`.
pub fn handle_respond_grant_request(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    request_id: &str,
    approved: bool,
    nonce_hex: &str,
    signature: &Signature,
) {
    // Decode the nonce up front: a malformed nonce is a wire-level error,
    // not authority-bearing input.
    let nonce_raw = match hex::decode(nonce_hex) {
        Ok(bytes) if bytes.len() == RESPOND_GRANT_REQUEST_NONCE_BYTES => bytes,
        _ => {
            respond(stream, b"REJECTED nonce malformed");
            return;
        }
    };

    let mut s = acquire_state(state);

    // Replay guard — refuse before touching the grant-request store so a
    // captured frame is structurally inert. Constant-time nonce lookup
    // is unnecessary because the nonce is single-use random material and
    // a hit cannot leak useful information beyond "this exact frame was
    // already accepted".
    if s.consumed_response_nonces.contains(nonce_hex) {
        respond(stream, b"REJECTED nonce replay");
        return;
    }

    // Lookup the request, snapshotting the bound pubkey so we can drop
    // the borrow before mutating the consumed-nonce set.
    let mut found_target: Option<String> = None;
    let mut found_index: Option<usize> = None;
    let mut already_resolved = false;
    let mut bound_pubkey: Option<PublicKey> = None;
    for (target, requests) in s.grant_requests.iter() {
        if let Some(idx) = requests.iter().position(|r| r.request_id == request_id) {
            let req = &requests[idx];
            if !matches!(req.status, GrantRequestStatus::Pending) {
                already_resolved = true;
            } else {
                bound_pubkey = Some(req.target_signing_pubkey.clone());
            }
            found_target = Some(target.clone());
            found_index = Some(idx);
            break;
        }
    }

    if found_target.is_none() {
        respond(stream, b"NOT_FOUND");
        return;
    }
    if already_resolved {
        respond(stream, b"ALREADY_RESOLVED");
        return;
    }
    let Some(pubkey) = bound_pubkey else {
        // Defensive: only reachable if a pending request lost its bound
        // pubkey, which the request store does not allow today.
        respond(stream, b"REJECTED missing bound responder pubkey");
        return;
    };

    // Verify the responder signature against the bound persona pubkey.
    // `Ed25519Verifier` is the algorithm-bound verifier per ADR 200 §3:
    // it rejects any signature whose key prefix is not `ed25519:`, so a
    // P-256 device signature cannot accidentally satisfy this gate.
    let payload = respond_grant_request_signing_payload(request_id, approved, &nonce_raw);
    if !Ed25519Verifier.verify(&pubkey, &payload, signature) {
        respond(stream, b"REJECTED signature verification failed");
        return;
    }

    // Tombstone the nonce before mutating grant state so any panic between
    // here and `respond` cannot leak an authenticated nonce back into the
    // accept-window. Cap the dedup set so a flood of valid responses
    // cannot drive unbounded memory growth — once we hit the soft cap we
    // refuse new responses rather than evict (eviction would re-open the
    // replay window for the evicted nonce).
    if s.consumed_response_nonces.len() >= MAX_CONSUMED_NONCES {
        respond(stream, b"REJECTED nonce store full");
        return;
    }
    s.consumed_response_nonces.insert(nonce_hex.to_string());

    // Apply the verdict.
    let target = found_target.expect("found_target checked above");
    let idx = found_index.expect("found_index checked above");
    if let Some(requests) = s.grant_requests.get_mut(&target) {
        let req = &mut requests[idx];
        req.status = if approved {
            GrantRequestStatus::Approved
        } else {
            GrantRequestStatus::Denied
        };
    }

    respond(stream, b"OK");
}

pub fn handle_envelope_submission(
    stream: &mut impl io::Write,
    payload: &[u8],
    config: &RelayConfig,
    state: &Arc<Mutex<RelayState>>,
) {
    {
        let s = acquire_state(state);
        if let Some(notice) = &s.shutdown_notice {
            respond(
                stream,
                format!(
                    "REJECTED relay is shutting down: {} (deadline={})",
                    notice.reason, notice.deadline_epoch
                )
                .as_bytes(),
            );
            return;
        }
    }
    match admit_submission_payload(payload, config, now_epoch_secs()) {
        Ok(submission) => {
            let mut s = acquire_state(state);
            let Some(target_peer_id) = submission.target_peer_id.clone() else {
                s.stats.rejected += 1;
                respond(stream, b"REJECTED submission missing target peer");
                return;
            };

            // Enforce per-peer mailbox quota
            if config.max_per_peer > 0 {
                let peer_count = s.mailboxes.get(&target_peer_id).map(Vec::len).unwrap_or(0);
                if peer_count >= config.max_per_peer {
                    s.stats.rejected += 1;
                    respond(
                        stream,
                        format!(
                            "REJECTED mailbox full for peer ({peer_count}/{} limit)",
                            config.max_per_peer
                        )
                        .as_bytes(),
                    );
                    return;
                }
            }

            // Enforce global queue quota
            if config.max_total > 0 && s.queued_count() >= config.max_total {
                s.stats.rejected += 1;
                respond(stream, b"REJECTED relay queue full");
                return;
            }

            if let Some(ref source) = submission.source_persona_id {
                s.stats.peers_seen.insert(source.clone());
            }
            s.mailboxes
                .entry(target_peer_id)
                .or_default()
                .push(submission);
            s.stats.accepted += 1;
            respond(stream, b"OK accepted");
        }
        Err(reason) => {
            let mut s = acquire_state(state);
            s.stats.rejected += 1;
            respond(stream, format!("REJECTED {reason}").as_bytes());
        }
    }
}

/// Store an encrypted grant offer envelope indexed by `offer_id`.
///
/// Wire response:
/// - `OK deposited <offer-id>` on success.
/// - `REJECTED <reason>` if the offer already exists, quotas are exceeded,
///   or the relay is shutting down.
pub fn handle_deposit_offer(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    config: &RelayConfig,
    offer_id: String,
    expires_at: u64,
    payload: Vec<u8>,
    source: &str,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    if let Some(notice) = &s.shutdown_notice {
        respond(
            stream,
            format!(
                "REJECTED relay is shutting down: {} (deadline={})",
                notice.reason, notice.deadline_epoch
            )
            .as_bytes(),
        );
        return;
    }

    // Reject offers that are already expired.
    if expires_at <= now {
        respond(stream, b"REJECTED offer already expired");
        return;
    }

    // R-H2: Cap TTL to configured maximum.
    let max_expires = now + config.max_offer_ttl_secs;
    let effective_expires = expires_at.min(max_expires);

    // R-M1: Purge expired offers BEFORE the duplicate check so that an
    // expired offer for the same ID does not block a fresh deposit.
    s.purge_expired_offers(now);

    // Idempotency: reject duplicate offer IDs.
    if s.offers.contains_key(&offer_id) {
        respond(stream, b"REJECTED offer already exists");
        return;
    }

    // R-H2: Per-peer offer count quota.
    if config.max_offers_per_peer > 0 {
        let count = s.offer_counts_by_source.get(source).copied().unwrap_or(0);
        if count >= config.max_offers_per_peer {
            respond(
                stream,
                format!(
                    "REJECTED offer quota exceeded ({count}/{} per peer)",
                    config.max_offers_per_peer
                )
                .as_bytes(),
            );
            return;
        }
    }

    // R-H2: Global byte quota.
    if config.max_offer_bytes_total > 0
        && s.offer_bytes_total + payload.len() > config.max_offer_bytes_total
    {
        respond(stream, b"REJECTED offer store byte quota exceeded");
        return;
    }

    // Update counters.
    s.offer_bytes_total += payload.len();
    *s.offer_counts_by_source
        .entry(source.to_string())
        .or_insert(0) += 1;

    s.offers.insert(
        offer_id.clone(),
        StoredOffer {
            payload,
            expires_at: effective_expires,
            claimed: false,
            source: source.to_string(),
        },
    );

    respond(stream, format!("OK deposited {offer_id}").as_bytes());
}

/// Fetch an encrypted grant offer envelope by `offer_id`.
///
/// Wire response:
/// - `OFFER <offer-id> <hex-payload>` on success.
/// - `NOT-FOUND` if the offer is unknown or expired.
/// - `CLAIMED` if the offer has already been consumed.
// DRY-8-MIGRATE: this is the representative handler that consumes a
// typed `AdmittedRequest`. The token is unused for now (the legacy
// open-mode wire protocol carries no persona/scope) but the *type
// signature* enforces that the dispatch site ran the gate. Other
// handlers (handle_claim_offer, handle_deposit_credential, ...) still
// take raw arguments; migrating each one is tracked under
// DRY-8-MIGRATE follow-ups.
pub fn handle_fetch_offer(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    offer_id: &str,
    _admission: &AdmittedRequest,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Purge expired offers before lookup.
    s.purge_expired_offers(now);

    match s.offers.get(offer_id) {
        None => respond(stream, b"NOT-FOUND"),
        Some(offer) if offer.claimed => respond(stream, b"CLAIMED"),
        Some(offer) => {
            let hex_payload = hex::encode(&offer.payload);
            respond(stream, format!("OFFER {offer_id} {hex_payload}").as_bytes());
        }
    }
}

/// Mark a grant offer as claimed (consumed).
///
/// Wire response:
/// - `OK claimed <offer-id>` on success.
/// - `NOT-FOUND` if the offer is unknown or expired.
/// - `CLAIMED` if the offer has already been consumed.
pub fn handle_claim_offer(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    offer_id: &str,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Purge expired offers before lookup.
    s.purge_expired_offers(now);

    match s.offers.get_mut(offer_id) {
        None => respond(stream, b"NOT-FOUND"),
        Some(offer) if offer.claimed => respond(stream, b"CLAIMED"),
        Some(offer) => {
            offer.claimed = true;
            // R-H2: Free the payload bytes — the offer becomes a compact
            // tombstone that only tracks claimed/expiry state.
            let freed = offer.payload.len();
            offer.payload = Vec::new();
            s.offer_bytes_total = s.offer_bytes_total.saturating_sub(freed);
            respond(stream, format!("OK claimed {offer_id}").as_bytes());
        }
    }
}

/// Atomically fetch and claim a grant offer in a single operation.
///
/// This eliminates the FETCH+CLAIM race condition where two clients could both
/// FETCH_OFFER before either sends CLAIM_OFFER, allowing both to obtain the
/// payload. With FETCH_AND_CLAIM, the offer is marked as claimed under the same
/// lock acquisition that returns the payload — only one client can ever receive it.
///
/// Wire response:
/// - `OFFER <offer-id> <hex-payload>` on success (offer is now claimed).
/// - `NOT-FOUND` if the offer is unknown or expired.
/// - `CLAIMED` if the offer has already been consumed.
pub fn handle_fetch_and_claim_offer(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    offer_id: &str,
) {
    let now = now_epoch_secs();
    let mut s = acquire_state(state);

    // Purge expired offers before lookup.
    s.purge_expired_offers(now);

    match s.offers.get_mut(offer_id) {
        None => respond(stream, b"NOT-FOUND"),
        Some(offer) if offer.claimed => respond(stream, b"CLAIMED"),
        Some(offer) => {
            offer.claimed = true;
            let hex_payload = hex::encode(&offer.payload);
            respond(stream, format!("OFFER {offer_id} {hex_payload}").as_bytes());
        }
    }
}

pub fn admit_submission_payload(
    payload: &[u8],
    config: &RelayConfig,
    now_epoch_secs: u64,
) -> Result<PortableRelaySubmission, String> {
    let submission =
        PortableRelaySubmission::decode(payload).map_err(|err| format!("decode: {err}"))?;
    if submission.target_peer_id.as_deref().is_none() {
        return Err("relay submission requires target peer metadata".to_string());
    }
    match check_relay_submission_admission(
        config.mode,
        &submission,
        config.threshold,
        &config.allowlist,
        &config.trusted_issuer_keys,
        now_epoch_secs,
        &Ed25519Verifier,
    ) {
        RelayAdmission::Accept => Ok(submission),
        RelayAdmission::Reject { reason } => Err(reason),
    }
}

pub fn handle_drain(stream: &mut impl io::Write, state: &Arc<Mutex<RelayState>>, peer_id: &str) {
    let mut s = acquire_state(state);
    let count = s.mailboxes.get(peer_id).map(Vec::len).unwrap_or(0);
    let notice = s.shutdown_notice.clone();

    let header = if let Some(ref notice) = notice {
        format!(
            "DRAIN {peer_id} {count} shutdown_reason={} shutdown_deadline={}",
            notice.reason, notice.deadline_epoch
        )
    } else {
        format!("DRAIN {peer_id} {count}")
    };
    respond(stream, header.as_bytes());

    let submissions = s.mailboxes.remove(peer_id).unwrap_or_default();
    s.stats.delivered += submissions.len() as u64;
    drop(s);

    // Buffer all envelope frames to avoid per-frame TCP flush
    let mut buf = Vec::with_capacity(submissions.len() * 1024);
    for submission in submissions {
        let encoded = submission.encode();
        let len = (encoded.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&encoded);
    }
    if let Err(e) = stream.write_all(&buf).and_then(|_| stream.flush()) {
        eprintln!("warning: failed to flush drain response for {peer_id}: {e}");
    }
}

pub fn handle_stats(stream: &mut impl io::Write, state: &Arc<Mutex<RelayState>>) {
    let s = acquire_state(state);
    let uptime = now_epoch_secs().saturating_sub(s.stats.started_at);
    let offers_stored = s.offers.len();
    let offers_claimed = s.offers.values().filter(|o| o.claimed).count();
    let response = format!(
        "STATS accepted={} rejected={} delivered={} queued={} mailboxes={} peers_seen={} offers_stored={} offers_claimed={} uptime={}s",
        s.stats.accepted,
        s.stats.rejected,
        s.stats.delivered,
        s.queued_count(),
        s.mailboxes.len(),
        s.stats.peers_seen.len(),
        offers_stored,
        offers_claimed,
        uptime,
    );
    respond(stream, response.as_bytes());
}

pub fn handle_shutdown_notice(
    stream: &mut impl io::Write,
    state: &Arc<Mutex<RelayState>>,
    notice: ShutdownNotice,
) {
    let mut s = acquire_state(state);
    let peer_count = s.mailboxes.len();
    s.shutdown_notice = Some(notice.clone());
    drop(s);

    respond(
        stream,
        format!(
            "SHUTDOWN-NOTICE reason={} deadline={} peers_notified={}",
            notice.reason, notice.deadline_epoch, peer_count
        )
        .as_bytes(),
    );
    eprintln!(
        "graceful shutdown initiated: reason={} deadline={} peers={}",
        notice.reason, notice.deadline_epoch, peer_count
    );
}

pub fn handle_shutdown(stream: &mut impl io::Write, state: &Arc<Mutex<RelayState>>) {
    let mut s = acquire_state(state);
    let queued = s.queued_count();
    s.mailboxes.clear();
    respond(stream, format!("SHUTDOWN flushed={queued}").as_bytes());
    eprintln!("shutdown requested, flushed {queued} envelopes");
    std::process::exit(0);
}

/// Acquire the relay state lock, recovering from poison if a peer thread panicked.
/// The data is still valid after a panic — we just need to clear the poison flag.
pub fn acquire_state(state: &Mutex<RelayState>) -> std::sync::MutexGuard<'_, RelayState> {
    state.lock().unwrap_or_else(|poisoned| {
        eprintln!("warning: relay state lock was poisoned by a panicked thread, recovering");
        poisoned.into_inner()
    })
}

/// Write a response frame to the client, logging failures for operator visibility.
pub fn respond(stream: &mut impl io::Write, payload: &[u8]) {
    if let Err(e) = write_frame(stream, payload) {
        eprintln!(
            "warning: failed to write response frame ({} bytes): {e}",
            payload.len()
        );
    }
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large (max 16MB)",
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Derive the host portion that auxiliary listeners should use from the main
/// relay bind address. This keeps health/JWKS/WS helpers inside the same bind
/// scope instead of silently widening to 0.0.0.0.
pub fn auxiliary_bind_host(bind_address: &str) -> String {
    if let Some(end) = bind_address.find(']')
        && bind_address.starts_with('[')
    {
        return bind_address[..=end].to_string();
    }

    bind_address
        .rsplit_once(':')
        .map(|(host, _port)| {
            if host.is_empty() {
                "0.0.0.0".to_string()
            } else {
                host.to_string()
            }
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn auxiliary_listener_addr(bind_host: &str, port: u16) -> String {
    if bind_host.starts_with('[') || !bind_host.contains(':') {
        format!("{bind_host}:{port}")
    } else {
        format!("[{bind_host}]:{port}")
    }
}

/// WebSocket listener that speaks the same relay protocol in a WS envelope.
///
/// Each incoming connection performs a WebSocket handshake, reads one Binary
/// message (the command payload — no 4-byte length prefix, WS provides framing),
/// dispatches the command through `dispatch_command`, and sends the response
/// bytes as a Binary WebSocket message before closing the connection.
pub fn run_ws_listener(
    port: u16,
    config: Arc<RelayConfig>,
    state: Arc<Mutex<RelayState>>,
    active_connections: Arc<AtomicUsize>,
) {
    run_ws_listener_bound(
        "127.0.0.1".to_string(),
        port,
        config,
        state,
        active_connections,
    );
}

pub fn run_ws_listener_bound(
    bind_host: String,
    port: u16,
    config: Arc<RelayConfig>,
    state: Arc<Mutex<RelayState>>,
    active_connections: Arc<AtomicUsize>,
) {
    let addr = auxiliary_listener_addr(&bind_host, port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ws listener: failed to bind {addr}: {e}");
            return;
        }
    };
    eprintln!("ws listener on {addr}");

    for stream in listener.incoming() {
        let Ok(tcp_stream) = stream else {
            continue;
        };

        // Enforce connection limit.
        if config.max_connections > 0 {
            let current = active_connections.load(Ordering::Relaxed);
            if current >= config.max_connections {
                eprintln!(
                    "ws: connection limit reached ({current}/{}) — dropping",
                    config.max_connections
                );
                continue;
            }
        }

        // Apply read/write timeouts before the WS handshake.
        if config.read_timeout_secs > 0 {
            let timeout = Duration::from_secs(config.read_timeout_secs);
            let _ = tcp_stream
                .set_read_timeout(Some(timeout))
                .and(tcp_stream.set_write_timeout(Some(timeout)));
        }

        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let active_connections = Arc::clone(&active_connections);

        thread::spawn(move || {
            active_connections.fetch_add(1, Ordering::Relaxed);
            handle_ws_connection(tcp_stream, &config, &state);
            active_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Handle a single WebSocket connection: handshake, read one Binary message,
/// dispatch, respond, close.
pub fn handle_ws_connection(
    tcp_stream: std::net::TcpStream,
    config: &RelayConfig,
    state: &Arc<Mutex<RelayState>>,
) {
    let mut ws = match tungstenite::accept(tcp_stream) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("ws handshake error: {e}");
            return;
        }
    };

    // Read exactly one Binary message.
    let payload = loop {
        match ws.read() {
            Ok(tungstenite::Message::Binary(data)) => break data,
            Ok(tungstenite::Message::Close(_)) | Err(_) => return,
            // Ignore Ping/Pong/Text — keep reading until Binary or close.
            Ok(_) => continue,
        }
    };

    // Dispatch through the shared handler, collecting response into a buffer.
    // The buffer receives length-prefixed frames (same wire format as TCP).
    let mut response_buf: Vec<u8> = Vec::new();
    dispatch_command(&mut response_buf, &payload, config, state);

    // Send the complete response as a single Binary WS message.
    if let Err(e) = ws.send(tungstenite::Message::Binary(response_buf.into())) {
        eprintln!("ws send error: {e}");
    }

    // Graceful close.
    let _ = ws.close(None);
    // Drain any remaining messages to complete the closing handshake.
    loop {
        match ws.read() {
            Ok(tungstenite::Message::Close(_)) | Err(_) => break,
            _ => continue,
        }
    }
}

pub fn print_usage() {
    eprintln!(
        "\
emberlink-relay — headless relay daemon for the Emberlink network

USAGE:
    emberlink-relay [OPTIONS]

OPTIONS:
    --bind <addr>       Listen address (default: 127.0.0.1:9100)
    --mode <mode>       Relay mode: open, trust-gated, network-scoped (default: open)
    --threshold <f32>   Trust threshold for trust-gated mode (0.0-1.0)
    --allow <persona>   Add persona to allowlist (network-scoped mode, repeatable)
    --trusted-issuer <persona=public-key>
                        Add a trusted token issuer (trust-gated mode, repeatable)

QUEUE LIMITS:
    --max-per-peer <n>  Max envelopes per peer mailbox (default: 10000, 0 = unlimited)
    --max-total <n>     Max total envelopes across all mailboxes (default: 1000000, 0 = unlimited)

OFFER LIMITS:
    --max-offers-per-peer <n>  Max offers per depositing peer (default: 100, 0 = unlimited)
    --max-offer-bytes <n>      Max total bytes across all offer payloads (default: 52428800)
    --max-offer-ttl <secs>     Max offer TTL in seconds (default: 259200 = 72h)

ADMIN SECURITY:
    --admin-token <tok> Shared secret required for STATS, SHUTDOWN, SHUTDOWN-NOTICE,
                        and DRAIN commands.  Omitting this flag disables admin
                        commands.

CONNECTION LIMITS:
    --max-connections <n>  Max simultaneous TCP connections (default: 1000, 0 = unlimited)
    --read-timeout <secs>  Read/write timeout per connection in seconds (default: 30, 0 = none)

WEBSOCKET:
    --ws-port <port>       Accepted for compatibility but disabled for v0.3.0
                           release containment.
    --no-ws                Disable the WebSocket listener (default)

TLS OPTIONS (mandatory in production builds — AUDIT-V030-RELAY-TLS):
    --tls-self-signed   Generate a self-signed certificate at startup (default)
    --tls-cert <path>   Path to PEM certificate file (e.g., Let's Encrypt fullchain.pem)
    --tls-key <path>    Path to PEM private key file (e.g., Let's Encrypt privkey.pem)
    (--no-tls is rejected in production; only the `insecure-no-tls` cargo
     feature re-exposes it for test loopback rigs.)

    --help              Show this help

WIRE PROTOCOL:
    All messages use 4-byte big-endian length prefix followed by payload.
    Submit:          send a PortableRelaySubmission payload
    Drain:           \"DRAIN <peer-id>\" or \"DRAIN <peer-id> <token>\" (when --admin-token set)
    Stats:           \"STATS\" or \"STATS <token>\"
    Shutdown Notice: \"SHUTDOWN-NOTICE <token> <reason> <deadline-epoch>\"
    Shutdown:        \"SHUTDOWN <token>\"
    Admin commands without the correct configured token receive AUTH-REQUIRED and are ignored.
    Deposit Offer:   \"DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>\"
    Fetch Offer:     \"FETCH_OFFER <offer-id>\"
    Claim Offer:     \"CLAIM_OFFER <offer-id>\"
    Fetch+Claim:     \"FETCH_AND_CLAIM <offer-id>\"  (atomic, recommended)
    Legacy credential and grant-request commands are rejected for v0.3.0 release containment.

EXAMPLES:
    emberlink-relay --mode open
    emberlink-relay --admin-token s3cr3t --mode open
    emberlink-relay --tls-cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \\
                    --tls-key /etc/letsencrypt/live/relay.example.com/privkey.pem
    emberlink-relay --mode trust-gated --threshold 0.5 --trusted-issuer persona-alice=ed25519:abcd
    emberlink-relay --mode network-scoped --allow persona-alice --allow persona-bob
"
    );
}

/// Minimal HTTP server for the /health readiness probe.
///
/// The compatibility helper listens on loopback. Production startup calls
/// [`run_health_server_bound`] with a host derived from the main relay
/// `--bind` address. The server responds to `GET /health` with a 200 JSON
/// body containing relay status, mode, and uptime in seconds.
/// Any other request receives a 404.  The listener runs in its own OS thread
/// and never terminates; it is intended to be spawned before the main accept
/// loop starts.
pub fn run_health_server(port: u16, mode: RelayMode, start_time: Instant, ws_port: Option<u16>) {
    run_health_server_bound("127.0.0.1".to_string(), port, mode, start_time, ws_port);
}

pub fn run_health_server_bound(
    bind_host: String,
    port: u16,
    mode: RelayMode,
    start_time: Instant,
    ws_port: Option<u16>,
) {
    let addr = auxiliary_listener_addr(&bind_host, port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("health server: failed to bind {addr}: {e}");
            return;
        }
    };
    eprintln!("health server listening on {addr}");

    for stream in listener.incoming() {
        let Ok(mut tcp) = stream else { continue };

        // Set a tight timeout so a slow client does not hold the thread.
        let timeout = Duration::from_secs(5);
        let _ = tcp.set_read_timeout(Some(timeout));
        let _ = tcp.set_write_timeout(Some(timeout));

        let mut buf = [0u8; 512];
        let n = match tcp.read(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

        // Only serve GET /health and the ADR 146 §2.b JWKS endpoint;
        // everything else is 404. The JWKS handler shares the health-server
        // listener (plain TCP, no TLS) because Phase 2 ships the resolver as
        // an extension of the existing health surface — providers fetch JWKS
        // over plain HTTP and verify the signature chain themselves.
        let is_health = request.starts_with("GET /health ")
            || request.starts_with("GET /health\r")
            || request == "GET /health";

        let jwks_did = parse_jwks_request(request);

        if is_health {
            let uptime = start_time.elapsed().as_secs();
            let ws_field = match ws_port {
                Some(p) => format!(r#","ws_port":{p}"#),
                None => String::new(),
            };
            let body = format!(
                r#"{{"status":"ok","mode":"{}","uptime_secs":{}{}}}"#,
                mode.as_str(),
                uptime,
                ws_field,
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tcp.write_all(response.as_bytes());
        } else if let Some(did_str) = jwks_did {
            // ADR 146 §2.b — emit the JWKS for `?did=did:emberlink:<root-pubkey>`.
            // Parse failures return 400 with a short JSON error body so the
            // operator (or the upstream OIDC provider) sees why the request
            // was rejected. Success returns 200 with `application/jwk-set+json`
            // per RFC 7517 §8.5.1.
            //
            // Anchor: `did_emberlink_resolver_phase2` — ADR-141-PHASE2-RELAY-RESOLVER-IMPL.
            match parse_did(&did_str) {
                Ok(did) => {
                    let jwks = resolve_did_jwks(&did);
                    let body = jwks.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tcp.write_all(response.as_bytes());
                }
                Err(e) => {
                    let body = format!(r#"{{"error":"invalid_did","reason":"{e}"}}"#);
                    let response = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tcp.write_all(response.as_bytes());
                }
            }
        } else {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = tcp.write_all(response.as_bytes());
        }
    }
}

/// Parse an HTTP request line and return the `did` query parameter when it
/// targets `GET /.well-known/jwks.json?did=…`. Returns `None` for any other
/// request shape (including a `/.well-known/jwks.json` path without the
/// required `did` parameter, which is treated as a malformed JWKS request
/// rather than a separate endpoint).
///
/// The parser is intentionally minimal — it walks the first request line
/// only, accepts both `HTTP/1.0` and `HTTP/1.1` as the trailing version,
/// and treats anything beyond the request line as opaque. URL decoding is
/// not applied to the `did=…` value because `did:emberlink:<base64url>` is
/// already restricted to characters that do not require percent-encoding;
/// callers sending percent-encoded forms get a 400 from `parse_did` once
/// the colons get mangled, which is the correct surface.
///
/// Anchor: `did_emberlink_resolver_phase2` — ADR-141-PHASE2-RELAY-RESOLVER-IMPL.
pub fn parse_jwks_request(request: &str) -> Option<String> {
    let request_line = request.lines().next()?;
    let path_and_query = request_line.strip_prefix("GET ")?;
    // Trim the trailing ` HTTP/1.x` token if present.
    let path_and_query = match path_and_query.split_once(' ') {
        Some((p, _version)) => p,
        None => path_and_query,
    };
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };
    if path != "/.well-known/jwks.json" {
        return None;
    }
    // Walk `did=<value>` out of the query string. The DID grammar contains
    // colons but no `&` or `=`, so the simple split-on-`&` then split-on-`=`
    // scheme suffices.
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("did=") {
            return Some(value.to_owned());
        }
    }
    None
}
