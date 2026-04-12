mod tls;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use core_crypto::Ed25519Verifier;
use core_sync::{PortableRelaySubmission, check_relay_submission_admission};
use core_types::{RelayAdmission, RelayMode, TrustThreshold};

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
    /// Optional shared secret that gates admin commands (STATS, SHUTDOWN,
    /// SHUTDOWN-NOTICE, DRAIN).  When set, every admin command must include
    /// the token as its first space-delimited argument; requests that omit or
    /// mis-state the token are rejected with `AUTH-REQUIRED`.
    /// When `None` the relay accepts admin commands from any connected client
    /// (suitable for local/test deployments only).
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
}

impl RelayConfig {
    fn from_args(args: &[String]) -> Result<Self, String> {
        let mut bind_address = "127.0.0.1:9100".to_string();
        let mut mode = RelayMode::Open;
        let mut threshold: Option<TrustThreshold> = None;
        let mut allowlist: Vec<String> = Vec::new();
        let mut trusted_issuer_keys = HashMap::new();
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;
        let mut tls_self_signed = false;
        let mut no_tls = false;
        let mut max_per_peer: usize = 10_000;
        let mut max_total: usize = 1_000_000;
        let mut admin_token: Option<String> = None;
        let mut max_connections: usize = 1_000;
        let mut read_timeout_secs: u64 = 30;
        let mut max_offers_per_peer: usize = 100;
        let mut max_offer_bytes_total: usize = 50 * 1024 * 1024; // 50 MB
        let mut max_offer_ttl_secs: u64 = 72 * 3600; // 72 hours

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
                    no_tls = true;
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
                    let token = args
                        .get(i)
                        .ok_or("--admin-token requires a value")?
                        .clone();
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
        })
    }
}

/// Graceful shutdown notice state.
#[derive(Debug, Clone)]
struct ShutdownNotice {
    reason: String,
    deadline_epoch: u64,
}

/// A stored grant offer envelope.
///
/// The relay stores offers as opaque encrypted blobs indexed by offer ID.
/// It never sees plaintext — the `payload` is the sealed envelope bytes
/// provided by the issuer.
#[derive(Debug)]
struct StoredOffer {
    /// Opaque encrypted offer payload (bytes as hex or raw, issuer-defined).
    payload: Vec<u8>,
    /// Epoch seconds after which this offer is expired and may be purged.
    expires_at: u64,
    /// Whether this offer has been claimed (consumed).
    claimed: bool,
    /// Source identifier (peer address) for per-peer quota tracking.
    source: String,
}

/// Shared relay state: queued envelopes waiting for pickup by downstream peers.
#[derive(Debug, Default)]
struct RelayState {
    mailboxes: HashMap<String, Vec<PortableRelaySubmission>>,
    /// Grant offer store: offer_id → StoredOffer.
    offers: HashMap<String, StoredOffer>,
    /// Per-source offer count tracking for quota enforcement.
    offer_counts_by_source: HashMap<String, usize>,
    /// Running total of offer payload bytes (updated on insert/purge).
    offer_bytes_total: usize,
    stats: RelayStats,
    shutdown_notice: Option<ShutdownNotice>,
}

#[derive(Debug)]
struct RelayStats {
    accepted: u64,
    rejected: u64,
    delivered: u64,
    started_at: u64,
    peers_seen: std::collections::HashSet<String>,
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
    fn queued_count(&self) -> usize {
        self.mailboxes.values().map(Vec::len).sum()
    }

    /// Remove all offers whose `expires_at` is at or before `now`.
    /// Also updates byte totals and per-source counts.
    fn purge_expired_offers(&mut self, now: u64) {
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
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().map(|a| a.as_str()) == Some("--help")
        || args.first().map(|a| a.as_str()) == Some("-h")
    {
        print_usage();
        return;
    }

    let config = match RelayConfig::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            std::process::exit(1);
        }
    };

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
        eprintln!("  admin commands: UNPROTECTED (set --admin-token for production use)");
    }
    if config.max_connections > 0 {
        eprintln!("  max connections: {}", config.max_connections);
    }
    if config.read_timeout_secs > 0 {
        eprintln!("  read/write timeout: {}s", config.read_timeout_secs);
    }

    let tls_config = match tls::build_server_config(&config.tls_mode) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("TLS setup failed: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(Mutex::new(RelayState::default()));
    let config = Arc::new(config);
    let active_connections = Arc::new(AtomicUsize::new(0));

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
///   - `DRAIN <peer-id>` or `DRAIN <peer-id> <admin-token>` — receive queued envelopes
///   - `STATS` or `STATS <admin-token>` — relay statistics
///   - `SHUTDOWN` or `SHUTDOWN <admin-token>` — immediate shutdown (flushes all mailboxes)
///   - `SHUTDOWN-NOTICE <reason> <deadline-epoch>` or
///     `SHUTDOWN-NOTICE <admin-token> <reason> <deadline-epoch>` — graceful shutdown
///   - `DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>` — store a grant offer envelope
///   - `FETCH_OFFER <offer-id>` — retrieve a grant offer envelope by ID
///   - `CLAIM_OFFER <offer-id>` — mark a grant offer as consumed
///   - `FETCH_AND_CLAIM <offer-id>` — atomically fetch and claim an offer (recommended)
///
/// When `--admin-token` is configured, admin commands without the correct token
/// receive an `AUTH-REQUIRED` response and are otherwise ignored.
/// Grant offer commands (DEPOSIT_OFFER, FETCH_OFFER, CLAIM_OFFER, FETCH_AND_CLAIM) are open to any
/// connected client — same policy as envelope submission.
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

    match parse_command(&payload, config.admin_token.as_deref()) {
        Command::Stats => handle_stats(&mut stream, state),
        Command::Shutdown => handle_shutdown(&mut stream, state),
        Command::ShutdownNotice(notice) => handle_shutdown_notice(&mut stream, state, notice),
        Command::Drain(peer_id) => handle_drain(&mut stream, state, &peer_id),
        Command::Submission => handle_envelope_submission(&mut stream, &payload, config, state),
        Command::DepositOffer { offer_id, expires_at, payload: offer_payload } => {
            // R-H1: Gate offer commands behind relay admission policy.
            if !offer_admission_ok(config) {
                respond(&mut stream, b"REJECTED relay admission policy requires authenticated submission");
                return;
            }
            handle_deposit_offer(&mut stream, state, config, offer_id, expires_at, offer_payload, "anon");
        }
        Command::FetchOffer(offer_id) => {
            if !offer_admission_ok(config) {
                respond(&mut stream, b"REJECTED relay admission policy requires authenticated submission");
                return;
            }
            handle_fetch_offer(&mut stream, state, &offer_id);
        }
        Command::ClaimOffer(offer_id) => {
            if !offer_admission_ok(config) {
                respond(&mut stream, b"REJECTED relay admission policy requires authenticated submission");
                return;
            }
            handle_claim_offer(&mut stream, state, &offer_id);
        }
        Command::FetchAndClaimOffer(offer_id) => {
            if !offer_admission_ok(config) {
                respond(&mut stream, b"REJECTED relay admission policy requires authenticated submission");
                return;
            }
            handle_fetch_and_claim_offer(&mut stream, state, &offer_id);
        }
        Command::AdminRequired => respond(&mut stream, b"AUTH-REQUIRED admin token required for this command"),
    }
}

/// Parsed command derived from an incoming payload frame.
enum Command {
    Stats,
    Shutdown,
    ShutdownNotice(ShutdownNotice),
    Drain(String),
    Submission,
    /// Deposit a grant offer envelope: DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>
    DepositOffer {
        offer_id: String,
        expires_at: u64,
        payload: Vec<u8>,
    },
    /// Fetch a grant offer envelope by ID: FETCH_OFFER <offer-id>
    FetchOffer(String),
    /// Claim (consume) a grant offer: CLAIM_OFFER <offer-id>
    ClaimOffer(String),
    /// Atomically fetch and claim a grant offer: FETCH_AND_CLAIM <offer-id>
    FetchAndClaimOffer(String),
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
/// When `admin_token` is `None` the relay is in open/test mode and accepts
/// the original unauthenticated command format.
fn parse_command(payload: &[u8], admin_token: Option<&str>) -> Command {
    let Ok(text) = std::str::from_utf8(payload) else {
        return Command::Submission;
    };

    // STATS
    if text == "STATS" {
        return match admin_token {
            None => Command::Stats,
            Some(_) => Command::AdminRequired,
        };
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
        return match admin_token {
            None => Command::Shutdown,
            Some(_) => Command::AdminRequired,
        };
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
            None => {
                // Original format: SHUTDOWN-NOTICE <reason> <deadline-epoch>
                parse_notice_args(remainder)
            }
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
            None => {
                // Original format: DRAIN <peer-id>
                let peer_id = rest.trim();
                if peer_id.is_empty() {
                    Command::Submission // malformed, fall through
                } else {
                    Command::Drain(peer_id.to_string())
                }
            }
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

    Command::Submission
}

/// Check whether unauthenticated offer commands are permitted under the
/// current relay admission mode.  Only `Open` mode allows offer operations
/// without an admission token — `TrustGated` and `NetworkScoped` require
/// the full envelope-level admission flow which offer commands do not carry.
fn offer_admission_ok(config: &RelayConfig) -> bool {
    config.mode == RelayMode::Open
}

fn admin_auth_ok(provided: &str, configured: Option<&str>) -> bool {
    match configured {
        None => true,
        Some(tok) => provided == tok,
    }
}

fn parse_notice_args(remainder: &str) -> Command {
    // Format: <reason> <deadline-epoch>  (deadline is the last space-separated token)
    if let Some((reason, deadline_str)) = remainder.rsplit_once(' ') {
        let reason = reason.trim();
        if !reason.is_empty() && let Ok(deadline_epoch) = deadline_str.trim().parse::<u64>() {
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
    Command::DepositOffer { offer_id, expires_at, payload }
}

fn handle_envelope_submission(
    stream: &mut RelayStream,
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
fn handle_deposit_offer(
    stream: &mut RelayStream,
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
    *s.offer_counts_by_source.entry(source.to_string()).or_insert(0) += 1;

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
fn handle_fetch_offer(
    stream: &mut RelayStream,
    state: &Arc<Mutex<RelayState>>,
    offer_id: &str,
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
            respond(
                stream,
                format!("OFFER {offer_id} {hex_payload}").as_bytes(),
            );
        }
    }
}

/// Mark a grant offer as claimed (consumed).
///
/// Wire response:
/// - `OK claimed <offer-id>` on success.
/// - `NOT-FOUND` if the offer is unknown or expired.
/// - `CLAIMED` if the offer has already been consumed.
fn handle_claim_offer(
    stream: &mut RelayStream,
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
fn handle_fetch_and_claim_offer(
    stream: &mut RelayStream,
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
            respond(
                stream,
                format!("OFFER {offer_id} {hex_payload}").as_bytes(),
            );
        }
    }
}

fn admit_submission_payload(
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

fn handle_drain(stream: &mut RelayStream, state: &Arc<Mutex<RelayState>>, peer_id: &str) {
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

fn handle_stats(stream: &mut RelayStream, state: &Arc<Mutex<RelayState>>) {
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

fn handle_shutdown_notice(
    stream: &mut RelayStream,
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

fn handle_shutdown(stream: &mut RelayStream, state: &Arc<Mutex<RelayState>>) {
    let mut s = acquire_state(state);
    let queued = s.queued_count();
    s.mailboxes.clear();
    respond(stream, format!("SHUTDOWN flushed={queued}").as_bytes());
    eprintln!("shutdown requested, flushed {queued} envelopes");
    std::process::exit(0);
}

/// Acquire the relay state lock, recovering from poison if a peer thread panicked.
/// The data is still valid after a panic — we just need to clear the poison flag.
fn acquire_state(state: &Mutex<RelayState>) -> std::sync::MutexGuard<'_, RelayState> {
    state.lock().unwrap_or_else(|poisoned| {
        eprintln!("warning: relay state lock was poisoned by a panicked thread, recovering");
        poisoned.into_inner()
    })
}

/// Write a response frame to the client, logging failures for operator visibility.
fn respond(stream: &mut RelayStream, payload: &[u8]) {
    if let Err(e) = write_frame(stream, payload) {
        eprintln!(
            "warning: failed to write response frame ({} bytes): {e}",
            payload.len()
        );
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
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

fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(payload)?;
    stream.flush()
}

fn print_usage() {
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
                        and DRAIN commands.  Omitting this flag leaves admin commands
                        unprotected — acceptable for local/test use only.

CONNECTION LIMITS:
    --max-connections <n>  Max simultaneous TCP connections (default: 1000, 0 = unlimited)
    --read-timeout <secs>  Read/write timeout per connection in seconds (default: 30, 0 = none)

TLS OPTIONS:
    --tls-self-signed   Generate a self-signed certificate at startup (default)
    --tls-cert <path>   Path to PEM certificate file (e.g., Let's Encrypt fullchain.pem)
    --tls-key <path>    Path to PEM private key file (e.g., Let's Encrypt privkey.pem)
    --no-tls            Disable TLS (plain TCP, for local development only)

    --help              Show this help

WIRE PROTOCOL:
    All messages use 4-byte big-endian length prefix followed by payload.
    Submit:          send a PortableRelaySubmission payload
    Drain:           \"DRAIN <peer-id>\" or \"DRAIN <peer-id> <token>\" (when --admin-token set)
    Stats:           \"STATS\" or \"STATS <token>\"
    Shutdown Notice: \"SHUTDOWN-NOTICE <reason> <deadline-epoch>\" or
                     \"SHUTDOWN-NOTICE <token> <reason> <deadline-epoch>\"
    Shutdown:        \"SHUTDOWN\" or \"SHUTDOWN <token>\"
    Admin commands without the correct token receive AUTH-REQUIRED and are ignored.
    Deposit Offer:   \"DEPOSIT_OFFER <offer-id> <expires-at-epoch> <hex-payload>\"
    Fetch Offer:     \"FETCH_OFFER <offer-id>\"
    Claim Offer:     \"CLAIM_OFFER <offer-id>\"
    Fetch+Claim:     \"FETCH_AND_CLAIM <offer-id>\"  (atomic, recommended)

EXAMPLES:
    emberlink-relay --mode open
    emberlink-relay --mode open --no-tls
    emberlink-relay --admin-token s3cr3t --mode open
    emberlink-relay --tls-cert /etc/letsencrypt/live/relay.example.com/fullchain.pem \\
                    --tls-key /etc/letsencrypt/live/relay.example.com/privkey.pem
    emberlink-relay --mode trust-gated --threshold 0.5 --trusted-issuer persona-alice=ed25519:abcd
    emberlink-relay --mode network-scoped --allow persona-alice --allow persona-bob
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{FixtureSigner, Signer as CryptoSigner};
    use core_sync::wrap_for_relay;
    use core_types::AdmissionToken;

    fn signed_admission_token(
        signer: &FixtureSigner,
        persona_id: &str,
        issuer_persona_id: &str,
        threshold: TrustThreshold,
        issued_at: u64,
        expires_at: u64,
    ) -> AdmissionToken {
        let unsigned = AdmissionToken {
            token_id: "token-1".into(),
            persona_id: persona_id.into(),
            issuer_persona_id: issuer_persona_id.into(),
            issued_at,
            expires_at,
            threshold_met: threshold,
            issuer_signature_hex: String::new(),
        };

        AdmissionToken {
            issuer_signature_hex: signer.sign(&unsigned.signing_payload()).0,
            ..unsigned
        }
    }

    #[test]
    fn config_defaults_to_open_mode() {
        let config = RelayConfig::from_args(&[]).unwrap();
        assert_eq!(config.mode, RelayMode::Open);
        assert_eq!(config.bind_address, "127.0.0.1:9100");
        assert!(config.threshold.is_none());
        assert!(config.allowlist.is_empty());
        assert!(config.trusted_issuer_keys.is_empty());
    }

    #[test]
    fn config_parses_trust_gated_mode() {
        let signer = FixtureSigner::new("relay-issuer");
        let args: Vec<String> = vec![
            "--mode",
            "trust-gated",
            "--threshold",
            "0.7",
            "--trusted-issuer",
            &format!("persona-issuer={}", signer.public_key().0),
            "--bind",
            "0.0.0.0:9200",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let config = RelayConfig::from_args(&args).unwrap();
        assert_eq!(config.mode, RelayMode::TrustGated);
        assert!((config.threshold.unwrap().value() - 0.7).abs() < f32::EPSILON);
        assert_eq!(config.bind_address, "0.0.0.0:9200");
        assert_eq!(
            config.trusted_issuer_keys.get("persona-issuer"),
            Some(&signer.public_key().0)
        );
    }

    #[test]
    fn config_parses_network_scoped_with_allowlist() {
        let args: Vec<String> = vec![
            "--mode",
            "network-scoped",
            "--allow",
            "persona-alice",
            "--allow",
            "persona-bob",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let config = RelayConfig::from_args(&args).unwrap();
        assert_eq!(config.mode, RelayMode::NetworkScoped);
        assert_eq!(config.allowlist, vec!["persona-alice", "persona-bob"]);
    }

    #[test]
    fn config_rejects_trust_gated_without_threshold() {
        let args: Vec<String> = vec!["--mode", "trust-gated"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(RelayConfig::from_args(&args).is_err());
    }

    #[test]
    fn config_rejects_trust_gated_without_trusted_issuer() {
        let args: Vec<String> = vec!["--mode", "trust-gated", "--threshold", "0.7"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(RelayConfig::from_args(&args).is_err());
    }

    #[test]
    fn frame_round_trips() {
        use std::io::Cursor;

        let payload = b"hello relay";
        let mut buf = Vec::new();

        // Write frame to buffer
        let len = (payload.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(payload);

        // Read it back
        let mut cursor = Cursor::new(buf);
        let mut len_buf = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut len_buf).unwrap();
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        let mut frame_payload = vec![0u8; frame_len];
        std::io::Read::read_exact(&mut cursor, &mut frame_payload).unwrap();

        assert_eq!(frame_payload, payload);
    }

    #[test]
    fn parse_drain_request_extracts_target_peer_id() {
        // No admin token configured — original format works
        assert!(
            matches!(parse_command(b"DRAIN peer:/tmp/client-b.tsv", None), Command::Drain(id) if id == "peer:/tmp/client-b.tsv")
        );
        // Bare DRAIN with no peer id falls through to Submission
        assert!(matches!(parse_command(b"DRAIN", None), Command::Submission));
    }

    #[test]
    fn parse_drain_requires_token_when_configured() {
        // Correct token
        assert!(
            matches!(parse_command(b"DRAIN my-peer s3cr3t", Some("s3cr3t")), Command::Drain(id) if id == "my-peer")
        );
        // Wrong token
        assert!(matches!(
            parse_command(b"DRAIN my-peer wrong", Some("s3cr3t")),
            Command::AdminRequired
        ));
        // No token provided
        assert!(matches!(
            parse_command(b"DRAIN my-peer", Some("s3cr3t")),
            Command::AdminRequired
        ));
        // No admin token configured — still works without token
        assert!(
            matches!(parse_command(b"DRAIN my-peer", None), Command::Drain(id) if id == "my-peer")
        );
    }

    #[test]
    fn parse_stats_requires_token_when_configured() {
        assert!(matches!(parse_command(b"STATS", None), Command::Stats));
        assert!(matches!(parse_command(b"STATS tok", Some("tok")), Command::Stats));
        assert!(matches!(parse_command(b"STATS wrong", Some("tok")), Command::AdminRequired));
        assert!(matches!(parse_command(b"STATS", Some("tok")), Command::AdminRequired));
    }

    #[test]
    fn parse_shutdown_requires_token_when_configured() {
        assert!(matches!(parse_command(b"SHUTDOWN", None), Command::Shutdown));
        assert!(matches!(parse_command(b"SHUTDOWN tok", Some("tok")), Command::Shutdown));
        assert!(matches!(parse_command(b"SHUTDOWN wrong", Some("tok")), Command::AdminRequired));
        assert!(matches!(parse_command(b"SHUTDOWN", Some("tok")), Command::AdminRequired));
    }

    #[test]
    fn admit_submission_payload_accepts_valid_signed_token() {
        let issuer_signer = FixtureSigner::new("relay-issuer");
        let token = signed_admission_token(
            &issuer_signer,
            "persona-source",
            "persona-issuer",
            TrustThreshold::new(0.8).unwrap(),
            100,
            200,
        );
        let submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0xaa, 0xbb]),
            admission_token: Some(token),
        };
        let config = RelayConfig {
            bind_address: "127.0.0.1:9100".into(),
            mode: RelayMode::TrustGated,
            threshold: Some(TrustThreshold::new(0.75).unwrap()),
            allowlist: Vec::new(),
            trusted_issuer_keys: HashMap::from([(
                "persona-issuer".to_string(),
                issuer_signer.public_key().0.clone(),
            )]),
            tls_mode: TlsMode::Plain,
            max_per_peer: 0,
            max_total: 0,
            admin_token: None,
            max_connections: 0,
            read_timeout_secs: 0,
            max_offers_per_peer: 100,
            max_offer_bytes_total: 50 * 1024 * 1024,
            max_offer_ttl_secs: 72 * 3600,
        };

        let result = admit_submission_payload(&submission.encode(), &config, 150).unwrap();

        assert_eq!(result.envelope.id, "relay-envelope-1");
        assert_eq!(result.envelope.opaque_payload, vec![0xaa, 0xbb]);
    }

    #[test]
    fn admit_submission_payload_rejects_missing_source_in_network_scoped_mode() {
        let submission = PortableRelaySubmission {
            source_persona_id: None,
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0xaa]),
            admission_token: None,
        };
        let config = RelayConfig {
            bind_address: "127.0.0.1:9100".into(),
            mode: RelayMode::NetworkScoped,
            threshold: None,
            allowlist: vec!["persona-allowed".into()],
            trusted_issuer_keys: HashMap::new(),
            tls_mode: TlsMode::Plain,
            max_per_peer: 0,
            max_total: 0,
            admin_token: None,
            max_connections: 0,
            read_timeout_secs: 0,
            max_offers_per_peer: 100,
            max_offer_bytes_total: 50 * 1024 * 1024,
            max_offer_ttl_secs: 72 * 3600,
        };

        let result = admit_submission_payload(&submission.encode(), &config, 0).unwrap_err();

        assert!(result.contains("source persona metadata"));
    }

    #[test]
    fn admit_submission_payload_rejects_missing_target_peer() {
        let submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: None,
            envelope: wrap_for_relay("relay-envelope-1", vec![0xaa]),
            admission_token: None,
        };
        let config = RelayConfig {
            bind_address: "127.0.0.1:9100".into(),
            mode: RelayMode::Open,
            threshold: None,
            allowlist: Vec::new(),
            trusted_issuer_keys: HashMap::new(),
            tls_mode: TlsMode::Plain,
            max_per_peer: 0,
            max_total: 0,
            admin_token: None,
            max_connections: 0,
            read_timeout_secs: 0,
            max_offers_per_peer: 100,
            max_offer_bytes_total: 50 * 1024 * 1024,
            max_offer_ttl_secs: 72 * 3600,
        };

        let result = admit_submission_payload(&submission.encode(), &config, 0).unwrap_err();

        assert!(result.contains("target peer"));
    }

    #[test]
    fn relay_state_tracks_mailboxes_per_target_peer() {
        let mut state = RelayState::default();
        state.mailboxes.insert(
            "peer:/tmp/client-a.tsv".into(),
            vec![PortableRelaySubmission {
                source_persona_id: Some("persona-source".into()),
                target_peer_id: Some("peer:/tmp/client-a.tsv".into()),
                envelope: wrap_for_relay("relay-envelope-1", vec![0x01]),
                admission_token: None,
            }],
        );
        state.mailboxes.insert(
            "peer:/tmp/client-b.tsv".into(),
            vec![
                PortableRelaySubmission {
                    source_persona_id: Some("persona-source".into()),
                    target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
                    envelope: wrap_for_relay("relay-envelope-2", vec![0x02]),
                    admission_token: None,
                },
                PortableRelaySubmission {
                    source_persona_id: Some("persona-source".into()),
                    target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
                    envelope: wrap_for_relay("relay-envelope-3", vec![0x03]),
                    admission_token: None,
                },
            ],
        );

        assert_eq!(state.queued_count(), 3);
        assert_eq!(state.mailboxes.len(), 2);
    }

    #[test]
    fn config_defaults_to_self_signed_tls() {
        let config = RelayConfig::from_args(&[]).unwrap();
        assert!(matches!(config.tls_mode, TlsMode::SelfSigned));
    }

    #[test]
    fn config_parses_no_tls_flag() {
        let args: Vec<String> = vec!["--no-tls"].into_iter().map(String::from).collect();
        let config = RelayConfig::from_args(&args).unwrap();
        assert!(matches!(config.tls_mode, TlsMode::Plain));
    }

    #[test]
    fn config_parses_tls_cert_and_key() {
        let args: Vec<String> = vec![
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let config = RelayConfig::from_args(&args).unwrap();
        match &config.tls_mode {
            TlsMode::FromFiles {
                cert_path,
                key_path,
            } => {
                assert_eq!(cert_path, "/path/to/cert.pem");
                assert_eq!(key_path, "/path/to/key.pem");
            }
            other => panic!("expected FromFiles, got {:?}", other),
        }
    }

    #[test]
    fn config_rejects_tls_cert_without_key() {
        let args: Vec<String> = vec!["--tls-cert", "/path/to/cert.pem"]
            .into_iter()
            .map(String::from)
            .collect();
        let err = RelayConfig::from_args(&args).unwrap_err();
        assert!(err.contains("must both be provided"));
    }

    #[test]
    fn config_parses_explicit_self_signed() {
        let args: Vec<String> = vec!["--tls-self-signed"]
            .into_iter()
            .map(String::from)
            .collect();
        let config = RelayConfig::from_args(&args).unwrap();
        assert!(matches!(config.tls_mode, TlsMode::SelfSigned));
    }

    #[test]
    fn self_signed_tls_config_builds_successfully() {
        let config = tls::build_server_config(&TlsMode::SelfSigned).unwrap();
        assert!(
            config.is_some(),
            "self-signed should produce a ServerConfig"
        );
    }

    #[test]
    fn plain_tls_config_returns_none() {
        let config = tls::build_server_config(&TlsMode::Plain).unwrap();
        assert!(
            config.is_none(),
            "plain mode should produce no ServerConfig"
        );
    }

    #[test]
    fn parse_shutdown_notice_extracts_reason_and_deadline() {
        let cmd = parse_command(b"SHUTDOWN-NOTICE legal-compliance 1700000000", None);
        let Command::ShutdownNotice(notice) = cmd else { panic!("expected ShutdownNotice") };
        assert_eq!(notice.reason, "legal-compliance");
        assert_eq!(notice.deadline_epoch, 1700000000);
    }

    #[test]
    fn parse_shutdown_notice_allows_multi_word_reason() {
        let cmd = parse_command(b"SHUTDOWN-NOTICE server maintenance window 1700000000", None);
        let Command::ShutdownNotice(notice) = cmd else { panic!("expected ShutdownNotice") };
        assert_eq!(notice.reason, "server maintenance window");
        assert_eq!(notice.deadline_epoch, 1700000000);
    }

    #[test]
    fn parse_shutdown_notice_rejects_missing_deadline() {
        assert!(matches!(parse_command(b"SHUTDOWN-NOTICE", None), Command::Submission));
        assert!(matches!(parse_command(b"SHUTDOWN-NOTICE ", None), Command::Submission));
    }

    #[test]
    fn parse_shutdown_notice_rejects_non_numeric_deadline() {
        assert!(matches!(
            parse_command(b"SHUTDOWN-NOTICE reason not-a-number", None),
            Command::Submission
        ));
    }

    #[test]
    fn parse_shutdown_notice_rejects_empty_reason() {
        assert!(matches!(
            parse_command(b"SHUTDOWN-NOTICE  1700000000", None),
            Command::Submission
        ));
    }

    #[test]
    fn parse_shutdown_notice_requires_token_when_configured() {
        // Authenticated format: SHUTDOWN-NOTICE <token> <reason> <deadline>
        let cmd = parse_command(b"SHUTDOWN-NOTICE tok maintenance 1700000000", Some("tok"));
        let Command::ShutdownNotice(notice) = cmd else { panic!("expected ShutdownNotice") };
        assert_eq!(notice.reason, "maintenance");
        assert_eq!(notice.deadline_epoch, 1700000000);

        // Wrong token
        assert!(matches!(
            parse_command(b"SHUTDOWN-NOTICE wrong maintenance 1700000000", Some("tok")),
            Command::AdminRequired
        ));
        // No token
        assert!(matches!(
            parse_command(b"SHUTDOWN-NOTICE maintenance 1700000000", Some("tok")),
            Command::AdminRequired
        ));
    }

    #[test]
    fn shutdown_notice_sets_state_and_rejects_submissions() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        assert!(state.lock().unwrap().shutdown_notice.is_none());

        // Set shutdown notice
        {
            let mut s = state.lock().unwrap();
            s.shutdown_notice = Some(ShutdownNotice {
                reason: "maintenance".to_string(),
                deadline_epoch: 1700000000,
            });
        }

        assert!(state.lock().unwrap().shutdown_notice.is_some());
        let notice = state.lock().unwrap().shutdown_notice.clone().unwrap();
        assert_eq!(notice.reason, "maintenance");
        assert_eq!(notice.deadline_epoch, 1700000000);
    }

    // ── Grant offer protocol tests ────────────────────────────────────────────

    /// Helper: hex-encode a payload for use in DEPOSIT_OFFER commands.
    fn hex_payload(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Default open-mode config for offer tests.
    fn test_offer_config() -> RelayConfig {
        RelayConfig {
            bind_address: "127.0.0.1:9100".into(),
            mode: RelayMode::Open,
            threshold: None,
            allowlist: Vec::new(),
            trusted_issuer_keys: HashMap::new(),
            tls_mode: TlsMode::Plain,
            max_per_peer: 0,
            max_total: 0,
            admin_token: None,
            max_connections: 0,
            read_timeout_secs: 0,
            max_offers_per_peer: 100,
            max_offer_bytes_total: 50 * 1024 * 1024,
            max_offer_ttl_secs: 72 * 3600,
        }
    }

    #[test]
    fn parse_deposit_offer_valid() {
        let hex = hex_payload(b"sealed-bytes");
        let cmd = parse_command(
            format!("DEPOSIT_OFFER offer-abc 9999999999 {hex}").as_bytes(),
            None,
        );
        assert!(matches!(cmd, Command::DepositOffer { offer_id, expires_at, payload }
            if offer_id == "offer-abc" && expires_at == 9999999999 && payload == b"sealed-bytes"
        ));
    }

    #[test]
    fn parse_deposit_offer_bad_hex_falls_through_to_submission() {
        let cmd = parse_command(b"DEPOSIT_OFFER offer-abc 9999999999 notvalidhex!", None);
        assert!(matches!(cmd, Command::Submission));
    }

    #[test]
    fn parse_fetch_offer_valid() {
        let cmd = parse_command(b"FETCH_OFFER offer-xyz", None);
        assert!(matches!(cmd, Command::FetchOffer(id) if id == "offer-xyz"));
    }

    #[test]
    fn parse_claim_offer_valid() {
        let cmd = parse_command(b"CLAIM_OFFER offer-xyz", None);
        assert!(matches!(cmd, Command::ClaimOffer(id) if id == "offer-xyz"));
    }

    /// Invoke a handler over a loopback TCP pair and read back the response frame.
    ///
    /// `f` is called with the server-side `RelayStream`.  The returned bytes are
    /// the raw framed response as written by `respond()`.
    fn with_loopback<F: FnOnce(&mut RelayStream) + Send + 'static>(f: F) -> Vec<u8> {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (server_tcp, _) = listener.accept().unwrap();
            let mut stream = RelayStream::Plain(server_tcp);
            f(&mut stream);
        });

        let client_tcp = std::net::TcpStream::connect(addr).unwrap();
        client_tcp
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        handle.join().unwrap();

        // Drain all bytes written by the handler.
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::BufReader::new(&client_tcp), &mut buf);
        buf
    }

    /// Decode the first framed response from a buffer.
    fn read_response(buf: &[u8]) -> String {
        if buf.len() < 4 {
            return String::new();
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        String::from_utf8_lossy(&buf[4..4 + len]).to_string()
    }

    /// Full lifecycle: deposit → fetch → claim → fetch returns CLAIMED.
    #[test]
    fn offer_deposit_fetch_claim_lifecycle() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let offer_id = "offer-test-1".to_string();
        let payload = b"encrypted-grant-blob".to_vec();
        let far_future = now_epoch_secs() + 86400; // 24 h from now

        // --- Deposit ---
        let s = Arc::clone(&state);
        let oid = offer_id.clone();
        let pl = payload.clone();
        let cfg = Arc::new(test_offer_config());
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, oid, far_future, pl, "test-peer");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("OK deposited offer-test-1"), "got: {resp}");
        assert!(state.lock().unwrap().offers.contains_key("offer-test-1"));

        // --- Fetch ---
        let s = Arc::clone(&state);
        let oid = offer_id.clone();
        let buf = with_loopback(move |stream| {
            handle_fetch_offer(stream, &s, &oid);
        });
        let resp = read_response(&buf);
        let expected_hex = hex::encode(&payload);
        assert!(
            resp.starts_with(&format!("OFFER offer-test-1 {expected_hex}")),
            "got: {resp}"
        );

        // --- Claim ---
        let s = Arc::clone(&state);
        let oid = offer_id.clone();
        let buf = with_loopback(move |stream| {
            handle_claim_offer(stream, &s, &oid);
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("OK claimed offer-test-1"), "got: {resp}");

        // --- Fetch after claim returns CLAIMED ---
        let s = Arc::clone(&state);
        let oid = offer_id.clone();
        let buf = with_loopback(move |stream| {
            handle_fetch_offer(stream, &s, &oid);
        });
        assert_eq!(read_response(&buf), "CLAIMED");

        // --- Second claim attempt also returns CLAIMED ---
        let s = Arc::clone(&state);
        let oid = offer_id.clone();
        let buf = with_loopback(move |stream| {
            handle_claim_offer(stream, &s, &oid);
        });
        assert_eq!(read_response(&buf), "CLAIMED");
    }

    #[test]
    fn fetch_unknown_offer_returns_not_found() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let buf = with_loopback(move |stream| {
            handle_fetch_offer(stream, &state, "offer-does-not-exist");
        });
        assert_eq!(read_response(&buf), "NOT-FOUND");
    }

    #[test]
    fn deposit_duplicate_offer_is_rejected() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let far_future = now_epoch_secs() + 86400;

        let s = Arc::clone(&state);
        let cfg = Arc::new(test_offer_config());
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-dup".to_string(), far_future, b"payload".to_vec(), "test-peer");
        });
        assert!(read_response(&buf).starts_with("OK deposited"));

        // Second deposit with same ID is rejected.
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &state, &c, "offer-dup".to_string(), far_future, b"payload".to_vec(), "test-peer");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("REJECTED offer already exists"), "got: {resp}");
    }

    #[test]
    fn deposit_already_expired_offer_is_rejected() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let past = now_epoch_secs().saturating_sub(1);

        let cfg = Arc::new(test_offer_config());
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &state, &cfg, "offer-expired".to_string(), past, b"payload".to_vec(), "test-peer");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("REJECTED offer already expired"), "got: {resp}");
    }

    #[test]
    fn expired_offers_are_purged_on_next_operation() {
        let state = Arc::new(Mutex::new(RelayState::default()));

        // Insert an offer that is already expired.
        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-stale".to_string(),
                StoredOffer {
                    payload: b"stale".to_vec(),
                    expires_at: 1, // epoch 1 — definitely in the past
                    claimed: false,
                    source: "test".into(),
                },
            );
        }

        // Fetching the stale offer triggers purge; it is gone.
        let s = Arc::clone(&state);
        let buf = with_loopback(move |stream| {
            handle_fetch_offer(stream, &s, "offer-stale");
        });
        assert_eq!(read_response(&buf), "NOT-FOUND");
        assert!(!state.lock().unwrap().offers.contains_key("offer-stale"));
    }

    #[test]
    fn purge_expired_offers_removes_only_expired() {
        let mut state = RelayState::default();
        let now = now_epoch_secs();

        state.offers.insert(
            "expired".to_string(),
            StoredOffer { payload: vec![], expires_at: now.saturating_sub(1), claimed: false, source: "test".into() },
        );
        state.offers.insert(
            "live".to_string(),
            StoredOffer { payload: vec![], expires_at: now + 3600, claimed: false, source: "test".into() },
        );

        state.purge_expired_offers(now);

        assert!(!state.offers.contains_key("expired"));
        assert!(state.offers.contains_key("live"));
    }

    #[test]
    fn claim_offer_during_shutdown_notice_is_allowed() {
        // Shutdown notice blocks envelope submissions but NOT offer operations.
        let state = Arc::new(Mutex::new(RelayState::default()));
        let far_future = now_epoch_secs() + 86400;

        // Pre-insert an offer (bypass deposit which IS blocked by shutdown notice).
        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-pre".to_string(),
                StoredOffer { payload: b"blob".to_vec(), expires_at: far_future, claimed: false, source: "test".into() },
            );
        }

        let buf = with_loopback(move |stream| {
            handle_claim_offer(stream, &state, "offer-pre");
        });
        assert!(read_response(&buf).starts_with("OK claimed"));
    }

    #[test]
    fn parse_fetch_and_claim_valid() {
        let cmd = parse_command(b"FETCH_AND_CLAIM offer-xyz", None);
        assert!(matches!(cmd, Command::FetchAndClaimOffer(id) if id == "offer-xyz"));
    }

    /// FETCH_AND_CLAIM atomically returns the payload and marks the offer as claimed.
    #[test]
    fn fetch_and_claim_returns_payload_and_marks_claimed() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let far_future = now_epoch_secs() + 86400;
        let payload = b"encrypted-grant-blob".to_vec();

        // Pre-insert an offer.
        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-atomic".to_string(),
                StoredOffer { payload: payload.clone(), expires_at: far_future, claimed: false, source: "test".into() },
            );
        }

        // FETCH_AND_CLAIM returns the payload.
        let s = Arc::clone(&state);
        let buf = with_loopback(move |stream| {
            handle_fetch_and_claim_offer(stream, &s, "offer-atomic");
        });
        let resp = read_response(&buf);
        let expected_hex = hex::encode(&payload);
        assert!(
            resp.starts_with(&format!("OFFER offer-atomic {expected_hex}")),
            "got: {resp}"
        );

        // Offer is now claimed.
        assert!(state.lock().unwrap().offers.get("offer-atomic").unwrap().claimed);
    }

    /// Second FETCH_AND_CLAIM on the same offer returns CLAIMED.
    #[test]
    fn fetch_and_claim_second_attempt_returns_claimed() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let far_future = now_epoch_secs() + 86400;

        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-once".to_string(),
                StoredOffer { payload: b"blob".to_vec(), expires_at: far_future, claimed: false, source: "test".into() },
            );
        }

        // First claim succeeds.
        let s = Arc::clone(&state);
        let buf = with_loopback(move |stream| {
            handle_fetch_and_claim_offer(stream, &s, "offer-once");
        });
        assert!(read_response(&buf).starts_with("OFFER offer-once"));

        // Second claim fails.
        let s = Arc::clone(&state);
        let buf = with_loopback(move |stream| {
            handle_fetch_and_claim_offer(stream, &s, "offer-once");
        });
        assert_eq!(read_response(&buf), "CLAIMED");
    }

    /// FETCH_AND_CLAIM on unknown offer returns NOT-FOUND.
    #[test]
    fn fetch_and_claim_unknown_returns_not_found() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let buf = with_loopback(move |stream| {
            handle_fetch_and_claim_offer(stream, &state, "offer-nope");
        });
        assert_eq!(read_response(&buf), "NOT-FOUND");
    }

    /// Simulates the FETCH+CLAIM race: two threads both try FETCH_AND_CLAIM
    /// concurrently. Exactly one gets the payload, the other gets CLAIMED.
    #[test]
    fn fetch_and_claim_race_condition_only_one_wins() {
        use std::sync::Barrier;

        let state = Arc::new(Mutex::new(RelayState::default()));
        let far_future = now_epoch_secs() + 86400;

        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-race".to_string(),
                StoredOffer { payload: b"secret".to_vec(), expires_at: far_future, claimed: false, source: "test".into() },
            );
        }

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let s = Arc::clone(&state);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait(); // synchronize both threads to maximize contention
                let buf = with_loopback(move |stream| {
                    handle_fetch_and_claim_offer(stream, &s, "offer-race");
                });
                read_response(&buf)
            }));
        }

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners = results.iter().filter(|r| r.starts_with("OFFER")).count();
        let losers = results.iter().filter(|r| *r == "CLAIMED").count();

        assert_eq!(winners, 1, "exactly one client should get the payload, got: {results:?}");
        assert_eq!(losers, 1, "exactly one client should be rejected, got: {results:?}");
    }

    #[test]
    fn deposit_offer_blocked_during_shutdown_notice() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        {
            let mut s = state.lock().unwrap();
            s.shutdown_notice = Some(ShutdownNotice {
                reason: "planned".to_string(),
                deadline_epoch: 9999999999,
            });
        }

        let cfg = Arc::new(test_offer_config());
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(
                stream,
                &state,
                &cfg,
                "offer-x".to_string(),
                now_epoch_secs() + 3600,
                b"payload".to_vec(),
                "test-peer",
            );
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("REJECTED relay is shutting down"), "got: {resp}");
    }

    // ── R-H1: Offer admission gating tests ──────────────────────────────────

    #[test]
    fn offer_admission_rejected_in_trust_gated_mode() {
        let config = RelayConfig {
            mode: RelayMode::TrustGated,
            ..test_offer_config()
        };
        assert!(!offer_admission_ok(&config));
    }

    #[test]
    fn offer_admission_rejected_in_network_scoped_mode() {
        let config = RelayConfig {
            mode: RelayMode::NetworkScoped,
            ..test_offer_config()
        };
        assert!(!offer_admission_ok(&config));
    }

    #[test]
    fn offer_admission_allowed_in_open_mode() {
        let config = test_offer_config();
        assert!(offer_admission_ok(&config));
    }

    // ── R-H2: Quota enforcement tests ───────────────────────────────────────

    #[test]
    fn deposit_rejected_when_per_peer_quota_exceeded() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let mut cfg = test_offer_config();
        cfg.max_offers_per_peer = 1; // only 1 allowed
        let cfg = Arc::new(cfg);
        let far_future = now_epoch_secs() + 3600;

        // First deposit succeeds.
        let s = Arc::clone(&state);
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-1".into(), far_future, b"a".to_vec(), "peer-a");
        });
        assert!(read_response(&buf).starts_with("OK deposited"), "first deposit should succeed");

        // Second deposit from same source is rejected.
        let s = Arc::clone(&state);
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-2".into(), far_future, b"b".to_vec(), "peer-a");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("REJECTED offer quota exceeded"), "got: {resp}");

        // Different source succeeds.
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &state, &c, "offer-3".into(), far_future, b"c".to_vec(), "peer-b");
        });
        assert!(read_response(&buf).starts_with("OK deposited"), "different peer should succeed");
    }

    #[test]
    fn deposit_rejected_when_byte_quota_exceeded() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let mut cfg = test_offer_config();
        cfg.max_offer_bytes_total = 10; // very small
        let cfg = Arc::new(cfg);
        let far_future = now_epoch_secs() + 3600;

        // First deposit with 8 bytes succeeds.
        let s = Arc::clone(&state);
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-1".into(), far_future, vec![0u8; 8], "p");
        });
        assert!(read_response(&buf).starts_with("OK deposited"));

        // Second deposit with 5 bytes exceeds the 10-byte limit.
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &state, &c, "offer-2".into(), far_future, vec![0u8; 5], "p");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("REJECTED offer store byte quota"), "got: {resp}");
    }

    #[test]
    fn deposit_ttl_capped_to_max() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let mut cfg = test_offer_config();
        cfg.max_offer_ttl_secs = 60; // 1 minute
        let cfg = Arc::new(cfg);
        let now = now_epoch_secs();
        let far_future = now + 86400; // 24h — way beyond the 60s cap

        let s = Arc::clone(&state);
        let c = Arc::clone(&cfg);
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-ttl".into(), far_future, b"x".to_vec(), "p");
        });
        assert!(read_response(&buf).starts_with("OK deposited"));

        // The stored expires_at should be capped to now + 60.
        let s = state.lock().unwrap();
        let offer = s.offers.get("offer-ttl").unwrap();
        assert!(offer.expires_at <= now + 60 + 1, "TTL should be capped; got expires_at={}", offer.expires_at);
    }

    #[test]
    fn claimed_offer_frees_payload_bytes() {
        let state = Arc::new(Mutex::new(RelayState::default()));
        let cfg = Arc::new(test_offer_config());
        let far_future = now_epoch_secs() + 3600;
        let payload = vec![0xAA; 100];

        // Deposit
        let s = Arc::clone(&state);
        let c = Arc::clone(&cfg);
        let pl = payload.clone();
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &s, &c, "offer-free".into(), far_future, pl, "p");
        });
        assert!(read_response(&buf).starts_with("OK deposited"));
        assert_eq!(state.lock().unwrap().offer_bytes_total, 100);

        // Claim
        let s = Arc::clone(&state);
        let buf = with_loopback(move |stream| {
            handle_claim_offer(stream, &s, "offer-free");
        });
        assert!(read_response(&buf).starts_with("OK claimed"));

        // Payload freed, byte total updated.
        let s = state.lock().unwrap();
        assert!(s.offers.get("offer-free").unwrap().payload.is_empty());
        assert_eq!(s.offer_bytes_total, 0);
    }

    // ── R-M1: Purge ordering test ───────────────────────────────────────────

    #[test]
    fn expired_offer_does_not_block_new_deposit_with_same_id() {
        let state = Arc::new(Mutex::new(RelayState::default()));

        // Insert an offer that is already expired.
        {
            let mut s = state.lock().unwrap();
            s.offers.insert(
                "offer-reuse".to_string(),
                StoredOffer {
                    payload: b"old".to_vec(),
                    expires_at: 1, // epoch 1 — expired
                    claimed: false,
                    source: "test".into(),
                },
            );
            s.offer_bytes_total = 3;
            *s.offer_counts_by_source.entry("test".into()).or_insert(0) += 1;
        }

        // A new deposit with the same offer ID should succeed (purge runs first).
        let cfg = Arc::new(test_offer_config());
        let far_future = now_epoch_secs() + 3600;
        let buf = with_loopback(move |stream| {
            handle_deposit_offer(stream, &state, &cfg, "offer-reuse".into(), far_future, b"new".to_vec(), "test");
        });
        let resp = read_response(&buf);
        assert!(resp.starts_with("OK deposited offer-reuse"), "got: {resp}");
    }
}
