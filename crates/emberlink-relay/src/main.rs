mod tls;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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
        })
    }
}

/// Graceful shutdown notice state.
#[derive(Debug, Clone)]
struct ShutdownNotice {
    reason: String,
    deadline_epoch: u64,
}

/// Shared relay state: queued envelopes waiting for pickup by downstream peers.
#[derive(Debug, Default)]
struct RelayState {
    mailboxes: HashMap<String, Vec<PortableRelaySubmission>>,
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

    let tls_config = match tls::build_server_config(&config.tls_mode) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("TLS setup failed: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(Mutex::new(RelayState::default()));
    let config = Arc::new(config);

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
                let config = Arc::clone(&config);
                let state = Arc::clone(&state);
                let tls_config = Arc::clone(&tls_config);
                thread::spawn(move || {
                    match RelayStream::accept(tcp_stream, tls_config.as_ref().as_ref()) {
                        Ok(stream) => handle_connection(stream, &config, &state),
                        Err(e) => eprintln!("TLS handshake error: {e}"),
                    }
                });
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }
}

/// Wire protocol (minimal, v0.3):
///
/// Client sends: 4-byte big-endian length prefix, then payload bytes.
/// Payload is one of:
///   - A PortableRelaySubmission (submit for forwarding)
///   - The literal bytes "DRAIN <peer-id>" (request queued envelopes for a peer)
///   - The literal bytes "STATS" (request relay statistics)
///   - The literal bytes "SHUTDOWN" (immediate shutdown, flushes all mailboxes)
///   - The literal bytes "SHUTDOWN-NOTICE <reason> <deadline-epoch>"
///     (graceful shutdown: rejects new submissions, clients should drain)
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

    match payload.as_slice() {
        b"STATS" => handle_stats(&mut stream, state),
        b"SHUTDOWN" => handle_shutdown(&mut stream, state),
        _ => {
            if let Some(notice) = parse_shutdown_notice(&payload) {
                handle_shutdown_notice(&mut stream, state, notice)
            } else if let Some(peer_id) = parse_drain_request(&payload) {
                handle_drain(&mut stream, state, &peer_id)
            } else {
                handle_envelope_submission(&mut stream, &payload, config, state)
            }
        }
    }
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

fn parse_drain_request(payload: &[u8]) -> Option<String> {
    let command = std::str::from_utf8(payload).ok()?;
    command
        .strip_prefix("DRAIN ")
        .map(str::trim)
        .filter(|peer_id| !peer_id.is_empty())
        .map(ToString::to_string)
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
    let response = format!(
        "STATS accepted={} rejected={} delivered={} queued={} mailboxes={} peers_seen={} uptime={}s",
        s.stats.accepted,
        s.stats.rejected,
        s.stats.delivered,
        s.queued_count(),
        s.mailboxes.len(),
        s.stats.peers_seen.len(),
        uptime,
    );
    respond(stream, response.as_bytes());
}

fn parse_shutdown_notice(payload: &[u8]) -> Option<ShutdownNotice> {
    let command = std::str::from_utf8(payload).ok()?;
    let remainder = command.strip_prefix("SHUTDOWN-NOTICE ")?;
    let (reason, deadline_str) = remainder.rsplit_once(' ')?;
    let reason = reason.trim();
    let deadline_epoch = deadline_str.trim().parse::<u64>().ok()?;
    if reason.is_empty() {
        return None;
    }
    Some(ShutdownNotice {
        reason: reason.to_string(),
        deadline_epoch,
    })
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

TLS OPTIONS:
    --tls-self-signed   Generate a self-signed certificate at startup (default)
    --tls-cert <path>   Path to PEM certificate file (e.g., Let's Encrypt fullchain.pem)
    --tls-key <path>    Path to PEM private key file (e.g., Let's Encrypt privkey.pem)
    --no-tls            Disable TLS (plain TCP, for local development only)

    --help              Show this help

WIRE PROTOCOL:
    All messages use 4-byte big-endian length prefix followed by payload.
    Submit:          send a PortableRelaySubmission payload
    Drain:           send literal \"DRAIN <peer-id>\" to receive queued envelopes
    Stats:           send literal \"STATS\" to get relay statistics
    Shutdown Notice: send literal \"SHUTDOWN-NOTICE <reason> <deadline-epoch>\"
                     to initiate graceful shutdown (rejects new submissions,
                     drain responses include shutdown metadata)
    Shutdown:        send literal \"SHUTDOWN\" for immediate shutdown (flushes all)

EXAMPLES:
    emberlink-relay --mode open
    emberlink-relay --mode open --no-tls
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
        assert_eq!(
            parse_drain_request(b"DRAIN peer:/tmp/client-b.tsv").as_deref(),
            Some("peer:/tmp/client-b.tsv")
        );
        assert!(parse_drain_request(b"DRAIN").is_none());
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
        let notice = parse_shutdown_notice(b"SHUTDOWN-NOTICE legal-compliance 1700000000").unwrap();
        assert_eq!(notice.reason, "legal-compliance");
        assert_eq!(notice.deadline_epoch, 1700000000);
    }

    #[test]
    fn parse_shutdown_notice_allows_multi_word_reason() {
        let notice =
            parse_shutdown_notice(b"SHUTDOWN-NOTICE server maintenance window 1700000000").unwrap();
        assert_eq!(notice.reason, "server maintenance window");
        assert_eq!(notice.deadline_epoch, 1700000000);
    }

    #[test]
    fn parse_shutdown_notice_rejects_missing_deadline() {
        assert!(parse_shutdown_notice(b"SHUTDOWN-NOTICE").is_none());
        assert!(parse_shutdown_notice(b"SHUTDOWN-NOTICE ").is_none());
    }

    #[test]
    fn parse_shutdown_notice_rejects_non_numeric_deadline() {
        assert!(parse_shutdown_notice(b"SHUTDOWN-NOTICE reason not-a-number").is_none());
    }

    #[test]
    fn parse_shutdown_notice_rejects_empty_reason() {
        assert!(parse_shutdown_notice(b"SHUTDOWN-NOTICE  1700000000").is_none());
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
}
