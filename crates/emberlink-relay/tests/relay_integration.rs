use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use emberlink_relay::{
    AdmittedRequest, Command, RelayConfig, RelayState, ShutdownNotice, StoredOffer, admission,
    admit_submission_payload, auxiliary_bind_host, dispatch_command, handle_claim_offer,
    handle_deposit_offer, handle_fetch_and_claim_offer, handle_fetch_grant_requests,
    handle_fetch_offer, handle_request_grant, handle_respond_grant_request, now_epoch_secs,
    offer_admission_ok, parse_command, run_health_server,
    tls::{self, RelayStream, TlsMode},
};

fn test_admitted(persona: &str, scope: &str) -> AdmittedRequest {
    admission::gate(None, Some(persona), Some(scope)).expect("test gate admits")
}
use core_crypto::{FixtureSigner, PublicKey, Signature, Signer as CryptoSigner};
use core_principals::AdmissionToken;
use core_principals::{RelayMode, TrustThreshold};
use core_sync::wrap_for_relay;
use emberlink_relay::{RESPOND_GRANT_REQUEST_NONCE_BYTES, respond_grant_request_signing_payload};

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
    assert_eq!(config.ws_port, None);
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
    assert!(
        matches!(parse_command(b"DRAIN peer:/tmp/client-b.tsv tok", Some("tok")), Command::Drain(id) if id == "peer:/tmp/client-b.tsv")
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
    assert!(matches!(
        parse_command(b"DRAIN my-peer", None),
        Command::AdminRequired
    ));
}

#[test]
fn parse_stats_requires_token_when_configured() {
    assert!(matches!(
        parse_command(b"STATS", None),
        Command::AdminRequired
    ));
    assert!(matches!(
        parse_command(b"STATS tok", Some("tok")),
        Command::Stats
    ));
    assert!(matches!(
        parse_command(b"STATS wrong", Some("tok")),
        Command::AdminRequired
    ));
    assert!(matches!(
        parse_command(b"STATS", Some("tok")),
        Command::AdminRequired
    ));
}

#[test]
fn parse_shutdown_requires_token_when_configured() {
    assert!(matches!(
        parse_command(b"SHUTDOWN", None),
        Command::AdminRequired
    ));
    assert!(matches!(
        parse_command(b"SHUTDOWN tok", Some("tok")),
        Command::Shutdown
    ));
    assert!(matches!(
        parse_command(b"SHUTDOWN wrong", Some("tok")),
        Command::AdminRequired
    ));
    assert!(matches!(
        parse_command(b"SHUTDOWN", Some("tok")),
        Command::AdminRequired
    ));
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
    let submission = core_sync::PortableRelaySubmission {
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
        health_port: None,
        ws_port: None,
    };

    let result = admit_submission_payload(&submission.encode(), &config, 150).unwrap();

    assert_eq!(result.envelope.id, "relay-envelope-1");
    assert_eq!(result.envelope.opaque_payload, vec![0xaa, 0xbb]);
}

#[test]
fn admit_submission_payload_rejects_missing_source_in_network_scoped_mode() {
    let submission = core_sync::PortableRelaySubmission {
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
        health_port: None,
        ws_port: None,
    };

    let result = admit_submission_payload(&submission.encode(), &config, 0).unwrap_err();

    assert!(result.contains("source persona metadata"));
}

#[test]
fn admit_submission_payload_rejects_missing_target_peer() {
    let submission = core_sync::PortableRelaySubmission {
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
        health_port: None,
        ws_port: None,
    };

    let result = admit_submission_payload(&submission.encode(), &config, 0).unwrap_err();

    assert!(result.contains("target peer"));
}

#[test]
fn relay_state_tracks_mailboxes_per_target_peer() {
    let mut state = RelayState::default();
    state.mailboxes.insert(
        "peer:/tmp/client-a.tsv".into(),
        vec![core_sync::PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-a.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0x01]),
            admission_token: None,
        }],
    );
    state.mailboxes.insert(
        "peer:/tmp/client-b.tsv".into(),
        vec![
            core_sync::PortableRelaySubmission {
                source_persona_id: Some("persona-source".into()),
                target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
                envelope: wrap_for_relay("relay-envelope-2", vec![0x02]),
                admission_token: None,
            },
            core_sync::PortableRelaySubmission {
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

/// Tier A §A4: when the
/// `insecure-no-tls` cargo feature is OFF (default), `--no-tls` is
/// rejected by `from_args` rather than silently downgrading to plain
/// TCP. Production builds compile without the feature; an operator who
/// types `--no-tls` sees an error referring to the relay-TLS ticket.
#[cfg(not(feature = "insecure-no-tls"))]
#[test]
fn config_rejects_no_tls_in_production_build() {
    let args: Vec<String> = vec!["--no-tls"].into_iter().map(String::from).collect();
    let err = RelayConfig::from_args(&args).unwrap_err();
    assert!(
        err.contains("--no-tls is rejected"),
        "expected production refusal, got: {err}"
    );
    assert!(
        err.contains("AUDIT-V030"),
        "expected ticket reference in error, got: {err}"
    );
}

/// Tier A §A4: when the
/// `insecure-no-tls` cargo feature is ON (test loopback rigs only),
/// `--no-tls` is accepted to keep `core-sim/tests/agent_e2e.rs` workable.
#[cfg(feature = "insecure-no-tls")]
#[test]
fn config_parses_no_tls_flag_when_feature_enabled() {
    let args: Vec<String> = vec!["--no-tls"].into_iter().map(String::from).collect();
    let config = RelayConfig::from_args(&args).unwrap();
    assert!(matches!(config.tls_mode, TlsMode::Plain));
}

#[test]
fn config_accepts_ws_port_as_disabled_compatibility_noop() {
    let args: Vec<String> = vec!["--ws-port", "9200"]
        .into_iter()
        .map(String::from)
        .collect();
    let config = RelayConfig::from_args(&args).unwrap();
    assert_eq!(
        config.ws_port, None,
        "v0.3.0 release containment must not enable the cleartext WS command surface"
    );
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
    let cmd = parse_command(
        b"SHUTDOWN-NOTICE tok legal-compliance 1700000000",
        Some("tok"),
    );
    let Command::ShutdownNotice(notice) = cmd else {
        panic!("expected ShutdownNotice")
    };
    assert_eq!(notice.reason, "legal-compliance");
    assert_eq!(notice.deadline_epoch, 1700000000);
}

#[test]
fn parse_shutdown_notice_allows_multi_word_reason() {
    let cmd = parse_command(
        b"SHUTDOWN-NOTICE tok server maintenance window 1700000000",
        Some("tok"),
    );
    let Command::ShutdownNotice(notice) = cmd else {
        panic!("expected ShutdownNotice")
    };
    assert_eq!(notice.reason, "server maintenance window");
    assert_eq!(notice.deadline_epoch, 1700000000);
}

#[test]
fn parse_shutdown_notice_rejects_missing_deadline() {
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE", None),
        Command::Submission
    ));
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE ", Some("tok")),
        Command::AdminRequired
    ));
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE tok ", Some("tok")),
        Command::Submission
    ));
}

#[test]
fn parse_shutdown_notice_rejects_non_numeric_deadline() {
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE tok reason not-a-number", Some("tok")),
        Command::Submission
    ));
}

#[test]
fn parse_shutdown_notice_rejects_empty_reason() {
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE tok  1700000000", Some("tok")),
        Command::Submission
    ));
}

#[test]
fn parse_shutdown_notice_requires_configured_token() {
    assert!(matches!(
        parse_command(b"SHUTDOWN-NOTICE maintenance 1700000000", None),
        Command::AdminRequired
    ));
}

#[test]
fn parse_shutdown_notice_requires_token_when_configured() {
    // Authenticated format: SHUTDOWN-NOTICE <token> <reason> <deadline>
    let cmd = parse_command(b"SHUTDOWN-NOTICE tok maintenance 1700000000", Some("tok"));
    let Command::ShutdownNotice(notice) = cmd else {
        panic!("expected ShutdownNotice")
    };
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
        health_port: None,
        ws_port: None,
    }
}

#[test]
fn parse_deposit_offer_valid() {
    let hex = hex_payload(b"sealed-bytes");
    let cmd = parse_command(
        format!("DEPOSIT_OFFER offer-abc 9999999999 {hex}").as_bytes(),
        None,
    );
    assert!(
        matches!(cmd, Command::DepositOffer { offer_id, expires_at, payload }
            if offer_id == "offer-abc" && expires_at == 9999999999 && payload == b"sealed-bytes"
        )
    );
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
        let admitted = test_admitted("anon", &oid);
        handle_fetch_offer(stream, &s, &oid, &admitted);
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
        let admitted = test_admitted("anon", &oid);
        handle_fetch_offer(stream, &s, &oid, &admitted);
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
        let admitted = test_admitted("anon", "offer-does-not-exist");
        handle_fetch_offer(stream, &state, "offer-does-not-exist", &admitted);
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
        handle_deposit_offer(
            stream,
            &s,
            &c,
            "offer-dup".to_string(),
            far_future,
            b"payload".to_vec(),
            "test-peer",
        );
    });
    assert!(read_response(&buf).starts_with("OK deposited"));

    // Second deposit with same ID is rejected.
    let c = Arc::clone(&cfg);
    let buf = with_loopback(move |stream| {
        handle_deposit_offer(
            stream,
            &state,
            &c,
            "offer-dup".to_string(),
            far_future,
            b"payload".to_vec(),
            "test-peer",
        );
    });
    let resp = read_response(&buf);
    assert!(
        resp.starts_with("REJECTED offer already exists"),
        "got: {resp}"
    );
}

#[test]
fn deposit_already_expired_offer_is_rejected() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let past = now_epoch_secs().saturating_sub(1);

    let cfg = Arc::new(test_offer_config());
    let buf = with_loopback(move |stream| {
        handle_deposit_offer(
            stream,
            &state,
            &cfg,
            "offer-expired".to_string(),
            past,
            b"payload".to_vec(),
            "test-peer",
        );
    });
    let resp = read_response(&buf);
    assert!(
        resp.starts_with("REJECTED offer already expired"),
        "got: {resp}"
    );
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
        let admitted = test_admitted("anon", "offer-stale");
        handle_fetch_offer(stream, &s, "offer-stale", &admitted);
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
        StoredOffer {
            payload: vec![],
            expires_at: now.saturating_sub(1),
            claimed: false,
            source: "test".into(),
        },
    );
    state.offers.insert(
        "live".to_string(),
        StoredOffer {
            payload: vec![],
            expires_at: now + 3600,
            claimed: false,
            source: "test".into(),
        },
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
            StoredOffer {
                payload: b"blob".to_vec(),
                expires_at: far_future,
                claimed: false,
                source: "test".into(),
            },
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
            StoredOffer {
                payload: payload.clone(),
                expires_at: far_future,
                claimed: false,
                source: "test".into(),
            },
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
    assert!(
        state
            .lock()
            .unwrap()
            .offers
            .get("offer-atomic")
            .unwrap()
            .claimed
    );
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
            StoredOffer {
                payload: b"blob".to_vec(),
                expires_at: far_future,
                claimed: false,
                source: "test".into(),
            },
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
            StoredOffer {
                payload: b"secret".to_vec(),
                expires_at: far_future,
                claimed: false,
                source: "test".into(),
            },
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

    assert_eq!(
        winners, 1,
        "exactly one client should get the payload, got: {results:?}"
    );
    assert_eq!(
        losers, 1,
        "exactly one client should be rejected, got: {results:?}"
    );
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
    assert!(
        resp.starts_with("REJECTED relay is shutting down"),
        "got: {resp}"
    );
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
        handle_deposit_offer(
            stream,
            &s,
            &c,
            "offer-1".into(),
            far_future,
            b"a".to_vec(),
            "peer-a",
        );
    });
    assert!(
        read_response(&buf).starts_with("OK deposited"),
        "first deposit should succeed"
    );

    // Second deposit from same source is rejected.
    let s = Arc::clone(&state);
    let c = Arc::clone(&cfg);
    let buf = with_loopback(move |stream| {
        handle_deposit_offer(
            stream,
            &s,
            &c,
            "offer-2".into(),
            far_future,
            b"b".to_vec(),
            "peer-a",
        );
    });
    let resp = read_response(&buf);
    assert!(
        resp.starts_with("REJECTED offer quota exceeded"),
        "got: {resp}"
    );

    // Different source succeeds.
    let c = Arc::clone(&cfg);
    let buf = with_loopback(move |stream| {
        handle_deposit_offer(
            stream,
            &state,
            &c,
            "offer-3".into(),
            far_future,
            b"c".to_vec(),
            "peer-b",
        );
    });
    assert!(
        read_response(&buf).starts_with("OK deposited"),
        "different peer should succeed"
    );
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
        handle_deposit_offer(
            stream,
            &s,
            &c,
            "offer-1".into(),
            far_future,
            vec![0u8; 8],
            "p",
        );
    });
    assert!(read_response(&buf).starts_with("OK deposited"));

    // Second deposit with 5 bytes exceeds the 10-byte limit.
    let c = Arc::clone(&cfg);
    let buf = with_loopback(move |stream| {
        handle_deposit_offer(
            stream,
            &state,
            &c,
            "offer-2".into(),
            far_future,
            vec![0u8; 5],
            "p",
        );
    });
    let resp = read_response(&buf);
    assert!(
        resp.starts_with("REJECTED offer store byte quota"),
        "got: {resp}"
    );
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
        handle_deposit_offer(
            stream,
            &s,
            &c,
            "offer-ttl".into(),
            far_future,
            b"x".to_vec(),
            "p",
        );
    });
    assert!(read_response(&buf).starts_with("OK deposited"));

    // The stored expires_at should be capped to now + 60.
    let s = state.lock().unwrap();
    let offer = s.offers.get("offer-ttl").unwrap();
    assert!(
        offer.expires_at <= now + 60 + 1,
        "TTL should be capped; got expires_at={}",
        offer.expires_at
    );
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
        handle_deposit_offer(
            stream,
            &state,
            &cfg,
            "offer-reuse".into(),
            far_future,
            b"new".to_vec(),
            "test",
        );
    });
    let resp = read_response(&buf);
    assert!(resp.starts_with("OK deposited offer-reuse"), "got: {resp}");
}

#[test]
fn health_endpoint_returns_ok_json() {
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    // Bind to port 0 to get an OS-assigned free port.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, None));
    // Give the server thread a moment to bind.
    thread::sleep(Duration::from_millis(50));

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    conn.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("\"status\":\"ok\""),
        "missing status field: {response}"
    );
    assert!(
        response.contains("\"mode\":\"open\""),
        "missing mode field: {response}"
    );
    assert!(
        response.contains("\"uptime_secs\":"),
        "missing uptime field: {response}"
    );
}

#[test]
fn health_endpoint_returns_404_for_unknown_path() {
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, None));
    thread::sleep(Duration::from_millis(50));

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    conn.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "expected 404, got: {response}"
    );
}

/// WebSocket: v0.3.0 release containment disables the listener by default.
#[test]
fn ws_listener_is_disabled_by_default() {
    assert_eq!(RelayConfig::from_args(&[]).unwrap().ws_port, None);
    assert_eq!(
        RelayConfig::from_args(&["--ws-port".into(), "9200".into()])
            .unwrap()
            .ws_port,
        None
    );
}

/// WebSocket: health endpoint includes ws_port when configured.
#[test]
fn health_endpoint_includes_ws_port() {
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, Some(9200)));
    thread::sleep(Duration::from_millis(50));

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    conn.write_all(b"GET /health HTTP/1.0\r\n\r\n").unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.contains("\"ws_port\":9200"),
        "missing ws_port: {response}"
    );
}

#[test]
fn auxiliary_bind_host_respects_main_bind_scope() {
    assert_eq!(auxiliary_bind_host("127.0.0.1:9100"), "127.0.0.1");
    assert_eq!(auxiliary_bind_host("0.0.0.0:9100"), "0.0.0.0");
    assert_eq!(auxiliary_bind_host("[::1]:9100"), "[::1]");
}

#[test]
fn dispatch_rejects_legacy_credential_commands_for_release_containment() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let config = test_offer_config();

    for payload in [
        b"DEPOSIT_CREDENTIAL grant-1 deadbeef".as_slice(),
        b"FETCH_CREDENTIAL grant-1".as_slice(),
    ] {
        let mut buf = Vec::new();
        dispatch_command(&mut buf, payload, &config, &state);
        let resp = read_response(&buf);
        assert!(
            resp.contains("disabled for v0.3.0 release containment"),
            "expected release containment rejection for {:?}, got: {resp}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn dispatch_rejects_legacy_grant_request_commands_for_release_containment() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let config = test_offer_config();

    // Use the current sealed-payload wire shapes so the dispatch refusal proves
    // the gate fires AFTER parse (containment, not parse-failure).
    let nonce_hex = hex::encode([0u8; RESPOND_GRANT_REQUEST_NONCE_BYTES]);
    let request_grant = format!(
        "REQUEST_GRANT human-alice ed25519:00 {sealed}",
        sealed = hex::encode(b"sealed-bytes"),
    );
    let respond = format!("RESPOND_GRANT_REQUEST gr-1 approved {nonce_hex} ed25519sig:cafe");
    let payloads: &[&[u8]] = &[
        request_grant.as_bytes(),
        b"FETCH_GRANT_REQUESTS human-alice".as_slice(),
        respond.as_bytes(),
    ];

    for payload in payloads {
        let mut buf = Vec::new();
        dispatch_command(&mut buf, payload, &config, &state);
        let resp = read_response(&buf);
        assert!(
            resp.contains("disabled for v0.3.0 release containment"),
            "expected release containment rejection for {:?}, got: {resp}",
            String::from_utf8_lossy(payload)
        );
    }
}

// ── Grant request protocol tests ────────────────────────────────────────

#[test]
fn parse_request_grant_valid() {
    let pubkey_hex = "ed25519:00112233";
    let sealed_hex = hex::encode(b"sealed-bytes");
    let cmd = parse_command(
        format!("REQUEST_GRANT human-alice {pubkey_hex} {sealed_hex}").as_bytes(),
        None,
    );
    assert!(matches!(
        cmd,
        Command::RequestGrant { target_id, target_signing_pubkey, sealed_payload }
            if target_id == "human-alice"
                && target_signing_pubkey.0 == pubkey_hex
                && sealed_payload == b"sealed-bytes"
    ));
}

#[test]
fn parse_request_grant_missing_sealed_payload() {
    // Two fields → no sealed payload → falls through to Submission.
    let cmd = parse_command(b"REQUEST_GRANT human-alice ed25519:00", None);
    assert!(matches!(cmd, Command::Submission));
}

#[test]
fn parse_request_grant_rejects_bad_hex() {
    // Third positional must decode as hex.
    let cmd = parse_command(b"REQUEST_GRANT human-alice ed25519:00 notvalidhex!", None);
    assert!(matches!(cmd, Command::Submission));
}

#[test]
fn parse_fetch_grant_requests_valid() {
    let cmd = parse_command(b"FETCH_GRANT_REQUESTS human-alice", None);
    assert!(matches!(cmd, Command::FetchGrantRequests(id) if id == "human-alice"));
}

#[test]
fn parse_respond_grant_request_approved() {
    let nonce_hex = hex::encode([0xAAu8; RESPOND_GRANT_REQUEST_NONCE_BYTES]);
    let sig_hex = "ed25519sig:deadbeef";
    let cmd = parse_command(
        format!("RESPOND_GRANT_REQUEST gr-0 approved {nonce_hex} {sig_hex}").as_bytes(),
        None,
    );
    assert!(
        matches!(cmd, Command::RespondGrantRequest { request_id, approved, .. }
        if request_id == "gr-0" && approved)
    );
}

#[test]
fn parse_respond_grant_request_denied() {
    let nonce_hex = hex::encode([0xBBu8; RESPOND_GRANT_REQUEST_NONCE_BYTES]);
    let sig_hex = "ed25519sig:deadbeef";
    let cmd = parse_command(
        format!("RESPOND_GRANT_REQUEST gr-0 denied {nonce_hex} {sig_hex}").as_bytes(),
        None,
    );
    assert!(
        matches!(cmd, Command::RespondGrantRequest { request_id, approved, .. }
        if request_id == "gr-0" && !approved)
    );
}

#[test]
fn parse_respond_grant_request_invalid_verdict() {
    let nonce_hex = hex::encode([0xCCu8; RESPOND_GRANT_REQUEST_NONCE_BYTES]);
    let cmd = parse_command(
        format!("RESPOND_GRANT_REQUEST gr-0 maybe {nonce_hex} ed25519sig:ab").as_bytes(),
        None,
    );
    assert!(matches!(cmd, Command::Submission));
}

#[test]
fn parse_respond_grant_request_rejects_short_nonce() {
    // Nonce must be exactly RESPOND_GRANT_REQUEST_NONCE_BYTES * 2 hex chars.
    let cmd = parse_command(
        b"RESPOND_GRANT_REQUEST gr-0 approved aabb ed25519sig:cd",
        None,
    );
    assert!(matches!(cmd, Command::Submission));
}

#[test]
fn parse_respond_grant_request_rejects_missing_signature() {
    let nonce_hex = hex::encode([0xDDu8; RESPOND_GRANT_REQUEST_NONCE_BYTES]);
    let cmd = parse_command(
        format!("RESPOND_GRANT_REQUEST gr-0 approved {nonce_hex}").as_bytes(),
        None,
    );
    assert!(matches!(cmd, Command::Submission));
}

/// Build a fresh responder fixture + the bound pubkey we pass to
/// `handle_request_grant` so the matching `RESPOND_GRANT_REQUEST`
/// signature verifies under `Ed25519Verifier`.
fn responder_fixture(label: &str) -> (FixtureSigner, PublicKey) {
    let signer = FixtureSigner::new(label);
    let pubkey = signer.public_key();
    (signer, pubkey)
}

/// Sign a `RESPOND_GRANT_REQUEST` payload using a `FixtureSigner` and
/// return `(nonce_hex, signature)` ready to feed into
/// `handle_respond_grant_request`. The nonce is deterministic per call
/// in tests so a re-run picks the same value, but each helper invocation
/// generates a distinct nonce so replay tests stay meaningful.
fn signed_respond_frame(
    signer: &FixtureSigner,
    request_id: &str,
    approved: bool,
    nonce: [u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
) -> (String, Signature) {
    let payload = respond_grant_request_signing_payload(request_id, approved, &nonce);
    let signature = signer.sign(&payload);
    (hex::encode(nonce), signature)
}

#[test]
fn grant_request_deposit_fetch_lifecycle() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (_, pubkey) = responder_fixture("relay-responder-fetch-lifecycle");

    // Deposit a grant request. The relay never sees plaintext payload.
    let sealed = b"sealed:requester=agent-bot;scope=netflix;justification=streaming".to_vec();
    let s = Arc::clone(&state);
    let pk = pubkey.clone();
    let sealed_clone = sealed.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "human-alice".into(), pk, sealed_clone);
    });
    let resp = read_response(&buf);
    assert!(resp.starts_with("OK gr-"), "got: {resp}");

    // Fetch grant requests for alice — the response carries only the
    // routing-cleartext fields and the opaque sealed payload as hex.
    let s = Arc::clone(&state);
    let buf = with_loopback(move |stream| {
        handle_fetch_grant_requests(stream, &s, "human-alice");
    });
    let resp = read_response(&buf);
    assert!(resp.contains("\"request_id\":\"gr-"), "got: {resp}");
    assert!(
        resp.contains(&format!("\"sealed_payload\":\"{}\"", hex::encode(&sealed))),
        "got: {resp}"
    );
    // Plaintext fields MUST NOT appear (sealed off-relay).
    assert!(!resp.contains("\"requester_id\""), "got: {resp}");
    assert!(!resp.contains("\"justification\""), "got: {resp}");
    assert!(!resp.contains("\"scope\""), "got: {resp}");
    assert!(resp.contains("\"status\":\"pending\""), "got: {resp}");
    assert!(resp.ends_with("\nEND"), "got: {resp}");
}

#[test]
fn grant_request_respond_approved_with_valid_signature() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (signer, pubkey) = responder_fixture("relay-responder-respond-approved");

    // Deposit a request.
    let s = Arc::clone(&state);
    let pk = pubkey.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(
            stream,
            &s,
            "human-alice".into(),
            pk,
            b"sealed:requester=agent-bot;scope=ssh-key".to_vec(),
        );
    });
    let resp = read_response(&buf);
    let request_id = resp.strip_prefix("OK ").unwrap().to_string();
    assert!(request_id.starts_with("gr-"), "got: {resp}");

    // Approve it with a fresh signed nonce.
    let (nonce_hex, signature) = signed_respond_frame(
        &signer,
        &request_id,
        true,
        [0xA1u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );
    let rid = request_id.clone();
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let s = Arc::clone(&state);
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, &rid, true, &nh, &sig);
    });
    let resp = read_response(&buf);
    assert_eq!(resp, "OK", "got: {resp}");

    // Fetch and verify status changed.
    let s = Arc::clone(&state);
    let buf = with_loopback(move |stream| {
        handle_fetch_grant_requests(stream, &s, "human-alice");
    });
    let resp = read_response(&buf);
    assert!(resp.contains("\"status\":\"approved\""), "got: {resp}");
}

/// Signed-response acceptance #2: a captured `RESPOND_GRANT_REQUEST` frame
/// MUST NOT verify when replayed. The relay tombstones the nonce so the
/// second frame is refused with `REJECTED nonce replay`.
#[test]
fn grant_request_respond_rejects_nonce_replay() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (signer, pubkey) = responder_fixture("relay-responder-replay");

    // Deposit two requests so replay surface is non-trivial.
    let s = Arc::clone(&state);
    let pk = pubkey.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "human-alice".into(), pk, b"sealed-1".to_vec());
    });
    let request_id = read_response(&buf).strip_prefix("OK ").unwrap().to_string();

    let (nonce_hex, signature) = signed_respond_frame(
        &signer,
        &request_id,
        true,
        [0xB2u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );

    // First call verifies.
    let s = Arc::clone(&state);
    let rid = request_id.clone();
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, &rid, true, &nh, &sig);
    });
    assert_eq!(read_response(&buf), "OK");

    // Replay the same nonce against a different request id (or even the
    // same one) — refused before the signature check runs.
    let s = Arc::clone(&state);
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, "gr-fakeid", true, &nh, &sig);
    });
    assert_eq!(read_response(&buf), "REJECTED nonce replay");
}

/// Signed-response acceptance #2: a tampered nonce flips the signed payload
/// so the signature stops verifying. Refused with
/// `REJECTED signature verification failed` and the grant request stays
/// `Pending`.
#[test]
fn grant_request_respond_rejects_tampered_nonce() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (signer, pubkey) = responder_fixture("relay-responder-tampered");

    let s = Arc::clone(&state);
    let pk = pubkey.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "human-alice".into(), pk, b"sealed-2".to_vec());
    });
    let request_id = read_response(&buf).strip_prefix("OK ").unwrap().to_string();

    let (good_nonce, signature) = signed_respond_frame(
        &signer,
        &request_id,
        true,
        [0xC3u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );
    // Tamper a single byte in the nonce — keep length valid hex so the
    // shape passes parser-level checks.
    let mut tampered = good_nonce.clone().into_bytes();
    tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
    let tampered_nonce = String::from_utf8(tampered).unwrap();

    let s = Arc::clone(&state);
    let rid = request_id.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, &rid, true, &tampered_nonce, &sig);
    });
    assert_eq!(
        read_response(&buf),
        "REJECTED signature verification failed"
    );

    // Verdict didn't move.
    let s = Arc::clone(&state);
    let buf = with_loopback(move |stream| {
        handle_fetch_grant_requests(stream, &s, "human-alice");
    });
    let resp = read_response(&buf);
    assert!(resp.contains("\"status\":\"pending\""), "got: {resp}");
}

/// Signed-response acceptance #2: flipping the verdict byte (signed for
/// `denied`, replayed as `approved`) must fail the signature check.
/// Defends against the canonical "captured deny → reuse as approve"
/// authority-bearing attack.
#[test]
fn grant_request_respond_rejects_verdict_flip() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (signer, pubkey) = responder_fixture("relay-responder-verdict-flip");

    let s = Arc::clone(&state);
    let pk = pubkey.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "human-alice".into(), pk, b"sealed-3".to_vec());
    });
    let request_id = read_response(&buf).strip_prefix("OK ").unwrap().to_string();

    // Sign for `denied`, replay as `approved`.
    let (nonce_hex, signature) = signed_respond_frame(
        &signer,
        &request_id,
        false,
        [0xD4u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );

    let s = Arc::clone(&state);
    let rid = request_id.clone();
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        // approved=true here, but the signature was made over approved=false.
        handle_respond_grant_request(stream, &s, &rid, true, &nh, &sig);
    });
    assert_eq!(
        read_response(&buf),
        "REJECTED signature verification failed"
    );
}

/// Signed-response acceptance #2: a signature produced by a different key
/// (the wrong responder, or a forged claimant) does not verify against
/// the bound pubkey. The relay refuses without mutating state.
#[test]
fn grant_request_respond_rejects_wrong_signer() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (_, bound_pubkey) = responder_fixture("relay-responder-bound");
    let (other_signer, _) = responder_fixture("relay-responder-impostor");

    let s = Arc::clone(&state);
    let pk = bound_pubkey.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "human-alice".into(), pk, b"sealed-4".to_vec());
    });
    let request_id = read_response(&buf).strip_prefix("OK ").unwrap().to_string();

    // Impostor signs the correctly-formatted payload.
    let (nonce_hex, signature) = signed_respond_frame(
        &other_signer,
        &request_id,
        true,
        [0xE5u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );

    let s = Arc::clone(&state);
    let rid = request_id.clone();
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, &rid, true, &nh, &sig);
    });
    assert_eq!(
        read_response(&buf),
        "REJECTED signature verification failed"
    );
}

#[test]
fn grant_request_fetch_unknown_target_returns_none() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let s = Arc::clone(&state);
    let buf = with_loopback(move |stream| {
        handle_fetch_grant_requests(stream, &s, "nobody");
    });
    let resp = read_response(&buf);
    assert_eq!(resp, "NONE", "got: {resp}");
}

#[test]
fn grant_request_respond_unknown_returns_not_found() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (signer, _) = responder_fixture("relay-responder-not-found");
    let (nonce_hex, signature) = signed_respond_frame(
        &signer,
        "gr-999",
        true,
        [0xF6u8; RESPOND_GRANT_REQUEST_NONCE_BYTES],
    );

    let s = Arc::clone(&state);
    let nh = nonce_hex.clone();
    let sig = signature.clone();
    let buf = with_loopback(move |stream| {
        handle_respond_grant_request(stream, &s, "gr-999", true, &nh, &sig);
    });
    let resp = read_response(&buf);
    assert_eq!(resp, "NOT_FOUND", "got: {resp}");
}

#[test]
fn grant_request_ids_are_unique() {
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (_, pubkey_a) = responder_fixture("relay-responder-uniq-a");
    let (_, pubkey_b) = responder_fixture("relay-responder-uniq-b");

    // Deposit two requests.
    let s = Arc::clone(&state);
    let pk = pubkey_a.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "alice".into(), pk, b"sealed-a".to_vec());
    });
    let resp1 = read_response(&buf);

    let s = Arc::clone(&state);
    let pk = pubkey_b.clone();
    let buf = with_loopback(move |stream| {
        handle_request_grant(stream, &s, "bob".into(), pk, b"sealed-b".to_vec());
    });
    let resp2 = read_response(&buf);

    assert_ne!(
        resp1, resp2,
        "request IDs should differ: {resp1} vs {resp2}"
    );
    assert!(resp1.starts_with("OK gr-"), "got: {resp1}");
    assert!(resp2.starts_with("OK gr-"), "got: {resp2}");
}

// ── ADR 146 §2.b DID resolver — JWKS endpoint integration tests ─────────────
//
// Anchor: `did_emberlink_resolver_phase2` — ADR-141-PHASE2-RELAY-RESOLVER-IMPL.
// These tests exercise the JWKS handler installed in `run_health_server`,
// covering the success path (200 + `application/jwk-set+json` body with the
// expected OKP shape), the invalid-DID path (400), and the no-`did` path
// (404). The body matches the round-trip pattern in
// `core_crypto::did::tests::parse_did_then_resolve_jwks_round_trip`.

#[test]
fn jwks_endpoint_returns_okp_jwks_for_valid_did() {
    use core_crypto::{did_from_root_pubkey, parse_did, resolve_did_jwks};
    use ed25519_dalek::SigningKey;
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, None));
    thread::sleep(Duration::from_millis(50));

    // Build a fresh Ed25519 key and the corresponding DID identifier.
    let signing = SigningKey::from_bytes(&[0x11u8; 32]);
    let did = did_from_root_pubkey(&signing.verifying_key());
    let did_str = did.as_str();

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    conn.write_all(
        format!("GET /.well-known/jwks.json?did={did_str} HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected 200, got: {response}"
    );
    assert!(
        response.contains("Content-Type: application/jwk-set+json"),
        "missing jwk-set content type: {response}"
    );

    // The body should serialize-equal to the resolver's JSON. Cross-check
    // via `parse_did → resolve_did_jwks` so the test fails if the relay
    // ever drifts off the core-crypto contract.
    let body_start = response.find("\r\n\r\n").unwrap() + 4;
    let body = &response[body_start..];
    let parsed: serde_json::Value = serde_json::from_str(body).expect("body must be JSON");
    let expected = resolve_did_jwks(&parse_did(&did_str).unwrap());
    assert_eq!(parsed, expected, "relay JWKS must equal core-crypto JWKS");

    // The decoded `x` field must equal the original key bytes — the
    // EIC-pod-auth-via-DID-OIDC-federation scenario depends on this.
    let x = parsed["keys"][0]["x"].as_str().unwrap();
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        x.as_bytes(),
    )
    .unwrap();
    assert_eq!(decoded.as_slice(), &signing.verifying_key().to_bytes()[..]);
}

#[test]
fn jwks_endpoint_returns_400_for_invalid_did() {
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, None));
    thread::sleep(Duration::from_millis(50));

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    // Wrong DID method — should be rejected by `parse_did` with
    // `DidError::MissingPrefix`, surfacing as a 400.
    conn.write_all(b"GET /.well-known/jwks.json?did=did:web:example.com HTTP/1.0\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 400"),
        "expected 400, got: {response}"
    );
    assert!(
        response.contains(r#""error":"invalid_did""#),
        "missing error tag: {response}"
    );
}

#[test]
fn jwks_endpoint_returns_404_when_did_query_missing() {
    use std::io::Read as IoRead;
    use std::io::Write as IoWrite;
    use std::net::{TcpListener, TcpStream};

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let start = Instant::now();
    thread::spawn(move || run_health_server(port, RelayMode::Open, start, None));
    thread::sleep(Duration::from_millis(50));

    let mut conn = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    // Path matches but no `did` query — parse_jwks_request returns None,
    // so the handler falls through to the 404 branch (the JWKS path is
    // an extension of the catch-all, not a standalone endpoint).
    conn.write_all(b"GET /.well-known/jwks.json HTTP/1.0\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    conn.read_to_string(&mut response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "expected 404, got: {response}"
    );
}
