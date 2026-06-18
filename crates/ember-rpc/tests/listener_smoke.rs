//! ember_rpc_phase_c_mtls_listener_wired — T2 smoke tests.
//!
//! Mirrors `crates/ember-daemon/src/infra/kms_edge.rs::edge_listener_bind_smoke`
//! shape, extended to cover the three Phase C acceptance scenarios:
//!
//! 1. Bind + accept handshake with a CA-signed client cert succeeds.
//! 2. Handshake fails when the client cert is signed by a different CA.
//! 3. The policy gate routes a plaintext-bearing method to the canonical
//!    `policy-denied:` response, and a non-plaintext method through the
//!    forwarded UDS lane.
//!
//! All certs are minted in-test via `rcgen`; no PEM fixtures are
//! committed to the tree. The CA path mirrors `kms_edge`'s in-test
//! pattern (deterministic seed → CA → leaf certs).

#![allow(clippy::expect_used)] // test code — panicking on setup failure is the bug surface

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener};
use tokio_rustls::TlsConnector;

use ember_rpc::{Listener, ListenerConfig};

// ---------------------------------------------------------------------------
// Test CA + cert mint helpers (rcgen)
// ---------------------------------------------------------------------------

struct TestCa {
    cert_pem: String,
    key_pair: KeyPair,
    cert_for_signing: rcgen::Certificate,
}

fn mint_test_ca(common_name: &str) -> TestCa {
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate().expect("ca keypair");
    let cert_for_signing = params.self_signed(&key_pair).expect("self-signed CA");
    let cert_pem = cert_for_signing.pem();

    TestCa {
        cert_pem,
        key_pair,
        cert_for_signing,
    }
}

struct LeafPair {
    cert_pem: String,
    key_pem: String,
}

fn bridge_client_sans() -> Vec<String> {
    vec![
        "urn:emberlink:agent:clientpersona".into(),
        "spiffe://emberd/persona/clientpersona".into(),
        "spiffe://emberd/container/sess-test".into(),
    ]
}

fn mint_leaf_cert(ca: &TestCa, common_name: &str, is_server: bool, sans: Vec<String>) -> LeafPair {
    mint_leaf_cert_with_ttl(ca, common_name, is_server, sans, None)
}

/// Same as [`mint_leaf_cert`] but with an optional explicit cert TTL
/// (seconds from now). Used by M12 ADR 173 tests to drive short-TTL
/// not_after windows so the listener's force-close fires in test time.
fn mint_leaf_cert_with_ttl(
    ca: &TestCa,
    common_name: &str,
    is_server: bool,
    sans: Vec<String>,
    ttl_secs: Option<i64>,
) -> LeafPair {
    let mut params = if is_server {
        CertificateParams::new(sans.clone()).expect("server leaf params")
    } else {
        CertificateParams::new(Vec::new()).expect("client leaf params")
    };
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![if is_server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    if !is_server {
        params.subject_alt_names = sans
            .into_iter()
            .map(|uri| {
                SanType::URI(
                    uri.try_into()
                        .expect("client bridge SAN URI must be valid IA5"),
                )
            })
            .collect();
    }
    if let Some(ttl) = ttl_secs {
        use time::OffsetDateTime;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_secs() as i64;
        params.not_before = OffsetDateTime::from_unix_timestamp(now - 5).expect("not_before");
        params.not_after = OffsetDateTime::from_unix_timestamp(now + ttl).expect("not_after");
    }

    let key_pair = KeyPair::generate().expect("leaf keypair");
    let issuer = rcgen::Issuer::from_ca_cert_pem(ca.cert_for_signing.pem().as_str(), &ca.key_pair)
        .expect("CA issuer");
    let cert = params
        .signed_by(&key_pair, &issuer)
        .expect("CA-signed leaf");
    LeafPair {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn write_temp_pems(
    dir: &tempfile::TempDir,
    ca: &TestCa,
    server: &LeafPair,
) -> (PathBuf, PathBuf, PathBuf) {
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write ca pem");
    std::fs::write(&cert_path, &server.cert_pem).expect("write server cert");
    std::fs::write(&key_path, &server.key_pem).expect("write server key");
    (ca_path, cert_path, key_path)
}

async fn ephemeral_listen_addr() -> SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe local_addr");
    drop(probe);
    addr
}

// ---------------------------------------------------------------------------
// Client-side TLS helper — connect to the listener using the given identity.
// ---------------------------------------------------------------------------

fn build_client_tls(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Arc<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    let mut ca_cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for ca in rustls_pemfile::certs(&mut ca_cursor) {
        let ca = ca.expect("ca cert pem");
        roots.add(ca).expect("add ca");
    }

    let mut cert_cursor = std::io::Cursor::new(client_cert_pem.as_bytes());
    let client_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .map(|c| c.expect("client cert pem"))
        .collect();

    let mut key_cursor = std::io::Cursor::new(client_key_pem.as_bytes());
    let client_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .expect("read client key")
        .expect("client key present");

    // rcgen serializes PKCS#8; rustls-pemfile returns PrivateKeyDer.
    // Both paths handle the wrapping.
    let key_for_config: PrivateKeyDer<'static> = match client_key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
        }
        other => other,
    };

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, key_for_config)
        .expect("client mTLS config");
    Arc::new(config)
}

async fn round_trip(
    addr: SocketAddr,
    client_config: Arc<ClientConfig>,
    request_line: &str,
) -> std::io::Result<String> {
    let connector = TlsConnector::from(client_config);
    let stream = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector.connect(server_name, stream).await?;

    tls_stream.write_all(request_line.as_bytes()).await?;
    tls_stream.write_all(b"\n").await?;
    tls_stream.flush().await?;

    let mut reader = BufReader::new(tls_stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

async fn spawn_forward_uds_echo(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind forward uds");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept forward uds");
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        // ADR 155 priv-sep (SLICE 2a) — the sibling now forwards a hand-rolled
        // TYPED FRAME (not bare JSON with a `_mtls_principal` field). It writes
        // the frame then half-closes its write half, so read-to-EOF yields the
        // whole frame.
        let mut frame_bytes = Vec::new();
        read_half
            .read_to_end(&mut frame_bytes)
            .await
            .expect("read forward frame");
        let decoded = ember_rpc::frame::decode(&frame_bytes).expect("decode bridge frame");
        // The cert-derived principal rides OUT-OF-BAND in the frame header.
        assert_eq!(decoded.persona_id, "clientpersona");
        assert_eq!(decoded.container_id, "sess-test");
        assert_eq!(decoded.cert_fingerprint.len(), 32);
        // The inner payload is the opaque JSON-RPC request — and carries NO
        // `_mtls_principal` field (the forgeable injection is gone).
        let request: serde_json::Value =
            serde_json::from_slice(&decoded.payload).expect("inner json-rpc payload");
        assert_eq!(
            request.get("method").and_then(serde_json::Value::as_str),
            Some("vault_status")
        );
        assert!(
            request["params"].get("_mtls_principal").is_none(),
            "inner payload must NOT carry a _mtls_principal field"
        );
        let mut response = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "forwarded": true,
                "lane": "uds"
            },
            "id": request.get("id").cloned().unwrap_or(serde_json::Value::Null),
        }))
        .expect("forward response json");
        response.push('\n');
        write_half
            .write_all(response.as_bytes())
            .await
            .expect("write forward response");
    })
}

// ---------------------------------------------------------------------------
// T2 smoke #1: bind + accept handshake with a CA-signed client cert.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_accepts_ca_signed_client_cert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, bridge_client_sans());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let forward_uds = dir.path().join("forward.sock");
    let forward_handle = spawn_forward_uds_echo(&forward_uds).await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds,
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    // Give the accept loop a moment to install the listener.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);
    let response = round_trip(
        listen_addr,
        client_tls,
        r#"{"jsonrpc":"2.0","method":"vault_status","params":{},"id":1}"#,
    )
    .await
    .expect("round-trip");
    let parsed: serde_json::Value =
        serde_json::from_str(response.trim_end()).expect("response is valid JSON");
    assert!(
        parsed["result"]["forwarded"].as_bool() == Some(true),
        "expected forwarded UDS response, got {parsed}"
    );

    forward_handle.abort();
    handle.abort();
}

// ---------------------------------------------------------------------------
// T2 smoke #4: non-canonical method name rejected (HIGH-1 fix).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_rejects_non_canonical_method_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, bridge_client_sans());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-phase-c"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);

    // Case-twiddled variant of vault_unseal. Before the HIGH-1 fix this
    // would slip past the gate (which uses byte-equality) and reach
    // PolicyDecision::AllowForward and the forward path. After the fix,
    // it's rejected at the canonical-shape check with -32600.
    let response = round_trip(
        listen_addr,
        client_tls,
        r#"{"jsonrpc":"2.0","method":"Vault_Unseal","params":{},"id":1}"#,
    )
    .await
    .expect("round-trip");
    let parsed: serde_json::Value =
        serde_json::from_str(response.trim_end()).expect("response is valid JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32600),
        "non-canonical method must be rejected with -32600 (HIGH-1 fix); got {parsed}"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// T2 smoke #5: oversized frame caps out at MAX_FRAME_BYTES (CRIT-1 fix).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_caps_oversized_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, bridge_client_sans());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-phase-c"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);

    // Construct a frame larger than MAX_FRAME_BYTES (1 MiB) — `params`
    // padded with a 2 MiB string. The server should refuse to read
    // beyond the cap; with the listener's `take(MAX_FRAME_BYTES)`
    // wrapper this will produce a truncated, invalid JSON-RPC frame.
    // Listener responds with parse-error and closes; we just need to
    // assert the listener didn't OOM-balloon trying to read it all.
    let huge_padding = "x".repeat(2 * 1024 * 1024);
    let huge_frame = format!(
        r#"{{"jsonrpc":"2.0","method":"vault_status","params":{{"pad":"{}"}},"id":1}}"#,
        huge_padding
    );

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        round_trip(listen_addr, client_tls, &huge_frame),
    )
    .await
    .expect("test should not hang");

    // Either the listener returned a parse-error response (truncated
    // frame failed to parse) or it closed the connection mid-write
    // (because the cap was hit). Both are acceptable outcomes — the
    // CRIT-1 invariant is that the server didn't accept the full 2 MiB.
    match result {
        Ok(response) => {
            let parsed: serde_json::Value =
                serde_json::from_str(response.trim_end()).expect("response is valid JSON");
            assert!(
                parsed["error"].is_object(),
                "oversized frame must produce an error response; got {parsed}"
            );
        }
        Err(_) => {
            // Connection closed mid-write — also a valid CRIT-1
            // defense. The test passes; we just couldn't read a
            // response because the listener tore the connection down.
        }
    }

    handle.abort();
}

// ---------------------------------------------------------------------------
// T2 smoke #2: handshake fails when client cert is signed by a different CA.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_rejects_handshake_with_wrong_ca_signed_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server_ca = mint_test_ca("server-bridge-ca");
    let attacker_ca = mint_test_ca("attacker-bridge-ca");

    let server = mint_leaf_cert(&server_ca, "server", true, vec!["localhost".into()]);
    let attacker_client = mint_leaf_cert(&attacker_ca, "client", false, Vec::new());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &server_ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-phase-c"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client trusts the server's CA so the server cert validates; client
    // presents a cert signed by a DIFFERENT CA so the server-side
    // WebPkiClientVerifier MUST refuse it.
    let client_tls = build_client_tls(
        &server_ca.cert_pem,
        &attacker_client.cert_pem,
        &attacker_client.key_pem,
    );

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        round_trip(
            listen_addr,
            client_tls,
            r#"{"jsonrpc":"2.0","method":"vault_status","params":{},"id":1}"#,
        ),
    )
    .await
    .expect("test should not hang");

    assert!(
        result.is_err(),
        "expected TLS handshake or read to fail when client cert is not CA-signed; got {result:?}"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// T2 smoke #2b: live listener reloads rotated CA/server materials.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_reloads_tls_materials_between_connections() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca_a = mint_test_ca("bridge-ca-a");
    let ca_b = mint_test_ca("bridge-ca-b");

    let server_a = mint_leaf_cert(&ca_a, "server-a", true, vec!["localhost".into()]);
    let server_b = mint_leaf_cert(&ca_b, "server-b", true, vec!["localhost".into()]);
    let client_a = mint_leaf_cert(&ca_a, "client-a", false, bridge_client_sans());
    let client_b = mint_leaf_cert(&ca_b, "client-b", false, bridge_client_sans());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca_a, &server_a);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-phase-c"),
        server_cert_path: server_cert_path.clone(),
        server_key_path: server_key_path.clone(),
        ca_cert_path: ca_path.clone(),
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls_a = build_client_tls(&ca_a.cert_pem, &client_a.cert_pem, &client_a.key_pem);
    let response_a = round_trip(
        listen_addr,
        client_tls_a,
        r#"{"jsonrpc":"2.0","method":"vault_unseal","params":{},"id":1}"#,
    )
    .await
    .expect("round-trip before rotation");
    let parsed_a: serde_json::Value =
        serde_json::from_str(response_a.trim_end()).expect("response is valid JSON");
    assert_eq!(parsed_a["error"]["code"].as_i64(), Some(-32601));

    std::fs::write(&ca_path, &ca_b.cert_pem).expect("rotate ca pem");
    std::fs::write(&server_cert_path, &server_b.cert_pem).expect("rotate server cert");
    std::fs::write(&server_key_path, &server_b.key_pem).expect("rotate server key");

    let client_tls_b = build_client_tls(&ca_b.cert_pem, &client_b.cert_pem, &client_b.key_pem);
    let response_b = round_trip(
        listen_addr,
        client_tls_b,
        r#"{"jsonrpc":"2.0","method":"vault_unseal","params":{},"id":2}"#,
    )
    .await
    .expect("round-trip after rotation without listener restart");
    let parsed_b: serde_json::Value =
        serde_json::from_str(response_b.trim_end()).expect("response is valid JSON");
    assert_eq!(
        parsed_b["error"]["code"].as_i64(),
        Some(-32601),
        "listener must reload CA/server cert/key for the next connection; got {parsed_b}"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// T2 smoke #3: policy gate denies plaintext-bearing method.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_denies_plaintext_bearing_method() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, bridge_client_sans());

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-phase-c"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);
    let response = round_trip(
        listen_addr,
        client_tls,
        // `vault_unseal` is on PLAINTEXT_BEARING_METHODS — gate MUST refuse.
        r#"{"jsonrpc":"2.0","method":"vault_unseal","params":{},"id":42}"#,
    )
    .await
    .expect("round-trip");

    let parsed: serde_json::Value =
        serde_json::from_str(response.trim_end()).expect("response is valid JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32601),
        "policy-denied error code; got {parsed}"
    );
    let msg = parsed["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.starts_with("policy-denied:"),
        "message must start with policy-denied: prefix; got {msg}"
    );
    assert!(
        msg.contains("vault_unseal"),
        "message should name the offending method; got {msg}"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// T3 smoke #6: M12 of ADR 173 — short-TTL connection is force-closed at
// `not_after` with a typed `connection-expired:` JSON-RPC error envelope.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_force_closes_short_ttl_connection_at_not_after() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    // 3-second client cert TTL — listener must force-close at the deadline.
    let client = mint_leaf_cert_with_ttl(&ca, "client", false, bridge_client_sans(), Some(3));

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        // No forward UDS will be touched — the client opens the connection
        // and then deliberately never writes a frame, so the listener stays
        // blocked on the bounded `read_until` until the deadline fires.
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-m12-test"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);

    // Open the TLS connection but DO NOT send a frame. The listener's
    // post-handshake `read_until(b'\n')` will block on the bounded reader
    // until either FRAME_READ_TIMEOUT (10s) or the cert deadline (3s).
    // With M12 the deadline wins and the listener writes a typed
    // `connection-expired:` envelope before closing.
    let connector = TlsConnector::from(client_tls);
    let stream = TcpStream::connect(listen_addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");

    // Wait up to 8s for the deadline-driven force-close response.
    let mut reader = BufReader::new(tls_stream);
    let mut line = String::new();
    let read_result = tokio::time::timeout(Duration::from_secs(8), reader.read_line(&mut line))
        .await
        .expect("test must not hang past the deadline");
    let _bytes = read_result.expect("listener writes ConnectionExpired before EOF");

    let parsed: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("ConnectionExpired is valid JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32099),
        "M12 ADR 173: force-close MUST emit -32099 ConnectionExpired; got {parsed}"
    );
    let msg = parsed["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.starts_with("connection-expired:"),
        "M12: message must start with canonical 'connection-expired:' prefix; got {msg}"
    );
    assert!(
        parsed["id"].is_null(),
        "M12: ConnectionExpired id is always null (deadline can fire pre-parse); got {}",
        parsed["id"]
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// T3 smoke #7: M12 negative — a client that refuses to refresh (we model
// this as "just hold the same short-TTL cert open past `not_after`") gets
// force-closed; no further authentication is possible on the same conn.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_refusing_client_gets_force_closed_no_further_authentication() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert_with_ttl(&ca, "client", false, bridge_client_sans(), Some(2));

    let (ca_path, server_cert_path, server_key_path) = write_temp_pems(&dir, &ca, &server);

    let listen_addr = ephemeral_listen_addr().await;
    let config = ListenerConfig {
        listen_addr,
        forward_uds: PathBuf::from("/dev/null-forward-not-used-in-m12-test"),
        server_cert_path,
        server_key_path,
        ca_cert_path: ca_path,
    };

    let handle = Listener::spawn(config).await.expect("listener spawn");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_tls = build_client_tls(&ca.cert_pem, &client.cert_pem, &client.key_pem);

    let connector = TlsConnector::from(client_tls);
    let stream = TcpStream::connect(listen_addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");

    // Wait past the cert's not_after — listener force-closes (M12).
    tokio::time::sleep(Duration::from_secs(3)).await;

    // After force-close, the connection is dead. Any subsequent write
    // either succeeds into a dead socket (peer-RST may not arrive
    // synchronously) but the subsequent read MUST return either the
    // queued ConnectionExpired envelope or EOF — and CANNOT return a
    // fresh successfully-authenticated response. We assert read returns
    // the ConnectionExpired envelope (queued at force-close) or EOF, not
    // any other response.
    let _ = tls_stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"vault_status\",\"params\":{},\"id\":1}\n")
        .await;

    let mut reader = BufReader::new(tls_stream);
    let mut line = String::new();
    let read_result = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("test must not hang");

    match read_result {
        Ok(0) => {
            // EOF — connection torn down, no further authentication
            // possible. Acceptable terminal state for the negative test.
        }
        Ok(_) => {
            let parsed: serde_json::Value =
                serde_json::from_str(line.trim_end()).expect("response is valid JSON");
            // Whatever envelope the client reads back, it MUST NOT be a
            // success path that re-uses the expired cert's authentication.
            // The only legitimate response shape here is the queued
            // ConnectionExpired envelope from the force-close write.
            let code = parsed["error"]["code"].as_i64();
            assert_eq!(
                code,
                Some(-32099),
                "M12 negative: a refusing client MUST NOT see authenticated success after force-close; got {parsed}"
            );
        }
        Err(e) => {
            // TLS error (likely a clean shutdown / RST after force-close).
            // Also a valid terminal state — no further authentication.
            let _ = e;
        }
    }

    handle.abort();
}
