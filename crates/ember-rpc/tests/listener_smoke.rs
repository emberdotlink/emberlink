//! ember_rpc_phase_c_mtls_listener_wired — T2 smoke tests.
//!
//! Mirrors `crates/ember-daemon/src/infra/kms_edge.rs::edge_listener_bind_smoke`
//! shape, extended to cover the three Phase C acceptance scenarios:
//!
//! 1. Bind + accept handshake with a CA-signed client cert succeeds.
//! 2. Handshake fails when the client cert is signed by a different CA.
//! 3. The policy gate routes a plaintext-bearing method to the canonical
//!    `policy-denied:` response, and a non-plaintext method to the
//!    Phase C `phase-c-stub` response.
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
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
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

fn mint_leaf_cert(ca: &TestCa, common_name: &str, is_server: bool, sans: Vec<String>) -> LeafPair {
    let mut params = CertificateParams::new(sans).expect("leaf params");
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

    let key_pair = KeyPair::generate().expect("leaf keypair");
    let cert = params
        .signed_by(&key_pair, &ca.cert_for_signing, &ca.key_pair)
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

// ---------------------------------------------------------------------------
// T2 smoke #1: bind + accept handshake with a CA-signed client cert.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_accepts_ca_signed_client_cert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, Vec::new());

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
    assert!(
        response.contains("phase-c-stub"),
        "expected allow-forward stub response, got: {response}"
    );
    // HIGH-2 fix verification: the stub MUST NOT echo the method name
    // back. A previous version returned `"method": "<req.method>"` in
    // the result object — a method-existence oracle and amplification
    // vector. Lock that fix down with a regression assertion.
    let parsed: serde_json::Value =
        serde_json::from_str(response.trim_end()).expect("response is valid JSON");
    assert!(
        parsed["result"]["method"].is_null(),
        "stub response must NOT echo the request method back (HIGH-2 fix); got {parsed}"
    );

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
    let client = mint_leaf_cert(&ca, "client", false, Vec::new());

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
    // PolicyDecision::AllowForward + the phase-c-stub. After the fix,
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
    let client = mint_leaf_cert(&ca, "client", false, Vec::new());

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
// T2 smoke #3: policy gate denies plaintext-bearing method.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listener_denies_plaintext_bearing_method() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = mint_test_ca("test-bridge-ca");
    let server = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client = mint_leaf_cert(&ca, "client", false, Vec::new());

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
