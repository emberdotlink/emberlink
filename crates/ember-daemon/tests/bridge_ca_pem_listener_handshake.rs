//! CLASSIFICATION: PUBLIC
//!
//! META-AP-DAEMON-BRIDGE-CA-PEM-PUBLISH-FORMAT — T3 integration coverage
//! for the bridge-CA publish-format reconciliation (Option A: emberd
//! publishes both raw `bridge_ca.pub` and PEM `bridge_ca.pem`).
//!
//! Anchor: `bridge_ca_pem_publish_format_reconciled`.
//!
//! ## What this test pins
//!
//! emberd's `load_or_mint_bridge_ca` publishes a self-signed root cert at
//! `<data_dir>/bridge_ca.pem`. The OS-supervised `ember-rpc` sibling's
//! `crates/ember-rpc/src/listener.rs::load_certs` reads the same file off
//! the `EMBER_RPC_CA_CERT` env-pin and PEM-parses it to build a closed
//! `RootCertStore` for client-auth verification.
//!
//! Before this reconciliation the listener pointed at the raw 32-byte
//! `bridge_ca.pub` (ed25519 verifying-key bytes), and the TLS handshake
//! setup at `load_certs(ca_cert_path)` failed: `rustls_pemfile::certs`
//! returns zero certs on the raw bytes, so the listener errored with
//! `EmptyPem` at startup.
//!
//! This test wires the full stack — emberd-side mint → ember-rpc listener
//! load → real mTLS handshake with a client cert signed by the same
//! BridgeCa — so a future regression in the publish format (drop the
//! `.pem`, swap to a different encoding, change the path) lands here at
//! `cargo test` time instead of at sibling-boot time.
//!
//! ## Why under `ember-daemon/tests` and not `ember-rpc/tests`
//!
//! The smoke tests at `crates/ember-rpc/tests/listener_smoke.rs` mint
//! their own `rcgen` CA — they don't exercise emberd's published-PEM
//! path. The T3 contract here is "the PEM emberd publishes is what the
//! ember-rpc listener loads", which requires both crates in the test's
//! dep graph. `ember-daemon` already depends on `ember-rpc` (see
//! `Cargo.toml:121`), so this is the natural home.

#![allow(clippy::expect_used)] // test code — panicking on setup failure is the bug surface

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ember_daemon::infra::runtime::{load_or_mint_bridge_ca, mint_or_rotate_ember_rpc_server_cert};
use ember_daemon::infra::vault::Vault;
use ember_rpc::{Listener, ListenerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};
use tokio_rustls::TlsConnector;

/// Stable deterministic vault key. Matches the pattern in
/// `tests/bridge_ca_persistence.rs`.
const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

/// Bind an ephemeral 127.0.0.1 port, then drop the probe listener so the
/// real listener can claim the same port. Tiny race window, but every
/// listener_smoke test in `crates/ember-rpc/tests/` uses this pattern
/// without flake.
async fn ephemeral_listen_addr() -> SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().expect("probe local_addr");
    drop(probe);
    addr
}

/// Spawn a one-shot UDS echo on `path` that decodes the bridge frame +
/// returns a canned JSON-RPC `forwarded: true` response. Mirrors the
/// shape used in `crates/ember-rpc/tests/listener_smoke.rs::
/// spawn_forward_uds_echo` (one frame, half-close, write response).
async fn spawn_forward_uds_echo(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).expect("bind forward uds");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept forward uds");
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let mut frame_bytes = Vec::new();
        read_half
            .read_to_end(&mut frame_bytes)
            .await
            .expect("read forward frame");
        let decoded = ember_rpc::frame::decode(&frame_bytes).expect("decode bridge frame");
        let request: serde_json::Value =
            serde_json::from_slice(&decoded.payload).expect("inner json-rpc payload");
        let mut response = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "forwarded": true,
                "lane": "uds",
                "persona_id": decoded.persona_id,
                "container_id": decoded.container_id,
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

/// Build the rustls `ClientConfig` from emberd's PEM artifacts. The root
/// cert is read directly off `<data_dir>/bridge_ca.pem` — the same file
/// the ember-rpc listener loads — so this exercises the published-format
/// contract end-to-end.
fn build_client_tls(
    bridge_ca_pem_bytes: &[u8],
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Arc<ClientConfig> {
    // Idempotent: rustls returns Err if a provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    let mut ca_cursor = std::io::Cursor::new(bridge_ca_pem_bytes);
    for ca in rustls_pemfile::certs(&mut ca_cursor) {
        let ca = ca.expect("ca cert pem parses");
        roots.add(ca).expect("add ca to root store");
    }

    let mut cert_cursor = std::io::Cursor::new(client_cert_pem.as_bytes());
    let client_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .map(|c| c.expect("client cert pem"))
        .collect();
    assert!(
        !client_certs.is_empty(),
        "client cert pem must contain at least one cert"
    );

    let mut key_cursor = std::io::Cursor::new(client_key_pem.as_bytes());
    let client_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .expect("read client key")
        .expect("client key present");
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

/// Pre: empty `<data_dir>`.
/// Post: emberd's bridge-CA mint + the ember-rpc sibling cert mint produce
/// PEM artifacts the ember-rpc listener loads cleanly, and a real mTLS
/// handshake against the listener succeeds when the client cert is signed
/// by the same `BridgeCa`. A failure here means the published PEM-format
/// contract drifted between emberd and ember-rpc — exactly the regression
/// this T3 is here to catch.
#[tokio::test]
async fn emberd_published_pem_loads_into_ember_rpc_listener_and_handshake_green() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let vault = Vault::new(TEST_VAULT_KEY);

    // 1. emberd mints the bridge CA and publishes the public artifacts to
    //    `<data_dir>/bridge_ca.pub` + `<data_dir>/bridge_ca.pem`.
    let bridge_ca = load_or_mint_bridge_ca(data_dir, &vault).expect("load_or_mint_bridge_ca");

    let pem_path = data_dir.join("bridge_ca.pem");
    let pub_path = data_dir.join("bridge_ca.pub");
    assert!(pem_path.exists(), "bridge_ca.pem must exist after mint");
    assert!(
        pub_path.exists(),
        "bridge_ca.pub must still exist (raw + PEM dual-publish)"
    );

    let pem_bytes = std::fs::read(&pem_path).expect("read bridge_ca.pem");
    // PEM parses to exactly one cert through rustls_pemfile (the same
    // path the listener uses).
    {
        let mut cursor = std::io::Cursor::new(&pem_bytes);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<_, _>>()
            .expect("rustls_pemfile parses published PEM");
        assert_eq!(
            certs.len(),
            1,
            "exactly one cert in the published bridge_ca.pem"
        );
    }

    // 2. emberd mints the ember-rpc sibling's server cert pair under
    //    `<data_dir>/ember-rpc/server.{crt,key}`.
    mint_or_rotate_ember_rpc_server_cert(data_dir, None, &bridge_ca)
        .expect("mint_or_rotate_ember_rpc_server_cert");
    let server_cert_path = data_dir.join("ember-rpc").join("server.crt");
    let server_key_path = data_dir.join("ember-rpc").join("server.key");
    assert!(server_cert_path.exists(), "server.crt exists");
    assert!(server_key_path.exists(), "server.key exists");

    // 3. Mint a client cert signed by the SAME bridge_ca — the
    //    container-MCP path's identity shape.
    let (client_cert_pem, client_key_pem) = bridge_ca
        .sign_client_cert(
            "test-persona",
            Some("test-container"),
            Duration::from_secs(3600),
        )
        .expect("sign client cert");

    // 4. Wire the ember-rpc listener with `ca_cert_path` = the published
    //    `bridge_ca.pem`. This is the load-bearing assertion: if the
    //    listener cannot load the PEM emberd just wrote, Listener::spawn
    //    surfaces ListenerError::EmptyPem / ParsePem here.
    let listen_addr = ephemeral_listen_addr().await;
    let forward_uds = data_dir.join("rpc-forward.sock");
    let forward_handle = spawn_forward_uds_echo(&forward_uds).await;

    let config = ListenerConfig {
        listen_addr,
        forward_uds: forward_uds.clone(),
        server_cert_path,
        server_key_path,
        ca_cert_path: pem_path.clone(),
    };
    let listener_handle = Listener::spawn(config).await.expect(
        "ember-rpc Listener::spawn must succeed against emberd's published bridge_ca.pem \
         (META-AP-DAEMON-BRIDGE-CA-PEM-PUBLISH-FORMAT)",
    );
    // Give the accept loop a moment to install.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. Drive a real mTLS handshake with the published PEM as the trust
    //    root. The listener's server cert is signed by the same BridgeCa,
    //    so the client's `WebPkiServerVerifier` over `RootCertStore`
    //    (built from `bridge_ca.pem`) must accept the server identity.
    let client_tls = build_client_tls(&pem_bytes, &client_cert_pem, &client_key_pem);
    let connector = TlsConnector::from(client_tls);
    let stream = TcpStream::connect(listen_addr)
        .await
        .expect("tcp connect to listener");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await
    .expect("handshake completed within 5s")
    .expect(
        "mTLS handshake must succeed: emberd's published bridge_ca.pem is the trust root for \
         both the client (verifying server) and the listener (verifying client)",
    );

    // 6. Round-trip a single JSON-RPC frame so the verdict isn't just
    //    "handshake landed", but "the frame reaches the forwarded UDS
    //    lane through the cert-validated channel".
    tls_stream
        .write_all(br#"{"jsonrpc":"2.0","method":"vault_status","params":{},"id":1}"#)
        .await
        .expect("write request");
    tls_stream.write_all(b"\n").await.expect("write newline");
    tls_stream.flush().await.expect("flush");

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tls_stream.read_to_end(&mut response),
    )
    .await
    .expect("response within 5s")
    .expect("read response");

    let body = String::from_utf8(response).expect("response is utf8");
    let parsed: serde_json::Value =
        serde_json::from_str(body.trim_end()).expect("response is valid JSON");
    assert_eq!(
        parsed["result"]["forwarded"].as_bool(),
        Some(true),
        "JSON-RPC must reach the forwarded UDS lane; got: {parsed}"
    );
    // The forward lane echoes back the cert-derived persona/container
    // identity, proving the cert SAN parse worked end-to-end.
    assert_eq!(
        parsed["result"]["persona_id"].as_str(),
        Some("test-persona"),
        "forwarded frame must carry the SPIFFE persona; got: {parsed}"
    );
    assert_eq!(
        parsed["result"]["container_id"].as_str(),
        Some("test-container"),
        "forwarded frame must carry the SPIFFE container; got: {parsed}"
    );

    listener_handle.abort();
    forward_handle.abort();
}
