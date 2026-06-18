//! emberlink_mcp_mtls_client_handshake — T2 smoke tests for the
//! META-AP-EMBERLINK-MCP-MTLS-CLIENT in-container bridge transport.
//!
//! Mirrors the test substrate in `crates/ember-rpc/tests/listener_smoke.rs`:
//! in-test CA + leaf certs minted via `rcgen`, no PEM fixtures committed
//! to the tree. The four scenarios cover the acceptance criteria from
//! the brief:
//!
//! 1. **Transport selection (env var presence).** When `EMBER_BRIDGE_URL`
//!    is set the constructor produces an mTLS variant; absent, a UDS one.
//! 2. **Fail-closed on missing cert files.** `load_bridge_cert_files` on
//!    an empty directory returns a typed `BridgeCertError` rather than
//!    panicking.
//! 3. **mTLS round-trip with CA-signed client cert.** Stand up a minimal
//!    rustls server keyed to the same in-test CA; the client transport
//!    handshakes + sends a JSON-RPC frame + reads back a response.
//! 4. **Negative: handshake fails when the server CA differs from the
//!    one the client trusts.** The client must error (not hang, not
//!    panic).

#![allow(clippy::expect_used)] // test code — panicking on setup failure is the bug surface

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use emberlink_mcp::daemon_transport::{
    DaemonTransport, MtlsBridgeConfig, build_client_tls_config, load_bridge_cert_files,
};

// ---------------------------------------------------------------------------
// Test CA + cert mint helpers (rcgen) — mirror crates/ember-rpc/tests/listener_smoke.rs
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

/// Lay out a cert bundle in `dir` matching the in-container path shape
/// the orchestrator mounts: `{dir}/client.crt`, `{dir}/client.key`,
/// `{dir}/ca.crt`.
fn write_bridge_cert_bundle(dir: &std::path::Path, ca: &TestCa, client: &LeafPair) {
    std::fs::write(dir.join("ca.crt"), &ca.cert_pem).expect("write ca");
    std::fs::write(dir.join("client.crt"), &client.cert_pem).expect("write client cert");
    std::fs::write(dir.join("client.key"), &client.key_pem).expect("write client key");
}

// ---------------------------------------------------------------------------
// In-test mTLS server — bind 127.0.0.1:0, accept one TLS handshake, echo one
// JSON-RPC frame back. Just enough surface for a client round-trip.
// ---------------------------------------------------------------------------

fn build_server_tls(ca: &TestCa, server: &LeafPair) -> Arc<ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Client-verifier roots = the in-test CA only. Matches the listener
    // pattern in crates/ember-rpc.
    let mut roots = RootCertStore::empty();
    let mut ca_cursor = std::io::Cursor::new(ca.cert_pem.as_bytes());
    for ca_cert in rustls_pemfile::certs(&mut ca_cursor) {
        let ca_cert = ca_cert.expect("ca cert");
        roots.add(ca_cert).expect("add ca to roots");
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let mut cert_cursor = std::io::Cursor::new(server.cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .map(|c| c.expect("server cert"))
        .collect();
    let mut key_cursor = std::io::Cursor::new(server.key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .expect("server key")
        .expect("server key present");
    let key_for_config: PrivateKeyDer<'static> = match key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
        }
        other => other,
    };

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key_for_config)
        .expect("server tls config");
    Arc::new(config)
}

// (sync `spawn_echo_server_sync` lower in the file is the path actually
// used — see the docstring on the round-trip test for the reason a
// sync-test + sync-server-on-thread pattern beats the obvious
// #[tokio::test] shape.)

// ---------------------------------------------------------------------------
// T2 case 1: transport selector reflects EMBER_BRIDGE_URL presence.
// ---------------------------------------------------------------------------

#[test]
fn uds_transport_when_endpoint_absent() {
    // Build the UDS transport directly (we don't go through main.rs here
    // since main() is a process — we exercise the construction primitive
    // that main.rs would call).
    let transport = DaemonTransport::new("/tmp/no-such-socket.sock");
    assert!(
        !transport.is_mtls(),
        "DaemonTransport::new must produce a UDS variant"
    );
}

#[test]
fn endpoint_from_bridge_url_strips_scheme_and_path() {
    use emberlink_mcp::daemon_transport::endpoint_from_bridge_url;
    // The unified EMBER_BRIDGE_URL is a full URL; the raw mTLS dial wants the
    // host:port authority (ADR 215 §4).
    assert_eq!(
        endpoint_from_bridge_url("https://host.docker.internal:8765"),
        "host.docker.internal:8765"
    );
    assert_eq!(
        endpoint_from_bridge_url("https://host.docker.internal:8765/"),
        "host.docker.internal:8765"
    );
    // Tolerates a bare host:port (no scheme).
    assert_eq!(
        endpoint_from_bridge_url("host.containers.internal:4243"),
        "host.containers.internal:4243"
    );
}

#[test]
fn mtls_transport_when_endpoint_present() {
    // Sync test (not `#[tokio::test]`) so the bridge runtime drop is
    // not inside an async context — tokio refuses to drop a runtime
    // from within another runtime's task.
    let ca = mint_test_ca("test-bridge-ca-selector");
    let client = mint_leaf_cert(&ca, "client", false, Vec::new());
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_bridge_cert_bundle(tempdir.path(), &ca, &client);

    let loaded = load_bridge_cert_files(tempdir.path()).expect("load certs");
    let tls_config = build_client_tls_config(loaded).expect("build tls config");
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build runtime"),
    );
    let config = MtlsBridgeConfig::new("127.0.0.1:1".to_string(), tls_config, "localhost".to_string());
    let transport = DaemonTransport::new_mtls(config, runtime);
    assert!(
        transport.is_mtls(),
        "DaemonTransport::new_mtls must produce an mTLS variant"
    );
}

// ---------------------------------------------------------------------------
// T2 case 2: missing cert files → fail-closed typed error (no panic).
// ---------------------------------------------------------------------------

#[test]
fn missing_cert_dir_returns_typed_error() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    // The directory exists but holds no cert bundle. `load_bridge_cert_files`
    // must surface a typed `BridgeCertError` rather than panic.
    let result = load_bridge_cert_files(tempdir.path());
    assert!(
        result.is_err(),
        "load on empty dir must error, got Ok — fail-closed contract violated"
    );
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("client.crt") || err_str.contains("client cert"),
        "error should name the missing client cert; got {err_str}"
    );
}

#[test]
fn empty_pem_file_returns_typed_error() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    // Touch all three files but leave them empty — `rustls_pemfile` will
    // succeed-parse-zero, and load_bridge_cert_files must catch that
    // emptiness rather than fall through to an anonymous-cert TLS config.
    std::fs::write(tempdir.path().join("client.crt"), b"").expect("write");
    std::fs::write(tempdir.path().join("client.key"), b"").expect("write");
    std::fs::write(tempdir.path().join("ca.crt"), b"").expect("write");
    let result = load_bridge_cert_files(tempdir.path());
    assert!(
        result.is_err(),
        "empty cert PEM must surface as error (not fall through to anonymous TLS)"
    );
}

// ---------------------------------------------------------------------------
// T2 case 3: end-to-end mTLS round-trip with CA-signed client cert.
//
// We use a sync `#[test]` rather than `#[tokio::test]` so the bridge
// runtime (owned by the DaemonTransport) can be dropped at end of test
// without the "Cannot drop a runtime in a context where blocking is not
// allowed" panic — that panic fires when one tokio runtime is dropped
// inside another runtime's task. Pattern: stand up the server on a
// dedicated server-runtime in its own thread, then run the sync client
// call from the test thread (no outer runtime).
// ---------------------------------------------------------------------------

/// Build and spawn the echo server on a fresh runtime in a background
/// thread, returning the bound address + a stop channel. Keeping the
/// server-runtime in a different thread from the client-runtime avoids
/// the nested-drop trap entirely.
fn spawn_echo_server_sync(
    tls_config: Arc<ServerConfig>,
) -> (std::net::SocketAddr, std::sync::mpsc::Sender<()>) {
    use std::sync::mpsc;
    let (addr_tx, addr_rx) = mpsc::channel::<std::net::SocketAddr>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("server bind");
            let addr = listener.local_addr().expect("server addr");
            addr_tx.send(addr).expect("send addr");
            let acceptor = TlsAcceptor::from(tls_config);
            // Accept loop runs until the stop signal arrives or the
            // process drops the receiver.
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((tcp, _peer)) = accept {
                            let acc = acceptor.clone();
                            tokio::spawn(async move {
                                if let Ok(tls) = acc.accept(tcp).await {
                                    let (read_half, mut write_half) = tokio::io::split(tls);
                                    let mut reader = BufReader::new(read_half);
                                    let mut line = String::new();
                                    if reader.read_line(&mut line).await.is_ok() {
                                        let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or(serde_json::json!({}));
                                        let id = request.get("id").cloned().unwrap_or(serde_json::json!("1"));
                                        let response = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": id,
                                            "result": {"ok": true},
                                        });
                                        let mut bytes = serde_json::to_vec(&response).expect("encode response");
                                        bytes.push(b'\n');
                                        let _ = write_half.write_all(&bytes).await;
                                        let _ = write_half.shutdown().await;
                                    }
                                }
                            });
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        // Periodic wakeup so we observe the stop channel
                        // without polling busily.
                        if stop_rx.try_recv().is_ok() {
                            break;
                        }
                    }
                }
            }
        });
    });
    let addr = addr_rx.recv().expect("server addr received");
    (addr, stop_tx)
}

#[test]
fn mtls_round_trip_with_ca_signed_client_cert() {
    let ca = mint_test_ca("test-bridge-ca-roundtrip");
    let server_leaf = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client_leaf = mint_leaf_cert(&ca, "client", false, Vec::new());

    let server_tls = build_server_tls(&ca, &server_leaf);
    let (server_addr, _stop_tx) = spawn_echo_server_sync(server_tls);

    // Client: lay out the cert bundle on disk and let the production
    // loader build the ClientConfig. This exercises the exact code path
    // main.rs runs in container mode.
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_bridge_cert_bundle(tempdir.path(), &ca, &client_leaf);
    let loaded = load_bridge_cert_files(tempdir.path()).expect("load");
    let tls_config = build_client_tls_config(loaded).expect("build tls config");

    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("bridge runtime"),
    );
    let bridge_config = MtlsBridgeConfig::new(server_addr.to_string(), tls_config, "localhost".to_string());
    let transport = DaemonTransport::new_mtls(bridge_config, bridge_runtime);

    let response = transport
        .call_raw("ping", &serde_json::json!({}))
        .expect("mTLS round-trip failed");
    assert_eq!(
        response.get("ok").and_then(|v| v.as_bool()),
        Some(true),
        "echo server should return {{ok: true}}; got {response}"
    );
}

// ---------------------------------------------------------------------------
// T2 case 4: handshake fails when client trusts a different CA than the server.
// ---------------------------------------------------------------------------

#[test]
fn mtls_handshake_fails_with_wrong_ca() {
    let server_ca = mint_test_ca("server-ca");
    let attacker_ca = mint_test_ca("attacker-ca");

    let server_leaf = mint_leaf_cert(&server_ca, "server", true, vec!["localhost".into()]);
    let attacker_client = mint_leaf_cert(&attacker_ca, "client", false, Vec::new());

    let server_tls = build_server_tls(&server_ca, &server_leaf);
    let (server_addr, _stop_tx) = spawn_echo_server_sync(server_tls);

    let tempdir = tempfile::tempdir().expect("tempdir");
    write_bridge_cert_bundle(tempdir.path(), &attacker_ca, &attacker_client);
    let loaded = load_bridge_cert_files(tempdir.path()).expect("load");
    let tls_config = build_client_tls_config(loaded).expect("build tls config");

    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("bridge runtime"),
    );
    let bridge_config = MtlsBridgeConfig::new(server_addr.to_string(), tls_config, "localhost".to_string());
    let transport = DaemonTransport::new_mtls(bridge_config, bridge_runtime);

    let result = transport.call_raw("ping", &serde_json::json!({}));
    assert!(
        result.is_err(),
        "handshake against wrong-CA server must error (no panic); got Ok({result:?})"
    );
}

// ---------------------------------------------------------------------------
// T2 case 5: 90% TTL deadline + leaf cert validity round-trip via parse_cert_validity.
// ---------------------------------------------------------------------------

#[test]
fn loaded_client_cert_parses_validity_window() {
    use emberlink_mcp::cert_expiry::parse_cert_validity;
    let ca = mint_test_ca("ttl-ca");
    let client = mint_leaf_cert(&ca, "client-ttl", false, Vec::new());
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_bridge_cert_bundle(tempdir.path(), &ca, &client);

    let loaded = load_bridge_cert_files(tempdir.path()).expect("load");
    let leaf = &loaded.client_certs[0];
    let validity = parse_cert_validity(leaf).expect("parse cert validity");
    assert!(
        validity.not_after > validity.not_before,
        "leaf cert validity window must be positive; got {validity:?}"
    );
    // rcgen defaults to validity windows on the order of a year; assert
    // a non-degenerate window without locking a specific duration.
    assert!(
        validity.total_secs() > 60,
        "cert TTL should be at least one minute; got {} secs",
        validity.total_secs()
    );
}

// ---------------------------------------------------------------------------
// META-AP-EMBERLINK-MCP-CERT-SWAP (M7) — T2 cert-swap tests.
//
// Anchor: `emberlink_mcp_cert_swap_landed`. These cases exercise the
// hot-update path for the in-container `rustls::ClientConfig`:
//
// - Swap → next mTLS handshake presents the NEW client cert (server-side
//   peer cert observation differs across the two RPCs).
// - Swap to an attacker cert (signed by an untrusted CA) → server-side
//   handshake refuses the new cert post-swap. This is the brief's "old
//   cert no longer accepted" invariant tested at the wire layer — once
//   the swap installs an untrusted leaf the server's
//   `WebPkiClientVerifier` refuses, demonstrating that the swap actually
//   replaced the cert presented by the next handshake.
// - Unit test that `swap_client_config` replaces the shared inner Arc
//   across all `MtlsBridgeConfig` clones (the "same swap visible to
//   every transport" invariant).
// ---------------------------------------------------------------------------

/// Echo server variant that captures the peer-presented client cert chain
/// on every accepted connection. The captured DER vec is appended to
/// `peer_certs_ledger` so the test thread can assert on which cert was
/// observed at which RPC index.
///
/// The implementation mirrors `spawn_echo_server_sync` but inlines the
/// `peer_certificates()` lookup before splitting the TLS stream — once
/// the stream is split that handle is gone.
fn spawn_echo_server_capturing_peer_certs(
    tls_config: Arc<ServerConfig>,
    peer_certs_ledger: Arc<std::sync::Mutex<Vec<Vec<CertificateDer<'static>>>>>,
) -> (std::net::SocketAddr, std::sync::mpsc::Sender<()>) {
    use std::sync::mpsc;
    let (addr_tx, addr_rx) = mpsc::channel::<std::net::SocketAddr>();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("server bind");
            let addr = listener.local_addr().expect("server addr");
            addr_tx.send(addr).expect("send addr");
            let acceptor = TlsAcceptor::from(tls_config);
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        if let Ok((tcp, _peer)) = accept {
                            let acc = acceptor.clone();
                            let ledger = Arc::clone(&peer_certs_ledger);
                            tokio::spawn(async move {
                                if let Ok(tls) = acc.accept(tcp).await {
                                    // Capture the peer cert chain BEFORE
                                    // splitting the stream — the
                                    // post-split halves don't expose the
                                    // peer cert.
                                    let peer_chain: Vec<CertificateDer<'static>> = tls
                                        .get_ref()
                                        .1
                                        .peer_certificates()
                                        .map(|chain| {
                                            chain
                                                .iter()
                                                .map(|c| CertificateDer::from(c.as_ref().to_vec()))
                                                .collect()
                                        })
                                        .unwrap_or_default();
                                    if let Ok(mut g) = ledger.lock() {
                                        g.push(peer_chain);
                                    }

                                    let (read_half, mut write_half) = tokio::io::split(tls);
                                    let mut reader = BufReader::new(read_half);
                                    let mut line = String::new();
                                    if reader.read_line(&mut line).await.is_ok() {
                                        let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or(serde_json::json!({}));
                                        let id = request.get("id").cloned().unwrap_or(serde_json::json!("1"));
                                        let response = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": id,
                                            "result": {"ok": true},
                                        });
                                        let mut bytes = serde_json::to_vec(&response).expect("encode response");
                                        bytes.push(b'\n');
                                        let _ = write_half.write_all(&bytes).await;
                                        let _ = write_half.shutdown().await;
                                    }
                                }
                            });
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        if stop_rx.try_recv().is_ok() {
                            break;
                        }
                    }
                }
            }
        });
    });
    let addr = addr_rx.recv().expect("server addr received");
    (addr, stop_tx)
}

/// Build the same in-container ClientConfig the production loader would
/// produce, but from in-memory PEM strings rather than off-disk.
/// Used by the swap tests to stage two cert+key pairs and feed them to
/// `MtlsBridgeConfig::swap_client_config` without going through the
/// file-IO loader twice.
fn build_client_tls_from_leaf_pem(
    ca: &TestCa,
    leaf: &LeafPair,
) -> Arc<rustls::ClientConfig> {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_bridge_cert_bundle(tempdir.path(), ca, leaf);
    let loaded = load_bridge_cert_files(tempdir.path()).expect("load");
    build_client_tls_config(loaded).expect("build tls config")
}

#[test]
fn cert_swap_next_handshake_presents_new_cert() {
    // emberlink_mcp_cert_swap_landed (T2). Stand up an mTLS server that
    // captures the peer cert per connection; do a round-trip with cert
    // A, swap to cert B, do another round-trip; assert the server
    // observed two distinct certs in handshake order A then B.
    let ca = mint_test_ca("swap-test-ca");
    let server_leaf = mint_leaf_cert(&ca, "server", true, vec!["localhost".into()]);
    let client_a = mint_leaf_cert(&ca, "client-a", false, Vec::new());
    let client_b = mint_leaf_cert(&ca, "client-b", false, Vec::new());

    let server_tls = build_server_tls(&ca, &server_leaf);
    let peer_ledger: Arc<std::sync::Mutex<Vec<Vec<CertificateDer<'static>>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let (server_addr, _stop_tx) =
        spawn_echo_server_capturing_peer_certs(server_tls, Arc::clone(&peer_ledger));

    let tls_a = build_client_tls_from_leaf_pem(&ca, &client_a);
    let tls_b = build_client_tls_from_leaf_pem(&ca, &client_b);

    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("bridge runtime"),
    );
    let bridge_config =
        MtlsBridgeConfig::new(server_addr.to_string(), tls_a, "localhost".to_string());
    let transport = DaemonTransport::new_mtls(bridge_config.clone(), Arc::clone(&bridge_runtime));

    // RPC #1 with cert A.
    let r1 = transport
        .call_raw("ping", &serde_json::json!({}))
        .expect("RPC #1 (cert A) should succeed");
    assert_eq!(r1.get("ok").and_then(|v| v.as_bool()), Some(true));

    // Hot-swap to cert B; the same transport (no rebuild) should pick up
    // the new ClientConfig on the next call because both transports share
    // the outer Arc<RwLock<Arc<ClientConfig>>>.
    bridge_config.swap_client_config(tls_b);

    let r2 = transport
        .call_raw("ping", &serde_json::json!({}))
        .expect("RPC #2 (cert B post-swap) should succeed");
    assert_eq!(r2.get("ok").and_then(|v| v.as_bool()), Some(true));

    // Read the ledger of peer certs observed by the server. The two
    // handshakes should have produced two distinct cert chains, in order.
    let observed = peer_ledger.lock().expect("lock");
    assert_eq!(
        observed.len(),
        2,
        "server should have observed exactly 2 handshakes; got {}",
        observed.len()
    );
    assert!(
        !observed[0].is_empty() && !observed[1].is_empty(),
        "both handshakes must present at least one cert"
    );
    assert_ne!(
        observed[0][0].as_ref(),
        observed[1][0].as_ref(),
        "the post-swap handshake must present a DIFFERENT cert than the pre-swap one — \
         if they're equal the swap didn't take effect"
    );
}

#[test]
fn cert_swap_to_untrusted_ca_causes_handshake_failure() {
    // emberlink_mcp_cert_swap_landed (T2). The "old cert no longer
    // accepted" invariant at the wire layer: install a server that
    // trusts CA-1 only; the client starts on a CA-1 cert (success), then
    // we swap to a CA-2 cert (untrusted by the server). The next RPC's
    // TLS handshake must fail — proving the swap actually replaces what
    // the new connection presents.
    let trusted_ca = mint_test_ca("swap-trusted-ca");
    let attacker_ca = mint_test_ca("swap-attacker-ca");
    let server_leaf =
        mint_leaf_cert(&trusted_ca, "server", true, vec!["localhost".into()]);
    let trusted_client =
        mint_leaf_cert(&trusted_ca, "client-trusted", false, Vec::new());
    let attacker_client =
        mint_leaf_cert(&attacker_ca, "client-attacker", false, Vec::new());

    let server_tls = build_server_tls(&trusted_ca, &server_leaf);
    let (server_addr, _stop_tx) = spawn_echo_server_sync(server_tls);

    // Client starts with the trusted CA's cert.
    let tls_trusted = build_client_tls_from_leaf_pem(&trusted_ca, &trusted_client);
    // Note: the attacker cert bundle includes the attacker CA in ca.crt
    // (build_client_tls_from_leaf_pem writes the CA passed in), so the
    // client's root store accepts the SERVER cert via the attacker CA's
    // CA file. But the server-side `WebPkiClientVerifier` trusts only
    // `trusted_ca`, so the attacker-signed CLIENT cert is rejected at
    // the server's client-auth step. That asymmetry is the load-bearing
    // assertion: the swap actually changed which client cert is
    // presented; the server's verifier sees the new (untrusted) cert
    // and refuses.
    let tls_attacker = build_client_tls_from_leaf_pem(&attacker_ca, &attacker_client);

    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("bridge runtime"),
    );
    let bridge_config = MtlsBridgeConfig::new(
        server_addr.to_string(),
        tls_trusted,
        "localhost".to_string(),
    );
    let transport = DaemonTransport::new_mtls(bridge_config.clone(), bridge_runtime);

    // Pre-swap call succeeds.
    let r1 = transport
        .call_raw("ping", &serde_json::json!({}))
        .expect("pre-swap RPC (trusted client cert) should succeed");
    assert_eq!(r1.get("ok").and_then(|v| v.as_bool()), Some(true));

    // Hot-swap to the attacker cert; the next call's TLS handshake must
    // fail because the server's WebPkiClientVerifier doesn't trust the
    // attacker CA. (The client side accepts the server cert here only
    // because we built tls_attacker using `attacker_ca` as the ca.crt;
    // that's an artifact of the test fixture, not of the swap. The
    // load-bearing assertion is that the post-swap connection presents
    // an UNTRUSTED client cert and is rejected.)
    bridge_config.swap_client_config(tls_attacker);

    let r2 = transport.call_raw("ping", &serde_json::json!({}));
    assert!(
        r2.is_err(),
        "post-swap RPC with untrusted client cert must error (no panic); got Ok({r2:?})"
    );
}

#[test]
fn swap_client_config_visible_across_cloned_bridge_configs() {
    // emberlink_mcp_cert_swap_landed (unit). `MtlsBridgeConfig` is
    // `Clone`; the outer `Arc<RwLock<Arc<ClientConfig>>>` is what
    // propagates a swap to every clone (production has the bridge refresh
    // client and the McpServer transport each cloning the same bridge_config
    // in main.rs). This unit-shape test stages two clones and verifies a swap
    // on one is visible from the other.
    let ca = mint_test_ca("clone-visibility-ca");
    let leaf_a = mint_leaf_cert(&ca, "client-a", false, Vec::new());
    let leaf_b = mint_leaf_cert(&ca, "client-b", false, Vec::new());
    let tls_a = build_client_tls_from_leaf_pem(&ca, &leaf_a);
    let tls_b = build_client_tls_from_leaf_pem(&ca, &leaf_b);

    let config1 =
        MtlsBridgeConfig::new("127.0.0.1:1".to_string(), tls_a.clone(), "localhost".to_string());
    let config2 = config1.clone();

    // Both clones see cert A initially.
    let snap1_pre = config1.current_client_config();
    let snap2_pre = config2.current_client_config();
    assert!(
        Arc::ptr_eq(&snap1_pre, &snap2_pre),
        "both clones should resolve to the same initial ClientConfig Arc"
    );
    assert!(
        Arc::ptr_eq(&snap1_pre, &tls_a),
        "the initial snapshot should be the cert-A Arc"
    );

    // Swap on config1; config2 (clone) must observe the new value.
    config1.swap_client_config(Arc::clone(&tls_b));

    let snap1_post = config1.current_client_config();
    let snap2_post = config2.current_client_config();
    assert!(
        Arc::ptr_eq(&snap1_post, &tls_b),
        "config1 should now resolve to the cert-B Arc"
    );
    assert!(
        Arc::ptr_eq(&snap2_post, &tls_b),
        "config2 (clone) should ALSO resolve to the cert-B Arc — \
         the swap must propagate through the shared outer Arc<RwLock<...>>"
    );
}

#[test]
fn refresh_failing_gate_refuses_new_call_tool_with_typed_error() {
    // emberlink_mcp_cert_refresh_client_landed (T2). ADR 173 §Component 5
    // "Soft fail-closed at 90% TTL": once `MtlsBridgeConfig::
    // set_refresh_failing(true)` flips the flag, `DaemonTransport::
    // call_tool` MUST refuse with the typed `RefreshFailing` error —
    // not a generic transport error, and not an unrelated DaemonError.
    use emberlink_mcp::daemon_transport::DaemonTransportError;

    let ca = mint_test_ca("refresh-failing-gate-ca");
    let leaf = mint_leaf_cert(&ca, "client-a", false, Vec::new());
    let tls = build_client_tls_from_leaf_pem(&ca, &leaf);

    let bridge_runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("bridge runtime"),
    );
    // Endpoint is never dialed because the gate trips before the round-trip.
    let bridge_config =
        MtlsBridgeConfig::new("127.0.0.1:0".to_string(), tls, "localhost".to_string());
    let transport =
        DaemonTransport::new_mtls(bridge_config.clone(), Arc::clone(&bridge_runtime));

    // Pre-flip: call_tool would try to dial 127.0.0.1:0 and fail Io; not
    // the typed RefreshFailing — confirm precondition.
    let pre = transport.call_tool("ping", &serde_json::json!({}));
    assert!(pre.is_err(), "call_tool to closed port should error");
    assert!(
        !matches!(pre.as_ref().unwrap_err(), DaemonTransportError::RefreshFailing),
        "before the flag flip, call_tool must NOT return RefreshFailing; got {:?}",
        pre.unwrap_err()
    );

    // Flip the soft-fail-closed flag (the 90% band in the refresh client
    // does this in production).
    bridge_config.set_refresh_failing(true);

    let gated = transport.call_tool("ping", &serde_json::json!({}));
    match gated {
        Err(DaemonTransportError::RefreshFailing) => { /* expected */ }
        other => panic!(
            "post-flip call_tool MUST return DaemonTransportError::RefreshFailing; got {other:?}"
        ),
    }

    // `call_raw` is NOT gated — the refresh-RPC path itself uses it and
    // must continue functioning past the 90% band. With the endpoint
    // unreachable, this should produce an Io error, not RefreshFailing.
    let raw = transport.call_raw("refresh_cert", &serde_json::json!({}));
    assert!(raw.is_err(), "call_raw to closed port should still error");
    assert!(
        !matches!(raw.as_ref().unwrap_err(), DaemonTransportError::RefreshFailing),
        "call_raw must NOT be gated by refresh_failing — the refresh \
         RPC path itself runs through call_raw and must continue past \
         the 90% band; got {:?}",
        raw.unwrap_err()
    );

    // Clearing the flag must re-open call_tool (still errors on Io for
    // the closed port, but no longer RefreshFailing).
    bridge_config.set_refresh_failing(false);
    let reopened = transport.call_tool("ping", &serde_json::json!({}));
    assert!(
        reopened.is_err(),
        "call_tool to closed port should error after re-open"
    );
    assert!(
        !matches!(
            reopened.as_ref().unwrap_err(),
            DaemonTransportError::RefreshFailing
        ),
        "after clearing the flag, call_tool must NOT return RefreshFailing; \
         got {:?}",
        reopened.unwrap_err()
    );
}
