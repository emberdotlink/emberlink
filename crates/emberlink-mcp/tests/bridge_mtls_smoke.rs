//! emberlink_mcp_mtls_client_handshake — T2 smoke tests for the
//! implementation-note-536 in-container bridge transport.
//!
//! Mirrors the test substrate in `crates/ember-rpc/tests/listener_smoke.rs`:
//! in-test CA + leaf certs minted via `rcgen`, no PEM fixtures committed
//! to the tree. The four scenarios cover the acceptance criteria from
//! the brief:
//!
//! 1. **Transport selection (env var presence).** When `EMBER_DAEMON_ENDPOINT`
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
    let cert = params
        .signed_by(&key_pair, &ca.cert_for_signing, &ca.key_pair)
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
// T2 case 1: transport selector reflects EMBER_DAEMON_ENDPOINT presence.
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
    let config = MtlsBridgeConfig {
        endpoint: "127.0.0.1:1".to_string(),
        tls_config,
        server_name: "localhost".to_string(),
    };
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
    let bridge_config = MtlsBridgeConfig {
        endpoint: server_addr.to_string(),
        tls_config,
        server_name: "localhost".to_string(),
    };
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
    let bridge_config = MtlsBridgeConfig {
        endpoint: server_addr.to_string(),
        tls_config,
        server_name: "localhost".to_string(),
    };
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
