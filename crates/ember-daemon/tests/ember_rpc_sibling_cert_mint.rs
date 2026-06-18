//! CLASSIFICATION: PUBLIC
//!
//! ARCH-EMBER-RPC-PHASE-C-SIBLING-CERT-MINT — T3 integration test.
//!
//! Anchor: `ember_rpc_sibling_server_cert_minted_at_startup`.
//!
//! Spinning up the full `DaemonRuntime::run` requires a PID file, a Unix
//! socket bind, broker registration, and tokio plumbing — none of which
//! are load-bearing for the mint-path contract. Instead, this test
//! drives the factored `infra::runtime::mint_or_rotate_ember_rpc_server_cert`
//! helper directly (the same call-site `run()` uses) against a real
//! on-disk `<data_dir>`.
//!
//! The acceptance bits (from the orchestrator brief):
//!
//!   1. Mint succeeds; `server.crt` + `server.key` exist under
//!      `<data_dir>/ember-rpc/` with mode 0640.
//!   2. The PEM pair parses through the same `rustls_pemfile` API the
//!      ember-rpc listener uses (so a future format mismatch surfaces
//!      here at `cargo test` time, not at sibling-boot time).
//!   3. SAN list includes `host.docker.internal` + the loopback IP +
//!      operator-supplied bridge_bind IP.
//!
//! T3 cross-process (emberd binary spawns + ember-rpc binary spawns +
//! real mTLS handshake) is intentionally NOT covered here — the orch
//! brief says "if Docker available; skip is ok" and a Rust-only test
//! that loads the cert pair through rustls is the high-value coverage.

use std::net::SocketAddr;

use ember_daemon::infra::runtime::mint_or_rotate_ember_rpc_server_cert;
use ember_daemon::trust::bridge_ca::BridgeCa;
use tempfile::TempDir;

/// Pre: empty data_dir + fresh BridgeCa.
/// Post: mint writes `ember-rpc/server.crt` + `ember-rpc/server.key`
/// with mode 0640, and both files round-trip through `rustls_pemfile`'s
/// `certs()` / `private_key()` parsers cleanly (same path the listener
/// in `crates/ember-rpc/src/listener.rs` uses).
#[test]
fn mint_writes_pair_that_rustls_pemfile_loads() {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let ca = BridgeCa::mint();

    mint_or_rotate_ember_rpc_server_cert(data_dir, None, &ca).expect("mint succeeds");

    let cert_path = data_dir.join("ember-rpc").join("server.crt");
    let key_path = data_dir.join("ember-rpc").join("server.key");

    // 1. Files exist + mode 0640.
    assert!(cert_path.exists(), "server.crt exists");
    assert!(key_path.exists(), "server.key exists");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(cert_mode, 0o640, "server.crt is mode 0640");
        assert_eq!(key_mode, 0o640, "server.key is mode 0640");
    }

    // 2. PEM cert parses through rustls_pemfile::certs (same path as
    // crates/ember-rpc/src/listener.rs::load_certs).
    let cert_bytes = std::fs::read(&cert_path).expect("read cert");
    let mut cursor = std::io::Cursor::new(cert_bytes);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<_, _>>()
        .expect("rustls_pemfile::certs parses minted cert");
    assert_eq!(certs.len(), 1, "exactly one cert in server.crt");

    // 3. PEM key parses through rustls_pemfile::private_key (same path
    // as crates/ember-rpc/src/listener.rs::load_private_key).
    let key_bytes = std::fs::read(&key_path).expect("read key");
    let mut cursor = std::io::Cursor::new(key_bytes);
    let key = rustls_pemfile::private_key(&mut cursor)
        .expect("rustls_pemfile::private_key parses minted key")
        .expect("private key is Some");
    // ed25519 keys come out as PKCS#8 v1 — rustls_pemfile classifies
    // them as Pkcs8Key.
    let _ = key;
}

/// Pre: empty data_dir + fresh BridgeCa + bridge_bind = 192.168.65.2.
/// Post: minted cert's SAN list includes `host.docker.internal` +
/// `127.0.0.1` + `192.168.65.2`.
#[test]
fn minted_cert_san_includes_bridge_bind_ip() {
    use x509_parser::prelude::*;

    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let ca = BridgeCa::mint();
    let bind: SocketAddr = "192.168.65.2:8443".parse().unwrap();

    mint_or_rotate_ember_rpc_server_cert(data_dir, Some(bind), &ca).expect("mint succeeds");

    let cert_pem = std::fs::read(data_dir.join("ember-rpc").join("server.crt")).expect("read");
    let (_, pem) = parse_x509_pem(&cert_pem).expect("pem");
    let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("der");

    let san = parsed
        .subject_alternative_name()
        .expect("san parses")
        .expect("san present");
    let joined: String = san
        .value
        .general_names
        .iter()
        .map(|gn| format!("{:?}", gn))
        .collect::<Vec<_>>()
        .join(",");

    // T3 positive: minted cert SAN matches expectations.
    assert!(
        joined.contains("host.docker.internal"),
        "host.docker.internal SAN present; got {joined}"
    );
    assert!(
        joined.contains("[127, 0, 0, 1]"),
        "loopback IP SAN present (rendered as [127, 0, 0, 1]); got {joined}"
    );
    assert!(
        joined.contains("[192, 168, 65, 2]"),
        "bridge_bind IP SAN present (rendered as [192, 168, 65, 2]); got {joined}"
    );
}

/// T3 negative: cert validates against the BridgeCa that signed it, but
/// validation against a DIFFERENT BridgeCa fails. This is the mTLS-handshake
/// failure mode a real client would see if its trust root doesn't match
/// the server's CA — surfaced here as a verifying-key mismatch on the
/// signature.
#[test]
fn cert_does_not_validate_against_unrelated_bridge_ca() {
    use ed25519_dalek::Verifier;
    use x509_parser::prelude::*;

    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path();
    let signer_ca = BridgeCa::mint();
    let unrelated_ca = BridgeCa::mint();

    mint_or_rotate_ember_rpc_server_cert(data_dir, None, &signer_ca).expect("mint succeeds");

    let cert_pem = std::fs::read(data_dir.join("ember-rpc").join("server.crt")).expect("read");
    let (_, pem) = parse_x509_pem(&cert_pem).expect("pem");
    let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("der");

    let tbs = parsed.tbs_certificate.as_ref();
    let sig_bytes = parsed.signature_value.as_ref();
    let sig = ed25519_dalek::Signature::try_from(sig_bytes).expect("sig decodes");

    // Positive: signer_ca validates.
    signer_ca
        .verifying_key()
        .verify(tbs, &sig)
        .expect("signer_ca validates the cert it signed");

    // Negative: unrelated_ca rejects.
    let err = unrelated_ca.verifying_key().verify(tbs, &sig);
    assert!(
        err.is_err(),
        "unrelated BridgeCa MUST NOT validate the cert (mTLS trust-root mismatch surface)"
    );
}
