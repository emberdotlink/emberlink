//! CLASSIFICATION: PUBLIC
//!
//! T2 integration tests for ember-relay.
//!
//! These tests cover the three load-bearing invariants in the brief:
//!   1. End-to-end roundtrip (AF_UNIX -> VM relay -> TCP/TLS -> host relay
//!      -> AF_UNIX echo server).
//!   2. The `--cert` arg is required.
//!   3. Mismatched CAs cause TLS handshake failure (not a silent fall-through).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, PKCS_ED25519,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::time::timeout;

// ─── cert helpers ───────────────────────────────────────────────────────────

struct Pki {
    /// CA cert PEM.
    ca_pem: String,
    /// Server leaf cert PEM (host relay's identity).
    server_cert_pem: String,
    server_key_pem: String,
    /// Client leaf cert PEM (VM relay's identity).
    client_cert_pem: String,
    client_key_pem: String,
}

fn make_pki(server_san: &str, client_san: &str) -> Pki {
    // CA
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).expect("ca keygen");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "ember-relay-test-ca");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let issuer = Issuer::from_ca_cert_pem(ca_cert.pem().as_str(), ca_key).expect("issuer");

    // Server leaf (host relay)
    let server_key = KeyPair::generate_for(&PKCS_ED25519).expect("server keygen");
    let mut server_params =
        CertificateParams::new(vec![server_san.to_string()]).expect("server params");
    server_params.is_ca = IsCa::NoCa;
    server_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    let server_signed = server_params
        .signed_by(&server_key, &issuer)
        .expect("server sign");

    // Client leaf (VM relay)
    let client_key = KeyPair::generate_for(&PKCS_ED25519).expect("client keygen");
    let mut client_params =
        CertificateParams::new(vec![client_san.to_string()]).expect("client params");
    client_params.is_ca = IsCa::NoCa;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    client_params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    let client_signed = client_params
        .signed_by(&client_key, &issuer)
        .expect("client sign");

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_signed.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_signed.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

struct PkiOnDisk {
    _dir: TempDir,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

fn write_pki_to_disk(pki: &Pki) -> PkiOnDisk {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = dir.path().join("ca.pem");
    let sc = dir.path().join("server.cert.pem");
    let sk = dir.path().join("server.key.pem");
    let cc = dir.path().join("client.cert.pem");
    let ck = dir.path().join("client.key.pem");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    std::fs::write(&sc, &pki.server_cert_pem).unwrap();
    std::fs::write(&sk, &pki.server_key_pem).unwrap();
    std::fs::write(&cc, &pki.client_cert_pem).unwrap();
    std::fs::write(&ck, &pki.client_key_pem).unwrap();
    PkiOnDisk {
        _dir: dir,
        ca,
        server_cert: sc,
        server_key: sk,
        client_cert: cc,
        client_key: ck,
    }
}

// ─── test fixture: AF_UNIX echo server ──────────────────────────────────────

/// Tokio task that listens on `path` and echoes each connection's bytes back
/// with a `"ECHO:"` prefix. Used as the "daemon" in the roundtrip test —
/// it stands in for the real AF_UNIX-listening emberd.
///
/// Also reads + discards a 4-byte length-prefix + body HELLO frame at the
/// start of each connection. The VM relay writes that frame; in the real
/// system the daemon parses it. For the echo-server fixture we just throw it
/// away so the echo of agent bytes can be compared cleanly.
async fn run_echo_server(path: PathBuf) {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("echo bind");
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        tokio::spawn(async move {
            // Skip HELLO frame.
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 1024 {
                return;
            }
            let mut hello = vec![0u8; len];
            if sock.read_exact(&mut hello).await.is_err() {
                return;
            }
            // Echo loop.
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        let mut payload = Vec::with_capacity(n + 5);
                        payload.extend_from_slice(b"ECHO:");
                        payload.extend_from_slice(&buf[..n]);
                        if sock.write_all(&payload).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

// ─── happy-path roundtrip via spawned binaries ─────────────────────────────

/// Locate a built binary for this crate. Cargo sets `CARGO_BIN_EXE_<name>`
/// for integration tests of a crate that defines that bin target.
fn bin_path(name: &str) -> PathBuf {
    let env_var = format!("CARGO_BIN_EXE_{name}");
    PathBuf::from(std::env::var(&env_var).unwrap_or_else(|_| {
        panic!("env var {env_var} not set; cargo should set it for integration tests")
    }))
}

#[tokio::test]
async fn happy_path_roundtrip() {
    let pki = make_pki("127.0.0.1", "vm-test-client");
    let on_disk = write_pki_to_disk(&pki);

    // 1. Pick a temp dir for sockets.
    let sockdir = tempfile::tempdir().expect("sockdir");
    let echo_sock = sockdir.path().join("echo.sock");
    let vm_sock = sockdir.path().join("vm.sock");

    // 2. Start the echo "daemon" (AF_UNIX) in-process.
    let echo_handle = tokio::spawn(run_echo_server(echo_sock.clone()));

    // 3. Pick an ephemeral TCP port by binding-then-releasing.
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let tcp_port = probe.local_addr().unwrap().port();
    drop(probe);
    // Brief race here is acceptable for a test.

    let tcp_addr = format!("127.0.0.1:{tcp_port}");

    // 4. Spawn ember-relay-host.
    let mut host_proc = tokio::process::Command::new(bin_path("ember-relay-host"))
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--uds-target")
        .arg(&echo_sock)
        .arg("--cert")
        .arg(&on_disk.server_cert)
        .arg("--key")
        .arg(&on_disk.server_key)
        .arg("--ca")
        .arg(&on_disk.ca)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn host relay");

    // 5. Spawn ember-relay-vm.
    let mut vm_proc = tokio::process::Command::new(bin_path("ember-relay-vm"))
        .arg("--uds-listen")
        .arg(&vm_sock)
        .arg("--tcp-target")
        .arg(&tcp_addr)
        .arg("--cert")
        .arg(&on_disk.client_cert)
        .arg("--key")
        .arg(&on_disk.client_key)
        .arg("--ca")
        .arg(&on_disk.ca)
        .arg("--claimed-persona")
        .arg("user-alpha")
        .arg("--server-name")
        .arg("127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vm relay");

    // 6. Wait for vm_sock to appear (the VM relay binds it).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !vm_sock.exists() {
        if std::time::Instant::now() > deadline {
            let _ = host_proc.kill().await;
            let _ = vm_proc.kill().await;
            panic!(
                "vm-side relay never created its uds listener at {}",
                vm_sock.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 7. Connect to the VM-side UDS, send bytes, expect ECHO: prefix back.
    let result = timeout(Duration::from_secs(10), async {
        let mut client = UnixStream::connect(&vm_sock)
            .await
            .expect("connect vm sock");
        client
            .write_all(b"roundtrip-test")
            .await
            .expect("client write");
        client.flush().await.expect("client flush");
        // Half-close write so the echo server's read-loop can EOF-detect if it
        // wants — but it pumps on every chunk regardless. We just read enough
        // bytes back to match the prefix-echo.
        let mut buf = vec![0u8; 19]; // "ECHO:roundtrip-test"
        client.read_exact(&mut buf).await.expect("client read");
        buf
    })
    .await;

    // 8. Tear down.
    let _ = host_proc.kill().await;
    let _ = vm_proc.kill().await;
    echo_handle.abort();

    let buf = result.expect("roundtrip timed out");
    assert_eq!(&buf[..], b"ECHO:roundtrip-test");
}

// ─── missing --cert arg returns nonzero exit ────────────────────────────────

#[tokio::test]
async fn missing_cert_arg_rejects() {
    let pki = make_pki("127.0.0.1", "vm-test-client");
    let on_disk = write_pki_to_disk(&pki);

    // Spawn host relay WITHOUT --cert.
    let output = tokio::process::Command::new(bin_path("ember-relay-host"))
        .arg("--tcp-listen")
        .arg("127.0.0.1:0")
        .arg("--uds-target")
        .arg("/tmp/nonexistent.sock")
        // intentionally omit --cert
        .arg("--key")
        .arg(&on_disk.server_key)
        .arg("--ca")
        .arg(&on_disk.ca)
        .output()
        .await
        .expect("spawn host without --cert");

    assert!(!output.status.success(), "must exit nonzero");
    // clap's default exit code for arg errors is 2.
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 (clap arg error)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lc = stderr.to_lowercase();
    assert!(
        lc.contains("cert") || lc.contains("--cert"),
        "stderr should mention cert; got:\n{stderr}"
    );
    assert!(
        lc.contains("required") || lc.contains("missing"),
        "stderr should indicate missing/required; got:\n{stderr}"
    );
}

// ─── mismatched CA produces TLS handshake failure ───────────────────────────

#[tokio::test]
async fn mismatched_ca_fails_handshake() {
    // Build TWO independent PKIs.
    let host_pki = make_pki("127.0.0.1", "vm-test-client");
    let rogue_pki = make_pki("127.0.0.1", "rogue-client");

    // The host trusts only host_pki.ca for client verification. The VM
    // presents a cert signed by rogue_pki.ca AND trusts only rogue_pki.ca
    // for server verification. Both sides reject the other; handshake fails.
    let host_disk = write_pki_to_disk(&host_pki);
    let rogue_disk = write_pki_to_disk(&rogue_pki);

    let sockdir = tempfile::tempdir().expect("sockdir");
    let echo_sock = sockdir.path().join("echo.sock");
    let vm_sock = sockdir.path().join("vm.sock");

    let echo_handle = tokio::spawn(run_echo_server(echo_sock.clone()));

    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let tcp_port = probe.local_addr().unwrap().port();
    drop(probe);

    let tcp_addr = format!("127.0.0.1:{tcp_port}");

    // host relay using host PKI.
    let mut host_proc = tokio::process::Command::new(bin_path("ember-relay-host"))
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--uds-target")
        .arg(&echo_sock)
        .arg("--cert")
        .arg(&host_disk.server_cert)
        .arg("--key")
        .arg(&host_disk.server_key)
        .arg("--ca")
        .arg(&host_disk.ca)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn host relay");

    // vm relay using rogue PKI (mismatched).
    let mut vm_proc = tokio::process::Command::new(bin_path("ember-relay-vm"))
        .arg("--uds-listen")
        .arg(&vm_sock)
        .arg("--tcp-target")
        .arg(&tcp_addr)
        .arg("--cert")
        .arg(&rogue_disk.client_cert)
        .arg("--key")
        .arg(&rogue_disk.client_key)
        .arg("--ca")
        .arg(&rogue_disk.ca)
        .arg("--claimed-persona")
        .arg("user-alpha")
        .arg("--server-name")
        .arg("127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vm relay");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !vm_sock.exists() {
        if std::time::Instant::now() > deadline {
            let _ = host_proc.kill().await;
            let _ = vm_proc.kill().await;
            panic!("vm-side relay never bound; can't run mismatched-ca test");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Try to send bytes. We expect EITHER:
    //   a) connect succeeds + write succeeds, but read times out / EOFs
    //      because the relay's onward TLS handshake to the host failed and
    //      the relay closed the AF_UNIX peer; OR
    //   b) connect fails outright.
    //
    // Test asserts no echoed bytes come back within a generous window.
    let result = timeout(Duration::from_secs(5), async {
        let mut client = match UnixStream::connect(&vm_sock).await {
            Ok(c) => c,
            Err(_) => return Err::<Vec<u8>, ()>(()),
        };
        if client.write_all(b"should-never-echo").await.is_err() {
            return Err(());
        }
        let _ = client.flush().await;
        let mut buf = vec![0u8; 22]; // "ECHO:should-never-echo"
        // If the handshake failed the relay will close the UDS peer; this
        // read either errors immediately or hangs (timeout catches the hang).
        match client.read_exact(&mut buf).await {
            Ok(_) => Ok(buf),
            Err(_) => Err(()),
        }
    })
    .await;

    let _ = host_proc.kill().await;
    let _ = vm_proc.kill().await;
    echo_handle.abort();

    match result {
        Ok(Ok(buf)) => panic!(
            "must not receive echo on mismatched CA, got: {:?}",
            String::from_utf8_lossy(&buf)
        ),
        Ok(Err(_)) => { /* connect/write/read errored — correct: relay closed peer */ }
        Err(_) => { /* timeout — correct: handshake never produced data */ }
    }
}
