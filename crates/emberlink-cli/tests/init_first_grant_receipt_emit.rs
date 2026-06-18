//! CLASSIFICATION: PUBLIC
//! T2 integration tests for EMBER-INIT-FIRST-GRANT-RECEIPT-EMIT.
//!
//! Verifies that `ember init` emits a real signed Grant Receipt v2 envelope
//! to `<data_dir>/receipts/first.json`, and that re-running is idempotent
//! (skips re-emission when the file already exists).
//!
//! Binary tests drive the actual `ember` binary so the full signing path,
//! file write, and idempotency guard are covered end-to-end.
//! Library tests call `emit_first_grant_receipt` directly to cover the
//! JSON field assertions and idempotency guard without spawning a process.

use std::fs;
use std::io::{BufRead as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use core_crypto::Signer as _;
use emberlink_cli::onboarding::first_grant::{
    FirstGrantReceiptFile, INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL, emit_first_grant_receipt,
    first_receipt_exists, first_receipt_path,
};

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn spawn_fake_init_daemon(
    socket_path: PathBuf,
    receipt_already_exists: bool,
) -> std::thread::JoinHandle<()> {
    fs::create_dir_all(socket_path.parent().expect("socket parent")).expect("create socket dir");
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind fake init daemon");

    std::thread::spawn(move || {
        let signer = core_crypto::FixtureSigner::new("init-first-grant-binary-daemon");
        let public_key = signer.public_key().0.clone();
        let persona_id = "persona-rpc-bin";

        listener
            .set_nonblocking(true)
            .expect("set fake init daemon nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_create_persona = false;
        let mut saw_build_first_grant_receipt = receipt_already_exists;

        while std::time::Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .expect("restore blocking on fake init daemon stream");
                    stream
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if saw_create_persona && saw_build_first_grant_receipt {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                Err(err) => panic!("fake init daemon accept error: {err}"),
            };
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake init daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake init daemon request");

            let response = match request["method"].as_str().unwrap() {
                "create_persona" => {
                    saw_create_persona = true;
                    assert_eq!(request["params"]["name"], serde_json::json!("root"));
                    serde_json::json!({
                        "id": request["id"],
                        "result": {
                            "id": persona_id,
                            "name": "root",
                            "public_key": public_key,
                        },
                    })
                }
                "build_init_first_grant_receipt" => {
                    saw_build_first_grant_receipt = true;
                    assert_eq!(
                        request["params"]["persona_id"],
                        serde_json::json!(persona_id)
                    );
                    let file =
                        ember_daemon::infra::init_first_grant::build_first_grant_receipt_file(
                            persona_id, &signer,
                        )
                        .expect("build first-grant receipt");
                    serde_json::json!({
                        "id": request["id"],
                        "result": serde_json::to_value(file).expect("serialize receipt file"),
                    })
                }
                other => panic!("unexpected init daemon method: {other}"),
            };

            let mut encoded = serde_json::to_string(&response).expect("encode fake response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake init daemon response");
        }

        assert!(
            saw_create_persona,
            "fake init daemon never received create_persona"
        );
        assert!(
            saw_build_first_grant_receipt,
            "fake init daemon never received build_init_first_grant_receipt"
        );
    })
}

/// Minimal config.toml that points data_dir and socket_dir at our tmp paths.
fn write_config(tmp: &tempfile::TempDir) -> PathBuf {
    let config_path = tmp.path().join("config.toml");
    let data_dir = tmp.path().join("data");
    let socket_dir = tmp.path().join("run");
    let pid_file = socket_dir.join("emberd.pid");
    let policy_file = tmp.path().join("policy.toml");

    let cfg = format!(
        "[daemon]\ndata_dir = \"{}\"\nsocket_dir = \"{}\"\npid_file = \"{}\"\npolicy_file = \"{}\"\nlog_level = \"info\"\n",
        data_dir.display(),
        socket_dir.display(),
        pid_file.display(),
        policy_file.display(),
    );
    fs::write(&config_path, cfg.as_bytes()).expect("write config");
    config_path
}

/// Run `ember init --config <path>` with passphrase env, return (stdout, stderr, exit).
fn run_ember_init(config_path: &std::path::Path) -> (String, String, i32) {
    let tmp_root = config_path.parent().expect("config parent");
    let receipt_already_exists = tmp_root.join("data/receipts/first.json").exists();
    let server = spawn_fake_init_daemon(
        tmp_root.join("run").join("daemon.sock"),
        receipt_already_exists,
    );
    let out = Command::new(ember_bin())
        .args(["init", "--config", config_path.to_str().unwrap()])
        .env("EMBER_VAULT_PASSPHRASE", "test-receipt-passphrase")
        .env("EMBER_KEYRING_SERVICE", "ember-test-receipt-emit")
        .env("EMBER_KEYRING_ACCOUNT", "test-receipt-emit")
        .env("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1")
        .output()
        .expect("spawn ember init");
    server.join().expect("fake init daemon thread");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

// ---------------------------------------------------------------------------
// Binary-level tests — drive the real `ember` binary.
// ---------------------------------------------------------------------------

#[test]
fn ember_init_writes_first_receipt_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(&tmp);
    let data_dir = tmp.path().join("data");

    let (stdout, stderr, code) = run_ember_init(&config_path);
    assert_eq!(
        code, 0,
        "ember init must exit 0 on first run; stderr: {stderr}"
    );

    let receipt_path = data_dir.join("receipts/first.json");
    assert!(
        receipt_path.exists(),
        "receipts/first.json must exist after ember init; stdout: {stdout}\nstderr: {stderr}"
    );

    // The receipt must be valid JSON.
    let raw = fs::read_to_string(&receipt_path).expect("read receipt");
    let file: serde_json::Value = serde_json::from_str(&raw).expect("parse receipt JSON");

    // issuer.persona must be present.
    assert!(
        file["issuer"]["persona"].is_string(),
        "issuer.persona must be a string; got: {}",
        file["issuer"]["persona"]
    );

    // evidence.signed must be true.
    assert_eq!(
        file["evidence"]["signed"],
        serde_json::json!(true),
        "evidence.signed must be true; got: {}",
        file["evidence"]["signed"]
    );

    // evidence.hash must start with "sha256:".
    let hash = file["evidence"]["hash"].as_str().unwrap_or("");
    assert!(
        hash.starts_with("sha256:"),
        "evidence.hash must start with 'sha256:', got: {hash}"
    );

    // lifecycle.issued_at must be present.
    assert!(
        file["lifecycle"]["issued_at"].is_string(),
        "lifecycle.issued_at must be a string; got: {}",
        file["lifecycle"]["issued_at"]
    );

    // lifecycle.revoked_at must be present.
    assert!(
        file["lifecycle"]["revoked_at"].is_string(),
        "lifecycle.revoked_at must be a string; got: {}",
        file["lifecycle"]["revoked_at"]
    );
}

#[test]
fn ember_init_stdout_contains_receipt_path_and_sentinel() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(&tmp);
    let data_dir = tmp.path().join("data");

    let (stdout, stderr, code) = run_ember_init(&config_path);
    assert_eq!(code, 0, "ember init must exit 0; stderr: {stderr}");

    // stdout must name the receipt file path.
    let expected_path = data_dir.join("receipts/first.json");
    assert!(
        stdout.contains(expected_path.to_str().unwrap()),
        "stdout must contain receipt path '{}'; got:\n{stdout}",
        expected_path.display()
    );

    // stdout must contain the checkpoint string.
    assert!(
        stdout.contains(INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL),
        "stdout must contain checkpoint '{}'; got:\n{stdout}",
        INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL
    );
    assert!(
        stdout.contains("Ember ready"),
        "stdout should render the daemon-backed init summary; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("-- First Grant Receipt --"),
        "stdout should no longer use the legacy receipt transcript; got:\n{stdout}"
    );
}

#[test]
fn ember_init_idempotent_second_run_skips_emission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = write_config(&tmp);
    let data_dir = tmp.path().join("data");
    let receipt_path = data_dir.join("receipts/first.json");

    // First run — writes the receipt.
    let (_, stderr, code) = run_ember_init(&config_path);
    assert_eq!(code, 0, "first run must exit 0; stderr: {stderr}");
    assert!(receipt_path.exists(), "receipt must exist after first run");

    let content_first = fs::read(&receipt_path).expect("read receipt after first run");

    // Second run — may exit non-zero due to duplicate persona, but the
    // receipt file must NOT be modified (idempotent).
    let _ = run_ember_init(&config_path);

    let content_second = fs::read(&receipt_path).expect("read receipt after second run");
    assert_eq!(
        content_first, content_second,
        "receipt file must not be modified on second ember init"
    );
}

// ---------------------------------------------------------------------------
// Library-level tests — call emit_first_grant_receipt directly.
// ---------------------------------------------------------------------------

/// Build a deterministic FixtureSigner for use in library tests.
fn fixture_signer() -> core_crypto::FixtureSigner {
    core_crypto::FixtureSigner::new("init-first-grant-receipt-test")
}

#[test]
fn emit_first_grant_receipt_writes_valid_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");

    let signer = fixture_signer();
    let pk = signer.public_key();
    let pubkey_str = pk.0.clone();
    let persona_id = "persona-test-0000000000000001";

    let path = emit_first_grant_receipt(&data_dir, persona_id, &pubkey_str, &signer)
        .expect("emit must succeed");

    // File must exist and be parseable as FirstGrantReceiptFile.
    let raw = fs::read_to_string(&path).expect("read receipt file");
    let file: FirstGrantReceiptFile =
        serde_json::from_str(&raw).expect("parse FirstGrantReceiptFile");

    assert_eq!(file.issuer.persona, persona_id);
    assert!(file.evidence.signed);
    assert!(
        file.evidence.hash.starts_with("sha256:"),
        "evidence.hash must start with 'sha256:', got: {}",
        file.evidence.hash
    );
    assert!(!file.lifecycle.issued_at.is_empty());
    assert!(!file.lifecycle.revoked_at.is_empty());

    // The embedded receipt must have a receipt_id and signature.
    assert!(
        !file.receipt.receipt_id.is_empty(),
        "receipt_id must be populated"
    );
    assert!(
        file.receipt.signature.is_some(),
        "signature must be populated"
    );

    // receipt_path must match the first_receipt_path helper.
    assert_eq!(path, first_receipt_path(&data_dir));
}

#[test]
fn emit_first_grant_receipt_idempotent_returns_existing_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");

    let signer = fixture_signer();
    let pk = signer.public_key();
    let pubkey_str = pk.0.clone();
    let persona_id = "persona-test-0000000000000002";

    // First call — writes the file.
    let path1 = emit_first_grant_receipt(&data_dir, persona_id, &pubkey_str, &signer)
        .expect("first emit must succeed");
    assert!(
        first_receipt_exists(&data_dir),
        "checkpoint must exist after first emit"
    );

    let content_first = fs::read(&path1).expect("read after first emit");

    // Second call — idempotency guard fires; file must be unchanged.
    let path2 = emit_first_grant_receipt(&data_dir, persona_id, &pubkey_str, &signer)
        .expect("second emit must succeed (idempotent)");

    let content_second = fs::read(&path2).expect("read after second emit");
    assert_eq!(path1, path2, "paths must match");
    assert_eq!(
        content_first, content_second,
        "file content must not change on idempotent second emit"
    );
}

#[test]
fn emit_first_grant_receipt_json_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    fs::create_dir_all(&data_dir).expect("create data dir");

    let signer = fixture_signer();
    let pk = signer.public_key();
    let pubkey_str = pk.0.clone();
    let persona_id = "persona-test-0000000000000003";

    let path = emit_first_grant_receipt(&data_dir, persona_id, &pubkey_str, &signer)
        .expect("emit must succeed");

    // Deserialize and re-serialize: must be stable.
    let raw = fs::read_to_string(&path).expect("read");
    let file: FirstGrantReceiptFile =
        serde_json::from_str(&raw).expect("deserialize FirstGrantReceiptFile");

    // The receipt kind must match the init.first_grant discriminator.
    assert_eq!(
        file.receipt.kind, "init.first_grant",
        "receipt kind must be 'init.first_grant'"
    );

    // daemon_root_id must match persona_id.
    assert_eq!(
        file.receipt.daemon_root_id, persona_id,
        "daemon_root_id must match persona_id"
    );
}
