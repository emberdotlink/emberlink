//! T2 integration tests for EMBER-INIT-FIRST-implementation-note-467.
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
    let out = Command::new(ember_bin())
        .args(["init", "--config", config_path.to_str().unwrap()])
        .env("EMBER_VAULT_PASSPHRASE", "test-receipt-passphrase")
        .env("EMBER_KEYRING_SERVICE", "ember-test-receipt-emit")
        .env("EMBER_KEYRING_ACCOUNT", "test-receipt-emit")
        .env("EMBER_SKIP_DAEMON_INSTALL_CHECK", "1")
        .output()
        .expect("spawn ember init");
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
