//! Integration tests for `ember receipt verify --file <PATH>` (RECEIPT-VERIFY-FILE-MODE).
//!
//! Drives the real `ember` binary so the clap conflicts_with rule and the
//! filesystem error paths are both covered. The v2 dispatch path is covered
//! by `verify_v2_sidecar_succeeds` / `verify_v2_sidecar_tamper_fails`; the v1
//! regression is covered by `verify_v1_receipt_still_succeeds`.

use std::io::Write as _;
use std::process::{Command, Stdio};

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(ember_bin())
        .args(args)
        .output()
        .expect("spawn ember");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn verify_with_id_and_file_is_a_clap_conflict() {
    let (_stdout, stderr, code) =
        run(&["receipt", "verify", "abc123", "--file", "/tmp/whatever.json"]);
    assert_ne!(code, 0, "id + --file together must fail");
    let combined = stderr.to_lowercase();
    assert!(
        combined.contains("cannot be used") || combined.contains("conflict"),
        "expected clap conflict message, got stderr: {stderr}"
    );
}

#[test]
fn verify_file_with_nonexistent_path_errors() {
    let (_stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "--file",
        "/nonexistent-emberlink-receipt-9d2f1.json",
    ]);
    assert_ne!(code, 0, "missing file must fail");
    assert!(
        stderr.contains("cannot read") || stderr.contains("No such file"),
        "expected file-read error, got: {stderr}"
    );
}

#[test]
fn verify_file_with_garbage_json_errors() {
    let (_stdout, stderr, code) = {
        let mut child = Command::new(ember_bin())
            .args(["receipt", "verify", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ember");
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            stdin.write_all(b"this is not a receipt").expect("write stdin");
        }
        let out = child.wait_with_output().expect("wait ember");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    };
    assert_ne!(code, 0, "garbage JSON on stdin must fail");
    assert!(
        stderr.contains("Grant Receipt") || stderr.contains("not a valid"),
        "expected JSON-parse error, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// v2 dispatch tests (implementation-note-317)
// ---------------------------------------------------------------------------

/// Build a signed v2 ReceiptEnvelope using the deterministic FixtureSigner,
/// returning (envelope_json, pubkey_bare_hex).
fn make_signed_v2_receipt() -> (String, String) {
    use core_crypto::{FixtureSigner, Signer as _};
    use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use core_events::receipt::sign::sign_receipt_v2;

    let signer = FixtureSigner::new("receipt-v2-sign");
    let pk = signer.public_key();
    // pubkey_bare_hex: strip the "ed25519:" prefix that PublicKey wraps.
    let pubkey_bare_hex = pk.0.strip_prefix("ed25519:").unwrap().to_string();

    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: "session.claude_code".into(),
        receipt_id: String::new(),
        daemon_root_id: "root-verify-test".into(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: serde_json::json!({
            "session_id": "sess_verify_v2_test",
            "claim_events": [],
            "permits_merkle_root": ""
        }),
        signature: None,
    };
    sign_receipt_v2(&mut env, &signer).expect("sign");
    let json = serde_json::to_string_pretty(&env).expect("serialize");
    (json, pubkey_bare_hex)
}

#[test]
fn verify_v2_sidecar_succeeds() {
    let (json, pubkey_hex) = make_signed_v2_receipt();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("receipt-v2.json");
    std::fs::write(&path, json.as_bytes()).expect("write fixture");

    let (stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "--file",
        path.to_str().unwrap(),
        "--pubkey",
        &pubkey_hex,
    ]);
    assert_eq!(
        code, 0,
        "v2 sidecar with correct pubkey must succeed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Verified:"),
        "expected 'Verified:' in stdout, got: {stdout}"
    );
}

#[test]
fn verify_v2_sidecar_tamper_fails() {
    let (json, pubkey_hex) = make_signed_v2_receipt();

    // Parse and tamper with the body field.
    let mut v: serde_json::Value = serde_json::from_str(&json).expect("parse");
    v["body"]["session_id"] = serde_json::json!("tampered-session-id");
    let tampered = serde_json::to_string(&v).expect("serialize tampered");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("receipt-v2-tampered.json");
    std::fs::write(&path, tampered.as_bytes()).expect("write tampered");

    let (_stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "--file",
        path.to_str().unwrap(),
        "--pubkey",
        &pubkey_hex,
    ]);
    assert_ne!(code, 0, "tampered v2 receipt must fail verification");
    assert!(
        stderr.contains("FAILED") || stderr.contains("failed") || stderr.contains("mismatch"),
        "expected verification failure message, got: {stderr}"
    );
}

#[test]
fn verify_v1_receipt_still_succeeds() {
    use core_grant_types::grant_receipt::{Evidence, GrantReceipt, Lifecycle, ReceiptSummary, TerminalReason};
    use core_grant_types::AttestationBinding;
    use ember_daemon::infra::receipt::{DaemonPersona, canonical_hash, CANONICAL_VERSION};

    // Create a DaemonPersona in a temp dir for signing.
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = DaemonPersona::load_or_create(dir.path()).expect("persona");
    let pubkey_hex = identity.pubkey_hex();

    // Construct a minimal GrantReceipt (v1 shape — no version field on wire).
    let mut receipt = GrantReceipt {
        id: "rct_v1test0000000000000000001".into(),
        grant_id: "grt_v1test000000000000000001".into(),
        summary: ReceiptSummary {
            human_owner: "test-owner".into(),
            persona_id: "persona-test".into(),
            agent_id: "claude_code".into(),
            service: "github".into(),
            resource: "github-token".into(),
        },
        approved_chain: vec![],
        per_statement_usage: vec![],
        approval_chain: vec![],
        actions_observed: vec![],
        lifecycle: Lifecycle {
            issued_at: 1_700_000_000,
            last_used_at: None,
            terminated_at: 1_700_001_000,
            terminal_reason: TerminalReason::Expired,
        },
        attestation: AttestationBinding::default(),
        evidence: Evidence::default(),
    };

    // Sign it using the same path as the production daemon.
    let hash_hex = canonical_hash(&receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(&*sig_bytes),
        signer_pubkey: pubkey_hex.clone(),
        canonical_version: CANONICAL_VERSION,
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize v1");
    let path = dir.path().join("receipt-v1.json");
    std::fs::write(&path, json.as_bytes()).expect("write v1 fixture");

    let (stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "--file",
        path.to_str().unwrap(),
        "--pubkey",
        &pubkey_hex,
    ]);
    assert_eq!(
        code, 0,
        "v1 receipt with correct pubkey must succeed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Verified:"),
        "expected 'Verified:' in stdout, got: {stdout}"
    );
}
