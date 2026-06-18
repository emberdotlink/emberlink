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
    let home = tempfile::tempdir().expect("home tempdir");
    let out = Command::new(ember_bin())
        .env("HOME", home.path())
        .env_remove("EMBER_CONFIG")
        .env_remove("EMBER_DEMO_DIR")
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
    let (_stdout, stderr, code) = run(&[
        "receipt",
        "verify",
        "abc123",
        "--file",
        "/tmp/whatever.json",
    ]);
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
    let home = tempfile::tempdir().expect("home tempdir");
    let (_stdout, stderr, code) = {
        let mut child = Command::new(ember_bin())
            .env("HOME", home.path())
            .env_remove("EMBER_CONFIG")
            .env_remove("EMBER_DEMO_DIR")
            .args(["receipt", "verify", "--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ember");
        {
            let stdin = child.stdin.as_mut().expect("stdin");
            stdin
                .write_all(b"this is not a receipt")
                .expect("write stdin");
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
// v2 dispatch tests (COHORT-A-V03-T3-FIX-RECEIPT-VERIFY-V2)
// ---------------------------------------------------------------------------

/// Build a signed v2 ReceiptEnvelope using the deterministic FixtureSigner,
/// returning (envelope_json, pubkey_bare_hex).
fn make_signed_v2_receipt_with_body(body: serde_json::Value) -> (String, String) {
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
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut env, &signer).expect("sign");
    let json = serde_json::to_string_pretty(&env).expect("serialize");
    (json, pubkey_bare_hex)
}

fn make_signed_v2_receipt() -> (String, String) {
    make_signed_v2_receipt_with_body(serde_json::json!({
        "session_id": "sess_verify_v2_test",
        "claim_events": [],
        "permits_merkle_root": ""
    }))
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
fn verify_v2_non_clean_termination_sidecars_cover_happy_and_tamper() {
    let cases = [
        (
            "heartbeat_lost",
            serde_json::json!({
                "session_id": "sess_verify_v2_heartbeat_lost",
                "claim_events": [],
                "permits_merkle_root": "",
                "termination_reason": "heartbeat_lost",
                "last_heartbeat_at": "2026-05-27T08:00:00Z",
                "pid_alive_at_check": false
            }),
            "last_heartbeat_at",
            serde_json::json!("1970-01-01T00:00:00Z"),
        ),
        (
            "ttl_expired",
            serde_json::json!({
                "session_id": "sess_verify_v2_ttl_expired",
                "claim_events": [],
                "permits_merkle_root": "",
                "termination_reason": "ttl_expired"
            }),
            "termination_reason",
            serde_json::json!("clean_exit"),
        ),
        (
            "explicit_revoke",
            serde_json::json!({
                "session_id": "sess_verify_v2_explicit_revoke",
                "claim_events": [],
                "permits_merkle_root": "",
                "termination_reason": "explicit_revoke"
            }),
            "termination_reason",
            serde_json::json!("clean_exit"),
        ),
    ];

    for (reason, body, tamper_field, tamper_value) in cases {
        let (json, pubkey_hex) = make_signed_v2_receipt_with_body(body);
        let dir = tempfile::tempdir().expect("tempdir");
        let happy_path = dir.path().join(format!("receipt-v2-{reason}.json"));
        std::fs::write(&happy_path, json.as_bytes()).expect("write fixture");

        let (stdout, stderr, code) = run(&[
            "receipt",
            "verify",
            "--file",
            happy_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ]);
        assert_eq!(
            code, 0,
            "{reason}: v2 sidecar must verify; stderr: {stderr}"
        );
        assert!(
            stdout.contains("Verified:"),
            "{reason}: expected 'Verified:' in stdout, got: {stdout}"
        );

        let mut v: serde_json::Value = serde_json::from_str(&json).expect("parse signed receipt");
        v["body"][tamper_field] = tamper_value;
        let tampered_path = dir
            .path()
            .join(format!("receipt-v2-{reason}-tampered.json"));
        std::fs::write(&tampered_path, serde_json::to_vec_pretty(&v).unwrap())
            .expect("write tampered fixture");

        let (_stdout, stderr, code) = run(&[
            "receipt",
            "verify",
            "--file",
            tampered_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ]);
        assert_ne!(code, 0, "{reason}: tampered v2 receipt must fail");
        assert!(
            stderr.contains("receipt_id mismatch"),
            "{reason}: expected receipt_id mismatch from canonical verifier, got: {stderr}"
        );
    }
}

#[test]
fn verify_v1_receipt_still_succeeds() {
    use core_grant_types::AttestationBinding;
    use core_grant_types::grant_receipt::{
        Evidence, GrantReceipt, Lifecycle, ReceiptSummary, TerminalReason,
    };
    use ember_daemon::infra::receipt::{CANONICAL_VERSION, DaemonPersona, canonical_hash};

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
        dev_mode_active: false,
        evidence: Evidence::default(),
    };

    // Sign it using the same path as the production daemon.
    let hash_hex = canonical_hash(&receipt);
    let sig_bytes = identity.sign(hash_hex.as_bytes());
    receipt.evidence = Evidence {
        hash: hash_hex,
        sig: hex::encode(*sig_bytes),
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
