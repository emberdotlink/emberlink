//! Integration tests for `ember receipt verify --file <PATH> --offline` walking
//! the local rotation-witness chain (META-AP-DAEMON-MEK-PERSISTENCE-E-4).
//!
//! Anchor: `ember_receipt_verify_walks_rotation_chain`.
//!
//! T2 tier per `.claude/rules/app-crates.md`: drives the real `ember` binary,
//! uses a tempdir for HOME + `--events <PATH>` so no daemon socket is needed
//! and no real keychain is touched. The synthetic chain is built off
//! `FixtureSigner` so the test is fully deterministic.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use core_crypto::{FixtureSigner, Signer as _};
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::sign_receipt_v2;
use serde_json::json;

fn ember_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ember")
}

fn run_with_home(home: &Path, args: &[&str]) -> (String, String, i32) {
    let out = Command::new(ember_bin())
        .env("HOME", home)
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

/// Build a single rotation witness Receipt envelope bridging `prev_id` →
/// `next_id`. The body carries the advisory pubkey hints (`prev_identity_pub`
/// / `new_identity_pub`) that the CLI loader uses until Slice E2 wires
/// daemon-vault pubkey resolution.
fn witness_envelope(
    prior_signer: &FixtureSigner,
    new_signer: &FixtureSigner,
    prev_id: &str,
    next_id: &str,
    rotated_at: u64,
) -> ReceiptEnvelope {
    let body = json!({
        "prev_epoch_root_id": prev_id,
        "next_epoch_root_id": next_id,
        "rotated_at_epoch_secs": rotated_at,
        "signature_by_prev_root": "ed25519sig:00",
        "signature_by_next_root": "ed25519sig:01",
        "prev_identity_pub": prior_signer.public_key().0,
        "new_identity_pub": new_signer.public_key().0,
    });
    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
        receipt_id: String::new(),
        daemon_root_id: prev_id.to_string(),
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
    sign_receipt_v2(&mut env, prior_signer).expect("sign witness");
    env
}

fn append_jsonl(path: &Path, env: &ReceiptEnvelope) {
    let line = serde_json::to_string(env).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(f, "{line}").unwrap();
}

/// Sign a target receipt under `signer` and return (json, pubkey_bare_hex).
fn make_target_signed_by(signer: &FixtureSigner) -> String {
    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: "session.claude_code".into(),
        receipt_id: String::new(),
        daemon_root_id: "target-epoch".into(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: json!({
            "session_id": "sess_rotation_test",
            "claim_events": [],
            "permits_merkle_root": ""
        }),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut env, signer).expect("sign target");
    serde_json::to_string_pretty(&env).expect("serialize target")
}

#[test]
fn verify_offline_walks_three_epoch_chain_to_anchor() {
    // ember_receipt_verify_walks_rotation_chain — happy path:
    // anchor=epoch0, target signed by epoch2, two witness hops in
    // local store. Offline verify must succeed and name chain depth + span.
    let home = tempfile::tempdir().expect("home tempdir");
    let events = home.path().join("events.jsonl");

    let s0 = FixtureSigner::new("rc-int-e0");
    let s1 = FixtureSigner::new("rc-int-e1");
    let s2 = FixtureSigner::new("rc-int-e2");

    append_jsonl(
        &events,
        &witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 1_700_000_000),
    );
    append_jsonl(
        &events,
        &witness_envelope(&s1, &s2, "epoch-1", "epoch-2", 1_700_000_500),
    );

    let target_json = make_target_signed_by(&s2);
    let target_path = home.path().join("target.json");
    std::fs::write(&target_path, target_json.as_bytes()).expect("write target");

    let anchor_pubkey_hex = s0.public_key().0.strip_prefix("ed25519:").unwrap().to_string();

    let (stdout, stderr, code) = run_with_home(
        home.path(),
        &[
            "receipt",
            "verify",
            "--file",
            target_path.to_str().unwrap(),
            "--pubkey",
            &anchor_pubkey_hex,
            "--events",
            events.to_str().unwrap(),
            "--offline",
        ],
    );
    assert_eq!(
        code, 0,
        "offline rotation-chain verify should succeed; stderr: {stderr}; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Verified:"),
        "expected Verified line in stdout: {stdout}"
    );
    assert!(
        stdout.contains("via 2 rotation(s)"),
        "expected chain depth 2 in stdout: {stdout}"
    );
    assert!(
        stdout.contains('→') || stdout.contains("->"),
        "expected iso timespan separator in stdout: {stdout}"
    );
}

#[test]
fn verify_offline_missing_witness_reports_untrusted_signer() {
    // Negative case: target signed by epoch-2 but the local store only
    // contains the epoch-0→epoch-1 witness. The walker must fail with
    // UntrustedSigner; the CLI must surface the "missing rotation witness"
    // CTA and exit non-zero.
    let home = tempfile::tempdir().expect("home tempdir");
    let events = home.path().join("events.jsonl");

    let s0 = FixtureSigner::new("rc-int-missing-e0");
    let s1 = FixtureSigner::new("rc-int-missing-e1");
    let s2 = FixtureSigner::new("rc-int-missing-e2");

    // Only the first hop is in the store. The second hop (epoch1 → epoch2)
    // is intentionally absent.
    append_jsonl(
        &events,
        &witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 1_700_000_000),
    );

    let target_json = make_target_signed_by(&s2);
    let target_path = home.path().join("target.json");
    std::fs::write(&target_path, target_json.as_bytes()).expect("write target");

    let anchor_pubkey_hex = s0.public_key().0.strip_prefix("ed25519:").unwrap().to_string();

    let (_stdout, stderr, code) = run_with_home(
        home.path(),
        &[
            "receipt",
            "verify",
            "--file",
            target_path.to_str().unwrap(),
            "--pubkey",
            &anchor_pubkey_hex,
            "--events",
            events.to_str().unwrap(),
            "--offline",
        ],
    );
    assert_ne!(code, 0, "missing-witness chain must exit non-zero");
    assert!(
        stderr.contains("missing rotation witness"),
        "expected 'missing rotation witness' CTA, got: {stderr}"
    );
    assert!(
        stderr.contains("CTA:"),
        "expected CTA marker in error, got: {stderr}"
    );
    // Silence unused-import warnings — the test reaches Signer for the
    // FixtureSigner closure path via the rotation_chain module.
    let _ = FixtureSigner::new("noop").sign(b"x");
}

#[test]
fn verify_offline_broken_chain_reports_distinct_error() {
    // Tamper a witness envelope body after signing — the walker must
    // surface BrokenChain (not UntrustedSigner). The CLI's failure
    // formatter must include "failed signature check" and a CTA.
    let home = tempfile::tempdir().expect("home tempdir");
    let events = home.path().join("events.jsonl");

    let s0 = FixtureSigner::new("rc-int-broken-e0");
    let s1 = FixtureSigner::new("rc-int-broken-e1");
    let s2 = FixtureSigner::new("rc-int-broken-e2");

    let w0 = witness_envelope(&s0, &s1, "epoch-0", "epoch-1", 1_700_000_000);
    let mut w1 = witness_envelope(&s1, &s2, "epoch-1", "epoch-2", 1_700_000_500);
    // Tamper the witness body — the embedded signature no longer matches
    // the canonical bytes, so the walker's per-witness verify_receipt_v2
    // call fails inside the loop → BrokenChain.
    if let Some(map) = w1.body.as_object_mut() {
        map.insert("rotation_reason".to_string(), json!("tampered"));
    }
    append_jsonl(&events, &w0);
    append_jsonl(&events, &w1);

    let target_json = make_target_signed_by(&s2);
    let target_path = home.path().join("target.json");
    std::fs::write(&target_path, target_json.as_bytes()).expect("write target");

    let anchor_pubkey_hex = s0.public_key().0.strip_prefix("ed25519:").unwrap().to_string();

    let (_stdout, stderr, code) = run_with_home(
        home.path(),
        &[
            "receipt",
            "verify",
            "--file",
            target_path.to_str().unwrap(),
            "--pubkey",
            &anchor_pubkey_hex,
            "--events",
            events.to_str().unwrap(),
            "--offline",
        ],
    );
    assert_ne!(code, 0, "broken chain must exit non-zero");
    assert!(
        stderr.contains("broken chain") || stderr.contains("Broken chain"),
        "expected broken-chain wording, got: {stderr}"
    );
    assert!(
        stderr.contains("failed signature check"),
        "expected 'failed signature check' phrase, got: {stderr}"
    );
    assert!(
        stderr.contains("CTA:"),
        "expected CTA in broken-chain error, got: {stderr}"
    );
}
