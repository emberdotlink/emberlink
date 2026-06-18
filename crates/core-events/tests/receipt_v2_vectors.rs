//! Receipt v2 cross-implementation golden test vectors.
//!
//! These fixtures lock JCS+blake3+Ed25519 determinism. A TS or Python verifier
//! that loads any fixture here MUST recompute identical receipt_id + signature.
//!
//! Regenerate (e.g. after a body schema change):
//!     cargo run --example regen_receipt_v2_fixtures -p core-events
//!
//! When `EMBER_RECEIPT_V2_REGEN=1` is set, each test prints the canonical JSON
//! envelope to stderr — useful when copying bytes back into the fixture file
//! during a manual regen.

use core_crypto::{FixtureSigner, FixtureVerifier, Signer};
use core_events::receipt::atomic::{
    BindingBody, BrokerMintBody, RECEIPT_KIND_BINDING_REGISTERED, RECEIPT_KIND_BROKER_MINT,
};
use core_events::receipt::body::{ClaimEvent, ClaimKind, ReceiptBody};
use core_events::receipt::cohort_a::{ClaudeCodeBody, RECEIPT_KIND_CLAUDE_CODE};
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::{compute_receipt_id, sign_receipt_v2, verify_receipt_v2};

fn deterministic_envelope_broker_mint() -> ReceiptEnvelope {
    let body = BrokerMintBody {
        vault_key: "anthropic-key".to_string(),
        scope_template_id: "tier0-default".to_string(),
        scope_resolved: vec!["llm:generate".to_string(), "credential:read".to_string()],
        ttl_seconds: 1800,
        expires_at: "2026-05-02T20:00:00Z".to_string(),
        revoke_token_hash: "blake3:fixture-revoke".to_string(),
        // BKR-5 scope-projection fields unset: skip-when-empty keeps this golden
        // vector byte-identical (receipt_id + signature unchanged).
        granted_scope: vec![],
        requested_scope: vec![],
        minted_scope: vec![],
        mint_stamp: vec![],
        mint_stamp_kind: None,
        chain_ref: String::new(),
    };
    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_BROKER_MINT.to_string(),
        receipt_id: String::new(),
        daemon_root_id: "fixture-daemon-root".to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::UserSession,
        presence_kind: None,
        body: serde_json::to_value(&body).unwrap(),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    let signer = FixtureSigner::new("receipt-v2-vector-broker-mint");
    sign_receipt_v2(&mut env, &signer).unwrap();
    env
}

fn deterministic_envelope_binding_registered() -> ReceiptEnvelope {
    let body = BindingBody {
        namespace: "ns-prod".to_string(),
        sa_name: "ml-eval".to_string(),
        persona_id: "persona-fixture".to_string(),
        persona_display_name: "ML Eval Worker".to_string(),
        scopes_granted: vec!["llm:generate".to_string()],
        binding_request_id: "br-fixture-001".to_string(),
    };
    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_BINDING_REGISTERED.to_string(),
        receipt_id: String::new(),
        daemon_root_id: "fixture-daemon-root".to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::UserSession,
        presence_kind: None,
        body: serde_json::to_value(&body).unwrap(),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    let signer = FixtureSigner::new("receipt-v2-vector-binding-registered");
    sign_receipt_v2(&mut env, &signer).unwrap();
    env
}

fn deterministic_envelope_session_claude_code() -> ReceiptEnvelope {
    let body = ClaudeCodeBody {
        base: ReceiptBody {
            claim_events: vec![ClaimEvent {
                ts: "2026-05-02T19:30:00Z".to_string(),
                kind: ClaimKind::Approval,
                tool: "Bash".to_string(),
                action_ref: None,
                input_hash: "blake3:fixture-input-hash".to_string(),
                input_redacted: serde_json::json!({"command": "echo hi"}),
                resolved: serde_json::json!({"allowed": true}),
            }],
            permits_merkle_root: "blake3:fixture-merkle-root".to_string(),
            device_id: Some("device-fixture".to_string()),
            ..Default::default()
        },
        audit_gaps: vec![],
        termination_reason: None,
        last_heartbeat_at: None,
        pid_alive_at_check: None,
    };
    let mut env = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_CLAUDE_CODE.to_string(),
        receipt_id: String::new(),
        daemon_root_id: "fixture-daemon-root".to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::UserSession,
        presence_kind: None,
        body: serde_json::to_value(&body).unwrap(),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    let signer = FixtureSigner::new("receipt-v2-vector-session-claude-code");
    sign_receipt_v2(&mut env, &signer).unwrap();
    env
}

fn maybe_print_regen(label: &str, env: &ReceiptEnvelope) {
    if std::env::var("EMBER_RECEIPT_V2_REGEN").is_ok() {
        let json = serde_json::to_string_pretty(env).unwrap();
        eprintln!("\n=== {label} ===\n{json}\n");
    }
}

#[test]
fn broker_mint_vector_determinism() {
    let env = deterministic_envelope_broker_mint();
    let recomputed_id = compute_receipt_id(&env).unwrap();
    assert_eq!(
        recomputed_id, env.receipt_id,
        "receipt_id JCS+blake3 determinism"
    );

    let signer = FixtureSigner::new("receipt-v2-vector-broker-mint");
    let pk = signer.public_key();
    verify_receipt_v2(&env, &pk, &FixtureVerifier).expect("signature determinism");

    maybe_print_regen("broker_mint.json", &env);

    let stored: ReceiptEnvelope =
        serde_json::from_str(include_str!("fixtures/receipt_v2/broker_mint.json")).unwrap();
    assert_eq!(
        stored.receipt_id, env.receipt_id,
        "fixture receipt_id matches re-run"
    );
    assert_eq!(
        stored.signature, env.signature,
        "fixture signature matches re-run"
    );
    assert_eq!(stored.kind, env.kind);
    assert_eq!(stored.body, env.body);
    assert_eq!(stored.daemon_root_id, env.daemon_root_id);
    assert_eq!(stored.version, env.version);
    verify_receipt_v2(&stored, &pk, &FixtureVerifier).expect("stored fixture verifies");
}

#[test]
fn binding_registered_vector_determinism() {
    let env = deterministic_envelope_binding_registered();
    let recomputed_id = compute_receipt_id(&env).unwrap();
    assert_eq!(recomputed_id, env.receipt_id);

    let signer = FixtureSigner::new("receipt-v2-vector-binding-registered");
    let pk = signer.public_key();
    verify_receipt_v2(&env, &pk, &FixtureVerifier).expect("signature determinism");

    maybe_print_regen("binding_registered.json", &env);

    let stored: ReceiptEnvelope =
        serde_json::from_str(include_str!("fixtures/receipt_v2/binding_registered.json")).unwrap();
    assert_eq!(stored.receipt_id, env.receipt_id);
    assert_eq!(stored.signature, env.signature);
    assert_eq!(stored.kind, env.kind);
    assert_eq!(stored.body, env.body);
    verify_receipt_v2(&stored, &pk, &FixtureVerifier).expect("stored fixture verifies");
}

#[test]
fn session_claude_code_vector_determinism() {
    let env = deterministic_envelope_session_claude_code();
    let recomputed_id = compute_receipt_id(&env).unwrap();
    assert_eq!(recomputed_id, env.receipt_id);

    let signer = FixtureSigner::new("receipt-v2-vector-session-claude-code");
    let pk = signer.public_key();
    verify_receipt_v2(&env, &pk, &FixtureVerifier).expect("signature determinism");

    maybe_print_regen("session_claude_code.json", &env);

    let stored: ReceiptEnvelope =
        serde_json::from_str(include_str!("fixtures/receipt_v2/session_claude_code.json")).unwrap();
    assert_eq!(stored.receipt_id, env.receipt_id);
    assert_eq!(stored.signature, env.signature);
    assert_eq!(stored.kind, env.kind);
    assert_eq!(stored.body, env.body);
    verify_receipt_v2(&stored, &pk, &FixtureVerifier).expect("stored fixture verifies");
}
