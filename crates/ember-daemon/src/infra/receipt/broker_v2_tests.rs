//! Phase A substrate tests for v2 broker envelope builders +
//! `store_broker_receipt_v2` (SCION-FOUNDATION-BROKER-RECEIPT-V2-MIGRATE).

use super::*;
use crate::infra::store::DaemonStore;
use core_broker::BrokerProvider;
use core_crypto::{FixtureSigner, FixtureVerifier, Signer as _};
use core_events::receipt::sign::{sign_receipt_v2, verify_receipt_v2};

// NOTE (ADR 205 §B.6, BKR-5 C2): there is no `build_broker_materialization_envelope`
// and no materialization-envelope test — a materialization is an AUDIT event,
// not a Receipt (the daemon is the sole witness of its own mint, so a self-
// signature earns no root-verifiability). The materialization record is the
// hash-chained audit row asserted in `broker::handler` tests; the surviving
// signed broker receipt is revocation, covered below.

#[test]
fn build_revocation_envelope_has_v2_shape() {
    let summary = crate::broker::handler::MaterializationSummary {
        materialization_id: "mat-revoked-1".to_string(),
        provider: BrokerProvider::Anthropic,
        issued_at: "2026-05-26T00:00:00Z".to_string(),
        expires_at: "2026-05-26T01:00:00Z".to_string(),
        reason: "revoked for test".to_string(),
        contract_id: Some("contract-fixture".to_string()),
        action_ref: Some(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "gh.pr_create",
            "v1",
        )),
        workspace_ref: Some("managed_worktree:fixture".to_string()),
        subject_ref: Some("forge:run:fixture".to_string()),
        coordination_ref: Some("forge:workflow_event:fixture".to_string()),
        caller_ref: Some("persona:fixture".to_string()),
        authority_ref: Some("grant:fixture".to_string()),
    };
    let env = build_broker_revocation_envelope(
        "mat-revoked-1",
        Some(&summary),
        "daemon-root-test",
        false,
    );
    assert_eq!(env.kind, RECEIPT_KIND_BROKER_REVOCATION);
    assert_eq!(env.kind, "broker.revocation");
    assert_eq!(env.daemon_root_id, "daemon-root-test");
    assert!(matches!(
        env.termination_authority,
        TerminationAuthority::DaemonPersona
    ));
    assert_eq!(
        env.body.get("provider").and_then(|v| v.as_str()),
        Some(BrokerProvider::Anthropic.as_str())
    );
    assert_eq!(
        env.body.get("materialization_id").and_then(|v| v.as_str()),
        Some("mat-revoked-1")
    );
    assert_eq!(
        env.body.get("contract_id").and_then(|v| v.as_str()),
        Some("contract-fixture")
    );
    assert_eq!(
        env.body
            .get("action_ref")
            .and_then(|v| v.get("action_key"))
            .and_then(|v| v.as_str()),
        Some("gh.pr_create")
    );
    assert_eq!(
        env.body.get("workspace_ref").and_then(|v| v.as_str()),
        Some("managed_worktree:fixture")
    );
    assert_eq!(
        env.body.get("subject_ref").and_then(|v| v.as_str()),
        Some("forge:run:fixture")
    );
    assert_eq!(
        env.body.get("coordination_ref").and_then(|v| v.as_str()),
        Some("forge:workflow_event:fixture")
    );
    assert_eq!(
        env.body.get("mock_broker").and_then(|v| v.as_bool()),
        Some(false),
        "real-broker revocation envelope must stamp mock_broker: false"
    );
}

/// META-DEV-PROD-PARITY-MOCK-BROKER-EXPLICIT: revocation receipt also
/// carries the mock_broker stamp.
#[test]
fn build_revocation_envelope_stamps_mock_broker_true() {
    let env = build_broker_revocation_envelope("mat-revoked-mock", None, "daemon-root", true);
    assert_eq!(
        env.body.get("mock_broker").and_then(|v| v.as_bool()),
        Some(true),
        "mock-registered revocation envelope must stamp mock_broker: true"
    );
}

#[test]
fn build_sign_store_verify_round_trip() {
    let signer = FixtureSigner::new("broker-v2-substrate");
    let pk = signer.public_key();

    // Revocation is the surviving signed broker receipt (materialization is
    // now audit-only — ADR 205 §B.6); it exercises the build→sign→store→verify
    // substrate path identically.
    let mut env = build_broker_revocation_envelope("mat-rt", None, "daemon-root-rt", false);
    sign_receipt_v2(&mut env, &signer).expect("sign v2 envelope");
    assert!(!env.receipt_id.is_empty(), "sign populates receipt_id");
    assert!(env.signature.is_some(), "sign populates signature");

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    store
        .store_broker_receipt_v2(&env)
        .expect("store v2 envelope");

    // Verify the in-memory envelope round-trips through verification.
    verify_receipt_v2(&env, &pk, &FixtureVerifier).expect("envelope verifies");
}

#[test]
fn store_rejects_non_broker_kind() {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let bad = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: "session.claude_code".to_string(),
        receipt_id: "deadbeef".repeat(8),
        daemon_root_id: "daemon-root".into(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: serde_json::json!({}),
        signature: Some("ed25519sig:00".to_string()),
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    let r = store.store_broker_receipt_v2(&bad);
    assert!(
        matches!(r, Err(StoreError::InvalidInput(_))),
        "non-broker kind must be rejected: {r:?}"
    );
}

#[test]
fn store_rejects_unsigned_envelope() {
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    // Built but not signed — receipt_id is empty.
    let env = build_broker_revocation_envelope("mat-unsigned", None, "daemon-root", false);
    let r = store.store_broker_receipt_v2(&env);
    assert!(
        matches!(r, Err(StoreError::InvalidInput(_))),
        "unsigned envelope must be rejected: {r:?}"
    );
}
