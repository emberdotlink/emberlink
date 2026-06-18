//! Receipt v2 `spawn.witness` body kind — round-trip + parent-signature
//! verification tests. SCION-RECEIPT-V2-SPAWN-WITNESS (CRIT-7 mitigation).
//!
//! These tests exercise the dual-signing model:
//!   1. The parent persona signs `JCS(spawn.witness body excluding parent_signature)`,
//!      populating the `parent_signature` field in the body.
//!   2. The issuer (typically the daemon) signs the outer `ReceiptEnvelope`
//!      with the populated body via `sign_receipt_v2`.
//!
//! Forgery rejection: swapping `parent_persona_id` to a different identity
//! after the parent signs MUST cause `verify_spawn_witness_parent_signature`
//! to fail, even if the outer envelope signature still verifies.

use core_crypto::{FixtureSigner, FixtureVerifier, Signer};
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::{
    RECEIPT_KIND_SPAWN_WITNESS, sign_receipt_v2, sign_spawn_witness_parent_signature,
    verify_receipt_v2, verify_spawn_witness_parent_signature,
};
use core_receipts::{RECEIPT_KIND_SPAWN_WITNESS as RECEIPTS_KIND, SpawnWitness};

fn make_envelope(body: serde_json::Value) -> ReceiptEnvelope {
    ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_SPAWN_WITNESS.to_string(),
        receipt_id: String::new(),
        daemon_root_id: "daemon-root-fixture".into(),
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
    }
}

#[test]
fn kind_constants_match_across_crates() {
    // The constant is mirrored across core-events and core-receipts to avoid
    // a cross-crate dep at the lib level. Both must stay in lockstep.
    assert_eq!(RECEIPT_KIND_SPAWN_WITNESS, "spawn.witness");
    assert_eq!(RECEIPTS_KIND, "spawn.witness");
    assert_eq!(RECEIPT_KIND_SPAWN_WITNESS, RECEIPTS_KIND);
}

#[test]
fn spawn_witness_round_trip_sign_and_verify() {
    let parent_signer = FixtureSigner::new("scion-spawn-witness-parent-key");
    let parent_pk = parent_signer.public_key();
    let issuer_signer = FixtureSigner::new("scion-spawn-witness-issuer-key");
    let issuer_pk = issuer_signer.public_key();

    // 1. Build the body with parent_signature empty.
    let witness = SpawnWitness::new(
        "persona-child-001",
        "persona-parent-001",
        "container-abc-123",
        "grant-spawn-fixture",
    );
    let mut body = serde_json::to_value(&witness).unwrap();

    // 2. Parent signs the body-without-parent_signature.
    sign_spawn_witness_parent_signature(&mut body, &parent_signer).unwrap();

    // The body now has a populated parent_signature.
    let psig = body
        .get("parent_signature")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(psig.starts_with("ed25519sig:"), "wire form: {psig}");

    // 3. Verify parent_signature against parent's pubkey.
    verify_spawn_witness_parent_signature(&body, &parent_pk, &FixtureVerifier)
        .expect("parent signature must verify");

    // 4. Issuer signs the outer envelope (body now includes parent_signature).
    let mut env = make_envelope(body);
    sign_receipt_v2(&mut env, &issuer_signer).unwrap();

    // 5. Outer envelope verifies under issuer pubkey.
    verify_receipt_v2(&env, &issuer_pk, &FixtureVerifier)
        .expect("outer envelope must verify under issuer key");

    // 6. Parent signature is preserved inside the envelope body and still
    //    verifies under the parent's pubkey.
    verify_spawn_witness_parent_signature(&env.body, &parent_pk, &FixtureVerifier)
        .expect("parent signature inside envelope must verify");
}

#[test]
fn forged_parent_persona_id_rejected() {
    let parent_signer = FixtureSigner::new("scion-spawn-witness-real-parent");
    let parent_pk = parent_signer.public_key();

    // 1. Parent legitimately signs a witness binding parent="persona-real".
    let real = SpawnWitness::new(
        "persona-child-001",
        "persona-real-parent",
        "container-abc",
        "grant-spawn-real",
    );
    let mut body = serde_json::to_value(&real).unwrap();
    sign_spawn_witness_parent_signature(&mut body, &parent_signer).unwrap();

    // 2. Attacker tampers with parent_persona_id (now claims a different parent
    //    authorized the spawn) while keeping the real parent's signature.
    body.as_object_mut().unwrap().insert(
        "parent_persona_id".into(),
        serde_json::json!("persona-FORGED-parent"),
    );

    // 3. Verification under the real parent's pubkey MUST fail — the canonical
    //    bytes the verifier recomputes no longer match what the parent signed.
    let r = verify_spawn_witness_parent_signature(&body, &parent_pk, &FixtureVerifier);
    assert!(
        matches!(
            r,
            Err(core_events::receipt::sign::SignError::SpawnWitnessParentSignatureInvalid)
        ),
        "forged parent_persona_id must be rejected, got {r:?}"
    );
}

#[test]
fn missing_parent_signature_field_rejected() {
    // A witness body lacking parent_signature entirely must be rejected with
    // SpawnWitnessMissingField — there is no fallback path.
    let parent_signer = FixtureSigner::new("scion-spawn-witness-missing");
    let parent_pk = parent_signer.public_key();
    let body = serde_json::json!({
        "spawned_persona_id": "child",
        "parent_persona_id": "parent",
        "container_id": "container-x",
        "spawn_grant_id": "grant-x",
    });
    let r = verify_spawn_witness_parent_signature(&body, &parent_pk, &FixtureVerifier);
    assert!(
        matches!(
            r,
            Err(
                core_events::receipt::sign::SignError::SpawnWitnessMissingField {
                    field: "parent_signature"
                }
            )
        ),
        "missing parent_signature must be flagged, got {r:?}"
    );
}

#[test]
fn parent_signature_with_wrong_key_rejected() {
    // Same body, but verifier is handed an unrelated public key (simulates
    // looking up the wrong parent_persona_id pubkey in the registry).
    let real_parent = FixtureSigner::new("scion-spawn-witness-real-key");
    let wrong_parent = FixtureSigner::new("scion-spawn-witness-wrong-key");
    let wrong_pk = wrong_parent.public_key();

    let w = SpawnWitness::new("child", "parent", "ctr", "grt");
    let mut body = serde_json::to_value(&w).unwrap();
    sign_spawn_witness_parent_signature(&mut body, &real_parent).unwrap();

    let r = verify_spawn_witness_parent_signature(&body, &wrong_pk, &FixtureVerifier);
    assert!(
        matches!(
            r,
            Err(core_events::receipt::sign::SignError::SpawnWitnessParentSignatureInvalid)
        ),
        "verifying with wrong pubkey must be rejected, got {r:?}"
    );
}

#[test]
fn parent_signature_stable_across_field_order() {
    // JCS canonicalization sorts keys lexicographically — the parent signature
    // must verify regardless of the JSON object's wire field order.
    let parent_signer = FixtureSigner::new("scion-spawn-witness-order-key");
    let parent_pk = parent_signer.public_key();

    let w = SpawnWitness::new("child-a", "parent-a", "container-a", "grant-a");
    let mut body = serde_json::to_value(&w).unwrap();
    sign_spawn_witness_parent_signature(&mut body, &parent_signer).unwrap();

    // Round-trip through a fresh JSON Object that re-inserts in a different
    // order. JCS sorts the keys identically — the canonical bytes match.
    // `ca_fingerprint` (Slice C, bridge_ca_fingerprint_in_spawn_receipt) is
    // included so the reorder preserves every field on the wire body; a
    // missing field would change the canonical bytes and break verification.
    let obj = body.as_object().unwrap();
    let mut reordered = serde_json::Map::new();
    for key in [
        "spawn_grant_id",
        "parent_signature",
        "ca_fingerprint",
        "container_id",
        "parent_persona_id",
        "spawned_persona_id",
    ] {
        reordered.insert(key.into(), obj.get(key).cloned().unwrap());
    }
    let reordered_body = serde_json::Value::Object(reordered);

    verify_spawn_witness_parent_signature(&reordered_body, &parent_pk, &FixtureVerifier)
        .expect("parent signature must verify regardless of wire field order");
}
