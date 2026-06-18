use super::*;

// ============================================================
// META-AP-DAEMON-MEK-PERSISTENCE-E-2-DAEMON-EMIT-WITNESS — T2
// round-trip: emit witness → chain-verify via Slice E3's
// `verify_receipt_v2_with_rotation_chain`.
//
// Anchor: rotation_witness_emitted_at_mek_rotation
// ============================================================

/// T2 round-trip — the witness envelope emitted by
/// `emit_identity_rotation_witness` bridges a pre-rotation trust
/// anchor (the prior signer's pub) forward to a post-rotation
/// signer, so a Receipt signed by the new signer verifies against
/// the prior anchor via Slice E3's
/// `verify_receipt_v2_with_rotation_chain`.
#[test]
fn rotation_witness_emit_chain_verifies_against_prior_anchor() {
    use core_crypto::{FixtureSigner, FixtureVerifier, Signer};
    use core_events::receipt::sign::{
        RotationWitnessEntry, sign_receipt_v2, verify_receipt_v2_with_rotation_chain,
    };
    use ed25519_dalek::SigningKey;

    let store = DaemonStore::open_in_memory().unwrap();

    // Prior identity — about to be retired.
    let prior_signer = FixtureSigner::new("e2-prior-epoch");
    let prior_pub = prior_signer.public_key();

    // New identity — generate a fresh dalek key. `SigningKey::from_bytes`
    // is deterministic so the test is reproducible.
    let new_seed: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];
    let new_signing_key = SigningKey::from_bytes(&new_seed);
    let new_verifying_key = new_signing_key.verifying_key();

    // Emit witness from prior signer over new identity pub.
    let rotation_at = chrono::Utc::now();
    let witness_env =
        emit_identity_rotation_witness(&store, &prior_signer, &new_verifying_key, rotation_at)
            .expect("witness emission must succeed");

    assert_eq!(
        witness_env.kind,
        core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
        "witness envelope must carry the rotation-witness kind discriminator"
    );
    assert!(
        !witness_env.receipt_id.is_empty(),
        "sign_receipt_v2 must have populated receipt_id"
    );
    assert!(
        witness_env.signature.is_some(),
        "sign_receipt_v2 must have populated signature"
    );

    // Synthesise a fresh `core_crypto::Signer` that produces wire-form
    // signatures under the new key — needed so the chain-walk
    // verifier can verify a target receipt signed by the new
    // identity.
    struct DalekFixtureSigner {
        verifying_key: ed25519_dalek::VerifyingKey,
        signing_key: ed25519_dalek::SigningKey,
    }
    impl core_crypto::Signer for DalekFixtureSigner {
        fn sign(&self, payload: &[u8]) -> core_crypto::Signature {
            use ed25519_dalek::Signer as _;
            let sig = self.signing_key.sign(payload);
            core_crypto::Signature(format!("ed25519sig:{}", hex::encode(sig.to_bytes())))
        }
        fn public_key(&self) -> core_crypto::PublicKey {
            core_crypto::PublicKey(format!(
                "ed25519:{}",
                hex::encode(self.verifying_key.to_bytes())
            ))
        }
    }
    let new_signer = DalekFixtureSigner {
        verifying_key: new_verifying_key,
        signing_key: new_signing_key,
    };
    let new_pub = new_signer.public_key();

    // Build a target Receipt signed by the new identity.
    let mut target = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: "atomic.tool_call".into(),
        receipt_id: String::new(),
        daemon_root_id: hex::encode(new_verifying_key.to_bytes()),
        traceparent: None,
        termination_authority: TerminationAuthority::UserSession,
        presence_kind: None,
        body: serde_json::json!({ "tool": "post-rotation-target" }),
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    sign_receipt_v2(&mut target, &new_signer).expect("target sign");

    // Build the chain entry that threads the trust set forward.
    let rotation_at_secs: u64 = rotation_at
        .timestamp()
        .try_into()
        .expect("test clock must be non-negative");
    let chain = vec![RotationWitnessEntry {
        envelope: witness_env.clone(),
        prior_identity_pub: prior_pub.clone(),
        new_identity_pub: new_pub.clone(),
        rotation_at: rotation_at_secs,
    }];

    // Pre-rotation trust anchor reaches post-rotation signer via
    // the single-hop chain.
    verify_receipt_v2_with_rotation_chain(&target, &[prior_pub.clone()], &chain, &FixtureVerifier)
        .expect("emitted witness must let chain-walk reach the post-rotation signer");

    // Negative: without the chain, the verifier MUST reject the
    // target (the prior anchor cannot directly verify a Receipt
    // signed by a different key).
    let err =
        verify_receipt_v2_with_rotation_chain(&target, &[prior_pub.clone()], &[], &FixtureVerifier)
            .expect_err("without the witness chain the target must not verify");
    assert!(
        matches!(err, core_events::receipt::sign::SignError::UntrustedSigner),
        "expected UntrustedSigner without the rotation chain, got: {err:?}"
    );
}

/// The emitted witness is persisted to the local Receipt store and
/// retrievable through `get_receipt_v2_envelope_json`'s sibling
/// scan — confirmed by re-parsing the row JSON and checking the
/// kind discriminator matches.
#[test]
fn rotation_witness_emit_persists_to_local_receipt_store() {
    use core_crypto::FixtureSigner;
    use ed25519_dalek::SigningKey;

    let store = DaemonStore::open_in_memory().unwrap();
    let prior_signer = FixtureSigner::new("e2-persist-prior");
    let new_seed: [u8; 32] = [7u8; 32];
    let new_verifying_key = SigningKey::from_bytes(&new_seed).verifying_key();

    let env = emit_identity_rotation_witness(
        &store,
        &prior_signer,
        &new_verifying_key,
        chrono::Utc::now(),
    )
    .expect("emit");

    // Scan the receipts table directly — the unified table carries
    // the row under `kind = 'identity.rotation_witness'`.
    let row_json: String = store
        .conn()
        .query_row(
            "SELECT receipt_json FROM receipts WHERE id = ?1 AND kind = ?2",
            rusqlite::params![
                env.receipt_id,
                core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
            ],
            |row| row.get(0),
        )
        .expect("witness row must be retrievable by receipt_id+kind");

    let parsed: ReceiptEnvelope =
        serde_json::from_str(&row_json).expect("row JSON must parse back to ReceiptEnvelope");
    assert_eq!(parsed.receipt_id, env.receipt_id);
    assert_eq!(
        parsed.kind,
        core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
    );
}

/// Defence in depth: emitting a witness with prior == new
/// (identical keys) is rejected so the body never violates Slice
/// E1's `IdentityRotationWitnessBody::validate()` (which requires
/// distinct prev/next epoch ids).
#[test]
fn rotation_witness_emit_refuses_equal_prior_and_new_pub() {
    use core_crypto::{FixtureSigner, Signer};
    use ed25519_dalek::VerifyingKey;

    let store = DaemonStore::open_in_memory().unwrap();
    let prior_signer = FixtureSigner::new("e2-equal-keys");
    let prior_pub_handle = prior_signer.public_key();

    // Reconstruct the dalek VerifyingKey from the prior signer's
    // wire-form pub so prior_pub == new_pub by construction.
    let hex_part = prior_pub_handle
        .0
        .strip_prefix("ed25519:")
        .expect("prior pub handle has ed25519: prefix");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_part, &mut bytes).expect("decode prior pub hex");
    let equal_pub = VerifyingKey::from_bytes(&bytes).expect("valid pub bytes");

    let err = emit_identity_rotation_witness(&store, &prior_signer, &equal_pub, chrono::Utc::now())
        .expect_err("emission with identical prior/new pub must be refused");
    match err {
        VaultError::WitnessEmit(msg) => {
            assert!(
                msg.contains("identical"),
                "expected 'identical' in error, got: {msg}"
            );
        }
        other => panic!("expected WitnessEmit error, got: {other}"),
    }
}
