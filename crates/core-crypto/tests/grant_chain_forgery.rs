//! Forgery-vector regression pins for the C1/H1/H3 fixes from the
//! 2026-06-09 pre-release security review.
//!
//! These tests are T2 integration pins (named, externalized) for the
//! crypto-layer attack shapes that the inline `core_crypto::grant_chain::tests`
//! module already covers — kept here as a SEPARATE surface so a regression
//! announces itself by the attack-shape name in test output rather than
//! lurking under a generic "tampered chain" rename.
//!
//! Anchor: `forgery_vector_pin`.
//!
//! Per ADR 205 §A.3 — use-time authority verification is a four-verifier
//! composition. This file pins the boundary owned by verifier (2):
//! `core_crypto::grant_chain::verify_chain`. The H1 widening-append vector
//! lives in `core-grants/tests/forgery_vectors.rs` because attenuation runs
//! at the `core-grants` layer, NOT in `verify_chain` (which only proves
//! signature/chain integrity).
//!
//! See `crates/core-crypto/src/grant_chain.rs:26-106` for the C1 fix.

#![allow(missing_docs)]

/// Anchor for grep/checkpoint checks (`forgery_vector_pin`).
pub const FORGERY_VECTOR_PIN: &str = "forgery_vector_pin/core-crypto";

use core_crypto::grant_chain::{
    ChainError, PubkeyNextKeyPair, RootKeyPair, sign_appended_block, sign_block_zero, verify_chain,
};
use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};
use ed25519_dalek::SigningKey;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_root_keypair(fill: u8) -> (RootKeyPair, [u8; 32]) {
    let seed = [fill; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing.verifying_key().to_bytes();
    let pair = RootKeyPair::from_hex(hex::encode(pubkey_bytes), hex::encode(seed))
        .expect("deterministic root keypair");
    (pair, pubkey_bytes)
}

fn narrow_block(sid: &str, issued_at: u64, target: &str) -> Block {
    Block {
        statements: vec![Statement {
            sid: sid.into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:pull_request:create".into()],
            resource: ResourceSelector::Glob {
                pattern: target.into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: "persona_work".into(),
        issued_at,
        approval: None,
        note: None,
    }
}

fn widening_block(sid: &str, issued_at: u64) -> Block {
    Block {
        statements: vec![Statement {
            sid: sid.into(),
            resource_type: ResourceType::Credential,
            actions: vec!["*".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }],
        nbf: None,
        expires_at: None,
        issued_by: "persona_rogue".into(),
        issued_at,
        approval: None,
        note: None,
    }
}

// ---------------------------------------------------------------------------
// Attack shape (1) — tail-key swap + widening append
//
// C1 fix: `chain_block_zero_msg` binds the successor's `pubkey_next` bytes
// inside the signed payload. Pre-fix the signature covered only the block
// body, leaving `pubkey_next` a sibling field a holder could rewrite —
// then sign a fresh widening append with an attacker key, and the chain
// would verify. Post-fix `verify_chain` MUST refuse.
// ---------------------------------------------------------------------------

#[test]
fn tail_key_swap_rejected() {
    // Honest chain prefix: [B0] under root R, narrow scope.
    let (root, root_pubkey) = make_root_keypair(7);
    let b0_block = narrow_block("Stmt0", 10, "acme/*");
    let b0 = sign_block_zero(&root, &b0_block).expect("sign block 0");

    // Honest chain verifies under R.
    verify_chain(std::slice::from_ref(&b0.signed), &root_pubkey).expect("honest chain verifies");

    // Attacker mints a fresh pubkey_next they control, swaps it into B0,
    // and signs a widening append with it.
    let attacker = PubkeyNextKeyPair::generate();
    let mut b0_forged = b0.signed.clone();
    b0_forged.pubkey_next = attacker.public_hex.clone();

    let b1_wide = widening_block("Forged", 99);
    let b1 = sign_appended_block(&attacker, &b1_wide).expect("attacker signs append");

    // Post-fix: signature over B0 covered the ORIGINAL pubkey_next bytes +
    // root pubkey bytes; swapping pubkey_next breaks the block-0 signature.
    // Either RootKeyMismatch (block 0 fails first) or SignatureMismatch{0}
    // is acceptable — both are the C1 fix refusing the attempt.
    let err = verify_chain(&[b0_forged, b1.signed], &root_pubkey)
        .expect_err("tail-key swap + widening append MUST be rejected");
    assert!(
        matches!(err, ChainError::RootKeyMismatch)
            || matches!(err, ChainError::SignatureMismatch { block_index: 0 }),
        "tail_key_swap_rejected: expected RootKeyMismatch or SignatureMismatch{{0}}, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Attack shape (2) — root-splice
//
// C1 fix: `chain_block_zero_msg` binds the persona root pubkey bytes into
// the signed payload. A block-0 signature minted under root_a MUST NOT
// re-verify under root_b even if all other fields are identical — defends
// against "forge a block 0 against a different persona root and splice."
// ---------------------------------------------------------------------------

#[test]
fn root_splice_rejected() {
    let (root_a, root_a_pubkey) = make_root_keypair(11);
    let (_root_b, root_b_pubkey) = make_root_keypair(12);

    let block = narrow_block("Stmt0", 10, "acme/*");
    let signed = sign_block_zero(&root_a, &block).expect("sign under root_a");

    // Sanity: chain verifies under root_a.
    verify_chain(std::slice::from_ref(&signed.signed), &root_a_pubkey)
        .expect("verifies under root_a");

    // Splicing the same block 0 into a chain rooted at root_b MUST fail.
    // The root-pubkey binding in `chain_block_zero_msg` makes the signed
    // message under root_a structurally different from the message that
    // would have been signed under root_b — so even an honest signer's
    // signature does not re-verify under a different root.
    let err = verify_chain(std::slice::from_ref(&signed.signed), &root_b_pubkey)
        .expect_err("block 0 signed under root_a MUST NOT verify under root_b");
    assert_eq!(
        err,
        ChainError::RootKeyMismatch,
        "root_splice_rejected: expected RootKeyMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sibling pin — `pubkey_next` swap alone (no append) still breaks block 0.
//
// Strengthens the C1 binding invariant: tampering ONLY with `pubkey_next`
// on a single-block chain (no appended block, no attacker signature) is
// already enough to invalidate block 0, because the signed payload binds
// the successor key. This rules out a partial-tamper bypass where an
// attacker swaps the tail key without producing an append.
// ---------------------------------------------------------------------------

#[test]
fn pubkey_next_swap_alone_rejected() {
    let (root, root_pubkey) = make_root_keypair(13);
    let block = narrow_block("Stmt0", 10, "acme/*");
    let mut signed = sign_block_zero(&root, &block).expect("sign block 0");

    let attacker = PubkeyNextKeyPair::generate();
    signed.signed.pubkey_next = attacker.public_hex.clone();

    let err = verify_chain(&[signed.signed], &root_pubkey)
        .expect_err("pubkey_next swap alone MUST invalidate block 0");
    assert_eq!(
        err,
        ChainError::RootKeyMismatch,
        "pubkey_next_swap_alone_rejected: expected RootKeyMismatch, got {err:?}"
    );
}
