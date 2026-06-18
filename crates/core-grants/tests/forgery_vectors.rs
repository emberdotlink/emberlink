//! Forgery-vector regression pins for the H1 / H3 fixes from the
//! 2026-06-09 pre-release security review.
//!
//! These pin the `core-grants` layer of the four-verifier composition
//! from ADR 205 §A.3:
//!
//! - **Verifier (3)** — `check_statement_attenuation` walked per hop.
//!   Pre-fix (H1) `verify_chain` was mistakenly assumed to prove
//!   attenuation: a legitimately-signed appended block could WIDEN the
//!   chain because `AccessGrant::statements()` flattens blocks into a
//!   union, and no pair-wise child-⊆-parent check ran at use time.
//!   Post-fix the daemon's `first_attenuation_violation` walks each
//!   appended block (i ≥ 1) through `check_statement_attenuation`
//!   against block i-1 and refuses the chain.
//!
//! - **H3 fix** — production delegation MUST extend the existing chain
//!   by signing an appended block with the predecessor's
//!   `pubkey_next` private key. Pre-fix the daemon's delegation path
//!   minted a FRESH single-block `AccessGrant` linked only by a
//!   mutable `parent_grant_id` column on the row — a holder of an
//!   active grant could synthesize a sibling single-block grant under
//!   the same parent that the use-time verifier could not tell apart
//!   from the legitimate child. Post-fix any block-0-only grant whose
//!   issuer asserts it is a delegation MUST fail attenuation, because
//!   the cross-chain comparison requires the parent's
//!   `pubkey_next`-signed continuation block to even exist.
//!
//! Anchor: `forgery_vector_pin`.
//!
//! See `crates/core-crypto/src/grant_chain.rs:26-106` (C1 fix surface) and
//! `crates/ember-daemon/src/trust/use_time_verify.rs:237-279`
//! (`first_attenuation_violation`).
//!
//! T2 — pure state-machine + chain-builder reasoning, no I/O.

#![allow(missing_docs)]

/// Anchor for grep/checkpoint checks (`forgery_vector_pin`).
pub const FORGERY_VECTOR_PIN: &str = "forgery_vector_pin/core-grants";

use core_crypto::grant_chain::{
    RootKeyPair, root_key_from_local_key_pair, sign_appended_block, sign_block_zero,
};
use core_event_types::PresentationAudienceKind;
use core_grant_types::{
    AccessGrant, AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile,
    ResourceSelector, ResourceType, SignedBlock, Statement, Usage,
};
use core_grants::check_statement_attenuation;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Mint a fresh Ed25519 `RootKeyPair` via the same keystore-generator the
/// daemon's production path uses (`generate_local_key_pair` →
/// `root_key_from_local_key_pair`). Mirrors the `fresh_root()` helper in
/// `ember-daemon::trust::use_time_verify::tests`.
fn fresh_root(label: &str) -> RootKeyPair {
    let lkp = core_crypto::generate_local_key_pair("persona", label);
    root_key_from_local_key_pair(&lkp).expect("ed25519 root key")
}

fn stmt(sid: &str, actions: Vec<String>, selector: ResourceSelector) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Credential,
        actions,
        resource: selector,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

fn block_with(statements: Vec<Statement>, issued_by: &str, issued_at: u64) -> Block {
    Block {
        statements,
        nbf: None,
        expires_at: None,
        issued_by: issued_by.into(),
        issued_at,
        approval: None,
        note: None,
    }
}

fn synthetic_grant_from_block(sb: &SignedBlock) -> AccessGrant {
    AccessGrant {
        id: "g".into(),
        version: 1,
        issuing_persona_id: sb.block.issued_by.clone(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "r".into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks: vec![sb.clone()],
        attestation: AttestationBinding::default(),
        created_at: sb.block.issued_at,
        updated_at: sb.block.issued_at,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

// ---------------------------------------------------------------------------
// Attack shape (3) — widening-append
//
// H1 regression. Build a cryptographically valid 2-block chain where
// B0 is narrow (`github:pull_request:create` on `acme/*`) and B1 widens
// to (`*` on `*`). `core_crypto::grant_chain::verify_chain` accepts the
// chain — the signatures are integrity-valid. The use-time path's
// `check_statement_attenuation` walked per hop MUST reject the appended
// block with a `DelegationViolation` naming the widened axis.
// ---------------------------------------------------------------------------

#[test]
fn widening_append_rejected() {
    // Honest narrow B0.
    let root = fresh_root("widening-parent");
    let b0_block = block_with(
        vec![stmt(
            "Narrow",
            vec!["github:pull_request:create".into()],
            ResourceSelector::Glob {
                pattern: "acme/*".into(),
            },
        )],
        "persona_dev",
        10,
    );
    let b0 = sign_block_zero(&root, &b0_block).expect("sign block 0");

    // Widening B1 — signed legitimately by B0's pubkey_next secret. Crypto
    // verifies, but the new block's statement widens both the action set
    // (`*`) and the resource selector (`Any`). The honest signer COULD
    // have done this; the attenuation predicate is what stops it.
    let b1_block = block_with(
        vec![stmt("Wide", vec!["*".into()], ResourceSelector::Any)],
        "persona_dev",
        20,
    );
    let b1 = sign_appended_block(&b0.pubkey_next_secret, &b1_block).expect("sign widening append");

    // Per-hop attenuation walk: B1 must be a subset of B0 across actions
    // and selector. Widening fails — the predicate names the violating
    // axis.
    let parent = synthetic_grant_from_block(&b0.signed);
    let child = synthetic_grant_from_block(&b1.signed);
    let violation = check_statement_attenuation(&parent, &child)
        .expect_err("widening append MUST fail attenuation");
    let reason = violation.reason.to_ascii_lowercase();
    assert!(
        reason.contains("selector") || reason.contains("actions") || reason.contains("no parent"),
        "widening_append_rejected: expected selector/actions violation, got {reason:?}"
    );
}

// ---------------------------------------------------------------------------
// Attack shape (4) — single-block delegation
//
// H3 regression. A production delegation MUST be an append-chain
// extension of the parent's signed chain. Pre-fix the daemon's
// delegation path minted a FRESH single-block `AccessGrant` (block 0
// signed under the parent persona's root) linked only by a mutable
// `parent_grant_id` row column. The use-time per-hop walk had no
// predecessor block to compare against, so a holder of an active
// grant could synthesize a sibling single-block grant whose statements
// did not have to attenuate the parent at all.
//
// The pin: when a "delegated" child arrives as a fresh single-block
// `AccessGrant` whose statements widen the parent, the per-hop
// attenuation predicate (the same one the use-time walk drives) MUST
// refuse the pair. We model "delegation by fresh single-block"
// explicitly by constructing the parent and the rogue "delegate" as
// two independent single-block AccessGrants and feeding them through
// `check_statement_attenuation` — the same predicate the H3 fix wires
// into the per-hop walk.
// ---------------------------------------------------------------------------

#[test]
fn single_block_delegation_rejected() {
    let parent_root = fresh_root("h3-parent");
    let rogue_root = fresh_root("h3-rogue");

    // Parent narrow grant: `github:pull_request:create` on `acme/*`.
    let parent_block = block_with(
        vec![stmt(
            "Parent",
            vec!["github:pull_request:create".into()],
            ResourceSelector::Glob {
                pattern: "acme/*".into(),
            },
        )],
        "persona_parent",
        10,
    );
    let parent_signed = sign_block_zero(&parent_root, &parent_block).expect("parent block 0");

    // Rogue "delegate" — a FRESH single-block AccessGrant whose block 0
    // is signed under a different root, claiming widened authority. This
    // models the pre-H3-fix shape: a delegated grant that is not an
    // append-chain extension of the parent. The mutable `parent_grant_id`
    // row column (modeled here as the absence of a chained `SignedBlock`)
    // is NOT enough for the attenuation walk to authorize it.
    let rogue_block = block_with(
        vec![stmt("Rogue", vec!["*".into()], ResourceSelector::Any)],
        "persona_rogue",
        20,
    );
    let rogue_signed = sign_block_zero(&rogue_root, &rogue_block).expect("rogue block 0");

    let parent_grant = synthetic_grant_from_block(&parent_signed.signed);
    let rogue_grant = synthetic_grant_from_block(&rogue_signed.signed);

    // The per-hop attenuation walk (same predicate the H3 fix drives)
    // MUST refuse: the rogue's widened statement has no parent statement
    // with a matching selector + actions subset. The error message
    // includes the violating axis.
    let violation = check_statement_attenuation(&parent_grant, &rogue_grant)
        .expect_err("fresh single-block delegation MUST fail attenuation");
    let reason = violation.reason.to_ascii_lowercase();
    assert!(
        reason.contains("selector") || reason.contains("actions") || reason.contains("no parent"),
        "single_block_delegation_rejected: expected selector/actions violation, got {reason:?}"
    );
}

// ---------------------------------------------------------------------------
// Sibling pin — append-chain extension that is a proper subset succeeds.
//
// Positive control for the H1/H3 pair: when delegation is an
// append-chain extension AND the new block is a proper subset of the
// predecessor, `check_statement_attenuation` returns Ok. Without this
// control a regression that made the attenuation predicate refuse
// EVERY pair would still pass the widening + single-block tests above.
// ---------------------------------------------------------------------------

#[test]
fn legit_append_chain_narrowing_accepted() {
    let root = fresh_root("legit-narrowing");
    let b0_block = block_with(
        vec![stmt(
            "Parent",
            vec!["github:pull_request:create".into()],
            ResourceSelector::Glob {
                pattern: "acme/*".into(),
            },
        )],
        "persona_dev",
        10,
    );
    let b0 = sign_block_zero(&root, &b0_block).expect("sign block 0");

    // Narrowing append — same action, more specific selector.
    let b1_block = block_with(
        vec![stmt(
            "Child",
            vec!["github:pull_request:create".into()],
            ResourceSelector::Exact {
                value: "acme/widgets".into(),
            },
        )],
        "persona_dev",
        20,
    );
    let b1 = sign_appended_block(&b0.pubkey_next_secret, &b1_block).expect("sign narrowing append");

    let parent = synthetic_grant_from_block(&b0.signed);
    let child = synthetic_grant_from_block(&b1.signed);
    check_statement_attenuation(&parent, &child)
        .expect("legitimate narrowing append must pass attenuation");
}
