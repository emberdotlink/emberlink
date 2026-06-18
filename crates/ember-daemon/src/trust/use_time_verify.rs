//! BKR-4b — use-time authority verification composition (ADR 205 §A.3).
//!
//! Every use-time authority decision is the **composition of four verifiers**,
//! never [`core_grants::resolve_need_against_grants`] alone — that predicate
//! trusts the grants it is handed, so on its own it would admit a
//! store-injected / forged grant that happens to satisfy `need ⊆ grant`. A
//! grant authorizes a need only if ALL FOUR hold:
//!
//!   1. **Root authorization** — its issuing persona's root key is currently
//!      authorized by the apex device-set (ADR 200 Model-C, presence-rooted).
//!      This is the [`PersonaRootAuthority`] seam: the convergence point ADR 206
//!      fills (`verify_chain_with_reverifier` over the device-set). Until that
//!      lands, a transitional daemon-key implementation occupies the seam — and
//!      it is, per ADR 205 §9 / §A.5, daemon-forgeable (the honest dev0 limit);
//!      the *structure* here does not change when presence anchoring arrives,
//!      only the implementation behind this trait.
//!   2. **Chain integrity** — its Biscuit block chain verifies against that
//!      root ([`core_crypto::grant_chain::verify_chain`]: block 0 by the root,
//!      each later block by the prior `pubkey_next`; tamper/reorder/tail-key
//!      swap (C1 fix) breaks it).
//!   3. **Inter-block attenuation** (H1 fix) — for each i in 1..N the chain's
//!      block i's statements must attenuate block i-1's per
//!      [`core_grants::scope::check_statement_attenuation`]. `verify_chain`
//!      proves signature integrity only; it does NOT prove each appended
//!      block narrows its predecessor. Without this step `AccessGrant`'s
//!      block-union flattening means a legitimately-signed appended block
//!      could WIDEN authority (Biscuit semantics require intersection, not
//!      union). Pre-fix ADR 205 §A.3 named `verify_chain` the attenuation
//!      proof — corrected post-fix.
//!   4. **`need ⊆ grant`** — over the root-authorized, chain-verified,
//!      per-hop-attenuated set only ([`core_grants::resolve_need_against_grants`],
//!      BKR-4a). Per-grant Active/revoked status is enforced inside that
//!      predicate; the multi-hop ancestor-Active revocation walk (§A.4) +
//!      I13 (§A.5) ride a follow-up slice once `parent_grant_id` ancestry lands.
//!
//! A forged or tampered grant fails (1)/(2); a legitimately-signed but
//! non-attenuating chain fails (3). Neither reaches (4).

use core_crypto::grant_chain::verify_chain;
use core_grant_types::{AccessGrant, SignedBlock, Statement};
use core_grants::{
    NeedResolution, NeedUnsatisfiable, RevokedAncestor, first_revoked_ancestor,
    resolve_need_against_grants, scope::check_statement_attenuation,
};

/// The convergence seam (ADR 205 §A.5 / ADR 206). Resolves a persona's root
/// verifying key **iff** that key is currently authorized by the apex
/// device-set; `None` means the persona is not device-set-authorized, so its
/// grants authorize nothing (fail-closed).
///
/// The production implementation (ADR 206 presence lane) is backed by
/// `core_eventlog::verify_chain_with_reverifier` /
/// `is_active_persona_key_under_root` — a persona key is authorized only while
/// it descends from an active presence Device in the operator's root set. The
/// transitional dev0 implementation returns the daemon-stored persona
/// `public_key` (forgeable; the §9 honest limit) and lives at the wiring site,
/// not here, so this module stays root-custody-agnostic and unit-testable.
pub trait PersonaRootAuthority {
    /// The 32-byte root verifying key for `persona_id`, iff it is authorized by
    /// the apex device-set; `None` otherwise (fail-closed).
    fn authorized_root_pubkey(&self, persona_id: &str) -> Option<[u8; 32]>;
}

/// The §A.4 revocation-walk seam (ADR 205 §A.4). Resolves a covering grant's
/// `parent_grant_id` ancestry + each ancestor's live status, so the composition
/// can refuse if **any** ancestor was revoked — the read-side, use-time check
/// (complementary to the daemon's write-side `cascade_revoke_children`; ADR 076
/// is the eager cascade, §A.4 is the online walk). The store-backed
/// implementation walks the existing `parent_grant_id` column and lives at the
/// wiring site, keeping this module store-agnostic + unit-testable. The walk
/// itself is [`core_grants::first_revoked_ancestor`].
pub trait GrantAncestry {
    /// Transitive ancestor grant-ids of `grant_id`, **nearest-parent first**,
    /// from the `parent_grant_id` chain. Empty for an apex (root) grant.
    fn ancestor_ids(&self, grant_id: &str) -> Vec<String>;

    /// Status-bearing records for `ids` that still exist (revoked / expired
    /// included). Reaped/missing ids are simply omitted — `first_revoked_ancestor`
    /// then treats them as fail-closed `Absent` (a vanished ancestor cannot be
    /// proven valid).
    fn status_of(&self, ids: &[String]) -> Vec<AccessGrant>;
}

/// Outcome of the composed use-time verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UseVerdict {
    /// A single root-authorized, chain-verified grant covers the whole need.
    Authorized {
        grant_id: String,
        matched_statement_sids: Vec<String>,
    },
    /// Refused — reason names the failing layer only (oracle-avoidance, like
    /// [`core_grants::DelegationViolation`]).
    Refused { reason: RefuseReason },
}

/// Why a use-time authority decision was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseReason {
    /// No candidate grant survived the root-authorization + chain-verify filter
    /// — every grant was either issued by a persona the device-set does not
    /// authorize, or carried a chain that failed `verify_chain`.
    NoRootedChainValidGrant,
    /// A candidate grant was root-authorized and chain-signature-valid, but
    /// an APPENDED block widened (failed to attenuate) its predecessor (H1
    /// fix). The reported `block_index` is the failing block (≥1). Pre-fix
    /// such a chain would have been accepted because `AccessGrant::statements()`
    /// flattened all blocks into one union and the use-time path never compared
    /// block i to block i-1.
    ChainAttenuationViolation {
        /// The grant id whose chain failed the per-hop attenuation check.
        grant_id: String,
        /// 0-indexed position of the block whose statements widened the
        /// predecessor's. Always ≥ 1 (block 0 has no predecessor).
        block_index: usize,
        /// Human-readable failure summary from `check_statement_attenuation`.
        /// Oracle-safe: same wording the daemon already emits on the write path.
        reason: String,
    },
    /// Grants are root-authorized & chain-valid, but none covers the need
    /// (carries the `need ⊆ grant` failure axis).
    Unsatisfiable(NeedUnsatisfiable),
    /// A single grant covered the need, but an **ancestor** in its
    /// `parent_grant_id` lineage was revoked / non-active / absent (ADR 205 §A.4
    /// online revocation walk). Carries the offending ancestor.
    AncestorRevoked(RevokedAncestor),
}

/// Compose the four verifiers (ADR 205 §A.3) **plus the §A.4 revocation walk**.
/// `grants` are the persona's candidate standing grants; only those whose
/// issuing persona is device-set-authorized AND whose chain verifies AND whose
/// every appended block attenuates its predecessor are eligible for the
/// `need ⊆ grant` resolution. The single covering grant is then subjected to
/// the online ancestry walk (§A.4): if any ancestor in its `parent_grant_id`
/// lineage is revoked, the decision is refused even though the leaf grant
/// itself is active.
pub fn verify_grant_for_use(
    authority: &dyn PersonaRootAuthority,
    ancestry: &dyn GrantAncestry,
    grants: &[AccessGrant],
    need: &[Statement],
) -> UseVerdict {
    // (1) + (2): retain only root-authorized, chain-verified grants. A grant
    // whose persona the device-set does not authorize (None), or whose chain
    // fails verification, is dropped before it can satisfy any need.
    let chain_verified: Vec<AccessGrant> = grants
        .iter()
        .filter(
            |g| match authority.authorized_root_pubkey(&g.issuing_persona_id) {
                Some(root) => verify_chain(&g.blocks, &root).is_ok(),
                None => false,
            },
        )
        .cloned()
        .collect();

    if chain_verified.is_empty() {
        return UseVerdict::Refused {
            reason: RefuseReason::NoRootedChainValidGrant,
        };
    }

    // (3) — H1 fix: per-hop inter-block attenuation. `verify_chain` proves
    // signature integrity; it does NOT prove each appended block narrows its
    // predecessor. `AccessGrant::statements()` is a union over all blocks, so
    // pre-fix a legitimately-signed appended block carrying broader statements
    // would have authority-WIDENED the chain at use time. We refuse any chain
    // whose block[i] (i≥1) does not attenuate block[i-1] via
    // `check_statement_attenuation` — the same predicate the daemon already
    // enforces on the WRITE path (grant.rs / approval.rs).
    //
    // We refuse on the FIRST non-attenuating chain we encounter (rather than
    // silently dropping it and falling through to a sibling grant); fail-loud
    // here surfaces store corruption / minting drift instead of silently
    // narrowing the operator's authority view.
    let mut verified: Vec<AccessGrant> = Vec::with_capacity(chain_verified.len());
    for grant in chain_verified {
        if let Some((block_index, reason)) = first_attenuation_violation(&grant.blocks, &grant.id) {
            return UseVerdict::Refused {
                reason: RefuseReason::ChainAttenuationViolation {
                    grant_id: grant.id,
                    block_index,
                    reason,
                },
            };
        }
        verified.push(grant);
    }

    // (4): need ⊆ grant over the verified set only (BKR-4a). Per-grant
    // Active/revoked status is checked inside the predicate (the LEAF grant).
    let (grant_id, matched_statement_sids) = match resolve_need_against_grants(&verified, need) {
        NeedResolution::Covered {
            grant_id,
            matched_statement_sids,
        } => (grant_id, matched_statement_sids),
        NeedResolution::Unsatisfiable { reason } => {
            return UseVerdict::Refused {
                reason: RefuseReason::Unsatisfiable(reason),
            };
        }
    };

    // (§A.4): online revocation walk over the covering grant's ancestry. The
    // leaf grant is active (checked in (3)), but an ANCESTOR may have been
    // revoked without the eager `cascade_revoke_children` write having reached
    // this leaf (crash mid-cascade, a race, or a presented embed-chain the
    // daemon's column never cascaded). Refuse if any ancestor is
    // revoked/non-active/absent. Empty ancestry (apex grant) is a no-op.
    let ancestor_ids = ancestry.ancestor_ids(&grant_id);
    if !ancestor_ids.is_empty() {
        let ancestor_status = ancestry.status_of(&ancestor_ids);
        if let Some(revoked) = first_revoked_ancestor(&ancestor_ids, &ancestor_status) {
            return UseVerdict::Refused {
                reason: RefuseReason::AncestorRevoked(revoked),
            };
        }
    }

    UseVerdict::Authorized {
        grant_id,
        matched_statement_sids,
    }
}

/// H1 fix — walk an `AccessGrant`'s blocks and verify each block i (i≥1)
/// attenuates block i-1. Returns the (block_index, reason) of the first
/// non-attenuating hop, or `None` if every hop attenuates cleanly.
///
/// Implementation: build a synthetic two-block `AccessGrant` per hop (one
/// block from the predecessor, one from the successor) and pass it through
/// the existing [`check_statement_attenuation`] predicate — the same one
/// the write paths use. This keeps the attenuation rule in exactly one
/// place; if the write-path predicate tightens (or relaxes) tomorrow, the
/// use-path picks up the change automatically.
fn first_attenuation_violation(blocks: &[SignedBlock], grant_id: &str) -> Option<(usize, String)> {
    if blocks.len() < 2 {
        return None;
    }
    for i in 1..blocks.len() {
        let parent = synthetic_grant_from_block(&blocks[i - 1], grant_id);
        let child = synthetic_grant_from_block(&blocks[i], grant_id);
        if let Err(violation) = check_statement_attenuation(&parent, &child) {
            return Some((i, violation.reason));
        }
    }
    None
}

/// Build a synthetic single-block `AccessGrant` view from one `SignedBlock`,
/// for the per-hop attenuation check. Only fields read by
/// `check_statement_attenuation` (the block's statements) need to be
/// populated faithfully; everything else is a stable filler.
fn synthetic_grant_from_block(sb: &SignedBlock, grant_id: &str) -> AccessGrant {
    use core_event_types::PresentationAudienceKind;
    use core_grant_types::{AttestationBinding, GrantMode, GrantStatus, RecipientProfile};
    AccessGrant {
        id: grant_id.to_string(),
        version: 1,
        issuing_persona_id: sb.block.issued_by.clone(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: String::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::grant_chain::{
        RootKeyPair, root_key_from_local_key_pair, sign_appended_block, sign_block_zero,
    };
    use core_event_types::PresentationAudienceKind;
    use core_grant_types::{
        AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, ResourceSelector,
        ResourceType, SignedBlock, Statement, Usage,
    };
    use std::collections::HashMap;

    /// Mint a fresh Ed25519 `RootKeyPair` for tests (no public `generate` on
    /// `RootKeyPair`; go through the keystore generator like production).
    fn fresh_root() -> RootKeyPair {
        let lkp = core_crypto::generate_local_key_pair("persona", "test-root");
        root_key_from_local_key_pair(&lkp).expect("ed25519 root key")
    }

    /// Mock device-set authority: persona_id → authorized root pubkey. A
    /// persona absent from the map is treated as not-device-set-authorized.
    struct MockAuthority(HashMap<String, [u8; 32]>);

    impl PersonaRootAuthority for MockAuthority {
        fn authorized_root_pubkey(&self, persona_id: &str) -> Option<[u8; 32]> {
            self.0.get(persona_id).copied()
        }
    }

    /// Mock §A.4 ancestry: grant_id → ordered ancestor ids, plus a flat status
    /// set the walk resolves against. A status-set absence models a reaped
    /// ancestor (→ fail-closed `Absent`).
    #[derive(Default)]
    struct MockAncestry {
        chains: HashMap<String, Vec<String>>,
        statuses: HashMap<String, AccessGrant>,
    }

    impl GrantAncestry for MockAncestry {
        fn ancestor_ids(&self, grant_id: &str) -> Vec<String> {
            self.chains.get(grant_id).cloned().unwrap_or_default()
        }
        fn status_of(&self, ids: &[String]) -> Vec<AccessGrant> {
            ids.iter()
                .filter_map(|id| self.statuses.get(id).cloned())
                .collect()
        }
    }

    /// The common case: the covering grant is an apex (no ancestry → no walk).
    fn no_ancestry() -> MockAncestry {
        MockAncestry::default()
    }

    /// A bare status-bearing grant fixture (id + status + revoked_at only —
    /// the walk reads nothing else).
    fn status_grant(id: &str, status: GrantStatus, revoked_at: Option<u64>) -> AccessGrant {
        let mut g = grant_from_blocks(id, "anc", Vec::new());
        g.status = status;
        g.revoked_at = revoked_at;
        g
    }

    fn need_stmt(action: &str, repo: &str) -> Statement {
        Statement {
            sid: "need".into(),
            resource_type: ResourceType::Session,
            actions: vec![action.into()],
            resource: ResourceSelector::Exact { value: repo.into() },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    fn grant_stmt(actions: Vec<String>, pattern: &str) -> Statement {
        Statement {
            sid: "s1".into(),
            resource_type: ResourceType::Session,
            actions,
            resource: ResourceSelector::Glob {
                pattern: pattern.into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    fn block_with(statements: Vec<Statement>, persona: &str) -> Block {
        Block {
            statements,
            nbf: None,
            expires_at: None,
            issued_by: persona.into(),
            issued_at: 0,
            approval: None,
            note: None,
        }
    }

    /// Assemble an `AccessGrant` from already-signed blocks for `persona`.
    fn grant_from_blocks(id: &str, persona: &str, blocks: Vec<SignedBlock>) -> AccessGrant {
        AccessGrant {
            id: id.into(),
            version: 1,
            issuing_persona_id: persona.into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "r".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks,
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    /// Mint a real single-block signed grant under a fresh root key. Returns the
    /// grant + the root's 32-byte pubkey (what the device-set would authorize).
    fn signed_single_block_grant(
        id: &str,
        persona: &str,
        statements: Vec<Statement>,
    ) -> (AccessGrant, [u8; 32]) {
        let root = fresh_root();
        let out = sign_block_zero(&root, &block_with(statements, persona)).expect("sign block 0");
        let grant = grant_from_blocks(id, persona, vec![out.signed]);
        (grant, root.public_bytes().expect("root pubkey bytes"))
    }

    fn pr_create_need() -> Vec<Statement> {
        vec![need_stmt("github:pull_request:create", "acme/widgets")]
    }

    #[test]
    fn authorized_persona_valid_chain_covering_need_is_authorized() {
        let (grant, root) = signed_single_block_grant(
            "g1",
            "p-dev",
            vec![grant_stmt(
                vec!["github:pull_request:create".into()],
                "acme/*",
            )],
        );
        let auth = MockAuthority(HashMap::from([("p-dev".to_string(), root)]));
        match verify_grant_for_use(&auth, &no_ancestry(), &[grant], &pr_create_need()) {
            UseVerdict::Authorized { grant_id, .. } => assert_eq!(grant_id, "g1"),
            other => panic!("expected Authorized, got {other:?}"),
        }
    }

    #[test]
    fn persona_not_authorized_by_device_set_is_refused() {
        // Valid chain, but the persona is absent from the device-set authority.
        let (grant, _root) = signed_single_block_grant(
            "g1",
            "p-rogue",
            vec![grant_stmt(
                vec!["github:pull_request:create".into()],
                "acme/*",
            )],
        );
        let auth = MockAuthority(HashMap::new()); // authorizes no one
        assert_eq!(
            verify_grant_for_use(&auth, &no_ancestry(), &[grant], &pr_create_need()),
            UseVerdict::Refused {
                reason: RefuseReason::NoRootedChainValidGrant
            }
        );
    }

    #[test]
    fn authorized_persona_but_wrong_root_key_fails_chain_verify() {
        // The device-set authorizes the persona, but hands back a DIFFERENT root
        // key than the one the chain was signed under → chain verify fails →
        // grant is dropped (substitution / forged-root defense).
        let (grant, _real_root) =
            signed_single_block_grant("g1", "p-dev", vec![grant_stmt(vec!["*".into()], "acme/*")]);
        let wrong_root = fresh_root().public_bytes().unwrap();
        let auth = MockAuthority(HashMap::from([("p-dev".to_string(), wrong_root)]));
        assert_eq!(
            verify_grant_for_use(&auth, &no_ancestry(), &[grant], &pr_create_need()),
            UseVerdict::Refused {
                reason: RefuseReason::NoRootedChainValidGrant
            }
        );
    }

    #[test]
    fn tampered_block_after_signing_fails_chain_verify() {
        // Sign a clean grant, then mutate a statement post-signature. The
        // canonical-encode signature no longer matches → dropped.
        let root = fresh_root();
        let out = sign_block_zero(
            &root,
            &block_with(
                vec![grant_stmt(vec!["github:contents:read".into()], "acme/*")],
                "p-dev",
            ),
        )
        .unwrap();
        let mut signed = out.signed;
        // Tamper: widen the action after the signature was computed.
        signed.block.statements[0].actions = vec!["github:contents:write".into()];
        let grant = grant_from_blocks("g1", "p-dev", vec![signed]);
        let auth = MockAuthority(HashMap::from([(
            "p-dev".to_string(),
            root.public_bytes().unwrap(),
        )]));
        assert_eq!(
            verify_grant_for_use(
                &auth,
                &no_ancestry(),
                &[grant],
                &[need_stmt("github:contents:write", "acme/widgets")]
            ),
            UseVerdict::Refused {
                reason: RefuseReason::NoRootedChainValidGrant
            }
        );
    }

    #[test]
    fn authorized_valid_chain_but_need_out_of_scope_is_unsatisfiable() {
        let (grant, root) = signed_single_block_grant(
            "g1",
            "p-dev",
            vec![grant_stmt(vec!["github:contents:read".into()], "acme/*")],
        );
        let auth = MockAuthority(HashMap::from([("p-dev".to_string(), root)]));
        // Need writes; grant only reads → root-authorized & chain-valid, but
        // need ⊄ grant.
        match verify_grant_for_use(
            &auth,
            &no_ancestry(),
            &[grant],
            &[need_stmt("github:contents:write", "acme/widgets")],
        ) {
            UseVerdict::Refused {
                reason: RefuseReason::Unsatisfiable(_),
            } => {}
            other => panic!("expected Unsatisfiable refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_block_attenuation_chain_verifies_and_authorizes() {
        // Block 0 (durable authority) signed by root; block 1 (attenuation)
        // signed by block 0's pubkey_next — the multi-hop descent shape.
        let root = fresh_root();
        let b0 = sign_block_zero(
            &root,
            &block_with(vec![grant_stmt(vec!["*".into()], "acme/*")], "p-durable"),
        )
        .unwrap();
        let b1 = sign_appended_block(
            &b0.pubkey_next_secret,
            &block_with(
                vec![grant_stmt(
                    vec!["github:pull_request:create".into()],
                    "acme/*",
                )],
                "p-runtime",
            ),
        )
        .unwrap();
        let grant = grant_from_blocks("g1", "p-durable", vec![b0.signed, b1.signed]);
        let auth = MockAuthority(HashMap::from([(
            "p-durable".to_string(),
            root.public_bytes().unwrap(),
        )]));
        match verify_grant_for_use(&auth, &no_ancestry(), &[grant], &pr_create_need()) {
            UseVerdict::Authorized { grant_id, .. } => assert_eq!(grant_id, "g1"),
            other => panic!("expected Authorized for 2-block chain, got {other:?}"),
        }
    }

    #[test]
    fn forged_grant_among_valid_ones_is_filtered_then_valid_one_authorizes() {
        // A forged grant (unauthorized persona) sits alongside a real one; the
        // forgery is filtered, the real grant authorizes. Proves resolution
        // never runs over the forgery.
        let (real, root) = signed_single_block_grant(
            "g-real",
            "p-dev",
            vec![grant_stmt(
                vec!["github:pull_request:create".into()],
                "acme/*",
            )],
        );
        let (forged, _) = signed_single_block_grant(
            "g-forged",
            "p-rogue",
            vec![grant_stmt(vec!["*".into()], "acme/*")],
        );
        let auth = MockAuthority(HashMap::from([("p-dev".to_string(), root)]));
        match verify_grant_for_use(&auth, &no_ancestry(), &[forged, real], &pr_create_need()) {
            UseVerdict::Authorized { grant_id, .. } => assert_eq!(grant_id, "g-real"),
            other => panic!("expected Authorized by g-real, got {other:?}"),
        }
    }

    // --- H1 inter-block attenuation -----------------------------------------

    /// **H1 regression** — a legitimately-signed appended block that
    /// WIDENS its predecessor MUST be refused at use time, even though
    /// the cryptographic chain verifies. Pre-fix `AccessGrant::statements()`
    /// flattened blocks into a union and the use-time path never compared
    /// blocks pair-wise, so a delegated chain
    /// `[B0 = pr:create on acme/*; B1 = * on *]` would have AUTHORIZED a
    /// `*` need — Biscuit semantics require intersection, not union.
    #[test]
    fn use_time_refuses_chain_whose_block_widens_predecessor() {
        let root = fresh_root();
        // B0: narrow — github:pull_request:create on acme/*.
        let b0 = sign_block_zero(
            &root,
            &block_with(
                vec![grant_stmt(
                    vec!["github:pull_request:create".into()],
                    "acme/*",
                )],
                "p-dev",
            ),
        )
        .unwrap();
        // B1: WIDENS — '*' on everything. Cryptographically legitimate (the
        // honest signer authored this) but it violates attenuation.
        let b1 = sign_appended_block(
            &b0.pubkey_next_secret,
            &block_with(vec![grant_stmt(vec!["*".into()], "*")], "p-rogue"),
        )
        .unwrap();
        let grant = grant_from_blocks("g1", "p-dev", vec![b0.signed, b1.signed]);
        let auth = MockAuthority(HashMap::from([(
            "p-dev".to_string(),
            root.public_bytes().unwrap(),
        )]));

        // Use ANY need — the chain must be refused before need resolution runs.
        // We pick a need the WIDENING block would otherwise satisfy (so this
        // test would have read as Authorized pre-fix).
        let need = vec![need_stmt(
            "github:pull_request:create",
            "evil-corp/secret-repo",
        )];

        match verify_grant_for_use(&auth, &no_ancestry(), &[grant], &need) {
            UseVerdict::Refused {
                reason:
                    RefuseReason::ChainAttenuationViolation {
                        grant_id,
                        block_index,
                        ..
                    },
            } => {
                assert_eq!(grant_id, "g1");
                assert_eq!(block_index, 1, "violating block index should be 1");
            }
            other => panic!(
                "widening appended block MUST be refused with ChainAttenuationViolation, got {other:?}"
            ),
        }
    }

    /// Confirms `first_attenuation_violation` is the failing layer (not
    /// signature verification): the attenuation refusal carries a non-empty
    /// human-readable reason that matches the write-path predicate.
    #[test]
    fn attenuation_violation_carries_explanatory_reason() {
        let root = fresh_root();
        let b0 = sign_block_zero(
            &root,
            &block_with(
                vec![grant_stmt(vec!["github:contents:read".into()], "acme/*")],
                "p-dev",
            ),
        )
        .unwrap();
        let b1 = sign_appended_block(
            &b0.pubkey_next_secret,
            &block_with(
                vec![grant_stmt(vec!["github:contents:write".into()], "acme/*")],
                "p-runtime",
            ),
        )
        .unwrap();
        let grant = grant_from_blocks("g1", "p-dev", vec![b0.signed, b1.signed]);
        let auth = MockAuthority(HashMap::from([(
            "p-dev".to_string(),
            root.public_bytes().unwrap(),
        )]));
        match verify_grant_for_use(&auth, &no_ancestry(), &[grant], &pr_create_need()) {
            UseVerdict::Refused {
                reason:
                    RefuseReason::ChainAttenuationViolation {
                        reason,
                        block_index,
                        ..
                    },
            } => {
                assert_eq!(block_index, 1);
                assert!(
                    !reason.is_empty(),
                    "attenuation refusal must carry a non-empty reason"
                );
            }
            other => panic!("expected ChainAttenuationViolation, got {other:?}"),
        }
    }

    // --- §A.4 ancestry revocation-walk composition ---

    /// A device-set-authorized, chain-valid grant "g1" that covers the need —
    /// so the decision turns entirely on the §A.4 ancestry walk.
    fn authorized_covering_grant() -> (AccessGrant, MockAuthority) {
        let (grant, root) = signed_single_block_grant(
            "g1",
            "p-dev",
            vec![grant_stmt(
                vec!["github:pull_request:create".into()],
                "acme/*",
            )],
        );
        (
            grant,
            MockAuthority(HashMap::from([("p-dev".to_string(), root)])),
        )
    }

    #[test]
    fn clean_ancestry_authorizes() {
        let (grant, auth) = authorized_covering_grant();
        let ancestry = MockAncestry {
            chains: HashMap::from([(
                "g1".to_string(),
                vec!["p-grant".to_string(), "root".to_string()],
            )]),
            statuses: HashMap::from([
                (
                    "p-grant".to_string(),
                    status_grant("p-grant", GrantStatus::Active, None),
                ),
                (
                    "root".to_string(),
                    status_grant("root", GrantStatus::Active, None),
                ),
            ]),
        };
        match verify_grant_for_use(&auth, &ancestry, &[grant], &pr_create_need()) {
            UseVerdict::Authorized { grant_id, .. } => assert_eq!(grant_id, "g1"),
            other => panic!("clean ancestry must authorize, got {other:?}"),
        }
    }

    #[test]
    fn revoked_ancestor_refuses_even_though_leaf_is_active() {
        let (grant, auth) = authorized_covering_grant();
        // Leaf g1 is active; its grandparent "root" is revoked → refuse. This is
        // the case the eager `cascade_revoke_children` write could miss (race /
        // crash / presented embed-chain) — the online walk catches it.
        let ancestry = MockAncestry {
            chains: HashMap::from([(
                "g1".to_string(),
                vec!["p-grant".to_string(), "root".to_string()],
            )]),
            statuses: HashMap::from([
                (
                    "p-grant".to_string(),
                    status_grant("p-grant", GrantStatus::Active, None),
                ),
                (
                    "root".to_string(),
                    status_grant("root", GrantStatus::Active, Some(123)),
                ),
            ]),
        };
        match verify_grant_for_use(&auth, &ancestry, &[grant], &pr_create_need()) {
            UseVerdict::Refused {
                reason: RefuseReason::AncestorRevoked(rev),
            } => assert_eq!(rev.grant_id, "root"),
            other => panic!("revoked ancestor must refuse, got {other:?}"),
        }
    }

    #[test]
    fn absent_ancestor_refuses_fail_closed() {
        let (grant, auth) = authorized_covering_grant();
        // The lineage references "reaped" but it's gone from the status set →
        // fail-closed Absent (a vanished ancestor cannot be proven valid).
        let ancestry = MockAncestry {
            chains: HashMap::from([("g1".to_string(), vec!["reaped".to_string()])]),
            statuses: HashMap::new(),
        };
        match verify_grant_for_use(&auth, &ancestry, &[grant], &pr_create_need()) {
            UseVerdict::Refused {
                reason: RefuseReason::AncestorRevoked(rev),
            } => {
                assert_eq!(rev.grant_id, "reaped");
                assert_eq!(rev.reason, core_grants::AncestorRevocation::Absent);
            }
            other => panic!("absent ancestor must fail-closed refuse, got {other:?}"),
        }
    }
}
