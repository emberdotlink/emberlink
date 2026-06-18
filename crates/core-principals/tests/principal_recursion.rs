//! T1: property tests for the unified recursive Principal type (ADR 200
//! 2026-06-15 amendment).
//!
//! CLASSIFICATION: PUBLIC
//!
//! These tests lock the recursive parent-chain invariants ADR 200 names:
//!
//! - A Principal chain terminates iff it reaches a self-parented Principal
//!   (`id == parent_id`).
//! - Chains that do not terminate at a self-parented Principal — cycles
//!   that close without a self-root, or missing parents — are rejected.
//! - Rotating Principal X targets every active grant whose issuer is X and
//!   no grant whose issuer is a different Principal (recursive cascade rule).
//!
//! Anchor: `identity_root_persona_core_principals_type_collapse_landed`.

use core_principals::{
    KeyAlgorithm, Principal, PublicKeyMaterial, SurvivalMode,
    principal_chain_terminates_at_self_root, rotation_cascade_targets,
};
use core_types::Validate;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

fn fixture_principal(id: &str, parent_id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        parent_id: parent_id.to_string(),
        label: format!("{id}-label"),
        disclosure_profile: None,
        survival_mode: SurvivalMode::Strict,
        active_key: PublicKeyMaterial {
            key_id: format!("{id}-key"),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: format!("devpub:{id}"),
        },
    }
}

fn id_strategy() -> impl Strategy<Value = String> {
    // small alphabet → frequent collisions → exercises the
    // self-root / cycle / missing-parent branches.
    "[a-c][0-9]".prop_map(|s| s.to_string())
}

proptest! {
    /// Any chain that resolves at a self-parented Principal must
    /// terminate. The validator returns Ok.
    #[test]
    fn principal_chain_self_root_terminates(
        chain_ids in prop_vec(id_strategy(), 1..6),
    ) {
        // Construct a synthetic chain: principals[0] is self-parented,
        // principals[i].parent_id = principals[i-1].id.
        let mut principals: HashMap<String, Principal> = HashMap::new();
        let mut last_id = chain_ids[0].clone();
        // Self-root.
        principals.insert(last_id.clone(), fixture_principal(&last_id, &last_id));
        for raw in chain_ids.iter().skip(1) {
            // Skip if the id is already present (would short-circuit chain).
            if principals.contains_key(raw) {
                continue;
            }
            principals.insert(raw.clone(), fixture_principal(raw, &last_id));
            last_id = raw.clone();
        }
        // Walking from the tip MUST terminate at the self-root.
        prop_assert!(principal_chain_terminates_at_self_root(&last_id, &principals).is_ok());
    }

    /// A chain whose tip does not transitively reach a self-parented
    /// Principal is rejected. This covers (a) cycles closed without a
    /// self-root and (b) missing-parent dangling references.
    #[test]
    fn principal_chain_rejects_cycle_without_self_root(
        ids in prop_vec(id_strategy(), 2..6),
    ) {
        // Build a closed-cycle ring: a -> b -> c -> a (no self-root).
        // Deduplicate while preserving order.
        let mut seen = HashSet::new();
        let unique: Vec<String> = ids
            .iter()
            .filter(|id| seen.insert((*id).clone()))
            .cloned()
            .collect();
        prop_assume!(unique.len() >= 2);
        let n = unique.len();
        let mut principals: HashMap<String, Principal> = HashMap::new();
        for (i, id) in unique.iter().enumerate() {
            let parent = &unique[(i + n - 1) % n];
            // Guarantee no element is self-parented in the ring.
            prop_assume!(id != parent);
            principals.insert(id.clone(), fixture_principal(id, parent));
        }
        let tip = &unique[0];
        prop_assert!(principal_chain_terminates_at_self_root(tip, &principals).is_err());

        // Also: dangling parent reference (parent not in the map) is rejected.
        let mut dangling: HashMap<String, Principal> = HashMap::new();
        dangling.insert(unique[0].clone(), fixture_principal(&unique[0], "missing-parent"));
        prop_assert!(
            principal_chain_terminates_at_self_root(&unique[0], &dangling).is_err()
        );
    }

    /// Rotating Principal X cascades to every active grant whose issuer
    /// is X and to no grant whose issuer is a different Principal.
    ///
    /// Grants are modeled as `(grant_id, issuer_principal_id)` tuples
    /// inside this crate to avoid a `core-grant-types` dep cycle.
    #[test]
    fn principal_rotation_cascade_targets_only_grants_signed_by_rotated_principal(
        rotated_id in id_strategy(),
        other_ids in prop_vec(id_strategy(), 0..6),
        own_grants in prop_vec("g[0-9]{2}", 0..8),
        other_grants in prop_vec(("g[0-9]{2}", id_strategy()), 0..8),
    ) {
        // Build the issuer set: every grant's issuer is either the
        // rotated Principal or one of the others. The rotation cascade
        // MUST target exactly the rotated-Principal grants.
        let mut grants: Vec<(String, String)> = Vec::new();
        for gid in &own_grants {
            grants.push((gid.clone(), rotated_id.clone()));
        }
        for (gid, issuer) in &other_grants {
            // Skip ambiguous case where another issuer happens to be the
            // rotated Principal — that's the "X also" case, not a
            // distinct issuer.
            if issuer == &rotated_id {
                continue;
            }
            // Skip if the gid collides with one we already classified as
            // rotated-issuer; canonical grant ids are unique by definition.
            if own_grants.iter().any(|own| own == gid) {
                continue;
            }
            grants.push((gid.clone(), issuer.clone()));
        }
        // Need at least one "other-issuer" candidate to make the test
        // meaningful for the non-target side; allow empty other_ids as
        // a benign edge case.
        let _ = other_ids;

        let targets = rotation_cascade_targets(&rotated_id, &grants);

        // Every targeted grant must have the rotated Principal as issuer.
        for gid in &targets {
            let issuer = grants
                .iter()
                .find(|(g, _)| g == gid)
                .map(|(_, i)| i.clone())
                .expect("targeted grant must exist in input");
            prop_assert_eq!(issuer, rotated_id.clone());
        }
        // Every grant issued by the rotated Principal must be targeted.
        for (gid, issuer) in &grants {
            if issuer == &rotated_id {
                prop_assert!(targets.contains(gid));
            } else {
                prop_assert!(!targets.contains(gid));
            }
        }
    }
}

#[test]
fn self_parented_principal_is_recognized_as_root() {
    let root = fixture_principal("root-a", "root-a");
    assert!(root.is_self_root());
    let child = fixture_principal("child-a", "root-a");
    assert!(!child.is_self_root());
}

#[test]
fn validate_rejects_empty_parent_id() {
    let mut p = fixture_principal("p-1", "p-1");
    p.parent_id.clear();
    assert!(p.validate().is_err());
}
