//! Property tests for 3-hop chained delegation attenuation
//! (T1 tier per `.claude/rules/test-tiers.md`).
//!
//! Per ADR 205 §A.3, attenuation is enforced per-hop: each appended
//! delegation block must be a (non-strict) subset of its predecessor on
//! every axis (actions, selector, conditions, budget, delegation). The
//! existing proptests cover the SINGLE-HOP property (`delegate_narrows_
//! scope` in `state_machine.rs` and `enforce_subset_*` in
//! `attenuation.rs`); this file pins the MULTI-HOP composition property
//! that the chain holds across at least three sequential delegations,
//! and that widening at ANY hop is rejected with
//! `GrantError::ScopeViolation`.
//!
//! Modeled with `core_grants::Scope` (`capability`, `resource_id`,
//! `constraints`). Narrowing happens by adding constraints, by
//! resource-id specialization, or by capability equality (capability
//! cannot widen). Widening is modeled by removing a constraint at one
//! hop, or by switching capability to a non-matching string.

use core_grants::{Grant, GrantError, GrantSpec, PrincipalId, Scope, create, delegate};
use proptest::prelude::*;

fn fixed_issuer() -> PrincipalId {
    PrincipalId("issuer-chain".into())
}

/// Strategy for a short alphabetic capability name.
fn arb_capability() -> impl Strategy<Value = String> {
    "[A-Z][a-z]{3,7}".prop_map(|s| s.to_string())
}

/// Strategy for a resource id segment.
fn arb_resource_id() -> impl Strategy<Value = String> {
    "[a-z]{3,8}".prop_map(|s| s.to_string())
}

/// Strategy for a single constraint label.
fn arb_constraint() -> impl Strategy<Value = String> {
    "[a-z]{3,6}".prop_map(|s| s.to_string())
}

/// Build a root grant with the given scope.
fn root_with_scope(scope: Scope) -> Grant {
    create(GrantSpec {
        issuer: fixed_issuer(),
        scope,
        expires_at: None,
    })
    .expect("create root for chained delegation fixture")
}

// ----------------------------------------------------------------------
// (1) Deterministic: 3-hop happy path preserves subset chain
// ----------------------------------------------------------------------

#[test]
fn three_hop_strict_narrowing_succeeds_and_preserves_subset_chain() {
    // Per `Scope::is_subset_of` (grant.rs:67-71), child constraints must
    // all appear in parent constraints. So narrowing = REMOVING
    // constraints (the child's allowed-pattern set is a subset of the
    // parent's). Resource_id narrows by going from `None` (any) to
    // `Some(specific)`.
    let root_scope = Scope {
        capability: "ReadCredential".into(),
        resource_id: None,
        constraints: vec![
            "branch:main".into(),
            "branch:dev".into(),
            "no-force-push".into(),
        ],
    };
    let hop1_scope = Scope {
        capability: "ReadCredential".into(),
        resource_id: Some("repo-x".into()),
        constraints: vec![
            "branch:main".into(),
            "branch:dev".into(),
            "no-force-push".into(),
        ],
    };
    let hop2_scope = Scope {
        capability: "ReadCredential".into(),
        resource_id: Some("repo-x".into()),
        constraints: vec!["branch:main".into(), "no-force-push".into()],
    };
    let hop3_scope = Scope {
        capability: "ReadCredential".into(),
        resource_id: Some("repo-x".into()),
        constraints: vec!["branch:main".into()],
    };

    let root = root_with_scope(root_scope.clone());
    let h1 = delegate(&root, hop1_scope.clone()).expect("hop1 delegate");
    let h2 = delegate(&h1, hop2_scope.clone()).expect("hop2 delegate");
    let h3 = delegate(&h2, hop3_scope.clone()).expect("hop3 delegate");

    // Per-hop subset (each hop ⊆ its parent).
    assert!(h1.scope.is_subset_of(&root.scope));
    assert!(h2.scope.is_subset_of(&h1.scope));
    assert!(h3.scope.is_subset_of(&h2.scope));

    // Transitive subset (last ⊆ root) — composition of the three hops.
    assert!(h3.scope.is_subset_of(&root.scope));

    // Delegation depth increments per hop.
    assert_eq!(root.delegation_depth, 0);
    assert_eq!(h1.delegation_depth, 1);
    assert_eq!(h2.delegation_depth, 2);
    assert_eq!(h3.delegation_depth, 3);

    // Parent-id linkage is correct.
    assert_eq!(h1.parent_id, Some(root.id));
    assert_eq!(h2.parent_id, Some(h1.id));
    assert_eq!(h3.parent_id, Some(h2.id));
}

// ----------------------------------------------------------------------
// (2) Property: 3-hop monotonic-narrowing chain succeeds
// ----------------------------------------------------------------------

proptest! {
    /// PROPERTY: a 3-hop chain that monotonically narrows by REMOVING
    /// constraints at each hop succeeds (per `Scope::is_subset_of`,
    /// child constraints ⊆ parent constraints, so removing constraints
    /// is the narrowing axis). Every hop scope is a subset of every
    /// earlier hop (transitive subset).
    ///
    /// Capability is held constant (capability cannot widen and is the
    /// equality axis); resource_id is `None`-only here so it doesn't
    /// affect the property; the narrowing axis is the constraints set.
    #[test]
    fn prop_three_hop_constraint_narrowing_succeeds(
        cap in arb_capability(),
        c1 in arb_constraint(),
        c2 in arb_constraint(),
        c3 in arb_constraint(),
    ) {
        prop_assume!(c1 != c2 && c2 != c3 && c1 != c3);

        // Root holds the full allowed-pattern set; each hop strictly
        // drops one constraint.
        let root_scope = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone(), c2.clone(), c3.clone()],
        };
        let hop1_scope = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone(), c2.clone(), c3.clone()],
        };
        let hop2_scope = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone(), c2.clone()],
        };
        let hop3_scope = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone()],
        };

        let root = root_with_scope(root_scope.clone());
        let h1 = delegate(&root, hop1_scope).expect("hop1");
        let h2 = delegate(&h1, hop2_scope).expect("hop2");
        let h3 = delegate(&h2, hop3_scope).expect("hop3");

        // Per-hop subset.
        prop_assert!(h1.scope.is_subset_of(&root.scope));
        prop_assert!(h2.scope.is_subset_of(&h1.scope));
        prop_assert!(h3.scope.is_subset_of(&h2.scope));
        // Transitive subset.
        prop_assert!(h3.scope.is_subset_of(&root.scope));
        prop_assert!(h2.scope.is_subset_of(&root.scope));
    }
}

// ----------------------------------------------------------------------
// (3) Property: widening at ANY hop is rejected
// ----------------------------------------------------------------------

proptest! {
    /// PROPERTY: in a 3-hop chain, attempting to widen by switching the
    /// capability at any hop is rejected with `ScopeViolation`. The
    /// widen attempt is parameterised over which hop (1, 2, or 3) tries
    /// to widen, and the rejection must happen at the widening hop
    /// regardless.
    #[test]
    fn prop_capability_widen_at_any_hop_rejected(
        cap_parent in arb_capability(),
        cap_widen in arb_capability(),
        widen_at_hop in 1usize..=3,
    ) {
        prop_assume!(cap_parent != cap_widen);

        // Base scope at root.
        let base_scope = Scope {
            capability: cap_parent.clone(),
            resource_id: None,
            constraints: vec![],
        };
        // Widening attempt swaps capability (which `is_subset_of`
        // requires to be equal).
        let widening_scope = Scope {
            capability: cap_widen.clone(),
            resource_id: None,
            constraints: vec![],
        };

        let root = root_with_scope(base_scope.clone());

        match widen_at_hop {
            1 => {
                // Hop 1 widens directly off the root.
                let result = delegate(&root, widening_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            2 => {
                // Hop 1 succeeds (equal scope), hop 2 widens.
                let h1 = delegate(&root, base_scope.clone()).expect("hop1 succeeds");
                let result = delegate(&h1, widening_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            3 => {
                // Hops 1+2 succeed (equal scope), hop 3 widens.
                let h1 = delegate(&root, base_scope.clone()).expect("hop1 succeeds");
                let h2 = delegate(&h1, base_scope.clone()).expect("hop2 succeeds");
                let result = delegate(&h2, widening_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            _ => unreachable!(),
        }
    }

    /// PROPERTY: in a 3-hop chain, attempting to widen by INTRODUCING
    /// a constraint pattern that does NOT appear in the parent's
    /// constraints set is rejected with `ScopeViolation` at the
    /// widening hop. (Per `Scope::is_subset_of`, child constraints
    /// ⊆ parent constraints — proposing an unknown constraint at
    /// the child violates subset-containment.)
    #[test]
    fn prop_constraint_add_unknown_widen_at_any_hop_rejected(
        cap in arb_capability(),
        c1 in arb_constraint(),
        c2 in arb_constraint(),
        unknown in arb_constraint(),
        widen_at_hop in 1usize..=3,
    ) {
        // The "unknown" constraint must not appear in the parent set.
        prop_assume!(c1 != c2 && unknown != c1 && unknown != c2);

        // Each "level" of the chain holds the parent's allowed set.
        let lvl0 = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone(), c2.clone()],
        };
        let lvl1 = lvl0.clone();
        let lvl2 = lvl0.clone();
        // The widen scope introduces an unknown constraint, which
        // breaks `child.constraints ⊆ parent.constraints`.
        let widen_scope = Scope {
            capability: cap.clone(),
            resource_id: None,
            constraints: vec![c1.clone(), unknown.clone()],
        };

        let root = root_with_scope(lvl0);

        match widen_at_hop {
            1 => {
                let result = delegate(&root, widen_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            2 => {
                let h1 = delegate(&root, lvl1.clone()).expect("hop1 keeps constraints");
                let result = delegate(&h1, widen_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            3 => {
                let h1 = delegate(&root, lvl1.clone()).expect("hop1 keeps constraints");
                let h2 = delegate(&h1, lvl2).expect("hop2 keeps constraints");
                let result = delegate(&h2, widen_scope);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            _ => unreachable!(),
        }
    }

    /// PROPERTY: in a 3-hop chain, attempting to widen by generalising
    /// the resource_id (specific → any) at any hop is rejected.
    ///
    /// `Scope::is_subset_of` treats `(parent=Some(x), child=None)` as a
    /// widening attempt because the child is broader than the parent.
    #[test]
    fn prop_resource_id_generalize_widen_rejected(
        cap in arb_capability(),
        res in arb_resource_id(),
        widen_at_hop in 1usize..=3,
    ) {
        let bounded = Scope {
            capability: cap.clone(),
            resource_id: Some(res.clone()),
            constraints: vec![],
        };
        let widened = Scope {
            capability: cap.clone(),
            resource_id: None, // generalise to "any resource"
            constraints: vec![],
        };

        let root = root_with_scope(bounded.clone());

        match widen_at_hop {
            1 => {
                let result = delegate(&root, widened);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            2 => {
                let h1 = delegate(&root, bounded.clone()).expect("hop1 keeps resource_id");
                let result = delegate(&h1, widened);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            3 => {
                let h1 = delegate(&root, bounded.clone()).expect("hop1 keeps resource_id");
                let h2 = delegate(&h1, bounded.clone()).expect("hop2 keeps resource_id");
                let result = delegate(&h2, widened);
                prop_assert!(result.is_err());
                prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
            }
            _ => unreachable!(),
        }
    }
}
