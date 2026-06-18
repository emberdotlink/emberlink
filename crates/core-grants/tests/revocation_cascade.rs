//! Property tests for cross-grant revocation cascade
//! (T1 tier per `.claude/rules/test-tiers.md`).
//!
//! Per ADR 205 §A.4, revocation is a mutable status set kept out of the
//! signed grant chain; use-time enforcement walks the `parent_id` ancestry
//! and refuses if any ancestor is revoked. This file pins the
//! cross-grant interaction property the existing single-grant
//! state-machine proptests in `state_machine.rs` and `attenuation.rs` do
//! not cover: revoking a parent grant invalidates every descendant in
//! the delegation graph.
//!
//! Modeled as an in-memory grant graph (parent → 2 children → 1
//! grandchild and arbitrary fan-out shapes). A helper
//! `is_effectively_revoked(graph, grant_id)` walks the `parent_id`
//! ancestry and returns `true` iff the grant itself OR any ancestor is
//! `Revoked` — this mirrors what the daemon's use-time verifier does at
//! every credential request (`trust::use_time_verify` per ADR 205).
//!
//! These are T1 (pure state-machine reasoning, no I/O).

use std::collections::HashMap;

use core_grants::{
    Grant, GrantError, GrantSpec, GrantState, PrincipalId, Scope, create, delegate, revoke,
};
use proptest::prelude::*;

// ----------------------------------------------------------------------
// In-memory grant graph + cascade helper
// ----------------------------------------------------------------------

/// Minimal in-memory grant graph keyed by `Grant.id`.
struct GrantGraph {
    grants: HashMap<uuid::Uuid, Grant>,
}

impl GrantGraph {
    fn new() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }

    fn insert(&mut self, grant: Grant) {
        self.grants.insert(grant.id, grant);
    }

    /// Mutate a grant in place via a closure (used to apply `revoke`).
    fn with_mut<F>(&mut self, id: &uuid::Uuid, f: F) -> Result<(), GrantError>
    where
        F: FnOnce(Grant) -> Result<Grant, GrantError>,
    {
        let grant = self.grants.remove(id).ok_or(GrantError::InvalidState)?;
        let updated = f(grant)?;
        self.grants.insert(updated.id, updated);
        Ok(())
    }

    /// Walk the `parent_id` ancestry of `grant_id`. Returns `true` iff
    /// the grant itself, or ANY ancestor in the chain, is `Revoked`.
    ///
    /// This is the use-time enforcement shape from ADR 205 §A.4 — the
    /// cascade is computed at use-time rather than stored.
    fn is_effectively_revoked(&self, grant_id: &uuid::Uuid) -> bool {
        let mut current = self.grants.get(grant_id);
        while let Some(g) = current {
            if g.state == GrantState::Revoked {
                return true;
            }
            current = g.parent_id.and_then(|pid| self.grants.get(&pid));
        }
        false
    }
}

// ----------------------------------------------------------------------
// Fixture builders
// ----------------------------------------------------------------------

fn fixed_issuer() -> PrincipalId {
    PrincipalId("issuer-cascade".into())
}

fn fixed_scope() -> Scope {
    Scope {
        capability: "ReadCredential".into(),
        resource_id: None,
        constraints: vec![],
    }
}

fn root_grant() -> Grant {
    create(GrantSpec {
        issuer: fixed_issuer(),
        scope: fixed_scope(),
        expires_at: None,
    })
    .expect("create root grant for cascade fixture")
}

// ----------------------------------------------------------------------
// (1) Deterministic shape: 3-level cascade tree
// ----------------------------------------------------------------------

/// Build the canonical cascade fixture: parent → 2 children → 1 grandchild
/// per child. Returns (graph, root_id, child_ids, grandchild_ids).
fn build_cascade_tree() -> (GrantGraph, uuid::Uuid, Vec<uuid::Uuid>, Vec<uuid::Uuid>) {
    let mut graph = GrantGraph::new();

    let root = root_grant();
    let root_id = root.id;

    let child_a = delegate(&root, fixed_scope()).expect("delegate child_a from root");
    let child_b = delegate(&root, fixed_scope()).expect("delegate child_b from root");
    let grandchild_a =
        delegate(&child_a, fixed_scope()).expect("delegate grandchild_a from child_a");
    let grandchild_b =
        delegate(&child_b, fixed_scope()).expect("delegate grandchild_b from child_b");

    let child_ids = vec![child_a.id, child_b.id];
    let grandchild_ids = vec![grandchild_a.id, grandchild_b.id];

    graph.insert(root);
    graph.insert(child_a);
    graph.insert(child_b);
    graph.insert(grandchild_a);
    graph.insert(grandchild_b);

    (graph, root_id, child_ids, grandchild_ids)
}

#[test]
fn cascade_tree_root_revoke_invalidates_every_descendant() {
    let (mut graph, root_id, child_ids, grandchild_ids) = build_cascade_tree();

    // Before revoke: nothing is effectively revoked.
    assert!(!graph.is_effectively_revoked(&root_id));
    for cid in &child_ids {
        assert!(!graph.is_effectively_revoked(cid));
    }
    for gid in &grandchild_ids {
        assert!(!graph.is_effectively_revoked(gid));
    }

    // Revoke the root.
    let issuer = fixed_issuer();
    graph
        .with_mut(&root_id, |g| revoke(g, &issuer))
        .expect("revoke root");

    // Every node in the tree is now effectively revoked.
    assert!(graph.is_effectively_revoked(&root_id));
    for cid in &child_ids {
        assert!(
            graph.is_effectively_revoked(cid),
            "child {cid} should be effectively revoked"
        );
    }
    for gid in &grandchild_ids {
        assert!(
            graph.is_effectively_revoked(gid),
            "grandchild {gid} should be effectively revoked"
        );
    }
}

#[test]
fn cascade_tree_child_revoke_invalidates_only_that_subtree() {
    let (mut graph, root_id, child_ids, grandchild_ids) = build_cascade_tree();

    let issuer = fixed_issuer();
    let revoked_child = child_ids[0];
    graph
        .with_mut(&revoked_child, |g| revoke(g, &issuer))
        .expect("revoke child_a");

    // Root is unaffected.
    assert!(!graph.is_effectively_revoked(&root_id));
    // The revoked child is revoked.
    assert!(graph.is_effectively_revoked(&revoked_child));
    // The sibling child is NOT revoked.
    let sibling = child_ids[1];
    assert!(!graph.is_effectively_revoked(&sibling));

    // The grandchild whose parent is revoked IS effectively revoked.
    // (grandchild_a was delegated from child_a, which is now revoked.)
    let grandchild_under_revoked = grandchild_ids[0];
    let grandchild_under_sibling = grandchild_ids[1];
    assert!(graph.is_effectively_revoked(&grandchild_under_revoked));
    assert!(!graph.is_effectively_revoked(&grandchild_under_sibling));
}

// ----------------------------------------------------------------------
// (2) Property: arbitrary fan-out cascade
// ----------------------------------------------------------------------

/// Strategy for a tree shape: (fanout_at_root, fanout_at_each_child),
/// each in the small bounded range that keeps the graph compact.
fn arb_fanout() -> impl Strategy<Value = (usize, usize)> {
    (1usize..=4, 1usize..=3)
}

proptest! {
    /// PROPERTY: revoking the root of a delegation tree (arbitrary
    /// fan-out at root and at each child) makes EVERY descendant
    /// effectively revoked via `parent_id` ancestry walk.
    ///
    /// This pins the cross-grant interaction invariant — the existing
    /// `state_machine.rs::prop_only_issuer_revokes` and
    /// `prop_revoked_is_terminal` proptests only see one grant at a
    /// time; this property ensures the cascade holds across an
    /// arbitrarily-shaped tree.
    #[test]
    fn prop_root_revoke_cascades_to_all_descendants(
        (fanout_root, fanout_child) in arb_fanout(),
    ) {
        let mut graph = GrantGraph::new();
        let issuer = fixed_issuer();

        let root = root_grant();
        let root_id = root.id;

        // Build the tree first to collect descendant ids.
        let mut descendant_ids: Vec<uuid::Uuid> = Vec::new();
        let mut children: Vec<Grant> = Vec::with_capacity(fanout_root);
        for _ in 0..fanout_root {
            let c = delegate(&root, fixed_scope())
                .expect("delegate child from root");
            descendant_ids.push(c.id);
            children.push(c);
        }
        let mut grandchildren: Vec<Grant> = Vec::new();
        for c in &children {
            for _ in 0..fanout_child {
                let gc = delegate(c, fixed_scope())
                    .expect("delegate grandchild from child");
                descendant_ids.push(gc.id);
                grandchildren.push(gc);
            }
        }

        graph.insert(root);
        for c in children {
            graph.insert(c);
        }
        for gc in grandchildren {
            graph.insert(gc);
        }

        // Pre-condition: nothing revoked.
        for did in &descendant_ids {
            prop_assert!(!graph.is_effectively_revoked(did));
        }

        // Revoke the root.
        graph
            .with_mut(&root_id, |g| revoke(g, &issuer))
            .expect("revoke root");

        // Post-condition: every descendant is effectively revoked.
        for did in &descendant_ids {
            prop_assert!(
                graph.is_effectively_revoked(did),
                "descendant {did} should be effectively revoked after root revoke"
            );
        }
        prop_assert!(graph.is_effectively_revoked(&root_id));
    }

    /// PROPERTY: revoking a non-root node only cascades to its own
    /// subtree — sibling subtrees remain effective.
    ///
    /// This is the inverse direction: the cascade is not global, it is
    /// strictly ancestry-scoped.
    #[test]
    fn prop_subtree_revoke_does_not_affect_sibling_subtrees(
        (fanout_root, fanout_child) in arb_fanout(),
    ) {
        // Need at least 2 children at the root so there IS a sibling
        // subtree to test against.
        prop_assume!(fanout_root >= 2);

        let mut graph = GrantGraph::new();
        let issuer = fixed_issuer();

        let root = root_grant();
        let root_id = root.id;

        let mut children: Vec<Grant> = Vec::with_capacity(fanout_root);
        for _ in 0..fanout_root {
            let c = delegate(&root, fixed_scope())
                .expect("delegate child from root");
            children.push(c);
        }
        let mut grandchild_under_each: Vec<Vec<uuid::Uuid>> = Vec::with_capacity(children.len());
        let mut grandchild_grants: Vec<Grant> = Vec::new();
        for c in &children {
            let mut row = Vec::with_capacity(fanout_child);
            for _ in 0..fanout_child {
                let gc = delegate(c, fixed_scope())
                    .expect("delegate grandchild from child");
                row.push(gc.id);
                grandchild_grants.push(gc);
            }
            grandchild_under_each.push(row);
        }

        let target_child_id = children[0].id;
        let target_subtree_grandchildren = grandchild_under_each[0].clone();
        let sibling_child_id = children[1].id;
        let sibling_subtree_grandchildren = grandchild_under_each[1].clone();

        graph.insert(root);
        for c in children {
            graph.insert(c);
        }
        for gc in grandchild_grants {
            graph.insert(gc);
        }

        // Revoke the target child (not the root).
        graph
            .with_mut(&target_child_id, |g| revoke(g, &issuer))
            .expect("revoke target child");

        // Root is unaffected.
        prop_assert!(!graph.is_effectively_revoked(&root_id));

        // Target subtree is fully revoked.
        prop_assert!(graph.is_effectively_revoked(&target_child_id));
        for gc_id in &target_subtree_grandchildren {
            prop_assert!(
                graph.is_effectively_revoked(gc_id),
                "grandchild {gc_id} under revoked target should be effectively revoked"
            );
        }

        // Sibling subtree is intact.
        prop_assert!(!graph.is_effectively_revoked(&sibling_child_id));
        for gc_id in &sibling_subtree_grandchildren {
            prop_assert!(
                !graph.is_effectively_revoked(gc_id),
                "grandchild {gc_id} under intact sibling should NOT be effectively revoked"
            );
        }
    }

    /// PROPERTY: revocation idempotence under cascade — applying
    /// `revoke` multiple times along the ancestry preserves the
    /// effective-revoked status of every descendant.
    #[test]
    fn prop_double_revoke_preserves_cascade(
        (fanout_root, fanout_child) in arb_fanout(),
    ) {
        let mut graph = GrantGraph::new();
        let issuer = fixed_issuer();

        let root = root_grant();
        let root_id = root.id;

        let mut descendant_ids: Vec<uuid::Uuid> = Vec::new();
        let mut children: Vec<Grant> = Vec::with_capacity(fanout_root);
        for _ in 0..fanout_root {
            let c = delegate(&root, fixed_scope())
                .expect("delegate child from root");
            descendant_ids.push(c.id);
            children.push(c);
        }
        let mut grandchild_grants: Vec<Grant> = Vec::new();
        for c in &children {
            for _ in 0..fanout_child {
                let gc = delegate(c, fixed_scope())
                    .expect("delegate grandchild from child");
                descendant_ids.push(gc.id);
                grandchild_grants.push(gc);
            }
        }
        graph.insert(root);
        for c in children {
            graph.insert(c);
        }
        for gc in grandchild_grants {
            graph.insert(gc);
        }

        // First revoke.
        graph
            .with_mut(&root_id, |g| revoke(g, &issuer))
            .expect("first revoke root");
        // Second revoke (idempotent per state.rs).
        graph
            .with_mut(&root_id, |g| revoke(g, &issuer))
            .expect("second revoke root is idempotent");

        for did in &descendant_ids {
            prop_assert!(graph.is_effectively_revoked(did));
        }
    }
}
