use core_grants::{
    Grant, GrantError, GrantSpec, GrantState, PrincipalId, Scope, TransitionEvent, Usage,
    UsageDelta, apply_event, create, delegate, extend, pause, resume, revoke, use_grant,
};
use proptest::prelude::*;

fn fixed_issuer() -> PrincipalId {
    PrincipalId("issuer-a".into())
}

fn fixed_scope() -> Scope {
    Scope {
        capability: "ReadCredential".into(),
        resource_id: Some("cred-1".into()),
        constraints: vec![],
    }
}

fn active_grant() -> Grant {
    create(GrantSpec {
        issuer: fixed_issuer(),
        scope: fixed_scope(),
        expires_at: None,
    })
    .unwrap()
}

fn arb_principal() -> impl Strategy<Value = PrincipalId> {
    "[a-z]{4,8}".prop_map(PrincipalId)
}

fn arb_scope() -> impl Strategy<Value = Scope> {
    (
        "[A-Za-z]{3,8}",
        proptest::option::of("[a-z]{4,8}"),
        proptest::collection::vec("[a-z]{3,6}", 0..3),
    )
        .prop_map(|(cap, res, cons)| Scope {
            capability: cap,
            resource_id: res,
            constraints: cons,
        })
}

fn arb_non_issuer_principal() -> impl Strategy<Value = PrincipalId> {
    // Generate a principal that is guaranteed different from fixed_issuer().
    "[a-z]{4,8}"
        .prop_filter("not the issuer", |s| s != "issuer-a")
        .prop_map(PrincipalId)
}

fn arb_duration() -> impl Strategy<Value = chrono::Duration> {
    (1i64..=3600).prop_map(|secs| chrono::Duration::seconds(secs))
}

fn arb_usage_delta() -> impl Strategy<Value = UsageDelta> {
    (1u64..=100).prop_map(|amount| UsageDelta { amount })
}

proptest! {
    /// prop_revoked_is_terminal: arbitrary Grant with state == Revoked; apply
    /// arbitrary event; assert all return GrantError::InvalidState or NotAuthorized.
    #[test]
    fn prop_revoked_is_terminal(
        principal in arb_principal(),
        scope in arb_scope(),
        ttl in arb_duration(),
        delta in arb_usage_delta(),
    ) {
        let mut grant = active_grant();
        grant.state = GrantState::Revoked;

        let events = vec![
            TransitionEvent::Extend(ttl),
            TransitionEvent::Delegate(scope),
            TransitionEvent::Use(delta),
            TransitionEvent::Pause(principal.clone()),
            TransitionEvent::Resume(principal.clone()),
            TransitionEvent::Revoke(principal.clone()),
        ];

        for event in events {
            let result = apply_event(grant.clone(), event);
            prop_assert!(
                result.is_err(),
                "Revoked grant accepted an event when it should be terminal"
            );
            let err = result.unwrap_err();
            prop_assert!(
                err == GrantError::InvalidState || err == GrantError::NotAuthorized,
                "expected InvalidState or NotAuthorized, got {:?}", err
            );
        }
    }

    /// prop_extend_requires_active: generate grant with state ∈ {Paused, Revoked};
    /// call extend; assert error.
    #[test]
    fn prop_extend_requires_active(ttl in arb_duration()) {
        for state in &[GrantState::Paused, GrantState::Revoked] {
            let mut grant = active_grant();
            grant.state = *state;
            let result = extend(grant, ttl);
            prop_assert!(result.is_err());
            prop_assert_eq!(result.unwrap_err(), GrantError::InvalidState);
        }
    }

    /// prop_delegation_narrows_scope: generate (parent_scope, child_scope) pairs
    /// where child ⊄ parent; assert delegate returns ScopeViolation.
    /// Also generate pairs where child ⊆ parent; assert child scope ⊆ parent.
    #[test]
    fn prop_delegation_narrows_scope(
        parent_cap in "[A-Z][a-z]{3,7}",
        child_cap in "[A-Z][a-z]{3,7}",
    ) {
        // Case 1: different capabilities — definitely not a subset.
        if parent_cap != child_cap {
            let parent_scope = Scope {
                capability: parent_cap.clone(),
                resource_id: None,
                constraints: vec![],
            };
            let child_scope = Scope {
                capability: child_cap.clone(),
                resource_id: None,
                constraints: vec![],
            };
            prop_assert!(!child_scope.is_subset_of(&parent_scope));

            let mut grant = active_grant();
            grant.scope = parent_scope;
            let result = delegate(&grant, child_scope);
            prop_assert!(result.is_err());
            prop_assert_eq!(result.unwrap_err(), GrantError::ScopeViolation);
        }

        // Case 2: same capability — child is subset; delegation succeeds.
        {
            let parent_scope = Scope {
                capability: parent_cap.clone(),
                resource_id: None,
                constraints: vec![],
            };
            let child_scope = Scope {
                capability: parent_cap.clone(),
                resource_id: None,
                constraints: vec![],
            };
            prop_assert!(child_scope.is_subset_of(&parent_scope));

            let mut grant = active_grant();
            grant.scope = parent_scope.clone();
            let child = delegate(&grant, child_scope).unwrap();
            prop_assert!(child.scope.is_subset_of(&parent_scope));
        }
    }

    /// prop_usage_monotonic: apply arbitrary sequence of use_grant calls on an
    /// Active grant; after each, assert grant.usage >= previous_usage.
    #[test]
    fn prop_usage_monotonic(deltas in proptest::collection::vec(arb_usage_delta(), 1..10)) {
        let mut grant = active_grant();
        let mut prev_usage = grant.usage.used;

        for delta in deltas {
            let result = use_grant(grant, delta);
            prop_assert!(result.is_ok());
            let (updated, _receipt) = result.unwrap();
            prop_assert!(
                updated.usage.used >= prev_usage,
                "usage decreased: {} < {}", updated.usage.used, prev_usage
            );
            prev_usage = updated.usage.used;
            grant = updated;
        }
    }

    /// prop_only_issuer_revokes: generate grant and random PrincipalId != grant.issuer;
    /// assert revoke returns NotAuthorized.
    #[test]
    fn prop_only_issuer_revokes(non_issuer in arb_non_issuer_principal()) {
        let grant = active_grant();
        // Verify the non_issuer is actually different.
        prop_assume!(non_issuer != fixed_issuer());

        let result = revoke(grant, &non_issuer);
        prop_assert!(result.is_err());
        prop_assert_eq!(result.unwrap_err(), GrantError::NotAuthorized);
    }

    /// prop_arbitrary_transition_sequence: generate Grant + sequence of TransitionEvents;
    /// apply in order; assert state machine invariants hold at every step.
    #[test]
    fn prop_arbitrary_transition_sequence(
        deltas in proptest::collection::vec(arb_usage_delta(), 1..5),
        ttl in arb_duration(),
    ) {
        let mut grant = active_grant();
        let issuer = fixed_issuer();
        let mut prev_usage = grant.usage.used;

        // Apply a deterministic but non-trivial sequence:
        // use × N → extend → pause → resume → revoke.
        for delta in &deltas {
            let result = use_grant(grant.clone(), *delta);
            prop_assert!(result.is_ok(), "use_grant failed on active grant");
            let (updated, _) = result.unwrap();
            prop_assert!(updated.usage.used >= prev_usage, "usage decreased");
            prop_assert_ne!(updated.state, GrantState::Revoked, "Revoked appeared unexpectedly after use");
            prev_usage = updated.usage.used;
            grant = updated;
        }

        // extend
        grant = extend(grant, ttl).unwrap();
        prop_assert_eq!(grant.state, GrantState::Active);

        // pause
        grant = pause(grant, &issuer).unwrap();
        prop_assert_eq!(grant.state, GrantState::Paused);

        // resume
        grant = resume(grant, &issuer).unwrap();
        prop_assert_eq!(grant.state, GrantState::Active);

        // revoke
        grant = revoke(grant, &issuer).unwrap();
        prop_assert_eq!(grant.state, GrantState::Revoked);

        // Any further event must fail.
        let post_result = use_grant(grant.clone(), UsageDelta { amount: 1 });
        prop_assert!(post_result.is_err());
        prop_assert_eq!(post_result.unwrap_err(), GrantError::InvalidState);
    }
}

/// Deterministic: revoked grant idempotent — revoking twice is fine.
#[test]
fn revoke_already_revoked_is_idempotent() {
    let grant = active_grant();
    let issuer = fixed_issuer();
    let revoked = revoke(grant, &issuer).unwrap();
    assert_eq!(revoked.state, GrantState::Revoked);
    // Revoking again should still succeed (idempotent per ADR 114 §2.2).
    let revoked2 = revoke(revoked, &issuer).unwrap();
    assert_eq!(revoked2.state, GrantState::Revoked);
}

/// Deterministic: delegation depth is bounded.
#[test]
fn delegation_depth_bounded() {
    let mut grant = active_grant();
    for _ in 0..core_grants::MAX_DELEGATION_DEPTH {
        grant = delegate(&grant, grant.scope.clone()).unwrap();
    }
    // One more delegation should fail.
    let result = delegate(&grant, grant.scope.clone());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), GrantError::InvalidState);
}

/// Deterministic: Usage::zero is the identity element for usage.
#[test]
fn usage_zero_is_default() {
    assert_eq!(Usage::zero().used, 0);
    let u = Usage::zero();
    let after = u.saturating_add(UsageDelta { amount: 42 });
    assert_eq!(after.used, 42);
}
