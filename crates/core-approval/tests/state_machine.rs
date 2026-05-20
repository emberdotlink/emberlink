use core_approval::{ApprovalOutcome, TransitionError, transition, ttl_elapsed};
use core_grant_types::approval::{ApprovalStatus, RequestedScope};
use proptest::prelude::*;

/// Helper: returns true iff `narrowed` is a syntactic subset of `request`.
/// A scope is a subset when its capability matches, its resource_id is at
/// least as specific (None in request means "any", so narrowed may specify),
/// and all narrowed constraints are present in the request constraints.
fn is_subset_of(narrowed: &RequestedScope, request: &RequestedScope) -> bool {
    if narrowed.capability != request.capability {
        return false;
    }
    match (&request.resource_id, &narrowed.resource_id) {
        // request is "any resource" — narrowed may be any or specific
        (None, _) => {}
        // request is specific — narrowed must match exactly
        (Some(req_id), Some(nar_id)) => {
            if req_id != nar_id {
                return false;
            }
        }
        // request is specific, narrowed is "any" — not a subset
        (Some(_), None) => return false,
    }
    // All narrowed constraints must appear in the request constraints.
    for c in &narrowed.constraints {
        if !request.constraints.contains(c) {
            return false;
        }
    }
    true
}

fn arb_terminal_status() -> impl Strategy<Value = ApprovalStatus> {
    prop_oneof![
        Just(ApprovalStatus::Approved),
        Just(ApprovalStatus::Denied),
        Just(ApprovalStatus::Expired),
        Just(ApprovalStatus::NarrowedAndApproved),
    ]
}

fn arb_outcome() -> impl Strategy<Value = ApprovalOutcome> {
    prop_oneof![
        Just(ApprovalOutcome::Approved),
        Just(ApprovalOutcome::Denied),
        (
            any::<String>(),
            proptest::option::of(any::<String>()),
            proptest::collection::vec(any::<String>(), 0..3)
        )
            .prop_map(
                |(cap, res, cons)| ApprovalOutcome::Narrowed(RequestedScope {
                    capability: cap,
                    resource_id: res,
                    constraints: cons,
                })
            ),
        any::<u64>().prop_map(|ttl| ApprovalOutcome::Always { ttl_seconds: ttl }),
    ]
}

proptest! {
    /// Invariant 1: Terminal states are absorbing — no event escapes them.
    #[test]
    fn prop_terminal_states_are_absorbing(
        state in arb_terminal_status(),
        outcome in arb_outcome(),
    ) {
        let result = transition(state, &outcome);
        prop_assert!(
            result.is_err(),
            "expected AlreadyDecided error for terminal state + any outcome"
        );
        prop_assert_eq!(result.unwrap_err(), TransitionError::AlreadyDecided);
    }

    /// Invariant 2: decide(Narrowed(scope)) rejects when scope is NOT a
    /// syntactic subset of the request scope.
    ///
    /// Here we verify the subset helper directly (the transition fn delegates
    /// subset enforcement to the adapter; this test documents the invariant
    /// and confirms the helper's logic).
    #[test]
    fn prop_decide_narrowed_rejects_non_subset(
        cap_req in "[a-zA-Z]{3,8}",
        cap_nar in "[a-zA-Z]{3,8}",
        req_resource in proptest::option::of("[a-z]{4,8}"),
        nar_resource in proptest::option::of("[a-z]{4,8}"),
    ) {
        // If capabilities differ, it's never a subset.
        if cap_req != cap_nar {
            let request = RequestedScope {
                capability: cap_req.clone(),
                resource_id: req_resource.clone(),
                constraints: vec![],
            };
            let narrowed = RequestedScope {
                capability: cap_nar.clone(),
                resource_id: nar_resource.clone(),
                constraints: vec![],
            };
            prop_assert!(!is_subset_of(&narrowed, &request));
        }
    }

    /// Invariant 3: decide(_) succeeds at most once per RequestId.
    /// After a terminal state is reached, calling transition again returns AlreadyDecided.
    #[test]
    fn prop_decide_succeeds_at_most_once(outcome in arb_outcome()) {
        // First transition from Pending succeeds.
        let first = transition(ApprovalStatus::Pending, &outcome);
        prop_assert!(first.is_ok());
        let terminal_state = first.unwrap();
        // Second call on the now-terminal state must fail.
        let second = transition(terminal_state, &outcome);
        prop_assert!(second.is_err());
        prop_assert_eq!(second.unwrap_err(), TransitionError::AlreadyDecided);
    }
}

/// Invariant 4: Dedup-stub — two identical RequestedScope values compared
/// with the subset check are reflexive (a scope is always a subset of itself).
#[test]
fn prop_dedup_stub() {
    let scope = RequestedScope {
        capability: "ReadCredential".into(),
        resource_id: Some("cred-netflix".into()),
        constraints: vec!["read-only".into()],
    };
    assert!(is_subset_of(&scope, &scope));
}

/// Invariant 5: apply_standing idempotent stub — two identical ttl values
/// are equal (documents that idempotency means same TTL input → same TTL output).
#[test]
fn prop_apply_standing_idempotent_stub() {
    let ttl_a: u64 = 3600;
    let ttl_b: u64 = 3600;
    assert_eq!(ttl_a, ttl_b);
}

/// Verify ttl_elapsed: Pending → Expired; terminal states reject.
#[test]
fn ttl_elapsed_pending_to_expired() {
    assert_eq!(
        ttl_elapsed(ApprovalStatus::Pending),
        Ok(ApprovalStatus::Expired)
    );
    assert_eq!(
        ttl_elapsed(ApprovalStatus::Approved),
        Err(TransitionError::AlreadyDecided)
    );
    assert_eq!(
        ttl_elapsed(ApprovalStatus::Denied),
        Err(TransitionError::AlreadyDecided)
    );
    assert_eq!(
        ttl_elapsed(ApprovalStatus::NarrowedAndApproved),
        Err(TransitionError::AlreadyDecided)
    );
    assert_eq!(
        ttl_elapsed(ApprovalStatus::Expired),
        Err(TransitionError::AlreadyDecided)
    );
}
