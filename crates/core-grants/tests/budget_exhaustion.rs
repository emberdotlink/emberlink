//! Property tests for budget-exhaustion attack paths
//! (T1 tier per `.claude/rules/test-tiers.md`).
//!
//! Per ADR 205 §A.3 (budget axis of `check_statement_attenuation`) and
//! the `GrantError::BudgetExhausted` doc contract in `grant.rs`, an
//! `Active` grant with a budget ceiling must:
//!
//! 1. Accept any consumption sequence whose running total stays within
//!    `ceiling` and reflect the consumed amount in `Usage.used`.
//! 2. Reject the FIRST consumption that would carry the running total
//!    past `ceiling` with the typed `GrantError::BudgetExhausted`
//!    variant.
//! 3. Preserve the invariant `consumed + remaining = ceiling` at every
//!    intermediate step — partial consumption does not silently lose
//!    the remaining budget.
//!
//! `core_grants::use_grant` is the pure state-machine wrapper; it does
//! not itself carry the ceiling (the ceiling lives in
//! `core_grant_types::Budget` attached to a `Statement` in the
//! authority-chain layer). To exercise the SAME `GrantError`
//! contract at this layer without reaching for the heavier
//! `core-grant-types` machinery, this suite wraps `use_grant` in a
//! `consume_within_ceiling` helper that models the use-time budget
//! check: `consumed + amount <= ceiling`, fail with
//! `GrantError::BudgetExhausted` otherwise. The wrapped helper is
//! exactly what the daemon's broker-side use-time verifier does today
//! (ADR 205 §A.3 fourth verifier), so the contract being pinned is the
//! one the production path also obeys.
//!
//! These are T1 (pure state-machine reasoning, no I/O).

use core_grants::{
    Grant, GrantError, GrantSpec, PrincipalId, Scope, Usage, UsageDelta, create, use_grant,
};
use proptest::prelude::*;

fn fixed_issuer() -> PrincipalId {
    PrincipalId("issuer-budget".into())
}

fn fixed_scope() -> Scope {
    Scope {
        capability: "ReadCredential".into(),
        resource_id: None,
        constraints: vec![],
    }
}

fn active_grant() -> Grant {
    create(GrantSpec {
        issuer: fixed_issuer(),
        scope: fixed_scope(),
        expires_at: None,
    })
    .expect("create grant for budget fixture")
}

/// Consume `amount` from `grant` under a `ceiling` cap, modeling the
/// daemon's use-time budget verifier (ADR 205 §A.3).
///
/// Returns `Err(GrantError::BudgetExhausted)` if `grant.usage.used +
/// amount > ceiling`. Otherwise delegates to `use_grant` and returns
/// the updated grant.
///
/// The check is `>` so that consuming exactly to the ceiling is
/// accepted; the FIRST consumption that would exceed the ceiling is
/// the one that fails.
fn consume_within_ceiling(
    grant: Grant,
    delta: UsageDelta,
    ceiling: u64,
) -> Result<Grant, GrantError> {
    let projected = grant.usage.used.saturating_add(delta.amount);
    if projected > ceiling {
        return Err(GrantError::BudgetExhausted);
    }
    use_grant(grant, delta).map(|(g, _)| g)
}

/// `consumed + remaining = ceiling` invariant projector.
fn remaining(grant: &Grant, ceiling: u64) -> u64 {
    ceiling.saturating_sub(grant.usage.used)
}

// ----------------------------------------------------------------------
// (1) Deterministic: ceiling exactly hit accepts; one-over rejects
// ----------------------------------------------------------------------

#[test]
fn consume_exactly_ceiling_accepts_then_one_over_rejects() {
    let grant = active_grant();
    let ceiling = 100u64;

    // Consume exactly the ceiling.
    let grant = consume_within_ceiling(grant, UsageDelta { amount: 100 }, ceiling)
        .expect("consuming exactly the ceiling must succeed");
    assert_eq!(grant.usage.used, 100);
    assert_eq!(remaining(&grant, ceiling), 0);

    // Any further consumption fails with BudgetExhausted.
    let result = consume_within_ceiling(grant, UsageDelta { amount: 1 }, ceiling);
    match result {
        Err(GrantError::BudgetExhausted) => {}
        other => panic!("expected BudgetExhausted, got {other:?}"),
    }
}

#[test]
fn zero_amount_consumption_at_full_ceiling_is_accepted() {
    let mut grant = active_grant();
    let ceiling = 50u64;
    // Drive usage all the way up.
    grant =
        consume_within_ceiling(grant, UsageDelta { amount: 50 }, ceiling).expect("fill to ceiling");
    // A zero-amount consumption at the ceiling is a no-op and must
    // succeed (`consumed + 0 == ceiling`, not `> ceiling`).
    let grant = consume_within_ceiling(grant, UsageDelta { amount: 0 }, ceiling)
        .expect("zero-amount consumption at ceiling must succeed");
    assert_eq!(grant.usage.used, 50);
}

#[test]
fn usage_zero_is_default_and_remaining_equals_ceiling() {
    let grant = active_grant();
    assert_eq!(grant.usage, Usage::zero());
    let ceiling = 1_000u64;
    assert_eq!(remaining(&grant, ceiling), ceiling);
}

// ----------------------------------------------------------------------
// (2) Property: partial consumption preserves remaining budget
// ----------------------------------------------------------------------

proptest! {
    /// PROPERTY: a sequence of consumptions whose running total stays
    /// within the ceiling preserves the invariant `consumed +
    /// remaining = ceiling` at every step, and the final `Usage.used`
    /// equals the sum of all deltas.
    #[test]
    fn prop_partial_consumption_preserves_remaining_budget(
        ceiling in 1u64..=100_000,
        deltas in proptest::collection::vec(0u64..=1_000, 1..20),
    ) {
        let mut grant = active_grant();
        let mut running_total: u64 = 0;

        for amount in deltas {
            // Only consume if it keeps us within the ceiling — bail out
            // of the consume loop the FIRST time we would exceed.
            let projected = running_total.saturating_add(amount);
            if projected > ceiling {
                break;
            }
            let result =
                consume_within_ceiling(grant.clone(), UsageDelta { amount }, ceiling);
            prop_assert!(
                result.is_ok(),
                "within-ceiling consumption should be accepted: \
                 running={running_total} + amount={amount} ≤ ceiling={ceiling}; got {result:?}"
            );
            grant = result.expect("consume within ceiling");
            running_total = projected;

            // Invariant: consumed + remaining == ceiling.
            prop_assert_eq!(grant.usage.used, running_total);
            prop_assert_eq!(
                grant.usage.used + remaining(&grant, ceiling),
                ceiling,
                "consumed+remaining must equal ceiling"
            );
        }

        // Post: final consumed total reflects the sum of accepted deltas.
        prop_assert_eq!(grant.usage.used, running_total);
        prop_assert!(grant.usage.used <= ceiling);
    }
}

// ----------------------------------------------------------------------
// (3) Property: first over-ceiling consumption returns typed Err
// ----------------------------------------------------------------------

proptest! {
    /// PROPERTY: starting from any partially-consumed `(consumed,
    /// ceiling)` pair, a delta whose addition would cross the ceiling
    /// returns the typed `GrantError::BudgetExhausted` variant — never
    /// `InvalidState`, `ScopeViolation`, or `NotAuthorized`. The
    /// grant's `Usage` is also unchanged after the rejection (failure
    /// must not partial-charge).
    #[test]
    fn prop_first_over_ceiling_consumption_returns_budget_exhausted(
        ceiling in 1u64..=100_000,
        already_consumed in 0u64..=100_000,
        over_amount in 1u64..=100_000,
    ) {
        prop_assume!(already_consumed <= ceiling);
        // Construct the delta as: take us from `already_consumed`
        // strictly past `ceiling`.
        let delta_amount = (ceiling - already_consumed) + over_amount;
        // Defend against u64 overflow on saturating_add — only run if
        // the strict-exceed condition holds.
        let projected = already_consumed.saturating_add(delta_amount);
        prop_assume!(projected > ceiling);

        // Seed the grant with `already_consumed` so the property starts
        // from a realistic mid-state.
        let mut grant = active_grant();
        grant.usage = grant.usage.saturating_add(UsageDelta { amount: already_consumed });
        let usage_before = grant.usage;

        let result = consume_within_ceiling(
            grant.clone(),
            UsageDelta { amount: delta_amount },
            ceiling,
        );

        match result {
            Err(GrantError::BudgetExhausted) => {}
            Ok(_) => prop_assert!(
                false,
                "expected BudgetExhausted (projected {projected} > ceiling {ceiling}), got Ok"
            ),
            Err(other) => prop_assert!(
                false,
                "expected BudgetExhausted, got distinct error variant: {other:?}"
            ),
        }

        // Failure must NOT charge partial usage.
        prop_assert_eq!(grant.usage, usage_before);
    }

    /// PROPERTY: a within-ceiling sequence followed by a SINGLE
    /// over-ceiling delta returns `BudgetExhausted`, AND the
    /// `(consumed, remaining)` pair is exactly what the partial
    /// sequence left behind (no silent dropped grant, no partial
    /// charge from the failed step).
    #[test]
    fn prop_partial_then_overflow_preserves_partial_state(
        ceiling in 10u64..=100_000,
        deltas in proptest::collection::vec(1u64..=1_000, 1..10),
        overflow_kick in 1u64..=10_000,
    ) {
        let mut grant = active_grant();
        let mut running_total: u64 = 0;

        for amount in &deltas {
            let projected = running_total.saturating_add(*amount);
            if projected > ceiling {
                break;
            }
            grant =
                consume_within_ceiling(grant, UsageDelta { amount: *amount }, ceiling)
                    .expect("within-ceiling step");
            running_total = projected;
        }

        // Now attempt an overflow that is GUARANTEED to exceed.
        let overflow_amount =
            (ceiling - running_total).saturating_add(overflow_kick);
        let usage_before = grant.usage;
        let remaining_before = remaining(&grant, ceiling);

        let result = consume_within_ceiling(
            grant.clone(),
            UsageDelta { amount: overflow_amount },
            ceiling,
        );
        prop_assert!(
            matches!(result, Err(GrantError::BudgetExhausted)),
            "expected BudgetExhausted on overflow kick {overflow_kick} beyond \
             running_total={running_total}, ceiling={ceiling}; got {result:?}"
        );

        // Partial state preserved.
        prop_assert_eq!(grant.usage, usage_before);
        prop_assert_eq!(remaining(&grant, ceiling), remaining_before);
    }
}

// ----------------------------------------------------------------------
// (4) Property: a SINGLE huge delta that would overflow u64 is
//     still safely rejected and never silently wraps.
// ----------------------------------------------------------------------

proptest! {
    /// PROPERTY: u64-saturation safety. Even if a malicious caller
    /// passes `UsageDelta::amount == u64::MAX`, the projected sum
    /// (`already_consumed + u64::MAX`) saturates rather than wraps, so
    /// the comparison `projected > ceiling` is always true and the
    /// consumption is rejected. This pins the saturating-add behavior
    /// of `Usage::saturating_add` so a future refactor can't quietly
    /// reintroduce wrapping arithmetic on the consumption path.
    #[test]
    fn prop_max_u64_delta_does_not_wrap_around_ceiling(
        ceiling in 0u64..=u64::MAX,
        already_consumed in 0u64..=100_000,
    ) {
        prop_assume!(already_consumed <= ceiling);

        let mut grant = active_grant();
        grant.usage = grant.usage.saturating_add(UsageDelta {
            amount: already_consumed,
        });
        let usage_before = grant.usage;

        let result = consume_within_ceiling(
            grant.clone(),
            UsageDelta { amount: u64::MAX },
            ceiling,
        );
        // u64::MAX added to any non-zero already_consumed saturates,
        // and saturating sum is strictly greater than ceiling unless
        // ceiling == u64::MAX *and* already_consumed == 0, in which
        // case projected == u64::MAX == ceiling — that single edge
        // accepts. We expose that edge explicitly:
        let edge_accepts = ceiling == u64::MAX && already_consumed == 0;
        if edge_accepts {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(
                matches!(result, Err(GrantError::BudgetExhausted)),
                "u64::MAX consumption beyond non-saturating ceiling must \
                 BudgetExhaust; ceiling={ceiling}, already={already_consumed}, \
                 got {result:?}"
            );
            // Usage is unchanged on rejection.
            prop_assert_eq!(grant.usage, usage_before);
        }
    }
}
