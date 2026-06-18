//! Property tests for `core_grants::scope` predicates
//! (T1 tier per `.claude/rules/test-tiers.md`).
//!
//! Per ARCH-GRANT-SCOPE-MODULE / ADR 114 §2.1, `core-grants` ships T1
//! property tests on day one. These properties exercise the two trust-boundary
//! invariants that `enforce_subset` and `check_budget_attenuation` are
//! supposed to uphold:
//!
//! 1. **Scope subset enforcement** — the function returns `Ok(())` iff the
//!    child scope is a subset of the parent scope, and a non-empty reason
//!    otherwise.
//! 2. **Budget monotonicity** — the function never accepts a child whose
//!    cap exceeds the parent's remaining allowance on a bounded axis.

use core_grant_types::{Budget, Usage};
use core_grants::scope::{check_budget_attenuation, enforce_subset};
use proptest::prelude::*;

// ----------------------------------------------------------------------
// (1) Scope subset properties
// ----------------------------------------------------------------------

/// Strategy for a non-empty, well-formed scope segment (no `:`, no empty).
fn segment_strat() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,7}".prop_map(|s| s.to_string())
}

/// Strategy for a 3-segment scope `provider:action:target`.
fn three_seg_scope() -> impl Strategy<Value = String> {
    (segment_strat(), segment_strat(), segment_strat()).prop_map(|(p, a, t)| format!("{p}:{a}:{t}"))
}

proptest! {
    /// A scope is always a subset of itself (reflexivity). `enforce_subset`
    /// must accept identical scopes regardless of their concrete shape.
    #[test]
    fn enforce_subset_reflexive(scope in three_seg_scope()) {
        prop_assert!(
            enforce_subset(&scope, &scope).is_ok(),
            "scope {scope} should be a subset of itself"
        );
    }

    /// The universal parent scope `*` accepts any well-formed child.
    #[test]
    fn enforce_subset_wildcard_parent_accepts_anything(child in three_seg_scope()) {
        prop_assert!(
            enforce_subset(&child, "*").is_ok(),
            "child {child} should be a subset of `*`"
        );
    }

    /// When the child provider differs from a non-wildcard parent provider,
    /// `enforce_subset` MUST reject and produce a non-empty reason.
    /// (Inverse direction: confirms the function does not silently accept
    /// out-of-scope children.)
    #[test]
    fn enforce_subset_rejects_distinct_provider(
        parent_provider in segment_strat(),
        child_provider in segment_strat(),
        action in segment_strat(),
        target in segment_strat(),
    ) {
        prop_assume!(parent_provider != child_provider);
        let parent = format!("{parent_provider}:{action}:{target}");
        let child = format!("{child_provider}:{action}:{target}");
        let result = enforce_subset(&child, &parent);
        prop_assert!(
            result.is_err(),
            "child {child} with provider {child_provider} should not be a subset of parent {parent}"
        );
        let violation = result.unwrap_err();
        prop_assert!(
            !violation.reason.is_empty(),
            "violation reason must be non-empty"
        );
    }

    /// When the child action differs from a non-wildcard parent action
    /// (and they are not push↔write synonyms), `enforce_subset` rejects.
    #[test]
    fn enforce_subset_rejects_distinct_action(
        provider in segment_strat(),
        parent_action in segment_strat(),
        child_action in segment_strat(),
        target in segment_strat(),
    ) {
        prop_assume!(parent_action != child_action);
        // Skip the push↔write synonym case which is intentionally accepted.
        prop_assume!(
            !((parent_action == "push" && child_action == "write")
                || (parent_action == "write" && child_action == "push"))
        );
        let parent = format!("{provider}:{parent_action}:{target}");
        let child = format!("{provider}:{child_action}:{target}");
        let result = enforce_subset(&child, &parent);
        prop_assert!(
            result.is_err(),
            "child action {child_action} should not be a subset of parent action {parent_action}"
        );
        prop_assert!(!result.unwrap_err().reason.is_empty());
    }
}

// ----------------------------------------------------------------------
// (2) Budget monotonicity
// ----------------------------------------------------------------------

fn usage_with_tokens(tokens: u64) -> Usage {
    Usage {
        tokens,
        cents: 0,
        requests: 0,
        workload_hours: 0,
        wall_clock_secs: 0,
        last_updated: 0,
        cents_micro: 0,
    }
}

fn budget_tokens(tokens: Option<u64>) -> Budget {
    Budget {
        tokens,
        cents: None,
        requests: None,
        workload_hours: None,
        wall_clock_secs: None,
    }
}

proptest! {
    /// Budget monotonicity invariant: when the parent bounds tokens with
    /// some cap C and has consumed U tokens, then for any child cap K:
    ///   - `K <= C - U` (saturating)  → accept
    ///   - `K  >  C - U` (saturating)  → reject with non-empty reason
    /// This is the load-bearing invariant — never accept a child exceeding
    /// parent remaining allowance on a bounded axis.
    #[test]
    fn budget_token_monotonicity(
        parent_cap in 0u64..1_000_000,
        usage_tokens in 0u64..1_000_000,
        child_cap in 0u64..1_000_000,
    ) {
        let parent = Some(budget_tokens(Some(parent_cap)));
        let used = usage_with_tokens(usage_tokens);
        let child = Some(budget_tokens(Some(child_cap)));

        let remaining = parent_cap.saturating_sub(usage_tokens);
        let result = check_budget_attenuation(&parent, &used, &child);

        if child_cap <= remaining {
            prop_assert!(
                result.is_ok(),
                "child cap {child_cap} ≤ remaining {remaining} should be accepted; got: {result:?}"
            );
        } else {
            prop_assert!(
                result.is_err(),
                "child cap {child_cap} > remaining {remaining} should be rejected; got: {result:?}"
            );
            let violation = result.unwrap_err();
            prop_assert!(
                !violation.reason.is_empty(),
                "violation reason must be non-empty"
            );
            prop_assert!(
                violation.reason.contains("tokens"),
                "violation reason should name the violating axis: {}",
                violation.reason
            );
        }
    }

    /// When parent bounds tokens but child carries no budget at all,
    /// `check_budget_attenuation` MUST reject.
    #[test]
    fn budget_parent_bounded_child_unbounded_rejected(
        parent_cap in 1u64..1_000_000,
    ) {
        let parent = Some(budget_tokens(Some(parent_cap)));
        let used = usage_with_tokens(0);
        let result = check_budget_attenuation(&parent, &used, &None);
        prop_assert!(result.is_err());
        prop_assert!(!result.unwrap_err().reason.is_empty());
    }

    /// When parent has no budget at all, any child budget (or no budget)
    /// is accepted. This anchors the "TTL-only parent" lower bound.
    #[test]
    fn budget_unbounded_parent_accepts_any_child(
        child_cap in proptest::option::of(0u64..1_000_000),
    ) {
        let used = usage_with_tokens(0);
        let child = child_cap.map(|c| budget_tokens(Some(c)));
        prop_assert!(check_budget_attenuation(&None, &used, &child).is_ok());
    }
}
