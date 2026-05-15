//! Offline attenuation predicates for delegated grants
//! (design § Offline attenuation, design §2.1).
//!
//! A delegated grant may reduce authority but never expand it. These helpers
//! verify — without hitting the wire or the issuer — that a requested child
//! grant is a subset of its parent along three axes:
//!
//! 1. **Scope** — child scope must be a subset of parent scope along the
//!    (provider, action, target, subtarget) tuple.
//! 2. **Budget** — for each axis a parent bounds, the child must bound the
//!    same axis and the child ceiling must fit inside parent's remaining
//!    allowance (parent budget minus parent usage).
//! 3. **Expiry** — if the parent has a TTL, the child must have one and it
//!    must be no later than the parent's.
//!
//! All helpers fail closed: anything ambiguous is rejected. Error messages
//! name only the violating axis (never the parent's full state) so that a
//! compromised child cannot use rejections as an oracle for parent state.
//!
//! Lifted verbatim from `ember-daemon::attenuation` per implementation-note-39.
//! No I/O — wasm32-compatible.

use core_grant_types::{AccessGrant, Budget, ResourceSelector, Statement, Usage};

/// Attenuation failure. `reason` names the violating dimension only —
/// parent values are deliberately elided so the error is not an oracle for a
/// compromised child probing parent state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationViolation {
    pub reason: String,
}

impl std::fmt::Display for DelegationViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "delegation violation: {}", self.reason)
    }
}

impl std::error::Error for DelegationViolation {}

impl DelegationViolation {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Tiny glob matcher supporting `*` as "any run of characters". Mirrors the
/// helper in `proxy.rs` (intentionally duplicated — this path runs in the
/// daemon's attenuation check, not inside request dispatch).
pub(crate) fn wildcard_match(pattern: &str, s: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == s;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == s;
    }
    let mut cursor = 0usize;
    // First fragment anchored to start.
    let first = parts[0];
    if !s[cursor..].starts_with(first) {
        return false;
    }
    cursor += first.len();
    // Middle fragments: find each in turn.
    for frag in &parts[1..parts.len() - 1] {
        if frag.is_empty() {
            continue;
        }
        match s[cursor..].find(frag) {
            Some(idx) => cursor += idx + frag.len(),
            None => return false,
        }
    }
    // Final fragment anchored to end (or empty = trailing wildcard).
    let last = parts[parts.len() - 1];
    if last.is_empty() {
        return true;
    }
    s[cursor..].ends_with(last) && s.len() - cursor >= last.len()
}

/// Parsed scope parts. Mirrors proxy.rs's parser shape.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeParts<'a> {
    provider: &'a str,
    action: &'a str,
    target: &'a str,
    subtarget: Option<&'a str>,
}

fn parse_scope(scope: &str) -> Result<ScopeParts<'_>, String> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Err("empty scope".into());
    }
    if scope == "*" {
        return Ok(ScopeParts {
            provider: "*",
            action: "*",
            target: "*",
            subtarget: None,
        });
    }
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("malformed scope: '{scope}'"));
    }
    if parts.len() > 4 {
        return Err(format!("scope has too many segments: '{scope}'"));
    }
    // Legacy bare-action form: "read", "push", "write".
    let parsed = match parts.as_slice() {
        [action] => ScopeParts {
            provider: "*",
            action,
            target: "*",
            subtarget: None,
        },
        [provider, action] => ScopeParts {
            provider,
            action,
            target: "*",
            subtarget: None,
        },
        [provider, action, target] => ScopeParts {
            provider,
            action,
            target,
            subtarget: None,
        },
        [provider, action, target, subtarget] => ScopeParts {
            provider,
            action,
            target,
            subtarget: Some(subtarget),
        },
        _ => return Err(format!("malformed scope: '{scope}'")),
    };
    Ok(parsed)
}

/// Check whether `child` scope is a subset of `parent` scope.
///
/// Returns `Ok(())` on subset; `Err(DelegationViolation)` otherwise.
///
/// Renamed from `scope_subset` per implementation-note-39 (design §2.1).
/// The behavior is identical — the rename clarifies that this is the
/// enforcement entry point (returns `Result`), distinct from the bool-returning
/// `Scope::is_subset_of` helper on the in-memory `core_grants::Grant` type.
///
/// Rules, each axis checked independently:
/// - **provider** — parent `*` subsumes any child provider; else must equal.
/// - **action** — parent `*` subsumes any child action; else must equal.
///   `write` and `push` are accepted as synonyms (mirrors proxy.rs).
/// - **target** — parent absent/`*` subsumes any child target; else the
///   parent target must glob-subsume the child target literal.
/// - **subtarget** — parent absent subsumes any child subtarget; else parent
///   subtarget must be present in child and glob-subsume it.
pub fn enforce_subset(child: &str, parent: &str) -> Result<(), DelegationViolation> {
    let p = parse_scope(parent).map_err(|e| {
        DelegationViolation::new(format!("parent scope unparseable: {e}"))
    })?;
    let c = parse_scope(child).map_err(|e| {
        DelegationViolation::new(format!("child scope unparseable: {e}"))
    })?;

    // Provider.
    if p.provider != "*" && p.provider != c.provider {
        return Err(DelegationViolation::new(
            "scope.provider not subset of parent",
        ));
    }

    // Action.
    if p.action != "*" && p.action != c.action {
        // Accept "write" as a synonym of "push" and vice versa.
        let synonym = matches!(
            (p.action, c.action),
            ("push", "write") | ("write", "push")
        );
        if !synonym {
            return Err(DelegationViolation::new(
                "scope.action not subset of parent",
            ));
        }
    }

    // Target. "*" in parent subsumes anything; else parent glob must match
    // the child target literal.
    if p.target != "*" && !wildcard_match(p.target, c.target) {
        return Err(DelegationViolation::new(
            "scope.target not subset of parent",
        ));
    }

    // Subtarget.
    match (p.subtarget, c.subtarget) {
        // Parent has no subtarget → any child subtarget is permitted.
        (None, _) => {}
        // Parent has a subtarget → child must too, and parent subtarget
        // must glob-subsume it.
        (Some(_), None) => {
            return Err(DelegationViolation::new(
                "scope.subtarget required: parent has subtarget",
            ));
        }
        (Some(ps), Some(cs)) => {
            if ps != "*" && !wildcard_match(ps, cs) {
                return Err(DelegationViolation::new(
                    "scope.subtarget not subset of parent",
                ));
            }
        }
    }

    Ok(())
}

/// Check whether a child's requested `Budget` fits inside the parent's
/// remaining allowance (parent budget minus parent usage), per design.
///
/// Semantics:
/// - `parent_budget == None` (or all-None fields) — OK, parent is TTL-only.
/// - Parent has a bounded axis & child is `None` — FAIL.
/// - For each axis the parent bounds, child must bound it too with
///   `child ≤ parent - usage`.
pub fn check_budget_attenuation(
    parent_budget: &Option<Budget>,
    parent_usage: &Usage,
    child_budget: &Option<Budget>,
) -> Result<(), DelegationViolation> {
    let Some(parent) = parent_budget.as_ref() else {
        return Ok(());
    };
    if parent.is_none_set() {
        return Ok(());
    }

    // Parent bounds at least one axis — child must carry a budget.
    let child = match child_budget.as_ref() {
        Some(c) if !c.is_none_set() => c,
        _ => {
            return Err(DelegationViolation::new(
                "budget required: parent has budget",
            ));
        }
    };

    fn axis_check(
        axis: &'static str,
        parent: Option<u64>,
        usage: u64,
        child: Option<u64>,
    ) -> Result<(), DelegationViolation> {
        let Some(parent_cap) = parent else {
            return Ok(());
        };
        let remaining = parent_cap.saturating_sub(usage);
        let Some(child_cap) = child else {
            return Err(DelegationViolation::new(format!(
                "budget.{axis} required: parent bounds {axis}"
            )));
        };
        if child_cap > remaining {
            return Err(DelegationViolation::new(format!(
                "budget.{axis} exceeds parent remaining"
            )));
        }
        Ok(())
    }

    axis_check("tokens", parent.tokens, parent_usage.tokens, child.tokens)?;
    axis_check("cents", parent.cents, parent_usage.cents, child.cents)?;
    axis_check(
        "requests",
        parent.requests,
        parent_usage.requests,
        child.requests,
    )?;
    axis_check(
        "workload_hours",
        parent.workload_hours,
        parent_usage.workload_hours,
        child.workload_hours,
    )?;
    axis_check(
        "wall_clock_secs",
        parent.wall_clock_secs,
        parent_usage.wall_clock_secs,
        child.wall_clock_secs,
    )?;

    Ok(())
}

/// Check whether a child's `expires_at` is inside the parent's.
///
/// - `parent == None` → OK.
/// - `parent == Some` & `child == None` → FAIL.
/// - else child ≤ parent (equal is allowed).
///
/// Both sides are epoch seconds (u64) as per `core_grant_types::AccessGrant`.
pub fn check_expiry_attenuation(
    parent_expires_at: Option<u64>,
    child_expires_at: Option<u64>,
) -> Result<(), DelegationViolation> {
    let Some(parent_ts) = parent_expires_at else {
        return Ok(());
    };
    let Some(child_ts) = child_expires_at else {
        return Err(DelegationViolation::new(
            "expiry required: parent has expiry",
        ));
    };
    if child_ts > parent_ts {
        return Err(DelegationViolation::new(
            "expiry exceeds parent remaining",
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Per-Statement attenuation (design / P69K-A2)
// ----------------------------------------------------------------------

/// True iff `child` selector is a subset of `parent` selector. `Any` in the
/// parent subsumes any child; `Exact` must match exactly; `Glob` uses the
/// same wildcard matcher as the scope path. Regex is not yet supported as a
/// parent — reject the child to fail closed.
fn selector_subset(child: &ResourceSelector, parent: &ResourceSelector) -> bool {
    match (parent, child) {
        (ResourceSelector::Any, _) => true,
        (ResourceSelector::Exact { value: p }, ResourceSelector::Exact { value: c }) => {
            p == c
        }
        (ResourceSelector::Glob { pattern: p }, ResourceSelector::Exact { value: c }) => {
            wildcard_match(p, c)
        }
        (ResourceSelector::Glob { pattern: p }, ResourceSelector::Glob { pattern: c }) => {
            // A glob-in-glob subset is only provable conservatively: treat
            // the child as a subset iff parent is "*" or parent == child.
            p == "*" || p == c
        }
        // P69E.5c: GlobWithSubtarget attenuation — the child must satisfy
        // both the parent's primary AND subtarget. We check primary like a
        // plain glob; subtarget is checked via string equality (or "*"
        // parent-subsumes-anything). `Glob` parents accept a
        // GlobWithSubtarget child only when the child's primary is
        // covered (the parent has no subtarget restriction), and a
        // GlobWithSubtarget parent never relaxes — it requires the same
        // subtarget shape. Conservative fail-closed: anything richer
        // returns false.
        (
            ResourceSelector::GlobWithSubtarget {
                primary_glob: pp,
                subtarget_glob: ps,
            },
            ResourceSelector::GlobWithSubtarget {
                primary_glob: cp,
                subtarget_glob: cs,
            },
        ) => (pp == "*" || pp == cp) && (ps == "*" || ps == cs),
        (
            ResourceSelector::Glob { pattern: p },
            ResourceSelector::GlobWithSubtarget { primary_glob: cp, .. },
        ) => p == "*" || p == cp,
        _ => false,
    }
}

/// True iff `child_actions` is a subset of `parent_actions`. Wildcard `*`
/// in the parent subsumes everything; otherwise every child action must
/// appear verbatim in the parent list. (Synonyms like push↔write, handled
/// by `enforce_subset` for legacy scopes, are NOT implied here — Statements
/// declare their actions explicitly.)
fn actions_subset(parent_actions: &[String], child_actions: &[String]) -> bool {
    if parent_actions.iter().any(|a| a == "*") {
        return true;
    }
    child_actions
        .iter()
        .all(|ca| parent_actions.iter().any(|pa| pa == ca))
}

/// Per-Statement attenuation check. For each statement in the child chain,
/// find a parent statement whose selector and action-set subsume it, and
/// whose budget leaves enough remaining headroom on every axis the child
/// bounds.
///
/// Semantics (child ≤ parent):
/// - Every child statement must have AT LEAST ONE matching parent statement
///   where `actions_subset(parent.actions, child.actions) &&
///   selector_subset(child.resource, parent.resource)`.
/// - For the matched parent, run `check_budget_attenuation` across the
///   parent's `(budget, usage)` and the child's budget.
///
/// Returns the first violation. On success, Ok(()).
pub fn check_statement_attenuation(
    parent: &AccessGrant,
    child: &AccessGrant,
) -> Result<(), DelegationViolation> {
    for (_ci, cstmt) in child.statements() {
        // Find a parent statement that subsumes this child statement.
        let matched = parent.statements().find(|(_, pstmt)| {
            actions_subset(&pstmt.actions, &cstmt.actions)
                && selector_subset(&cstmt.resource, &pstmt.resource)
        });

        let Some((_pi, pstmt)) = matched else {
            return Err(DelegationViolation::new(format!(
                "statement[{}] has no parent with matching selector/actions",
                cstmt.sid
            )));
        };

        // NOTE (P69K-A2-I4): resource_type is intentionally NOT an
        // attenuation axis. design §Attenuation names six axes —
        // actions, resource, budget, nbf, expires_at, conditions — and
        // resource_type is not among them. resource_type is a dispatch
        // hint used by the authorize walker and proxy routing, not an
        // authority axis. Requiring an exact match here would reject
        // legitimate attenuations of fully-permissive parents (e.g. the
        // `"*"` shim minted by `create_grant` which projects to
        // ResourceType::Credential) into typed child statements
        // (Session / Time / Payment).

        // Budget: child must fit inside parent's remaining allowance.
        check_budget_attenuation(&pstmt.budget, &pstmt.usage, &cstmt.budget)
            .map_err(|e| {
                DelegationViolation::new(format!(
                    "statement[{}] {}",
                    cstmt.sid, e.reason
                ))
            })?;
    }
    Ok(())
}

/// Compute the **union bound** of a set of approved statements (REVIEW2-F4).
///
/// The union bound is the minimal set `B` of parent statements such that every
/// approved child statement is dominated by at least one statement in `B` per
/// [`check_statement_attenuation`]'s rules (selector subsume, action subset,
/// budget headroom). For heterogeneous statement shapes the minimal bound is
/// just the input statements themselves: each child statement dominates itself
/// (matching selectors, identical action sets, and `child ≤ parent_remaining`
/// holds when usage is reset to zero).
///
/// This helper exists so callers minting an operator-approved composite chain
/// can synthesize a meaningful parent for the bipartite-dominance check that
/// `overwrite_grant_blocks` runs. Without it, the parent defaults to the
/// scope-`*` projection from `create_grant`, which dominates everything and
/// renders the dominance check trivially true. With this bound in place the
/// check has real teeth: any future attempt to overwrite the chain with a
/// statement outside the operator-approved set is rejected.
///
/// Notes on the returned bound:
/// - Each parent statement preserves its child's `actions`, `resource`,
///   `resource_type`, `conditions`, and `budget` verbatim.
/// - `usage` is reset to `Usage::default()` so the parent's "remaining
///   allowance" equals its full budget — required for the budget arm of the
///   dominance check to accept a child whose budget equals the parent's.
/// - `sid`s are preserved so error messages on a future violation still name
///   the offending statement intelligibly.
pub fn compute_statements_union_bound(stmts: &[Statement]) -> Vec<Statement> {
    stmts
        .iter()
        .map(|s| Statement {
            sid: s.sid.clone(),
            resource_type: s.resource_type,
            actions: s.actions.clone(),
            resource: s.resource.clone(),
            budget: s.budget.clone(),
            usage: Usage::default(),
            conditions: s.conditions.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(
        tokens: Option<u64>,
        cents: Option<u64>,
        requests: Option<u64>,
        workload_hours: Option<u64>,
        wall_clock_secs: Option<u64>,
    ) -> Budget {
        Budget {
            tokens,
            cents,
            requests,
            workload_hours,
            wall_clock_secs,
        }
    }

    fn usage(tokens: u64, cents: u64) -> Usage {
        Usage {
            tokens,
            cents,
            requests: 0,
            workload_hours: 0,
            wall_clock_secs: 0,
            last_updated: 0,
            cents_micro: cents.saturating_mul(1_000_000),
        }
    }

    // --- scope tests ---

    #[test]
    fn scope_strict_match_ok() {
        assert!(enforce_subset(
            "github:read:acme/widgets:main",
            "github:read:acme/widgets:main"
        )
        .is_ok());
    }

    #[test]
    fn scope_child_wider_target_rejected() {
        // Parent locks owner/repo; child asks for all-of-github — rejected.
        assert!(enforce_subset("github:read:*", "github:read:acme/widgets").is_err());
    }

    #[test]
    fn scope_parent_wildcard_provider_ok() {
        assert!(enforce_subset("github:read:acme/widgets", "*:read:*").is_ok());
        assert!(enforce_subset("github:read:acme/widgets", "*").is_ok());
    }

    #[test]
    fn scope_different_action_rejected() {
        assert!(
            enforce_subset("github:push:acme/widgets", "github:read:acme/widgets").is_err()
        );
    }

    #[test]
    fn scope_parent_target_glob_subsumes_child() {
        assert!(enforce_subset("github:read:acme/widgets", "github:read:acme/*").is_ok());
        assert!(
            enforce_subset("github:read:other/widgets", "github:read:acme/*").is_err()
        );
    }

    #[test]
    fn scope_subtarget_parent_absent_child_any() {
        // Parent has no subtarget → child may add one.
        assert!(enforce_subset(
            "github:read:acme/widgets:main",
            "github:read:acme/widgets"
        )
        .is_ok());
    }

    #[test]
    fn scope_subtarget_parent_present_child_absent_rejected() {
        assert!(enforce_subset(
            "github:read:acme/widgets",
            "github:read:acme/widgets:main"
        )
        .is_err());
    }

    #[test]
    fn scope_subtarget_glob_subsumes_child() {
        assert!(enforce_subset(
            "github:push:acme/widgets:feat/foo",
            "github:push:acme/widgets:feat/*"
        )
        .is_ok());
        assert!(enforce_subset(
            "github:push:acme/widgets:main",
            "github:push:acme/widgets:feat/*"
        )
        .is_err());
    }

    #[test]
    fn scope_push_write_synonyms() {
        assert!(
            enforce_subset("github:write:acme/widgets", "github:push:acme/widgets").is_ok()
        );
        assert!(
            enforce_subset("github:push:acme/widgets", "github:write:acme/widgets").is_ok()
        );
    }

    #[test]
    fn scope_malformed_rejected() {
        // Empty segment.
        assert!(enforce_subset("github::acme/widgets", "github:read:*").is_err());
        // Too many segments.
        assert!(enforce_subset("a:b:c:d:e", "*").is_err());
    }

    // --- budget tests ---

    #[test]
    fn budget_parent_none_child_any_ok() {
        assert!(check_budget_attenuation(&None, &usage(0, 0), &None).is_ok());
        assert!(check_budget_attenuation(
            &None,
            &usage(0, 0),
            &Some(budget(Some(999), None, None, None, None))
        )
        .is_ok());
    }

    #[test]
    fn budget_parent_some_child_none_rejected() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        let err = check_budget_attenuation(&parent, &usage(0, 0), &None).unwrap_err();
        assert!(err.reason.contains("budget"));
    }

    #[test]
    fn budget_child_fits_remaining_ok() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        let child = Some(budget(Some(3_000), None, None, None, None));
        assert!(check_budget_attenuation(&parent, &usage(2_000, 0), &child).is_ok());
        // Exactly remaining is ok.
        let child_exact = Some(budget(Some(8_000), None, None, None, None));
        assert!(
            check_budget_attenuation(&parent, &usage(2_000, 0), &child_exact).is_ok()
        );
    }

    #[test]
    fn budget_child_exceeds_remaining_rejected() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        let child = Some(budget(Some(15_000), None, None, None, None));
        let err =
            check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
        assert!(err.reason.contains("tokens"));
    }

    #[test]
    fn budget_child_exceeds_remaining_after_usage_rejected() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        // Remaining = 10_000 - 6_000 = 4_000. Child asks 5_000.
        let child = Some(budget(Some(5_000), None, None, None, None));
        let err =
            check_budget_attenuation(&parent, &usage(6_000, 0), &child).unwrap_err();
        assert!(err.reason.contains("tokens"));
    }

    #[test]
    fn budget_axis_parent_bounded_child_missing_rejected() {
        // Parent bounds cents; child only bounds tokens.
        let parent = Some(budget(None, Some(500), None, None, None));
        let child = Some(budget(Some(100), None, None, None, None));
        let err =
            check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
        assert!(err.reason.contains("cents"));
    }

    #[test]
    fn budget_unbounded_axes_skipped() {
        // Parent is Some but all fields None — equivalent to no budget.
        let parent = Some(budget(None, None, None, None, None));
        let child = Some(budget(Some(999_999), None, None, None, None));
        assert!(check_budget_attenuation(&parent, &usage(0, 0), &child).is_ok());
    }

    #[test]
    fn budget_multi_axis_all_enforced() {
        let parent = Some(budget(Some(10_000), Some(5000), Some(100), None, None));
        // Tokens OK, cents OK, requests too high.
        let child = Some(budget(Some(1000), Some(500), Some(999), None, None));
        let err =
            check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
        assert!(err.reason.contains("requests"));
    }

    // --- expiry tests ---

    #[test]
    fn expiry_parent_none_child_any_ok() {
        assert!(check_expiry_attenuation(None, None).is_ok());
        assert!(check_expiry_attenuation(None, Some(1_700_000_000)).is_ok());
    }

    #[test]
    fn expiry_parent_some_child_none_rejected() {
        let err = check_expiry_attenuation(Some(1_700_000_000), None).unwrap_err();
        assert!(err.reason.contains("expiry"));
    }

    #[test]
    fn expiry_child_earlier_ok() {
        assert!(
            check_expiry_attenuation(Some(1_700_000_000), Some(1_699_999_000)).is_ok()
        );
    }

    #[test]
    fn expiry_child_equal_ok() {
        assert!(
            check_expiry_attenuation(Some(1_700_000_000), Some(1_700_000_000)).is_ok()
        );
    }

    #[test]
    fn expiry_child_later_rejected() {
        let err = check_expiry_attenuation(Some(1_700_000_000), Some(1_700_001_000))
            .unwrap_err();
        assert!(err.reason.contains("expiry"));
    }

    // --- per-Statement attenuation tests ---

    fn make_grant(statements: Vec<core_grant_types::Statement>) -> AccessGrant {
        use core_grant_types::{
            AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, SignedBlock,
        };
        use core_event_types::PresentationAudienceKind;
        AccessGrant {
            id: "g".into(),
            version: 1,
            issuing_persona_id: "p".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "r".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block: Block {
                    statements,
                    nbf: None,
                    expires_at: None,
                    issued_by: "p".into(),
                    issued_at: 0,
                    approval: None,
                    note: None,
                },
                pubkey_next: "x".into(),
                signature: "x".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    fn stmt(
        sid: &str,
        actions: Vec<String>,
        resource: ResourceSelector,
        budget: Option<Budget>,
    ) -> core_grant_types::Statement {
        use core_grant_types::ResourceType;
        core_grant_types::Statement {
            sid: sid.into(),
            resource_type: ResourceType::Session,
            actions,
            resource,
            budget,
            usage: Usage::default(),
            conditions: Vec::new(),
        }
    }

    #[test]
    fn per_stmt_attenuation_accepted_when_child_bounds_smaller() {
        // Parent: llm:generate on any resource, 1000 tokens AND 600s wall-clock.
        let parent = make_grant(vec![stmt(
            "P",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(1000),
                wall_clock_secs: Some(600),
                ..Default::default()
            }),
        )]);
        // Child: same action/selector, 500 tokens + 300s.
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(500),
                wall_clock_secs: Some(300),
                ..Default::default()
            }),
        )]);
        assert!(check_statement_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn per_stmt_attenuation_rejects_child_budget_exceeds_parent() {
        let parent = make_grant(vec![stmt(
            "P",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(1000),
                wall_clock_secs: Some(600),
                ..Default::default()
            }),
        )]);
        // Child asks for 2000 tokens — violates.
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(2000),
                wall_clock_secs: Some(300),
                ..Default::default()
            }),
        )]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(err.reason.contains("tokens"), "reason: {}", err.reason);
    }

    #[test]
    fn per_stmt_attenuation_rejects_child_wall_clock_exceeds_parent() {
        let parent = make_grant(vec![stmt(
            "P",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(1000),
                wall_clock_secs: Some(600),
                ..Default::default()
            }),
        )]);
        // Child within token budget but asks for 900s — exceeds parent's 600.
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(500),
                wall_clock_secs: Some(900),
                ..Default::default()
            }),
        )]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(err.reason.contains("wall_clock"), "reason: {}", err.reason);
    }

    #[test]
    fn per_stmt_attenuation_rejects_when_selector_not_subset() {
        let parent = make_grant(vec![stmt(
            "P",
            vec!["llm:generate".into()],
            ResourceSelector::Exact { value: "model:haiku".into() },
            None,
        )]);
        // Child asks for a different exact resource.
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Exact { value: "model:opus".into() },
            None,
        )]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(err.reason.contains("no parent"), "reason: {}", err.reason);
    }

    #[test]
    fn per_stmt_attenuation_rejects_when_action_not_subset() {
        let parent = make_grant(vec![stmt(
            "P",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            None,
        )]);
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:finetune".into()],
            ResourceSelector::Any,
            None,
        )]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(err.reason.contains("no parent"), "reason: {}", err.reason);
    }

    #[test]
    fn per_stmt_attenuation_wildcard_parent_subsumes_any_child() {
        let parent = make_grant(vec![stmt(
            "P",
            vec!["*".into()],
            ResourceSelector::Any,
            None,
        )]);
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Exact { value: "x".into() },
            None,
        )]);
        assert!(check_statement_attenuation(&parent, &child).is_ok());
    }
}
