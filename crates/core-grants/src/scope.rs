//! Offline attenuation predicates for delegated grants
//! (ADR 072 § Offline attenuation, ADR 114 §2.1).
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
//! Lifted verbatim from `ember-daemon::attenuation` per ARCH-GRANT-SCOPE-MODULE.
//! No I/O — wasm32-compatible.

use core_grant_types::{
    AccessGrant, Budget, CanDelegate, Condition, GrantStatus, ResourceSelector, Statement, Usage,
};

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
/// Renamed from `scope_subset` per ARCH-GRANT-SCOPE-MODULE (ADR 114 §2.1).
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
    let p = parse_scope(parent)
        .map_err(|e| DelegationViolation::new(format!("parent scope unparseable: {e}")))?;
    let c = parse_scope(child)
        .map_err(|e| DelegationViolation::new(format!("child scope unparseable: {e}")))?;

    // Provider.
    if p.provider != "*" && p.provider != c.provider {
        return Err(DelegationViolation::new(
            "scope.provider not subset of parent",
        ));
    }

    // Action.
    if p.action != "*" && p.action != c.action {
        // Accept "write" as a synonym of "push" and vice versa.
        let synonym = matches!((p.action, c.action), ("push", "write") | ("write", "push"));
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
/// remaining allowance (parent budget minus parent usage), per ADR 072.
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
        return Err(DelegationViolation::new("expiry exceeds parent remaining"));
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Per-Statement attenuation (ADR 073 / P69K-A2)
// ----------------------------------------------------------------------

/// True iff `child` selector is a subset of `parent` selector. `Any` in the
/// parent subsumes any child; `Exact` must match exactly; `Glob` uses the
/// same wildcard matcher as the scope path. Regex is not yet supported as a
/// parent — reject the child to fail closed.
fn selector_subset(child: &ResourceSelector, parent: &ResourceSelector) -> bool {
    match (parent, child) {
        (ResourceSelector::Any, _) => true,
        (ResourceSelector::Exact { value: p }, ResourceSelector::Exact { value: c }) => p == c,
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
            ResourceSelector::GlobWithSubtarget {
                primary_glob: cp, ..
            },
        ) => p == "*" || p == cp,
        _ => false,
    }
}

/// True iff `child_actions` is a subset of `parent_actions`. Wildcard `*`
/// in the parent subsumes everything; an anchored provider wildcard
/// `<provider>:*` subsumes any child action under that same provider
/// (`<provider>:<object>:<verb>`) but NEVER a different provider; otherwise
/// every child action must appear verbatim in the parent list. (Synonyms like
/// push↔write, handled by `enforce_subset` for legacy scopes, are NOT implied
/// here — Statements declare their actions explicitly.)
fn actions_subset(parent_actions: &[String], child_actions: &[String]) -> bool {
    // Full wildcard: parent action exactly `*` subsumes anything (all providers).
    if parent_actions.iter().any(|a| a == "*") {
        return true;
    }
    child_actions
        .iter()
        .all(|ca| parent_actions.iter().any(|pa| action_covers(pa, ca)))
}

/// True iff a single parent action covers a single child action.
///
/// Covers when either:
/// - they are exactly equal (verbatim membership), or
/// - the parent is an anchored provider wildcard `<provider>:*` and the child
///   begins with that exact `<provider>:` literal prefix.
///
/// SECURITY-LOAD-BEARING. The provider segment is matched EXACTLY (split on the
/// FIRST `:`); the parent's remainder must be exactly `*`. No substring/partial
/// matching: `github:*` covers `github:<object>:<verb>` but never `aws:...`, and
/// `aws:*` never covers `github:...`. Fail-closed on malformed parents (no
/// colon, empty provider) — such a wildcard covers nothing.
fn action_covers(parent_action: &str, child_action: &str) -> bool {
    if parent_action == child_action {
        return true;
    }
    // Anchored `<provider>:*` wildcard. Split on the FIRST colon so the provider
    // segment is compared exactly and the remainder must be exactly `*`.
    if let Some((p_provider, p_rest)) = parent_action.split_once(':') {
        if p_rest != "*" || p_provider.is_empty() {
            return false;
        }
        // Child must carry the same provider segment, anchored by `<provider>:`.
        match child_action.split_once(':') {
            Some((c_provider, _c_rest)) => return c_provider == p_provider,
            None => return false,
        }
    }
    false
}

/// True iff every condition the parent imposes is also present (verbatim) in
/// the child — i.e. `child_conditions ⊇ parent_conditions`. The child may ADD
/// conditions (strictly narrower) but may never DROP or weaken one; otherwise a
/// delegated child could strip a parent's `MerchantAllowlist` / `Cidr` /
/// `TimeWindow` and widen. Conservative + fail-closed: equality-based, so a
/// semantically-narrower-but-not-identical child condition is treated as a drop;
/// richer condition-implication is future work. (ADR 205 §8 predicate hardening.)
fn conditions_subsumed(parent_conditions: &[Condition], child_conditions: &[Condition]) -> bool {
    parent_conditions
        .iter()
        .all(|pc| child_conditions.iter().any(|cc| cc == pc))
}

/// child ≤ parent on the delegation axis: a not-delegable child is always
/// fine (narrower); a delegable child requires a delegable parent and may
/// not exceed its remaining depth. (ADR 205 §8.)
fn can_delegate_subsumed(parent: &Option<CanDelegate>, child: &Option<CanDelegate>) -> bool {
    match (parent, child) {
        (_, None) => true,
        (Some(p), Some(c)) => c.max_depth <= p.max_depth,
        (None, Some(_)) => false,
    }
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
        // Find a parent statement that subsumes this child statement across
        // all authority axes. Heterogeneous statements can share action and
        // resource selectors while bounding different budget axes, so the
        // first selector match is not necessarily a valid attenuation parent.
        let mut saw_selector_match = false;
        let mut budget_violation = None;
        let mut conditions_violation = None;
        let mut delegation_violation = None;
        let mut matched = false;

        for (_pi, pstmt) in parent.statements() {
            if !(actions_subset(&pstmt.actions, &cstmt.actions)
                && selector_subset(&cstmt.resource, &pstmt.resource))
            {
                continue;
            }

            saw_selector_match = true;

            // child ≤ parent on the conditions axis: the child must carry every
            // condition the parent imposes (it may add conditions = narrower,
            // never drop or weaken one). Without this a delegated child strips a
            // parent's MerchantAllowlist / Cidr / TimeWindow and widens.
            // (ADR 205 §8 predicate hardening.)
            if !conditions_subsumed(&pstmt.conditions, &cstmt.conditions) {
                if conditions_violation.is_none() {
                    conditions_violation = Some(DelegationViolation::new(format!(
                        "statement[{}] drops or weakens a parent condition",
                        cstmt.sid
                    )));
                }
                continue;
            }

            // child ≤ parent on the delegation axis: a not-delegable child is
            // always fine; a delegable child requires a delegable parent and
            // may not exceed its remaining depth. (ADR 205 §8.)
            if !can_delegate_subsumed(&pstmt.can_delegate, &cstmt.can_delegate) {
                if delegation_violation.is_none() {
                    delegation_violation = Some(DelegationViolation::new(format!(
                        "statement[{}] requests delegation beyond parent",
                        cstmt.sid
                    )));
                }
                continue;
            }

            match check_budget_attenuation(&pstmt.budget, &pstmt.usage, &cstmt.budget) {
                Ok(()) => {
                    matched = true;
                    break;
                }
                Err(err) if budget_violation.is_none() => budget_violation = Some(err),
                Err(_) => {}
            }
        }

        if matched {
            continue;
        }

        if !saw_selector_match {
            return Err(DelegationViolation::new(format!(
                "statement[{}] has no parent with matching selector/actions",
                cstmt.sid
            )));
        }

        // Error precedence: a budget mismatch can only be recorded for a parent
        // whose conditions the child already satisfied (the conditions check
        // `continue`s before budget), so it is the closest failure — surface it
        // first, then any conditions violation.
        if let Some(err) = budget_violation {
            return Err(DelegationViolation::new(format!(
                "statement[{}] {}",
                cstmt.sid, err.reason
            )));
        }
        if let Some(err) = delegation_violation {
            return Err(err);
        }
        if let Some(err) = conditions_violation {
            return Err(err);
        }

        // NOTE (ADR 205 §8 / P69K-A2-I4): the enforced attenuation axes are
        // actions, resource, budget, and conditions. `resource_type` is
        // intentionally NOT an axis — it is a dispatch hint for the authorize
        // walker / proxy routing, not an authority axis; requiring an exact
        // match would reject legitimate attenuations of a fully-permissive
        // parent (e.g. the `"*"` shim minted by `create_grant`,
        // ResourceType::Credential) into typed child statements
        // (Session / Time / Payment). `nbf` / `expires_at` are enforced at the
        // envelope level (effective_nbf / effective_expires_at), not here.
    }
    Ok(())
}

// ───────────────────────── BKR-4a: use-time authorization ─────────────────────────
//
// `check_statement_attenuation` above is the DELEGATION predicate (a child
// *grant* ≤ a parent *grant*; conditions are *subsumed* — a child may not drop
// one). Authorization at point-of-use is a different reduction of the same
// `need ⊆ grant` algebra (ADR 205 §1/§8 I8): an action's least-privilege
// capability *need* (declared by the action manifest in the one
// `provider:object:verb` Statement vocabulary) is checked against the persona's
// *set* of active standing grants. The axes here are need.actions ⊆ grant.actions,
// need.resource ⊆ grant.resource, and the grant still has budget headroom — the
// request is the "child", but it carries no budget/conditions of its own, so this
// is NOT `check_statement_attenuation(grant, need)` (that would wrongly demand the
// need re-state every grant condition). See `clause_covers_need`.

/// Outcome of resolving an action's capability `need` against a persona's set
/// of active standing grants (ADR 205 §1, I8/I10). Fail-closed: anything not
/// provably covered by a **single** grant is `Unsatisfiable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedResolution {
    /// Exactly one standing grant covers every clause of the need. `grant_id`
    /// is the covering grant; `matched_statement_sids` records, per need clause,
    /// the grant statement that covered it (audit / receipt evidence).
    Covered {
        grant_id: String,
        matched_statement_sids: Vec<String>,
    },
    /// No single active grant covers the whole need. `reason` names the axis
    /// of failure only (never grant state — same oracle-avoidance discipline as
    /// [`DelegationViolation`]).
    Unsatisfiable { reason: NeedUnsatisfiable },
}

/// Why a need could not be satisfied by any single active standing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedUnsatisfiable {
    /// The action declared no capability need. The caller MUST distinguish a
    /// genuinely credential-less action (transparent passthrough, ADR 205 §4)
    /// from a missing/undeclared manifest need (refuse, I11) *before* calling
    /// this predicate — an empty need reaching here is treated fail-closed.
    EmptyNeed,
    /// The persona holds no active standing grant at all.
    NoActiveGrant,
    /// Some clause of the need is covered by no active grant.
    UncoveredClause,
    /// Every clause is individually coverable, but no *single* grant covers them
    /// all — the need spans two sibling grants, which is unsatisfiable at the
    /// cap (ADR 205 I10: `match_active_grant` returns a single covering grant).
    SpansMultipleGrants,
}

impl std::fmt::Display for NeedUnsatisfiable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NeedUnsatisfiable::EmptyNeed => "empty_need",
            NeedUnsatisfiable::NoActiveGrant => "no_active_standing_grant",
            NeedUnsatisfiable::UncoveredClause => "need_clause_uncovered",
            NeedUnsatisfiable::SpansMultipleGrants => "need_spans_multiple_grants",
        };
        f.write_str(s)
    }
}

/// True iff a single grant `Statement` covers a single need clause at use-time.
///
/// Axes (need = the request, grant = held authority):
/// - `need.actions ⊆ grant.actions` (`actions_subset`, parent=grant)
/// - `need.resource ⊆ grant.resource` (`selector_subset`, child=need)
/// - the grant statement still has budget headroom on every axis it bounds.
/// - **conditions: fail-closed.** A grant statement carrying any `Condition`
///   does NOT cover a need here, because use-time condition *satisfaction*
///   (TimeWindow / Cidr / MerchantAllowlist evaluated against the request
///   context) is not yet wired at any boundary (the proxy does not evaluate
///   them either). Authorizing past an unevaluated condition would silently
///   widen, so a conditioned statement is unusable on this path until the
///   evaluator lands. Conditions are still preserved downhill by
///   [`check_statement_attenuation`] at delegation time. Documented limit
///   (ADR 205 §8 conditions axis; no silent cap).
fn clause_covers_need(grant_stmt: &Statement, need_clause: &Statement) -> bool {
    actions_subset(&grant_stmt.actions, &need_clause.actions)
        && selector_subset(&need_clause.resource, &grant_stmt.resource)
        && grant_stmt.has_budget_remaining()
        && grant_stmt.conditions.is_empty()
}

/// True iff `grant` (must be Active) covers EVERY clause of `need`, each by some
/// statement within this one grant. Returns the matched statement sid per clause.
fn grant_covers_need(grant: &AccessGrant, need: &[Statement]) -> Option<Vec<String>> {
    if grant.status != GrantStatus::Active || grant.revoked_at.is_some() {
        return None;
    }
    let mut matched = Vec::with_capacity(need.len());
    for clause in need {
        let hit = grant
            .statements()
            .find(|(_, gstmt)| clause_covers_need(gstmt, clause));
        match hit {
            Some((_, gstmt)) => matched.push(gstmt.sid.clone()),
            None => return None,
        }
    }
    Some(matched)
}

/// Resolve an action's capability `need` against a persona's set of active
/// standing grants (ADR 205 §1 — the use-time authorization spine, BKR-4a).
///
/// Returns the **single** covering grant, or `Unsatisfiable` (fail-closed). A
/// need is satisfiable only when one grant covers all of it: a need spanning two
/// sibling grants is refused (I10). At dev0/team0 the set is cardinality-1 by
/// policy, so the "spans" case is structurally absent — but the predicate handles
/// N>1 so the policy cap, not the type, is the only thing to relax later (§3).
///
/// `need` is the action manifest's least-privilege requirement expressed as
/// `Statement`s (one algebra, I8); only `actions` and `resource` are read from
/// each need clause (a request carries no budget/conditions of its own).
/// `grants` should be the persona's candidate grants; non-Active/revoked grants
/// are skipped defensively here regardless.
pub fn resolve_need_against_grants(grants: &[AccessGrant], need: &[Statement]) -> NeedResolution {
    if need.is_empty() {
        return NeedResolution::Unsatisfiable {
            reason: NeedUnsatisfiable::EmptyNeed,
        };
    }

    let mut saw_active = false;
    for grant in grants {
        if grant.status != GrantStatus::Active || grant.revoked_at.is_some() {
            continue;
        }
        saw_active = true;
        if let Some(matched_statement_sids) = grant_covers_need(grant, need) {
            return NeedResolution::Covered {
                grant_id: grant.id.clone(),
                matched_statement_sids,
            };
        }
    }

    if !saw_active {
        return NeedResolution::Unsatisfiable {
            reason: NeedUnsatisfiable::NoActiveGrant,
        };
    }

    // No single grant covered the whole need. Distinguish "some clause is
    // coverable by no active grant at all" (UncoveredClause) from "every clause
    // is individually coverable, just not by one grant" (SpansMultipleGrants),
    // so the operator-facing message can say which (request-up vs split-grant).
    let every_clause_coverable_somewhere = need.iter().all(|clause| {
        grants.iter().any(|grant| {
            (grant.status == GrantStatus::Active && grant.revoked_at.is_none())
                && grant
                    .statements()
                    .any(|(_, gstmt)| clause_covers_need(gstmt, clause))
        })
    });

    NeedResolution::Unsatisfiable {
        reason: if every_clause_coverable_somewhere {
            NeedUnsatisfiable::SpansMultipleGrants
        } else {
            NeedUnsatisfiable::UncoveredClause
        },
    }
}

// ---------------------------------------------------------------------------
// ADR 205 §A.4 — online revocation walk over grant ancestry
// ---------------------------------------------------------------------------

/// The first ancestor grant that blocks a descendant's use, found by the
/// ADR 205 §A.4 revocation walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedAncestor {
    /// The offending ancestor grant-id (an entry from the descendant's
    /// `ancestor_grant_ids`).
    pub grant_id: String,
    /// Why it blocks use — names the axis only (oracle-avoidance discipline,
    /// like [`NeedUnsatisfiable`]).
    pub reason: AncestorRevocation,
}

/// Why an ancestor grant blocks a descendant at use-time (ADR 205 §A.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestorRevocation {
    /// The ancestor carries a `revoked_at` timestamp.
    Revoked,
    /// The ancestor's status is not `Active` (expired / exhausted / …).
    NonActive,
    /// The ancestor grant-id is **absent** from the set handed in. Treated as
    /// blocking (FAIL-CLOSED): a holder cannot prove that a reaped or deleted
    /// ancestor was still valid, so a missing ancestor must never silently keep
    /// a descendant alive.
    Absent,
}

impl std::fmt::Display for AncestorRevocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AncestorRevocation::Revoked => "revoked",
            AncestorRevocation::NonActive => "non_active",
            AncestorRevocation::Absent => "absent",
        })
    }
}

/// Walk a grant's ancestry and return the first ancestor that blocks use, per
/// ADR 205 §A.4 (the **online** revocation walk).
///
/// `ancestry_ids` is the descendant's transitive ancestor grant-ids
/// (`AccessGrant::ancestor_grant_ids`, BKR-4b-1), ordered nearest-parent-first.
/// `active_grants` is the live set each id is resolved against — the §A.4
/// **mutable status set kept OUTSIDE the signed chain**, so revoking an ancestor
/// never re-signs any descendant block and in-flight already-minted leases
/// survive to their TTL (§A.4: honest latency, not an instant cascade — this
/// gates authorize/mint time, not live leases).
///
/// Returns `Some(RevokedAncestor)` for the **first** (nearest) ancestor that is
/// revoked, non-`Active`, or **absent** from `active_grants` (absent is
/// fail-closed). Returns `None` only when every ancestor resolves to an
/// `Active`, non-revoked grant.
///
/// This is the grant-level half of §A.4 and is intentionally **orthogonal** to
/// per-statement-SID revocation: a grant can be revoked at any ancestry depth
/// without touching individual statements, so both checks stack at a boundary.
///
/// **Root-agnostic** — it trusts `active_grants` are themselves chain-verified
/// (the §A.3 composition gates authenticity upstream). Use it only inside that
/// composition, never as the sole authority check.
pub fn first_revoked_ancestor(
    ancestry_ids: &[String],
    active_grants: &[AccessGrant],
) -> Option<RevokedAncestor> {
    for ancestor_id in ancestry_ids {
        let reason = match active_grants.iter().find(|g| &g.id == ancestor_id) {
            None => Some(AncestorRevocation::Absent),
            Some(g) if g.revoked_at.is_some() => Some(AncestorRevocation::Revoked),
            Some(g) if g.status != GrantStatus::Active => Some(AncestorRevocation::NonActive),
            Some(_) => None,
        };
        if let Some(reason) = reason {
            return Some(RevokedAncestor {
                grant_id: ancestor_id.clone(),
                reason,
            });
        }
    }
    None
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
            can_delegate: s.can_delegate.clone(),
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
        assert!(
            enforce_subset(
                "github:read:acme/widgets:main",
                "github:read:acme/widgets:main"
            )
            .is_ok()
        );
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
        assert!(enforce_subset("github:push:acme/widgets", "github:read:acme/widgets").is_err());
    }

    #[test]
    fn scope_parent_target_glob_subsumes_child() {
        assert!(enforce_subset("github:read:acme/widgets", "github:read:acme/*").is_ok());
        assert!(enforce_subset("github:read:other/widgets", "github:read:acme/*").is_err());
    }

    #[test]
    fn scope_subtarget_parent_absent_child_any() {
        // Parent has no subtarget → child may add one.
        assert!(
            enforce_subset("github:read:acme/widgets:main", "github:read:acme/widgets").is_ok()
        );
    }

    #[test]
    fn scope_subtarget_parent_present_child_absent_rejected() {
        assert!(
            enforce_subset("github:read:acme/widgets", "github:read:acme/widgets:main").is_err()
        );
    }

    #[test]
    fn scope_subtarget_glob_subsumes_child() {
        assert!(
            enforce_subset(
                "github:push:acme/widgets:feat/foo",
                "github:push:acme/widgets:feat/*"
            )
            .is_ok()
        );
        assert!(
            enforce_subset(
                "github:push:acme/widgets:main",
                "github:push:acme/widgets:feat/*"
            )
            .is_err()
        );
    }

    #[test]
    fn scope_push_write_synonyms() {
        assert!(enforce_subset("github:write:acme/widgets", "github:push:acme/widgets").is_ok());
        assert!(enforce_subset("github:push:acme/widgets", "github:write:acme/widgets").is_ok());
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
        assert!(
            check_budget_attenuation(
                &None,
                &usage(0, 0),
                &Some(budget(Some(999), None, None, None, None))
            )
            .is_ok()
        );
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
        assert!(check_budget_attenuation(&parent, &usage(2_000, 0), &child_exact).is_ok());
    }

    #[test]
    fn budget_child_exceeds_remaining_rejected() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        let child = Some(budget(Some(15_000), None, None, None, None));
        let err = check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
        assert!(err.reason.contains("tokens"));
    }

    #[test]
    fn budget_child_exceeds_remaining_after_usage_rejected() {
        let parent = Some(budget(Some(10_000), None, None, None, None));
        // Remaining = 10_000 - 6_000 = 4_000. Child asks 5_000.
        let child = Some(budget(Some(5_000), None, None, None, None));
        let err = check_budget_attenuation(&parent, &usage(6_000, 0), &child).unwrap_err();
        assert!(err.reason.contains("tokens"));
    }

    #[test]
    fn budget_axis_parent_bounded_child_missing_rejected() {
        // Parent bounds cents; child only bounds tokens.
        let parent = Some(budget(None, Some(500), None, None, None));
        let child = Some(budget(Some(100), None, None, None, None));
        let err = check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
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
        let err = check_budget_attenuation(&parent, &usage(0, 0), &child).unwrap_err();
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
        assert!(check_expiry_attenuation(Some(1_700_000_000), Some(1_699_999_000)).is_ok());
    }

    #[test]
    fn expiry_child_equal_ok() {
        assert!(check_expiry_attenuation(Some(1_700_000_000), Some(1_700_000_000)).is_ok());
    }

    #[test]
    fn expiry_child_later_rejected() {
        let err = check_expiry_attenuation(Some(1_700_000_000), Some(1_700_001_000)).unwrap_err();
        assert!(err.reason.contains("expiry"));
    }

    // --- per-Statement attenuation tests ---

    fn make_grant(statements: Vec<core_grant_types::Statement>) -> AccessGrant {
        use core_event_types::PresentationAudienceKind;
        use core_grant_types::{
            AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile, SignedBlock,
        };
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

    // --- ADR 205 §A.4 revocation-walk tests ---

    /// A grant fixture with a specific id / status / revoked_at, reusing
    /// `make_grant` so it stays correct when BKR-4b-1 adds ancestry fields.
    fn gf(id: &str, status: GrantStatus, revoked_at: Option<u64>) -> AccessGrant {
        let mut g = make_grant(vec![]);
        g.id = id.into();
        g.status = status;
        g.revoked_at = revoked_at;
        g
    }

    #[test]
    fn revwalk_empty_ancestry_is_none() {
        // Apex grant: no ancestors → nothing to block.
        assert_eq!(
            first_revoked_ancestor(&[], &[gf("g", GrantStatus::Active, None)]),
            None
        );
    }

    #[test]
    fn revwalk_all_ancestors_active_is_none() {
        let grants = vec![
            gf("a", GrantStatus::Active, None),
            gf("b", GrantStatus::Active, None),
        ];
        let anc = vec!["a".to_string(), "b".to_string()];
        assert_eq!(first_revoked_ancestor(&anc, &grants), None);
    }

    #[test]
    fn revwalk_revoked_at_set_blocks() {
        let grants = vec![gf("a", GrantStatus::Active, Some(123))];
        let got = first_revoked_ancestor(&["a".to_string()], &grants).unwrap();
        assert_eq!(got.grant_id, "a");
        assert_eq!(got.reason, AncestorRevocation::Revoked);
    }

    #[test]
    fn revwalk_non_active_status_blocks() {
        // status != Active (Expired here), revoked_at unset → NonActive.
        let grants = vec![gf("a", GrantStatus::Expired, None)];
        let got = first_revoked_ancestor(&["a".to_string()], &grants).unwrap();
        assert_eq!(got.grant_id, "a");
        assert_eq!(got.reason, AncestorRevocation::NonActive);
    }

    #[test]
    fn revwalk_absent_ancestor_is_fail_closed() {
        // Ancestor id not in the active set → Absent (a missing/reaped ancestor
        // must not silently keep a descendant alive).
        let got = first_revoked_ancestor(&["ghost".to_string()], &[]).unwrap();
        assert_eq!(got.grant_id, "ghost");
        assert_eq!(got.reason, AncestorRevocation::Absent);
    }

    #[test]
    fn revwalk_returns_first_bad_in_walk_order() {
        // Nearest parent "a" active, grandparent "b" revoked → returns "b".
        let grants = vec![
            gf("a", GrantStatus::Active, None),
            gf("b", GrantStatus::Active, Some(1)),
        ];
        let anc = vec!["a".to_string(), "b".to_string()];
        assert_eq!(first_revoked_ancestor(&anc, &grants).unwrap().grant_id, "b");
    }

    #[test]
    fn revwalk_stops_at_nearest_when_multiple_bad() {
        // Both ancestors revoked → returns the nearest ("a"), not the farthest.
        let grants = vec![
            gf("a", GrantStatus::Active, Some(1)),
            gf("b", GrantStatus::Active, Some(2)),
        ];
        let anc = vec!["a".to_string(), "b".to_string()];
        assert_eq!(first_revoked_ancestor(&anc, &grants).unwrap().grant_id, "a");
    }

    #[test]
    fn revwalk_absent_takes_precedence_over_later_active() {
        // A missing nearest ancestor blocks even if farther ancestors are fine.
        let grants = vec![gf("b", GrantStatus::Active, None)];
        let anc = vec!["missing".to_string(), "b".to_string()];
        let got = first_revoked_ancestor(&anc, &grants).unwrap();
        assert_eq!(got.grant_id, "missing");
        assert_eq!(got.reason, AncestorRevocation::Absent);
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
            can_delegate: None,
        }
    }

    fn act(parent: &[&str], child: &[&str]) -> bool {
        let parent: Vec<String> = parent.iter().map(|s| s.to_string()).collect();
        let child: Vec<String> = child.iter().map(|s| s.to_string()).collect();
        actions_subset(&parent, &child)
    }

    #[test]
    fn actions_subset_provider_wildcard_covers_same_provider() {
        // `github:*` subsumes any `github:<object>:<verb>` child.
        assert!(act(&["github:*"], &["github:contents:write"]));
        assert!(act(&["github:*"], &["github:pull_request:create"]));
        assert!(act(
            &["github:*"],
            &["github:contents:write", "github:pull_request:create"]
        ));
    }

    #[test]
    fn actions_subset_provider_wildcard_never_crosses_providers() {
        // `github:*` MUST NOT subsume a different provider's actions.
        assert!(!act(&["github:*"], &["aws:assume_role"]));
        assert!(!act(&["github:*"], &["aws_sts:assume_role"]));
        // `aws:*` MUST NOT subsume github actions.
        assert!(!act(&["aws:*"], &["github:contents:write"]));
    }

    #[test]
    fn actions_subset_full_wildcard_covers_everything() {
        assert!(act(&["*"], &["github:contents:write"]));
        assert!(act(&["*"], &["aws:assume_role"]));
        assert!(act(
            &["*"],
            &[
                "github:contents:write",
                "aws:assume_role",
                "anything:at:all"
            ]
        ));
    }

    #[test]
    fn actions_subset_provider_wildcard_requires_anchored_colon() {
        // A bare provider segment with no colon is NOT covered by `<provider>:*`
        // (anchoring requires the literal `<provider>:` prefix on the child).
        assert!(!act(&["github:*"], &["github"]));
        // And a malformed parent wildcard (no colon) covers nothing.
        assert!(!act(&["github"], &["github:contents:write"]));
        // Empty provider parent wildcard (`:*`) covers nothing.
        assert!(!act(&[":*"], &["github:contents:write"]));
    }

    #[test]
    fn actions_subset_provider_wildcard_no_partial_provider_match() {
        // No substring/prefix-of-provider matching: `git:*` must not cover
        // `github:...` even though "git" is a prefix of "github".
        assert!(!act(&["git:*"], &["github:contents:write"]));
        // And `github:*` must not cover a provider that merely starts with it.
        assert!(!act(&["github:*"], &["github_actions:contents:write"]));
    }

    #[test]
    fn actions_subset_mixed_provider_child_each_must_be_covered() {
        // A child list spanning providers is subsumed only if EVERY child
        // action is covered. `github:*` covers the github clause but not aws.
        assert!(!act(
            &["github:*"],
            &["github:contents:write", "aws:assume_role"]
        ));
        // Two wildcards together cover both.
        assert!(act(
            &["github:*", "aws:*"],
            &["github:contents:write", "aws:assume_role"]
        ));
    }

    #[test]
    fn actions_subset_verbatim_still_required_without_wildcard() {
        // Exact membership unaffected by the wildcard addition.
        assert!(act(
            &["github:contents:write", "github:pull_request:create"],
            &["github:contents:write"]
        ));
        assert!(!act(&["github:contents:read"], &["github:contents:write"]));
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
    fn per_stmt_attenuation_rejects_dropped_parent_condition() {
        use core_grant_types::{Condition, ResourceType};
        let parent_stmt = core_grant_types::Statement {
            sid: "P".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["x402:pay".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(50),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: vec![Condition::MerchantAllowlist {
                merchants: vec!["openai.com".into(), "anthropic.com".into()],
            }],
            can_delegate: None,
        };
        // Child keeps the action/selector/budget but DROPS the merchant
        // allowlist — a widening that must be rejected.
        let child_stmt = core_grant_types::Statement {
            sid: "C".into(),
            conditions: vec![],
            ..parent_stmt.clone()
        };
        let parent = make_grant(vec![parent_stmt]);
        let child = make_grant(vec![child_stmt]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(
            err.reason.contains("condition"),
            "expected a conditions violation, got: {}",
            err.reason
        );
    }

    #[test]
    fn per_stmt_attenuation_accepts_child_that_retains_parent_condition() {
        use core_grant_types::{Condition, ResourceType};
        let parent_stmt = core_grant_types::Statement {
            sid: "P".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["x402:pay".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(50),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: vec![Condition::MerchantAllowlist {
                merchants: vec!["openai.com".into()],
            }],
            can_delegate: None,
        };
        // Child retains the parent condition verbatim and tightens budget → ok.
        let child_stmt = core_grant_types::Statement {
            sid: "C".into(),
            budget: Some(Budget {
                cents: Some(25),
                ..Default::default()
            }),
            ..parent_stmt.clone()
        };
        let parent = make_grant(vec![parent_stmt]);
        let child = make_grant(vec![child_stmt]);
        assert!(check_statement_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn per_stmt_attenuation_tries_later_matching_parent_when_budget_fits() {
        let parent = make_grant(vec![
            stmt(
                "P-too-small",
                vec!["llm:generate".into()],
                ResourceSelector::Any,
                Some(Budget {
                    tokens: Some(100),
                    ..Default::default()
                }),
            ),
            stmt(
                "P-fit",
                vec!["llm:generate".into()],
                ResourceSelector::Any,
                Some(Budget {
                    tokens: Some(1000),
                    ..Default::default()
                }),
            ),
        ]);
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            Some(Budget {
                tokens: Some(500),
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
            ResourceSelector::Exact {
                value: "model:haiku".into(),
            },
            None,
        )]);
        // Child asks for a different exact resource.
        let child = make_grant(vec![stmt(
            "C",
            vec!["llm:generate".into()],
            ResourceSelector::Exact {
                value: "model:opus".into(),
            },
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

    fn stmt_with_delegate(
        sid: &str,
        can_delegate: Option<CanDelegate>,
    ) -> core_grant_types::Statement {
        let mut s = stmt(
            sid,
            vec!["llm:generate".into()],
            ResourceSelector::Any,
            None,
        );
        s.can_delegate = can_delegate;
        s
    }

    #[test]
    fn per_stmt_attenuation_rejects_child_delegation_beyond_parent() {
        let parent = make_grant(vec![stmt_with_delegate(
            "P",
            Some(CanDelegate { max_depth: 2 }),
        )]);
        let child = make_grant(vec![stmt_with_delegate(
            "C",
            Some(CanDelegate { max_depth: 3 }),
        )]);
        let err = check_statement_attenuation(&parent, &child).unwrap_err();
        assert!(
            err.reason.contains("delegation"),
            "expected a delegation violation, got: {}",
            err.reason
        );
    }

    #[test]
    fn per_stmt_attenuation_accepts_child_delegation_within_parent() {
        let parent = make_grant(vec![stmt_with_delegate(
            "P",
            Some(CanDelegate { max_depth: 2 }),
        )]);
        let child = make_grant(vec![stmt_with_delegate(
            "C",
            Some(CanDelegate { max_depth: 1 }),
        )]);
        assert!(check_statement_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn per_stmt_attenuation_accepts_non_delegable_child_under_delegable_parent() {
        let parent = make_grant(vec![stmt_with_delegate(
            "P",
            Some(CanDelegate { max_depth: 2 }),
        )]);
        let child = make_grant(vec![stmt_with_delegate("C", None)]);
        assert!(check_statement_attenuation(&parent, &child).is_ok());
    }

    // ───────────── BKR-4a: resolve_need_against_grants ─────────────

    /// Build a named grant with an explicit status / revoked posture so the
    /// active-filtering paths can be exercised independently of `make_grant`.
    fn grant_named(
        id: &str,
        status: core_grant_types::GrantStatus,
        revoked: bool,
        statements: Vec<core_grant_types::Statement>,
    ) -> AccessGrant {
        let mut g = make_grant(statements);
        g.id = id.into();
        g.status = status;
        g.revoked_at = revoked.then_some(1);
        g
    }

    fn exact(repo: &str) -> ResourceSelector {
        ResourceSelector::Exact { value: repo.into() }
    }

    fn glob(pattern: &str) -> ResourceSelector {
        ResourceSelector::Glob {
            pattern: pattern.into(),
        }
    }

    /// A need clause is a `Statement` whose only meaningful fields are
    /// `actions` + `resource` (the request carries no budget/conditions).
    fn need_clause(
        actions: Vec<String>,
        resource: ResourceSelector,
    ) -> core_grant_types::Statement {
        stmt("need", actions, resource, None)
    }

    use core_grant_types::GrantStatus;

    #[test]
    fn resolve_covers_single_clause_need() {
        let grant = grant_named(
            "g-dev",
            GrantStatus::Active,
            false,
            vec![stmt(
                "s1",
                vec!["github:contents:write".into()],
                glob("acme/*"),
                None,
            )],
        );
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("acme/widgets"),
        )];
        match resolve_need_against_grants(&[grant], &need) {
            NeedResolution::Covered {
                grant_id,
                matched_statement_sids,
            } => {
                assert_eq!(grant_id, "g-dev");
                assert_eq!(matched_statement_sids, vec!["s1".to_string()]);
            }
            other => panic!("expected Covered, got {other:?}"),
        }
    }

    #[test]
    fn resolve_covers_multi_clause_need_within_one_grant() {
        // gh.pr_create-shaped need: three capability clauses, one repo.
        let grant = grant_named(
            "g-dev",
            GrantStatus::Active,
            false,
            vec![stmt(
                "s1",
                vec![
                    "github:contents:write".into(),
                    "github:pull_request:create".into(),
                    "github:actions:read".into(),
                ],
                glob("acme/*"),
                None,
            )],
        );
        let need = vec![
            need_clause(vec!["github:contents:write".into()], exact("acme/widgets")),
            need_clause(
                vec!["github:pull_request:create".into()],
                exact("acme/widgets"),
            ),
            need_clause(vec!["github:actions:read".into()], exact("acme/widgets")),
        ];
        assert!(matches!(
            resolve_need_against_grants(&[grant], &need),
            NeedResolution::Covered { .. }
        ));
    }

    #[test]
    fn resolve_uncovered_clause_when_action_not_granted() {
        let grant = grant_named(
            "g-dev",
            GrantStatus::Active,
            false,
            vec![stmt(
                "s1",
                vec!["github:contents:read".into()],
                glob("acme/*"),
                None,
            )],
        );
        // Need writes; grant only reads → uncovered (push needs write).
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("acme/widgets"),
        )];
        assert!(matches!(
            resolve_need_against_grants(&[grant], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::UncoveredClause
            }
        ));
    }

    #[test]
    fn resolve_uncovered_when_resource_out_of_scope() {
        let grant = grant_named(
            "g-dev",
            GrantStatus::Active,
            false,
            vec![stmt(
                "s1",
                vec!["github:contents:write".into()],
                glob("acme/*"),
                None,
            )],
        );
        // Right action, wrong owner → resource out of scope.
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("other/widgets"),
        )];
        assert!(matches!(
            resolve_need_against_grants(&[grant], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::UncoveredClause
            }
        ));
    }

    #[test]
    fn resolve_refuses_need_spanning_two_sibling_grants() {
        // Clause A only in grant-1, clause B only in grant-2; neither grant
        // covers both → unsatisfiable at the cap (I10), even though the union
        // would. Fail-closed.
        let g1 = grant_named(
            "g-1",
            GrantStatus::Active,
            false,
            vec![stmt(
                "a",
                vec!["github:contents:write".into()],
                glob("acme/*"),
                None,
            )],
        );
        let g2 = grant_named(
            "g-2",
            GrantStatus::Active,
            false,
            vec![stmt(
                "b",
                vec!["github:pull_request:create".into()],
                glob("acme/*"),
                None,
            )],
        );
        let need = vec![
            need_clause(vec!["github:contents:write".into()], exact("acme/widgets")),
            need_clause(
                vec!["github:pull_request:create".into()],
                exact("acme/widgets"),
            ),
        ];
        assert!(matches!(
            resolve_need_against_grants(&[g1, g2], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::SpansMultipleGrants
            }
        ));
    }

    #[test]
    fn resolve_picks_the_single_grant_that_covers_all_even_among_many() {
        let g_partial = grant_named(
            "g-partial",
            GrantStatus::Active,
            false,
            vec![stmt(
                "p",
                vec!["github:contents:write".into()],
                glob("acme/*"),
                None,
            )],
        );
        let g_full = grant_named(
            "g-full",
            GrantStatus::Active,
            false,
            vec![stmt(
                "f",
                vec![
                    "github:contents:write".into(),
                    "github:pull_request:create".into(),
                ],
                glob("acme/*"),
                None,
            )],
        );
        let need = vec![
            need_clause(vec!["github:contents:write".into()], exact("acme/widgets")),
            need_clause(
                vec!["github:pull_request:create".into()],
                exact("acme/widgets"),
            ),
        ];
        match resolve_need_against_grants(&[g_partial, g_full], &need) {
            NeedResolution::Covered { grant_id, .. } => assert_eq!(grant_id, "g-full"),
            other => panic!("expected Covered by g-full, got {other:?}"),
        }
    }

    #[test]
    fn resolve_no_active_grant_when_all_revoked_or_inactive() {
        let revoked = grant_named(
            "g-rev",
            GrantStatus::Active, // status stale-Active but revoked_at set
            true,
            vec![stmt(
                "s",
                vec!["github:contents:write".into()],
                ResourceSelector::Any,
                None,
            )],
        );
        let paused = grant_named(
            "g-paused",
            GrantStatus::Paused,
            false,
            vec![stmt(
                "s",
                vec!["github:contents:write".into()],
                ResourceSelector::Any,
                None,
            )],
        );
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("acme/widgets"),
        )];
        assert!(matches!(
            resolve_need_against_grants(&[revoked, paused], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::NoActiveGrant
            }
        ));
    }

    #[test]
    fn resolve_skips_revoked_grant_but_uses_active_sibling() {
        let revoked = grant_named(
            "g-rev",
            GrantStatus::Revoked,
            true,
            vec![stmt(
                "r",
                vec!["github:contents:write".into()],
                ResourceSelector::Any,
                None,
            )],
        );
        let active = grant_named(
            "g-ok",
            GrantStatus::Active,
            false,
            vec![stmt(
                "ok",
                vec!["github:contents:write".into()],
                glob("acme/*"),
                None,
            )],
        );
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("acme/widgets"),
        )];
        match resolve_need_against_grants(&[revoked, active], &need) {
            NeedResolution::Covered { grant_id, .. } => assert_eq!(grant_id, "g-ok"),
            other => panic!("expected Covered by g-ok, got {other:?}"),
        }
    }

    #[test]
    fn resolve_empty_need_is_fail_closed() {
        let grant = grant_named(
            "g",
            GrantStatus::Active,
            false,
            vec![stmt("s", vec!["*".into()], ResourceSelector::Any, None)],
        );
        assert!(matches!(
            resolve_need_against_grants(&[grant], &[]),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::EmptyNeed
            }
        ));
    }

    #[test]
    fn resolve_exhausted_budget_does_not_cover() {
        // Grant statement bounds 100 tokens, already fully used → no headroom.
        let grant = grant_named(
            "g",
            GrantStatus::Active,
            false,
            vec![core_grant_types::Statement {
                usage: Usage {
                    tokens: 100,
                    ..Default::default()
                },
                ..stmt(
                    "s",
                    vec!["llm:generate".into()],
                    ResourceSelector::Any,
                    Some(Budget {
                        tokens: Some(100),
                        ..Default::default()
                    }),
                )
            }],
        );
        let need = vec![need_clause(
            vec!["llm:generate".into()],
            ResourceSelector::Any,
        )];
        assert!(matches!(
            resolve_need_against_grants(&[grant], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::UncoveredClause
            }
        ));
    }

    #[test]
    fn resolve_conditioned_statement_fails_closed_until_evaluator_lands() {
        // A grant statement carrying a use-time condition is NOT usable on the
        // authorization path yet (no condition evaluator wired) — fail-closed,
        // never authorize past an unevaluated condition. Documented limit.
        let grant = grant_named(
            "g",
            GrantStatus::Active,
            false,
            vec![core_grant_types::Statement {
                conditions: vec![Condition::TimeWindow {
                    start_secs_of_day: 0,
                    end_secs_of_day: 3600,
                }],
                ..stmt(
                    "s",
                    vec!["github:contents:write".into()],
                    glob("acme/*"),
                    None,
                )
            }],
        );
        let need = vec![need_clause(
            vec!["github:contents:write".into()],
            exact("acme/widgets"),
        )];
        assert!(matches!(
            resolve_need_against_grants(&[grant], &need),
            NeedResolution::Unsatisfiable {
                reason: NeedUnsatisfiable::UncoveredClause
            }
        ));
    }

    #[test]
    fn resolve_apex_wildcard_actions_cover_any_need_action() {
        // The `*` action shim (apex) covers any action verb. NB ADR 205 §6
        // CRITICAL-3 rider: the durable/apex grant must be ENUMERATED, not `*`,
        // for the "dangerous verbs unreachable" property — this test only fixes
        // the predicate semantics, not the policy that `*` must not be minted.
        let apex = grant_named(
            "apex",
            GrantStatus::Active,
            false,
            vec![stmt("star", vec!["*".into()], ResourceSelector::Any, None)],
        );
        let need = vec![need_clause(
            vec!["github:administration:write".into()],
            exact("acme/widgets"),
        )];
        assert!(matches!(
            resolve_need_against_grants(&[apex], &need),
            NeedResolution::Covered { .. }
        ));
    }
}
