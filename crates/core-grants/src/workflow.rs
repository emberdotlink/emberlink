//! Workflow grants — per-session composite grants minted from a workflow
//! template at session-open.
//!
//! Per design §Component 1: instead of issuing 8–30 per-action grants over a
//! session's lifetime (one per `gh.pr_create` / `git.push` / etc.), the
//! operator picks a workflow template at `ember claude-code` launch, Touch
//! IDs once, and the daemon mints a single `WorkflowGrant` whose scope set is
//! the template's `scopes` (minus `excludes`) at the time of issuance.
//!
//! `broker.resolve` evaluates the session's active workflow grant FIRST: if
//! the requested action key is in scope, return APPROVED with the workflow
//! grant's TTL; otherwise fall through to per-action standing pre-grants, then
//! JIT, then deny (per design §Component 2 ordered evaluation).
//!
//! Resolution is one-shot at issuance: template edits made after a
//! `WorkflowGrant` is live do NOT retroactively expand or contract scopes.
//! The operator must `ember workflow revoke && open-new-session` to pick up
//! template edits.
//!
//! Checkpoint for this slice (TYPE-only): `workflow_grant_type_foundation_landed`.
//! The parent task's `pregrant_workflow_grant_primitive_landed` checkpoint lands
//! when the daemon wiring (SessionMeta extension + broker.resolve ordering)
//! lands in a follow-up PR — this PR is only Component 1 of the brief.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::grant::PrincipalId;

// `PregrantPath` lives in `core-event-types::workflow_receipt` so the
// Receipt body in `core-events` can stamp it without forcing `core-events`
// to depend on `core-grants` (which would be a cycle — `core-grants` already
// depends on `core-event-types`). Re-exported here so existing callers of
// `core_grants::PregrantPath` keep working.
pub use core_event_types::PregrantPath;

/// Opaque per-grant identifier. ULID-shaped in practice (callers generate via
/// the daemon-side ULID source) but stored as a string so this type does not
/// pull in a `ulid` crate dependency and works the same way across daemon,
/// dashboard, and CLI deserialization paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkflowId(pub String);

/// A time-bounded, scope-limited delegation minted from a workflow template
/// at session-open after operator Touch ID.
///
/// Field choices:
/// - `workflow_id` / `template_name` — identity. `workflow_id` is the unique
///   per-grant ID stamped on every Receipt; `template_name` is the human-
///   readable label (e.g. `emberd-development`).
/// - `grantor_id` / `persona_id` — who delegated and from which persona. The
///   persona binding is per design — the workflow grant inherits the
///   session's persona, and a persona-mismatch on incoming `broker.resolve`
///   triggers a deny (defense against cross-persona authority drift).
/// - `scopes` / `excludes` — the template's allow-list at the moment of
///   issuance, copied verbatim. Each entry is an exact action key (`gh.pr_create`)
///   or a namespace glob (`git.*`). `excludes` overrides `scopes`.
/// - `issued_at` / `expires_at` — pre-computed for fast time-window checks
///   inside `broker.resolve` (no per-call duration arithmetic).
/// - `ttl_seconds` — the original template TTL ceiling, retained for audit
///   and for `ember workflow extend` to reason about how much further the
///   grant can extend.
/// - `presence_proof_ref` — opaque reference to the presence-proof Receipt
///   that authorized issuance. The daemon resolves this back to a full proof
///   when an auditor pulls the chain.
/// - `spawn_max_depth` — if the template carried a `[capability.spawn_subagent]`
///   block, its `max_depth`. None means the template did not authorize spawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowGrant {
    pub workflow_id: WorkflowId,
    pub template_name: String,
    pub grantor_id: PrincipalId,
    pub persona_id: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    pub ttl_seconds: i64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub presence_proof_ref: String,
    #[serde(default)]
    pub spawn_max_depth: Option<u32>,
}

/// Errors returned by [`WorkflowGrant::new`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowGrantError {
    #[error("ttl_seconds must be > 0, got {0}")]
    InvalidTtl(i64),

    #[error("template name {0:?} is empty or contains characters outside [a-z0-9-]")]
    InvalidTemplateName(String),

    #[error("scope entry {0:?} does not match `<namespace>.<action>` or `<namespace>.*`")]
    InvalidActionKey(String),

    #[error("persona_id is empty")]
    EmptyPersonaId,

    #[error("workflow_id is empty")]
    EmptyWorkflowId,

    #[error("presence_proof_ref is empty")]
    EmptyPresenceProofRef,
}

impl WorkflowGrant {
    /// Construct + validate. Computes `expires_at = issued_at + ttl_seconds`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_id: WorkflowId,
        template_name: String,
        grantor_id: PrincipalId,
        persona_id: String,
        scopes: Vec<String>,
        excludes: Vec<String>,
        ttl_seconds: i64,
        issued_at: DateTime<Utc>,
        presence_proof_ref: String,
        spawn_max_depth: Option<u32>,
    ) -> Result<Self, WorkflowGrantError> {
        if workflow_id.0.is_empty() {
            return Err(WorkflowGrantError::EmptyWorkflowId);
        }
        if persona_id.is_empty() {
            return Err(WorkflowGrantError::EmptyPersonaId);
        }
        if presence_proof_ref.is_empty() {
            return Err(WorkflowGrantError::EmptyPresenceProofRef);
        }
        if ttl_seconds <= 0 {
            return Err(WorkflowGrantError::InvalidTtl(ttl_seconds));
        }
        validate_template_name(&template_name)?;
        for k in &scopes {
            validate_action_key(k)?;
        }
        for k in &excludes {
            validate_action_key(k)?;
        }
        let expires_at = issued_at + chrono::Duration::seconds(ttl_seconds);
        Ok(Self {
            workflow_id,
            template_name,
            grantor_id,
            persona_id,
            scopes,
            excludes,
            ttl_seconds,
            issued_at,
            expires_at,
            presence_proof_ref,
            spawn_max_depth,
        })
    }

    /// Return true iff `now < expires_at`. Inclusive at `issued_at`; exclusive
    /// at `expires_at` — a grant whose `expires_at` equals `now` is expired.
    pub fn is_live_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Resolve an action key against the grant's `scopes` and `excludes`.
    /// `excludes` override `scopes`; namespace glob `<ns>.*` matches any
    /// action in that namespace.
    pub fn permits(&self, action_key: &str) -> bool {
        if matches_any(&self.excludes, action_key) {
            return false;
        }
        matches_any(&self.scopes, action_key)
    }

    /// Resolve an action key under the grant. Three outcomes:
    /// - `Some(PregrantPath::Workflow)` — grant is live AND permits the action.
    /// - `Some(PregrantPath::Deny)` — grant is live AND explicitly forbids.
    /// - `None` — grant is expired OR action is unscoped; caller falls
    ///   through to the next evaluation layer (per-action / JIT / deny).
    ///
    /// Per design §Component 2: `Workflow` and `Deny` short-circuit the
    /// broker's resolution chain; `None` means "this layer has nothing
    /// authoritative to say."
    ///
    /// **Exclude precedes scope (LOW-6 from the 2026-05-18 prior change
    /// adversarial review):** an action in `excludes` returns `Deny` even
    /// when `scopes` does not match. `excludes` is an absolute deny list,
    /// not a subtraction from scope. Template authors who write
    /// `excludes = ["gh.repo_delete"]` without including `gh.*` in scopes
    /// still get the deny behavior — by design, since the deny is the
    /// safety property the template is asserting.
    pub fn evaluate(&self, action_key: &str, now: DateTime<Utc>) -> Option<PregrantPath> {
        if !self.is_live_at(now) {
            return None;
        }
        if matches_any(&self.excludes, action_key) {
            return Some(PregrantPath::Deny);
        }
        if matches_any(&self.scopes, action_key) {
            return Some(PregrantPath::Workflow);
        }
        None
    }
}

fn validate_template_name(name: &str) -> Result<(), WorkflowGrantError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(WorkflowGrantError::InvalidTemplateName(name.to_string()));
    }
    Ok(())
}

fn validate_action_key(key: &str) -> Result<(), WorkflowGrantError> {
    let (ns, action) = key
        .split_once('.')
        .ok_or_else(|| WorkflowGrantError::InvalidActionKey(key.to_string()))?;
    if ns.is_empty() || action.is_empty() {
        return Err(WorkflowGrantError::InvalidActionKey(key.to_string()));
    }
    let ns_ok = ns
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    let action_ok = action == "*"
        || action
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ns_ok || !action_ok {
        return Err(WorkflowGrantError::InvalidActionKey(key.to_string()));
    }
    Ok(())
}

fn matches_any(patterns: &[String], action_key: &str) -> bool {
    patterns.iter().any(|p| matches_one(p, action_key))
}

fn matches_one(pattern: &str, action_key: &str) -> bool {
    if pattern == action_key {
        return true;
    }
    if let Some(ns) = pattern.strip_suffix(".*") {
        return action_key.starts_with(ns) && action_key[ns.len()..].starts_with('.');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(s: &str) -> DateTime<Utc> {
        s.parse::<DateTime<Utc>>().unwrap()
    }

    fn fixture() -> WorkflowGrant {
        WorkflowGrant::new(
            WorkflowId("wfg_01HQ0".to_string()),
            "emberd-development".to_string(),
            PrincipalId("root_alice".to_string()),
            "persona_dev0".to_string(),
            vec!["git.*".to_string(), "gh.pr_create".to_string()],
            vec!["gh.repo_delete".to_string()],
            4 * 3600,
            iso("2026-05-18T12:00:00Z"),
            "ppr_abc123".to_string(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn rejects_empty_fields() {
        let now = iso("2026-05-18T12:00:00Z");
        let err = WorkflowGrant::new(
            WorkflowId(String::new()),
            "x".to_string(),
            PrincipalId("r".to_string()),
            "p".to_string(),
            vec![],
            vec![],
            10,
            now,
            "ppr".to_string(),
            None,
        )
        .unwrap_err();
        assert_eq!(err, WorkflowGrantError::EmptyWorkflowId);
    }

    #[test]
    fn rejects_non_positive_ttl() {
        let now = iso("2026-05-18T12:00:00Z");
        for bad in [-1, 0] {
            let err = WorkflowGrant::new(
                WorkflowId("w".to_string()),
                "x".to_string(),
                PrincipalId("r".to_string()),
                "p".to_string(),
                vec!["git.push".to_string()],
                vec![],
                bad,
                now,
                "ppr".to_string(),
                None,
            )
            .unwrap_err();
            assert_eq!(err, WorkflowGrantError::InvalidTtl(bad));
        }
    }

    #[test]
    fn computes_expires_at_from_ttl() {
        let g = fixture();
        let delta = g.expires_at - g.issued_at;
        assert_eq!(delta.num_seconds(), 4 * 3600);
    }

    #[test]
    fn is_live_window_closed_inclusively_at_start_and_exclusively_at_end() {
        let g = fixture();
        assert!(g.is_live_at(g.issued_at));
        assert!(g.is_live_at(g.issued_at + chrono::Duration::seconds(1)));
        assert!(g.is_live_at(g.expires_at - chrono::Duration::seconds(1)));
        assert!(!g.is_live_at(g.expires_at));
        assert!(!g.is_live_at(g.expires_at + chrono::Duration::seconds(1)));
        assert!(!g.is_live_at(g.issued_at - chrono::Duration::seconds(1)));
    }

    #[test]
    fn permits_exact_action_key_in_scope() {
        let g = fixture();
        assert!(g.permits("gh.pr_create"));
    }

    #[test]
    fn permits_namespace_glob_match() {
        let g = fixture();
        assert!(g.permits("git.push"));
        assert!(g.permits("git.fetch"));
        assert!(g.permits("git.clone"));
    }

    #[test]
    fn rejects_excluded_action_key() {
        let g = fixture();
        assert!(!g.permits("gh.repo_delete"));
    }

    #[test]
    fn rejects_action_key_outside_scope() {
        let g = fixture();
        assert!(!g.permits("trust.rotate"));
        assert!(!g.permits("kubectl.apply"));
    }

    #[test]
    fn glob_does_not_match_unrelated_namespaces() {
        // git.* matches git.push but not gitlab.push (no leading-substring
        // matching across namespace boundaries).
        let g = WorkflowGrant::new(
            WorkflowId("w".to_string()),
            "x".to_string(),
            PrincipalId("r".to_string()),
            "p".to_string(),
            vec!["git.*".to_string()],
            vec![],
            3600,
            iso("2026-05-18T12:00:00Z"),
            "ppr".to_string(),
            None,
        )
        .unwrap();
        assert!(g.permits("git.push"));
        assert!(!g.permits("gitlab.push"));
        assert!(!g.permits("git_ext.push"));
    }

    #[test]
    fn evaluate_returns_workflow_path_on_scope_hit() {
        let g = fixture();
        let now = g.issued_at + chrono::Duration::seconds(30);
        assert_eq!(
            g.evaluate("gh.pr_create", now),
            Some(PregrantPath::Workflow)
        );
        assert_eq!(g.evaluate("git.push", now), Some(PregrantPath::Workflow));
    }

    #[test]
    fn evaluate_returns_deny_on_explicit_exclude() {
        let g = fixture();
        let now = g.issued_at + chrono::Duration::seconds(30);
        assert_eq!(g.evaluate("gh.repo_delete", now), Some(PregrantPath::Deny));
    }

    #[test]
    fn evaluate_returns_none_on_unscoped_action_so_caller_falls_through() {
        let g = fixture();
        let now = g.issued_at + chrono::Duration::seconds(30);
        assert_eq!(g.evaluate("trust.rotate", now), None);
    }

    #[test]
    fn evaluate_returns_none_when_expired_even_for_in_scope_action() {
        let g = fixture();
        let now = g.expires_at + chrono::Duration::seconds(1);
        assert_eq!(g.evaluate("gh.pr_create", now), None);
        assert_eq!(g.evaluate("gh.repo_delete", now), None);
    }

    #[test]
    fn serde_round_trip_preserves_all_fields() {
        let g = fixture();
        let json = serde_json::to_string(&g).unwrap();
        let back: WorkflowGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    // ---- Property tests --------------------------------------------------
    use proptest::prelude::*;

    fn arb_action_key() -> impl Strategy<Value = String> {
        (
            "[a-z][a-z0-9_-]{0,7}",
            prop::option::of("[a-z][a-z0-9_-]{0,7}"),
        )
            .prop_map(|(ns, action)| match action {
                Some(a) => format!("{ns}.{a}"),
                None => format!("{ns}.*"),
            })
    }

    proptest! {
        #[test]
        fn invariant_excludes_always_override_scopes(
            scopes in prop::collection::vec(arb_action_key(), 1..6),
            excludes in prop::collection::vec(arb_action_key(), 0..4),
        ) {
            let g = WorkflowGrant::new(
                WorkflowId("w".to_string()),
                "x".to_string(),
                PrincipalId("r".to_string()),
                "p".to_string(),
                scopes.clone(),
                excludes.clone(),
                3600,
                iso("2026-05-18T12:00:00Z"),
                "ppr".to_string(),
                None,
            ).unwrap();
            // Any action key that matches an exclude pattern must NOT permit,
            // regardless of scopes.
            for excl in &excludes {
                let probe = if let Some(ns) = excl.strip_suffix(".*") {
                    format!("{ns}.probe_action")
                } else {
                    excl.clone()
                };
                prop_assert!(!g.permits(&probe),
                    "exclude pattern {excl:?} must forbid probe {probe:?}");
            }
        }

        #[test]
        fn invariant_permits_decision_independent_of_unrelated_keys(
            extra_scopes in prop::collection::vec(arb_action_key(), 0..4),
        ) {
            let mut scopes = vec!["git.*".to_string()];
            scopes.extend(extra_scopes);
            let g = WorkflowGrant::new(
                WorkflowId("w".to_string()),
                "x".to_string(),
                PrincipalId("r".to_string()),
                "p".to_string(),
                scopes,
                vec![],
                3600,
                iso("2026-05-18T12:00:00Z"),
                "ppr".to_string(),
                None,
            ).unwrap();
            // Adding unrelated scopes never invalidates an existing permit.
            prop_assert!(g.permits("git.push"));
        }

        #[test]
        fn invariant_ttl_window_strictly_bounded(
            ttl_seconds in 1i64..(7 * 86400),
            offset in -86400i64..(8 * 86400),
        ) {
            let issued = iso("2026-05-18T12:00:00Z");
            let g = WorkflowGrant::new(
                WorkflowId("w".to_string()),
                "x".to_string(),
                PrincipalId("r".to_string()),
                "p".to_string(),
                vec!["git.push".to_string()],
                vec![],
                ttl_seconds,
                issued,
                "ppr".to_string(),
                None,
            ).unwrap();
            let probe = issued + chrono::Duration::seconds(offset);
            let expected_live = offset >= 0 && offset < ttl_seconds;
            prop_assert_eq!(g.is_live_at(probe), expected_live);
        }
    }
}

// workflow_grant_type_foundation_landed
