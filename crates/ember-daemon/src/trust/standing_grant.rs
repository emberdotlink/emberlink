use chrono::{DateTime, Utc};
use core_event_types::{ActionRef, ActionSelector};
use uuid::Uuid;

use core_proxy_forward::r#match::host_matches_domain;

use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::grant::MAX_GRANT_TTL_SECS;

/// Per-Statement standing grant match (ADR 073). Returned when an active
/// grant for the persona carries a Statement whose selector covers the
/// incoming (action, resource) pair. Used as a fast-path approval signal
/// during agent-facing authorize flows: a hit here means the human has
/// already delegated enough authority to bypass the HITL handoff for this
/// specific call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingStatementMatch {
    pub grant_id: String,
    pub block_index: usize,
    pub statement_sid: String,
}

pub struct StandingGrantInfo {
    pub id: String,
    pub persona_id: String,
    pub action_selector: ActionSelector,
    pub scope: String,
    pub expires_at: Option<String>,
}

/// Check `resource` against a grant's `allowed_targets` field.
///
/// - `None`  → no restriction; allowed.
/// - Empty / whitespace-only / empty JSON-array → deny-all; not allowed.
/// - `Some("[\"a.com\",\"*.b.com\"]")` → `resource` must match at least one
///   entry. Storage encoding is the JSON array written by `create_grant`
///   (`allowed_targets_storage_and_parse_one_encoding` reconciliation).
///
/// Entry matching mirrors the proxy's FINDING-1-fixed logic: an entry
/// without a `*.` prefix requires an exact host match; `*.domain` matches
/// `domain` itself or any subdomain. If `resource` looks like a URL, the
/// host component is extracted first; otherwise the raw string is compared.
fn resource_matches_allowed_targets(allowed_targets: Option<&str>, resource: &str) -> bool {
    let Some(targets) = allowed_targets else {
        return true; // no restriction
    };
    let entries = core_proxy_forward::parse_allowed_targets(targets);
    if entries.is_empty() {
        return false; // empty list is deny-all
    }
    // Try to extract the host from a URL; fall back to the raw resource string.
    let candidate: String = if resource.contains("://") {
        resource
            .parse::<hyper::Uri>()
            .ok()
            .and_then(|u| u.host().map(|h| h.to_owned()))
            .unwrap_or_else(|| resource.to_owned())
    } else {
        resource.to_owned()
    };
    entries.iter().any(|pattern| {
        if let Some(domain) = pattern.strip_prefix("*.") {
            host_matches_domain(&candidate, domain)
        } else {
            candidate.as_str() == pattern.as_str()
        }
    })
}

impl DaemonStore {
    pub fn create_standing_grant(
        &self,
        persona_id: &str,
        action_selector: &ActionSelector,
        scope: &str,
        expires_at: Option<&str>,
    ) -> Result<(), StoreError> {
        // standing_grant_expires_at_capped — Per adversarial-review
        // 2026-05-19 HIGH-7. The `Always` approval outcome funnels through
        // here with a caller-supplied `expires_at` string. Without a cap, an
        // approver (or coerced/buggy dashboard) could mint a year-2099
        // standing grant, defeating ADR 072's "bounded" invariant. Parse
        // the RFC-3339 string, compute seconds-from-now, refuse when the
        // window exceeds [`MAX_GRANT_TTL_SECS`]. `None` (indefinite) is
        // left to caller discretion — daemon-internal flows occasionally
        // mint genuinely persistent standing grants and the cap there is
        // architectural intent rather than a per-row check.
        if let Some(s) = expires_at {
            let parsed = DateTime::parse_from_rfc3339(s)
                .map_err(|e| {
                    StoreError::InvalidInput(format!(
                        "standing-grant expires_at {s:?} is not RFC-3339: {e}"
                    ))
                })?
                .with_timezone(&Utc);
            let now = Utc::now();
            let secs_from_now = (parsed - now).num_seconds();
            if secs_from_now > MAX_GRANT_TTL_SECS as i64 {
                return Err(StoreError::InvalidInput(format!(
                    "standing-grant expires_at {s:?} is {secs_from_now}s from now, \
                     exceeding MAX_GRANT_TTL_SECS ({MAX_GRANT_TTL_SECS}s); grants are \
                     bounded per ADR 072"
                )));
            }
        }
        action_selector
            .validate()
            .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO standing_grants \
                 (id, persona_id, action_pattern, scope, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("sg-{}", Uuid::new_v4()),
                    persona_id,
                    action_selector.to_string(),
                    scope,
                    expires_at,
                ],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn check_standing_grant(&self, persona_id: &str, action: &str) -> Result<bool, StoreError> {
        Ok(self
            .list_standing_grants()?
            .into_iter()
            .filter(|grant| grant.persona_id == persona_id)
            .filter(|grant| standing_grant_is_active(grant.expires_at.as_deref()))
            .any(|grant| grant.action_selector.matches_action(action)))
    }

    pub fn check_standing_grant_action_ref(
        &self,
        persona_id: &str,
        action_ref: &ActionRef,
    ) -> Result<bool, StoreError> {
        Ok(self
            .list_standing_grants()?
            .into_iter()
            .filter(|grant| grant.persona_id == persona_id)
            .filter(|grant| standing_grant_is_active(grant.expires_at.as_deref()))
            .any(|grant| grant.action_selector.matches_action_ref(action_ref)))
    }

    pub fn list_standing_grants(&self) -> Result<Vec<StandingGrantInfo>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, persona_id, action_pattern, scope, expires_at \
                 FROM standing_grants ORDER BY created_at DESC",
            )
            .map_err(StoreError::Sqlite)?;
        let rows = stmt
            .query_map([], |row| {
                let stored_action_pattern: String = row.get(2)?;
                Ok(StandingGrantInfo {
                    id: row.get(0)?,
                    persona_id: row.get(1)?,
                    action_selector: parse_action_selector(&stored_action_pattern)?,
                    scope: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })
            .map_err(StoreError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::Sqlite)
    }

    /// Walk every active grant for the persona and return the first that
    /// carries a Statement applicable to the request. Used by approval
    /// flows to short-circuit the HITL handoff when a prior grant already
    /// authorizes the call at the Statement level.
    ///
    /// Returns `Ok(None)` if no active grant has an applicable Statement —
    /// the caller falls back to the classical `check_standing_grant`
    /// persona-level action-pattern cache or to interactive approval.
    pub fn match_standing_statement(
        &self,
        persona_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<Option<StandingStatementMatch>, StoreError> {
        let grants = self.list_active_grants()?;
        for g in grants {
            if g.persona_id != persona_id {
                continue;
            }
            // Enforce allowed_targets at the standing-grant level.
            // Empty list is deny-all, not wildcard.
            if !resource_matches_allowed_targets(g.allowed_targets.as_deref(), resource) {
                continue;
            }
            let ag = match self.get_access_grant(&g.id) {
                Ok(a) => a,
                Err(_) => continue,
            };
            for (block_idx, stmt) in ag.statements() {
                if stmt.applicable_to(action, resource) {
                    return Ok(Some(StandingStatementMatch {
                        grant_id: g.id.clone(),
                        block_index: block_idx,
                        statement_sid: stmt.sid.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn remove_standing_grant(&self, id: &str) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "DELETE FROM standing_grants WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }
}

fn parse_action_selector(stored: &str) -> rusqlite::Result<ActionSelector> {
    ActionSelector::parse(stored).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            stored.len(),
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })
}

fn standing_grant_is_active(expires_at: Option<&str>) -> bool {
    match expires_at {
        None => true,
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|parsed| parsed.with_timezone(&Utc) > Utc::now())
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named_selector(pattern: &str) -> ActionSelector {
        ActionSelector::named(pattern)
    }

    fn setup() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("agent-test").expect("create persona");
        store
    }

    fn persona_id(store: &DaemonStore) -> String {
        store
            .list_personas()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .id
    }

    #[test]
    fn create_and_list_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "*", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].persona_id, pid);
        assert_eq!(
            grants[0].action_selector,
            named_selector("credential.access")
        );
        assert_eq!(grants[0].scope, "*");
        assert!(grants[0].id.starts_with("sg-"));
        assert!(grants[0].expires_at.is_none());
    }

    #[test]
    fn check_standing_grant_exact_match() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "*", None)
            .unwrap();
        assert!(
            store
                .check_standing_grant(&pid, "credential.access")
                .unwrap()
        );
        assert!(
            !store
                .check_standing_grant(&pid, "credential.write")
                .unwrap()
        );
    }

    #[test]
    fn check_standing_grant_wildcard_pattern() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.*"), "*", None)
            .unwrap();
        assert!(
            store
                .check_standing_grant(&pid, "credential.access")
                .unwrap()
        );
        assert!(
            store
                .check_standing_grant(&pid, "credential.write")
                .unwrap()
        );
        assert!(!store.check_standing_grant(&pid, "sandbox.run").unwrap());
    }

    #[test]
    fn check_standing_grant_star_pattern_matches_all() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("*"), "*", None)
            .unwrap();
        assert!(store.check_standing_grant(&pid, "any.action").unwrap());
    }

    #[test]
    fn check_standing_grant_structured_action_ref_match() {
        let store = setup();
        let pid = persona_id(&store);
        let selector = ActionSelector::action_ref(core_event_types::ActionRefPattern::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1",
        ));
        store
            .create_standing_grant(&pid, &selector, "*", None)
            .unwrap();
        assert!(
            store
                .check_standing_grant_action_ref(
                    &pid,
                    &ActionRef::new(
                        "registry.ember.systems/ember-systems/ember-gh",
                        "pr_merge",
                        "v1",
                    ),
                )
                .unwrap()
        );
        assert!(
            !store
                .check_standing_grant_action_ref(
                    &pid,
                    &ActionRef::new(
                        "registry.ember.systems/ember-systems/ember-gh",
                        "pr_create",
                        "v1",
                    ),
                )
                .unwrap()
        );
    }

    #[test]
    fn remove_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "*", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        store.remove_standing_grant(&grants[0].id).unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert!(grants.is_empty());
    }

    #[test]
    fn upsert_replaces_on_duplicate_persona_pattern() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "read", None)
            .unwrap();
        store
            .create_standing_grant(
                &pid,
                &named_selector("credential.access"),
                "read:write",
                None,
            )
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].scope, "read:write");
    }

    #[test]
    fn check_standing_grant_wrong_persona() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "*", None)
            .unwrap();
        assert!(
            !store
                .check_standing_grant("other-persona", "credential.access")
                .unwrap()
        );
    }

    #[test]
    fn expired_standing_grant_not_matched() {
        let store = setup();
        let pid = persona_id(&store);
        // standing_grant_expires_at_capped: parser is now strict RFC-3339;
        // emit the past timestamp via `.to_rfc3339()` rather than the legacy
        // naive-ISO shape. Past dates do not trip the MAX_GRANT_TTL_SECS
        // cap (secs_from_now is negative).
        let past = (Utc::now() - chrono::Duration::days(7300)).to_rfc3339();
        store
            .create_standing_grant(&pid, &named_selector("credential.access"), "*", Some(&past))
            .unwrap();
        // Must not match even though the action and persona are correct.
        assert!(
            !store
                .check_standing_grant(&pid, "credential.access")
                .unwrap()
        );
    }

    #[test]
    fn future_expiry_standing_grant_matches() {
        let store = setup();
        let pid = persona_id(&store);
        // standing_grant_expires_at_capped: needs strict RFC-3339 AND a
        // future date within MAX_GRANT_TTL_SECS. 1 day satisfies both.
        let future = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        store
            .create_standing_grant(
                &pid,
                &named_selector("credential.access"),
                "*",
                Some(&future),
            )
            .unwrap();
        assert!(
            store
                .check_standing_grant(&pid, "credential.access")
                .unwrap()
        );
    }

    #[test]
    fn create_standing_grant_refuses_expires_at_past_cap() {
        // Direct test of the MAX_GRANT_TTL_SECS enforcement at the
        // standing-grant write path. Tracks adversarial-review 2026-05-19
        // HIGH-7 closure.
        let store = setup();
        let pid = persona_id(&store);
        let past_cap = (Utc::now() + chrono::Duration::days(60)).to_rfc3339();
        let err = store
            .create_standing_grant(
                &pid,
                &named_selector("credential.access"),
                "*",
                Some(&past_cap),
            )
            .expect_err("expected MAX_GRANT_TTL_SECS refusal");
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.contains("MAX_GRANT_TTL_SECS"),
                    "error message must reference the cap: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_standing_grant_refuses_non_rfc3339_expires_at() {
        // Direct test: the parser is strict RFC-3339 (TZ required). Tracks
        // adversarial-review 2026-05-19 HIGH-7 — the legacy naive-ISO
        // format is no longer accepted, closing the audit-shape ambiguity.
        let store = setup();
        let pid = persona_id(&store);
        let err = store
            .create_standing_grant(
                &pid,
                &named_selector("credential.access"),
                "*",
                Some("2099-01-01T00:00:00"),
            )
            .expect_err("expected RFC-3339 refusal");
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(msg.contains("RFC-3339"), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn match_standing_statement_returns_matching_grant() {
        let store = setup();
        let pid = persona_id(&store);
        // create_grant synthesizes a single-statement chain with scope
        // `github:read:emberdotlink/widgets`, action=github:read,
        // selector=Exact{"emberdotlink/widgets"}.
        store
            .create_grant(&pid, "gh-token", "github:read:emberdotlink/widgets", None)
            .unwrap();

        let hit = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(hit.is_some(), "should match on applicable Statement");

        // Request with a different resource — no match.
        let miss = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/other")
            .unwrap();
        assert!(miss.is_none(), "must not match a different resource");

        // Wrong persona — no match.
        let miss = store
            .match_standing_statement("other-persona", "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(miss.is_none(), "must not match a different persona");
    }

    // --- allowed_targets enforcement tests -------------------------

    #[test]
    fn resource_matches_allowed_targets_none_is_unrestricted() {
        // None = no restriction; any resource is allowed.
        assert!(resource_matches_allowed_targets(
            None,
            "any.host.example.com"
        ));
        assert!(resource_matches_allowed_targets(None, ""));
    }

    #[test]
    fn resource_matches_allowed_targets_empty_is_deny_all() {
        // Empty string → deny-all, not wildcard.
        assert!(!resource_matches_allowed_targets(
            Some(""),
            "api.github.com"
        ));
        assert!(!resource_matches_allowed_targets(
            Some("  "),
            "api.github.com"
        ));
        assert!(!resource_matches_allowed_targets(
            Some(" , , "),
            "api.github.com"
        ));
    }

    #[test]
    fn resource_matches_allowed_targets_exact_match() {
        assert!(resource_matches_allowed_targets(
            Some("api.github.com"),
            "api.github.com"
        ));
        assert!(!resource_matches_allowed_targets(
            Some("api.github.com"),
            "evil.example.com"
        ));
    }

    #[test]
    fn resource_matches_allowed_targets_wildcard_subdomain() {
        assert!(resource_matches_allowed_targets(
            Some("*.github.com"),
            "api.github.com"
        ));
        assert!(resource_matches_allowed_targets(
            Some("*.github.com"),
            "uploads.api.github.com"
        ));
        assert!(resource_matches_allowed_targets(
            Some("*.github.com"),
            "github.com"
        ));
        assert!(!resource_matches_allowed_targets(
            Some("*.github.com"),
            "evil.example.com"
        ));
    }

    #[test]
    fn resource_matches_allowed_targets_url_host_extraction() {
        // When the resource is a full URL, extract the host for matching.
        assert!(resource_matches_allowed_targets(
            Some("api.github.com"),
            "https://api.github.com/repos/foo/bar"
        ));
        assert!(!resource_matches_allowed_targets(
            Some("api.github.com"),
            "https://evil.example.com/steal"
        ));
    }

    #[test]
    fn resource_matches_allowed_targets_multi_entry() {
        // Canonical storage encoding is JSON array
        // (allowed_targets_storage_and_parse_one_encoding) — comma-form is
        // not recognised; per-entry validation at the write site refuses
        // it before any reader sees it.
        let targets = "[\"api.github.com\",\"anthropic.com\"]";
        assert!(resource_matches_allowed_targets(
            Some(targets),
            "api.github.com"
        ));
        assert!(resource_matches_allowed_targets(
            Some(targets),
            "anthropic.com"
        ));
        assert!(!resource_matches_allowed_targets(
            Some(targets),
            "evil.example.com"
        ));
    }

    #[test]
    fn match_standing_statement_empty_allowed_targets_is_deny_all() {
        let store = setup();
        let pid = persona_id(&store);
        let grant = store
            .create_grant(&pid, "gh-token", "github:read:emberdotlink/widgets", None)
            .unwrap();

        // Set allowed_targets to empty string — must be deny-all.
        store
            .conn()
            .execute(
                "UPDATE grants SET allowed_targets = '' WHERE id = ?1",
                rusqlite::params![grant.id],
            )
            .unwrap();

        let result = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(result.is_none(), "empty allowed_targets must be deny-all");
    }

    #[test]
    fn match_standing_statement_non_matching_allowed_targets_denied() {
        let store = setup();
        let pid = persona_id(&store);
        let grant = store
            .create_grant(&pid, "gh-token", "github:read:emberdotlink/widgets", None)
            .unwrap();

        // Restrict to a target that doesn't match the resource.
        store
            .conn()
            .execute(
                "UPDATE grants SET allowed_targets = 'api.other.com' WHERE id = ?1",
                rusqlite::params![grant.id],
            )
            .unwrap();

        let result = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(result.is_none(), "non-matching allowed_targets must deny");
    }

    #[test]
    fn match_standing_statement_matching_allowed_targets_permitted() {
        let store = setup();
        let pid = persona_id(&store);
        let grant = store
            .create_grant(&pid, "gh-token", "github:read:emberdotlink/widgets", None)
            .unwrap();

        // Restrict to the resource used in the call — should still match.
        store
            .conn()
            .execute(
                "UPDATE grants SET allowed_targets = 'emberdotlink/widgets' WHERE id = ?1",
                rusqlite::params![grant.id],
            )
            .unwrap();

        let result = store
            .match_standing_statement(&pid, "github:read", "emberdotlink/widgets")
            .unwrap();
        assert!(result.is_some(), "matching allowed_targets must permit");
    }
}
