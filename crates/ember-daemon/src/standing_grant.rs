use uuid::Uuid;

use crate::proxy::host_matches_domain;
use crate::store::{DaemonStore, StoreError};

/// Per-Statement standing grant match (design). Returned when an active
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
    pub action_pattern: String,
    pub scope: String,
    pub expires_at: Option<String>,
}

/// Check `resource` against a grant's `allowed_targets` field.
///
/// - `None`  → no restriction; allowed.
/// - `Some("")` (empty after trimming all entries) → deny-all; not allowed.
/// - `Some("a.com,b.com")` → `resource` must match at least one entry.
///
/// Entry matching mirrors the proxy's FINDING-1-fixed logic: an entry
/// without a `*.` prefix requires an exact host match; `*.domain` matches
/// `domain` itself or any subdomain. If `resource` looks like a URL, the
/// host component is extracted first; otherwise the raw string is compared.
fn resource_matches_allowed_targets(allowed_targets: Option<&str>, resource: &str) -> bool {
    let Some(targets) = allowed_targets else {
        return true; // no restriction
    };
    let entries: Vec<&str> = targets.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
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
            candidate.as_str() == *pattern
        }
    })
}

impl DaemonStore {
    pub fn create_standing_grant(
        &self,
        persona_id: &str,
        action_pattern: &str,
        scope: &str,
        expires_at: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO standing_grants \
                 (id, persona_id, action_pattern, scope, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    format!("sg-{}", Uuid::new_v4()),
                    persona_id,
                    action_pattern,
                    scope,
                    expires_at,
                ],
            )
            .map_err(StoreError::Sqlite)?;
        Ok(())
    }

    pub fn check_standing_grant(&self, persona_id: &str, action: &str) -> Result<bool, StoreError> {
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM standing_grants \
                 WHERE persona_id = ?1 \
                   AND (?2 GLOB action_pattern OR action_pattern = '*') \
                   AND (expires_at IS NULL OR expires_at > datetime('now'))",
                rusqlite::params![persona_id, action],
                |row| row.get(0),
            )
            .map_err(StoreError::Sqlite)?;
        Ok(count > 0)
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
                Ok(StandingGrantInfo {
                    id: row.get(0)?,
                    persona_id: row.get(1)?,
                    action_pattern: row.get(2)?,
                    scope: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })
            .map_err(StoreError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::Sqlite)
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
            // security check: enforce allowed_targets at the standing-grant level.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.create_persona("agent-test").expect("create persona");
        store
    }

    fn persona_id(store: &DaemonStore) -> String {
        store.list_personas().unwrap().into_iter().next().unwrap().id
    }

    #[test]
    fn create_and_list_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        let grants = store.list_standing_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].persona_id, pid);
        assert_eq!(grants[0].action_pattern, "credential.access");
        assert_eq!(grants[0].scope, "*");
        assert!(grants[0].id.starts_with("sg-"));
        assert!(grants[0].expires_at.is_none());
    }

    #[test]
    fn check_standing_grant_exact_match() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
        assert!(!store.check_standing_grant(&pid, "credential.write").unwrap());
    }

    #[test]
    fn check_standing_grant_wildcard_pattern() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.*", "*", None)
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
        assert!(store.check_standing_grant(&pid, "credential.write").unwrap());
        assert!(!store.check_standing_grant(&pid, "sandbox.run").unwrap());
    }

    #[test]
    fn check_standing_grant_star_pattern_matches_all() {
        let store = setup();
        let pid = persona_id(&store);
        store.create_standing_grant(&pid, "*", "*", None).unwrap();
        assert!(store.check_standing_grant(&pid, "any.action").unwrap());
    }

    #[test]
    fn remove_standing_grant() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", None)
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
            .create_standing_grant(&pid, "credential.access", "read", None)
            .unwrap();
        store
            .create_standing_grant(&pid, "credential.access", "read:write", None)
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
            .create_standing_grant(&pid, "credential.access", "*", None)
            .unwrap();
        assert!(!store.check_standing_grant("other-persona", "credential.access").unwrap());
    }

    #[test]
    fn expired_standing_grant_not_matched() {
        let store = setup();
        let pid = persona_id(&store);
        // Insert a grant that expired in the past.
        store
            .create_standing_grant(&pid, "credential.access", "*", Some("2000-01-01T00:00:00"))
            .unwrap();
        // Must not match even though the action and persona are correct.
        assert!(!store.check_standing_grant(&pid, "credential.access").unwrap());
    }

    #[test]
    fn future_expiry_standing_grant_matches() {
        let store = setup();
        let pid = persona_id(&store);
        store
            .create_standing_grant(&pid, "credential.access", "*", Some("2099-01-01T00:00:00"))
            .unwrap();
        assert!(store.check_standing_grant(&pid, "credential.access").unwrap());
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

    // --- security check: allowed_targets enforcement tests -------------------------

    #[test]
    fn resource_matches_allowed_targets_none_is_unrestricted() {
        // None = no restriction; any resource is allowed.
        assert!(resource_matches_allowed_targets(None, "any.host.example.com"));
        assert!(resource_matches_allowed_targets(None, ""));
    }

    #[test]
    fn resource_matches_allowed_targets_empty_is_deny_all() {
        // Empty string → deny-all, not wildcard.
        assert!(!resource_matches_allowed_targets(Some(""), "api.github.com"));
        assert!(!resource_matches_allowed_targets(Some("  "), "api.github.com"));
        assert!(!resource_matches_allowed_targets(Some(" , , "), "api.github.com"));
    }

    #[test]
    fn resource_matches_allowed_targets_exact_match() {
        assert!(resource_matches_allowed_targets(Some("api.github.com"), "api.github.com"));
        assert!(!resource_matches_allowed_targets(Some("api.github.com"), "evil.example.com"));
    }

    #[test]
    fn resource_matches_allowed_targets_wildcard_subdomain() {
        assert!(resource_matches_allowed_targets(Some("*.github.com"), "api.github.com"));
        assert!(resource_matches_allowed_targets(Some("*.github.com"), "uploads.api.github.com"));
        assert!(resource_matches_allowed_targets(Some("*.github.com"), "github.com"));
        assert!(!resource_matches_allowed_targets(Some("*.github.com"), "evil.example.com"));
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
        let targets = "api.github.com,anthropic.com";
        assert!(resource_matches_allowed_targets(Some(targets), "api.github.com"));
        assert!(resource_matches_allowed_targets(Some(targets), "anthropic.com"));
        assert!(!resource_matches_allowed_targets(Some(targets), "evil.example.com"));
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
