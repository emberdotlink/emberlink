//! Workflow-template schema — Serde-derived from TOML, validated at parse time.
//!
//! Per design §Component 1 + design §Component 6 + design Stage 4: workflow
//! templates are operator-editable, bundled-by-default TOMLs that name a set
//! of action scopes (e.g. `git.push`, `gh.pr_create`), a TTL ceiling, and
//! optional capability blocks (e.g. `[capability.spawn_subagent]`).
//!
//! Bundled templates live under `lib/ember/workflow-templates/` in the
//! source repo; install pipelines (design §Component 3) copy them to
//! `/usr/local/lib/ember/workflow-templates/` (prod) or
//! `/usr/local/lib/ember-dev/workflow-templates/` (dev). Operator overlays
//! at `~/.config/emberlink/workflow-templates/<name>.toml` take precedence.
//!
//! Action-key naming convention is locked at `<namespace>.<snake_case_action>`
//! (e.g. `gh.pr_create`, `git.push`, `kubectl.apply`). The convention is
//! already used across 14 construct.toml files + `crates/ember-construct/
//! src/policy.rs::credential_policy`. A glob suffix `<namespace>.*` is also
//! allowed in scope/excludes lists and matches any action in that namespace.
//!
//! Anchor: `onboarding_workflow_templates_landed`.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A workflow template — the operator-facing unit a launcher prompt offers
/// at `ember claude-code` (per design §Component 1). Templates compose into
/// `WorkflowGrant`s at session-open time, after operator Touch ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    /// Template name, must match the filename stem (e.g. `emberd-development`
    /// for `emberd-development.toml`). Used in launcher prompts and stamped
    /// onto every credentialed Receipt as `workflow_template`.
    pub name: String,

    /// One-line human description of the workflow this template represents
    /// (rendered in the selector UX).
    pub description: String,

    /// TTL ceiling for any grant issued from this template, as a duration
    /// string (e.g. `4h`, `90m`, `1h30m`). Enforced at issuance — the daemon
    /// refuses TTLs above this ceiling. Cohort defaults further compress it
    /// per design §Component 7 (dev0 ≤ 8h, team0 ≤ 4h, ent0 ≤ 1h).
    pub ttl: String,

    /// Action keys this template permits. Each entry is either an exact
    /// action key (`gh.pr_create`) or a namespace glob (`git.*`). Keys are
    /// matched by `broker.resolve` against the requested action; a match
    /// approves via `pregrant_path: workflow`.
    pub scopes: Vec<String>,

    /// Action keys explicitly excluded even when a broader `scopes` glob
    /// would otherwise match. Examples: `trust.*` excluded from every
    /// non-trust template; `gh.repo_delete` excluded from `emberd-development`.
    #[serde(default)]
    pub excludes: Vec<String>,

    /// Optional capability blocks. The only capability currently defined is
    /// `spawn_subagent` (enables `ember-scion.start` for headless-enrolled
    /// headless templates per design §Component 6). Unknown capability
    /// names parse but are ignored by the broker — forward-compat for
    /// future capabilities.
    #[serde(default)]
    pub capability: BTreeMap<String, Capability>,
}

/// A capability block attached to a workflow template. Currently a single
/// shape covering all defined capabilities (`spawn_subagent`); future
/// capabilities extend this struct rather than introducing parallel types,
/// keeping the TOML surface flat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Maximum spawn depth for `spawn_subagent`. None = unlimited (refused
    /// at broker side; templates must specify). Ignored for other
    /// capabilities.
    #[serde(default)]
    pub max_depth: Option<u32>,
}

/// Errors returned by [`WorkflowTemplate::parse`].
#[derive(Debug, thiserror::Error)]
pub enum WorkflowTemplateError {
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("ttl parse error: {0}")]
    Ttl(String),

    #[error("scope entry {0:?} does not match `<namespace>.<action>` or `<namespace>.*`")]
    InvalidActionKey(String),

    #[error("template name {0:?} is empty or contains characters outside [a-z0-9-]")]
    InvalidName(String),
}

impl WorkflowTemplate {
    /// Parse a workflow template from TOML text. Validates name, action-key
    /// shape, and TTL duration; returns descriptive errors that point at the
    /// offending field.
    pub fn parse(toml_text: &str) -> Result<Self, WorkflowTemplateError> {
        let template: WorkflowTemplate = toml::from_str(toml_text)?;
        template.validate()?;
        Ok(template)
    }

    /// Validate the template's own fields. Called by [`Self::parse`] but also
    /// useful when a `WorkflowTemplate` is constructed programmatically.
    pub fn validate(&self) -> Result<(), WorkflowTemplateError> {
        validate_name(&self.name)?;
        parse_ttl(&self.ttl)?;
        for key in &self.scopes {
            validate_action_key(key)?;
        }
        for key in &self.excludes {
            validate_action_key(key)?;
        }
        Ok(())
    }

    /// Resolve the TTL string to a `Duration`. Returns the cohort-pre-cap
    /// ceiling; the daemon further compresses it per cohort default.
    pub fn ttl_duration(&self) -> Result<Duration, WorkflowTemplateError> {
        parse_ttl(&self.ttl)
    }

    /// Return true if `action_key` is in scope and not excluded. Glob suffix
    /// `.*` matches any action in the namespace.
    pub fn allows(&self, action_key: &str) -> bool {
        if matches_any(&self.excludes, action_key) {
            return false;
        }
        matches_any(&self.scopes, action_key)
    }
}

fn validate_name(name: &str) -> Result<(), WorkflowTemplateError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(WorkflowTemplateError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_action_key(key: &str) -> Result<(), WorkflowTemplateError> {
    let (ns, action) = key
        .split_once('.')
        .ok_or_else(|| WorkflowTemplateError::InvalidActionKey(key.to_string()))?;
    if ns.is_empty() || action.is_empty() {
        return Err(WorkflowTemplateError::InvalidActionKey(key.to_string()));
    }
    let ns_ok = ns
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    let action_ok = action == "*"
        || action
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ns_ok || !action_ok {
        return Err(WorkflowTemplateError::InvalidActionKey(key.to_string()));
    }
    Ok(())
}

fn parse_ttl(s: &str) -> Result<Duration, WorkflowTemplateError> {
    let mut total = Duration::ZERO;
    let mut current = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
            continue;
        }
        let n: u64 = current
            .parse()
            .map_err(|_| WorkflowTemplateError::Ttl(s.to_string()))?;
        current.clear();
        let unit = match ch {
            's' => Duration::from_secs(n),
            'm' => Duration::from_secs(n * 60),
            'h' => Duration::from_secs(n * 3600),
            'd' => Duration::from_secs(n * 86400),
            _ => return Err(WorkflowTemplateError::Ttl(s.to_string())),
        };
        total += unit;
    }
    if !current.is_empty() {
        return Err(WorkflowTemplateError::Ttl(s.to_string()));
    }
    if total == Duration::ZERO {
        return Err(WorkflowTemplateError::Ttl(s.to_string()));
    }
    Ok(total)
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

    const MIN_TEMPLATE: &str = r#"
        name = "emberd-development"
        description = "dev"
        ttl = "4h"
        scopes = ["git.*", "gh.pr_create"]
    "#;

    #[test]
    fn parses_minimum_template() {
        let t = WorkflowTemplate::parse(MIN_TEMPLATE).unwrap();
        assert_eq!(t.name, "emberd-development");
        assert_eq!(t.ttl_duration().unwrap(), Duration::from_secs(4 * 3600));
        assert!(t.allows("git.push"));
        assert!(t.allows("gh.pr_create"));
        assert!(!t.allows("gh.repo_delete"));
    }

    #[test]
    fn excludes_override_scopes() {
        let t = WorkflowTemplate::parse(
            r#"
                name = "x"
                description = "x"
                ttl = "1h"
                scopes = ["gh.*"]
                excludes = ["gh.repo_delete"]
            "#,
        )
        .unwrap();
        assert!(t.allows("gh.pr_create"));
        assert!(!t.allows("gh.repo_delete"));
    }

    #[test]
    fn capability_block_parses() {
        let t = WorkflowTemplate::parse(
            r#"
                name = "headless"
                description = "headless tick workers"
                ttl = "4h"
                scopes = ["git.*"]
                [capability.spawn_subagent]
                max_depth = 3
            "#,
        )
        .unwrap();
        let cap = t.capability.get("spawn_subagent").unwrap();
        assert_eq!(cap.max_depth, Some(3));
    }

    #[test]
    fn ttl_units_compose() {
        assert_eq!(parse_ttl("4h").unwrap(), Duration::from_secs(4 * 3600));
        assert_eq!(parse_ttl("90m").unwrap(), Duration::from_secs(90 * 60));
        assert_eq!(parse_ttl("1h30m").unwrap(), Duration::from_secs(90 * 60));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86400));
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("4x").is_err());
        assert!(parse_ttl("").is_err());
    }

    #[test]
    fn invalid_action_key_rejected() {
        let bad = r#"
            name = "x"
            description = "x"
            ttl = "1h"
            scopes = ["NoDot"]
        "#;
        assert!(matches!(
            WorkflowTemplate::parse(bad),
            Err(WorkflowTemplateError::InvalidActionKey(_))
        ));
    }

    #[test]
    fn invalid_name_rejected() {
        let bad = r#"
            name = "Has Spaces"
            description = "x"
            ttl = "1h"
            scopes = ["git.push"]
        "#;
        assert!(matches!(
            WorkflowTemplate::parse(bad),
            Err(WorkflowTemplateError::InvalidName(_))
        ));
    }
}
