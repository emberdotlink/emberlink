//! Workflow-template schema — Serde-derived from TOML, validated at parse time.
//!
//! Per ADR 158 §Component 1 + ADR 162 §Component 6 + ADR 163 Stage 4: workflow
//! templates are operator-editable, bundled-by-default TOMLs that name a set
//! of action scopes, a TTL ceiling, and
//! optional capability blocks (e.g. `[capability.spawn_subagent]`).
//!
//! Bundled templates live under `lib/ember/delegation-templates/` in the
//! source repo; install pipelines (ADR 157 §Component 3) copy them to
//! `/usr/local/lib/ember/delegation-templates/` (prod) or
//! `/usr/local/lib/ember-dev/delegation-templates/` (dev). Operator overlays
//! at `~/.config/emberlink/delegation-templates/<name>.toml` take precedence.
//!
//! Workflow-template scopes use canonical `plugin_address/action_key@version`
//! strings and are parsed into structured action-ref patterns. `*` is allowed
//! in the `action_key` or `action_version` positions for whole-field matching.
//!
//! Anchor: `onboarding_delegation_templates_landed`.

use std::collections::BTreeMap;
use std::time::Duration;

use core_event_types::{ActionRef, ActionRefPattern};
use serde::{Deserialize, Serialize};

/// One compile-time bundled delegation template TOML payload.
pub struct BundledWorkflowTemplateToml {
    pub name: &'static str,
    pub toml: &'static str,
}

/// Canonical bundled workflow-template set baked into the binary so launchers
/// and the daemon can survive install/package drift where the managed
/// `delegation-templates/` directory is missing or partial.
pub const BUNDLED_DELEGATION_TEMPLATE_TOMLS: &[BundledWorkflowTemplateToml] = &[
    BundledWorkflowTemplateToml {
        name: "autopilot",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/autopilot.toml"
        )),
    },
    BundledWorkflowTemplateToml {
        name: "emberd-development",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/emberd-development.toml"
        )),
    },
    BundledWorkflowTemplateToml {
        name: "infra-iteration",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/infra-iteration.toml"
        )),
    },
    BundledWorkflowTemplateToml {
        name: "landing-page-edits",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/landing-page-edits.toml"
        )),
    },
    BundledWorkflowTemplateToml {
        name: "read-only",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/read-only.toml"
        )),
    },
    BundledWorkflowTemplateToml {
        name: "trust-management",
        toml: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../lib/ember/delegation-templates/trust-management.toml"
        )),
    },
];

pub fn bundled_delegation_template_toml(name: &str) -> Option<&'static str> {
    BUNDLED_DELEGATION_TEMPLATE_TOMLS
        .iter()
        .find(|template| template.name == name)
        .map(|template| template.toml)
}

/// A delegation template — the operator-facing unit a launcher prompt offers
/// at `ember claude-code` (per ADR 158 §Component 1). Templates lower into the
/// runtime persona's `StandingGrant` at session-open time per ADR 205 §6,
/// after operator Touch ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationTemplate {
    /// Template name, must match the filename stem (e.g. `emberd-development`
    /// for `emberd-development.toml`). Used in launcher prompts and stamped
    /// onto every credentialed Receipt as `delegation_template`.
    pub name: String,

    /// One-line human description of the workflow this template represents
    /// (rendered in the selector UX).
    pub description: String,

    /// TTL ceiling for any grant issued from this template, as a duration
    /// string (e.g. `4h`, `90m`, `1h30m`). Enforced at issuance — the daemon
    /// refuses TTLs above this ceiling. Cohort defaults further compress it
    /// per ADR 158 §Component 7 (dev0 ≤ 8h, team0 ≤ 4h, ent0 ≤ 1h).
    pub ttl: String,

    /// Structured action-ref patterns this template permits.
    pub scopes: Vec<ActionRefPattern>,

    /// Structured action-ref patterns explicitly excluded even when a broader
    /// `scopes` entry would otherwise match.
    #[serde(default)]
    pub excludes: Vec<ActionRefPattern>,

    /// Optional capability blocks. The only capability currently defined is
    /// `spawn_subagent` (enables `ember-scion.start` for headless-enrolled
    /// autopilot templates per ADR 158 §Component 6). Unknown capability
    /// names parse but are ignored by the broker — forward-compat for
    /// future capabilities.
    #[serde(default)]
    pub capability: BTreeMap<String, Capability>,
}

/// A capability block attached to a delegation template. Currently a single
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

/// Errors returned by [`DelegationTemplate::parse`].
#[derive(Debug, thiserror::Error)]
pub enum DelegationTemplateError {
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("ttl parse error: {0}")]
    Ttl(String),

    #[error("scope entry {0:?} is not a valid action-ref pattern")]
    InvalidActionRefPattern(String),

    #[error("template name {0:?} is empty or contains characters outside [a-z0-9-]")]
    InvalidName(String),
}

impl DelegationTemplate {
    /// Parse a delegation template from TOML text. Validates name, action-ref
    /// shape, and TTL duration; returns descriptive errors that point at the
    /// offending field.
    pub fn parse(toml_text: &str) -> Result<Self, DelegationTemplateError> {
        let template: DelegationTemplate = toml::from_str(toml_text)?;
        template.validate()?;
        Ok(template)
    }

    /// Validate the template's own fields. Called by [`Self::parse`] but also
    /// useful when a `DelegationTemplate` is constructed programmatically.
    pub fn validate(&self) -> Result<(), DelegationTemplateError> {
        validate_name(&self.name)?;
        parse_ttl(&self.ttl)?;
        for pattern in &self.scopes {
            validate_action_ref_pattern(pattern)?;
        }
        for pattern in &self.excludes {
            validate_action_ref_pattern(pattern)?;
        }
        Ok(())
    }

    /// Resolve the TTL string to a `Duration`. Returns the cohort-pre-cap
    /// ceiling; the daemon further compresses it per cohort default.
    pub fn ttl_duration(&self) -> Result<Duration, DelegationTemplateError> {
        parse_ttl(&self.ttl)
    }

    /// Return true if `action_ref` is in scope and not excluded.
    pub fn allows(&self, action_ref: &ActionRef) -> bool {
        if matches_any(&self.excludes, action_ref) {
            return false;
        }
        matches_any(&self.scopes, action_ref)
    }
}

fn validate_name(name: &str) -> Result<(), DelegationTemplateError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(DelegationTemplateError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_action_ref_pattern(pattern: &ActionRefPattern) -> Result<(), DelegationTemplateError> {
    pattern
        .validate()
        .map_err(|_| DelegationTemplateError::InvalidActionRefPattern(pattern.to_string()))
}

fn parse_ttl(s: &str) -> Result<Duration, DelegationTemplateError> {
    let mut total = Duration::ZERO;
    let mut current = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
            continue;
        }
        let n: u64 = current
            .parse()
            .map_err(|_| DelegationTemplateError::Ttl(s.to_string()))?;
        current.clear();
        let unit = match ch {
            's' => Duration::from_secs(n),
            'm' => Duration::from_secs(n * 60),
            'h' => Duration::from_secs(n * 3600),
            'd' => Duration::from_secs(n * 86400),
            _ => return Err(DelegationTemplateError::Ttl(s.to_string())),
        };
        total += unit;
    }
    if !current.is_empty() {
        return Err(DelegationTemplateError::Ttl(s.to_string()));
    }
    if total == Duration::ZERO {
        return Err(DelegationTemplateError::Ttl(s.to_string()));
    }
    Ok(total)
}

fn matches_any(patterns: &[ActionRefPattern], action_ref: &ActionRef) -> bool {
    patterns.iter().any(|p| p.matches(action_ref))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_TEMPLATE: &str = r#"
        name = "emberd-development"
        description = "dev"
        ttl = "4h"
        scopes = [
            "registry.ember.systems/ember-systems/ember-git/*@v1",
            "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
        ]
    "#;

    fn action_ref(plugin: &str, action: &str) -> ActionRef {
        ActionRef::new(plugin, action, "v1")
    }

    #[test]
    fn parses_minimum_template() {
        let t = DelegationTemplate::parse(MIN_TEMPLATE).unwrap();
        assert_eq!(t.name, "emberd-development");
        assert_eq!(t.ttl_duration().unwrap(), Duration::from_secs(4 * 3600));
        assert!(t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-git",
            "push"
        )));
        assert!(t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_create"
        )));
        assert!(!t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-gh",
            "repo_delete"
        )));
    }

    #[test]
    fn excludes_override_scopes() {
        let t = DelegationTemplate::parse(
            r#"
                name = "x"
                description = "x"
                ttl = "1h"
                scopes = ["registry.ember.systems/ember-systems/ember-gh/*@v1"]
                excludes = ["registry.ember.systems/ember-systems/ember-gh/repo_delete@v1"]
            "#,
        )
        .unwrap();
        assert!(t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_create"
        )));
        assert!(!t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-gh",
            "repo_delete"
        )));
    }

    #[test]
    fn capability_block_parses() {
        let t = DelegationTemplate::parse(
            r#"
                name = "autopilot"
                description = "autopilot tick workers"
                ttl = "4h"
                scopes = ["registry.ember.systems/ember-systems/ember-git/*@v1"]
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
    fn invalid_action_ref_pattern_rejected() {
        let bad = r#"
            name = "x"
            description = "x"
            ttl = "1h"
            scopes = ["Nope"]
        "#;
        let err = DelegationTemplate::parse(bad).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("plugin_address/action_key@action_version"),
            "got: {msg}"
        );
    }

    #[test]
    fn invalid_name_rejected() {
        let bad = r#"
            name = "Has Spaces"
            description = "x"
            ttl = "1h"
            scopes = ["registry.ember.systems/ember-systems/ember-git/push@v1"]
        "#;
        assert!(matches!(
            DelegationTemplate::parse(bad),
            Err(DelegationTemplateError::InvalidName(_))
        ));
    }

    #[test]
    fn bundled_delegation_template_tomls_include_known_templates() {
        let names: Vec<&str> = BUNDLED_DELEGATION_TEMPLATE_TOMLS
            .iter()
            .map(|template| template.name)
            .collect();
        assert!(names.contains(&"read-only"));
        assert!(names.contains(&"autopilot"));
        assert!(bundled_delegation_template_toml("trust-management").is_some());
    }
}
