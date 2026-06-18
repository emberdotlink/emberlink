pub use core_event_types::{ActionRef, ActionSelector};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    Auto,
    Required,
    Denied,
}

/// P69L.3 approval tier (ADR 047 §Approval UX).
///
/// Tiers classify how an action reaches its decision, separate from the
/// decision itself:
/// - `Tier0` → silent auto-approve, zero interruption.
/// - `Tier1` → interactive approval (desktop notification / dashboard).
/// - `Tier2` → hardware-key approval (YubiKey touch / biometric).
///
/// Tier is a projection of `ApprovalRequirement` by default, but rules may
/// pin a stricter tier explicitly (e.g. an auto-approve action the
/// operator still wants routed through hardware). The runtime gate in
/// the approval handler refuses Tier 2 with a clear "not yet supported"
/// error until the hardware path ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Tier0,
    Tier1,
    Tier2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Pattern to match generic named actions or structured construct refs.
    #[serde(serialize_with = "serialize_policy_action")]
    pub action: ActionSelector,
    /// Risk level for this action
    pub risk: RiskLevel,
    /// What to do when this action is requested
    pub requirement: ApprovalRequirement,
    /// Explicit tier override. When absent, the tier is derived from
    /// `requirement` via [`classify_tier`].
    #[serde(default)]
    pub tier: Option<Tier>,
}

/// Default tier for a given requirement (per ADR 047): auto is
/// Tier 0 (silent), required is Tier 1 (interactive), denied is
/// Tier 2 (hardware-key required to override).
pub fn classify_tier(requirement: &ApprovalRequirement) -> Tier {
    match requirement {
        ApprovalRequirement::Auto => Tier::Tier0,
        ApprovalRequirement::Required => Tier::Tier1,
        ApprovalRequirement::Denied => Tier::Tier2,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Rules evaluated in order — first match wins
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Default requirement for unmatched actions
    #[serde(default = "default_requirement")]
    pub default_requirement: ApprovalRequirement,
    /// Default risk level for unmatched actions
    #[serde(default = "default_risk")]
    pub default_risk: RiskLevel,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_requirement: default_requirement(),
            default_risk: default_risk(),
        }
    }
}

impl PolicyConfig {
    /// Merge another config into this one. The other config's rules are
    /// prepended (higher priority, first-match-wins). Defaults are NOT
    /// overridden — user-level defaults always win.
    pub fn merge(&mut self, other: PolicyConfig) {
        let mut merged_rules = other.rules;
        merged_rules.append(&mut self.rules);
        self.rules = merged_rules;
    }
}

fn default_requirement() -> ApprovalRequirement {
    ApprovalRequirement::Required
}

fn default_risk() -> RiskLevel {
    RiskLevel::Medium
}

pub struct PolicyEvaluation {
    pub requirement: ApprovalRequirement,
    pub risk: RiskLevel,
    pub matched_rule: Option<String>,
    /// P69L.3 — approval tier for this evaluation. Derived from the
    /// rule's explicit `tier` field when present, otherwise projected
    /// from `requirement` via [`classify_tier`].
    pub tier: Tier,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid action: {0}")]
    InvalidAction(String),
}

/// Normalize an action string: lowercase, strip leading/trailing dots,
/// collapse consecutive dots, reject empty or invalid segments.
///
/// This applies only to generic named actions such as `git.push.main`,
/// not structured authority refs like `plugin/action@version`.
pub fn normalize_action(action: &str) -> Result<String, PolicyError> {
    let trimmed = action.trim().to_lowercase();

    if trimmed.is_empty() {
        return Err(PolicyError::InvalidAction(
            "empty action string".to_string(),
        ));
    }

    let stripped = trimmed.trim_matches('.');

    if stripped.is_empty() {
        return Err(PolicyError::InvalidAction(
            "action contains only dots".to_string(),
        ));
    }

    let segments: Vec<&str> = stripped.split('.').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return Err(PolicyError::InvalidAction("no valid segments".to_string()));
    }

    for seg in &segments {
        if !seg
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '*')
        {
            return Err(PolicyError::InvalidAction(format!(
                "invalid character in segment '{seg}'"
            )));
        }
    }

    Ok(segments.join("."))
}

pub struct PolicyEngine {
    config: PolicyConfig,
}

enum RequestedAction {
    Named(String),
    ActionRef(ActionRef),
}

fn matches_glob(pattern: &str, input: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pat_parts: Vec<&str> = pattern.split('.').collect();
    let inp_parts: Vec<&str> = input.split('.').collect();
    if pat_parts.len() != inp_parts.len() {
        return false;
    }
    pat_parts
        .iter()
        .zip(inp_parts.iter())
        .all(|(p, i)| *p == "*" || *p == *i)
}

fn parse_requested_action(action: &str) -> Result<RequestedAction, PolicyError> {
    let trimmed = action.trim();
    if let Ok(action_ref) = ActionRef::parse(trimmed) {
        return Ok(RequestedAction::ActionRef(action_ref));
    }
    normalize_action(trimmed).map(RequestedAction::Named)
}

fn rule_matches_requested_action(rule: &ActionSelector, requested: &RequestedAction) -> bool {
    match requested {
        RequestedAction::Named(action) => match rule {
            ActionSelector::Named { pattern } => matches_glob(pattern, action),
            ActionSelector::ActionRef(_) => false,
        },
        RequestedAction::ActionRef(action_ref) => match rule {
            ActionSelector::Named { pattern } => matches_glob(pattern, &action_ref.to_string()),
            ActionSelector::ActionRef(pattern) => pattern.matches(action_ref),
        },
    }
}

fn invalid_action_evaluation() -> PolicyEvaluation {
    PolicyEvaluation {
        requirement: ApprovalRequirement::Denied,
        risk: RiskLevel::Critical,
        matched_rule: Some("invalid action".to_string()),
        tier: Tier::Tier2,
    }
}

fn serialize_policy_action<S>(action: &ActionSelector, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&action.to_string())
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        let config: PolicyConfig = toml::from_str(toml_str)?;
        Ok(Self::new(config))
    }

    /// Load user policy, then merge project-level overrides if present.
    pub fn load_with_overrides(
        user_policy: &std::path::Path,
        project_policy: Option<&std::path::Path>,
    ) -> Result<Self, PolicyError> {
        let mut config = if user_policy.exists() {
            let text = std::fs::read_to_string(user_policy)?;
            toml::from_str(&text)?
        } else {
            PolicyConfig::default()
        };

        if let Some(project) = project_policy
            && project.exists()
        {
            let text = std::fs::read_to_string(project)?;
            let project_config: PolicyConfig = toml::from_str(&text)?;
            config.merge(project_config);
        }

        Ok(Self::new(config))
    }

    pub fn evaluate(&self, action: &str) -> PolicyEvaluation {
        let requested = match parse_requested_action(action) {
            Ok(requested) => requested,
            Err(_) => return invalid_action_evaluation(),
        };
        self.evaluate_requested_action(&requested)
    }

    pub fn evaluate_action_ref(&self, action_ref: &ActionRef) -> PolicyEvaluation {
        self.evaluate_requested_action(&RequestedAction::ActionRef(action_ref.clone()))
    }

    fn evaluate_requested_action(&self, requested: &RequestedAction) -> PolicyEvaluation {
        for rule in &self.config.rules {
            if rule_matches_requested_action(&rule.action, requested) {
                let tier = rule
                    .tier
                    .unwrap_or_else(|| classify_tier(&rule.requirement));
                return PolicyEvaluation {
                    requirement: rule.requirement.clone(),
                    risk: rule.risk.clone(),
                    matched_rule: Some(rule.action.to_string()),
                    tier,
                };
            }
        }
        let tier = classify_tier(&self.config.default_requirement);
        PolicyEvaluation {
            requirement: self.config.default_requirement.clone(),
            risk: self.config.default_risk.clone(),
            matched_rule: None,
            tier,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        let rules = vec![
            PolicyRule {
                action: ActionSelector::named("git.push.main"),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            },
            PolicyRule {
                action: ActionSelector::named("git.push.*"),
                risk: RiskLevel::Medium,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
            PolicyRule {
                action: ActionSelector::named("deploy.production"),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Required,
                tier: Some(Tier::Tier2),
            },
            PolicyRule {
                action: ActionSelector::named("deploy.staging"),
                risk: RiskLevel::Medium,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
            PolicyRule {
                action: ActionSelector::named("credential.access"),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Required,
                tier: None,
            },
            PolicyRule {
                action: ActionSelector::named("*"),
                risk: RiskLevel::Medium,
                requirement: ApprovalRequirement::Required,
                tier: None,
            },
        ];
        Self::new(PolicyConfig {
            rules,
            default_requirement: default_requirement(),
            default_risk: default_risk(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_git_push_main_deny() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("git.push.main");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.risk, RiskLevel::Critical);
        assert_eq!(eval.matched_rule.as_deref(), Some("git.push.main"));
    }

    #[test]
    fn default_git_push_branch_auto_approve() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("git.push.feat-branch");
        assert_eq!(eval.requirement, ApprovalRequirement::Auto);
        assert_eq!(eval.matched_rule.as_deref(), Some("git.push.*"));
    }

    #[test]
    fn default_deploy_production_require_approval() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("deploy.production");
        assert_eq!(eval.requirement, ApprovalRequirement::Required);
        assert_eq!(eval.risk, RiskLevel::Critical);
    }

    #[test]
    fn default_unknown_action_require_approval() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("some.unknown.action");
        assert_eq!(eval.requirement, ApprovalRequirement::Required);
        assert_eq!(eval.matched_rule.as_deref(), Some("*"));
    }

    #[test]
    fn parse_from_toml_evaluates_correctly() {
        let toml_str = r#"
default_requirement = "denied"
default_risk = "medium"

[[rules]]
action = "git.push.main"
risk = "critical"
requirement = "denied"

[[rules]]
action = "deploy.staging"
risk = "medium"
requirement = "auto"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("git.push.main");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.risk, RiskLevel::Critical);

        let eval2 = engine.evaluate("deploy.staging");
        assert_eq!(eval2.requirement, ApprovalRequirement::Auto);
    }

    #[test]
    fn custom_toml_overrides_defaults() {
        let toml_str = r#"
default_requirement = "denied"
default_risk = "high"

[[rules]]
action = "safe.action"
risk = "low"
requirement = "auto"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("unsafe.action");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.risk, RiskLevel::High);
        assert!(eval.matched_rule.is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let toml_str = r#"
[[rules]]
action = "git.push.main"
risk = "medium"
requirement = "auto"

[[rules]]
action = "git.push.main"
risk = "critical"
requirement = "denied"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("git.push.main");
        assert_eq!(eval.requirement, ApprovalRequirement::Auto);
        assert_eq!(eval.risk, RiskLevel::Medium);
    }

    #[test]
    fn empty_rules_use_default_decision() {
        let toml_str = r#"
default_requirement = "auto"
default_risk = "low"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("any.action");
        assert_eq!(eval.requirement, ApprovalRequirement::Auto);
        assert_eq!(eval.risk, RiskLevel::Low);
        assert!(eval.matched_rule.is_none());
    }

    #[test]
    fn glob_wildcard_matches_any_segment() {
        assert!(matches_glob("git.*", "git.push"));
        assert!(matches_glob("git.*", "git.pull"));
        assert!(!matches_glob("git.*", "git.push.main"));
        assert!(matches_glob("*", "anything"));
        assert!(!matches_glob("git.*", "svn.push"));
    }

    #[test]
    fn normalize_strips_dots() {
        assert_eq!(normalize_action("..git.push..").unwrap(), "git.push");
    }

    #[test]
    fn normalize_collapses_dots() {
        assert_eq!(normalize_action("git...push").unwrap(), "git.push");
    }

    #[test]
    fn normalize_lowercases() {
        assert_eq!(normalize_action("Git.Push").unwrap(), "git.push");
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(normalize_action("").is_err());
    }

    #[test]
    fn normalize_rejects_special_chars() {
        assert!(normalize_action("git;drop").is_err());
    }

    #[test]
    fn normalize_accepts_wildcards() {
        assert_eq!(normalize_action("git.*").unwrap(), "git.*");
    }

    #[test]
    fn evaluate_rejects_invalid_action() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.risk, RiskLevel::Critical);
        assert_eq!(eval.matched_rule.as_deref(), Some("invalid action"));
    }

    #[test]
    fn merge_prepends_rules() {
        let mut user_config = PolicyConfig {
            rules: vec![PolicyRule {
                action: ActionSelector::named("deploy.production"),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Required,
                tier: None,
            }],
            ..PolicyConfig::default()
        };
        let project_config = PolicyConfig {
            rules: vec![PolicyRule {
                action: ActionSelector::named("deploy.production"),
                risk: RiskLevel::Low,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            }],
            ..PolicyConfig::default()
        };
        user_config.merge(project_config);
        // Project rule is now first — it should win
        let engine = PolicyEngine::new(user_config);
        let eval = engine.evaluate("deploy.production");
        assert_eq!(eval.requirement, ApprovalRequirement::Auto);
        assert_eq!(eval.risk, RiskLevel::Low);
    }

    #[test]
    fn merge_does_not_override_defaults() {
        let mut user_config = PolicyConfig {
            rules: vec![],
            default_requirement: ApprovalRequirement::Denied,
            default_risk: RiskLevel::High,
        };
        let project_config = PolicyConfig {
            rules: vec![],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        };
        user_config.merge(project_config);
        // User defaults remain unchanged
        assert_eq!(user_config.default_requirement, ApprovalRequirement::Denied);
        assert_eq!(user_config.default_risk, RiskLevel::High);
    }

    #[test]
    fn load_with_overrides_project_wins() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut user_file = NamedTempFile::new().unwrap();
        write!(
            user_file,
            r#"
default_requirement = "required"
default_risk = "medium"

[[rules]]
action = "deploy.staging"
risk = "medium"
requirement = "auto"
"#
        )
        .unwrap();

        let mut project_file = NamedTempFile::new().unwrap();
        write!(
            project_file,
            r#"
[[rules]]
action = "deploy.staging"
risk = "high"
requirement = "denied"
"#
        )
        .unwrap();

        let engine =
            PolicyEngine::load_with_overrides(user_file.path(), Some(project_file.path())).unwrap();

        let eval = engine.evaluate("deploy.staging");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.risk, RiskLevel::High);
    }

    // --- P69L.3 — Tier classification ---

    #[test]
    fn tier_classification_defaults_from_decision() {
        // Auto → Tier 0, Required → Tier 1, Denied → Tier 2.
        let engine = PolicyEngine::default();

        // `git.push.feat/*` auto-approves → Tier 0.
        let auto = engine.evaluate("git.push.feat-branch");
        assert_eq!(auto.requirement, ApprovalRequirement::Auto);
        assert_eq!(auto.tier, Tier::Tier0);

        // `credential.access` requires approval → Tier 1.
        let interactive = engine.evaluate("credential.access");
        assert_eq!(interactive.requirement, ApprovalRequirement::Required);
        assert_eq!(interactive.tier, Tier::Tier1);

        // `git.push.main` denies → Tier 2.
        let denied = engine.evaluate("git.push.main");
        assert_eq!(denied.requirement, ApprovalRequirement::Denied);
        assert_eq!(denied.tier, Tier::Tier2);
    }

    #[test]
    fn tier_explicit_override_wins() {
        // A rule can pin a stricter tier than the default classifier would
        // derive — e.g. an auto-approve action the operator still wants
        // routed through hardware.
        let toml_str = r#"
[[rules]]
action = "deploy.production"
risk = "critical"
requirement = "required"
tier = "tier2"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("deploy.production");
        assert_eq!(eval.requirement, ApprovalRequirement::Required);
        // Classifier default for Required is Tier1, but the rule
        // pins Tier2 — the explicit override must win.
        assert_eq!(eval.tier, Tier::Tier2);
    }

    #[test]
    fn tier_unmatched_action_uses_default_decision_tier() {
        let toml_str = r#"
default_requirement = "auto"
default_risk = "low"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("any.unmatched.action");
        assert!(eval.matched_rule.is_none());
        // Default requirement is Auto → Tier 0.
        assert_eq!(eval.tier, Tier::Tier0);
    }

    #[test]
    fn tier_invalid_action_is_tier2() {
        // Invalid actions are denied at Tier 2 (the strictest gate) so
        // garbage input can never slip into the Tier 0 silent-approve
        // path.
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(eval.tier, Tier::Tier2);
    }

    #[test]
    fn structured_action_ref_rule_matches_string_input() {
        let toml_str = r#"
[[rules]]
action = "registry.ember.systems/ember-systems/ember-gh/pr_merge@v1"
risk = "critical"
requirement = "denied"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1");
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(
            eval.matched_rule.as_deref(),
            Some("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1")
        );
    }

    #[test]
    fn structured_action_ref_rule_matches_typed_input() {
        let engine = PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: ActionSelector::action_ref(core_event_types::ActionRefPattern::new(
                    "registry.ember.systems/ember-systems/ember-gh",
                    "pr_merge",
                    "v1",
                )),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            }],
            default_requirement: ApprovalRequirement::Required,
            default_risk: RiskLevel::Medium,
        });
        let eval = engine.evaluate_action_ref(&ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_merge",
            "v1",
        ));
        assert_eq!(eval.requirement, ApprovalRequirement::Denied);
        assert_eq!(
            eval.matched_rule.as_deref(),
            Some("registry.ember.systems/ember-systems/ember-gh/pr_merge@v1")
        );
    }

    #[test]
    fn policy_config_serializes_named_rules_as_strings() {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: ActionSelector::named("git.push.main"),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            }],
            ..PolicyConfig::default()
        };
        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("action = \"git.push.main\""));
    }

    #[test]
    fn policy_config_serializes_structured_rules_as_canonical_strings() {
        let config = PolicyConfig {
            rules: vec![PolicyRule {
                action: ActionSelector::action_ref(core_event_types::ActionRefPattern::new(
                    "registry.ember.systems/ember-systems/ember-gh",
                    "pr_merge",
                    "v1",
                )),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            }],
            ..PolicyConfig::default()
        };
        let toml = toml::to_string(&config).unwrap();
        assert!(
            toml.contains("action = \"registry.ember.systems/ember-systems/ember-gh/pr_merge@v1\"")
        );
    }
}
