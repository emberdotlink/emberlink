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
pub enum PolicyDecision {
    AutoApprove,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Pattern to match action names (supports glob: "git.*", "deploy.*", "*")
    pub action: String,
    /// Risk level for this action
    pub risk: RiskLevel,
    /// What to do when this action is requested
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Rules evaluated in order — first match wins
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Default decision for unmatched actions
    #[serde(default = "default_decision")]
    pub default_decision: PolicyDecision,
    /// Default risk level for unmatched actions
    #[serde(default = "default_risk")]
    pub default_risk: RiskLevel,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default_decision: default_decision(),
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

fn default_decision() -> PolicyDecision {
    PolicyDecision::RequireApproval
}

fn default_risk() -> RiskLevel {
    RiskLevel::Medium
}

pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub risk: RiskLevel,
    pub matched_rule: Option<String>,
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
pub fn normalize_action(action: &str) -> Result<String, PolicyError> {
    let trimmed = action.trim().to_lowercase();

    if trimmed.is_empty() {
        return Err(PolicyError::InvalidAction("empty action string".to_string()));
    }

    let stripped = trimmed.trim_matches('.');

    if stripped.is_empty() {
        return Err(PolicyError::InvalidAction("action contains only dots".to_string()));
    }

    let segments: Vec<&str> = stripped.split('.').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return Err(PolicyError::InvalidAction("no valid segments".to_string()));
    }

    for seg in &segments {
        if !seg.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '*') {
            return Err(PolicyError::InvalidAction(
                format!("invalid character in segment '{seg}'"),
            ));
        }
    }

    Ok(segments.join("."))
}

pub struct PolicyEngine {
    config: PolicyConfig,
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
    pat_parts.iter().zip(inp_parts.iter()).all(|(p, i)| *p == "*" || *p == *i)
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
        let action = match normalize_action(action) {
            Ok(a) => a,
            Err(_) => {
                return PolicyEvaluation {
                    decision: PolicyDecision::Deny,
                    risk: RiskLevel::Critical,
                    matched_rule: Some("invalid action".to_string()),
                }
            }
        };
        for rule in &self.config.rules {
            if matches_glob(&rule.action, &action) {
                return PolicyEvaluation {
                    decision: rule.decision.clone(),
                    risk: rule.risk.clone(),
                    matched_rule: Some(rule.action.clone()),
                };
            }
        }
        PolicyEvaluation {
            decision: self.config.default_decision.clone(),
            risk: self.config.default_risk.clone(),
            matched_rule: None,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        let rules = vec![
            PolicyRule {
                action: "git.push.main".to_string(),
                risk: RiskLevel::Critical,
                decision: PolicyDecision::Deny,
            },
            PolicyRule {
                action: "git.push.*".to_string(),
                risk: RiskLevel::Medium,
                decision: PolicyDecision::AutoApprove,
            },
            PolicyRule {
                action: "deploy.production".to_string(),
                risk: RiskLevel::Critical,
                decision: PolicyDecision::RequireApproval,
            },
            PolicyRule {
                action: "deploy.staging".to_string(),
                risk: RiskLevel::Medium,
                decision: PolicyDecision::AutoApprove,
            },
            PolicyRule {
                action: "credential.access".to_string(),
                risk: RiskLevel::High,
                decision: PolicyDecision::RequireApproval,
            },
            PolicyRule {
                action: "*".to_string(),
                risk: RiskLevel::Medium,
                decision: PolicyDecision::RequireApproval,
            },
        ];
        Self::new(PolicyConfig {
            rules,
            default_decision: default_decision(),
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
        assert_eq!(eval.decision, PolicyDecision::Deny);
        assert_eq!(eval.risk, RiskLevel::Critical);
        assert_eq!(eval.matched_rule.as_deref(), Some("git.push.main"));
    }

    #[test]
    fn default_git_push_branch_auto_approve() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("git.push.feat-branch");
        assert_eq!(eval.decision, PolicyDecision::AutoApprove);
        assert_eq!(eval.matched_rule.as_deref(), Some("git.push.*"));
    }

    #[test]
    fn default_deploy_production_require_approval() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("deploy.production");
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert_eq!(eval.risk, RiskLevel::Critical);
    }

    #[test]
    fn default_unknown_action_require_approval() {
        let engine = PolicyEngine::default();
        let eval = engine.evaluate("some.unknown.action");
        assert_eq!(eval.decision, PolicyDecision::RequireApproval);
        assert_eq!(eval.matched_rule.as_deref(), Some("*"));
    }

    #[test]
    fn parse_from_toml_evaluates_correctly() {
        let toml_str = r#"
default_decision = "require_approval"
default_risk = "medium"

[[rules]]
action = "git.push.main"
risk = "critical"
decision = "deny"

[[rules]]
action = "deploy.staging"
risk = "medium"
decision = "auto_approve"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("git.push.main");
        assert_eq!(eval.decision, PolicyDecision::Deny);
        assert_eq!(eval.risk, RiskLevel::Critical);

        let eval2 = engine.evaluate("deploy.staging");
        assert_eq!(eval2.decision, PolicyDecision::AutoApprove);
    }

    #[test]
    fn custom_toml_overrides_defaults() {
        let toml_str = r#"
default_decision = "deny"
default_risk = "high"

[[rules]]
action = "safe.action"
risk = "low"
decision = "auto_approve"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("unsafe.action");
        assert_eq!(eval.decision, PolicyDecision::Deny);
        assert_eq!(eval.risk, RiskLevel::High);
        assert!(eval.matched_rule.is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let toml_str = r#"
[[rules]]
action = "git.push.main"
risk = "medium"
decision = "auto_approve"

[[rules]]
action = "git.push.main"
risk = "critical"
decision = "deny"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("git.push.main");
        assert_eq!(eval.decision, PolicyDecision::AutoApprove);
        assert_eq!(eval.risk, RiskLevel::Medium);
    }

    #[test]
    fn empty_rules_use_default_decision() {
        let toml_str = r#"
default_decision = "auto_approve"
default_risk = "low"
"#;
        let engine = PolicyEngine::from_toml(toml_str).unwrap();
        let eval = engine.evaluate("any.action");
        assert_eq!(eval.decision, PolicyDecision::AutoApprove);
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
        assert_eq!(eval.decision, PolicyDecision::Deny);
        assert_eq!(eval.risk, RiskLevel::Critical);
        assert_eq!(eval.matched_rule.as_deref(), Some("invalid action"));
    }

    #[test]
    fn merge_prepends_rules() {
        let mut user_config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "deploy.production".to_string(),
                risk: RiskLevel::Critical,
                decision: PolicyDecision::RequireApproval,
            }],
            ..PolicyConfig::default()
        };
        let project_config = PolicyConfig {
            rules: vec![PolicyRule {
                action: "deploy.production".to_string(),
                risk: RiskLevel::Low,
                decision: PolicyDecision::AutoApprove,
            }],
            ..PolicyConfig::default()
        };
        user_config.merge(project_config);
        // Project rule is now first — it should win
        let engine = PolicyEngine::new(user_config);
        let eval = engine.evaluate("deploy.production");
        assert_eq!(eval.decision, PolicyDecision::AutoApprove);
        assert_eq!(eval.risk, RiskLevel::Low);
    }

    #[test]
    fn merge_does_not_override_defaults() {
        let mut user_config = PolicyConfig {
            rules: vec![],
            default_decision: PolicyDecision::Deny,
            default_risk: RiskLevel::High,
        };
        let project_config = PolicyConfig {
            rules: vec![],
            default_decision: PolicyDecision::AutoApprove,
            default_risk: RiskLevel::Low,
        };
        user_config.merge(project_config);
        // User defaults remain unchanged
        assert_eq!(user_config.default_decision, PolicyDecision::Deny);
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
default_decision = "require_approval"
default_risk = "medium"

[[rules]]
action = "deploy.staging"
risk = "medium"
decision = "auto_approve"
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
decision = "deny"
"#
        )
        .unwrap();

        let engine = PolicyEngine::load_with_overrides(
            user_file.path(),
            Some(project_file.path()),
        )
        .unwrap();

        let eval = engine.evaluate("deploy.staging");
        assert_eq!(eval.decision, PolicyDecision::Deny);
        assert_eq!(eval.risk, RiskLevel::High);
    }
}
