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

    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        let config: PolicyConfig = toml::from_str(toml_str)?;
        Ok(Self::new(config))
    }

    pub fn evaluate(&self, action: &str) -> PolicyEvaluation {
        for rule in &self.config.rules {
            if matches_glob(&rule.action, action) {
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
}
