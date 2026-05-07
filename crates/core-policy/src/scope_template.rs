//! Scope template schema + parser for cohort A `claude-code-default-v1`.
//!
//! Per design §3. Pure types with pre-compiled regexes; the evaluator
//! hot path (in `ember-proxy/src/evaluator.rs`) does no allocation.

use serde::Deserialize;

/// Embedded copy of the default Claude Code scope template. Written to
/// `~/.ember/grant-template.toml` on `ember init --for claude-code` per
/// design §2.
pub const DEFAULT_CLAUDE_CODE_TEMPLATE_TOML: &str =
    include_str!("templates/claude_code_default_v1.toml");

pub const DEFAULT_CLAUDE_CODE_TEMPLATE_ID: &str = "claude-code-default-v1";

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid regex in {field}: {source}")]
    Regex {
        field: String,
        #[source]
        source: regex::Error,
    },
}

/// Decision returned by the evaluator. `rule` is a stable string id from
/// the template (e.g. `"approval.git_push"`) so audit logs can attribute
/// the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    Permit,
    Deny { reason: String, rule: String },
    RequireApproval { reason: String, rule: String },
}

/// Parsed + validated scope template. Constructed from TOML via
/// [`ScopeTemplate::from_toml_str`]; regexes are pre-compiled so the
/// evaluator hot path is allocation-free.
#[derive(Debug, Clone)]
pub struct ScopeTemplate {
    pub id: String,
    pub description: String,
    pub bash_allowlist: Vec<regex::Regex>,
    pub web_url_allowlist: Vec<regex::Regex>,
    pub approval_credential_paths: Vec<regex::Regex>,
    pub approval_git_push: Option<regex::Regex>,
    pub approval_package_install: Vec<regex::Regex>,
    pub deny_destructive_bash: Vec<regex::Regex>,
    /// Resolution mode for project_root: `"git_toplevel"` (resolved by
    /// caller before evaluate) is the only accepted value for cohort A.
    pub project_root_mode: String,
}

impl ScopeTemplate {
    pub fn default_claude_code() -> Result<Self, ParseError> {
        Self::from_toml_str(DEFAULT_CLAUDE_CODE_TEMPLATE_TOML)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, ParseError> {
        let raw: RawTemplate = toml::from_str(s)?;
        Self::compile(raw)
    }

    fn compile(raw: RawTemplate) -> Result<Self, ParseError> {
        let bash_allowlist = compile_list(
            &raw.permit.bash.allowlist_patterns,
            "permit.bash.allowlist_patterns",
        )?;
        let web_url_allowlist = compile_list(
            &raw.permit.web_fetch.url_allowlist,
            "permit.web_fetch.url_allowlist",
        )?;
        let approval_credential_paths = compile_list(
            &raw.approval.credential_path_read.path_patterns,
            "approval.credential_path_read.path_patterns",
        )?;
        let approval_git_push = match raw.approval.git_push.bash_pattern {
            Some(p) => Some(regex::Regex::new(&p).map_err(|e| ParseError::Regex {
                field: "approval.git_push.bash_pattern".to_string(),
                source: e,
            })?),
            None => None,
        };
        let approval_package_install = compile_list(
            &raw.approval.package_install.bash_patterns,
            "approval.package_install.bash_patterns",
        )?;
        let deny_destructive_bash = compile_list(
            &raw.deny.destructive.bash_patterns,
            "deny.destructive.bash_patterns",
        )?;

        Ok(ScopeTemplate {
            id: raw.template.id,
            description: raw.template.description,
            bash_allowlist,
            web_url_allowlist,
            approval_credential_paths,
            approval_git_push,
            approval_package_install,
            deny_destructive_bash,
            project_root_mode: raw.permit.read_write_edit.project_root,
        })
    }
}

fn compile_list(patterns: &[String], field: &str) -> Result<Vec<regex::Regex>, ParseError> {
    let mut out = Vec::with_capacity(patterns.len());
    for (i, p) in patterns.iter().enumerate() {
        let r = regex::Regex::new(p).map_err(|e| ParseError::Regex {
            field: format!("{field}[{i}]"),
            source: e,
        })?;
        out.push(r);
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct RawTemplate {
    template: RawHeader,
    permit: RawPermit,
    approval: RawApproval,
    deny: RawDeny,
}

#[derive(Debug, Deserialize)]
struct RawHeader {
    id: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct RawPermit {
    read_write_edit: RawReadWriteEdit,
    bash: RawBash,
    web_fetch: RawWebFetch,
}

#[derive(Debug, Deserialize)]
struct RawReadWriteEdit {
    project_root: String,
}

#[derive(Debug, Deserialize)]
struct RawBash {
    allowlist_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawWebFetch {
    url_allowlist: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawApproval {
    #[serde(default)]
    #[allow(dead_code)]
    cross_project_file_access: Option<RawCrossProject>,
    credential_path_read: RawCredentialPathRead,
    git_push: RawGitPush,
    #[serde(default)]
    #[allow(dead_code)]
    novel_bash: Option<RawNovelBash>,
    package_install: RawPackageInstall,
}

#[derive(Debug, Deserialize)]
struct RawCrossProject {
    #[allow(dead_code)]
    trigger: String,
}

#[derive(Debug, Deserialize)]
struct RawCredentialPathRead {
    path_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawGitPush {
    bash_pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawNovelBash {
    #[allow(dead_code)]
    trigger: String,
}

#[derive(Debug, Deserialize)]
struct RawPackageInstall {
    bash_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawDeny {
    destructive: RawDestructive,
}

#[derive(Debug, Deserialize)]
struct RawDestructive {
    bash_patterns: Vec<String>,
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn default_template_always_parses(_seed in 0u32..1) {
            let t = ScopeTemplate::default_claude_code();
            prop_assert!(t.is_ok(), "default template must parse: {:?}", t.err());
        }

        #[test]
        fn id_round_trips(_seed in 0u32..1) {
            let t = ScopeTemplate::default_claude_code().unwrap();
            prop_assert_eq!(t.id, DEFAULT_CLAUDE_CODE_TEMPLATE_ID);
        }

        #[test]
        fn allowlists_non_empty(_seed in 0u32..1) {
            let t = ScopeTemplate::default_claude_code().unwrap();
            prop_assert!(!t.bash_allowlist.is_empty());
            prop_assert!(!t.web_url_allowlist.is_empty());
            prop_assert!(!t.deny_destructive_bash.is_empty());
        }
    }
}
