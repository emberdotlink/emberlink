//! Evaluates a Claude Code PreToolUse request against a `ScopeTemplate`.
//! Per design §3.

use core_policy::{ScopeDecision, ScopeTemplate};
use serde_json::Value;
use std::path::Path;

/// Reduce a `(tool_name, params)` pair to a [`ScopeDecision`].
///
/// `project_root` is the resolved git toplevel of the agent's session.
/// `params` is the opaque object from Claude Code's PreToolUse payload
/// (see `claude_code_hook::PreToolUseRequest::params`).
pub fn evaluate_tool_call(
    template: &ScopeTemplate,
    project_root: &Path,
    tool_name: &str,
    params: &Value,
) -> ScopeDecision {
    match tool_name {
        "Bash" => evaluate_bash(template, params),
        "Read" | "Write" | "Edit" | "MultiEdit" => evaluate_filepath(template, project_root, params),
        "WebFetch" | "WebSearch" => evaluate_web(template, params),
        // MCP tools and anything not in the above set: require approval.
        _ => ScopeDecision::RequireApproval {
            reason: format!("tool '{tool_name}' not in default permit list"),
            rule: "approval.novel_tool".to_string(),
        },
    }
}

fn evaluate_bash(template: &ScopeTemplate, params: &Value) -> ScopeDecision {
    let cmd = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
    // 1. Deny destructive first (highest priority).
    for pat in &template.deny_destructive_bash {
        if pat.is_match(cmd) {
            return ScopeDecision::Deny {
                reason: format!("destructive bash pattern matched: {}", pat.as_str()),
                rule: "deny.destructive".to_string(),
            };
        }
    }
    // 2. Approval: git push.
    if let Some(p) = &template.approval_git_push
        && p.is_match(cmd)
    {
        return ScopeDecision::RequireApproval {
            reason: "git push requires approval".to_string(),
            rule: "approval.git_push".to_string(),
        };
    }
    // 3. Approval: package install.
    for pat in &template.approval_package_install {
        if pat.is_match(cmd) {
            return ScopeDecision::RequireApproval {
                reason: format!("package install requires approval: {}", pat.as_str()),
                rule: "approval.package_install".to_string(),
            };
        }
    }
    // 4. Permit if matches allowlist.
    for pat in &template.bash_allowlist {
        if pat.is_match(cmd) {
            return ScopeDecision::Permit;
        }
    }
    // 5. Default: require approval (novel bash).
    ScopeDecision::RequireApproval {
        reason: format!("bash command outside allowlist: {cmd}"),
        rule: "approval.novel_bash".to_string(),
    }
}

fn evaluate_filepath(template: &ScopeTemplate, project_root: &Path, params: &Value) -> ScopeDecision {
    let path = params
        .get("file_path")
        .or_else(|| params.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // 1. Approval: credential paths.
    for pat in &template.approval_credential_paths {
        if pat.is_match(path) {
            return ScopeDecision::RequireApproval {
                reason: format!("credential path access requires approval: {path}"),
                rule: "approval.credential_path_read".to_string(),
            };
        }
    }
    // 2. Permit if under project_root.
    if let Ok(p) = std::path::PathBuf::from(path).canonicalize() {
        if p.starts_with(project_root) {
            return ScopeDecision::Permit;
        }
    } else {
        // Path may not exist yet (Write); fall through to string-prefix check.
        if path.starts_with(&project_root.display().to_string()) {
            return ScopeDecision::Permit;
        }
    }
    // 3. Default: approval (outside project root).
    ScopeDecision::RequireApproval {
        reason: format!("path outside project root: {path}"),
        rule: "approval.cross_project_file_access".to_string(),
    }
}

fn evaluate_web(template: &ScopeTemplate, params: &Value) -> ScopeDecision {
    let url = params.get("url").and_then(|v| v.as_str()).unwrap_or("");
    for pat in &template.web_url_allowlist {
        if pat.is_match(url) {
            return ScopeDecision::Permit;
        }
    }
    ScopeDecision::RequireApproval {
        reason: format!("URL not in allowlist: {url}"),
        rule: "approval.novel_url".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl() -> ScopeTemplate {
        ScopeTemplate::default_claude_code().expect("template parses")
    }
    fn root() -> std::path::PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn bash_cargo_permit() {
        let p = serde_json::json!({"command": "cargo build"});
        assert_eq!(
            evaluate_tool_call(&tmpl(), &root(), "Bash", &p),
            ScopeDecision::Permit
        );
    }

    #[test]
    fn bash_rm_rf_deny() {
        let p = serde_json::json!({"command": "rm -rf /"});
        match evaluate_tool_call(&tmpl(), &root(), "Bash", &p) {
            ScopeDecision::Deny { rule, .. } => assert_eq!(rule, "deny.destructive"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn bash_git_push_approval() {
        let p = serde_json::json!({"command": "git push origin main"});
        match evaluate_tool_call(&tmpl(), &root(), "Bash", &p) {
            ScopeDecision::RequireApproval { rule, .. } => assert_eq!(rule, "approval.git_push"),
            other => panic!("expected RequireApproval, got {other:?}"),
        }
    }

    #[test]
    fn bash_novel_approval() {
        let p = serde_json::json!({"command": "weird-binary --do-thing"});
        match evaluate_tool_call(&tmpl(), &root(), "Bash", &p) {
            ScopeDecision::RequireApproval { rule, .. } => assert_eq!(rule, "approval.novel_bash"),
            other => panic!("expected novel_bash approval, got {other:?}"),
        }
    }

    #[test]
    fn web_fetch_github_permit() {
        let p = serde_json::json!({"url": "https://github.com/emberdotlink/emberlink"});
        assert_eq!(
            evaluate_tool_call(&tmpl(), &root(), "WebFetch", &p),
            ScopeDecision::Permit
        );
    }

    #[test]
    fn unknown_tool_approval() {
        let p = serde_json::json!({});
        match evaluate_tool_call(&tmpl(), &root(), "mcp__random_thing", &p) {
            ScopeDecision::RequireApproval { rule, .. } => assert_eq!(rule, "approval.novel_tool"),
            other => panic!("expected approval, got {other:?}"),
        }
    }
}
