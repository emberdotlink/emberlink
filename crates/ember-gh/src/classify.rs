//! Argv classifier: maps `gh <verb> <subverb> ...` to a `construct.toml`
//! action_key. Per design §3 — this lives shim-side BUT the daemon
//! re-classifies the argv server-side (untrusts the shim).
//!
//! v1 covers the most common gh verbs the construct.toml schema declares.
//! Unknown shapes return Err — daemon will refuse exec.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedAction {
    /// Action key matching a `[[actions]]` entry in construct.toml.
    pub action_key: String,
    /// Subset of argv that the daemon will pass to the real `gh` binary
    /// (after server-side re-classification).
    pub forwarded_argv: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("empty argv")]
    EmptyArgv,
    #[error("unrecognized verb: {0}")]
    UnknownVerb(String),
    #[error("unrecognized subverb '{1}' for verb '{0}'")]
    UnknownSubverb(String, String),
}

/// Classify `gh <verb> <subverb> ...` argv into an action_key.
pub fn classify_gh_argv(argv: &[String]) -> Result<ClassifiedAction, ClassifyError> {
    if argv.is_empty() {
        return Err(ClassifyError::EmptyArgv);
    }
    let verb = &argv[0];
    let subverb = argv.get(1).map(String::as_str);

    let action_key = match (verb.as_str(), subverb) {
        ("pr", Some("create")) => "pr_create",
        ("pr", Some("merge")) => "pr_merge",
        ("pr", Some("close")) => "pr_close",
        ("pr", Some("comment")) => "pr_comment",
        ("pr", Some("list")) => "pr_list",
        ("pr", Some("view")) => "pr_view",
        ("repo", Some("create")) => "repo_create",
        ("repo", Some("delete")) => "repo_delete",
        ("repo", Some("clone")) => "repo_clone",
        ("repo", Some("view")) => "repo_view",
        ("auth", Some("login")) => "auth_login",
        ("auth", Some("status")) => "auth_status",
        ("workflow", Some("run")) => "workflow_run",
        ("workflow", Some("list")) => "workflow_list",
        ("issue", Some("create")) => "issue_create",
        ("issue", Some("close")) => "issue_close",
        ("issue", Some("list")) => "issue_list",
        (v, Some(s)) => return Err(ClassifyError::UnknownSubverb(v.to_string(), s.to_string())),
        (v, None) => return Err(ClassifyError::UnknownVerb(v.to_string())),
    };

    Ok(ClassifiedAction {
        action_key: action_key.to_string(),
        forwarded_argv: argv.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classifies_pr_create() {
        let r = classify_gh_argv(&args(&["pr", "create", "--title", "x"]));
        assert_eq!(r.unwrap().action_key, "pr_create");
    }

    #[test]
    fn classifies_repo_delete() {
        let r = classify_gh_argv(&args(&["repo", "delete", "owner/repo"]));
        assert_eq!(r.unwrap().action_key, "repo_delete");
    }

    #[test]
    fn unknown_verb_returns_err() {
        assert!(matches!(
            classify_gh_argv(&args(&["unknown_verb", "foo"])),
            Err(ClassifyError::UnknownVerb(_))
        ));
    }

    #[test]
    fn empty_argv_returns_err() {
        assert!(matches!(
            classify_gh_argv(&[]),
            Err(ClassifyError::EmptyArgv)
        ));
    }
}
