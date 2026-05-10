//! Argv classifier for `gh`. Action keys mirror the cohort-A construct.toml
//! (pr_create, pr_merge, repo_delete, auth_login, workflow_run, ...). Daemon
//! server-side re-classifies on broker.exec; this impl is shim-side only.

use core_construct_runtime::{ActionKey, ClassifyArgv};

#[derive(Debug, Default, Clone)]
pub struct GhClassifier;

impl ClassifyArgv for GhClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        classify_gh_argv(argv)
    }
}

/// Free-function entry point for the `VendorManifest` classifier field.
pub fn classify_gh_argv(argv: &[String]) -> Option<ActionKey> {
    if argv.is_empty() {
        return None;
    }
    let verb = argv[0].as_str();
    let subverb = argv.get(1).map(String::as_str);
    let key = match (verb, subverb) {
        ("pr", Some("create")) => "pr_create",
        ("pr", Some("merge")) => "pr_merge",
        ("pr", Some("close")) => "pr_close",
        ("pr", Some("comment")) => "pr_comment",
        ("pr", Some("list")) => "pr_list",
        ("pr", Some("view")) => "pr_view",
        ("pr", Some("edit")) => "pr_edit",
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
        ("release", Some("create")) => "release_create",
        _ => return None,
    };
    Some(ActionKey(format!("gh.{key}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_construct_runtime::ClassifyArgv;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classifies_known_verb() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["pr", "create"])),
            Some(ActionKey("gh.pr_create".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["pr", "merge", "--squash"])),
            Some(ActionKey("gh.pr_merge".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["repo", "delete", "myrepo"])),
            Some(ActionKey("gh.repo_delete".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["auth", "login"])),
            Some(ActionKey("gh.auth_login".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["workflow", "run", "ci.yml"])),
            Some(ActionKey("gh.workflow_run".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["issue", "list"])),
            Some(ActionKey("gh.issue_list".to_string()))
        );
    }

    #[test]
    fn classifies_pr_edit() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["pr", "edit", "42", "--title", "New title"])),
            Some(ActionKey("gh.pr_edit".to_string()))
        );
    }

    #[test]
    fn classifies_release_create() {
        let c = GhClassifier;
        assert_eq!(
            c.classify(&argv(&["release", "create", "v1.2.3", "--title", "v1.2.3"])),
            Some(ActionKey("gh.release_create".to_string()))
        );
    }

    #[test]
    fn unknown_verb_returns_none() {
        let c = GhClassifier;
        assert_eq!(c.classify(&argv(&["secret", "set"])), None);
        assert_eq!(c.classify(&argv(&["pr", "unknown"])), None);
        assert_eq!(c.classify(&argv(&["unknown"])), None);
    }

    #[test]
    fn empty_argv_returns_none() {
        let c = GhClassifier;
        assert_eq!(c.classify(&[]), None);
    }
}
