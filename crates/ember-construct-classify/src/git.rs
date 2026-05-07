//! Argv classifier for `git`. Cohort A scope: credential-bearing verbs only
//! (push, fetch, clone). Other verbs (commit, status, diff) are local-only
//! and pass through unsupervised.

use core_construct_runtime::{ActionKey, ClassifyArgv};

#[derive(Debug, Default, Clone)]
pub struct GitClassifier;

impl ClassifyArgv for GitClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        let verb = argv.first()?.as_str();
        let key = match verb {
            "push" => "push",
            "fetch" => "fetch",
            "clone" => "clone",
            "commit" => "commit",
            _ => return None,
        };
        Some(ActionKey(format!("git.{key}")))
    }
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
        let c = GitClassifier;
        assert_eq!(
            c.classify(&argv(&["push", "origin", "main"])),
            Some(ActionKey("git.push".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["fetch", "--all"])),
            Some(ActionKey("git.fetch".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["clone", "https://github.com/foo/bar"])),
            Some(ActionKey("git.clone".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["commit", "-m", "msg"])),
            Some(ActionKey("git.commit".to_string()))
        );
    }

    #[test]
    fn unknown_verb_returns_none() {
        let c = GitClassifier;
        assert_eq!(c.classify(&argv(&["status"])), None);
        assert_eq!(c.classify(&argv(&["diff"])), None);
        assert_eq!(c.classify(&argv(&["log", "--oneline"])), None);
        assert_eq!(c.classify(&argv(&["checkout", "-b", "feature"])), None);
    }

    #[test]
    fn empty_argv_returns_none() {
        let c = GitClassifier;
        assert_eq!(c.classify(&[]), None);
    }
}
