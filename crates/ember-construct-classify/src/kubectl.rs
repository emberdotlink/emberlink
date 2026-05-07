//! Argv classifier for `kubectl`. Cohort A scope: apply, delete, get.

use core_construct_runtime::{ActionKey, ClassifyArgv};

#[derive(Debug, Default, Clone)]
pub struct KubectlClassifier;

impl ClassifyArgv for KubectlClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        let verb = argv.first()?.as_str();
        let key = match verb {
            "apply" => "apply",
            "delete" => "delete",
            "get" => "get",
            _ => return None,
        };
        Some(ActionKey(format!("kubectl.{key}")))
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
        let c = KubectlClassifier;
        assert_eq!(
            c.classify(&argv(&["apply", "-f", "deployment.yaml"])),
            Some(ActionKey("kubectl.apply".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["delete", "pod", "mypod"])),
            Some(ActionKey("kubectl.delete".to_string()))
        );
        assert_eq!(
            c.classify(&argv(&["get", "pods", "-n", "default"])),
            Some(ActionKey("kubectl.get".to_string()))
        );
    }

    #[test]
    fn unknown_verb_returns_none() {
        let c = KubectlClassifier;
        assert_eq!(c.classify(&argv(&["describe", "pod", "mypod"])), None);
        assert_eq!(c.classify(&argv(&["logs", "mypod"])), None);
        assert_eq!(c.classify(&argv(&["exec", "-it", "mypod", "--", "sh"])), None);
    }

    #[test]
    fn empty_argv_returns_none() {
        let c = KubectlClassifier;
        assert_eq!(c.classify(&[]), None);
    }
}
