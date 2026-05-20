//! Argv classifier: maps `pulumi <verb> ...` to a `construct.toml` action_key.
//! Per design §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Coverage:
//!   - up                   → pulumi.up          (biometric=required)
//!   - render               → pulumi.render       (gated)
//!   - destroy              → pulumi.destroy      (biometric=required, budget 1/session)
//!   - refresh              → pulumi.refresh      (gated)
//!   - config set           → pulumi.config.set   (biometric=required; multi-word)
//!   - config rm            → pulumi.config.rm    (biometric=required; multi-word)
//!   - import               → pulumi.import       (biometric=required)
//!   - policy publish       → pulumi.policy.publish (gated; multi-word)
//!   - stack ls / preview / config get / about / version → None (passthrough)

use core_construct_runtime::ActionKey;

/// Classify `pulumi <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime treats
/// `None` as passthrough (no broker mediation).
pub fn classify_pulumi_argv(argv: &[String]) -> Option<ActionKey> {
    let verb = argv.first()?.as_str();

    match verb {
        // Read-only / informational → passthrough.
        "preview" | "about" | "version" => None,

        // stack subcommand: only `stack ls` (and variants) are passthrough;
        // other stack subcommands are gated by the daemon's re-classification.
        "stack" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("ls") | Some("list") | None => None,
                _ => None,
            }
        }

        // config subcommand — multi-word verbs.
        "config" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("set") => Some(ActionKey("pulumi.config.set".to_string())),
                Some("rm") | Some("remove") => Some(ActionKey("pulumi.config.rm".to_string())),
                // config get → passthrough (read-only).
                Some("get") | None => None,
                // Any other config sub → passthrough; daemon re-classifies.
                _ => None,
            }
        }

        // policy subcommand — multi-word verb.
        "policy" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("publish") => Some(ActionKey("pulumi.policy.publish".to_string())),
                _ => None,
            }
        }

        // Cluster-mutation verbs (biometric=required).
        "up" => Some(ActionKey("pulumi.up".to_string())),
        "import" => Some(ActionKey("pulumi.import".to_string())),

        // Destructive verbs (biometric=required, budget cap).
        "destroy" => Some(ActionKey("pulumi.destroy".to_string())),

        // State-mutation but not resource-mutation.
        "refresh" => Some(ActionKey("pulumi.refresh".to_string())),

        // GitOps YAML render (gated — design gitops lane).
        "render" => Some(ActionKey("pulumi.render".to_string())),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- gated verbs ---

    #[test]
    fn up_classified() {
        let r = classify_pulumi_argv(&args(&["up"])).unwrap();
        assert_eq!(r.0, "pulumi.up");
    }

    #[test]
    fn up_with_flags_classified() {
        let r = classify_pulumi_argv(&args(&["up", "--yes", "--stack", "dev"])).unwrap();
        assert_eq!(r.0, "pulumi.up");
    }

    #[test]
    fn destroy_classified() {
        let r = classify_pulumi_argv(&args(&["destroy"])).unwrap();
        assert_eq!(r.0, "pulumi.destroy");
    }

    #[test]
    fn destroy_with_flags_classified() {
        let r = classify_pulumi_argv(&args(&["destroy", "--yes"])).unwrap();
        assert_eq!(r.0, "pulumi.destroy");
    }

    #[test]
    fn refresh_classified() {
        let r = classify_pulumi_argv(&args(&["refresh"])).unwrap();
        assert_eq!(r.0, "pulumi.refresh");
    }

    #[test]
    fn render_classified() {
        let r = classify_pulumi_argv(&args(&["render"])).unwrap();
        assert_eq!(r.0, "pulumi.render");
    }

    #[test]
    fn import_classified() {
        let r = classify_pulumi_argv(&args(&[
            "import",
            "aws:s3/bucket:Bucket",
            "my-bucket",
            "my-bucket-id",
        ]))
        .unwrap();
        assert_eq!(r.0, "pulumi.import");
    }

    // --- multi-word verbs: config ---

    #[test]
    fn config_set_classified() {
        let r = classify_pulumi_argv(&args(&["config", "set", "myKey", "myVal"])).unwrap();
        assert_eq!(r.0, "pulumi.config.set");
    }

    #[test]
    fn config_rm_classified() {
        let r = classify_pulumi_argv(&args(&["config", "rm", "myKey"])).unwrap();
        assert_eq!(r.0, "pulumi.config.rm");
    }

    #[test]
    fn config_remove_alias_classified() {
        let r = classify_pulumi_argv(&args(&["config", "remove", "myKey"])).unwrap();
        assert_eq!(r.0, "pulumi.config.rm");
    }

    #[test]
    fn config_get_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["config", "get", "myKey"])).is_none(),
            "config get should passthrough"
        );
    }

    #[test]
    fn config_bare_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["config"])).is_none(),
            "bare config should passthrough"
        );
    }

    // --- multi-word verbs: policy ---

    #[test]
    fn policy_publish_classified() {
        let r = classify_pulumi_argv(&args(&["policy", "publish"])).unwrap();
        assert_eq!(r.0, "pulumi.policy.publish");
    }

    #[test]
    fn policy_other_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["policy", "ls"])).is_none(),
            "policy ls should passthrough"
        );
    }

    // --- passthrough verbs ---

    #[test]
    fn preview_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["preview"])).is_none(),
            "preview should passthrough"
        );
    }

    #[test]
    fn about_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["about"])).is_none(),
            "about should passthrough"
        );
    }

    #[test]
    fn version_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["version"])).is_none(),
            "version should passthrough"
        );
    }

    #[test]
    fn stack_ls_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["stack", "ls"])).is_none(),
            "stack ls should passthrough"
        );
    }

    #[test]
    fn stack_list_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["stack", "list"])).is_none(),
            "stack list should passthrough"
        );
    }

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_pulumi_argv(&[]).is_none());
    }

    #[test]
    fn unknown_verb_passthrough() {
        assert!(
            classify_pulumi_argv(&args(&["whoami"])).is_none(),
            "unknown verb should passthrough"
        );
    }
}
