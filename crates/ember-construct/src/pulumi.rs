//! Argv classifier: maps `pulumi <verb> ...` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
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
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

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

        // GitOps YAML render (gated — ADR 086 gitops lane).
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

// ---------------------------------------------------------------------------
// PulumiFactory — P24 construct-factory contract for the pulumi construct
// ---------------------------------------------------------------------------

static PULUMI_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/pulumi.toml"))
            .expect("bundled pulumi.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("pulumi.")?;
    PULUMI_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key == format!("pulumi.{suffix}"))
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

fn action_in_manifest(action_key: &str) -> bool {
    PULUMI_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("pulumi.")
                .is_some_and(|suffix| a.key == format!("pulumi.{suffix}"))
    })
}

/// Extended factory classifier that supplements the legacy classifier with
/// verbs the legacy path doesn't classify (login, stack rm/remove).
fn classify_pulumi_factory_argv(argv: &[String]) -> Option<ActionKey> {
    if let Some(key) = classify_pulumi_argv(argv) {
        return Some(key);
    }
    let verb = argv.first()?.as_str();
    match verb {
        "login" => Some(ActionKey("pulumi.login".to_string())),
        "stack" => {
            let sub = argv.get(1).map(|s| s.as_str());
            match sub {
                Some("rm") | Some("remove") => Some(ActionKey("pulumi.stack.rm".to_string())),
                _ => None,
            }
        }
        _ => None,
    }
}

#[derive(Debug, Default, Clone)]
pub struct PulumiFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulumiFactoryTarget {
    pub provider: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulumiFactoryNeed(pub Vec<String>);

impl InvocationGrammar for PulumiFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_pulumi_factory_argv(argv)
    }
}

impl TargetExtractor for PulumiFactory {
    type Target = PulumiFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, _argv: &[String]) -> Option<Self::Target> {
        None
    }
}

impl NeedTemplate for PulumiFactory {
    type Need = PulumiFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(PulumiFactoryNeed)
    }
}

impl ConstructFactory for PulumiFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            // No classified action — but check raw argv for `login` since
            // the runtime path uses the legacy classifier which doesn't
            // classify it.
            let verb = argv.first().map(|s| s.as_str());
            if verb == Some("login") {
                return FactoryDisposition::UnsupportedFailClosed;
            }
            return FactoryDisposition::Credentialless;
        };

        if key.0 == "pulumi.up" || key.0 == "pulumi.destroy" {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        if key.0 == "pulumi.login" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        if action_in_manifest(&key.0) {
            return FactoryDisposition::ResolverRequired;
        }

        FactoryDisposition::ResolverRequired
    }
}

#[cfg(test)]
mod factory_tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pulumi_factory_version_credentialless() {
        let f = PulumiFactory;
        let a = argv(&["version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn pulumi_factory_up_is_payload_analysis() {
        let f = PulumiFactory;
        let a = argv(&["up", "--yes"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn pulumi_factory_destroy_is_payload_analysis() {
        let f = PulumiFactory;
        let a = argv(&["destroy", "--yes"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn pulumi_factory_stack_rm_is_resolver_required() {
        let f = PulumiFactory;
        let a = argv(&["stack", "rm", "prod"]);
        let key = f.action_key_for_argv(&a).expect("classified by factory");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn pulumi_factory_login_fails_closed() {
        let f = PulumiFactory;
        let a = argv(&["login", "s3://state-bucket"]);
        let key = f.action_key_for_argv(&a).expect("classified by factory");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn pulumi_factory_login_fails_closed_via_legacy_path() {
        let f = PulumiFactory;
        let a = argv(&["login", "s3://state-bucket"]);
        // Simulate the runtime path: legacy classifier returns None for login
        let legacy_key = classify_pulumi_argv(&a);
        assert!(
            legacy_key.is_none(),
            "legacy classifier should not classify login"
        );
        assert_eq!(
            f.disposition_for_argv(legacy_key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn pulumi_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/pulumi/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/pulumi.toml"),
        )
        .expect("pulumi manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &PulumiFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
