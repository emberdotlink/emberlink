//! Argv classifier: maps `terraform <verb> [<sub> ...]` to a `construct.toml`
//! action_key. Per ADR 124 §3 — this lives shim-side BUT the daemon
//! re-classifies the argv server-side (untrusts the shim).
//!
//! Terraform CLI argv shape:
//!
//! ```text
//! terraform [global-flags...] <verb> [<sub> ...] [verb-args...]
//! ```
//!
//! Global flags (`-chdir=<dir>`, `-help`, `-version`, `-json`) are stripped
//! before pattern-matching, so classification is stable under flag
//! reordering. Note: Terraform uses *single*-dash long-flags (the convention
//! OpenTofu inherited), not the GNU double-dash convention.
//!
//! Coverage (mutating verbs are gated; read-only verbs passthrough as `None`):
//!
//! | argv prefix                          | action_key                            |
//! |--------------------------------------|---------------------------------------|
//! | `apply`                              | `terraform.apply`                     |
//! | `destroy`                            | `terraform.destroy` (biometric)       |
//! | `import`                             | `terraform.import`                    |
//! | `taint` / `untaint`                  | `terraform.taint` / `terraform.untaint` |
//! | `state rm`                           | `terraform.state.rm` (biometric)      |
//! | `state mv`                           | `terraform.state.mv`                  |
//! | `state replace-provider`             | `terraform.state.replace-provider` (biometric) |
//! | `state push`                         | `terraform.state.push` (biometric)    |
//! | `workspace new`                      | `terraform.workspace.new`             |
//! | `workspace select`                   | `terraform.workspace.select`          |
//! | `workspace delete`                   | `terraform.workspace.delete` (biometric) |
//! | `refresh`                            | `terraform.refresh`                   |
//! | `force-unlock`                       | `terraform.force-unlock` (biometric)  |
//! | read-only (`plan`, `validate`, `show`, `state list`, `state show`, `output`, `version`, `providers`, `init`, `fmt`, `console`) | `None` (passthrough) |

use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

/// Terraform global flags that take a value as the *next* argv token (when
/// written as `-flag value`). The `-chdir=<dir>` form (and any future
/// `-flag=value` form) is handled by the equals-form branch below.
const VALUE_BEARING_GLOBAL_FLAGS: &[&str] = &["-chdir"];

/// Terraform global flags that are valueless (boolean toggles).
const BOOLEAN_GLOBAL_FLAGS: &[&str] = &["-help", "-h", "-version", "-v", "-json"];

/// Strip global flags (and their values, where applicable) from `argv`.
///
/// Recognizes both `-flag value` and `-flag=value` forms for the
/// value-bearing flags, plus the boolean toggles in
/// [`BOOLEAN_GLOBAL_FLAGS`]. Non-flag tokens and unknown flags pass
/// through unchanged (the daemon re-classifies anyway).
pub(crate) fn strip_global_flags(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];

        // `-flag=value` form — drop in one step regardless of whether
        // it's a value-bearing or boolean global flag (boolean flags
        // shouldn't have `=value` but accept it tolerantly).
        if let Some(eq) = tok.find('=') {
            let name = &tok[..eq];
            if VALUE_BEARING_GLOBAL_FLAGS.contains(&name) || BOOLEAN_GLOBAL_FLAGS.contains(&name) {
                i += 1;
                continue;
            }
        }

        // `-flag value` form for value-bearing globals.
        if VALUE_BEARING_GLOBAL_FLAGS.contains(&tok.as_str()) {
            i += 1;
            if i < argv.len() {
                i += 1;
            }
            continue;
        }

        // Boolean global flags — skip just the flag itself.
        if BOOLEAN_GLOBAL_FLAGS.contains(&tok.as_str()) {
            i += 1;
            continue;
        }

        out.push(tok.clone());
        i += 1;
    }
    out
}

/// Returns `true` if `verb` is a top-level read-only Terraform verb.
fn is_read_only_top_verb(verb: &str) -> bool {
    matches!(
        verb,
        "plan"
            | "validate"
            | "show"
            | "output"
            | "version"
            | "providers"
            | "init"
            | "fmt"
            | "console"
            | "help"
            | "graph"
            | "get"
            | "login"
            | "logout"
            | "test"
    )
}

/// Classify `terraform <verb> [<sub> ...]` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime
/// treats `None` as passthrough (no broker mediation).
pub fn classify_terraform_argv(argv: &[String]) -> Option<ActionKey> {
    let stripped = strip_global_flags(argv);

    let verb = stripped.first()?.as_str();

    // Top-level read-only verbs always passthrough.
    if is_read_only_top_verb(verb) {
        return None;
    }

    match verb {
        // Top-level mutating verbs.
        "apply" => Some(ActionKey("terraform.apply".to_string())),
        "destroy" => Some(ActionKey("terraform.destroy".to_string())),
        "import" => Some(ActionKey("terraform.import".to_string())),
        "taint" => Some(ActionKey("terraform.taint".to_string())),
        "untaint" => Some(ActionKey("terraform.untaint".to_string())),
        "refresh" => Some(ActionKey("terraform.refresh".to_string())),
        "force-unlock" => Some(ActionKey("terraform.force-unlock".to_string())),

        // `state <sub>` — 3-level prefix. `state list` and `state show` are
        // read-only and passthrough; mutating sub-verbs are classified.
        "state" => {
            let sub = stripped.get(1).map(|s| s.as_str())?;
            match sub {
                "list" | "show" | "pull" => None,
                "rm" => Some(ActionKey("terraform.state.rm".to_string())),
                "mv" => Some(ActionKey("terraform.state.mv".to_string())),
                "replace-provider" => {
                    Some(ActionKey("terraform.state.replace-provider".to_string()))
                }
                "push" => Some(ActionKey("terraform.state.push".to_string())),
                _ => None,
            }
        }

        // `workspace <sub>` — 3-level prefix. `workspace list` / `show` /
        // `default` are read-only and passthrough.
        "workspace" => {
            let sub = stripped.get(1).map(|s| s.as_str())?;
            match sub {
                "list" | "show" | "default" => None,
                "new" => Some(ActionKey("terraform.workspace.new".to_string())),
                "select" => Some(ActionKey("terraform.workspace.select".to_string())),
                "delete" => Some(ActionKey("terraform.workspace.delete".to_string())),
                _ => None,
            }
        }

        // Unknown top-level verb → passthrough; daemon re-classifies.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // --- top-level mutating verbs ---

    #[test]
    fn apply_classified() {
        let r = classify_terraform_argv(&args(&["apply"])).unwrap();
        assert_eq!(r.0, "terraform.apply");
    }

    #[test]
    fn apply_with_flags_classified() {
        let r = classify_terraform_argv(&args(&["apply", "-auto-approve"])).unwrap();
        assert_eq!(r.0, "terraform.apply");
    }

    #[test]
    fn destroy_classified() {
        let r = classify_terraform_argv(&args(&["destroy"])).unwrap();
        assert_eq!(r.0, "terraform.destroy");
    }

    #[test]
    fn destroy_with_flags_classified() {
        let r = classify_terraform_argv(&args(&["destroy", "-auto-approve"])).unwrap();
        assert_eq!(r.0, "terraform.destroy");
    }

    #[test]
    fn import_classified() {
        let r =
            classify_terraform_argv(&args(&["import", "aws_s3_bucket.b", "my-bucket"])).unwrap();
        assert_eq!(r.0, "terraform.import");
    }

    #[test]
    fn taint_classified() {
        let r = classify_terraform_argv(&args(&["taint", "aws_instance.foo"])).unwrap();
        assert_eq!(r.0, "terraform.taint");
    }

    #[test]
    fn untaint_classified() {
        let r = classify_terraform_argv(&args(&["untaint", "aws_instance.foo"])).unwrap();
        assert_eq!(r.0, "terraform.untaint");
    }

    #[test]
    fn refresh_classified() {
        let r = classify_terraform_argv(&args(&["refresh"])).unwrap();
        assert_eq!(r.0, "terraform.refresh");
    }

    #[test]
    fn force_unlock_classified() {
        let r = classify_terraform_argv(&args(&["force-unlock", "lock-id"])).unwrap();
        assert_eq!(r.0, "terraform.force-unlock");
    }

    // --- state <sub> (3-level prefix) ---

    #[test]
    fn state_rm_classified() {
        let r = classify_terraform_argv(&args(&["state", "rm", "aws_instance.foo"])).unwrap();
        assert_eq!(r.0, "terraform.state.rm");
    }

    #[test]
    fn state_mv_classified() {
        let r =
            classify_terraform_argv(&args(&["state", "mv", "aws_instance.a", "aws_instance.b"]))
                .unwrap();
        assert_eq!(r.0, "terraform.state.mv");
    }

    #[test]
    fn state_replace_provider_classified() {
        let r = classify_terraform_argv(&args(&[
            "state",
            "replace-provider",
            "registry.terraform.io/-/aws",
            "registry.opentofu.org/-/aws",
        ]))
        .unwrap();
        assert_eq!(r.0, "terraform.state.replace-provider");
    }

    #[test]
    fn state_push_classified() {
        let r = classify_terraform_argv(&args(&["state", "push", "tfstate.backup"])).unwrap();
        assert_eq!(r.0, "terraform.state.push");
    }

    #[test]
    fn state_list_passthrough() {
        assert!(classify_terraform_argv(&args(&["state", "list"])).is_none());
    }

    #[test]
    fn state_show_passthrough() {
        assert!(classify_terraform_argv(&args(&["state", "show", "aws_instance.foo"])).is_none());
    }

    #[test]
    fn state_pull_passthrough() {
        // `state pull` reads remote state to stdout — read-only.
        assert!(classify_terraform_argv(&args(&["state", "pull"])).is_none());
    }

    #[test]
    fn state_bare_passthrough() {
        // bare `state` (no sub) → passthrough.
        assert!(classify_terraform_argv(&args(&["state"])).is_none());
    }

    #[test]
    fn state_unknown_sub_passthrough() {
        assert!(classify_terraform_argv(&args(&["state", "nonsense"])).is_none());
    }

    // --- workspace <sub> ---

    #[test]
    fn workspace_new_classified() {
        let r = classify_terraform_argv(&args(&["workspace", "new", "dev"])).unwrap();
        assert_eq!(r.0, "terraform.workspace.new");
    }

    #[test]
    fn workspace_select_classified() {
        let r = classify_terraform_argv(&args(&["workspace", "select", "dev"])).unwrap();
        assert_eq!(r.0, "terraform.workspace.select");
    }

    #[test]
    fn workspace_delete_classified() {
        let r = classify_terraform_argv(&args(&["workspace", "delete", "dev"])).unwrap();
        assert_eq!(r.0, "terraform.workspace.delete");
    }

    #[test]
    fn workspace_list_passthrough() {
        assert!(classify_terraform_argv(&args(&["workspace", "list"])).is_none());
    }

    #[test]
    fn workspace_show_passthrough() {
        assert!(classify_terraform_argv(&args(&["workspace", "show"])).is_none());
    }

    // --- read-only top-level verbs ---

    #[test]
    fn plan_passthrough() {
        assert!(classify_terraform_argv(&args(&["plan"])).is_none());
    }

    #[test]
    fn validate_passthrough() {
        assert!(classify_terraform_argv(&args(&["validate"])).is_none());
    }

    #[test]
    fn show_passthrough() {
        assert!(classify_terraform_argv(&args(&["show"])).is_none());
    }

    #[test]
    fn output_passthrough() {
        assert!(classify_terraform_argv(&args(&["output"])).is_none());
    }

    #[test]
    fn version_passthrough() {
        assert!(classify_terraform_argv(&args(&["version"])).is_none());
    }

    #[test]
    fn providers_passthrough() {
        assert!(classify_terraform_argv(&args(&["providers"])).is_none());
    }

    #[test]
    fn init_passthrough() {
        assert!(classify_terraform_argv(&args(&["init"])).is_none());
    }

    #[test]
    fn fmt_passthrough() {
        assert!(classify_terraform_argv(&args(&["fmt"])).is_none());
    }

    #[test]
    fn console_passthrough() {
        assert!(classify_terraform_argv(&args(&["console"])).is_none());
    }

    // --- global flag stripping (-chdir= and friends) ---

    #[test]
    fn chdir_equals_form_stripped() {
        let r = classify_terraform_argv(&args(&["-chdir=infra/prod", "destroy"])).unwrap();
        assert_eq!(r.0, "terraform.destroy");
    }

    #[test]
    fn chdir_value_form_stripped() {
        // `-chdir <dir>` (space-separated) — also stripped (both flag
        // and value).
        let r = classify_terraform_argv(&args(&["-chdir", "infra/prod", "apply"])).unwrap();
        assert_eq!(r.0, "terraform.apply");
    }

    #[test]
    fn json_flag_stripped() {
        let r = classify_terraform_argv(&args(&["-json", "apply"])).unwrap();
        assert_eq!(r.0, "terraform.apply");
    }

    #[test]
    fn help_flag_stripped() {
        // `-help` before a verb is unusual but tolerated; classification
        // should land on the verb after stripping.
        let r = classify_terraform_argv(&args(&["-help", "destroy"])).unwrap();
        assert_eq!(r.0, "terraform.destroy");
    }

    #[test]
    fn version_flag_only_passthrough() {
        // `-version` alone → no verb → passthrough.
        assert!(classify_terraform_argv(&args(&["-version"])).is_none());
    }

    #[test]
    fn chdir_then_state_rm_classified() {
        // `-chdir=` followed by 3-level state verb — composite.
        let r = classify_terraform_argv(&args(&[
            "-chdir=infra/prod",
            "state",
            "rm",
            "aws_instance.foo",
        ]))
        .unwrap();
        assert_eq!(r.0, "terraform.state.rm");
    }

    #[test]
    fn multiple_globals_stripped() {
        let r = classify_terraform_argv(&args(&[
            "-chdir=infra/prod",
            "-json",
            "workspace",
            "delete",
            "dev",
        ]))
        .unwrap();
        assert_eq!(r.0, "terraform.workspace.delete");
    }

    // --- unknown / empty / corner cases ---

    #[test]
    fn empty_argv_passthrough() {
        assert!(classify_terraform_argv(&[]).is_none());
    }

    #[test]
    fn only_global_flags_passthrough() {
        assert!(
            classify_terraform_argv(&args(&["-chdir=foo", "-json"])).is_none(),
            "globals only → no verb → passthrough"
        );
    }

    #[test]
    fn unknown_top_verb_passthrough() {
        assert!(classify_terraform_argv(&args(&["whoami"])).is_none());
    }

    // --- proptest: argv fuzzer; no panics; passthrough is a fixed point ---

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            ..proptest::test_runner::Config::default()
        })]

        /// Fuzz arbitrary argv shapes — must never panic.
        #[test]
        fn fuzz_classify_no_panic(
            argv in proptest::collection::vec("[a-zA-Z0-9_:.-]{0,16}", 0..8usize)
        ) {
            // We only care that no panic escapes.
            let _ = classify_terraform_argv(&argv);
        }

        /// Inserting a `-chdir=<dir>` global flag at the front of a known
        /// classified argv must not change the classification.
        #[test]
        fn fuzz_chdir_flag_insertion_stable(
            dir in "[a-z][a-z0-9/_-]{0,15}"
        ) {
            let base = vec![
                "destroy".to_string(),
            ];
            let base_class = classify_terraform_argv(&base).unwrap();

            let mut with_flag = base.clone();
            with_flag.insert(0, format!("-chdir={dir}"));

            let class2 = classify_terraform_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }

        /// Inserting a boolean global flag (`-json`) at any position into a
        /// known classified argv must not change the classification.
        #[test]
        fn fuzz_boolean_flag_insertion_stable(insert_at in 0usize..4) {
            let base = vec![
                "state".to_string(),
                "rm".to_string(),
                "aws_instance.foo".to_string(),
            ];
            let base_class = classify_terraform_argv(&base).unwrap();

            let mut with_flag = base.clone();
            let pos = insert_at.min(with_flag.len());
            with_flag.insert(pos, "-json".to_string());

            let class2 = classify_terraform_argv(&with_flag).unwrap();
            proptest::prop_assert_eq!(base_class.0, class2.0);
        }
    }
}

// ---------------------------------------------------------------------------
// TerraformFactory — P24 construct-factory contract for the terraform construct
// ---------------------------------------------------------------------------

static TERRAFORM_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!(
            "../construct/terraform.toml"
        ))
        .expect("bundled terraform.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("terraform.")?;
    TERRAFORM_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key == format!("terraform.{suffix}"))
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
    TERRAFORM_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("terraform.")
                .is_some_and(|suffix| a.key == format!("terraform.{suffix}"))
    })
}

const UNSUPPORTED_KEYS: &[&str] = &[
    "terraform.state.push",
    "terraform.state.rm",
    "terraform.state.replace-provider",
    "terraform.force-unlock",
];

#[derive(Debug, Default, Clone)]
pub struct TerraformFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerraformFactoryTarget {
    pub provider: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerraformFactoryNeed(pub Vec<String>);

impl InvocationGrammar for TerraformFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_terraform_argv(argv)
    }
}

impl TargetExtractor for TerraformFactory {
    type Target = TerraformFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, _argv: &[String]) -> Option<Self::Target> {
        None
    }
}

impl NeedTemplate for TerraformFactory {
    type Need = TerraformFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(TerraformFactoryNeed)
    }
}

impl ConstructFactory for TerraformFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        _argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        if key.0 == "terraform.apply" || key.0 == "terraform.destroy" {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        if UNSUPPORTED_KEYS.iter().any(|k| key.0 == *k) {
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
    fn terraform_factory_version_credentialless() {
        let f = TerraformFactory;
        let a = argv(&["version"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn terraform_factory_apply_is_payload_analysis() {
        let f = TerraformFactory;
        let a = argv(&["apply", "-auto-approve"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn terraform_factory_destroy_is_payload_analysis() {
        let f = TerraformFactory;
        let a = argv(&["destroy", "-auto-approve"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn terraform_factory_workspace_delete_is_resolver_required() {
        let f = TerraformFactory;
        let a = argv(&["workspace", "delete", "prod"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn terraform_factory_state_push_fails_closed() {
        let f = TerraformFactory;
        let a = argv(&["state", "push", "terraform.tfstate"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn terraform_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/terraform/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/terraform.toml"),
        )
        .expect("terraform manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &TerraformFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
