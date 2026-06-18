//! Argv classifier: maps `kubectl <verb> [flags…]` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Returns `None` for read-only and context-switching verbs (passthrough — no broker
//! mediation). Returns `Some(ActionKey)` for anything gated.
//!
//! Critical distinctions:
//!   `get pods`                     → None (passthrough)
//!   `describe pod foo`             → None (passthrough)
//!   `logs -f deploy/api`           → None (passthrough)
//!   `apply -f file.yaml`           → kubectl.apply (biometric)
//!   `apply -k ./overlays/prod`     → kubectl.apply (biometric)
//!   `delete pod foo`               → kubectl.delete (biometric + budget 3/session)
//!   `exec pod -- cmd`              → kubectl.exec (biometric)
//!   `exec -it pod cmd`             → kubectl.exec (biometric)
//!   `rollout pause deploy/api`     → kubectl.rollout.pause (gated)
//!   `rollout resume deploy/api`    → kubectl.rollout.resume (gated)
//!   `rollout undo deploy/api`      → kubectl.rollout.undo (biometric)
//!   `rollout restart deploy/api`   → kubectl.rollout.restart (gated)
//!   `rollout status deploy/api`    → None (passthrough)
//!   `set image deploy/api c=img`   → kubectl.set.image (biometric)
//!   `set env deploy/api KEY=VAL`   → kubectl.set.env (biometric)
//!   `set resources deploy/api ...` → kubectl.set.resources (biometric)
//!   `set selector svc/foo ...`     → kubectl.set (biometric, generic fallback)
//!   `debug pod/foo --image=bar`    → kubectl.debug (biometric)
//!   `debug pod/foo --copy-to=bar`  → kubectl.debug (biometric)
//!   `config view`                  → None (passthrough)
//!   `config use-context staging`   → None (passthrough — local context switch)

use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};
use core_construct_runtime::{ActionKey, ClassifyArgv};

/// Struct wrapper for daemon-side classify calls (ADR 124 §3).
#[derive(Debug, Default, Clone)]
pub struct KubectlClassifier;

impl ClassifyArgv for KubectlClassifier {
    fn classify(&self, argv: &[String]) -> Option<ActionKey> {
        classify_kubectl_argv(argv)
    }
}

/// Classify `kubectl <verb> [flags…]` argv into an action_key.
///
/// `argv` is the slice AFTER the `kubectl` binary name (i.e. `argv[0]` is the
/// subcommand, including any global flags like `-n namespace`). Returns `None`
/// for passthrough (read-only / context switching).
pub fn classify_kubectl_argv(argv: &[String]) -> Option<ActionKey> {
    // Skip any leading global flags (e.g. `-n`, `--namespace`, `--context`, etc.)
    // to reach the actual verb. Global flags appear before the subcommand.
    let verb_idx = find_verb_index(argv)?;
    let verb = argv[verb_idx].as_str();
    let rest = &argv[verb_idx + 1..];

    match verb {
        // Read-only verbs — always passthrough.
        "get" | "describe" | "logs" | "top" | "cluster-info" | "version" | "api-resources"
        | "api-versions" | "explain" | "wait" | "events" => None,

        // auth subcommand — `auth can-i` is read-only; all auth subcommands are passthrough.
        "auth" => None,

        // config — view, current-context, get-contexts, use-context are passthrough.
        "config" => None,

        // help / completion — always passthrough.
        "help" | "completion" => None,

        // Verbs with multi-word patterns.
        "rollout" => classify_rollout(rest),
        "set" => classify_set(rest),

        // Node-state mutations.
        "cordon" => Some(ActionKey("kubectl.node.cordon".to_string())),
        "drain" => Some(ActionKey("kubectl.node.drain".to_string())),
        "uncordon" => Some(ActionKey("kubectl.node.uncordon".to_string())),
        "taint" => Some(ActionKey("kubectl.node.taint".to_string())),

        // Gated single-word verbs.
        "apply" => Some(ActionKey("kubectl.apply".to_string())),
        "delete" => Some(ActionKey("kubectl.delete".to_string())),
        "patch" => Some(ActionKey("kubectl.patch".to_string())),
        "edit" => Some(ActionKey("kubectl.edit".to_string())),
        "replace" => Some(ActionKey("kubectl.replace".to_string())),
        "exec" => Some(ActionKey("kubectl.exec".to_string())),
        "cp" => Some(ActionKey("kubectl.cp".to_string())),
        "port-forward" => Some(ActionKey("kubectl.port_forward".to_string())),
        "proxy" => Some(ActionKey("kubectl.proxy".to_string())),
        "scale" => Some(ActionKey("kubectl.scale".to_string())),
        "label" => Some(ActionKey("kubectl.label".to_string())),
        "annotate" => Some(ActionKey("kubectl.annotate".to_string())),
        "create" => Some(ActionKey("kubectl.create".to_string())),
        "run" => Some(ActionKey("kubectl.run".to_string())),
        "debug" => Some(ActionKey("kubectl.debug".to_string())),

        // Catch-all: unknown verbs are passthrough (daemon will re-classify).
        _ => None,
    }
}

/// Find the index of the first non-flag token in `argv` — that's the verb.
///
/// kubectl global flags appear before the verb:
///   `-n namespace`, `--namespace=foo`, `--context=prod`, `--kubeconfig=~/.kube/config`, etc.
/// We treat any token starting with `-` (and its value, if it's a separate token) as
/// a flag to skip. The first non-flag token is the subcommand/verb.
fn find_verb_index(argv: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < argv.len() {
        let token = argv[i].as_str();
        if token.starts_with('-') {
            // If the flag doesn't embed its value (e.g. `-n` not `--namespace=x`),
            // skip the next token as its value, but only for known value-taking flags.
            if needs_value_arg(token) {
                i += 2; // skip flag + value
            } else {
                i += 1; // skip flag (boolean or has =value embedded)
            }
        } else {
            return Some(i);
        }
    }
    None
}

/// Returns true for global kubectl flags that consume the next argv token as their value.
///
/// This is a conservative list. Unrecognized flags are treated as booleans
/// (skip 1 token). False negatives — skipping a value token that looks like a
/// verb — are acceptable because the daemon re-classifies server-side.
fn needs_value_arg(flag: &str) -> bool {
    matches!(
        flag,
        "-n" | "--namespace"
            | "--context"
            | "--cluster"
            | "--user"
            | "--kubeconfig"
            | "--server"
            | "--token"
            | "--as"
            | "--as-group"
            | "--as-uid"
            | "--certificate-authority"
            | "--client-certificate"
            | "--client-key"
            | "-l"
            | "--selector"
            | "--field-selector"
            | "--output"
            | "-o"
            | "--log-level"
            | "-v"
    )
}

/// `kubectl rollout <subverb>` — pause/resume/undo/restart gated; status passthrough.
fn classify_rollout(rest: &[String]) -> Option<ActionKey> {
    let subverb = rest.first()?.as_str();
    match subverb {
        "status" => None,
        "pause" => Some(ActionKey("kubectl.rollout.pause".to_string())),
        "resume" => Some(ActionKey("kubectl.rollout.resume".to_string())),
        "undo" => Some(ActionKey("kubectl.rollout.undo".to_string())),
        "restart" => Some(ActionKey("kubectl.rollout.restart".to_string())),
        // Unknown rollout subverb — default gate.
        _ => Some(ActionKey("kubectl.rollout.pause".to_string())),
    }
}

/// `kubectl set <subverb>` — image/env/resources have specific keys; others fall back to kubectl.set.
fn classify_set(rest: &[String]) -> Option<ActionKey> {
    let subverb = rest.first().map(|s| s.as_str()).unwrap_or("");
    match subverb {
        "image" => Some(ActionKey("kubectl.set.image".to_string())),
        "env" => Some(ActionKey("kubectl.set.env".to_string())),
        "resources" => Some(ActionKey("kubectl.set.resources".to_string())),
        // Any other subverb (selector, serviceaccount, subject) or bare `set` → generic gate.
        _ => Some(ActionKey("kubectl.set".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    fn key(strs: &[&str]) -> Option<String> {
        classify_kubectl_argv(&args(strs)).map(|k| k.0)
    }

    // --- read-only passthrough ---

    #[test]
    fn get_pods_is_passthrough() {
        assert_eq!(key(&["get", "pods"]), None);
    }

    #[test]
    fn get_pods_with_namespace_flag() {
        assert_eq!(key(&["-n", "production", "get", "pods"]), None);
    }

    #[test]
    fn describe_pod_is_passthrough() {
        assert_eq!(key(&["describe", "pod", "foo-abc"]), None);
    }

    #[test]
    fn logs_is_passthrough() {
        assert_eq!(key(&["logs", "-f", "deploy/api"]), None);
    }

    #[test]
    fn top_is_passthrough() {
        assert_eq!(key(&["top", "nodes"]), None);
    }

    #[test]
    fn cluster_info_is_passthrough() {
        assert_eq!(key(&["cluster-info"]), None);
    }

    #[test]
    fn version_is_passthrough() {
        assert_eq!(key(&["version"]), None);
    }

    #[test]
    fn api_resources_is_passthrough() {
        assert_eq!(key(&["api-resources"]), None);
    }

    #[test]
    fn api_versions_is_passthrough() {
        assert_eq!(key(&["api-versions"]), None);
    }

    #[test]
    fn explain_is_passthrough() {
        assert_eq!(key(&["explain", "pods"]), None);
    }

    #[test]
    fn wait_is_passthrough() {
        assert_eq!(key(&["wait", "--for=condition=ready", "pod/foo"]), None);
    }

    #[test]
    fn events_is_passthrough() {
        assert_eq!(key(&["events"]), None);
    }

    #[test]
    fn auth_can_i_is_passthrough() {
        assert_eq!(key(&["auth", "can-i", "list", "pods"]), None);
    }

    #[test]
    fn config_view_is_passthrough() {
        assert_eq!(key(&["config", "view"]), None);
    }

    #[test]
    fn config_use_context_is_passthrough() {
        assert_eq!(key(&["config", "use-context", "staging"]), None);
    }

    #[test]
    fn config_get_contexts_is_passthrough() {
        assert_eq!(key(&["config", "get-contexts"]), None);
    }

    #[test]
    fn help_is_passthrough() {
        assert_eq!(key(&["help"]), None);
    }

    #[test]
    fn completion_is_passthrough() {
        assert_eq!(key(&["completion", "bash"]), None);
    }

    // --- apply ---

    #[test]
    fn apply_file_is_gated() {
        assert_eq!(
            key(&["apply", "-f", "foo.yaml"]),
            Some("kubectl.apply".to_string())
        );
    }

    #[test]
    fn apply_kustomize_is_gated() {
        assert_eq!(
            key(&["apply", "-k", "./overlays/prod"]),
            Some("kubectl.apply".to_string())
        );
    }

    #[test]
    fn apply_with_namespace_prefix_flag() {
        assert_eq!(
            key(&["-n", "production", "apply", "-f", "deploy.yaml"]),
            Some("kubectl.apply".to_string())
        );
    }

    // --- delete ---

    #[test]
    fn delete_pod_is_gated() {
        assert_eq!(
            key(&["delete", "pod", "foo"]),
            Some("kubectl.delete".to_string())
        );
    }

    #[test]
    fn delete_pods_all_namespaces() {
        assert_eq!(
            key(&["delete", "pods", "--all-namespaces"]),
            Some("kubectl.delete".to_string())
        );
    }

    #[test]
    fn delete_deployment_is_gated() {
        assert_eq!(
            key(&["delete", "deployment", "api"]),
            Some("kubectl.delete".to_string())
        );
    }

    // --- patch ---

    #[test]
    fn patch_is_gated() {
        assert_eq!(
            key(&["patch", "deploy/api", "-p", r#"{"spec":{"replicas":3}}"#]),
            Some("kubectl.patch".to_string())
        );
    }

    // --- edit ---

    #[test]
    fn edit_is_gated() {
        assert_eq!(
            key(&["edit", "deploy", "api"]),
            Some("kubectl.edit".to_string())
        );
    }

    // --- replace ---

    #[test]
    fn replace_is_gated() {
        assert_eq!(
            key(&["replace", "-f", "file.yaml"]),
            Some("kubectl.replace".to_string())
        );
    }

    // --- exec — two forms ---

    #[test]
    fn exec_double_dash_form() {
        // kubectl exec <pod> -- <cmd>
        assert_eq!(
            key(&["exec", "mypod", "--", "bash"]),
            Some("kubectl.exec".to_string())
        );
    }

    #[test]
    fn exec_interactive_form() {
        // kubectl exec -it <pod> <cmd>  (no --)
        assert_eq!(
            key(&["exec", "-it", "mypod", "sh"]),
            Some("kubectl.exec".to_string())
        );
    }

    #[test]
    fn exec_with_namespace_prefix() {
        assert_eq!(
            key(&["-n", "prod", "exec", "mypod", "--", "env"]),
            Some("kubectl.exec".to_string())
        );
    }

    // --- cp ---

    #[test]
    fn cp_is_gated() {
        assert_eq!(
            key(&["cp", "foo.txt", "mypod:/tmp/"]),
            Some("kubectl.cp".to_string())
        );
    }

    // --- port-forward ---

    #[test]
    fn port_forward_is_gated() {
        assert_eq!(
            key(&["port-forward", "svc/api", "8080:80"]),
            Some("kubectl.port_forward".to_string())
        );
    }

    // --- proxy ---

    #[test]
    fn proxy_is_gated() {
        assert_eq!(key(&["proxy"]), Some("kubectl.proxy".to_string()));
    }

    // --- node state ---

    #[test]
    fn cordon_is_gated() {
        assert_eq!(
            key(&["cordon", "node01"]),
            Some("kubectl.node.cordon".to_string())
        );
    }

    #[test]
    fn drain_is_gated() {
        assert_eq!(
            key(&["drain", "node01", "--ignore-daemonsets"]),
            Some("kubectl.node.drain".to_string())
        );
    }

    #[test]
    fn uncordon_is_gated() {
        assert_eq!(
            key(&["uncordon", "node01"]),
            Some("kubectl.node.uncordon".to_string())
        );
    }

    #[test]
    fn taint_is_gated() {
        assert_eq!(
            key(&["taint", "node01", "key=val:NoSchedule"]),
            Some("kubectl.node.taint".to_string())
        );
    }

    // --- scale ---

    #[test]
    fn scale_is_gated() {
        assert_eq!(
            key(&["scale", "--replicas=3", "deploy/api"]),
            Some("kubectl.scale".to_string())
        );
    }

    // --- rollout ---

    #[test]
    fn rollout_status_is_passthrough() {
        assert_eq!(key(&["rollout", "status", "deploy/api"]), None);
    }

    #[test]
    fn rollout_pause_is_gated() {
        assert_eq!(
            key(&["rollout", "pause", "deploy/api"]),
            Some("kubectl.rollout.pause".to_string())
        );
    }

    #[test]
    fn rollout_resume_is_gated() {
        assert_eq!(
            key(&["rollout", "resume", "deploy/api"]),
            Some("kubectl.rollout.resume".to_string())
        );
    }

    #[test]
    fn rollout_undo_is_gated() {
        assert_eq!(
            key(&["rollout", "undo", "deploy/api"]),
            Some("kubectl.rollout.undo".to_string())
        );
    }

    #[test]
    fn rollout_restart_is_gated() {
        assert_eq!(
            key(&["rollout", "restart", "deploy/api"]),
            Some("kubectl.rollout.restart".to_string())
        );
    }

    // --- set ---

    #[test]
    fn set_image_is_gated() {
        assert_eq!(
            key(&["set", "image", "deploy/api", "api=myimage:v2"]),
            Some("kubectl.set.image".to_string())
        );
    }

    #[test]
    fn set_env_is_gated() {
        assert_eq!(
            key(&["set", "env", "deploy/api", "KEY=VALUE"]),
            Some("kubectl.set.env".to_string())
        );
    }

    #[test]
    fn set_resources_is_gated() {
        assert_eq!(
            key(&["set", "resources", "deploy/api", "--limits=cpu=200m"]),
            Some("kubectl.set.resources".to_string())
        );
    }

    #[test]
    fn set_no_subverb_is_gated_generic() {
        // bare `kubectl set` (unusual but possible) → generic fallback
        assert_eq!(key(&["set"]), Some("kubectl.set".to_string()));
    }

    #[test]
    fn set_selector_is_gated_generic() {
        // kubectl set selector svc/foo ...
        assert_eq!(
            key(&["set", "selector", "svc/foo", "app=myapp"]),
            Some("kubectl.set".to_string())
        );
    }

    // --- label / annotate ---

    #[test]
    fn label_is_gated() {
        assert_eq!(
            key(&["label", "pod/foo", "env=prod"]),
            Some("kubectl.label".to_string())
        );
    }

    #[test]
    fn annotate_is_gated() {
        assert_eq!(
            key(&["annotate", "pod/foo", "note=test"]),
            Some("kubectl.annotate".to_string())
        );
    }

    // --- create ---

    #[test]
    fn create_is_gated() {
        assert_eq!(
            key(&["create", "namespace", "staging"]),
            Some("kubectl.create".to_string())
        );
    }

    #[test]
    fn create_secret_is_gated() {
        assert_eq!(
            key(&[
                "create",
                "secret",
                "generic",
                "mysecret",
                "--from-literal=key=val"
            ]),
            Some("kubectl.create".to_string())
        );
    }

    // --- run ---

    #[test]
    fn run_create_pod_is_gated() {
        assert_eq!(
            key(&["run", "mypod", "--image=nginx"]),
            Some("kubectl.run".to_string())
        );
    }

    #[test]
    fn run_interactive_is_gated() {
        assert_eq!(
            key(&["run", "-i", "--tty", "debug", "--image=busybox"]),
            Some("kubectl.run".to_string())
        );
    }

    // --- debug ---

    #[test]
    fn debug_with_image_is_gated() {
        assert_eq!(
            key(&["debug", "--image=busybox", "pod/foo"]),
            Some("kubectl.debug".to_string())
        );
    }

    #[test]
    fn debug_copy_to_is_gated() {
        assert_eq!(
            key(&["debug", "pod/foo", "--copy-to=debug-pod"]),
            Some("kubectl.debug".to_string())
        );
    }

    // --- empty argv ---

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_kubectl_argv(&[]).is_none());
    }
}

// ---------------------------------------------------------------------------
// KubectlFactory — P24 construct-factory contract for the kubectl construct
// ---------------------------------------------------------------------------

static KUBECTL_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!(
            "../construct/kubectl.toml"
        ))
        .expect("bundled kubectl.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("kubectl.")?;
    KUBECTL_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key == format!("kubectl.{suffix}"))
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
    KUBECTL_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("kubectl.")
                .is_some_and(|suffix| a.key == format!("kubectl.{suffix}"))
    })
}

fn has_kubeconfig_flag(argv: &[String]) -> bool {
    argv.iter()
        .any(|tok| tok == "--kubeconfig" || tok.starts_with("--kubeconfig="))
}

#[derive(Debug, Default, Clone)]
pub struct KubectlFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubectlFactoryTarget {
    pub provider: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubectlFactoryNeed(pub Vec<String>);

impl InvocationGrammar for KubectlFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_kubectl_argv(argv)
    }
}

impl TargetExtractor for KubectlFactory {
    type Target = KubectlFactoryTarget;

    fn target_for_argv(&self, _action_key: &ActionKey, _argv: &[String]) -> Option<Self::Target> {
        None
    }
}

impl NeedTemplate for KubectlFactory {
    type Need = KubectlFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(KubectlFactoryNeed)
    }
}

impl ConstructFactory for KubectlFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        argv: &[String],
    ) -> FactoryDisposition {
        if has_kubeconfig_flag(argv) {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        if key.0 == "kubectl.apply" {
            return FactoryDisposition::PayloadAnalysisRequired;
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
    fn kubectl_factory_version_credentialless() {
        let f = KubectlFactory;
        let a = argv(&["version", "--client"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn kubectl_factory_apply_is_payload_analysis() {
        let f = KubectlFactory;
        let a = argv(&["apply", "-f", "deployment.yaml"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn kubectl_factory_delete_is_resolver_required() {
        let f = KubectlFactory;
        let a = argv(&["delete", "pod", "web"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn kubectl_factory_kubeconfig_fails_closed() {
        let f = KubectlFactory;
        let a = argv(&["--kubeconfig", "prod.kubeconfig", "delete", "pod", "web"]);
        let key = f.action_key_for_argv(&a);
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn kubectl_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/kubectl/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/kubectl.toml"),
        )
        .expect("kubectl manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &KubectlFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
