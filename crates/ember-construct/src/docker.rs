//! Argv classifier: maps `docker <verb> ...` to a `construct.toml` action_key.
//! Per ADR 124 §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Coverage:
//!   - `push <host/repo:tag>`  → `docker.push.<registry-host>`
//!   - `login [host]`          → `docker.login.<host-or-default>`
//!   - `logout [host]`         → `docker.logout.<host-or-default>`
//!   - run [...]             → docker.run, OR docker.run.privileged when
//!     --privileged / --pid=host / --network=host / --volume /:... is
//!     present (default = deny in construct.toml so the broker refuses).
//!   - build / exec / cp     → `docker.<verb>`
//!   - stop / start / kill / rm / rmi / pull / tag → `docker.<verb>`
//!   - ps / images / inspect / logs / stats → None (passthrough — read-only)
//!   - anything else         → None (passthrough)
//!
use core_construct_runtime::ActionKey;
use core_construct_runtime::factory::{
    ConstructFactory, FactoryDisposition, InvocationGrammar, NeedTemplate, TargetExtractor,
};

const DEFAULT_REGISTRY: &str = "dockerhub";

/// Classify `docker <verb> ...` argv into an action_key.
///
/// Returns `None` for read-only / unrecognized shapes — the runtime treats
/// `None` as passthrough (no broker mediation).
pub fn classify_docker_argv(argv: &[String]) -> Option<ActionKey> {
    let verb = argv.first()?.as_str();

    match verb {
        // Reads → passthrough. Daemon re-classifies; runtime spawns docker
        // directly without minting credentials.
        "ps" | "images" | "inspect" | "logs" | "stats" => None,

        "push" => {
            let target = argv.iter().skip(1).find(|a| !a.starts_with('-'))?;
            let host = extract_registry_host(target);
            Some(ActionKey(format!("docker.push.{host}")))
        }

        "login" => {
            let host = argv
                .iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .map(|s| s.as_str())
                .unwrap_or(DEFAULT_REGISTRY);
            Some(ActionKey(format!("docker.login.{host}")))
        }

        "logout" => {
            let host = argv
                .iter()
                .skip(1)
                .find(|a| !a.starts_with('-'))
                .map(|s| s.as_str())
                .unwrap_or(DEFAULT_REGISTRY);
            Some(ActionKey(format!("docker.logout.{host}")))
        }

        "run" => {
            if has_privileged_flag(&argv[1..]) {
                Some(ActionKey("docker.run.privileged".to_string()))
            } else {
                Some(ActionKey("docker.run".to_string()))
            }
        }

        "build" => Some(ActionKey("docker.build".to_string())),
        "exec" => Some(ActionKey("docker.exec".to_string())),
        "cp" => Some(ActionKey("docker.cp".to_string())),

        // Container lifecycle (cleanup verbs — previously uncovered, H2 gap).
        "stop" => Some(ActionKey("docker.stop".to_string())),
        "start" => Some(ActionKey("docker.start".to_string())),
        "kill" => Some(ActionKey("docker.kill".to_string())),
        "rm" => Some(ActionKey("docker.rm".to_string())),
        "rmi" => Some(ActionKey("docker.rmi".to_string())),

        // Image management.
        "pull" => Some(ActionKey("docker.pull".to_string())),
        "tag" => Some(ActionKey("docker.tag".to_string())),

        _ => None,
    }
}

/// Extract the registry host from a docker image reference.
///
/// Per the docker reference grammar, an image reference takes the shape
/// `[<host>[:<port>]/]<path>[:<tag>][@<digest>]`. The leading slash-segment is
/// only treated as a host if it contains `.`, `:`, or is literally `localhost`
/// — otherwise it's a Docker Hub user namespace and the registry is the
/// default Hub.
fn extract_registry_host(image: &str) -> String {
    let (head, _rest) = image.split_once('/').unwrap_or(("", image));

    if head.is_empty() {
        return DEFAULT_REGISTRY.to_string();
    }

    if head == "localhost" || head.contains('.') || head.contains(':') {
        head.to_string()
    } else {
        DEFAULT_REGISTRY.to_string()
    }
}

/// Returns true if any of the argv tokens trigger the privileged refuse-path:
///   --privileged, --pid=host, --network=host, --volume /:..., -v /:...
fn has_privileged_flag(args: &[String]) -> bool {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == "--privileged" {
            return true;
        }
        if a == "--pid=host" || a == "--network=host" || a == "--net=host" {
            return true;
        }
        if (a == "--pid" || a == "--network" || a == "--net")
            && iter.clone().next().map(|s| s.as_str()) == Some("host")
        {
            return true;
        }
        if let Some(spec) = a
            .strip_prefix("--volume=")
            .or_else(|| a.strip_prefix("-v="))
            && mounts_root(spec)
        {
            return true;
        }
        if (a == "--volume" || a == "-v" || a == "--mount")
            && let Some(spec) = iter.clone().next()
            && mounts_root(spec)
        {
            return true;
        }
        if let Some(spec) = a.strip_prefix("--mount=")
            && mounts_root(spec)
        {
            return true;
        }
    }
    false
}

/// Detect bind-mounts whose source is the host root `/`.
///
/// Matches `-v /:...`, `--volume /:/host`, and `--mount type=bind,source=/,...`.
fn mounts_root(spec: &str) -> bool {
    if spec.starts_with("/:") || spec == "/" {
        return true;
    }
    // --mount key=value form
    for part in spec.split(',') {
        let (k, v) = match part.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if (k == "source" || k == "src") && (v == "/" || v.starts_with("/:")) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// DockerFactory — P24 construct-factory contract for the docker construct
// ---------------------------------------------------------------------------

static DOCKER_MANIFEST: std::sync::LazyLock<core_events::construct_toml::ParsedActionManifest> =
    std::sync::LazyLock::new(|| {
        core_events::construct_toml::parse_action_manifest(include_str!("../construct/docker.toml"))
            .expect("bundled docker.toml must be valid")
    });

fn manifest_need_for_action(action_key: &str) -> Option<Vec<String>> {
    let suffix = action_key.strip_prefix("docker.")?;
    DOCKER_MANIFEST
        .manifest
        .actions
        .iter()
        .find(|a| a.key == action_key || a.key.strip_prefix("docker.").is_some_and(|k| k == suffix))
        .and_then(|a| {
            let need = &a.need;
            if need.is_empty() {
                None
            } else {
                Some(need.clone())
            }
        })
}

// retained for parity with manifest_need_for_action; reversible allow for the lint-clear
#[allow(dead_code)]
fn action_in_manifest(action_key: &str) -> bool {
    DOCKER_MANIFEST.manifest.actions.iter().any(|a| {
        a.key == action_key
            || action_key
                .strip_prefix("docker.")
                .and_then(|suffix| {
                    let base = suffix.split('.').next()?;
                    Some(a.key == format!("docker.{base}") || a.key == action_key)
                })
                .unwrap_or(false)
    })
}

#[derive(Debug, Default, Clone)]
pub struct DockerFactory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerFactoryTarget {
    pub provider: &'static str,
    pub registry_host: String,
    pub image_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerFactoryNeed(pub Vec<String>);

impl InvocationGrammar for DockerFactory {
    fn action_key_for_argv(&self, argv: &[String]) -> Option<ActionKey> {
        classify_docker_argv(argv)
    }
}

impl TargetExtractor for DockerFactory {
    type Target = DockerFactoryTarget;

    fn target_for_argv(&self, action_key: &ActionKey, argv: &[String]) -> Option<Self::Target> {
        let k = &action_key.0;
        if !k.starts_with("docker.push.") && k != "docker.pull" {
            return None;
        }
        let image_ref = argv.iter().skip(1).find(|a| !a.starts_with('-'))?.clone();
        let registry_host = extract_registry_host(&image_ref);
        Some(DockerFactoryTarget {
            provider: "docker",
            registry_host,
            image_ref,
        })
    }
}

impl NeedTemplate for DockerFactory {
    type Need = DockerFactoryNeed;

    fn need_for_target(
        &self,
        action_key: &ActionKey,
        _target: &Self::Target,
        _argv: &[String],
    ) -> Option<Self::Need> {
        manifest_need_for_action(&action_key.0).map(DockerFactoryNeed)
    }
}

impl ConstructFactory for DockerFactory {
    fn disposition_for_argv(
        &self,
        action_key: Option<&ActionKey>,
        _argv: &[String],
    ) -> FactoryDisposition {
        let Some(key) = action_key else {
            return FactoryDisposition::Credentialless;
        };

        let k = &key.0;

        // Credential escape vectors — always fail closed.
        if k.starts_with("docker.login.") || k.starts_with("docker.logout.") {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        if k == "docker.run.privileged" {
            return FactoryDisposition::UnsupportedFailClosed;
        }

        // Authority-bearing payloads need analysis before materialization.
        // Build: Dockerfile + context + base image pulls.
        // Run: may pull images from private registries, mount volumes.
        // Pull: can't determine public vs private at classification time.
        if k == "docker.build" || k == "docker.run" || k == "docker.pull" {
            return FactoryDisposition::PayloadAnalysisRequired;
        }

        // Push: factory knows the target (registry + image) but cannot mint
        // registry credentials yet — the resolver (registry credential broker)
        // is unbuilt. Falls through to legacy path in lib.rs wiring.
        if k.starts_with("docker.push.") {
            return FactoryDisposition::ResolverRequired;
        }

        // Local container operations (stop, start, kill, rm, rmi, tag,
        // exec, cp) — no credentials needed.
        FactoryDisposition::Credentialless
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn push_dockerhub_default() {
        let r = classify_docker_argv(&args(&["push", "myuser/myimage:latest"])).unwrap();
        assert_eq!(r.0, "docker.push.dockerhub");
    }

    #[test]
    fn push_dockerhub_bare_name() {
        // No slash → still the default Hub registry.
        let r = classify_docker_argv(&args(&["push", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.push.dockerhub");
    }

    #[test]
    fn push_ecr() {
        let r = classify_docker_argv(&args(&[
            "push",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo:v1",
        ]))
        .unwrap();
        assert_eq!(
            r.0,
            "docker.push.123456789012.dkr.ecr.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn push_gcr() {
        let r = classify_docker_argv(&args(&["push", "gcr.io/my-project/api:1.2.3"])).unwrap();
        assert_eq!(r.0, "docker.push.gcr.io");
    }

    #[test]
    fn push_ip_port() {
        let r = classify_docker_argv(&args(&["push", "10.0.0.5:5000/internal/app:dev"])).unwrap();
        assert_eq!(r.0, "docker.push.10.0.0.5:5000");
    }

    #[test]
    fn push_localhost_port() {
        let r = classify_docker_argv(&args(&["push", "localhost:5000/foo:bar"])).unwrap();
        assert_eq!(r.0, "docker.push.localhost:5000");
    }

    #[test]
    fn login_default() {
        let r = classify_docker_argv(&args(&["login"])).unwrap();
        assert_eq!(r.0, "docker.login.dockerhub");
    }

    #[test]
    fn login_with_host() {
        let r = classify_docker_argv(&args(&["login", "ghcr.io"])).unwrap();
        assert_eq!(r.0, "docker.login.ghcr.io");
    }

    #[test]
    fn logout_with_host() {
        let r = classify_docker_argv(&args(&["logout", "ghcr.io"])).unwrap();
        assert_eq!(r.0, "docker.logout.ghcr.io");
    }

    #[test]
    fn run_normal() {
        let r = classify_docker_argv(&args(&["run", "--rm", "alpine", "echo", "hi"])).unwrap();
        assert_eq!(r.0, "docker.run");
    }

    #[test]
    fn run_privileged_refuses() {
        let r = classify_docker_argv(&args(&["run", "--privileged", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");
    }

    #[test]
    fn run_pid_host_refuses() {
        let r = classify_docker_argv(&args(&["run", "--pid=host", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");
    }

    #[test]
    fn run_network_host_refuses() {
        let r = classify_docker_argv(&args(&["run", "--network=host", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");

        let r = classify_docker_argv(&args(&["run", "--network", "host", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");
    }

    #[test]
    fn run_volume_root_refuses() {
        let r = classify_docker_argv(&args(&["run", "-v", "/:/host", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");

        let r = classify_docker_argv(&args(&["run", "--volume=/:/host", "alpine"])).unwrap();
        assert_eq!(r.0, "docker.run.privileged");
    }

    #[test]
    fn run_mount_source_root_refuses() {
        let r = classify_docker_argv(&args(&[
            "run",
            "--mount",
            "type=bind,source=/,target=/host",
            "alpine",
        ]))
        .unwrap();
        assert_eq!(r.0, "docker.run.privileged");
    }

    #[test]
    fn build_classified() {
        let r = classify_docker_argv(&args(&["build", "-t", "foo", "."])).unwrap();
        assert_eq!(r.0, "docker.build");
    }

    #[test]
    fn exec_classified() {
        let r = classify_docker_argv(&args(&["exec", "-it", "ctr", "sh"])).unwrap();
        assert_eq!(r.0, "docker.exec");
    }

    #[test]
    fn cp_classified() {
        let r = classify_docker_argv(&args(&["cp", "ctr:/etc/hosts", "./hosts"])).unwrap();
        assert_eq!(r.0, "docker.cp");
    }

    #[test]
    fn reads_passthrough() {
        for verb in &["ps", "images", "inspect", "logs", "stats"] {
            assert!(
                classify_docker_argv(&args(&[verb])).is_none(),
                "{verb} should passthrough"
            );
        }
    }

    #[test]
    fn empty_argv_is_passthrough() {
        assert!(classify_docker_argv(&[]).is_none());
    }

    // T1: container lifecycle verbs (COHORT-A-V03-CONSTRUCT-GAP-DOCKER-LIFECYCLE)

    #[test]
    fn stop_classified() {
        let r = classify_docker_argv(&args(&["stop", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.stop");
    }

    #[test]
    fn stop_with_time_flag_classified() {
        let r = classify_docker_argv(&args(&["stop", "-t", "30", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.stop");
    }

    #[test]
    fn start_classified() {
        let r = classify_docker_argv(&args(&["start", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.start");
    }

    #[test]
    fn kill_classified() {
        let r = classify_docker_argv(&args(&["kill", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.kill");
    }

    #[test]
    fn kill_with_signal_classified() {
        let r = classify_docker_argv(&args(&["kill", "--signal=SIGTERM", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.kill");
    }

    #[test]
    fn rm_classified() {
        let r = classify_docker_argv(&args(&["rm", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.rm");
    }

    #[test]
    fn rm_with_force_classified() {
        let r = classify_docker_argv(&args(&["rm", "-f", "my_container"])).unwrap();
        assert_eq!(r.0, "docker.rm");
    }

    #[test]
    fn rmi_classified() {
        let r = classify_docker_argv(&args(&["rmi", "my_image:latest"])).unwrap();
        assert_eq!(r.0, "docker.rmi");
    }

    #[test]
    fn rmi_with_force_classified() {
        let r = classify_docker_argv(&args(&["rmi", "-f", "my_image:latest"])).unwrap();
        assert_eq!(r.0, "docker.rmi");
    }

    #[test]
    fn pull_classified() {
        let r = classify_docker_argv(&args(&["pull", "alpine:3.18"])).unwrap();
        assert_eq!(r.0, "docker.pull");
    }

    #[test]
    fn pull_private_registry_classified() {
        let r = classify_docker_argv(&args(&["pull", "ghcr.io/org/image:latest"])).unwrap();
        assert_eq!(r.0, "docker.pull");
    }

    #[test]
    fn tag_classified() {
        let r =
            classify_docker_argv(&args(&["tag", "source_image:v1", "target_image:v2"])).unwrap();
        assert_eq!(r.0, "docker.tag");
    }

    #[test]
    fn unknown_verb_is_passthrough() {
        assert!(classify_docker_argv(&args(&["version"])).is_none());
        assert!(classify_docker_argv(&args(&["info"])).is_none());
        assert!(classify_docker_argv(&args(&["network", "ls"])).is_none());
    }

    // --- DockerFactory tests ---

    #[test]
    fn docker_factory_images_is_credentialless() {
        let f = DockerFactory;
        let a = args(&["images", "--format", "{{.Repository}}:{{.Tag}}"]);
        let key = f.action_key_for_argv(&a);
        assert!(key.is_none());
        assert_eq!(
            f.disposition_for_argv(key.as_ref(), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn docker_factory_push_is_resolver_required() {
        let f = DockerFactory;
        let a = args(&["push", "myuser/myimage:latest"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn docker_factory_push_ecr_is_resolver_required() {
        let f = DockerFactory;
        let a = args(&[
            "push",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo:v1",
        ]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::ResolverRequired
        );
    }

    #[test]
    fn docker_factory_login_is_unsupported() {
        let f = DockerFactory;
        let a = args(&["login", "ghcr.io"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn docker_factory_privileged_run_is_unsupported() {
        let f = DockerFactory;
        let a = args(&["run", "--privileged", "--pid=host", "alpine"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn docker_factory_build_is_payload_analysis() {
        let f = DockerFactory;
        let a = args(&["build", "-t", "registry.example.com/app:latest", "."]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn docker_factory_run_needs_payload_analysis() {
        let f = DockerFactory;
        let a = args(&["run", "--rm", "alpine", "echo", "hi"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn docker_factory_pull_needs_payload_analysis() {
        let f = DockerFactory;
        let a = args(&["pull", "alpine:3.18"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::PayloadAnalysisRequired
        );
    }

    #[test]
    fn docker_factory_logout_is_unsupported() {
        let f = DockerFactory;
        let a = args(&["logout"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::UnsupportedFailClosed
        );
    }

    #[test]
    fn docker_factory_exec_is_credentialless() {
        let f = DockerFactory;
        let a = args(&["exec", "-it", "ctr", "sh"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn docker_factory_rm_is_credentialless() {
        let f = DockerFactory;
        let a = args(&["rm", "-f", "old_container"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn docker_factory_stop_is_credentialless() {
        let f = DockerFactory;
        let a = args(&["stop", "my_container"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert_eq!(
            f.disposition_for_argv(Some(&key), &a),
            FactoryDisposition::Credentialless
        );
    }

    #[test]
    fn docker_factory_target_extraction_push() {
        let f = DockerFactory;
        let a = args(&["push", "ghcr.io/org/image:v1"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "docker");
        assert_eq!(target.registry_host, "ghcr.io");
        assert_eq!(target.image_ref, "ghcr.io/org/image:v1");
    }

    #[test]
    fn docker_factory_target_extraction_pull() {
        let f = DockerFactory;
        let a = args(&["pull", "ghcr.io/org/image:latest"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.provider, "docker");
        assert_eq!(target.registry_host, "ghcr.io");
        assert_eq!(target.image_ref, "ghcr.io/org/image:latest");
    }

    #[test]
    fn docker_factory_target_extraction_pull_dockerhub() {
        let f = DockerFactory;
        let a = args(&["pull", "alpine:3.18"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        let target = f.target_for_argv(&key, &a).expect("target extracted");
        assert_eq!(target.registry_host, "dockerhub");
        assert_eq!(target.image_ref, "alpine:3.18");
    }

    #[test]
    fn docker_factory_target_extraction_non_push_pull_returns_none() {
        let f = DockerFactory;
        let a = args(&["run", "--rm", "alpine"]);
        let key = f.action_key_for_argv(&a).expect("classified");
        assert!(f.target_for_argv(&key, &a).is_none());
    }

    #[test]
    fn docker_factory_contract_runs_conformance_corpus() {
        let corpus = core_construct_runtime::factory::parse_factory_fixture_corpus(include_str!(
            "../conformance/docker/factory-fixtures.toml"
        ))
        .expect("fixture corpus parses");
        let validation_errors =
            core_construct_runtime::factory::validate_factory_fixture_corpus(&corpus);
        assert!(validation_errors.is_empty(), "{validation_errors:#?}");

        let carrier = core_construct_runtime::factory::ActionManifestV2Carrier::parse(
            include_str!("../construct/docker.toml"),
        )
        .expect("docker manifest carrier parses");
        let report = core_construct_runtime::factory::run_factory_fixtures(
            &DockerFactory,
            Some(&carrier),
            &corpus,
        );
        assert!(report.is_clean(), "{:#?}", report.failures);
    }
}
