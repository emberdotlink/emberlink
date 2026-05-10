//! Argv classifier: maps `docker <verb> ...` to a `construct.toml` action_key.
//! Per design §3 — this lives shim-side BUT the daemon re-classifies the argv
//! server-side (untrusts the shim).
//!
//! Coverage:
//!   - push <host/repo:tag>  → docker.push.<registry-host>
//!   - login [host]          → docker.login.<host-or-default>
//!   - logout [host]         → docker.logout.<host-or-default>
//!   - run [...]             → docker.run, OR docker.run.privileged when
//!     --privileged / --pid=host / --network=host / --volume /:... is
//!     present (default = deny in construct.toml so the broker refuses).
//!   - build / exec / cp     → docker.<verb>
//!   - stop / start / kill / rm / rmi / pull / tag → docker.<verb>
//!   - ps / images / inspect / logs / stats → None (passthrough — read-only)
//!   - anything else         → None (passthrough)

use core_construct_runtime::ActionKey;

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
        if let Some(spec) = a.strip_prefix("--volume=").or_else(|| a.strip_prefix("-v="))
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

    // T1: container lifecycle verbs (implementation-note-32)

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
        let r = classify_docker_argv(&args(&["tag", "source_image:v1", "target_image:v2"])).unwrap();
        assert_eq!(r.0, "docker.tag");
    }

    #[test]
    fn unknown_verb_is_passthrough() {
        assert!(classify_docker_argv(&args(&["version"])).is_none());
        assert!(classify_docker_argv(&args(&["info"])).is_none());
        assert!(classify_docker_argv(&args(&["network", "ls"])).is_none());
    }
}
