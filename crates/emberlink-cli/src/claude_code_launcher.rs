//! CLASSIFICATION: PUBLIC
//! `ember claude [--dev|--prod]` compatibility wrapper.
//!
//! The real session/register/close + grant/proxy env wiring now lives in
//! `launcher::claude_code`. This module remains only as the `--dev|--prod`
//! flavor selector under the current CLI dispatch layer, translating flavor
//! into socket/shadow-root choice and then delegating to the real launcher.
//!
//! Anchor: `dev_prod_parity_ember_claude_code_launcher_landed`

use std::io;
use std::path::PathBuf;

use crate::dev_runtime::compact_runtime_banner;
use crate::install_paths::prod_daemon_socket_path;

/// Which daemon flavor to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Prod,
    Dev,
}

/// Resolved environment for a claude-code launch.
#[derive(Debug, Clone)]
pub struct LaunchEnv {
    pub ember_daemon_socket: PathBuf,
    pub shadow_root: PathBuf,
    pub ember_daemon_flavor: &'static str,
    pub runtime_banner: Option<String>,
    pub dev_runtime_id: Option<String>,
}

/// Build a [`LaunchEnv`] for the given flavor.
///
/// Resolves `home_dir` via `dirs_next::home_dir()`.
/// Returns `Err` if the home directory cannot be determined.
pub fn build_launch_env(flavor: Flavor) -> io::Result<LaunchEnv> {
    let home = dirs_next::home_dir().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "cannot determine home directory")
    })?;
    build_launch_env_for_home(flavor, &home)
}

fn explicit_config_socket_path() -> io::Result<Option<PathBuf>> {
    let Some(raw) = std::env::var_os("EMBER_CONFIG") else {
        return Ok(None);
    };
    if raw.as_os_str().is_empty() {
        return Ok(None);
    }

    let config_path = PathBuf::from(raw);
    let cfg = ember_daemon::infra::config::DaemonConfig::load(&config_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to load config from {}: {e}", config_path.display()),
        )
    })?;
    Ok(Some(
        cfg.socket_dir.join(ember_daemon::paths::DAEMON_SOCKET_FILE),
    ))
}

fn build_launch_env_for_home(flavor: Flavor, home: &std::path::Path) -> io::Result<LaunchEnv> {
    match flavor {
        Flavor::Prod => Ok(LaunchEnv {
            // ADR 218: prod socket is an absolute system path
            // (`/Library/Application Support/Emberlink/run/daemon.sock`
            // on macOS, `/run/ember/daemon.sock` on Linux) — NOT under
            // the operator's HOME. `home` is unused for the prod arm
            // but still resolved above to keep the prod/dev signature
            // symmetric (dev still resolves a per-runtime socket under
            // HOME pending its own follow-up rewire).
            //
            // An explicit EMBER_CONFIG remains an operator/test override:
            // the default is still ADR-218 system layout, but callers that
            // intentionally pin a config get its daemon socket.
            ember_daemon_socket: explicit_config_socket_path()?
                .unwrap_or_else(prod_daemon_socket_path),
            shadow_root: home.join(".ember/shadow"),
            ember_daemon_flavor: "prod",
            runtime_banner: None,
            dev_runtime_id: None,
        }),
        Flavor::Dev => {
            let runtime = crate::dev_runtime::resolve_current_dev_runtime_for_home(home)
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
            let runtime_banner = compact_runtime_banner(&runtime);
            let dev_runtime_id = (!runtime.is_shared()).then(|| runtime.worktree_id.clone());
            Ok(LaunchEnv {
                ember_daemon_socket: runtime.socket_path,
                shadow_root: runtime.shadow_root,
                ember_daemon_flavor: "dev",
                runtime_banner: Some(runtime_banner),
                dev_runtime_id,
            })
        }
    }
}

/// Ping the daemon socket to verify it is reachable before launching Claude Code.
///
/// Opens a `UnixStream` to `socket_path`. On failure, returns an
/// operator-actionable error for the top-level CLI to print once.
fn daemon_ping_error_message_with_ember_command(
    env: &LaunchEnv,
    flavor: Flavor,
    err: &io::Error,
    ember_cmd: Option<&str>,
) -> String {
    let rewrite_prod_guidance =
        |text: String| crate::rewrite_daemon_guidance_with_ember_command(&text, ember_cmd);
    let path = env.ember_daemon_socket.display();

    if crate::is_daemon_socket_permission_denied(err) {
        return match flavor {
            Flavor::Prod => rewrite_prod_guidance(format!(
                "prod daemon socket access is denied at {path}; confirm this shell can reach the managed daemon socket (ember-clients group, fresh login shell), then retry or repair with `sudo ember daemon install`"
            )),
            Flavor::Dev => format!(
                "dev daemon socket access is denied at {path}; confirm this shell can reach the dev daemon socket, then retry or rerun `ember dev install`"
            ),
        };
    }

    match flavor {
        Flavor::Prod => rewrite_prod_guidance(format!(
            "prod daemon not reachable at {path}; run `sudo ember daemon install` first\n  (inner: {err})"
        )),
        Flavor::Dev => format!(
            "dev daemon not reachable at {path}; run `ember dev install` first\n  (inner: {err})"
        ),
    }
}

fn daemon_ping_error_message(env: &LaunchEnv, flavor: Flavor, err: &io::Error) -> String {
    let ember_cmd = crate::current_repo_build_ember_command();
    daemon_ping_error_message_with_ember_command(env, flavor, err, ember_cmd.as_deref())
}

pub fn ping_daemon(env: &LaunchEnv, flavor: Flavor) -> io::Result<()> {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(&env.ember_daemon_socket).map_err(|e| {
        let cta = daemon_ping_error_message(env, flavor, &e);
        io::Error::new(io::ErrorKind::ConnectionRefused, cta)
    })?;
    Ok(())
}

/// Launch Claude Code through the real session-registering launcher.
///
/// The caller is responsible for calling `ping_daemon` before this function.
pub fn launch(
    flavor: Flavor,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
) -> io::Result<()> {
    launch_with_workspace_ref(
        flavor,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        extra_args,
        None,
    )
}

pub fn launch_with_workspace_ref(
    flavor: Flavor,
    authority_strict: bool,
    delegated_template: Option<&str>,
    attach_runtime_persona_id: Option<&str>,
    extra_args: &[String],
    workspace_ref: Option<&str>,
) -> io::Result<()> {
    let env = build_launch_env(flavor)?;
    ping_daemon(&env, flavor)?;
    if let Some(runtime_banner) = env.runtime_banner.as_deref() {
        eprintln!("ember --dev runtime: {runtime_banner}");
    }
    let bin = crate::launcher::claude_code::resolve_claude_bin();
    let persona = crate::launcher::claude_code::resolve_persona_name();
    let construct_specs = match flavor {
        Flavor::Prod => {
            let specs = crate::launcher::claude_code::managed_prod_construct_specs();
            if !crate::launcher::claude_code::prod_required_constructs_present(&specs) {
                return Err(io::Error::other(
                    "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` from the installed product, not repo-built target artifacts. Repair or reinstall the managed product before running `ember claude --prod`.",
                ));
            }
            specs
        }
        Flavor::Dev => crate::launcher::claude_code::cohort_a_construct_specs(),
    };
    let child_workspace_ref = child_workspace_ref_for_launch(&env, workspace_ref);
    let code =
        crate::launcher::claude_code::launch_claude_code_with_shadow_dir_and_constructs_with_workspace_ref(
        extra_args,
        &env.ember_daemon_socket,
        &env.shadow_root,
        &bin,
        &persona,
        &construct_specs,
        authority_strict,
        delegated_template,
        attach_runtime_persona_id,
        child_workspace_ref.as_deref(),
    )?;
    std::process::exit(code);
}

fn workspace_ref_for_runtime_id(runtime_id: &str) -> String {
    format!("managed_worktree:{runtime_id}")
}

pub(crate) fn child_workspace_ref_for_launch(
    env: &LaunchEnv,
    workspace_ref: Option<&str>,
) -> Option<String> {
    env.dev_runtime_id
        .as_deref()
        .map(workspace_ref_for_runtime_id)
        .or_else(|| workspace_ref.map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_runtime::derive_dev_runtime_env;

    // ── T1: env composition ──────────────────────────────────────────────────

    /// ADR 218 (operator-locked 2026-06-14): prod socket is an absolute
    /// system path, NOT under any user's HOME. The pre-ADR-218 assertion
    /// that the socket ends with `.ember/run/daemon.sock` is superseded.
    #[test]
    fn prod_flavor_uses_prod_socket() {
        let env =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("build_launch_env prod");
        let sock = env.ember_daemon_socket.to_string_lossy();
        assert!(
            env.ember_daemon_socket.is_absolute(),
            "prod socket must be absolute: {sock}"
        );
        assert!(
            !sock.starts_with("/Users/") && !sock.starts_with("/home/"),
            "ADR 218 boundary violated: prod socket at {sock} is under a user HOME"
        );
        assert!(
            !sock.contains("/.ember/"),
            "legacy ~/.ember/ leaked into prod socket: {sock}"
        );
        assert!(
            sock.ends_with("daemon.sock"),
            "prod socket must end with daemon.sock, got: {sock}"
        );
    }

    #[test]
    fn dev_flavor_uses_worktree_scoped_dev_socket() {
        let home = std::path::Path::new("/home/test-operator");
        let workspace_root = std::path::Path::new("/tmp/emberlink-dev/worktree-a");
        let runtime = derive_dev_runtime_env(home, workspace_root);
        let env = LaunchEnv {
            ember_daemon_socket: runtime.socket_path.clone(),
            shadow_root: runtime.shadow_root.clone(),
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let sock = env.ember_daemon_socket.to_string_lossy();
        assert!(
            sock.contains(".ember-dev/envs/") && sock.ends_with("/run/daemon.sock"),
            "dev socket must be worktree-scoped, got: {sock}"
        );
    }

    #[test]
    fn prod_flavor_prepends_prod_shadow_bin_dir() {
        let env =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("build_launch_env prod");
        let prefix = env.shadow_root.to_string_lossy();
        assert!(
            prefix.ends_with(".ember/shadow"),
            "prod shadow_root must end with .ember/shadow, got: {prefix}"
        );
    }

    #[test]
    fn dev_flavor_prepends_worktree_shadow_bin_dir() {
        let runtime = derive_dev_runtime_env(
            std::path::Path::new("/home/test-operator"),
            std::path::Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let env = LaunchEnv {
            ember_daemon_socket: runtime.socket_path,
            shadow_root: runtime.shadow_root,
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let prefix = env.shadow_root.to_string_lossy();
        assert!(
            prefix.contains(".ember-dev/envs/") && prefix.ends_with("/shadow"),
            "dev shadow_root must be worktree-scoped, got: {prefix}"
        );
    }

    #[test]
    fn prod_flavor_label_is_prod() {
        let env = build_launch_env(Flavor::Prod).expect("build_launch_env prod");
        assert_eq!(env.ember_daemon_flavor, "prod");
        assert!(env.runtime_banner.is_none());
        assert!(env.dev_runtime_id.is_none());
    }

    #[test]
    fn dev_flavor_label_is_dev() {
        let runtime = derive_dev_runtime_env(
            std::path::Path::new("/home/test-operator"),
            std::path::Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let env = LaunchEnv {
            ember_daemon_socket: runtime.socket_path,
            shadow_root: runtime.shadow_root,
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        assert_eq!(env.ember_daemon_flavor, "dev");
    }

    #[test]
    fn prod_launch_env_does_not_set_dev_runtime_id() {
        let env =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("prod");
        assert!(env.dev_runtime_id.is_none());
        assert!(env.runtime_banner.is_none());
    }

    #[test]
    fn managed_prod_launch_uses_workspace_ref_for_child_contracts() {
        let env =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("prod");

        assert_eq!(
            child_workspace_ref_for_launch(&env, Some("managed_worktree:rt-yankee")).as_deref(),
            Some("managed_worktree:rt-yankee"),
            "managed --host --worktree launches must pass a workspace ref so construct shims emit execution_contract.workspace_ref"
        );
    }

    #[test]
    fn dev_launch_runtime_id_maps_to_workspace_ref_before_worktree_override() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/run/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/shadow"),
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: Some("rt-dev-env".to_string()),
        };

        assert_eq!(
            child_workspace_ref_for_launch(&env, Some("managed_worktree:rt-managed")).as_deref(),
            Some("managed_worktree:rt-dev-env")
        );
    }

    // ── T2: daemon-ping pipeline ─────────────────────────────────────────────

    #[test]
    fn ping_daemon_fails_fast_when_socket_missing_prod() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/nonexistent/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember/shadow"),
            ember_daemon_flavor: "prod",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let err = ping_daemon(&env, Flavor::Prod).expect_err("should fail for missing socket");
        let msg = err.to_string();
        assert!(
            msg.contains("prod daemon not reachable") || msg.contains("daemon.sock"),
            "error must mention prod daemon: {msg}"
        );
        assert!(
            msg.contains("sudo ember daemon install"),
            "error must include CTA 'sudo ember daemon install': {msg}"
        );
    }

    #[test]
    fn ping_daemon_fails_fast_when_socket_missing_dev() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/nonexistent/worktree-dev/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/shadow"),
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let err = ping_daemon(&env, Flavor::Dev).expect_err("should fail for missing socket");
        let msg = err.to_string();
        assert!(
            msg.contains("dev daemon not reachable") || msg.contains("daemon.sock"),
            "error must mention dev daemon: {msg}"
        );
        assert!(
            msg.contains("ember dev install"),
            "error must include CTA 'ember dev install': {msg}"
        );
    }

    #[test]
    fn daemon_ping_error_message_maps_permission_denied_for_prod() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/tmp/.ember/run/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember/shadow"),
            ember_daemon_flavor: "prod",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let err = io::Error::from_raw_os_error(1);
        let msg = daemon_ping_error_message(&env, Flavor::Prod, &err);
        assert!(msg.contains("socket access is denied"), "got: {msg}");
        assert!(msg.contains("ember-clients group"), "got: {msg}");
        assert!(msg.contains("sudo ember daemon install"), "got: {msg}");
    }

    #[test]
    fn daemon_ping_error_message_preserves_repo_build_repair_command_for_prod() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/tmp/.ember/run/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember/shadow"),
            ember_daemon_flavor: "prod",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let err = io::Error::from_raw_os_error(13);
        let msg = daemon_ping_error_message_with_ember_command(
            &env,
            Flavor::Prod,
            &err,
            Some("/home/operator/emberlink-example/target/debug/ember"),
        );
        assert!(
            msg.contains("sudo /home/operator/emberlink-example/target/debug/ember daemon install"),
            "prod daemon socket guidance must preserve the invoking repo-built launcher path: {msg}"
        );
    }

    #[test]
    fn daemon_ping_error_message_maps_permission_denied_for_dev() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/run/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/shadow"),
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        let err = io::Error::from_raw_os_error(13);
        let msg = daemon_ping_error_message(&env, Flavor::Dev, &err);
        assert!(msg.contains("socket access is denied"), "got: {msg}");
        assert!(msg.contains("dev daemon socket"), "got: {msg}");
        assert!(msg.contains("ember dev install"), "got: {msg}");
    }

    #[test]
    fn prod_and_dev_sockets_are_disjoint() {
        let prod =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("prod");
        let runtime = derive_dev_runtime_env(
            std::path::Path::new("/home/test-operator"),
            std::path::Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let dev = LaunchEnv {
            ember_daemon_socket: runtime.socket_path,
            shadow_root: runtime.shadow_root,
            ember_daemon_flavor: "dev",
            runtime_banner: None,
            dev_runtime_id: None,
        };
        assert_ne!(
            prod.ember_daemon_socket, dev.ember_daemon_socket,
            "prod and dev sockets must be different paths"
        );
        assert_ne!(
            prod.shadow_root, dev.shadow_root,
            "prod and dev shadow roots must be different paths"
        );
    }
}
