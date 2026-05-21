//! `ember claude-code [--dev|--prod]` compatibility wrapper.
//!
//! The real session/register/close + grant/proxy env wiring now lives in
//! `launcher::claude_code`. This module remains only as the `--dev|--prod`
//! flavor selector under the current CLI dispatch layer, translating flavor
//! into socket/shadow-root choice and then delegating to the real launcher.
//!
//! Anchor: `dev_prod_parity_ember_claude_code_launcher_landed`

use std::io;
use std::path::PathBuf;

use crate::dev_runtime::derive_dev_runtime_env;
use crate::install_paths::PROD_DAEMON_SOCKET_REL;

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

fn build_launch_env_for_home(flavor: Flavor, home: &std::path::Path) -> io::Result<LaunchEnv> {
    match flavor {
        Flavor::Prod => Ok(LaunchEnv {
            ember_daemon_socket: home.join(PROD_DAEMON_SOCKET_REL),
            shadow_root: home.join(".ember/shadow"),
            ember_daemon_flavor: "prod",
        }),
        Flavor::Dev => {
            let workspace_root = crate::dev_runtime::resolve_workspace_root()
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;
            let runtime = derive_dev_runtime_env(home, &workspace_root);
            Ok(LaunchEnv {
                ember_daemon_socket: runtime.socket_path,
                shadow_root: runtime.shadow_root,
                ember_daemon_flavor: "dev",
            })
        }
    }
}

/// Ping the daemon socket to verify it is reachable before launching Claude Code.
///
/// Opens a `UnixStream` to `socket_path`. On failure, returns an
/// operator-actionable error for the top-level CLI to print once.
fn daemon_ping_error_message(env: &LaunchEnv, flavor: Flavor, err: &io::Error) -> String {
    let path = env.ember_daemon_socket.display();

    if crate::is_daemon_socket_permission_denied(err) {
        return match flavor {
            Flavor::Prod => format!(
                "prod daemon socket access is denied at {path}; confirm this shell can reach the managed daemon socket (ember-clients group, fresh login shell), then retry or repair with `sudo ember daemon install`"
            ),
            Flavor::Dev => format!(
                "dev daemon socket access is denied at {path}; confirm this shell can reach the dev daemon socket, then retry or rerun `ember dev install`"
            ),
        };
    }

    match flavor {
        Flavor::Prod => format!(
            "prod daemon not reachable at {path}; run `sudo ember daemon install` first\n  (inner: {err})"
        ),
        Flavor::Dev => format!(
            "dev daemon not reachable at {path}; run `ember dev install` first\n  (inner: {err})"
        ),
    }
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
pub fn launch(flavor: Flavor, extra_args: &[String]) -> io::Result<()> {
    let env = build_launch_env(flavor)?;
    ping_daemon(&env, flavor)?;
    let bin = crate::launcher::claude_code::resolve_claude_bin();
    let persona = crate::launcher::claude_code::resolve_persona_name();
    let construct_specs = match flavor {
        Flavor::Prod => {
            let specs = crate::launcher::claude_code::managed_prod_construct_specs();
            if !crate::launcher::claude_code::prod_required_constructs_present(&specs) {
                return Err(io::Error::other(
                    "prod construct bundle is incomplete: expected managed `ember-gh` and `ember-git` from the installed product, not repo-built target artifacts. Repair or reinstall the managed product before running `ember claude-code --prod`.",
                ));
            }
            specs
        }
        Flavor::Dev => crate::launcher::claude_code::cohort_a_construct_specs(),
    };
    let code = crate::launcher::claude_code::launch_claude_code_with_shadow_dir_and_constructs(
        extra_args,
        &env.ember_daemon_socket,
        &env.shadow_root,
        &bin,
        &persona,
        &construct_specs,
    )?;
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── T1: env composition ──────────────────────────────────────────────────

    #[test]
    fn prod_flavor_uses_prod_socket() {
        let env =
            build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
                .expect("build_launch_env prod");
        let sock = env.ember_daemon_socket.to_string_lossy();
        assert!(
            sock.ends_with(".ember/run/daemon.sock"),
            "prod socket must end with .ember/run/daemon.sock, got: {sock}"
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
        };
        assert_eq!(env.ember_daemon_flavor, "dev");
    }

    // ── T2: daemon-ping pipeline ─────────────────────────────────────────────

    #[test]
    fn ping_daemon_fails_fast_when_socket_missing_prod() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/nonexistent/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember/shadow"),
            ember_daemon_flavor: "prod",
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
        };
        let err = io::Error::from_raw_os_error(1);
        let msg = daemon_ping_error_message(&env, Flavor::Prod, &err);
        assert!(msg.contains("socket access is denied"), "got: {msg}");
        assert!(msg.contains("ember-clients group"), "got: {msg}");
        assert!(msg.contains("sudo ember daemon install"), "got: {msg}");
    }

    #[test]
    fn daemon_ping_error_message_maps_permission_denied_for_dev() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/run/daemon.sock"),
            shadow_root: PathBuf::from("/tmp/.ember-dev/envs/worktree-a/shadow"),
            ember_daemon_flavor: "dev",
        };
        let err = io::Error::from_raw_os_error(13);
        let msg = daemon_ping_error_message(&env, Flavor::Dev, &err);
        assert!(msg.contains("socket access is denied"), "got: {msg}");
        assert!(msg.contains("dev daemon socket"), "got: {msg}");
        assert!(msg.contains("ember dev install"), "got: {msg}");
    }

    #[test]
    fn prod_and_dev_sockets_are_disjoint() {
        let prod = build_launch_env_for_home(Flavor::Prod, std::path::Path::new("/home/test-operator"))
            .expect("prod");
        let runtime = derive_dev_runtime_env(
            std::path::Path::new("/home/test-operator"),
            std::path::Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let dev = LaunchEnv {
            ember_daemon_socket: runtime.socket_path,
            shadow_root: runtime.shadow_root,
            ember_daemon_flavor: "dev",
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
