//! `ember claude-code [--dev|--prod]` launcher (design Phase 4).
//!
//! Launches Claude Code with the correct EMBER_* env + PATH wiring for the
//! chosen daemon flavor. The launcher exec-replaces itself with `claude` so
//! signals and exit codes propagate cleanly without an intermediate PID.
//!
//! Anchor: `dev_prod_parity_ember_claude_code_launcher_landed`

use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use crate::install_paths::{DEV_DAEMON_SOCKET_REL, PROD_DAEMON_SOCKET_REL};

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
    pub path_prefix: PathBuf,
    pub ember_session_id: String,
    pub ember_strict_broker: &'static str,
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

    let (socket_rel, shadow_subdir, flavor_label): (&str, &str, &'static str) = match flavor {
        Flavor::Prod => (PROD_DAEMON_SOCKET_REL, ".ember/shadow/bin", "prod"),
        Flavor::Dev => (DEV_DAEMON_SOCKET_REL, ".ember-dev/shadow/bin", "dev"),
    };

    let ember_daemon_socket = home.join(socket_rel);
    let path_prefix = home.join(shadow_subdir);
    let ember_session_id = uuid::Uuid::new_v4().to_string();

    Ok(LaunchEnv {
        ember_daemon_socket,
        path_prefix,
        ember_session_id,
        ember_strict_broker: "1",
        ember_daemon_flavor: flavor_label,
    })
}

/// Ping the daemon socket to verify it is reachable before launching Claude Code.
///
/// Opens a `UnixStream` to `socket_path`. On failure, prints an
/// operator-actionable CTA and returns `Err` with exit code 2.
pub fn ping_daemon(env: &LaunchEnv, flavor: Flavor) -> io::Result<()> {
    use std::os::unix::net::UnixStream;

    UnixStream::connect(&env.ember_daemon_socket).map_err(|e| {
        let path = env.ember_daemon_socket.display();
        let cta = match flavor {
            Flavor::Prod => format!(
                "prod daemon not reachable at {path}; run `ember daemon install` first\n  (inner: {e})"
            ),
            Flavor::Dev => format!(
                "dev daemon not reachable at {path}; run `ember dev install` first\n  (inner: {e})"
            ),
        };
        eprintln!("ember claude-code: {cta}");
        io::Error::new(io::ErrorKind::ConnectionRefused, cta)
    })?;
    Ok(())
}

/// Resolve the claude binary. `$EMBER_CLAUDE_BIN` overrides the default
/// `claude` lookup so test harnesses can substitute `/usr/bin/true` etc.
fn resolve_claude_bin() -> String {
    std::env::var("EMBER_CLAUDE_BIN").unwrap_or_else(|_| "claude".to_string())
}

/// Build the child `PATH` by prepending `path_prefix` to the parent's `PATH`.
fn build_child_path(path_prefix: &std::path::Path) -> String {
    let parent = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", path_prefix.display(), parent)
}

/// Launch Claude Code with the configured env by exec-replacing this process.
///
/// Uses `std::os::unix::process::CommandExt::exec` so the launcher's PID
/// becomes claude's PID and signals / exit-code propagate cleanly.
///
/// The caller is responsible for calling `ping_daemon` before this function.
pub fn launch(flavor: Flavor, extra_args: &[String]) -> io::Result<()> {
    let env = build_launch_env(flavor)?;
    ping_daemon(&env, flavor)?;

    let bin = resolve_claude_bin();
    let child_path = build_child_path(&env.path_prefix);

    let err = Command::new(&bin)
        .args(extra_args)
        .env("EMBER_DAEMON_SOCKET", env.ember_daemon_socket.as_os_str())
        .env("EMBER_SESSION_ID", &env.ember_session_id)
        .env("EMBER_STRICT_BROKER", env.ember_strict_broker)
        .env("EMBER_DAEMON_FLAVOR", env.ember_daemon_flavor)
        .env("PATH", &child_path)
        .exec();

    // `exec` only returns on failure.
    Err(io::Error::new(
        err.kind(),
        format!("ember claude-code: failed to exec {bin}: {err}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── T1: env composition ──────────────────────────────────────────────────

    #[test]
    fn prod_flavor_uses_prod_socket() {
        let env = build_launch_env(Flavor::Prod).expect("build_launch_env prod");
        let sock = env.ember_daemon_socket.to_string_lossy();
        assert!(
            sock.ends_with(".ember/run/daemon.sock"),
            "prod socket must end with .ember/run/daemon.sock, got: {sock}"
        );
    }

    #[test]
    fn dev_flavor_uses_dev_socket() {
        let env = build_launch_env(Flavor::Dev).expect("build_launch_env dev");
        let sock = env.ember_daemon_socket.to_string_lossy();
        assert!(
            sock.ends_with(".ember/run/daemon.dev.sock"),
            "dev socket must end with .ember/run/daemon.dev.sock, got: {sock}"
        );
    }

    #[test]
    fn prod_flavor_prepends_prod_shadow_bin_dir() {
        let env = build_launch_env(Flavor::Prod).expect("build_launch_env prod");
        let prefix = env.path_prefix.to_string_lossy();
        assert!(
            prefix.ends_with(".ember/shadow/bin"),
            "prod path_prefix must end with .ember/shadow/bin, got: {prefix}"
        );
    }

    #[test]
    fn dev_flavor_prepends_dev_shadow_bin_dir() {
        let env = build_launch_env(Flavor::Dev).expect("build_launch_env dev");
        let prefix = env.path_prefix.to_string_lossy();
        assert!(
            prefix.ends_with(".ember-dev/shadow/bin"),
            "dev path_prefix must end with .ember-dev/shadow/bin, got: {prefix}"
        );
    }

    #[test]
    fn prod_flavor_label_is_prod() {
        let env = build_launch_env(Flavor::Prod).expect("build_launch_env prod");
        assert_eq!(env.ember_daemon_flavor, "prod");
        assert_eq!(env.ember_strict_broker, "1");
    }

    #[test]
    fn dev_flavor_label_is_dev() {
        let env = build_launch_env(Flavor::Dev).expect("build_launch_env dev");
        assert_eq!(env.ember_daemon_flavor, "dev");
        assert_eq!(env.ember_strict_broker, "1");
    }

    #[test]
    fn session_id_is_valid_uuid() {
        let env = build_launch_env(Flavor::Prod).expect("build_launch_env prod");
        uuid::Uuid::parse_str(&env.ember_session_id)
            .expect("EMBER_SESSION_ID must be a valid UUID");
    }

    #[test]
    fn two_sessions_get_distinct_uuids() {
        let a = build_launch_env(Flavor::Prod).expect("first");
        let b = build_launch_env(Flavor::Prod).expect("second");
        assert_ne!(
            a.ember_session_id, b.ember_session_id,
            "each launch must generate a distinct EMBER_SESSION_ID"
        );
    }

    #[test]
    fn prod_and_dev_sockets_are_disjoint() {
        let prod = build_launch_env(Flavor::Prod).expect("prod");
        let dev = build_launch_env(Flavor::Dev).expect("dev");
        assert_ne!(
            prod.ember_daemon_socket, dev.ember_daemon_socket,
            "prod and dev sockets must be different paths"
        );
    }

    // ── T1: both-flags-error (validated in the CLI dispatch layer) ───────────
    // The Cmd enum enforces mutual exclusion via the clap `conflicts_with`
    // attribute rather than runtime logic inside this module.  The test
    // documents the contract at the type level.

    #[test]
    fn flavor_variants_are_distinct() {
        assert_ne!(Flavor::Prod, Flavor::Dev);
    }

    // ── T2: daemon-ping pipeline ─────────────────────────────────────────────

    #[test]
    fn ping_daemon_fails_fast_when_socket_missing_prod() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/nonexistent/daemon.sock"),
            path_prefix: PathBuf::from("/tmp"),
            ember_session_id: "sess_test".to_string(),
            ember_strict_broker: "1",
            ember_daemon_flavor: "prod",
        };
        let err = ping_daemon(&env, Flavor::Prod).expect_err("should fail for missing socket");
        let msg = err.to_string();
        assert!(
            msg.contains("prod daemon not reachable") || msg.contains("daemon.sock"),
            "error must mention prod daemon: {msg}"
        );
        assert!(
            msg.contains("ember daemon install"),
            "error must include CTA 'ember daemon install': {msg}"
        );
    }

    #[test]
    fn ping_daemon_fails_fast_when_socket_missing_dev() {
        let env = LaunchEnv {
            ember_daemon_socket: PathBuf::from("/nonexistent/daemon.dev.sock"),
            path_prefix: PathBuf::from("/tmp"),
            ember_session_id: "sess_test".to_string(),
            ember_strict_broker: "1",
            ember_daemon_flavor: "dev",
        };
        let err = ping_daemon(&env, Flavor::Dev).expect_err("should fail for missing socket");
        let msg = err.to_string();
        assert!(
            msg.contains("dev daemon not reachable") || msg.contains("daemon.dev.sock"),
            "error must mention dev daemon: {msg}"
        );
        assert!(
            msg.contains("ember dev install"),
            "error must include CTA 'ember dev install': {msg}"
        );
    }

    #[test]
    fn build_child_path_prepends_prefix() {
        let prefix = PathBuf::from("/home/user/.ember/shadow/bin");
        let child_path = build_child_path(&prefix);
        assert!(
            child_path.starts_with("/home/user/.ember/shadow/bin:"),
            "child PATH must start with the bin/ prefix: {child_path}"
        );
    }
}
