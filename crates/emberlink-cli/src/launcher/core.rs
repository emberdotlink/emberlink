//! Shared launcher core for harness adapters.
//!
//! Keeps the daemon session contract and child-process env injection in one
//! place so harness adapters (`claude`, `codex`, later others) only own
//! binary-specific policy.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const OPERATOR_PRESENCE_TOKEN_ENV: &str = "EMBER_OPERATOR_PRESENCE_TOKEN";

/// Outcome of the daemon `register_session` RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRegistration {
    pub session_id: String,
    pub grant_id: String,
    pub proxy_url: String,
    /// Serialized daemon-minted operator presence token. Forwarded into
    /// child construct shims so `broker_resolve` / `broker_exec` keep the
    /// session-runtime authority class unlocked after `register_session`.
    pub presence_token_json: Option<String>,
    /// Optional Anthropic gateway base URL for launcher-mediated Claude
    /// sessions.
    pub anthropic_base_url: Option<String>,
    /// Newline-separated `Name: Value` headers for Claude's
    /// `ANTHROPIC_CUSTOM_HEADERS` env var.
    pub anthropic_custom_headers: Option<String>,
    /// Git credential-injection proxy URL.
    pub git_proxy_url: Option<String>,
    /// Path to the daemon-managed ssh-agent socket for this session.
    pub ssh_auth_sock: Option<String>,
    /// Optional workflow grant ULID minted at session-open.
    pub workflow_id: Option<String>,
    /// Optional workflow template name paired with `workflow_id`.
    pub workflow_template: Option<String>,
}

/// Generic launch request once a harness has already registered a session.
pub struct LauncherInvocation<'a> {
    pub launcher_name: &'a str,
    pub binary: &'a str,
    pub extra_args: &'a [String],
    pub socket_path: &'a Path,
    pub shadow_bin_dir: &'a Path,
    pub current_dir: Option<&'a Path>,
}

/// Resolve the shared shadow root directory: `~/.ember/shadow/`, overridable
/// via `$EMBER_SHADOW_DIR` for test harnesses.
pub fn resolve_shadow_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("EMBER_SHADOW_DIR") {
        return PathBuf::from(override_dir);
    }
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ember")
        .join("shadow")
}

fn legacy_private_worktree_launch_message(
    launcher_name: &str,
    repo_root: &Path,
    cwd: &Path,
) -> Option<String> {
    let legacy_root = crate::launcher::worktree::legacy_worktrees_dir(&repo_root);
    if !cwd.starts_with(&legacy_root) {
        return None;
    }

    let suggested = cwd.file_name().map_or_else(
        || crate::launcher::worktree::primary_worktrees_dir(&repo_root),
        |leaf| crate::launcher::worktree::primary_worktrees_dir(&repo_root).join(leaf),
    );
    Some(format!(
        "ember {launcher_name}: host-mode launch from legacy private worktrees under {} is unsupported because brokered child processes cannot traverse that path.\n  launch from the repo root or migrate this worktree under {}",
        legacy_root.display(),
        suggested.display()
    ))
}

fn legacy_private_worktree_launch_error(launcher_name: &str, cwd: &Path) -> Option<io::Error> {
    let repo_root = crate::launcher::worktree::resolve_repo_root().ok()?;
    legacy_private_worktree_launch_message(launcher_name, &repo_root, cwd).map(io::Error::other)
}

pub fn ensure_broker_safe_launch_cwd(launcher_name: &str) -> io::Result<()> {
    let cwd = std::env::current_dir()?;
    if let Some(err) = legacy_private_worktree_launch_error(launcher_name, &cwd) {
        return Err(err);
    }
    Ok(())
}

/// Spawn the upstream harness binary with the common Ember session env layered
/// on top of the inherited parent environment.
pub fn run_with_registration<I>(
    invocation: LauncherInvocation<'_>,
    registration: &SessionRegistration,
    extra_env: I,
) -> io::Result<i32>
where
    I: IntoIterator<Item = (String, String)>,
{
    eprintln!(
        "ember {}: launching {} (session={}, grant={}, proxy={})",
        invocation.launcher_name,
        invocation.binary,
        registration.session_id,
        registration.grant_id,
        registration.proxy_url,
    );

    let parent_path = std::env::var("PATH").unwrap_or_default();
    let child_path = format!("{}:{}", invocation.shadow_bin_dir.display(), parent_path);

    let mut cmd = Command::new(invocation.binary);
    cmd.args(invocation.extra_args)
        .env("EMBER_GRANT_ID", &registration.grant_id)
        .env("EMBER_PROXY_URL", &registration.proxy_url)
        .env("EMBER_SOCKET_PATH", invocation.socket_path.as_os_str())
        .env("EMBER_DAEMON_SOCKET", invocation.socket_path.as_os_str())
        .env("EMBER_SESSION_ID", &registration.session_id)
        .env("PATH", &child_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(token_json) = registration.presence_token_json.as_deref() {
        cmd.env(OPERATOR_PRESENCE_TOKEN_ENV, token_json);
    }

    if let Some(current_dir) = invocation.current_dir {
        cmd.current_dir(current_dir);
    }

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let status = cmd.status().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "ember {}: failed to spawn {}: {e}",
                invocation.launcher_name, invocation.binary
            ),
        )
    })?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SessionRegistration {
        SessionRegistration {
            session_id: "sess_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            proxy_url: "http://127.0.0.1:9999".to_string(),
            presence_token_json: None,
            anthropic_base_url: None,
            anthropic_custom_headers: None,
            git_proxy_url: None,
            ssh_auth_sock: None,
            workflow_id: None,
            workflow_template: None,
        }
    }

    fn invocation<'a>(binary: &'a str) -> LauncherInvocation<'a> {
        LauncherInvocation {
            launcher_name: "test",
            binary,
            extra_args: &[],
            socket_path: Path::new("/nonexistent.sock"),
            shadow_bin_dir: Path::new("/tmp"),
            current_dir: None,
        }
    }

    #[test]
    fn run_with_registration_propagates_zero_exit() {
        let code = run_with_registration(invocation("/usr/bin/true"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/true");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_registration_propagates_nonzero_exit() {
        let code = run_with_registration(invocation("/usr/bin/false"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/false");
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_registration_does_not_pollute_parent_env() {
        let _ = run_with_registration(invocation("/usr/bin/true"), &fixture(), Vec::new())
            .expect("spawn /usr/bin/true");
        let leaked = std::env::var("EMBER_GRANT_ID")
            .map(|v| v.contains("grt_fixture"))
            .unwrap_or(false);
        assert!(
            !leaked,
            "launcher must not write EMBER_GRANT_ID into parent env"
        );
    }

    #[test]
    fn run_with_registration_reports_spawn_failure() {
        let result = run_with_registration(
            invocation("/no/such/binary-that-must-not-exist"),
            &fixture(),
            Vec::new(),
        );
        assert!(
            result.is_err(),
            "missing binary must surface as Err, not silent zero exit"
        );
    }

    #[test]
    fn resolve_shadow_dir_honors_override() {
        unsafe {
            std::env::set_var("EMBER_SHADOW_DIR", "/tmp/ember-shadow-override");
        }
        assert_eq!(
            resolve_shadow_dir(),
            PathBuf::from("/tmp/ember-shadow-override")
        );
        unsafe {
            std::env::remove_var("EMBER_SHADOW_DIR");
        }
    }

    #[test]
    fn legacy_private_worktree_launch_error_flags_legacy_paths() {
        let repo_root = PathBuf::from("/tmp/repo");
        let cwd = repo_root.join(".claude/worktrees/pulumi");
        let msg = legacy_private_worktree_launch_message("claude", &repo_root, &cwd)
            .expect("legacy path must produce guidance");
        assert!(msg.contains("/tmp/repo/.claude/worktrees"));
        assert!(msg.contains("/tmp/repo/.ember/worktrees/pulumi"));
    }
}
