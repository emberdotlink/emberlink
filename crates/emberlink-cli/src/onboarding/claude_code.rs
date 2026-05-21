//! `ember init --for claude-code` and `ember uninstall --for claude-code`
//! orchestration (implementation-note-451).
//!
//! Per design §2 / §3: a one-command first-run setup that wires Claude Code
//! to the local ember daemon. This module is the orchestration layer — the
//! individual primitives (settings.json patch, persona create, grant create,
//! vault add) live elsewhere and are glued together here.
//!
//! The flow:
//!   1. Resolve the persona name `claude-code-{hostname}` (idempotent reuse).
//!   2. Write the default scope template to `~/.ember/grant-template.toml`
//!      (idempotent — never overwrites an existing file).
//!   3. Create a 24h grant from the template (idempotent — reuses an active
//!      grant for the persona if one exists).
//!   4. Patch `~/.claude/settings.json` to install the `ember-proxy hook`
//!      PreToolUse hook (idempotent — see `settings_patch.rs`).
//!   5. GitHub fallback guidance: keep the HTTPS/App lane as canonical.
//!      The degraded `github-pat` lane remains available later through
//!      `ember vault add --name github-pat`, but init no longer captures
//!      PATs interactively.
//!   6. Print the next two commands per design §2:
//!      `ember claude-code` and `ember receipt show`.
//!
//! The uninstall flow reverses (4) by removing only the lines we added; the
//! other artifacts (persona, grant, vault entry) are intentionally left in
//! place because they may be in use by other tools.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::onboarding::settings_patch::{
    PatchError, add_pretooluse_hook, has_pretooluse_hook, remove_pretooluse_hook,
};

/// Default 24-hour grant TTL per design §3.
pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;

/// Vault credential name used for the captured GitHub PAT.
pub const GH_PAT_VAULT_NAME: &str = "github-pat";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubOnboardingPosture {
    AppConfiguredReal,
    PatConfigured,
    AppConfiguredMock,
    AppBroken(String),
    AppNotConfigured,
}

/// Truthful operator-facing follow-up when the onboarding flow skips PAT
/// capture or a vault write fails.
pub fn gh_pat_later_command() -> String {
    format!("ember vault add --name {GH_PAT_VAULT_NAME}")
}

/// Embedded grant scope template (design §3 / γ). Sourced from
/// `core-policy/src/templates/claude_code_default_v1.toml` so the template
/// shipped with the binary always matches the policy crate's reference copy.
pub const CLAUDE_CODE_DEFAULT_TEMPLATE: &str =
    include_str!("../../../core-policy/src/templates/claude_code_default_v1.toml");

/// Errors raised by the cohort A orchestrator. Each variant maps to a
/// non-zero exit code in `cmd_init` / `cmd_uninstall`.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("home directory not resolvable (HOME unset)")]
    NoHomeDir,
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("settings.json patch error: {0}")]
    Patch(#[from] PatchError),
    #[error("settings.json json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Resolve `~/.ember/grant-template.toml`.
pub fn default_grant_template_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?.join(".ember").join("grant-template.toml"))
}

/// Resolve `~/.claude/settings.json`.
pub fn default_settings_json_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?.join(".claude").join("settings.json"))
}

/// Compute the default persona name for cohort A in the locked 2-slot
/// Persona schema (CONTEXT.md "Identity surface" §Persona ID schema):
/// `claude-code-<context>` via [`crate::launcher::default_persona_id_for_runtime`].
///
/// The `<context>` slot resolves to the worktree directory name when the
/// caller passed one (future `-w` flag); without context, it falls back
/// to `default`. This drops the prior hostname-keyed default — multi-host
/// users who relied on per-host persona separation must now set
/// `EMBER_PERSONA` explicitly or pass `-w <name>` to the launcher.
///
/// implementation-note-483 anchor: routes
/// through `default_persona_id_for_runtime` so launcher + init agree on
/// the same persona-id shape.
pub fn claude_code_persona_name() -> String {
    crate::launcher::default_persona_id_for_runtime("claude-code", None)
}

/// Resolve the user's home directory. Wraps `dirs_next::home_dir`.
fn home_dir() -> Result<PathBuf, InitError> {
    dirs_next::home_dir().ok_or(InitError::NoHomeDir)
}

/// Best-effort hostname resolution. Returns `None` if the platform call
/// fails or the result isn't valid UTF-8. Intentionally permissive — the
/// Write the grant scope template to `~/.ember/grant-template.toml` if
/// missing. Returns `true` on a fresh write, `false` if the file already
/// existed (idempotent path).
pub fn write_grant_template_if_missing(path: &Path) -> Result<bool, InitError> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|source| InitError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, CLAUDE_CODE_DEFAULT_TEMPLATE).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

/// Read `~/.claude/settings.json` (creating an empty file if missing) and
/// patch it to include our PreToolUse hook. Returns `true` if a write was
/// made, `false` if the hook was already present.
pub fn patch_claude_settings_file(path: &Path) -> Result<bool, InitError> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|source| InitError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let raw = if path.exists() {
        fs::read_to_string(path).map_err(|source| InitError::Io {
            path: path.to_path_buf(),
            source,
        })?
    } else {
        String::new()
    };
    let mut value: serde_json::Value = if raw.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&raw)?
    };
    if !value.is_object() {
        return Err(PatchError::RootNotObject("non-object").into());
    }
    if has_pretooluse_hook(&value) {
        return Ok(false);
    }
    let _wrote = add_pretooluse_hook(&mut value)?;
    let serialized = serde_json::to_string_pretty(&value)?;
    fs::write(path, serialized).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

/// Reverse of `patch_claude_settings_file`: removes only our hook entry.
/// Returns `true` if a write was made, `false` if our hook wasn't present
/// (or the file didn't exist). Never modifies user-authored hooks.
pub fn unpatch_claude_settings_file(path: &Path) -> Result<bool, InitError> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if raw.trim().is_empty() {
        return Ok(false);
    }
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    if !value.is_object() {
        return Err(PatchError::RootNotObject("non-object").into());
    }
    let made_change = remove_pretooluse_hook(&mut value)?;
    if !made_change {
        return Ok(false);
    }
    let serialized = serde_json::to_string_pretty(&value)?;
    fs::write(path, serialized).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

/// Print posture-aware next commands plus the launcher-vs-bare-claude
/// gradient explanation. Single point of truth so the wording stays in sync
/// between `init` success and any other output paths that want to nudge the
/// user forward.
///
/// `init_claude_code_launcher_finish_slimmed` — for `v0.3.0`, the init finish
/// screen should reinforce one canonical next step, not teach every advanced
/// lane. Bare `claude` and headless automation remain real surfaces, but they
/// are intentionally demoted out of the first-run success path so friendlies
/// leave init with one supported launcher mental model.
pub fn print_next_commands(posture: GitHubOnboardingPosture) {
    print!("{}", next_commands_text(posture));
}

fn next_commands_text(posture: GitHubOnboardingPosture) -> String {
    let mut lines = vec!["", "Next steps:"];
    match posture {
        GitHubOnboardingPosture::AppConfiguredReal => {
            lines.extend_from_slice(&[
                "  ember claude-code        # launch Claude Code with this grant (recommended)",
                "  ember receipt show       # see the audit trail of the grant",
            ]);
        }
        GitHubOnboardingPosture::PatConfigured => {
            lines.extend_from_slice(&[
                "  ember claude-code        # launch now on the degraded PAT lane",
                "  ember github setup       # upgrade to the real App lane when ready",
                "  ember receipt show       # see the audit trail of the grant",
            ]);
        }
        GitHubOnboardingPosture::AppBroken(_) => {
            lines.extend_from_slice(&[
                "  ember github setup       # repair or replace the local App credential triple",
                "  ember github status      # confirm the App lane is healthy",
                "  ember claude-code        # launch once GitHub is repaired",
            ]);
        }
        GitHubOnboardingPosture::AppConfiguredMock | GitHubOnboardingPosture::AppNotConfigured => {
            lines.extend_from_slice(&[
                "  ember github setup       # register PEM + App ID + installation URL/ID + slug",
                "  ember github status      # confirm the App lane is ready",
                "  ember claude-code        # launch once GitHub is configured",
            ]);
        }
    }
    lines.extend_from_slice(&[
        "",
        "About the launcher",
        "------------------",
        "`ember claude-code` is the canonical v0.3.0 launcher. It opens a fresh session,",
        "attaches a scoped grant, and keeps audit plus revocation on the supported path.",
        "",
        "Use that path first. Bare `claude` and headless automation remain advanced",
        "surfaces, but they are intentionally outside the friendly default.",
    ]);
    lines.join("\n") + "\n"
}

/// Render GitHub onboarding guidance for the current posture.
///
/// For `v0.3.0`, init keeps the App lane as the canonical onboarding path.
/// The degraded `github-pat` lane remains available later via
/// `ember vault add --name github-pat`, but we do not teach that fallback as
/// part of the first-run path when the App lane is simply not configured yet.
pub fn render_github_onboarding_guidance(posture: GitHubOnboardingPosture) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str("GitHub access:\n");

    match posture {
        GitHubOnboardingPosture::AppConfiguredReal => {
            out.push_str("  Ready: GitHub App broker configured for the HTTPS/API lane.\n");
            out.push_str("  `ember claude-code` will use short-lived installation tokens there.\n");
        }
        GitHubOnboardingPosture::PatConfigured => {
            out.push_str("  Degraded PAT fallback is configured today.\n");
            out.push_str("  Preferred fix: run `ember github setup` to move onto the App lane.\n");
            out.push_str("  Until then, gh/git will attribute through your GitHub identity.\n");
        }
        GitHubOnboardingPosture::AppConfiguredMock => {
            out.push_str("  Not ready: this daemon only has a mock GitHub broker right now.\n");
            out.push_str(
                "  Run `ember github setup` to register the real App credential triple.\n",
            );
            out.push_str("  Have these ready: private key PEM, App ID, installation URL or ID, and App slug.\n");
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
        GitHubOnboardingPosture::AppBroken(detail) => {
            out.push_str("  Broken: this daemon has local GitHub authority configured, but it is not usable yet.\n");
            let _ = writeln!(out, "  Detail: {detail}");
            out.push_str("  Repair path: run `ember github setup` again to replace or complete the credential triple.\n");
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
        GitHubOnboardingPosture::AppNotConfigured => {
            out.push_str(
                "  Not ready: this daemon does not have a real GitHub App broker configured yet.\n",
            );
            out.push_str("  Run `ember github setup` to register the App credential triple.\n");
            out.push_str("  Have these ready: private key PEM, App ID, installation URL or ID, and App slug.\n");
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
    }

    out
}

/// Print GitHub onboarding guidance for the current posture.
pub fn print_github_onboarding_guidance(posture: GitHubOnboardingPosture) -> io::Result<()> {
    eprint!("{}", render_github_onboarding_guidance(posture));
    Ok(())
}

/// Decide whether the autostart path should install a LaunchAgent / systemd
/// user unit, or fall back to a raw `--background` daemon spawn.
///
/// implementation-note-486: the LaunchAgent / systemd-user
/// path is correct for the canonical "production user" install (single
/// always-up daemon per login session) — but it baked an absolute `~/.ember/`
/// path resolved against the operator's *real* HOME at install time, so an
/// `init --for claude-code` invocation under an isolated `HOME=/tmp/...`
/// would write a service file pointing at the production socket while the
/// Returns `true` only when the invocation is running in the canonical
/// friendly-install topology:
///   - `home` looks like a default user home (not `/tmp/`, `/var/folders/`,
///     `/private/var/`), AND
///   - `config` is `None` (no `--config` / `EMBER_CONFIG` override).
///
/// `ember init` and `ember init --for claude-code` may only offer to run the
/// managed separate-uid installer in this topology. In isolated HOME / custom
/// config environments, running `sudo ember daemon install` would provision
/// the operator's real installed daemon instead of the isolated test target,
/// so the correct behavior is to refuse and surface a clear manual path.
pub fn supports_managed_daemon_install(
    home: &std::path::Path,
    config: Option<&std::path::Path>,
) -> bool {
    // Any explicit --config / EMBER_CONFIG override means the caller is
    // running outside the default install topology — skip the LaunchAgent.
    if config.is_some() {
        return false;
    }
    // Heuristic: ephemeral HOMEs commonly used by tests / CI / QA isolation.
    let home_str = home.to_string_lossy();
    if home_str.starts_with("/tmp/")
        || home_str.starts_with("/var/folders/")
        || home_str.starts_with("/private/var/")
        || home_str.starts_with("/private/tmp/")
    {
        return false;
    }
    true
}

/// Resolve the autostart liveness-wait timeout in seconds. Honors the
/// `EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS` env override; falls back to a
/// 10s default (raised from 5s in implementation-note-486
/// because first-time provisioning — vault.salt + daemon.db schema — can
/// exceed 5s on slow disks).
pub fn autostart_liveness_timeout_secs() -> u64 {
    std::env::var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(10)
}

/// Top-level summary output emitted by the orchestrator. Returned as a
/// struct (rather than printed inside the helper) so callers control the
/// exact moment of the user-facing write — useful for tests and for the
/// `--json` path in the parent `cmd_init`.
#[derive(Debug, Default)]
pub struct InitSummary {
    pub persona_name: String,
    pub persona_id: Option<String>,
    pub grant_id: Option<String>,
    pub template_path: PathBuf,
    pub template_written: bool,
    pub settings_path: PathBuf,
    pub settings_patched: bool,
    pub gh_pat_stored: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn persona_name_uses_2_slot_default_shape() {
        // implementation-note-483: the default
        // persona now follows the locked 2-slot Persona schema
        // (CONTEXT.md "Identity surface" §Persona ID schema) —
        // `claude-code-<context>` where `<context>` is `default` until
        // the `-w` flag wires worktree-dir-name through. Hostname keying
        // is gone; multi-host users who relied on per-host separation
        // must set EMBER_PERSONA explicitly.
        let name = claude_code_persona_name();
        assert_eq!(name, "claude-code-default");
    }

    #[test]
    fn write_grant_template_creates_then_skips() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".ember").join("grant-template.toml");
        // First call writes.
        let wrote = write_grant_template_if_missing(&path).unwrap();
        assert!(wrote);
        assert!(path.exists());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("claude-code-default-v1"));
        // Second call no-ops (idempotent).
        let wrote_again = write_grant_template_if_missing(&path).unwrap();
        assert!(!wrote_again);
    }

    #[test]
    fn patch_settings_creates_file_when_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(".claude").join("settings.json");
        let wrote = patch_claude_settings_file(&path).unwrap();
        assert!(wrote);
        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn patch_settings_idempotent_second_call() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        let first = patch_claude_settings_file(&path).unwrap();
        assert!(first);
        let second = patch_claude_settings_file(&path).unwrap();
        assert!(!second, "second call should no-op");
    }

    #[test]
    fn patch_settings_preserves_existing_keys() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        let preexisting = serde_json::to_string_pretty(&json!({
            "theme": "dark",
            "model": "sonnet",
            "permissions": {"allow": ["Bash(ls)"]}
        }))
        .unwrap();
        fs::write(&path, &preexisting).unwrap();

        let wrote = patch_claude_settings_file(&path).unwrap();
        assert!(wrote);
        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v.get("theme").and_then(|v| v.as_str()), Some("dark"));
        assert_eq!(v.get("model").and_then(|v| v.as_str()), Some("sonnet"));
        assert!(v.get("permissions").is_some());
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn unpatch_undoes_patch() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        // Empty file so the patch creates the only hook entry.
        let _ = patch_claude_settings_file(&path).unwrap();
        let removed = unpatch_claude_settings_file(&path).unwrap();
        assert!(removed);
        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        // After removal, file is back to {}.
        assert_eq!(v, json!({}));
    }

    #[test]
    fn unpatch_preserves_user_hooks() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        let preexisting = serde_json::to_string_pretty(&json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "/usr/local/bin/my-hook"}
                    ]}
                ]
            }
        }))
        .unwrap();
        fs::write(&path, &preexisting).unwrap();

        let _ = patch_claude_settings_file(&path).unwrap();
        let removed = unpatch_claude_settings_file(&path).unwrap();
        assert!(removed);

        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        // User's Bash hook is still there.
        let pretooluse = v.pointer("/hooks/PreToolUse").unwrap().as_array().unwrap();
        assert_eq!(pretooluse.len(), 1);
        assert_eq!(
            pretooluse[0].pointer("/hooks/0/command").unwrap().as_str(),
            Some("/usr/local/bin/my-hook")
        );
    }

    #[test]
    fn unpatch_noop_when_file_missing() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nonexistent.json");
        let removed = unpatch_claude_settings_file(&path).unwrap();
        assert!(!removed);
    }

    #[test]
    fn unpatch_noop_when_hook_absent() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        fs::write(&path, "{}").unwrap();
        let removed = unpatch_claude_settings_file(&path).unwrap();
        assert!(!removed);
    }

    #[test]
    fn embedded_template_has_expected_id() {
        // Sanity check that include_str! actually pulled the file in. If
        // this fails, the path in the macro is wrong — fix it here, not
        // in core-policy.
        assert!(
            CLAUDE_CODE_DEFAULT_TEMPLATE.contains(r#"id = "claude-code-default-v1""#),
            "template must contain its id literal"
        );
    }

    #[test]
    fn guidance_for_app_not_configured_names_one_next_command() {
        let rendered = render_github_onboarding_guidance(GitHubOnboardingPosture::AppNotConfigured);
        assert!(rendered.contains("Run `ember github setup`"));
        assert!(rendered.contains("HTTPS/App first"));
        assert!(
            !rendered.contains("github-pat"),
            "friendly not-configured guidance should not teach degraded PAT fallback up front"
        );
    }

    #[test]
    fn guidance_prints_for_real_app_lane() {
        let rendered =
            render_github_onboarding_guidance(GitHubOnboardingPosture::AppConfiguredReal);
        assert!(rendered.contains("Ready: GitHub App broker configured"));
    }

    #[test]
    fn guidance_prints_for_broken_app_lane() {
        let rendered = render_github_onboarding_guidance(GitHubOnboardingPosture::AppBroken(
            "github/apps/ember/install-123: partial credential triple".to_string(),
        ));
        assert!(rendered.contains("Repair path: run `ember github setup` again"));
    }

    #[test]
    fn guidance_prints_for_pat_fallback() {
        let rendered = render_github_onboarding_guidance(GitHubOnboardingPosture::PatConfigured);
        assert!(rendered.contains("Degraded PAT fallback is configured today."));
        assert!(rendered.contains("Preferred fix: run `ember github setup`"));
    }

    #[test]
    fn gh_pat_later_command_uses_real_vault_add_shape() {
        assert_eq!(
            gh_pat_later_command(),
            "ember vault add --name github-pat",
            "friendly fallback must use the real `vault add` CLI shape"
        );
    }

    #[test]
    fn next_commands_text_stays_truthful_about_launcher_presence() {
        let text = next_commands_text(GitHubOnboardingPosture::AppConfiguredReal);
        assert!(
            text.contains(
                "`ember claude-code` is the canonical v0.3.0 launcher. It opens a fresh session,"
            ),
            "launcher guidance should still recommend the session-scoped path"
        );
        assert!(
            text.contains(
                "attaches a scoped grant, and keeps audit plus revocation on the supported path."
            ),
            "launcher guidance should keep the actual scoping/revocation value proposition"
        );
        assert!(
            !text.contains("Touch ID"),
            "launcher guidance must not overclaim session-open Touch ID until the presence flow exists"
        );
        assert!(
            !text.contains("You CAN launch bare `claude`"),
            "friendly init should not teach the partial bare-claude lane as a first-run path"
        );
        assert!(
            !text.contains("ember headless enroll --duration"),
            "friendly init should not dump headless automation instructions into the first-run finish screen"
        );
    }

    #[test]
    fn next_commands_text_blocks_launch_until_app_lane_is_ready() {
        let text = next_commands_text(GitHubOnboardingPosture::AppNotConfigured);
        assert!(text.contains("ember github setup"));
        assert!(text.contains("ember github status"));
        assert!(text.contains("launch once GitHub is configured"));
    }

    #[test]
    fn next_commands_text_names_pat_lane_as_degraded() {
        let text = next_commands_text(GitHubOnboardingPosture::PatConfigured);
        assert!(text.contains("launch now on the degraded PAT lane"));
        assert!(text.contains("upgrade to the real App lane"));
    }

    #[test]
    fn next_commands_text_names_broken_app_lane_as_repair_path() {
        let text = next_commands_text(GitHubOnboardingPosture::AppBroken(
            "github/apps/ember/install-123: partial credential triple".to_string(),
        ));
        assert!(text.contains("repair or replace the local App credential triple"));
        assert!(text.contains("confirm the App lane is healthy"));
        assert!(text.contains("launch once GitHub is repaired"));
    }

    // ── implementation-note-487 tests ───────────────────────

    /// Integration-level: init_for_claude_code_autostarts_daemon_when_not_running
    ///
    /// Full end-to-end process spawn is not attempted here because it would
    /// require a real ember binary + keychain on the test host. It is marked
    /// #[ignore] for the real process-spawn variant (which the operator runs
    /// manually per T4 protocol).
    #[test]
    #[ignore = "T4 manual: requires real ember binary + keychain; run `ember daemon stop && ember init --for claude-code`"]
    fn init_for_claude_code_autostarts_daemon_when_not_running() {
        // Manual T4 invariant: with the daemon stopped, `ember init --for
        // claude-code` should:
        //   1. Detect live daemon absence.
        //   2. Call `install_agent` (or background spawn on unsupported platform).
        //   3. Print "started managed daemon service".
        //   4. Wait for the daemon's socket/RPC seam to become live (up to 5s).
        //   5. Proceed with persona + grant + settings.json patch.
        // Outcome: daemon is alive AND init completed successfully.
        unimplemented!("run manually: ember daemon stop && ember init --for claude-code")
    }

    // ── implementation-note-486 tests ───────────────────────

    /// LaunchAgent/systemd path is appropriate for a default user HOME with
    /// no --config override.
    #[test]
    fn supports_managed_daemon_install_true_for_default_home() {
        let home = std::path::PathBuf::from("/home/alice");
        assert!(supports_managed_daemon_install(&home, None));
    }

    /// `--config` (or `EMBER_CONFIG`) being set always disables the automatic
    /// managed-daemon install offer — the caller is running outside the
    /// canonical install topology.
    #[test]
    fn supports_managed_daemon_install_false_when_config_overridden() {
        let home = std::path::PathBuf::from("/home/alice");
        let config = std::path::PathBuf::from("/home/alice/custom/config.toml");
        assert!(!supports_managed_daemon_install(&home, Some(&config)));
    }

    /// HOME under `/tmp/` (T3 isolation pattern) must refuse the automatic
    /// managed-daemon install offer.
    #[test]
    fn supports_managed_daemon_install_false_for_tmp_home() {
        let home = std::path::PathBuf::from("/tmp/t3-1778351393");
        assert!(!supports_managed_daemon_install(&home, None));
    }

    /// macOS ephemeral HOMEs (`/var/folders/...`, `/private/var/...`,
    /// `/private/tmp/...`) also refuse the automatic managed-daemon offer.
    #[test]
    fn supports_managed_daemon_install_false_for_macos_ephemeral_homes() {
        for path in [
            "/var/folders/zz/qa-iso/T/abc",
            "/private/var/folders/zz/qa-iso/T/abc",
            "/private/tmp/qa-iso",
        ] {
            let home = std::path::PathBuf::from(path);
            assert!(
                !supports_managed_daemon_install(&home, None),
                "expected false for {path}"
            );
        }
    }

    /// Default timeout is 10s when the env override is unset or invalid.
    #[test]
    fn autostart_liveness_timeout_default_is_10() {
        // Serialize against the other EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS-
        // mutating test below; cargo's parallel runner would otherwise
        // interleave set/remove and produce test-order-dependent failures.
        let _g = crate::EMBER_DAEMON_AUTOSTART_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS").ok();
        // SAFETY: holds the test lock for the duration of the env
        // mutation; restored before return.
        unsafe { std::env::remove_var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS") };
        let secs = autostart_liveness_timeout_secs();
        if let Some(v) = prev {
            unsafe { std::env::set_var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS", v) };
        }
        assert_eq!(secs, 10);
    }

    /// Env override is honored when it parses as a positive integer.
    #[test]
    fn autostart_liveness_timeout_honors_env() {
        // Serialize against the other EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS-
        // mutating test above; same rationale.
        let _g = crate::EMBER_DAEMON_AUTOSTART_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS").ok();
        // SAFETY: holds the test lock for the duration of the env
        // mutation; restored before return.
        unsafe { std::env::set_var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS", "30") };
        let secs = autostart_liveness_timeout_secs();
        match prev {
            Some(v) => unsafe { std::env::set_var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS", v) },
            None => unsafe { std::env::remove_var("EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS") },
        }
        assert_eq!(secs, 30);
    }

    /// Manual T3 walk: init under isolated HOME now refuses to auto-install a
    /// managed daemon into the wrong topology. Marked #[ignore] so it doesn't
    /// run in CI — invoked manually by the operator per T3 protocol.
    #[test]
    #[ignore = "T3 manual: HOME=/tmp/t3-... target/release/ember init --for claude-code"]
    fn init_for_claude_code_refuses_managed_install_in_isolated_home() {
        // Manual T3 invariant: with an isolated HOME=/tmp/t3-..., `ember
        // init --for claude-code` should:
        //   1. Detect socket absence under $HOME/.ember/.
        //   2. Refuse the automatic managed-daemon install
        //      (supports_managed_daemon_install → false).
        //   3. Exit with a loud explanation that friendly init only supports
        //      the canonical default HOME/config topology.
        // Outcome: no same-uid daemon is spawned under the isolated HOME.
        unimplemented!(
            "run manually: HOME=/tmp/t3-XXX EMBER_KEYRING_SERVICE=... \
             target/release/ember init --for claude-code"
        )
    }

    /// Integration-level: init_for_claude_code_uses_existing_daemon_when_running
    ///
    /// Similarly stubbed for manual T4 run. The unit-level proxy is the
    /// daemon_socket_exists_true_when_file_present test above.
    #[test]
    #[ignore = "T4 manual: requires real ember binary + keychain; run with daemon already started"]
    fn init_for_claude_code_uses_existing_daemon_when_running() {
        // Manual T4 invariant: with the daemon running, `ember init --for
        // claude-code` should:
        //   1. Detect socket presence.
        //   2. Print "daemon already running (socket ...)".
        //   3. NOT attempt daemon-service autostart (no double-start).
        //   4. Proceed with persona + grant + settings.json patch.
        // Outcome: daemon still alive (same PID) AND init completed successfully.
        unimplemented!("run manually with daemon pre-started: ember init --for claude-code")
    }
}
