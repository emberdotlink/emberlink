//! `ember init --for claude` and `ember uninstall --for claude`
//! orchestration (COHORT-A-1-INIT-FLOW).
//!
//! Per ADR 120 §2 / §3: a one-command first-run setup that wires Claude Code
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
//!   4. GitHub fallback guidance: keep the HTTPS/App lane as canonical.
//!      The degraded `github-pat` lane remains available later through
//!      `ember vault add --name github-pat`, but init no longer captures
//!      PATs interactively.
//!   5. Print the next two commands per ADR 120 §2:
//!      `ember claude` and `ember receipt list`.
//!
//! The brokered Claude session's `permissions.deny` overlay is authored
//! per-Construct in each `construct.toml`'s `[settings_overlay]` block
//! and unioned by the launcher into a fresh overlay `settings.json` in a
//! relocated `CLAUDE_CONFIG_DIR` (V030-CLAUDE-OVERLAY). The operator's
//! bare `~/.claude/settings.json` is never mutated by `ember init` or
//! `ember uninstall`. Operators who ran the pre-V030 init flow may have
//! residual deny entries in bare; those are harmless duplicates against
//! the launcher overlay and can be removed by hand if desired.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default 24-hour grant TTL per ADR 120 §3.
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

/// Embedded grant scope template (ADR 120 §3 / γ). The canonical default
/// scope template lives alongside this onboarding code at
/// `onboarding/templates/claude_code_default_v1.toml`.
pub const CLAUDE_CODE_DEFAULT_TEMPLATE: &str =
    include_str!("templates/claude_code_default_v1.toml");

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
/// COHORT-A-V03-T3-FIX-LAUNCHER-PERSONA-DEFAULT-V2 anchor: routes
/// through `default_persona_id_for_runtime` so launcher + init agree on
/// the same persona-id shape.
pub fn claude_code_persona_name() -> String {
    crate::launcher::default_persona_id_for_runtime("claude-code", None)
}

/// Install or repair the managed production shadow toolchain under
/// `~/.ember/shadow/bin/`.
///
/// This is the init-time repair seam for operator/friendly hosts:
/// the launcher and host-proof both expect `gh` / `git` shims to resolve
/// through the installed product construct bundle rather than repo-local
/// `target/...` artifacts.
pub fn install_managed_prod_shadow_path() -> Result<PathBuf, String> {
    install_managed_prod_shadow_path_inner()
}

fn install_managed_prod_shadow_path_inner() -> Result<PathBuf, String> {
    let shadow_root = home_dir()
        .map_err(|e| e.to_string())?
        .join(".ember")
        .join("shadow");
    let specs = crate::launcher::claude_code::managed_prod_construct_specs();
    if !crate::launcher::claude_code::prod_required_constructs_present(&specs) {
        return Err(
            "managed product construct bundle is incomplete: expected installed `ember-gh` and `ember-git`, not repo-built target artifacts".to_string(),
        );
    }
    if let Some(verified) =
        crate::launcher::claude_code::verify_construct_manifest_before_spawn(&specs)
            .map_err(|e| format!("manifest trust gate on {}: {e}", shadow_root.display()))?
    {
        crate::launcher::claude_code::install_verified_path_shadow(&shadow_root, &verified)
            .map_err(|e| format!("io error on {}: {e}", shadow_root.display()))?;
    } else {
        crate::launcher::path_shadow::install_path_shadow(&shadow_root, &specs)
            .map_err(|e| format!("io error on {}: {e}", shadow_root.display()))?;
    }
    Ok(shadow_root)
}

/// Resolve the user's home directory. Wraps `dirs_next::home_dir`.
fn home_dir() -> Result<PathBuf, InitError> {
    dirs_next::home_dir().ok_or(InitError::NoHomeDir)
}

/// Public surface of [`home_dir`] used by the `cmd_migrate_path_shadow_layout`
/// CLI handler so the binary doesn't have to depend on `dirs_next` directly.
/// META-AP-SHADOW-PATH-MIGRATE-CLI-FLAG.
pub fn home_dir_for_migrate() -> Result<PathBuf, String> {
    home_dir().map_err(|e| e.to_string())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherBoundaryNote {
    pub detail: String,
    pub repair_guidance: String,
}

pub fn print_next_commands_with_launcher_boundary(
    posture: GitHubOnboardingPosture,
    launcher_boundary: Option<&LauncherBoundaryNote>,
) {
    print_next_commands_with_launcher_boundary_and_ember_command(
        posture,
        launcher_boundary,
        "ember",
    );
}

pub fn print_next_commands_with_launcher_boundary_and_ember_command(
    posture: GitHubOnboardingPosture,
    launcher_boundary: Option<&LauncherBoundaryNote>,
    ember_cmd: &str,
) {
    print!(
        "{}",
        next_commands_with_launcher_boundary_text(posture, launcher_boundary, ember_cmd)
    );
}

fn next_commands_text(posture: GitHubOnboardingPosture) -> String {
    next_commands_text_with_ember_command(posture, "ember")
}

fn next_commands_text_with_ember_command(
    posture: GitHubOnboardingPosture,
    ember_cmd: &str,
) -> String {
    let mut lines = vec![String::new(), "Next steps:".to_string()];
    match posture {
        GitHubOnboardingPosture::AppConfiguredReal => {
            lines.push(format!(
                "  {ember_cmd} claude             # launch Claude with this grant (recommended)"
            ));
            lines.push(format!(
                "  {ember_cmd} receipt list       # find the receipt after the first brokered action"
            ));
        }
        GitHubOnboardingPosture::PatConfigured => {
            lines.push(format!(
                "  {ember_cmd} claude             # launch now on the degraded PAT lane"
            ));
            lines.push(format!(
                "  {ember_cmd} github setup       # upgrade to the real App lane when ready"
            ));
            lines.push(format!(
                "  {ember_cmd} receipt list       # find the receipt after the first brokered action"
            ));
        }
        GitHubOnboardingPosture::AppBroken(_) => {
            lines.push(format!(
                "  {ember_cmd} github setup       # repair or replace the local App credential triple"
            ));
            lines.push(format!(
                "  {ember_cmd} github status      # confirm the App lane is healthy"
            ));
            lines.push(format!(
                "  {ember_cmd} claude             # launch once GitHub is repaired"
            ));
        }
        GitHubOnboardingPosture::AppConfiguredMock | GitHubOnboardingPosture::AppNotConfigured => {
            lines.push(format!(
                "  {ember_cmd} github setup       # register PEM + App ID + installation URL/ID + slug"
            ));
            lines.push(format!(
                "  {ember_cmd} github status      # confirm the App lane is ready"
            ));
            lines.push(format!(
                "  {ember_cmd} claude             # launch once GitHub is configured"
            ));
        }
    }
    lines.push(String::new());
    lines.push("About the launcher".to_string());
    lines.push("------------------".to_string());
    lines.push(format!(
        "`{ember_cmd} claude` is the managed v0.3.0 launcher. It opens a fresh session,"
    ));
    lines.push(
        "attaches a scoped grant, and keeps audit plus revocation on the supported path."
            .to_string(),
    );
    lines.push(String::new());
    lines.push(
        "Use that path first. Bare `claude` and headless automation remain advanced".to_string(),
    );
    lines.push("surfaces, but they are intentionally outside the friendly default.".to_string());
    lines.join("\n") + "\n"
}

fn next_commands_with_launcher_boundary_text(
    posture: GitHubOnboardingPosture,
    launcher_boundary: Option<&LauncherBoundaryNote>,
    ember_cmd: &str,
) -> String {
    let mut out = next_commands_text_with_ember_command(posture, ember_cmd);
    if let Some(note) = launcher_boundary {
        out.push('\n');
        out.push_str("Host launcher boundary\n");
        out.push_str("----------------------\n");
        let _ = writeln!(out, "Installed host launcher: {}", note.detail);
        let _ = writeln!(out, "Repair first: {}", note.repair_guidance);
    }
    out
}

/// Render GitHub onboarding guidance for the current posture.
///
/// For `v0.3.0`, init keeps the App lane as the canonical onboarding path.
/// The degraded `github-pat` lane remains available later via
/// `ember vault add --name github-pat`, but we do not teach that fallback as
/// part of the first-run path when the App lane is simply not configured yet.
pub fn render_github_onboarding_guidance(posture: GitHubOnboardingPosture) -> String {
    render_github_onboarding_guidance_with_ember_command(posture, "ember")
}

pub fn render_github_onboarding_guidance_with_ember_command(
    posture: GitHubOnboardingPosture,
    ember_cmd: &str,
) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str("GitHub access:\n");

    match posture {
        GitHubOnboardingPosture::AppConfiguredReal => {
            out.push_str("  Ready: GitHub App broker configured for the HTTPS/API lane.\n");
            let _ = writeln!(
                out,
                "  `{ember_cmd} claude` will use short-lived installation tokens there."
            );
        }
        GitHubOnboardingPosture::PatConfigured => {
            out.push_str("  Degraded PAT fallback is configured today.\n");
            let _ = writeln!(
                out,
                "  Preferred fix: run `{ember_cmd} github setup` to move onto the App lane."
            );
            out.push_str("  Until then, gh/git will attribute through your GitHub identity.\n");
        }
        GitHubOnboardingPosture::AppConfiguredMock => {
            out.push_str("  Not ready: this daemon only has a mock GitHub broker right now.\n");
            let _ = writeln!(
                out,
                "  Run `{ember_cmd} github setup` to register the real App credential triple."
            );
            out.push_str("  Have these ready: private key PEM, App ID, installation URL or ID, and App slug.\n");
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
        GitHubOnboardingPosture::AppBroken(detail) => {
            out.push_str("  Broken: this daemon has local GitHub authority configured, but it is not usable yet.\n");
            let _ = writeln!(out, "  Detail: {detail}");
            let _ = writeln!(
                out,
                "  Repair path: run `{ember_cmd} github setup` again to replace or complete the credential triple."
            );
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
        GitHubOnboardingPosture::AppNotConfigured => {
            out.push_str(
                "  Not ready: this daemon does not have a real GitHub App broker configured yet.\n",
            );
            let _ = writeln!(
                out,
                "  Run `{ember_cmd} github setup` to register the App credential triple."
            );
            out.push_str("  Have these ready: private key PEM, App ID, installation URL or ID, and App slug.\n");
            out.push_str("  The friendly v0.3.0 path is HTTPS/App first.\n");
        }
    }

    out
}

/// Print GitHub onboarding guidance for the current posture.
pub fn print_github_onboarding_guidance(posture: GitHubOnboardingPosture) -> io::Result<()> {
    print_github_onboarding_guidance_with_ember_command(posture, "ember")
}

pub fn print_github_onboarding_guidance_with_ember_command(
    posture: GitHubOnboardingPosture,
    ember_cmd: &str,
) -> io::Result<()> {
    eprint!(
        "{}",
        render_github_onboarding_guidance_with_ember_command(posture, ember_cmd)
    );
    Ok(())
}

/// Decide whether the autostart path should install a LaunchAgent / systemd
/// user unit, or fall back to a raw `--background` daemon spawn.
///
/// COHORT-A-V03-T3-FIX-AUTOSTART-HONOR-HOME: the LaunchAgent / systemd-user
/// path is correct for the canonical "production user" install (single
/// always-up daemon per login session) — but it baked an absolute `~/.ember/`
/// path resolved against the operator's *real* HOME at install time, so an
/// `init --for claude` invocation under an isolated `HOME=/tmp/...`
/// would write a service file pointing at the production socket while the
/// Returns `true` only when the invocation is running in the canonical
/// friendly-install topology:
///   - `home` looks like a default user home (not `/tmp/`, `/var/folders/`,
///     `/private/var/`), AND
///   - `config` is `None` (no `--config` / `EMBER_CONFIG` override).
///
/// `ember init` and `ember init --for claude` may only offer to run the
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
/// 10s default (raised from 5s in COHORT-A-V03-T3-FIX-AUTOSTART-HONOR-HOME
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
    pub gh_pat_stored: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persona_name_uses_2_slot_default_shape() {
        // COHORT-A-V03-T3-FIX-LAUNCHER-PERSONA-DEFAULT-V2: the default
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
    fn github_guidance_uses_explicit_repo_build_ember_command_when_provided() {
        let app_ready = render_github_onboarding_guidance_with_ember_command(
            GitHubOnboardingPosture::AppConfiguredReal,
            "/home/operator/emberlink-example/target/debug/ember",
        );
        assert!(app_ready.contains(
            "`/home/operator/emberlink-example/target/debug/ember claude` will use short-lived installation tokens there."
        ));

        let app_setup = render_github_onboarding_guidance_with_ember_command(
            GitHubOnboardingPosture::AppNotConfigured,
            "/home/operator/emberlink-example/target/debug/ember",
        );
        assert!(app_setup.contains(
            "Run `/home/operator/emberlink-example/target/debug/ember github setup` to register the App credential triple."
        ));
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
                "`ember claude` is the managed v0.3.0 launcher. It opens a fresh session,"
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

    #[test]
    fn next_commands_text_surfaces_launcher_boundary_when_present() {
        let text = next_commands_with_launcher_boundary_text(
            GitHubOnboardingPosture::AppConfiguredReal,
            Some(&LauncherBoundaryNote {
                detail: "/usr/local/bin/ember -> /usr/local/lib/ember.app/Contents/MacOS/ember (older than managed runtime surface: /usr/local/bin/emberd)".to_string(),
                repair_guidance: "Repair the installed `ember` launcher path first: /usr/local/bin/ember is older than the managed daemon/construct binaries on this host. Reinstall the managed CLI artifact or release package so `/usr/local/bin/ember` matches the runtime surface. `sudo ember daemon install` refreshes daemon/runtime sidecars, but it does not rebuild `/usr/local/lib/ember.app`.".to_string(),
            }),
            "ember",
        );
        assert!(text.contains("Host launcher boundary"));
        assert!(text.contains("Installed host launcher: /usr/local/bin/ember ->"));
        assert!(text.contains("does not rebuild `/usr/local/lib/ember.app`"));
    }

    #[test]
    fn next_commands_text_uses_explicit_repo_build_ember_command_when_provided() {
        let text = next_commands_with_launcher_boundary_text(
            GitHubOnboardingPosture::AppConfiguredReal,
            None,
            "/home/operator/emberlink-example/target/debug/ember",
        );
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember claude"));
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember receipt list"));
        assert!(text.contains(
            "`/home/operator/emberlink-example/target/debug/ember claude` is the managed v0.3.0 launcher."
        ));
    }

    // ── COHORT-A-V03-T3-FIX-INIT-DAEMON-ORDERING tests ───────────────────────

    /// Integration-level: init_for_claude_code_autostarts_daemon_when_not_running
    ///
    /// Full end-to-end process spawn is not attempted here because it would
    /// require a real ember binary + keychain on the test host. It is marked
    /// #[ignore] for the real process-spawn variant (which the operator runs
    /// manually per T4 protocol).
    #[test]
    #[ignore = "T4 manual: requires real ember binary + keychain; run `ember daemon stop && ember init --for claude`"]
    fn init_for_claude_code_autostarts_daemon_when_not_running() {
        // Manual T4 invariant: with the daemon stopped, `ember init --for
        // claude` should:
        //   1. Detect live daemon absence.
        //   2. Call `install_agent` (or background spawn on unsupported platform).
        //   3. Print "started managed daemon service".
        //   4. Wait for the daemon's socket/RPC seam to become live (up to 5s).
        //   5. Proceed with persona + grant + settings.json patch.
        // Outcome: daemon is alive AND init completed successfully.
        unimplemented!("run manually: ember daemon stop && ember init --for claude")
    }

    // ── COHORT-A-V03-T3-FIX-AUTOSTART-HONOR-HOME tests ───────────────────────

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
    #[ignore = "T3 manual: HOME=/tmp/t3-... target/release/ember init --for claude"]
    fn init_for_claude_code_refuses_managed_install_in_isolated_home() {
        // Manual T3 invariant: with an isolated HOME=/tmp/t3-..., `ember
        // init --for claude` should:
        //   1. Detect socket absence under $HOME/.ember/.
        //   2. Refuse the automatic managed-daemon install
        //      (supports_managed_daemon_install → false).
        //   3. Exit with a loud explanation that friendly init only supports
        //      the canonical default HOME/config topology.
        // Outcome: no same-uid daemon is spawned under the isolated HOME.
        unimplemented!(
            "run manually: HOME=/tmp/t3-XXX EMBER_KEYRING_SERVICE=... \
             target/release/ember init --for claude"
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
        // claude` should:
        //   1. Detect socket presence.
        //   2. Print "daemon already running (socket ...)".
        //   3. NOT attempt daemon-service autostart (no double-start).
        //   4. Proceed with persona + grant + settings.json patch.
        // Outcome: daemon still alive (same PID) AND init completed successfully.
        unimplemented!("run manually with daemon pre-started: ember init --for claude")
    }
}
