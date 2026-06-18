//! `ember init --for codex` and `ember uninstall --for codex` orchestration.
//!
//! Codex keeps its native login UX, but Ember can import that local
//! `~/.codex/auth.json` token blob into the managed vault (keyed by ChatGPT
//! account/subject under `openai/plan/chatgpt-oauth/<account>/<subject>`) and
//! bind the Codex persona to a brokered OpenAI Responses grant.

use std::fs;
use std::path::{Path, PathBuf};

use crate::onboarding::claude_code::InitError;

pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
pub const CODEX_DEFAULT_TEMPLATE: &str = include_str!("templates/codex_default_v1.toml");
pub const CODEX_OPENAI_PLAN_CREDENTIAL_PREFIX: &str = "openai/plan/chatgpt-oauth/";
pub const CODEX_OPENAI_PLAN_CREDENTIAL_PATTERN: &str =
    "openai/plan/chatgpt-oauth/<account>/<subject>";

pub fn default_grant_template_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?.join(".ember").join("grant-template-codex.toml"))
}

pub fn codex_persona_name() -> String {
    crate::launcher::default_persona_id_for_runtime("codex", None)
}

fn home_dir() -> Result<PathBuf, InitError> {
    dirs_next::home_dir().ok_or(InitError::NoHomeDir)
}

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
    fs::write(path, CODEX_DEFAULT_TEMPLATE).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

pub fn codex_auth_status_line() -> String {
    format!(
        "  Codex:    OpenAI auth is imported with consent into {CODEX_OPENAI_PLAN_CREDENTIAL_PATTERN}; use `codex login status` / `codex login --device-auth` before rerunning `ember init --for codex`"
    )
}

pub fn print_next_commands() {
    print_next_commands_with_ember_command("ember");
}

pub fn print_next_commands_with_ember_command(ember_cmd: &str) {
    print!("{}", next_commands_text(ember_cmd));
}

fn next_commands_text(ember_cmd: &str) -> String {
    format!(
        "\nNext steps:\n  {ember_cmd} init --for codex    # import Codex auth and refresh the brokered OpenAI grant\n  {ember_cmd} codex               # launch Codex with an Ember-managed session\n  codex login status        # check Codex's native login state if needed\n  codex login --device-auth # headless host sign-in if browser login is unavailable\n  {ember_cmd} receipt list        # find the receipt after the first brokered action\n\n`{ember_cmd} codex` is the launcher alias over `{ember_cmd} session open codex`.\nCodex login remains native, but `{ember_cmd} init --for codex` imports `~/.codex/auth.json` into `{CODEX_OPENAI_PLAN_CREDENTIAL_PATTERN}` with operator consent so model traffic can use Ember's brokered OpenAI Responses lane.\nIf the host is headless or browser sign-in is blocked, use `codex login --device-auth`; isolated `{ember_cmd} codex` keeps host auth live while routing mutable Codex state through per-session overlays.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_persona_name_uses_default_slot() {
        assert_eq!(codex_persona_name(), "codex-default");
    }

    #[test]
    fn template_contains_codex_id() {
        assert!(CODEX_DEFAULT_TEMPLATE.contains(r#"id = "codex-default-v1""#));
    }

    #[test]
    fn next_commands_text_uses_explicit_repo_build_ember_command_when_provided() {
        let text = next_commands_text("/home/operator/emberlink-example/target/debug/ember");
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember codex"));
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember init --for codex"));
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember receipt list"));
        assert!(text.contains(
            "`/home/operator/emberlink-example/target/debug/ember codex` is the launcher alias"
        ));
    }
}
