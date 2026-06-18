//! `ember init --for gemini` orchestration (ADR 215 §2).
//!
//! The Gemini CLI keeps its native "Sign in with Google" (Code Assist) login
//! UX, but Ember imports that local `~/.gemini/oauth_creds.json` blob into the
//! managed vault under the single fixed name `google/code-assist-oauth` and
//! binds the gemini persona to a brokered Google Code Assist grant. The durable
//! `refresh_token` then lives only in the vault (the daemon refreshes it
//! server-side); the launcher relocates `GEMINI_CLI_HOME` to a per-session dir
//! with a refresh-token-less copy so the child cannot reach the durable
//! credential.

use std::path::PathBuf;

/// TTL for the minted brokered Code Assist grant. Mirrors the codex lane (24h).
pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;

/// The single fixed vault credential name for the gemini Code Assist OAuth blob
/// (unlike codex's account/subject-keyed credential).
pub const GEMINI_CODE_ASSIST_CREDENTIAL: &str = "google/code-assist-oauth";

pub fn gemini_persona_name() -> String {
    crate::launcher::default_persona_id_for_runtime("gemini", None)
}

/// Path to the host Gemini CLI's OAuth credential blob: `$GEMINI_CLI_HOME/.gemini`
/// if set (the gemini-cli's `homedir()` honours `GEMINI_CLI_HOME`), else
/// `~/.gemini/oauth_creds.json`. `None` when no home dir can be resolved.
pub fn host_oauth_creds_path() -> Option<PathBuf> {
    let home = std::env::var_os("GEMINI_CLI_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(dirs_next::home_dir)?;
    Some(home.join(".gemini").join("oauth_creds.json"))
}

pub fn gemini_auth_status_line() -> String {
    format!(
        "  Gemini:   Google Code Assist auth is imported with consent into {GEMINI_CODE_ASSIST_CREDENTIAL}; run `gemini` once and choose \"Login with Google\" before rerunning `ember init --for gemini`"
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
        "\nNext steps:\n  {ember_cmd} init --for gemini   # import Gemini Code Assist auth and refresh the brokered Google grant\n  {ember_cmd} gemini              # launch the Gemini CLI with an Ember-managed session\n  {ember_cmd} receipt list        # find the receipt after the first brokered action\n\n`{ember_cmd} gemini` is the launcher alias over `{ember_cmd} session open gemini`.\nGemini login remains native, but `{ember_cmd} init --for gemini` imports `~/.gemini/oauth_creds.json` into `{GEMINI_CODE_ASSIST_CREDENTIAL}` with operator consent so model traffic can use Ember's brokered Google Code Assist lane. The durable refresh token stays daemon-only; `{ember_cmd} gemini` relocates GEMINI_CLI_HOME with a refresh-token-less copy.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_persona_name_uses_default_slot() {
        assert_eq!(gemini_persona_name(), "gemini-default");
    }

    #[test]
    fn next_commands_text_uses_explicit_repo_build_ember_command_when_provided() {
        let text = next_commands_text("/home/operator/emberlink-example/target/debug/ember");
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember gemini"));
        assert!(text.contains("/home/operator/emberlink-example/target/debug/ember init --for gemini"));
        assert!(text.contains("the launcher alias"));
    }

    #[test]
    fn host_oauth_creds_path_ends_in_gemini_oauth_creds() {
        // Whatever the home resolution, the tail is stable.
        if let Some(p) = host_oauth_creds_path() {
            assert!(p.ends_with(".gemini/oauth_creds.json"));
        }
    }
}
