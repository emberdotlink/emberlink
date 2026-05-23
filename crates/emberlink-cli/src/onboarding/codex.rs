//! `ember init --for codex` and `ember uninstall --for codex` orchestration.
//!
//! Codex differs from Claude Code in one important way: Codex keeps its own
//! OpenAI auth/login lane. Ember can broker the session, tool path, and audit
//! surface, but it does not currently own Codex model auth.

use std::fs;
use std::path::{Path, PathBuf};

use crate::onboarding::claude_code::InitError;
use crate::onboarding::settings_patch::{
    EMBER_PROXY_HOOK_COMMAND, PatchError, add_command_hook, remove_command_hook,
};

pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
pub const CODEX_SHELL_HOOK_MATCHER: &str = "shell_command|exec_command|unified_exec";
pub const CODEX_HOOK_REVIEW_HINT: &str =
    "  /hooks                 # approve Ember's hook inside Codex if it asks for review";
pub const CODEX_DEFAULT_TEMPLATE: &str =
    include_str!("../../../core-policy/src/templates/codex_default_v1.toml");

pub fn default_grant_template_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?.join(".ember").join("grant-template-codex.toml"))
}

pub fn default_hooks_json_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?.join(".codex").join("hooks.json"))
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

pub fn patch_codex_hooks_file(path: &Path) -> Result<bool, InitError> {
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
    let changed = add_command_hook(
        &mut value,
        "PreToolUse",
        CODEX_SHELL_HOOK_MATCHER,
        EMBER_PROXY_HOOK_COMMAND,
    )?;
    if !changed {
        return Ok(false);
    }
    let serialized = serde_json::to_string_pretty(&value)?;
    fs::write(path, serialized).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

pub fn unpatch_codex_hooks_file(path: &Path) -> Result<bool, InitError> {
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
    let changed = remove_command_hook(&mut value, "PreToolUse", EMBER_PROXY_HOOK_COMMAND)?;
    if !changed {
        return Ok(false);
    }
    let serialized = serde_json::to_string_pretty(&value)?;
    fs::write(path, serialized).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

pub fn codex_auth_status_line() -> &'static str {
    "  Codex:    auth remains managed by Codex itself (`codex login status` / `codex login` / `codex login --device-auth`)"
}

pub fn print_next_commands() {
    println!();
    println!("Next steps:");
    println!("  ember codex              # launch Codex with an Ember-managed session");
    println!("  codex login status       # check Codex's own auth state if needed");
    println!("  codex login --device-auth  # headless host sign-in if browser login is unavailable");
    println!("{CODEX_HOOK_REVIEW_HINT}");
    println!("  ember receipt show       # inspect the signed audit trail");
    println!();
    println!("`ember codex` is the launcher alias over `ember session open codex`.");
    println!(
        "The session + tool path are brokered by Ember; Codex's own OpenAI auth remains on Codex's native login lane."
    );
    println!(
        "If the host is headless or browser sign-in is blocked, use `codex login --device-auth`; isolated `ember codex` reuses the host `~/.codex` auth state."
    );
    println!(
        "On first launch, Codex may require hook review before PreToolUse commands can run; if prompted, open `/hooks` and approve the Ember hook."
    );
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
    fn hook_review_hint_mentions_hooks_command() {
        assert!(CODEX_HOOK_REVIEW_HINT.contains("/hooks"));
    }

    #[test]
    fn patch_codex_hooks_file_adds_shell_matcher_block() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".codex").join("hooks.json");
        let changed = patch_codex_hooks_file(&path).expect("patch hooks");
        assert!(changed);
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            crate::onboarding::settings_patch::has_command_hook(
                &value,
                "PreToolUse",
                CODEX_SHELL_HOOK_MATCHER,
                EMBER_PROXY_HOOK_COMMAND
            ),
            "codex shell matcher hook must be installed"
        );
    }

    #[test]
    fn unpatch_codex_hooks_file_preserves_unrelated_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".codex").join("hooks.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": CODEX_SHELL_HOOK_MATCHER,
                            "hooks": [
                                {"type": "command", "command": EMBER_PROXY_HOOK_COMMAND}
                            ]
                        },
                        {
                            "matcher": "imagegen",
                            "hooks": [
                                {"type": "command", "command": "echo keep-me"}
                            ]
                        }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let changed = unpatch_codex_hooks_file(&path).expect("unpatch hooks");
        assert!(changed);
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let blocks = value
            .pointer("/hooks/PreToolUse")
            .and_then(|v| v.as_array())
            .expect("PreToolUse blocks");
        assert!(blocks.iter().any(|block| {
            block.get("matcher").and_then(|v| v.as_str()) == Some("imagegen")
        }));
        assert!(!blocks.iter().any(|block| {
            block.get("matcher").and_then(|v| v.as_str()) == Some(CODEX_SHELL_HOOK_MATCHER)
        }));
    }
}
