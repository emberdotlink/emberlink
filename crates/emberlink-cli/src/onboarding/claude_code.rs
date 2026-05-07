//! `ember init --for claude-code` and `ember uninstall --for claude-code`
//! orchestration (implementation-note-108).
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
//!   5. Optional GH PAT capture: prompt the user; if accepted, run
//!      `gh auth token` in-process and pipe the value directly into the
//!      vault as `github-pat`. The token never crosses a visible-shell
//!      boundary.
//!   6. Print the next two commands per design §2:
//!      `ember claude-code` and `ember receipt show`.
//!
//! The uninstall flow reverses (4) by removing only the lines we added; the
//! other artifacts (persona, grant, vault entry) are intentionally left in
//! place because they may be in use by other tools.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::onboarding::settings_patch::{
    add_pretooluse_hook, has_pretooluse_hook, remove_pretooluse_hook, PatchError,
};

/// Default 24-hour grant TTL per design §3.
pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;

/// Vault credential name used for the captured GitHub PAT.
pub const GH_PAT_VAULT_NAME: &str = "github-pat";

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

/// Compute the default persona name for cohort A: `claude-code-{hostname}`.
/// Falls back to `claude-code-localhost` if the hostname can't be resolved.
pub fn claude_code_persona_name() -> String {
    let raw = current_hostname().unwrap_or_else(|| "localhost".to_string());
    // Sanitize: lowercase, keep `[a-z0-9-]`, collapse runs of other chars
    // into `-`. Personas are user-visible, so a clean slug is friendlier.
    let mut slug = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let lc = ch.to_ascii_lowercase();
        if lc.is_ascii_alphanumeric() || lc == '-' {
            slug.push(lc);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let trimmed = slug.trim_matches('-');
    let final_slug = if trimmed.is_empty() {
        "localhost"
    } else {
        trimmed
    };
    format!("claude-code-{final_slug}")
}

/// Resolve the user's home directory. Wraps `dirs_next::home_dir`.
fn home_dir() -> Result<PathBuf, InitError> {
    dirs_next::home_dir().ok_or(InitError::NoHomeDir)
}

/// Best-effort hostname resolution. Returns `None` if the platform call
/// fails or the result isn't valid UTF-8. Intentionally permissive — the
/// caller has a fallback.
fn current_hostname() -> Option<String> {
    // libc's gethostname is portable; we keep this dep-free by reading
    // the `HOSTNAME` env var first (set on most shells) and falling back
    // to `uname -n` via `nix`-style direct syscall through `std`. Since
    // we don't have `hostname` in deps, env-var-only is acceptable.
    if let Ok(h) = std::env::var("HOSTNAME")
        && !h.is_empty()
    {
        return Some(h);
    }
    // Try `nodename` from `uname -n` shape — the `command -v hostname`
    // shell-out is intentionally avoided (we'd just return None and use
    // the fallback). On macOS / Linux, `HOST` is sometimes set instead.
    if let Ok(h) = std::env::var("HOST")
        && !h.is_empty()
    {
        return Some(h);
    }
    None
}

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

/// Print the next two commands per design §2 to stdout. Single point of
/// truth so the wording stays in sync between `init` success and any other
/// output paths that want to nudge the user forward.
pub fn print_next_commands() {
    println!();
    println!("Next steps:");
    println!("  ember claude-code        # launch Claude Code with this grant");
    println!("  ember receipt show       # see the audit trail of the grant");
}

/// Interactive GH PAT prompt. If the user types a non-empty string, returns
/// `Some(value)`. If the user hits enter on an empty line, returns `None`.
/// Writes the prompt to stderr so stdout stays clean for callers that
/// pipe `ember init` output.
///
/// **Security note:** the value never appears in any subprocess argv or
/// environment. The intended caller writes it directly to the vault via
/// the in-process `Vault::add` API.
///
/// Stub limitation per the brief: today the user pastes the value
/// directly. A future revision can shell out to `gh auth token` in-process
/// and pipe the bytes — but that requires a `Command::output()` call with
/// careful buffer handling, which we defer to keep the implementation-note-116 surface
/// minimal. The `ember vault add --stdin` path is the same shape.
pub fn prompt_for_gh_pat(stdin_is_terminal: bool) -> io::Result<Option<String>> {
    if !stdin_is_terminal {
        // Non-interactive context (CI, scripted) — skip the prompt. The
        // user can re-run with a PAT in env or call `ember vault add
        // github-pat` separately.
        return Ok(None);
    }
    eprintln!();
    eprintln!("Optional: paste your GitHub PAT to enable repository access.");
    eprintln!("(or hit enter to skip — you can run `ember vault add github-pat` later)");
    eprint!("PAT: ");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
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
    fn persona_name_uses_hostname_when_set() {
        let prev = std::env::var("HOSTNAME").ok();
        // Safety: tests run single-threaded under cargo's default harness for
        // this isolated env mutation; the value is restored at end-of-test.
        unsafe { std::env::set_var("HOSTNAME", "alice-laptop") };
        let name = claude_code_persona_name();
        match prev {
            Some(v) => unsafe { std::env::set_var("HOSTNAME", v) },
            None => unsafe { std::env::remove_var("HOSTNAME") },
        }
        assert_eq!(name, "claude-code-alice-laptop");
    }

    #[test]
    fn persona_name_sanitizes_special_chars() {
        let prev = std::env::var("HOSTNAME").ok();
        unsafe { std::env::set_var("HOSTNAME", "Alice.M1.local") };
        let name = claude_code_persona_name();
        match prev {
            Some(v) => unsafe { std::env::set_var("HOSTNAME", v) },
            None => unsafe { std::env::remove_var("HOSTNAME") },
        }
        // Dots collapse into a single dash; case lowered.
        assert_eq!(name, "claude-code-alice-m1-local");
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
            pretooluse[0]
                .pointer("/hooks/0/command")
                .unwrap()
                .as_str(),
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
    fn prompt_returns_none_when_stdin_not_terminal() {
        // No real prompt fired — non-interactive returns None.
        let result = prompt_for_gh_pat(false).unwrap();
        assert!(result.is_none());
    }
}
