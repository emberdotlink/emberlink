//! EMBER_OVERRIDE_SHADOW
//! CLASSIFICATION: PUBLIC
//! Override pattern for agent-container bind-mount source paths.
//!
//! ADR 166 Component 3 — container-resident agents bind-mount host Constructs
//! plus the Claude binary into the worker container at well-known target
//! paths. In
//! production these sources are fixed paths on the host (`~/.ember/shadow/bin`
//! for the Construct library and `/usr/local/bin/claude` for the Claude
//! binary). During dev iteration, multi-version testing, or canary promotion
//! it is useful to redirect those sources without modifying the compose
//! template or the daemon configuration.
//!
//! The two env vars `EMBER_OVERRIDE_SHADOW` and `EMBER_OVERRIDE_CLAUDE`
//! redirect the bind-mount source paths at render time. The template
//! (`crates/emberlink-cli/templates/compose.yml.j2`) picks them up via Jinja2
//! variables `ember_override_shadow` / `ember_override_claude`.
//!
//! Overrides are never silent: `status_banner` returns a one-line string that
//! must be printed to the operator before the compose stack is started.

use std::env;
use std::path::{Path, PathBuf};

/// Env-var-sourced bind-mount source overrides.
#[derive(Debug, Default)]
pub struct Overrides {
    /// Override for the shadow-bin bind-mount source path.
    /// Corresponds to `EMBER_OVERRIDE_SHADOW`.
    pub shadow: Option<PathBuf>,
    /// Override for the Claude binary bind-mount source path.
    /// Corresponds to `EMBER_OVERRIDE_CLAUDE`.
    pub claude: Option<PathBuf>,
}

/// Errors produced by [`validate`].
#[derive(Debug, thiserror::Error)]
pub enum OverrideError {
    /// The path lies outside `$HOME`.
    #[error("override path must be inside $HOME")]
    OutsideHome,
    /// The file name starts with `--`, which looks like a CLI flag.
    #[error("override path file name must not start with `--`")]
    ArgvLookalike,
    /// The path is a symlink whose canonicalized target is outside `$HOME`.
    #[error("override symlink target escapes $HOME")]
    SymlinkEscapes,
    /// `$HOME` is not set in the environment.
    #[error("$HOME is not set; cannot validate override path")]
    NoHomeEnv,
}

/// Read `EMBER_OVERRIDE_SHADOW` and `EMBER_OVERRIDE_CLAUDE` from the environment.
///
/// Missing variables produce `None`; present variables are stored as `PathBuf`
/// without any validation. Call [`validate`] on each non-None path before use.
pub fn read_from_env() -> Overrides {
    Overrides {
        shadow: env::var_os("EMBER_OVERRIDE_SHADOW").map(PathBuf::from),
        claude: env::var_os("EMBER_OVERRIDE_CLAUDE").map(PathBuf::from),
    }
}

/// Validate an override path.
///
/// Rules (in order):
/// 1. `$HOME` must be set — returns [`OverrideError::NoHomeEnv`] if absent.
/// 2. The file name must not begin with `--` — returns [`OverrideError::ArgvLookalike`].
/// 3. If the path is a symlink, canonicalize the target and verify it is
///    inside `$HOME` — returns [`OverrideError::SymlinkEscapes`] when the
///    target is provably outside `$HOME`. If canonicalization fails the
///    symlink is accepted (cannot prove it escapes).
/// 4. The path (or, for symlinks, the un-canonicalized path itself) must
///    start with `$HOME` — returns [`OverrideError::OutsideHome`].
pub fn validate(p: &Path) -> Result<(), OverrideError> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(OverrideError::NoHomeEnv)?;

    // Rule 2: argv lookalike guard.
    if let Some(name) = p.file_name() {
        let name_str = name.to_string_lossy();
        if name_str.starts_with("--") {
            return Err(OverrideError::ArgvLookalike);
        }
    }

    // Rule 3 + 4: symlink resolution.
    if p.is_symlink()
        && let Ok(canonical) = p.canonicalize()
    {
        if !canonical.starts_with(&home) {
            return Err(OverrideError::SymlinkEscapes);
        }
        // Symlink target is inside $HOME — accept.
        return Ok(());
        // Canonicalization failed; fall through to the plain starts_with check.
    }

    // Rule 4: plain path must be inside $HOME.
    if !p.starts_with(&home) {
        return Err(OverrideError::OutsideHome);
    }

    Ok(())
}

/// Return an operator-visible status banner when any override is active.
///
/// Returns `None` when both fields are `None` (no overrides). When at least
/// one field is `Some`, returns a single line suitable for printing to stdout
/// before the compose stack is started, ensuring the substitution is never
/// silent.
pub fn status_banner(o: &Overrides) -> Option<String> {
    if o.shadow.is_none() && o.claude.is_none() {
        return None;
    }
    let shadow_str = o
        .shadow
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<default>".to_string());
    let claude_str = o
        .claude
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<default>".to_string());
    Some(format!(
        "ember-up: shadow={shadow_str} claude={claude_str} (override active)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_from_env_returns_none_when_unset() {
        // Remove both vars for this test, then restore.
        let shadow_was = env::var_os("EMBER_OVERRIDE_SHADOW");
        let claude_was = env::var_os("EMBER_OVERRIDE_CLAUDE");

        // SAFETY: single-threaded test context.
        unsafe {
            env::remove_var("EMBER_OVERRIDE_SHADOW");
            env::remove_var("EMBER_OVERRIDE_CLAUDE");
        }

        let o = read_from_env();
        assert!(o.shadow.is_none(), "shadow must be None when var unset");
        assert!(o.claude.is_none(), "claude must be None when var unset");

        // Restore.
        unsafe {
            if let Some(v) = shadow_was {
                env::set_var("EMBER_OVERRIDE_SHADOW", v);
            }
            if let Some(v) = claude_was {
                env::set_var("EMBER_OVERRIDE_CLAUDE", v);
            }
        }
    }

    #[test]
    fn validate_rejects_path_outside_home() {
        // Temporarily set $HOME to a known directory.
        let old_home = env::var_os("HOME");
        unsafe { env::set_var("HOME", "/home/user") };

        let result = validate(Path::new("/etc/passwd"));
        assert!(
            matches!(result, Err(OverrideError::OutsideHome)),
            "expected OutsideHome, got {result:?}"
        );

        unsafe {
            match old_home {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn validate_rejects_argv_lookalike() {
        let old_home = env::var_os("HOME");
        unsafe { env::set_var("HOME", "/home/user") };

        let result = validate(Path::new("/home/user/--bad-path"));
        assert!(
            matches!(result, Err(OverrideError::ArgvLookalike)),
            "expected ArgvLookalike, got {result:?}"
        );

        unsafe {
            match old_home {
                Some(v) => env::set_var("HOME", v),
                None => env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn status_banner_present_when_any_set() {
        let o = Overrides {
            shadow: Some(PathBuf::from("/home/user/.ember/shadow/bin")),
            claude: None,
        };
        let banner = status_banner(&o);
        assert!(banner.is_some(), "banner must be Some when shadow is set");
        let s = banner.unwrap();
        assert!(
            s.contains("override active"),
            "banner must contain 'override active': {s}"
        );
        assert!(
            s.contains("/home/user/.ember/shadow/bin"),
            "banner must contain the shadow path: {s}"
        );
        assert!(
            s.contains("<default>"),
            "banner must show <default> for unset claude: {s}"
        );
    }
}
