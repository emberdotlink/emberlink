//! `ember init --for cursor` orchestration.
//!
//! Cursor baseline launch is intentionally not a governed model-auth lane:
//! Cursor account/model auth remains Cursor-owned. This module provisions only
//! the Ember runtime persona, local-only launcher grant, and operator guidance
//! needed for the host launcher to register sessions.

use std::fs;
use std::path::{Path, PathBuf};

use crate::onboarding::claude_code::InitError;

pub const DEFAULT_GRANT_TTL_SECS: u64 = 24 * 60 * 60;
pub const CURSOR_DEFAULT_TEMPLATE: &str = include_str!("templates/cursor_default_v1.toml");

pub fn default_grant_template_path() -> Result<PathBuf, InitError> {
    Ok(home_dir()?
        .join(".ember")
        .join("grant-template-cursor.toml"))
}

pub fn cursor_persona_name() -> String {
    crate::launcher::default_persona_id_for_runtime("cursor", None)
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
    fs::write(path, CURSOR_DEFAULT_TEMPLATE).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

pub fn cursor_auth_status_line() -> String {
    "  Cursor:   account/model auth remains Cursor-owned; install Cursor CLI with `curl https://cursor.com/install -fsS | bash` and sign in through Cursor's own flow".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_persona_name_uses_default_slot() {
        assert_eq!(cursor_persona_name(), "cursor-default");
    }

    #[test]
    fn template_contains_cursor_id() {
        assert!(CURSOR_DEFAULT_TEMPLATE.contains(r#"id = "cursor-default-v1""#));
    }
}
