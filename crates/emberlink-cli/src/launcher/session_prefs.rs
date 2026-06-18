//! CLASSIFICATION: PUBLIC
//! Session-persistent preferences for the `ember claude` launcher.
//!
//! Stores `~/.ember/session-prefs.json` with a `host_mode_disclaimer_suppressed`
//! flag. When the user presses `[S]` at the host-mode mediation disclaimer
//! (ADR 166 §Component 5a), the launcher writes `true` here so subsequent
//! launches skip the prompt.
//!
//! File format: JSON object `{ "host_mode_disclaimer_suppressed": bool }`.
//! Missing file → default false (not suppressed).

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// All session-level preferences persisted between launcher invocations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPrefs {
    /// When `true`, the host-mode mediation disclaimer is skipped at launch.
    /// Default: `false`.
    #[serde(default)]
    pub host_mode_disclaimer_suppressed: bool,
}

/// Return the path to `~/.ember/session-prefs.json`.
///
/// `$EMBER_HOME` overrides `~/.ember` for test harnesses.
pub fn session_prefs_path() -> PathBuf {
    let ember_home = if let Ok(override_dir) = std::env::var("EMBER_HOME") {
        PathBuf::from(override_dir)
    } else {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".ember")
    };
    ember_home.join("session-prefs.json")
}

/// Load session preferences from disk.
///
/// Returns `SessionPrefs::default()` when the file does not exist or cannot
/// be parsed (graceful degradation — a corrupt prefs file must not block launch).
pub fn load() -> SessionPrefs {
    let path = session_prefs_path();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return SessionPrefs::default(),
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Persist session preferences atomically to disk.
///
/// Writes to `<path>.tmp` then renames to `<path>` so a crash during write
/// does not leave a half-written file.
pub fn save(prefs: &SessionPrefs) -> io::Result<()> {
    let path = session_prefs_path();
    // Ensure the parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(prefs).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("session_prefs: serialize error: {e}"),
        )
    })?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Set `host_mode_disclaimer_suppressed = true` and persist.
pub fn suppress_host_mode_disclaimer() -> io::Result<()> {
    let mut prefs = load();
    prefs.host_mode_disclaimer_suppressed = true;
    save(&prefs)
}

/// Process-wide mutex serializing tests that mutate the `EMBER_HOME` env
/// var. `std::env::set_var` is process-wide; without a lock, parallel
/// cargo-test threads racing here corrupt each other's view of the
/// override. The same lock is used by `launcher::claude_code` tests for
/// the same reason. Exposed under `#[cfg(test)]` so other test modules
/// can `.lock()` it before their own `set_var("EMBER_HOME", ...)` calls.
#[cfg(test)]
pub(crate) static EMBER_HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_ember_home() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("create temp dir")
    }

    #[test]
    fn default_prefs_not_suppressed() {
        let prefs = SessionPrefs::default();
        assert!(!prefs.host_mode_disclaimer_suppressed);
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let _g = EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_ember_home();
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        let prefs = load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(!prefs.host_mode_disclaimer_suppressed);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let _g = EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_ember_home();
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        let prefs = SessionPrefs {
            host_mode_disclaimer_suppressed: true,
        };
        save(&prefs).expect("save prefs");
        let loaded = load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(loaded.host_mode_disclaimer_suppressed);
    }

    #[test]
    fn suppress_host_mode_disclaimer_persists() {
        let _g = EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_ember_home();
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        suppress_host_mode_disclaimer().expect("suppress");
        let loaded = load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        assert!(
            loaded.host_mode_disclaimer_suppressed,
            "suppression must persist after suppress_host_mode_disclaimer"
        );
    }

    #[test]
    fn load_returns_default_on_corrupt_file() {
        let _g = EMBER_HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tmp_ember_home();
        unsafe { std::env::set_var("EMBER_HOME", dir.path()) };
        let path = session_prefs_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not valid json!!!").unwrap();
        let prefs = load();
        unsafe { std::env::remove_var("EMBER_HOME") };
        // Corrupt file → graceful default (not suppressed).
        assert!(!prefs.host_mode_disclaimer_suppressed);
    }
}
