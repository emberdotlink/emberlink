use std::path::PathBuf;

/// Explicit paths for the app's local data.
///
/// Both the CLI and GUI construct this from env-var overrides or explicit
/// arguments — never relying on implicit home-dir behavior inside library
/// code. The `EMBERLINK_DATA_DIR` env var overrides the entire data directory;
/// individual path env vars override specific files.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Directory that holds the database and state file.
    pub data_dir: PathBuf,
    /// Path to the SQLite event store.
    pub db_path: PathBuf,
    /// Path to the encrypted local-state file (`local-state.enc`).
    pub state_path: PathBuf,
}

impl AppConfig {
    /// Build an `AppConfig` from a data directory, deriving db and state paths.
    pub fn from_data_dir(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let db_path = data_dir.join("local-state.sqlite");
        let state_path = data_dir.join("local-state.enc");
        Self {
            data_dir,
            db_path,
            state_path,
        }
    }

    /// Resolve the data directory from env vars or fall back to `fallback`.
    ///
    /// Env var precedence (first wins):
    /// 1. `EMBERLINK_DATA_DIR` — overrides the whole data dir
    /// 2. `fallback` argument — typically `default_user_dir()`
    ///
    /// Individual path overrides:
    /// - `EMBERLINK_DB_PATH` — overrides `db_path` only
    /// - `EMBERLINK_STATE_PATH` — overrides `state_path` only
    pub fn resolve(fallback: PathBuf) -> Self {
        let data_dir = std::env::var("EMBERLINK_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or(fallback);

        let db_path = std::env::var("EMBERLINK_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("local-state.sqlite"));

        let state_path = std::env::var("EMBERLINK_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("local-state.enc"));

        Self {
            data_dir,
            db_path,
            state_path,
        }
    }
}

/// The default user-facing data directory: `~/.config/emberlink`.
///
/// Shells call this and pass the result to [`AppConfig::resolve`]. Library
/// code never calls this directly — callers decide where data lives.
pub fn default_user_dir() -> PathBuf {
    dirs_next::home_dir() // crate is named dirs-next, re-exported as dirs_next
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("emberlink")
}
