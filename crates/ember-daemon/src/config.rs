use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("could not determine home directory")]
    NoHomeDir,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// Raw TOML structure — paths may contain `~` and are expanded on load.
#[derive(Debug, Deserialize)]
struct RawDaemonSection {
    socket_dir: Option<String>,
    data_dir: Option<String>,
    pid_file: Option<String>,
    log_level: Option<LogLevel>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    daemon: Option<RawDaemonSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_dir: PathBuf,
    pub data_dir: PathBuf,
    pub pid_file: PathBuf,
    pub log_level: LogLevel,
}

fn expand_tilde(path: &str) -> Result<PathBuf, ConfigError> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs_next::home_dir().ok_or(ConfigError::NoHomeDir)?;
        Ok(home.join(rest))
    } else if path == "~" {
        dirs_next::home_dir().ok_or(ConfigError::NoHomeDir)
    } else {
        Ok(PathBuf::from(path))
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        // Fallback to a fixed path when home dir is unavailable — tests that
        // call `Default::default()` without a real home dir will still compile.
        let base = dirs_next::home_dir()
            .map(|h| h.join(".ember"))
            .unwrap_or_else(|| PathBuf::from("/tmp/.ember"));

        Self {
            socket_dir: base.join("run"),
            data_dir: base.join("data"),
            pid_file: base.join("run").join("emberd.pid"),
            log_level: LogLevel::Info,
        }
    }
}

impl DaemonConfig {
    pub fn default_config_path() -> PathBuf {
        dirs_next::home_dir()
            .map(|h| h.join(".ember").join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("/tmp/.ember/config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&text)?;

        let defaults = DaemonConfig::default();
        let section = raw.daemon.unwrap_or(RawDaemonSection {
            socket_dir: None,
            data_dir: None,
            pid_file: None,
            log_level: None,
        });

        let socket_dir = match section.socket_dir {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.socket_dir,
        };
        let data_dir = match section.data_dir {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.data_dir,
        };
        let pid_file = match section.pid_file {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.pid_file,
        };
        let log_level = section.log_level.unwrap_or(defaults.log_level);

        Ok(DaemonConfig {
            socket_dir,
            data_dir,
            pid_file,
            log_level,
        })
    }

    pub fn ensure_dirs(&self) -> Result<(), ConfigError> {
        fs::create_dir_all(&self.socket_dir)?;
        fs::create_dir_all(&self.data_dir)?;
        if let Some(parent) = self.pid_file.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    #[test]
    fn default_paths_contain_ember() {
        let cfg = DaemonConfig::default();
        assert!(cfg.socket_dir.to_string_lossy().contains(".ember"));
        assert!(cfg.data_dir.to_string_lossy().contains(".ember"));
        assert!(cfg.pid_file.to_string_lossy().contains(".ember"));
        assert_eq!(cfg.log_level, LogLevel::Info);
    }

    #[test]
    fn round_trip_toml() {
        let defaults = DaemonConfig::default();

        // Build a TOML string from defaults and re-parse it.
        let toml_str = format!(
            "[daemon]\nsocket_dir = \"{}\"\ndata_dir = \"{}\"\npid_file = \"{}\"\nlog_level = \"info\"\n",
            defaults.socket_dir.display(),
            defaults.data_dir.display(),
            defaults.pid_file.display(),
        );

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();

        assert_eq!(loaded.socket_dir, defaults.socket_dir);
        assert_eq!(loaded.data_dir, defaults.data_dir);
        assert_eq!(loaded.pid_file, defaults.pid_file);
        assert_eq!(loaded.log_level, defaults.log_level);
    }

    #[test]
    fn ensure_dirs_creates_directories() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("ember");
        let cfg = DaemonConfig {
            socket_dir: base.join("run"),
            data_dir: base.join("data"),
            pid_file: base.join("run").join("emberd.pid"),
            log_level: LogLevel::Info,
        };

        cfg.ensure_dirs().unwrap();

        assert!(cfg.socket_dir.is_dir());
        assert!(cfg.data_dir.is_dir());
        assert!(cfg.pid_file.parent().unwrap().is_dir());
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        // TOML with only log_level set — other fields use defaults.
        let toml_str = "[daemon]\nlog_level = \"debug\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        let defaults = DaemonConfig::default();

        assert_eq!(loaded.socket_dir, defaults.socket_dir);
        assert_eq!(loaded.data_dir, defaults.data_dir);
        assert_eq!(loaded.pid_file, defaults.pid_file);
        assert_eq!(loaded.log_level, LogLevel::Debug);
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let toml_str = "";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        let defaults = DaemonConfig::default();

        assert_eq!(loaded, defaults);
    }

    #[test]
    fn invalid_toml_returns_parse_error() {
        let toml_str = "[daemon\nthis is not valid toml :::";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let err = DaemonConfig::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn tilde_expansion_in_paths() {
        let home = dirs_next::home_dir().expect("home dir required for this test");
        let toml_str = "[daemon]\nsocket_dir = \"~/.ember/run\"\ndata_dir = \"~/.ember/data\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.socket_dir, home.join(".ember/run"));
        assert_eq!(loaded.data_dir, home.join(".ember/data"));
    }

    #[test]
    fn default_config_path_contains_ember() {
        let p = DaemonConfig::default_config_path();
        assert!(p.to_string_lossy().contains(".ember"));
        assert!(p.to_string_lossy().ends_with("config.toml"));
    }
}
