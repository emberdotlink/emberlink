use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    #[error("validation error: {0}")]
    Validation(String),
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
    policy_file: Option<String>,
    log_level: Option<LogLevel>,
    dashboard_addr: Option<String>,
    stale_approval_threshold_secs: Option<u64>,
    /// Bind address for the git-echo credential-injection proxy. `None` (key
    /// absent) ⇒ default `127.0.0.1:0` (random port). Empty string ⇒ disabled.
    /// (implementation-note-10)
    git_proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    daemon: Option<RawDaemonSection>,
    keyring: Option<KeyringConfig>,
    presence: Option<PresenceConfigSection>,
}

/// Keyring service/account identifiers written into `config.toml`.
///
/// Resolution order in `Vault::open_from_config`:
/// 1. Config field (if `Some`)
/// 2. Env var override (`EMBER_KEYRING_SERVICE` / `EMBER_KEYRING_ACCOUNT`) — debug backdoor
/// 3. Compile-time default (`"ember-daemon"` / `"vault"`)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringConfig {
    pub service: Option<String>,
    pub account: Option<String>,
}

/// security check: per-operation user-presence gate config. Optional; all
/// `None` ⇒ presence module uses defaults (15min idle, no quiet hours).
///
/// ```toml
/// [presence]
/// idle_timeout_secs = 900       # default 900 (15min)
/// quiet_hours_start = 22        # 22:00 UTC
/// quiet_hours_end = 6           #  6:00 UTC (wrap-around supported)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceConfigSection {
    pub idle_timeout_secs: Option<u64>,
    pub quiet_hours_start: Option<u8>,
    pub quiet_hours_end: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_dir: PathBuf,
    pub data_dir: PathBuf,
    pub pid_file: PathBuf,
    pub policy_file: PathBuf,
    pub log_level: LogLevel,
    /// Address for the dashboard HTTP listener. `None` disables the dashboard (useful for tests).
    /// Defaults to `127.0.0.1:3141` — loopback only, never 0.0.0.0.
    pub dashboard_addr: Option<SocketAddr>,
    /// Bind address for the git-echo credential-injection proxy used by
    /// sandboxed agents (`EMBER_PROXY_URL`). `None` disables the proxy.
    /// Defaults to `127.0.0.1:0` (loopback, ephemeral port). implementation-note-10.
    pub git_proxy_addr: Option<SocketAddr>,
    /// Keyring service/account override. `None` fields fall back to env var, then compile-time default.
    pub keyring: KeyringConfig,
    /// Startup sweep: mark `pending` approval_requests older than this many seconds as `timed_out`.
    /// Default 3600 (1 hour). Set to 0 to disable the sweep.
    pub stale_approval_threshold_secs: u64,
    /// security check per-op user-presence gate. Loaded from `[presence]`
    /// in config.toml; `None` fields fall back to module defaults.
    pub presence: PresenceConfigSection,
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
            policy_file: base.join("policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: Some("127.0.0.1:3141".parse().expect("valid default addr")),
            git_proxy_addr: Some("127.0.0.1:0".parse().expect("valid default addr")),
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: PresenceConfigSection::default(),
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
            policy_file: None,
            log_level: None,
            dashboard_addr: None,
            stale_approval_threshold_secs: None,
            git_proxy_addr: None,
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
        let policy_file = match section.policy_file {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.policy_file,
        };
        let log_level = section.log_level.unwrap_or(defaults.log_level);

        let dashboard_addr = match section.dashboard_addr {
            Some(ref s) if s.is_empty() => None,
            Some(ref s) => Some(SocketAddr::from_str(s).map_err(|e| {
                ConfigError::Validation(format!("invalid dashboard_addr '{}': {}", s, e))
            })?),
            None => defaults.dashboard_addr,
        };

        let git_proxy_addr = match section.git_proxy_addr {
            Some(ref s) if s.is_empty() => None,
            Some(ref s) => Some(SocketAddr::from_str(s).map_err(|e| {
                ConfigError::Validation(format!("invalid git_proxy_addr '{}': {}", s, e))
            })?),
            None => defaults.git_proxy_addr,
        };

        let keyring = raw.keyring.unwrap_or_default();
        let presence = raw.presence.unwrap_or_default();
        let stale_approval_threshold_secs = section
            .stale_approval_threshold_secs
            .unwrap_or(defaults.stale_approval_threshold_secs);

        let cfg = DaemonConfig {
            socket_dir,
            data_dir,
            pid_file,
            policy_file,
            log_level,
            dashboard_addr,
            git_proxy_addr,
            keyring,
            stale_approval_threshold_secs,
            presence,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.socket_dir.as_os_str().is_empty() {
            return Err(ConfigError::Validation("socket_dir cannot be empty".to_string()));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Validation("data_dir cannot be empty".to_string()));
        }
        if self.pid_file.as_os_str().is_empty() {
            return Err(ConfigError::Validation("pid_file cannot be empty".to_string()));
        }
        if self.socket_dir == self.data_dir {
            return Err(ConfigError::Validation(
                "socket_dir and data_dir must be different".to_string(),
            ));
        }
        Ok(())
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
            policy_file: base.join("policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: PresenceConfigSection::default(),
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

    #[test]
    fn validate_default_config_passes() {
        let cfg = DaemonConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_empty_socket_dir_fails() {
        let cfg = DaemonConfig {
            socket_dir: PathBuf::from(""),
            data_dir: PathBuf::from("/tmp/.ember/data"),
            pid_file: PathBuf::from("/tmp/.ember/run/emberd.pid"),
            policy_file: PathBuf::from("/tmp/.ember/policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: PresenceConfigSection::default(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(ref s) if s.contains("socket_dir")));
    }

    #[test]
    fn validate_same_dirs_fails() {
        let cfg = DaemonConfig {
            socket_dir: PathBuf::from("/tmp/.ember/same"),
            data_dir: PathBuf::from("/tmp/.ember/same"),
            pid_file: PathBuf::from("/tmp/.ember/same/emberd.pid"),
            policy_file: PathBuf::from("/tmp/.ember/policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            presence: PresenceConfigSection::default(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(ref s) if s.contains("must be different")));
    }

    #[test]
    fn keyring_section_loaded_from_toml() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[keyring]\nservice = \"my-service\"\naccount = \"my-account\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring.service.as_deref(), Some("my-service"));
        assert_eq!(loaded.keyring.account.as_deref(), Some("my-account"));
    }

    #[test]
    fn keyring_section_absent_gives_defaults() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring, KeyringConfig::default());
        assert!(loaded.keyring.service.is_none());
        assert!(loaded.keyring.account.is_none());
    }

    #[test]
    fn presence_section_loaded_from_toml() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[presence]\nidle_timeout_secs = 600\nquiet_hours_start = 22\nquiet_hours_end = 6\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.presence.idle_timeout_secs, Some(600));
        assert_eq!(loaded.presence.quiet_hours_start, Some(22));
        assert_eq!(loaded.presence.quiet_hours_end, Some(6));
    }

    #[test]
    fn presence_section_absent_gives_defaults() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert!(loaded.presence.idle_timeout_secs.is_none());
        assert!(loaded.presence.quiet_hours_start.is_none());
        assert!(loaded.presence.quiet_hours_end.is_none());
    }

    #[test]
    fn keyring_partial_section_service_only() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[keyring]\nservice = \"only-service\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring.service.as_deref(), Some("only-service"));
        assert!(loaded.keyring.account.is_none());
    }
}
