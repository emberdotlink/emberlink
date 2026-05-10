//! Ember-wide config loading. Load order: ENV > ~/.ember/config.toml > defaults.
//!
//! Compatible with wasm32-unknown-unknown (no filesystem I/O at the type level).
//! Filesystem read happens in `EmberConfig::load()` which is only available
//! when the `std` feature is enabled (default).

pub mod github_app;

use serde::{Deserialize, Serialize};

/// Ember-wide config. Fields default to safe values; missing config file = all defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmberConfig {
    /// implementation-note-10: when true, hook unreachable/panic paths permit. When false, all deny.
    /// Default: true (fail-open during cohort A friendly-dev rollout).
    pub explicit_fail_open: bool,
}

impl Default for EmberConfig {
    fn default() -> Self {
        Self {
            explicit_fail_open: true,
        }
    }
}

#[cfg(feature = "std")]
impl EmberConfig {
    /// Load from `$HOME/.ember/config.toml`, falling back to defaults if missing.
    /// Errors only on parse failure (file not found is NOT an error).
    pub fn load_or_default() -> Self {
        Self::load().unwrap_or_default()
    }

    /// Load from `$HOME/.ember/config.toml`. Returns None if file missing.
    /// Returns Err on parse failure.
    pub fn load() -> Result<Self, ConfigError> {
        let home = std::env::var("HOME").map_err(|_| ConfigError::NoHome)?;
        let path = std::path::Path::new(&home).join(".ember").join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path).map_err(ConfigError::Io)?;
        toml::from_str(&content).map_err(ConfigError::Parse)
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ConfigError {
    NoHome,
    Io(std::io::Error),
    Parse(toml::de::Error),
}

#[cfg(feature = "std")]
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHome => write!(f, "$HOME not set"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Parse(e) => write!(f, "parse: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fail_open_true() {
        let cfg = EmberConfig::default();
        assert!(cfg.explicit_fail_open);
    }

    #[test]
    fn parse_minimal_toml() {
        let cfg: EmberConfig = toml::from_str("explicit_fail_open = false").unwrap();
        assert!(!cfg.explicit_fail_open);
    }

    #[test]
    fn parse_empty_toml_uses_defaults() {
        let cfg: EmberConfig = toml::from_str("").unwrap();
        assert!(cfg.explicit_fail_open);
    }
}
