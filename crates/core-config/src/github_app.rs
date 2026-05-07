//! GitHub App configuration shape (design credential broker).
//!
//! The daemon loads these values from its config file (or env vars); the
//! operator fills in `app_id`, `installation_id`, and `private_key_path`
//! once the App is registered with GitHub. Until then all fields are
//! `None` and the broker returns [`ember_broker::github_app::GhAppError::NotConfigured`].

use serde::{Deserialize, Serialize};

/// GitHub App credentials configuration.
///
/// All fields are optional; absent fields cause the broker to return a clear
/// `NotConfigured` error rather than panicking. The private key itself is
/// NOT stored here — only its on-disk path. The daemon reads the PEM bytes
/// at mint time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GitHubAppConfig {
    /// Numeric GitHub App ID as a string (e.g. `"123456"`).
    pub app_id: Option<String>,
    /// Installation ID for the target account or organisation.
    pub installation_id: Option<String>,
    /// Path to the PEM-encoded RSA private key exported from GitHub.
    /// May be an absolute path or relative to `$HOME/.ember/`.
    #[cfg(feature = "std")]
    pub private_key_path: Option<std::path::PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_all_none() {
        let cfg = GitHubAppConfig::default();
        assert!(cfg.app_id.is_none());
        assert!(cfg.installation_id.is_none());
    }

    #[test]
    fn parse_partial_toml() {
        let cfg: GitHubAppConfig =
            toml::from_str(r#"app_id = "99999""#).expect("parse must succeed");
        assert_eq!(cfg.app_id.as_deref(), Some("99999"));
        assert!(cfg.installation_id.is_none());
    }

    #[test]
    fn parse_full_toml() {
        let cfg: GitHubAppConfig = toml::from_str(
            r#"
            app_id = "11111"
            installation_id = "22222"
            "#,
        )
        .expect("parse must succeed");
        assert_eq!(cfg.app_id.as_deref(), Some("11111"));
        assert_eq!(cfg.installation_id.as_deref(), Some("22222"));
    }
}
