//! GitHub App credential discovery for the daemon's broker registry.
//!
//! Reads `~/.config/emberlink/ember-engine.env` (key-value, `KEY=value`
//! lines) and `~/.config/emberlink/ember-engine-app.pem` (RSA private key)
//! to build the [`GhAppCredentials`] the daemon hands to
//! [`ember_broker::GitHubBroker`].
//!
//! Path scheme matches today's `crates/headless-runtime/src/ship.rs::resolve_bot_identity`
//! discovery so the migration to construct-mediated ships (T-CONSTRUCT-SHIP-RS-MIGRATION)
//! is a drop-in: the same files satisfy both code paths until ship.rs is
//! converted, after which ship.rs deletes its discovery and the daemon
//! becomes the sole reader.
//!
//! Behaviour contract:
//!
//! - Both files present + valid → `Ok(Some(creds))`. Daemon registers
//!   [`ember_broker::GitHubBroker`] for `BrokerProvider::Github`.
//! - Either file absent → `Ok(None)`. Daemon logs a warning and falls
//!   back to `MockBroker` for github (preserves today's pre-T1 behaviour
//!   for hosts without GH App config — local dev, fresh installs).
//! - Files present but malformed (env file missing required keys, PEM
//!   unreadable, etc.) → `Err`. Daemon surfaces as a startup warning;
//!   does NOT panic since other brokers still work.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use ember_broker::github_app::GhAppCredentials;

/// Filename inside `~/.config/emberlink/` containing `EMBER_ENGINE_APP_ID`
/// and `EMBER_ENGINE_INSTALLATION_ID` shell-style assignments.
const ENV_FILENAME: &str = "ember-engine.env";

/// Filename inside `~/.config/emberlink/` containing the GitHub App's
/// RSA private key (PEM-encoded PKCS#8 or PKCS#1).
const PEM_FILENAME: &str = "ember-engine-app.pem";

/// Required key for the App ID in `ember-engine.env`.
const KEY_APP_ID: &str = "EMBER_ENGINE_APP_ID";

/// Required key for the installation ID in `ember-engine.env`.
const KEY_INSTALLATION_ID: &str = "EMBER_ENGINE_INSTALLATION_ID";

/// Try to load GitHub App credentials from the operator's user-level
/// configuration. Returns `Ok(None)` if either file is absent (graceful
/// — daemon continues with `MockBroker` for github).
pub fn load_gh_app_credentials() -> anyhow::Result<Option<GhAppCredentials>> {
    let home = std::env::var("HOME").context("HOME env var unset")?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> anyhow::Result<Option<GhAppCredentials>> {
    let env_path = base.join(ENV_FILENAME);
    let pem_path = base.join(PEM_FILENAME);

    if !env_path.exists() || !pem_path.exists() {
        return Ok(None);
    }

    let env_contents = fs::read_to_string(&env_path)
        .with_context(|| format!("reading {}", env_path.display()))?;
    let app_id = parse_env_var(&env_contents, KEY_APP_ID).ok_or_else(|| {
        anyhow!(
            "{} present but missing {KEY_APP_ID}",
            env_path.display()
        )
    })?;
    let installation_id =
        parse_env_var(&env_contents, KEY_INSTALLATION_ID).ok_or_else(|| {
            anyhow!(
                "{} present but missing {KEY_INSTALLATION_ID}",
                env_path.display()
            )
        })?;

    let private_key_pem = fs::read_to_string(&pem_path)
        .with_context(|| format!("reading {}", pem_path.display()))?;

    if private_key_pem.trim().is_empty() {
        return Err(anyhow!(
            "{} is empty — expected RSA private key",
            pem_path.display()
        ));
    }

    Ok(Some(GhAppCredentials {
        app_id,
        installation_id,
        private_key_pem,
    }))
}

/// Store-key namespace constants used by `github_config_from_store`.
const STORE_KEY_APP_ID: &str = "github/app-id";
const STORE_KEY_INSTALLATION_ID: &str = "github/installation-id";
const STORE_KEY_PRIVATE_KEY_PEM: &str = "github/private-key-pem";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `github/app-id`, `github/installation-id`, and
/// `github/private-key-pem` (the PEM bytes themselves, not a filesystem
/// path) from a generic [`CredentialStore`] impl. Returns `Ok(None)` if
/// any of the three keys is absent so daemon startup falls back to
/// `MockBroker` cleanly when the store is empty (mirrors the env-file
/// loader's "missing-file → None" semantics).
pub async fn github_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<GhAppCredentials>, crate::infra::credential_store::StoreError> {
    use crate::infra::credential_store::StoreError;

    async fn get_opt(
        store: &dyn crate::infra::credential_store::CredentialStore,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        match store.get(key).await {
            Ok(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|e| {
                StoreError::Other(format!("non-utf8 in {}: {e}", key))
            })?)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    let app_id = get_opt(store, STORE_KEY_APP_ID).await?;
    let installation_id = get_opt(store, STORE_KEY_INSTALLATION_ID).await?;
    let private_key_pem = get_opt(store, STORE_KEY_PRIVATE_KEY_PEM).await?;

    let (app_id, installation_id, private_key_pem) =
        match (app_id, installation_id, private_key_pem) {
            (Some(a), Some(i), Some(p)) if !p.trim().is_empty() => (a, i, p),
            _ => return Ok(None),
        };

    Ok(Some(GhAppCredentials {
        app_id,
        installation_id,
        private_key_pem,
    }))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `ship.rs::read_env_var` so the
/// migration is byte-compatible with today's discovery.
fn parse_env_var(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let Some(val) = rest.strip_prefix('=') else {
            continue;
        };
        let trimmed = val.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &std::path::Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn parse_env_var_returns_first_match() {
        let env = "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n";
        assert_eq!(parse_env_var(env, "EMBER_ENGINE_APP_ID"), Some("12345".to_string()));
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_INSTALLATION_ID"),
            Some("67890".to_string())
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = r#"EMBER_ENGINE_APP_ID="12345"
EMBER_ENGINE_INSTALLATION_ID='67890'
"#;
        assert_eq!(parse_env_var(env, "EMBER_ENGINE_APP_ID"), Some("12345".to_string()));
        assert_eq!(
            parse_env_var(env, "EMBER_ENGINE_INSTALLATION_ID"),
            Some("67890".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nEMBER_ENGINE_APP_ID=42\n";
        assert_eq!(parse_env_var(env, "EMBER_ENGINE_APP_ID"), Some("42".to_string()));
    }

    #[test]
    fn parse_env_var_missing_returns_none() {
        let env = "OTHER_KEY=value\n";
        assert!(parse_env_var(env, "EMBER_ENGINE_APP_ID").is_none());
    }

    #[test]
    fn load_from_dir_missing_files_returns_ok_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = load_from_dir(tmp.path()).expect("load must succeed gracefully");
        assert!(result.is_none(), "missing files must return Ok(None)");
    }

    #[test]
    fn load_from_dir_only_env_present_returns_ok_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=1\nEMBER_ENGINE_INSTALLATION_ID=2\n",
        );
        // No PEM
        let result = load_from_dir(tmp.path()).expect("load must succeed gracefully");
        assert!(
            result.is_none(),
            "missing PEM must return Ok(None) (graceful, not error)"
        );
    }

    #[test]
    fn load_from_dir_both_present_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), "\x2d----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n");
        let result = load_from_dir(tmp.path()).expect("load must succeed").expect("creds present");
        assert_eq!(result.app_id, "12345");
        assert_eq!(result.installation_id, "67890");
        assert!(result.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn load_from_dir_env_missing_app_id_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), "\x2d----BEGIN PRIVATE KEY-----\n");
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("EMBER_ENGINE_APP_ID"), "error must name the missing key: {msg}");
    }

    #[test]
    fn load_from_dir_env_missing_installation_id_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(&tmp.path().join(ENV_FILENAME), "EMBER_ENGINE_APP_ID=12345\n");
        write(&tmp.path().join(PEM_FILENAME), "\x2d----BEGIN PRIVATE KEY-----\n");
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("EMBER_ENGINE_INSTALLATION_ID"),
            "error must name the missing key: {msg}"
        );
    }

    #[test]
    fn load_from_dir_empty_pem_is_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "EMBER_ENGINE_APP_ID=12345\nEMBER_ENGINE_INSTALLATION_ID=67890\n",
        );
        write(&tmp.path().join(PEM_FILENAME), "");
        let err = match load_from_dir(tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("empty"), "error must mention empty PEM: {msg}");
    }

    #[tokio::test]
    async fn github_config_from_store_happy_path() {
        use crate::infra::credential_store::test_helpers::MockCredentialStore;
        use crate::infra::credential_store::CredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_APP_ID, b"12345").await.unwrap();
        mock.put(STORE_KEY_INSTALLATION_ID, b"67890").await.unwrap();
        mock.put(
            STORE_KEY_PRIVATE_KEY_PEM,
            b"\x2d----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        )
        .await
        .unwrap();

        let result = github_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.app_id, "12345");
        assert_eq!(creds.installation_id, "67890");
        assert!(creds.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
