//! Vercel parent-token discovery for the daemon's broker registry.
//! Mirrors the shape of `fly_config.rs` / `azure_config.rs` so wireup
//! is homogeneous across providers.
//!
//! Reads `~/.config/emberlink/vercel.env` (key-value, `KEY=value`
//! lines) for the parent `VERCEL_TOKEN` (required) and an optional
//! default team id (`VERCEL_DEFAULT_TEAM_ID`) the broker hands to
//! [`ember_broker::VercelBroker`].
//!
//! Behaviour contract:
//!
//! - File present + `VERCEL_TOKEN` set → `Some(VercelParentToken)`.
//!   Daemon registers [`ember_broker::VercelBroker`] for
//!   `BrokerProvider::Vercel`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without Vercel config still answer
//!   `broker_issue` without a panic.
//! - File present but `VERCEL_TOKEN` missing → `None` (treated as
//!   misconfigured; daemon falls back to mock).

use std::fs;
use std::path::PathBuf;

use ember_broker::VercelParentToken;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// Vercel credentials.
const ENV_FILENAME: &str = "vercel.env";

/// Required: long-lived Vercel API token (a personal-account or team
/// token with `tokens:create` scope) the broker exchanges for
/// short-lived scoped tokens via Vercel's `POST /v3/user/tokens`
/// endpoint. Held in [`SecretString`] inside the loaded credentials so
/// it cannot be accidentally `Debug`-printed.
const KEY_API_TOKEN: &str = "VERCEL_TOKEN";

/// Optional: default team id used when [`ember_broker::VercelScope::team_id`]
/// is empty. When set, the broker scopes the minted token to this team
/// by default. When unset, the minted token is personal-account-scoped.
const KEY_DEFAULT_TEAM_ID: &str = "VERCEL_DEFAULT_TEAM_ID";

/// Try to load Vercel parent credentials from the operator's user-level
/// configuration. Returns `None` if the file is absent or
/// `VERCEL_TOKEN` is missing (graceful — daemon continues with
/// `MockBroker`).
pub fn load_vercel_credentials() -> Option<VercelParentToken> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<VercelParentToken> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let token = parse_env_var(&env_contents, KEY_API_TOKEN)?;
    let default_team_id = parse_env_var(&env_contents, KEY_DEFAULT_TEAM_ID);

    Some(VercelParentToken {
        token: SecretString::from(token),
        default_team_id,
    })
}

/// Store-key namespace constants used by `vercel_config_from_store`.
const STORE_KEY_API_TOKEN: &str = "vercel/api-token";
const STORE_KEY_DEFAULT_TEAM_ID: &str = "vercel/default-team-id";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `vercel/api-token` (required) and the optional
/// `vercel/default-team-id` from a generic [`CredentialStore`] impl.
/// Returns `Ok(None)` if `vercel/api-token` is absent so daemon startup
/// falls back to `MockBroker` cleanly when the store is empty.
pub async fn vercel_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<VercelParentToken>, crate::infra::credential_store::StoreError> {
    use crate::infra::credential_store::StoreError;

    async fn get_opt(
        store: &dyn crate::infra::credential_store::CredentialStore,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        match store.get(key).await {
            Ok(bytes) => {
                Ok(Some(String::from_utf8(bytes).map_err(|e| {
                    StoreError::Other(format!("non-utf8 in {}: {e}", key))
                })?))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    let token = get_opt(store, STORE_KEY_API_TOKEN).await?;
    let default_team_id = get_opt(store, STORE_KEY_DEFAULT_TEAM_ID).await?;

    let token = match token {
        Some(t) => t,
        None => return Ok(None),
    };

    Ok(Some(VercelParentToken {
        token: SecretString::from(token),
        default_team_id,
    }))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `fly_config::parse_env_var` so the
/// dotenv shape stays consistent across providers.
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
    use secrecy::ExposeSecret;

    fn write(path: &std::path::Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn load_from_dir_missing_file_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = load_from_dir(tmp.path());
        assert!(result.is_none(), "missing file must return None");
    }

    #[test]
    fn load_from_dir_with_api_token_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "VERCEL_TOKEN=vc1_test_parent_token\n\
             VERCEL_DEFAULT_TEAM_ID=team_default\n",
        );
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "vc1_test_parent_token");
        assert_eq!(creds.default_team_id.as_deref(), Some("team_default"));
    }

    #[test]
    fn load_from_dir_with_only_api_token_returns_credentials_no_default_team() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(&tmp.path().join(ENV_FILENAME), "VERCEL_TOKEN=vc1_solo\n");
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "vc1_solo");
        assert!(
            creds.default_team_id.is_none(),
            "missing VERCEL_DEFAULT_TEAM_ID must be None"
        );
    }

    #[test]
    fn load_from_dir_missing_api_token_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "VERCEL_DEFAULT_TEAM_ID=team_default\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing VERCEL_TOKEN must return None"
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "VERCEL_TOKEN=\"vc1_quoted\"\nVERCEL_DEFAULT_TEAM_ID='team_x'\n";
        assert_eq!(
            parse_env_var(env, "VERCEL_TOKEN"),
            Some("vc1_quoted".to_string())
        );
        assert_eq!(
            parse_env_var(env, "VERCEL_DEFAULT_TEAM_ID"),
            Some("team_x".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nVERCEL_TOKEN=abc\n";
        assert_eq!(parse_env_var(env, "VERCEL_TOKEN"), Some("abc".to_string()));
    }

    #[tokio::test]
    async fn vercel_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_API_TOKEN, b"vc1_test_parent_token")
            .await
            .unwrap();
        mock.put(STORE_KEY_DEFAULT_TEAM_ID, b"team_default")
            .await
            .unwrap();

        let result = vercel_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.token.expose_secret(), "vc1_test_parent_token");
        assert_eq!(creds.default_team_id.as_deref(), Some("team_default"));
    }
}
