//! Fly.io parent-token discovery for the daemon's broker registry.
//! Mirrors the shape of `azure_config.rs` / `gcp_config.rs` so wireup
//! is homogeneous across providers.
//!
//! Reads `~/.config/emberlink/fly.env` (key-value, `KEY=value` lines)
//! for the parent `FLY_API_TOKEN` (required) and an optional default
//! org slug (`FLY_DEFAULT_ORG_SLUG`) the broker hands to
//! [`ember_broker::FlyBroker`].
//!
//! Behaviour contract:
//!
//! - File present + `FLY_API_TOKEN` set → `Some(FlyParentToken)`.
//!   Daemon registers [`ember_broker::FlyBroker`] for
//!   `BrokerProvider::FlyIo`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without Fly config still answer
//!   `broker_issue` without a panic.
//! - File present but `FLY_API_TOKEN` missing → `None` (treated as
//!   misconfigured; daemon falls back to mock).

use std::fs;
use std::path::PathBuf;

use ember_broker::FlyParentToken;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// Fly.io credentials.
const ENV_FILENAME: &str = "fly.env";

/// Required: long-lived Fly API token (e.g. a personal access token or
/// an org admin token) the broker exchanges for short-lived scoped
/// tokens via Fly's GraphQL `createApiToken` mutation. Held in
/// [`SecretString`] inside the loaded credentials so it cannot be
/// accidentally `Debug`-printed.
const KEY_API_TOKEN: &str = "FLY_API_TOKEN";

/// Optional: default org slug used when [`ember_broker::FlyScope::org_slug`]
/// is empty AND `app_name` is also empty. When set, the broker scopes
/// the minted token to this org by default.
const KEY_DEFAULT_ORG_SLUG: &str = "FLY_DEFAULT_ORG_SLUG";

/// Try to load Fly.io parent credentials from the operator's user-level
/// configuration. Returns `None` if the file is absent or
/// `FLY_API_TOKEN` is missing (graceful — daemon continues with
/// `MockBroker`).
pub fn load_fly_credentials() -> Option<FlyParentToken> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<FlyParentToken> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let token = parse_env_var(&env_contents, KEY_API_TOKEN)?;
    let default_org_slug = parse_env_var(&env_contents, KEY_DEFAULT_ORG_SLUG);

    Some(FlyParentToken {
        token: SecretString::from(token),
        default_org_slug,
    })
}

/// Store-key namespace constants used by `fly_config_from_store`.
const STORE_KEY_API_TOKEN: &str = "fly/api-token";
const STORE_KEY_DEFAULT_ORG_SLUG: &str = "fly/default-org-slug";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `fly/api-token` (required) and the optional
/// `fly/default-org-slug` from a generic [`CredentialStore`] impl.
/// Returns `Ok(None)` if `fly/api-token` is absent so daemon startup
/// falls back to `MockBroker` cleanly when the store is empty.
pub async fn fly_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<FlyParentToken>, crate::infra::credential_store::StoreError> {
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
    let default_org_slug = get_opt(store, STORE_KEY_DEFAULT_ORG_SLUG).await?;

    let token = match token {
        Some(t) => t,
        None => return Ok(None),
    };

    Ok(Some(FlyParentToken {
        token: SecretString::from(token),
        default_org_slug,
    }))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `azure_config::parse_env_var` so the
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
            "FLY_API_TOKEN=fo1_test_parent_token\n\
             FLY_DEFAULT_ORG_SLUG=acme\n",
        );
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "fo1_test_parent_token");
        assert_eq!(creds.default_org_slug.as_deref(), Some("acme"));
    }

    #[test]
    fn load_from_dir_with_only_api_token_returns_credentials_no_default_org() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(&tmp.path().join(ENV_FILENAME), "FLY_API_TOKEN=fo1_solo\n");
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "fo1_solo");
        assert!(
            creds.default_org_slug.is_none(),
            "missing FLY_DEFAULT_ORG_SLUG must be None"
        );
    }

    #[test]
    fn load_from_dir_missing_api_token_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "FLY_DEFAULT_ORG_SLUG=acme\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing FLY_API_TOKEN must return None"
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "FLY_API_TOKEN=\"fo1_quoted\"\nFLY_DEFAULT_ORG_SLUG='acme'\n";
        assert_eq!(
            parse_env_var(env, "FLY_API_TOKEN"),
            Some("fo1_quoted".to_string())
        );
        assert_eq!(
            parse_env_var(env, "FLY_DEFAULT_ORG_SLUG"),
            Some("acme".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nFLY_API_TOKEN=abc\n";
        assert_eq!(parse_env_var(env, "FLY_API_TOKEN"), Some("abc".to_string()));
    }

    #[tokio::test]
    async fn fly_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_API_TOKEN, b"fo1_test_parent_token")
            .await
            .unwrap();
        mock.put(STORE_KEY_DEFAULT_ORG_SLUG, b"acme").await.unwrap();

        let result = fly_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.token.expose_secret(), "fo1_test_parent_token");
        assert_eq!(creds.default_org_slug.as_deref(), Some("acme"));
    }
}
