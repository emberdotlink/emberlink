//! HashiCorp Vault parent-token discovery for the daemon's broker
//! registry. Mirrors the shape of `azure_config.rs` / `gcp_config.rs` /
//! `fly_config.rs` so wireup is homogeneous across providers.
//!
//! Reads `~/.config/emberlink/hashivault.env` (key-value, `KEY=value`
//! lines) for the parent `VAULT_TOKEN` (required), the Vault server
//! address `VAULT_ADDR` (required), and an optional `VAULT_NAMESPACE`
//! (Vault Enterprise namespace passed through as `X-Vault-Namespace`).
//!
//! Behaviour contract:
//!
//! - File present + both `VAULT_TOKEN` and `VAULT_ADDR` set →
//!   `Some(HashiVaultParentToken)`. Daemon registers
//!   [`ember_broker::HashiVaultBroker`] for `BrokerProvider::HashiVault`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without Vault config still answer
//!   `broker_issue` without a panic.
//! - File present but a required key missing → `None` (treated as
//!   misconfigured; daemon falls back to mock).

use std::fs;
use std::path::PathBuf;

use ember_broker::HashiVaultParentToken;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// HashiCorp Vault credentials.
const ENV_FILENAME: &str = "hashivault.env";

/// Required: long-lived Vault token (with the `auth/token/create`
/// capability) the broker exchanges for short-lived child tokens.
const KEY_VAULT_TOKEN: &str = "VAULT_TOKEN";

/// Required: base URL of the Vault server (e.g.
/// `https://vault.example.com:8200`). Embedded into both the request
/// URL at issue time and the `VAULT_ADDR` env var the daemon-side
/// handler exports alongside `VAULT_TOKEN`.
const KEY_VAULT_ADDR: &str = "VAULT_ADDR";

/// Optional: Vault Enterprise namespace passed through as the
/// `X-Vault-Namespace` header.
const KEY_VAULT_NAMESPACE: &str = "VAULT_NAMESPACE";

/// Try to load HashiCorp Vault parent credentials from the operator's
/// user-level configuration. Returns `None` if the file is absent or
/// either of the required keys (`VAULT_TOKEN`, `VAULT_ADDR`) is
/// missing (graceful — daemon continues with `MockBroker`).
pub fn load_hashivault_credentials() -> Option<HashiVaultParentToken> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<HashiVaultParentToken> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let token = parse_env_var(&env_contents, KEY_VAULT_TOKEN)?;
    let address = parse_env_var(&env_contents, KEY_VAULT_ADDR)?;
    let namespace = parse_env_var(&env_contents, KEY_VAULT_NAMESPACE);

    Some(HashiVaultParentToken {
        token: SecretString::from(token),
        address,
        namespace,
    })
}

/// Store-key namespace constants used by `hashivault_config_from_store`.
const STORE_KEY_VAULT_TOKEN: &str = "hashivault/token";
const STORE_KEY_VAULT_ADDR: &str = "hashivault/address";
const STORE_KEY_VAULT_NAMESPACE: &str = "hashivault/namespace";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `hashivault/token`, `hashivault/address`, and the optional
/// `hashivault/namespace` from a generic [`CredentialStore`] impl.
/// Returns `Ok(None)` if either of the required keys (`token`,
/// `address`) is absent so daemon startup falls back to `MockBroker`
/// cleanly when the store is empty.
pub async fn hashivault_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<HashiVaultParentToken>, crate::infra::credential_store::StoreError> {
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

    let token = get_opt(store, STORE_KEY_VAULT_TOKEN).await?;
    let address = get_opt(store, STORE_KEY_VAULT_ADDR).await?;
    let namespace = get_opt(store, STORE_KEY_VAULT_NAMESPACE).await?;

    let (token, address) = match (token, address) {
        (Some(t), Some(a)) => (t, a),
        _ => return Ok(None),
    };

    Ok(Some(HashiVaultParentToken {
        token: SecretString::from(token),
        address,
        namespace,
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
    fn load_from_dir_with_required_keys_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "VAULT_TOKEN=hvs.test_parent_token\n\
             VAULT_ADDR=https://vault.example.com:8200\n\
             VAULT_NAMESPACE=admin/team-zero\n",
        );
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "hvs.test_parent_token");
        assert_eq!(creds.address, "https://vault.example.com:8200");
        assert_eq!(creds.namespace.as_deref(), Some("admin/team-zero"));
    }

    #[test]
    fn load_from_dir_without_namespace_is_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "VAULT_TOKEN=hvs.solo\n\
             VAULT_ADDR=https://vault.example.com:8200\n",
        );
        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.token.expose_secret(), "hvs.solo");
        assert_eq!(creds.address, "https://vault.example.com:8200");
        assert!(
            creds.namespace.is_none(),
            "missing VAULT_NAMESPACE must be None"
        );
    }

    #[test]
    fn load_from_dir_missing_token_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "VAULT_ADDR=https://vault.example.com:8200\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing VAULT_TOKEN must return None"
        );
    }

    #[test]
    fn load_from_dir_missing_address_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(&tmp.path().join(ENV_FILENAME), "VAULT_TOKEN=hvs.solo\n");
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing VAULT_ADDR must return None"
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "VAULT_TOKEN=\"hvs.quoted\"\nVAULT_ADDR='https://vault.example.com:8200'\n";
        assert_eq!(
            parse_env_var(env, "VAULT_TOKEN"),
            Some("hvs.quoted".to_string())
        );
        assert_eq!(
            parse_env_var(env, "VAULT_ADDR"),
            Some("https://vault.example.com:8200".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nVAULT_TOKEN=abc\n";
        assert_eq!(parse_env_var(env, "VAULT_TOKEN"), Some("abc".to_string()));
    }

    #[tokio::test]
    async fn hashivault_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_VAULT_TOKEN, b"hvs.test_parent_token")
            .await
            .unwrap();
        mock.put(STORE_KEY_VAULT_ADDR, b"https://vault.example.com:8200")
            .await
            .unwrap();
        mock.put(STORE_KEY_VAULT_NAMESPACE, b"admin/team-zero")
            .await
            .unwrap();

        let result = hashivault_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.token.expose_secret(), "hvs.test_parent_token");
        assert_eq!(creds.address, "https://vault.example.com:8200");
        assert_eq!(creds.namespace.as_deref(), Some("admin/team-zero"));
    }
}
