//! Okta service-app discovery for the daemon's broker registry.
//! Mirrors the shape of `hashivault_config.rs` / `gcp_config.rs` /
//! `azure_config.rs` so wireup is homogeneous across providers.
//!
//! Reads `~/.config/emberlink/okta.env` (key-value, `KEY=value` lines)
//! for the service-app credentials:
//!
//! - `OKTA_ORG_URL` (required) — base URL, e.g. `https://example.okta.com`.
//! - `OKTA_CLIENT_ID` (required) — OAuth client id of the service app.
//! - `OKTA_PRIVATE_KEY_PATH` (required) — filesystem path to the
//!   PEM-encoded RSA private key.
//! - `OKTA_KEY_ID` (required) — JWK kid Okta selects the public key by.
//!
//! Behaviour contract:
//!
//! - File present + all required keys set + PEM file readable →
//!   `Some(OktaServiceApp)`. Daemon registers
//!   [`ember_broker::OktaBroker`] for `BrokerProvider::Okta`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without Okta config still answer
//!   `broker_issue` without a panic.
//! - File present but a required key missing OR PEM file unreadable →
//!   `None` (treated as misconfigured; daemon falls back to mock).

use std::fs;
use std::path::PathBuf;

use ember_broker::OktaServiceApp;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// Okta service-app config.
const ENV_FILENAME: &str = "okta.env";

/// Required: base URL of the Okta org (e.g. `https://example.okta.com`).
const KEY_ORG_URL: &str = "OKTA_ORG_URL";

/// Required: OAuth client id of the service app.
const KEY_CLIENT_ID: &str = "OKTA_CLIENT_ID";

/// Required: path to the PEM-encoded RSA private key file.
const KEY_PRIVATE_KEY_PATH: &str = "OKTA_PRIVATE_KEY_PATH";

/// Required: JWK kid Okta uses to look up the matching public key.
const KEY_KEY_ID: &str = "OKTA_KEY_ID";

/// Try to load Okta service-app credentials from the operator's
/// user-level configuration. Returns `None` if the file is absent,
/// any required key is missing, or the PEM file cannot be read.
pub fn load_okta_credentials() -> Option<OktaServiceApp> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<OktaServiceApp> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let org_url = parse_env_var(&env_contents, KEY_ORG_URL)?;
    let client_id = parse_env_var(&env_contents, KEY_CLIENT_ID)?;
    let private_key_path = parse_env_var(&env_contents, KEY_PRIVATE_KEY_PATH)?;
    let key_id = parse_env_var(&env_contents, KEY_KEY_ID)?;

    let pem_contents = match fs::read_to_string(&private_key_path) {
        Ok(s) => s,
        Err(_) => return None,
    };
    if !pem_contents.contains("PRIVATE KEY") {
        // Sanity-check: the PEM file should at least look like a PEM.
        // Fail closed → daemon falls back to mock so a malformed key
        // does not get exercised on the first real broker_issue.
        return None;
    }

    Some(OktaServiceApp {
        org_url,
        client_id,
        private_key_pem: SecretString::from(pem_contents),
        key_id,
    })
}

/// Store-key namespace constants used by `okta_config_from_store`.
///
/// The store-backed loader keys directly on the PEM bytes
/// (`okta/private_key_pem`) rather than a filesystem path, so an
/// external KMS or Vault can supply the material without writing it to
/// disk. The PEM-marker sanity check is preserved for parity with the
/// env-file loader.
const STORE_KEY_ORG_URL: &str = "okta/org-url";
const STORE_KEY_CLIENT_ID: &str = "okta/client-id";
const STORE_KEY_PRIVATE_KEY_PEM: &str = "okta/private-key-pem";
const STORE_KEY_KEY_ID: &str = "okta/key-id";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `okta/org-url`, `okta/client-id`, `okta/private-key-pem` (the
/// PEM bytes themselves, not a filesystem path), and `okta/key-id` from
/// a generic [`CredentialStore`] impl. Returns `Ok(None)` if any
/// required key is absent or if the PEM bytes lack a `PRIVATE KEY`
/// marker, so daemon startup falls back to `MockBroker` cleanly when
/// the store is empty or misconfigured (mirrors `load_from_dir`).
pub async fn okta_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<OktaServiceApp>, crate::infra::credential_store::StoreError> {
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

    let org_url = get_opt(store, STORE_KEY_ORG_URL).await?;
    let client_id = get_opt(store, STORE_KEY_CLIENT_ID).await?;
    let private_key_pem = get_opt(store, STORE_KEY_PRIVATE_KEY_PEM).await?;
    let key_id = get_opt(store, STORE_KEY_KEY_ID).await?;

    let (org_url, client_id, private_key_pem, key_id) =
        match (org_url, client_id, private_key_pem, key_id) {
            (Some(o), Some(c), Some(p), Some(k)) => (o, c, p, k),
            _ => return Ok(None),
        };

    if !private_key_pem.contains("PRIVATE KEY") {
        // Fail closed → daemon falls back to mock so a malformed key
        // does not get exercised on the first real broker_issue.
        return Ok(None);
    }

    Ok(Some(OktaServiceApp {
        org_url,
        client_id,
        private_key_pem: SecretString::from(private_key_pem),
        key_id,
    }))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `hashivault_config::parse_env_var` so
/// the dotenv shape stays consistent across providers.
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

    // PEM fixture lives at `crates/ember-daemon/tests/fixtures/okta_service_app.pem`
    // so it resolves under the gitleaks `.gitleaks.toml` path allowlist for
    // `crates/.+/tests/fixtures/.+` and never appears as an inline PEM literal
    // in `src/` (which the public-mirror sync would otherwise flag).
    const FIXTURE_PEM: &str = include_str!("../../tests/fixtures/okta_service_app.pem");

    fn write(path: &std::path::Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn load_from_dir_missing_file_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_with_all_keys_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_path = tmp.path().join("okta-key.pem");
        write(&pem_path, FIXTURE_PEM);
        let env = format!(
            "OKTA_ORG_URL=https://example.okta.com\n\
             OKTA_CLIENT_ID=0oa-service-app\n\
             OKTA_PRIVATE_KEY_PATH={}\n\
             OKTA_KEY_ID=test-kid-1\n",
            pem_path.display()
        );
        write(&tmp.path().join(ENV_FILENAME), &env);

        let creds = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.org_url, "https://example.okta.com");
        assert_eq!(creds.client_id, "0oa-service-app");
        assert_eq!(creds.key_id, "test-kid-1");
        assert!(
            creds
                .private_key_pem
                .expose_secret()
                .contains("PRIVATE KEY"),
            "PEM contents must be loaded into the secret"
        );
    }

    #[test]
    fn load_from_dir_missing_org_url_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_path = tmp.path().join("okta-key.pem");
        write(&pem_path, FIXTURE_PEM);
        let env = format!(
            "OKTA_CLIENT_ID=0oa-service-app\n\
             OKTA_PRIVATE_KEY_PATH={}\n\
             OKTA_KEY_ID=test-kid-1\n",
            pem_path.display()
        );
        write(&tmp.path().join(ENV_FILENAME), &env);
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_missing_client_id_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_path = tmp.path().join("okta-key.pem");
        write(&pem_path, FIXTURE_PEM);
        let env = format!(
            "OKTA_ORG_URL=https://example.okta.com\n\
             OKTA_PRIVATE_KEY_PATH={}\n\
             OKTA_KEY_ID=test-kid-1\n",
            pem_path.display()
        );
        write(&tmp.path().join(ENV_FILENAME), &env);
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_missing_key_id_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_path = tmp.path().join("okta-key.pem");
        write(&pem_path, FIXTURE_PEM);
        let env = format!(
            "OKTA_ORG_URL=https://example.okta.com\n\
             OKTA_CLIENT_ID=0oa-service-app\n\
             OKTA_PRIVATE_KEY_PATH={}\n",
            pem_path.display()
        );
        write(&tmp.path().join(ENV_FILENAME), &env);
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_unreadable_pem_path_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = "OKTA_ORG_URL=https://example.okta.com\n\
                   OKTA_CLIENT_ID=0oa-service-app\n\
                   OKTA_PRIVATE_KEY_PATH=/nonexistent/path/key.pem\n\
                   OKTA_KEY_ID=test-kid-1\n";
        write(&tmp.path().join(ENV_FILENAME), env);
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_pem_without_marker_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pem_path = tmp.path().join("okta-key.pem");
        // Not a PEM — just garbage. The loader fails closed so we
        // don't get a confusing error when the JWT signer rejects it.
        write(&pem_path, "this is not a pem file");
        let env = format!(
            "OKTA_ORG_URL=https://example.okta.com\n\
             OKTA_CLIENT_ID=0oa-service-app\n\
             OKTA_PRIVATE_KEY_PATH={}\n\
             OKTA_KEY_ID=test-kid-1\n",
            pem_path.display()
        );
        write(&tmp.path().join(ENV_FILENAME), &env);
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "OKTA_ORG_URL=\"https://example.okta.com\"\n\
                   OKTA_CLIENT_ID='0oa-quoted'\n";
        assert_eq!(
            parse_env_var(env, "OKTA_ORG_URL"),
            Some("https://example.okta.com".to_string())
        );
        assert_eq!(
            parse_env_var(env, "OKTA_CLIENT_ID"),
            Some("0oa-quoted".to_string())
        );
    }

    #[tokio::test]
    async fn okta_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_ORG_URL, b"https://example.okta.com")
            .await
            .unwrap();
        mock.put(STORE_KEY_CLIENT_ID, b"0oa-service-app")
            .await
            .unwrap();
        mock.put(STORE_KEY_PRIVATE_KEY_PEM, FIXTURE_PEM.as_bytes())
            .await
            .unwrap();
        mock.put(STORE_KEY_KEY_ID, b"test-kid-1").await.unwrap();

        let result = okta_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.org_url, "https://example.okta.com");
        assert_eq!(creds.client_id, "0oa-service-app");
        assert_eq!(creds.key_id, "test-kid-1");
        assert!(
            creds
                .private_key_pem
                .expose_secret()
                .contains("PRIVATE KEY"),
            "PEM contents must be loaded into the secret"
        );
    }
}
