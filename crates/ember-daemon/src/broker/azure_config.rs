//! Azure AD service-principal discovery for the daemon's broker
//! registry. Mirrors the shape of `aws_sts_config.rs` /
//! `gcp_config.rs` so wireup is homogeneous across providers.
//!
//! Reads `~/.config/emberlink/azure.env` (key-value, `KEY=value`
//! lines) for the tenant id, client id, and either a client secret
//! (default) or an OIDC-token path for Workload Identity Federation.
//! The chosen credentials are handed to
//! [`ember_broker::AzureCliBroker`].
//!
//! Behaviour contract:
//!
//! - File present + (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID`) and EITHER
//!   `AZURE_CLIENT_SECRET` (default) OR `AZURE_OIDC_TOKEN_PATH` (WIF) →
//!   `Some(AzureServicePrincipal)`. Daemon registers
//!   [`ember_broker::AzureCliBroker`] for `BrokerProvider::AzureCli`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without Azure config still answer
//!   `broker_issue` without a panic.
//! - File present but missing required keys, OR neither of
//!   client-secret / oidc-token-path is set → `None` (treated as
//!   misconfigured; daemon falls back to mock).
//!
//! `AZURE_CLIENT_SECRET` is the historical default; setting
//! `AZURE_OIDC_TOKEN_PATH` opts in to Workload Identity Federation
//! (Kubernetes / GitHub Actions / generic-OIDC). When BOTH are set,
//! `AZURE_CLIENT_SECRET` wins so existing dev configs keep working
//! without surprise after a partial WIF rollout.

use std::fs;
use std::path::PathBuf;

use ember_broker::{AzureAuthMethod, AzureServicePrincipal};
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// Azure AD service-principal credentials.
const ENV_FILENAME: &str = "azure.env";

/// Required: Azure AD tenant id (UUID). Embedded in the OAuth token
/// endpoint URL.
const KEY_TENANT_ID: &str = "AZURE_TENANT_ID";

/// Required: service-principal application (client) id.
const KEY_CLIENT_ID: &str = "AZURE_CLIENT_ID";

/// Optional (default auth method): service-principal client secret.
/// Held in [`SecretString`] inside the loaded credentials so it cannot
/// be accidentally `Debug`-printed. Mutually exclusive with
/// `AZURE_OIDC_TOKEN_PATH` at the auth-method level; if both are set,
/// `AZURE_CLIENT_SECRET` wins.
const KEY_CLIENT_SECRET: &str = "AZURE_CLIENT_SECRET";

/// Optional (Workload Identity Federation): filesystem path to a fresh
/// OIDC token. The broker reads this file on every `issue()` and
/// submits the contents as `client_assertion`. Pairs with a
/// federated-credential trust record on the SP app registration.
const KEY_OIDC_TOKEN_PATH: &str = "AZURE_OIDC_TOKEN_PATH";

/// Try to load Azure AD service-principal credentials from the
/// operator's user-level configuration. Returns `None` if the file is
/// absent or any required key is missing (graceful — daemon
/// continues with `MockBroker`).
pub fn load_azure_credentials() -> Option<AzureServicePrincipal> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<AzureServicePrincipal> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let tenant_id = parse_env_var(&env_contents, KEY_TENANT_ID)?;
    let client_id = parse_env_var(&env_contents, KEY_CLIENT_ID)?;

    // Default: client-secret if present. Otherwise fall back to WIF
    // when AZURE_OIDC_TOKEN_PATH is set. Neither set → misconfigured.
    let auth_method = if let Some(client_secret) = parse_env_var(&env_contents, KEY_CLIENT_SECRET) {
        AzureAuthMethod::ClientSecret {
            client_secret: SecretString::from(client_secret),
        }
    } else if let Some(path) = parse_env_var(&env_contents, KEY_OIDC_TOKEN_PATH) {
        AzureAuthMethod::FederatedIdentity {
            oidc_token_path: PathBuf::from(path),
        }
    } else {
        return None;
    };

    Some(AzureServicePrincipal {
        tenant_id,
        client_id,
        auth_method,
    })
}

/// Store-key namespace constants used by `azure_config_from_store`.
///
/// The store-keying convention (`azure/<lowercase-field>`) mirrors the
/// existing vault-namespacing per ADR 099 and keeps backends like
/// HashiCorp Vault from colliding when multiple providers share the
/// same secret store.
const STORE_KEY_TENANT_ID: &str = "azure/tenant-id";
const STORE_KEY_CLIENT_ID: &str = "azure/client-id";
const STORE_KEY_CLIENT_SECRET: &str = "azure/client-secret";
const STORE_KEY_OIDC_TOKEN_PATH: &str = "azure/oidc-token-path";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads the same fields as the env-file loader from a generic
/// [`CredentialStore`] impl. Returns `Ok(None)` if `azure/tenant-id` or
/// `azure/client-id` is absent, OR if neither `azure/client-secret` nor
/// `azure/oidc-token-path` is set. Matches the env-file loader's
/// graceful-degrade behaviour so daemon startup falls back to
/// `MockBroker` cleanly when the store is empty.
///
/// Precedence rule mirrors [`load_from_dir`]: when both
/// `azure/client-secret` and `azure/oidc-token-path` are present,
/// `client_secret` wins (backward-compat with existing dev configs that
/// pre-date Workload Identity Federation support).
pub async fn azure_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<Option<AzureServicePrincipal>, crate::infra::credential_store::StoreError> {
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

    let tenant_id = get_opt(store, STORE_KEY_TENANT_ID).await?;
    let client_id = get_opt(store, STORE_KEY_CLIENT_ID).await?;
    let client_secret = get_opt(store, STORE_KEY_CLIENT_SECRET).await?;
    let oidc_token_path = get_opt(store, STORE_KEY_OIDC_TOKEN_PATH).await?;

    let (tenant_id, client_id) = match (tenant_id, client_id) {
        (Some(t), Some(c)) => (t, c),
        _ => return Ok(None),
    };

    let auth_method = if let Some(secret) = client_secret {
        AzureAuthMethod::ClientSecret {
            client_secret: SecretString::from(secret),
        }
    } else if let Some(path) = oidc_token_path {
        AzureAuthMethod::FederatedIdentity {
            oidc_token_path: PathBuf::from(path),
        }
    } else {
        return Ok(None);
    };

    Ok(Some(AzureServicePrincipal {
        tenant_id,
        client_id,
        auth_method,
    }))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `aws_sts_config::parse_env_var` so
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
            "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n\
             AZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n\
             AZURE_CLIENT_SECRET=client-secret-xyz\n",
        );
        let sp = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(sp.tenant_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(sp.client_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        match &sp.auth_method {
            AzureAuthMethod::ClientSecret { client_secret } => {
                assert_eq!(client_secret.expose_secret(), "client-secret-xyz");
            }
            other => panic!("expected ClientSecret auth_method, got {other:?}"),
        }
    }

    #[test]
    fn load_from_dir_with_oidc_token_path_returns_federated_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n\
             AZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n\
             AZURE_OIDC_TOKEN_PATH=/var/run/secrets/azure/tokens/azure-identity-token\n",
        );
        let sp = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(sp.tenant_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(sp.client_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        match &sp.auth_method {
            AzureAuthMethod::FederatedIdentity { oidc_token_path } => {
                assert_eq!(
                    oidc_token_path.to_str(),
                    Some("/var/run/secrets/azure/tokens/azure-identity-token")
                );
            }
            other => panic!("expected FederatedIdentity auth_method, got {other:?}"),
        }
    }

    #[test]
    fn load_from_dir_client_secret_wins_when_both_auth_methods_set() {
        // Backward-compat invariant: existing dev configs that pre-date
        // WIF support keep working even after an operator adds an
        // AZURE_OIDC_TOKEN_PATH key alongside the legacy secret.
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n\
             AZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n\
             AZURE_CLIENT_SECRET=client-secret-xyz\n\
             AZURE_OIDC_TOKEN_PATH=/var/run/secrets/azure/tokens/azure-identity-token\n",
        );
        let sp = load_from_dir(tmp.path()).expect("must load");
        match &sp.auth_method {
            AzureAuthMethod::ClientSecret { client_secret } => {
                assert_eq!(client_secret.expose_secret(), "client-secret-xyz");
            }
            other => panic!("expected ClientSecret to win, got {other:?}"),
        }
    }

    #[test]
    fn load_from_dir_missing_tenant_id_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n\
             AZURE_CLIENT_SECRET=client-secret-xyz\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing tenant id must return None"
        );
    }

    #[test]
    fn load_from_dir_missing_client_id_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n\
             AZURE_CLIENT_SECRET=client-secret-xyz\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing client id must return None"
        );
    }

    #[test]
    fn load_from_dir_missing_both_auth_methods_returns_none() {
        // Tenant + client_id present but neither client_secret nor
        // oidc_token_path → misconfigured; daemon falls back to mock.
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555\n\
             AZURE_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing both client_secret and oidc_token_path must return None"
        );
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "AZURE_TENANT_ID=\"tenant-uuid\"\nAZURE_CLIENT_ID='client-uuid'\nAZURE_CLIENT_SECRET=plain\n";
        assert_eq!(
            parse_env_var(env, "AZURE_TENANT_ID"),
            Some("tenant-uuid".to_string())
        );
        assert_eq!(
            parse_env_var(env, "AZURE_CLIENT_ID"),
            Some("client-uuid".to_string())
        );
        assert_eq!(
            parse_env_var(env, "AZURE_CLIENT_SECRET"),
            Some("plain".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nAZURE_TENANT_ID=42\n";
        assert_eq!(
            parse_env_var(env, "AZURE_TENANT_ID"),
            Some("42".to_string())
        );
    }

    #[tokio::test]
    async fn azure_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_TENANT_ID, b"11111111-2222-3333-4444-555555555555")
            .await
            .unwrap();
        mock.put(STORE_KEY_CLIENT_ID, b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            .await
            .unwrap();
        mock.put(STORE_KEY_CLIENT_SECRET, b"client-secret-xyz")
            .await
            .unwrap();

        let result = azure_config_from_store(&mock).await.unwrap();
        let creds = result.expect("credentials should be present");
        assert_eq!(creds.tenant_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(creds.client_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        match &creds.auth_method {
            AzureAuthMethod::ClientSecret { client_secret } => {
                assert_eq!(client_secret.expose_secret(), "client-secret-xyz");
            }
            other => panic!("expected ClientSecret auth_method, got {other:?}"),
        }
    }
}
