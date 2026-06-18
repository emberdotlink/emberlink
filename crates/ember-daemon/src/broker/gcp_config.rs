//! GCP service-account key discovery for the daemon's broker registry.
//!
//! Reads `~/.config/emberlink/gcp.env` (key-value, `KEY=value` lines)
//! for the path to a downloaded GCP service-account JSON key file plus
//! an optional default impersonation target. The JSON key file is
//! parsed at daemon startup and the relevant fields handed to
//! [`ember_broker::GcpBroker`].
//!
//! Behaviour contract (mirrors `aws_sts_config`):
//!
//! - `gcp.env` present + `GCP_SERVICE_ACCOUNT_KEY_PATH` set + JSON key
//!   file readable + JSON has `client_email` + `private_key` +
//!   `project_id` → `Some((key, default_target))`. Daemon registers
//!   [`ember_broker::GcpBroker`] for `BrokerProvider::Gcp`.
//! - `gcp.env` absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without GCP config still answer
//!   `broker_issue` without a panic.
//! - `gcp.env` present but `GCP_SERVICE_ACCOUNT_KEY_PATH` missing /
//!   unreadable / JSON malformed → `None` (treated as misconfigured;
//!   daemon falls back to mock).

use std::fs;
use std::path::PathBuf;

use ember_broker::{GcpAuthMethod, GcpServiceAccountKey};
use secrecy::SecretString;
use serde::Deserialize;

/// Filename inside `~/.config/emberlink/` containing the env-style
/// GCP config (path to the JSON key, optional default target).
const ENV_FILENAME: &str = "gcp.env";

/// Required key in `gcp.env`: filesystem path to the downloaded GCP
/// service-account JSON key file.
const KEY_KEY_PATH: &str = "GCP_SERVICE_ACCOUNT_KEY_PATH";

/// Optional key in `gcp.env`: default impersonation target service
/// account email used when `BrokerRequest::scope.target_service_account`
/// is empty.
const KEY_DEFAULT_TARGET: &str = "GCP_DEFAULT_TARGET_SERVICE_ACCOUNT";

/// Optional key in `gcp.env`: filesystem path holding an OIDC token
/// (k8s SA projected volume, GitHub Actions $ACTIONS_ID_TOKEN_REQUEST_TOKEN
/// one-shot, generic Workload Identity Federation token-exchange
/// material). When set, the daemon should read the token at request
/// time and route the broker call through
/// [`GcpAuthMethod::WorkloadIdentityFederation`] (sts.googleapis.com
/// token-exchange — see `ember_broker::gcp::gcp_workload_identity_exchange`).
///
/// Precedence rule (mirrors `aws_sts_config::KEY_OIDC_TOKEN_PATH`):
///
/// 1. `GCP_SERVICE_ACCOUNT_KEY_PATH` set + JSON readable → SA-key
///    mode (the historical default; SA-key wins for backward compat
///    so existing configurations keep working unchanged).
/// 2. `GCP_OIDC_TOKEN_PATH` set + readable file (and SA-key path
///    absent) → Workload Identity Federation mode.
/// 3. neither present → daemon registers `MockBroker` (current
///    behaviour for unconfigured dev hosts).
///
/// The receiving const is reserved here; load_from_dir() does not yet
/// read it (full daemon-side wireup follows in
/// BROKER-GCP-WORKLOAD-IDENTITY-DAEMON-WIRE — the broker accepts an
/// already-resolved [`GcpAuthMethod`] per the BROKER-GCP-WORKLOAD-
/// IDENTITY brief, mirroring the AWS-STS WI groundwork).
#[allow(dead_code)]
const KEY_OIDC_TOKEN_PATH: &str = "GCP_OIDC_TOKEN_PATH";

/// Optional key in `gcp.env`: full Workload Identity Pool / Provider
/// audience URL used as the `audience` parameter on the STS token-
/// exchange call. Required alongside `GCP_OIDC_TOKEN_PATH` when WIF
/// mode is selected. Reserved here for the same reason as
/// [`KEY_OIDC_TOKEN_PATH`] — receiving const, no load wireup yet.
#[allow(dead_code)]
const KEY_WIF_AUDIENCE: &str = "GCP_WIF_AUDIENCE";

/// Subset of fields we read from the GCP service-account JSON key
/// file. Google's downloaded JSON includes additional fields
/// (`type`, `private_key_id`, `client_id`, `auth_uri`, etc.) we ignore.
#[derive(Debug, Deserialize)]
struct GcpKeyJson {
    client_email: String,
    private_key: String,
    project_id: String,
}

/// Try to load GCP service-account credentials from the operator's
/// user-level configuration. Returns `None` if any step fails (file
/// missing, env value missing, key file unreadable, JSON malformed).
pub fn load_gcp_credentials() -> Option<(GcpServiceAccountKey, Option<String>)> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<(GcpServiceAccountKey, Option<String>)> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }
    let env_contents = fs::read_to_string(&env_path).ok()?;

    let key_path = parse_env_var(&env_contents, KEY_KEY_PATH)?;
    let default_target = parse_env_var(&env_contents, KEY_DEFAULT_TARGET);

    let key_path = PathBuf::from(key_path);
    let key_json_bytes = fs::read_to_string(&key_path).ok()?;
    let parsed: GcpKeyJson = serde_json::from_str(&key_json_bytes).ok()?;

    if parsed.client_email.is_empty()
        || parsed.private_key.is_empty()
        || parsed.project_id.is_empty()
    {
        return None;
    }

    Some((
        GcpServiceAccountKey {
            client_email: parsed.client_email,
            private_key: SecretString::from(parsed.private_key),
            project_id: parsed.project_id,
            // SA-key path remains the default (precedence rule above).
            // Full WIF wireup is deferred to a follow-up; the broker
            // already handles the WIF variant — this loader just hasn't
            // been taught to construct it yet.
            auth_method: GcpAuthMethod::ServiceAccountKey,
        },
        default_target,
    ))
}

/// Store-key namespace constants used by `gcp_config_from_store`.
///
/// Unlike the env-file loader (which reads a path to a JSON key file
/// and parses it), the store-backed loader keys directly on the three
/// fields the broker actually needs (`client_email`, `private_key`,
/// `project_id`) plus an optional default impersonation target. This
/// mirrors how an external KMS or Vault would be expected to expose
/// pre-extracted material rather than the original JSON envelope.
const STORE_KEY_CLIENT_EMAIL: &str = "gcp/client-email";
const STORE_KEY_PRIVATE_KEY: &str = "gcp/private-key";
const STORE_KEY_PROJECT_ID: &str = "gcp/project-id";
const STORE_KEY_DEFAULT_TARGET: &str = "gcp/default-target-service-account";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads `gcp/client-email`, `gcp/private-key`, `gcp/project-id`, and
/// the optional `gcp/default-target-service-account` from a generic
/// [`CredentialStore`] impl. Returns `Ok(None)` if any of the three
/// required keys is absent or empty so daemon startup falls back to
/// `MockBroker` cleanly when the store is empty.
pub async fn gcp_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<
    Option<(GcpServiceAccountKey, Option<String>)>,
    crate::infra::credential_store::StoreError,
> {
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

    let client_email = get_opt(store, STORE_KEY_CLIENT_EMAIL).await?;
    let private_key = get_opt(store, STORE_KEY_PRIVATE_KEY).await?;
    let project_id = get_opt(store, STORE_KEY_PROJECT_ID).await?;
    let default_target = get_opt(store, STORE_KEY_DEFAULT_TARGET).await?;

    let (client_email, private_key, project_id) = match (client_email, private_key, project_id) {
        (Some(c), Some(k), Some(p)) if !c.is_empty() && !k.is_empty() && !p.is_empty() => (c, k, p),
        _ => return Ok(None),
    };

    Ok(Some((
        GcpServiceAccountKey {
            client_email,
            private_key: SecretString::from(private_key),
            project_id,
            // Mirrors load_from_dir: SA-key path is the historical
            // default for backward compat. Full WIF wireup follows in
            // BROKER-GCP-WORKLOAD-IDENTITY-DAEMON-WIRE.
            auth_method: GcpAuthMethod::ServiceAccountKey,
        },
        default_target,
    )))
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

    fn fixture_key_json() -> String {
        // Minimal subset of a real downloaded GCP SA key JSON.
        // private_key value is a placeholder PEM; load_from_dir does
        // not crypto-validate it (that happens at issue-time).
        serde_json::json!({
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "abc123",
            "private_key": fake_private_key_pem(),
            "client_email": "ember-broker@test-project.iam.gserviceaccount.com",
            "client_id": "1234567890",
        })
        .to_string()
    }

    fn fake_private_key_pem() -> String {
        format!(
            "{}PRIVATE KEY-----\nFAKEKEYDATA\n{}PRIVATE KEY-----\n",
            "-----BEGIN ",
            "-----END "
        )
    }

    #[test]
    fn load_from_dir_missing_env_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_with_key_path_returns_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("sa-key.json");
        write(&key_path, &fixture_key_json());
        write(
            &tmp.path().join(ENV_FILENAME),
            &format!("GCP_SERVICE_ACCOUNT_KEY_PATH={}\n", key_path.display()),
        );
        let (key, default_target) = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(
            key.client_email,
            "ember-broker@test-project.iam.gserviceaccount.com"
        );
        assert_eq!(key.project_id, "test-project");
        assert!(
            key.private_key
                .expose_secret()
                .contains("BEGIN PRIVATE KEY")
        );
        assert_eq!(default_target, None);
    }

    #[test]
    fn load_from_dir_with_default_target_returns_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("sa-key.json");
        write(&key_path, &fixture_key_json());
        write(
            &tmp.path().join(ENV_FILENAME),
            &format!(
                "GCP_SERVICE_ACCOUNT_KEY_PATH={}\nGCP_DEFAULT_TARGET_SERVICE_ACCOUNT=deployer@target.iam.gserviceaccount.com\n",
                key_path.display(),
            ),
        );
        let (_key, default_target) = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(
            default_target.as_deref(),
            Some("deployer@target.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn load_from_dir_missing_key_path_var_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "GCP_DEFAULT_TARGET_SERVICE_ACCOUNT=x@y\n",
        );
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_unreadable_key_file_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "GCP_SERVICE_ACCOUNT_KEY_PATH=/nonexistent/path/sa.json\n",
        );
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_malformed_json_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("sa-key.json");
        write(&key_path, "not json at all");
        write(
            &tmp.path().join(ENV_FILENAME),
            &format!("GCP_SERVICE_ACCOUNT_KEY_PATH={}\n", key_path.display()),
        );
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn load_from_dir_json_missing_required_field_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("sa-key.json");
        // Omits client_email
        write(
            &key_path,
            &serde_json::json!({
                "project_id": "p",
                "private_key": "---KEY---",
            })
            .to_string(),
        );
        write(
            &tmp.path().join(ENV_FILENAME),
            &format!("GCP_SERVICE_ACCOUNT_KEY_PATH={}\n", key_path.display()),
        );
        assert!(load_from_dir(tmp.path()).is_none());
    }

    #[test]
    fn parse_env_var_strips_quotes() {
        let env = "GCP_SERVICE_ACCOUNT_KEY_PATH=\"/path/to/key.json\"\nGCP_DEFAULT_TARGET_SERVICE_ACCOUNT='x@y'\n";
        assert_eq!(
            parse_env_var(env, "GCP_SERVICE_ACCOUNT_KEY_PATH"),
            Some("/path/to/key.json".to_string())
        );
        assert_eq!(
            parse_env_var(env, "GCP_DEFAULT_TARGET_SERVICE_ACCOUNT"),
            Some("x@y".to_string())
        );
    }

    #[tokio::test]
    async fn gcp_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(
            STORE_KEY_CLIENT_EMAIL,
            b"ember-broker@test-project.iam.gserviceaccount.com",
        )
        .await
        .unwrap();
        let private_key = fake_private_key_pem();
        mock.put(STORE_KEY_PRIVATE_KEY, private_key.as_bytes())
            .await
            .unwrap();
        mock.put(STORE_KEY_PROJECT_ID, b"test-project")
            .await
            .unwrap();

        let result = gcp_config_from_store(&mock).await.unwrap();
        let (key, default_target) = result.expect("credentials should be present");
        assert_eq!(
            key.client_email,
            "ember-broker@test-project.iam.gserviceaccount.com"
        );
        assert_eq!(key.project_id, "test-project");
        assert!(
            key.private_key
                .expose_secret()
                .contains("BEGIN PRIVATE KEY")
        );
        assert_eq!(default_target, None);
    }
}
