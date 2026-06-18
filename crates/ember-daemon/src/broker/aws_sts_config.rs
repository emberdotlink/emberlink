//! AWS long-lived credential discovery for the daemon's broker
//! registry. Mirrors the shape of `github_config.rs` so wireup is
//! homogeneous across providers.
//!
//! Reads `~/.config/emberlink/aws-sts.env` (key-value, `KEY=value`
//! lines) for the IAM-user access key id + secret + region the
//! daemon hands to [`ember_broker::AwsStsBroker`]. The optional
//! `AWS_DEFAULT_ROLE_ARN` value is the role assumed when a broker
//! request omits an explicit `role_arn`.
//!
//! Behaviour contract:
//!
//! - File present + required keys → `Some(creds)`. Daemon registers
//!   [`ember_broker::AwsStsBroker`] for `BrokerProvider::AwsSts`.
//! - File absent → `None`. Daemon logs a warning and falls back to
//!   `MockBroker` so dev hosts without AWS config still answer
//!   `broker_issue` without a panic.
//! - File present but missing required keys → `None` (treated as
//!   misconfigured; daemon falls back to mock). Required keys:
//!   `AWS_LONG_LIVED_KEY_ID`, `AWS_LONG_LIVED_KEY_SECRET`,
//!   `AWS_LONG_LIVED_REGION`.

use std::fs;
use std::path::PathBuf;

use ember_broker::AwsLongLivedCredentials;
use secrecy::SecretString;

/// Filename inside `~/.config/emberlink/` containing the AWS long-lived
/// access key id + secret + default region (and optional role ARN).
const ENV_FILENAME: &str = "aws-sts.env";

/// Required: AWS access key id of the long-lived IAM user backing the
/// broker.
const KEY_ACCESS_KEY_ID: &str = "AWS_LONG_LIVED_KEY_ID";

/// Required: AWS secret access key paired with `AWS_LONG_LIVED_KEY_ID`.
const KEY_SECRET_ACCESS_KEY: &str = "AWS_LONG_LIVED_KEY_SECRET";

/// Required: AWS region for the STS endpoint
/// (`sts.<region>.amazonaws.com`).
const KEY_REGION: &str = "AWS_LONG_LIVED_REGION";

/// Optional: session token for already-session-scoped long-lived
/// credentials. Most installs use IAM-user keys with no session token,
/// so this is rare in practice.
const KEY_SESSION_TOKEN: &str = "AWS_LONG_LIVED_SESSION_TOKEN";

/// Optional: default role ARN to assume when `BrokerRequest::scope`
/// omits one. Lets a dev host pre-configure "always assume role X"
/// without coupling every caller to the ARN.
const KEY_DEFAULT_ROLE_ARN: &str = "AWS_DEFAULT_ROLE_ARN";

/// Optional: filesystem path holding an OIDC token (k8s SA projected
/// volume, GitHub Actions $ACTIONS_ID_TOKEN_REQUEST_TOKEN one-shot,
/// EKS IRSA `AWS_WEB_IDENTITY_TOKEN_FILE`, etc.). When set, the
/// daemon should read the token at request time and route the broker
/// call through `AwsStsScope::WebIdentity` (AssumeRoleWithWebIdentity
/// — see `ember_broker::aws_sts::assume_role_with_web_identity`)
/// **in preference to** the long-lived `AWS_LONG_LIVED_KEY_*`
/// credentials. Long-lived keys remain a fallback for hosts that
/// don't have a federated identity.
///
/// Precedence rule (when daemon-side wireup lands; see
/// BROKER-AWS-STS-WEB-IDENTITY-DAEMON-WIRE follow-up):
///
/// 1. `AWS_OIDC_TOKEN_PATH` set + readable file → WebIdentity mode
/// 2. `AWS_LONG_LIVED_KEY_ID` + secret + region present → AssumeRole
///    / GetSessionToken via SigV4
/// 3. neither present → daemon registers `MockBroker` (current
///    behaviour for unconfigured dev hosts)
///
/// The receiving field is reserved here; load_from_dir() does not
/// yet read it (the broker accepts an already-loaded
/// `SecretString` per the BROKER-AWS-STS-WEB-IDENTITY brief).
#[allow(dead_code)]
const KEY_OIDC_TOKEN_PATH: &str = "AWS_OIDC_TOKEN_PATH";

/// Try to load AWS long-lived credentials from the operator's user-level
/// configuration. Returns `None` if the file is absent or required keys
/// are missing (graceful — daemon continues with `MockBroker`).
///
/// The optional default role ARN is returned alongside the credentials
/// so the broker can be instantiated with one constructor call.
pub fn load_aws_sts_credentials() -> Option<(AwsLongLivedCredentials, Option<String>)> {
    let home = std::env::var("HOME").ok()?;
    let base = PathBuf::from(&home).join(".config").join("emberlink");
    load_from_dir(&base)
}

/// Inner function — takes a base directory so unit tests can point at
/// a tempdir without touching the user's real `~/.config/emberlink`.
pub fn load_from_dir(base: &std::path::Path) -> Option<(AwsLongLivedCredentials, Option<String>)> {
    let env_path = base.join(ENV_FILENAME);
    if !env_path.exists() {
        return None;
    }

    let env_contents = match fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let access_key_id = parse_env_var(&env_contents, KEY_ACCESS_KEY_ID)?;
    let secret_access_key = parse_env_var(&env_contents, KEY_SECRET_ACCESS_KEY)?;
    let region = parse_env_var(&env_contents, KEY_REGION)?;

    let session_token = parse_env_var(&env_contents, KEY_SESSION_TOKEN);
    let default_role_arn = parse_env_var(&env_contents, KEY_DEFAULT_ROLE_ARN);

    Some((
        AwsLongLivedCredentials {
            access_key_id,
            secret_access_key: SecretString::from(secret_access_key),
            session_token,
            region,
        },
        default_role_arn,
    ))
}

/// Store-key namespace constants used by `aws_sts_config_from_store`.
const STORE_KEY_ACCESS_KEY_ID: &str = "aws-sts/access-key-id";
const STORE_KEY_SECRET_ACCESS_KEY: &str = "aws-sts/secret-access-key";
const STORE_KEY_REGION: &str = "aws-sts/region";
const STORE_KEY_SESSION_TOKEN: &str = "aws-sts/session-token";
const STORE_KEY_DEFAULT_ROLE_ARN: &str = "aws-sts/default-role-arn";

/// `CredentialStore`-backed sibling to [`load_from_dir`].
///
/// Reads the same fields as the env-file loader from a generic
/// [`CredentialStore`] impl. Returns `Ok(None)` if any of the required
/// keys (`aws-sts/access-key-id`, `aws-sts/secret-access-key`,
/// `aws-sts/region`) is absent. The optional default role ARN is
/// returned alongside the credentials so the broker can be instantiated
/// with one constructor call (mirrors [`load_from_dir`]'s tuple shape).
pub async fn aws_sts_config_from_store(
    store: &dyn crate::infra::credential_store::CredentialStore,
) -> Result<
    Option<(AwsLongLivedCredentials, Option<String>)>,
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

    let access_key_id = get_opt(store, STORE_KEY_ACCESS_KEY_ID).await?;
    let secret_access_key = get_opt(store, STORE_KEY_SECRET_ACCESS_KEY).await?;
    let region = get_opt(store, STORE_KEY_REGION).await?;
    let session_token = get_opt(store, STORE_KEY_SESSION_TOKEN).await?;
    let default_role_arn = get_opt(store, STORE_KEY_DEFAULT_ROLE_ARN).await?;

    let (access_key_id, secret_access_key, region) =
        match (access_key_id, secret_access_key, region) {
            (Some(a), Some(s), Some(r)) => (a, s, r),
            _ => return Ok(None),
        };

    Ok(Some((
        AwsLongLivedCredentials {
            access_key_id,
            secret_access_key: SecretString::from(secret_access_key),
            session_token,
            region,
        },
        default_role_arn,
    )))
}

/// Parse a single `KEY=value` line from a dotenv-style file. Strips
/// surrounding double or single quotes from the value. Returns `None`
/// if the key is absent. Mirrors `github_config::parse_env_var` so the
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
            "AWS_LONG_LIVED_KEY_ID=AKIATESTKEY\n\
             AWS_LONG_LIVED_KEY_SECRET=secretvaluexyz\n\
             AWS_LONG_LIVED_REGION=us-west-2\n",
        );
        let (creds, default_role) = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.access_key_id, "AKIATESTKEY");
        assert_eq!(creds.secret_access_key.expose_secret(), "secretvaluexyz");
        assert_eq!(creds.region, "us-west-2");
        assert_eq!(creds.session_token, None);
        assert_eq!(default_role, None);
    }

    #[test]
    fn load_from_dir_with_optional_default_role_arn_returns_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AWS_LONG_LIVED_KEY_ID=AKIATESTKEY\n\
             AWS_LONG_LIVED_KEY_SECRET=secretvaluexyz\n\
             AWS_LONG_LIVED_REGION=us-east-1\n\
             AWS_DEFAULT_ROLE_ARN=arn:aws:iam::111122223333:role/dev\n",
        );
        let (_creds, default_role) = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(
            default_role.as_deref(),
            Some("arn:aws:iam::111122223333:role/dev")
        );
    }

    #[test]
    fn load_from_dir_missing_required_key_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Missing AWS_LONG_LIVED_REGION
        write(
            &tmp.path().join(ENV_FILENAME),
            "AWS_LONG_LIVED_KEY_ID=AKIATESTKEY\n\
             AWS_LONG_LIVED_KEY_SECRET=secretvaluexyz\n",
        );
        assert!(
            load_from_dir(tmp.path()).is_none(),
            "missing region must return None"
        );
    }

    #[test]
    fn load_from_dir_with_session_token_returns_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write(
            &tmp.path().join(ENV_FILENAME),
            "AWS_LONG_LIVED_KEY_ID=AKIATESTKEY\n\
             AWS_LONG_LIVED_KEY_SECRET=secretvaluexyz\n\
             AWS_LONG_LIVED_REGION=us-east-1\n\
             AWS_LONG_LIVED_SESSION_TOKEN=tok123\n",
        );
        let (creds, _) = load_from_dir(tmp.path()).expect("must load");
        assert_eq!(creds.session_token.as_deref(), Some("tok123"));
    }

    #[test]
    fn parse_env_var_strips_quotes_and_whitespace() {
        let env = "AWS_LONG_LIVED_KEY_ID=\"AKIATESTKEY\"\nAWS_LONG_LIVED_REGION='us-east-1'\n";
        assert_eq!(
            parse_env_var(env, "AWS_LONG_LIVED_KEY_ID"),
            Some("AKIATESTKEY".to_string())
        );
        assert_eq!(
            parse_env_var(env, "AWS_LONG_LIVED_REGION"),
            Some("us-east-1".to_string())
        );
    }

    #[test]
    fn parse_env_var_skips_comments_and_blanks() {
        let env = "\n# comment\n\nAWS_LONG_LIVED_KEY_ID=42\n";
        assert_eq!(
            parse_env_var(env, "AWS_LONG_LIVED_KEY_ID"),
            Some("42".to_string())
        );
    }

    #[tokio::test]
    async fn aws_sts_config_from_store_happy_path() {
        use crate::infra::credential_store::CredentialStore;
        use crate::infra::credential_store::test_helpers::MockCredentialStore;

        let mock = MockCredentialStore::new();
        mock.put(STORE_KEY_ACCESS_KEY_ID, b"AKIATESTKEY")
            .await
            .unwrap();
        mock.put(STORE_KEY_SECRET_ACCESS_KEY, b"secretvaluexyz")
            .await
            .unwrap();
        mock.put(STORE_KEY_REGION, b"us-west-2").await.unwrap();

        let result = aws_sts_config_from_store(&mock).await.unwrap();
        let (creds, default_role) = result.expect("credentials should be present");
        assert_eq!(creds.access_key_id, "AKIATESTKEY");
        assert_eq!(creds.secret_access_key.expose_secret(), "secretvaluexyz");
        assert_eq!(creds.region, "us-west-2");
        assert_eq!(creds.session_token, None);
        assert_eq!(default_role, None);
    }
}
