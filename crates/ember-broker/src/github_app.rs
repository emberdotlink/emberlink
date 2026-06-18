//! GitHub App installation token minting (ADR 094 credential broker).
//!
//! Implements the three-step flow:
//! 1. Sign a short-lived JWT (RS256, 10-minute window) with the app's private key.
//! 2. POST to `https://api.github.com/app/installations/<id>/access_tokens` with
//!    the scoped repos + permissions in the body.
//! 3. Return the 1-hour installation token as [`InstallationToken`].
//!
//! No real GitHub API calls are made in tests — the [`HttpClient`] trait lets
//! tests inject a mock response.

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum GhAppError {
    #[error("not configured: {0}")]
    NotConfigured(String),
    #[error("jwt signing failed: {0}")]
    JwtSigning(String),
    #[error("http request failed: {0}")]
    Http(String),
    #[error("unexpected response (status={status}): {body}")]
    BadResponse { status: u16, body: String },
    #[error("response parse failed: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Credentials needed to authenticate as a GitHub App.
///
/// All three fields are required. `private_key_pem` is the RSA private key
/// exactly as exported from GitHub (PEM-encoded PKCS#8 or PKCS#1). Load from
/// the daemon vault path configured in the host's `GitHubAppConfig`
/// or fall back to the `GH_APP_PRIVATE_KEY_PEM` environment variable; the daemon
/// supplies a clear error when neither is set.
#[derive(Clone)]
pub struct GhAppCredentials {
    /// The numeric GitHub App ID (e.g. `"123456"`).
    pub app_id: String,
    /// The installation ID for the target account or organisation.
    pub installation_id: String,
    /// PEM-encoded RSA private key (PKCS#8 or traditional PKCS#1).
    /// Wrapped in `SecretString` — zeroized on drop so the PEM never
    /// lingers in freed heap memory.
    pub private_key_pem: SecretString,
}

/// A scoped, time-bound GitHub App installation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationToken {
    /// The raw bearer token string to pass as `Authorization: Bearer <token>`.
    pub token: String,
    /// When GitHub says this token expires (normally ~1 hour from mint time).
    pub expires_at: DateTime<Utc>,
    /// The provider's **authoritative scope echo** from the access-token
    /// response: the `permissions` GitHub actually granted, sorted for a stable
    /// record. The provider-truth half of the materialization audit event
    /// (ADR 204 amendment 2 / ADR 205 §B). Empty when GitHub omitted the field.
    #[serde(default)]
    pub granted_permissions: Vec<(String, String)>,
    /// The repositories (full `owner/repo` names, sorted) the token is scoped to.
    /// Empty when `repository_selection == "all"` (an all-repos token) or when
    /// GitHub omitted the field — an empty/all echo fails the downstream
    /// `native_upper_bound` bound closed rather than recording it as narrow.
    #[serde(default)]
    pub granted_repositories: Vec<String>,
    /// GitHub's `repository_selection` — `"all"` or `"selected"`. `"all"` means
    /// the token is NOT repo-bounded (the unbounded case).
    #[serde(default)]
    pub repository_selection: Option<String>,
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/// RS256 claims for the 10-minute GitHub App JWT. GitHub requires exactly
/// this shape: `iss` = app_id, `iat` = now, `exp` = now + 10 min.
#[derive(Debug, Serialize, Deserialize)]
struct GhJwtClaims {
    iss: String,
    iat: i64,
    exp: i64,
}

/// Build (but do not transmit) the RS256 JWT from a PEM key string and
/// the current time expressed as seconds-since-epoch.
///
/// Extracted as a free function so unit tests can call it with a deterministic
/// fixture key and a pinned timestamp without hitting the network.
pub fn build_jwt(
    app_id: &str,
    private_key_pem: &str,
    now_epoch_secs: i64,
) -> Result<String, GhAppError> {
    let exp = now_epoch_secs + 600; // 10-minute window per GitHub docs.
    let claims = GhJwtClaims {
        iss: app_id.to_string(),
        iat: now_epoch_secs,
        exp,
    };
    crate::install_jwt_crypto_provider();
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| GhAppError::JwtSigning(e.to_string()))?;
    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| GhAppError::JwtSigning(e.to_string()))
}

// ---------------------------------------------------------------------------
// Access-token request body
// ---------------------------------------------------------------------------

/// Body sent to `POST /app/installations/<id>/access_tokens`.
#[derive(Debug, Serialize)]
pub struct AccessTokenRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub permissions: std::collections::HashMap<String, String>,
}

/// Build the request body from caller-supplied slices.
///
/// Exported so tests can verify the serialized shape without hitting the
/// network.
pub fn build_access_token_request(
    repos: &[String],
    permissions: &[(String, String)],
) -> AccessTokenRequest {
    AccessTokenRequest {
        repositories: repos.to_vec(),
        permissions: permissions.iter().cloned().collect(),
    }
}

// ---------------------------------------------------------------------------
// GitHub API response
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GhAccessTokenResponse {
    token: String,
    expires_at: String, // RFC3339 from GitHub
    /// Permissions GitHub actually granted (`{"contents":"read", ...}`). The
    /// provider's authoritative scope echo (ADR 204 amendment 2 / ADR 205 §B).
    #[serde(default)]
    permissions: std::collections::HashMap<String, String>,
    /// The repositories the token is scoped to — present when
    /// `repository_selection == "selected"`.
    #[serde(default)]
    repositories: Vec<GhRepoRef>,
    /// `"all"` (not repo-bounded) or `"selected"`.
    #[serde(default)]
    repository_selection: Option<String>,
}

/// One repository in the access-token response's `repositories` array. We keep
/// only `full_name` (`owner/repo`) — the scope echo's target axis.
#[derive(Debug, Deserialize)]
struct GhRepoRef {
    full_name: String,
}

// ---------------------------------------------------------------------------
// HTTP abstraction (mockable in tests)
// ---------------------------------------------------------------------------

/// Minimal HTTP client trait so tests inject a mock without spinning up a
/// real TLS stack or hitting `api.github.com`.
///
/// Production callers use [`ReqwestClient`] (constructed from a live
/// `reqwest::Client`). Test callers use [`MockHttpClient`] below.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// POST JSON body to `url` with `Bearer <token>` authentication.
    /// Returns `(status_code, response_body_string)`.
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: &str,
    ) -> Result<(u16, String), GhAppError>;
}

// ---------------------------------------------------------------------------
// Real reqwest-backed client
// ---------------------------------------------------------------------------

/// Production [`HttpClient`] backed by `reqwest`.
pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new() -> Result<Self, GhAppError> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/gh-app-token-minter")
            .build()
            .map_err(|e| GhAppError::Http(format!("build reqwest client: {e}")))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction should not fail in production")
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: &str,
    ) -> Result<(u16, String), GhAppError> {
        let resp = self
            .inner
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| GhAppError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| GhAppError::Http(e.to_string()))?;
        Ok((status, text))
    }
}

// ---------------------------------------------------------------------------
// Core mint function
// ---------------------------------------------------------------------------

/// Mint a scoped GitHub App installation token.
///
/// # Parameters
/// - `creds` — App ID, installation ID, and PEM private key.
/// - `repos` — Repository names (without owner prefix) to restrict the token
///   to. Pass an empty slice to get the full installation scope.
/// - `permissions` — Fine-grained permission pairs such as
///   `[("contents", "read"), ("pull_requests", "write")]`. Pass an empty
///   slice to inherit all permissions granted to the installation.
///
/// # Errors
/// Returns [`GhAppError::NotConfigured`] when `creds` fields are empty so the
/// daemon can surface a clear message when the operator hasn't provisioned the
/// App credentials yet.
pub async fn mint_installation_token(
    creds: &GhAppCredentials,
    repos: &[String],
    permissions: &[(String, String)],
) -> Result<InstallationToken, GhAppError> {
    mint_installation_token_with_client(creds, repos, permissions, &ReqwestClient::default()).await
}

/// Testable variant of [`mint_installation_token`] with an injected HTTP client.
///
/// The `?Sized` bound lets callers pass `&dyn HttpClient` (or
/// `Arc<dyn HttpClient>::as_ref()`), which is what
/// [`crate::github_broker::GitHubBroker`] uses so it can hold the client
/// behind a trait object and swap implementations at construction time.
pub async fn mint_installation_token_with_client<C: HttpClient + ?Sized>(
    creds: &GhAppCredentials,
    repos: &[String],
    permissions: &[(String, String)],
    client: &C,
) -> Result<InstallationToken, GhAppError> {
    if creds.app_id.is_empty() {
        return Err(GhAppError::NotConfigured("app_id is empty".to_string()));
    }
    if creds.installation_id.is_empty() {
        return Err(GhAppError::NotConfigured(
            "installation_id is empty".to_string(),
        ));
    }
    if creds.private_key_pem.expose_secret().is_empty() {
        return Err(GhAppError::NotConfigured(
            "private_key_pem is empty".to_string(),
        ));
    }

    let now_secs = Utc::now().timestamp();
    let jwt = build_jwt(
        &creds.app_id,
        creds.private_key_pem.expose_secret(),
        now_secs,
    )?;

    let req_body = build_access_token_request(repos, permissions);
    let body_str = serde_json::to_string(&req_body)
        .map_err(|e| GhAppError::Parse(format!("serialize access token request: {e}")))?;

    let url = format!(
        "https://api.github.com/app/installations/{}/access_tokens",
        creds.installation_id
    );

    let (status, resp_body) = client.post_json_bearer(&url, &jwt, &body_str).await?;

    if status != 201 {
        return Err(GhAppError::BadResponse {
            status,
            body: resp_body,
        });
    }

    let parsed: GhAccessTokenResponse = serde_json::from_str(&resp_body)
        .map_err(|e| GhAppError::Parse(format!("parse access token response: {e}")))?;

    let expires_at = DateTime::parse_from_rfc3339(&parsed.expires_at)
        .map_err(|e| GhAppError::Parse(format!("parse expires_at: {e}")))?
        .with_timezone(&Utc);

    // Capture the provider's authoritative scope echo (ADR 204 amendment 2 /
    // ADR 205 §B), sorted so the materialization audit record is byte-stable
    // (GitHub's `permissions` object and `repositories` array have no
    // guaranteed order; a `HashMap` iterates nondeterministically).
    let mut granted_permissions: Vec<(String, String)> = parsed.permissions.into_iter().collect();
    granted_permissions.sort();
    let mut granted_repositories: Vec<String> = parsed
        .repositories
        .into_iter()
        .map(|r| r.full_name)
        .collect();
    granted_repositories.sort();

    Ok(InstallationToken {
        token: parsed.token,
        expires_at,
        granted_permissions,
        granted_repositories,
        repository_selection: parsed.repository_selection,
    })
}

// ---------------------------------------------------------------------------
// Mock HTTP client (for T1 unit tests)
// ---------------------------------------------------------------------------

/// Canned-response mock client for unit tests. Constructed with a fixed
/// `(status_code, body)` pair; every call returns that pair.
pub struct MockHttpClient {
    pub status: u16,
    pub body: String,
}

#[async_trait::async_trait]
impl HttpClient for MockHttpClient {
    async fn post_json_bearer(
        &self,
        _url: &str,
        _bearer: &str,
        _body: &str,
    ) -> Result<(u16, String), GhAppError> {
        Ok((self.status, self.body.clone()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RSA private key fixture generated with `openssl genrsa 2048` (PKCS#8 output).
    // Safe to embed — used only to verify JWT construction; not a real credential.
    const FIXTURE_RSA_PEM: &str = include_str!("../tests/fixtures/rsa_pem.pem");

    fn fixture_rsa_pem() -> String {
        FIXTURE_RSA_PEM.to_string()
    }

    #[test]
    fn build_jwt_encodes_claims() {
        // Use the fixture RSA key.
        let pem = fixture_rsa_pem();
        let now = 1_700_000_000i64;
        let token = build_jwt("99999", &pem, now).expect("jwt must encode");

        // Decode header + claims WITHOUT signature verification to inspect
        // the payload (we don't need to verify against the public key here;
        // we just need to confirm claim values are embedded correctly).
        let mut val = jsonwebtoken::Validation::new(Algorithm::RS256);
        val.insecure_disable_signature_validation();
        val.validate_exp = false;

        // We can't decode without a decoding key even with disabled sig
        // validation in jsonwebtoken v9. Use base64 header/payload split
        // instead — the JWT is a .<b64url>. structure.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // Decode payload (base64url, no padding).
        use base64::Engine as _;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload must be valid base64url");
        let claims: GhJwtClaims =
            serde_json::from_slice(&payload_bytes).expect("payload must deserialize");

        assert_eq!(claims.iss, "99999");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + 600);
    }

    #[test]
    fn build_jwt_bad_pem_returns_error() {
        let err = build_jwt("1", "not-a-pem", 0).unwrap_err();
        assert!(
            matches!(err, GhAppError::JwtSigning(_)),
            "expected JwtSigning, got {err:?}"
        );
    }

    #[test]
    fn build_access_token_request_serializes() {
        let repos = vec!["my-repo".to_string()];
        let perms = vec![
            ("contents".to_string(), "read".to_string()),
            ("pull_requests".to_string(), "write".to_string()),
        ];
        let req = build_access_token_request(&repos, &perms);
        let json = serde_json::to_string(&req).expect("must serialize");
        assert!(json.contains("my-repo"), "repos must appear in body");
        assert!(json.contains("contents"), "permissions must appear in body");
        assert!(
            json.contains("pull_requests"),
            "permissions must appear in body"
        );
    }

    #[test]
    fn build_access_token_request_empty_omits_fields() {
        let req = build_access_token_request(&[], &[]);
        let json = serde_json::to_string(&req).expect("must serialize");
        // Both fields are skip_serializing_if = empty so they must be absent.
        assert!(
            !json.contains("repositories"),
            "empty repos must be omitted: {json}"
        );
        assert!(
            !json.contains("permissions"),
            "empty perms must be omitted: {json}"
        );
    }

    #[tokio::test]
    async fn mint_token_with_mock_client_success() {
        let pem = fixture_rsa_pem();
        let creds = GhAppCredentials {
            app_id: "12345".to_string(),
            installation_id: "67890".to_string(),
            private_key_pem: SecretString::from(pem),
        };
        let mock_body = serde_json::json!({
            "token": "ghs_test_token_xyz",
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string();
        let client = MockHttpClient {
            status: 201,
            body: mock_body,
        };

        let result = mint_installation_token_with_client(&creds, &[], &[], &client)
            .await
            .expect("mint must succeed");

        assert_eq!(result.token, "ghs_test_token_xyz");
        // expires_at must be far in the future (year >= 2099).
        assert!(result.expires_at.timestamp() > 4_000_000_000i64);
    }

    #[tokio::test]
    async fn mint_token_with_mock_client_bad_status() {
        let pem = fixture_rsa_pem();
        let creds = GhAppCredentials {
            app_id: "12345".to_string(),
            installation_id: "67890".to_string(),
            private_key_pem: SecretString::from(pem),
        };
        let client = MockHttpClient {
            status: 401,
            body: r#"{"message":"Bad credentials"}"#.to_string(),
        };

        let err = mint_installation_token_with_client(&creds, &[], &[], &client)
            .await
            .unwrap_err();

        assert!(
            matches!(err, GhAppError::BadResponse { status: 401, .. }),
            "expected BadResponse 401, got {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_token_not_configured_empty_app_id() {
        let creds = GhAppCredentials {
            app_id: String::new(),
            installation_id: "67890".to_string(),
            private_key_pem: SecretString::from("dummy".to_string()),
        };
        let client = MockHttpClient {
            status: 201,
            body: "{}".to_string(),
        };
        let err = mint_installation_token_with_client(&creds, &[], &[], &client)
            .await
            .unwrap_err();
        assert!(matches!(err, GhAppError::NotConfigured(_)));
    }

    #[tokio::test]
    async fn mint_token_not_configured_empty_installation_id() {
        let pem = fixture_rsa_pem();
        let creds = GhAppCredentials {
            app_id: "12345".to_string(),
            installation_id: String::new(),
            private_key_pem: SecretString::from(pem),
        };
        let client = MockHttpClient {
            status: 201,
            body: "{}".to_string(),
        };
        let err = mint_installation_token_with_client(&creds, &[], &[], &client)
            .await
            .unwrap_err();
        assert!(matches!(err, GhAppError::NotConfigured(_)));
    }

    #[tokio::test]
    async fn mint_token_not_configured_empty_pem() {
        let creds = GhAppCredentials {
            app_id: "12345".to_string(),
            installation_id: "67890".to_string(),
            private_key_pem: SecretString::from(String::new()),
        };
        let client = MockHttpClient {
            status: 201,
            body: "{}".to_string(),
        };
        let err = mint_installation_token_with_client(&creds, &[], &[], &client)
            .await
            .unwrap_err();
        assert!(matches!(err, GhAppError::NotConfigured(_)));
    }
}
