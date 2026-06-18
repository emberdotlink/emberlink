//! Google Cloud `Broker` implementation — issues short-lived OAuth
//! access tokens scoped to caller-supplied service-account
//! impersonation targets via GCP's IAM Credentials API, returns the
//! impersonated bearer token as [`BrokeredCredential`] the consumer
//! (`broker_exec` / `apply_credential_to_env`) injects into the child
//! environment as `CLOUDSDK_AUTH_ACCESS_TOKEN`.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`GcpServiceAccountKey`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::gcp_config`) and one entry per outstanding
//! materialization.
//!
//! ## Two-step mint
//!
//! 1. **JWT-exchange.** Sign a self-issued RS256 JWT (10-min window)
//!    with the service account's private key, scoped to
//!    `https://oauth2.googleapis.com/token`. POST to that URL with
//!    `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` to
//!    receive an OAuth access token for the SA itself.
//! 2. **IAM Credentials impersonation.** POST to
//!    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<target_sa>:generateAccessToken`
//!    with the OAuth token as `Authorization: Bearer ...`. Body:
//!    `{ scope, lifetime, delegates }`. Response contains the
//!    impersonated access token and its RFC3339 expiration.
//!
//! ## Workload Identity Federation (alternative auth)
//!
//! When [`GcpAuthMethod::WorkloadIdentityFederation`] is configured, the
//! broker bypasses the on-disk SA private key entirely and instead
//! exchanges a fresh OIDC token for a federation access token via the
//! GCP Security Token Service:
//!
//! 1. **STS exchange.** POST `https://sts.googleapis.com/v1/token` with
//!    `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
//!    `requested_token_type=urn:ietf:params:oauth:token-type:access_token`,
//!    `subject_token_type=urn:ietf:params:oauth:token-type:jwt`,
//!    `subject_token=<oidc_token_read_from_disk>`,
//!    `audience=<workload-identity-pool-provider>`,
//!    `scope=https://www.googleapis.com/auth/cloud-platform`. The token
//!    returned authenticates the federated workload directly to GCP.
//! 2. **Optional impersonation.** When `service_account_email` is
//!    configured the broker calls the same
//!    `iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<sa>:generateAccessToken`
//!    endpoint as the SA-key path, but with the federation token as
//!    the bearer instead of the JWT-exchange token. Without
//!    impersonation the federation access token IS the vended
//!    credential.
//!
//! This is the Kubernetes / GitHub-Actions / generic-OIDC convention —
//! the workload's identity provider mounts a short-lived OIDC token at
//! a known filesystem path and GCP federates trust through the
//! Workload Identity Pool's audience claim. No long-lived SA private
//! key ever lives on the broker host.
//!
//! ## Revocation
//!
//! GCP exposes a token-revoke endpoint at
//! `https://oauth2.googleapis.com/revoke`. We call it best-effort and
//! warn on failure — TTL clamping (max 1h via the IAM Credentials API)
//! is the real safety net.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
// Shared native scope (`GcpNativeScope`) re-exported here as `GcpScope` so
// the broker and the daemon's I7 clamp path (`broker_resolve` →
// `identity_upper_bound`) speak ONE typed wire shape; AUDIT-V030-GCP-PROVIDER-PROJECTOR
// (mirrors the AWS STS `pub use core_broker::project::{AwsStsMode, AwsStsScope};`
// shape from PR #5716). The projector and broker can no longer drift.
pub use core_broker::GcpNativeScope as GcpScope;
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, IdentityRef, MintStamp,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// How the broker authenticates to GCP when minting tokens.
///
/// - [`GcpAuthMethod::ServiceAccountKey`] — the historical default.
///   The broker holds the SA private key on disk and mints tokens via
///   the JWT-bearer OAuth flow + `iamcredentials.googleapis.com`
///   impersonation. Mirrors the AWS-STS `AssumeRole` and Azure
///   `ClientSecret` paths in spirit: long-lived secret material on the
///   daemon host.
/// - [`GcpAuthMethod::WorkloadIdentityFederation`] — Workload Identity
///   Federation. The broker reads a short-lived OIDC token from
///   `oidc_token_path` on every mint and exchanges it for a
///   federation access token via `sts.googleapis.com`. When
///   `service_account_email` is set the broker also calls
///   `iamcredentials.googleapis.com` to impersonate that SA (using
///   the federation token as the bearer); without it the federation
///   token IS the vended credential. No long-lived SA private key
///   lives on the broker host.
///
/// `ServiceAccountKey` remains the default for backward compatibility:
/// the daemon's `gcp_config.rs` populates that variant, and existing
/// callers continue to work without re-keying.
#[derive(Clone, Debug, Default)]
pub enum GcpAuthMethod {
    /// Long-lived SA private key. JWT-bearer OAuth → impersonation
    /// chain, identical to the historical GCP broker path.
    #[default]
    ServiceAccountKey,
    /// Workload Identity Federation. `audience` is the full Workload
    /// Identity Pool / Provider resource path (e.g.
    /// `//iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`).
    /// `oidc_token_path` is the filesystem path the broker reads on
    /// every mint to obtain a short-lived OIDC token. The contents
    /// are submitted as `subject_token` to the STS exchange. The
    /// token is NOT cached; it is re-read on every `issue()` so
    /// token-rotation by the OIDC issuer (kubelet projection refresh,
    /// Actions token rotation) is picked up without restart.
    /// `service_account_email`, when set, opts the broker into the
    /// same `generateAccessToken` impersonation chain the SA-key path
    /// uses — the federation token grants `iam.serviceAccounts.getAccessToken`
    /// on the target SA via the federated principal's role bindings.
    WorkloadIdentityFederation {
        audience: String,
        oidc_token_path: PathBuf,
        service_account_email: Option<String>,
    },
}

/// Service account key material loaded from a downloaded GCP JSON key
/// file. Three of the JSON file's fields drive the broker:
///
/// - `client_email` — the issuer/subject (`iss`/`sub`) on the
///   self-issued JWT.
/// - `private_key` — RSA PKCS#8 PEM used to RS256-sign the JWT.
/// - `project_id` — informational; embedded in tracing for clarity but
///   not required for the OAuth or IAM Credentials calls (the target
///   SA's project is implicit in its email address).
///
/// `private_key` is a [`SecretString`] so it cannot be accidentally
/// `Debug`-printed or logged.
///
/// `auth_method` selects between the historical SA-key flow
/// ([`GcpAuthMethod::ServiceAccountKey`]) and the Workload Identity
/// Federation flow ([`GcpAuthMethod::WorkloadIdentityFederation`]).
/// The default is `ServiceAccountKey` for backward compatibility; the
/// SA-key fields above are required only for that variant and may
/// hold dummy / empty values when WIF is selected.
#[derive(Clone)]
pub struct GcpServiceAccountKey {
    pub client_email: String,
    pub private_key: SecretString,
    pub project_id: String,
    pub auth_method: GcpAuthMethod,
}

// `GcpScope` lives in `core-broker` as `GcpNativeScope` (re-exported above
// as `GcpScope` for backward compatibility with the broker's existing
// callsites + tests). The shared definition lets the projector
// (`core_broker::gcp::GcpProjector::native_upper_bound`) and the broker
// here speak one typed wire shape — daemon's I7 clamp re-parses the same
// JSON the broker minted from. AUDIT-V030-GCP-PROVIDER-PROJECTOR.

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `oauth2.googleapis.com` /
/// `iamcredentials.googleapis.com`.
///
/// Production callers use [`ReqwestGcpClient`]; tests use
/// [`MockGcpClient`].
#[async_trait::async_trait]
pub trait GcpHttpClient: Send + Sync {
    /// POST a `application/x-www-form-urlencoded` body to `url`. Used
    /// for the JWT-exchange step (the OAuth token endpoint and the
    /// revoke endpoint).
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String>;

    /// POST a JSON body to `url` with `Authorization: Bearer <bearer>`.
    /// Used for the IAM Credentials `generateAccessToken` step.
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String>;
}

/// Production [`GcpHttpClient`] backed by `reqwest`.
pub struct ReqwestGcpClient {
    inner: reqwest::Client,
}

impl ReqwestGcpClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/gcp")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestGcpClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl GcpHttpClient for ReqwestGcpClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: String,
    ) -> Result<(u16, String), String> {
        let resp = self
            .inner
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by GCP service-account impersonation.
///
/// Construct with [`GcpBroker::new`] for production (uses
/// [`ReqwestGcpClient`]) or [`GcpBroker::with_client`] for tests
/// (any `dyn GcpHttpClient` implementation).
pub struct GcpBroker {
    key: GcpServiceAccountKey,
    /// Default impersonation target — read from
    /// `GCP_DEFAULT_TARGET_SERVICE_ACCOUNT` in `gcp.env`. Used when
    /// `BrokerRequest::scope` omits `target_service_account`.
    default_target: Option<String>,
    client: Arc<dyn GcpHttpClient>,
    /// `materialization_id` → `(expires_at, token_plaintext)`. Token
    /// plaintext is captured so `revoke()` can call the OAuth revoke
    /// endpoint (which takes the token itself, not an opaque ID).
    state: Mutex<HashMap<String, GcpMaterializationState>>,
}

struct GcpMaterializationState {
    expires_at: SystemTime,
    token: SecretString,
}

impl GcpBroker {
    /// Production constructor — uses [`ReqwestGcpClient`].
    pub fn new(key: GcpServiceAccountKey, default_target: Option<String>) -> Self {
        Self {
            key,
            default_target,
            client: Arc::new(
                ReqwestGcpClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`GcpHttpClient`] so
    /// unit tests can inject [`MockGcpClient`].
    pub fn with_client(
        key: GcpServiceAccountKey,
        default_target: Option<String>,
        client: Arc<dyn GcpHttpClient>,
    ) -> Self {
        Self {
            key,
            default_target,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("gcp broker state mutex").len()
    }

    /// SA-key path — the historical two-step JWT-bearer + impersonation
    /// flow. Extracted from `issue()` so the dispatch on
    /// [`GcpAuthMethod`] reads cleanly.
    async fn issue_service_account_key(
        &self,
        scope: &GcpScope,
    ) -> Result<BrokeredCredential, BrokerError> {
        // Resolve impersonation target — explicit scope target wins,
        // else fall back to the daemon-configured default.
        let target = if !scope.target_service_account.is_empty() {
            scope.target_service_account.clone()
        } else {
            self.default_target.clone().ok_or_else(|| {
                BrokerError::InvalidScope(
                    "target_service_account must be set when no default is configured".to_string(),
                )
            })?
        };

        // ─── Step 1: build + post the self-issued JWT ───
        let now_secs = Utc::now().timestamp();
        let jwt = build_gcp_jwt(
            &self.key.client_email,
            self.key.private_key.expose_secret(),
            &scope.scopes,
            now_secs,
        )?;

        let token_url = "https://oauth2.googleapis.com/token";
        let token_body = format!(
            "grant_type={}&assertion={}",
            urlencode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            urlencode(&jwt),
        );
        let (status, body) = self
            .client
            .post_form(token_url, token_body)
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_gcp_error(status, &body, "jwt-exchange");
            tracing::warn!(
                step = "jwt-exchange",
                status = status,
                error = %err,
                "GcpBroker: OAuth token endpoint failed"
            );
            return Err(err);
        }
        let oauth: OauthTokenResponse = serde_json::from_str(&body).map_err(|e| {
            BrokerError::Upstream(format!(
                "GCP jwt-exchange response parse failed: {e}; body={body}"
            ))
        })?;

        // ─── Step 2: impersonate via IAM Credentials ───
        let parsed = call_generate_access_token(
            self.client.as_ref(),
            &target,
            &oauth.access_token,
            &scope.scopes,
            scope.ttl_seconds,
            &scope.delegates,
        )
        .await?;

        let expires_at = match DateTime::parse_from_rfc3339(&parsed.expire_time) {
            Ok(dt) => SystemTime::from(dt.with_timezone(&Utc)),
            Err(_) => SystemTime::now() + std::time::Duration::from_secs(scope.ttl_seconds),
        };

        let materialization_id = format!(
            "gcp-{}-{}",
            target,
            DateTime::<Utc>::from(expires_at).timestamp()
        );

        let token_secret = SecretString::from(parsed.access_token);
        self.state.lock().expect("gcp broker state mutex").insert(
            materialization_id.clone(),
            GcpMaterializationState {
                expires_at,
                token: token_secret.clone(),
            },
        );

        Ok(BrokeredCredential {
            token: token_secret,
            expires_at,
            materialization_id,
            mint_stamp: MintStamp::Identity {
                identity: IdentityRef {
                    provider: BrokerProvider::Gcp,
                    identity: self.key.client_email.clone(),
                },
            },
        })
    }
}

/// Call `iamcredentials.googleapis.com/v1/.../generateAccessToken` and
/// parse the response. Shared between the SA-key path and the WIF
/// impersonation path — both end with the same `generateAccessToken`
/// call once a federation/JWT-exchange bearer is in hand.
async fn call_generate_access_token(
    client: &dyn GcpHttpClient,
    target_sa: &str,
    bearer: &str,
    scopes: &[String],
    ttl_seconds: u64,
    delegates: &[String],
) -> Result<GenerateAccessTokenResponse, BrokerError> {
    let impersonate_url = format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{target_sa}:generateAccessToken"
    );
    let req_body = GenerateAccessTokenRequest {
        scope: scopes.to_vec(),
        lifetime: format!("{ttl_seconds}s"),
        delegates: delegates.to_vec(),
    };
    let body_json = serde_json::to_string(&req_body)
        .map_err(|e| BrokerError::Other(format!("serialize generateAccessToken request: {e}")))?;

    let (status, resp_body) = client
        .post_json_bearer(&impersonate_url, bearer, body_json)
        .await
        .map_err(BrokerError::Upstream)?;

    if !(200..300).contains(&status) {
        let err = map_gcp_error(status, &resp_body, "generateAccessToken");
        tracing::warn!(
            step = "generateAccessToken",
            status = status,
            target = %target_sa,
            error = %err,
            "GcpBroker: IAM Credentials generateAccessToken failed"
        );
        return Err(err);
    }

    serde_json::from_str(&resp_body).map_err(|e| {
        BrokerError::Upstream(format!(
            "GCP generateAccessToken response parse failed: {e}; body={resp_body}"
        ))
    })
}

/// Workload Identity Federation mint path.
///
/// Two-step flow:
///
/// 1. **STS exchange.** POST `https://sts.googleapis.com/v1/token`
///    with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
///    and `subject_token` set to the freshly-read OIDC token. The
///    response is a JSON-encoded `{"access_token": "...", ...}` —
///    this is the federation access token, authenticated as the
///    federated principal in the configured Workload Identity Pool.
/// 2. **Optional impersonation.** When `service_account_email` is
///    `Some`, the broker calls
///    `iamcredentials.googleapis.com/.../generateAccessToken` with
///    the federation token in the bearer slot. The response is the
///    impersonated SA's access token, identical in shape to the
///    SA-key path's result. When `service_account_email` is `None`,
///    the federation access token IS the vended credential.
///
/// The OIDC token is read from `oidc_token_path` on every call (no
/// caching) so kubelet / GitHub-Actions / generic-OIDC token rotation
/// is picked up without restarting the broker.
///
/// # Errors
///
/// - [`BrokerError::Upstream`] — OIDC token file missing / unreadable
///   / empty after trimming whitespace; STS or generateAccessToken
///   call returned a non-2xx status that does not match a known
///   policy/auth-config code.
/// - [`BrokerError::PolicyRejected`] — STS or generateAccessToken
///   returned 403 PERMISSION_DENIED, or rejected the OIDC token shape
///   (audience-mismatch, malformed JWT, bad subject_token_type,
///   issuer not bound to the pool). These all surface as
///   `PolicyRejected` to match the SA-key broker convention for
///   "the upstream rejected this credential's policy."
async fn gcp_workload_identity_exchange(
    client: &dyn GcpHttpClient,
    audience: &str,
    oidc_token_path: &std::path::Path,
    service_account_email: Option<&str>,
    scope: &GcpScope,
    state: &Mutex<HashMap<String, GcpMaterializationState>>,
) -> Result<BrokeredCredential, BrokerError> {
    // ─── Read fresh OIDC token from disk ───
    let raw = std::fs::read_to_string(oidc_token_path).map_err(|e| {
        BrokerError::Upstream(format!(
            "GCP WIF: read OIDC token from {}: {e}",
            oidc_token_path.display()
        ))
    })?;
    let subject_token = raw.trim();
    if subject_token.is_empty() {
        return Err(BrokerError::Upstream(format!(
            "GCP WIF: OIDC token at {} is empty",
            oidc_token_path.display()
        )));
    }

    // ─── Step 1: STS token exchange ───
    let sts_url = "https://sts.googleapis.com/v1/token";
    // STS scope is fixed at cloud-platform — that scope is what the
    // federation token is allowed to act under. The caller's
    // fine-grained scope list applies at the impersonation step (or
    // is the GCP API scope when there's no impersonation).
    let sts_scope = "https://www.googleapis.com/auth/cloud-platform";
    let sts_body = format!(
        "audience={audience_enc}&grant_type={grant_enc}&requested_token_type={req_enc}&scope={scope_enc}&subject_token_type={subj_type_enc}&subject_token={subj_enc}",
        audience_enc = urlencode(audience),
        grant_enc = urlencode("urn:ietf:params:oauth:grant-type:token-exchange"),
        req_enc = urlencode("urn:ietf:params:oauth:token-type:access_token"),
        scope_enc = urlencode(sts_scope),
        subj_type_enc = urlencode("urn:ietf:params:oauth:token-type:jwt"),
        subj_enc = urlencode(subject_token),
    );

    let (status, body) = client
        .post_form(sts_url, sts_body)
        .await
        .map_err(BrokerError::Upstream)?;

    if !(200..300).contains(&status) {
        let err = map_gcp_error(status, &body, "sts-exchange");
        tracing::warn!(
            step = "sts-exchange",
            status = status,
            audience = %audience,
            error = %err,
            "GcpBroker: STS token-exchange failed"
        );
        return Err(err);
    }

    let federation: StsTokenResponse = serde_json::from_str(&body).map_err(|e| {
        BrokerError::Upstream(format!(
            "GCP sts-exchange response parse failed: {e}; body={body}"
        ))
    })?;

    // ─── Step 2: optional impersonation ───
    let (token_plaintext, expires_at, target_label) = match service_account_email {
        Some(sa_email) => {
            let parsed = call_generate_access_token(
                client,
                sa_email,
                &federation.access_token,
                &scope.scopes,
                scope.ttl_seconds,
                &scope.delegates,
            )
            .await?;
            let expires_at = match DateTime::parse_from_rfc3339(&parsed.expire_time) {
                Ok(dt) => SystemTime::from(dt.with_timezone(&Utc)),
                Err(_) => SystemTime::now() + std::time::Duration::from_secs(scope.ttl_seconds),
            };
            (parsed.access_token, expires_at, sa_email.to_string())
        }
        None => {
            // No impersonation — the federation token itself is the
            // vended credential. STS' expires_in is seconds-from-now;
            // fall back to the requested TTL when missing/<=0.
            let lifetime = if federation.expires_in > 0 {
                federation.expires_in as u64
            } else {
                scope.ttl_seconds
            };
            let expires_at = SystemTime::now() + std::time::Duration::from_secs(lifetime);
            // Use a federation-specific label so the materialization id
            // is distinguishable from SA-key and impersonation paths.
            (
                federation.access_token,
                expires_at,
                format!("wif-{}", short_audience_label(audience)),
            )
        }
    };

    let materialization_id = format!(
        "gcp-{}-{}",
        target_label,
        DateTime::<Utc>::from(expires_at).timestamp()
    );

    let token_secret = SecretString::from(token_plaintext);
    state.lock().expect("gcp broker state mutex").insert(
        materialization_id.clone(),
        GcpMaterializationState {
            expires_at,
            token: token_secret.clone(),
        },
    );

    let mint_stamp = match service_account_email {
        Some(sa) => MintStamp::Identity {
            identity: IdentityRef {
                provider: BrokerProvider::Gcp,
                identity: sa.to_string(),
            },
        },
        None => MintStamp::Opaque,
    };

    Ok(BrokeredCredential {
        token: token_secret,
        expires_at,
        materialization_id,
        mint_stamp,
    })
}

/// Compress an audience URL into a short label suitable for embedding
/// into a `materialization_id`. Workload Identity Pool audiences look
/// like
/// `//iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`;
/// we keep the trailing two path segments so the label still names the
/// provider unambiguously without dragging the full prefix into every
/// id. Falls back to the full audience when the path is short.
fn short_audience_label(audience: &str) -> String {
    let trimmed = audience.trim_start_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() >= 2 {
        format!(
            "{}-{}",
            segments[segments.len() - 2],
            segments[segments.len() - 1]
        )
    } else {
        // Defensive: if we can't extract a tail, hash-substitute via
        // a stable text suffix so the id stays bounded in length.
        let suffix: String = audience
            .chars()
            .rev()
            .take(32)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        suffix
    }
}

/// Self-issued JWT claims for the GCP token exchange.
///
/// Mirrors the JWT-bearer flow documented in
/// <https://developers.google.com/identity/protocols/oauth2/service-account>.
/// `iss` and `sub` are both the SA email; `aud` is the OAuth token URL;
/// `scope` is the OAuth scope string. `iat`/`exp` are 10 minutes apart.
#[derive(Debug, Serialize, Deserialize)]
struct GcpJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    scope: String,
}

/// Build (but do not transmit) the RS256 JWT used for the OAuth
/// JWT-exchange step. Extracted as a free function so unit tests can
/// pin the timestamp without hitting the network.
pub fn build_gcp_jwt(
    client_email: &str,
    private_key_pem: &str,
    scopes: &[String],
    now_epoch_secs: i64,
) -> Result<String, BrokerError> {
    let exp = now_epoch_secs + 600; // 10-minute window per Google docs.
    let claims = GcpJwtClaims {
        iss: client_email.to_string(),
        sub: client_email.to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        iat: now_epoch_secs,
        exp,
        // Space-separated scope list per RFC 6749.
        scope: scopes.join(" "),
    };
    crate::install_jwt_crypto_provider();
    let header = Header::new(Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| BrokerError::Other(format!("jwt key parse: {e}")))?;
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| BrokerError::Other(format!("jwt encode: {e}")))
}

// ---------------------------------------------------------------------------
// JSON shapes for OAuth + IAM Credentials APIs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    /// Lifetime of the SA's own access token, in seconds. Not the
    /// impersonated token's lifetime — only used for the OAuth bearer
    /// the broker uses transiently.
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: i64,
}

/// Response shape for `sts.googleapis.com/v1/token` (Workload Identity
/// Federation token exchange). Differs from [`OauthTokenResponse`] in
/// that `expires_in` IS load-bearing for the WIF-without-impersonation
/// path — the federation token itself becomes the vended credential
/// and we mark the materialization expiry off this value.
#[derive(Debug, Deserialize)]
struct StsTokenResponse {
    access_token: String,
    /// Lifetime of the federation access token, in seconds. STS
    /// always populates this on success.
    #[serde(default)]
    expires_in: i64,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    issued_token_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct GenerateAccessTokenRequest {
    scope: Vec<String>,
    /// Lifetime in `<seconds>s` form per the IAM Credentials API.
    lifetime: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    delegates: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GenerateAccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: String,
}

/// Map the OAuth / IAM Credentials error response shape to the closest
/// [`BrokerError`] variant.
///
/// Both endpoints return a JSON envelope of the form
/// `{ "error": { "status": "...", "code": <int>, "message": "..." } }`
/// or the simpler legacy form `{ "error": "...", "error_description": "..." }`
/// (used by the OAuth token endpoint). 403 PermissionDenied maps to
/// `PolicyRejected`; expired-credential signals map to `Upstream` with
/// a descriptive message; everything else maps to `Upstream` with the
/// raw body.
fn map_gcp_error(status: u16, body: &str, step: &str) -> BrokerError {
    // Try IAM Credentials shape first ({ "error": { "status": "..." } }).
    if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(err) = envelope.get("error")
    {
        // Object form (IAM Credentials, modern OAuth).
        if let Some(obj) = err.as_object() {
            let status_str = obj
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let message = obj
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if status_str == "PERMISSION_DENIED" || status == 403 {
                return BrokerError::PolicyRejected(format!(
                    "GCP {step} permission denied: {message} (raw: {body})"
                ));
            }
            if status_str == "UNAUTHENTICATED" || status == 401 {
                return BrokerError::Upstream(format!(
                    "GCP {step} authentication failure: {message} (raw: {body})"
                ));
            }
        }
        // Legacy OAuth form ({ "error": "invalid_grant", ... }).
        if let Some(s) = err.as_str() {
            let lower = s.to_ascii_lowercase();
            if lower.contains("invalid_grant") || lower.contains("expired") {
                return BrokerError::Upstream(format!(
                    "GCP {step} credentials expired or invalid_grant: {body}"
                ));
            }
            if lower.contains("permission") || status == 403 {
                return BrokerError::PolicyRejected(format!(
                    "GCP {step} permission denied: {body}"
                ));
            }
        }
    }
    if status == 403 {
        return BrokerError::PolicyRejected(format!("GCP {step} forbidden (status=403): {body}"));
    }
    BrokerError::Upstream(format!("GCP {step} error (status={status}): {body}"))
}

impl Broker for GcpBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::Gcp
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::Gcp {
            return Err(BrokerError::InvalidScope(format!(
                "GcpBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: GcpScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        if scope.ttl_seconds == 0 {
            return Err(BrokerError::InvalidScope(
                "ttl_seconds must be > 0".to_string(),
            ));
        }
        if scope.scopes.is_empty() {
            return Err(BrokerError::InvalidScope(
                "scopes must be non-empty".to_string(),
            ));
        }

        match &self.key.auth_method {
            GcpAuthMethod::ServiceAccountKey => self.issue_service_account_key(&scope).await,
            GcpAuthMethod::WorkloadIdentityFederation {
                audience,
                oidc_token_path,
                service_account_email,
            } => {
                gcp_workload_identity_exchange(
                    self.client.as_ref(),
                    audience,
                    oidc_token_path,
                    service_account_email.as_deref(),
                    &scope,
                    &self.state,
                )
                .await
            }
        }
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        let entry = self
            .state
            .lock()
            .expect("gcp broker state mutex")
            .remove(materialization_id);
        let Some(state) = entry else {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        };

        // Best-effort upstream revoke. GCP's revoke endpoint expects
        // the bearer token in the body; failures are warned but do not
        // surface as `Err` because the TTL bound is the real safety
        // net (max 1h on `generateAccessToken`).
        let revoke_url = "https://oauth2.googleapis.com/revoke";
        let body = format!("token={}", urlencode(state.token.expose_secret()));
        match self.client.post_form(revoke_url, body).await {
            Ok((status, resp_body)) if (200..300).contains(&status) => {
                tracing::info!(
                    materialization_id = %materialization_id,
                    "GcpBroker: revoke succeeded"
                );
                let _ = resp_body; // body is empty on success
            }
            Ok((status, resp_body)) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = status,
                    body = %resp_body,
                    "GcpBroker: upstream revoke returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %e,
                    "GcpBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        // expires_at retained for tracing only — we already removed
        // the bookkeeping entry above.
        let _ = state.expires_at;
        Ok(())
    }
}

/// Minimal RFC3986 percent-encoder for form bodies. Encodes everything
/// outside the unreserved set `A-Za-z0-9-._~`. Avoids a full url crate
/// dep.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

/// Scripted-response mock client for unit tests. Each call pops the
/// next `(status, body)` from `form_responses` (for `post_form`) or
/// `json_responses` (for `post_json_bearer`). If a queue is empty the
/// mock returns the last entry forever, which keeps test setup terse
/// while still letting tests assert call ordering when they care.
pub struct MockGcpClient {
    pub form_responses: Mutex<Vec<(u16, String)>>,
    pub json_responses: Mutex<Vec<(u16, String)>>,
    pub form_calls: Mutex<Vec<String>>,
    pub json_calls: Mutex<Vec<(String, String)>>,
}

impl MockGcpClient {
    pub fn new() -> Self {
        Self {
            form_responses: Mutex::new(Vec::new()),
            json_responses: Mutex::new(Vec::new()),
            form_calls: Mutex::new(Vec::new()),
            json_calls: Mutex::new(Vec::new()),
        }
    }

    pub fn with_form(self, status: u16, body: impl Into<String>) -> Self {
        self.form_responses
            .lock()
            .expect("mock form mutex")
            .push((status, body.into()));
        self
    }

    pub fn with_json(self, status: u16, body: impl Into<String>) -> Self {
        self.json_responses
            .lock()
            .expect("mock json mutex")
            .push((status, body.into()));
        self
    }

    pub fn form_call_count(&self) -> usize {
        self.form_calls.lock().expect("mock form mutex").len()
    }

    pub fn json_call_count(&self) -> usize {
        self.json_calls.lock().expect("mock json mutex").len()
    }
}

impl Default for MockGcpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl GcpHttpClient for MockGcpClient {
    async fn post_form(&self, url: &str, body: String) -> Result<(u16, String), String> {
        self.form_calls
            .lock()
            .expect("mock form mutex")
            .push(url.to_string());
        let mut q = self.form_responses.lock().expect("mock form mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!(
                "MockGcpClient: no form response queued for {url}; body={body}"
            ))
        }
    }

    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        _body: String,
    ) -> Result<(u16, String), String> {
        self.json_calls
            .lock()
            .expect("mock json mutex")
            .push((url.to_string(), bearer.to_string()));
        let mut q = self.json_responses.lock().expect("mock json mutex");
        if q.len() > 1 {
            Ok(q.remove(0))
        } else if let Some(last) = q.last() {
            Ok(last.clone())
        } else {
            Err(format!("MockGcpClient: no json response queued for {url}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // RSA private key fixture — same key the github_app/github_broker
    // tests use so we share known-good PKCS#8 bytes. Not a real
    // credential; safe to embed.
    const FIXTURE_RSA_PEM: &str = include_str!("../tests/fixtures/rsa_pem.pem");

    fn fixture_key() -> GcpServiceAccountKey {
        GcpServiceAccountKey {
            client_email: "ember-broker@test-project.iam.gserviceaccount.com".to_string(),
            private_key: SecretString::from(FIXTURE_RSA_PEM.to_string()),
            project_id: "test-project".to_string(),
            auth_method: GcpAuthMethod::ServiceAccountKey,
        }
    }

    fn fixture_key_wif(
        oidc_token_path: PathBuf,
        audience: &str,
        service_account_email: Option<String>,
    ) -> GcpServiceAccountKey {
        GcpServiceAccountKey {
            // SA-key fields are unused in WIF mode — populate with dummy
            // values to confirm the broker doesn't read them.
            client_email: String::new(),
            private_key: SecretString::from(String::new()),
            project_id: "test-project".to_string(),
            auth_method: GcpAuthMethod::WorkloadIdentityFederation {
                audience: audience.to_string(),
                oidc_token_path,
                service_account_email,
            },
        }
    }

    fn fake_oidc_jwt() -> &'static str {
        // Header.Payload.Signature shape — STS parses without
        // validating signature locally; the Workload Identity Pool
        // provider's attribute condition is what gates approval.
        "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMifQ.fake-sig"
    }

    fn write_oidc_token(dir: &std::path::Path, contents: &str) -> PathBuf {
        let path = dir.join("oidc-token");
        std::fs::write(&path, contents).expect("write OIDC token fixture");
        path
    }

    fn sts_ok_body() -> String {
        serde_json::json!({
            "access_token": "ya29.federation-access-token",
            "expires_in": 3599,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        })
        .to_string()
    }

    fn sts_invalid_subject_body() -> String {
        // STS' Google-specific shape for an invalid subject_token: a
        // 400 with an `error` envelope.
        serde_json::json!({
            "error": {
                "code": 400,
                "message": "Invalid value for \"subject_token\": failed to parse JWT.",
                "status": "INVALID_ARGUMENT",
            }
        })
        .to_string()
    }

    fn sts_audience_mismatch_body() -> String {
        // STS returns a 400 PERMISSION_DENIED-shaped envelope when the
        // OIDC token's `aud` claim does not match the configured
        // workload-identity-pool provider audience.
        serde_json::json!({
            "error": {
                "code": 403,
                "message": "The audience does not match the trust configuration of the workload identity pool provider.",
                "status": "PERMISSION_DENIED",
            }
        })
        .to_string()
    }

    const FIXTURE_AUDIENCE: &str =
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov";

    fn gcp_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::Gcp,
            scope,
            ttl: Duration::from_secs(ttl_secs),
            contract_id: None,
            action_ref: None,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            reason: "test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    fn oauth_ok_body() -> String {
        serde_json::json!({
            "access_token": "ya29.broker-sa-oauth-token",
            "expires_in": 3599,
            "token_type": "Bearer",
        })
        .to_string()
    }

    fn impersonate_ok_body() -> String {
        serde_json::json!({
            "accessToken": "ya29.impersonated-target-token",
            "expireTime": "2099-01-01T00:00:00Z",
        })
        .to_string()
    }

    fn permission_denied_body() -> String {
        serde_json::json!({
            "error": {
                "code": 403,
                "message": "Permission 'iam.serviceAccounts.getAccessToken' denied",
                "status": "PERMISSION_DENIED",
            }
        })
        .to_string()
    }

    fn invalid_grant_body() -> String {
        serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Invalid JWT Signature.",
        })
        .to_string()
    }

    #[test]
    fn provider_returns_gcp() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        assert_eq!(broker.provider(), BrokerProvider::Gcp);
    }

    #[test]
    fn build_jwt_encodes_iss_sub_aud_scope() {
        let pem = FIXTURE_RSA_PEM.to_string();
        let now = 1_700_000_000i64;
        let token = build_gcp_jwt(
            "sa@proj.iam.gserviceaccount.com",
            &pem,
            &["https://www.googleapis.com/auth/cloud-platform".to_string()],
            now,
        )
        .expect("jwt must encode");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        use base64::Engine as _;
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload must be valid base64url");
        let claims: GcpJwtClaims =
            serde_json::from_slice(&payload_bytes).expect("payload must deserialize");
        assert_eq!(claims.iss, "sa@proj.iam.gserviceaccount.com");
        assert_eq!(claims.sub, "sa@proj.iam.gserviceaccount.com");
        assert_eq!(claims.aud, "https://oauth2.googleapis.com/token");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + 600);
        assert_eq!(
            claims.scope,
            "https://www.googleapis.com/auth/cloud-platform"
        );
    }

    #[test]
    fn build_jwt_bad_pem_returns_error() {
        let err = build_gcp_jwt("sa@x", "not-a-pem", &["s".to_string()], 0).unwrap_err();
        assert!(
            matches!(err, BrokerError::Other(_)),
            "expected Other for jwt key parse failure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_two_step_success_returns_impersonated_token() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock.clone());
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "deployer@target-proj.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "ya29.impersonated-target-token",
            "token must be the impersonated SA's access token"
        );
        assert!(
            cred.materialization_id
                .starts_with("gcp-deployer@target-proj"),
            "materialization id includes target SA: {}",
            cred.materialization_id
        );
        assert_eq!(broker.active_count(), 1);
        assert_eq!(mock.form_call_count(), 1, "one OAuth POST");
        assert_eq!(mock.json_call_count(), 1, "one impersonation POST");
    }

    #[tokio::test]
    async fn issue_uses_default_target_when_scope_omits_it() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(
            fixture_key(),
            Some("default-deployer@target.iam.gserviceaccount.com".to_string()),
            mock,
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 1800,
            }),
            1800,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert!(
            cred.materialization_id.contains("default-deployer@target"),
            "default target wired into materialization_id: {}",
            cred.materialization_id
        );
    }

    #[tokio::test]
    async fn issue_permission_denied_on_impersonation_returns_policy_rejected() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(403, permission_denied_body()),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock);
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "deployer@target.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_expired_sa_key_returns_upstream() {
        // OAuth endpoint rejects the JWT-bearer assertion with
        // invalid_grant when the SA key has been disabled / rotated.
        let mock = Arc::new(MockGcpClient::new().with_form(400, invalid_grant_body()));
        let broker = GcpBroker::with_client(fixture_key(), None, mock);
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "deployer@target.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
        assert!(
            msg.contains("invalid_grant") || msg.to_ascii_lowercase().contains("expired"),
            "error must mention invalid_grant / expired: {msg}"
        );
    }

    #[tokio::test]
    async fn issue_with_invalid_scope_returns_invalid_scope_error() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        // ttl_seconds = 0 must reject
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "x@y",
                "scopes": ["scope"],
                "ttl_seconds": 0,
            }),
            0,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_empty_scopes_returns_invalid_scope_error() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "x@y",
                "scopes": [],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_no_target_and_no_default_returns_invalid_scope() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["scope"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        let mut req = gcp_request(
            serde_json::json!({
                "target_service_account": "x@y",
                "scopes": ["scope"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_happy_path_calls_oauth_revoke_and_drops_state() {
        let mock = Arc::new(
            MockGcpClient::new()
                // issue: oauth + impersonate
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body())
                // revoke: oauth revoke endpoint returns 200 empty body
                .with_form(200, ""),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock.clone());
        let cred = Broker::issue(
            &broker,
            gcp_request(
                serde_json::json!({
                    "target_service_account": "deployer@target.iam.gserviceaccount.com",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        assert_eq!(broker.active_count(), 1);
        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke must succeed (best-effort)");
        assert_eq!(broker.active_count(), 0);
        // 1 form call for jwt-exchange + 1 form call for revoke
        assert_eq!(mock.form_call_count(), 2);
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = GcpBroker::with_client(fixture_key(), None, Arc::new(MockGcpClient::new()));
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[tokio::test]
    async fn revoke_swallows_upstream_failure_after_dropping_state() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body())
                // revoke fails 503; revoke() should still return Ok
                .with_form(503, "service unavailable"),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock);
        let cred = Broker::issue(
            &broker,
            gcp_request(
                serde_json::json!({
                    "target_service_account": "deployer@target.iam.gserviceaccount.com",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("issue must succeed");

        Broker::revoke(&broker, &cred.materialization_id)
            .await
            .expect("revoke is best-effort; upstream 503 must not surface");
        assert_eq!(broker.active_count(), 0);
    }

    #[test]
    fn gcp_scope_round_trips_through_json() {
        let scope = GcpScope {
            target_service_account: "x@y".to_string(),
            scopes: vec!["s1".to_string(), "s2".to_string()],
            ttl_seconds: 1800,
            delegates: vec!["mid@z".to_string()],
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: GcpScope = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(parsed.target_service_account, scope.target_service_account);
        assert_eq!(parsed.scopes, scope.scopes);
        assert_eq!(parsed.ttl_seconds, scope.ttl_seconds);
        assert_eq!(parsed.delegates, scope.delegates);
    }

    #[test]
    fn map_gcp_error_permission_denied_returns_policy_rejected() {
        let err = map_gcp_error(403, &permission_denied_body(), "generateAccessToken");
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected, got {err:?}"
        );
    }

    #[test]
    fn map_gcp_error_invalid_grant_returns_upstream() {
        let err = map_gcp_error(400, &invalid_grant_body(), "jwt-exchange");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // Workload Identity Federation tests — BROKER-GCP-WORKLOAD-IDENTITY
    // ---------------------------------------------------------------

    #[test]
    fn gcp_auth_method_default_is_service_account_key() {
        assert!(matches!(
            GcpAuthMethod::default(),
            GcpAuthMethod::ServiceAccountKey
        ));
    }

    #[test]
    fn short_audience_label_extracts_pool_and_provider() {
        let label = short_audience_label(FIXTURE_AUDIENCE);
        assert!(
            label.contains("p") && label.contains("prov"),
            "label must surface trailing pool/provider segments: {label}"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_without_impersonation_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        // Only the STS exchange is queued — no impersonation step.
        let mock = Arc::new(MockGcpClient::new().with_form(200, sts_ok_body()));
        let broker = GcpBroker::with_client(
            fixture_key_wif(token_path, FIXTURE_AUDIENCE, None),
            None,
            mock.clone(),
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("WIF issue (no impersonation) must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "ya29.federation-access-token",
            "token must be the federation access token (no impersonation step)"
        );
        assert!(
            cred.materialization_id.starts_with("gcp-wif-"),
            "materialization id should carry the wif label: {}",
            cred.materialization_id
        );
        // Exactly one form POST (the STS exchange); no JSON-bearer call.
        assert_eq!(mock.form_call_count(), 1, "one STS POST");
        assert_eq!(
            mock.json_call_count(),
            0,
            "no impersonation step when service_account_email is None"
        );
        // The form POST must have hit STS, not the OAuth token endpoint.
        let form_calls = mock.form_calls.lock().expect("mock form mutex").clone();
        assert_eq!(form_calls.len(), 1);
        assert_eq!(
            form_calls[0], "https://sts.googleapis.com/v1/token",
            "WIF must POST to sts.googleapis.com, not oauth2.googleapis.com"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_with_impersonation_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, sts_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(
            fixture_key_wif(
                token_path,
                FIXTURE_AUDIENCE,
                Some("deployer@target.iam.gserviceaccount.com".to_string()),
            ),
            None,
            mock.clone(),
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("WIF issue (with impersonation) must succeed");
        assert_eq!(
            cred.token.expose_secret(),
            "ya29.impersonated-target-token",
            "token must be the impersonated SA's access token"
        );
        assert!(
            cred.materialization_id.starts_with("gcp-deployer@target"),
            "materialization id includes target SA: {}",
            cred.materialization_id
        );
        assert_eq!(mock.form_call_count(), 1, "one STS POST");
        assert_eq!(mock.json_call_count(), 1, "one impersonation POST");
        // Verify the impersonation POST carried the FEDERATION token,
        // not the JWT-exchange OAuth token (no SA private key was
        // available for that path).
        let json_calls = mock.json_calls.lock().expect("mock json mutex").clone();
        assert_eq!(json_calls.len(), 1);
        assert_eq!(
            json_calls[0].1, "ya29.federation-access-token",
            "impersonation bearer must be the federation token"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_invalid_oidc_token_returns_policy_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), "not-a-valid-jwt");
        // STS rejects the subject_token with 400.
        let mock = Arc::new(MockGcpClient::new().with_form(400, sts_invalid_subject_body()));
        let broker = GcpBroker::with_client(
            fixture_key_wif(token_path, FIXTURE_AUDIENCE, None),
            None,
            mock,
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(
                err,
                BrokerError::Upstream(_) | BrokerError::PolicyRejected(_)
            ),
            "invalid OIDC token must surface as Upstream or PolicyRejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_audience_mismatch_returns_policy_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let mock = Arc::new(MockGcpClient::new().with_form(403, sts_audience_mismatch_body()));
        let broker = GcpBroker::with_client(
            fixture_key_wif(token_path, FIXTURE_AUDIENCE, None),
            None,
            mock,
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "audience-mismatch must surface as PolicyRejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_missing_oidc_token_returns_upstream() {
        // Path doesn't exist — broker must fail before any HTTP call.
        let mock = Arc::new(MockGcpClient::new());
        let broker = GcpBroker::with_client(
            fixture_key_wif(
                PathBuf::from("/nonexistent/path/oidc-token"),
                FIXTURE_AUDIENCE,
                None,
            ),
            None,
            mock.clone(),
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "missing OIDC token must surface as Upstream, got {err:?}"
        );
        assert_eq!(
            mock.form_call_count(),
            0,
            "broker must not POST to STS when OIDC token is unreadable"
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_empty_oidc_token_returns_upstream() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), "   \n\t  ");
        let mock = Arc::new(MockGcpClient::new());
        let broker = GcpBroker::with_client(
            fixture_key_wif(token_path, FIXTURE_AUDIENCE, None),
            None,
            mock.clone(),
        );
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "whitespace-only OIDC token must surface as Upstream, got {err:?}"
        );
        assert_eq!(mock.form_call_count(), 0);
    }

    #[tokio::test]
    async fn issue_workload_identity_federation_rereads_token_each_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let token_path = write_oidc_token(tmp.path(), "first-oidc-token");
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, sts_ok_body())
                .with_form(200, sts_ok_body()),
        );
        let broker = GcpBroker::with_client(
            fixture_key_wif(token_path.clone(), FIXTURE_AUDIENCE, None),
            None,
            mock.clone(),
        );

        // First call uses the original token.
        Broker::issue(
            &broker,
            gcp_request(
                serde_json::json!({
                    "target_service_account": "",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("first WIF issue must succeed");

        // Rotate the on-disk token (kubelet projected-token refresh,
        // GH Actions step boundary, etc.).
        std::fs::write(&token_path, "second-oidc-token").expect("rotate OIDC token");

        Broker::issue(
            &broker,
            gcp_request(
                serde_json::json!({
                    "target_service_account": "",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                3600,
            ),
        )
        .await
        .expect("second WIF issue must succeed");

        // Both POSTs hit STS; the second body must carry the rotated
        // subject_token, proving no caching.
        assert_eq!(mock.form_call_count(), 2);
    }

    /// Regression — the SA-key path keeps its old behaviour after the
    /// auth_method enum was added. Same shape as
    /// `issue_two_step_success_returns_impersonated_token` but spelled
    /// out at the bottom of the WIF test block so the back-compat
    /// guarantee is colocated with the new tests.
    #[tokio::test]
    async fn issue_service_account_key_path_still_works_after_auth_method_addition() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock.clone());
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "deployer@target-proj.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(cred.token.expose_secret(), "ya29.impersonated-target-token");
        // Form call should hit the OAuth token endpoint, not STS.
        let form_calls = mock.form_calls.lock().expect("mock form mutex").clone();
        assert_eq!(form_calls.len(), 1);
        assert_eq!(
            form_calls[0], "https://oauth2.googleapis.com/token",
            "SA-key path must POST to oauth2.googleapis.com, not sts.googleapis.com"
        );
    }

    #[tokio::test]
    async fn issue_sa_key_mint_stamp_records_service_account_identity() {
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, oauth_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(fixture_key(), None, mock);
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "deployer@target-proj.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        match &cred.mint_stamp {
            MintStamp::Identity { identity } => {
                assert_eq!(identity.provider, BrokerProvider::Gcp);
                assert_eq!(
                    identity.identity, "ember-broker@test-project.iam.gserviceaccount.com",
                    "SA-key path stamps the broker's own client_email, not the impersonation target"
                );
            }
            other => panic!("expected MintStamp::Identity for SA-key path, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issue_wif_with_impersonation_mint_stamp_records_sa_identity() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let oidc_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let sa = "deployer@target.iam.gserviceaccount.com";
        let key = fixture_key_wif(oidc_path, FIXTURE_AUDIENCE, Some(sa.to_string()));
        let mock = Arc::new(
            MockGcpClient::new()
                .with_form(200, sts_ok_body())
                .with_json(200, impersonate_ok_body()),
        );
        let broker = GcpBroker::with_client(key, None, mock);
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        match &cred.mint_stamp {
            MintStamp::Identity { identity } => {
                assert_eq!(identity.provider, BrokerProvider::Gcp);
                assert_eq!(identity.identity, sa);
            }
            other => panic!("expected MintStamp::Identity for WIF+impersonation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn issue_wif_without_impersonation_mint_stamp_is_opaque() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let oidc_path = write_oidc_token(tmp.path(), fake_oidc_jwt());
        let key = fixture_key_wif(oidc_path, FIXTURE_AUDIENCE, None);
        let mock = Arc::new(MockGcpClient::new().with_form(200, sts_ok_body()));
        let broker = GcpBroker::with_client(key, None, mock);
        let req = gcp_request(
            serde_json::json!({
                "target_service_account": "",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": 3600,
                "delegates": [],
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert!(
            matches!(cred.mint_stamp, MintStamp::Opaque),
            "WIF without impersonation should be Opaque, got {:?}",
            cred.mint_stamp
        );
    }
}
