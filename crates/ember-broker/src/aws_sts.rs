//! AWS STS `Broker` implementation — issues short-lived AWS credentials
//! (access key id + secret access key + session token) scoped to caller-
//! supplied role / policy via `AssumeRole` or `GetSessionToken`, returns
//! them as [`BrokeredCredential`] with a JSON-encoded credential bundle
//! the consumer (`broker_exec` / `apply_credential_to_env`) can split into
//! `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_SESSION_TOKEN` env
//! vars at exec time.
//!
//! Companion to the daemon-side registration in
//! `ember-daemon::infra::runtime::run` — this struct holds the
//! [`AwsLongLivedCredentials`] (loaded from disk at daemon startup via
//! `ember_daemon::broker::aws_sts_config`) and one entry per outstanding
//! materialization.
//!
//! ## Mode selection
//!
//! - `role_arn = Some(arn)` → `AssumeRole` (preferred for IAM-based
//!   delegation; supports cross-account via `external_id`).
//! - `role_arn = None`      → `GetSessionToken` (MFA-bearer for the
//!   long-lived credentials' own permissions).
//! - `mode = WebIdentity`   → `AssumeRoleWithWebIdentity` (OIDC-based
//!   path that swaps an OIDC token — k8s SA projection, GitHub Actions
//!   OIDC, EKS IRSA — for STS credentials. Bypasses long-lived AWS
//!   keys entirely; the OIDC token IS the authentication.).
//!
//! ## Signing
//!
//! `AssumeRole` and `GetSessionToken` are signed with AWS Signature
//! Version 4 via the standalone `aws-sigv4` crate. We deliberately
//! avoid `aws-sdk-sts` / `aws-sdk-rust` — the full SDK pulls dozens of
//! transitive crates for one HTTPS POST.
//!
//! `AssumeRoleWithWebIdentity` is **unsigned** — the OIDC token is the
//! authentication, so the SigV4 path is skipped for that mode.
//!
//! ## Revocation
//!
//! STS sessions are TTL-bound only; AWS does not offer a programmatic
//! mid-TTL revoke API. `revoke()` therefore drops bookkeeping and emits
//! a `tracing::warn!` so the audit trail records the best-effort
//! semantics. The credential remains valid until its `expires_at`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use chrono::{DateTime, Utc};
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Long-lived AWS credentials backing the broker. Loaded once at daemon
/// startup from `~/.config/emberlink/aws-sts.env` (see
/// `ember_daemon::broker::aws_sts_config::load_aws_sts_credentials`).
///
/// The broker uses these to sign STS calls; their plaintext never leaves
/// the daemon. Vended credentials (returned from STS) replace them in
/// the spawned subprocess's environment.
#[derive(Clone)]
pub struct AwsLongLivedCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    /// Optional session token — set when the long-lived credentials are
    /// themselves session-scoped (MFA-bearing). Most installations use
    /// IAM-user keys with no session token.
    pub session_token: Option<String>,
    /// AWS region for the STS endpoint. The STS service is regional —
    /// `sts.<region>.amazonaws.com` — and signing scope embeds it.
    pub region: String,
}

/// Provider-specific scope payload for the AWS STS broker.
///
/// Deserialized from the opaque `BrokerRequest::scope` (`serde_json::Value`)
/// inside `issue()`. Three modes are supported:
///
/// - [`AwsStsScope::AssumeRole`] — IAM-based delegation, signed with
///   SigV4 against the long-lived credentials.
/// - [`AwsStsScope::GetSessionToken`] — MFA-bearer scope for the
///   long-lived credentials' own permissions.
/// - [`AwsStsScope::WebIdentity`] — OIDC-based exchange (k8s SA
///   projection, GitHub Actions OIDC, EKS IRSA). Unsigned (the OIDC
///   token is the authentication).
///
/// ## JSON wire shape & back-compat
///
/// New callers SHOULD include a `"mode"` discriminant
/// (`"assume_role"` / `"get_session_token"` / `"web_identity"`).
/// Legacy callers that omit `mode` continue to work via the custom
/// [`Deserialize`] impl below: presence of `role_arn` selects
/// `AssumeRole`, absence selects `GetSessionToken`. `web_identity`
/// requires the explicit `mode` discriminant (we don't infer it from
/// `oidc_token` presence — that would silently change semantics if a
/// future scope grows an unrelated OIDC field).
#[derive(Debug, Clone)]
pub enum AwsStsScope {
    /// `AssumeRole` request. SigV4-signed against the broker's
    /// long-lived credentials.
    AssumeRole {
        /// IAM role to assume. `None` falls back to the broker's
        /// `default_role_arn` if configured; otherwise `issue()`
        /// rejects the request.
        role_arn: Option<String>,
        /// `RoleSessionName` — also used as part of the
        /// materialization id so the audit trail names the session.
        session_name: String,
        /// Requested credential lifetime. STS clamps to provider
        /// min/max (15 min – 12 h for AssumeRole). We pass through.
        ttl_seconds: u64,
        /// Managed policy ARNs to attach as a session-scope filter
        /// (`PolicyArns.member.N`).
        policy_arns: Vec<String>,
        /// Inline IAM policy document (JSON string) to attach as the
        /// session policy (`Policy`).
        inline_policy: Option<String>,
        /// `ExternalId` for cross-account AssumeRole.
        external_id: Option<String>,
    },
    /// `GetSessionToken` request. SigV4-signed against the broker's
    /// long-lived credentials. Returns session credentials with the
    /// same effective permissions as the long-lived IAM user.
    GetSessionToken {
        /// Used as part of the materialization id so the audit trail
        /// names the session.
        session_name: String,
        /// Requested credential lifetime. STS clamps to 15 min – 36 h
        /// for GetSessionToken.
        ttl_seconds: u64,
    },
    /// `AssumeRoleWithWebIdentity` request. Unsigned — the OIDC token
    /// is the authentication. Used by k8s SA projection, GitHub
    /// Actions OIDC, EKS IRSA, and any other OIDC-issuing identity
    /// federation.
    WebIdentity {
        /// IAM role to assume.
        role_arn: String,
        /// OIDC token (already loaded from disk / env / projected SA
        /// volume by the caller). Held as [`SecretString`] so a Debug
        /// print won't leak it. The daemon-side `aws_sts_config`
        /// loads this from `oidc_token_path` (see follow-up wireup)
        /// and hands it to the broker as the request scope.
        oidc_token: SecretString,
        /// `RoleSessionName` — used as part of the materialization
        /// id so the audit trail names the session.
        session_name: String,
        /// Requested credential lifetime. STS clamps to 15 min – 12 h
        /// for AssumeRoleWithWebIdentity.
        ttl_seconds: u64,
    },
}

/// JSON discriminant for [`AwsStsScope`]. Serialized as snake_case so
/// the wire shape is `"assume_role"` / `"get_session_token"` /
/// `"web_identity"` — matches the AWS STS Action names in lower-snake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsStsMode {
    AssumeRole,
    GetSessionToken,
    WebIdentity,
}

impl AwsStsScope {
    /// `session_name` accessor — every variant carries one.
    pub fn session_name(&self) -> &str {
        match self {
            AwsStsScope::AssumeRole { session_name, .. }
            | AwsStsScope::GetSessionToken { session_name, .. }
            | AwsStsScope::WebIdentity { session_name, .. } => session_name,
        }
    }

    /// `ttl_seconds` accessor — every variant carries one.
    pub fn ttl_seconds(&self) -> u64 {
        match self {
            AwsStsScope::AssumeRole { ttl_seconds, .. }
            | AwsStsScope::GetSessionToken { ttl_seconds, .. }
            | AwsStsScope::WebIdentity { ttl_seconds, .. } => *ttl_seconds,
        }
    }

    /// Discriminant — the [`AwsStsMode`] this variant corresponds to.
    pub fn mode(&self) -> AwsStsMode {
        match self {
            AwsStsScope::AssumeRole { .. } => AwsStsMode::AssumeRole,
            AwsStsScope::GetSessionToken { .. } => AwsStsMode::GetSessionToken,
            AwsStsScope::WebIdentity { .. } => AwsStsMode::WebIdentity,
        }
    }
}

/// Internal flat-JSON shape used by the custom [`Deserialize`] /
/// [`Serialize`] impls. Every field is optional so a single shape
/// covers all three variants; the `mode` discriminant (or, for
/// legacy callers, presence of `role_arn`) selects the variant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AwsStsScopeRaw {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<AwsStsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_arn: Option<String>,
    session_name: String,
    ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policy_arns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inline_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    /// OIDC token for `web_identity` mode. Plaintext on the wire (the
    /// scope is already inside the daemon's trust boundary by the
    /// time it deserializes); wrapped in [`SecretString`] in memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc_token: Option<String>,
}

impl Serialize for AwsStsScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            AwsStsScope::AssumeRole {
                role_arn,
                session_name,
                ttl_seconds,
                policy_arns,
                inline_policy,
                external_id,
            } => AwsStsScopeRaw {
                mode: Some(AwsStsMode::AssumeRole),
                role_arn: role_arn.clone(),
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                policy_arns: policy_arns.clone(),
                inline_policy: inline_policy.clone(),
                external_id: external_id.clone(),
                oidc_token: None,
            },
            AwsStsScope::GetSessionToken {
                session_name,
                ttl_seconds,
            } => AwsStsScopeRaw {
                mode: Some(AwsStsMode::GetSessionToken),
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                ..Default::default()
            },
            AwsStsScope::WebIdentity {
                role_arn,
                oidc_token,
                session_name,
                ttl_seconds,
            } => AwsStsScopeRaw {
                mode: Some(AwsStsMode::WebIdentity),
                role_arn: Some(role_arn.clone()),
                session_name: session_name.clone(),
                ttl_seconds: *ttl_seconds,
                oidc_token: Some(oidc_token.expose_secret().to_string()),
                ..Default::default()
            },
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AwsStsScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = AwsStsScopeRaw::deserialize(deserializer)?;
        // Mode resolution: explicit `mode` wins; fall back to legacy
        // role_arn-presence-based dispatch when omitted. We do NOT
        // infer `web_identity` from `oidc_token` presence — that
        // requires the explicit discriminant.
        let mode = raw.mode.unwrap_or_else(|| {
            if raw.role_arn.is_some() {
                AwsStsMode::AssumeRole
            } else {
                AwsStsMode::GetSessionToken
            }
        });
        match mode {
            AwsStsMode::AssumeRole => Ok(AwsStsScope::AssumeRole {
                role_arn: raw.role_arn,
                session_name: raw.session_name,
                ttl_seconds: raw.ttl_seconds,
                policy_arns: raw.policy_arns,
                inline_policy: raw.inline_policy,
                external_id: raw.external_id,
            }),
            AwsStsMode::GetSessionToken => Ok(AwsStsScope::GetSessionToken {
                session_name: raw.session_name,
                ttl_seconds: raw.ttl_seconds,
            }),
            AwsStsMode::WebIdentity => {
                let role_arn = raw.role_arn.ok_or_else(|| {
                    serde::de::Error::custom(
                        "web_identity mode requires role_arn",
                    )
                })?;
                let oidc_token = raw.oidc_token.ok_or_else(|| {
                    serde::de::Error::custom(
                        "web_identity mode requires oidc_token",
                    )
                })?;
                Ok(AwsStsScope::WebIdentity {
                    role_arn,
                    oidc_token: SecretString::from(oidc_token),
                    session_name: raw.session_name,
                    ttl_seconds: raw.ttl_seconds,
                })
            }
        }
    }
}

/// Vended STS credentials in the JSON shape the consumer (`broker_exec` /
/// `apply_credential_to_env`) splits into env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsVendedCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// RFC3339-encoded expiration time (matches what STS returns).
    pub expiration: String,
}

/// Minimal HTTP client trait so tests inject a mock without spinning up
/// a real TLS stack or hitting `sts.<region>.amazonaws.com`.
///
/// Production callers use [`ReqwestStsClient`]; tests use
/// [`MockStsClient`].
#[async_trait::async_trait]
pub trait StsHttpClient: Send + Sync {
    /// POST a SigV4-signed form body to `url` with the given headers.
    /// Returns `(status_code, response_body_string)`.
    ///
    /// The body is `application/x-www-form-urlencoded` per the STS
    /// Query API. Headers include the `Authorization` SigV4 header,
    /// `X-Amz-Date`, optional `X-Amz-Security-Token`, etc.
    async fn post_form_signed(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: String,
    ) -> Result<(u16, String), String>;
}

/// Production [`StsHttpClient`] backed by `reqwest`.
pub struct ReqwestStsClient {
    inner: reqwest::Client,
}

impl ReqwestStsClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/aws-sts")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestStsClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait::async_trait]
impl StsHttpClient for ReqwestStsClient {
    async fn post_form_signed(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        body: String,
    ) -> Result<(u16, String), String> {
        let mut req = self
            .inner
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// `Broker` impl backed by AWS STS.
///
/// Construct with [`AwsStsBroker::new`] for production (uses
/// [`ReqwestStsClient`]) or [`AwsStsBroker::with_client`] for tests
/// (any `dyn StsHttpClient` implementation).
pub struct AwsStsBroker {
    creds: AwsLongLivedCredentials,
    /// Default role ARN to use when scope omits one. Read from
    /// `AWS_DEFAULT_ROLE_ARN` in `aws-sts.env`. Optional.
    default_role_arn: Option<String>,
    client: Arc<dyn StsHttpClient>,
    /// `materialization_id` → `expires_at`. Populated on `issue()`,
    /// drained on `revoke()`. The broker holds nothing else per
    /// outstanding token.
    state: Mutex<HashMap<String, SystemTime>>,
}

impl AwsStsBroker {
    /// Production constructor — uses [`ReqwestStsClient`].
    pub fn new(creds: AwsLongLivedCredentials, default_role_arn: Option<String>) -> Self {
        Self {
            creds,
            default_role_arn,
            client: Arc::new(
                ReqwestStsClient::new()
                    .expect("reqwest client construction must not fail in production"),
            ),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Test constructor — accepts an arbitrary [`StsHttpClient`] so unit
    /// tests can inject [`MockStsClient`].
    pub fn with_client(
        creds: AwsLongLivedCredentials,
        default_role_arn: Option<String>,
        client: Arc<dyn StsHttpClient>,
    ) -> Self {
        Self {
            creds,
            default_role_arn,
            client,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Number of materializations the broker currently tracks. Used by
    /// tests to assert state transitions across `issue`/`revoke` calls.
    pub fn active_count(&self) -> usize {
        self.state.lock().expect("aws-sts broker state mutex").len()
    }

    fn endpoint_url(&self) -> String {
        format!("https://sts.{}.amazonaws.com/", self.creds.region)
    }
}

/// Build the form-urlencoded body for an STS Query API request.
///
/// AWS STS uses Query strings (`Action=Foo&Version=...&Param=...`)
/// posted as `application/x-www-form-urlencoded`. We construct the
/// body manually to avoid pulling another url-form crate.
fn build_form_body(params: &[(&str, String)]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            s.push('&');
        }
        let _ = write!(&mut s, "{}={}", urlencode(k), urlencode(v));
    }
    s
}

/// Minimal RFC3986 percent-encoder for STS form bodies. Encodes
/// everything outside the unreserved set `A-Za-z0-9-._~`. Avoids a
/// full url crate dep for one function.
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

/// Build SigV4 headers for an STS POST. Uses `aws-sigv4`'s builder
/// API with an `aws-credential-types::Credentials` identity.
///
/// Extracted as a free function so unit tests can verify signature
/// material without driving a full broker.
fn build_signed_headers(
    creds: &AwsLongLivedCredentials,
    url: &str,
    body: &str,
    now: SystemTime,
) -> Result<Vec<(String, String)>, BrokerError> {
    // aws-sigv4's `v4::SigningParams::builder().identity(...)` accepts
    // a `&Identity` from aws-smithy-runtime-api. The conversion path is
    // `Credentials -> Identity` via the `From` impl shipped by
    // aws-credential-types. We construct the Credentials, convert to
    // Identity, and bind it to a stack value so the builder's
    // `&'a Identity` reference stays valid for the call.
    let aws_creds = Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.expose_secret().to_string(),
        creds.session_token.clone(),
        None,
        "ember-broker-aws-sts",
    );
    let identity = aws_creds.into();

    let v4_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&creds.region)
        .name("sts")
        .time(now)
        .settings(SigningSettings::default())
        .build()
        .map_err(|e| BrokerError::Other(format!("sigv4 params build: {e}")))?;
    let params: aws_sigv4::http_request::SigningParams = v4_params.into();

    let signable = SignableRequest::new(
        "POST",
        url,
        std::iter::once(("content-type", "application/x-www-form-urlencoded")),
        SignableBody::Bytes(body.as_bytes()),
    )
    .map_err(|e| BrokerError::Other(format!("sigv4 signable: {e}")))?;

    let signing_output = sign(signable, &params)
        .map_err(|e| BrokerError::Other(format!("sigv4 sign: {e}")))?;
    let (instructions, _sig) = signing_output.into_parts();
    let (sig_headers, sig_params) = instructions.into_parts();
    debug_assert!(
        sig_params.is_empty(),
        "expected header-form signing (no query params)"
    );
    let mut headers: Vec<(String, String)> = Vec::new();
    for h in sig_headers {
        headers.push((h.name().to_string(), h.value().to_string()));
    }
    Ok(headers)
}

/// Parse an STS XML response of `AssumeRole` / `GetSessionToken` shape.
///
/// Returns `Ok(creds)` on success. STS errors come back as XML bodies
/// with status >= 400 and an `<ErrorResponse>` envelope; mapping those
/// is handled by the caller via [`map_sts_error`].
fn parse_sts_credentials(body: &str, action: StsAction) -> Result<AwsVendedCredentials, BrokerError> {
    // Real-world STS XML uses an `<*Result><Credentials>` envelope. We
    // do a minimal regex-free extract by tag matching — STS responses
    // are deterministic XML produced by AWS, not user input.
    let creds_tag_open = "<Credentials>";
    let creds_tag_close = "</Credentials>";
    let creds_block = body
        .find(creds_tag_open)
        .and_then(|start| {
            let after = start + creds_tag_open.len();
            body[after..].find(creds_tag_close).map(|end| &body[after..after + end])
        })
        .ok_or_else(|| {
            BrokerError::Upstream(format!(
                "STS {action:?} response missing <Credentials> block: {body}"
            ))
        })?;

    let extract = |tag: &str| -> Option<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let s = creds_block.find(&open)?;
        let after = s + open.len();
        let e = creds_block[after..].find(&close)?;
        Some(creds_block[after..after + e].to_string())
    };

    let access_key_id = extract("AccessKeyId").ok_or_else(|| {
        BrokerError::Upstream("STS response missing AccessKeyId".to_string())
    })?;
    let secret_access_key = extract("SecretAccessKey").ok_or_else(|| {
        BrokerError::Upstream("STS response missing SecretAccessKey".to_string())
    })?;
    let session_token = extract("SessionToken").ok_or_else(|| {
        BrokerError::Upstream("STS response missing SessionToken".to_string())
    })?;
    let expiration = extract("Expiration").ok_or_else(|| {
        BrokerError::Upstream("STS response missing Expiration".to_string())
    })?;

    Ok(AwsVendedCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

/// STS `<ErrorResponse><Error><Code>...</Code></Error></ErrorResponse>`
/// shape. Map well-known codes to the closest [`BrokerError`] variant.
fn map_sts_error(status: u16, body: &str) -> BrokerError {
    let code = extract_error_code(body).unwrap_or_default();
    match code.as_str() {
        "AccessDenied" | "AccessDeniedException" => BrokerError::PolicyRejected(format!(
            "STS access denied: {body}"
        )),
        // AssumeRoleWithWebIdentity-specific: the OIDC token is bad
        // (malformed, expired, audience-mismatched, signature-invalid,
        // or issuer not in the role's trust policy). Map to
        // PolicyRejected — the caller's identity credential failed
        // policy at AWS' end, same shape as AccessDenied.
        "InvalidIdentityToken" | "IDPRejectedClaim" | "IDPCommunicationError" => {
            BrokerError::PolicyRejected(format!(
                "STS rejected web identity token: {body}"
            ))
        }
        "ExpiredToken" | "ExpiredTokenException" | "TokenRefreshRequired" => {
            BrokerError::Upstream(format!("STS credentials expired: {body}"))
        }
        "InvalidClientTokenId" | "SignatureDoesNotMatch" => {
            BrokerError::Upstream(format!("STS authentication failure: {body}"))
        }
        _ => BrokerError::Upstream(format!("STS error (status={status}, code={code}): {body}")),
    }
}

fn extract_error_code(body: &str) -> Option<String> {
    let open = "<Code>";
    let close = "</Code>";
    let s = body.find(open)?;
    let after = s + open.len();
    let e = body[after..].find(close)?;
    Some(body[after..after + e].to_string())
}

/// STS Action variant. Used to label tracing + error messages and to
/// build the form body in [`build_assume_role_body`] /
/// [`build_get_session_token_body`] /
/// [`assume_role_with_web_identity`].
#[derive(Debug, Clone, Copy)]
enum StsAction {
    AssumeRole,
    GetSessionToken,
    AssumeRoleWithWebIdentity,
}

/// Build the form body for `AssumeRole`.
///
/// Caller passes the resolved `role_arn` (defaulted from
/// `default_role_arn` if the scope omitted one) plus the optional
/// `Policy` / `PolicyArns.member.N.arn` / `ExternalId` parameters
/// from the scope.
fn build_assume_role_body(
    role_arn: &str,
    session_name: &str,
    ttl_seconds: u64,
    policy_arns: &[String],
    inline_policy: Option<&str>,
    external_id: Option<&str>,
) -> String {
    let mut params: Vec<(&str, String)> = Vec::new();
    params.push(("Action", "AssumeRole".to_string()));
    params.push(("Version", "2011-06-15".to_string()));
    params.push(("RoleArn", role_arn.to_string()));
    params.push(("RoleSessionName", session_name.to_string()));
    params.push(("DurationSeconds", ttl_seconds.to_string()));
    if let Some(pol) = inline_policy {
        params.push(("Policy", pol.to_string()));
    }
    if let Some(eid) = external_id {
        params.push(("ExternalId", eid.to_string()));
    }
    // PolicyArns.member.<N>.arn=...
    let policy_arn_keys: Vec<String> = (0..policy_arns.len())
        .map(|i| format!("PolicyArns.member.{}.arn", i + 1))
        .collect();
    let policy_arn_pairs: Vec<(&str, String)> = policy_arns
        .iter()
        .zip(policy_arn_keys.iter())
        .map(|(arn, k)| (k.as_str(), arn.clone()))
        .collect();
    params.extend(policy_arn_pairs);
    build_form_body(&params)
}

/// Build the form body for `GetSessionToken`.
fn build_get_session_token_body(ttl_seconds: u64) -> String {
    let params: Vec<(&str, String)> = vec![
        ("Action", "GetSessionToken".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("DurationSeconds", ttl_seconds.to_string()),
    ];
    build_form_body(&params)
}

/// Build the form body for `AssumeRoleWithWebIdentity`.
///
/// **Unsigned** — this STS Action does NOT use SigV4. The `oidc_token`
/// IS the authentication; the long-lived AWS keys are not consulted
/// (and may be entirely absent on hosts using IRSA / k8s SA
/// projection / GitHub Actions OIDC).
///
/// Wire shape (form-urlencoded):
/// ```text
/// Action=AssumeRoleWithWebIdentity
/// Version=2011-06-15
/// RoleArn=<role_arn>
/// RoleSessionName=<session_name>
/// WebIdentityToken=<oidc_token>
/// DurationSeconds=<ttl>
/// ```
fn assume_role_with_web_identity(
    role_arn: &str,
    session_name: &str,
    oidc_token: &SecretString,
    ttl_seconds: u64,
) -> String {
    let params: Vec<(&str, String)> = vec![
        ("Action", "AssumeRoleWithWebIdentity".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("RoleArn", role_arn.to_string()),
        ("RoleSessionName", session_name.to_string()),
        ("WebIdentityToken", oidc_token.expose_secret().to_string()),
        ("DurationSeconds", ttl_seconds.to_string()),
    ];
    build_form_body(&params)
}

impl Broker for AwsStsBroker {
    fn provider(&self) -> BrokerProvider {
        BrokerProvider::AwsSts
    }

    async fn issue(&self, req: BrokerRequest) -> Result<BrokeredCredential, BrokerError> {
        if req.provider != BrokerProvider::AwsSts {
            return Err(BrokerError::InvalidScope(format!(
                "AwsStsBroker received request for {}",
                req.provider.as_str()
            )));
        }

        let scope: AwsStsScope = serde_json::from_value(req.scope)
            .map_err(|e| BrokerError::InvalidScope(format!("scope deserialize: {e}")))?;

        if scope.session_name().is_empty() {
            return Err(BrokerError::InvalidScope(
                "session_name must be non-empty".to_string(),
            ));
        }
        if scope.ttl_seconds() == 0 {
            return Err(BrokerError::InvalidScope(
                "ttl_seconds must be > 0".to_string(),
            ));
        }

        // Build form body + headers per variant. AssumeRole and
        // GetSessionToken sign with SigV4 against the long-lived
        // creds; AssumeRoleWithWebIdentity is unsigned (the OIDC
        // token is the authentication).
        let url = self.endpoint_url();
        let now = SystemTime::now();
        let (action, body, headers) = match &scope {
            AwsStsScope::AssumeRole {
                role_arn,
                session_name,
                ttl_seconds,
                policy_arns,
                inline_policy,
                external_id,
            } => {
                let effective_role = role_arn
                    .clone()
                    .or_else(|| self.default_role_arn.clone());
                let arn = effective_role.ok_or_else(|| {
                    BrokerError::InvalidScope(
                        "assume_role mode requires role_arn (no default_role_arn configured)"
                            .to_string(),
                    )
                })?;
                let body = build_assume_role_body(
                    &arn,
                    session_name,
                    *ttl_seconds,
                    policy_arns,
                    inline_policy.as_deref(),
                    external_id.as_deref(),
                );
                let headers = build_signed_headers(&self.creds, &url, &body, now)?;
                (StsAction::AssumeRole, body, headers)
            }
            AwsStsScope::GetSessionToken { ttl_seconds, .. } => {
                let body = build_get_session_token_body(*ttl_seconds);
                let headers = build_signed_headers(&self.creds, &url, &body, now)?;
                (StsAction::GetSessionToken, body, headers)
            }
            AwsStsScope::WebIdentity {
                role_arn,
                oidc_token,
                session_name,
                ttl_seconds,
            } => {
                let body = assume_role_with_web_identity(
                    role_arn,
                    session_name,
                    oidc_token,
                    *ttl_seconds,
                );
                // Unsigned — no Authorization header. STS validates
                // the OIDC token directly against the role's trust
                // policy.
                let headers: Vec<(String, String)> = Vec::new();
                (StsAction::AssumeRoleWithWebIdentity, body, headers)
            }
        };

        let (status, resp_body) = self
            .client
            .post_form_signed(&url, headers, body)
            .await
            .map_err(BrokerError::Upstream)?;

        if !(200..300).contains(&status) {
            let err = map_sts_error(status, &resp_body);
            tracing::warn!(
                action = ?action,
                status = status,
                error = %err,
                "AwsStsBroker: STS call failed"
            );
            return Err(err);
        }

        let vended = parse_sts_credentials(&resp_body, action)?;

        // STS Expiration is RFC3339; parse to SystemTime for the
        // BrokeredCredential. Fall back to TTL-from-now if parse fails
        // (defensive — STS responses are well-formed in practice).
        let expires_at = match DateTime::parse_from_rfc3339(&vended.expiration) {
            Ok(dt) => SystemTime::from(dt.with_timezone(&Utc)),
            Err(_) => now + std::time::Duration::from_secs(scope.ttl_seconds()),
        };

        let materialization_id = format!(
            "aws-sts-{}-{}",
            scope.session_name(),
            DateTime::<Utc>::from(expires_at).timestamp()
        );

        // The token is a JSON-encoded credential bundle so the consumer
        // (broker_exec / apply_credential_to_env) can split into
        // AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_SESSION_TOKEN.
        let token_json = serde_json::to_string(&vended).map_err(|e| {
            BrokerError::Other(format!("serialize vended credentials: {e}"))
        })?;

        self.state
            .lock()
            .expect("aws-sts broker state mutex")
            .insert(materialization_id.clone(), expires_at);

        Ok(BrokeredCredential {
            token: SecretString::from(token_json),
            expires_at,
            materialization_id,
        })
    }

    async fn revoke(&self, materialization_id: &str) -> Result<(), BrokerError> {
        // STS sessions cannot be programmatically revoked — TTL-bound
        // only. Drop bookkeeping; the credential remains valid until
        // its expires_at. See module docs.
        let mut st = self.state.lock().expect("aws-sts broker state mutex");
        if st.remove(materialization_id).is_none() {
            return Err(BrokerError::UnknownMaterialization(
                materialization_id.to_string(),
            ));
        }
        tracing::warn!(
            materialization_id = %materialization_id,
            "AwsStsBroker: revoke is best-effort — STS credentials are TTL-bound; the vended token remains valid until expiration"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

/// Canned-response mock client for unit tests. Constructed with a fixed
/// `(status_code, body)` pair; every call returns that pair.
pub struct MockStsClient {
    pub status: u16,
    pub body: String,
}

#[async_trait::async_trait]
impl StsHttpClient for MockStsClient {
    async fn post_form_signed(
        &self,
        _url: &str,
        _headers: Vec<(String, String)>,
        _body: String,
    ) -> Result<(u16, String), String> {
        Ok((self.status, self.body.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture_creds() -> AwsLongLivedCredentials {
        AwsLongLivedCredentials {
            access_key_id: "AKIAFIXTUREKEY1234567".to_string(),
            secret_access_key: SecretString::from("fake_secret_value_for_tests".to_string()),
            session_token: None,
            region: "us-east-1".to_string(),
        }
    }

    fn sts_request(scope: serde_json::Value, ttl_secs: u64) -> BrokerRequest {
        BrokerRequest {
            provider: BrokerProvider::AwsSts,
            scope,
            ttl: Duration::from_secs(ttl_secs),
            reason: "test".to_string(),
            caller_persona: None,
            grants_file_rev: None,
            grants_file_credential_name: None,
        }
    }

    fn assume_role_ok_xml() -> String {
        r#"<?xml version="1.0"?>
<AssumeRoleResponse>
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>testSecretAccessKeyValue</SecretAccessKey>
      <SessionToken>testSessionTokenValue</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
            .to_string()
    }

    fn get_session_token_ok_xml() -> String {
        r#"<?xml version="1.0"?>
<GetSessionTokenResponse>
  <GetSessionTokenResult>
    <Credentials>
      <AccessKeyId>ASIASESSIONKEY</AccessKeyId>
      <SecretAccessKey>sessionSecretAccessKey</SecretAccessKey>
      <SessionToken>sessionTokenValueXyz</SessionToken>
      <Expiration>2099-06-01T00:00:00Z</Expiration>
    </Credentials>
  </GetSessionTokenResult>
</GetSessionTokenResponse>"#
            .to_string()
    }

    fn access_denied_xml() -> String {
        r#"<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: arn:aws:iam::111122223333:user/u is not authorized to perform: sts:AssumeRole</Message>
  </Error>
  <RequestId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</RequestId>
</ErrorResponse>"#
            .to_string()
    }

    fn expired_token_xml() -> String {
        r#"<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>ExpiredToken</Code>
    <Message>The security token included in the request is expired</Message>
  </Error>
  <RequestId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</RequestId>
</ErrorResponse>"#
            .to_string()
    }

    #[test]
    fn provider_returns_aws_sts() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        assert_eq!(broker.provider(), BrokerProvider::AwsSts);
    }

    #[test]
    fn parse_assume_role_xml_extracts_credentials() {
        let parsed =
            parse_sts_credentials(&assume_role_ok_xml(), StsAction::AssumeRole).expect("parse ok");
        assert_eq!(parsed.access_key_id, "ASIATESTACCESSKEY");
        assert_eq!(parsed.secret_access_key, "testSecretAccessKeyValue");
        assert_eq!(parsed.session_token, "testSessionTokenValue");
        assert_eq!(parsed.expiration, "2099-01-01T00:00:00Z");
    }

    #[test]
    fn parse_get_session_token_xml_extracts_credentials() {
        let parsed = parse_sts_credentials(
            &get_session_token_ok_xml(),
            StsAction::GetSessionToken,
        )
        .expect("parse ok");
        assert_eq!(parsed.access_key_id, "ASIASESSIONKEY");
        assert_eq!(parsed.session_token, "sessionTokenValueXyz");
    }

    #[test]
    fn map_sts_error_access_denied_returns_policy_rejected() {
        let err = map_sts_error(403, &access_denied_xml());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected, got {err:?}"
        );
    }

    #[test]
    fn map_sts_error_expired_token_returns_upstream() {
        let err = map_sts_error(403, &expired_token_xml());
        let msg = format!("{err}");
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream"
        );
        assert!(
            msg.contains("expired") || msg.contains("Expired"),
            "error message should mention expiration: {msg}"
        );
    }

    #[test]
    fn build_form_body_encodes_values() {
        let body = build_form_body(&[
            ("Action", "AssumeRole".to_string()),
            ("RoleSessionName", "ember/agent-1".to_string()),
        ]);
        // Slash must be percent-encoded; '=' and '&' are separators.
        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("RoleSessionName=ember%2Fagent-1"));
    }

    #[test]
    fn build_assume_role_body_includes_required_params() {
        let body = build_assume_role_body(
            "arn:aws:iam::111122223333:role/dev",
            "agent-1",
            3600,
            &["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()],
            None,
            Some("ext123"),
        );
        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("Version=2011-06-15"));
        assert!(body.contains("RoleArn="));
        assert!(body.contains("RoleSessionName=agent-1"));
        assert!(body.contains("DurationSeconds=3600"));
        assert!(body.contains("ExternalId=ext123"));
        assert!(body.contains("PolicyArns.member.1.arn"));
    }

    #[test]
    fn build_get_session_token_body_omits_role_fields() {
        let body = build_get_session_token_body(1800);
        assert!(body.contains("Action=GetSessionToken"));
        assert!(body.contains("DurationSeconds=1800"));
        assert!(!body.contains("RoleArn"));
        assert!(!body.contains("RoleSessionName"));
    }

    #[tokio::test]
    async fn issue_assume_role_success_returns_json_token() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "role_arn": "arn:aws:iam::111122223333:role/dev",
                "session_name": "agent-1",
                "ttl_seconds": 3600,
                "policy_arns": [],
                "inline_policy": null,
                "external_id": null,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req).await.expect("issue must succeed");
        assert!(cred.materialization_id.starts_with("aws-sts-agent-1-"));

        // Token is a JSON bundle — parse it and verify the three fields.
        let bundle: AwsVendedCredentials =
            serde_json::from_str(cred.token.expose_secret()).expect("bundle must parse");
        assert_eq!(bundle.access_key_id, "ASIATESTACCESSKEY");
        assert_eq!(bundle.secret_access_key, "testSecretAccessKeyValue");
        assert_eq!(bundle.session_token, "testSessionTokenValue");
        assert_eq!(broker.active_count(), 1);
    }

    #[tokio::test]
    async fn issue_get_session_token_when_role_arn_omitted() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: get_session_token_ok_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "session_name": "agent-2",
                "ttl_seconds": 1800,
            }),
            1800,
        );
        let cred = Broker::issue(&broker, req).await.expect("issue must succeed");
        let bundle: AwsVendedCredentials =
            serde_json::from_str(cred.token.expose_secret()).expect("bundle must parse");
        assert_eq!(bundle.access_key_id, "ASIASESSIONKEY");
    }

    #[tokio::test]
    async fn issue_uses_default_role_arn_when_scope_omits_role() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            Some("arn:aws:iam::111122223333:role/default".to_string()),
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "session_name": "agent-3",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        // Should use AssumeRole (default role) not GetSessionToken.
        let cred = Broker::issue(&broker, req).await.expect("issue must succeed");
        assert!(cred.materialization_id.starts_with("aws-sts-agent-3-"));
    }

    #[tokio::test]
    async fn issue_access_denied_returns_policy_rejected() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 403,
                body: access_denied_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "role_arn": "arn:aws:iam::111122223333:role/dev",
                "session_name": "agent-1",
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
    async fn issue_expired_token_returns_upstream() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 403,
                body: expired_token_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "session_name": "agent-1",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::Upstream(_)),
            "expected Upstream, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_invalid_scope_returns_invalid_scope_error() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        // session_name is required (no default) — leaving it out is a parse error.
        let req = sts_request(serde_json::json!({"ttl_seconds": 3600}), 3600);
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::InvalidScope(_)),
            "expected InvalidScope, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_with_wrong_provider_in_request_is_rejected() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        let mut req = sts_request(
            serde_json::json!({
                "session_name": "agent-1",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        req.provider = BrokerProvider::Cloudflare;
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(matches!(err, BrokerError::InvalidScope(_)));
    }

    #[tokio::test]
    async fn revoke_drops_state_returns_ok_with_warn() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        let cred = Broker::issue(
            &broker,
            sts_request(
                serde_json::json!({
                    "role_arn": "arn:aws:iam::111122223333:role/dev",
                    "session_name": "agent-1",
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
    }

    #[tokio::test]
    async fn revoke_unknown_id_returns_unknown_materialization() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_ok_xml(),
            }),
        );
        let err = Broker::revoke(&broker, "does-not-exist").await.unwrap_err();
        assert!(matches!(err, BrokerError::UnknownMaterialization(_)));
    }

    #[test]
    fn aws_sts_scope_round_trips_through_json() {
        let scope = AwsStsScope::AssumeRole {
            role_arn: Some("arn:role".to_string()),
            session_name: "s".to_string(),
            ttl_seconds: 900,
            policy_arns: vec!["arn:pol".to_string()],
            inline_policy: Some("{}".to_string()),
            external_id: Some("ext".to_string()),
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        let parsed: AwsStsScope = serde_json::from_str(&s).expect("deserialize");
        match parsed {
            AwsStsScope::AssumeRole {
                role_arn,
                session_name,
                policy_arns,
                external_id,
                ..
            } => {
                assert_eq!(session_name, "s");
                assert_eq!(role_arn.as_deref(), Some("arn:role"));
                assert_eq!(policy_arns, vec!["arn:pol".to_string()]);
                assert_eq!(external_id.as_deref(), Some("ext"));
            }
            other => panic!("expected AssumeRole, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // AssumeRoleWithWebIdentity — implementation-note-46 tests
    // -----------------------------------------------------------------

    fn assume_role_with_web_identity_ok_xml() -> String {
        // STS' AssumeRoleWithWebIdentity response shape uses the same
        // `<Credentials>` envelope as AssumeRole; the wrapping element
        // is `<AssumeRoleWithWebIdentityResult>`. The shared
        // `parse_sts_credentials` extractor doesn't care about the
        // wrapper — it tag-matches on `<Credentials>`.
        r#"<?xml version="1.0"?>
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>system:serviceaccount:default:agent</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <Credentials>
      <AccessKeyId>ASIAWEBIDENTITYKEY</AccessKeyId>
      <SecretAccessKey>webIdentitySecretAccessKey</SecretAccessKey>
      <SessionToken>webIdentitySessionToken</SessionToken>
      <Expiration>2099-12-31T23:59:59Z</Expiration>
    </Credentials>
    <Provider>arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/abc</Provider>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#
            .to_string()
    }

    fn invalid_identity_token_xml() -> String {
        r#"<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>InvalidIdentityToken</Code>
    <Message>The web identity token has expired or is otherwise invalid</Message>
  </Error>
  <RequestId>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</RequestId>
</ErrorResponse>"#
            .to_string()
    }

    #[test]
    fn assume_role_with_web_identity_body_has_required_params() {
        let token = SecretString::from("eyJhbGciOiJSUzI1NiIsImtpZCI6Im9pZGMifQ.body.sig".to_string());
        let body = assume_role_with_web_identity(
            "arn:aws:iam::111122223333:role/oidc-federated",
            "agent-web",
            &token,
            3600,
        );
        assert!(body.contains("Action=AssumeRoleWithWebIdentity"));
        assert!(body.contains("Version=2011-06-15"));
        assert!(body.contains("RoleSessionName=agent-web"));
        assert!(body.contains("DurationSeconds=3600"));
        // The token's '.' separators are unreserved (RFC3986); check
        // they survive verbatim, prefixed by the form key.
        assert!(
            body.contains("WebIdentityToken=eyJhbGciOiJSUzI1NiIsImtpZCI6Im9pZGMifQ.body.sig"),
            "expected verbatim WebIdentityToken=..., got body: {body}"
        );
        // RoleArn percent-encoding: ':' encodes to %3A, '/' to %2F.
        assert!(body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Foidc-federated"));
    }

    #[test]
    fn aws_sts_scope_web_identity_round_trips_through_json() {
        let scope = AwsStsScope::WebIdentity {
            role_arn: "arn:aws:iam::111122223333:role/oidc-federated".to_string(),
            oidc_token: SecretString::from("oidc-jwt-token".to_string()),
            session_name: "agent-web".to_string(),
            ttl_seconds: 3600,
        };
        let s = serde_json::to_string(&scope).expect("serialize");
        // Discriminant should be present on the wire.
        assert!(s.contains("\"mode\":\"web_identity\""));
        let parsed: AwsStsScope = serde_json::from_str(&s).expect("deserialize");
        match parsed {
            AwsStsScope::WebIdentity {
                role_arn,
                oidc_token,
                session_name,
                ttl_seconds,
            } => {
                assert_eq!(role_arn, "arn:aws:iam::111122223333:role/oidc-federated");
                assert_eq!(oidc_token.expose_secret(), "oidc-jwt-token");
                assert_eq!(session_name, "agent-web");
                assert_eq!(ttl_seconds, 3600);
            }
            other => panic!("expected WebIdentity, got {other:?}"),
        }
    }

    #[test]
    fn aws_sts_scope_legacy_json_without_mode_still_deserializes() {
        // Backward-compat: a legacy caller that omits `mode` and
        // includes `role_arn` should resolve to AssumeRole.
        let raw = serde_json::json!({
            "role_arn": "arn:aws:iam::111122223333:role/dev",
            "session_name": "legacy",
            "ttl_seconds": 3600,
        });
        let scope: AwsStsScope = serde_json::from_value(raw).expect("legacy deserialize");
        assert!(matches!(scope, AwsStsScope::AssumeRole { .. }));
        // And without role_arn → GetSessionToken.
        let raw = serde_json::json!({
            "session_name": "legacy",
            "ttl_seconds": 3600,
        });
        let scope: AwsStsScope = serde_json::from_value(raw).expect("legacy deserialize");
        assert!(matches!(scope, AwsStsScope::GetSessionToken { .. }));
    }

    #[test]
    fn map_sts_error_invalid_identity_token_returns_policy_rejected() {
        let err = map_sts_error(400, &invalid_identity_token_xml());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for InvalidIdentityToken, got {err:?}"
        );
    }

    /// Captures the headers/body the broker hands to the HTTP client
    /// so the test can assert "no Authorization header" for
    /// AssumeRoleWithWebIdentity.
    struct CapturingStsClient {
        status: u16,
        body: String,
        captured: Mutex<Option<(Vec<(String, String)>, String)>>,
    }

    #[async_trait::async_trait]
    impl StsHttpClient for CapturingStsClient {
        async fn post_form_signed(
            &self,
            _url: &str,
            headers: Vec<(String, String)>,
            body: String,
        ) -> Result<(u16, String), String> {
            *self.captured.lock().expect("captured mutex") = Some((headers, body));
            Ok((self.status, self.body.clone()))
        }
    }

    #[tokio::test]
    async fn issue_web_identity_success_skips_sigv4_and_returns_credentials() {
        let captor = Arc::new(CapturingStsClient {
            status: 200,
            body: assume_role_with_web_identity_ok_xml(),
            captured: Mutex::new(None),
        });
        let broker = AwsStsBroker::with_client(fixture_creds(), None, captor.clone());
        let req = sts_request(
            serde_json::json!({
                "mode": "web_identity",
                "role_arn": "arn:aws:iam::111122223333:role/oidc-federated",
                "oidc_token": "oidc-jwt-from-projected-sa-volume",
                "session_name": "agent-web",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req).await.expect("issue must succeed");

        // Vended credentials parse + match XML fixture.
        let bundle: AwsVendedCredentials =
            serde_json::from_str(cred.token.expose_secret()).expect("bundle must parse");
        assert_eq!(bundle.access_key_id, "ASIAWEBIDENTITYKEY");
        assert_eq!(bundle.secret_access_key, "webIdentitySecretAccessKey");
        assert_eq!(bundle.session_token, "webIdentitySessionToken");
        assert!(cred.materialization_id.starts_with("aws-sts-agent-web-"));

        // Inspect the request the broker built. AssumeRoleWithWebIdentity
        // is unsigned — there should be NO Authorization header (or
        // any other SigV4 header like X-Amz-Date).
        let captured = captor.captured.lock().expect("captured mutex").clone();
        let (headers, body) = captured.expect("client must have been called");
        assert!(
            body.contains("Action=AssumeRoleWithWebIdentity"),
            "expected AssumeRoleWithWebIdentity action in body, got: {body}"
        );
        assert!(
            body.contains("WebIdentityToken=oidc-jwt-from-projected-sa-volume"),
            "expected WebIdentityToken in body, got: {body}"
        );
        for (name, _) in &headers {
            let lower = name.to_ascii_lowercase();
            assert_ne!(
                lower, "authorization",
                "AssumeRoleWithWebIdentity must not carry Authorization (SigV4) header"
            );
            assert!(
                !lower.starts_with("x-amz-"),
                "AssumeRoleWithWebIdentity must not carry SigV4 X-Amz-* headers, got {name}"
            );
        }
    }

    #[tokio::test]
    async fn issue_web_identity_invalid_token_returns_policy_rejected() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 400,
                body: invalid_identity_token_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "mode": "web_identity",
                "role_arn": "arn:aws:iam::111122223333:role/oidc-federated",
                "oidc_token": "expired-or-malformed-jwt",
                "session_name": "agent-web",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for InvalidIdentityToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_web_identity_access_denied_returns_policy_rejected() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 403,
                body: access_denied_xml(),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "mode": "web_identity",
                "role_arn": "arn:aws:iam::111122223333:role/oidc-federated",
                "oidc_token": "valid-but-not-trusted-jwt",
                "session_name": "agent-web",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for AccessDenied, got {err:?}"
        );
    }

    #[tokio::test]
    async fn issue_web_identity_missing_oidc_token_is_invalid_scope() {
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_with_web_identity_ok_xml(),
            }),
        );
        // mode=web_identity but no oidc_token → custom Deserialize
        // returns an error → InvalidScope.
        let req = sts_request(
            serde_json::json!({
                "mode": "web_identity",
                "role_arn": "arn:aws:iam::111122223333:role/oidc-federated",
                "session_name": "agent-web",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        let err = Broker::issue(&broker, req).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::InvalidScope(_)),
            "expected InvalidScope when oidc_token is missing, got {err:?}"
        );
    }
}
