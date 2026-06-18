//! AWS STS `Broker` implementation — issues short-lived AWS credentials
//! (access key id + secret access key + session token) scoped to daemon-
//! derived STS scope via `AssumeRole`, `GetSessionToken`, or web identity, returns
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
//! - `mode = AssumeRole`       → `AssumeRole` (preferred for IAM-based
//!   delegation; supports `role_arn` and cross-account `external_id`).
//! - `mode = GetSessionToken`  → `GetSessionToken` (MFA-bearer for the
//!   long-lived credentials' own permissions).
//! - `mode = WebIdentity`      → `AssumeRoleWithWebIdentity` (OIDC-based
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
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use chrono::{DateTime, Utc};
pub use core_broker::project::{AwsStsMode, AwsStsScope};
use core_broker::{
    Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential, IdentityRef, MintStamp,
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
        let resp = req.body(body).send().await.map_err(|e| e.to_string())?;
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

    let signing_output =
        sign(signable, &params).map_err(|e| BrokerError::Other(format!("sigv4 sign: {e}")))?;
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
fn parse_sts_credentials(
    body: &str,
    action: StsAction,
) -> Result<AwsVendedCredentials, BrokerError> {
    // Real-world STS XML uses an `<*Result><Credentials>` envelope. We
    // do a minimal regex-free extract by tag matching — STS responses
    // are deterministic XML produced by AWS, not user input.
    let creds_tag_open = "<Credentials>";
    let creds_tag_close = "</Credentials>";
    let creds_block = body
        .find(creds_tag_open)
        .and_then(|start| {
            let after = start + creds_tag_open.len();
            body[after..]
                .find(creds_tag_close)
                .map(|end| &body[after..after + end])
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

    let access_key_id = extract("AccessKeyId")
        .ok_or_else(|| BrokerError::Upstream("STS response missing AccessKeyId".to_string()))?;
    let secret_access_key = extract("SecretAccessKey")
        .ok_or_else(|| BrokerError::Upstream("STS response missing SecretAccessKey".to_string()))?;
    let session_token = extract("SessionToken")
        .ok_or_else(|| BrokerError::Upstream("STS response missing SessionToken".to_string()))?;
    let expiration = extract("Expiration")
        .ok_or_else(|| BrokerError::Upstream("STS response missing Expiration".to_string()))?;

    Ok(AwsVendedCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}

/// Minimal tag-slice helper. STS responses are deterministic AWS-produced XML,
/// not user input, so a tag match is sufficient (same approach as
/// [`parse_sts_credentials`]). Returns the slice between the first `open` tag and
/// the next `close` tag, or `None` if either is absent.
fn slice_between<'a>(haystack: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = haystack.find(open)? + open.len();
    let end = haystack[start..].find(close)?;
    Some(&haystack[start..start + end])
}

/// Extract `<AssumedRoleUser><Arn>...</Arn>` from an STS `AssumeRole` /
/// `AssumeRoleWithWebIdentity` response. `None` for a `GetSessionToken` response
/// (which carries no `AssumedRoleUser`) or a malformed body.
fn parse_assumed_role_arn(body: &str) -> Option<String> {
    let block = slice_between(body, "<AssumedRoleUser>", "</AssumedRoleUser>")?;
    slice_between(block, "<Arn>", "</Arn>").map(str::to_string)
}

/// Parse `(partition, account_id, role_name)` from an IAM role ARN
/// (`arn:<partition>:iam::<account>:role/<path?><name>`). The partition is parsed
/// generically (`aws`, `aws-us-gov`, `aws-cn`, …) rather than hardcoded, so a
/// GovCloud/China role compares correctly against its assumed-role response. The
/// role name is the final path segment — STS drops any IAM path in the
/// assumed-role ARN, so the terminal name is the comparable identity. `None` if
/// not a well-formed IAM role ARN.
fn parse_iam_role_identity(arn: &str) -> Option<(&str, &str, &str)> {
    // arn:<partition>:iam::<account>:role/<path?><name>
    let mut parts = arn.splitn(6, ':');
    if parts.next()? != "arn" {
        return None;
    }
    let partition = parts.next()?;
    if parts.next()? != "iam" {
        return None;
    }
    let _region = parts.next()?; // empty for IAM
    let account = parts.next()?;
    let path_and_name = parts.next()?.strip_prefix("role/")?;
    let name = path_and_name.rsplit('/').next()?;
    (!partition.is_empty() && !account.is_empty() && !name.is_empty())
        .then_some((partition, account, name))
}

/// Parse `(partition, account_id, role_name)` from an STS assumed-role ARN
/// (`arn:<partition>:sts::<account>:assumed-role/<role_name>/<session>`). The
/// partition is parsed generically (GovCloud/China safe). The role name is the
/// segment between `assumed-role/` and the session suffix. `None` if not a
/// well-formed assumed-role ARN.
fn parse_assumed_role_identity(arn: &str) -> Option<(&str, &str, &str)> {
    // arn:<partition>:sts::<account>:assumed-role/<role_name>/<session>
    let mut parts = arn.splitn(6, ':');
    if parts.next()? != "arn" {
        return None;
    }
    let partition = parts.next()?;
    if parts.next()? != "sts" {
        return None;
    }
    let _region = parts.next()?; // empty for STS
    let account = parts.next()?;
    let name = parts
        .next()?
        .strip_prefix("assumed-role/")?
        .split('/')
        .next()?;
    (!partition.is_empty() && !account.is_empty() && !name.is_empty())
        .then_some((partition, account, name))
}

/// Build the AWS STS provider-scope echo (ADR 204 amendment 2 / ADR 205 §B) from
/// the minted scope and the STS response's attested assumed-role identity.
///
/// **STS attests the role IDENTITY, not the effective permissions.** The mint
/// response carries `<AssumedRoleUser><Arn>` (which role was assumed) but never
/// the effective session permissions — the inline session policy is request-side;
/// STS applies it but does not echo it back. So the echo is a **role-identity
/// attestation only** (`{ "assumed_role_arn": <arn> }`). It deliberately does NOT
/// carry the request's inline policy: copying our own permission claim into the
/// echo would let a request-side policy masquerade as provider-attested scope on
/// the materialization audit event. AWS sits in the identity-attestable tier; the
/// permission bound is enforced upstream by `need ⊆ grant` plus the STS-applied
/// session policy, not by this echo.
///
/// `None` ⇒ no attestable echo, consistent with the github "unbounded ⇒ None"
/// rule:
/// - non-`AssumeRole` mints (`GetSessionToken` / `WebIdentity`) carry no bounded
///   identity the daemon clamp consumes;
/// - a full-role `AssumeRole` (no inline session policy) is unbounded;
/// - a response with no parseable `AssumedRoleUser` (anomalous for `AssumeRole`)
///   yields no role identity to attest — degrade to `None` rather than fabricate.
///
/// On a role-identity MISMATCH (STS assumed a different role than minted — a
/// provider/projector anomaly), the echo carries the role STS ACTUALLY assumed so
/// the daemon clamp's role-identity check fails closed and revokes the credential.
fn aws_mint_stamp(
    scope: &AwsStsScope,
    effective_role_arn: &str,
    assumed_role_arn: Option<&str>,
) -> Result<MintStamp, BrokerError> {
    // Non-AssumeRole mints (GetSessionToken / WebIdentity) and AssumeRole
    // without inline_policy carry NO bounded identity the daemon clamp can
    // verify; they yield MintStamp::Unbounded (the G3 "request shape
    // carries no narrow bound" variant). This is policy-distinct from a
    // bounded mint with an unobservable echo (H-1 fail-closed path below).
    let AwsStsScope::AssumeRole {
        inline_policy: Some(_),
        ..
    } = scope
    else {
        return Ok(MintStamp::Unbounded);
    };

    // Below: bounded AssumeRole mint. STS SHOULD have attested an
    // <AssumedRoleUser>; if it didn't, the mint succeeded but provider
    // truth is unobservable — REFUSE the mint at the broker rather than
    // silently degrading the audit to G3 with a live bounded credential
    // attached (adversarial finding H-1 fail-closed).
    let Some(assumed) = assumed_role_arn else {
        return Err(BrokerError::Upstream(
            "aws provider echo: AssumeRole succeeded with inline session policy but \
             STS response carried no parseable <AssumedRoleUser> — refusing mint \
             rather than recording unverified bounded credential as G3 \
             (ADR 213 §D4 / H-1)"
                .to_string(),
        ));
    };
    let Some((sts_partition, sts_account, sts_role)) = parse_assumed_role_identity(assumed) else {
        return Err(BrokerError::Upstream(format!(
            "aws provider echo: <AssumedRoleUser> ARN '{assumed}' unparseable \
             (expected arn:<partition>:sts::<account>:assumed-role/<name>/<session>) \
             — refusing mint (ADR 213 §D4 / H-1)"
        )));
    };
    let Some((minted_partition, minted_account, minted_role)) =
        parse_iam_role_identity(effective_role_arn)
    else {
        return Err(BrokerError::Upstream(format!(
            "aws provider echo: minted IAM role ARN '{effective_role_arn}' unparseable \
             — refusing mint (ADR 213 §D4 / H-1)"
        )));
    };

    let attested_role_arn = if sts_partition == minted_partition
        && sts_account == minted_account
        && sts_role == minted_role
    {
        // STS confirmed exactly the minted role — echo the minted IAM role ARN
        // (preserves any IAM path the assumed-role ARN drops).
        effective_role_arn.to_string()
    } else {
        // STS assumed a different role/partition/account than minted — echo what
        // STS attested so the daemon clamp catches the discrepancy. Best-effort IAM
        // ARN: the identity already differs, so the dropped path cannot mask it.
        format!("arn:{sts_partition}:iam::{sts_account}:role/{sts_role}")
    };

    // ADR 213 §D4 G2 — AWS attests WHICH identity was minted, not its
    // permissions. `IdentityRef` is a closed shape (no permission field by
    // type, AC-4): the request-side session policy is structurally
    // unrepresentable here, which is the load-bearing invariant that
    // prevents the AWS request-policy masquerade (#5734 caught the runtime
    // form of this; D4 makes it unrepresentable).
    Ok(MintStamp::Identity {
        identity: IdentityRef {
            provider: BrokerProvider::AwsSts,
            identity: attested_role_arn,
        },
    })
}

/// STS `<ErrorResponse><Error><Code>...</Code></Error></ErrorResponse>`
/// shape. Map well-known codes to the closest [`BrokerError`] variant.
fn map_sts_error(status: u16, body: &str) -> BrokerError {
    let code = extract_error_code(body).unwrap_or_default();
    match code.as_str() {
        "AccessDenied" | "AccessDeniedException" => {
            BrokerError::PolicyRejected(format!("STS access denied: {body}"))
        }
        // AssumeRoleWithWebIdentity-specific: the OIDC token is bad
        // (malformed, expired, audience-mismatched, signature-invalid,
        // or issuer not in the role's trust policy). Map to
        // PolicyRejected — the caller's identity credential failed
        // policy at AWS' end, same shape as AccessDenied.
        "InvalidIdentityToken" | "IDPRejectedClaim" | "IDPCommunicationError" => {
            BrokerError::PolicyRejected(format!("STS rejected web identity token: {body}"))
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
    let mut params: Vec<(&str, String)> = vec![
        ("Action", "AssumeRole".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("RoleArn", role_arn.to_string()),
        ("RoleSessionName", session_name.to_string()),
        ("DurationSeconds", ttl_seconds.to_string()),
    ];
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
        // `effective_role_arn` is the IAM role ARN actually sent to STS for an
        // `AssumeRole` mint (after the `default_role_arn` fallback). It is the
        // minted role identity the provider-scope echo cross-checks against the
        // STS `<AssumedRoleUser>`. `None` for `GetSessionToken` / `WebIdentity`,
        // which carry no attestable PermissionSpec-bounded echo.
        let (action, body, headers, effective_role_arn) = match &scope {
            AwsStsScope::AssumeRole {
                role_arn,
                session_name,
                ttl_seconds,
                policy_arns,
                inline_policy,
                external_id,
            } => {
                let effective_role = role_arn.clone().or_else(|| self.default_role_arn.clone());
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
                (StsAction::AssumeRole, body, headers, Some(arn))
            }
            AwsStsScope::GetSessionToken { ttl_seconds, .. } => {
                let body = build_get_session_token_body(*ttl_seconds);
                let headers = build_signed_headers(&self.creds, &url, &body, now)?;
                (StsAction::GetSessionToken, body, headers, None)
            }
            AwsStsScope::WebIdentity {
                role_arn,
                oidc_token,
                session_name,
                ttl_seconds,
            } => {
                let body =
                    assume_role_with_web_identity(role_arn, session_name, oidc_token, *ttl_seconds);
                // Unsigned — no Authorization header. STS validates
                // the OIDC token directly against the role's trust
                // policy.
                let headers: Vec<(String, String)> = Vec::new();
                (StsAction::AssumeRoleWithWebIdentity, body, headers, None)
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

        // ADR 204 amendment 2 / ADR 205 §B / ADR 213 §D4 — the provider-scope
        // echo. STS attests which role it assumed via `<AssumedRoleUser>`;
        // build the typed variant from that identity. Variant semantics:
        //   MintStamp::Identity { … }     — AssumeRole + inline_policy +
        //                                       parseable AssumedRoleUser (G2)
        //   MintStamp::Unbounded          — non-AssumeRole / full-role
        //                                       AssumeRole (G3 unbounded)
        //   Err(BrokerError::Upstream)       — bounded AssumeRole but STS
        //                                       failed to attest the role
        //                                       (anomaly — refuse the mint,
        //                                       H-1 fail-closed)
        //
        // The mint is refused via `?` so a live bounded credential is NEVER
        // injected without provider-truth verification.
        //
        // Built BEFORE the token string is moved into the `SecretString`.
        let mint_stamp = match effective_role_arn.as_deref() {
            Some(role) => {
                aws_mint_stamp(&scope, role, parse_assumed_role_arn(&resp_body).as_deref())?
            }
            // No effective role to attest (GetSessionToken / WebIdentity
            // without a resolved role): unbounded by request shape.
            None => MintStamp::Unbounded,
        };

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
        let token_json = serde_json::to_string(&vended)
            .map_err(|e| BrokerError::Other(format!("serialize vended credentials: {e}")))?;

        self.state
            .lock()
            .expect("aws-sts broker state mutex")
            .insert(materialization_id.clone(), expires_at);

        Ok(BrokeredCredential {
            token: SecretString::from(token_json),
            expires_at,
            materialization_id,
            mint_stamp,
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
        let parsed = parse_sts_credentials(&get_session_token_ok_xml(), StsAction::GetSessionToken)
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
        assert!(matches!(err, BrokerError::Upstream(_)), "expected Upstream");
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
                "mode": "assume_role",
                "role_arn": "arn:aws:iam::111122223333:role/dev",
                "session_name": "agent-1",
                "ttl_seconds": 3600,
                "policy_arns": [],
                "inline_policy": null,
                "external_id": null,
            }),
            3600,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
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
                "mode": "get_session_token",
                "session_name": "agent-2",
                "ttl_seconds": 1800,
            }),
            1800,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
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
                "mode": "assume_role",
                "session_name": "agent-3",
                "ttl_seconds": 3600,
            }),
            3600,
        );
        // Should use AssumeRole (default role) not GetSessionToken.
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
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
                "mode": "assume_role",
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
                "mode": "get_session_token",
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
        // mode and session_name are required — leaving them out is a parse error.
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
                "mode": "get_session_token",
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
                    "mode": "assume_role",
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
    // AssumeRoleWithWebIdentity — BROKER-AWS-STS-WEB-IDENTITY tests
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
        let token =
            SecretString::from("eyJhbGciOiJSUzI1NiIsImtpZCI6Im9pZGMifQ.body.sig".to_string());
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
    fn aws_sts_scope_without_mode_is_rejected() {
        let raw = serde_json::json!({
            "role_arn": "arn:aws:iam::111122223333:role/dev",
            "session_name": "missing-mode",
            "ttl_seconds": 3600,
        });
        let err = serde_json::from_value::<AwsStsScope>(raw).expect_err("mode is required");
        assert!(
            err.to_string().contains("mode"),
            "error should name missing mode, got: {err}"
        );

        let raw = serde_json::json!({
            "session_name": "missing-mode",
            "ttl_seconds": 3600,
        });
        let err = serde_json::from_value::<AwsStsScope>(raw).expect_err("mode is required");
        assert!(
            err.to_string().contains("mode"),
            "error should name missing mode, got: {err}"
        );
    }

    #[test]
    fn map_sts_error_invalid_identity_token_returns_policy_rejected() {
        let err = map_sts_error(400, &invalid_identity_token_xml());
        assert!(
            matches!(err, BrokerError::PolicyRejected(_)),
            "expected PolicyRejected for InvalidIdentityToken, got {err:?}"
        );
    }

    /// Shape captured by [`CapturingStsClient`]: the (headers, body)
    /// tuple the broker handed to the STS HTTP client.
    type CapturedStsRequest = (Vec<(String, String)>, String);

    /// Captures the headers/body the broker hands to the HTTP client
    /// so the test can assert "no Authorization header" for
    /// AssumeRoleWithWebIdentity.
    struct CapturingStsClient {
        status: u16,
        body: String,
        captured: Mutex<Option<CapturedStsRequest>>,
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
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");

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

    // ---------------------------------------------------------------------
    // ADR 204 amendment 2 / ADR 205 §B — provider-scope echo. AWS is the
    // identity-attestable tier: STS attests WHICH role it assumed (not the
    // permissions), so the echo is a role-identity attestation
    // (`{ "assumed_role_arn": <arn> }`) the daemon I7 clamp compares against the
    // minted role. It deliberately carries NO permission claim.
    // ---------------------------------------------------------------------

    /// A bounded inline session policy (PermissionSpec-derived shape). Its
    /// presence gates echo emission; it is deliberately NOT carried in the echo.
    const TEST_INLINE_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::ember-test-bucket/agent/report.txt"]}]}"#;

    /// A minted `AssumeRole` scope shaped exactly like the projector's output:
    /// explicit role ARN + a PermissionSpec-derived inline session policy.
    fn minted_assume_role_scope(role_arn: &str) -> AwsStsScope {
        AwsStsScope::AssumeRole {
            role_arn: Some(role_arn.to_string()),
            session_name: "agent-1".to_string(),
            ttl_seconds: 900,
            policy_arns: Vec::new(),
            inline_policy: Some(TEST_INLINE_POLICY.to_string()),
            external_id: None,
        }
    }

    /// Realistic STS `AssumeRole` response carrying the `<AssumedRoleUser>` block
    /// real STS always returns (the `assume_role_ok_xml` fixture omits it).
    fn assume_role_xml_with_assumed_user(assumed_role_arn: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<AssumeRoleResponse>
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROAEXAMPLEID:agent-1</AssumedRoleId>
      <Arn>{assumed_role_arn}</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>testSecretAccessKeyValue</SecretAccessKey>
      <SessionToken>testSessionTokenValue</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
        )
    }

    /// Unwrap a `MintStamp::Identity` and return the attested identity (role
    /// ARN), or panic if the echo is the wrong variant. The closed `IdentityRef`
    /// shape is the AC-4 invariant; this helper exists so test reads of the
    /// echoed identity stay one line.
    fn echo_role(echo: &MintStamp) -> &str {
        match echo {
            MintStamp::Identity { identity } => {
                assert_eq!(
                    identity.provider,
                    BrokerProvider::AwsSts,
                    "AWS echo must bind BrokerProvider::AwsSts"
                );
                &identity.identity
            }
            other => panic!("expected MintStamp::Identity, got: {other:?}"),
        }
    }

    /// Test-only helper: unwrap the successful echo or panic with the broker
    /// error. Tests that exercise the H-1 fail-closed path call `_err` on
    /// the raw `Result` directly.
    fn echo_ok(result: Result<MintStamp, BrokerError>) -> MintStamp {
        result.expect("aws_mint_stamp must succeed for this fixture")
    }

    #[test]
    fn parse_assumed_role_arn_extracts_from_assume_role_response() {
        let body = assume_role_xml_with_assumed_user(
            "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1",
        );
        assert_eq!(
            parse_assumed_role_arn(&body).as_deref(),
            Some("arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1")
        );
    }

    #[test]
    fn parse_assumed_role_arn_none_for_get_session_token_response() {
        // GetSessionToken responses carry no <AssumedRoleUser>.
        assert_eq!(parse_assumed_role_arn(&get_session_token_ok_xml()), None);
    }

    #[test]
    fn parse_iam_role_identity_handles_partition_path_and_rejects() {
        assert_eq!(
            parse_iam_role_identity("arn:aws:iam::123456789012:role/ember-agent"),
            Some(("aws", "123456789012", "ember-agent"))
        );
        // An IAM path is dropped to the terminal role name (STS drops it too in
        // the assumed-role ARN), so the terminal name is the comparable identity.
        assert_eq!(
            parse_iam_role_identity("arn:aws:iam::123456789012:role/team/sub/ember-agent"),
            Some(("aws", "123456789012", "ember-agent"))
        );
        // GovCloud / China partitions parse (finding-2 coverage).
        assert_eq!(
            parse_iam_role_identity("arn:aws-us-gov:iam::123456789012:role/ember-agent"),
            Some(("aws-us-gov", "123456789012", "ember-agent"))
        );
        assert_eq!(
            parse_iam_role_identity("arn:aws:sts::1:assumed-role/x/y"),
            None
        );
        assert_eq!(parse_iam_role_identity("not-an-arn"), None);
    }

    #[test]
    fn parse_assumed_role_identity_extracts_partition_account_role() {
        assert_eq!(
            parse_assumed_role_identity(
                "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1"
            ),
            Some(("aws", "123456789012", "ember-agent"))
        );
        assert_eq!(
            parse_assumed_role_identity(
                "arn:aws-us-gov:sts::123456789012:assumed-role/ember-agent/s"
            ),
            Some(("aws-us-gov", "123456789012", "ember-agent"))
        );
        assert_eq!(parse_assumed_role_identity("arn:aws:iam::1:role/x"), None);
    }

    #[test]
    fn aws_mint_stamp_attests_minted_role_only() {
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(role);
        let assumed = "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1";

        let echo = echo_ok(aws_mint_stamp(&minted, role, Some(assumed)));
        assert_eq!(echo_role(&echo), role);
    }

    #[test]
    fn aws_mint_stamp_carries_no_permission_claim() {
        // The echo must NOT carry the request-side inline policy / permissions —
        // AWS attests identity, not permissions (G2). The AC-4 invariant is now
        // type-enforced (`IdentityRef` has no permission field), but the
        // serialization guard remains so a future serde rename of `IdentityRef`
        // can't silently smuggle the inline policy through the audit JSON.
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(role);
        let assumed = "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1";

        let echo = echo_ok(aws_mint_stamp(&minted, role, Some(assumed)));
        match &echo {
            MintStamp::Identity { identity } => {
                assert_eq!(identity.provider, BrokerProvider::AwsSts);
                assert!(!identity.identity.is_empty(), "identity must be populated");
            }
            other => panic!("expected MintStamp::Identity, got: {other:?}"),
        }
        let serialized = serde_json::to_string(&echo).expect("MintStamp must serialize as JSON");
        assert!(
            !serialized.contains("Statement") && !serialized.contains("s3:PutObject"),
            "echo must not contain the request inline policy: {serialized}"
        );
    }

    #[test]
    fn aws_mint_stamp_preserves_iam_path_on_match() {
        // The STS assumed-role ARN drops the IAM path; on a match the echo must
        // carry the minted IAM ARN (path intact) so the clamp does not
        // false-positive on a legitimate pathed role.
        let role = "arn:aws:iam::123456789012:role/team/ember-agent";
        let minted = minted_assume_role_scope(role);
        let assumed = "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1";

        let echo = echo_ok(aws_mint_stamp(&minted, role, Some(assumed)));
        assert_eq!(
            echo_role(&echo),
            role,
            "echo must preserve the full IAM path"
        );
    }

    #[test]
    fn aws_mint_stamp_matches_across_govcloud_partition() {
        // Finding-2 coverage: a GovCloud role + its GovCloud assumed-role response
        // must match and emit an echo (the prior hardcoded `arn:aws:` prefix
        // silently dropped the echo for non-standard partitions).
        let role = "arn:aws-us-gov:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(role);
        let assumed = "arn:aws-us-gov:sts::123456789012:assumed-role/ember-agent/agent-1";

        let echo = echo_ok(aws_mint_stamp(&minted, role, Some(assumed)));
        assert_eq!(echo_role(&echo), role);
    }

    #[test]
    fn aws_mint_stamp_carries_sts_role_on_mismatch_so_clamp_catches_it() {
        // STS attests a DIFFERENT role than minted — the echo must carry the role
        // STS actually assumed so the daemon clamp's role comparison fails closed.
        let minted_role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(minted_role);
        let assumed_other = "arn:aws:sts::123456789012:assumed-role/admin-role/agent-1";

        let echo = echo_ok(aws_mint_stamp(&minted, minted_role, Some(assumed_other)));
        assert_ne!(
            echo_role(&echo),
            minted_role,
            "a role mismatch must surface in the echo so the I7 clamp revokes"
        );
        assert_eq!(
            echo_role(&echo),
            "arn:aws:iam::123456789012:role/admin-role"
        );
    }

    #[test]
    fn aws_mint_stamp_refuses_mint_without_assumed_role_user_h1() {
        // H-1 fail-closed (adversarial finding): an AssumeRole mint with
        // inline_policy that returned no parseable <AssumedRoleUser> must
        // REFUSE the mint via BrokerError::Upstream — not silently degrade
        // to G3 with the live bounded credential attached. The prior
        // behaviour (MintStamp::None) collapsed into the same audit
        // discriminator as anthropic-by-design, hiding the anomaly.
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(role);
        let err = aws_mint_stamp(&minted, role, None)
            .expect_err("missing <AssumedRoleUser> on bounded AssumeRole must refuse mint");
        match err {
            BrokerError::Upstream(msg) => assert!(
                msg.contains("AssumedRoleUser") || msg.contains("H-1"),
                "error must name the anomaly: {msg}"
            ),
            other => panic!("expected BrokerError::Upstream, got: {other:?}"),
        }
    }

    #[test]
    fn aws_mint_stamp_refuses_mint_with_unparseable_assumed_role_arn_h1() {
        // H-1 sibling: parseable AssumedRoleUser but a malformed ARN — also
        // refuse the mint rather than silently degrading.
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let minted = minted_assume_role_scope(role);
        let garbage_arn = "not-an-arn-at-all";
        let err = aws_mint_stamp(&minted, role, Some(garbage_arn))
            .expect_err("unparseable AssumedRoleUser ARN must refuse mint");
        assert!(matches!(err, BrokerError::Upstream(_)));
    }

    #[test]
    fn aws_mint_stamp_unbounded_for_full_role_assume_role() {
        // No inline session policy ⇒ unbounded full-role mint ⇒
        // MintStamp::Unbounded (the explicit G3 "request shape carries
        // no narrow bound" variant, ADR 213 §D4). Mirrors github's
        // repository_selection=all path.
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let full_role = AwsStsScope::AssumeRole {
            role_arn: Some(role.to_string()),
            session_name: "agent-1".to_string(),
            ttl_seconds: 900,
            policy_arns: Vec::new(),
            inline_policy: None,
            external_id: None,
        };
        let assumed = "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1";
        let echo = echo_ok(aws_mint_stamp(&full_role, role, Some(assumed)));
        assert!(matches!(echo, MintStamp::Unbounded));
    }

    #[test]
    fn aws_mint_stamp_unbounded_for_get_session_token() {
        let scope = AwsStsScope::GetSessionToken {
            session_name: "agent-1".to_string(),
            ttl_seconds: 900,
        };
        // A non-AssumeRole mint has no PermissionSpec-bounded echo.
        let echo = echo_ok(aws_mint_stamp(&scope, "arn:aws:iam::1:role/x", None));
        assert!(matches!(echo, MintStamp::Unbounded));
    }

    #[tokio::test]
    async fn issue_assume_role_populates_mint_stamp_from_assumed_role_user() {
        let role = "arn:aws:iam::123456789012:role/ember-agent";
        let broker = AwsStsBroker::with_client(
            fixture_creds(),
            None,
            Arc::new(MockStsClient {
                status: 200,
                body: assume_role_xml_with_assumed_user(
                    "arn:aws:sts::123456789012:assumed-role/ember-agent/agent-1",
                ),
            }),
        );
        let req = sts_request(
            serde_json::json!({
                "mode": "assume_role",
                "role_arn": role,
                "session_name": "agent-1",
                "ttl_seconds": 900,
                "policy_arns": [],
                "inline_policy": TEST_INLINE_POLICY,
                "external_id": null,
            }),
            900,
        );
        let cred = Broker::issue(&broker, req)
            .await
            .expect("issue must succeed");
        assert_eq!(echo_role(&cred.mint_stamp), role);
    }

    #[tokio::test]
    async fn issue_assume_role_refuses_mint_when_response_omits_assumed_role_user_h1() {
        // H-1 (adversarial finding) — the legacy fixture omits
        // <AssumedRoleUser>; pre-D4 the echo degraded to `MintStamp::None`
        // (silent G3 with a live bounded credential attached). D4 promotes
        // this anomaly to a hard mint refusal at the broker boundary, so the
        // daemon never sees a credential it can't clamp-verify. This test is
        // the integration-level guard that the AwsStsBroker::issue path
        // actually propagates the error rather than recording the
        // pre-refusal failure as a silent G3 mint.
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
                "mode": "assume_role",
                "role_arn": "arn:aws:iam::123456789012:role/ember-agent",
                "session_name": "agent-1",
                "ttl_seconds": 900,
                "policy_arns": [],
                "inline_policy": TEST_INLINE_POLICY,
                "external_id": null,
            }),
            900,
        );
        let err = Broker::issue(&broker, req)
            .await
            .expect_err("missing <AssumedRoleUser> on bounded AssumeRole must refuse mint");
        match err {
            BrokerError::Upstream(msg) => assert!(
                msg.contains("AssumedRoleUser") || msg.contains("H-1"),
                "broker error must name the anomaly: {msg}"
            ),
            other => panic!("expected BrokerError::Upstream, got: {other:?}"),
        }
    }
}
