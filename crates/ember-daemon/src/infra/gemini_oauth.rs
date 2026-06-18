//! CLASSIFICATION: PUBLIC
//!
//! gemini Code Assist ("Sign in with Google") OAuth handling for the gemini
//! Code Assist loopback lane (ADR 215 slice 2).
//!
//! The daemon owns the gemini `oauth_creds.json` token blob
//! (`{access_token, refresh_token, expiry_date, token_type, scope, id_token}` —
//! the google-auth-library `Credentials` shape) in the vault, refreshes the
//! short-window access token against Google's OAuth token endpoint when near
//! expiry, and persists it back. The proxy receives ONLY the injected access
//! token (`Authorization: Bearer …`) — the `refresh_token` never crosses that
//! boundary (it is the structural-absence root the loopback lane relies on).
//!
//! Sibling to [`crate::infra::codex_oauth`]; intentionally kept separate (the
//! blob shapes, token endpoints, and rotation semantics differ) but mirrors its
//! structure. Notable deltas: google-auth-library stores a plain numeric
//! `expiry_date` (ms-since-epoch) rather than a JWT `exp` claim (no JWT decode);
//! Google's token endpoint speaks `application/x-www-form-urlencoded` and
//! requires the (public, installed-app) client secret; and Google does NOT
//! rotate the `refresh_token` on a refresh-grant (the response carries only a
//! fresh access token + `expires_in`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Env var carrying the Gemini Code Assist installed-application OAuth client id.
///
/// The Gemini lane is experimental. Do not embed provider client material in
/// source: GitHub push protection treats it as a secret even for installed-app
/// OAuth clients. Operators validating this lane must provide the client
/// material through daemon environment.
pub const GEMINI_OAUTH_CLIENT_ID_ENV: &str = "EMBER_GEMINI_OAUTH_CLIENT_ID";

/// Env var carrying the Gemini Code Assist installed-application OAuth client secret.
pub const GEMINI_OAUTH_CLIENT_SECRET_ENV: &str = "EMBER_GEMINI_OAUTH_CLIENT_SECRET";

/// Google's OAuth 2.0 token endpoint (google-auth-library's default).
pub const GEMINI_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Operator-only env override for the token endpoint (test/repin without a
/// rebuild). Mirrors [`crate::infra::codex_oauth::CHATGPT_REFRESH_TOKEN_URL_OVERRIDE_ENV`].
pub const GEMINI_TOKEN_URL_OVERRIDE_ENV: &str = "EMBER_GEMINI_OAUTH_TOKEN_URL";

/// The token endpoint, honouring [`GEMINI_TOKEN_URL_OVERRIDE_ENV`].
pub fn token_url() -> String {
    match std::env::var(GEMINI_TOKEN_URL_OVERRIDE_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => GEMINI_TOKEN_URL.to_string(),
    }
}

/// Refresh when the access token is within this many seconds of expiry (or
/// already expired). gemini-cli refreshes ~5 minutes ahead.
pub const REFRESH_WINDOW_SECONDS: i64 = 300;

/// Errors parsing/handling the gemini token blob.
#[derive(Debug, thiserror::Error)]
pub enum GeminiOAuthError {
    #[error("token blob is not valid JSON: {0}")]
    Json(String),
    #[error("token blob has no access_token")]
    MissingAccessToken,
}

/// The gemini `oauth_creds.json` blob subset we consume — the google-auth-library
/// `Credentials` shape. `expiry_date` is ms-since-epoch (NOT a JWT claim).
///
/// Stored in the vault as JSON. The operator obtains it by running the gemini
/// "Sign in with Google" flow once, then storing `~/.gemini/oauth_creds.json`
/// into the vault (the launcher slice automates the harvest).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeminiOAuthBlob {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Expiry as ms-since-epoch (google-auth-library `Credentials.expiry_date`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<i64>,
}

/// Parse the stored vault blob into a [`GeminiOAuthBlob`].
///
/// Accepts EITHER the bare `Credentials` object (`{access_token, ...}`) OR a
/// wrapper carrying it under `.tokens` — we locate the object with
/// `access_token` so the operator can store whichever shape is convenient.
pub fn parse_oauth_blob(bytes: &[u8]) -> Result<GeminiOAuthBlob, GeminiOAuthError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| GeminiOAuthError::Json(e.to_string()))?;

    let obj = if value.get("access_token").is_some() {
        value.clone()
    } else if let Some(tokens) = value.get("tokens") {
        tokens.clone()
    } else {
        return Err(GeminiOAuthError::MissingAccessToken);
    };

    let blob: GeminiOAuthBlob =
        serde_json::from_value(obj).map_err(|e| GeminiOAuthError::Json(e.to_string()))?;
    if blob.access_token.is_empty() {
        return Err(GeminiOAuthError::MissingAccessToken);
    }
    Ok(blob)
}

/// Serialize a [`GeminiOAuthBlob`] back to JSON for vault write-back.
pub fn serialize_oauth_blob(blob: &GeminiOAuthBlob) -> Vec<u8> {
    serde_json::to_vec(blob).unwrap_or_default()
}

/// The access token's expiry, from the numeric `expiry_date` (ms epoch).
pub fn access_token_expiry(blob: &GeminiOAuthBlob) -> Option<DateTime<Utc>> {
    blob.expiry_date
        .and_then(DateTime::<Utc>::from_timestamp_millis)
}

/// Whether the access token should be refreshed (within the refresh window of
/// expiry, or already expired). Returns `true` when expiry is unknown — refresh
/// to be safe rather than ship a possibly-dead token.
pub fn needs_refresh(blob: &GeminiOAuthBlob, now: DateTime<Utc>) -> bool {
    match access_token_expiry(blob) {
        Some(exp) => exp <= now + chrono::Duration::seconds(REFRESH_WINDOW_SECONDS),
        None => true,
    }
}

/// Whether the access token is already expired (past, not just within the
/// refresh window). Unknown expiry → treat as NOT hard-expired so a transient
/// refresh blip can fall back to the stored token.
pub fn is_hard_expired(blob: &GeminiOAuthBlob, now: DateTime<Utc>) -> bool {
    matches!(access_token_expiry(blob), Some(exp) if exp <= now)
}

// ── Refresh (daemon-owned) ──────────────────────────────────────────────────

/// Outcome of a successful refresh-token grant. Google returns a fresh access
/// token + `expires_in` (and may echo scope/token_type/id_token); it does NOT
/// return a new `refresh_token` (no rotation), so the caller keeps the stored one.
#[derive(Debug, Clone, Default)]
pub struct RefreshOutcome {
    pub access_token: Option<String>,
    pub expires_in_secs: Option<i64>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
    pub token_type: Option<String>,
}

/// Why a refresh failed.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// The experimental Gemini lane needs operator-supplied OAuth client
    /// material. Missing config is not recoverable by retrying the token
    /// endpoint.
    #[error("gemini oauth client configuration missing ({0})")]
    Config(String),
    /// The refresh token is expired / revoked / invalid. Google returns
    /// `error: "invalid_grant"`. The operator must re-run the gemini Sign-in
    /// flow — retrying cannot recover. Maps to a fail-closed re-auth signal.
    #[error("refresh token unusable ({0}) — re-auth required")]
    Permanent(String),
    /// Network / 5xx / transient server error — the existing token (if still
    /// valid) may keep working; a later attempt may succeed.
    #[error("refresh transient error: {0}")]
    Transient(String),
}

#[derive(Deserialize)]
struct RefreshResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

struct GeminiOAuthClientConfig {
    client_id: String,
    client_secret: String,
}

fn required_oauth_env(name: &str) -> Result<String, RefreshError> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| RefreshError::Config(format!("{name} is not set")))
}

fn oauth_client_config() -> Result<GeminiOAuthClientConfig, RefreshError> {
    Ok(GeminiOAuthClientConfig {
        client_id: required_oauth_env(GEMINI_OAUTH_CLIENT_ID_ENV)?,
        client_secret: required_oauth_env(GEMINI_OAUTH_CLIENT_SECRET_ENV)?,
    })
}

/// Classify a Google OAuth token-endpoint error body into permanent (re-auth)
/// vs transient. Google returns `{"error": "invalid_grant", "error_description":
/// "..."}`; `invalid_grant`/`invalid_client`/`unauthorized_client` are permanent.
fn classify_refresh_failure(status: reqwest::StatusCode, body: &str) -> RefreshError {
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|c| c.as_str()).map(str::to_string))
        .map(|s| s.to_ascii_lowercase());

    match code.as_deref() {
        Some("invalid_grant") => RefreshError::Permanent("invalid_grant".into()),
        Some("invalid_client") => RefreshError::Permanent("invalid_client".into()),
        Some("unauthorized_client") => RefreshError::Permanent("unauthorized_client".into()),
        _ => {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                RefreshError::Permanent("unauthorized".into())
            } else {
                RefreshError::Transient(format!("{status}: {body}"))
            }
        }
    }
}

/// Perform the OAuth refresh-token grant against the (override-aware) Google
/// token endpoint. Owns only `&str`s so the returned future is `Send` (it runs
/// between the synchronous vault read and write — the caller must NOT hold the
/// `!Send` vault/store across this await). The `refresh_token` is passed by
/// reference and never logged.
///
/// Google's token endpoint requires `application/x-www-form-urlencoded` with the
/// client id + installed-app client secret. Those values are provided through
/// daemon environment for the experimental Gemini lane.
pub async fn refresh_access_token(refresh_token: &str) -> Result<RefreshOutcome, RefreshError> {
    let endpoint = token_url();
    let oauth_client = oauth_client_config()?;
    let form = [
        ("client_id", oauth_client.client_id.as_str()),
        ("client_secret", oauth_client.client_secret.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];

    // reqwest is built without default features, so `RequestBuilder::form` is
    // unavailable — encode the body ourselves (this is exactly what `.form()`
    // does internally). `serde_urlencoded` percent-encodes the values, which the
    // refresh token (`1//0g…`, contains `/`) requires.
    let body = serde_urlencoded::to_string(form)
        .map_err(|e| RefreshError::Transient(format!("form encode: {e}")))?;

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| RefreshError::Transient(e.to_string()))?;

    let resp = client
        .post(&endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|e| RefreshError::Transient(e.to_string()))?;

    let status = resp.status();
    if status.is_success() {
        let parsed: RefreshResponse = resp
            .json()
            .await
            .map_err(|e| RefreshError::Transient(e.to_string()))?;
        Ok(RefreshOutcome {
            access_token: parsed.access_token,
            expires_in_secs: parsed.expires_in,
            id_token: parsed.id_token,
            scope: parsed.scope,
            token_type: parsed.token_type,
        })
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(classify_refresh_failure(status, &body))
    }
}

/// Merge a [`RefreshOutcome`] into a blob: replace the access token, recompute
/// `expiry_date` from `expires_in` (relative to `now`), and update any echoed
/// scope/token_type/id_token. The `refresh_token` is left UNCHANGED (Google does
/// not rotate it).
pub fn apply_refresh(blob: &mut GeminiOAuthBlob, outcome: RefreshOutcome, now: DateTime<Utc>) {
    if let Some(access_token) = outcome.access_token {
        blob.access_token = access_token;
    }
    if let Some(secs) = outcome.expires_in_secs {
        // ms-since-epoch, matching google-auth-library's `expiry_date`. Both the
        // *1000 and the add saturate: a hostile/garbage `expires_in` must not
        // panic a debug build (or wrap) on the shared proxy thread — worst case
        // the expiry pins to `i64::MAX` and the next read treats it as valid,
        // which is no worse than honouring the server's stated lifetime.
        blob.expiry_date = Some(
            now.timestamp_millis()
                .saturating_add(secs.saturating_mul(1000)),
        );
    }
    if let Some(id_token) = outcome.id_token {
        blob.id_token = Some(id_token);
    }
    if let Some(scope) = outcome.scope {
        blob.scope = Some(scope);
    }
    if let Some(token_type) = outcome.token_type {
        blob.token_type = Some(token_type);
    }
}

#[cfg(test)]
#[path = "gemini_oauth_tests.rs"]
mod tests;
