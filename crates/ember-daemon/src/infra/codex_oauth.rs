//! CLASSIFICATION: PUBLIC
//!
//! ChatGPT plan/subscription OAuth handling for the codex GPT-plan responses
//! lane (P22-S2 / ADR 197 codex).
//!
//! The daemon owns the codex `auth.json` token blob (`{id_token, access_token,
//! refresh_token, account_id}`) in the vault, refreshes the short-window access
//! token against `auth.openai.com/oauth/token` when near expiry, and persists
//! the rotated `refresh_token` back to vault. The proxy receives ONLY the
//! injected fields (access token + account id + fedramp) — the `refresh_token`
//! never leaves the daemon (see [`crate::infra::proxy`]).
//!
//! Upstream alignment: codex-rs does NOT publish its crates to crates.io, so the
//! OAuth contract values below are VENDORED with per-item provenance rather than
//! linked. They are wire/OAuth-contract constants (a public client id and a
//! stable OAuth URL), not internal types, so drift risk is low. The
//! [`tests`] module asserts the vendored shapes against the documented contract.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Public OAuth client id baked into the shipped codex binary (a *public*
/// client — no secret; the refresh flow is `grant_type=refresh_token` +
/// `client_id`).
///
/// provenance: codex-rs `login/src/auth/manager.rs` `CLIENT_ID` @ rust-v0.134.0
pub const CHATGPT_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// OAuth token endpoint used for the refresh-token grant.
///
/// provenance: codex-rs `login/src/auth/manager.rs` `REFRESH_TOKEN_URL` @ rust-v0.134.0
pub const CHATGPT_REFRESH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// Operator-only env override for the refresh endpoint. VERSION-RESILIENCE: if
/// OpenAI ever moves the OAuth token endpoint, an operator repins without a
/// rebuild. Mirrors codex's own `CODEX_REFRESH_TOKEN_URL_OVERRIDE`.
pub const CHATGPT_REFRESH_TOKEN_URL_OVERRIDE_ENV: &str = "EMBER_CHATGPT_REFRESH_TOKEN_URL";

/// The refresh endpoint, honouring [`CHATGPT_REFRESH_TOKEN_URL_OVERRIDE_ENV`].
pub fn refresh_token_url() -> String {
    match std::env::var(CHATGPT_REFRESH_TOKEN_URL_OVERRIDE_ENV) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => CHATGPT_REFRESH_TOKEN_URL.to_string(),
    }
}

/// Refresh the access token proactively when it is within this many minutes of
/// expiry. codex itself uses 5 minutes
/// (`CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES`); we use a more generous
/// window so a token cannot expire mid-session. Access tokens are long-lived
/// (~10 days empirically — `exp - iat = 240h`), so even this generous window
/// fires a refresh only about once per token lifetime.
pub const REFRESH_WINDOW_MINUTES: i64 = 60;

/// Errors parsing/handling the codex token blob.
#[derive(Debug, thiserror::Error)]
pub enum CodexOAuthError {
    #[error("token blob is not valid JSON: {0}")]
    Json(String),
    #[error("token blob has no access_token")]
    MissingAccessToken,
}

/// The codex `auth.json` token blob subset we consume. Mirrors codex-rs
/// `TokenData` (`login/src/token_data.rs`) but keeps `id_token` as the raw JWT
/// string (codex parses it into claims on load; we parse claims lazily).
///
/// Stored in the vault as JSON. The operator obtains it by running `codex
/// login` (browser OAuth) once, then storing `jq '.tokens' ~/.codex/auth.json`
/// into the vault.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodexTokenBlob {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// Parse the stored vault blob into a [`CodexTokenBlob`].
///
/// Accepts EITHER the bare `tokens` object (`{access_token, ...}`) OR a whole
/// `auth.json` (`{tokens: {...}, OPENAI_API_KEY, last_refresh}`) — we locate the
/// object carrying `access_token` so the operator can store whichever shape is
/// convenient.
pub fn parse_token_blob(bytes: &[u8]) -> Result<CodexTokenBlob, CodexOAuthError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| CodexOAuthError::Json(e.to_string()))?;

    // Prefer a top-level `access_token`; else descend into `.tokens`.
    let obj = if value.get("access_token").is_some() {
        value.clone()
    } else if let Some(tokens) = value.get("tokens") {
        tokens.clone()
    } else {
        return Err(CodexOAuthError::MissingAccessToken);
    };

    let blob: CodexTokenBlob =
        serde_json::from_value(obj).map_err(|e| CodexOAuthError::Json(e.to_string()))?;
    if blob.access_token.is_empty() {
        return Err(CodexOAuthError::MissingAccessToken);
    }
    Ok(blob)
}

/// Serialize a [`CodexTokenBlob`] back to the bare-`tokens` JSON shape for
/// vault write-back after a refresh.
pub fn serialize_token_blob(blob: &CodexTokenBlob) -> Vec<u8> {
    serde_json::to_vec(blob).unwrap_or_default()
}

// ── JWT claim decode (id_token / access_token) ──────────────────────────────

#[derive(Deserialize)]
struct ExpClaim {
    #[serde(default)]
    exp: Option<i64>,
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize, Default)]
struct AuthClaims {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: bool,
}

/// Decode a JWT payload (the middle `header.PAYLOAD.sig` segment) into `T`.
/// Returns `None` on any malformed input — callers treat absence as "unknown".
fn decode_jwt_payload<T: DeserializeOwned>(jwt: &str) -> Option<T> {
    let mut parts = jwt.split('.');
    let (_h, payload, _s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if !h.is_empty() && !p.is_empty() && !s.is_empty() => (h, p, s),
        _ => return None,
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Expiry instant of the access token (`exp` claim), if parseable.
pub fn access_token_expiry(blob: &CodexTokenBlob) -> Option<DateTime<Utc>> {
    let claims: ExpClaim = decode_jwt_payload(&blob.access_token)?;
    claims
        .exp
        .and_then(|exp| DateTime::<Utc>::from_timestamp(exp, 0))
}

/// Whether the access token should be refreshed now (within the refresh window
/// of expiry, or already expired). Returns `false` when expiry can't be parsed
/// — we forward the token as-is and let upstream's 401 drive recovery rather
/// than spuriously burning a (rotating) refresh token.
pub fn needs_refresh(blob: &CodexTokenBlob, now: DateTime<Utc>) -> bool {
    match access_token_expiry(blob) {
        Some(exp) => exp <= now + chrono::Duration::minutes(REFRESH_WINDOW_MINUTES),
        None => false,
    }
}

/// Whether the access token is already past its `exp`.
pub fn is_hard_expired(blob: &CodexTokenBlob, now: DateTime<Utc>) -> bool {
    matches!(access_token_expiry(blob), Some(exp) if exp <= now)
}

/// The ChatGPT account/workspace id for the `ChatGPT-Account-ID` header:
/// the explicit `account_id` field, else the `id_token`'s
/// `chatgpt_account_id` claim.
pub fn account_id(blob: &CodexTokenBlob) -> Option<String> {
    if let Some(id) = blob.account_id.as_ref().filter(|s| !s.is_empty()) {
        return Some(id.clone());
    }
    let id_token = blob.id_token.as_deref()?;
    let claims: IdClaims = decode_jwt_payload(id_token)?;
    claims.auth.and_then(|a| a.chatgpt_account_id)
}

/// Stable OIDC subject for the logged-in ChatGPT user, if present in
/// `id_token`. Used only to derive a vault credential key; absence falls back
/// to a token fingerprint.
pub fn subject(blob: &CodexTokenBlob) -> Option<String> {
    let id_token = blob.id_token.as_deref()?;
    let claims: IdClaims = decode_jwt_payload(id_token)?;
    claims.sub
}

/// Whether the account must route through the FedRAMP edge
/// (`id_token` `chatgpt_account_is_fedramp` claim).
pub fn is_fedramp(blob: &CodexTokenBlob) -> bool {
    let Some(id_token) = blob.id_token.as_deref() else {
        return false;
    };
    decode_jwt_payload::<IdClaims>(id_token)
        .and_then(|c| c.auth)
        .map(|a| a.chatgpt_account_is_fedramp)
        .unwrap_or(false)
}

// ── Refresh (daemon-owned) ──────────────────────────────────────────────────

/// Outcome of a successful refresh-token grant. Any field may be absent — the
/// OAuth server returns only what changed. Callers merge non-`None` fields into
/// the stored blob (refresh tokens ROTATE, so a returned `refresh_token` MUST
/// replace the old one and be persisted).
#[derive(Debug, Clone, Default)]
pub struct RefreshOutcome {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Why a refresh failed.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// The refresh token is expired / already-used (rotation) / revoked. The
    /// operator must re-run `codex login` — retrying cannot recover. Maps to a
    /// fail-closed re-auth signal.
    #[error("refresh token unusable ({0}) — re-auth required")]
    Permanent(String),
    /// Network / 5xx / transient server error — the existing token (if still
    /// valid) may keep working; a later attempt may succeed.
    #[error("refresh transient error: {0}")]
    Transient(String),
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    grant_type: &'a str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct RefreshResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// Classify an OAuth refresh error body into permanent (re-auth) vs transient.
/// Mirrors codex-rs `classify_refresh_token_failure`
/// (`login/src/auth/manager.rs`): the `error.code` (or top-level `error`
/// string) values `refresh_token_expired` / `refresh_token_reused` /
/// `refresh_token_invalidated` are permanent.
fn classify_refresh_failure(status: reqwest::StatusCode, body: &str) -> RefreshError {
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| match v.get("error") {
            Some(serde_json::Value::Object(o)) => {
                o.get("code").and_then(|c| c.as_str()).map(str::to_string)
            }
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => None,
        })
        .map(|s| s.to_ascii_lowercase());

    match code.as_deref() {
        Some("refresh_token_expired") => RefreshError::Permanent("expired".into()),
        Some("refresh_token_reused") => RefreshError::Permanent("reused".into()),
        Some("refresh_token_invalidated") => RefreshError::Permanent("revoked".into()),
        _ => {
            if status == reqwest::StatusCode::UNAUTHORIZED {
                RefreshError::Permanent("unauthorized".into())
            } else {
                RefreshError::Transient(format!("{status}: {body}"))
            }
        }
    }
}

/// Perform the OAuth refresh-token grant against the (override-aware) refresh
/// endpoint. Owns only `String`s so the returned future is `Send` (it runs on
/// the daemon's `LocalSet` between the synchronous vault read and write — the
/// caller must NOT hold the `!Send` vault/store across this await).
///
/// The `refresh_token` is passed by reference and never logged.
pub async fn refresh_access_token(refresh_token: &str) -> Result<RefreshOutcome, RefreshError> {
    let endpoint = refresh_token_url();
    let req = RefreshRequest {
        client_id: CHATGPT_OAUTH_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token,
    };

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| RefreshError::Transient(e.to_string()))?;

    let resp = client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .json(&req)
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
            id_token: parsed.id_token,
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
        })
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(classify_refresh_failure(status, &body))
    }
}

/// Merge a [`RefreshOutcome`] into a blob, replacing only the fields the server
/// returned. A returned `refresh_token` MUST overwrite the old one (rotation).
pub fn apply_refresh(blob: &mut CodexTokenBlob, outcome: RefreshOutcome) {
    if let Some(id_token) = outcome.id_token {
        blob.id_token = Some(id_token);
    }
    if let Some(access_token) = outcome.access_token {
        blob.access_token = access_token;
    }
    if let Some(refresh_token) = outcome.refresh_token {
        blob.refresh_token = Some(refresh_token);
    }
}

#[cfg(test)]
#[path = "codex_oauth_tests.rs"]
mod tests;
