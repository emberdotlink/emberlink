//! HashiCorp Vault `CredentialStore` backend (ADR 137 — sub-piece B).
//!
//! `HashiVaultStore` adapts a real HashiCorp Vault server's KV v2 secrets
//! engine to the `CredentialStore` trait. The daemon wires this backend
//! when an operator has an external Vault cluster and prefers it over
//! the local sealed-credential store.
//!
//! # Auth methods
//!
//! Three auth methods are supported:
//!
//! - [`HashiVaultAuth::Token`] — the operator pre-mints a long-lived
//!   token (typically via `vault token create`) and the daemon submits
//!   it as the `X-Vault-Token` header on every request. No login dance.
//! - [`HashiVaultAuth::AppRole`] — the daemon exchanges
//!   `(role_id, secret_id)` at `POST /v1/auth/approle/login` for a
//!   short-lived client token that is cached and renewed by a background
//!   task before expiry. This is the production-recommended auth method
//!   (no long-lived tokens on disk).
//! - [`HashiVaultAuth::Aws`] — the daemon proves its surrounding AWS
//!   IAM identity (EC2 instance profile / EKS IRSA / ECS task role /
//!   Fargate) by submitting a SigV4-signed `sts:GetCallerIdentity`
//!   request as the proof to `POST /v1/auth/aws/login`. Vault verifies
//!   the SigV4 signature against AWS's public-key infrastructure and
//!   returns a Vault client_token. This is the no-static-credentials
//!   path for daemons running on AWS infrastructure.
//! - [`HashiVaultAuth::HcpServicePrincipal`] — HashiCorp Cloud Platform
//!   (HCP) Vault uses a different auth flow than self-hosted Vault.
//!   The daemon exchanges `(client_id, client_secret)` for an HCP
//!   access_token via the standard OAuth2 client_credentials grant at
//!   `https://auth.idp.hashicorp.com/oauth2/token`, then submits the
//!   returned access_token as `Authorization: Bearer` against the
//!   HCP-hosted Vault cluster's `addr`.
//! - [`HashiVaultAuth::JwtOidc`] — generic JWT/OIDC login at
//!   `POST <addr>/v1/<mount_path>/login` with `{ role, jwt }`. Vault
//!   validates the JWT against the configured OIDC provider and returns
//!   a Vault client_token bound to `role`. The daemon supplies the JWT
//!   as a pre-acquired `SecretString` (read from a SA-token mount, an
//!   env var like GitHub Actions' `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, or
//!   any other OIDC-aware compute platform). `mount_path` is `"auth/jwt"`
//!   or `"auth/oidc"` depending on Vault config (the two mounts are the
//!   same primitive with different opinionation).
//! - [`HashiVaultAuth::Kubernetes`] — Kubernetes service-account login
//!   at `POST <addr>/v1/auth/kubernetes/login` with `{ role, jwt }`,
//!   where the JWT is the pod's projected service-account token. The
//!   daemon reads the token from `token_path` (defaults to the standard
//!   K8s SA mount `/var/run/secrets/kubernetes.io/serviceaccount/token`)
//!   on every login + re-login, so the kubelet's token rotation is
//!   transparent. This is functionally a specialization of `JwtOidc`
//!   pinned to `auth/kubernetes` with the JWT sourced from a file.
//!
//! Other auth methods (cert) are out of scope; future follow-ups.
//!
//! # KV v2 wire surface
//!
//! - `get` → `GET <addr>/v1/<mount>/data/<key>` — KV v2 wraps the value
//!   under `.data.data.<key>`. The store is opinionated: it stores the
//!   blob under a fixed inner field name (`"value"`) so the round-trip
//!   shape is stable regardless of upstream conventions.
//! - `put` → `POST <addr>/v1/<mount>/data/<key>` with body
//!   `{"data":{"value":"<base64-or-utf8>"}}`.
//! - `list` → `LIST <addr>/v1/<mount>/metadata/<prefix>` — Vault uses a
//!   non-standard `LIST` HTTP verb (RFC says any method is allowed; some
//!   proxies strip it, but `reqwest` supports custom verbs).
//! - `delete` → `DELETE <addr>/v1/<mount>/metadata/<key>` — KV v2's
//!   "metadata" path performs a destroy-all-versions delete; the
//!   "data" path only soft-deletes the latest version.
//!
//! # Failure handling
//!
//! - 5xx / connect failure → respect [`UnavailablePolicy`]
//!   ([`UnavailablePolicy::FailHard`] returns `StoreError::Unavailable`;
//!   [`UnavailablePolicy::FallBackToCache`] consults a local
//!   plaintext-in-memory cache + TTL).
//! - 401 + AppRole → re-login once and retry; if that still fails,
//!   `StoreError::AuthFailed`.
//! - 403 → `StoreError::AuthFailed` (parent token lacks the relevant
//!   capability — operator must rotate creds).
//! - 404 → `StoreError::NotFound(key)`.
//! - everything else → `StoreError::Other`.
//!
//! # Threading
//!
//! `HashiVaultStore` holds an `Arc<dyn HttpClient>` (mockable for tests)
//! and is `Send + Sync` without any unsafe — the trait object is the
//! only `!Send` candidate and we require `Send + Sync` on it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::RwLock;

use super::{CredentialStore, StoreError};

// ---------------------------------------------------------------------------
// HTTP client trait — mockable for tests
// ---------------------------------------------------------------------------

/// Successful HTTP response captured from the underlying transport.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Transport-level failure raised by the HTTP client (connect refused,
/// TLS handshake failure, body decode failure, …). Mapped to
/// `StoreError::Unavailable` (or fall-back-to-cache) by the store.
#[derive(Debug, Clone)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HttpError {}

/// Minimal HTTP-client surface so tests inject a mock without spinning
/// up a real TLS stack or hitting a Vault cluster.
///
/// Mirrors the `AzureHttpClient` + `HashiVaultHttpClient` pattern from
/// `crates/ember-broker/`. Production callers use [`ReqwestHttpClient`];
/// tests use [`MockHttpClient`].
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform an HTTP request. `method` is the verb (uppercase, e.g.
    /// `"GET"`, `"POST"`, `"DELETE"`, `"LIST"`). `headers` is a slice of
    /// `(name, value)` pairs. `body` is the raw request body bytes,
    /// already serialized by the caller.
    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, HttpError>;
}

/// Production [`HttpClient`] backed by `reqwest`.
pub struct ReqwestHttpClient {
    inner: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self, String> {
        let inner = reqwest::Client::builder()
            .user_agent("ember-daemon/credential-store-hashivault")
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        Ok(Self { inner })
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new().expect("reqwest client construction must not fail in production")
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, HttpError> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| HttpError(format!("invalid HTTP method {method}: {e}")))?;
        let mut req = self.inner.request(m, url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        let resp = req.send().await.map_err(|e| HttpError(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| HttpError(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

// ---------------------------------------------------------------------------
// Auth + policy types
// ---------------------------------------------------------------------------

/// How the daemon authenticates to Vault when issuing requests.
pub enum HashiVaultAuth {
    /// Long-lived static token. The daemon submits it as `X-Vault-Token`
    /// on every request. No login dance is performed.
    Token { token: SecretString },
    /// AppRole login at `/v1/auth/approle/login`. The store exchanges
    /// `(role_id, secret_id)` for a short-lived client token, caches it,
    /// and re-logs in periodically before expiry.
    AppRole {
        role_id: String,
        secret_id: SecretString,
    },
    /// AWS IAM login at `/v1/auth/aws/login`. The daemon submits a
    /// SigV4-signed `sts:GetCallerIdentity` request (against the
    /// surrounding AWS IAM identity available via env vars or instance
    /// metadata) as the proof; Vault re-plays the request server-side
    /// against AWS' public-key infrastructure to verify and returns a
    /// Vault client token bound to `role`.
    ///
    /// AWS credentials are read from the standard env-var chain
    /// (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
    /// `AWS_SESSION_TOKEN`); production deployments populate these
    /// from the IAM role attached to the host / pod / container
    /// (EC2 instance profile, EKS IRSA, ECS task role, Fargate).
    Aws { role: String },
    /// HashiCorp Cloud Platform (HCP) service-principal login at
    /// `https://auth.idp.hashicorp.com/oauth2/token` (standard OAuth2
    /// `client_credentials` grant). The store exchanges
    /// `(client_id, client_secret)` for an HCP `access_token`, caches
    /// it, and submits it as `Authorization: Bearer <access_token>`
    /// against the HCP-hosted Vault cluster's `addr`.
    ///
    /// HCP-hosted Vault clusters reject the `X-Vault-Token` header that
    /// self-hosted clusters use; this auth method drives the cluster
    /// via the HCP-IdP-minted access_token instead. The access_token
    /// has a TTL (typically 24h); v1 follows the AppRole/AWS pattern of
    /// single login at startup + re-login-on-401 retry. Background
    /// renewal is a follow-up.
    HcpServicePrincipal {
        client_id: String,
        client_secret: SecretString,
    },
    /// Generic JWT/OIDC login at `/v1/<mount_path>/login`. The daemon
    /// presents `{ role, jwt }` to Vault; Vault validates the JWT
    /// against the configured OIDC provider and returns a Vault
    /// client_token bound to `role`.
    ///
    /// `mount_path` is `"auth/jwt"` or `"auth/oidc"` depending on
    /// Vault config (Vault's "jwt" vs "oidc" auth methods are the
    /// same primitive with different opinionation; the path is
    /// operator-controlled).
    ///
    /// `jwt` is a pre-acquired OIDC token. v1 caller is responsible
    /// for sourcing it (env-var like GitHub Actions'
    /// `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, K8s SA-token projection,
    /// AWS IRSA token file, etc.) and for refreshing it before
    /// expiry. A future task will add an `OidcTokenProvider` trait
    /// to do refresh in-process.
    JwtOidc {
        mount_path: String,
        role: String,
        jwt: SecretString,
    },
    /// Kubernetes service-account login at
    /// `/v1/auth/kubernetes/login`. The daemon reads the projected SA
    /// JWT from `token_path` and presents `{ role, jwt }` to Vault;
    /// Vault validates the JWT against the cluster's TokenReview API
    /// (configured at the auth mount) and returns a Vault client_token
    /// bound to `role`.
    ///
    /// `token_path` is the on-disk path to the SA token; production
    /// pods leave this at the standard kubelet mount
    /// `/var/run/secrets/kubernetes.io/serviceaccount/token`. The token
    /// is read fresh on every `login()` and `try_relogin()` so the
    /// kubelet's token rotation (every ~1h on modern clusters) is
    /// transparent to the daemon.
    Kubernetes { role: String, token_path: PathBuf },
}

/// Policy that controls behavior when Vault is unreachable / sealed /
/// returning 5xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailablePolicy {
    /// Surface `StoreError::Unavailable` to the caller. No fallback.
    FailHard,
    /// Consult an in-memory cache (most-recent successful read per key)
    /// before surfacing `StoreError::Unavailable`. Entries older than the
    /// configured TTL are treated as misses.
    FallBackToCache,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// `CredentialStore` impl backed by a HashiCorp Vault KV v2 mount.
pub struct HashiVaultStore {
    client: Arc<dyn HttpClient>,
    addr: String,
    mount: String,
    auth: HashiVaultAuth,
    /// Cached client token for AppRole auth. `None` until first
    /// successful login. Token-auth callers ignore this field — the
    /// static token is read straight from `auth` on every request.
    cached_token: RwLock<Option<SecretString>>,
    /// Optional response cache — populated on every successful `get` and
    /// consulted by `FallBackToCache` when the upstream is unavailable.
    #[allow(clippy::type_complexity)]
    cache: Option<Arc<RwLock<HashMap<String, (Vec<u8>, Instant)>>>>,
    cache_ttl: Option<Duration>,
    unavailable_policy: UnavailablePolicy,
}

impl HashiVaultStore {
    /// Construct a new `HashiVaultStore`.
    ///
    /// - `client` — production callers pass `Arc::new(ReqwestHttpClient::new()?)`;
    ///   tests pass [`MockHttpClient`].
    /// - `addr` — base URL of the Vault server (no trailing `/v1`),
    ///   e.g. `"https://vault.example.com:8200"`.
    /// - `mount` — KV v2 mount path, typically `"secret"`.
    /// - `auth` — token or AppRole credentials.
    /// - `unavailable_policy` — what to do when the upstream is 5xx /
    ///   unreachable.
    /// - `cache_ttl` — when `Some`, enables a per-key in-memory cache
    ///   used by `FallBackToCache`. `None` disables the cache (and
    ///   `FallBackToCache` then degrades to "always unavailable" on 5xx).
    pub fn new(
        client: Arc<dyn HttpClient>,
        addr: impl Into<String>,
        mount: impl Into<String>,
        auth: HashiVaultAuth,
        unavailable_policy: UnavailablePolicy,
        cache_ttl: Option<Duration>,
    ) -> Self {
        let cache = cache_ttl.map(|_| Arc::new(RwLock::new(HashMap::new())));
        Self {
            client,
            addr: addr.into(),
            mount: mount.into(),
            auth,
            cached_token: RwLock::new(None),
            cache,
            cache_ttl,
            unavailable_policy,
        }
    }

    /// Authenticate to Vault. For [`HashiVaultAuth::Token`] this is a
    /// no-op (the token is statically configured). For
    /// [`HashiVaultAuth::AppRole`] this calls
    /// `POST /v1/auth/approle/login` with `(role_id, secret_id)` and
    /// caches the returned `auth.client_token`.
    ///
    /// `&mut self` is intentional — callers typically `login` once at
    /// startup before sharing the store via `Arc<dyn CredentialStore>`.
    /// Internal re-login on 401 happens via interior mutability through
    /// `cached_token: RwLock<...>`.
    pub async fn login(&mut self) -> Result<(), StoreError> {
        match &self.auth {
            HashiVaultAuth::Token { .. } => Ok(()),
            HashiVaultAuth::AppRole { role_id, secret_id } => {
                let token = self
                    .approle_login(role_id, secret_id.expose_secret())
                    .await?;
                *self.cached_token.write().await = Some(SecretString::from(token));
                Ok(())
            }
            HashiVaultAuth::Aws { role } => {
                let token = vault_aws_login(self.client.as_ref(), &self.addr, role).await?;
                *self.cached_token.write().await = Some(SecretString::from(token));
                Ok(())
            }
            HashiVaultAuth::HcpServicePrincipal {
                client_id,
                client_secret,
            } => {
                if client_id.is_empty() || client_secret.expose_secret().is_empty() {
                    return Err(StoreError::AuthFailed(
                        "HCP credentials missing".to_string(),
                    ));
                }
                let token = hcp_vault_login(
                    self.client.as_ref(),
                    client_id,
                    client_secret.expose_secret(),
                )
                .await?;
                *self.cached_token.write().await = Some(SecretString::from(token));
                Ok(())
            }
            HashiVaultAuth::JwtOidc {
                mount_path,
                role,
                jwt,
            } => {
                let token = vault_jwt_login(
                    self.client.as_ref(),
                    &self.addr,
                    mount_path,
                    role,
                    jwt.expose_secret(),
                )
                .await?;
                *self.cached_token.write().await = Some(SecretString::from(token));
                Ok(())
            }
            HashiVaultAuth::Kubernetes { role, token_path } => {
                let token =
                    vault_kubernetes_login(self.client.as_ref(), &self.addr, role, token_path)
                        .await?;
                *self.cached_token.write().await = Some(SecretString::from(token));
                Ok(())
            }
        }
    }

    /// Internal AppRole login — POSTs `(role_id, secret_id)` to
    /// `/v1/auth/approle/login` and returns the raw `client_token`
    /// string. Used by both `login()` (initial) and the 401-retry path.
    async fn approle_login(&self, role_id: &str, secret_id: &str) -> Result<String, StoreError> {
        let url = format!("{}/v1/auth/approle/login", self.addr.trim_end_matches('/'));
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        })
        .to_string();
        let resp = self
            .client
            .request(
                "POST",
                &url,
                &[("Content-Type", "application/json")],
                Some(body.as_bytes()),
            )
            .await
            .map_err(|e| StoreError::Unavailable(format!("approle/login transport: {e}")))?;

        match resp.status {
            200..=299 => {
                let parsed: ApproleLoginResponse =
                    serde_json::from_str(&resp.body).map_err(|e| {
                        StoreError::Other(format!(
                            "approle/login response parse failed: {e}; body={}",
                            resp.body
                        ))
                    })?;
                let auth = parsed.auth.ok_or_else(|| {
                    StoreError::Other(format!(
                        "approle/login response missing 'auth' block: body={}",
                        resp.body
                    ))
                })?;
                Ok(auth.client_token)
            }
            400 | 401 | 403 => Err(StoreError::AuthFailed(format!(
                "approle/login rejected (status={}): {}",
                resp.status, resp.body
            ))),
            500..=599 => Err(StoreError::Unavailable(format!(
                "approle/login upstream {}: {}",
                resp.status, resp.body
            ))),
            other => Err(StoreError::Other(format!(
                "approle/login unexpected status {other}: {}",
                resp.body
            ))),
        }
    }

    /// Resolve the `X-Vault-Token` header value for the next request.
    /// For static-token auth this returns the configured token; for
    /// AppRole this returns the cached client token (or errors if
    /// `login()` has not been called yet).
    async fn current_token(&self) -> Result<String, StoreError> {
        match &self.auth {
            HashiVaultAuth::Token { token } => Ok(token.expose_secret().to_string()),
            HashiVaultAuth::AppRole { .. }
            | HashiVaultAuth::Aws { .. }
            | HashiVaultAuth::HcpServicePrincipal { .. }
            | HashiVaultAuth::JwtOidc { .. }
            | HashiVaultAuth::Kubernetes { .. } => {
                let cached = self.cached_token.read().await;
                cached
                    .as_ref()
                    .map(|s| s.expose_secret().to_string())
                    .ok_or_else(|| {
                        StoreError::AuthFailed(
                            "client token not cached; call login() first".to_string(),
                        )
                    })
            }
        }
    }

    /// Re-login (AppRole only) after a 401. Token-auth callers cannot
    /// recover from 401 via re-login; they bubble `AuthFailed` straight
    /// out.
    async fn try_relogin(&self) -> Result<(), StoreError> {
        match &self.auth {
            HashiVaultAuth::Token { .. } => Err(StoreError::AuthFailed(
                "static token rejected; operator must rotate".to_string(),
            )),
            HashiVaultAuth::AppRole { role_id, secret_id } => {
                let new_token = self
                    .approle_login(role_id, secret_id.expose_secret())
                    .await?;
                *self.cached_token.write().await = Some(SecretString::from(new_token));
                Ok(())
            }
            HashiVaultAuth::Aws { role } => {
                let new_token = vault_aws_login(self.client.as_ref(), &self.addr, role).await?;
                *self.cached_token.write().await = Some(SecretString::from(new_token));
                Ok(())
            }
            HashiVaultAuth::HcpServicePrincipal {
                client_id,
                client_secret,
            } => {
                if client_id.is_empty() || client_secret.expose_secret().is_empty() {
                    return Err(StoreError::AuthFailed(
                        "HCP credentials missing".to_string(),
                    ));
                }
                let new_token = hcp_vault_login(
                    self.client.as_ref(),
                    client_id,
                    client_secret.expose_secret(),
                )
                .await?;
                *self.cached_token.write().await = Some(SecretString::from(new_token));
                Ok(())
            }
            HashiVaultAuth::JwtOidc {
                mount_path,
                role,
                jwt,
            } => {
                let new_token = vault_jwt_login(
                    self.client.as_ref(),
                    &self.addr,
                    mount_path,
                    role,
                    jwt.expose_secret(),
                )
                .await?;
                *self.cached_token.write().await = Some(SecretString::from(new_token));
                Ok(())
            }
            HashiVaultAuth::Kubernetes { role, token_path } => {
                // Re-read the SA token from disk on every relogin; the
                // kubelet rotates the projected token (~1h cadence) so
                // the bytes on disk may differ from what we read at
                // first login().
                let new_token =
                    vault_kubernetes_login(self.client.as_ref(), &self.addr, role, token_path)
                        .await?;
                *self.cached_token.write().await = Some(SecretString::from(new_token));
                Ok(())
            }
        }
    }

    /// Resolve the auth header that goes on every Vault data-plane
    /// request. Self-hosted Vault expects `X-Vault-Token`; HCP-hosted
    /// Vault expects an OAuth2 `Authorization: Bearer` carrying the
    /// HCP-IdP-minted access_token.
    fn auth_header_for_token<'a>(
        &self,
        token: &'a str,
    ) -> (&'static str, std::borrow::Cow<'a, str>) {
        match &self.auth {
            HashiVaultAuth::HcpServicePrincipal { .. } => (
                "Authorization",
                std::borrow::Cow::Owned(format!("Bearer {token}")),
            ),
            _ => ("X-Vault-Token", std::borrow::Cow::Borrowed(token)),
        }
    }

    fn data_url(&self, key: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.addr.trim_end_matches('/'),
            self.mount.trim_matches('/'),
            key.trim_start_matches('/'),
        )
    }

    fn metadata_url(&self, key: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.addr.trim_end_matches('/'),
            self.mount.trim_matches('/'),
            key.trim_start_matches('/'),
        )
    }

    /// Look up `key` in the cache. Returns `Some(bytes)` only when an
    /// entry is present AND younger than `cache_ttl`.
    async fn cache_lookup(&self, key: &str) -> Option<Vec<u8>> {
        let (cache, ttl) = match (self.cache.as_ref(), self.cache_ttl) {
            (Some(c), Some(t)) => (c, t),
            _ => return None,
        };
        let guard = cache.read().await;
        let (value, ts) = guard.get(key)?;
        if ts.elapsed() <= ttl {
            Some(value.clone())
        } else {
            None
        }
    }

    /// Store `key → value` in the cache. No-op when cache is disabled.
    async fn cache_insert(&self, key: &str, value: &[u8]) {
        if let Some(cache) = self.cache.as_ref() {
            cache
                .write()
                .await
                .insert(key.to_string(), (value.to_vec(), Instant::now()));
        }
    }

    /// Remove `key` from the cache. No-op when cache is disabled.
    async fn cache_remove(&self, key: &str) {
        if let Some(cache) = self.cache.as_ref() {
            cache.write().await.remove(key);
        }
    }

    /// Single GET attempt. Returns `Ok(Some(bytes))` on 2xx, `Ok(None)`
    /// for the auth-retry path (401 → caller re-logs in and retries).
    /// Maps the rest to `StoreError`.
    async fn try_get_once(&self, key: &str, token: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let url = self.data_url(key);
        let (hname, hval) = self.auth_header_for_token(token);
        let resp = self
            .client
            .request("GET", &url, &[(hname, hval.as_ref())], None)
            .await
            .map_err(|e| StoreError::Unavailable(format!("vault get transport: {e}")))?;

        match resp.status {
            200..=299 => {
                let bytes = parse_kv_v2_value(&resp.body)?;
                Ok(Some(bytes))
            }
            401 => Ok(None),
            403 => Err(StoreError::AuthFailed(format!(
                "vault get 403 for key {key}: {}",
                resp.body
            ))),
            404 => Err(StoreError::NotFound(key.to_string())),
            500..=599 => Err(StoreError::Unavailable(format!(
                "vault get {} for key {key}: {}",
                resp.status, resp.body
            ))),
            other => Err(StoreError::Other(format!(
                "vault get unexpected status {other} for key {key}: {}",
                resp.body
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ApproleLoginResponse {
    #[serde(default)]
    auth: Option<ApproleAuthBlock>,
}

#[derive(Debug, Deserialize)]
struct ApproleAuthBlock {
    client_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    lease_duration: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    renewable: Option<bool>,
}

// ---------------------------------------------------------------------------
// AWS IAM login
// ---------------------------------------------------------------------------

/// Vault `auth/aws/login` response — same envelope shape as the
/// AppRole login, but kept as a separate struct so the two code paths
/// don't share serde defaults.
#[derive(Debug, Deserialize)]
struct AwsLoginResponse {
    #[serde(default)]
    auth: Option<AwsAuthBlock>,
}

#[derive(Debug, Deserialize)]
struct AwsAuthBlock {
    client_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    lease_duration: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    renewable: Option<bool>,
}

/// Read the daemon's surrounding AWS identity from the standard env-var
/// chain. For v1 we only consult the env vars; production deployments
/// have the IAM role attached to the host / pod / container populate
/// these (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` and, for
/// session-bearing roles, `AWS_SESSION_TOKEN`).
///
/// Returns `(access_key_id, secret_access_key, session_token, region)`.
/// Region falls back to `AWS_REGION` → `AWS_DEFAULT_REGION` → the
/// global STS endpoint's signing region (`us-east-1`).
///
/// Absent / blank `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` →
/// `StoreError::AuthFailed("no AWS identity available")`. The brief
/// caller maps this to "the IAM role probably isn't attached" in its
/// error message.
fn read_aws_identity_from_env() -> Result<(String, String, Option<String>, String), StoreError> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
        .ok()
        .filter(|v| !v.is_empty());
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    let session_token = std::env::var("AWS_SESSION_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    let region = std::env::var("AWS_REGION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("AWS_DEFAULT_REGION")
                .ok()
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| "us-east-1".to_string());

    match (access_key_id, secret_access_key) {
        (Some(akid), Some(sak)) => Ok((akid, sak, session_token, region)),
        _ => Err(StoreError::AuthFailed(
            "no AWS identity available — set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY \
             (typically via the IAM role attached to this host / pod / container)"
                .to_string(),
        )),
    }
}

/// Build a SigV4-signed `sts:GetCallerIdentity` request and return
/// `(request_url, headers, body)` ready to be base64-encoded into the
/// Vault AWS-login form fields. The signing path mirrors
/// `ember_broker::aws_sts::build_signed_headers` (small deliberate
/// duplication for v1 — see module docs); a future refactor could
/// extract a shared `core-aws-sigv4` helper crate.
#[allow(clippy::type_complexity)]
fn build_get_caller_identity_signed(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    now: std::time::SystemTime,
) -> Result<(String, Vec<(String, String)>, String), StoreError> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
    use aws_sigv4::sign::v4;

    // Vault expects the `iam:GetCallerIdentity` request to be POSTed at
    // the regional STS endpoint (Vault uses `sts.<region>.amazonaws.com`
    // by default; the global endpoint `https://sts.amazonaws.com/` is
    // signed against `us-east-1`. We pick the regional endpoint to
    // match what the IAM role's trust policy is most likely to allow,
    // and to stay consistent with `ember_broker::aws_sts`).
    let url = format!("https://sts.{region}.amazonaws.com/");
    let body = "Action=GetCallerIdentity&Version=2011-06-15".to_string();

    let aws_creds = Credentials::new(
        access_key_id.to_string(),
        secret_access_key.to_string(),
        session_token.map(|s| s.to_string()),
        None,
        "ember-daemon-vault-aws-login",
    );
    let identity = aws_creds.into();

    let v4_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("sts")
        .time(now)
        .settings(SigningSettings::default())
        .build()
        .map_err(|e| {
            StoreError::Other(format!("vault aws login: sigv4 params build failed: {e}"))
        })?;
    let params: aws_sigv4::http_request::SigningParams = v4_params.into();

    let signable = SignableRequest::new(
        "POST",
        &url,
        std::iter::once(("content-type", "application/x-www-form-urlencoded")),
        SignableBody::Bytes(body.as_bytes()),
    )
    .map_err(|e| StoreError::Other(format!("vault aws login: sigv4 signable failed: {e}")))?;

    let signing_output = sign(signable, &params)
        .map_err(|e| StoreError::Other(format!("vault aws login: sigv4 sign failed: {e}")))?;
    let (instructions, _sig) = signing_output.into_parts();
    let (sig_headers, _sig_params) = instructions.into_parts();

    // Vault's AWS auth re-plays the request server-side, so it needs
    // every header that participated in the SigV4 signed-headers list,
    // plus the Content-Length (Vault validates the canonical request
    // includes a Content-Length header). Add the static
    // Content-Type and a pinned Host so the canonical request matches.
    let mut headers: Vec<(String, String)> = Vec::new();
    headers.push((
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    ));
    headers.push(("Content-Length".to_string(), body.len().to_string()));
    headers.push(("Host".to_string(), format!("sts.{region}.amazonaws.com")));
    if let Some(tok) = session_token {
        // The session token participates in SigV4; the upstream signer
        // emitted X-Amz-Security-Token in `sig_headers` so this is a
        // belt-and-braces in case a smithy version change drops it.
        headers.push(("X-Amz-Security-Token".to_string(), tok.to_string()));
    }
    for h in sig_headers {
        headers.push((h.name().to_string(), h.value().to_string()));
    }
    Ok((url, headers, body))
}

/// Encode `headers` into the JSON shape Vault's `iam_request_headers`
/// field expects: `{"<Header-Name>":["<value>"], ...}`. Vault re-plays
/// these against AWS' STS endpoint, so the encoding has to match what
/// the AWS SDK produces (case-preserved keys, values as JSON arrays).
fn encode_headers_for_vault(headers: &[(String, String)]) -> String {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in headers {
        map.entry(k.clone()).or_default().push(v.clone());
    }
    let value = serde_json::Value::Object(
        map.into_iter()
            .map(|(k, vs)| {
                (
                    k,
                    serde_json::Value::Array(
                        vs.into_iter().map(serde_json::Value::String).collect(),
                    ),
                )
            })
            .collect(),
    );
    value.to_string()
}

/// Authenticate to Vault via the AWS IAM auth method.
///
/// 1. Read the daemon's surrounding AWS IAM identity from the env-var
///    chain (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
///    `AWS_SESSION_TOKEN`). Production deployments populate these from
///    the IAM role attached to the host / pod / container.
/// 2. Build a SigV4-signed `sts:GetCallerIdentity` request as the
///    proof; base64-encode the URL, headers, and body.
/// 3. POST `<addr>/v1/auth/aws/login` with the form body
///    `iam_http_request_method=POST&iam_request_url=<base64>&...&role=<role>`.
/// 4. Vault re-plays the request server-side against AWS' public-key
///    infrastructure to verify the signature, then returns a Vault
///    client_token bound to `role`.
///
/// The literal name `vault_aws_login` is a stable anchor — do not
/// rename it without updating the matching documentation.
pub async fn vault_aws_login(
    client: &dyn HttpClient,
    addr: &str,
    role: &str,
) -> Result<String, StoreError> {
    use base64::Engine;

    let (access_key_id, secret_access_key, session_token, region) = read_aws_identity_from_env()?;

    let now = std::time::SystemTime::now();
    let (sts_url, sts_headers, sts_body) = build_get_caller_identity_signed(
        &access_key_id,
        &secret_access_key,
        session_token.as_deref(),
        &region,
        now,
    )?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let iam_request_url = b64.encode(sts_url.as_bytes());
    let iam_request_headers = b64.encode(encode_headers_for_vault(&sts_headers).as_bytes());
    let iam_request_body = b64.encode(sts_body.as_bytes());

    // Form-encode the body. The field names are fixed by the Vault
    // AWS auth spec; values are URL-encoded (base64 strings include
    // '+' and '=' which require encoding for x-www-form-urlencoded).
    let body = form_urlencode(&[
        ("iam_http_request_method", "POST"),
        ("iam_request_url", iam_request_url.as_str()),
        ("iam_request_headers", iam_request_headers.as_str()),
        ("iam_request_body", iam_request_body.as_str()),
        ("role", role),
    ]);

    let url = format!("{}/v1/auth/aws/login", addr.trim_end_matches('/'));
    let resp = client
        .request(
            "POST",
            &url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(body.as_bytes()),
        )
        .await
        .map_err(|e| StoreError::Unavailable(format!("aws/login transport: {e}")))?;

    match resp.status {
        200..=299 => {
            let parsed: AwsLoginResponse = serde_json::from_str(&resp.body).map_err(|e| {
                StoreError::Other(format!(
                    "aws/login response parse failed: {e}; body={}",
                    resp.body
                ))
            })?;
            let auth = parsed.auth.ok_or_else(|| {
                StoreError::Other(format!(
                    "aws/login response missing 'auth' block: body={}",
                    resp.body
                ))
            })?;
            Ok(auth.client_token)
        }
        400 => Err(StoreError::AuthFailed(format!(
            "aws/login rejected (status=400) — role likely not configured at the \
             configured Vault mount, or the IAM identity does not match the role's \
             bound principal: {}",
            resp.body
        ))),
        401 => Err(StoreError::AuthFailed(format!(
            "aws/login rejected (status=401) — the SigV4-signed STS request was \
             rejected by Vault (invalid signature, expired credentials, or AWS \
             public-key validation failure): {}",
            resp.body
        ))),
        403 => Err(StoreError::AuthFailed(format!(
            "aws/login rejected (status=403) — the IAM role likely lacks the \
             policy Vault expects for this role at /v1/auth/aws/login: {}",
            resp.body
        ))),
        500..=599 => Err(StoreError::Unavailable(format!(
            "aws/login upstream {}: {}",
            resp.status, resp.body
        ))),
        other => Err(StoreError::Other(format!(
            "aws/login unexpected status {other}: {}",
            resp.body
        ))),
    }
}

// ---------------------------------------------------------------------------
// HCP service-principal login
// ---------------------------------------------------------------------------

/// HCP IdP `oauth2/token` response — standard OAuth2 client_credentials
/// envelope. We pluck `access_token` and surface it as the cached
/// "client token" the data-plane requests carry as `Authorization:
/// Bearer`.
#[derive(Debug, Deserialize)]
struct HcpTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
}

/// HCP IdP token endpoint. Service-principal credentials minted in HCP
/// (Project → Service Principals) exchange here for an HCP access_token
/// that the HCP-hosted Vault cluster accepts as `Authorization:
/// Bearer`.
const HCP_IDP_TOKEN_URL: &str = "https://auth.idp.hashicorp.com/oauth2/token";

/// HCP API audience. Required by the HCP IdP for service-principal
/// `client_credentials` grants — without it the IdP returns a 400 with
/// `audience is required`.
const HCP_API_AUDIENCE: &str = "https://api.hashicorp.cloud";

/// Authenticate to HCP via the service-principal `client_credentials`
/// grant.
///
/// 1. POST `https://auth.idp.hashicorp.com/oauth2/token` with form body
///    `grant_type=client_credentials&client_id=...&client_secret=...&audience=https://api.hashicorp.cloud`.
/// 2. Parse the JSON response — `access_token` + `expires_in`.
/// 3. Return the access_token; the caller caches it for use as
///    `Authorization: Bearer <access_token>` against the HCP-hosted
///    Vault cluster.
///
/// Status mapping:
/// - 200..=299 → return `access_token`.
/// - 400 / 401 / 403 → `StoreError::AuthFailed("HCP credentials invalid")`.
/// - 5xx → `StoreError::Unavailable("HCP IdP unreachable")`.
///
/// The literal name `hcp_vault_login` is a stable anchor — do not
/// rename it without updating the matching documentation.
pub async fn hcp_vault_login(
    client: &dyn HttpClient,
    client_id: &str,
    client_secret: &str,
) -> Result<String, StoreError> {
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(StoreError::AuthFailed(
            "HCP credentials missing".to_string(),
        ));
    }
    let body = form_urlencode(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("audience", HCP_API_AUDIENCE),
    ]);
    let resp = client
        .request(
            "POST",
            HCP_IDP_TOKEN_URL,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(body.as_bytes()),
        )
        .await
        .map_err(|e| StoreError::Unavailable(format!("HCP IdP unreachable: {e}")))?;

    match resp.status {
        200..=299 => {
            let parsed: HcpTokenResponse = serde_json::from_str(&resp.body).map_err(|e| {
                StoreError::Other(format!(
                    "hcp/oauth2 response parse failed: {e}; body={}",
                    resp.body
                ))
            })?;
            parsed.access_token.ok_or_else(|| {
                StoreError::Other(format!(
                    "hcp/oauth2 response missing 'access_token': body={}",
                    resp.body
                ))
            })
        }
        400 | 401 | 403 => Err(StoreError::AuthFailed(
            "HCP credentials invalid".to_string(),
        )),
        500..=599 => Err(StoreError::Unavailable("HCP IdP unreachable".to_string())),
        other => Err(StoreError::Other(format!(
            "hcp/oauth2 unexpected status {other}: {}",
            resp.body
        ))),
    }
}

// ---------------------------------------------------------------------------
// JWT/OIDC login
// ---------------------------------------------------------------------------

/// Vault `<mount_path>/login` response — same envelope shape as the
/// AppRole/AWS logins. Kept as a separate struct per the local
/// convention (each auth method owns its serde defaults).
#[derive(Debug, Deserialize)]
struct JwtLoginResponse {
    #[serde(default)]
    auth: Option<JwtAuthBlock>,
}

#[derive(Debug, Deserialize)]
struct JwtAuthBlock {
    client_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    lease_duration: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    renewable: Option<bool>,
}

/// Authenticate to Vault via the JWT/OIDC auth method.
///
/// 1. POST `<addr>/v1/<mount_path>/login` with JSON body
///    `{ "role": "<role>", "jwt": "<jwt>" }`.
/// 2. Vault validates the JWT against the OIDC provider configured at
///    `<mount_path>` (issuer, JWKS endpoint, bound audience/claims).
/// 3. On success, Vault returns a Vault `client_token` bound to `role`.
///
/// `mount_path` is typically `"auth/jwt"` or `"auth/oidc"` but
/// operators may mount the auth method at any path; the caller passes
/// the operator-controlled value through verbatim. Leading and
/// trailing `/` are trimmed defensively.
///
/// Status mapping mirrors `vault_aws_login`:
/// - 200..=299 → return `client_token`.
/// - 400 → `AuthFailed` (role typically not configured / role not
///   bound to the JWT's claims).
/// - 401 → `AuthFailed` (JWT signature invalid, expired, or
///   audience/issuer mismatch).
/// - 403 → `AuthFailed` (role lacks the policy Vault expects).
/// - 5xx → `Unavailable` (Vault upstream).
///
/// The literal name `vault_jwt_login` is a stable anchor — do not
/// rename it without updating the matching documentation.
pub async fn vault_jwt_login(
    client: &dyn HttpClient,
    addr: &str,
    mount_path: &str,
    role: &str,
    jwt: &str,
) -> Result<String, StoreError> {
    if jwt.is_empty() {
        return Err(StoreError::AuthFailed("JWT/OIDC token empty".to_string()));
    }
    let url = format!(
        "{}/v1/{}/login",
        addr.trim_end_matches('/'),
        mount_path.trim_matches('/'),
    );
    let body = serde_json::json!({
        "role": role,
        "jwt": jwt,
    })
    .to_string();
    let resp = client
        .request(
            "POST",
            &url,
            &[("Content-Type", "application/json")],
            Some(body.as_bytes()),
        )
        .await
        .map_err(|e| StoreError::Unavailable(format!("jwt/login transport: {e}")))?;

    match resp.status {
        200..=299 => {
            let parsed: JwtLoginResponse = serde_json::from_str(&resp.body).map_err(|e| {
                StoreError::Other(format!(
                    "jwt/login response parse failed: {e}; body={}",
                    resp.body
                ))
            })?;
            let auth = parsed.auth.ok_or_else(|| {
                StoreError::Other(format!(
                    "jwt/login response missing 'auth' block: body={}",
                    resp.body
                ))
            })?;
            Ok(auth.client_token)
        }
        400 => Err(StoreError::AuthFailed(format!(
            "jwt/login rejected (status=400) — role likely not configured at the \
             configured Vault mount, or the JWT's bound claims do not match the \
             role's bound subjects/audiences: {}",
            resp.body
        ))),
        401 => Err(StoreError::AuthFailed(format!(
            "jwt/login rejected (status=401) — JWT signature invalid, expired, or \
             audience/issuer mismatch against the OIDC provider configured at the \
             mount: {}",
            resp.body
        ))),
        403 => Err(StoreError::AuthFailed(format!(
            "jwt/login rejected (status=403) — the role likely lacks the policy \
             Vault expects for this role at /v1/{}/login: {}",
            mount_path.trim_matches('/'),
            resp.body
        ))),
        500..=599 => Err(StoreError::Unavailable(format!(
            "jwt/login upstream {}: {}",
            resp.status, resp.body
        ))),
        other => Err(StoreError::Other(format!(
            "jwt/login unexpected status {other}: {}",
            resp.body
        ))),
    }
}

// ---------------------------------------------------------------------------
// Kubernetes service-account login
// ---------------------------------------------------------------------------

/// Standard kubelet projected service-account token mount path. Pods
/// running inside Kubernetes find their SA JWT here unless the
/// operator overrode the projection.
pub const KUBERNETES_SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Authenticate to Vault via the Kubernetes auth method.
///
/// 1. Read the projected SA JWT from `token_path` (typically
///    [`KUBERNETES_SA_TOKEN_PATH`]). Empty file or missing-file maps
///    to `AuthFailed` (the daemon is misconfigured or the SA-token
///    projection is missing on the pod spec).
/// 2. POST `<addr>/v1/auth/kubernetes/login` with JSON body
///    `{ "role": "<role>", "jwt": "<sa_jwt>" }`. This is the same
///    wire shape as Vault's JWT/OIDC auth method — the Kubernetes
///    auth method differs only in *how* Vault validates the JWT
///    (against the cluster's TokenReview API rather than against an
///    OIDC provider's JWKS endpoint).
/// 3. Vault returns a Vault `client_token` bound to `role` on success.
///
/// Implementation delegates to [`vault_jwt_login`] with `mount_path
/// = "auth/kubernetes"` after reading the file — keeps the Vault wire
/// + status-mapping logic single-sourced.
///
/// The literal name `vault_kubernetes_login` is a stable anchor — do not
/// rename it without updating the matching documentation.
pub async fn vault_kubernetes_login(
    client: &dyn HttpClient,
    addr: &str,
    role: &str,
    token_path: &Path,
) -> Result<String, StoreError> {
    let raw = std::fs::read_to_string(token_path).map_err(|e| {
        StoreError::AuthFailed(format!(
            "kubernetes SA token not readable at {}: {e} \
             (is the pod's service-account token projected? check spec.serviceAccountName \
             and spec.containers[].volumeMounts for the projected SA volume)",
            token_path.display()
        ))
    })?;
    let jwt = raw.trim();
    if jwt.is_empty() {
        return Err(StoreError::AuthFailed(format!(
            "kubernetes SA token empty at {} (file present but blank — check the \
             projected SA volume's expirationSeconds and audience configuration)",
            token_path.display()
        )));
    }
    vault_jwt_login(client, addr, "auth/kubernetes", role, jwt).await
}

/// Minimal `application/x-www-form-urlencoded` builder for Vault's
/// AWS-login body. Encodes everything outside the unreserved set
/// `A-Za-z0-9-._~`. Avoids pulling another url-form crate just for
/// this single function (mirrors `ember_broker::aws_sts::urlencode`).
fn form_urlencode(params: &[(&str, &str)]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            s.push('&');
        }
        let _ = write!(&mut s, "{}={}", form_pct(k), form_pct(v));
    }
    s
}

fn form_pct(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
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

/// Parse the KV v2 GET response shape and pluck the inner blob.
///
/// KV v2 returns:
/// ```json
/// { "data": { "data": { "<inner_key>": "<value>" }, "metadata": {...} } }
/// ```
///
/// We store under a fixed inner field name (`KV_VALUE_FIELD = "value"`)
/// so the round-trip shape is stable. If the inner block has exactly
/// one field with a different name we accept that (interop with secrets
/// written outside ember).
const KV_VALUE_FIELD: &str = "value";

fn parse_kv_v2_value(body: &str) -> Result<Vec<u8>, StoreError> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| StoreError::Other(format!("kv v2 response parse: {e}; body={body}")))?;
    let inner = v.get("data").and_then(|d| d.get("data")).ok_or_else(|| {
        StoreError::Other(format!(
            "kv v2 response missing .data.data block: body={body}"
        ))
    })?;
    // Prefer the canonical `"value"` field; fall back to the sole field
    // if the secret was written outside ember.
    let raw = if let Some(v) = inner.get(KV_VALUE_FIELD) {
        v
    } else if let Some(map) = inner.as_object() {
        if map.len() == 1 {
            map.values().next().unwrap()
        } else {
            return Err(StoreError::Other(format!(
                "kv v2 response inner block has {} fields, none named '{KV_VALUE_FIELD}': body={body}",
                map.len()
            )));
        }
    } else {
        return Err(StoreError::Other(format!(
            "kv v2 response .data.data is not an object: body={body}"
        )));
    };
    match raw {
        serde_json::Value::String(s) => Ok(s.as_bytes().to_vec()),
        other => Ok(other.to_string().into_bytes()),
    }
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    data: Option<ListData>,
}

#[derive(Debug, Deserialize)]
struct ListData {
    #[serde(default)]
    keys: Vec<String>,
}

// ---------------------------------------------------------------------------
// CredentialStore impl
// ---------------------------------------------------------------------------

#[async_trait]
impl CredentialStore for HashiVaultStore {
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let token = match self.current_token().await {
            Ok(t) => t,
            Err(e) => return Err(e),
        };

        let first = self.try_get_once(key, &token).await;

        let result = match first {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => {
                // 401 — try re-login once (AppRole only) and retry.
                self.try_relogin().await?;
                let new_token = self.current_token().await?;
                match self.try_get_once(key, &new_token).await? {
                    Some(bytes) => Ok(bytes),
                    None => Err(StoreError::AuthFailed(format!(
                        "vault get for key {key} returned 401 after re-login"
                    ))),
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(bytes) => {
                self.cache_insert(key, &bytes).await;
                Ok(bytes)
            }
            Err(StoreError::Unavailable(msg)) => match self.unavailable_policy {
                UnavailablePolicy::FailHard => Err(StoreError::Unavailable(msg)),
                UnavailablePolicy::FallBackToCache => {
                    if let Some(bytes) = self.cache_lookup(key).await {
                        tracing::warn!(
                            key = %key,
                            "HashiVaultStore: upstream unavailable; serving from cache"
                        );
                        Ok(bytes)
                    } else {
                        Err(StoreError::Unavailable(msg))
                    }
                }
            },
            Err(other) => Err(other),
        }
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let token = self.current_token().await?;
        let url = self.data_url(key);
        let value_str = std::str::from_utf8(value).map_err(|_| {
            StoreError::Other(
                "HashiVaultStore.put: value must be UTF-8 (binary blobs unsupported in v1)"
                    .to_string(),
            )
        })?;
        let body = serde_json::json!({
            "data": { KV_VALUE_FIELD: value_str },
        })
        .to_string();
        let (hname, hval) = self.auth_header_for_token(&token);
        let resp = self
            .client
            .request(
                "POST",
                &url,
                &[(hname, hval.as_ref()), ("Content-Type", "application/json")],
                Some(body.as_bytes()),
            )
            .await
            .map_err(|e| StoreError::Unavailable(format!("vault put transport: {e}")))?;

        match resp.status {
            200..=299 => {
                self.cache_insert(key, value).await;
                Ok(())
            }
            401 => {
                self.try_relogin().await?;
                let new_token = self.current_token().await?;
                let (hname2, hval2) = self.auth_header_for_token(&new_token);
                let resp2 = self
                    .client
                    .request(
                        "POST",
                        &url,
                        &[
                            (hname2, hval2.as_ref()),
                            ("Content-Type", "application/json"),
                        ],
                        Some(body.as_bytes()),
                    )
                    .await
                    .map_err(|e| {
                        StoreError::Unavailable(format!("vault put retry transport: {e}"))
                    })?;
                match resp2.status {
                    200..=299 => {
                        self.cache_insert(key, value).await;
                        Ok(())
                    }
                    401 | 403 => Err(StoreError::AuthFailed(format!(
                        "vault put for key {key} returned {} after re-login",
                        resp2.status
                    ))),
                    404 => Err(StoreError::NotFound(key.to_string())),
                    500..=599 => map_unavailable(
                        StoreError::Unavailable(format!(
                            "vault put retry {} for key {key}: {}",
                            resp2.status, resp2.body
                        )),
                        self,
                    ),
                    other => Err(StoreError::Other(format!(
                        "vault put retry unexpected status {other} for key {key}: {}",
                        resp2.body
                    ))),
                }
            }
            403 => Err(StoreError::AuthFailed(format!(
                "vault put 403 for key {key}: {}",
                resp.body
            ))),
            404 => Err(StoreError::NotFound(key.to_string())),
            500..=599 => map_unavailable(
                StoreError::Unavailable(format!(
                    "vault put {} for key {key}: {}",
                    resp.status, resp.body
                )),
                self,
            ),
            other => Err(StoreError::Other(format!(
                "vault put unexpected status {other} for key {key}: {}",
                resp.body
            ))),
        }
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        let token = self.current_token().await?;
        let prefix_path = prefix.unwrap_or("");
        let url = self.metadata_url(prefix_path);
        let (hname, hval) = self.auth_header_for_token(&token);
        let resp = self
            .client
            .request("LIST", &url, &[(hname, hval.as_ref())], None)
            .await
            .map_err(|e| StoreError::Unavailable(format!("vault list transport: {e}")))?;

        match resp.status {
            200..=299 => {
                let parsed: ListResponse = serde_json::from_str(&resp.body).map_err(|e| {
                    StoreError::Other(format!(
                        "vault list response parse: {e}; body={}",
                        resp.body
                    ))
                })?;
                Ok(parsed.data.map(|d| d.keys).unwrap_or_default())
            }
            401 | 403 => Err(StoreError::AuthFailed(format!(
                "vault list {} for prefix {prefix_path}: {}",
                resp.status, resp.body
            ))),
            404 => Ok(Vec::new()),
            500..=599 => map_unavailable(
                StoreError::Unavailable(format!(
                    "vault list {} for prefix {prefix_path}: {}",
                    resp.status, resp.body
                )),
                self,
            ),
            other => Err(StoreError::Other(format!(
                "vault list unexpected status {other} for prefix {prefix_path}: {}",
                resp.body
            ))),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let token = self.current_token().await?;
        let url = self.metadata_url(key);
        let (hname, hval) = self.auth_header_for_token(&token);
        let resp = self
            .client
            .request("DELETE", &url, &[(hname, hval.as_ref())], None)
            .await
            .map_err(|e| StoreError::Unavailable(format!("vault delete transport: {e}")))?;

        match resp.status {
            200..=299 => {
                self.cache_remove(key).await;
                Ok(())
            }
            401 | 403 => Err(StoreError::AuthFailed(format!(
                "vault delete {} for key {key}: {}",
                resp.status, resp.body
            ))),
            404 => Err(StoreError::NotFound(key.to_string())),
            500..=599 => map_unavailable(
                StoreError::Unavailable(format!(
                    "vault delete {} for key {key}: {}",
                    resp.status, resp.body
                )),
                self,
            ),
            other => Err(StoreError::Other(format!(
                "vault delete unexpected status {other} for key {key}: {}",
                resp.body
            ))),
        }
    }
}

/// `Unavailable` paths on `put` / `list` / `delete` honor the
/// `unavailable_policy` field. Read-side fallback only meaningfully
/// applies to `get` (we have a value to return); for the other verbs
/// `FallBackToCache` degrades to "log + return Unavailable".
fn map_unavailable<T>(err: StoreError, store: &HashiVaultStore) -> Result<T, StoreError> {
    match store.unavailable_policy {
        UnavailablePolicy::FailHard => Err(err),
        UnavailablePolicy::FallBackToCache => {
            tracing::warn!(
                error = %err,
                "HashiVaultStore: upstream unavailable on write; surfacing Unavailable (no write-side cache)"
            );
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP client — for unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub use test_mock::*;

#[cfg(test)]
mod test_mock {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct MockHttpCall {
        pub method: String,
        pub url: String,
        pub headers: Vec<(String, String)>,
        pub body: Option<Vec<u8>>,
    }

    /// Scripted-response mock client. Each call pops the next
    /// `(status, body)` from `responses`. If only one entry remains it
    /// is reused; if the queue is empty the mock returns a transport
    /// error so missing-fixture bugs surface loudly.
    pub struct MockHttpClient {
        pub responses: Mutex<Vec<(u16, String)>>,
        pub calls: Mutex<Vec<MockHttpCall>>,
        pub force_transport_error: Mutex<Option<String>>,
    }

    impl MockHttpClient {
        pub fn new() -> Self {
            Self {
                responses: Mutex::new(Vec::new()),
                calls: Mutex::new(Vec::new()),
                force_transport_error: Mutex::new(None),
            }
        }

        pub fn with_response(self, status: u16, body: impl Into<String>) -> Self {
            self.responses
                .lock()
                .expect("mock mutex")
                .push((status, body.into()));
            self
        }

        pub fn push_response(&self, status: u16, body: impl Into<String>) {
            self.responses
                .lock()
                .expect("mock mutex")
                .push((status, body.into()));
        }

        pub fn last_call(&self) -> Option<MockHttpCall> {
            self.calls.lock().expect("mock mutex").last().cloned()
        }

        pub fn call_count(&self) -> usize {
            self.calls.lock().expect("mock mutex").len()
        }
    }

    impl Default for MockHttpClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, &str)],
            body: Option<&[u8]>,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.lock().expect("mock mutex").push(MockHttpCall {
                method: method.to_string(),
                url: url.to_string(),
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                body: body.map(|b| b.to_vec()),
            });
            if let Some(err) = self
                .force_transport_error
                .lock()
                .expect("mock mutex")
                .as_ref()
            {
                return Err(HttpError(err.clone()));
            }
            let mut q = self.responses.lock().expect("mock mutex");
            if q.is_empty() {
                return Err(HttpError(format!(
                    "MockHttpClient: no response queued for {method} {url}"
                )));
            }
            let (status, body) = if q.len() > 1 {
                q.remove(0)
            } else {
                q.last().cloned().unwrap()
            };
            Ok(HttpResponse { status, body })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (T1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn kv_v2_ok_body(value: &str) -> String {
        serde_json::json!({
            "request_id": "req-1",
            "lease_id": "",
            "renewable": false,
            "lease_duration": 0,
            "data": {
                "data": { "value": value },
                "metadata": {
                    "created_time": "2026-05-09T00:00:00Z",
                    "version": 1
                }
            },
            "wrap_info": null,
            "warnings": null,
            "auth": null
        })
        .to_string()
    }

    fn approle_login_ok_body(client_token: &str) -> String {
        serde_json::json!({
            "auth": {
                "client_token": client_token,
                "accessor": "acc-xyz",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": null,
                "lease_duration": 3600,
                "renewable": true,
                "entity_id": "",
                "token_type": "service",
                "orphan": true
            }
        })
        .to_string()
    }

    fn token_auth() -> HashiVaultAuth {
        HashiVaultAuth::Token {
            token: SecretString::from("hvs.static-token".to_string()),
        }
    }

    fn approle_auth() -> HashiVaultAuth {
        HashiVaultAuth::AppRole {
            role_id: "role-id-uuid".to_string(),
            secret_id: SecretString::from("secret-id-uuid".to_string()),
        }
    }

    #[test]
    fn token_auth_get_happy_path() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(200, kv_v2_ok_body("hunter2")));
            let store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let got = store.get("svc/api-token").await.expect("get must succeed");
            assert_eq!(got, b"hunter2");
            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "GET");
            assert_eq!(
                call.url,
                "https://vault.example.com:8200/v1/secret/data/svc/api-token"
            );
            assert!(
                call.headers
                    .iter()
                    .any(|(k, v)| k == "X-Vault-Token" && v == "hvs.static-token")
            );
        });
    }

    #[test]
    fn token_auth_get_404_returns_not_found() {
        rt().block_on(async {
            let mock =
                Arc::new(MockHttpClient::new().with_response(404, r#"{"errors":[]}"#.to_string()));
            let store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.get("missing").await.expect_err("must error");
            match err {
                StoreError::NotFound(k) => assert_eq!(k, "missing"),
                other => panic!("expected NotFound, got {other:?}"),
            }
        });
    }

    #[test]
    fn token_auth_get_401_returns_auth_failed() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new()
                    .with_response(401, r#"{"errors":["invalid token"]}"#.to_string()),
            );
            let store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.get("svc/api-token").await.expect_err("must error");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn approle_login_happy_path() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, approle_login_ok_body("hvs.child-token")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                approle_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("login must succeed");
            let token = store.current_token().await.expect("token cached");
            assert_eq!(token, "hvs.child-token");
            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "POST");
            assert!(call.url.ends_with("/v1/auth/approle/login"));
            let body = String::from_utf8(call.body.expect("body sent")).expect("utf8");
            assert!(body.contains("\"role_id\":\"role-id-uuid\""));
            assert!(body.contains("\"secret_id\":\"secret-id-uuid\""));
        });
    }

    #[test]
    fn approle_login_invalid_secret_id() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new()
                    .with_response(400, r#"{"errors":["invalid secret id"]}"#.to_string()),
            );
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                approle_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn unavailable_fail_hard_returns_error() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(503, r#"{"errors":["sealed"]}"#.to_string()),
            );
            let store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.get("svc/api-token").await.expect_err("must error");
            assert!(
                matches!(err, StoreError::Unavailable(_)),
                "expected Unavailable, got {err:?}"
            );
        });
    }

    #[test]
    fn unavailable_fall_back_to_cache_returns_cached() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new());
            // First response: success → seeds the cache.
            mock.push_response(200, kv_v2_ok_body("cached-value"));
            let store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FallBackToCache,
                Some(Duration::from_secs(60)),
            );
            // Prime the cache.
            let first = store.get("svc/api-token").await.expect("first get");
            assert_eq!(first, b"cached-value");

            // Now upstream goes 503 — fallback should serve from cache.
            mock.push_response(503, r#"{"errors":["sealed"]}"#.to_string());
            let second = store
                .get("svc/api-token")
                .await
                .expect("second get falls back to cache");
            assert_eq!(second, b"cached-value");
        });
    }

    #[test]
    fn unavailable_fall_back_to_cache_no_cache_returns_unavailable() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(503, r#"{"errors":["sealed"]}"#.to_string()),
            );
            let store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FallBackToCache,
                Some(Duration::from_secs(60)),
            );
            let err = store
                .get("svc/api-token")
                .await
                .expect_err("must error — cache miss");
            assert!(
                matches!(err, StoreError::Unavailable(_)),
                "expected Unavailable, got {err:?}"
            );
        });
    }

    #[test]
    fn kv_v2_response_parsing() {
        let body = kv_v2_ok_body("my-secret-blob");
        let bytes = parse_kv_v2_value(&body).expect("parse must succeed");
        assert_eq!(bytes, b"my-secret-blob");

        // Sole-field fallback.
        let other_field = serde_json::json!({
            "data": {
                "data": { "non_canonical": "fallback-value" }
            }
        })
        .to_string();
        let bytes = parse_kv_v2_value(&other_field).expect("fallback parse");
        assert_eq!(bytes, b"fallback-value");

        // Missing block → Other.
        let bad = r#"{"foo":1}"#;
        let err = parse_kv_v2_value(bad).expect_err("must error");
        assert!(matches!(err, StoreError::Other(_)));
    }

    #[test]
    fn put_then_get_round_trip() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new());
            mock.push_response(200, r#"{"data":{"version":1}}"#.to_string());
            mock.push_response(200, kv_v2_ok_body("round-trip"));
            let store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                token_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            store
                .put("svc/round-trip", b"round-trip")
                .await
                .expect("put must succeed");
            let put_call = mock.last_call().expect("put recorded");
            assert_eq!(put_call.method, "POST");
            assert_eq!(
                put_call.url,
                "https://vault.example.com:8200/v1/secret/data/svc/round-trip"
            );
            let put_body = String::from_utf8(put_call.body.expect("put body")).expect("utf8");
            assert!(put_body.contains("\"value\":\"round-trip\""));

            let got = store.get("svc/round-trip").await.expect("get must succeed");
            assert_eq!(got, b"round-trip");
        });
    }

    // -----------------------------------------------------------------
    // `vault_aws_login` unit tests
    // -----------------------------------------------------------------

    /// Serialize tests that mutate `AWS_*` env vars. `std::env::set_var`
    /// is a process-global mutation; if two tests touch the same vars
    /// in parallel the values flicker, races between threads land
    /// arbitrary state in the read, and the test suite turns flaky.
    /// Each AWS-login test acquires this mutex for the duration of its
    /// env mutation + read window.
    fn aws_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Snapshot the current `AWS_*` env vars and apply `set` (replacing
    /// each var to either Some(value) — which sets it — or None, which
    /// removes it). Returns a guard that restores the original values
    /// on drop. Use inside a `let _g = aws_env_lock();` scope.
    struct AwsEnvScope {
        prev: Vec<(&'static str, Option<String>)>,
    }

    impl AwsEnvScope {
        fn apply(set: &[(&'static str, Option<&str>)]) -> Self {
            let names = [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
            ];
            let mut prev: Vec<(&'static str, Option<String>)> = Vec::new();
            for n in names {
                prev.push((n, std::env::var(n).ok()));
            }
            // SAFETY: We hold `aws_env_lock()` across the entire
            // mutation+observe window, and the AWS env vars are not
            // touched anywhere else in this crate's tests. The
            // global mutability rule of `set_var` is enforced by the
            // mutex; the `unsafe` is the post-1.84 API requirement
            // (set_var is unsafe in modern Rust because it
            // synchronises with a single-threaded read-side promise
            // outside the test framework's purview).
            for (k, v) in set {
                match v {
                    Some(val) => unsafe { std::env::set_var(k, val) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
            // Anything we didn't explicitly set: clear so a previous
            // test's leak doesn't bleed in.
            let touched: std::collections::HashSet<&str> = set.iter().map(|(k, _)| *k).collect();
            for n in names {
                if !touched.contains(n) {
                    unsafe { std::env::remove_var(n) };
                }
            }
            Self { prev }
        }
    }

    impl Drop for AwsEnvScope {
        fn drop(&mut self) {
            for (k, v) in self.prev.drain(..) {
                match v {
                    Some(val) => unsafe { std::env::set_var(k, val) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
        }
    }

    fn aws_login_ok_body(client_token: &str) -> String {
        // Matches Vault's `auth/aws/login` response envelope — same
        // shape as AppRole login.
        serde_json::json!({
            "auth": {
                "client_token": client_token,
                "accessor": "aws-acc-xyz",
                "policies": ["default", "ember-daemon"],
                "token_policies": ["default", "ember-daemon"],
                "metadata": {
                    "account_id": "111122223333",
                    "auth_type": "iam",
                    "role": "ember-daemon"
                },
                "lease_duration": 3600,
                "renewable": true,
                "entity_id": "ent-aws",
                "token_type": "service",
                "orphan": true
            }
        })
        .to_string()
    }

    fn aws_auth() -> HashiVaultAuth {
        HashiVaultAuth::Aws {
            role: "ember-daemon".to_string(),
        }
    }

    #[test]
    fn aws_login_happy_path() {
        let _g = aws_env_lock();
        let _scope = AwsEnvScope::apply(&[
            ("AWS_ACCESS_KEY_ID", Some("AKIAFIXTUREKEY1234567")),
            ("AWS_SECRET_ACCESS_KEY", Some("fake_secret_value_for_tests")),
            ("AWS_SESSION_TOKEN", None),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
        ]);
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, aws_login_ok_body("hvs.aws-token")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                aws_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("aws login must succeed");
            let token = store.current_token().await.expect("token cached");
            assert_eq!(token, "hvs.aws-token");

            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "POST");
            assert!(
                call.url.ends_with("/v1/auth/aws/login"),
                "expected /v1/auth/aws/login, got {}",
                call.url
            );
            // The form body must contain Vault's required field set.
            let body = String::from_utf8(call.body.expect("body sent")).expect("utf8");
            assert!(
                body.contains("iam_http_request_method=POST"),
                "missing iam_http_request_method=POST in {body}"
            );
            assert!(
                body.contains("iam_request_url="),
                "missing iam_request_url field in {body}"
            );
            assert!(
                body.contains("iam_request_headers="),
                "missing iam_request_headers field in {body}"
            );
            assert!(
                body.contains("iam_request_body="),
                "missing iam_request_body field in {body}"
            );
            assert!(
                body.contains("role=ember-daemon"),
                "missing role=ember-daemon in {body}"
            );
        });
    }

    #[test]
    fn aws_login_iam_permission_mismatch() {
        let _g = aws_env_lock();
        let _scope = AwsEnvScope::apply(&[
            ("AWS_ACCESS_KEY_ID", Some("AKIAFIXTUREKEY1234567")),
            ("AWS_SECRET_ACCESS_KEY", Some("fake_secret_value_for_tests")),
            ("AWS_SESSION_TOKEN", None),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
        ]);
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(
                403,
                r#"{"errors":["permission denied for role ember-daemon"]}"#.to_string(),
            ));
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                aws_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn aws_login_role_not_configured() {
        let _g = aws_env_lock();
        let _scope = AwsEnvScope::apply(&[
            ("AWS_ACCESS_KEY_ID", Some("AKIAFIXTUREKEY1234567")),
            ("AWS_SECRET_ACCESS_KEY", Some("fake_secret_value_for_tests")),
            ("AWS_SESSION_TOKEN", None),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
        ]);
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(
                400,
                r#"{"errors":["entry for role \"ember-daemon\" not found"]}"#.to_string(),
            ));
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                aws_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn aws_login_no_aws_identity() {
        let _g = aws_env_lock();
        let _scope = AwsEnvScope::apply(&[
            ("AWS_ACCESS_KEY_ID", None),
            ("AWS_SECRET_ACCESS_KEY", None),
            ("AWS_SESSION_TOKEN", None),
            ("AWS_REGION", None),
            ("AWS_DEFAULT_REGION", None),
        ]);
        rt().block_on(async {
            // The mock would be reached only if we got past the env
            // check; supply a 200 so a regression where we DO call out
            // surfaces as a wrong-result rather than a transport-error.
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, aws_login_ok_body("must-not-be-returned")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                aws_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::AuthFailed(msg) => {
                    assert!(
                        msg.contains("no AWS identity available"),
                        "expected 'no AWS identity available' in error, got: {msg}"
                    );
                }
                other => panic!("expected AuthFailed, got {other:?}"),
            }
            // And we must NOT have made any HTTP call when env is absent.
            assert_eq!(
                mock.call_count(),
                0,
                "vault_aws_login should short-circuit before HTTP when AWS env is absent"
            );
        });
    }

    #[test]
    fn aws_login_invalid_oidc_or_signature() {
        let _g = aws_env_lock();
        let _scope = AwsEnvScope::apply(&[
            ("AWS_ACCESS_KEY_ID", Some("AKIAFIXTUREKEY1234567")),
            ("AWS_SECRET_ACCESS_KEY", Some("fake_secret_value_for_tests")),
            ("AWS_SESSION_TOKEN", None),
            ("AWS_REGION", Some("us-east-1")),
            ("AWS_DEFAULT_REGION", None),
        ]);
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(
                401,
                r#"{"errors":["invalid signature; AWS rejected the SigV4 proof"]}"#.to_string(),
            ));
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                aws_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    // -----------------------------------------------------------------
    // `hcp_vault_login` unit tests
    // -----------------------------------------------------------------

    fn hcp_token_ok_body(access_token: &str) -> String {
        // Mirrors HCP IdP's OAuth2 client_credentials response shape.
        serde_json::json!({
            "access_token": access_token,
            "expires_in": 86400,
            "token_type": "Bearer"
        })
        .to_string()
    }

    fn hcp_auth() -> HashiVaultAuth {
        HashiVaultAuth::HcpServicePrincipal {
            client_id: "hcp-sp-client-id".to_string(),
            client_secret: SecretString::from("hcp-sp-client-secret".to_string()),
        }
    }

    #[test]
    fn hcp_login_happy_path() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, hcp_token_ok_body("hcp.access-token-xyz")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                hcp_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("hcp login must succeed");
            let token = store.current_token().await.expect("token cached");
            assert_eq!(token, "hcp.access-token-xyz");

            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "POST");
            assert_eq!(call.url, "https://auth.idp.hashicorp.com/oauth2/token");
            let body = String::from_utf8(call.body.expect("body sent")).expect("utf8");
            assert!(
                body.contains("grant_type=client_credentials"),
                "missing grant_type=client_credentials in {body}"
            );
            assert!(
                body.contains("client_id=hcp-sp-client-id"),
                "missing client_id=... in {body}"
            );
            assert!(
                body.contains("client_secret=hcp-sp-client-secret"),
                "missing client_secret=... in {body}"
            );
            // audience is URL-encoded by form_urlencode (`:` and `/`
            // are outside the unreserved set).
            assert!(
                body.contains("audience=https%3A%2F%2Fapi.hashicorp.cloud"),
                "missing audience=... in {body}"
            );
        });
    }

    #[test]
    fn hcp_login_invalid_credentials() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(
                    401,
                    r#"{"error":"invalid_client","error_description":"client_id or client_secret is invalid"}"#
                        .to_string(),
                ),
            );
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                hcp_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::AuthFailed(msg) => {
                    assert!(
                        msg.contains("HCP credentials invalid"),
                        "expected 'HCP credentials invalid' in error, got: {msg}"
                    );
                }
                other => panic!("expected AuthFailed, got {other:?}"),
            }
        });
    }

    #[test]
    fn hcp_login_idp_unavailable() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new()
                    .with_response(503, r#"{"error":"service_unavailable"}"#.to_string()),
            );
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                hcp_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::Unavailable(msg) => {
                    assert!(
                        msg.contains("HCP IdP unreachable"),
                        "expected 'HCP IdP unreachable' in error, got: {msg}"
                    );
                }
                other => panic!("expected Unavailable, got {other:?}"),
            }
        });
    }

    #[test]
    fn hcp_login_token_refresh() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new());
            // First call: HCP IdP token exchange — login() at startup.
            mock.push_response(200, hcp_token_ok_body("hcp.first-token"));
            // Second call: data-plane GET against Vault returns 401
            // (token expired / rejected) — triggers re-login.
            mock.push_response(401, r#"{"errors":["token expired"]}"#.to_string());
            // Third call: HCP IdP token exchange (re-login).
            mock.push_response(200, hcp_token_ok_body("hcp.refreshed-token"));
            // Fourth call: data-plane GET retry with refreshed token.
            mock.push_response(200, kv_v2_ok_body("after-refresh-value"));

            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                hcp_auth(),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("initial login must succeed");
            let initial_token = store.current_token().await.expect("token cached");
            assert_eq!(initial_token, "hcp.first-token");

            // Trigger the 401 → re-login → retry path on a normal get().
            let got = store
                .get("svc/api-token")
                .await
                .expect("get must succeed after re-login");
            assert_eq!(got, b"after-refresh-value");

            let refreshed = store.current_token().await.expect("token refreshed");
            assert_eq!(refreshed, "hcp.refreshed-token");
        });
    }

    #[test]
    fn hcp_login_missing_credentials() {
        rt().block_on(async {
            // Empty client_id should short-circuit before any HTTP call.
            let mock_empty_id = Arc::new(
                MockHttpClient::new().with_response(200, hcp_token_ok_body("must-not-reach")),
            );
            let mut store = HashiVaultStore::new(
                mock_empty_id.clone(),
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                HashiVaultAuth::HcpServicePrincipal {
                    client_id: "".to_string(),
                    client_secret: SecretString::from("nonempty".to_string()),
                },
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::AuthFailed(msg) => {
                    assert!(
                        msg.contains("HCP credentials missing"),
                        "expected 'HCP credentials missing' in error, got: {msg}"
                    );
                }
                other => panic!("expected AuthFailed, got {other:?}"),
            }
            assert_eq!(
                mock_empty_id.call_count(),
                0,
                "hcp_vault_login must short-circuit before HTTP when credentials are missing"
            );

            // Empty client_secret — same short-circuit.
            let mock_empty_secret = Arc::new(
                MockHttpClient::new().with_response(200, hcp_token_ok_body("must-not-reach")),
            );
            let mut store2 = HashiVaultStore::new(
                mock_empty_secret.clone(),
                "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200",
                "secret",
                HashiVaultAuth::HcpServicePrincipal {
                    client_id: "nonempty".to_string(),
                    client_secret: SecretString::from("".to_string()),
                },
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store2.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
            assert_eq!(
                mock_empty_secret.call_count(),
                0,
                "hcp_vault_login must short-circuit before HTTP when credentials are missing"
            );
        });
    }

    // -----------------------------------------------------------------
    // `vault_jwt_login` unit tests
    // -----------------------------------------------------------------

    fn jwt_login_ok_body(client_token: &str) -> String {
        // Vault JWT/OIDC `auth/jwt/login` response — same envelope shape
        // as AppRole / AWS login.
        serde_json::json!({
            "auth": {
                "client_token": client_token,
                "accessor": "jwt-acc-xyz",
                "policies": ["default", "ember-daemon"],
                "token_policies": ["default", "ember-daemon"],
                "metadata": {
                    "role": "ember-daemon"
                },
                "lease_duration": 3600,
                "renewable": true,
                "entity_id": "ent-jwt",
                "token_type": "service",
                "orphan": true
            }
        })
        .to_string()
    }

    fn jwt_auth(jwt: &str) -> HashiVaultAuth {
        HashiVaultAuth::JwtOidc {
            mount_path: "auth/jwt".to_string(),
            role: "ember-daemon".to_string(),
            jwt: SecretString::from(jwt.to_string()),
        }
    }

    #[test]
    fn jwt_login_happy_path() {
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("hvs.jwt-token")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                jwt_auth("eyJhbGciOiJSUzI1NiJ9.fixture-jwt.signature"),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("jwt login must succeed");
            let token = store.current_token().await.expect("token cached");
            assert_eq!(token, "hvs.jwt-token");

            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "POST");
            assert!(
                call.url.ends_with("/v1/auth/jwt/login"),
                "expected /v1/auth/jwt/login, got {}",
                call.url
            );
            // The JSON body must contain Vault's required field set.
            let body = String::from_utf8(call.body.expect("body sent")).expect("utf8");
            assert!(
                body.contains("\"role\":\"ember-daemon\""),
                "missing role=ember-daemon in {body}"
            );
            assert!(
                body.contains("\"jwt\":\"eyJhbGciOiJSUzI1NiJ9.fixture-jwt.signature\""),
                "missing jwt field in {body}"
            );
        });
    }

    #[test]
    fn jwt_login_oidc_mount_path_routes_correctly() {
        // Vault's "oidc" auth method is the same primitive as "jwt"
        // mounted at a different path; the daemon honors operator
        // config verbatim.
        rt().block_on(async {
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("hvs.oidc-token")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                HashiVaultAuth::JwtOidc {
                    mount_path: "auth/oidc".to_string(),
                    role: "ember-daemon".to_string(),
                    jwt: SecretString::from("oidc.fixture.jwt".to_string()),
                },
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("oidc login must succeed");

            let call = mock.last_call().expect("a call was made");
            assert!(
                call.url.ends_with("/v1/auth/oidc/login"),
                "expected /v1/auth/oidc/login, got {}",
                call.url
            );
        });
    }

    #[test]
    fn jwt_login_invalid_jwt() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(
                401,
                r#"{"errors":["invalid token: signature is invalid"]}"#.to_string(),
            ));
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                jwt_auth("eyJhbGciOiJSUzI1NiJ9.tampered.bad-sig"),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn jwt_login_role_not_bound() {
        rt().block_on(async {
            let mock = Arc::new(MockHttpClient::new().with_response(
                400,
                r#"{"errors":["role \"ember-daemon\" could not be found"]}"#.to_string(),
            ));
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                jwt_auth("eyJhbGciOiJSUzI1NiJ9.valid-jwt.signature"),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
        });
    }

    #[test]
    fn jwt_login_empty_jwt_short_circuits() {
        rt().block_on(async {
            // Empty JWT must short-circuit before any HTTP call —
            // matches the HCP "missing credentials" pattern.
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("must-not-reach")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                jwt_auth(""),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );
            assert_eq!(
                mock.call_count(),
                0,
                "vault_jwt_login must short-circuit before HTTP when JWT is empty"
            );
        });
    }

    // -----------------------------------------------------------------
    // `vault_kubernetes_login` unit tests
    // -----------------------------------------------------------------
    //
    // Reuses the JWT-shaped `jwt_login_ok_body` helper above — the
    // Kubernetes auth method shares Vault's standard auth response
    // envelope.

    fn k8s_auth_with_token_path(token_path: PathBuf) -> HashiVaultAuth {
        HashiVaultAuth::Kubernetes {
            role: "ember-daemon".to_string(),
            token_path,
        }
    }

    /// Write a SA-token fixture file under a unique tmp path. Returns
    /// the path; caller is responsible for cleanup (tests delete it
    /// at end via Drop on a scopeguard-style helper, OR ignore — the
    /// OS reclaims tmp on next reboot).
    fn write_sa_token_fixture(name: &str, contents: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ember-vault-k8s-test-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, contents).expect("write SA token fixture");
        p
    }

    #[test]
    fn k8s_login_happy_path() {
        rt().block_on(async {
            let token_path =
                write_sa_token_fixture("happy", "eyJhbGciOiJSUzI1NiJ9.k8s-sa-fixture.signature");
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("hvs.k8s-token")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                k8s_auth_with_token_path(token_path.clone()),
                UnavailablePolicy::FailHard,
                None,
            );
            store.login().await.expect("k8s login must succeed");
            let token = store.current_token().await.expect("token cached");
            assert_eq!(token, "hvs.k8s-token");

            let call = mock.last_call().expect("a call was made");
            assert_eq!(call.method, "POST");
            assert!(
                call.url.ends_with("/v1/auth/kubernetes/login"),
                "expected /v1/auth/kubernetes/login, got {}",
                call.url
            );
            // Body must contain role + the SA JWT we wrote to the
            // fixture file.
            let body = String::from_utf8(call.body.expect("body sent")).expect("utf8");
            assert!(
                body.contains("\"role\":\"ember-daemon\""),
                "missing role in {body}"
            );
            assert!(
                body.contains("eyJhbGciOiJSUzI1NiJ9.k8s-sa-fixture.signature"),
                "missing fixture JWT in {body}"
            );

            let _ = std::fs::remove_file(&token_path);
        });
    }

    #[test]
    fn k8s_login_missing_sa_token_mount() {
        rt().block_on(async {
            // Point at a path that is guaranteed not to exist — no
            // file written. vault_kubernetes_login must short-circuit
            // before any HTTP call with AuthFailed.
            let mut bogus = std::env::temp_dir();
            bogus.push(format!(
                "ember-vault-k8s-MISSING-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            assert!(!bogus.exists(), "fixture path must not exist for this test");

            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("must-not-reach")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                k8s_auth_with_token_path(bogus),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::AuthFailed(msg) => {
                    assert!(
                        msg.contains("kubernetes SA token not readable"),
                        "expected 'kubernetes SA token not readable' in error, got: {msg}"
                    );
                }
                other => panic!("expected AuthFailed, got {other:?}"),
            }
            assert_eq!(
                mock.call_count(),
                0,
                "vault_kubernetes_login must short-circuit before HTTP when token file is missing"
            );
        });
    }

    #[test]
    fn k8s_login_empty_sa_token_file() {
        rt().block_on(async {
            // File present but blank — kubelet projection misconfigured.
            let token_path = write_sa_token_fixture("empty", "   \n  \t\n");
            let mock = Arc::new(
                MockHttpClient::new().with_response(200, jwt_login_ok_body("must-not-reach")),
            );
            let mut store = HashiVaultStore::new(
                mock.clone(),
                "https://vault.example.com:8200",
                "secret",
                k8s_auth_with_token_path(token_path.clone()),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            match err {
                StoreError::AuthFailed(msg) => {
                    assert!(
                        msg.contains("kubernetes SA token empty"),
                        "expected 'kubernetes SA token empty' in error, got: {msg}"
                    );
                }
                other => panic!("expected AuthFailed, got {other:?}"),
            }
            assert_eq!(
                mock.call_count(),
                0,
                "vault_kubernetes_login must short-circuit before HTTP when SA token is empty"
            );

            let _ = std::fs::remove_file(&token_path);
        });
    }

    #[test]
    fn k8s_login_role_not_bound() {
        rt().block_on(async {
            let token_path = write_sa_token_fixture(
                "rolebind",
                "eyJhbGciOiJSUzI1NiJ9.valid-sa.signature",
            );
            let mock = Arc::new(
                MockHttpClient::new().with_response(
                    400,
                    r#"{"errors":["service account name not authorized for role \"ember-daemon\""]}"#
                        .to_string(),
                ),
            );
            let mut store = HashiVaultStore::new(
                mock,
                "https://vault.example.com:8200",
                "secret",
                k8s_auth_with_token_path(token_path.clone()),
                UnavailablePolicy::FailHard,
                None,
            );
            let err = store.login().await.expect_err("login must fail");
            assert!(
                matches!(err, StoreError::AuthFailed(_)),
                "expected AuthFailed, got {err:?}"
            );

            let _ = std::fs::remove_file(&token_path);
        });
    }

    #[test]
    fn k8s_login_default_sa_path_constant() {
        // The KUBERNETES_SA_TOKEN_PATH constant must match the
        // standard kubelet projection path; if this test breaks the
        // doc on HashiVaultAuth::Kubernetes is misleading.
        assert_eq!(
            KUBERNETES_SA_TOKEN_PATH,
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
    }
}
