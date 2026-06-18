//! HTTP listener + routes for the Vault Transit KMS surface.
//!
//! See crate-level docs and ADR 100 for the full design.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use core_grant_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind, ReceiptOutcome,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::warn;
use uuid::Uuid;

use crate::transit::{
    DecryptData, DecryptRequest, EncryptData, EncryptRequest, KeyData, TransitError,
    TransitKeyring, VaultResponse, warn_auth_failure,
};

/// Sink for receipts emitted by ember-kms encrypt / decrypt handlers.
///
/// Implementations live in the daemon (where the signing identity + receipt
/// store are wired). The kms crate ships a [`NoopReceiptSink`] for tests
/// and standalone runs that bypass the daemon.
///
/// Implementations MUST be cheap to call from the request path — receipt
/// emission is per-call and on the hot path. A failing sink MUST NOT fail
/// the underlying kms operation; sinks are responsible for swallowing /
/// logging their own errors.
pub trait ReceiptSink: Send + Sync {
    /// Persist a single [`KmsReceipt`]. Sinks MUST NOT mutate the receipt;
    /// signing happens upstream of this call.
    fn record(&self, receipt: KmsReceipt);
}

/// Default no-op sink used when the kms server is started without daemon
/// wiring (standalone runs, integration tests). Drops every receipt.
#[derive(Debug, Default)]
pub struct NoopReceiptSink;

impl ReceiptSink for NoopReceiptSink {
    fn record(&self, _receipt: KmsReceipt) {}
}

/// Default localhost port for the KMS listener (per ADR 100).
///
/// Chosen to avoid collisions with the existing dashboard at `3141`. Used when
/// a caller constructs [`KmsServer`] without specifying a port.
pub const DEFAULT_KMS_PORT: u16 = 9941;

/// Vault Transit KMS server.
///
/// Bound to `127.0.0.1` by construction; the [`KmsServer::new`] /
/// [`KmsServer::with_port`] APIs do not accept a non-loopback address. See
/// crate-level docs (and ADR 100 §"Listening surface") for the rationale.
pub struct KmsServer {
    addr: SocketAddr,
    router: Router,
}

impl KmsServer {
    /// Construct a server bound to `127.0.0.1:0` (ephemeral port). Uses
    /// the [`NoopReceiptSink`] — no receipts are persisted.
    pub fn new() -> Self {
        Self::with_port(0)
    }

    /// Construct a server bound to `127.0.0.1:<port>`. Uses the
    /// [`NoopReceiptSink`] — no receipts are persisted.
    pub fn with_port(port: u16) -> Self {
        Self::with_port_and_sink(port, Arc::new(NoopReceiptSink))
    }

    /// Construct a server bound to `127.0.0.1:<port>` with an explicit
    /// receipt sink. Daemon wiring uses this constructor to inject the
    /// real receipt store; tests can pass an in-memory test double.
    pub fn with_port_and_sink(port: u16, sink: Arc<dyn ReceiptSink>) -> Self {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        Self {
            addr,
            router: build_router(TransitKeyring::new(), sink),
        }
    }

    /// Configured bind address (port may be `0` until [`KmsServer::bind`]).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bind the TCP listener and return a handle whose `local_addr` reports the
    /// concrete port.
    ///
    /// Refuses to bind any non-loopback address.
    pub async fn bind(self) -> Result<BoundKmsServer, KmsServerError> {
        if !self.addr.ip().is_loopback() {
            return Err(KmsServerError::NonLoopbackBind(self.addr));
        }
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(KmsServerError::Bind)?;
        let local_addr = listener.local_addr().map_err(KmsServerError::Bind)?;
        Ok(BoundKmsServer {
            listener,
            local_addr,
            router: self.router,
        })
    }
}

impl Default for KmsServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Server bound to a concrete port; produced by [`KmsServer::bind`].
pub struct BoundKmsServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    router: Router,
}

impl BoundKmsServer {
    /// Concrete bound socket address (with the OS-assigned port).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Run the listener until the future is cancelled.
    pub async fn serve(self) -> Result<(), KmsServerError> {
        axum::serve(self.listener, self.router)
            .await
            .map_err(KmsServerError::Serve)
    }
}

/// Convenience: bind + serve in one call. Returns once the server stops.
pub async fn run(server: KmsServer) -> Result<(), KmsServerError> {
    let bound = server.bind().await?;
    bound.serve().await
}

/// Errors produced by the KMS server.
#[derive(Debug, Error)]
pub enum KmsServerError {
    /// Caller attempted to bind a non-loopback address.
    #[error("ember-kms refuses to bind non-loopback address: {0}")]
    NonLoopbackBind(SocketAddr),
    /// Failed to bind the TCP listener.
    #[error("failed to bind TCP listener: {0}")]
    Bind(#[source] std::io::Error),
    /// `axum::serve` returned an error.
    #[error("axum serve error: {0}")]
    Serve(#[source] std::io::Error),
}

// ---------------------------------------------------------------------------
// Router + middleware + handlers
// ---------------------------------------------------------------------------

/// Bundled state shared with each handler — the in-memory keyring plus the
/// configured receipt sink.
#[derive(Clone)]
struct AppState {
    keyring: Arc<TransitKeyring>,
    receipt_sink: Arc<dyn ReceiptSink>,
}

fn build_router(keyring: TransitKeyring, receipt_sink: Arc<dyn ReceiptSink>) -> Router {
    let state = AppState {
        keyring: Arc::new(keyring),
        receipt_sink,
    };
    Router::new()
        .route("/v1/{engine}/encrypt/{key}", post(encrypt_handler))
        .route("/v1/{engine}/decrypt/{key}", post(decrypt_handler))
        .route(
            "/v1/{engine}/keys/{key}",
            post(create_key_handler).get(get_key_handler),
        )
        .with_state(state)
        .layer(middleware::from_fn(auth_middleware))
}

/// Bearer-token / X-Vault-Token validation middleware.
///
/// Accepts `Authorization: Bearer <token>` or `X-Vault-Token: <token>`.
/// Returns `401 Unauthorized` if no valid, non-empty token is present.
/// Warns on auth failures via `tracing::warn!`.
pub async fn auth_middleware(headers: HeaderMap, mut request: Request, next: Next) -> Response {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            warn_auth_failure("missing or empty bearer token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    request.extensions_mut().insert(token);
    next.run(request).await
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<SecretString> {
    // Accept Authorization: Bearer <token> OR X-Vault-Token: <token>
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(|s| s.trim().to_owned())
        .or_else(|| {
            headers
                .get("x-vault-token")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_owned())
        })?;

    if raw.is_empty() {
        return None;
    }
    Some(SecretString::from(raw))
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn encrypt_handler(
    State(state): State<AppState>,
    Path((_engine, key_name)): Path<(String, String)>,
    Json(body): Json<EncryptRequest>,
) -> Response {
    let request_size = body.plaintext.len() as u64;
    let result = state.keyring.encrypt(&key_name, &body.plaintext);
    let outcome = match &result {
        Ok(_) => ReceiptOutcome::Success,
        Err(_) => ReceiptOutcome::Failure,
    };
    // Emit a kms_wrap receipt for every call (success and failure). Body
    // carries metadata only — never plaintext bytes.
    emit_kms_receipt(
        &state.receipt_sink,
        ReceiptKind::KmsWrap,
        &key_name,
        request_size,
        outcome,
    );

    match result {
        Ok(ciphertext) => {
            let resp = VaultResponse::new(EncryptData { ciphertext });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(TransitError::KeyNotFound(_)) => vault_error(StatusCode::NOT_FOUND, "key not found"),
        Err(TransitError::InvalidPlaintext) => {
            vault_error(StatusCode::BAD_REQUEST, "plaintext must be valid base64")
        }
        Err(e) => {
            warn!(error = %e, "encrypt error");
            vault_error(StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed")
        }
    }
}

async fn decrypt_handler(
    State(state): State<AppState>,
    Path((_engine, key_name)): Path<(String, String)>,
    Json(body): Json<DecryptRequest>,
) -> Response {
    let request_size = body.ciphertext.len() as u64;
    let result = state.keyring.decrypt(&key_name, &body.ciphertext);
    let outcome = match &result {
        Ok(_) => ReceiptOutcome::Success,
        Err(_) => ReceiptOutcome::Failure,
    };
    // Emit a kms_unwrap receipt for every call. Body carries metadata
    // only — never ciphertext bytes or recovered plaintext.
    emit_kms_receipt(
        &state.receipt_sink,
        ReceiptKind::KmsUnwrap,
        &key_name,
        request_size,
        outcome,
    );

    match result {
        Ok(plaintext) => {
            let resp = VaultResponse::new(DecryptData { plaintext });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(TransitError::KeyNotFound(_)) => vault_error(StatusCode::NOT_FOUND, "key not found"),
        Err(TransitError::MalformedCiphertext) => vault_error(
            StatusCode::BAD_REQUEST,
            "ciphertext must start with 'vault:v1:'",
        ),
        Err(TransitError::AesGcm) => vault_error(
            StatusCode::BAD_REQUEST,
            "decryption failed: authentication tag mismatch",
        ),
        Err(e) => {
            warn!(error = %e, "decrypt error");
            vault_error(StatusCode::INTERNAL_SERVER_ERROR, "decrypt failed")
        }
    }
}

async fn create_key_handler(
    State(state): State<AppState>,
    Path((_engine, key_name)): Path<(String, String)>,
) -> Response {
    match state.keyring.create_key(&key_name) {
        Ok(info) => {
            let resp = VaultResponse::new(KeyData { info });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(TransitError::KeyAlreadyExists(_)) => {
            // Vault Transit returns 204 No Content for idempotent key creation;
            // we return 200 with existing metadata to aid debugging.
            match state.keyring.key_info(&key_name) {
                Ok(info) => {
                    let resp = VaultResponse::new(KeyData { info });
                    (StatusCode::OK, Json(resp)).into_response()
                }
                Err(e) => {
                    warn!(error = %e, "key_info after create collision");
                    vault_error(StatusCode::INTERNAL_SERVER_ERROR, "key state inconsistency")
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "create_key error");
            vault_error(StatusCode::INTERNAL_SERVER_ERROR, "key creation failed")
        }
    }
}

async fn get_key_handler(
    State(state): State<AppState>,
    Path((_engine, key_name)): Path<(String, String)>,
) -> Response {
    match state.keyring.key_info(&key_name) {
        Ok(info) => {
            let resp = VaultResponse::new(KeyData { info });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(TransitError::KeyNotFound(_)) => vault_error(StatusCode::NOT_FOUND, "key not found"),
        Err(e) => {
            warn!(error = %e, "key_info error");
            vault_error(StatusCode::INTERNAL_SERVER_ERROR, "key info failed")
        }
    }
}

/// Build + dispatch a `KmsReceipt` to the configured sink.
///
/// **Hard invariant:** never include the plaintext / ciphertext payload,
/// the recovered plaintext, or any byte-derived material here. Sizes only.
///
/// `caller_persona` is `"unknown"` until the daemon wires per-token
/// caller identification; `grant_evaluation` is `denied` with no grant id
/// for the same reason. Once the broker (ADR 094) is in front of ember-kms
/// and grants the token, both fields populate from the request context.
fn emit_kms_receipt(
    sink: &Arc<dyn ReceiptSink>,
    kind: ReceiptKind,
    key_name: &str,
    request_size_bytes: u64,
    outcome: ReceiptOutcome,
) {
    debug_assert!(
        matches!(kind, ReceiptKind::KmsWrap | ReceiptKind::KmsUnwrap),
        "emit_kms_receipt called with non-kms ReceiptKind: {kind:?}"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipt = KmsReceipt {
        id: format!("rct-{}", Uuid::new_v4()),
        kind,
        key_name: key_name.to_owned(),
        // Phase 1: ember-kms is not yet in front of the broker — the
        // request token does not yet identify a persona. Until that wiring
        // lands, every receipt records the bypass explicitly.
        caller_persona: "unknown".to_owned(),
        request_size_bytes,
        materialized_at_epoch_secs: now,
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        },
        outcome,
        // Loopback path — no mTLS peer identity.
        peer_identity: None,
        // Evidence is zeroed at the kms surface — the daemon's receipt
        // sink signs and re-stores via its identity key.
        evidence: Evidence::default(),
    };
    sink.record(receipt);
}

fn vault_error(status: StatusCode, message: &str) -> Response {
    let body = json!({ "errors": [message] });
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

// Keep the import used so clippy doesn't warn on it; this is the standard
// idiom for consumers of the token extension.
#[allow(dead_code)]
fn _assert_expose_secret_usable() {
    let s = SecretString::from(String::new());
    let _ = s.expose_secret();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    type JsonClient = Client<hyper_util::client::legacy::connect::HttpConnector, String>;

    /// Spawn a test server with an isolated keyring.
    async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
        let server = KmsServer::new();
        let bound = server.bind().await.expect("bind ephemeral");
        let url = format!("http://{}", bound.local_addr());
        let handle = tokio::spawn(async move {
            let _ = bound.serve().await;
        });
        (url, handle)
    }

    fn json_client() -> JsonClient {
        Client::builder(TokioExecutor::new()).build_http()
    }

    fn authed_post(url: &str) -> hyper::http::request::Builder {
        hyper::Request::builder()
            .method("POST")
            .uri(url)
            .header(AUTHORIZATION, "Bearer test-token")
            .header("content-type", "application/json")
    }

    fn authed_get(url: &str) -> hyper::http::request::Builder {
        hyper::Request::builder()
            .method("GET")
            .uri(url)
            .header(AUTHORIZATION, "Bearer test-token")
    }

    // -----------------------------------------------------------------------
    // Scaffold / loopback invariant tests (must NOT regress)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn server_starts_on_loopback_ephemeral_port() {
        let server = KmsServer::new();
        let bound = server.bind().await.expect("bind ephemeral");
        let local = bound.local_addr();
        assert!(
            local.ip().is_loopback(),
            "expected loopback, got {}",
            local.ip()
        );
        assert_ne!(local.port(), 0, "expected OS-assigned port, got 0");
    }

    #[tokio::test]
    async fn refuses_non_loopback_bind() {
        let server = KmsServer {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            router: build_router(TransitKeyring::new(), Arc::new(NoopReceiptSink)),
        };
        match server.bind().await {
            Err(KmsServerError::NonLoopbackBind(addr)) => {
                assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            }
            Err(other) => panic!("expected NonLoopbackBind, got {other:?}"),
            Ok(_) => panic!("expected NonLoopbackBind, got Ok(BoundKmsServer)"),
        }
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let (base, _h) = spawn_test_server().await;
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("{base}/v1/transit/encrypt/test-key"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = client.request(req).await.expect("no-auth request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = resp.into_body().collect().await;
    }

    #[tokio::test]
    async fn empty_bearer_token_returns_401() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("{base}/v1/transit/encrypt/test-key"))
            .header(AUTHORIZATION, "Bearer ")
            .header("content-type", "application/json")
            .body(String::from("{}"))
            .unwrap();
        let resp = client.request(req).await.expect("empty-token request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Key create / get tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn key_create_returns_200_with_metadata() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        let req = authed_post(&format!("{base}/v1/transit/keys/my-key"))
            .body(String::from("{}"))
            .unwrap();
        let resp = client.request(req).await.expect("create key");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(v["data"]["type"], "aes256-gcm96");
        assert_eq!(v["data"]["name"], "my-key");
    }

    #[tokio::test]
    async fn key_get_after_create_returns_metadata() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        // Create
        let req = authed_post(&format!("{base}/v1/transit/keys/get-test"))
            .body(String::from("{}"))
            .unwrap();
        client.request(req).await.expect("create key");
        // GET
        let req2 = authed_get(&format!("{base}/v1/transit/keys/get-test"))
            .body(String::new())
            .unwrap();
        let resp = client.request(req2).await.expect("get key");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(v["data"]["name"], "get-test");
        assert_eq!(v["data"]["type"], "aes256-gcm96");
    }

    #[tokio::test]
    async fn get_missing_key_returns_404() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        let req = authed_get(&format!("{base}/v1/transit/keys/does-not-exist"))
            .body(String::new())
            .unwrap();
        let resp = client.request(req).await.expect("get missing key");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // Encrypt / decrypt integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn keyless_encrypt_returns_404() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        let pt_b64 = BASE64.encode(b"my-dek-bytes");
        let body = serde_json::json!({ "plaintext": pt_b64 }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/encrypt/missing-key"))
            .body(body)
            .unwrap();
        let resp = client.request(req).await.expect("encrypt missing");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn keyless_decrypt_returns_404() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();
        let body = serde_json::json!({ "ciphertext": "vault:v1:abc123" }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/decrypt/missing-key"))
            .body(body)
            .unwrap();
        let resp = client.request(req).await.expect("decrypt missing");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn encrypt_roundtrip_via_http() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();

        // Create key
        let req = authed_post(&format!("{base}/v1/transit/keys/roundtrip"))
            .body(String::from("{}"))
            .unwrap();
        client.request(req).await.expect("create key");

        // Encrypt
        let pt_b64 = BASE64.encode(b"the-secret-dek-material-padded!!");
        let enc_body = serde_json::json!({ "plaintext": pt_b64 }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/encrypt/roundtrip"))
            .body(enc_body)
            .unwrap();
        let resp = client.request(req).await.expect("encrypt");
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let enc_val: serde_json::Value = serde_json::from_slice(&body_bytes).expect("encrypt json");
        let ciphertext = enc_val["data"]["ciphertext"]
            .as_str()
            .expect("ciphertext field")
            .to_owned();
        assert!(ciphertext.starts_with("vault:v1:"));

        // Decrypt
        let dec_body = serde_json::json!({ "ciphertext": ciphertext }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/decrypt/roundtrip"))
            .body(dec_body)
            .unwrap();
        let resp = client.request(req).await.expect("decrypt");
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let dec_val: serde_json::Value = serde_json::from_slice(&body_bytes).expect("decrypt json");
        let recovered = dec_val["data"]["plaintext"]
            .as_str()
            .expect("plaintext field");
        assert_eq!(recovered, pt_b64);
    }

    #[tokio::test]
    async fn decrypt_malformed_prefix_returns_400() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();

        // Create key
        let req = authed_post(&format!("{base}/v1/transit/keys/prefix-test"))
            .body(String::from("{}"))
            .unwrap();
        client.request(req).await.expect("create key");

        // Decrypt with bad prefix
        let body = serde_json::json!({ "ciphertext": "badprefix:abc123" }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/decrypt/prefix-test"))
            .body(body)
            .unwrap();
        let resp = client.request(req).await.expect("decrypt bad prefix");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decrypt_wrong_key_returns_400() {
        let (base, _h) = spawn_test_server().await;
        let client = json_client();

        // Create two keys
        for k in &["key-a", "key-b"] {
            let req = authed_post(&format!("{base}/v1/transit/keys/{k}"))
                .body(String::from("{}"))
                .unwrap();
            client.request(req).await.expect("create key");
        }

        // Encrypt with key-a
        let pt_b64 = BASE64.encode(b"some-dek-material-that-is-long-enough!!");
        let enc_body = serde_json::json!({ "plaintext": pt_b64 }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/encrypt/key-a"))
            .body(enc_body)
            .unwrap();
        let resp = client.request(req).await.expect("encrypt");
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let enc_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let ciphertext = enc_val["data"]["ciphertext"].as_str().unwrap().to_owned();

        // Decrypt with key-b — must fail
        let dec_body = serde_json::json!({ "ciphertext": ciphertext }).to_string();
        let req = authed_post(&format!("{base}/v1/transit/decrypt/key-b"))
            .body(dec_body)
            .unwrap();
        let resp = client.request(req).await.expect("decrypt wrong key");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn x_vault_token_header_accepted() {
        let (base, _h) = spawn_test_server().await;
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("{base}/v1/transit/keys/vault-token-test"))
            .header("x-vault-token", "my-vault-token")
            .header("content-type", "application/json")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = client.request(req).await.expect("x-vault-token request");
        // Should not be 401
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Receipt emission (KMS-RECEIPT-PERSIST)
    // -----------------------------------------------------------------------

    /// Test-double sink that records every call into a Mutex<Vec<_>>.
    #[derive(Default)]
    struct CapturingSink {
        receipts: std::sync::Mutex<Vec<KmsReceipt>>,
    }

    impl ReceiptSink for CapturingSink {
        fn record(&self, receipt: KmsReceipt) {
            self.receipts.lock().unwrap().push(receipt);
        }
    }

    /// Spawn a test server backed by a [`CapturingSink`] so the test can
    /// inspect every emitted receipt.
    async fn spawn_test_server_with_sink(
        sink: Arc<CapturingSink>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let server = KmsServer::with_port_and_sink(0, sink);
        let bound = server.bind().await.expect("bind ephemeral");
        let url = format!("http://{}", bound.local_addr());
        let handle = tokio::spawn(async move {
            let _ = bound.serve().await;
        });
        (url, handle)
    }

    #[tokio::test]
    async fn encrypt_emits_kms_wrap_receipt_on_success() {
        let sink = Arc::new(CapturingSink::default());
        let (base, _h) = spawn_test_server_with_sink(sink.clone()).await;
        let client = json_client();

        // Create the key.
        let req = authed_post(&format!("{base}/v1/transit/keys/wrap-key"))
            .body(String::from("{}"))
            .unwrap();
        client.request(req).await.expect("create key");

        // Encrypt a fixed payload.
        let pt_b64 = BASE64.encode(b"audit-trail-test");
        let pt_b64_len = pt_b64.len() as u64;
        let req = authed_post(&format!("{base}/v1/transit/encrypt/wrap-key"))
            .body(serde_json::json!({ "plaintext": pt_b64 }).to_string())
            .unwrap();
        let resp = client.request(req).await.expect("encrypt");
        assert_eq!(resp.status(), StatusCode::OK);

        // The sink received exactly one kms_wrap receipt with non-sensitive metadata.
        let captured = sink.receipts.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "expected 1 receipt, got {}",
            captured.len()
        );
        let r = &captured[0];
        assert_eq!(r.kind, ReceiptKind::KmsWrap);
        assert_eq!(r.key_name, "wrap-key");
        assert_eq!(r.outcome, ReceiptOutcome::Success);
        assert_eq!(r.request_size_bytes, pt_b64_len);
        // Phase 1 — caller_persona is "unknown" until the broker wiring lands.
        assert_eq!(r.caller_persona, "unknown");
        // No payload bytes anywhere in the receipt JSON.
        let json = serde_json::to_string(r).expect("serialize");
        assert!(
            !json.contains(&pt_b64),
            "receipt JSON contains the plaintext: {json}"
        );
    }

    #[tokio::test]
    async fn decrypt_emits_kms_unwrap_receipt_on_success_and_failure() {
        let sink = Arc::new(CapturingSink::default());
        let (base, _h) = spawn_test_server_with_sink(sink.clone()).await;
        let client = json_client();

        // Create key + encrypt to get a real ciphertext.
        let req = authed_post(&format!("{base}/v1/transit/keys/unwrap-key"))
            .body(String::from("{}"))
            .unwrap();
        client.request(req).await.expect("create key");
        let pt_b64 = BASE64.encode(b"unwrap-target");
        let req = authed_post(&format!("{base}/v1/transit/encrypt/unwrap-key"))
            .body(serde_json::json!({ "plaintext": pt_b64 }).to_string())
            .unwrap();
        let resp = client.request(req).await.expect("encrypt");
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let enc_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let ciphertext = enc_val["data"]["ciphertext"].as_str().unwrap().to_owned();

        // Drop the kms_wrap receipts — we only care about decrypt below.
        sink.receipts.lock().unwrap().clear();

        // Successful decrypt → kms_unwrap success.
        let ct_len = ciphertext.len() as u64;
        let req = authed_post(&format!("{base}/v1/transit/decrypt/unwrap-key"))
            .body(serde_json::json!({ "ciphertext": ciphertext }).to_string())
            .unwrap();
        let resp = client.request(req).await.expect("decrypt");
        assert_eq!(resp.status(), StatusCode::OK);

        // Malformed-prefix decrypt → kms_unwrap failure.
        let bad = "badprefix:abc".to_owned();
        let bad_len = bad.len() as u64;
        let req = authed_post(&format!("{base}/v1/transit/decrypt/unwrap-key"))
            .body(serde_json::json!({ "ciphertext": bad }).to_string())
            .unwrap();
        let resp = client.request(req).await.expect("decrypt malformed");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let captured = sink.receipts.lock().unwrap();
        assert_eq!(
            captured.len(),
            2,
            "expected 2 receipts, got {}",
            captured.len()
        );
        assert!(captured.iter().all(|r| r.kind == ReceiptKind::KmsUnwrap));
        assert_eq!(captured[0].outcome, ReceiptOutcome::Success);
        assert_eq!(captured[0].request_size_bytes, ct_len);
        assert_eq!(captured[1].outcome, ReceiptOutcome::Failure);
        assert_eq!(captured[1].request_size_bytes, bad_len);
        for r in captured.iter() {
            let json = serde_json::to_string(r).unwrap();
            assert!(
                !json.contains("audit"),
                "receipt JSON leaked plaintext substring"
            );
            assert!(
                !json.contains("ciphertext"),
                "receipt JSON contains 'ciphertext' field name: {json}"
            );
        }
    }

    #[tokio::test]
    async fn encrypt_missing_key_emits_failure_receipt() {
        let sink = Arc::new(CapturingSink::default());
        let (base, _h) = spawn_test_server_with_sink(sink.clone()).await;
        let client = json_client();

        let pt_b64 = BASE64.encode(b"x");
        let req = authed_post(&format!("{base}/v1/transit/encrypt/missing"))
            .body(serde_json::json!({ "plaintext": pt_b64 }).to_string())
            .unwrap();
        let resp = client.request(req).await.expect("encrypt missing");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let captured = sink.receipts.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].kind, ReceiptKind::KmsWrap);
        assert_eq!(captured[0].outcome, ReceiptOutcome::Failure);
        assert_eq!(captured[0].key_name, "missing");
    }
}
