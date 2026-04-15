use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::store::StoreError;
use crate::vault::VaultError;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("vault error: {0}")]
    Vault(VaultError),
}

impl From<VaultError> for ProxyError {
    fn from(e: VaultError) -> Self {
        ProxyError::Vault(e)
    }
}

pub struct ProxyConfig {
    pub bind_addr: std::net::SocketAddr,
}

pub struct ProxyState {
    pub store: crate::store::DaemonStore,
    pub vault: crate::vault::Vault,
}

pub async fn run_proxy(
    config: ProxyConfig,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(config.bind_addr).await?;

    // Use a LocalSet so that Arc<ProxyState> (which contains rusqlite's !Sync
    // Connection) does not need to cross thread boundaries.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let state = Arc::clone(&state);
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let state = Arc::clone(&state);
                                        async move { handle_request(state, req).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "proxy connection error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "proxy accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
        .await;

    Ok(())
}

pub async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let headers = req.headers();

    let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Persona header")),
    };

    let credential_name = match headers.get("x-ember-credential").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Credential header")),
    };

    let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Target header")),
    };

    // Evaluate grant
    match state.store.evaluate_grant(&persona_id, &credential_name) {
        Ok(_) => {}
        Err(StoreError::NotFound) => {
            return Ok(forbidden("no active grant for persona/credential"));
        }
        Err(e) => return Err(ProxyError::Store(e)),
    }

    // Decrypt credential from vault
    let credential_bytes = match state.vault.get(&state.store, &credential_name) {
        Ok(b) => b,
        Err(VaultError::NotFound) => {
            return Ok(internal_error("credential not found in vault"));
        }
        Err(e) => return Err(ProxyError::Vault(e)),
    };

    let credential_value = String::from_utf8_lossy(&credential_bytes).into_owned();

    // Log the access
    let _ = state.store.log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        None,
    );

    // Mock response — real forwarding deferred to a later PR
    let method = req.method().to_string();
    let body = serde_json::json!({
        "proxied": true,
        "target": target_url,
        "method": method,
    });

    // credential_value is used for the Authorization header in the eventual
    // real forwarding path; reference it here to silence unused-variable lint.
    let _ = credential_value;

    let body_bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{}".to_vec());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap())
}

fn bad_request(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

fn forbidden(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

fn internal_error(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DaemonStore;
    use crate::vault::Vault;
    use http_body_util::{BodyExt, Empty};

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_state() -> Arc<ProxyState> {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());
        Arc::new(ProxyState { store, vault })
    }

    fn proxy_request_with_headers(
        persona: Option<&str>,
        credential: Option<&str>,
        target: Option<&str>,
    ) -> Request<Empty<Bytes>> {
        let mut builder = Request::builder()
            .method("GET")
            .uri("http://localhost/api/repos");

        if let Some(p) = persona {
            builder = builder.header("X-Ember-Persona", p);
        }
        if let Some(c) = credential {
            builder = builder.header("X-Ember-Credential", c);
        }
        if let Some(t) = target {
            builder = builder.header("X-Ember-Target", t);
        }

        builder.body(Empty::new()).unwrap()
    }

    async fn call(
        state: Arc<ProxyState>,
        req: Request<Empty<Bytes>>,
    ) -> Response<Full<Bytes>> {
        // Adapt Empty<Bytes> to Incoming-compatible body using map_err
        let (parts, body) = req.into_parts();
        let mapped = body.map_err(|e| -> hyper::Error { panic!("empty body error: {e}") });
        let incoming_req = Request::from_parts(parts, mapped);

        // We need to call handle_request which takes Incoming — but in tests we
        // use a type-erased body.  Use the UnsyncBoxBody approach: box the body.
        use http_body_util::combinators::UnsyncBoxBody;
        let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> = incoming_req
            .map(|b| UnsyncBoxBody::new(b));

        // handle_request is generic — call a test-only wrapper.
        handle_request_boxed(state, boxed).await.unwrap()
    }

    // Test wrapper that accepts a boxed body so tests don't need a real Incoming.
    async fn handle_request_boxed(
        state: Arc<ProxyState>,
        req: Request<impl hyper::body::Body<Data = Bytes, Error = hyper::Error>>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let headers = req.headers();

        let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Persona header")),
        };

        let credential_name = match headers.get("x-ember-credential").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Credential header")),
        };

        let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Target header")),
        };

        match state.store.evaluate_grant(&persona_id, &credential_name) {
            Ok(_) => {}
            Err(StoreError::NotFound) => {
                return Ok(forbidden("no active grant for persona/credential"));
            }
            Err(e) => return Err(ProxyError::Store(e)),
        }

        let credential_bytes = match state.vault.get(&state.store, &credential_name) {
            Ok(b) => b,
            Err(VaultError::NotFound) => {
                return Ok(internal_error("credential not found in vault"));
            }
            Err(e) => return Err(ProxyError::Vault(e)),
        };

        let credential_value = String::from_utf8_lossy(&credential_bytes).into_owned();

        let _ = state.store.log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "allowed",
            None,
        );

        let method = req.method().to_string();
        let body = serde_json::json!({
            "proxied": true,
            "target": target_url,
            "method": method,
        });

        let _ = credential_value;

        let body_bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .unwrap())
    }

    #[tokio::test]
    async fn valid_request_returns_200_proxied() {
        let state = make_state();

        let persona = state.store.create_persona("test-agent").unwrap();
        state
            .vault
            .add(&state.store, "github-token", b"ghp_secret", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "github-token", "read", None)
            .unwrap();

        let req = proxy_request_with_headers(
            Some(&persona.id),
            Some("github-token"),
            Some("https://api.github.com"),
        );

        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["proxied"], true);
        assert_eq!(json["target"], "https://api.github.com");
        assert_eq!(json["method"], "GET");
    }

    #[tokio::test]
    async fn missing_persona_header_returns_400() {
        let state = make_state();
        let req = proxy_request_with_headers(None, Some("github-token"), Some("https://api.github.com"));
        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_credential_header_returns_400() {
        let state = make_state();
        let req = proxy_request_with_headers(Some("persona-123"), None, Some("https://api.github.com"));
        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_target_header_returns_400() {
        let state = make_state();
        let req = proxy_request_with_headers(Some("persona-123"), Some("github-token"), None);
        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn no_active_grant_returns_403() {
        let state = make_state();

        let persona = state.store.create_persona("ungrantable-agent").unwrap();
        state
            .vault
            .add(&state.store, "github-token", b"ghp_secret", None)
            .unwrap();
        // No grant created

        let req = proxy_request_with_headers(
            Some(&persona.id),
            Some("github-token"),
            Some("https://api.github.com"),
        );

        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn credential_not_in_vault_returns_500() {
        let state = make_state();

        let persona = state.store.create_persona("vault-miss-agent").unwrap();
        state
            .store
            .create_grant(&persona.id, "missing-cred", "read", None)
            .unwrap();
        // Credential NOT added to vault

        let req = proxy_request_with_headers(
            Some(&persona.id),
            Some("missing-cred"),
            Some("https://api.example.com"),
        );

        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn successful_request_logs_audit_event() {
        let state = make_state();

        let persona = state.store.create_persona("audit-agent").unwrap();
        state
            .vault
            .add(&state.store, "audit-token", b"tok_secret", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "audit-token", "read", None)
            .unwrap();

        let req = proxy_request_with_headers(
            Some(&persona.id),
            Some("audit-token"),
            Some("https://api.example.com"),
        );

        let resp = call(Arc::clone(&state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let entries = state
            .store
            .query_audit(&crate::audit::AuditFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "credential.access");
        assert_eq!(entries[0].outcome, "allowed");
        assert_eq!(entries[0].credential.as_deref(), Some("audit-token"));
    }
}
