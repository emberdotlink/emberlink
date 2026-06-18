//! CLASSIFICATION: PUBLIC
//!
//! Integration coverage for the codex loopback-TCP responses lane
//! (P22-S2 / ADR 197 codex): drive `run_codex_forward_accept_loop` over a real
//! `127.0.0.1` listener and assert the strict-endpoint gate + lifecycle
//! teardown across the wire.
//!
//! These do NOT forward to a real upstream — the upstream is pinned server-side
//! to the ChatGPT backend (`chatgpt.com/backend-api/codex/responses`;
//! operator-overridable via `EMBER_CODEX_UPSTREAM_URL` but never
//! session/model-controllable, because the pin is a security property — INV-4).
//! The GPT-plan strip/inject/pin invariants are covered by the unit tests in
//! `forward.rs::codex_responses_tests` (pass-through + `inject_chatgpt_plan_auth`),
//! and the full ChatGPT-backend round-trip is a operator live-verify item. What's
//! verified HERE is the wire-level behavior of the per-session listener: the
//! strict gate rejects before any upstream hit, and the listener vanishes on
//! shutdown.

use std::sync::Arc;

use async_trait::async_trait;
use core_proxy_forward::{
    PolicyBackend, PolicyError, PreflightDecision, ResolvedGrant, SessionGatewayAuthority,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

/// Backend that resolves a session authority so the gate path reaches the
/// resolve step. The gate tests reject before forwarding, so the forward
/// methods are never exercised against a real upstream here.
struct Backend;

#[async_trait]
impl PolicyBackend for Backend {
    async fn resolve_session_authority(
        &self,
        _session_id: &str,
    ) -> Result<Option<SessionGatewayAuthority>, PolicyError> {
        Ok(Some(SessionGatewayAuthority {
            session_id: "sess_codex".into(),
            persona_id: "alice".into(),
            grant_id: "g-codex".into(),
            credential_name: "openai/session-key".into(),
        }))
    }

    async fn resolve_grant(
        &self,
        _persona_id: &str,
        _credential_name: &str,
        _resolved_grant_id: Option<&str>,
        _effective_uri: &http::Uri,
        _method: &str,
    ) -> Result<ResolvedGrant, PolicyError> {
        // Not reached on the gate-rejection paths these tests drive.
        Err(PolicyError::NotFound("unused".into()))
    }

    async fn preflight_budget(
        &self,
        _resolved: &ResolvedGrant,
        _body_bytes: &[u8],
    ) -> Result<PreflightDecision, PolicyError> {
        Ok(PreflightDecision::Allowed)
    }

    async fn get_credential(
        &self,
        _credential_name: &str,
    ) -> Result<Zeroizing<String>, PolicyError> {
        Ok(Zeroizing::new("sk-vault".into()))
    }

    async fn post_flight(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn post_flight_meter(
        &self,
        _resolved: &ResolvedGrant,
        _usage: Option<core_grant_types::Usage>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }

    async fn log_event(
        &self,
        _persona_id: &str,
        _event_kind: &str,
        _credential_name: Option<&str>,
        _outcome: &str,
        _detail: Option<&str>,
    ) -> Result<(), PolicyError> {
        Ok(())
    }
}

/// Send a raw HTTP/1.1 request to `port` and return the response status line.
async fn send_request(port: u16, request_line: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!(
        "{request_line}\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let status = text.lines().next().unwrap_or("").to_string();
    Ok(status)
}

/// Stand up the codex accept loop on an ephemeral loopback port; return the
/// port + a shutdown sender. The loop runs on its own thread with a current-
/// thread runtime + LocalSet (mirrors the daemon's per-session spawn).
fn spawn_codex_loop() -> (
    u16,
    tokio::sync::watch::Sender<bool>,
    std::thread::JoinHandle<()>,
) {
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    std_listener.set_nonblocking(true).unwrap();
    let port = std_listener.local_addr().unwrap().port();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            let backend = Arc::new(Backend);
            proxy_forward_runtime::forward::run_codex_forward_accept_loop(
                listener,
                "sess_codex".to_string(),
                backend,
                shutdown_rx,
            )
            .await;
        });
    });

    (port, shutdown_tx, handle)
}

#[tokio::test]
async fn codex_loopback_rejects_get_with_403() {
    let (port, shutdown_tx, handle) = spawn_codex_loop();
    // Give the loop a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let status = send_request(port, "GET /v1/responses HTTP/1.1")
        .await
        .expect("request");
    assert!(
        status.contains("403"),
        "GET /v1/responses must be 403, got: {status:?}"
    );

    let _ = shutdown_tx.send(true);
    // Connect after shutdown should eventually be refused.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let refused = TcpStream::connect(("127.0.0.1", port)).await.is_err();
    assert!(
        refused,
        "after shutdown the per-session listener must stop accepting"
    );
    let _ = handle.join();
}

#[tokio::test]
async fn codex_loopback_rejects_wrong_path_with_403() {
    let (port, shutdown_tx, handle) = spawn_codex_loop();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let status = send_request(port, "POST /v1/chat/completions HTTP/1.1")
        .await
        .expect("request");
    assert!(
        status.contains("403"),
        "POST to a non-/v1/responses path must be 403, got: {status:?}"
    );

    let _ = shutdown_tx.send(true);
    let _ = handle.join();
}

#[tokio::test]
async fn codex_loopback_rejects_query_string_with_403() {
    let (port, shutdown_tx, handle) = spawn_codex_loop();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let status = send_request(port, "POST /v1/responses?stream=true HTTP/1.1")
        .await
        .expect("request");
    assert!(
        status.contains("403"),
        "a query string on /v1/responses must be 403, got: {status:?}"
    );

    let _ = shutdown_tx.send(true);
    let _ = handle.join();
}

#[tokio::test]
async fn codex_loopback_binds_127_0_0_1() {
    let (port, shutdown_tx, handle) = spawn_codex_loop();
    assert_ne!(port, 0, "ephemeral port must be assigned");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // A connection to 127.0.0.1:<port> succeeds (loopback bind).
    let ok = TcpStream::connect(("127.0.0.1", port)).await.is_ok();
    assert!(ok, "listener must accept loopback connections");
    let _ = shutdown_tx.send(true);
    let _ = handle.join();
}
