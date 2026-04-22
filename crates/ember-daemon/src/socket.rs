use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tokio::task::LocalSet;
use tracing::{debug, info, warn};

use crate::events::GrantEvent;
use crate::policy::PolicyEngine;
use crate::rate_limit::RateLimiter;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MB
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const EVENT_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind failed: {0}")]
    Bind(std::io::Error),
    #[error("socket path already bound")]
    AlreadyBound,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<ErrorPayload>,
}

/// Server-initiated JSON-RPC notification sent to clients over the socket.
/// Uses `jsonrpc: "2.0"` and omits the `id` field, matching the standard
/// JSON-RPC 2.0 notification shape. No response is expected from the client.
#[derive(Debug, Serialize)]
struct Notification<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

pub struct SocketListener {
    path: PathBuf,
    shutdown: watch::Receiver<bool>,
    store: Rc<crate::store::DaemonStore>,
    vault: Rc<crate::vault::Vault>,
    policy: Rc<PolicyEngine>,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
}

impl SocketListener {
    pub fn new(
        path: PathBuf,
        shutdown: watch::Receiver<bool>,
        store: Rc<crate::store::DaemonStore>,
        vault: Rc<crate::vault::Vault>,
        policy: Rc<PolicyEngine>,
        rate_limiter: Rc<RefCell<RateLimiter>>,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            path,
            shutdown,
            store,
            vault,
            policy,
            rate_limiter,
            events_tx,
        }
    }

    /// Expose the event broadcast sender so the daemon runtime can publish
    /// events from other tasks (e.g. scheduled grant expiry).
    pub fn events_sender(&self) -> broadcast::Sender<GrantEvent> {
        self.events_tx.clone()
    }

    pub fn bind(&self) -> Result<UnixListener, SocketError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(SocketError::Bind)?;
        }
        UnixListener::bind(&self.path).map_err(SocketError::Bind)
    }

    /// Run the accept loop without creating a LocalSet.
    ///
    /// The caller must ensure this runs inside a `LocalSet` (e.g. via
    /// `local.run_until()` or `spawn_local()`).
    pub async fn accept_loop(self) -> Result<(), SocketError> {
        let listener = self.bind()?;
        info!(path = %self.path.display(), "socket listener started");

        let mut shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            info!("client connected");
                            let store = Rc::clone(&self.store);
                            let vault = Rc::clone(&self.vault);
                            let policy = Rc::clone(&self.policy);
                            let rate_limiter = Rc::clone(&self.rate_limiter);
                            let events_tx = self.events_tx.clone();
                            let events_rx = self.events_tx.subscribe();
                            tokio::task::spawn_local(handle_connection(
                                stream,
                                store,
                                vault,
                                policy,
                                rate_limiter,
                                events_tx,
                                events_rx,
                            ));
                        }
                        Err(e) => {
                            warn!(error = %e, "accept error");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("shutdown signal received, draining connections");
                        break;
                    }
                }
            }
        }

        // Drop listener; give spawned tasks a moment to drain.
        drop(listener);
        tokio::time::sleep(DRAIN_TIMEOUT.min(Duration::from_millis(100))).await;
        info!(path = %self.path.display(), "socket listener stopped");

        Ok(())
    }

    /// Run the socket listener with its own LocalSet (standalone mode).
    pub async fn run(self) -> Result<(), SocketError> {
        let local = LocalSet::new();
        local.run_until(self.accept_loop()).await
    }
}

async fn handle_connection(
    stream: UnixStream,
    store: Rc<crate::store::DaemonStore>,
    vault: Rc<crate::vault::Vault>,
    policy: Rc<PolicyEngine>,
    rate_limiter: Rc<RefCell<RateLimiter>>,
    events_tx: broadcast::Sender<GrantEvent>,
    mut events_rx: broadcast::Receiver<GrantEvent>,
) {
    let peer = stream.peer_addr().ok();
    debug!(?peer, "handling connection");

    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    // Merge inbound request handling and outbound event forwarding into a
    // single task so writes to the socket are serialized without a shared
    // mutex. Either a request line or an event will be processed per
    // iteration of the select.
    loop {
        tokio::select! {
            // Inbound request from client.
            line = lines.next_line() => {
                let line = match line {
                    Ok(Some(line)) => line,
                    Ok(None) => break, // EOF
                    Err(e) => {
                        warn!(error = %e, "read error");
                        break;
                    }
                };

                if line.len() > MAX_MESSAGE_BYTES {
                    let resp = Response {
                        id: String::new(),
                        result: None,
                        error: Some(ErrorPayload {
                            code: -32600,
                            message: "Message too large".to_string(),
                        }),
                    };
                    if let Err(e) = write_response(&mut write_half, &resp).await {
                        warn!(error = %e, "write error");
                        break;
                    }
                    continue;
                }

                let req: Request = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => {
                        let resp = Response {
                            id: String::new(),
                            result: None,
                            error: Some(ErrorPayload {
                                code: -32700,
                                message: "Parse error".to_string(),
                            }),
                        };
                        if let Err(e) = write_response(&mut write_half, &resp).await {
                            warn!(error = %e, "write error");
                            break;
                        }
                        continue;
                    }
                };

                debug!(id = %req.id, method = %req.method, "dispatching request");

                let response = match crate::handler::dispatch_method_with_events(
                    &store,
                    &vault,
                    &policy,
                    &rate_limiter,
                    Some(&events_tx),
                    &req.method,
                    &req.params,
                ).await {
                    Ok(result) => Response {
                        id: req.id,
                        result: Some(result),
                        error: None,
                    },
                    Err((code, message)) => Response {
                        id: req.id,
                        result: None,
                        error: Some(ErrorPayload { code, message }),
                    },
                };

                debug!(id = %response.id, "sending response");

                if let Err(e) = write_response(&mut write_half, &response).await {
                    warn!(error = %e, "write error");
                    break;
                }
            }
            // Server-initiated event pushed to this connection.
            event = events_rx.recv() => {
                match event {
                    Ok(ev) => {
                        if let Err(e) = write_notification(&mut write_half, &ev).await {
                            warn!(error = %e, "notification write error");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "connection lagged on event channel");
                        // Continue — we don't want a slow client to stall
                        // revocation broadcasts to other connections.
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed; stop forwarding but keep serving
                        // request/response.
                        debug!("event channel closed");
                    }
                }
            }
        }
    }

    debug!(?peer, "connection closed");
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &Response,
) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(resp).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await
}

async fn write_notification(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    event: &GrantEvent,
) -> std::io::Result<()> {
    let notif = Notification {
        jsonrpc: "2.0",
        method: event.method_name(),
        params: event.params(),
    };
    let mut bytes = serde_json::to_vec(&notif).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn make_store_vault() -> (Rc<crate::store::DaemonStore>, Rc<crate::vault::Vault>) {
        let store = crate::store::DaemonStore::open_in_memory().unwrap();
        let vault = crate::vault::Vault::new([42u8; 32]);
        (Rc::new(store), Rc::new(vault))
    }

    async fn start_listener(tmp: &TempDir) -> (PathBuf, watch::Sender<bool>) {
        let path = tmp.path().join("ember.sock");
        let (tx, rx) = watch::channel(false);
        let (store, vault) = make_store_vault();
        let policy = Rc::new(PolicyEngine::default());
        let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
        let listener =
            SocketListener::new(path.clone(), rx, store, vault, policy, rate_limiter);
        tokio::task::spawn_local(async move {
            listener.run().await.unwrap();
        });
        // Give listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(20)).await;
        (path, tx)
    }

    async fn connect(path: &PathBuf) -> (tokio::net::unix::OwnedWriteHalf, tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>) {
        let stream = UnixStream::connect(path).await.unwrap();
        let (r, w) = stream.into_split();
        (w, BufReader::new(r))
    }

    async fn send_recv(
        w: &mut tokio::net::unix::OwnedWriteHalf,
        r: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
        msg: &str,
    ) -> Response {
        let mut line = msg.to_string();
        line.push('\n');
        w.write_all(line.as_bytes()).await.unwrap();

        let mut resp_line = String::new();
        r.read_line(&mut resp_line).await.unwrap();
        serde_json::from_str(&resp_line).unwrap()
    }

    #[tokio::test]
    async fn test_ping() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"1","method":"ping","params":null}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "1");
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            assert_eq!(result["pong"], serde_json::json!(true));
        }).await;
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"2","method":"no_such_method"}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "2");
            assert!(resp.result.is_none());
            let err = resp.error.unwrap();
            assert_eq!(err.code, -32601);
        }).await;
    }

    #[tokio::test]
    async fn test_malformed_json() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = "not json at all\n";
            w.write_all(req.as_bytes()).await.unwrap();

            let mut resp_line = String::new();
            r.read_line(&mut resp_line).await.unwrap();
            let resp: Response = serde_json::from_str(&resp_line).unwrap();

            assert!(resp.result.is_none());
            let err = resp.error.unwrap();
            assert_eq!(err.code, -32700);
        }).await;
    }

    #[tokio::test]
    async fn test_shutdown() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, tx) = start_listener(&tmp).await;

            // Signal shutdown.
            tx.send(true).unwrap();

            // After shutdown the listener should stop accepting.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let result = UnixStream::connect(&path).await;
            assert!(result.is_err(), "expected connection refused after shutdown");
        }).await;
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;

            let mut handles = vec![];
            for i in 0..5u32 {
                let p = path.clone();
                handles.push(tokio::task::spawn_local(async move {
                    let (mut w, mut r) = connect(&p).await;
                    let req = format!(r#"{{"id":"{i}","method":"ping"}}"#);
                    let resp = send_recv(&mut w, &mut r, &req).await;
                    assert_eq!(resp.id, i.to_string());
                    assert!(resp.error.is_none());
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        }).await;
    }

    #[tokio::test]
    async fn test_create_persona_returns_id() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"10","method":"create_persona","params":{"name":"test-agent"}}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "10");
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            assert!(result["id"].as_str().unwrap().starts_with("persona-"));
            assert_eq!(result["name"], serde_json::json!("test-agent"));
        }).await;
    }

    #[tokio::test]
    async fn test_list_personas_empty() {
        let local = LocalSet::new();
        local.run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"11","method":"list_personas","params":null}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "11");
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            let arr = result.as_array().unwrap();
            assert!(arr.is_empty());
        }).await;
    }
}
