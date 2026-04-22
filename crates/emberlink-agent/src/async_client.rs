//! Tokio-based socket client that multiplexes responses and server-initiated
//! notifications on a single unix-socket connection.
//!
//! The reader task demultiplexes inbound JSON lines:
//! - Lines with an `id` and `result`/`error` are responses, routed by id to
//!   the matching pending request waiter.
//! - Lines with `method` and `params` (no `id`) are notifications. The
//!   `grant_revoked` notification triggers immediate zeroization of the
//!   matching [`CredentialCache`] entry.
//!
//! This client is intended for long-running agent processes that hold cached
//! credentials. For one-shot RPC calls, the synchronous [`SocketTransport`]
//! in `socket_transport.rs` remains the simpler choice.
//!
//! [`SocketTransport`]: crate::socket_transport::SocketTransport

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, oneshot};
use tracing::debug;

use crate::cached_secret::CredentialCache;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Request<'a> {
    id: String,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct IncomingResponse {
    id: String,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<ErrorPayload>,
}

#[derive(Deserialize)]
struct IncomingNotification {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Deserialize, Debug, Clone)]
struct ErrorPayload {
    code: i32,
    message: String,
}

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Protocol(String),
    Daemon { code: i32, message: String },
    Closed,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "I/O error: {e}"),
            ClientError::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            ClientError::Daemon { code, message } => {
                write!(f, "Daemon error {code}: {message}")
            }
            ClientError::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, ClientError>>>>>;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// An async socket client that processes server-initiated notifications.
///
/// Internally, a background reader task demultiplexes responses and
/// notifications. Drop the client to tear down the connection and abort the
/// reader task.
pub struct AsyncSocketClient {
    writer: Arc<Mutex<OwnedWriteHalf>>,
    pending: PendingMap,
    cache: CredentialCache,
    reader_task: tokio::task::JoinHandle<()>,
}

impl AsyncSocketClient {
    /// Connect to the daemon at the given socket path and start the reader
    /// task. The provided [`CredentialCache`] receives invalidation callbacks
    /// for `grant_revoked` notifications.
    pub async fn connect(path: &Path, cache: CredentialCache) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).await?;
        let (read_half, write_half) = stream.into_split();
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);
        let cache_reader = cache.clone();

        let reader_task = tokio::spawn(async move {
            let reader = BufReader::new(read_half);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        dispatch_line(&line, &pending_reader, &cache_reader).await;
                    }
                    Ok(None) => {
                        // EOF: fail any pending waiters.
                        let mut guard = pending_reader.lock().await;
                        for (_, tx) in guard.drain() {
                            let _ = tx.send(Err(ClientError::Closed));
                        }
                        break;
                    }
                    Err(e) => {
                        let mut guard = pending_reader.lock().await;
                        for (_, tx) in guard.drain() {
                            let _ = tx.send(Err(ClientError::Io(std::io::Error::other(
                                e.to_string(),
                            ))));
                        }
                        break;
                    }
                }
            }
        });

        Ok(Self {
            writer: Arc::new(Mutex::new(write_half)),
            pending,
            cache,
            reader_task,
        })
    }

    /// Send a request and await the matching response.
    pub async fn send(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed).to_string();
        let req = Request {
            id: id.clone(),
            method,
            params,
        };
        let mut line = serde_json::to_string(&req)
            .map_err(|e| ClientError::Protocol(format!("serialize: {e}")))?;
        line.push('\n');

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            guard.insert(id.clone(), tx);
        }

        {
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(line.as_bytes()).await {
                // Remove the waiter we just installed so it doesn't leak.
                self.pending.lock().await.remove(&id);
                return Err(ClientError::Io(e));
            }
        }

        match rx.await {
            Ok(result) => result,
            Err(_) => Err(ClientError::Closed),
        }
    }

    /// Access the shared credential cache.
    pub fn cache(&self) -> &CredentialCache {
        &self.cache
    }
}

impl Drop for AsyncSocketClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

// ---------------------------------------------------------------------------
// Line dispatch
// ---------------------------------------------------------------------------

async fn dispatch_line(line: &str, pending: &PendingMap, cache: &CredentialCache) {
    // Try response first (has `id`). If that fails, try notification.
    if let Ok(resp) = serde_json::from_str::<IncomingResponse>(line) {
        // Only treat as response if it has result or error; otherwise fall
        // through to notification parsing (some notifications may include
        // spurious keys).
        if resp.result.is_some() || resp.error.is_some() {
            let waiter = pending.lock().await.remove(&resp.id);
            if let Some(tx) = waiter {
                let outcome = if let Some(err) = resp.error {
                    Err(ClientError::Daemon {
                        code: err.code,
                        message: err.message,
                    })
                } else {
                    Ok(resp.result.unwrap_or(serde_json::Value::Null))
                };
                let _ = tx.send(outcome);
            }
            return;
        }
    }

    if let Ok(notif) = serde_json::from_str::<IncomingNotification>(line) {
        handle_notification(&notif, cache).await;
    }
}

async fn handle_notification(notif: &IncomingNotification, cache: &CredentialCache) {
    match notif.method.as_str() {
        "grant_revoked" => {
            let grant_id = match notif.params.get("grant_id").and_then(|v| v.as_str()) {
                Some(g) => g,
                None => return,
            };
            debug!(grant_id, "received grant_revoked; zeroizing cached handle");
            cache.revoke(grant_id);
        }
        other => {
            debug!(method = %other, "ignoring unknown notification");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// Simulate a daemon: accept one connection, echo a response, then
    /// push a `grant_revoked` notification for `grant_id`.
    async fn spawn_mock_daemon(
        path: std::path::PathBuf,
        grant_id: String,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).expect("bind");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let reader = BufReader::new(read_half);
            let mut lines = reader.lines();
            // Respond to the first request, then push a revocation.
            if let Ok(Some(line)) = lines.next_line().await {
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let id = req["id"].as_str().unwrap_or("0");
                let resp = serde_json::json!({
                    "id": id,
                    "result": {"ok": true},
                });
                let mut out = serde_json::to_vec(&resp).unwrap();
                out.push(b'\n');
                write_half.write_all(&out).await.unwrap();
            }
            // Push the notification.
            let notif = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "grant_revoked",
                "params": {"grant_id": grant_id, "persona_id": "persona-x"},
            });
            let mut out = serde_json::to_vec(&notif).unwrap();
            out.push(b'\n');
            write_half.write_all(&out).await.unwrap();
            // Hold the connection open briefly.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        })
    }

    fn tmp_socket_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ember-agent-{}-{}.sock",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn client_receives_notification_and_revokes_cache() {
        let path = tmp_socket_path("revoke");
        let _ = std::fs::remove_file(&path);
        let server = spawn_mock_daemon(path.clone(), "grant-revoke-me".into()).await;

        // Give the listener a moment to be ready.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let cache = CredentialCache::new();
        cache.insert("grant-revoke-me", b"secret-bytes".to_vec());
        assert!(cache.is_active("grant-revoke-me"));

        let client = AsyncSocketClient::connect(&path, cache.clone())
            .await
            .expect("connect");

        // Issue one request so the mock server pushes the notification.
        let resp = client
            .send("ping", serde_json::Value::Null)
            .await
            .expect("response");
        assert_eq!(resp["ok"], true);

        // Wait for the notification to be processed.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while cache.is_active("grant-revoke-me") {
            if std::time::Instant::now() > deadline {
                panic!("revocation not received within 1s");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(!cache.is_active("grant-revoke-me"));
        let err = cache.use_credential("grant-revoke-me", |_| ()).unwrap_err();
        assert!(matches!(err, crate::cached_secret::UseError::Revoked));

        drop(client);
        let _ = server.await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn client_ignores_unknown_notification_method() {
        // Isolated unit: pass a notification directly through dispatch.
        let cache = CredentialCache::new();
        cache.insert("grant-safe", b"v".to_vec());
        let notif = IncomingNotification {
            method: "unknown_method".into(),
            params: serde_json::json!({"grant_id": "grant-safe"}),
        };
        handle_notification(&notif, &cache).await;
        // Unknown notifications must not invalidate cache.
        assert!(cache.is_active("grant-safe"));
    }

    #[tokio::test]
    async fn client_ignores_notification_without_grant_id() {
        let cache = CredentialCache::new();
        cache.insert("grant-a", b"v".to_vec());
        let notif = IncomingNotification {
            method: "grant_revoked".into(),
            params: serde_json::json!({}),
        };
        handle_notification(&notif, &cache).await;
        assert!(cache.is_active("grant-a"));
    }
}
