use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{debug, info, warn};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MB
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

pub struct SocketListener {
    path: PathBuf,
    shutdown: watch::Receiver<bool>,
}

impl SocketListener {
    pub fn new(path: PathBuf, shutdown: watch::Receiver<bool>) -> Self {
        Self { path, shutdown }
    }

    pub fn bind(&self) -> Result<UnixListener, SocketError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(SocketError::Bind)?;
        }
        UnixListener::bind(&self.path).map_err(SocketError::Bind)
    }

    pub async fn run(&self) -> Result<(), SocketError> {
        let listener = self.bind()?;
        info!(path = %self.path.display(), "socket listener started");

        let mut shutdown = self.shutdown.clone();
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            info!("client connected");
                            tasks.spawn(handle_connection(stream));
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

        // Drop listener to stop accepting; drain existing connections with timeout.
        drop(listener);
        let drain = async {
            while tasks.join_next().await.is_some() {}
        };
        tokio::time::timeout(DRAIN_TIMEOUT, drain).await.ok();
        info!(path = %self.path.display(), "socket listener stopped");
        Ok(())
    }
}

async fn handle_connection(stream: UnixStream) {
    let peer = stream.peer_addr().ok();
    debug!(?peer, "handling connection");

    let (read_half, mut write_half) = stream.into_split();
    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();

    loop {
        let line = match lines.next_line().await {
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
            }
            continue;
        }

        let response = dispatch(&line);
        debug!(id = %response.id, "sending response");

        if let Err(e) = write_response(&mut write_half, &response).await {
            warn!(error = %e, "write error");
            break;
        }
    }

    debug!(?peer, "connection closed");
}

fn dispatch(line: &str) -> Response {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => {
            return Response {
                id: String::new(),
                result: None,
                error: Some(ErrorPayload {
                    code: -32700,
                    message: "Parse error".to_string(),
                }),
            };
        }
    };

    debug!(id = %req.id, method = %req.method, "dispatching request");

    match req.method.as_str() {
        "ping" => Response {
            id: req.id,
            result: Some(serde_json::json!({ "pong": true })),
            error: None,
        },
        _ => Response {
            id: req.id,
            result: None,
            error: Some(ErrorPayload {
                code: -32601,
                message: "Method not found".to_string(),
            }),
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    async fn start_listener(tmp: &TempDir) -> (PathBuf, watch::Sender<bool>) {
        let path = tmp.path().join("ember.sock");
        let (tx, rx) = watch::channel(false);
        let listener = SocketListener::new(path.clone(), rx);
        tokio::spawn(async move {
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
        let tmp = TempDir::new().unwrap();
        let (path, _tx) = start_listener(&tmp).await;
        let (mut w, mut r) = connect(&path).await;

        let req = r#"{"id":"1","method":"ping","params":null}"#;
        let resp = send_recv(&mut w, &mut r, req).await;

        assert_eq!(resp.id, "1");
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["pong"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let tmp = TempDir::new().unwrap();
        let (path, _tx) = start_listener(&tmp).await;
        let (mut w, mut r) = connect(&path).await;

        let req = r#"{"id":"2","method":"no_such_method"}"#;
        let resp = send_recv(&mut w, &mut r, req).await;

        assert_eq!(resp.id, "2");
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
    }

    #[tokio::test]
    async fn test_malformed_json() {
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
    }

    #[tokio::test]
    async fn test_shutdown() {
        let tmp = TempDir::new().unwrap();
        let (path, tx) = start_listener(&tmp).await;

        // Signal shutdown.
        tx.send(true).unwrap();

        // After shutdown the listener should stop accepting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let result = UnixStream::connect(&path).await;
        assert!(result.is_err(), "expected connection refused after shutdown");
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let tmp = TempDir::new().unwrap();
        let (path, _tx) = start_listener(&tmp).await;

        let mut handles = vec![];
        for i in 0..5u32 {
            let p = path.clone();
            handles.push(tokio::spawn(async move {
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
    }
}
