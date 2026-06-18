//! Unix socket transport for connecting to the ember daemon.
//!
//! Provides a synchronous client over a JSON-lines Unix socket protocol.
//! Each request is a JSON object terminated by `\n`; each response is a
//! JSON object terminated by `\n`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wire types (mirrored from ember-daemon — will move to shared crate later)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Request {
    id: String,
    method: String,
    params: serde_json::Value,
}

#[derive(Deserialize)]
#[allow(dead_code)] // retained as a typed shape for test deserialization
struct Response {
    id: String,
    result: Option<serde_json::Value>,
    error: Option<ErrorPayload>,
}

#[derive(Deserialize)]
struct ErrorPayload {
    code: i32,
    message: String,
}

/// A generic envelope we use to distinguish responses (have `id`) from
/// server-initiated notifications (have `method`, no `id`).
#[derive(Deserialize)]
struct AnyMessage {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<ErrorPayload>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during socket transport operations.
#[derive(Debug)]
pub enum TransportError {
    /// Connection or read/write failure.
    Io(std::io::Error),
    /// Unexpected response format (missing fields, wrong shape, etc.).
    Protocol(String),
    /// Daemon returned an error in the response envelope.
    DaemonError { code: i32, message: String },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "I/O error: {e}"),
            TransportError::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            TransportError::DaemonError { code, message } => {
                write!(f, "Daemon error {code}: {message}")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Synchronous Unix socket client for the ember daemon.
pub struct SocketTransport {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl SocketTransport {
    /// Connect to the daemon at the given socket path.
    pub fn connect(path: &Path) -> Result<Self, TransportError> {
        let stream = UnixStream::connect(path)?;
        let writer = stream.try_clone()?;
        let reader = BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    /// Send a request and wait for the matching response.
    ///
    /// Auto-generates a unique request ID. Returns the `result` field on
    /// success, or a `TransportError` if the daemon returned an error or the
    /// response was malformed.
    pub fn send(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed).to_string();

        let req = Request {
            id: id.clone(),
            method: method.to_string(),
            params,
        };

        let mut line = serde_json::to_string(&req)
            .map_err(|e| TransportError::Protocol(format!("Failed to serialize request: {e}")))?;
        line.push('\n');

        self.writer.write_all(line.as_bytes())?;

        // Read lines until we see a response matching our request id. Lines
        // that look like server-initiated notifications (have `method`, no
        // `id`) are silently dropped — the synchronous transport doesn't
        // dispatch notifications. Callers that need notifications should use
        // the async client in `async_client.rs` instead.
        loop {
            let mut response_line = String::new();
            self.reader.read_line(&mut response_line)?;

            if response_line.is_empty() {
                return Err(TransportError::Protocol(
                    "Connection closed before response".to_string(),
                ));
            }

            let trimmed = response_line.trim_end();
            let msg: AnyMessage = serde_json::from_str(trimmed)
                .map_err(|e| TransportError::Protocol(format!("Failed to parse message: {e}")))?;

            // Notification: no id, has method. Skip and keep reading.
            if msg.id.is_none() && msg.method.is_some() {
                continue;
            }

            let resp_id = msg.id.unwrap_or_default();
            if resp_id != id {
                // A stray response for a different id (shouldn't happen on a
                // single-threaded sync client, but guard anyway).
                return Err(TransportError::Protocol(format!(
                    "Response ID mismatch: expected {id}, got {resp_id}"
                )));
            }

            if let Some(err) = msg.error {
                return Err(TransportError::DaemonError {
                    code: err.code,
                    message: err.message,
                });
            }

            return msg.result.ok_or_else(|| {
                TransportError::Protocol("Response has neither result nor error".to_string())
            });
        }
    }

    /// Send a ping and return true if the daemon responds with pong.
    pub fn ping(&mut self) -> Result<bool, TransportError> {
        let result = self.send("ping", serde_json::Value::Null)?;
        let pong = result
            .as_str()
            .map(|s| s == "pong")
            .unwrap_or_else(|| result.get("status").and_then(|v| v.as_str()) == Some("pong"));
        Ok(pong)
    }

    /// Request a grant from the daemon.
    pub fn request_grant(
        &mut self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<serde_json::Value, TransportError> {
        let mut params = serde_json::json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
            "scope": scope,
        });
        if let Some(ttl) = ttl_secs {
            params["ttl_secs"] = serde_json::json!(ttl);
        }
        self.send("request_grant", params)
    }

    /// Use a previously granted credential.
    pub fn use_credential(
        &mut self,
        persona_id: &str,
        credential_name: &str,
    ) -> Result<serde_json::Value, TransportError> {
        let params = serde_json::json!({
            "persona_id": persona_id,
            "credential_name": credential_name,
        });
        self.send("use_credential", params)
    }

    /// Request access to a resource through the policy engine.
    pub fn request_access(
        &mut self,
        persona_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<serde_json::Value, TransportError> {
        let params = serde_json::json!({
            "persona_id": persona_id,
            "action": action,
            "resource": resource,
        });
        self.send("request_access", params)
    }
}

/// Map a [`TransportError`] onto the agent runtime's minimal
/// [`crate::runtime::DaemonClientError`]. I/O failures surface as
/// `Unavailable`; protocol and daemon-side errors collapse to `Daemon`
/// so raw server text never reaches the calling agent.
fn map_transport_error(e: TransportError) -> crate::runtime::DaemonClientError {
    tracing::debug!(error = %e, "daemon call failed");
    match e {
        TransportError::Io(_) => crate::runtime::DaemonClientError::Unavailable,
        TransportError::Protocol(_) | TransportError::DaemonError { .. } => {
            crate::runtime::DaemonClientError::Daemon
        }
    }
}

/// Adapt [`SocketTransport`] to the [`DaemonClient`] trait consumed by the
/// agent runtime. Keeps the transport's richer error enum internal: the
/// agent runtime only needs to know "unreachable" vs "daemon said no" to
/// decide how to respond to its caller without leaking daemon internals.
impl crate::runtime::DaemonClient for SocketTransport {
    fn request_access(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, crate::runtime::DaemonClientError> {
        self.send("request_access", params.clone())
            .map_err(map_transport_error)
    }

    fn list_grants(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, crate::runtime::DaemonClientError> {
        self.send("list_grants", params.clone())
            .map_err(map_transport_error)
    }

    fn grant_status(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, crate::runtime::DaemonClientError> {
        self.send("grant_status", params.clone())
            .map_err(map_transport_error)
    }

    fn use_credential(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, crate::runtime::DaemonClientError> {
        self.send("use_credential", params.clone())
            .map_err(map_transport_error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Request serialization ---

    #[test]
    fn request_serializes_with_id_method_params() {
        let req = Request {
            id: "42".to_string(),
            method: "ping".to_string(),
            params: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "42");
        assert_eq!(parsed["method"], "ping");
        assert!(parsed["params"].is_null());
    }

    #[test]
    fn request_with_object_params_serializes() {
        let req = Request {
            id: "1".to_string(),
            method: "request_grant".to_string(),
            params: serde_json::json!({"scope": "read", "ttl_secs": 3600}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["params"]["scope"], "read");
        assert_eq!(parsed["params"]["ttl_secs"], 3600);
    }

    // --- Response parsing ---

    #[test]
    fn response_with_result_deserializes() {
        let json = r#"{"id":"1","result":{"status":"ok"},"error":null}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "1");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["status"], "ok");
    }

    #[test]
    fn response_with_error_deserializes() {
        let json =
            r#"{"id":"2","result":null,"error":{"code":-32601,"message":"Method not found"}}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "2");
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[test]
    fn response_without_error_field_deserializes() {
        // Daemon may omit the error field entirely when there's no error.
        let json = r#"{"id":"3","result":"pong"}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "3");
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), "pong");
    }

    // --- TransportError display ---

    #[test]
    fn transport_error_display_io() {
        let e = TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(e.to_string().contains("I/O error"));
    }

    #[test]
    fn transport_error_display_protocol() {
        let e = TransportError::Protocol("unexpected EOF".to_string());
        assert!(e.to_string().contains("Protocol error"));
        assert!(e.to_string().contains("unexpected EOF"));
    }

    #[test]
    fn transport_error_display_daemon_error() {
        let e = TransportError::DaemonError {
            code: 403,
            message: "Forbidden".to_string(),
        };
        assert!(e.to_string().contains("403"));
        assert!(e.to_string().contains("Forbidden"));
    }

    // --- Integration test: mock socket server ---

    #[test]
    fn ping_pong_via_mock_socket() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket_path = std::env::temp_dir().join(format!(
            "ember-test-{}.sock",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));

        // Clean up any leftover socket from a previous run.
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("bind mock socket");
        let server_path = socket_path.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut writer = stream.try_clone().expect("clone");
            let reader = BufReader::new(stream);
            // Intentionally single-shot: the loop body breaks after the
            // first request (see `break // one request only` below).
            #[allow(clippy::never_loop)]
            for line in reader.lines() {
                let line = line.expect("read line");
                let req: serde_json::Value = serde_json::from_str(&line).expect("parse request");
                let id = req["id"].as_str().unwrap_or("0").to_string();
                let method = req["method"].as_str().unwrap_or("").to_string();
                let result = if method == "ping" {
                    serde_json::json!("pong")
                } else {
                    serde_json::json!({"error": "unknown method"})
                };
                let resp = serde_json::json!({"id": id, "result": result});
                let mut resp_line = serde_json::to_string(&resp).unwrap();
                resp_line.push('\n');
                writer.write_all(resp_line.as_bytes()).expect("write");
                break; // one request only
            }
            let _ = std::fs::remove_file(&server_path);
        });

        let mut transport = SocketTransport::connect(&socket_path).expect("connect to mock socket");
        let is_pong = transport.ping().expect("ping");
        assert!(is_pong, "expected pong response");

        server.join().expect("server thread panicked");
    }
}
