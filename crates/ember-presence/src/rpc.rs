//! Plain daemon UDS JSON-RPC client + the shared RPC error type.
//!
//! This is the *unadorned* transport: connect, send one newline-delimited
//! JSON-RPC request, read one response. It deliberately does **not** attach a
//! cached operator presence token — that is an `emberlink-cli` concern (the
//! token type lives in `ember-daemon`, which this crate must not depend on).
//! Callers that want token caching wrap [`daemon_rpc_once`] in their own
//! function.
//!
//! CLASSIFICATION: PUBLIC

use std::path::Path;

/// Errors a daemon JSON-RPC call can surface.
#[derive(Debug)]
pub enum DaemonRpcError {
    /// The daemon socket is absent or refused the connection (daemon down).
    Unavailable(std::io::Error),
    /// The daemon socket exists but this process was denied access
    /// (EACCES/EPERM on connect).
    PermissionDenied(std::io::Error),
    /// A lower-level I/O failure on an otherwise-reachable socket.
    Io(std::io::Error),
    /// The response was not well-formed JSON-RPC, or a payload failed to parse.
    Protocol(String),
    /// The daemon returned a JSON-RPC error object.
    Rpc { code: i32, message: String },
}

impl std::fmt::Display for DaemonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonRpcError::Unavailable(e) => write!(f, "daemon unavailable: {e}"),
            DaemonRpcError::PermissionDenied(e) => write!(f, "permission denied: {e}"),
            DaemonRpcError::Io(e) => write!(f, "io error: {e}"),
            DaemonRpcError::Protocol(m) => write!(f, "protocol error: {m}"),
            DaemonRpcError::Rpc { code, message } => {
                write!(f, "daemon error (code {code}): {message}")
            }
        }
    }
}

impl std::error::Error for DaemonRpcError {}

/// Read timeout for daemon RPC responses. Prevents the client from blocking
/// forever when the daemon accepts a connection but never responds (hang,
/// crash-after-accept, slow status handler under load).
const RPC_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn classify_connect_error(e: std::io::Error) -> DaemonRpcError {
    match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            DaemonRpcError::Unavailable(e)
        }
        std::io::ErrorKind::PermissionDenied => DaemonRpcError::PermissionDenied(e),
        _ if matches!(e.raw_os_error(), Some(1 | 13)) => DaemonRpcError::PermissionDenied(e),
        _ => DaemonRpcError::Io(e),
    }
}

/// Single-shot JSON-RPC call over the daemon's Unix socket.
///
/// Connects, writes one `{"id","method","params"}` line, reads one response
/// line, and returns the `result` value (or a [`DaemonRpcError`]). No presence
/// token is attached — see the module docs.
pub fn daemon_rpc_once(
    socket_path: &Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    use std::io::{BufRead, BufReader, Write as _};

    let stream =
        std::os::unix::net::UnixStream::connect(socket_path).map_err(classify_connect_error)?;

    let _ = stream.set_read_timeout(Some(RPC_READ_TIMEOUT));

    let mut writer = stream.try_clone().map_err(DaemonRpcError::Io)?;
    let mut reader = BufReader::new(stream);

    let request = serde_json::json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize daemon request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(DaemonRpcError::Io)?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(DaemonRpcError::Io)?;

    if response_line.is_empty() {
        return Err(DaemonRpcError::Protocol(
            "daemon closed the connection without responding (EOF)".to_string(),
        ));
    }

    let response: serde_json::Value = serde_json::from_str(response_line.trim())
        .map_err(|e| DaemonRpcError::Protocol(format!("invalid daemon JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown daemon error")
            .to_string();
        return Err(DaemonRpcError::Rpc { code, message });
    }

    Ok(response
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

/// Extract the structured `reason` field from a daemon authority-error message
/// (the daemon encodes `{"reason":"missing", ...}` as the JSON-RPC error
/// message string). Returns `None` when the message is not JSON or has no
/// `reason`.
pub fn authority_error_reason(message: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_error_reason_parses_structured_message() {
        assert_eq!(
            authority_error_reason(r#"{"reason":"missing","class":"session-runtime"}"#).as_deref(),
            Some("missing")
        );
    }

    #[test]
    fn authority_error_reason_none_for_plain_message() {
        assert_eq!(authority_error_reason("session is locked"), None);
    }

    #[test]
    fn classify_connect_not_found_is_unavailable() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        assert!(matches!(
            classify_connect_error(err),
            DaemonRpcError::Unavailable(_)
        ));
    }

    #[test]
    fn classify_connect_connection_refused_is_unavailable() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(matches!(
            classify_connect_error(err),
            DaemonRpcError::Unavailable(_)
        ));
    }

    #[test]
    fn classify_connect_permission_denied_is_permission_denied() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        assert!(matches!(
            classify_connect_error(err),
            DaemonRpcError::PermissionDenied(_)
        ));
    }

    #[test]
    fn classify_connect_other_is_io() {
        let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        assert!(matches!(classify_connect_error(err), DaemonRpcError::Io(_)));
    }

    #[test]
    fn daemon_rpc_once_returns_unavailable_for_missing_socket() {
        let result = daemon_rpc_once(
            Path::new("/tmp/nonexistent-ember-test-socket.sock"),
            "ping",
            &serde_json::Value::Null,
        );
        assert!(matches!(result, Err(DaemonRpcError::Unavailable(_))));
    }

    #[test]
    fn daemon_rpc_once_detects_eof_on_closed_connection() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).expect("bind");

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || daemon_rpc_once(&sock, "status", &serde_json::Value::Null)
        });

        let (stream, _) = listener.accept().expect("accept");
        let mut reader = std::io::BufReader::new(&stream);
        let mut req_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut req_line).expect("read request");
        drop(stream);

        let result = handle.join().expect("join");
        match result {
            Err(DaemonRpcError::Protocol(msg)) => {
                assert!(msg.contains("EOF"), "expected EOF message, got: {msg}");
            }
            other => panic!("expected Protocol(EOF), got: {other:?}"),
        }
    }

    #[test]
    fn daemon_rpc_once_parses_valid_rpc_error() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).expect("bind");

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || daemon_rpc_once(&sock, "bad_method", &serde_json::Value::Null)
        });

        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
        let mut req_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut req_line).expect("read request");
        let response = r#"{"id":"1","error":{"code":-32601,"message":"method not found"}}"#;
        writeln!(stream, "{response}").expect("write response");

        let result = handle.join().expect("join");
        match result {
            Err(DaemonRpcError::Rpc { code, message }) => {
                assert_eq!(code, -32601);
                assert_eq!(message, "method not found");
            }
            other => panic!("expected Rpc error, got: {other:?}"),
        }
    }

    #[test]
    fn daemon_rpc_once_returns_result_on_success() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).expect("bind");

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || daemon_rpc_once(&sock, "ping", &serde_json::Value::Null)
        });

        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
        let mut req_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut req_line).expect("read request");
        let response = r#"{"id":"1","result":{"pong":true}}"#;
        writeln!(stream, "{response}").expect("write response");

        let result = handle.join().expect("join").expect("should succeed");
        assert_eq!(result, serde_json::json!({"pong": true}));
    }

    #[test]
    fn daemon_rpc_once_handles_malformed_json_response() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).expect("bind");

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || daemon_rpc_once(&sock, "status", &serde_json::Value::Null)
        });

        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
        let mut req_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut req_line).expect("read request");
        writeln!(stream, "not valid json at all").expect("write response");

        let result = handle.join().expect("join");
        match result {
            Err(DaemonRpcError::Protocol(msg)) => {
                assert!(
                    msg.contains("invalid daemon JSON-RPC response"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }
}
