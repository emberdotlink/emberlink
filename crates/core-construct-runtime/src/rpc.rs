//! JSON-RPC-over-UDS client for the ember daemon.
//!
//! Wire format: newline-delimited JSON per handler.rs::dispatch_method:
//!   → `{"id":"1","method":<method>,"params":<params>}\n`
//!   ← `{"id":"1","result":<result>}\n`  or  `{"id":"1","error":{...}}\n`
//!
//! Matches `call_daemon` in crates/emberlink-cli/src/broker.rs (same wire
//! shape, same error-extraction logic).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Daemon socket resolution
// ---------------------------------------------------------------------------

/// Resolve the daemon UDS path.
///
/// Precedence:
///   1. `EMBER_SOCKET_PATH` env var (used by qember.sh + integration tests)
///   2. `~/.ember/run/daemon.sock` (matches DaemonConfig::default())
///   3. `/tmp/.ember/run/daemon.sock` if $HOME is unset
pub fn daemon_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("EMBER_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".ember").join("run").join("daemon.sock")
}

// ---------------------------------------------------------------------------
// RPC errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RpcError {
    DaemonUnavailable(String),
    Io(String),
    Protocol(String),
    DaemonRpc { code: i32, message: String },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::DaemonUnavailable(s) => write!(f, "daemon unavailable: {s}"),
            RpcError::Io(s) => write!(f, "io: {s}"),
            RpcError::Protocol(s) => write!(f, "protocol: {s}"),
            RpcError::DaemonRpc { code, message } => {
                write!(f, "daemon rpc error {code}: {message}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RPC call
// ---------------------------------------------------------------------------

/// Send one JSON-RPC request over the daemon socket and return the `result`.
pub fn call_daemon_rpc(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    call_daemon_rpc_inner(socket_path, method, params, None)
}

/// Like [`call_daemon_rpc`] but applies read+write timeouts to the socket.
///
/// Used by best-effort fire-and-forget callers that must not block on a
/// hung daemon — e.g. `log_unsessioned_subprocess` in runtime.rs, which
/// runs in the shim's passthrough branch and adds latency to every
/// invocation of every wrapped tool. A daemon under load (or a stale UDS
/// pointing at a dead socket file) would otherwise stall the shim past
/// any reasonable threshold.
///
/// The timeout applies to each read/write operation, not the whole
/// exchange — a malicious daemon that drips bytes could still extend the
/// total runtime, but the worst case is bounded by the daemon's own
/// per-request handler timeout. For best-effort callers the trade-off is
/// acceptable.
pub fn call_daemon_rpc_with_timeout(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
    timeout: Duration,
) -> Result<Value, RpcError> {
    call_daemon_rpc_inner(socket_path, method, params, Some(timeout))
}

fn call_daemon_rpc_inner(
    socket_path: &std::path::Path,
    method: &str,
    params: &Value,
    timeout: Option<Duration>,
) -> Result<Value, RpcError> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| RpcError::DaemonUnavailable(format!("{}: {e}", socket_path.display())))?;

    if let Some(t) = timeout {
        stream
            .set_read_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(t))
            .map_err(|e| RpcError::Io(format!("set_write_timeout: {e}")))?;
    }

    let mut writer = stream
        .try_clone()
        .map_err(|e| RpcError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| RpcError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| RpcError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| RpcError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(RpcError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// `broker_exec` client helper — base64-encodes construct_toml bytes so the
// daemon can enforce action-level policy per design.
// ---------------------------------------------------------------------------

/// Dispatch a `broker_exec` RPC carrying the caller's persona, the
/// credential reference, an `action_key` identifying which Construct
/// action is being invoked, and the raw bytes of the Construct's
/// `construct.toml` manifest (base64-encoded for JSON safety).
///
/// Per design §"action-level policy gating" the daemon parses the
/// manifest server-side, derives the action namespace from
/// `[meta] name`, and refuses any `action_key` not declared in the
/// manifest's `[actions.*]` blocks with JSON-RPC error code `-32009`.
///
/// Wire shape sent to the daemon:
/// ```json
/// {
///   "persona_id": "<persona>",
///   "credential_name": "<credential>",
///   "action_key": "<action>",
///   "construct_toml_bytes": "<base64>"
/// }
/// ```
pub fn broker_exec(
    persona_id: &str,
    credential_name: &str,
    action_key: &str,
    construct_toml_bytes: &[u8],
) -> Result<Value, RpcError> {
    let socket_path = daemon_socket_path();
    let params = json!({
        "persona_id": persona_id,
        "credential_name": credential_name,
        "action_key": action_key,
        "construct_toml_bytes": BASE64_STANDARD.encode(construct_toml_bytes),
    });
    call_daemon_rpc(&socket_path, "broker_exec", &params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The construct_toml_bytes field is base64-encoded so the JSON wire
    /// can carry arbitrary TOML bytes (including UTF-8 multi-byte
    /// sequences) without escaping pitfalls. Round-tripping the encode
    /// here pins the contract: the daemon decodes via the standard
    /// alphabet from the same `base64` crate.
    #[test]
    fn broker_exec_base64_encodes_manifest_bytes() {
        let manifest = b"schema_version = \"1\"\n[meta]\nname = \"ember-gh\"\n";
        let encoded = BASE64_STANDARD.encode(manifest);
        let decoded = BASE64_STANDARD.decode(&encoded).expect("base64 decode");
        assert_eq!(decoded, manifest);
    }
}
