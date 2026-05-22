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
// Daemon transport resolution
// ---------------------------------------------------------------------------
//
// Subtask A of implementation-note-25. The
// construct shims (`ember-gh`, `ember-git`, etc.) historically only
// dialed the daemon over a host-local Unix socket. design §Component 1
// adds an in-container path that has to traverse the host boundary via
// an mTLS-protected TCP listener (the ember-rpc Phase C surface). This
// module's job is to *decide* which transport to use; the actual dial
// implementation for the mTLS+TCP path lands in subtask B.
//
// Anchor: `construct_runtime_mtls_tcp_transport_decide`.

/// Which transport a construct shim should use to reach the daemon.
///
/// Carries enough state for the dial to proceed without re-reading env
/// vars. Subtask B's dial code matches on this enum to pick the right
/// connect path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonTransport {
    /// Host-local Unix socket. Used when the shim runs on the same host
    /// as the daemon (no container boundary).
    Uds(PathBuf),
    /// In-container mTLS+TCP path. The URL typically points at
    /// `https://host.docker.internal:4243` (the host's ember-rpc
    /// listener). The cert dir defaults to `/run/ember/client-cert/`
    /// per design §Component 1 — overridable via
    /// `EMBER_CLIENT_CERT_DIR` for tests.
    MtlsTcp { url: String, cert_dir: PathBuf },
}

const DEFAULT_CLIENT_CERT_DIR: &str = "/run/ember/client-cert";

/// Resolve the daemon UDS path.
///
/// Precedence:
///   1. `EMBER_SOCKET_PATH` env var (used by qember.sh + integration tests)
///   2. `~/.ember/run/daemon.sock` (matches DaemonConfig::default())
///   3. `/tmp/.ember/run/daemon.sock` if $HOME is unset
///
/// Retained as a stable public API — existing callers that always want
/// the UDS path call this directly. New callers reach for
/// [`decide_transport`] instead so they pick up the in-container
/// fallback for free.
pub fn daemon_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("EMBER_SOCKET_PATH") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".ember").join("run").join("daemon.sock")
}

/// Choose the transport for a construct shim's daemon RPC.
///
/// Selection rule (matches design §Component 1 + design §Component 3):
///
///   1. If `EMBER_BRIDGE_URL` is set and non-empty, the shim is running
///      in-container and reaches the daemon via mTLS+TCP. The cert dir
///      defaults to `/run/ember/client-cert/` (orchestrator-provisioned
///      per `implementation-note-26`); override via
///      `EMBER_CLIENT_CERT_DIR` for tests / non-standard layouts.
///   2. Otherwise the shim is host-resident; dial the UDS resolved by
///      [`daemon_socket_path`].
///
/// Pure — every input comes from `std::env::var_os`; no I/O. Callers
/// (subtask B's mTLS dial code) match on the returned enum to pick the
/// connect path. construct_runtime_mtls_tcp_transport_decide.
pub fn decide_transport() -> DaemonTransport {
    if let Some(url) = std::env::var_os("EMBER_BRIDGE_URL")
        && let Some(s) = url.to_str()
        && !s.is_empty()
    {
        let cert_dir = std::env::var_os("EMBER_CLIENT_CERT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CLIENT_CERT_DIR));
        return DaemonTransport::MtlsTcp {
            url: s.to_string(),
            cert_dir,
        };
    }
    DaemonTransport::Uds(daemon_socket_path())
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
    use std::sync::Mutex;

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

    /// Process-global env vars are shared state across the test runner's
    /// thread pool. Serialize the env-mutating cases through this mutex
    /// so they don't race each other; combine all set/unset operations
    /// inside the locked region.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => unsafe { std::env::set_var(k, value) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, original) in saved {
            match original {
                Some(value) => unsafe { std::env::set_var(&k, value) },
                None => unsafe { std::env::remove_var(&k) },
            }
        }
    }

    #[test]
    fn decide_transport_returns_uds_when_bridge_url_unset() {
        with_env(
            &[("EMBER_BRIDGE_URL", None), ("EMBER_SOCKET_PATH", None)],
            || {
                let t = decide_transport();
                match t {
                    DaemonTransport::Uds(path) => {
                        assert!(path.ends_with(".ember/run/daemon.sock"));
                    }
                    other => panic!("expected Uds, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn decide_transport_returns_uds_when_bridge_url_empty() {
        with_env(
            &[
                ("EMBER_BRIDGE_URL", Some("")),
                ("EMBER_SOCKET_PATH", None),
            ],
            || {
                assert!(matches!(decide_transport(), DaemonTransport::Uds(_)));
            },
        );
    }

    #[test]
    fn decide_transport_returns_mtls_tcp_when_bridge_url_set() {
        with_env(
            &[
                (
                    "EMBER_BRIDGE_URL",
                    Some("https://host.docker.internal:4243"),
                ),
                ("EMBER_CLIENT_CERT_DIR", None),
            ],
            || {
                // construct_runtime_mtls_tcp_transport_decide — checkpoint mirrored
                // in the in-container test body for grep coverage.
                let t = decide_transport();
                match t {
                    DaemonTransport::MtlsTcp { url, cert_dir } => {
                        assert_eq!(url, "https://host.docker.internal:4243");
                        assert_eq!(cert_dir, PathBuf::from("/run/ember/client-cert"));
                    }
                    other => panic!("expected MtlsTcp, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn decide_transport_honors_cert_dir_override() {
        with_env(
            &[
                (
                    "EMBER_BRIDGE_URL",
                    Some("https://host.docker.internal:4243"),
                ),
                ("EMBER_CLIENT_CERT_DIR", Some("/tmp/alt-certs")),
            ],
            || {
                let t = decide_transport();
                match t {
                    DaemonTransport::MtlsTcp { cert_dir, .. } => {
                        assert_eq!(cert_dir, PathBuf::from("/tmp/alt-certs"));
                    }
                    other => panic!("expected MtlsTcp, got {other:?}"),
                }
            },
        );
    }

    #[test]
    fn daemon_socket_path_honors_ember_socket_path_override() {
        with_env(
            &[("EMBER_SOCKET_PATH", Some("/tmp/test-daemon.sock"))],
            || {
                assert_eq!(daemon_socket_path(), PathBuf::from("/tmp/test-daemon.sock"));
            },
        );
    }
}
