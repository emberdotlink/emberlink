//! `ember trust list` — call the daemon's `trust.list` JSON-RPC and
//! render the operator-visible trust-set snapshot.
//!
//! Per design §Component 2 / implementation-note-295. Read-only
//! query (`AuthorityClass::ConnectOnly` on the daemon side); the
//! returned snapshot was assembled at startup so the CLI sees exactly
//! the trust set the daemon would verify against if a manifest reached
//! it right now.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

/// One row in the daemon's startup trust snapshot. Mirrors
/// `ember_daemon::binary_manifest::TrustRootRecord` on the wire; the
/// CLI side redefines the type instead of cross-depending on the
/// daemon crate (CLI should not link against the daemon's internals).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TrustRootView {
    pub fingerprint_hex: String,
    /// `"release"` or `"operator"` (lowercase). Stable wire form.
    pub source: String,
}

/// Decoded body of the `trust.list` RPC response. `dev_mode_active`
/// is the same flag the daemon stamps onto Receipts; surfacing it
/// alongside the roots lets the CLI render "prod" vs "dev" posture in
/// one line.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustListResponse {
    pub roots: Vec<TrustRootView>,
    pub dev_mode_active: bool,
}

/// Errors surfaced by [`fetch_trust_list`].
#[derive(Debug, thiserror::Error)]
pub enum TrustListError {
    #[error("daemon socket at {socket} unreachable: {source}")]
    DaemonUnavailable {
        socket: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("daemon RPC error {code}: {message}")]
    DaemonRpc { code: i32, message: String },
    #[error("invalid daemon response: {0}")]
    Protocol(String),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Call `trust.list` against the daemon socket and parse the response.
/// Pure I/O — no rendering. Tests use it via the parse helpers below.
pub fn fetch_trust_list(socket_path: &Path) -> Result<TrustListResponse, TrustListError> {
    let response = call_daemon(socket_path, "trust.list", &Value::Object(Default::default()))?;
    parse_trust_list_response(&response)
}

/// Parse the daemon's `trust.list` response body into a typed struct.
/// Separated from the socket I/O so tests can exercise the parsing
/// path against a fixture without needing a live daemon.
pub fn parse_trust_list_response(body: &Value) -> Result<TrustListResponse, TrustListError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        TrustListError::Protocol(format!("decode trust.list response: {e}"))
    })
}

/// Render the response as a human-readable block (line-per-root, with
/// the posture line above). Mirrors
/// `ember_daemon::trust::introspect::render_trust_list_human`; kept
/// CLI-side so the daemon doesn't grow a string-formatting surface for
/// every operator-display field.
pub fn render_human(resp: &TrustListResponse) -> String {
    let mut out = String::new();
    if resp.roots.is_empty() {
        out.push_str(
            "no trust roots loaded — daemon was opened without startup verification \
             (the daemon may have started before the manifest path was set, or it is \
             running in an in-memory test mode)\n",
        );
        return out;
    }
    let posture = if resp.dev_mode_active { "dev" } else { "prod" };
    out.push_str(&format!(
        "Trust posture: {} ({} root{}, dev_mode_active = {})\n",
        posture,
        resp.roots.len(),
        if resp.roots.len() == 1 { "" } else { "s" },
        resp.dev_mode_active,
    ));
    for (i, r) in resp.roots.iter().enumerate() {
        let source_label = match r.source.as_str() {
            "release" => "release ",
            "operator" => "operator",
            other => other,
        };
        out.push_str(&format!("  [{i}] {source_label}  {}\n", r.fingerprint_hex));
    }
    out
}

/// Entry point for the `ember trust list` subcommand. Calls the daemon,
/// prints the rendered block to stdout. Returns a non-zero exit code on
/// any error (socket unreachable, RPC failure, malformed response).
pub fn run(socket_path: &Path) -> i32 {
    match fetch_trust_list(socket_path) {
        Ok(resp) => {
            print!("{}", render_human(&resp));
            0
        }
        Err(TrustListError::DaemonUnavailable { socket, source }) => {
            eprintln!(
                "ember trust list: daemon socket at {} unreachable ({source}). \
                 Is emberd running? (ember daemon status)",
                socket.display()
            );
            2
        }
        Err(err) => {
            eprintln!("ember trust list: {err}");
            2
        }
    }
}

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, TrustListError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        TrustListError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| TrustListError::Io(format!("clone socket: {e}")))?;
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
        .map_err(|e| TrustListError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| TrustListError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| TrustListError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(TrustListError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decodes_release_plus_operator() {
        let body = json!({
            "roots": [
                {"fingerprint_hex": "aa".repeat(32), "source": "release"},
                {"fingerprint_hex": "bb".repeat(32), "source": "operator"},
            ],
            "dev_mode_active": true,
        });
        let resp = parse_trust_list_response(&body).unwrap();
        assert_eq!(resp.roots.len(), 2);
        assert_eq!(resp.roots[0].source, "release");
        assert_eq!(resp.roots[1].source, "operator");
        assert!(resp.dev_mode_active);
    }

    #[test]
    fn parse_decodes_empty_set() {
        let body = json!({"roots": [], "dev_mode_active": false});
        let resp = parse_trust_list_response(&body).unwrap();
        assert!(resp.roots.is_empty());
        assert!(!resp.dev_mode_active);
    }

    #[test]
    fn parse_rejects_missing_fields() {
        let body = json!({"roots": []}); // missing dev_mode_active
        let err = parse_trust_list_response(&body).unwrap_err();
        match err {
            TrustListError::Protocol(_) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn render_empty_set_explains_why() {
        let resp = TrustListResponse {
            roots: vec![],
            dev_mode_active: false,
        };
        let out = render_human(&resp);
        assert!(out.contains("no trust roots loaded"));
    }

    #[test]
    fn render_prod_posture_one_release_root() {
        let resp = TrustListResponse {
            roots: vec![TrustRootView {
                fingerprint_hex: "aa".repeat(32),
                source: "release".to_string(),
            }],
            dev_mode_active: false,
        };
        let out = render_human(&resp);
        assert!(out.contains("Trust posture: prod (1 root"));
        assert!(out.contains("dev_mode_active = false"));
        assert!(out.contains("release "));
    }

    #[test]
    fn render_dev_posture_release_plus_operator() {
        let resp = TrustListResponse {
            roots: vec![
                TrustRootView {
                    fingerprint_hex: "aa".repeat(32),
                    source: "release".to_string(),
                },
                TrustRootView {
                    fingerprint_hex: "bb".repeat(32),
                    source: "operator".to_string(),
                },
            ],
            dev_mode_active: true,
        };
        let out = render_human(&resp);
        assert!(out.contains("Trust posture: dev (2 roots"));
        assert!(out.contains("dev_mode_active = true"));
    }
}
