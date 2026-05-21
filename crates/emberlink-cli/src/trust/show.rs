//! `ember trust show <root-id>` — drill-down lookup of one trust root by
//! full fingerprint or unique hex prefix.
//!
//! Per design §Component 2 Phase 2. Pairs with the daemon's
//! `trust.show` JSON-RPC. Read-only operation
//! (`AuthorityClass::ConnectOnly` on the daemon side).
//!
//! Anchor: `trust_show_landed`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

/// Decoded body of the `trust.show` RPC response. Fields mirror the
/// daemon's `handle_trust_show` output. `posture` is the same
/// `dev`/`prod` derivation that `trust.list` surfaces alongside the
/// roots; including it here lets `show` render a self-contained block
/// without a second RPC call.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TrustRootShowResponse {
    pub fingerprint_hex: String,
    /// `"release"` or `"operator"` (lowercase). Stable wire form.
    pub source: String,
    /// `"prod"` or `"dev"`. Stable wire form.
    pub posture: String,
}

/// Errors surfaced by [`fetch_trust_show`].
#[derive(Debug, thiserror::Error)]
pub enum TrustShowError {
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

/// Call `trust.show` against the daemon socket and parse the response.
pub fn fetch_trust_show(
    socket_path: &Path,
    root_id: &str,
) -> Result<TrustRootShowResponse, TrustShowError> {
    let response = call_daemon(socket_path, "trust.show", &json!({"root_id": root_id}))?;
    parse_trust_show_response(&response)
}

/// Parse the daemon's `trust.show` response body into a typed struct.
pub fn parse_trust_show_response(body: &Value) -> Result<TrustRootShowResponse, TrustShowError> {
    serde_json::from_value(body.clone())
        .map_err(|e| TrustShowError::Protocol(format!("decode trust.show response: {e}")))
}

/// Render the response as a human-readable detail block — a vertical
/// `key: value` listing that complements the tabular `trust list`
/// output. Mirrors `ember_daemon::trust::introspect::render_trust_show_human`.
pub fn render_human(resp: &TrustRootShowResponse) -> String {
    format!(
        "Trust root:\n  Fingerprint: {fp}\n  Source:      {src}\n  Posture:     {posture}\n",
        fp = resp.fingerprint_hex,
        src = resp.source,
        posture = resp.posture,
    )
}

/// Entry point for the `ember trust show <root-id>` subcommand.
pub fn run(socket_path: &Path, root_id: &str) -> i32 {
    match fetch_trust_show(socket_path, root_id) {
        Ok(resp) => {
            print!("{}", render_human(&resp));
            0
        }
        Err(TrustShowError::DaemonUnavailable { socket, source }) => {
            eprintln!(
                "ember trust show: {}",
                crate::format_daemon_unavailable(&socket, &source)
            );
            2
        }
        Err(TrustShowError::DaemonRpc { code, message }) => {
            // Surface daemon-side validation errors directly. The daemon
            // emits structured `trust_root_not_found` /
            // `trust_root_prefix_ambiguous` payloads that read fine as-is.
            eprintln!("ember trust show: {message} (code {code})");
            1
        }
        Err(err) => {
            eprintln!("ember trust show: {err}");
            2
        }
    }
}

fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, TrustShowError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        TrustShowError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| TrustShowError::Io(format!("clone socket: {e}")))?;
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
        .map_err(|e| TrustShowError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| TrustShowError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| TrustShowError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(TrustShowError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decodes_release_root() {
        let body = json!({
            "fingerprint_hex": "aa".repeat(32),
            "source": "release",
            "posture": "prod",
        });
        let resp = parse_trust_show_response(&body).unwrap();
        assert_eq!(resp.source, "release");
        assert_eq!(resp.posture, "prod");
        assert_eq!(resp.fingerprint_hex, "aa".repeat(32));
    }

    #[test]
    fn parse_decodes_operator_dev_root() {
        let body = json!({
            "fingerprint_hex": "bb".repeat(32),
            "source": "operator",
            "posture": "dev",
        });
        let resp = parse_trust_show_response(&body).unwrap();
        assert_eq!(resp.source, "operator");
        assert_eq!(resp.posture, "dev");
    }

    #[test]
    fn parse_rejects_missing_field() {
        let body = json!({"fingerprint_hex": "aa".repeat(32), "source": "release"});
        let err = parse_trust_show_response(&body).unwrap_err();
        match err {
            TrustShowError::Protocol(_) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn render_human_includes_all_three_fields() {
        let resp = TrustRootShowResponse {
            fingerprint_hex: "aa".repeat(32),
            source: "release".to_string(),
            posture: "prod".to_string(),
        };
        let out = render_human(&resp);
        assert!(out.contains("Trust root:"));
        assert!(out.contains("Fingerprint:"));
        assert!(out.contains("Source:"));
        assert!(out.contains("Posture:"));
        assert!(out.contains(&"aa".repeat(32)));
        assert!(out.contains("release"));
        assert!(out.contains("prod"));
    }
}
