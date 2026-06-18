//! `ember trust list` — call the daemon's `trust.list` JSON-RPC and
//! render the operator-visible trust-set snapshot.
//!
//! Per ADR 162 §Component 2 / META-TRUST-LIST-SHOW-EXPLAIN. Read-only
//! query (`AuthorityClass::ConnectOnly` on the daemon side); the
//! returned snapshot was assembled at startup so the CLI sees exactly
//! the trust set the daemon would verify against if a manifest reached
//! it right now.

use std::io::{BufRead, BufReader, IsTerminal as _, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One row in the daemon's startup trust snapshot. Mirrors
/// `ember_daemon::binary_manifest::TrustRootRecord` on the wire; the
/// CLI side redefines the type instead of cross-depending on the
/// daemon crate (CLI should not link against the daemon's internals).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustRootView {
    pub fingerprint_hex: String,
    /// `"release"` or `"operator"` (lowercase). Stable wire form.
    pub source: String,
}

/// Decoded body of the `trust.list` RPC response. `dev_mode_active`
/// is the same flag the daemon stamps onto Receipts; surfacing it
/// alongside the roots lets the CLI render "prod" vs "dev" posture in
/// one line.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Clone, Copy)]
struct TrustRenderTheme {
    color: bool,
}

impl TrustRenderTheme {
    fn current() -> Self {
        Self {
            color: std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal(),
        }
    }

    fn title(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1m{text}\x1b[0m")
    }

    fn heading(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1m\x1b[38;2;217;106;29m{text}\x1b[0m")
    }

    fn table_heading(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1m{text}\x1b[0m")
    }

    fn command(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1m{text}\x1b[0m")
    }

    fn badge(self, text: &str) -> String {
        let code = match text.trim().to_ascii_lowercase().as_str() {
            "prod" | "release" | "operator" => Some("\x1b[32m"),
            "dev" => Some("\x1b[33m"),
            _ => None,
        };
        match (self.color, code) {
            (true, Some(code)) => format!("\x1b[1m{code}{text}\x1b[0m"),
            _ => self.command(text),
        }
    }
}

/// Call `trust.list` against the daemon socket and parse the response.
/// Pure I/O — no rendering. Tests use it via the parse helpers below.
pub fn fetch_trust_list(socket_path: &Path) -> Result<TrustListResponse, TrustListError> {
    let response = call_daemon(
        socket_path,
        "trust.list",
        &Value::Object(Default::default()),
    )?;
    parse_trust_list_response(&response)
}

/// Parse the daemon's `trust.list` response body into a typed struct.
/// Separated from the socket I/O so tests can exercise the parsing
/// path against a fixture without needing a live daemon.
pub fn parse_trust_list_response(body: &Value) -> Result<TrustListResponse, TrustListError> {
    serde_json::from_value(body.clone())
        .map_err(|e| TrustListError::Protocol(format!("decode trust.list response: {e}")))
}

/// Render the response as a human-readable block (line-per-root, with
/// the posture line above). Mirrors
/// `ember_daemon::trust::introspect::render_trust_list_human`; kept
/// CLI-side so the daemon doesn't grow a string-formatting surface for
/// every operator-display field.
pub fn render_human(resp: &TrustListResponse) -> String {
    let theme = TrustRenderTheme::current();
    let mut out = String::new();
    if resp.roots.is_empty() {
        out.push_str(&theme.title("Trust roots"));
        out.push('\n');
        out.push_str(
            "No trust roots are loaded right now; startup verification is not active on this daemon.\n\n",
        );
        out.push_str(&theme.heading("Next"));
        out.push('\n');
        out.push_str(&format!(
            "  {}\n    Inspect the current machine posture before relying on local verification\n",
            theme.command("ember doctor")
        ));
        out.push_str(&format!(
            "  {}\n    Read how trust roots and receipt verification fit together\n",
            theme.command("ember explain trust")
        ));
        return out.trim_end().to_string();
    }
    let posture = if resp.dev_mode_active { "dev" } else { "prod" };
    out.push_str(&theme.title("Trust roots"));
    out.push('\n');
    out.push_str(&format!(
        "{} posture with {} active.\n",
        theme.badge(posture),
        if resp.roots.len() == 1 {
            "1 trust root".to_string()
        } else {
            format!("{} trust roots", resp.roots.len())
        }
    ));
    out.push('\n');
    out.push_str(&theme.heading("Current set"));
    out.push('\n');
    out.push_str(&format!(
        "  {:<12} {}\n",
        theme.table_heading("SOURCE"),
        theme.table_heading("FINGERPRINT")
    ));
    for (i, r) in resp.roots.iter().enumerate() {
        let _ = i;
        out.push_str(&format!(
            "  {:<12} {}\n",
            theme.badge(&r.source),
            r.fingerprint_hex
        ));
    }
    out.push('\n');
    out.push_str(&theme.heading("Inspect"));
    out.push('\n');
    out.push_str(&format!(
        "  {}\n    Drill into one root by full fingerprint or unique prefix\n",
        theme.command("ember trust show <fingerprint>")
    ));
    out.push_str(&format!(
        "  {}\n    Verify a signed witness against the active trust roots\n",
        theme.command("ember receipt verify <id>")
    ));
    out.trim_end().to_string()
}

/// Render the typed daemon response as stable machine-readable JSON.
pub fn render_json(resp: &TrustListResponse) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(resp)
}

/// Entry point for the `ember trust list` subcommand. Calls the daemon,
/// prints the rendered block to stdout. Returns a non-zero exit code on
/// any error (socket unreachable, RPC failure, malformed response).
pub fn run(socket_path: &Path, json_output: bool) -> i32 {
    match fetch_trust_list(socket_path) {
        Ok(resp) => {
            if json_output {
                match render_json(&resp) {
                    Ok(body) => println!("{body}"),
                    Err(err) => {
                        eprintln!("ember trust list: encode JSON output: {err}");
                        return 2;
                    }
                }
            } else {
                println!("{}", render_human(&resp));
            }
            0
        }
        Err(TrustListError::DaemonUnavailable { socket, source }) => {
            eprintln!(
                "ember trust list: {}",
                crate::format_daemon_unavailable(&socket, &source)
            );
            2
        }
        Err(err) => {
            eprintln!("ember trust list: {err}");
            2
        }
    }
}

fn call_daemon(socket_path: &Path, method: &str, params: &Value) -> Result<Value, TrustListError> {
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
        assert!(out.contains("Trust roots"));
        assert!(out.contains("No trust roots are loaded"));
        assert!(out.contains("ember doctor"));
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
        assert!(out.contains("prod posture with 1 trust root active."));
        assert!(out.contains("Current set"));
        assert!(out.contains("release"));
        assert!(out.contains("ember trust show <fingerprint>"));
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
        assert!(out.contains("dev posture with 2 trust roots active."));
        assert!(out.contains("release"));
        assert!(out.contains("operator"));
        assert!(out.contains(&"aa".repeat(32)));
        assert!(out.contains(&"bb".repeat(32)));
    }

    #[test]
    fn render_json_preserves_typed_response() {
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
        let json: Value = serde_json::from_str(&render_json(&resp).unwrap()).unwrap();
        assert_eq!(json["dev_mode_active"], true);
        assert_eq!(json["roots"][0]["source"], "release");
        assert_eq!(json["roots"][1]["fingerprint_hex"], "bb".repeat(32));
    }
}
