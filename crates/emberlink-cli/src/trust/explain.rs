//! `ember trust explain <artifact-path> [--sidecar <path>] [--kind <kind>]`
//! — chain-walk a signed artifact back to the trust root that verifies it.
//!
//! Per ADR 162 §Component 2 Phase 3. Pairs with the daemon's
//! `trust.explain` JSON-RPC. Supported `artifact_kind` values:
//!
//! - `binary_manifest` (default) — reads sidecar from `<artifact>.sig` or
//!   the explicit `--sidecar` path.
//! - `receipt` (META-TRUST-EXPLAIN-RECEIPT) — Receipt envelope JSON; no
//!   sidecar (the signature is inline). `--sidecar` is ignored on this
//!   kind, and the wire sidecar bytes are sent empty.
//!
//! Delegation grant chain walk lands in META-TRUST-EXPLAIN-WORKFLOW-GRANT.
//!
//! The CLI reads the artifact + (when applicable) sidecar from disk and
//! base64-encodes both for the wire. The daemon never touches a
//! filesystem path the operator supplied — it only sees raw bytes — so
//! this surface is safe to expose to any caller that can reach the
//! daemon socket.
//!
//! Sentinels: `trust_explain_landed` (binary manifest) /
//! `trust_explain_receipt_chain_walked` (Receipt envelope).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One trust-root row in the daemon's verdict response. Present only
/// when `verdict == "verified"`; the wire form is `null` for every
/// other verdict.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustRootMatch {
    pub fingerprint_hex: String,
    /// `"release"` or `"operator"` (lowercase). Stable wire form.
    pub source: String,
}

/// Decoded body of the `trust.explain` RPC response. `verdict` is a
/// stable enum-of-strings (see daemon's `handle_trust_explain` for the
/// authoritative list); `trust_root` is `Some` iff `verdict ==
/// "verified"`; `chain` is the human-readable narrative the daemon
/// renders for operator display.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustExplainResponse {
    pub verdict: String,
    #[serde(default)]
    pub trust_root: Option<TrustRootMatch>,
    pub chain: String,
}

/// Errors surfaced by [`fetch_trust_explain`].
#[derive(Debug, thiserror::Error)]
pub enum TrustExplainError {
    #[error("daemon socket at {socket} unreachable: {source}")]
    DaemonUnavailable {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("daemon RPC error {code}: {message}")]
    DaemonRpc { code: i32, message: String },
    #[error("invalid daemon response: {0}")]
    Protocol(String),
    #[error("could not read {what} at {path}: {source}")]
    ReadFile {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(String),
}

/// Read the artifact + (optionally) sidecar from disk, base64-encode
/// both, call `trust.explain`, and parse the response.
///
/// `sidecar_path = None` is the path for artifact kinds that carry the
/// signature inline (Receipt envelope, delegation grant). The wire
/// `sidecar_bytes_b64` is sent as the empty string; the daemon enforces
/// "non-empty sidecar bytes" → `sidecar_not_supported_for_kind` for
/// those kinds.
pub fn fetch_trust_explain(
    socket_path: &Path,
    artifact_kind: &str,
    artifact_path: &Path,
    sidecar_path: Option<&Path>,
) -> Result<TrustExplainResponse, TrustExplainError> {
    let artifact_bytes = std::fs::read(artifact_path).map_err(|e| TrustExplainError::ReadFile {
        what: "artifact",
        path: artifact_path.to_path_buf(),
        source: e,
    })?;
    let sidecar_bytes = match sidecar_path {
        Some(p) => std::fs::read(p).map_err(|e| TrustExplainError::ReadFile {
            what: "sidecar",
            path: p.to_path_buf(),
            source: e,
        })?,
        None => Vec::new(),
    };

    let b64 = base64::engine::general_purpose::STANDARD;
    let params = json!({
        "artifact_kind": artifact_kind,
        "artifact_bytes_b64": b64.encode(&artifact_bytes),
        "sidecar_bytes_b64": b64.encode(&sidecar_bytes),
    });

    let response = call_daemon(socket_path, "trust.explain", &params)?;
    parse_trust_explain_response(&response)
}

/// Parse the daemon's `trust.explain` response body into a typed struct.
pub fn parse_trust_explain_response(
    body: &Value,
) -> Result<TrustExplainResponse, TrustExplainError> {
    serde_json::from_value(body.clone())
        .map_err(|e| TrustExplainError::Protocol(format!("decode trust.explain response: {e}")))
}

/// Default sidecar path convention: `<artifact_path>.sig`. Matches the
/// daemon's `ManifestSidecar` location convention for binary manifests.
pub fn default_sidecar_path(artifact_path: &Path) -> PathBuf {
    let mut p = artifact_path.as_os_str().to_owned();
    p.push(".sig");
    PathBuf::from(p)
}

/// Render the response as a human-readable block:
///
/// - First line: posture banner (e.g. `Verdict: VERIFIED`).
/// - Trust-root block (when verified): fingerprint + source.
/// - Chain narrative: the daemon-rendered chain walk.
pub fn render_human(resp: &TrustExplainResponse) -> String {
    let mut out = String::new();
    let verdict_banner = match resp.verdict.as_str() {
        "verified" => "VERIFIED".to_string(),
        other => other.to_ascii_uppercase().replace('_', " "),
    };
    out.push_str(&format!("Verdict: {verdict_banner}\n"));
    if let Some(root) = &resp.trust_root {
        out.push_str(&format!(
            "Trust root:\n  Fingerprint: {}\n  Source:      {}\n",
            root.fingerprint_hex, root.source,
        ));
    }
    out.push_str(&format!("Chain: {}\n", resp.chain));
    out
}

/// Render the typed daemon response as stable machine-readable JSON.
pub fn render_json(resp: &TrustExplainResponse) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(resp)
}

/// Returns true for artifact kinds whose wire shape carries the
/// signature inline (Receipt envelope, delegation grant). For these, the
/// CLI sends empty sidecar bytes; `--sidecar` is ignored.
fn artifact_kind_uses_inline_signature(kind: &str) -> bool {
    matches!(kind, "receipt" | "authority_delegation")
}

/// Entry point for the `ember trust explain` subcommand. Returns 0 on
/// `verdict == "verified"` so the command composes naturally into
/// shell pipelines that gate on signature health; non-zero otherwise.
pub fn run(
    socket_path: &Path,
    artifact_kind: &str,
    artifact_path: &Path,
    sidecar_path: Option<&Path>,
    json_output: bool,
) -> i32 {
    let computed_sidecar;
    let sidecar: Option<&Path> = if artifact_kind_uses_inline_signature(artifact_kind) {
        // Receipt + authority_delegation envelopes carry their signature
        // inline. Ignore --sidecar entirely; daemon rejects non-empty
        // sidecar bytes for these kinds.
        None
    } else {
        Some(match sidecar_path {
            Some(p) => p,
            None => {
                computed_sidecar = default_sidecar_path(artifact_path);
                &computed_sidecar
            }
        })
    };

    match fetch_trust_explain(socket_path, artifact_kind, artifact_path, sidecar) {
        Ok(resp) => {
            if json_output {
                match render_json(&resp) {
                    Ok(body) => println!("{body}"),
                    Err(err) => {
                        eprintln!("ember trust explain: encode JSON output: {err}");
                        return 2;
                    }
                }
            } else {
                print!("{}", render_human(&resp));
            }
            if resp.verdict == "verified" {
                0
            } else {
                1
            }
        }
        Err(TrustExplainError::DaemonUnavailable { socket, source }) => {
            eprintln!(
                "ember trust explain: {}",
                crate::format_daemon_unavailable(&socket, &source)
            );
            2
        }
        Err(TrustExplainError::DaemonRpc { code, message }) => {
            eprintln!("ember trust explain: {message} (code {code})");
            1
        }
        Err(TrustExplainError::ReadFile { what, path, source }) => {
            eprintln!(
                "ember trust explain: could not read {what} at {} ({source})",
                path.display()
            );
            2
        }
        Err(err) => {
            eprintln!("ember trust explain: {err}");
            2
        }
    }
}

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, TrustExplainError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        TrustExplainError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| TrustExplainError::Io(format!("clone socket: {e}")))?;
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
        .map_err(|e| TrustExplainError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| TrustExplainError::Io(format!("read response: {e}")))?;

    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| TrustExplainError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(TrustExplainError::DaemonRpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decodes_verified_response() {
        let body = json!({
            "verdict": "verified",
            "trust_root": {"fingerprint_hex": "aa".repeat(32), "source": "release"},
            "chain": "artifact → trust root aaaaaaaaaaaaaaaa (release) — VERIFIED",
        });
        let resp = parse_trust_explain_response(&body).unwrap();
        assert_eq!(resp.verdict, "verified");
        let root = resp.trust_root.expect("trust_root present on verified");
        assert_eq!(root.source, "release");
        assert!(resp.chain.contains("VERIFIED"));
    }

    #[test]
    fn parse_decodes_no_matching_root_response() {
        let body = json!({
            "verdict": "no_matching_root",
            "trust_root": Value::Null,
            "chain": "tried 1 trust root(s) — NO VERIFICATION",
        });
        let resp = parse_trust_explain_response(&body).unwrap();
        assert_eq!(resp.verdict, "no_matching_root");
        assert!(resp.trust_root.is_none());
        assert!(resp.chain.contains("NO VERIFICATION"));
    }

    #[test]
    fn parse_decodes_sidecar_parse_error() {
        let body = json!({
            "verdict": "sidecar_parse_error",
            "trust_root": Value::Null,
            "chain": "sidecar parse FAILED",
        });
        let resp = parse_trust_explain_response(&body).unwrap();
        assert_eq!(resp.verdict, "sidecar_parse_error");
        assert!(resp.trust_root.is_none());
    }

    #[test]
    fn parse_rejects_missing_required_field() {
        let body = json!({"verdict": "verified"}); // missing 'chain'
        let err = parse_trust_explain_response(&body).unwrap_err();
        match err {
            TrustExplainError::Protocol(_) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn render_verified_includes_trust_root_block() {
        let resp = TrustExplainResponse {
            verdict: "verified".to_string(),
            trust_root: Some(TrustRootMatch {
                fingerprint_hex: "aa".repeat(32),
                source: "release".to_string(),
            }),
            chain: "artifact → trust root aaaaaaaaaaaaaaaa (release) — VERIFIED".to_string(),
        };
        let out = render_human(&resp);
        assert!(out.contains("Verdict: VERIFIED"));
        assert!(out.contains("Trust root:"));
        assert!(out.contains("Fingerprint:"));
        assert!(out.contains(&"aa".repeat(32)));
        assert!(out.contains("release"));
        assert!(out.contains("Chain:"));
    }

    #[test]
    fn render_no_match_omits_trust_root_block() {
        let resp = TrustExplainResponse {
            verdict: "no_matching_root".to_string(),
            trust_root: None,
            chain: "tried 1 trust root(s) — NO VERIFICATION".to_string(),
        };
        let out = render_human(&resp);
        assert!(out.contains("Verdict: NO MATCHING ROOT"));
        assert!(!out.contains("Trust root:"));
        assert!(out.contains("Chain:"));
    }

    #[test]
    fn render_json_preserves_typed_response() {
        let resp = TrustExplainResponse {
            verdict: "verified".to_string(),
            trust_root: Some(TrustRootMatch {
                fingerprint_hex: "aa".repeat(32),
                source: "release".to_string(),
            }),
            chain: "artifact to release root".to_string(),
        };
        let json: Value = serde_json::from_str(&render_json(&resp).unwrap()).unwrap();
        assert_eq!(json["verdict"], "verified");
        assert_eq!(json["trust_root"]["source"], "release");
        assert_eq!(json["chain"], "artifact to release root");
    }

    #[test]
    fn default_sidecar_path_appends_dot_sig() {
        let p = default_sidecar_path(Path::new("/tmp/manifest.toml"));
        assert_eq!(p, PathBuf::from("/tmp/manifest.toml.sig"));
    }

    #[test]
    fn default_sidecar_path_handles_no_extension() {
        let p = default_sidecar_path(Path::new("/tmp/release"));
        assert_eq!(p, PathBuf::from("/tmp/release.sig"));
    }

    /// META-TRUST-EXPLAIN-RECEIPT: receipt + authority_delegation kinds carry
    /// the signature inline; the run path must NOT compute a default
    /// sidecar path (it would fail trying to read a `.sig` that doesn't
    /// exist) and must pass empty bytes for the wire sidecar.
    #[test]
    fn artifact_kind_inline_signature_dispatch() {
        assert!(
            artifact_kind_uses_inline_signature("receipt"),
            "receipt envelopes carry the signature inline"
        );
        assert!(
            artifact_kind_uses_inline_signature("authority_delegation"),
            "delegation grants carry the signature inline"
        );
        assert!(
            !artifact_kind_uses_inline_signature("binary_manifest"),
            "binary manifest signatures live in a sidecar"
        );
        assert!(
            !artifact_kind_uses_inline_signature(""),
            "empty kind is not an inline-signature kind"
        );
        assert!(
            !artifact_kind_uses_inline_signature("unknown_kind"),
            "unknown kinds are not inline-signature by default"
        );
    }
}
