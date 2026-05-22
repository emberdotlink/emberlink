//!
//! `ember audit verify` — CLI client for the daemon's `audit_verify`
//! socket method.
//!
//! The daemon owns the audit chain; this client only formats the
//! daemon's answer. Routing through the socket (rather than reading
//! the SQLite DB directly) ensures the operator sees the chain through
//! the same gate the daemon uses internally — including the quarantine
//! latch a tampered chain flips on startup.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{Value, json};

/// Errors returned by the CLI verify path. Distinct from the daemon-side
/// `VerifyOutcome::Break`, which is *part of a successful RPC* (the chain
/// has a break, but the verify call succeeded).
#[derive(Debug)]
pub enum VerifyError {
    DaemonUnavailable {
        socket: std::path::PathBuf,
        source: std::io::Error,
    },
    Io(String),
    Rpc {
        code: i32,
        message: String,
    },
    Protocol(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonUnavailable { socket, source } => {
                write!(f, "{}", crate::format_daemon_unavailable(socket, source))
            }
            Self::Io(s) => write!(f, "{s}"),
            Self::Rpc { code, message } => write!(f, "daemon error {code}: {message}"),
            Self::Protocol(s) => write!(f, "protocol error: {s}"),
        }
    }
}
impl std::error::Error for VerifyError {}

/// Verdict shape returned by `run_audit_verify_cli`. The CLI's caller
/// decides exit code + format from this value.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyVerdict {
    Ok {
        rows_walked: u64,
        tail: Option<usize>,
    },
    Break {
        at_row_id: i64,
        expected_hash: String,
        stored_hash: Option<String>,
        rows_walked_before: u64,
        tail: Option<usize>,
    },
}

/// implementation-note-262 (B): `ember audit verify` CLI entry
/// point. Walks the daemon's audit chain via the `audit_verify` socket
/// method. `tail = None` requests a full-chain walk; `Some(n)` requests
/// the last N rows.
pub fn run_audit_verify_cli(
    socket_path: &Path,
    tail: Option<usize>,
) -> Result<VerifyVerdict, VerifyError> {
    let result = call_audit_verify(socket_path, tail)?;
    parse_verdict(&result, tail)
}

/// Render a verdict for human or JSON output. The CLI side picks which
/// based on the global `--json` flag.
pub fn format_verdict_human(verdict: &VerifyVerdict) -> String {
    match verdict {
        VerifyVerdict::Ok { rows_walked, tail } => {
            let scope = match tail {
                Some(n) => format!("last {n} rows"),
                None => "full chain".to_string(),
            };
            format!("audit chain: OK ({scope}); rows walked: {rows_walked}\n")
        }
        VerifyVerdict::Break {
            at_row_id,
            expected_hash,
            stored_hash,
            rows_walked_before,
            tail,
        } => {
            let scope = match tail {
                Some(n) => format!("last {n} rows"),
                None => "full chain".to_string(),
            };
            format!(
                "audit chain: BREAK ({scope})\n  at_row_id: {at_row_id}\n  expected_hash: {expected_hash}\n  stored_hash: {stored_hash:?}\n  rows_walked_before: {rows_walked_before}\n"
            )
        }
    }
}

pub fn format_verdict_json(verdict: &VerifyVerdict) -> Value {
    match verdict {
        VerifyVerdict::Ok { rows_walked, tail } => json!({
            "ok": true,
            "rows_walked": rows_walked,
            "tail": tail,
        }),
        VerifyVerdict::Break {
            at_row_id,
            expected_hash,
            stored_hash,
            rows_walked_before,
            tail,
        } => json!({
            "ok": false,
            "break": {
                "at_row_id": at_row_id,
                "expected_hash": expected_hash,
                "stored_hash": stored_hash,
                "rows_walked_before": rows_walked_before,
            },
            "tail": tail,
        }),
    }
}

fn call_audit_verify(socket_path: &Path, tail: Option<usize>) -> Result<Value, VerifyError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        VerifyError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| VerifyError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let params = match tail {
        Some(n) => json!({"tail": n}),
        None => json!({}),
    };
    let request = json!({
        "id": "1",
        "method": "audit_verify",
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| VerifyError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| VerifyError::Io(format!("read response: {e}")))?;
    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| VerifyError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(VerifyError::Rpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn parse_verdict(result: &Value, tail: Option<usize>) -> Result<VerifyVerdict, VerifyError> {
    let ok = result
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| VerifyError::Protocol("response missing `ok` field".to_string()))?;
    if ok {
        let rows_walked = result
            .get("rows_walked")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(VerifyVerdict::Ok { rows_walked, tail })
    } else {
        let br = result
            .get("break")
            .ok_or_else(|| VerifyError::Protocol("response missing `break` field".to_string()))?;
        Ok(VerifyVerdict::Break {
            at_row_id: br.get("at_row_id").and_then(|v| v.as_i64()).unwrap_or(0),
            expected_hash: br
                .get("expected_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            stored_hash: br
                .get("stored_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            rows_walked_before: br
                .get("rows_walked_before")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            tail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verdict_ok_branch() {
        let r = json!({"ok": true, "rows_walked": 42, "tail": null});
        let v = parse_verdict(&r, None).expect("parse ok");
        assert_eq!(
            v,
            VerifyVerdict::Ok {
                rows_walked: 42,
                tail: None,
            }
        );
    }

    #[test]
    fn parse_verdict_break_branch() {
        let r = json!({
            "ok": false,
            "break": {
                "at_row_id": 7,
                "expected_hash": "abc",
                "stored_hash": "def",
                "rows_walked_before": 6,
            },
        });
        let v = parse_verdict(&r, Some(100)).expect("parse break");
        assert_eq!(
            v,
            VerifyVerdict::Break {
                at_row_id: 7,
                expected_hash: "abc".to_string(),
                stored_hash: Some("def".to_string()),
                rows_walked_before: 6,
                tail: Some(100),
            }
        );
    }

    #[test]
    fn parse_verdict_missing_ok_is_protocol_error() {
        let r = json!({"not_ok": "x"});
        let err = parse_verdict(&r, None).expect_err("must error");
        assert!(matches!(err, VerifyError::Protocol(_)));
    }

    #[test]
    fn format_verdict_human_ok_mentions_scope_and_rows() {
        let v = VerifyVerdict::Ok {
            rows_walked: 12,
            tail: Some(500),
        };
        let s = format_verdict_human(&v);
        assert!(s.contains("OK"));
        assert!(s.contains("last 500 rows"));
        assert!(s.contains("12"));
    }

    #[test]
    fn format_verdict_human_break_mentions_row_id() {
        let v = VerifyVerdict::Break {
            at_row_id: 3,
            expected_hash: "h1".to_string(),
            stored_hash: None,
            rows_walked_before: 2,
            tail: None,
        };
        let s = format_verdict_human(&v);
        assert!(s.contains("BREAK"));
        assert!(s.contains("at_row_id: 3"));
        assert!(s.contains("full chain"));
    }
}
