//! CLASSIFICATION: PUBLIC
//!
//! `ember audit verify` — CLI client for the daemon's `audit_verify`
//! socket method.
//!
//! The daemon owns the audit chain; this client only formats the
//! daemon's answer. Routing through the socket (rather than reading
//! the SQLite DB directly) ensures the operator sees the chain through
//! the same gate the daemon uses internally — including the quarantine
//! latch a tampered chain flips on startup.
//!
//! Break-kind discipline: the daemon's `audit_verify` JSON response
//! distinguishes `row_hash_mismatch` (a row's stored `row_hash` does not
//! match what the canonical body hashes to) from `forward_link_mismatch`
//! (a row's `prev_hash` does not match the actual predecessor row's
//! `row_hash`). The two carry different fields and the operator needs
//! the forward-link case's `predecessor_row_id` + `expected_prev_hash`
//! to populate `audit_repair_chain`'s `from_row_id` +
//! `current_chain_tip_hash` trigger values (see the audit-cosign
//! companion ceremony in `docs/runbooks/ac2-oob-proof-ceremony.md`).
//! Flattening both shapes loses that data — see PR retiring the
//! quarantine-event runbook claim.

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

/// Kind-specific data for a chain break. Mirrors the daemon's
/// `crates/ember-daemon/src/infra/audit.rs::BreakKind`; the field names
/// here match the JSON the daemon emits in `handle_verify`.
#[derive(Debug, Clone, PartialEq)]
pub enum BreakKind {
    /// A row's stored `row_hash` does not match the canonical hash of
    /// its body. `at_row_id` is the offending row.
    RowHashMismatch {
        at_row_id: i64,
        expected_hash: String,
        stored_hash: Option<String>,
    },
    /// A row's `prev_hash` does not match the predecessor row's
    /// `row_hash`. `predecessor_row_id` is the last good row (the
    /// operator's `audit_repair_chain` `from_row_id`); `expected_prev_hash`
    /// is that predecessor's `row_hash` (the chain tip going into the
    /// repair, i.e. the operator's `current_chain_tip_hash`).
    ForwardLinkMismatch {
        at_row_id: i64,
        predecessor_row_id: i64,
        expected_prev_hash: String,
        stored_prev_hash: Option<String>,
    },
}

/// Verdict shape returned by `run_audit_verify_cli`. The CLI's caller
/// decides exit code + format from this value.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyVerdict {
    Ok {
        rows_walked: u64,
        tail: Option<usize>,
    },
    Break {
        kind: BreakKind,
        rows_walked_before: u64,
        tail: Option<usize>,
    },
}

/// SEC-S5-V030-AUDIT-CHAIN-C-WIRES (B): `ember audit verify` CLI entry
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
            kind,
            rows_walked_before,
            tail,
        } => {
            let scope = match tail {
                Some(n) => format!("last {n} rows"),
                None => "full chain".to_string(),
            };
            match kind {
                BreakKind::RowHashMismatch {
                    at_row_id,
                    expected_hash,
                    stored_hash,
                } => format!(
                    "audit chain: BREAK ({scope})\n  kind: row_hash_mismatch\n  at_row_id: {at_row_id}\n  expected_hash: {expected_hash}\n  stored_hash: {stored_hash:?}\n  rows_walked_before: {rows_walked_before}\n"
                ),
                BreakKind::ForwardLinkMismatch {
                    at_row_id,
                    predecessor_row_id,
                    expected_prev_hash,
                    stored_prev_hash,
                } => format!(
                    "audit chain: BREAK ({scope})\n  kind: forward_link_mismatch\n  at_row_id: {at_row_id}\n  predecessor_row_id: {predecessor_row_id}\n  expected_prev_hash: {expected_prev_hash}\n  stored_prev_hash: {stored_prev_hash:?}\n  rows_walked_before: {rows_walked_before}\n  audit_repair_chain trigger values:\n    from_row_id:            {predecessor_row_id}\n    current_chain_tip_hash: {expected_prev_hash}\n"
                ),
            }
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
            kind,
            rows_walked_before,
            tail,
        } => {
            let break_obj = match kind {
                BreakKind::RowHashMismatch {
                    at_row_id,
                    expected_hash,
                    stored_hash,
                } => json!({
                    "kind": "row_hash_mismatch",
                    "at_row_id": at_row_id,
                    "expected_hash": expected_hash,
                    "stored_hash": stored_hash,
                    "rows_walked_before": rows_walked_before,
                }),
                BreakKind::ForwardLinkMismatch {
                    at_row_id,
                    predecessor_row_id,
                    expected_prev_hash,
                    stored_prev_hash,
                } => json!({
                    "kind": "forward_link_mismatch",
                    "at_row_id": at_row_id,
                    "predecessor_row_id": predecessor_row_id,
                    "expected_prev_hash": expected_prev_hash,
                    "stored_prev_hash": stored_prev_hash,
                    "rows_walked_before": rows_walked_before,
                    "audit_repair_chain_trigger": {
                        "from_row_id": predecessor_row_id,
                        "current_chain_tip_hash": expected_prev_hash,
                    },
                }),
            };
            json!({
                "ok": false,
                "break": break_obj,
                "tail": tail,
            })
        }
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
        return Ok(VerifyVerdict::Ok { rows_walked, tail });
    }
    let br = result
        .get("break")
        .ok_or_else(|| VerifyError::Protocol("response missing `break` field".to_string()))?;
    let at_row_id = br.get("at_row_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let rows_walked_before = br
        .get("rows_walked_before")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let kind_str = br.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let kind = match kind_str {
        "forward_link_mismatch" => {
            let predecessor_row_id = br
                .get("predecessor_row_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let expected_prev_hash = br
                .get("expected_prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let stored_prev_hash = br
                .get("stored_prev_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            BreakKind::ForwardLinkMismatch {
                at_row_id,
                predecessor_row_id,
                expected_prev_hash,
                stored_prev_hash,
            }
        }
        // Default to row_hash_mismatch when `kind` is missing or unknown:
        // older daemons emitted the row-hash-mismatch shape without an
        // explicit `kind` field. Forward-link parsing above is keyed on
        // the explicit string the current daemon emits, so this fallback
        // only fires for legacy/unknown shapes — surface what we can.
        _ => {
            let expected_hash = br
                .get("expected_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let stored_hash = br
                .get("stored_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            BreakKind::RowHashMismatch {
                at_row_id,
                expected_hash,
                stored_hash,
            }
        }
    };
    Ok(VerifyVerdict::Break {
        kind,
        rows_walked_before,
        tail,
    })
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
    fn parse_verdict_row_hash_mismatch_with_kind() {
        let r = json!({
            "ok": false,
            "break": {
                "kind": "row_hash_mismatch",
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
                kind: BreakKind::RowHashMismatch {
                    at_row_id: 7,
                    expected_hash: "abc".to_string(),
                    stored_hash: Some("def".to_string()),
                },
                rows_walked_before: 6,
                tail: Some(100),
            }
        );
    }

    #[test]
    fn parse_verdict_row_hash_mismatch_legacy_no_kind_field() {
        // Older daemon payloads emitted the row-hash-mismatch shape without
        // an explicit `kind` field. Parser must still surface the fields.
        let r = json!({
            "ok": false,
            "break": {
                "at_row_id": 7,
                "expected_hash": "abc",
                "stored_hash": "def",
                "rows_walked_before": 6,
            },
        });
        let v = parse_verdict(&r, Some(100)).expect("parse legacy break");
        assert_eq!(
            v,
            VerifyVerdict::Break {
                kind: BreakKind::RowHashMismatch {
                    at_row_id: 7,
                    expected_hash: "abc".to_string(),
                    stored_hash: Some("def".to_string()),
                },
                rows_walked_before: 6,
                tail: Some(100),
            }
        );
    }

    #[test]
    fn parse_verdict_forward_link_mismatch_carries_repair_trigger_fields() {
        // Mirrors the exact JSON shape
        // `crates/ember-daemon/src/infra/handler/audit_receipts.rs::audit_verify`
        // emits for `BreakKind::ForwardLinkMismatch`.
        let r = json!({
            "ok": false,
            "break": {
                "kind": "forward_link_mismatch",
                "at_row_id": 1234,
                "predecessor_row_id": 1233,
                "expected_prev_hash": "feedbeef",
                "stored_prev_hash": "deadc0de",
                "rows_walked_before": 1232,
            },
        });
        let v = parse_verdict(&r, Some(50)).expect("parse forward-link break");
        let VerifyVerdict::Break {
            kind:
                BreakKind::ForwardLinkMismatch {
                    at_row_id,
                    predecessor_row_id,
                    expected_prev_hash,
                    stored_prev_hash,
                },
            rows_walked_before,
            tail,
        } = v
        else {
            panic!("expected ForwardLinkMismatch break, got something else");
        };
        assert_eq!(at_row_id, 1234);
        assert_eq!(predecessor_row_id, 1233);
        assert_eq!(expected_prev_hash, "feedbeef");
        assert_eq!(stored_prev_hash, Some("deadc0de".to_string()));
        assert_eq!(rows_walked_before, 1232);
        assert_eq!(tail, Some(50));
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
    fn format_verdict_human_row_hash_mismatch_labels_kind() {
        let v = VerifyVerdict::Break {
            kind: BreakKind::RowHashMismatch {
                at_row_id: 3,
                expected_hash: "h1".to_string(),
                stored_hash: None,
            },
            rows_walked_before: 2,
            tail: None,
        };
        let s = format_verdict_human(&v);
        assert!(s.contains("BREAK"));
        assert!(s.contains("kind: row_hash_mismatch"));
        assert!(s.contains("at_row_id: 3"));
        assert!(s.contains("full chain"));
    }

    #[test]
    fn format_verdict_human_forward_link_mismatch_surfaces_repair_trigger() {
        let v = VerifyVerdict::Break {
            kind: BreakKind::ForwardLinkMismatch {
                at_row_id: 1234,
                predecessor_row_id: 1233,
                expected_prev_hash: "feedbeef".to_string(),
                stored_prev_hash: Some("deadc0de".to_string()),
            },
            rows_walked_before: 1232,
            tail: Some(20),
        };
        let s = format_verdict_human(&v);
        assert!(s.contains("kind: forward_link_mismatch"));
        assert!(s.contains("predecessor_row_id: 1233"));
        assert!(s.contains("expected_prev_hash: feedbeef"));
        // The trigger-value summary block is the load-bearing operator
        // affordance — if it's missing the operator falls back to
        // reading SQLite by hand, which is the friction this surface
        // exists to remove.
        assert!(
            s.contains("audit_repair_chain trigger values"),
            "human renderer must surface the trigger-value block: {s}"
        );
        assert!(s.contains("from_row_id:            1233"));
        assert!(s.contains("current_chain_tip_hash: feedbeef"));
    }

    #[test]
    fn format_verdict_json_forward_link_carries_trigger_object() {
        let v = VerifyVerdict::Break {
            kind: BreakKind::ForwardLinkMismatch {
                at_row_id: 1234,
                predecessor_row_id: 1233,
                expected_prev_hash: "feedbeef".to_string(),
                stored_prev_hash: Some("deadc0de".to_string()),
            },
            rows_walked_before: 1232,
            tail: Some(20),
        };
        let out = format_verdict_json(&v);
        assert_eq!(out["ok"], Value::Bool(false));
        assert_eq!(out["break"]["kind"], "forward_link_mismatch");
        assert_eq!(out["break"]["predecessor_row_id"], 1233);
        assert_eq!(out["break"]["expected_prev_hash"], "feedbeef");
        // Machine-readable trigger object for piping into
        // `ember audit canonical-repair-intent` / `ember audit repair-chain`.
        assert_eq!(
            out["break"]["audit_repair_chain_trigger"]["from_row_id"],
            1233
        );
        assert_eq!(
            out["break"]["audit_repair_chain_trigger"]["current_chain_tip_hash"],
            "feedbeef"
        );
    }

    #[test]
    fn format_verdict_json_row_hash_mismatch_no_trigger_object() {
        // Row-hash-mismatch breaks need an additional row_hash lookup
        // for `current_chain_tip_hash`, so the verifier deliberately does
        // NOT emit a trigger object for this kind — surfacing a partial
        // one would invite the operator to sign over zeroed/empty bytes.
        let v = VerifyVerdict::Break {
            kind: BreakKind::RowHashMismatch {
                at_row_id: 3,
                expected_hash: "h1".to_string(),
                stored_hash: None,
            },
            rows_walked_before: 2,
            tail: None,
        };
        let out = format_verdict_json(&v);
        assert_eq!(out["break"]["kind"], "row_hash_mismatch");
        assert!(out["break"].get("audit_repair_chain_trigger").is_none());
    }
}
