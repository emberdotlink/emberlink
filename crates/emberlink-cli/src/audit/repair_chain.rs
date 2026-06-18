//! CLASSIFICATION: PUBLIC
//!
//! `ember audit repair-chain` — CLI client for the daemon's
//! `audit_repair_chain` socket method (ADR 174 v2 §2 / ADR 200 §6,
//! F1 closed in PR #5684). The operator co-signs a `RepairIntent` with
//! a presence Device off-host; this CLI verb submits the signed intent
//! to the daemon, which verifies the signature against the enrolled
//! presence-Device set under the operator root and, on success,
//! truncates the audit chain past the broken row.
//!
//! Companion verbs:
//! - `ember audit canonical-repair-intent` — emit the bytes to sign
//!   (pure offline; lives in the `ember.rs` bin).
//! - `ember audit verify-repair-intent` — offline-verify the signed
//!   intent against the AC-2 device pubkeys (pure offline; lives in the
//!   `ember.rs` bin).
//!
//! This module mirrors the shape of `audit::verify` — a daemon JSON-RPC
//! client with a typed verdict, formatted by the CLI caller. The trust
//! source is the daemon-side `verify_repair_intent_signature`; this CLI
//! is just the wire driver, retiring the runbook's "submit by hand" step.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{Value, json};

#[derive(Debug)]
pub enum RepairChainError {
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

impl std::fmt::Display for RepairChainError {
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
impl std::error::Error for RepairChainError {}

/// Outcome shape mirroring the daemon-side `RepairOutcome` JSON
/// (`audit_receipts::handle_repair_chain`). Three variants — success
/// with the new chain tip, and two incomplete-repair signals the daemon
/// returns when it crashed mid-repair (the ADR 174 v2 §6 recovery
/// surface). Carried as a typed value so the caller picks format +
/// exit code from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairChainOutcome {
    Ok {
        repair_id: String,
        new_chain_tip_hash: String,
        tombstone_row_id: i64,
        truncated_row_count: u64,
    },
    IncompleteRepair {
        receipt_id_orphan: String,
    },
    IncompleteRepairReceipt {
        tombstone_row_id_orphan: i64,
    },
}

/// Inputs the operator supplies on the CLI. These mirror the
/// daemon-RPC `params` shape (`audit_receipts::handle_repair_chain`),
/// so the CLI is a thin shim — no canonical-bytes recomputation,
/// no signature work. The daemon is the trust source.
#[derive(Debug, Clone)]
pub struct RepairChainRequest {
    pub from_row_id: i64,
    pub repair_kind: String,
    pub operator_signature_hex: String,
    pub operator_pubkey: String,
    pub current_chain_tip_hash: String,
    pub daemon_identity_root_fingerprint: String,
}

/// CLI entry point. Submits the operator's signed repair intent to the
/// daemon and returns the typed outcome. The caller decides exit code +
/// human/JSON formatting based on the variant.
pub fn run_audit_repair_chain_cli(
    socket_path: &Path,
    request: &RepairChainRequest,
) -> Result<RepairChainOutcome, RepairChainError> {
    let result = call_audit_repair_chain(socket_path, request)?;
    parse_outcome(&result)
}

pub fn format_outcome_human(outcome: &RepairChainOutcome) -> String {
    match outcome {
        RepairChainOutcome::Ok {
            repair_id,
            new_chain_tip_hash,
            tombstone_row_id,
            truncated_row_count,
        } => format!(
            "audit_repair_chain: OK\n  repair_id:           {repair_id}\n  new_chain_tip_hash:  {new_chain_tip_hash}\n  tombstone_row_id:    {tombstone_row_id}\n  truncated_row_count: {truncated_row_count}\n"
        ),
        RepairChainOutcome::IncompleteRepair { receipt_id_orphan } => format!(
            "audit_repair_chain: incomplete_repair\n  receipt_id_orphan: {receipt_id_orphan}\n  Re-run after resolving the orphan receipt.\n"
        ),
        RepairChainOutcome::IncompleteRepairReceipt {
            tombstone_row_id_orphan,
        } => format!(
            "audit_repair_chain: incomplete_repair_receipt\n  tombstone_row_id_orphan: {tombstone_row_id_orphan}\n  Re-run after resolving the orphan tombstone.\n"
        ),
    }
}

pub fn format_outcome_json(outcome: &RepairChainOutcome) -> Value {
    match outcome {
        RepairChainOutcome::Ok {
            repair_id,
            new_chain_tip_hash,
            tombstone_row_id,
            truncated_row_count,
        } => json!({
            "ok": true,
            "repair_id": repair_id,
            "new_chain_tip_hash": new_chain_tip_hash,
            "tombstone_row_id": tombstone_row_id,
            "truncated_row_count": truncated_row_count,
        }),
        RepairChainOutcome::IncompleteRepair { receipt_id_orphan } => json!({
            "ok": false,
            "incomplete_repair": { "receipt_id_orphan": receipt_id_orphan },
        }),
        RepairChainOutcome::IncompleteRepairReceipt {
            tombstone_row_id_orphan,
        } => json!({
            "ok": false,
            "incomplete_repair_receipt": {
                "tombstone_row_id_orphan": tombstone_row_id_orphan,
            },
        }),
    }
}

fn call_audit_repair_chain(
    socket_path: &Path,
    request: &RepairChainRequest,
) -> Result<Value, RepairChainError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        RepairChainError::DaemonUnavailable {
            socket: socket_path.to_path_buf(),
            source: e,
        }
    })?;

    let mut writer = stream
        .try_clone()
        .map_err(|e| RepairChainError::Io(format!("clone socket: {e}")))?;
    let mut reader = BufReader::new(stream);

    let params = json!({
        "from_row_id": request.from_row_id,
        "repair_kind": request.repair_kind,
        "operator_signature_hex": request.operator_signature_hex,
        "operator_pubkey": request.operator_pubkey,
        "current_chain_tip_hash": request.current_chain_tip_hash,
        "daemon_identity_root_fingerprint": request.daemon_identity_root_fingerprint,
    });
    let rpc = json!({
        "id": "1",
        "method": "audit_repair_chain",
        "params": params,
    });
    let mut line = serde_json::to_string(&rpc).expect("serialize request");
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| RepairChainError::Io(format!("write request: {e}")))?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| RepairChainError::Io(format!("read response: {e}")))?;
    let response: Value = serde_json::from_str(response_line.trim())
        .map_err(|e| RepairChainError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32;
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(RepairChainError::Rpc { code, message });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn parse_outcome(result: &Value) -> Result<RepairChainOutcome, RepairChainError> {
    let ok = result
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| RepairChainError::Protocol("response missing `ok` field".to_string()))?;
    if ok {
        let repair_id = result
            .get("repair_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RepairChainError::Protocol("ok response missing `repair_id`".to_string())
            })?
            .to_string();
        let new_chain_tip_hash = result
            .get("new_chain_tip_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RepairChainError::Protocol("ok response missing `new_chain_tip_hash`".to_string())
            })?
            .to_string();
        let tombstone_row_id = result
            .get("tombstone_row_id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                RepairChainError::Protocol("ok response missing `tombstone_row_id`".to_string())
            })?;
        let truncated_row_count = result
            .get("truncated_row_count")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                RepairChainError::Protocol("ok response missing `truncated_row_count`".to_string())
            })?;
        Ok(RepairChainOutcome::Ok {
            repair_id,
            new_chain_tip_hash,
            tombstone_row_id,
            truncated_row_count,
        })
    } else if let Some(ir) = result.get("incomplete_repair") {
        let receipt_id_orphan = ir
            .get("receipt_id_orphan")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RepairChainError::Protocol(
                    "incomplete_repair missing `receipt_id_orphan`".to_string(),
                )
            })?
            .to_string();
        Ok(RepairChainOutcome::IncompleteRepair { receipt_id_orphan })
    } else if let Some(irr) = result.get("incomplete_repair_receipt") {
        let tombstone_row_id_orphan = irr
            .get("tombstone_row_id_orphan")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                RepairChainError::Protocol(
                    "incomplete_repair_receipt missing `tombstone_row_id_orphan`".to_string(),
                )
            })?;
        Ok(RepairChainOutcome::IncompleteRepairReceipt {
            tombstone_row_id_orphan,
        })
    } else {
        Err(RepairChainError::Protocol(
            "response had ok=false but no incomplete_repair{,_receipt} field".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_outcome_ok_branch() {
        let r = json!({
            "ok": true,
            "repair_id": "rid-abc",
            "new_chain_tip_hash": "deadbeef",
            "tombstone_row_id": 42,
            "truncated_row_count": 7,
        });
        let outcome = parse_outcome(&r).expect("parse ok");
        assert_eq!(
            outcome,
            RepairChainOutcome::Ok {
                repair_id: "rid-abc".to_string(),
                new_chain_tip_hash: "deadbeef".to_string(),
                tombstone_row_id: 42,
                truncated_row_count: 7,
            }
        );
    }

    #[test]
    fn parse_outcome_incomplete_repair_branch() {
        let r = json!({
            "ok": false,
            "incomplete_repair": { "receipt_id_orphan": "rcpt-orphan-1" },
        });
        let outcome = parse_outcome(&r).expect("parse incomplete_repair");
        assert_eq!(
            outcome,
            RepairChainOutcome::IncompleteRepair {
                receipt_id_orphan: "rcpt-orphan-1".to_string()
            }
        );
    }

    #[test]
    fn parse_outcome_incomplete_repair_receipt_branch() {
        let r = json!({
            "ok": false,
            "incomplete_repair_receipt": { "tombstone_row_id_orphan": 9 },
        });
        let outcome = parse_outcome(&r).expect("parse incomplete_repair_receipt");
        assert_eq!(
            outcome,
            RepairChainOutcome::IncompleteRepairReceipt {
                tombstone_row_id_orphan: 9
            }
        );
    }

    #[test]
    fn parse_outcome_missing_ok_is_protocol_error() {
        let r = json!({"not_ok": "x"});
        let err = parse_outcome(&r).expect_err("must error");
        match err {
            RepairChainError::Protocol(s) => {
                assert!(
                    s.contains("`ok`"),
                    "protocol error should name the field: {s}"
                );
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_outcome_ok_missing_required_field_is_protocol_error() {
        // Daemon must always return all four fields on success — partial
        // success would mask a chain-state inconsistency.
        let r = json!({"ok": true, "repair_id": "x"});
        let err = parse_outcome(&r).expect_err("partial ok must error");
        match err {
            RepairChainError::Protocol(_) => {}
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_outcome_ok_false_without_incomplete_is_protocol_error() {
        let r = json!({"ok": false});
        let err = parse_outcome(&r).expect_err("ok=false without incomplete must error");
        match err {
            RepairChainError::Protocol(s) => {
                assert!(
                    s.contains("incomplete_repair"),
                    "should name the missing incomplete_repair* shape: {s}"
                );
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn format_outcome_human_ok_includes_all_fields() {
        let outcome = RepairChainOutcome::Ok {
            repair_id: "rid".to_string(),
            new_chain_tip_hash: "tip".to_string(),
            tombstone_row_id: 1,
            truncated_row_count: 2,
        };
        let s = format_outcome_human(&outcome);
        assert!(s.contains("rid"));
        assert!(s.contains("tip"));
        assert!(s.contains("truncated_row_count: 2"));
    }

    #[test]
    fn format_outcome_json_ok_includes_all_fields() {
        let outcome = RepairChainOutcome::Ok {
            repair_id: "rid".to_string(),
            new_chain_tip_hash: "tip".to_string(),
            tombstone_row_id: 1,
            truncated_row_count: 2,
        };
        let v = format_outcome_json(&outcome);
        assert_eq!(v["ok"], true);
        assert_eq!(v["repair_id"], "rid");
        assert_eq!(v["new_chain_tip_hash"], "tip");
        assert_eq!(v["tombstone_row_id"], 1);
        assert_eq!(v["truncated_row_count"], 2);
    }
}
