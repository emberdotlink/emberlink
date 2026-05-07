//! Receipt v2 issuance helper for cohort-A `session.claude_code` Receipts.
//!
//! Per design §"Envelope" + design §7. Builds a `ReceiptEnvelope` wrapping a
//! `ClaudeCodeBody` (claim_events + audit_gaps + permits_merkle_root) at session
//! termination. Signing is deferred to a follow-up PR (design persona signing
//! integration); see TODO comments below.

use std::fs;
use std::path::Path;

use blake3::Hasher;
use core_events::receipt::{
    AuditGap, ClaimEvent, ClaudeCodeBody, ReceiptBody, ReceiptEnvelope, ReceiptVersion,
    RECEIPT_KIND_CLAUDE_CODE, TerminationAuthority, merkle_leaf, merkle_root,
};

/// Errors raised by [`issue_cohort_a_receipt`].
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("serialize Receipt body: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("read audit-gaps file at {path}: {source}")]
    AuditGapsRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Build a signed-by-design (signature populated by follow-up PR) cohort-A
/// `session.claude_code` Receipt envelope.
///
/// Steps per design §"Envelope":
/// 1. Build [`ClaudeCodeBody`] from `claim_events` + parsed `audit_gaps.jsonl`
///    (lines parsed individually, malformed lines skipped — fail-open shape
///    matches implementation-note-8's writer).
/// 2. Compute `permits_merkle_root` over `claim_events[].input_hash` blake3
///    leaves (design §"Merkle leaf format" — leaf form simplified for now;
///    proper canonical leaf payload is a follow-up).
/// 3. Construct [`ReceiptEnvelope`] with `version="2"`, `kind="session.claude_code"`,
///    `daemon_root_id`, `termination_authority`, body=JSON, `signature=None`.
/// 4. Compute `receipt_id = blake3(serde_json::to_vec(envelope_without_signature))`.
///    TODO: replace with JCS canonicalization per design §"Envelope" once a
///    JCS helper lands.
/// 5. Set `receipt_id` and return.
///
/// `audit_gaps_path = None` (or a non-existent file) → `audit_gaps = []` —
/// the daemon was reachable for the entire session.
pub fn issue_cohort_a_receipt(
    _session_id: &str,
    claim_events: Vec<ClaimEvent>,
    audit_gaps_path: Option<&Path>,
    termination_authority: TerminationAuthority,
    daemon_root_id: &str,
) -> Result<ReceiptEnvelope, IssueError> {
    // 1. Parse audit gaps (fail-open: skip malformed lines, treat missing
    //    file as "no gaps recorded").
    let audit_gaps = match audit_gaps_path {
        Some(path) if path.exists() => parse_audit_gaps(path)?,
        _ => Vec::new(),
    };

    // 2. Compute Merkle root over claim_events[].input_hash leaves.
    //    Empty claim_events → all-zeros merkle root path (per
    //    `merkle::merkle_root` empty-input contract). We still emit a hex
    //    string for the field so envelope shape stays uniform; an empty
    //    body simply has the zero-root encoded.
    let leaves: Vec<[u8; 32]> = claim_events
        .iter()
        .map(|ce| merkle_leaf(ce.input_hash.as_bytes()))
        .collect();
    let permits_merkle_root = if claim_events.is_empty() {
        // Empty body: leave the field empty so it's omitted from wire form
        // (matches the `skip_serializing_if = "String::is_empty"` on
        // `ReceiptBody.permits_merkle_root`).
        String::new()
    } else {
        hex_lower(&merkle_root(&leaves))
    };

    // 3. Build the body.
    let body = ClaudeCodeBody {
        base: ReceiptBody {
            claim_events,
            permits_merkle_root,
            device_id: None,
        },
        audit_gaps,
    };

    // 4. Build envelope (signature=None, receipt_id placeholder).
    let body_value = serde_json::to_value(&body).map_err(IssueError::Serialize)?;
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_CLAUDE_CODE.into(),
        receipt_id: String::new(),
        daemon_root_id: daemon_root_id.into(),
        traceparent: None,
        termination_authority,
        body: body_value,
        // TODO: Persona-sign per design once the daemon-as-persona signing
        // helper lands. For now `signature=None` matches the shipped
        // `ReceiptEnvelope` scaffold's `skip_serializing_if = "Option::is_none"`.
        signature: None,
    };

    // 5. Compute receipt_id over the unsigned envelope.
    //    TODO: replace plain `serde_json::to_vec` with JCS canonicalization
    //    per design §"Envelope" once a JCS helper lands. Until then this
    //    is deterministic-enough for round-trip (serde_json sorts struct
    //    fields by declaration order) but is NOT yet wire-stable across
    //    other implementations.
    let unsigned_bytes = serde_json::to_vec(&envelope).map_err(IssueError::Serialize)?;
    envelope.receipt_id = format!("blake3:{}", hex_lower(&blake3_bytes(&unsigned_bytes)));

    Ok(envelope)
}

/// Parse `~/.ember/sessions/<id>/audit-gaps.jsonl` line-by-line, skipping
/// malformed lines (matches the fail-open posture of implementation-note-8's writer).
fn parse_audit_gaps(path: &Path) -> Result<Vec<AuditGap>, IssueError> {
    let raw = fs::read_to_string(path).map_err(|source| IssueError::AuditGapsRead {
        path: path.display().to_string(),
        source,
    })?;
    let mut gaps = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(gap) = serde_json::from_str::<AuditGap>(trimmed) {
            gaps.push(gap);
        }
        // Malformed line: silently skipped. The fail-open posture of the
        // writer means a partially-corrupt file shouldn't lose every gap;
        // we recover whatever lines parse cleanly.
    }
    Ok(gaps)
}

fn blake3_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_events::receipt::body::{ClaimEvent, ClaimKind};
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn sample_claim_event(input_hash: &str) -> ClaimEvent {
        ClaimEvent {
            ts: "2026-05-01T12:00:00Z".into(),
            kind: ClaimKind::Approval,
            tool: "Bash".into(),
            input_hash: input_hash.into(),
            input_redacted: serde_json::json!({"command": "echo hi"}),
            resolved: serde_json::json!({"allowed": true}),
        }
    }

    #[test]
    fn empty_claim_events_omits_merkle_root() {
        let env = issue_cohort_a_receipt(
            "sess-1",
            vec![],
            None,
            TerminationAuthority::UserSession,
            "daemon-root-1",
        )
        .unwrap();
        assert_eq!(env.kind, RECEIPT_KIND_CLAUDE_CODE);
        assert_eq!(env.daemon_root_id, "daemon-root-1");
        assert_eq!(env.version.0, "2");
        assert!(env.signature.is_none());
        assert!(env.receipt_id.starts_with("blake3:"));
        // Body should serialize without permits_merkle_root (skip_if empty).
        let body_str = serde_json::to_string(&env.body).unwrap();
        assert!(
            !body_str.contains("permits_merkle_root"),
            "empty claim_events should omit permits_merkle_root: {body_str}"
        );
    }

    #[test]
    fn one_claim_event_populates_merkle_root_and_round_trips() {
        let env = issue_cohort_a_receipt(
            "sess-2",
            vec![sample_claim_event("blake3:abc123")],
            None,
            TerminationAuthority::DaemonPersona,
            "daemon-root-2",
        )
        .unwrap();
        // Round-trip the envelope through serde_json — guards against any
        // field that isn't (de)serializable.
        let json = serde_json::to_string(&env).unwrap();
        let back: ReceiptEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, RECEIPT_KIND_CLAUDE_CODE);
        assert_eq!(back.receipt_id, env.receipt_id);
        // Body now has a non-empty permits_merkle_root.
        let body_str = serde_json::to_string(&back.body).unwrap();
        assert!(
            body_str.contains("permits_merkle_root"),
            "single claim_event should populate permits_merkle_root: {body_str}"
        );
    }

    #[test]
    fn audit_gaps_file_parses_and_skips_malformed_lines() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"from":"2026-05-01T12:01:00Z","to":"2026-05-01T12:01:30Z","reason":"daemon_unreachable"}}"#
        )
        .unwrap();
        writeln!(f, "garbage line {{ not json").unwrap();
        writeln!(f).unwrap();
        writeln!(
            f,
            r#"{{"from":"2026-05-01T12:05:00Z","to":"2026-05-01T12:05:10Z","reason":"daemon_unreachable"}}"#
        )
        .unwrap();
        f.flush().unwrap();

        let env = issue_cohort_a_receipt(
            "sess-3",
            vec![sample_claim_event("blake3:def456")],
            Some(f.path()),
            TerminationAuthority::UserSession,
            "daemon-root-3",
        )
        .unwrap();
        let body: ClaudeCodeBody = serde_json::from_value(env.body).unwrap();
        assert_eq!(body.audit_gaps.len(), 2, "should recover both valid lines");
        assert_eq!(body.audit_gaps[0].reason, "daemon_unreachable");
    }

    #[test]
    fn missing_audit_gaps_path_yields_no_gaps() {
        let env = issue_cohort_a_receipt(
            "sess-4",
            vec![],
            Some(Path::new("/nonexistent/audit-gaps.jsonl")),
            TerminationAuthority::UserSession,
            "daemon-root-4",
        )
        .unwrap();
        let body: ClaudeCodeBody = serde_json::from_value(env.body).unwrap();
        assert!(body.audit_gaps.is_empty());
    }
}
