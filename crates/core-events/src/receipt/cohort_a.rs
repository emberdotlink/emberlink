//! Cohort-A `session.claude_code` Receipt body extension. design §7 + design.
//!
//! design permits additive body fields per `kind`. Cohort A adds `audit_gaps[]`
//! to the generic `ReceiptBody` so a session-end receipt can record contiguous
//! daemon-unreachable windows captured by implementation-note-8's fail-open path.
//! See design §7 ("Audit gaps") for the wedge-claim rationale: a gap is
//! *named, timestamped, and signed* so "every action is auditable" remains a
//! property of the receipt rather than a false-positive.

use serde::{Deserialize, Serialize};

use super::body::ReceiptBody;

/// Audit gap window — one entry per contiguous daemon-unreachable window.
/// Populated from `~/.ember/sessions/<id>/audit-gaps.jsonl`, which is written
/// by the implementation-note-8 fail-open path each time the launcher hook can't reach
/// emberd. See design §"Failure modes" row 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditGap {
    /// ISO-8601 start of the contiguous unreachable window.
    pub from: String,
    /// ISO-8601 end of the contiguous unreachable window.
    pub to: String,
    /// Coarse-grained reason — e.g. `"daemon_unreachable"`. Free-form so future
    /// fail-open shapes can reuse this struct without a schema bump.
    pub reason: String,
}

/// Cohort A `session.claude_code` Receipt body. Wraps the generic
/// [`ReceiptBody`] (so all v2 fields — `claim_events[]`, `permits_merkle_root`
/// — flow through unchanged) and adds the cohort-A-specific `audit_gaps[]`
/// extension permitted by design.
///
/// `#[serde(flatten)]` on `base` ensures the wire shape is one flat object
/// (matching design §"Body" and design §7), not a nested `{ base: { ... } }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaudeCodeBody {
    #[serde(flatten)]
    pub base: ReceiptBody,
    /// Daemon-unreachable windows recorded during the session. Empty when the
    /// daemon was reachable for the entire session — in which case the field
    /// is omitted from the wire form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_gaps: Vec<AuditGap>,
}

/// Locked `kind` discriminator for the cohort-A `session.claude_code` Receipt.
/// Used as `ReceiptEnvelope.kind` per design §"Envelope".
pub const RECEIPT_KIND_CLAUDE_CODE: &str = "session.claude_code";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::body::{ClaimEvent, ClaimKind};

    fn sample_claim_event() -> ClaimEvent {
        ClaimEvent {
            ts: "2026-05-01T12:00:00Z".into(),
            kind: ClaimKind::Approval,
            tool: "Bash".into(),
            input_hash: "blake3:abcdef0123456789".into(),
            input_redacted: serde_json::json!({"command": "echo hi"}),
            resolved: serde_json::json!({"allowed": true}),
        }
    }

    #[test]
    fn empty_body_round_trip_omits_audit_gaps() {
        let body = ClaudeCodeBody::default();
        let json = serde_json::to_string(&body).unwrap();
        // audit_gaps is empty by default; skip_serializing_if drops it from wire.
        assert!(
            !json.contains("audit_gaps"),
            "empty audit_gaps should not appear in wire form: {json}"
        );
        let back: ClaudeCodeBody = serde_json::from_str(&json).unwrap();
        assert!(back.audit_gaps.is_empty());
        assert!(back.base.claim_events.is_empty());
    }

    #[test]
    fn body_with_audit_gaps_round_trips() {
        let body = ClaudeCodeBody {
            base: ReceiptBody {
                claim_events: vec![sample_claim_event()],
                permits_merkle_root: "deadbeef".into(),
                device_id: None,
            },
            audit_gaps: vec![
                AuditGap {
                    from: "2026-05-01T12:01:00Z".into(),
                    to: "2026-05-01T12:01:30Z".into(),
                    reason: "daemon_unreachable".into(),
                },
                AuditGap {
                    from: "2026-05-01T12:05:00Z".into(),
                    to: "2026-05-01T12:05:10Z".into(),
                    reason: "daemon_unreachable".into(),
                },
            ],
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("audit_gaps"));
        assert!(json.contains("claim_events"));
        assert!(json.contains("permits_merkle_root"));
        let back: ClaudeCodeBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.audit_gaps.len(), 2);
        assert_eq!(back.audit_gaps[0].reason, "daemon_unreachable");
        assert_eq!(back.base.claim_events.len(), 1);
        assert_eq!(back.base.permits_merkle_root, "deadbeef");
    }

    #[test]
    fn flatten_keeps_wire_shape_flat() {
        // Per design §"Body": claim_events / permits_merkle_root / audit_gaps
        // sit at the same JSON level — no nested `base` wrapper.
        let body = ClaudeCodeBody {
            base: ReceiptBody {
                claim_events: vec![sample_claim_event()],
                permits_merkle_root: String::new(),
                device_id: None,
            },
            audit_gaps: vec![],
        };
        let value: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = value.as_object().expect("body serializes to object");
        assert!(obj.contains_key("claim_events"));
        assert!(!obj.contains_key("base"));
    }

    #[test]
    fn kind_constant_matches_adr() {
        assert_eq!(RECEIPT_KIND_CLAUDE_CODE, "session.claude_code");
    }
}
