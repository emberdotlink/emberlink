//! Cohort-A `session.claude_code` Receipt body extension. ADR 120 §7 + ADR 118.
//!
//! ADR 118 permits additive body fields per `kind`. Cohort A adds `audit_gaps[]`
//! to the generic `ReceiptBody` so a session-end receipt can record contiguous
//! daemon-unreachable windows captured by COHORT-A-9's fail-open path.
//! See ADR 120 §7 ("Audit gaps") for the wedge-claim rationale: a gap is
//! *named, timestamped, and signed* so "every action is auditable" remains a
//! property of the receipt rather than a false-positive.

use serde::{Deserialize, Serialize};

use super::body::ReceiptBody;

/// Audit gap window — one entry per contiguous daemon-unreachable window.
/// Populated from `~/.ember/sessions/<id>/audit-gaps.jsonl`, which is written
/// by the COHORT-A-9 fail-open path each time the launcher hook can't reach
/// emberd. See ADR 120 §"Failure modes" row 1.
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

/// Termination reason discriminator for the cohort-A `session.claude_code`
/// Receipt body. H1 invariant (cohort-A test plan): every grant terminates
/// in a signed Receipt across all four termination paths.
///
/// Wire form uses `kind = "snake_case"` so a future fifth shape (e.g.
/// `"daemon_shutdown"`) can be added without breaking parsers.
///
/// `Heartbeat`-related fields (`last_heartbeat_at`, `pid_alive_at_check`)
/// only populate the `HeartbeatLost` variant — clean exit / TTL expiry /
/// explicit revoke leave them at `None` / `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    /// Launcher sent `session.close` cleanly.
    CleanExit,
    /// Daemon detected the launcher's heartbeat lost (>90s without a fresh
    /// heartbeat AND PID no longer alive). COHORT-A-V03-HEARTBEAT-TERMINATION.
    HeartbeatLost,
    /// Grant TTL elapsed before the launcher closed the session.
    TtlExpired,
    /// Operator explicitly revoked via `ember grant revoke`.
    ExplicitRevoke,
    /// Grant exhausted one of its budget axes before the session ended.
    ExhaustedByBudget,
    /// Grant terminated because an ancestor grant was revoked.
    ParentCascadeRevoked,
}

/// Cohort A `session.claude_code` Receipt body. Wraps the generic
/// [`ReceiptBody`] (so all v2 fields — `claim_events[]`, `permits_merkle_root`
/// — flow through unchanged) and adds the cohort-A-specific extensions
/// permitted by ADR 118: `audit_gaps[]` for daemon-unreachable windows, and
/// the termination-reason triple (`termination_reason`, `last_heartbeat_at`,
/// `pid_alive_at_check`) for COHORT-A-V03-HEARTBEAT-TERMINATION's H1 invariant.
///
/// `#[serde(flatten)]` on `base` ensures the wire shape is one flat object
/// (matching ADR 118 §"Body" and ADR 120 §7), not a nested `{ base: { ... } }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaudeCodeBody {
    #[serde(flatten)]
    pub base: ReceiptBody,
    /// Daemon-unreachable windows recorded during the session. Empty when the
    /// daemon was reachable for the entire session — in which case the field
    /// is omitted from the wire form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_gaps: Vec<AuditGap>,
    /// Termination reason. `None` for receipts predating
    /// COHORT-A-V03-HEARTBEAT-TERMINATION; required for receipts emitted by
    /// the daemon-driven dirty-exit path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_reason: Option<TerminationReason>,
    /// ISO-8601 timestamp of the most recent heartbeat the daemon observed
    /// before it gave up. Populated only on `HeartbeatLost` — `None` for
    /// the other termination paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_at: Option<String>,
    /// Whether the launcher PID was alive at the moment the daemon checked.
    /// Populated only on `HeartbeatLost` — `Some(false)` on the canonical
    /// dirty-exit path, `Some(true)` only as a diagnostic when the daemon
    /// observed heartbeat-loss but the PID was still alive (a rare race
    /// the daemon should re-check rather than terminate on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_alive_at_check: Option<bool>,
}

/// Locked `kind` discriminator for the cohort-A `session.claude_code` Receipt.
/// Used as `ReceiptEnvelope.kind` per ADR 118 §"Envelope".
pub const RECEIPT_KIND_CLAUDE_CODE: &str = "session.claude_code";

/// Locked `kind` discriminator for composite-grant terminal session receipts.
pub const RECEIPT_KIND_COMPOSITE_GRANT: &str = "session.composite_grant";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::body::{ClaimEvent, ClaimKind};

    fn sample_claim_event() -> ClaimEvent {
        ClaimEvent {
            ts: "2026-05-01T12:00:00Z".into(),
            kind: ClaimKind::Approval,
            tool: "Bash".into(),
            action_ref: None,
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
                ..Default::default()
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
            termination_reason: None,
            last_heartbeat_at: None,
            pid_alive_at_check: None,
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
        // Per ADR 118 §"Body": claim_events / permits_merkle_root / audit_gaps
        // sit at the same JSON level — no nested `base` wrapper.
        let body = ClaudeCodeBody {
            base: ReceiptBody {
                claim_events: vec![sample_claim_event()],
                permits_merkle_root: String::new(),
                device_id: None,
                ..Default::default()
            },
            audit_gaps: vec![],
            termination_reason: None,
            last_heartbeat_at: None,
            pid_alive_at_check: None,
        };
        let value: serde_json::Value = serde_json::to_value(&body).unwrap();
        let obj = value.as_object().expect("body serializes to object");
        assert!(obj.contains_key("claim_events"));
        assert!(!obj.contains_key("base"));
    }

    #[test]
    fn termination_reason_round_trips_as_snake_case() {
        let cases = [
            (TerminationReason::CleanExit, "\"clean_exit\""),
            (TerminationReason::HeartbeatLost, "\"heartbeat_lost\""),
            (TerminationReason::TtlExpired, "\"ttl_expired\""),
            (TerminationReason::ExplicitRevoke, "\"explicit_revoke\""),
            (
                TerminationReason::ExhaustedByBudget,
                "\"exhausted_by_budget\"",
            ),
            (
                TerminationReason::ParentCascadeRevoked,
                "\"parent_cascade_revoked\"",
            ),
        ];
        for (reason, expected) in cases {
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, expected);
            let back: TerminationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn heartbeat_lost_body_round_trips_with_pid_diagnostic_fields() {
        let body = ClaudeCodeBody {
            base: ReceiptBody::default(),
            audit_gaps: vec![],
            termination_reason: Some(TerminationReason::HeartbeatLost),
            last_heartbeat_at: Some("2026-05-08T12:00:00Z".into()),
            pid_alive_at_check: Some(false),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"termination_reason\":\"heartbeat_lost\""));
        assert!(json.contains("\"last_heartbeat_at\":\"2026-05-08T12:00:00Z\""));
        assert!(json.contains("\"pid_alive_at_check\":false"));
        let back: ClaudeCodeBody = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.termination_reason,
            Some(TerminationReason::HeartbeatLost)
        );
        assert_eq!(
            back.last_heartbeat_at.as_deref(),
            Some("2026-05-08T12:00:00Z")
        );
        assert_eq!(back.pid_alive_at_check, Some(false));
    }

    #[test]
    fn termination_reason_fields_omit_when_none() {
        // Backward-compat: a body without termination metadata must not
        // emit the new fields onto the wire — receipts predating
        // COHORT-A-V03-HEARTBEAT-TERMINATION still parse and round-trip.
        let body = ClaudeCodeBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("termination_reason"));
        assert!(!json.contains("last_heartbeat_at"));
        assert!(!json.contains("pid_alive_at_check"));
    }
}
