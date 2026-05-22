//! Receipt v2 body types. design §"Body" + §F6 (vocabulary lock — `claim_events[]`, NOT `decisions[]`).
//!
//! Checkpoint `pregrant_receipt_correlation_landed`: per design §Component 5,
//! every credentialed Receipt body carries (`workflow_id`,
//! `workflow_template`, `pregrant_path`) so auditors can trace a credential
//! back to the workflow grant that authorised it. The fields are
//! `Option<>` so system-class callers (housekeeping) and pre-rollout
//! Receipts continue to deserialize cleanly. T1 property tests
//! (`body_omits_workflow_fields_when_none`, `body_round_trips_workflow_fields`,
//! `body_accepts_each_pregrant_path_variant`,
//! `body_forward_compat_old_bodies_deserialize_with_none_workflow_fields`)
//! live in the `tests` module below.

use core_event_types::PregrantPath;
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

/// Per design §F6. The vocabulary is locked: `claim_events`, not `decisions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    Approval,
    Denial,
    CredentialVended,
    ScopeCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimEvent {
    pub ts: String,
    pub kind: ClaimKind,
    pub tool: String,
    pub input_hash: String,
    /// Tool-aware redacted form. design §"Tool-aware redaction".
    pub input_redacted: serde_json::Value,
    pub resolved: serde_json::Value,
}

/// Segment digest for scalable session/composite receipt materialization.
///
/// This is additive receipt-wire state for long-lived scopes whose full claim
/// history should not be forced into one terminal in-memory blob. Atomic
/// receipts leave this empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSegmentDigest {
    pub segment_no: u64,
    pub first_scope_seq: u64,
    pub last_scope_seq: u64,
    pub claim_count: u64,
    pub started_at: String,
    pub ended_at: String,
    pub merkle_root: String,
}

/// Generic Receipt v2 body. Kind-specific extensions live in sibling modules
/// (e.g. `receipt::cohort_a` will add `audit_gaps[]` per implementation-note-47).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub claim_events: Vec<ClaimEvent>,
    /// Total claims represented by this receipt scope. When this exceeds
    /// `claim_events.len()`, the receipt is carrying a bounded recent tail plus
    /// segment summaries rather than the full claim history inline.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub claim_count_total: Option<u64>,
    /// Whether `claim_events` is a bounded tail rather than the complete set of
    /// claims for this scope.
    #[serde(skip_serializing_if = "is_false", default)]
    pub claim_events_truncated: bool,
    /// Segment digests for scalable session/composite rollups. Empty for
    /// atomic receipts and small session receipts that still inline every
    /// claim event.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub claim_segment_summaries: Vec<ClaimSegmentDigest>,
    /// Full-scope history root over `claim_segment_summaries[]`.
    ///
    /// This is distinct from `permits_merkle_root`, which continues to cover
    /// the inline `claim_events[]` field only. When `claim_events_truncated` is
    /// true, this field anchors the complete scope history.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub claim_history_merkle_root: String,
    /// `blake3` Merkle root over `claim_events[].input_hash` per design §"Merkle leaf format".
    /// Empty until populated by signing helper.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub permits_merkle_root: String,
    /// Device identity that issued this Receipt. Decoupled from Persona ID
    /// per design — Device gets first-class signed Receipt body field
    /// representation independent of which Persona was active.
    /// `None` for Receipts predating the Device-first-class transition;
    /// MUST be `Some` for Receipts issued after the rollout completes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device_id: Option<String>,
    /// Active workflow grant at the time of the call (ULID-shaped). `None`
    /// for system-class callers that have no workflow context (the daemon's
    /// own housekeeping). Per design §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workflow_id: Option<String>,
    /// Human-readable template name (e.g. `emberd-development`). `None`
    /// whenever `workflow_id` is `None`. Per design §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workflow_template: Option<String>,
    /// Which broker-resolve evaluation lane approved (or denied) this call.
    /// `None` for Receipts that pre-date the workflow primitive rollout or
    /// for system-class callers; populated for every credentialed Receipt
    /// after the daemon's `broker.resolve` wiring lands. Per design
    /// §Component 2 + §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pregrant_path: Option<PregrantPath>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_kind_round_trip() {
        let cases = [
            (ClaimKind::Approval, "approval"),
            (ClaimKind::Denial, "denial"),
            (ClaimKind::CredentialVended, "credential_vended"),
            (ClaimKind::ScopeCheck, "scope_check"),
        ];
        for (kind, expected) in cases {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn body_default_empty() {
        let body = ReceiptBody::default();
        assert!(body.claim_events.is_empty());
        assert_eq!(body.claim_count_total, None);
        assert!(!body.claim_events_truncated);
        assert!(body.claim_segment_summaries.is_empty());
        assert!(body.claim_history_merkle_root.is_empty());
        assert!(body.permits_merkle_root.is_empty());
    }

    #[test]
    fn body_with_device_id_round_trip() {
        let body = ReceiptBody {
            device_id: Some("device-example-laptop".to_string()),
            ..ReceiptBody::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"device_id\":\"device-example-laptop\""));
        let back: ReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.device_id, Some("device-example-laptop".to_string()));
    }

    #[test]
    fn body_omits_device_id_when_none() {
        let body = ReceiptBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("device_id"));
    }

    #[test]
    fn body_omits_segmented_rollup_fields_when_empty() {
        let body = ReceiptBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("claim_count_total"));
        assert!(!json.contains("claim_events_truncated"));
        assert!(!json.contains("claim_segment_summaries"));
        assert!(!json.contains("claim_history_merkle_root"));
    }

    #[test]
    fn body_round_trips_segmented_rollup_fields() {
        let mut body = ReceiptBody::default();
        body.claim_events = vec![ClaimEvent {
            ts: "2026-05-22T12:00:00Z".to_string(),
            kind: ClaimKind::CredentialVended,
            tool: "Claude".to_string(),
            input_hash: "h1".to_string(),
            input_redacted: serde_json::json!({"cmd": "deploy"}),
            resolved: serde_json::json!({"allowed": true}),
        }];
        body.claim_count_total = Some(9);
        body.claim_events_truncated = true;
        body.claim_segment_summaries = vec![ClaimSegmentDigest {
            segment_no: 0,
            first_scope_seq: 1,
            last_scope_seq: 8,
            claim_count: 8,
            started_at: "2026-05-22T12:00:00Z".to_string(),
            ended_at: "2026-05-22T12:05:00Z".to_string(),
            merkle_root: "deadbeef".to_string(),
        }];
        body.claim_history_merkle_root = "cafebabe".to_string();
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("claim_count_total"));
        assert!(json.contains("claim_events_truncated"));
        assert!(json.contains("claim_segment_summaries"));
        assert!(json.contains("claim_history_merkle_root"));
        let back: ReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.claim_count_total, Some(9));
        assert!(back.claim_events_truncated);
        assert_eq!(back.claim_segment_summaries.len(), 1);
        assert_eq!(back.claim_segment_summaries[0].claim_count, 8);
        assert_eq!(back.claim_history_merkle_root, "cafebabe");
    }

    #[test]
    fn body_omits_workflow_fields_when_none() {
        let body = ReceiptBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("workflow_id"));
        assert!(!json.contains("workflow_template"));
        assert!(!json.contains("pregrant_path"));
    }

    #[test]
    fn body_round_trips_workflow_fields() {
        let body = ReceiptBody {
            workflow_id: Some("wfg_01HQ0EXAMPLE".to_string()),
            workflow_template: Some("emberd-development".to_string()),
            pregrant_path: Some(PregrantPath::Workflow),
            ..ReceiptBody::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"workflow_id\":\"wfg_01HQ0EXAMPLE\""));
        assert!(json.contains("\"workflow_template\":\"emberd-development\""));
        assert!(json.contains("\"pregrant_path\":\"workflow\""));
        let back: ReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workflow_id, body.workflow_id);
        assert_eq!(back.workflow_template, body.workflow_template);
        assert_eq!(back.pregrant_path, body.pregrant_path);
    }

    #[test]
    fn body_accepts_each_pregrant_path_variant() {
        for variant in [
            PregrantPath::Workflow,
            PregrantPath::PerAction,
            PregrantPath::Jit,
            PregrantPath::Deny,
        ] {
            let body = ReceiptBody {
                pregrant_path: Some(variant),
                ..ReceiptBody::default()
            };
            let json = serde_json::to_string(&body).unwrap();
            let back: ReceiptBody = serde_json::from_str(&json).unwrap();
            assert_eq!(back.pregrant_path, Some(variant));
        }
    }

    #[test]
    fn body_forward_compat_old_bodies_deserialize_with_none_workflow_fields() {
        // Older Receipts shipped before workflow primitives — serde defaults
        // the new Optional fields to None on absent input.
        let old_json = r#"{"claim_events":[]}"#;
        let body: ReceiptBody = serde_json::from_str(old_json).unwrap();
        assert_eq!(body.workflow_id, None);
        assert_eq!(body.workflow_template, None);
        assert_eq!(body.pregrant_path, None);
    }
}
