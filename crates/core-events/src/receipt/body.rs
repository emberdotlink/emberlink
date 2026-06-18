//! Receipt v2 body types. ADR 118 §"Body" + §F6 (vocabulary lock — `claim_events[]`, NOT `decisions[]`).
//!
//! Checkpoint `pregrant_receipt_correlation_landed`: per ADR 158 §Component 5,
//! every credentialed Receipt body carries (`delegation_id`,
//! `delegation_template`, `pregrant_path`) so auditors can trace a credential
//! back to the delegation grant that authorised it. The fields are
//! `Option<>` so system-class callers (housekeeping) and pre-rollout
//! Receipts continue to deserialize cleanly. T1 property tests
//! (`body_omits_workflow_fields_when_none`, `body_round_trips_workflow_fields`,
//! `body_accepts_each_pregrant_path_variant`,
//! `body_forward_compat_old_bodies_deserialize_with_none_workflow_fields`)
//! live in the `tests` module below.

use core_event_types::{ActionRef, PregrantPath};
use serde::{Deserialize, Serialize};

fn is_false(value: &bool) -> bool {
    !*value
}

/// Per ADR 118 §F6. The vocabulary is locked: `claim_events`, not `decisions`.
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
    /// Canonical structured action identity when the originating authority
    /// exercise was tied to a construct action.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub action_ref: Option<ActionRef>,
    pub input_hash: String,
    /// Tool-aware redacted form. ADR 118 §"Tool-aware redaction".
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
/// (e.g. `receipt::cohort_a` will add `audit_gaps[]` per COHORT-A-7).
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
    /// `blake3` Merkle root over `claim_events[].input_hash` per ADR 118 §"Merkle leaf format".
    /// Empty until populated by signing helper.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub permits_merkle_root: String,
    /// Device identity that issued this Receipt. Decoupled from Persona ID
    /// per ADR 116 — Device gets first-class signed Receipt body field
    /// representation independent of which Persona was active.
    /// `None` for Receipts predating the Device-first-class transition;
    /// MUST be `Some` for Receipts issued after the rollout completes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub device_id: Option<String>,
    /// Active delegation grant at the time of the call (ULID-shaped). `None`
    /// for system-class callers that have no workflow context (the daemon's
    /// own housekeeping). Per ADR 158 §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegation_id: Option<String>,
    /// Human-readable template name (e.g. `emberd-development`). `None`
    /// whenever `delegation_id` is `None`. Per ADR 158 §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegation_template: Option<String>,
    /// Which broker-resolve evaluation lane approved (or denied) this call.
    /// `None` for Receipts that pre-date the workflow primitive rollout or
    /// for system-class callers; populated for every credentialed Receipt
    /// after the daemon's `broker.resolve` wiring lands. Per ADR 158
    /// §Component 2 + §Component 5.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pregrant_path: Option<PregrantPath>,
}

/// Why a successful bridge cert refresh was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCertRefreshTriggerReason {
    TimerTriggered,
    RetryAfterFailure,
    OperatorInduced,
}

/// ADR 118 Extension 4 body for `bridge.cert_refreshed`.
///
/// Anchor: `refresh_cert_receipts_landed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCertRefreshedBody {
    pub old_cert_fingerprint: String,
    pub new_cert_fingerprint: String,
    pub persona_id: String,
    pub container_id: String,
    pub grant_id: String,
    pub refresh_seq: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_receipt_id: Option<String>,
    pub trigger_reason: BridgeCertRefreshTriggerReason,
    pub recovered_from_failure_count: u32,
}

/// ADR 118 Extension 5 body for `bridge.cert_refresh_failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCertRefreshFailedBody {
    pub persona_id: String,
    pub container_id: String,
    pub grant_id: String,
    pub refresh_seq: u32,
    pub attempt_count: u32,
    pub failure_cause: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retry_after_seconds: Option<u32>,
}

/// ADR 118 Extension 6 body for `bridge.cert_superseded` (ADR 173 M4).
///
/// Emitted immediately after a successful `refresh_cert` RPC commits the
/// new persona-row cert pin, recording that the previous fingerprint has
/// been deprecated. Pairs with the signed `bridge.cert_refreshed` receipt
/// minted on the same UPDATE — that receipt records the new-cert authority
/// half; this body records the old-cert deprecation half so an audit
/// walker can correlate the refresh lifecycle without re-parsing the
/// refreshed body.
///
/// Lossy-acceptable: the event is informational. The authoritative
/// refresh decision lives on the signed `bridge.cert_refreshed` receipt
/// (which carries the same `old_cert_fingerprint` field).
///
/// Anchor: `daemon_bridge_cert_superseded_event_emitted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCertSupersededBody {
    pub old_cert_fingerprint: String,
    pub new_cert_fingerprint: String,
    pub persona_id: String,
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
    fn bridge_cert_refresh_bodies_round_trip() {
        let refreshed = BridgeCertRefreshedBody {
            old_cert_fingerprint: "old".to_string(),
            new_cert_fingerprint: "new".to_string(),
            persona_id: "persona-1".to_string(),
            container_id: "ctr-1".to_string(),
            grant_id: "grant-1".to_string(),
            refresh_seq: 2,
            parent_receipt_id: Some("rct-parent".to_string()),
            trigger_reason: BridgeCertRefreshTriggerReason::RetryAfterFailure,
            recovered_from_failure_count: 1,
        };
        let json = serde_json::to_string(&refreshed).unwrap();
        assert!(json.contains("\"trigger_reason\":\"retry_after_failure\""));
        let back: BridgeCertRefreshedBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, refreshed);

        let failed = BridgeCertRefreshFailedBody {
            persona_id: "persona-1".to_string(),
            container_id: "ctr-1".to_string(),
            grant_id: "grant-1".to_string(),
            refresh_seq: 3,
            attempt_count: 4,
            failure_cause: "auth_failure_revoked".to_string(),
            reason: "grant revoked".to_string(),
            retry_after_seconds: None,
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert!(json.contains("\"failure_cause\":\"auth_failure_revoked\""));
        let back: BridgeCertRefreshFailedBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, failed);
    }

    #[test]
    fn bridge_cert_superseded_body_round_trips() {
        // `daemon_bridge_cert_superseded_event_emitted` — ADR 118 Extension 6.
        let body = BridgeCertSupersededBody {
            old_cert_fingerprint: "deadbeef".to_string(),
            new_cert_fingerprint: "feedface".to_string(),
            persona_id: "persona-1".to_string(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"old_cert_fingerprint\":\"deadbeef\""));
        assert!(json.contains("\"new_cert_fingerprint\":\"feedface\""));
        assert!(json.contains("\"persona_id\":\"persona-1\""));
        let back: BridgeCertSupersededBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn body_round_trips_segmented_rollup_fields() {
        let mut body = ReceiptBody::default();
        body.claim_events = vec![ClaimEvent {
            ts: "2026-05-22T12:00:00Z".to_string(),
            kind: ClaimKind::CredentialVended,
            tool: "Claude".to_string(),
            action_ref: Some(ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            )),
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
        assert!(json.contains("action_ref"));
        let back: ReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.claim_count_total, Some(9));
        assert!(back.claim_events_truncated);
        assert_eq!(back.claim_segment_summaries.len(), 1);
        assert_eq!(back.claim_segment_summaries[0].claim_count, 8);
        assert_eq!(back.claim_history_merkle_root, "cafebabe");
        assert_eq!(
            back.claim_events[0]
                .action_ref
                .as_ref()
                .map(ToString::to_string),
            Some("registry.ember.systems/ember-systems/ember-gh/pr_create@v1".to_string())
        );
    }

    #[test]
    fn claim_event_action_ref_string_round_trips_through_parser() {
        let refs = [
            ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            ),
            ActionRef::new("registry.ember.systems/ember-systems/git", "push", "v2"),
            ActionRef::new("did:web:example.com/acme/kubectl", "apply", "2026-05-25"),
        ];

        for action_ref in refs {
            let encoded = action_ref.to_string();
            let parsed = ActionRef::parse(&encoded).expect("parse displayed action_ref");
            assert_eq!(parsed, action_ref);

            let event = ClaimEvent {
                ts: "2026-05-22T12:00:00Z".to_string(),
                kind: ClaimKind::CredentialVended,
                tool: encoded,
                action_ref: Some(action_ref.clone()),
                input_hash: "h1".to_string(),
                input_redacted: serde_json::json!({"cmd": "deploy"}),
                resolved: serde_json::json!({"allowed": true}),
            };
            let json = serde_json::to_string(&event).unwrap();
            let back: ClaimEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back.action_ref, Some(action_ref));
        }
    }

    #[test]
    fn body_omits_delegation_fields_when_none() {
        let body = ReceiptBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("delegation_id"));
        assert!(!json.contains("delegation_template"));
        assert!(!json.contains("pregrant_path"));
    }

    #[test]
    fn body_round_trips_delegation_fields() {
        let body = ReceiptBody {
            delegation_id: Some("wfg_01HQ0EXAMPLE".to_string()),
            delegation_template: Some("emberd-development".to_string()),
            pregrant_path: Some(PregrantPath::StandingGrant),
            ..ReceiptBody::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"delegation_id\":\"wfg_01HQ0EXAMPLE\""));
        assert!(json.contains("\"delegation_template\":\"emberd-development\""));
        assert!(json.contains("\"pregrant_path\":\"standing_grant\""));
        let back: ReceiptBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.delegation_id, body.delegation_id);
        assert_eq!(back.delegation_template, body.delegation_template);
        assert_eq!(back.pregrant_path, body.pregrant_path);
    }

    #[test]
    fn body_accepts_each_pregrant_path_variant() {
        for variant in [
            PregrantPath::StandingGrant,
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
        assert_eq!(body.delegation_id, None);
        assert_eq!(body.delegation_template, None);
        assert_eq!(body.pregrant_path, None);
    }
}
