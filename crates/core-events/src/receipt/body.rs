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

/// Generic Receipt v2 body. Kind-specific extensions live in sibling modules
/// (e.g. `receipt::cohort_a` will add `audit_gaps[]` per implementation-note-45).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub claim_events: Vec<ClaimEvent>,
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
        assert!(body.permits_merkle_root.is_empty());
    }

    #[test]
    fn body_with_device_id_round_trip() {
        let mut body = ReceiptBody::default();
        body.device_id = Some("device-example-laptop".to_string());
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
    fn body_omits_workflow_fields_when_none() {
        let body = ReceiptBody::default();
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("workflow_id"));
        assert!(!json.contains("workflow_template"));
        assert!(!json.contains("pregrant_path"));
    }

    #[test]
    fn body_round_trips_workflow_fields() {
        let mut body = ReceiptBody::default();
        body.workflow_id = Some("wfg_01HQ0EXAMPLE".to_string());
        body.workflow_template = Some("emberd-development".to_string());
        body.pregrant_path = Some(PregrantPath::Workflow);
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
            let mut body = ReceiptBody::default();
            body.pregrant_path = Some(variant);
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
