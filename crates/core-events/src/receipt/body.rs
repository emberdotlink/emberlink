//! Receipt v2 body types. design §"Body" + §F6 (vocabulary lock — `claim_events[]`, NOT `decisions[]`).

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
/// (e.g. `receipt::cohort_a` will add `audit_gaps[]` per implementation-note-28).
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
}
