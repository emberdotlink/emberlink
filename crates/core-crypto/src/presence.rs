//! Presence attestation trait.
//! .B: Tier 1/2 approvals consult an attester before flipping
//! approved state. Real macOS SE wiring deferred to .B-SE-WIRE.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceProof {
    /// Bytes the attester signed/proved (typically grant_id || statement_hash || now).
    pub challenge: Vec<u8>,
    /// Timestamp when proof was produced (millis since epoch).
    pub produced_at_ms: u64,
    /// Implementation name, for audit (e.g. "null", "se-macos-v1").
    pub attester_name: String,
    /// Optional implementation-specific attestation bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("presence attestation unavailable: {0}")]
    Unavailable(String),
    #[error("presence attestation refused by user")]
    Refused,
    #[error("presence proof too stale (age_ms={age_ms})")]
    Stale { age_ms: u64 },
}

pub trait PresenceAttester: Send + Sync {
    fn name(&self) -> &str;
    fn attest(&self, challenge: &[u8]) -> Result<PresenceProof, PresenceError>;
}

#[derive(Debug, Default)]
pub struct NullAttester;

impl PresenceAttester for NullAttester {
    fn name(&self) -> &str {
        "null"
    }
    fn attest(&self, _challenge: &[u8]) -> Result<PresenceProof, PresenceError> {
        Err(PresenceError::Unavailable(
            "NullAttester always refuses; configure SecureEnclaveAttester or alternative".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
pub struct SecureEnclaveAttester;

#[cfg(target_os = "macos")]
impl PresenceAttester for SecureEnclaveAttester {
    fn name(&self) -> &str {
        "se-macos-v1-stub"
    }
    fn attest(&self, _challenge: &[u8]) -> Result<PresenceProof, PresenceError> {
        Err(PresenceError::Unavailable(
            "SecureEnclaveAttester wire-up deferred to .B-SE-WIRE".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_attester_always_refuses() {
        let a = NullAttester;
        let r = a.attest(b"test-challenge");
        assert!(matches!(r, Err(PresenceError::Unavailable(_))));
        assert_eq!(a.name(), "null");
    }

    #[test]
    fn presence_proof_round_trips_through_serde() {
        let p = PresenceProof {
            challenge: vec![0xde, 0xad],
            produced_at_ms: 42,
            attester_name: "test".to_string(),
            attestation: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PresenceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
