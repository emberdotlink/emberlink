//! Receipt v2 envelope. design §"Envelope".
//!
//! All fields are JCS-canonicalized for signing. `receipt_id` is `blake3(JCS(envelope-without-signature))`.

use serde::{Deserialize, Serialize};

/// Locked at "2" for design compliance.
pub const RECEIPT_VERSION_V2: &str = "2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptVersion(pub String);

impl Default for ReceiptVersion {
    fn default() -> Self {
        Self(RECEIPT_VERSION_V2.into())
    }
}

/// Per design §F5. Distinguishes *who* terminated the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationAuthority {
    /// Clean launcher exit OR explicit `ember grant revoke`.
    UserSession,
    /// Daemon-detected heartbeat orphan OR TTL expiry.
    DaemonPersona,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub version: ReceiptVersion,
    /// `kind` discriminates the body shape: `session.claude_code`, `atomic.tool_call`, etc.
    pub kind: String,
    /// `blake3(JCS(envelope-without-signature))`. Computed by signing helpers (out of scope this PR).
    pub receipt_id: String,
    /// Daemon's root persona ID (per design).
    pub daemon_root_id: String,
    /// W3C traceparent for distributed correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    pub termination_authority: TerminationAuthority,
    /// Body is opaque at the envelope level — kind-specific deserialization elsewhere.
    pub body: serde_json::Value,
    /// Persona-signed (per design). Hex-encoded ed25519. Out of scope this PR — populated by signing helper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_defaults_to_2() {
        assert_eq!(ReceiptVersion::default().0, "2");
    }

    #[test]
    fn termination_authority_round_trip() {
        let user = TerminationAuthority::UserSession;
        let json = serde_json::to_string(&user).unwrap();
        assert_eq!(json, "\"user_session\"");
        let back: TerminationAuthority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, user);
    }
}
