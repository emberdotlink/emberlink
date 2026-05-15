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

/// receipt_v2_presence_kind — per design §Amendments + design Topic 6 D5.
/// Audit-honesty discriminator for receipts that touch identity: distinguishes
/// "the caller was present at request time" from "the caller's cert was minted
/// while present and is still valid" from "the caller was present at mint, but
/// the underlying statement was revoked before this call landed."
///
/// `None` on receipts that don't touch identity (today: every non-bridge,
/// non-host-CLI receipt). Existing v2 envelopes get `None` during the schema
/// migration; the field's serde-default and `skip_serializing_if = is_none`
/// keep the wire format backward-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceKind {
    /// Peer-cred + presence-proof attested at request time (host CLI lane —
    /// per design). The strongest claim: the caller's uid was inspected via
    /// SO_PEERCRED and their session presence was re-verified at the moment
    /// the RPC landed.
    AttestedNow,
    /// mTLS client cert SAN, attested at cert mint time (bridge lane — per
    /// design Component 2). The cert proves the caller was present when the
    /// daemon minted the credential; the daemon does NOT re-prove presence
    /// per-call. Honest framing: "was here at mint", not "is here now."
    AttestedAtMint,
    /// Identity was valid but the underlying statement was revoked before
    /// this call landed. Receipt is emitted for the audit trail; the call
    /// itself returned a `PolicyError::Forbidden("statement_revoked:<sid>")`.
    RevokedBefore,
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
    /// Identity-presence audit discriminator. `None` on receipts that don't
    /// touch identity (most receipts pre-design-bridge). See [`PresenceKind`]
    /// for the variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_kind: Option<PresenceKind>,
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

    #[test]
    fn presence_kind_round_trip() {
        for (k, want) in [
            (PresenceKind::AttestedNow, "\"attested_now\""),
            (PresenceKind::AttestedAtMint, "\"attested_at_mint\""),
            (PresenceKind::RevokedBefore, "\"revoked_before\""),
        ] {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, want);
            let back: PresenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, k);
        }
    }
}
