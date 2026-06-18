//! Receipt v2 envelope. ADR 118 §"Envelope".
//!
//! All fields are JCS-canonicalized for signing. `receipt_id` is `blake3(JCS(envelope-without-signature))`.

use serde::{Deserialize, Serialize};

/// Locked at "2" for ADR 118 compliance.
pub const RECEIPT_VERSION_V2: &str = "2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptVersion(pub String);

impl Default for ReceiptVersion {
    fn default() -> Self {
        Self(RECEIPT_VERSION_V2.into())
    }
}

/// Per ADR 118 §F5. Distinguishes *who* terminated the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationAuthority {
    /// Clean launcher exit OR explicit `ember grant revoke`.
    UserSession,
    /// Daemon-detected heartbeat orphan OR TTL expiry.
    DaemonPersona,
}

/// receipt_v2_presence_kind — per ADR 118 §Amendments + ADR 154 Topic 6 D5.
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
    /// per ADR 152). The strongest claim: the caller's uid was inspected via
    /// SO_PEERCRED and their session presence was re-verified at the moment
    /// the RPC landed.
    AttestedNow,
    /// mTLS client cert SAN, attested at cert mint time (bridge lane — per
    /// ADR 154 Component 2). The cert proves the caller was present when the
    /// daemon minted the credential; the daemon does NOT re-prove presence
    /// per-call. Honest framing: "was here at mint", not "is here now."
    AttestedAtMint,
    /// Identity was valid but the underlying statement was revoked before
    /// this call landed. Receipt is emitted for the audit trail; the call
    /// itself returned a `PolicyError::Forbidden("statement_revoked:<sid>")`.
    RevokedBefore,
}

/// receipt_v2_presence_reason — per ADR 154 Topic 6 D5 / META-AP-PRESENCE-BRIDGE-RECEIPT-FIELDS.
/// *Why* the presence proof was requested. Distinct from [`PresenceKind`]
/// (which is *what kind* of presence the receipt witnesses): `PresenceReason`
/// records the lifecycle event that triggered re-prompting the user for
/// physical presence — opening a fresh session, extending a near-expiry
/// handle, adding scope to an existing handle, just-in-time provisioning at
/// the moment of first use, or re-authenticating after a step-up trigger.
///
/// `None` on receipts where presence wasn't re-elicited for this call
/// (e.g. mid-session tool calls that ride an already-bound presence handle).
/// The serde-default + `skip_serializing_if = is_none` keep older fixtures
/// round-tripping cleanly without setting the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceReason {
    /// A new session/handle was opened — first presence challenge in the
    /// session's lifetime. Strongest baseline claim.
    SessionOpen,
    /// An existing handle was extended past its original expiry. Presence
    /// was re-elicited because the original window was about to lapse.
    Extend,
    /// Scope was added to an existing handle (broader caps than originally
    /// minted). Presence was re-elicited because the new scope crosses a
    /// policy threshold that demands fresh consent.
    AddScope,
    /// Just-in-time mint at the moment of first use. Presence was elicited
    /// because no live handle existed when the call landed; the handle was
    /// created on-demand for this RPC.
    Jit,
    /// Step-up re-authentication triggered by a policy event (e.g. risk
    /// signal, anomaly detection, explicit `reauth` admin action). Presence
    /// was re-elicited despite an existing valid handle.
    ReAuth,
}

/// Opaque handle ID for a presence-proof binding (per ADR 154 Topic 6).
/// String alias kept newtype-light to avoid churn on call sites that
/// already carry handle IDs as strings (UUID, opaque server-issued tokens).
pub type HandleId = String;

/// WebAuthn AAGUID of the authenticator that produced the presence proof
/// (16 bytes, per the FIDO2 spec). Captured on receipts where the presence
/// proof was sourced from a hardware authenticator so audit can distinguish
/// platform vs roaming authenticators (and specific vendor/model).
pub type Aaguid = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub version: ReceiptVersion,
    /// `kind` discriminates the body shape: `session.claude_code`, `atomic.tool_call`, etc.
    pub kind: String,
    /// `blake3(JCS(envelope-without-signature))`. Computed by signing helpers (out of scope this PR).
    pub receipt_id: String,
    /// Daemon's root persona ID (per ADR 116).
    pub daemon_root_id: String,
    /// W3C traceparent for distributed correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
    pub termination_authority: TerminationAuthority,
    /// Identity-presence audit discriminator. `None` on receipts that don't
    /// touch identity (most receipts pre-ADR-154-bridge). See [`PresenceKind`]
    /// for the variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_kind: Option<PresenceKind>,
    /// Body is opaque at the envelope level — kind-specific deserialization elsewhere.
    pub body: serde_json::Value,
    /// Persona-signed (per ADR 116). Hex-encoded ed25519. Out of scope this PR — populated by signing helper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Principal identity captured at the daemon's accept gate via SO_PEERCRED.
    /// `None` on receipts where peer-cred was not captured (pre-ADR-152 receipts).
    /// `skip_serializing_if` is load-bearing: `None` must not emit the key so
    /// existing receipts signed without this field continue to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_principal: Option<crate::receipt::sign::CallingPrincipal>,
    /// *Why* presence was re-elicited for this call (session-open / extend /
    /// add-scope / jit / re-auth). `None` on receipts where presence wasn't
    /// re-elicited (mid-session tool calls riding an existing handle). See
    /// [`PresenceReason`] for the variants. Per ADR 154 Topic 6 D5 /
    /// META-AP-PRESENCE-BRIDGE-RECEIPT-FIELDS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_reason: Option<PresenceReason>,
    /// Opaque handle ID for the presence-proof binding this call rode (or
    /// minted). `None` on receipts that don't touch a presence handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_id: Option<HandleId>,
    /// SHA-256 of the presence challenge bound to the call, as produced by
    /// `core_crypto::presence::bind_presence_challenge`. Recorded so audit can
    /// re-bind the challenge tuple (delegation_id, action_key, spiffe_uri,
    /// nonce) deterministically without storing the components themselves.
    /// `None` on receipts without an associated presence challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_hash: Option<[u8; 32]>,
    /// AAGUID of the WebAuthn authenticator that produced the presence
    /// proof. `None` when the proof did not originate from a hardware
    /// authenticator (e.g. presence delegated to OS biometric, or the
    /// receipt didn't witness a hardware presence event).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_aaguid: Option<Aaguid>,
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

    #[test]
    fn presence_reason_round_trip() {
        for (r, want) in [
            (PresenceReason::SessionOpen, "\"session_open\""),
            (PresenceReason::Extend, "\"extend\""),
            (PresenceReason::AddScope, "\"add_scope\""),
            (PresenceReason::Jit, "\"jit\""),
            (PresenceReason::ReAuth, "\"re_auth\""),
        ] {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(json, want);
            let back: PresenceReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, r);
        }
    }
}
