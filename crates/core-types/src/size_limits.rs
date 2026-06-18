//! Per-field and envelope-level size caps for events.
//!
//! Background: a sync peer (or local attacker tampering with SQLite) can
//! sign and submit an `EventEnvelope` whose attacker-controlled string
//! field — e.g. `MessageSentEvent::ciphertext_hex` — is hundreds of MB.
//! Without a cap, the event passes `validate_non_empty`, the signature
//! verifies, the authorizer accepts it, and the daemon persists the blob
//! to the authoritative event log. Repeating the attack inflates SQLite
//! and bloats every peer that sync-pulls. See
//! `docs/security-reviews/events-rs-2026-04-23.md` H-1.
//!
//! The fix is two layers:
//!
//! 1. Per-field caps applied inside each affected `Validate` impl so the
//!    attack is rejected at the structural level.
//! 2. An envelope-level `MAX_EVENT_PAYLOAD_BYTES` backstop applied inside
//!    `EventEnvelope::validate` (in `core-events`) that bounds the total
//!    canonical payload regardless of which field the attacker stuffed.
//!    This catches future field additions that forget to add a cap.
//!
//! Caps are deliberately generous (≈2× the legitimate worst case) so
//! they reject pathological payloads without breaking real workloads.
//! Truncation is NOT used — truncation would change the canonical bytes
//! and break the signature. The only safe response to an oversized field
//! is to reject the event.

use crate::ValidationError;

/// Maximum size of a hex-encoded ciphertext field (e.g.
/// `MessageSentEvent::ciphertext_hex`, `ContentPublishedEvent::payload_hex`).
/// 64 KiB hex covers ~32 KiB plaintext plus framing — comfortably above
/// any realistic single-message DM or content payload.
pub const MAX_CIPHERTEXT_HEX_BYTES: usize = 64 * 1024;

/// Maximum size of the sealed grant payload hex (e.g.
/// `GrantOfferCreatedEvent::sealed_payload_hex`,
/// `GrantOfferClaimedEvent::claim_response_hex`). 16 KiB is generous for
/// a sealed-box encrypted grant body (typical: a few hundred bytes).
pub const MAX_SEALED_PAYLOAD_HEX_BYTES: usize = 16 * 1024;

/// Maximum size of a hex-encoded ephemeral public key (e.g.
/// `GrantOfferCreatedEvent::ephemeral_public_key_hex`). 32 bytes raw =
/// 64 hex chars; 256 bytes hex is more than enough headroom for any
/// reasonable curve we might add later.
pub const MAX_PUBLIC_KEY_HEX_BYTES: usize = 256;

/// Maximum size of the JSON-encoded conditions tree on a grant offer
/// (`GrantOfferCreatedEvent::conditions_json`). 8 KiB fits a deeply
/// nested condition list (badge gates, time windows, peer allowlists)
/// many times over.
pub const MAX_CONDITIONS_JSON_BYTES: usize = 8 * 1024;

/// Maximum size of a human-readable reason field (every `reason: String`
/// in events.rs). 1 KiB is plenty for a structured human explanation
/// and stops a peer from stuffing megabytes into the audit log.
pub const MAX_REASON_BYTES: usize = 1024;

/// Maximum size of an evidence payload attached to a badge issuance
/// (`BadgeEvidence::payload_hex`) or a badge dispute
/// (`BadgeDisputedEvent::evidence`). 4 KiB hex = ~2 KiB raw; bigger
/// evidence (e.g. photos, signed proofs) belongs in vault storage with
/// only a manifest hash here.
pub const MAX_BADGE_PAYLOAD_HEX_BYTES: usize = 4 * 1024;

/// Maximum size of a transport hint string (e.g.
/// `RelayHintUpdatedEvent::transport_hint`,
/// `EndpointRotatedEvent::new_transport_hint`,
/// `GrantOfferCreatedEvent::relay_hint`). 1 KiB easily fits any
/// reasonable URL.
pub const MAX_TRANSPORT_HINT_BYTES: usize = 1024;

/// Maximum size of a free-form display label (`label`, `display_name`,
/// `evidence_type`, `badge_type`, `domain`, `content_type`). 256 bytes
/// is bigger than any UI will render and stops gigabyte labels.
pub const MAX_LABEL_BYTES: usize = 256;

/// Maximum size of a canonical event payload — the envelope-level
/// backstop applied in `EventEnvelope::validate`.
///
/// Sized to comfortably exceed the largest legitimate single field
/// (`MAX_ENCRYPTED_BLOCKS_JSON_BYTES = 1 MiB` on
/// `CredentialDepositedEvent`) plus framing overhead. Anything bigger
/// is structurally suspect even if every individual field is within its
/// per-field cap (or if a future field forgot to add a cap).
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Validate that `value.len() <= limit`. Rejects with a specific,
/// caller-actionable error that names the field and shows actual vs
/// limit so a peer sending oversized payloads can be diagnosed.
pub fn validate_size(value: &str, field: &str, limit: usize) -> Result<(), ValidationError> {
    if value.len() > limit {
        return Err(ValidationError::invalid_format(format!(
            "{field} exceeds maximum size: {actual} > {limit} bytes",
            field = field,
            actual = value.len(),
            limit = limit,
        )));
    }
    Ok(())
}

/// Validate that an optional string is within its size cap. None is
/// always OK (the field's absence carries no payload).
pub fn validate_optional_size(
    value: Option<&str>,
    field: &str,
    limit: usize,
) -> Result<(), ValidationError> {
    match value {
        Some(s) => validate_size(s, field, limit),
        None => Ok(()),
    }
}

/// Validate the envelope-level cap on the canonical payload bytes.
/// Called from `EventEnvelope::validate`.
pub fn validate_envelope_payload_size(payload_len: usize) -> Result<(), ValidationError> {
    if payload_len > MAX_EVENT_PAYLOAD_BYTES {
        return Err(ValidationError::invalid_format(format!(
            "event payload exceeds maximum size: {payload_len} > {MAX_EVENT_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_size_accepts_at_limit() {
        let value = "x".repeat(MAX_REASON_BYTES);
        assert!(validate_size(&value, "reason", MAX_REASON_BYTES).is_ok());
    }

    #[test]
    fn validate_size_rejects_over_limit() {
        let value = "x".repeat(MAX_REASON_BYTES + 1);
        let err = validate_size(&value, "reason", MAX_REASON_BYTES).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "expected size error, got: {err}"
        );
        assert!(
            err.to_string().contains("reason"),
            "error must name the offending field, got: {err}"
        );
    }

    #[test]
    fn validate_optional_size_none_is_ok() {
        assert!(validate_optional_size(None, "field", 16).is_ok());
    }

    #[test]
    fn validate_optional_size_some_enforces_cap() {
        let value = "x".repeat(17);
        let err = validate_optional_size(Some(&value), "field", 16).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn validate_envelope_payload_size_accepts_at_limit() {
        assert!(validate_envelope_payload_size(MAX_EVENT_PAYLOAD_BYTES).is_ok());
    }

    #[test]
    fn validate_envelope_payload_size_rejects_over_limit() {
        let err = validate_envelope_payload_size(MAX_EVENT_PAYLOAD_BYTES + 1).unwrap_err();
        assert!(err.to_string().contains("event payload exceeds"));
    }
}
