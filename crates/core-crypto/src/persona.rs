//! CLASSIFICATION: PUBLIC
//! Daemon-as-Persona signing helper per ADR 116.
//!
//! Receipts are signed by the Daemon Persona's Ed25519 key. The canonical
//! byte sequence that gets signed is JCS(envelope with receipt_id, without
//! signature) — produced by `core_events::receipt::sign::sign_receipt_v2`.
//!
//! Canonicalization contract (bit-stable across releases):
//!   - The envelope is serialized to a `serde_json::Value`.
//!   - The `"signature"` key is removed.
//!   - The resulting value is JCS-canonicalized per RFC 8785 (UTF-16 key
//!     order, I-JSON number form, minimal string escaping).
//!   - The resulting bytes are signed directly with Ed25519.
//!
//! This function is the single named call site for Receipt signing per ADR 116;
//! `sign_receipt_v2` in `core-events` drives the canonicalization and calls
//! through to here via the `Signer` trait.

use crate::{Signature, Signer};

/// Sign a JCS-canonical Receipt body with the Daemon Persona key.
///
/// `canonical_body` is the JCS-canonical bytes of the Receipt envelope
/// (with `receipt_id` present, `signature` key removed). Produced by
/// `core_events::receipt::sign::sign_receipt_v2` before calling `signer.sign`.
///
/// The returned `Signature` uses the canonical `ed25519sig:<hex>` wire form.
///
/// Canonicalization note: the bytes are JCS per RFC 8785 — deterministic
/// across JVM/Rust/browser implementations, bit-stable across serializer
/// upgrades as long as the envelope field set and `serde_jcs` version are
/// pinned. Any envelope field addition is a wire-breaking change requiring
/// a version bump.
pub fn daemon_persona_sign_receipt(canonical_body: &[u8], signer: &dyn Signer) -> Signature {
    signer.sign(canonical_body)
}

/// Verify a Receipt signature against a public key.
///
/// Returns `true` iff the `signature` verifies over `canonical_body` under
/// `public_key`. Callers should use `verify_receipt_v2` in `core_events`
/// for the full envelope-level check (receipt_id + signature); this function
/// is the raw cryptographic primitive exposed for property testing.
pub fn daemon_persona_verify_receipt(
    canonical_body: &[u8],
    public_key: &crate::PublicKey,
    signature: &Signature,
    verifier: &dyn crate::Verifier,
) -> bool {
    verifier.verify(public_key, canonical_body, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ed25519Verifier, FixtureSigner, Signer as _};

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = FixtureSigner::new("persona-receipt-sign");
        let pk = signer.public_key();
        let payload = b"canonicalized receipt body bytes";
        let sig = daemon_persona_sign_receipt(payload, &signer);
        assert!(daemon_persona_verify_receipt(
            payload,
            &pk,
            &sig,
            &Ed25519Verifier
        ));
    }

    #[test]
    fn tamper_single_byte_fails_verify() {
        let signer = FixtureSigner::new("persona-receipt-tamper");
        let pk = signer.public_key();
        let mut payload = b"canonicalized receipt body bytes".to_vec();
        let sig = daemon_persona_sign_receipt(&payload, &signer);
        // Flip one byte — any modification must break verification.
        payload[0] ^= 0x01;
        assert!(!daemon_persona_verify_receipt(
            &payload,
            &pk,
            &sig,
            &Ed25519Verifier
        ));
    }

    #[test]
    fn empty_payload_round_trips() {
        let signer = FixtureSigner::new("persona-receipt-empty");
        let pk = signer.public_key();
        let sig = daemon_persona_sign_receipt(b"", &signer);
        assert!(daemon_persona_verify_receipt(
            b"",
            &pk,
            &sig,
            &Ed25519Verifier
        ));
    }

    #[test]
    fn wrong_public_key_fails_verify() {
        let signer_a = FixtureSigner::new("persona-receipt-key-a");
        let signer_b = FixtureSigner::new("persona-receipt-key-b");
        let pk_b = signer_b.public_key();
        let payload = b"receipt body signed by key A";
        let sig = daemon_persona_sign_receipt(payload, &signer_a);
        // Verifying key-A's signature under key-B must fail.
        assert!(!daemon_persona_verify_receipt(
            payload,
            &pk_b,
            &sig,
            &Ed25519Verifier
        ));
    }

    /// T1 property test: sign → verify round-trip holds for any payload.
    /// Also exercises tamper-fails-verify (flipping first byte).
    ///
    /// Uses a table of varied-length inputs to cover the key property
    /// without the proptest dependency in core-crypto's minimal dep set.
    #[test]
    fn property_sign_verify_and_tamper_varied_inputs() {
        let signer = FixtureSigner::new("persona-property-t1");
        let pk = signer.public_key();
        let verifier = Ed25519Verifier;

        let payloads: &[&[u8]] = &[
            b"",
            b"a",
            b"{}",
            b"{\"kind\":\"session.claude_code\",\"receipt_id\":\"abcd\"}",
            &[0u8; 64],
            &[0xffu8; 128],
            // Simulate a realistic JCS envelope with a long body.
            br#"{"body":{"audit_gaps":[],"claim_events":[]},"daemon_root_id":"root-abc","kind":"session.claude_code","receipt_id":"0000000000000000000000000000000000000000000000000000000000000000","termination_authority":"user_session","version":"2"}"#,
        ];

        for payload in payloads {
            // Property 1: sign → verify → ok
            let sig = daemon_persona_sign_receipt(payload, &signer);
            assert!(
                daemon_persona_verify_receipt(payload, &pk, &sig, &verifier),
                "sign+verify must succeed for payload of len {}",
                payload.len()
            );

            // Property 2: tamper → verify fails
            if !payload.is_empty() {
                let mut tampered = payload.to_vec();
                tampered[0] ^= 0x01;
                assert!(
                    !daemon_persona_verify_receipt(&tampered, &pk, &sig, &verifier),
                    "tampered payload must fail verification for original len {}",
                    payload.len()
                );
            }
        }
    }
}
