//! Receipt v2 sign / verify helpers. design §"Cryptographic discipline".
//!
//! Receipt-id derivation: `receipt_id = blake3(JCS(envelope without signature
//! and receipt_id))` (hex-encoded).
//!
//! Signature derivation: `signature = Ed25519(JCS(envelope without signature))`.
//! The signature is stored as the existing `core_crypto::Signature` string
//! representation (`ed25519sig:<hex>`), which is the canonical wire form used
//! everywhere else in the protocol.

use core_crypto::{
    CanonicalizeError, PublicKey, Signature, Signer, Verifier, canonicalize_jcs,
    daemon_persona_sign_receipt, daemon_persona_verify_receipt,
};
use thiserror::Error;

// receipt_v2_presence_kind — per design §Amendments + design Topic 6 D5.
// The discriminator enum lives in `super::envelope::PresenceKind`; the
// ReceiptEnvelope carries it as `presence_kind: Option<PresenceKind>` with
// serde-default + skip-if-none so existing fixtures round-trip cleanly
// without setting the field. Signing/verification (this module) treat the
// field as part of the canonical body — JCS preserves it when present,
// omits it when None, both deterministically.
use super::envelope::ReceiptEnvelope;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("canonicalization failed: {0}")]
    Canonicalize(#[from] CanonicalizeError),
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("signature missing")]
    SignatureMissing,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("receipt_id mismatch: stored={stored} computed={computed}")]
    ReceiptIdMismatch { stored: String, computed: String },
    #[error("spawn.witness body missing required field: {field}")]
    SpawnWitnessMissingField { field: &'static str },
    #[error("spawn.witness parent_signature verification failed")]
    SpawnWitnessParentSignatureInvalid,
}

/// Serialize envelope to a `serde_json::Value`, then strip `signature` and
/// (optionally) `receipt_id` for hashing.
fn envelope_for_hashing(
    envelope: &ReceiptEnvelope,
    include_receipt_id: bool,
) -> Result<serde_json::Value, SignError> {
    let mut v = serde_json::to_value(envelope)?;
    if let serde_json::Value::Object(map) = &mut v {
        map.remove("signature");
        if !include_receipt_id {
            map.remove("receipt_id");
        }
    }
    Ok(v)
}

/// Compute `receipt_id` = blake3(JCS(envelope without signature + receipt_id))
/// — hex-encoded.
pub fn compute_receipt_id(envelope: &ReceiptEnvelope) -> Result<String, SignError> {
    let v = envelope_for_hashing(envelope, /* include_receipt_id */ false)?;
    let bytes = canonicalize_jcs(&v)?;
    let hash = blake3::hash(&bytes);
    Ok(hash.to_hex().to_string())
}

/// Populate `receipt_id`, then sign `JCS(envelope without signature)` with
/// Ed25519 via the Daemon Persona per design.
///
/// The signature is stored as the canonical `ed25519sig:<hex>` form. Signing
/// routes through [`daemon_persona_sign_receipt`] — the named primitive for
/// design Daemon Persona signing — rather than calling `signer.sign` directly,
/// so the single call site is greppable and auditable.
pub fn sign_receipt_v2(
    envelope: &mut ReceiptEnvelope,
    signer: &dyn Signer,
) -> Result<(), SignError> {
    envelope.receipt_id = compute_receipt_id(envelope)?;
    let v = envelope_for_hashing(envelope, /* include_receipt_id */ true)?;
    let bytes = canonicalize_jcs(&v)?;
    let sig = daemon_persona_sign_receipt(&bytes, signer);
    envelope.signature = Some(sig.0);
    Ok(())
}

/// Verify both `receipt_id` and `signature`. Both must match for `Ok`.
///
/// Requires a non-None `signature` — unsigned Receipts are rejected with
/// [`SignError::SignatureMissing`]. Verification routes through
/// [`daemon_persona_verify_receipt`] per design.
pub fn verify_receipt_v2(
    envelope: &ReceiptEnvelope,
    public_key: &PublicKey,
    verifier: &dyn Verifier,
) -> Result<(), SignError> {
    let computed = compute_receipt_id(envelope)?;
    if computed != envelope.receipt_id {
        return Err(SignError::ReceiptIdMismatch {
            stored: envelope.receipt_id.clone(),
            computed,
        });
    }
    let sig_str = envelope
        .signature
        .as_deref()
        .ok_or(SignError::SignatureMissing)?;
    let sig = Signature(sig_str.to_string());
    let v = envelope_for_hashing(envelope, /* include_receipt_id */ true)?;
    let bytes = canonicalize_jcs(&v)?;
    if core_crypto::daemon_persona_verify_receipt(&bytes, public_key, &sig, verifier) {
        Ok(())
    } else {
        Err(SignError::InvalidSignature)
    }
}

/// Locked `kind` discriminator for `spawn.witness` Receipt v2 envelopes.
/// Matches `core_receipts::RECEIPT_KIND_SPAWN_WITNESS`; duplicated here so
/// `core-events` does not need to depend on `core-receipts` to compose the
/// envelope kind field. Both must stay in sync — see the constant-equality
/// test in `core_receipts` for the lock.
pub const RECEIPT_KIND_SPAWN_WITNESS: &str = "spawn.witness";

/// Serialize a spawn.witness body to a JCS-canonical byte sequence with
/// `parent_signature` excluded — the exact bytes the parent persona must
/// Ed25519-sign.
///
/// **Pre:** `body` is a JSON object representing a `spawn.witness` body. The
/// `parent_signature` key may be absent or present (with any value); either
/// way it is dropped before canonicalization.
/// **Post:** returns JCS bytes of `body \ {parent_signature}`.
///
/// **Errors:** [`SignError::Canonicalize`] if JCS canonicalization fails (e.g.
/// non-finite floats); [`SignError::Serialize`] if the body cannot be cloned
/// through serde_json.
pub fn spawn_witness_canonical_bytes_for_parent(
    body: &serde_json::Value,
) -> Result<Vec<u8>, SignError> {
    let mut v = body.clone();
    if let serde_json::Value::Object(map) = &mut v {
        map.remove("parent_signature");
    }
    Ok(canonicalize_jcs(&v)?)
}

/// Sign a spawn.witness body's `parent_signature` field with the parent
/// persona's key, mutating `body` in place. The signature is over the JCS
/// canonical bytes of the body with `parent_signature` excluded.
///
/// **Pre:** `body` is a JSON object representing a `spawn.witness` body with
/// at minimum `spawned_persona_id`, `parent_persona_id`, `container_id`, and
/// `spawn_grant_id` fields. The `parent_signature` field, if present, will be
/// overwritten.
/// **Post:** `body["parent_signature"]` is set to the canonical `ed25519sig:<hex>`
/// wire form, signed by `parent_signer` over the canonical body excluding the
/// signature field itself.
///
/// **Errors:** propagates [`SignError::Canonicalize`] / [`SignError::Serialize`]
/// from [`spawn_witness_canonical_bytes_for_parent`]; [`SignError::SpawnWitnessMissingField`]
/// if `body` is not an object.
pub fn sign_spawn_witness_parent_signature(
    body: &mut serde_json::Value,
    parent_signer: &dyn Signer,
) -> Result<(), SignError> {
    if !body.is_object() {
        return Err(SignError::SpawnWitnessMissingField { field: "<root-object>" });
    }
    let bytes = spawn_witness_canonical_bytes_for_parent(body)?;
    let sig = parent_signer.sign(&bytes);
    if let serde_json::Value::Object(map) = body {
        map.insert(
            "parent_signature".into(),
            serde_json::Value::String(sig.0),
        );
    }
    Ok(())
}

/// Verify a spawn.witness body's `parent_signature` against the parent's
/// public key. This is the CRIT-7 mitigation check — without it, an emberd
/// impersonator could forge `spawned_persona_id` + `parent_persona_id` without
/// the parent's corroborating authorization.
///
/// **Pre:** `body` is a JSON object representing a `spawn.witness` body with
/// a populated `parent_signature` field (`ed25519sig:<hex>` wire form).
/// **Post:** returns `Ok(())` iff the signature verifies over the canonical
/// body with `parent_signature` excluded; otherwise an error variant.
///
/// **Errors:** [`SignError::SpawnWitnessMissingField`] (`parent_signature`)
/// if the field is absent or not a string; [`SignError::SpawnWitnessParentSignatureInvalid`]
/// if the signature does not verify under `parent_public_key`.
pub fn verify_spawn_witness_parent_signature(
    body: &serde_json::Value,
    parent_public_key: &PublicKey,
    verifier: &dyn Verifier,
) -> Result<(), SignError> {
    let sig_str = body
        .as_object()
        .and_then(|obj| obj.get("parent_signature"))
        .and_then(|v| v.as_str())
        .ok_or(SignError::SpawnWitnessMissingField {
            field: "parent_signature",
        })?;
    let sig = Signature(sig_str.to_string());
    let bytes = spawn_witness_canonical_bytes_for_parent(body)?;
    if daemon_persona_verify_receipt(&bytes, parent_public_key, &sig, verifier) {
        Ok(())
    } else {
        Err(SignError::SpawnWitnessParentSignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use core_crypto::{FixtureSigner, FixtureVerifier};
    use serde_json::json;

    fn sample_envelope() -> ReceiptEnvelope {
        ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "atomic.tool_call".into(),
            receipt_id: String::new(),
            daemon_root_id: "root-fixture".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: json!({"tool":"echo","args":{}}),
            signature: None,
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        sign_receipt_v2(&mut env, &signer).unwrap();
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
    }

    #[test]
    fn body_tamper_fails_verification() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        sign_receipt_v2(&mut env, &signer).unwrap();
        env.body = json!({"tool":"different","args":{}});
        let r = verify_receipt_v2(&env, &pk, &FixtureVerifier);
        assert!(r.is_err(), "body tamper should fail verification");
    }

    #[test]
    fn receipt_id_tamper_fails_verification() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        sign_receipt_v2(&mut env, &signer).unwrap();
        env.receipt_id = "0".repeat(64);
        let r = verify_receipt_v2(&env, &pk, &FixtureVerifier);
        assert!(r.is_err(), "receipt_id tamper should fail verification");
    }

    #[test]
    fn empty_body_signs() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        env.body = json!({});
        sign_receipt_v2(&mut env, &signer).unwrap();
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
    }

    #[test]
    fn missing_signature_fails_verification() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        sign_receipt_v2(&mut env, &signer).unwrap();
        env.signature = None;
        let r = verify_receipt_v2(&env, &pk, &FixtureVerifier);
        assert!(matches!(r, Err(SignError::SignatureMissing)));
    }

    #[test]
    fn receipt_id_is_deterministic() {
        let mut env = sample_envelope();
        let id1 = compute_receipt_id(&env).unwrap();
        // Stamping a stale id must not change recomputation.
        env.receipt_id = "stale".into();
        let id2 = compute_receipt_id(&env).unwrap();
        assert_eq!(id1, id2);
    }
}
