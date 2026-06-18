//! Receipt v2 sign / verify helpers. ADR 118 §"Cryptographic discipline".
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
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Principal identity (uid/gid/pid) captured at the daemon's accept
/// gate via SO_PEERCRED / LOCAL_PEERCRED. Carried on Receipt v2 so
/// audit binding is "uid+gid+pid did X at T" rather than just "uid".
/// Per ADR 152 §"Destination".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallingPrincipal {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

// receipt_v2_presence_kind — per ADR 118 §Amendments + ADR 154 Topic 6 D5.
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
    /// Rotation-chain walk could not reach the signer of the target Receipt.
    /// Per META-AP-DAEMON-MEK-PERSISTENCE-E-3 §"Errors:".
    #[error("untrusted signer: rotation chain did not reach the receipt signer")]
    UntrustedSigner,
    /// A witness in the rotation chain failed its own signature check, or the
    /// chain order is wrong (witness signed by a key not yet in the trust set,
    /// or `rotated_at` not monotonically ascending).
    /// Per META-AP-DAEMON-MEK-PERSISTENCE-E-3 §"Errors:".
    #[error("broken chain: witness {index} failed verification: {reason}")]
    BrokenChain { index: usize, reason: String },
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
/// Ed25519 via the Daemon Persona per ADR 116.
///
/// The signature is stored as the canonical `ed25519sig:<hex>` form. Signing
/// routes through [`daemon_persona_sign_receipt`] — the named primitive for
/// ADR 116 Daemon Persona signing — rather than calling `signer.sign` directly,
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
/// [`daemon_persona_verify_receipt`] per ADR 116.
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
        return Err(SignError::SpawnWitnessMissingField {
            field: "<root-object>",
        });
    }
    let bytes = spawn_witness_canonical_bytes_for_parent(body)?;
    let sig = parent_signer.sign(&bytes);
    if let serde_json::Value::Object(map) = body {
        map.insert("parent_signature".into(), serde_json::Value::String(sig.0));
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

// identity_rotation_witness_chain_verified —
// META-AP-DAEMON-MEK-PERSISTENCE-E-3 checkpoint. The chain-walk verifier
// below threads the caller's trust set forward through a sorted slice
// of `identity.rotation_witness` Receipts so a Receipt signed by an
// identity not in the caller's initial trust set still verifies, so
// long as each witness in the chain is signed by a key already in the
// trust set and introduces the next epoch's public key.

/// One entry in a rotation-witness chain — the bundle Slice E3 needs to
/// thread `verify_receipt_v2_with_rotation_chain`'s trust set forward
/// across a `identity.rotation_witness` envelope.
///
/// Carries the envelope plus the `prior_identity_pub` and
/// `new_identity_pub` referenced by the brief's algorithm. The pubs are
/// passed alongside the envelope (rather than parsed out of the body)
/// because Slice E1's [`IdentityRotationWitnessBody`](super::IdentityRotationWitnessBody)
/// shipped the bridge as epoch-root *IDs* (`prev_epoch_root_id`,
/// `next_epoch_root_id`), not Ed25519 verifying keys — Ed25519 has no
/// signature-to-pub recovery, so the caller must supply the resolved
/// pubs. Slice E2 will own the production wire-up from epoch-root IDs
/// to `core_crypto::PublicKey` via the daemon vault; Slice E3 ships
/// against synthetic FixtureSigner pubs.
///
/// Anchor: `identity_rotation_witness_chain_verified`.
#[derive(Debug, Clone)]
pub struct RotationWitnessEntry {
    /// The signed `identity.rotation_witness` envelope. Its outer
    /// signature must verify under `prior_identity_pub`.
    pub envelope: ReceiptEnvelope,
    /// The previous epoch's identity public key — the key that signed
    /// this witness envelope. MUST already be in the chain-walker's
    /// trust set at the moment this witness is consumed.
    pub prior_identity_pub: PublicKey,
    /// The next epoch's identity public key — added to the chain-walker's
    /// trust set after this witness verifies. The receipt the caller is
    /// ultimately verifying may be signed by this key (or by a later
    /// `new_identity_pub` after further chain hops).
    pub new_identity_pub: PublicKey,
    /// Monotonic ordering field. The chain MUST be sorted ascending
    /// by `rotation_at`. The walker checks the ordering invariant
    /// and rejects out-of-order chains with [`SignError::BrokenChain`].
    pub rotation_at: u64,
}

/// Verify a Receipt v2 envelope, extending the trust set forward
/// through `identity.rotation_witness` Receipts as they appear in the
/// `witness_chain` slice.
///
/// **Pre:**
/// - `trusted_identities` is non-empty (at least one anchor). An empty
///   anchor set cannot witness any receipt.
/// - `witness_chain` is sorted by `rotation_at` ascending. The walker
///   enforces the invariant and rejects out-of-order chains.
///
/// **Post:**
/// - Returns `Ok(())` iff:
///   (a) `envelope`'s outer signature verifies against some
///   `signer_pub` AND
///   (b) `signer_pub` is in `trusted_identities` OR a `witness_chain`
///   walk from a trusted identity reaches `signer_pub` via a
///   contiguous chain of valid witnesses.
/// - Each witness in `witness_chain` MUST itself verify against the
///   trust set built up by the prior witnesses; the walker rejects
///   any chain where this transitive invariant breaks.
/// - The caller's `trusted_identities` slice is unmodified — the
///   trust set extension is local to this call.
///
/// **Errors:**
/// - [`SignError::UntrustedSigner`] if no key in the final trust set
///   verifies the target `envelope`. This is the canonical "the
///   signer is not in the chain" failure.
/// - [`SignError::BrokenChain`] if any witness fails its own
///   signature check, the witness `kind` field is wrong, the chain
///   ordering is non-monotonic, or `trusted_identities` is empty.
/// - All errors propagated from [`verify_receipt_v2`] (canonicalize,
///   serialize, receipt_id-mismatch) on the per-envelope check.
///
/// **Algorithm:**
/// 1. Start with `trust_set = trusted_identities` (cloned).
/// 2. For each witness `w_i` in `witness_chain` (in slice order, which
///    MUST be `rotation_at` ascending), require `w_i.prior_identity_pub`
///    to be in `trust_set`, verify `w_i.envelope` under that prior key,
///    require the identity-rotation witness kind, then add
///    `w_i.new_identity_pub` to `trust_set`.
/// 3. Verify the target `envelope` against `trust_set` — try each pub
///    in turn; first success returns `Ok(())`. If none succeed, return
///    [`SignError::UntrustedSigner`].
///
/// **Existing callers unaffected** — this is a strictly additive entry
/// point. [`verify_receipt_v2`] remains the single-anchor path.
pub fn verify_receipt_v2_with_rotation_chain(
    envelope: &ReceiptEnvelope,
    trusted_identities: &[PublicKey],
    witness_chain: &[RotationWitnessEntry],
    verifier: &dyn Verifier,
) -> Result<(), SignError> {
    // Pre: trust set is non-empty.
    if trusted_identities.is_empty() {
        return Err(SignError::BrokenChain {
            index: 0,
            reason: "trusted_identities must be non-empty".to_string(),
        });
    }

    let mut trust_set: Vec<PublicKey> = trusted_identities.to_vec();
    let mut last_rotation_at: Option<u64> = None;

    for (index, witness) in witness_chain.iter().enumerate() {
        // Pre: chain is sorted ascending by rotation_at.
        if let Some(prev_ts) = last_rotation_at
            && witness.rotation_at < prev_ts
        {
            return Err(SignError::BrokenChain {
                index,
                reason: format!(
                    "out-of-order witness chain: rotation_at={} < prior={}",
                    witness.rotation_at, prev_ts
                ),
            });
        }
        last_rotation_at = Some(witness.rotation_at);

        // Step 2.a: prior pub must already be in trust set.
        if !trust_set.contains(&witness.prior_identity_pub) {
            return Err(SignError::BrokenChain {
                index,
                reason: "prior_identity_pub not in current trust set".to_string(),
            });
        }

        // Step 2.c: kind discriminator must be the witness kind. Done
        // before signature verification so a kind mismatch surfaces as
        // BrokenChain rather than InvalidSignature.
        if witness.envelope.kind != super::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS {
            return Err(SignError::BrokenChain {
                index,
                reason: format!(
                    "witness envelope.kind={:?} != {:?}",
                    witness.envelope.kind,
                    super::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS
                ),
            });
        }

        // Step 2.b: verify the witness envelope under the prior pub.
        verify_receipt_v2(&witness.envelope, &witness.prior_identity_pub, verifier).map_err(
            |e| SignError::BrokenChain {
                index,
                reason: format!("witness envelope signature invalid: {e}"),
            },
        )?;

        // Step 2.d: extend trust set with the new identity. Dedup so we
        // don't repeatedly add the same pub on degenerate chains.
        if !trust_set.contains(&witness.new_identity_pub) {
            trust_set.push(witness.new_identity_pub.clone());
        }
    }

    // Step 3: verify target envelope against the (possibly extended)
    // trust set.
    let mut last_err: Option<SignError> = None;
    for candidate in &trust_set {
        match verify_receipt_v2(envelope, candidate, verifier) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    // If we ran past the loop without an Ok, none of the candidates
    // verified — surface as UntrustedSigner regardless of which inner
    // SignError variant the last candidate produced. `last_err` is
    // kept around so future telemetry can surface the underlying
    // failure if needed; today we collapse into UntrustedSigner per
    // the brief's contract.
    let _ = last_err;
    Err(SignError::UntrustedSigner)
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
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
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

    #[test]
    fn calling_principal_roundtrips_through_sign_verify() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        let pk = signer.public_key();
        let mut env = sample_envelope();
        env.calling_principal = Some(CallingPrincipal {
            uid: 501,
            gid: 502,
            pid: 12345,
        });
        sign_receipt_v2(&mut env, &signer).unwrap();
        // Verify signature holds with calling_principal present.
        verify_receipt_v2(&env, &pk, &FixtureVerifier).unwrap();
        // Deserialize round-trip: serialize to JSON then back.
        let wire = serde_json::to_vec(&env).unwrap();
        let decoded: ReceiptEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            decoded.calling_principal,
            Some(CallingPrincipal {
                uid: 501,
                gid: 502,
                pid: 12345
            }),
            "calling_principal must survive JSON round-trip"
        );
        // Signature must still verify after round-trip.
        verify_receipt_v2(&decoded, &pk, &FixtureVerifier).unwrap();
    }

    #[test]
    fn calling_principal_none_omits_from_canonical_bytes() {
        let signer = FixtureSigner::new("receipt-v2-sign");
        // Build two envelopes: one with calling_principal: None explicitly,
        // one default (which also has None via sample_envelope).
        let mut env_a = sample_envelope(); // calling_principal: None
        let mut env_b = sample_envelope(); // calling_principal: None (same)
        // Sign both and collect the JCS bytes used for the receipt_id
        // by checking that the resulting receipt_ids are identical — they are
        // computed from JCS bytes and JCS omits the field when None.
        sign_receipt_v2(&mut env_a, &signer).unwrap();
        sign_receipt_v2(&mut env_b, &signer).unwrap();
        assert_eq!(
            env_a.receipt_id, env_b.receipt_id,
            "receipt_id must be identical when calling_principal is None on both"
        );
        // Also assert the field is absent from the serialized JSON wire form.
        let wire_a = serde_json::to_value(&env_a).unwrap();
        assert!(
            wire_a
                .as_object()
                .map_or(true, |m| !m.contains_key("calling_principal")),
            "calling_principal=None must not appear in serialized JSON"
        );
    }

    // ===== Rotation-chain walk tests
    // (META-AP-DAEMON-MEK-PERSISTENCE-E-3) =====
    //
    // Anchor: identity_rotation_witness_chain_verified

    /// Build a witness envelope signed by `prior_signer` whose body
    /// bridges from prior epoch to next epoch. The body shape follows
    /// Slice E1's `IdentityRotationWitnessBody` JSON layout but is
    /// composed inline here so the test does not depend on Slice E1's
    /// constructor surface.
    fn witness_envelope(
        prior_signer: &FixtureSigner,
        prev_epoch_root_id: &str,
        next_epoch_root_id: &str,
        rotated_at_epoch_secs: u64,
    ) -> ReceiptEnvelope {
        let body = json!({
            "prev_epoch_root_id": prev_epoch_root_id,
            "next_epoch_root_id": next_epoch_root_id,
            "rotated_at_epoch_secs": rotated_at_epoch_secs,
            "signature_by_prev_root": "ed25519sig:00",
            "signature_by_next_root": "ed25519sig:01",
        });
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: super::super::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
            receipt_id: String::new(),
            daemon_root_id: prev_epoch_root_id.to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, prior_signer).unwrap();
        env
    }

    /// Three-epoch chain helper. Returns (epoch0_pub, witnesses_in_order,
    /// epoch_n_signer). Useful for building chains of arbitrary length.
    fn build_chain(epoch_count: usize) -> (PublicKey, Vec<RotationWitnessEntry>, FixtureSigner) {
        assert!(epoch_count >= 2, "chain must bridge at least two epochs");
        let signers: Vec<FixtureSigner> = (0..epoch_count)
            .map(|i| FixtureSigner::new(format!("chain-epoch-{i}")))
            .collect();
        let mut entries = Vec::with_capacity(epoch_count - 1);
        for i in 0..epoch_count - 1 {
            let env = witness_envelope(
                &signers[i],
                &format!("epoch-{i}"),
                &format!("epoch-{}", i + 1),
                1_000 + i as u64,
            );
            entries.push(RotationWitnessEntry {
                envelope: env,
                prior_identity_pub: signers[i].public_key(),
                new_identity_pub: signers[i + 1].public_key(),
                rotation_at: 1_000 + i as u64,
            });
        }
        let epoch0_pub = signers[0].public_key();
        let last_signer = signers.into_iter().last().unwrap();
        (epoch0_pub, entries, last_signer)
    }

    #[test]
    fn test_rotation_chain_single_hop_verifies() {
        // Single rotation: target Receipt signed by epoch-1, anchor is
        // epoch-0 — chain of length 1 must bridge them.
        let (epoch0_pub, chain, epoch1_signer) = build_chain(2);
        let mut target = sample_envelope();
        target.body = json!({"tool":"echo","args":{}});
        sign_receipt_v2(&mut target, &epoch1_signer).unwrap();
        verify_receipt_v2_with_rotation_chain(&target, &[epoch0_pub], &chain, &FixtureVerifier)
            .expect("single-hop rotation chain must verify");
    }

    #[test]
    fn test_rotation_chain_multi_hop_verifies() {
        // N=4 rotations; receipt signed by epoch-4 must verify against
        // anchor at epoch-0 via a contiguous chain.
        let (epoch0_pub, chain, last_signer) = build_chain(5);
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &last_signer).unwrap();
        verify_receipt_v2_with_rotation_chain(&target, &[epoch0_pub], &chain, &FixtureVerifier)
            .expect("multi-hop rotation chain must verify");
    }

    #[test]
    fn test_rotation_chain_anchor_already_signs_receipt() {
        // Degenerate case: the target is signed by a key already in
        // `trusted_identities`. Empty chain → still Ok.
        let signer = FixtureSigner::new("anchor-only");
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &signer).unwrap();
        verify_receipt_v2_with_rotation_chain(
            &target,
            &[signer.public_key()],
            &[],
            &FixtureVerifier,
        )
        .expect("anchor already signs target; empty chain must verify");
    }

    #[test]
    fn test_rotation_chain_out_of_order_breaks_chain() {
        // Build a valid 3-hop chain, then swap entries[1] and entries[2]
        // so rotation_at is non-monotonic — walker MUST reject as
        // BrokenChain.
        let (epoch0_pub, mut chain, last_signer) = build_chain(4);
        chain.swap(1, 2);
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &last_signer).unwrap();
        let err =
            verify_receipt_v2_with_rotation_chain(&target, &[epoch0_pub], &chain, &FixtureVerifier)
                .expect_err("out-of-order witness chain must fail");
        match err {
            SignError::BrokenChain { reason, .. } => {
                assert!(
                    reason.contains("out-of-order") || reason.contains("not in"),
                    "expected ordering or trust-set error; got {reason}"
                );
            }
            other => panic!("expected BrokenChain; got {other:?}"),
        }
    }

    #[test]
    fn test_rotation_chain_tampered_witness_body_breaks_chain() {
        // Build a valid chain, then tamper one witness envelope's body
        // post-signing. The envelope signature check inside the walk
        // MUST fail with BrokenChain.
        let (epoch0_pub, mut chain, last_signer) = build_chain(3);
        // Tamper the middle witness body — receipt_id no longer matches.
        chain[1].envelope.body = json!({"tampered": true});
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &last_signer).unwrap();
        let err =
            verify_receipt_v2_with_rotation_chain(&target, &[epoch0_pub], &chain, &FixtureVerifier)
                .expect_err("tampered witness body must fail");
        assert!(
            matches!(err, SignError::BrokenChain { .. }),
            "expected BrokenChain; got {err:?}"
        );
    }

    #[test]
    fn test_rotation_chain_untrusted_signer() {
        // Target Receipt signed by a foreign identity NOT in the chain.
        // The walk extends trust_set through the legitimate chain but
        // the target's signer is still outside it → UntrustedSigner.
        let (epoch0_pub, chain, _epoch_n_signer) = build_chain(3);
        let foreign_signer = FixtureSigner::new("foreign-never-rotated");
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &foreign_signer).unwrap();
        let err =
            verify_receipt_v2_with_rotation_chain(&target, &[epoch0_pub], &chain, &FixtureVerifier)
                .expect_err("foreign signer must not verify");
        assert!(
            matches!(err, SignError::UntrustedSigner),
            "expected UntrustedSigner; got {err:?}"
        );
    }

    #[test]
    fn test_rotation_chain_empty_trust_set_is_broken_chain() {
        // Pre-condition violation: empty trusted_identities. Walker
        // MUST refuse with BrokenChain rather than allowing any chain
        // to "anchor itself" by introducing the first witness.
        let signer = FixtureSigner::new("any");
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &signer).unwrap();
        let err = verify_receipt_v2_with_rotation_chain(&target, &[], &[], &FixtureVerifier)
            .expect_err("empty trust set must be rejected");
        assert!(
            matches!(err, SignError::BrokenChain { .. }),
            "expected BrokenChain; got {err:?}"
        );
    }

    #[test]
    fn test_rotation_chain_kind_mismatch_breaks_chain() {
        // A non-witness envelope in the witness_chain MUST be
        // rejected — the kind discriminator gate enforces that the
        // chain is composed exclusively of `identity.rotation_witness`
        // receipts.
        let signer_a = FixtureSigner::new("chain-bad-kind-a");
        let signer_b = FixtureSigner::new("chain-bad-kind-b");
        let mut bad_env = sample_envelope(); // kind = atomic.tool_call
        sign_receipt_v2(&mut bad_env, &signer_a).unwrap();
        let entry = RotationWitnessEntry {
            envelope: bad_env,
            prior_identity_pub: signer_a.public_key(),
            new_identity_pub: signer_b.public_key(),
            rotation_at: 1,
        };
        let mut target = sample_envelope();
        sign_receipt_v2(&mut target, &signer_b).unwrap();
        let err = verify_receipt_v2_with_rotation_chain(
            &target,
            &[signer_a.public_key()],
            &[entry],
            &FixtureVerifier,
        )
        .expect_err("non-witness kind in chain must fail");
        match err {
            SignError::BrokenChain { reason, .. } => {
                assert!(
                    reason.contains("kind"),
                    "expected kind-mismatch reason; got {reason}"
                );
            }
            other => panic!("expected BrokenChain(kind); got {other:?}"),
        }
    }
}

#[cfg(test)]
mod rotation_chain_proptests {
    //! T1 property tests for `verify_receipt_v2_with_rotation_chain`.
    //!
    //! Per `.claude/rules/library-crates.md` — property tests are the
    //! default for state machines. The chain walker IS a state machine
    //! (`trust_set` grows witness-by-witness), so the doc-comment
    //! Pre/Post conditions appear here as property assertions:
    //!
    //! - **Pre `trusted_identities.is_empty() == false`** →
    //!   `empty_trust_set_is_broken_chain` asserts every input rejects.
    //! - **Pre `witness_chain` sorted ascending by `rotation_at`** →
    //!   `valid_chain_of_length_k_verifies` constructs only ascending
    //!   chains; `out_of_order_breaks_chain` flips an adjacent pair
    //!   and asserts failure.
    //! - **Post `Ok(())` iff chain reaches signer** →
    //!   `valid_chain_of_length_k_verifies` asserts the positive case
    //!   for arbitrary chain length 1..=8; `foreign_signer_always_fails`
    //!   asserts the negative case.
    //!
    //! Anchor: `identity_rotation_witness_chain_verified`.
    use super::*;
    use crate::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use core_crypto::{FixtureSigner, FixtureVerifier, Signer};
    use proptest::prelude::*;
    use serde_json::json;

    fn make_target_envelope(signer: &FixtureSigner, tag: &str) -> ReceiptEnvelope {
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "atomic.tool_call".into(),
            receipt_id: String::new(),
            daemon_root_id: "root-fixture".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: json!({ "tool": tag }),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, signer).unwrap();
        env
    }

    fn make_witness(
        prior_signer: &FixtureSigner,
        prev_id: &str,
        next_id: &str,
        rotated_at: u64,
    ) -> ReceiptEnvelope {
        let body = json!({
            "prev_epoch_root_id": prev_id,
            "next_epoch_root_id": next_id,
            "rotated_at_epoch_secs": rotated_at,
            "signature_by_prev_root": "ed25519sig:00",
            "signature_by_next_root": "ed25519sig:01",
        });
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: super::super::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
            receipt_id: String::new(),
            daemon_root_id: prev_id.to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::DaemonPersona,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, prior_signer).unwrap();
        env
    }

    /// Build a contiguous chain of `k` rotations starting from
    /// epoch-0. Returns the anchor pub, the chain, and the final
    /// epoch's signer.
    fn build_chain_k(k: usize) -> (PublicKey, Vec<RotationWitnessEntry>, FixtureSigner) {
        let signers: Vec<FixtureSigner> = (0..=k)
            .map(|i| FixtureSigner::new(format!("proptest-epoch-{i}")))
            .collect();
        let mut chain = Vec::with_capacity(k);
        for i in 0..k {
            let env = make_witness(
                &signers[i],
                &format!("epoch-{i}"),
                &format!("epoch-{}", i + 1),
                1_000 + i as u64,
            );
            chain.push(RotationWitnessEntry {
                envelope: env,
                prior_identity_pub: signers[i].public_key(),
                new_identity_pub: signers[i + 1].public_key(),
                rotation_at: 1_000 + i as u64,
            });
        }
        let anchor = signers[0].public_key();
        let last = signers.into_iter().last().unwrap();
        (anchor, chain, last)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Post: a contiguous chain of length k MUST verify a receipt
        /// signed by epoch-k against the epoch-0 anchor, for any
        /// 1 <= k <= 8.
        #[test]
        fn valid_chain_of_length_k_verifies(k in 1usize..=8) {
            let (anchor, chain, last_signer) = build_chain_k(k);
            let target = make_target_envelope(&last_signer, "proptest");
            verify_receipt_v2_with_rotation_chain(
                &target,
                &[anchor],
                &chain,
                &FixtureVerifier,
            ).expect("valid chain must verify");
        }

        /// Pre: trusted_identities is non-empty. The walker MUST
        /// reject empty trust sets regardless of chain or target.
        #[test]
        fn empty_trust_set_is_broken_chain(k in 0usize..=4) {
            let (_anchor, chain, last_signer) = build_chain_k(k.max(1));
            let target = make_target_envelope(&last_signer, "empty-trust");
            let err = verify_receipt_v2_with_rotation_chain(
                &target,
                &[],
                &chain,
                &FixtureVerifier,
            ).expect_err("empty trust set must be rejected");
            let is_broken_chain = matches!(err, SignError::BrokenChain { .. });
            prop_assert!(is_broken_chain);
        }

        /// Post (negative): a receipt signed by a foreign identity
        /// outside the chain MUST return UntrustedSigner.
        #[test]
        fn foreign_signer_always_fails(k in 1usize..=6, foreign_tag in "[a-z]{1,8}") {
            let (anchor, chain, _last) = build_chain_k(k);
            let foreign = FixtureSigner::new(format!("foreign-{foreign_tag}"));
            let target = make_target_envelope(&foreign, "foreign-sig");
            let err = verify_receipt_v2_with_rotation_chain(
                &target,
                &[anchor],
                &chain,
                &FixtureVerifier,
            ).expect_err("foreign signer must not verify");
            prop_assert!(matches!(err, SignError::UntrustedSigner));
        }

        /// Pre: chain sorted ascending. Swapping any adjacent pair so
        /// rotation_at goes backwards MUST yield BrokenChain.
        #[test]
        fn out_of_order_breaks_chain(k in 2usize..=6, swap_at in 0usize..5) {
            let (anchor, mut chain, last_signer) = build_chain_k(k);
            let i = swap_at % (chain.len() - 1);
            chain.swap(i, i + 1);
            let target = make_target_envelope(&last_signer, "out-of-order");
            let err = verify_receipt_v2_with_rotation_chain(
                &target,
                &[anchor],
                &chain,
                &FixtureVerifier,
            ).expect_err("out-of-order chain must fail");
            let is_broken_chain = matches!(err, SignError::BrokenChain { .. });
            prop_assert!(is_broken_chain);
        }
    }
}
