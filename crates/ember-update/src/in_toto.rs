//! CLASSIFICATION: PUBLIC
//!
//! in-toto Statement v1 envelope — JCS-canonicalized predicate, Ed25519 sign/verify.
//!
//! Implements the in-toto Statement v1 shape (<https://in-toto.io/Statement/v1>) as
//! defined in ADR-DRAFT-IMG-SIGNING-AND-UPDATE-FLOW D2. The envelope wraps a
//! generic predicate `P` which is serialized to JCS-canonical JSON before signing.
//!
//! # Signing payload
//!
//! The Ed25519 signature covers, in order, each component length-prefixed with a
//! `u64` big-endian length:
//!
//! 1. Domain-separation prefix `"emberlink/v1/in-toto-statement"`.
//! 2. JCS-canonical encoding of `_type`.
//! 3. JCS-canonical encoding of `subject`.
//! 4. JCS-canonical encoding of `predicate_type`.
//! 5. JCS-canonical encoding of `predicate`.
//!
//! Binding `_type`, `subject`, and `predicate_type` into the signed bytes
//! prevents a "signature lift" attack where an attacker takes a valid
//! `(signature, predicate)` pair from statement A and swaps in a different
//! `subject` or `predicate_type` to forge statement B. Without binding these
//! envelope fields, the signature would still verify, allowing an attacker to
//! re-target a legitimately-signed provenance predicate at a malicious artifact.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain-separation prefix used in the signing payload.
const DOMAIN_PREFIX: &[u8] = b"emberlink/v1/in-toto-statement";

/// The `_type` URI for in-toto Statement v1.
pub const IN_TOTO_STATEMENT_V1_TYPE: &str = "https://in-toto.io/Statement/v1";

/// A resource-descriptor subject within an in-toto Statement v1 envelope.
///
/// Each subject names an artifact the statement applies to and records one or
/// more digest values (e.g. `{"sha256": "<hex>"}` or `{"blake3": "<hex>"}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

/// in-toto Statement v1 envelope wrapping a JCS-canonicalized predicate `P`.
///
/// The checkpoint type name `InTotoStatementV1` is the `target_state_anchor` anchor
/// for this task (ARCH-IMG-IN-TOTO-ENVELOPE).
///
/// # Field semantics
///
/// - `_type`: always `"https://in-toto.io/Statement/v1"`.
/// - `subject`: one or more artifacts this statement applies to.
/// - `predicate_type`: URI identifying the predicate schema
///   (e.g. `"https://slsa.dev/provenance/v1"`).
/// - `predicate`: the domain-specific predicate payload; serialized via JCS
///   before signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoStatementV1<P> {
    #[serde(rename = "_type")]
    pub _type: String,
    pub subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: P,
}

impl<P: Serialize> InTotoStatementV1<P> {
    /// Construct a new statement with `_type` pre-set to the in-toto v1 URI.
    pub fn new(subject: Vec<Subject>, predicate_type: String, predicate: P) -> Self {
        Self {
            _type: IN_TOTO_STATEMENT_V1_TYPE.to_string(),
            subject,
            predicate_type,
            predicate,
        }
    }
}

/// A signed in-toto Statement v1 envelope.
///
/// The `signature` field holds the raw Ed25519 signature bytes (64 bytes) over
/// the signing payload — see module-level doc for encoding details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope<P> {
    pub statement: InTotoStatementV1<P>,
    pub signature: Vec<u8>,
}

/// Errors returned by [`verify`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error(
        "in-toto statement _type field must be \
         'https://in-toto.io/Statement/v1', got '{0}'"
    )]
    WrongType(String),

    #[error("predicate canonicalization (JCS) failed: {0}")]
    Canonicalize(String),

    #[error(
        "in-toto envelope signature is invalid or was signed by an untrusted key; \
         the statement may have been tampered with"
    )]
    SignatureInvalid,
}

/// JCS-canonicalize an arbitrary serializable value.
///
/// Serializes `v` to `serde_json::Value` then applies RFC 8785 key ordering
/// so the canonical byte sequence is stable across map insertion order.
///
/// Used internally by [`sign`] and [`verify`] for every envelope field that
/// participates in the signing payload (`_type`, `subject`, `predicate_type`,
/// `predicate`).
pub fn canonicalize_value(v: &impl Serialize) -> Result<Vec<u8>, EnvelopeError> {
    let value = serde_json::to_value(v).map_err(|e| EnvelopeError::Canonicalize(e.to_string()))?;
    let s = serde_jcs::to_string(&value).map_err(|e| EnvelopeError::Canonicalize(e.to_string()))?;
    Ok(s.into_bytes())
}

/// JCS-canonicalize a predicate value.
///
/// Thin wrapper around [`canonicalize_value`] retained as the predicate-specific
/// entry point used by external callers that want to inspect or log the
/// canonical predicate bytes before committing.
pub fn canonicalize_predicate(p: &impl Serialize) -> Result<Vec<u8>, EnvelopeError> {
    canonicalize_value(p)
}

/// Append a length-prefixed (`u64 BE`) byte slice to `buf`.
fn append_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Build the signing payload for an `InTotoStatementV1<P>`.
///
/// Each component is encoded as `u64 BE` length followed by the canonical
/// bytes. Layout:
///
/// 1. Domain-separation prefix.
/// 2. JCS-canonical `_type` (a JSON string).
/// 3. JCS-canonical `subject` (a JSON array of resource descriptors).
/// 4. JCS-canonical `predicate_type` (a JSON string).
/// 5. JCS-canonical `predicate`.
///
/// Binding `_type`, `subject`, and `predicate_type` into the signed bytes
/// prevents a "signature lift" attack where an attacker swaps envelope fields
/// while keeping a valid signature from a different statement.
fn signing_payload<P: Serialize>(stmt: &InTotoStatementV1<P>) -> Result<Vec<u8>, EnvelopeError> {
    let canonical_type = canonicalize_value(&stmt._type)?;
    let canonical_subject = canonicalize_value(&stmt.subject)?;
    let canonical_predicate_type = canonicalize_value(&stmt.predicate_type)?;
    let canonical_predicate = canonicalize_value(&stmt.predicate)?;

    let mut buf = Vec::new();

    // Domain-separation prefix
    append_length_prefixed(&mut buf, DOMAIN_PREFIX);

    // Envelope fields — bound so a signature cannot be lifted onto a different
    // _type / subject / predicate_type.
    append_length_prefixed(&mut buf, &canonical_type);
    append_length_prefixed(&mut buf, &canonical_subject);
    append_length_prefixed(&mut buf, &canonical_predicate_type);

    // Canonical predicate
    append_length_prefixed(&mut buf, &canonical_predicate);

    Ok(buf)
}

/// Sign an `InTotoStatementV1<P>` with an Ed25519 `SigningKey`.
///
/// Returns a [`SignedEnvelope`] containing the original statement and the
/// 64-byte Ed25519 signature over the canonical signing payload.
pub fn sign<P: Serialize>(
    statement: InTotoStatementV1<P>,
    key: &SigningKey,
) -> Result<SignedEnvelope<P>, EnvelopeError> {
    let payload = signing_payload(&statement)?;
    let sig: Signature = key.sign(&payload);
    Ok(SignedEnvelope {
        statement,
        signature: sig.to_bytes().to_vec(),
    })
}

/// Verify a [`SignedEnvelope`] against a known Ed25519 `VerifyingKey`.
///
/// # Errors
///
/// - [`EnvelopeError::WrongType`] — `_type` is not the expected in-toto v1 URI.
/// - [`EnvelopeError::Canonicalize`] — predicate could not be JCS-encoded.
/// - [`EnvelopeError::SignatureInvalid`] — signature does not verify.
pub fn verify<P: Serialize>(
    signed: &SignedEnvelope<P>,
    key: &VerifyingKey,
) -> Result<(), EnvelopeError> {
    if signed.statement._type != IN_TOTO_STATEMENT_V1_TYPE {
        return Err(EnvelopeError::WrongType(signed.statement._type.clone()));
    }

    if signed.signature.len() != 64 {
        return Err(EnvelopeError::SignatureInvalid);
    }
    let sig_arr: [u8; 64] = signed.signature[..64].try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);

    let payload = signing_payload(&signed.statement)?;

    key.verify(&payload, &signature)
        .map_err(|_| EnvelopeError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn test_signing_key() -> SigningKey {
        let seed: [u8; 32] = [99u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn test_subject() -> Subject {
        let mut digest = BTreeMap::new();
        digest.insert(
            "sha256".to_string(),
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc1".to_string(),
        );
        Subject {
            name: "ember-installer-x86_64.tar.gz".to_string(),
            digest,
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestPredicate {
        builder: String,
        version: String,
    }

    fn test_statement() -> InTotoStatementV1<TestPredicate> {
        InTotoStatementV1::new(
            vec![test_subject()],
            "https://slsa.dev/provenance/v1".to_string(),
            TestPredicate {
                builder: "https://github.com/emberdotlink/emberlink".to_string(),
                version: "0.3.0".to_string(),
            },
        )
    }

    #[test]
    fn round_trip_sign_verify() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let stmt = test_statement();
        let signed = sign(stmt.clone(), &sk).expect("sign should succeed");
        verify(&signed, &vk).expect("verify should succeed");
        assert_eq!(signed.statement, stmt);
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let stmt = test_statement();
        let mut signed = sign(stmt, &sk).expect("sign should succeed");
        signed.signature[0] ^= 0xFF;
        let err = verify(&signed, &vk).unwrap_err();
        assert_eq!(err, EnvelopeError::SignatureInvalid);
    }

    #[test]
    fn wrong_type_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut stmt = test_statement();
        stmt._type = "https://wrong.example/type".to_string();
        // Must still produce a signature so we can call verify.
        let payload = signing_payload(&stmt).unwrap();
        let sig: Signature = sk.sign(&payload);
        let signed = SignedEnvelope {
            statement: stmt,
            signature: sig.to_bytes().to_vec(),
        };
        let err = verify(&signed, &vk).unwrap_err();
        assert!(matches!(err, EnvelopeError::WrongType(_)));
    }

    #[test]
    fn canonicalize_predicate_is_stable() {
        // Serializing the same predicate twice must produce identical bytes.
        let pred = TestPredicate {
            builder: "https://example.com".to_string(),
            version: "1.0".to_string(),
        };
        let a = canonicalize_predicate(&pred).unwrap();
        let b = canonicalize_predicate(&pred).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn in_toto_statement_v1_type_field_is_correct() {
        let stmt = test_statement();
        assert_eq!(stmt._type, IN_TOTO_STATEMENT_V1_TYPE);
    }

    /// Cross-statement signature-lift attack must be rejected.
    ///
    /// An attacker takes a valid signature from statement A (signed over its
    /// `_type` / `subject` / `predicate_type` / `predicate`) and pastes it onto
    /// statement B whose `subject` and `predicate_type` differ but whose
    /// `predicate` bytes are identical. Before the
    /// META-AUDIT-INTOTO-SIGBIND fix the signed bytes only covered the
    /// predicate, so this lift verified successfully — letting an attacker
    /// re-target a legitimately-signed provenance predicate at a malicious
    /// artifact name or claim it under a different predicate schema URI.
    ///
    /// After the fix the signing payload binds `_type`, `subject`, and
    /// `predicate_type`, so the lifted signature must not verify.
    #[test]
    fn signature_lifted_from_other_statement_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        // Statement A: legitimate provenance for the real installer.
        let stmt_a = test_statement();
        let signed_a = sign(stmt_a, &sk).expect("sign A should succeed");

        // Statement B: same predicate bytes, but the attacker has swapped the
        // subject (different artifact name + digest) and predicate_type
        // (different schema URI). If only the predicate is bound, signed_a's
        // signature still verifies over the predicate bytes.
        let mut evil_digest = BTreeMap::new();
        evil_digest.insert(
            "sha256".to_string(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        );
        let evil_subject = Subject {
            name: "ember-installer-evil.tar.gz".to_string(),
            digest: evil_digest,
        };
        let lifted = SignedEnvelope {
            statement: InTotoStatementV1::new(
                vec![evil_subject],
                "https://attacker.example/predicate/v1".to_string(),
                signed_a.statement.predicate.clone(),
            ),
            signature: signed_a.signature.clone(),
        };

        let err = verify(&lifted, &vk).expect_err("lifted signature must not verify");
        assert_eq!(err, EnvelopeError::SignatureInvalid);

        // Sanity: lifting just the subject (keeping predicate_type intact) is
        // also rejected — proves `subject` alone is part of the binding.
        let mut evil_digest2 = BTreeMap::new();
        evil_digest2.insert(
            "sha256".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );
        let subject_only_swap = SignedEnvelope {
            statement: InTotoStatementV1::new(
                vec![Subject {
                    name: "ember-installer-imposter.tar.gz".to_string(),
                    digest: evil_digest2,
                }],
                signed_a.statement.predicate_type.clone(),
                signed_a.statement.predicate.clone(),
            ),
            signature: signed_a.signature.clone(),
        };
        let err = verify(&subject_only_swap, &vk).expect_err("subject-only lift must not verify");
        assert_eq!(err, EnvelopeError::SignatureInvalid);

        // Sanity: lifting just the predicate_type (keeping subject intact) is
        // also rejected — proves `predicate_type` alone is part of the
        // binding.
        let predicate_type_only_swap = SignedEnvelope {
            statement: InTotoStatementV1::new(
                signed_a.statement.subject.clone(),
                "https://attacker.example/predicate/v1".to_string(),
                signed_a.statement.predicate.clone(),
            ),
            signature: signed_a.signature.clone(),
        };
        let err = verify(&predicate_type_only_swap, &vk)
            .expect_err("predicate_type-only lift must not verify");
        assert_eq!(err, EnvelopeError::SignatureInvalid);
    }
}
