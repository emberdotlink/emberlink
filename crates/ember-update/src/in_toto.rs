//!
//! in-toto Statement v1 envelope — JCS-canonicalized predicate, Ed25519 sign/verify.
//!
//! Implements the in-toto Statement v1 shape (https://in-toto.io/Statement/v1) as
//! defined in update-policy D2. The envelope wraps a
//! generic predicate `P` which is serialized to JCS-canonical JSON before signing.
//!
//! # Signing payload
//!
//! The Ed25519 signature covers:
//!
//! 1. Domain-separation prefix `"emberlink/v1/in-toto-statement"` (length-prefixed, u64 BE).
//! 2. JCS-canonical encoding of the predicate (length-prefixed, u64 BE).
//!
//! This binds the signature to both the Emberlink context and the exact predicate
//! bytes, preventing cross-context signature reuse.

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
/// The anchor type name `InTotoStatementV1` is the `target_state_anchor` anchor
/// for this task (implementation-note-379).
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

/// JCS-canonicalize a predicate value.
///
/// Serializes `p` to `serde_json::Value` then applies RFC 8785 key ordering
/// so the canonical byte sequence is stable across map insertion order.
///
/// Used internally by [`sign`] and [`verify`]; exposed so callers can inspect
/// or log the canonical bytes before committing.
pub fn canonicalize_predicate(p: &impl Serialize) -> Result<Vec<u8>, EnvelopeError> {
    let value = serde_json::to_value(p).map_err(|e| EnvelopeError::Canonicalize(e.to_string()))?;
    let s = serde_jcs::to_string(&value).map_err(|e| EnvelopeError::Canonicalize(e.to_string()))?;
    Ok(s.into_bytes())
}

/// Build the signing payload for an `InTotoStatementV1<P>`.
///
/// Layout:
/// 1. `u64 BE` length of domain prefix, then domain prefix bytes.
/// 2. `u64 BE` length of canonical predicate bytes, then those bytes.
fn signing_payload<P: Serialize>(stmt: &InTotoStatementV1<P>) -> Result<Vec<u8>, EnvelopeError> {
    let canonical = canonicalize_predicate(&stmt.predicate)?;

    let mut buf = Vec::new();

    // Domain-separation prefix
    buf.extend_from_slice(&(DOMAIN_PREFIX.len() as u64).to_be_bytes());
    buf.extend_from_slice(DOMAIN_PREFIX);

    // Canonical predicate
    buf.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    buf.extend_from_slice(&canonical);

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
}
