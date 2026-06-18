//! CLASSIFICATION: PUBLIC
//!
//! T1 property tests for the edge CA primitives (ADR 100 Amendment 1 v3).
//!
//! All tests are pure — no filesystem, no network, no SystemTime::now().

use core_crypto::ca::{
    CaError, ClientCertSpec, ca_fingerprint, generate_csr_pem, generate_edge_ca,
    parse_csr_signed_by, parse_spiffe_uri, sign_client_cert,
};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;

// ─── T1-001: deterministic CA generation ────────────────────────────────────

proptest! {
    /// Same seed → same cert_der and same fingerprint across two calls.
    #[test]
    fn prop_ca_generation_deterministic_given_seed(
        seed in proptest::array::uniform32(any::<u8>())
    ) {
        let ca1 = generate_edge_ca(Some(seed)).expect("CA generation must succeed");
        let ca2 = generate_edge_ca(Some(seed)).expect("CA generation must succeed");

        prop_assert_eq!(
            ca1.cert_der, ca2.cert_der,
            "same seed must produce identical cert_der"
        );
        prop_assert_eq!(
            ca1.fingerprint, ca2.fingerprint,
            "same seed must produce identical fingerprint"
        );
        prop_assert_eq!(
            ca1.signing_key.to_bytes(), ca2.signing_key.to_bytes(),
            "same seed must produce identical signing key"
        );
    }
}

// ─── T1-002: grammar enforcement ────────────────────────────────────────────

proptest! {
    /// Strings that don't match `^[a-z][a-z0-9-]{0,62}$` must produce
    /// `Err(CaError::OutOfGrammar*)` when used as persona or hostname.
    ///
    /// We generate strings from a set of known-bad patterns and verify that
    /// `sign_client_cert` rejects them.
    #[test]
    fn prop_client_cert_refuses_out_of_grammar(
        // Generate from a known out-of-grammar set: digit-start, uppercase, or underscore.
        bad_label in prop::sample::select(vec![
            "0starts-with-digit".to_owned(),
            "HasUppercase".to_owned(),
            "has_underscore".to_owned(),
            "Has Space".to_owned(),
            "".to_owned(),
            "A".to_owned(),
            "ALLCAPS".to_owned(),
            "-leading".to_owned(),
            // 64-char string starting with 'a' — one char too long (max is 63)
            "a234567890123456789012345678901234567890123456789012345678901234".to_owned(),
        ])
    ) {
        let ca = generate_edge_ca(Some([42u8; 32])).expect("CA must generate");
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let valid_uri = "spiffe://emberd/persona/alice/peer/laptop-1";
        let csr_pem = generate_csr_pem(&signing_key, valid_uri)
            .expect("CSR must generate for valid inputs");
        let csr = parse_csr_signed_by(&csr_pem, &signing_key.verifying_key())
            .expect("CSR must parse");

        // All entries in the select set are known out-of-grammar — all must be rejected.

        // Try bad_label as persona.
        let spec_bad_persona = ClientCertSpec {
            persona: bad_label.clone(),
            peer_hostname: "valid-host".to_owned(),
            ttl_seconds: 3600,
        };
        let result = sign_client_cert(&ca, &csr, &spec_bad_persona);
        prop_assert!(
            matches!(result, Err(CaError::OutOfGrammarPersona(_))),
            "bad persona {:?} must produce OutOfGrammarPersona, got {:?}",
            bad_label, result
        );

        // Try bad_label as hostname.
        let spec_bad_host = ClientCertSpec {
            persona: "alice".to_owned(),
            peer_hostname: bad_label.clone(),
            ttl_seconds: 3600,
        };
        let result2 = sign_client_cert(&ca, &csr, &spec_bad_host);
        prop_assert!(
            matches!(result2, Err(CaError::OutOfGrammarHostname(_))),
            "bad hostname {:?} must produce OutOfGrammarHostname, got {:?}",
            bad_label, result2
        );
    }
}

// ─── T1-003: CSR signature round-trip ───────────────────────────────────────

/// Generate a keypair, build a CSR, then:
///  (a) `parse_csr_signed_by` accepts the matching public key.
///  (b) `parse_csr_signed_by` refuses a mismatching public key with `InvalidCsrSignature`.
#[test]
fn csr_signature_round_trip() {
    let seed: [u8; 32] = [0x55; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let spiffe_uri = "spiffe://emberd/persona/bob/peer/server-1";
    let csr_pem = generate_csr_pem(&signing_key, spiffe_uri).expect("CSR generation must succeed");

    // (a) Correct public key → success.
    let csr = parse_csr_signed_by(&csr_pem, &verifying_key)
        .expect("parse_csr_signed_by must accept the correct public key");

    assert_eq!(
        csr.public_key.to_bytes(),
        verifying_key.to_bytes(),
        "parsed public key must match the signing key's verifying key"
    );
    assert_eq!(
        csr.spiffe_uri_requested, spiffe_uri,
        "parsed SPIFFE URI must match the requested URI"
    );

    // (b) Wrong public key → InvalidCsrSignature.
    let wrong_seed: [u8; 32] = [0xaa; 32];
    let wrong_key = SigningKey::from_bytes(&wrong_seed).verifying_key();
    let err = parse_csr_signed_by(&csr_pem, &wrong_key)
        .expect_err("mismatching public key must be rejected");
    assert!(
        matches!(err, CaError::InvalidCsrSignature),
        "expected InvalidCsrSignature, got {:?}",
        err
    );
}

// ─── T1-004: fingerprint stability ──────────────────────────────────────────

/// Calling `ca_fingerprint` on the same cert_der bytes returns the same hash twice.
#[test]
fn ca_fingerprint_stable() {
    let seed: [u8; 32] = [0x11; 32];
    let ca = generate_edge_ca(Some(seed)).expect("CA must generate");

    let fp1 = ca_fingerprint(&ca.cert_der);
    let fp2 = ca_fingerprint(&ca.cert_der);

    assert_eq!(fp1, fp2, "ca_fingerprint must be deterministic");
    assert_eq!(
        fp1, ca.fingerprint,
        "ca_fingerprint must equal the fingerprint stored in EdgeCa"
    );
}

// ─── T1-005: SPIFFE URI strict parsing ──────────────────────────────────────

/// Positive case: accepts well-formed SPIFFE URIs.
/// Negative cases: rejects uppercase, URL-encoding, double-slash, missing fields.
#[test]
fn parse_spiffe_uri_strict() {
    // ── Positive cases ──
    let ok_cases = [
        "spiffe://emberd/persona/alice/peer/laptop-1",
        "spiffe://emberd/persona/z/peer/h",
        "spiffe://emberd/persona/a0/peer/b1",
        "spiffe://emberd/persona/abc-def/peer/xyz-123",
    ];
    for uri in &ok_cases {
        let id =
            parse_spiffe_uri(uri).unwrap_or_else(|e| panic!("must accept {:?}, got {:?}", uri, e));
        // Verify round-trippable structure.
        assert!(
            !id.persona.is_empty(),
            "persona must not be empty for {:?}",
            uri
        );
        assert!(
            !id.peer_hostname.is_empty(),
            "peer_hostname must not be empty for {:?}",
            uri
        );
    }

    // ── Negative cases ──

    // Uppercase letters.
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/Alice/peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "uppercase persona must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/alice/peer/Laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "uppercase hostname must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("SPIFFE://emberd/persona/alice/peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "uppercase scheme must be rejected"
    );

    // URL-encoded characters.
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/al%69ce/peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "percent-encoded chars must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/alice/peer/lap%2Dtop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "percent-encoded hyphen must be rejected"
    );

    // Double-slash collapse / path structure violations.
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd//persona/alice/peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "double-slash in path must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/alice/peer/laptop/extra"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "extra path segments must be rejected"
    );

    // Missing fields.
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/alice/peer/"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "empty peer hostname must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona//peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "empty persona must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://emberd/persona/alice"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "missing peer segment must be rejected"
    );
    assert!(
        matches!(
            parse_spiffe_uri("spiffe://other-trust-domain/persona/alice/peer/laptop"),
            Err(CaError::SpiffeUriParseFailed)
        ),
        "wrong trust domain must be rejected"
    );
}
