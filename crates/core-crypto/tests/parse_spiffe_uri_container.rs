//! CLASSIFICATION: PUBLIC
//!
//! T1 unit tests for `parse_spiffe_uri_container` — the typed parser that
//! accepts both SPIFFE URI shapes specified by ADR 154 §Component 2
//! (`spiffe://emberd/persona/<p>/peer/<h>` and
//! `spiffe://emberd/container/<container-ref>`).
//!
//! Anchor: `parse_spiffe_uri_container` —
//! META-AP-CORE-CRYPTO-SAN-CONTAINER-URI.
//!
//! Pure tests — no filesystem, no network, no `SystemTime::now()`.

use core_crypto::ca::{CaError, SpiffeUri, parse_spiffe_uri, parse_spiffe_uri_container};

/// Happy path: a container URI with a Docker-style hash and the
/// `orbstack:5f3a-…` style from ADR 154's worked example parse into
/// [`SpiffeUri::Container`] with the container-ref preserved verbatim.
#[test]
fn parses_container_uri_happy_path() {
    let uri = "spiffe://emberd/container/orbstack:5f3a-1234567890abcdef";
    let parsed = parse_spiffe_uri_container(uri).expect("container URI should parse");
    assert_eq!(
        parsed,
        SpiffeUri::Container {
            container_ref: "orbstack:5f3a-1234567890abcdef".to_owned(),
        }
    );

    // Docker-style 64-hex container hash.
    let docker = "spiffe://emberd/container/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let parsed = parse_spiffe_uri_container(docker).expect("docker-hash URI should parse");
    match parsed {
        SpiffeUri::Container { container_ref } => {
            assert_eq!(
                container_ref,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            );
        }
        other => panic!("expected Container variant, got {other:?}"),
    }

    // UUID with dashes (k3s pod uid shape).
    let pod_uid = "spiffe://emberd/container/3b9c2e7a-4d51-4f8b-9a2c-1234567890ab";
    let parsed = parse_spiffe_uri_container(pod_uid).expect("pod-uid URI should parse");
    assert!(matches!(parsed, SpiffeUri::Container { .. }));
}

/// Malformed container URIs are rejected with [`CaError::SpiffeUriParseFailed`].
///
/// Covers: empty container-ref, percent-encoded characters, uppercase,
/// extra path segments, slash-in-ref, leading non-alphanumeric.
#[test]
fn rejects_malformed_container_uri() {
    // Empty container-ref.
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Trailing slash with extra segment (path-traversal smuggle attempt).
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/abc/extra"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Percent-encoding rejected before regex match.
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/orbstack%3A5f3a"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Uppercase rejected by grammar (canonicalization invariant).
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/OrbStack-VM"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Leading character must be `[a-z0-9]`, not `:` or `-`.
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/:orbstack"),
        Err(CaError::SpiffeUriParseFailed)
    );
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/container/-abc"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Different trust domain rejected.
    assert_eq!(
        parse_spiffe_uri_container("spiffe://other-trust-domain/container/abc"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Wrong path component (not `/container/`, not `/persona/`).
    assert_eq!(
        parse_spiffe_uri_container("spiffe://emberd/spawn/abc"),
        Err(CaError::SpiffeUriParseFailed)
    );

    // Container-ref too long (> 128 chars).
    let long_ref = "a".repeat(129);
    let long_uri = format!("spiffe://emberd/container/{long_ref}");
    assert_eq!(
        parse_spiffe_uri_container(&long_uri),
        Err(CaError::SpiffeUriParseFailed)
    );
}

/// Regression: the typed parser still accepts the persona URI shape, returning
/// [`SpiffeUri::Persona`] with the same `{persona, peer_hostname}` pair the
/// existing [`parse_spiffe_uri`] surface returns.
#[test]
fn persona_uri_still_parses_via_typed_parser() {
    let uri = "spiffe://emberd/persona/alice/peer/laptop";
    let parsed = parse_spiffe_uri_container(uri).expect("persona URI should parse");
    assert_eq!(
        parsed,
        SpiffeUri::Persona {
            persona: "alice".to_owned(),
            peer_hostname: "laptop".to_owned(),
        }
    );
}

/// Regression: the original [`parse_spiffe_uri`] surface is unchanged —
/// persona shape still parses into [`core_crypto::ca::SpiffeIdentity`] with
/// the same field semantics every cross-crate caller relies on.
#[test]
fn persona_uri_still_parses_via_original_parser() {
    let parsed = parse_spiffe_uri("spiffe://emberd/persona/alice/peer/laptop")
        .expect("persona URI should parse on the original surface");
    assert_eq!(parsed.persona, "alice");
    assert_eq!(parsed.peer_hostname, "laptop");

    // Original parser must still reject the container shape (it only knows
    // persona); the new shape is exclusively accessible via the typed parser.
    // SpiffeIdentity does not implement PartialEq, so match on the result.
    match parse_spiffe_uri("spiffe://emberd/container/orbstack-vm-1") {
        Err(CaError::SpiffeUriParseFailed) => {}
        other => panic!(
            "expected SpiffeUriParseFailed on container URI via legacy parser; got {other:?}"
        ),
    }
}
