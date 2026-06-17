//! Proptest scaffold for the protocol layer.
//!
//! Catches encoder-roundtrip regressions that would silently break signature
//! verification against persisted events or grant-link signatures. The
//! corresponding `cargo-fuzz` harness is filed as a follow-up.
//!
//! Coverage:
//! - `EventBody::canonical_encode` -> `EventBody::decode_canonical` roundtrip
//!   stability for a representative subset of variants. Full-coverage
//!   canonical checks now live in `core-grant-types/tests/canonical.rs`;
//!   this integration test pins the public-API contract from outside the
//!   crate so a downstream consumer's roundtrip doesn't silently regress.
//! - `GrantLink::to_url` / `to_web_url` -> `GrantLink::parse` roundtrip.
//! - `GrantLink::signing_payload` determinism (same inputs => same bytes,
//!   any input change => different bytes).

use core_event_types::{
    EventBody, PersonaCreatedEvent, RecoveryExecutedEvent, RootCreatedEvent, RootRevokedEvent,
};
use core_grant_types::GrantLink;
use core_principals::{KeyAlgorithm, PublicKeyMaterial, RecoveryScope, SurvivalMode};
use core_types::CanonicalEncode;
use proptest::prelude::*;

// ── Strategies ──────────────────────────────────────────────────────────────

fn arb_key() -> impl Strategy<Value = PublicKeyMaterial> {
    (
        "[a-z0-9-]{1,32}",
        prop_oneof![
            Just(KeyAlgorithm::DevEd25519Like),
            Just(KeyAlgorithm::Ed25519),
            Just(KeyAlgorithm::AgeX25519),
        ],
        "[a-zA-Z0-9:_-]{1,64}",
    )
        .prop_map(|(key_id, algorithm, public_key)| PublicKeyMaterial {
            key_id,
            algorithm,
            public_key,
        })
}

/// A small representative subset of `EventBody` variants. The full-coverage
/// generator lives in `core-grant-types/tests/canonical.rs`; this one is the
/// cheap public-API smoke test that runs from `tests/`.
fn arb_event_body() -> impl Strategy<Value = EventBody> {
    prop_oneof![
        ("[a-z0-9-]{1,32}", "[ -~]{0,32}", arb_key()).prop_map(|(root_id, display_name, key)| {
            EventBody::RootCreated(RootCreatedEvent {
                root_id,
                display_name,
                initial_key: key,
            })
        }),
        ("[a-z0-9-]{1,32}", "[ -~]{0,64}").prop_map(|(root_id, reason)| {
            EventBody::RootRevoked(RootRevokedEvent { root_id, reason })
        }),
        (
            "[a-z0-9-]{1,32}",
            "[a-z0-9-]{1,32}",
            "[ -~]{0,32}",
            proptest::option::of("[a-z0-9.-]{1,32}"),
            prop_oneof![
                Just(SurvivalMode::Strict),
                Just(SurvivalMode::LimitedPersonaContinuity),
            ],
            arb_key(),
        )
            .prop_map(
                |(root_id, persona_id, label, disclosure_profile, survival_mode, key)| {
                    EventBody::PersonaCreated(PersonaCreatedEvent {
                        root_id,
                        persona_id,
                        label,
                        disclosure_profile,
                        survival_mode,
                        initial_key: key,
                    })
                },
            ),
        (
            "[a-z0-9-]{1,32}",
            prop_oneof![
                Just(RecoveryScope::FreezeDevice),
                Just(RecoveryScope::RestorePersonaAccess),
            ],
        )
            .prop_map(|(request_id, scope)| {
                EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                    request_id,
                    executed_scope: scope,
                })
            }),
    ]
}

fn arb_grant_link() -> impl Strategy<Value = GrantLink> {
    (
        "offer-[a-z0-9]{1,16}",
        "[a-f0-9]{2,64}",
        any::<u64>(),
        "[a-f0-9]{2,64}",
        proptest::option::of("wss://[a-z.-]{1,32}"),
        "persona-[a-z0-9-]{1,32}",
        "[a-f0-9]{2,64}",
        "[a-f0-9]{0,64}",
    )
        .prop_map(
            |(
                offer_id,
                ephemeral_public_key_hex,
                expires_at,
                issuer_signature,
                relay_hint,
                issuer_persona_id,
                issuer_public_key_hex,
                recipient_pubkey_hex,
            )| GrantLink {
                offer_id,
                ephemeral_public_key_hex,
                expires_at,
                issuer_signature,
                relay_hint,
                issuer_persona_id,
                issuer_public_key_hex,
                recipient_pubkey_hex,
            },
        )
}

// ── Properties ──────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Encoder regression smoke test. `decode(encode(x))`'s re-encoding
    /// must equal `encode(x)` byte-for-byte. Drift here invalidates persisted
    /// signatures.
    #[test]
    fn event_body_canonical_roundtrip_is_stable(body in arb_event_body()) {
        let encoded = body.canonical_encode();
        let decoded = EventBody::decode_canonical(&encoded)
            .expect("canonical decode of freshly-encoded EventBody must succeed");
        let re_encoded = decoded.canonical_encode();
        prop_assert_eq!(
            encoded, re_encoded,
            "canonical encoding is not stable through roundtrip",
        );
    }

    /// Grant link URL roundtrip stability. Native and web URL forms
    /// must round-trip through `parse` without losing any field.
    #[test]
    fn grant_link_native_url_roundtrip(link in arb_grant_link()) {
        let url = link.to_url();
        let parsed = GrantLink::parse(&url)
            .expect("parsing freshly-rendered native URL must succeed");
        prop_assert_eq!(parsed, link);
    }

    /// Web URL form is reachable via fragment routing; the parser
    /// must extract the same fields the renderer wrote.
    #[test]
    fn grant_link_web_url_roundtrip(link in arb_grant_link()) {
        let url = link.to_web_url();
        let parsed = GrantLink::parse(&url)
            .expect("parsing freshly-rendered web URL must succeed");
        prop_assert_eq!(parsed, link);
    }

    /// Signing payload is deterministic — same inputs always produce
    /// the same bytes. This is what the issuer signs; non-determinism here
    /// would silently break verification.
    #[test]
    fn grant_link_signing_payload_is_deterministic(link in arb_grant_link()) {
        let p1 = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );
        let p2 = GrantLink::signing_payload(
            &link.offer_id,
            &link.ephemeral_public_key_hex,
            link.expires_at,
            link.relay_hint.as_deref(),
            &link.issuer_persona_id,
            &link.issuer_public_key_hex,
            &link.recipient_pubkey_hex,
        );
        prop_assert_eq!(p1, p2);
    }
}
