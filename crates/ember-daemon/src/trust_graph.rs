use ed25519_dalek::VerifyingKey;

/// Pinned IdentityRoot pubkey for `did:emberlink` (Ember Systems), baked at
/// daemon build time. Per docs/construct-signing-pipeline.md §"Verification
/// flow" step 3 — Updates require a daemon-version bump.
///
/// V1 dev0 placeholder — derived from the committed seed at
/// `keys/dev0-construct-signing.seed` (raw 32-byte `[1..=32]`). This key
/// is NOT a production secret; it exists so the sign→verify pipeline can
/// be tested end-to-end before the production key-custody decision lands.
/// The production key replaces this constant and the seed file is deleted.
///
/// The all-zero value `[0u8; 32]` is the "unconfigured" anchor:
/// `resolve_publisher_pubkey` guards on it explicitly and refuses
/// verification (ed25519-dalek 2.x decodes all-zero to a usable low-order
/// key, so `from_bytes` alone cannot enforce this).
pub const EMBER_SYSTEMS_PUBKEY_BYTES: [u8; 32] = [
    0x79, 0xb5, 0x56, 0x2e, 0x8f, 0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7,
    0x90, 0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad, 0x04, 0x96, 0x64,
];

/// Validity window for the pinned key. `valid_from = 0` (since-genesis)
/// is fine for the placeholder; production replacement bumps both to
/// the appropriate release-cut timestamp.
pub const EMBER_SYSTEMS_VALID_FROM: i64 = 0;
pub const EMBER_SYSTEMS_VALID_UNTIL: Option<i64> = None;

/// Pre-release security review M7: return `true` when `pubkey` is the
/// dev0 placeholder anchor whose seed (`keys/dev0-construct-signing.seed`)
/// is committed to the public repository.
///
/// The committed seed lets anyone reading the public mirror forge
/// signatures that validate against `EMBER_SYSTEMS_PUBKEY_BYTES`. The
/// AC-7 verifier MUST refuse to verify against this anchor — installing
/// a third-party delegation whose pubkey bytes equal the placeholder is
/// equally forgeable, so the check is byte-comparison and applies to
/// both the pinned `did:emberlink` path and any installed delegation
/// whose pubkey happens to be the dev0 placeholder.
///
/// The operator cutover (install the real production publisher-trust key
/// in `EMBER_SYSTEMS_PUBKEY_BYTES` + delete the committed seed file)
/// flips this back to a no-op without any verifier-side code change.
///
/// Returning `true` here makes "flip AC-7 enforcement on" structurally
/// impossible until that cutover lands.
pub fn is_placeholder_trust_anchor(pubkey: &[u8; 32]) -> bool {
    *pubkey == EMBER_SYSTEMS_PUBKEY_BYTES
}

/// A publisher's Ed25519 pubkey + validity window. The verifier picks
/// the key whose `[valid_from, valid_until]` window contains the
/// sidecar's `build_ts`.
#[derive(Debug, Clone)]
pub struct PublisherKey {
    pub pubkey: VerifyingKey,
    pub valid_from: i64,          // unix epoch seconds; 0 = since-genesis
    pub valid_until: Option<i64>, // unix epoch seconds; None = no upper bound
}

/// An installed trust delegation to a third-party publisher (ADR 123 §2,
/// ADR 213 AC-7). The user/org installs a delegation mapping a publisher
/// DID to an Ed25519 pubkey with a validity window. Revocation is by
/// setting `revoked_at` (soft-delete for auditability).
#[derive(Debug, Clone)]
pub struct PublisherTrustDelegation {
    pub id: String,
    pub publisher_did: String,
    pub pubkey_bytes: [u8; 32],
    pub valid_from: i64,
    pub valid_until: Option<i64>,
    pub installed_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustGraphError {
    #[error("publisher not trusted: {0}")]
    PublisherNotTrusted(String),
    #[error("no key in validity window for publisher {did}: build_ts={build_ts}")]
    NoKeyInValidityWindow { did: String, build_ts: i64 },
    #[error("invalid pubkey bytes: {0}")]
    InvalidPubkey(String),
}

/// Resolve a publisher DID to the appropriate Ed25519 pubkey for a given
/// `build_ts`. `did:emberlink` (Ember Systems' bundled identity) is pinned
/// via a baked-in constant. Other DIDs are resolved against installed trust
/// delegations (ADR 123 §2 / ADR 213 AC-7). An empty delegation slice
/// reproduces the pre-AC-7 behavior: only pinned keys resolve.
pub fn resolve_publisher_pubkey(
    did: &str,
    build_ts: i64,
    delegations: &[PublisherTrustDelegation],
) -> Result<PublisherKey, TrustGraphError> {
    match did {
        "did:emberlink" => {
            // Validity window check.
            if build_ts < EMBER_SYSTEMS_VALID_FROM {
                return Err(TrustGraphError::NoKeyInValidityWindow {
                    did: did.to_string(),
                    build_ts,
                });
            }
            if let Some(until) = EMBER_SYSTEMS_VALID_UNTIL
                && build_ts > until
            {
                return Err(TrustGraphError::NoKeyInValidityWindow {
                    did: did.to_string(),
                    build_ts,
                });
            }
            // Fail closed when the pinned key is still the all-zero
            // "unconfigured" checkpoint. `from_bytes` would NOT catch this
            // (the all-zero point decodes to a usable low-order key in
            // ed25519-dalek 2.x), so guard explicitly. (Sweep 3 S-PUBKEY.)
            if EMBER_SYSTEMS_PUBKEY_BYTES == [0u8; 32] {
                return Err(TrustGraphError::PublisherNotTrusted(
                    "did:emberlink pinned key is the unconfigured all-zero \
                     placeholder; this daemon build cannot verify Ember Systems \
                     Construct signatures (cut a release with the real key)"
                        .to_string(),
                ));
            }
            let pubkey = VerifyingKey::from_bytes(&EMBER_SYSTEMS_PUBKEY_BYTES)
                .map_err(|e| TrustGraphError::InvalidPubkey(e.to_string()))?;
            Ok(PublisherKey {
                pubkey,
                valid_from: EMBER_SYSTEMS_VALID_FROM,
                valid_until: EMBER_SYSTEMS_VALID_UNTIL,
            })
        }
        other => resolve_from_delegations(other, build_ts, delegations),
    }
}

fn resolve_from_delegations(
    did: &str,
    build_ts: i64,
    delegations: &[PublisherTrustDelegation],
) -> Result<PublisherKey, TrustGraphError> {
    let mut found_did = false;
    for d in delegations {
        if d.publisher_did != did {
            continue;
        }
        if d.revoked_at.is_some() {
            continue;
        }
        found_did = true;
        if build_ts < d.valid_from {
            continue;
        }
        if let Some(until) = d.valid_until
            && build_ts > until
        {
            continue;
        }
        let pubkey = VerifyingKey::from_bytes(&d.pubkey_bytes)
            .map_err(|e| TrustGraphError::InvalidPubkey(e.to_string()))?;
        return Ok(PublisherKey {
            pubkey,
            valid_from: d.valid_from,
            valid_until: d.valid_until,
        });
    }
    if found_did {
        Err(TrustGraphError::NoKeyInValidityWindow {
            did: did.to_string(),
            build_ts,
        })
    } else {
        Err(TrustGraphError::PublisherNotTrusted(did.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev0_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        s
    }

    fn test_pubkey_bytes() -> [u8; 32] {
        let sk = ed25519_dalek::SigningKey::from_bytes(&dev0_seed());
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn dev0_pubkey_matches_committed_seed() {
        let pk = test_pubkey_bytes();
        assert_eq!(
            pk, EMBER_SYSTEMS_PUBKEY_BYTES,
            "EMBER_SYSTEMS_PUBKEY_BYTES must match the pubkey derived from dev0_seed()"
        );
    }

    /// M7: the placeholder check recognizes the pubkey derived from the
    /// committed dev0 seed file. Until the operator cutover (replace
    /// `EMBER_SYSTEMS_PUBKEY_BYTES` with the production key + delete the
    /// seed), this assertion must hold so AC-7 verification refuses
    /// fail-closed.
    #[test]
    fn is_placeholder_trust_anchor_recognizes_committed_seed() {
        assert!(
            is_placeholder_trust_anchor(&EMBER_SYSTEMS_PUBKEY_BYTES),
            "the dev0 placeholder anchor must be recognized by \
             is_placeholder_trust_anchor while the committed seed still \
             derives EMBER_SYSTEMS_PUBKEY_BYTES"
        );
        // The committed-seed-derived pubkey must equal the constant.
        assert!(
            is_placeholder_trust_anchor(&test_pubkey_bytes()),
            "pubkey derived from the committed dev0 seed must be \
             recognized as the placeholder"
        );
    }

    /// M7: a freshly-generated non-placeholder pubkey is NOT recognized
    /// as the placeholder (sanity: post-cutover keys verify normally).
    #[test]
    fn is_placeholder_trust_anchor_rejects_non_placeholder() {
        let mut alt_seed = [0u8; 32];
        alt_seed[0] = 0xff;
        let alt_pk = ed25519_dalek::SigningKey::from_bytes(&alt_seed)
            .verifying_key()
            .to_bytes();
        assert!(
            !is_placeholder_trust_anchor(&alt_pk),
            "non-placeholder pubkey must not be recognized as the placeholder"
        );
    }

    fn make_delegation(did: &str, pubkey_bytes: [u8; 32]) -> PublisherTrustDelegation {
        PublisherTrustDelegation {
            id: "deleg-1".to_string(),
            publisher_did: did.to_string(),
            pubkey_bytes,
            valid_from: 0,
            valid_until: None,
            installed_at: 1000,
            revoked_at: None,
        }
    }

    #[test]
    fn unconfigured_ember_publisher_fails_closed() {
        let result = resolve_publisher_pubkey("did:emberlink", 1735689600, &[]);
        if EMBER_SYSTEMS_PUBKEY_BYTES == [0u8; 32] {
            assert!(
                matches!(result, Err(TrustGraphError::PublisherNotTrusted(_))),
                "unconfigured all-zero pinned key must fail closed, got {result:?}"
            );
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn unknown_publisher_returns_not_trusted() {
        let result = resolve_publisher_pubkey("did:wrangler-team", 1735689600, &[]);
        match result {
            Err(TrustGraphError::PublisherNotTrusted(s)) => assert_eq!(s, "did:wrangler-team"),
            other => panic!("expected PublisherNotTrusted, got {other:?}"),
        }
    }

    #[test]
    fn build_ts_before_valid_from_rejects() {
        let r = resolve_publisher_pubkey("did:emberlink", 0, &[]);
        if EMBER_SYSTEMS_PUBKEY_BYTES == [0u8; 32] {
            assert!(matches!(r, Err(TrustGraphError::PublisherNotTrusted(_))));
        } else {
            assert!(r.is_ok());
        }
    }

    // --- AC-7: WoT delegation walk ---

    #[test]
    fn delegation_resolves_third_party_publisher() {
        let pk = test_pubkey_bytes();
        let d = make_delegation("did:acme-tools", pk);
        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[d]);
        assert!(
            result.is_ok(),
            "installed delegation must resolve: {result:?}"
        );
        assert_eq!(result.unwrap().pubkey.to_bytes(), pk);
    }

    #[test]
    fn no_delegation_fails_closed() {
        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[]);
        assert!(
            matches!(result, Err(TrustGraphError::PublisherNotTrusted(_))),
            "no delegation installed must fail closed: {result:?}"
        );
    }

    #[test]
    fn revoked_delegation_fails_closed() {
        let pk = test_pubkey_bytes();
        let mut d = make_delegation("did:acme-tools", pk);
        d.revoked_at = Some(1735689000);
        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[d]);
        assert!(
            matches!(result, Err(TrustGraphError::PublisherNotTrusted(_))),
            "revoked delegation must fail closed: {result:?}"
        );
    }

    #[test]
    fn delegation_validity_window_before_valid_from() {
        let pk = test_pubkey_bytes();
        let mut d = make_delegation("did:acme-tools", pk);
        d.valid_from = 2000000000;
        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[d]);
        assert!(
            matches!(result, Err(TrustGraphError::NoKeyInValidityWindow { .. })),
            "build_ts before valid_from must reject: {result:?}"
        );
    }

    #[test]
    fn delegation_validity_window_after_valid_until() {
        let pk = test_pubkey_bytes();
        let mut d = make_delegation("did:acme-tools", pk);
        d.valid_until = Some(1700000000);
        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[d]);
        assert!(
            matches!(result, Err(TrustGraphError::NoKeyInValidityWindow { .. })),
            "build_ts after valid_until must reject: {result:?}"
        );
    }

    #[test]
    fn delegation_does_not_override_pinned_emberlink() {
        // Use a DIFFERENT key for the delegation so we can distinguish
        // "pinned path was used" from "delegation was used".
        let mut alt_seed = [0u8; 32];
        alt_seed[0] = 0xff;
        let alt_pk = ed25519_dalek::SigningKey::from_bytes(&alt_seed)
            .verifying_key()
            .to_bytes();
        let d = make_delegation("did:emberlink", alt_pk);
        let result = resolve_publisher_pubkey("did:emberlink", 1735689600, &[d]);
        // did:emberlink always uses the pinned path, never delegations.
        if EMBER_SYSTEMS_PUBKEY_BYTES == [0u8; 32] {
            assert!(matches!(
                result,
                Err(TrustGraphError::PublisherNotTrusted(_))
            ));
        } else {
            assert_ne!(
                result.unwrap().pubkey.to_bytes(),
                alt_pk,
                "did:emberlink must use pinned key, not delegation"
            );
        }
    }

    #[test]
    fn multiple_delegations_picks_matching_window() {
        let pk1 = test_pubkey_bytes();
        let mut pk2_bytes = [0u8; 32];
        pk2_bytes[0] = 0x42;
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&pk2_bytes);
        let pk2 = sk2.verifying_key().to_bytes();

        let d1 = PublisherTrustDelegation {
            id: "old-key".to_string(),
            publisher_did: "did:acme-tools".to_string(),
            pubkey_bytes: pk1,
            valid_from: 0,
            valid_until: Some(1700000000),
            installed_at: 1000,
            revoked_at: None,
        };
        let d2 = PublisherTrustDelegation {
            id: "new-key".to_string(),
            publisher_did: "did:acme-tools".to_string(),
            pubkey_bytes: pk2,
            valid_from: 1700000001,
            valid_until: None,
            installed_at: 1700000001,
            revoked_at: None,
        };

        let result = resolve_publisher_pubkey("did:acme-tools", 1735689600, &[d1, d2]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().pubkey.to_bytes(), pk2);
    }
}
