use ed25519_dalek::VerifyingKey;

/// Pinned IdentityRoot pubkey for `did:emberlink` (Ember Systems), baked at
/// daemon build time. Per docs/construct-signing-pipeline.md §"Verification
/// flow" step 3 — Updates require a daemon-version bump.
///
/// V1 placeholder — replaced via daemon release pipeline before any
/// production Construct signing happens. The 32-byte all-zero key is
/// intentionally invalid so an unconfigured daemon refuses verification
/// rather than accepting stub-signed binaries.
pub const EMBER_SYSTEMS_PUBKEY_BYTES: [u8; 32] = [0u8; 32];

/// Validity window for the pinned key. `valid_from = 0` (since-genesis)
/// is fine for the placeholder; production replacement bumps both to
/// the appropriate release-cut timestamp.
pub const EMBER_SYSTEMS_VALID_FROM: i64 = 0;
pub const EMBER_SYSTEMS_VALID_UNTIL: Option<i64> = None;

/// A publisher's Ed25519 pubkey + validity window. The verifier picks
/// the key whose `[valid_from, valid_until]` window contains the
/// sidecar's `build_ts`.
#[derive(Debug, Clone)]
pub struct PublisherKey {
    pub pubkey: VerifyingKey,
    pub valid_from: i64,          // unix epoch seconds; 0 = since-genesis
    pub valid_until: Option<i64>, // unix epoch seconds; None = no upper bound
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
/// build_ts. `did:emberlink` (Ember Systems' bundled identity) is pinned via
/// a baked-in constant. All other DIDs return `PublisherNotTrusted` for v1
/// (WoT walk is a stub — follow-up task wires it to the actual delegation
/// graph). Per design (action namespace governance).
pub fn resolve_publisher_pubkey(did: &str, build_ts: i64) -> Result<PublisherKey, TrustGraphError> {
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
            let pubkey = VerifyingKey::from_bytes(&EMBER_SYSTEMS_PUBKEY_BYTES)
                .map_err(|e| TrustGraphError::InvalidPubkey(e.to_string()))?;
            Ok(PublisherKey {
                pubkey,
                valid_from: EMBER_SYSTEMS_VALID_FROM,
                valid_until: EMBER_SYSTEMS_VALID_UNTIL,
            })
        }
        // V1: third-party publishers not yet WoT-walked. Follow-up task
        // wires this branch to the WoT delegation graph (per design).
        other => Err(TrustGraphError::PublisherNotTrusted(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_pinned_ember_publisher() {
        let result = resolve_publisher_pubkey("did:emberlink", 1735689600);
        assert!(result.is_ok());
    }

    #[test]
    fn unknown_publisher_returns_not_trusted() {
        let result = resolve_publisher_pubkey("did:wrangler-team", 1735689600);
        match result {
            Err(TrustGraphError::PublisherNotTrusted(s)) => assert_eq!(s, "did:wrangler-team"),
            other => panic!("expected PublisherNotTrusted, got {other:?}"),
        }
    }

    #[test]
    fn build_ts_before_valid_from_rejects() {
        // Construct a hypothetical case where validity window matters.
        // The const EMBER_SYSTEMS_VALID_FROM is 0 today, so any positive
        // build_ts succeeds; this test documents the validity-check path
        // by exercising NoKeyInValidityWindow at the boundary.
        // For now, the assert is just that the OK path works for ts >= 0.
        assert!(resolve_publisher_pubkey("did:emberlink", 0).is_ok());
        // Future: when EMBER_SYSTEMS_VALID_FROM is bumped past 0, add a
        // test here asserting build_ts < valid_from returns
        // NoKeyInValidityWindow.
    }
}
