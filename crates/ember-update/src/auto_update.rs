//! CLASSIFICATION: PUBLIC
//!
//! Auto-update decision composition (subtask A of `ARCH-IMG-EMBER-UP-AUTO-UPDATE`).
//!
//! Anchor: `ember_up_auto_update`.
//!
//! The launcher path (`ember session open`, with friendly aliases
//! `ember claude` / `ember codex` / `ember headless`; `ember up` is a
//! hidden preset over the same path) and the daemon's image-rotation
//! tick both need a single pure function that combines the three
//! update-flow primitives — the signed channel pointer, the in-toto
//! signed manifest verification, and the signed revocations document — into
//! one `UpdateDecision`. This module is that function.
//!
//! The function is **pure**: no I/O, no clock reads, no network. All
//! inputs (current digest, channel pointer, channel-signer public key,
//! signed revocations document bytes, the current Unix time) are passed in.
//! Network fetching of the pointer and revocations lives in the caller
//! (the daemon's revocation poller + a separate channel-pointer
//! fetcher); pinning the decision to a pure function keeps the trust
//! boundary explicit and makes T1 testing trivial — every branch is
//! exercised with deterministic fixtures.
//!
//! ## Decision branches
//!
//! 1. **Channel pointer fails to verify** → return
//!    [`UpdateDecisionError::PointerInvalid`]. Caller MUST fail-closed:
//!    a tampered pointer is the same threat shape as the daemon
//!    accepting an unsigned manifest. No-update is the wrong default;
//!    refuse-to-decide is right.
//! 2. **Revocations document fails to parse or verify** → return
//!    [`UpdateDecisionError::RevocationsInvalid`]. Same fail-closed
//!    posture as pointer-invalid — an unsigned or unverifiable revocations
//!    document cannot be safely treated as "no revocations".
//! 3. **Signed revocations document is stale (older than 30 min by default,
//!    per ADR-DRAFT-IMG-SIGNING-AND-UPDATE-FLOW D5)** → return
//!    [`UpdateDecision::BlockedByStaleRevocations`] so the operator
//!    sees the staleness, not a misleading "no update available".
//!    Other revocation trust failures, including future-issued documents,
//!    return [`UpdateDecisionError::RevocationsInvalid`].
//! 4. **Current digest is in the (fresh) revocations document** →
//!    return [`UpdateDecision::CurrentRevoked`] with the matched
//!    entry's severity and action. The caller routes per severity per
//!    the revocations module's mapping (Critical → IsolateDrainKill,
//!    High → DrainToTtl, Medium/Low → Log).
//! 5. **Pointer's manifest digest matches the current digest** →
//!    [`UpdateDecision::NoUpdate`]. Steady state — the operator is on
//!    the latest channel image.
//! 6. **Pointer's manifest digest differs from current** →
//!    [`UpdateDecision::UpdateAvailable`] with the new digest + the
//!    manifest URI the caller pulls + verifies in-toto next.
//!
//! The manifest in-toto verification itself happens in the caller's
//! follow-up — this function decides *whether* to fetch the new
//! manifest, not *whether the fetched manifest is trustworthy*. That
//! split keeps the decision function side-effect-free while preserving
//! the layered trust property (pointer signs the manifest reference;
//! manifest is in-toto signed by the builder).

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::channel::{ChannelPointer, ChannelPointerError, verify_channel_pointer};
use crate::revocations::{
    RevocationAction, RevocationPollError, RevocationSeverity, RevocationsPoller,
};

/// Verdict from [`decide_update`]. Carries enough context for the
/// caller to log + act without re-parsing the inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision {
    /// Pointer's `manifest_digest_hex` equals `current_digest`. No
    /// fetch needed.
    NoUpdate,
    /// Pointer references a manifest digest that differs from
    /// `current_digest`. Caller pulls + in-toto-verifies the manifest
    /// at `manifest_uri` next, then schedules new-container start with
    /// `new_digest`.
    UpdateAvailable {
        new_digest: String,
        manifest_uri: String,
    },
    /// `current_digest` is listed in the fresh revocations document.
    /// Caller routes per `action` (per ADR-DRAFT-IMG-SIGNING-AND-UPDATE-FLOW
    /// D5 severity-action table) and surfaces `reason` to the operator.
    CurrentRevoked {
        severity: RevocationSeverity,
        action: RevocationAction,
        reason: String,
    },
    /// Revocations document is stale (older than the poller's
    /// `stale_threshold_secs`). The whole decision fails closed
    /// because we cannot tell whether a revocation has since been
    /// issued for `current_digest`. Caller surfaces the staleness to
    /// the operator and refuses to start new containers until the
    /// document refreshes.
    BlockedByStaleRevocations { reason: String },
}

/// Errors that make the decision impossible to compute. Distinct from
/// [`UpdateDecision`] because they indicate input-trust failures
/// rather than authoritative verdicts. Callers MUST fail-closed on
/// any of these — proceeding-as-if-no-update would be a security
/// regression.
#[derive(Debug, Error)]
pub enum UpdateDecisionError {
    /// Channel pointer signature did not verify, or the TTL is
    /// expired / not-yet-valid. The pointer cannot be trusted.
    #[error("channel pointer trust failure: {0}")]
    PointerInvalid(#[from] ChannelPointerError),
    /// The revocations document could not be parsed as a signed envelope,
    /// failed signature verification, or failed schema validation. Same
    /// fail-closed posture as a tampered pointer.
    #[error("revocations document trust failure: {0}")]
    RevocationsInvalid(#[from] RevocationPollError),
}

/// Compose the channel pointer + revocations document + current
/// digest into a single [`UpdateDecision`]. Pure.
///
/// `current_digest` is the digest of the image the operator is
/// presently running (matches the `digest` field on
/// [`crate::revocations::RevocationEntry`]). Typical form is
/// `sha256:<64 hex>`.
///
/// `now_unix_ms` is the wall-clock at decision time, passed in so the
/// function stays deterministic for testing. The caller normally
/// reads it from `SystemTime::now()` immediately before the call.
/// `revocations_poller` controls the signer pin and stale-threshold for
/// fail-closed behavior. [`RevocationsPoller::new()`] has no trusted signer and
/// therefore fails closed; owned signing infrastructure must provide a poller
/// from [`RevocationsPoller::with_trusted_signer`].
///
/// ember_up_auto_update.
pub fn decide_update(
    current_digest: &str,
    pointer: &ChannelPointer,
    pointer_signer: &VerifyingKey,
    revocations_raw: &[u8],
    revocations_poller: &RevocationsPoller,
    now_unix_ms: u64,
) -> Result<UpdateDecision, UpdateDecisionError> {
    // 1. Verify the pointer — fail-closed on tampered / expired.
    verify_channel_pointer(pointer, pointer_signer, now_unix_ms)?;

    // 2. Parse + evaluate revocations.
    let now_unix_secs = now_unix_ms / 1000;
    let decisions = match revocations_poller.evaluate(revocations_raw, now_unix_secs) {
        Ok(decisions) => decisions,
        Err(RevocationPollError::StaleDocument {
            age_secs,
            threshold_secs,
        }) => {
            return Ok(UpdateDecision::BlockedByStaleRevocations {
                reason: format!(
                    "revocation document stale: age {age_secs}s > threshold {threshold_secs}s"
                ),
            });
        }
        Err(e) => return Err(UpdateDecisionError::RevocationsInvalid(e)),
    };

    // 3. Legacy compatibility guard — older poller variants represented
    //    staleness as a per-entry FailClosed action. Current signed pollers
    //    return RevocationPollError::StaleDocument above, but keep this branch
    //    so callers never silently treat FailClosed as "no revocations".
    if let Some(stale) = decisions
        .iter()
        .find(|d| matches!(d.action, RevocationAction::FailClosed { .. }))
    {
        let reason = match &stale.action {
            RevocationAction::FailClosed { reason } => reason.clone(),
            _ => "stale".to_string(),
        };
        return Ok(UpdateDecision::BlockedByStaleRevocations { reason });
    }

    // 4. Current digest revoked?
    if let Some(hit) = decisions.iter().find(|d| d.entry.digest == current_digest) {
        return Ok(UpdateDecision::CurrentRevoked {
            severity: hit.entry.severity.clone(),
            action: hit.action.clone(),
            reason: hit.entry.reason.clone(),
        });
    }

    // 5. Same digest → steady state.
    if pointer.manifest_digest_hex == current_digest {
        return Ok(UpdateDecision::NoUpdate);
    }

    // 6. New manifest available — caller pulls + verifies in-toto next.
    Ok(UpdateDecision::UpdateAvailable {
        new_digest: pointer.manifest_digest_hex.clone(),
        manifest_uri: pointer.manifest_uri.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Channel, sign_channel_pointer};
    use crate::in_toto;
    use crate::revocations::{RevocationDocument, RevocationEntry, revocation_statement};
    use ed25519_dalek::SigningKey;

    /// Helper: produce a deterministic signing key + verifying key for
    /// the tests. ember-update's library-crate rule requires
    /// deterministic fixtures rather than random key generation, but
    /// this crate's own internal tests can spin a fixed seed.
    fn fixture_keys() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn revocation_fixture_keys() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_pointer(signer: &SigningKey, digest_hex: &str, now_ms: u64) -> ChannelPointer {
        sign_channel_pointer(
            Channel::Release,
            "https://manifest.example/manifest-001.json".to_string(),
            digest_hex.to_string(),
            60 * 60 * 1000, // 1h TTL
            now_ms,
            signer,
        )
    }

    fn empty_revocations(signer: &SigningKey, now_unix_secs: u64) -> Vec<u8> {
        let doc = RevocationDocument {
            revocations: Vec::new(),
            issued_at_unix_secs: now_unix_secs,
        };
        sign_revocations(signer, doc)
    }

    fn revocations_with(
        signer: &SigningKey,
        entries: &[(&str, RevocationSeverity, &str)],
        now_unix_secs: u64,
    ) -> Vec<u8> {
        let revocations = entries
            .iter()
            .map(|(digest, severity, reason)| RevocationEntry {
                digest: (*digest).to_string(),
                severity: severity.clone(),
                reason: (*reason).to_string(),
            })
            .collect();
        sign_revocations(
            signer,
            RevocationDocument {
                revocations,
                issued_at_unix_secs: now_unix_secs,
            },
        )
    }

    fn sign_revocations(signer: &SigningKey, doc: RevocationDocument) -> Vec<u8> {
        let signed = in_toto::sign(revocation_statement(doc), signer).unwrap();
        serde_json::to_vec(&signed).unwrap()
    }

    fn unsigned_empty_revocations(now_unix_secs: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "revocations": [],
            "issued_at_unix_secs": now_unix_secs,
        }))
        .unwrap()
    }

    #[test]
    fn no_update_when_pointer_matches_current_digest() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let revs = empty_revocations(&rev_sk, now_ms / 1000);
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        // ember_up_auto_update — checkpoint mirrored in a test body so
        // grep verification covers production + test paths.
        assert_eq!(decision, UpdateDecision::NoUpdate);
    }

    #[test]
    fn update_available_when_pointer_advances() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let new = "sha256:bbbbbbbb";
        let p = make_pointer(&sk, new, now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let revs = empty_revocations(&rev_sk, now_ms / 1000);
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        match decision {
            UpdateDecision::UpdateAvailable {
                new_digest,
                manifest_uri,
            } => {
                assert_eq!(new_digest, new);
                assert_eq!(manifest_uri, "https://manifest.example/manifest-001.json");
            }
            other => panic!("expected UpdateAvailable, got {other:?}"),
        }
    }

    #[test]
    fn current_revoked_returns_action_and_reason() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, "sha256:bbbbbbbb", now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let revs = revocations_with(
            &rev_sk,
            &[(current, RevocationSeverity::Critical, "CVE-2026-1234")],
            now_ms / 1000,
        );
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        match decision {
            UpdateDecision::CurrentRevoked {
                severity,
                action,
                reason,
            } => {
                assert_eq!(severity, RevocationSeverity::Critical);
                assert_eq!(action, RevocationAction::IsolateDrainKill);
                assert_eq!(reason, "CVE-2026-1234");
            }
            other => panic!("expected CurrentRevoked, got {other:?}"),
        }
    }

    #[test]
    fn stale_revocations_blocks_decision_even_when_pointer_steady() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        // Revocations issued 2 hours ago — past the 30-min stale threshold.
        let revs = revocations_with(
            &rev_sk,
            &[("sha256:cccccccc", RevocationSeverity::Low, "stale-test")],
            (now_ms / 1000) - 2 * 3600,
        );
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        match decision {
            UpdateDecision::BlockedByStaleRevocations { reason } => {
                assert!(reason.contains("stale"));
            }
            other => panic!("expected BlockedByStaleRevocations, got {other:?}"),
        }
    }

    #[test]
    fn pointer_signed_by_wrong_key_returns_pointer_invalid_error() {
        let (sk, _vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        // Different signing key → wrong verifying key
        let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
        let wrong_vk = wrong_sk.verifying_key();
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let revs = empty_revocations(&rev_sk, now_ms / 1000);
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let err = decide_update(current, &p, &wrong_vk, &revs, &poller, now_ms).unwrap_err();
        match err {
            UpdateDecisionError::PointerInvalid(_) => {}
            other => panic!("expected PointerInvalid, got {other:?}"),
        }
    }

    #[test]
    fn malformed_revocations_returns_revocations_invalid_error() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let bad_revs = b"not valid json";
        let (_rev_sk, rev_vk) = revocation_fixture_keys();
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let err = decide_update(current, &p, &vk, bad_revs, &poller, now_ms).unwrap_err();
        match err {
            UpdateDecisionError::RevocationsInvalid(_) => {}
            other => panic!("expected RevocationsInvalid, got {other:?}"),
        }
    }

    #[test]
    fn fresh_revocation_for_unrelated_digest_does_not_block_steady_state() {
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        // Revocation lists a DIFFERENT digest.
        let revs = revocations_with(
            &rev_sk,
            &[("sha256:cccccccc", RevocationSeverity::High, "other-cve")],
            now_ms / 1000,
        );
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        assert_eq!(decision, UpdateDecision::NoUpdate);
    }

    #[test]
    fn current_revoked_takes_precedence_over_pointer_advance() {
        // A current-digest revocation matters more than a new pointer:
        // the operator must learn that the running image is unsafe,
        // not just that a newer one is available. (Caller may decide
        // to roll forward to the new image as remediation, but that's
        // a higher-layer decision.)
        let (sk, vk) = fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, "sha256:bbbbbbbb", now_ms);
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let revs = revocations_with(
            &rev_sk,
            &[(current, RevocationSeverity::High, "regression-found")],
            now_ms / 1000,
        );
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);
        let decision = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap();
        assert!(matches!(
            decision,
            UpdateDecision::CurrentRevoked {
                severity: RevocationSeverity::High,
                action: RevocationAction::DrainToTtl,
                ..
            }
        ));
    }

    #[test]
    fn unsigned_revocations_cannot_produce_no_update() {
        let (sk, vk) = fixture_keys();
        let (_rev_sk, rev_vk) = revocation_fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let unsigned_revs = unsigned_empty_revocations(now_ms / 1000);
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);

        let err = decide_update(current, &p, &vk, &unsigned_revs, &poller, now_ms).unwrap_err();
        assert!(matches!(err, UpdateDecisionError::RevocationsInvalid(_)));
    }

    #[test]
    fn future_dated_revocations_cannot_produce_no_update() {
        let (sk, vk) = fixture_keys();
        let (rev_sk, rev_vk) = revocation_fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, current, now_ms);
        let revs = empty_revocations(&rev_sk, now_ms / 1000 + 60);
        let poller = RevocationsPoller::with_trusted_signer(rev_vk);

        let err = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap_err();
        assert!(matches!(err, UpdateDecisionError::RevocationsInvalid(_)));
    }

    #[test]
    fn missing_revocation_signer_cannot_produce_update_available() {
        let (sk, vk) = fixture_keys();
        let (rev_sk, _rev_vk) = revocation_fixture_keys();
        let now_ms = 1_800_000_000_000u64;
        let current = "sha256:aaaaaaaa";
        let p = make_pointer(&sk, "sha256:bbbbbbbb", now_ms);
        let revs = empty_revocations(&rev_sk, now_ms / 1000);
        let poller = RevocationsPoller::new();

        let err = decide_update(current, &p, &vk, &revs, &poller, now_ms).unwrap_err();
        assert!(matches!(err, UpdateDecisionError::RevocationsInvalid(_)));
    }
}
