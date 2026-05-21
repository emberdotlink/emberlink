//!
//! Offline chain integrity + signature verification for a sequence of
//! `EventEnvelope`s. Covers design §Component 4 checks 1–3 (envelope
//! signature, body hash, chain integrity) as a shared substrate.
//!
//! This module is deliberately ignorant of storage and transport — it
//! takes a slice of envelopes and a trusted identity-root public key and
//! returns a structured `VerifyOutcome`. The daemon-side audit path
//! materializes envelopes from `core-eventlog::EventLog` and calls into
//! this primitive; the CLI export-import path materializes envelopes
//! from a CBOR-on-disk shape and calls into the same primitive. Keeping
//! the verifier free of I/O is what makes "offline verifiability" a
//! cheap property.
//!
//! # What this verifier covers (and what it does not)
//!
//! Per design §Component 4 the full operator-visible verify surface
//! has five checks. This module ships checks 1–3 as the minimum-viable
//! substrate; checks 4 and 5 (materialization correlation, workflow
//! grant scope at issuance) require additional context this primitive
//! does not own and are covered by follow-up tasks
//! (`implementation-note-38`,
//! `implementation-note-39`).
//!
//! 1. **Envelope signature** — Ed25519 verify of `envelope.signature`
//!    over `envelope.signed_bytes()` under `envelope.signer`, gated by
//!    the canonical `DOMAIN_EVENT` context tag. Catches forged events
//!    and cross-domain signature replay.
//! 2. **Body hash** — re-runs `envelope.validate()` which asserts
//!    `envelope.payload == envelope.body.canonical_encode()`. Catches
//!    body-tamper that left the signed metadata intact.
//! 3. **Chain integrity** — for each `root_id` present in the slice,
//!    walks the `EventRef::Previous` refs and asserts (a) the target
//!    matches the prior head's `event_id`, (b) the `seq` is the prior
//!    head's `seq + 1` (no skip, no replay), (c) the genesis event has
//!    no `Previous` ref. Maps to the same semantic class as
//!    `core-eventlog::materialize::check_chain` but operates standalone
//!    on a slice without needing a materialized state.
//!
//! # Identity-root pinning
//!
//! `verify_chain` takes an `identity_root: &PublicKey` argument. When
//! the slice contains root-signed events (signer role indicates a root
//! key), the verifier confirms the signer key material matches the
//! pinned identity root. This catches "valid signature, wrong root"
//! attacks where an attacker substitutes a slice signed by their own
//! root for the operator's expected root. Non-root events (persona-
//! signed, broker-signed, etc.) are signature-checked against the
//! embedded `signer` key only — chain-of-trust resolution back to the
//! identity root is a separate concern owned by the trust-anchor
//! resolver and is out of scope for this primitive.
//!
//! # Checkpoint
//!
//! The checkpoint `audit_verify_cli_landed` (used by implementation-note-40
//! to confirm the substrate shipped) is anchored below.

// anchor: audit_verify_cli_landed

use core_crypto::{DOMAIN_EVENT, Ed25519Verifier, PublicKey, verify_with_context};
use core_event_types::{EventRefRelation, KeyRole};
use core_events::EventEnvelope;
use core_types::Validate;

/// Verdict returned by `verify_chain`. `Pass` means every check ran
/// clean across every envelope; `Break` enumerates each per-envelope
/// failure with a structured reason class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every envelope passed all three checks.
    ///
    /// `verified_count` is the number of envelopes walked successfully;
    /// `head_event_id` is the `event_id` of the last envelope in the
    /// slice (useful for operator-facing render: "verified up to
    /// `<head>`"). An empty input slice returns `Pass { verified_count:
    /// 0, head_event_id: None }`.
    Pass {
        verified_count: usize,
        head_event_id: Option<String>,
    },
    /// One or more envelopes failed verification. `verified_count` is
    /// the number of envelopes that passed cleanly before the first
    /// failure; `failures` lists every failure encountered (the
    /// verifier does NOT short-circuit so the operator sees the full
    /// blast radius in one pass).
    Break {
        verified_count: usize,
        failures: Vec<VerifyFailure>,
    },
}

/// One envelope's failure, with enough context for the operator to
/// locate the bad row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailure {
    /// `EventEnvelope::event_id` of the failing envelope. The CLI
    /// surfaces this verbatim so the operator can drill down via
    /// `ember audit show <event_id>`.
    pub event_id: String,
    /// Coarse failure class — drives operator-facing summary lines
    /// (e.g. "3 signature failures, 1 chain break").
    pub reason_class: VerifyReasonClass,
    /// Human-readable detail. Stable enough for log greps but not part
    /// of the type-level contract — operators read it, automation
    /// keys on `reason_class`.
    pub detail: String,
}

/// Failure classes covered by this substrate. Forward-compatible:
/// follow-up tasks adding checks 4 and 5 will extend this enum (chain
/// integrity by `materialization_id`, workflow scope violation).
/// Marked `#[non_exhaustive]` so adding variants is non-breaking for
/// downstream `match` sites that include a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyReasonClass {
    /// Check type 1 — Ed25519 signature failed to verify against the
    /// embedded `signer` key under `DOMAIN_EVENT`. Includes the case
    /// where the embedded `signer` key does not match the pinned
    /// `identity_root` for root-signed events.
    SignatureInvalid,
    /// Check type 2 — `envelope.validate()` rejected the envelope. Most
    /// commonly: `payload != body.canonical_encode()`. Also catches
    /// other invariants the envelope enforces (duplicate refs, payload
    /// size cap, body-event-type mismatch).
    BodyHashMismatch,
    /// Check type 3 — chain walk found an out-of-order envelope. The
    /// `Previous` ref's `target_event_id` did not match the prior
    /// head's `event_id`, or `seq` did not match `prior_seq + 1`, or a
    /// non-genesis event was missing its `Previous` ref.
    ChainKindOutOfOrder,
}

/// Walk `events` and verify checks 1–3 against `identity_root`.
///
/// `events` is expected in chronological (insertion) order — the chain
/// walk's seq-monotonicity check depends on it. Out-of-order slices
/// will report `ChainKindOutOfOrder` failures, which is correct: if a
/// caller hands the verifier a shuffled slice the chain claim does not
/// hold.
///
/// `identity_root` is the trusted root public key the operator pinned
/// (either from a release-bundled trust set or from their own
/// IdentityRoot export). When an envelope's `signer_binding.role`
/// indicates a root key (`KeyRole::Root`), the verifier asserts
/// `envelope.signer == *identity_root`; on mismatch the envelope is
/// flagged `SignatureInvalid` with detail
/// `"root signer pubkey does not match pinned identity root"`. Non-
/// root-signed envelopes are signature-checked against their embedded
/// `signer` only (delegation-chain resolution to the root is owned by
/// `core-trust` and is not invoked here).
///
/// The verifier walks every envelope before returning — it does NOT
/// short-circuit on the first failure. This is deliberate: the
/// operator's debug workflow is "show me everything that's wrong" in
/// one pass, not "fix one, re-run, repeat."
pub fn verify_chain(events: &[EventEnvelope], identity_root: &PublicKey) -> VerifyOutcome {
    if events.is_empty() {
        return VerifyOutcome::Pass {
            verified_count: 0,
            head_event_id: None,
        };
    }

    let mut failures: Vec<VerifyFailure> = Vec::new();
    let verifier = Ed25519Verifier;
    let mut verified_count: usize = 0;

    // Per-root chain head tracking: maps root_id → (head_event_id, head_seq).
    // The chain check operates per-root because the EventEnvelope chain
    // is per-root monotonic, not workspace-global.
    use std::collections::BTreeMap;
    let mut chain_heads: BTreeMap<String, (String, u64)> = BTreeMap::new();

    for envelope in events {
        let mut envelope_clean = true;

        // Check 1 — envelope signature.
        // First: if this is a root-signed envelope, the embedded signer
        // pubkey MUST match the pinned identity_root. This catches the
        // "valid signature against a different root" substitution
        // attack.
        if envelope.signer_binding.role == KeyRole::Root && envelope.signer != *identity_root {
            failures.push(VerifyFailure {
                event_id: envelope.event_id.clone(),
                reason_class: VerifyReasonClass::SignatureInvalid,
                detail: format!(
                    "root signer pubkey does not match pinned identity root \
                     (envelope.signer={:?}, expected={:?})",
                    envelope.signer, identity_root,
                ),
            });
            envelope_clean = false;
        }
        // Second: Ed25519 verify the signature itself, regardless of
        // role. Even if the root-mismatch check above flagged this
        // envelope, run the signature check too — the operator may
        // want to know both facts (bad-root AND bad-sig), not just
        // the first one we tripped.
        let signed_bytes = envelope.signed_bytes();
        let sig_ok = verify_with_context(
            DOMAIN_EVENT,
            &verifier,
            &envelope.signer,
            &signed_bytes,
            &envelope.signature,
        );
        if !sig_ok {
            failures.push(VerifyFailure {
                event_id: envelope.event_id.clone(),
                reason_class: VerifyReasonClass::SignatureInvalid,
                detail: "Ed25519 signature failed to verify under DOMAIN_EVENT".to_string(),
            });
            envelope_clean = false;
        }

        // Check 2 — body hash. envelope.validate() asserts the payload
        // bytes match body.canonical_encode() (along with several
        // envelope-shape invariants); a payload-tamper that left the
        // signed metadata intact would slip past check 1 but trips
        // here. This is the eventlog-level analogue of the design
        // sidecar blake3 check (we don't have a sidecar at this layer
        // — body bytes are inline in the envelope — but the integrity
        // claim is the same: the payload binds the typed body).
        if let Err(e) = envelope.validate() {
            failures.push(VerifyFailure {
                event_id: envelope.event_id.clone(),
                reason_class: VerifyReasonClass::BodyHashMismatch,
                detail: format!("envelope validate failed: {e}"),
            });
            envelope_clean = false;
        }

        // Check 3 — chain integrity. Walk the Previous ref against the
        // per-root head. Same semantic class as
        // core-eventlog::materialize::check_chain but operates against
        // a local chain-head map (not a MaterializedState) so the
        // verifier stays I/O-free.
        let root_id_opt = envelope.body.root_id().map(str::to_string);
        if let Some(root_id) = &root_id_opt {
            let prev_ref = envelope
                .refs
                .iter()
                .find(|r| r.relation == EventRefRelation::Previous);
            match (prev_ref, chain_heads.get(root_id)) {
                // Genesis: no prev ref and no known head — allow.
                (None, None) => {}
                // No prev ref but a head exists — chain break (missing
                // required ref).
                (None, Some((head_event_id, head_seq))) => {
                    failures.push(VerifyFailure {
                        event_id: envelope.event_id.clone(),
                        reason_class: VerifyReasonClass::ChainKindOutOfOrder,
                        detail: format!(
                            "missing Previous ref for root {root_id}; \
                             expected prev_event_id={head_event_id} seq={}",
                            head_seq + 1,
                        ),
                    });
                    envelope_clean = false;
                }
                // Prev ref but no head — chain break (dangling ref).
                (Some(r), None) => {
                    failures.push(VerifyFailure {
                        event_id: envelope.event_id.clone(),
                        reason_class: VerifyReasonClass::ChainKindOutOfOrder,
                        detail: format!(
                            "Previous ref points to {} but root {} has no chain head in slice",
                            r.target_event_id, root_id,
                        ),
                    });
                    envelope_clean = false;
                }
                // Prev ref and known head — enforce target + seq.
                (Some(r), Some((head_event_id, head_seq))) => {
                    let expected_seq = head_seq + 1;
                    if r.target_event_id != *head_event_id || r.seq != expected_seq {
                        failures.push(VerifyFailure {
                            event_id: envelope.event_id.clone(),
                            reason_class: VerifyReasonClass::ChainKindOutOfOrder,
                            detail: format!(
                                "chain break: expected prev_event_id={head_event_id} \
                                 seq={expected_seq}, got prev_event_id={} seq={}",
                                r.target_event_id, r.seq,
                            ),
                        });
                        envelope_clean = false;
                    }
                }
            }
        }

        if envelope_clean {
            verified_count += 1;
        }

        // Always advance the chain head even if checks failed, so
        // subsequent envelopes are evaluated against the head they
        // claim to follow (not the last good head). This avoids
        // cascading "missing prev" errors after a single bad envelope.
        if let Some(root_id) = root_id_opt {
            let seq = envelope
                .refs
                .iter()
                .find(|r| r.relation == EventRefRelation::Previous)
                .map(|r| r.seq)
                .unwrap_or(0);
            chain_heads.insert(root_id, (envelope.event_id.clone(), seq));
        }
    }

    let head_event_id = events.last().map(|e| e.event_id.clone());
    if failures.is_empty() {
        VerifyOutcome::Pass {
            verified_count,
            head_event_id,
        }
    } else {
        VerifyOutcome::Break {
            verified_count,
            failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{FixtureSigner, Signer};
    use core_event_types::{EventBody, PersonaCreatedEvent, RootCreatedEvent, SignerBinding};
    use core_events::EventRef;
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};

    fn principal_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: format!("devpub:{key_id}"),
        }
    }

    fn make_root_created(
        event_id: &str,
        root_id: &str,
        signer: &FixtureSigner,
    ) -> EventEnvelope {
        let pk = signer.public_key();
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: root_id.into(),
            display_name: "Primary".into(),
            initial_key: PublicKeyMaterial {
                key_id: format!("{root_id}-initial"),
                algorithm: KeyAlgorithm::Ed25519,
                public_key: pk.0.clone(),
            },
        });
        EventEnvelope::from_body(
            event_id,
            body,
            vec![],
            SignerBinding::root(root_id, format!("{root_id}-initial")),
            signer,
        )
        .expect("from_body")
    }

    fn make_persona_created(
        event_id: &str,
        root_id: &str,
        persona_id: &str,
        prev_event_id: &str,
        prev_seq: u64,
        signer: &FixtureSigner,
    ) -> EventEnvelope {
        let body = EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: root_id.into(),
            persona_id: persona_id.into(),
            label: "Work".into(),
            disclosure_profile: None,
            survival_mode: SurvivalMode::Strict,
            initial_key: principal_key(&format!("{persona_id}-key")),
        });
        EventEnvelope::from_body(
            event_id,
            body,
            vec![EventRef::previous(prev_event_id, prev_seq)],
            SignerBinding::root(root_id, format!("{root_id}-initial")),
            signer,
        )
        .expect("from_body")
    }

    #[test]
    fn empty_input_is_pass() {
        let signer = FixtureSigner::new("root-key");
        let outcome = verify_chain(&[], &signer.public_key());
        assert!(matches!(
            outcome,
            VerifyOutcome::Pass {
                verified_count: 0,
                head_event_id: None,
            }
        ));
    }

    #[test]
    fn genesis_then_child_passes_clean_chain() {
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();
        let e0 = make_root_created("evt-0", "root-1", &signer);
        let e1 = make_persona_created("evt-1", "root-1", "persona-1", "evt-0", 1, &signer);
        let outcome = verify_chain(&[e0, e1], &identity_root);
        match outcome {
            VerifyOutcome::Pass {
                verified_count,
                head_event_id,
            } => {
                assert_eq!(verified_count, 2);
                assert_eq!(head_event_id.as_deref(), Some("evt-1"));
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    #[test]
    fn tampered_payload_trips_body_hash_check() {
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();
        let mut e0 = make_root_created("evt-0", "root-1", &signer);
        // Corrupt the payload so it no longer matches body.canonical_encode().
        e0.payload.push(0xff);
        let outcome = verify_chain(&[e0], &identity_root);
        match outcome {
            VerifyOutcome::Break {
                verified_count,
                failures,
            } => {
                assert_eq!(verified_count, 0);
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason_class == VerifyReasonClass::BodyHashMismatch),
                    "expected BodyHashMismatch in failures: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn forged_signature_trips_signature_check() {
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();
        let mut e0 = make_root_created("evt-0", "root-1", &signer);
        // Swap the signature for an invalid one. Use an arbitrary
        // 64-byte signature (128 hex chars) whose decoded bytes won't
        // verify under the signer's key.
        e0.signature = core_crypto::Signature(format!("ed25519sig:{}", "00".repeat(64)));
        let outcome = verify_chain(&[e0], &identity_root);
        match outcome {
            VerifyOutcome::Break {
                verified_count,
                failures,
            } => {
                assert_eq!(verified_count, 0);
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason_class == VerifyReasonClass::SignatureInvalid),
                    "expected SignatureInvalid in failures: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn root_signer_mismatching_pinned_identity_root_trips_signature_check() {
        let signer = FixtureSigner::new("real-root-key");
        // Operator pinned a DIFFERENT root than the one that signed
        // the envelope. The signature itself is valid against the
        // embedded signer, but the embedded signer does not match the
        // pinned root.
        let attacker_root = PublicKey("ed25519:attackerpubkey".to_string());
        let e0 = make_root_created("evt-0", "root-1", &signer);
        let outcome = verify_chain(&[e0], &attacker_root);
        match outcome {
            VerifyOutcome::Break {
                verified_count,
                failures,
            } => {
                assert_eq!(verified_count, 0);
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason_class == VerifyReasonClass::SignatureInvalid
                            && f.detail.contains("pinned identity root")),
                    "expected pinned-identity-root failure: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn chain_break_missing_previous_ref_is_reported() {
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();
        let e0 = make_root_created("evt-0", "root-1", &signer);
        // Second event has NO Previous ref despite the head existing.
        // Build via from_body with empty refs to construct the
        // chain-broken envelope explicitly.
        let body = EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-1".into(),
            persona_id: "persona-1".into(),
            label: "Work".into(),
            disclosure_profile: None,
            survival_mode: SurvivalMode::Strict,
            initial_key: principal_key("persona-1-key"),
        });
        let e1 = EventEnvelope::from_body(
            "evt-1",
            body,
            vec![], // no Previous ref
            SignerBinding::root("root-1", "root-1-initial"),
            &signer,
        )
        .unwrap();
        let outcome = verify_chain(&[e0, e1], &identity_root);
        match outcome {
            VerifyOutcome::Break {
                verified_count,
                failures,
            } => {
                assert_eq!(verified_count, 1, "e0 should pass; only e1 fails");
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason_class == VerifyReasonClass::ChainKindOutOfOrder
                            && f.detail.contains("missing Previous ref")),
                    "expected missing-Previous-ref failure: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn chain_break_wrong_seq_is_reported() {
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();
        let e0 = make_root_created("evt-0", "root-1", &signer);
        // Build a child envelope claiming seq=5 (skip). The expected
        // seq after a genesis with no Previous ref is 1.
        let e1 = make_persona_created("evt-1", "root-1", "persona-1", "evt-0", 5, &signer);
        let outcome = verify_chain(&[e0, e1], &identity_root);
        match outcome {
            VerifyOutcome::Break {
                verified_count,
                failures,
            } => {
                assert_eq!(verified_count, 1);
                assert!(
                    failures
                        .iter()
                        .any(|f| f.reason_class == VerifyReasonClass::ChainKindOutOfOrder
                            && f.detail.contains("chain break")),
                    "expected chain-break failure: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn multiple_failures_in_one_pass_are_all_collected() {
        // Two bad envelopes — verifier does NOT short-circuit; the
        // operator sees the full blast radius.
        let signer = FixtureSigner::new("root-key");
        let identity_root = signer.public_key();

        let mut e0 = make_root_created("evt-0", "root-1", &signer);
        e0.payload.push(0xff); // body-hash break

        let mut e1 = make_root_created("evt-1", "root-2", &signer);
        // signature break — different attack from e0
        e1.signature = core_crypto::Signature(format!("ed25519sig:{}", "00".repeat(64)));

        let outcome = verify_chain(&[e0, e1], &identity_root);
        match outcome {
            VerifyOutcome::Break { failures, .. } => {
                let body_failures = failures
                    .iter()
                    .filter(|f| f.reason_class == VerifyReasonClass::BodyHashMismatch)
                    .count();
                let sig_failures = failures
                    .iter()
                    .filter(|f| f.reason_class == VerifyReasonClass::SignatureInvalid)
                    .count();
                assert!(
                    body_failures >= 1,
                    "expected ≥1 body-hash failure: {failures:?}"
                );
                assert!(
                    sig_failures >= 1,
                    "expected ≥1 signature failure: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }
}
