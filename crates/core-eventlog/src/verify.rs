//! CLASSIFICATION: PUBLIC
//!
//! Offline chain integrity + signature verification for a sequence of
//! `EventEnvelope`s. Covers ADR 160 §Component 4 checks 1–3 (envelope
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
//! Per ADR 160 §Component 4 the full operator-visible verify surface
//! has five checks. This module ships checks 1–3 as the minimum-viable
//! substrate; checks 4 and 5 (materialization correlation, workflow
//! grant scope at issuance) require additional context this primitive
//! does not own and are covered by follow-up tasks
//! (`META-AUDIT-VERIFY-CLI-FOLLOWUP-MATERIALIZATION-CHECK`,
//! `META-AUDIT-VERIFY-CLI-FOLLOWUP-WORKFLOW-SCOPE-CHECK`).
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
//! # Identity-root pinning and Principal recursion
//!
//! `verify_chain` takes an `identity_root: &PublicKey` argument. When
//! the slice contains root-signed events (signer role indicates a root
//! key), the verifier confirms the signer key material matches the
//! pinned identity root. This catches "valid signature, wrong root"
//! attacks where an attacker substitutes a slice signed by their own root for
//! the operator's expected root.
//!
//! Per ADR 200's 2026-06-15 Principal unification, non-root signer attribution
//! also has to resolve through a recursive Principal chain. Until the canonical
//! `Principal { id, parent_id, ... }` event shape lands, this verifier builds a
//! compatibility graph from existing events: `RootCreated.root_id` is a
//! self-parented Principal, and `PersonaCreated.root_id` is treated as the
//! pre-freeze alias for `parent_id`. Persona-signed events are accepted only
//! when the signing Principal's parent walk terminates at the pinned
//! self-parented trust anchor; missing parents, cycles, and wrong-anchor chains
//! are rejected. Grant/endorsement policy along that path remains a higher-layer
//! authority concern.
//!
//! # Checkpoint
//!
//! The checkpoint `audit_verify_cli_landed` (used by META-AUDIT-VERIFY-CLI
//! to confirm the substrate shipped) is anchored below.

// anchor: audit_verify_cli_landed

use core_crypto::{DOMAIN_EVENT, DeviceSignatureVerifier, PublicKey, verify_with_context};
use core_event_types::{AttestationTier, CustodyClass, EventBody, EventRefRelation, KeyRole};
use core_events::EventEnvelope;
use core_principals::PublicKeyMaterial;
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
    /// Principal-chain verification failed. The signer attribution did
    /// not resolve through `parent_id` recursion to the verifier's
    /// independently pinned self-parented trust anchor.
    PrincipalChainInvalid,
}

#[derive(Debug, Clone)]
struct VerifyPrincipal {
    id: String,
    parent_id: String,
    active_key_id: String,
    active_public_key: String,
}

impl VerifyPrincipal {
    fn self_parented(
        id: impl Into<String>,
        active_key_id: impl Into<String>,
        active_public_key: impl Into<String>,
    ) -> Self {
        let id = id.into();
        Self {
            parent_id: id.clone(),
            id,
            active_key_id: active_key_id.into(),
            active_public_key: active_public_key.into(),
        }
    }

    fn child(
        id: impl Into<String>,
        parent_id: impl Into<String>,
        active_key_id: impl Into<String>,
        active_public_key: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            parent_id: parent_id.into(),
            active_key_id: active_key_id.into(),
            active_public_key: active_public_key.into(),
        }
    }

    fn is_self_parented(&self) -> bool {
        self.id == self.parent_id
    }
}

fn signer_principal_id(binding: &core_event_types::SignerBinding) -> Option<&str> {
    match binding.role {
        KeyRole::Principal | KeyRole::Root | KeyRole::Persona => {
            Some(binding.signer.subject_id.as_str())
        }
        KeyRole::Device | KeyRole::Guardian | KeyRole::Unknown => None,
    }
}

fn root_created_candidate(body: &EventBody, principal_id: &str) -> Option<VerifyPrincipal> {
    match body {
        EventBody::RootCreated(root) if root.root_id == principal_id => {
            Some(VerifyPrincipal::self_parented(
                &root.root_id,
                &root.initial_key.key_id,
                &root.initial_key.public_key,
            ))
        }
        _ => None,
    }
}

fn verify_signer_principal_chain(
    envelope: &EventEnvelope,
    identity_root: &PublicKey,
    principals: &std::collections::BTreeMap<String, VerifyPrincipal>,
    trusted: &std::collections::BTreeSet<String>,
    device_keys: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    let Some(principal_id) = signer_principal_id(&envelope.signer_binding) else {
        return Ok(());
    };

    let mut current = principal_id.to_string();
    let mut seen = std::collections::BTreeSet::new();
    let mut first = true;

    loop {
        if !seen.insert(current.clone()) {
            return Err(format!(
                "Principal parent chain contains a cycle at {current}"
            ));
        }

        let record = principals
            .get(&current)
            .cloned()
            .or_else(|| root_created_candidate(&envelope.body, &current))
            .ok_or_else(|| format!("missing Principal record while walking parent_id={current}"))?;

        if first
            && matches!(
                envelope.signer_binding.role,
                KeyRole::Principal | KeyRole::Persona
            )
        {
            let active_key_matches = record.active_key_id == envelope.signer_binding.key_id
                && record.active_public_key == envelope.signer.0;
            let signing_device_matches = device_keys
                .get(&envelope.signer_binding.key_id)
                .is_some_and(|pk| *pk == envelope.signer.0);
            let root_authority_matches = record.is_self_parented()
                && trusted.contains(&envelope.signer.0)
                && (active_key_matches || signing_device_matches);

            if !active_key_matches && !root_authority_matches {
                return Err(format!(
                    "signer key_id {} / pubkey do not match Principal {}",
                    envelope.signer_binding.key_id, record.id
                ));
            }
        }

        if record.is_self_parented() {
            if record.active_public_key != identity_root.0 {
                return Err(format!(
                    "Principal chain terminates at {} but that anchor is not the pinned trust anchor",
                    record.id
                ));
            }
            return Ok(());
        }

        current = record.parent_id;
        first = false;
    }
}

fn apply_principal_event(
    body: &EventBody,
    principals: &mut std::collections::BTreeMap<String, VerifyPrincipal>,
) {
    match body {
        EventBody::RootCreated(root) => {
            principals.insert(
                root.root_id.clone(),
                VerifyPrincipal::self_parented(
                    &root.root_id,
                    &root.initial_key.key_id,
                    &root.initial_key.public_key,
                ),
            );
        }
        EventBody::PersonaCreated(persona) => {
            principals.insert(
                persona.persona_id.clone(),
                VerifyPrincipal::child(
                    &persona.persona_id,
                    &persona.root_id,
                    &persona.initial_key.key_id,
                    &persona.initial_key.public_key,
                ),
            );
        }
        EventBody::PersonaKeyRotated(persona) => {
            if let Some(record) = principals.get_mut(&persona.persona_id) {
                record.active_key_id = persona.new_key.key_id.clone();
                record.active_public_key = persona.new_key.public_key.clone();
            }
        }
        EventBody::PersonaRevoked(persona) => {
            principals.remove(&persona.persona_id);
        }
        _ => {}
    }
}

/// Walk `events` and verify checks 1–3 against `identity_root`.
///
/// `events` is expected in chronological (insertion) order — the chain
/// walk's seq-monotonicity check depends on it. Out-of-order slices
/// will report `ChainKindOutOfOrder` failures, which is correct: if a
/// caller hands the verifier a shuffled slice the chain claim does not
/// hold.
///
/// `identity_root` is the OOB-pinned **genesis anchor** — the operator's
/// founding presence-Device key (or the daemon key for the N=1 daemon root),
/// confirmed out-of-band per ADR 200 §5/AC-2. Under Model C the root's
/// authority is a *set* of devices, so the verifier seeds a trusted set with
/// this anchor and **extends** it as it walks: a clean `DeviceEnrolled(presence)`
/// signed by an already-trusted key adds the new device; a revoke/freeze/replace
/// removes it. A `KeyRole::Root` envelope whose `signer` is not in the current
/// trusted set is flagged `SignatureInvalid` with detail
/// `"root signer pubkey is not in the root authority set"`. Trust therefore
/// terminates at the single OOB anchor and propagates only through signatures
/// the anchor transitively authorized. Non-root-signed envelopes are
/// signature-checked against their embedded `signer` only (delegation-chain
/// resolution to the root is owned by `core-trust` and is not invoked here).
///
/// The verifier walks every envelope before returning — it does NOT
/// short-circuit on the first failure. This is deliberate: the
/// operator's debug workflow is "show me everything that's wrong" in
/// one pass, not "fix one, re-run, repeat."
///
/// **Precondition:** verifies a SINGLE root's chain — `identity_root` is that
/// root's genesis anchor and the trust set is not keyed by `root_id`. Pass only
/// events for the root being verified; mixing multiple roots' events in one call
/// would conflate their authority sets and is unsupported.
/// Re-verifies a recorded attestation statement to the tier it PROVES — the
/// independent-verifier laundering close (ADR 200 §3 / AC-1). [`verify_chain`]
/// honors a presence Device at a tier above [`AttestationTier::None`] only when
/// an injected reverifier reproduces that exact tier from the recorded statement;
/// without one, only the `None` (OOB-anchored) dev0 floor extends authority, so a
/// daemon-asserted higher tier can never launder itself into root authority.
///
/// The concrete impls live ABOVE this crate (PIV x509 for `VendorHw`, App Attest
/// for `GenuineApp`) so the trust walk stays free of x509/CBOR vendor deps and
/// I/O — what makes "offline verifiability" cheap.
pub trait AttestationReverifier {
    /// The HIGHEST attestation tier `statement` provably supports for `device_key`.
    /// MUST return [`AttestationTier::None`] when it cannot prove the claimed tier —
    /// never report a tier the statement does not cryptographically reproduce.
    fn proven_tier(
        &self,
        device_key: &PublicKeyMaterial,
        statement: Option<&str>,
    ) -> AttestationTier;
}

/// Verify a chain with no attestation reverifier — only the `AttestationTier::None`
/// (OOB-anchored) floor extends authority; higher-tier presence enrollments fail
/// closed (gain no authority). Inject a reverifier via [`verify_chain_with_reverifier`]
/// to honor `vendor_hw`/`genuine_app` devices.
pub fn verify_chain(events: &[EventEnvelope], identity_root: &PublicKey) -> VerifyOutcome {
    verify_chain_with_reverifier(events, identity_root, None)
}

/// As [`verify_chain`], but with an injected [`AttestationReverifier`] so a presence
/// Device enrolled at a tier above `None` extends root authority iff the reverifier
/// reproduces its claimed tier from the recorded statement (ADR 200 §3 / AC-1).
pub fn verify_chain_with_reverifier(
    events: &[EventEnvelope],
    identity_root: &PublicKey,
    reverifier: Option<&dyn AttestationReverifier>,
) -> VerifyOutcome {
    if events.is_empty() {
        return VerifyOutcome::Pass {
            verified_count: 0,
            head_event_id: None,
        };
    }

    let mut failures: Vec<VerifyFailure> = Vec::new();
    // Dispatch by the signer key's algorithm prefix: `daemon`-class
    // roots/personas are Ed25519, device-rooted `presence` identities (the
    // operator IdentityRoot, ADR 200 §2/§3) are ECDSA-P256. A single-algorithm
    // verifier here would reject every device-rooted chain as "bad signature",
    // defeating the independent-verifier invariant (AC-1/AC-5).
    let verifier = DeviceSignatureVerifier;
    let mut verified_count: usize = 0;

    use std::collections::{BTreeMap, BTreeSet};
    // Per-root chain head tracking: maps root_id → (head_event_id, head_seq).
    // The chain check operates per-root because the EventEnvelope chain
    // is per-root monotonic, not workspace-global.
    let mut chain_heads: BTreeMap<String, (String, u64)> = BTreeMap::new();

    // Model C root-authority set (ADR 200 §2/§5): the keys allowed to sign
    // root-level events for the pinned root. Seeded with the OOB-pinned genesis
    // anchor (`identity_root` — the operator's founding presence-device key, or
    // the daemon key for the N=1 daemon root) and EXTENDED as the walk verifies
    // device-lifecycle events: a clean `DeviceEnrolled(presence)` signed by an
    // already-trusted key adds the new device; a revoke/freeze/replace removes
    // it. Trust therefore terminates at the single OOB anchor and propagates
    // only through signatures the anchor (transitively) authorized — never a
    // daemon-asserted flag (AC-1/AC-5).
    let mut trusted: BTreeSet<String> = BTreeSet::new();
    trusted.insert(identity_root.0.clone());
    // device_id → active pubkey, so a revoke/freeze/replace (which names a
    // device_id, not a key) can drop the right key from `trusted`.
    let mut device_keys: BTreeMap<String, String> = BTreeMap::new();
    // Compatibility Principal graph for ADR 200's recursive signer model.
    // Existing event bodies still carry `root_id` / `persona_id`; inside the
    // verifier those are interpreted as Principal ids, with `PersonaCreated.root_id`
    // serving as the pre-freeze alias for `parent_id`.
    let mut principals: BTreeMap<String, VerifyPrincipal> = BTreeMap::new();

    for envelope in events {
        let mut envelope_clean = true;

        // Check 1 — envelope signature.
        // First: a root-signed envelope's signer pubkey MUST be in the root's
        // current authority set. For the N=1 daemon root that is exactly the
        // pinned anchor; for the operator root (Model C) it is the anchor plus
        // any presence Device enrolled-and-not-yet-revoked earlier in the walk.
        // Catches the "valid signature against a non-authorized key"
        // substitution attack.
        if envelope.signer_binding.role == KeyRole::Root && !trusted.contains(&envelope.signer.0) {
            failures.push(VerifyFailure {
                event_id: envelope.event_id.clone(),
                reason_class: VerifyReasonClass::SignatureInvalid,
                detail: format!(
                    "root signer pubkey is not in the root authority set \
                     (envelope.signer={:?})",
                    envelope.signer,
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
                detail: "device signature failed to verify under DOMAIN_EVENT".to_string(),
            });
            envelope_clean = false;
        }

        if let Err(detail) = verify_signer_principal_chain(
            envelope,
            identity_root,
            &principals,
            &trusted,
            &device_keys,
        ) {
            failures.push(VerifyFailure {
                event_id: envelope.event_id.clone(),
                reason_class: VerifyReasonClass::PrincipalChainInvalid,
                detail,
            });
            envelope_clean = false;
        }

        // Check 2 — body hash. envelope.validate() asserts the payload
        // bytes match body.canonical_encode() (along with several
        // envelope-shape invariants); a payload-tamper that left the
        // signed metadata intact would slip past check 1 but trips
        // here. This is the eventlog-level analogue of the ADR 160
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

        // Model C trust evolution: only an event that PASSED every check AND was
        // signed by an already-trusted key may mutate the authority set. The
        // `trusted.contains(signer)` gate is belt-and-suspenders over the
        // role==Root pin above — it also closes a non-Root-role DeviceEnrolled
        // that slipped the pin: such an event can never extend trust.
        if envelope_clean && trusted.contains(&envelope.signer.0) {
            match &envelope.body {
                // A presence Device gains root authority once enrolled by a
                // trusted signer (the 1-of-N device set). daemon/co-authority/
                // container devices do NOT — only `presence`.
                EventBody::DeviceEnrolled(b) if b.custody_class == CustodyClass::Presence => {
                    // Tier-laundering close (ADR 200 §3 / AC-1): a presence Device
                    // extends root authority only at a tier the INDEPENDENT verifier
                    // can PROVE. `None` (the dev0 floor) rests on the OOB anchor —
                    // the signer is already trusted — and extends. A claimed tier
                    // ABOVE `None` is honored only if the injected reverifier
                    // reproduces it from the recorded statement; with no reverifier
                    // (or a reverifier that proves less) the claim is unproven HERE
                    // and the Device fails closed — it gains NO authority. This is
                    // what stops a compromised daemon from minting a fake `vendor_hw`
                    // enrollment that the operator's key signs during an upgrade and
                    // a relying party then trusts as root-authoritative.
                    let admits = b.attestation_tier == AttestationTier::None
                        || reverifier
                            .map(|r| {
                                r.proven_tier(&b.device_key, b.attestation_statement.as_deref())
                                    == b.attestation_tier
                            })
                            .unwrap_or(false);
                    if admits {
                        // Re-enrollment of an existing device_id: drop its PREVIOUS
                        // key from trust first, so `device_keys[device_id]` always
                        // names the current key and a later revoke (which names the
                        // device_id) fully revokes — no orphaned key survives.
                        if let Some(old) = device_keys.get(&b.device_id) {
                            trusted.remove(old);
                        }
                        trusted.insert(b.device_key.public_key.clone());
                        device_keys.insert(b.device_id.clone(), b.device_key.public_key.clone());
                    }
                    // else: fail closed — authority NOT extended. The envelope's
                    // signature + chain remain structurally valid (only the tier
                    // claim is unhonored), so the chain itself is not failed here;
                    // a reverifier that ACTIVELY disproves a claim becomes a hard
                    // chain failure when the concrete reverifier lands (PR4b-2).
                }
                // Track daemon-class device keys for later revoke lookups, but
                // they are not root-authoritative so they are never trusted.
                EventBody::DeviceAdded(b) => {
                    device_keys.insert(b.device_id.clone(), b.initial_key.public_key.clone());
                }
                // Key rotation swaps the device's key: the old key loses
                // authority, the new key inherits it iff the device was
                // root-authoritative (presence). Keeps `device_keys` current so
                // revocation still maps to the live key.
                EventBody::DeviceKeyRotated(b) => {
                    if let Some(old) = device_keys.get(&b.device_id).cloned() {
                        let was_trusted = trusted.remove(&old);
                        device_keys.insert(b.device_id.clone(), b.new_key.public_key.clone());
                        if was_trusted {
                            trusted.insert(b.new_key.public_key.clone());
                        }
                    }
                }
                // A revoked / frozen / replaced Device loses authority for all
                // subsequent events (in-order walk preserves historical validity
                // — events it signed while active already verified).
                EventBody::DeviceRevoked(b) => {
                    if let Some(k) = device_keys.get(&b.device_id) {
                        trusted.remove(k);
                    }
                }
                EventBody::DeviceFrozen(b) => {
                    if let Some(k) = device_keys.get(&b.device_id) {
                        trusted.remove(k);
                    }
                }
                EventBody::DeviceReplaced(b) => {
                    if let Some(k) = device_keys.get(&b.replaced_device_id) {
                        trusted.remove(k);
                    }
                }
                _ => {}
            }
        }

        if envelope_clean {
            apply_principal_event(&envelope.body, &mut principals);
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
    use core_event_types::{
        CustodyClass, DeviceAddedEvent, DeviceEnrolledEvent, DeviceRevokedEvent, EventBody,
        PersonaCreatedEvent, PersonaKeyRotatedEvent, PresenceFactor, RootCreatedEvent,
        SignerBinding,
    };
    use core_events::EventRef;
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};

    // anchor: identity_root_persona_eventlog_verifier_landed

    fn principal_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::DevEd25519Like,
            public_key: format!("devpub:{key_id}"),
        }
    }

    fn make_root_created(event_id: &str, root_id: &str, signer: &FixtureSigner) -> EventEnvelope {
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

    /// A device-rooted (ECDSA-P256) signer, mirroring how the operator
    /// IdentityRoot is rooted on its YubiKey PIV key (ADR 200 §2/§3).
    struct P256TestSigner {
        pk: core_crypto::PublicKey,
        signing: p256::ecdsa::SigningKey,
    }

    impl P256TestSigner {
        fn new(scalar_byte: u8) -> Self {
            let signing = p256::ecdsa::SigningKey::from_bytes(&[scalar_byte; 32].into())
                .expect("fixed scalar is a valid P256 key");
            let sec1 = signing.verifying_key().to_encoded_point(false);
            let pk = core_crypto::PublicKey(format!("p256:{}", hex::encode(sec1.as_bytes())));
            Self { pk, signing }
        }
    }

    impl Signer for P256TestSigner {
        fn sign(&self, payload: &[u8]) -> core_crypto::Signature {
            use p256::ecdsa::signature::Signer as _;
            let sig: p256::ecdsa::Signature = self.signing.sign(payload);
            core_crypto::Signature(format!("p256sig:{}", hex::encode(sig.to_der().as_bytes())))
        }
        fn public_key(&self) -> core_crypto::PublicKey {
            self.pk.clone()
        }
    }

    #[test]
    fn verify_chain_accepts_p256_device_rooted_root() {
        // The independent verifier (AC-1/AC-5) must re-verify a device-rooted
        // P256 root chain — verify_chain previously hardcoded Ed25519 and would
        // have rejected it as "bad signature".
        let signer = P256TestSigner::new(0x42);
        let identity_root = signer.public_key();
        assert!(identity_root.0.starts_with("p256:"));

        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "operator-root".into(),
            display_name: "Operator".into(),
            initial_key: PublicKeyMaterial {
                key_id: "operator-root-initial".into(),
                algorithm: KeyAlgorithm::EcdsaP256,
                public_key: identity_root.0.clone(),
            },
        });
        let e0 = EventEnvelope::from_body(
            "evt-0",
            body,
            vec![],
            SignerBinding::root("operator-root", "operator-root-initial"),
            &signer,
        )
        .expect("from_body");

        match verify_chain(&[e0], &identity_root) {
            VerifyOutcome::Pass { verified_count, .. } => assert_eq!(verified_count, 1),
            other => panic!("expected Pass for P256-rooted chain, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_rejects_p256_root_signed_by_wrong_key() {
        // A P256 root whose signature comes from a different key (substitution)
        // must fail — the dispatch must not be a blanket "P256 → accept".
        let real = P256TestSigner::new(0x42);
        let attacker = P256TestSigner::new(0x99);
        let identity_root = real.public_key();
        let body = EventBody::RootCreated(RootCreatedEvent {
            root_id: "operator-root".into(),
            display_name: "Operator".into(),
            initial_key: PublicKeyMaterial {
                key_id: "operator-root-initial".into(),
                algorithm: KeyAlgorithm::EcdsaP256,
                public_key: identity_root.0.clone(),
            },
        });
        // Sign with the attacker key but claim the real root's pinned identity.
        let e0 = EventEnvelope::from_body(
            "evt-0",
            body,
            vec![],
            SignerBinding::root("operator-root", "operator-root-initial"),
            &attacker,
        )
        .expect("from_body");
        assert!(matches!(
            verify_chain(&[e0], &identity_root),
            VerifyOutcome::Break { .. }
        ));
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
                            && f.detail.contains("root authority set")),
                    "expected root-authority-set failure: {failures:?}"
                );
            }
            other => panic!("expected Break, got {other:?}"),
        }
    }

    // --- Model C: root authority is a device SET (walk-and-extend trust) ---

    fn pk_mat(signer: &FixtureSigner, key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: signer.public_key().0,
        }
    }

    /// Build a root-level event under "root-1" signed by `by`.
    fn c_event(
        id: &str,
        body: EventBody,
        prev: Option<(&str, u64)>,
        by: &FixtureSigner,
    ) -> EventEnvelope {
        let refs = match prev {
            Some((tid, seq)) => vec![EventRef::previous(tid, seq)],
            None => vec![],
        };
        EventEnvelope::from_body(id, body, refs, SignerBinding::root("root-1", "k"), by).unwrap()
    }

    fn c_root_created(id: &str, founding: &FixtureSigner) -> EventEnvelope {
        c_event(
            id,
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-1".into(),
                display_name: "R".into(),
                initial_key: pk_mat(founding, "k-root"),
            }),
            None,
            founding,
        )
    }

    fn c_device_enrolled(
        id: &str,
        prev: (&str, u64),
        device_id: &str,
        device: &FixtureSigner,
        custody: CustodyClass,
        by: &FixtureSigner,
    ) -> EventEnvelope {
        c_event(
            id,
            EventBody::DeviceEnrolled(DeviceEnrolledEvent {
                root_id: "root-1".into(),
                device_id: device_id.into(),
                label: device_id.into(),
                device_key: pk_mat(device, &format!("k-{device_id}")),
                encryption_key: pk_mat(device, &format!("k-{device_id}-ecies")),
                custody_class: custody,
                attestation_statement: Some("att".into()),
                // dev0-floor tier so the device extends authority from the OOB
                // anchor without a reverifier (the laundering close honors `None`).
                attestation_tier: AttestationTier::None,
                presence_factor: if custody == CustodyClass::Presence {
                    PresenceFactor::UserPresence
                } else {
                    PresenceFactor::Unattended
                },
            }),
            Some(prev),
            by,
        )
    }

    fn c_persona_created(id: &str, prev: (&str, u64), by: &FixtureSigner) -> EventEnvelope {
        c_event(
            id,
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-1".into(),
                persona_id: "p1".into(),
                label: "P".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(by, "k-p1"),
            }),
            Some(prev),
            by,
        )
    }

    #[test]
    fn c_authority_extends_to_enrolled_presence_device() {
        // Founding key enrolls a backup presence Device d2; a later root op
        // signed by d2 (NOT the founding key) verifies — d2 gained authority.
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &d2,
                CustodyClass::Presence,
                &founding,
            ),
            c_persona_created("evt-2", ("evt-1", 2), &d2),
        ];
        let outcome = verify_chain(&events, &founding.public_key());
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Pass {
                    verified_count: 3,
                    ..
                }
            ),
            "d2 should be root-authoritative after enrollment: {outcome:?}"
        );
    }

    #[test]
    fn c_principal_root_op_uses_signing_device_id() {
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let root = c_root_created("evt-0", &founding);
        let enrolled = c_device_enrolled(
            "evt-1",
            ("evt-0", 1),
            "d2",
            &d2,
            CustodyClass::Presence,
            &founding,
        );
        let principal_signed = EventEnvelope::from_body(
            "evt-2",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-1".into(),
                persona_id: "p1".into(),
                label: "P".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&d2, "k-p1"),
            }),
            vec![EventRef::previous("evt-1", 2)],
            SignerBinding::principal("root-1", "d2"),
            &d2,
        )
        .expect("principal signed root op");

        let outcome = verify_chain(&[root, enrolled, principal_signed], &founding.public_key());
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Pass {
                    verified_count: 3,
                    ..
                }
            ),
            "root Principal should verify when signed on enrolled presence device d2: {outcome:?}"
        );
    }

    /// A presence `DeviceEnrolled` at an explicit attestation tier (laundering-close
    /// tests). Vendor/genuine tiers carry a recorded statement.
    fn c_device_enrolled_tier(
        id: &str,
        prev: (&str, u64),
        device_id: &str,
        device: &FixtureSigner,
        tier: AttestationTier,
        factor: PresenceFactor,
        by: &FixtureSigner,
    ) -> EventEnvelope {
        c_event(
            id,
            EventBody::DeviceEnrolled(DeviceEnrolledEvent {
                root_id: "root-1".into(),
                device_id: device_id.into(),
                label: device_id.into(),
                device_key: pk_mat(device, &format!("k-{device_id}")),
                encryption_key: pk_mat(device, &format!("k-{device_id}-ecies")),
                custody_class: CustodyClass::Presence,
                attestation_statement: Some("vendor-chain".into()),
                attestation_tier: tier,
                presence_factor: factor,
            }),
            Some(prev),
            by,
        )
    }

    /// A reverifier that always reports a fixed proven tier (test double).
    struct ProveTier(AttestationTier);
    impl AttestationReverifier for ProveTier {
        fn proven_tier(&self, _d: &PublicKeyMaterial, _s: Option<&str>) -> AttestationTier {
            self.0
        }
    }

    #[test]
    fn c_vendor_hw_enrollment_fails_closed_without_reverifier() {
        // Tier-laundering close (ADR 200 §3 / AC-1): a presence Device claiming
        // tier=VendorHw gains NO authority when no reverifier can re-run its
        // statement — a compromised daemon cannot launder a fake `vendor_hw`
        // device into root authority via the operator's enrolling signature.
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled_tier(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &d2,
                AttestationTier::VendorHw,
                PresenceFactor::HardwareTouch,
                &founding,
            ),
            // d2 attempts a root op — it must be rejected (never gained authority).
            c_persona_created("evt-2", ("evt-1", 2), &d2),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Break { .. }
            ),
            "an unproven vendor_hw device must NOT gain root authority"
        );
    }

    #[test]
    fn c_vendor_hw_enrollment_extends_with_proving_reverifier() {
        // With a reverifier that reproduces the claimed tier from the statement,
        // the vendor_hw device DOES extend authority (the honoring path).
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled_tier(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &d2,
                AttestationTier::VendorHw,
                PresenceFactor::HardwareTouch,
                &founding,
            ),
            c_persona_created("evt-2", ("evt-1", 2), &d2),
        ];
        let outcome = verify_chain_with_reverifier(
            &events,
            &founding.public_key(),
            Some(&ProveTier(AttestationTier::VendorHw)),
        );
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Pass {
                    verified_count: 3,
                    ..
                }
            ),
            "a proven vendor_hw device should gain authority: {outcome:?}"
        );
    }

    #[test]
    fn c_vendor_hw_claim_a_reverifier_disproves_fails_closed() {
        // The forged-statement case: a reverifier that can only prove a LOWER tier
        // than claimed must NOT extend authority — the claim is not honored.
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled_tier(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &d2,
                AttestationTier::VendorHw,
                PresenceFactor::HardwareTouch,
                &founding,
            ),
            c_persona_created("evt-2", ("evt-1", 2), &d2),
        ];
        let outcome = verify_chain_with_reverifier(
            &events,
            &founding.public_key(),
            Some(&ProveTier(AttestationTier::None)), // proves None != claimed VendorHw
        );
        assert!(
            matches!(outcome, VerifyOutcome::Break { .. }),
            "a vendor_hw claim the reverifier disproves must fail closed: {outcome:?}"
        );
    }

    #[test]
    fn c_root_op_from_unenrolled_key_rejected() {
        // A root op signed by a key that was never enrolled must fail.
        let founding = FixtureSigner::new("founding");
        let stranger = FixtureSigner::new("stranger");
        let events = [
            c_root_created("evt-0", &founding),
            c_persona_created("evt-1", ("evt-0", 1), &stranger),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Break { .. }
            ),
            "an unenrolled key must not authorize a root op"
        );
    }

    #[test]
    fn c_revoked_presence_device_loses_authority() {
        // d2 is enrolled, then revoked; a root op signed by d2 AFTER revocation
        // must fail (authority removed mid-walk; historical validity preserved).
        let founding = FixtureSigner::new("founding");
        let d2 = FixtureSigner::new("backup-d2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &d2,
                CustodyClass::Presence,
                &founding,
            ),
            c_event(
                "evt-2",
                EventBody::DeviceRevoked(DeviceRevokedEvent {
                    root_id: "root-1".into(),
                    device_id: "d2".into(),
                    reason: "lost".into(),
                }),
                Some(("evt-1", 2)),
                &founding,
            ),
            c_persona_created("evt-3", ("evt-2", 3), &d2),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Break { .. }
            ),
            "a revoked device must lose root authority"
        );
    }

    #[test]
    fn c_daemon_class_device_is_not_root_authoritative() {
        // A daemon-class Device added under the root does NOT gain root
        // authority — only `presence` devices do.
        let founding = FixtureSigner::new("founding");
        let dd = FixtureSigner::new("daemon-dd");
        let events = [
            c_root_created("evt-0", &founding),
            c_event(
                "evt-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-1".into(),
                    device_id: "dd".into(),
                    label: "dd".into(),
                    initial_key: pk_mat(&dd, "k-dd"),
                    initial_encryption_key: PublicKeyMaterial {
                        key_id: "enc-dd".into(),
                        algorithm: KeyAlgorithm::AgeX25519,
                        public_key: "age1ddfixture".into(),
                    },
                }),
                Some(("evt-0", 1)),
                &founding,
            ),
            c_persona_created("evt-2", ("evt-1", 2), &dd),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Break { .. }
            ),
            "a daemon-class device must not be root-authoritative"
        );
    }

    #[test]
    fn c_reenrollment_drops_the_previous_key() {
        // Re-enrolling the same device_id with a new key must drop the OLD key's
        // authority — otherwise a later revoke (which names the device_id) would
        // remove only the new key and leave the old key trusted (incomplete
        // revocation). Regression for the double-enrollment key-leak.
        let founding = FixtureSigner::new("founding");
        let k1 = FixtureSigner::new("d2-k1");
        let k2 = FixtureSigner::new("d2-k2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &k1,
                CustodyClass::Presence,
                &founding,
            ),
            c_device_enrolled(
                "evt-2",
                ("evt-1", 2),
                "d2",
                &k2,
                CustodyClass::Presence,
                &founding,
            ),
            // Signed by the SUPERSEDED key k1.
            c_persona_created("evt-3", ("evt-2", 3), &k1),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Break { .. }
            ),
            "the superseded key of a re-enrolled device must lose authority"
        );
    }

    #[test]
    fn c_reenrollment_new_key_is_authoritative() {
        // The flip side: after re-enrollment the NEW key IS authoritative.
        let founding = FixtureSigner::new("founding");
        let k1 = FixtureSigner::new("d2-k1");
        let k2 = FixtureSigner::new("d2-k2");
        let events = [
            c_root_created("evt-0", &founding),
            c_device_enrolled(
                "evt-1",
                ("evt-0", 1),
                "d2",
                &k1,
                CustodyClass::Presence,
                &founding,
            ),
            c_device_enrolled(
                "evt-2",
                ("evt-1", 2),
                "d2",
                &k2,
                CustodyClass::Presence,
                &founding,
            ),
            c_persona_created("evt-3", ("evt-2", 3), &k2),
        ];
        assert!(
            matches!(
                verify_chain(&events, &founding.public_key()),
                VerifyOutcome::Pass {
                    verified_count: 4,
                    ..
                }
            ),
            "the current key of a re-enrolled device must be authoritative"
        );
    }

    #[test]
    fn verify_receipt_rejects_principal_cycle() {
        let anchor = FixtureSigner::new("anchor");
        let cycle_a = FixtureSigner::new("cycle-a");
        let cycle_b = FixtureSigner::new("cycle-b");

        let e0 = make_root_created("evt-0", "anchor-root", &anchor);
        let e1 = EventEnvelope::from_body(
            "evt-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "cycle-b".into(),
                persona_id: "cycle-a".into(),
                label: "Cycle A".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&cycle_a, "k-cycle-a"),
            }),
            vec![],
            SignerBinding::root("anchor-root", "anchor-root-initial"),
            &anchor,
        )
        .expect("cycle-a persona event");
        let e2 = EventEnvelope::from_body(
            "evt-2",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "cycle-a".into(),
                persona_id: "cycle-b".into(),
                label: "Cycle B".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&cycle_b, "k-cycle-b"),
            }),
            vec![],
            SignerBinding::root("anchor-root", "anchor-root-initial"),
            &anchor,
        )
        .expect("cycle-b persona event");
        let e3 = EventEnvelope::from_body(
            "evt-3",
            EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
                root_id: "cycle-b".into(),
                persona_id: "cycle-a".into(),
                previous_key_id: "k-cycle-a".into(),
                new_key: principal_key("cycle-a-next"),
            }),
            vec![EventRef::previous("evt-1", 1)],
            SignerBinding::principal("cycle-a", "k-cycle-a"),
            &cycle_a,
        )
        .expect("cycle-a signed event");

        let outcome = verify_chain(&[e0, e1, e2, e3], &anchor.public_key());
        assert!(
            matches!(outcome, VerifyOutcome::Break { .. }),
            "a signer Principal cycle must be rejected: {outcome:?}"
        );
    }

    #[test]
    fn verify_receipt_walks_principal_parent_chain() {
        let root = FixtureSigner::new("person-root");
        let operator = FixtureSigner::new("operator-role");
        let attacker = FixtureSigner::new("attacker-role");

        let e0 = make_root_created("evt-0", "person-root", &root);
        let e1 = EventEnvelope::from_body(
            "evt-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "person-root".into(),
                persona_id: "operator-role".into(),
                label: "Operator".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&operator, "operator-device"),
            }),
            vec![EventRef::previous("evt-0", 1)],
            SignerBinding::root("person-root", "person-root-initial"),
            &root,
        )
        .expect("operator principal");
        let body = EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
            root_id: "person-root".into(),
            persona_id: "operator-role".into(),
            previous_key_id: "operator-device".into(),
            new_key: principal_key("operator-next"),
        });
        let e2 = EventEnvelope::from_body(
            "evt-2",
            body.clone(),
            vec![EventRef::previous("evt-1", 2)],
            SignerBinding::principal("operator-role", "operator-device"),
            &operator,
        )
        .expect("operator signed event");

        let outcome = verify_chain(&[e0.clone(), e1.clone(), e2], &root.public_key());
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Pass {
                    verified_count: 3,
                    ..
                }
            ),
            "operator Principal child should verify through parent chain: {outcome:?}"
        );

        let forged = EventEnvelope::from_body(
            "evt-2",
            body,
            vec![EventRef::previous("evt-1", 2)],
            SignerBinding::principal("operator-role", "operator-device"),
            &attacker,
        )
        .expect("forged operator signed event");
        let outcome = verify_chain(&[e0, e1, forged], &root.public_key());
        assert!(
            matches!(outcome, VerifyOutcome::Break { .. }),
            "valid signature by the wrong key must not satisfy the operator Principal chain: {outcome:?}"
        );
    }

    #[test]
    fn daemon_and_operator_principal_chains_are_not_confusable() {
        let operator_root = FixtureSigner::new("operator-root");
        let daemon_root = FixtureSigner::new("daemon-root");
        let daemon_child = FixtureSigner::new("daemon-child");

        let e0 = make_root_created("evt-0", "operator-root", &operator_root);
        let e1 = EventEnvelope::from_body(
            "evt-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "daemon-root".into(),
                display_name: "Daemon".into(),
                initial_key: pk_mat(&daemon_root, "daemon-device"),
            }),
            vec![],
            SignerBinding::root("operator-root", "operator-root-initial"),
            &operator_root,
        )
        .expect("daemon root record");
        let e2 = EventEnvelope::from_body(
            "evt-2",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "daemon-root".into(),
                persona_id: "daemon-child".into(),
                label: "Daemon child".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&daemon_child, "daemon-child-device"),
            }),
            vec![EventRef::previous("evt-1", 1)],
            SignerBinding::principal("daemon-root", "daemon-device"),
            &daemon_root,
        )
        .expect("daemon-root signed event");

        let outcome = verify_chain(&[e0, e1, e2], &operator_root.public_key());
        match outcome {
            VerifyOutcome::Break { failures, .. } => assert!(
                failures.iter().any(|f| {
                    f.reason_class == VerifyReasonClass::PrincipalChainInvalid
                        && f.detail.contains("not the pinned trust anchor")
                }),
                "expected wrong-anchor Principal-chain failure: {failures:?}"
            ),
            other => panic!("daemon self-root must not verify as operator-rooted: {other:?}"),
        }
    }

    #[test]
    fn verify_receipt_rejects_missing_principal_parent() {
        let anchor = FixtureSigner::new("anchor");
        let orphan = FixtureSigner::new("orphan");

        let e0 = make_root_created("evt-0", "anchor-root", &anchor);
        let e1 = EventEnvelope::from_body(
            "evt-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "missing-parent".into(),
                persona_id: "orphan".into(),
                label: "Orphan".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: pk_mat(&orphan, "orphan-device"),
            }),
            vec![],
            SignerBinding::root("anchor-root", "anchor-root-initial"),
            &anchor,
        )
        .expect("orphan Principal record");
        let e2 = EventEnvelope::from_body(
            "evt-2",
            EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
                root_id: "missing-parent".into(),
                persona_id: "orphan".into(),
                previous_key_id: "orphan-device".into(),
                new_key: principal_key("orphan-next"),
            }),
            vec![EventRef::previous("evt-1", 1)],
            SignerBinding::principal("orphan", "orphan-device"),
            &orphan,
        )
        .expect("orphan signed event");

        let outcome = verify_chain(&[e0, e1, e2], &anchor.public_key());
        match outcome {
            VerifyOutcome::Break { failures, .. } => assert!(
                failures.iter().any(|f| {
                    f.reason_class == VerifyReasonClass::PrincipalChainInvalid
                        && f.detail.contains("missing Principal record")
                }),
                "expected missing-parent Principal-chain failure: {failures:?}"
            ),
            other => panic!("missing Principal parent must be rejected: {other:?}"),
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
