// Event authorization matrix — see module docs in this file for the
// per-event-kind decision logic.
use core_crypto::PublicKey;
use core_event_types::{CustodyClass, EventBody, KeyRole, SignerBinding, SubjectKind};
use core_events::EventEnvelope;
use core_principals::PublicKeyMaterial;
use core_types::ValidationError;

use crate::{
    DeviceStatus, GrantOfferStatus, MaterializedState, PersonaStatus, RecoveryRequestStatus,
    RootStatus,
};

pub trait Authorizer {
    /// Raw authorization: returns the precise error variant
    /// (NotFound / StateViolation / Unauthorized with specific detail).
    /// Internal callers (store append, materializer, test harness) call
    /// this directly so they can pattern-match on exact failure modes.
    fn authorize_raw(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError>;

    /// Public-facing authorization: state-leaking error variants are
    /// collapsed to a generic `unauthorized for the requested operation`.
    /// HTTP handlers, dashboard emitters, and any consumer that returns
    /// errors to untrusted clients should call this. Default implementation
    /// sanitizes; implementors only need `authorize_raw`.
    fn authorize(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        self.authorize_raw(event, state, now_epoch_secs)
            .map_err(sanitize_authorize_error)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAuthorizer;

impl Authorizer for AllowAllAuthorizer {
    fn authorize_raw(
        &self,
        _event: &EventEnvelope,
        _state: &MaterializedState,
        _now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityAuthorizer;

impl IdentityAuthorizer {
    fn authorize_inner(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        let signer_pk = &event.signer;
        // P79.1a I-1: audit-clarity cross-check — the signer_binding.signer
        // subject id should be coherent with the body's declared authority.
        // Not security-critical (the key material binding is the authority),
        // but a mismatch means auditors will be misled. Fail-closed so that
        // malformed audit trails never land.
        check_signer_subject_coherence(&event.signer_binding, &event.body)?;
        match &event.body {
            // RootCreated is self-asserting — nothing in state yet binds its
            // authority. Two structural guards apply (ADR 200 §2 / AC-1):
            //
            // 1. **Self-root invariant (signer == initial_key).** A Root genesis is
            //    accepted by an external `verify_chain` ONLY if the signing key IS
            //    the recorded founding `initial_key`. The append-time signature
            //    check alone binds signature↔signer, NOT signer↔initial_key, so
            //    without this guard the authority layer would accept a genesis
            //    whose materialized `active_key` names a key that never signed it —
            //    local state an independent verifier would reject. This is the
            //    structurally-complete home for the guard `operator_identity`'s
            //    `check_genesis_self_root` enforces at the daemon layer; binding it
            //    here makes the property hold for ALL genesis paths (daemon
            //    self-root, operator OOB, any in-process builder) by construction.
            //    (Named follow-up from the #5079 / #5082 adversarial reviews.)
            // 2. **Cross-root pubkey uniqueness.** A second RootCreated reusing an
            //    existing root's pubkey is rejected — it bounds the blast radius of
            //    key-material collisions. (Squatting on a fresh `root_id` with the
            //    signer's own key is still possible; recovery is out-of-band: the
            //    real operator picks a fresh root_id and proves custody through a
            //    side channel.)
            EventBody::RootCreated(body) => {
                if signer_pk.0 != body.initial_key.public_key {
                    return Err(ValidationError::unauthorized(
                        "root genesis signer key does not match the recorded initial_key \
                         (self-root invariant — an external verify_chain would reject)",
                    ));
                }
                for existing in state.roots_current.values() {
                    if existing.root_id != body.root_id
                        && existing.active_key.public_key == body.initial_key.public_key
                    {
                        return Err(ValidationError::unauthorized(format!(
                            "root initial key material collides with existing root {}",
                            existing.root_id
                        )));
                    }
                }
                Ok(())
            }
            EventBody::RootKeyRotated(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::RootRevoked(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::DeviceAdded(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::DeviceEnrolled(body) => {
                // Enrollment binds a presence/co-authority Device to the
                // operator's root; the root signs it (ADR 200 §5). The
                // attestation chain is verified at enroll-time in the daemon.
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::PersonaCreated(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::DeviceKeyRotated(body) => {
                // P79.1a M-5: event body carries root_id; require it to match
                // the device's stored root_id to prevent audit-trail lies.
                require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::DeviceEncryptionKeyRotated(body) => {
                // P79.1a M-5: mirror DeviceKeyRotated — body.root_id must match
                // the device's stored root_id.
                require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::DeviceRevoked(body) => {
                if authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
                    .is_ok()
                {
                    require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::DeviceFrozen(body) => {
                if authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
                    .is_ok()
                {
                    require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::DeviceReplaced(body) => {
                // Cross-root ownership check: authorize the signing root first, then require that
                // BOTH the replaced and replacement devices are owned by that root.
                // Without the ownership checks, root-A could flip device-B (owned
                // by root-B) into Replaced status, setting its replacement to any
                // attacker-controlled device id — a cross-root state-corruption
                // / denial-of-service vector.
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)?;
                require_device_owned_by_root(&body.replaced_device_id, &body.root_id, state)?;
                require_device_owned_by_root(&body.replacement_device_id, &body.root_id, state)?;
                Ok(())
            }
            EventBody::PersonaKeyRotated(body) => {
                authorize_persona_key(&event.signer_binding, signer_pk, &body.persona_id, state)
            }
            EventBody::PersonaRevoked(body) => {
                if authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
                    .is_ok()
                {
                    require_persona_owned_by_root(&body.persona_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_persona_key(&event.signer_binding, signer_pk, &body.persona_id, state)
            }
            EventBody::TrustAttested(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.attester_persona_id,
                state,
            ),
            EventBody::TrustRevoked(body) => {
                authorize_persona_key(
                    &event.signer_binding,
                    signer_pk,
                    &body.attester_persona_id,
                    state,
                )?;
                // P79.1a L-2: when the attestation is not present in local
                // state (cross-device delivery is legitimate), we accept the
                // revocation — materialize.rs no-ops on the missing edge.
                // This leaves a DoS surface for peers spamming revocations
                // against non-existent edges. The cost of each such event is
                // bounded by the attacker expending a valid persona signature
                // (authorize_persona_key already required an active persona),
                // so the attacker must either be on-graph themselves or hold
                // a compromised persona key. Rate-limiting / unmatched-revoke
                // bounding is deferred to the sync/accept layer — this crate
                // intentionally does not add a logger dependency.
                if let Some(existing) = state.trust_edges_current.get(&body.attestation_id)
                    && existing.attester != body.attester_persona_id
                {
                    return Err(ValidationError::unauthorized(
                        "trust revocation signer does not match original attester",
                    ));
                }
                Ok(())
            }
            EventBody::RecoveryPolicyCreated(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::RecoveryRequested(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::GuardianEnrolled(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::GuardianKeyRotated(body) => {
                // Root can rotate a guardian's key (same authority as enrollment).
                // Guardian can also rotate their own key using their current key.
                if authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
                    .is_ok()
                {
                    return Ok(());
                }
                authorize_enrolled_guardian(
                    &event.signer_binding,
                    signer_pk,
                    &body.guardian_id,
                    &body.root_id,
                    state,
                )
            }
            EventBody::RecoveryApproved(body) => {
                if event.signer_binding.role != KeyRole::Guardian {
                    return Err(ValidationError::unauthorized(
                        "recovery approvals must be signed by a guardian role",
                    ));
                }
                let request = state
                    .recovery_requests_current
                    .get(&body.request_id)
                    .ok_or_else(|| {
                        ValidationError::not_found("recovery request", &body.request_id)
                    })?;
                authorize_enrolled_guardian(
                    &event.signer_binding,
                    signer_pk,
                    &body.guardian_id,
                    &request.root_id,
                    state,
                )
            }
            EventBody::RecoveryContested(body) => {
                if event.signer_binding.role != KeyRole::Guardian {
                    return Err(ValidationError::unauthorized(
                        "recovery contests must be signed by a guardian role",
                    ));
                }
                let request = state
                    .recovery_requests_current
                    .get(&body.request_id)
                    .ok_or_else(|| {
                        ValidationError::not_found("recovery request", &body.request_id)
                    })?;
                authorize_enrolled_guardian(
                    &event.signer_binding,
                    signer_pk,
                    &body.guardian_id,
                    &request.root_id,
                    state,
                )
            }
            EventBody::RecoveryRejected(body) => {
                let request = state
                    .recovery_requests_current
                    .get(&body.request_id)
                    .ok_or_else(|| {
                        ValidationError::not_found("recovery request", &body.request_id)
                    })?;
                authorize_root_key(&event.signer_binding, signer_pk, &request.root_id, state)
            }
            EventBody::RecoveryExecuted(body) => {
                let request = state
                    .recovery_requests_current
                    .get(&body.request_id)
                    .ok_or_else(|| {
                        ValidationError::not_found("recovery request", &body.request_id)
                    })?;
                // P79.1a I-2: cooldown is a "must be at/after" check; uses the
                // shared check_time_window helper.
                check_time_window(
                    now_epoch_secs,
                    request.cooldown_until,
                    None,
                    "recovery request is in cooldown after contest",
                    "recovery request cannot have a past-dated window",
                )?;
                if request.status != RecoveryRequestStatus::Approved {
                    return Err(ValidationError::state_violation(
                        "recovery request must be approved before execution",
                    ));
                }
                authorize_root_key(&event.signer_binding, signer_pk, &request.root_id, state)
            }
            EventBody::RelayHintUpdated(body) => {
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::EndpointRotated(body) => {
                authorize_device_key(&event.signer_binding, signer_pk, &body.device_id, state)
            }
            EventBody::RelayShutdownNotice(body) => {
                // P79.1a M-3: shutdown notices are relay-operator actions, but
                // when the claimed `relay_peer_id` is a known endpoint in local
                // state we require the signer to be the device backing that
                // endpoint. If the relay is not yet in endpoints_current we
                // pass through — the consumer layer (UI, daemon hints) must
                // still treat unknown-relay notices as untrusted and only act
                // on notices whose peer is in the trust graph.
                if let Some(endpoint) = state.endpoints_current.get(&body.relay_peer_id) {
                    let device = state
                        .devices_current
                        .get(&endpoint.device_id)
                        .ok_or_else(|| ValidationError::not_found("device", &endpoint.device_id))?;
                    if device.active_key.key_id != event.signer_binding.key_id
                        || device.active_key.public_key != signer_pk.0
                    {
                        return Err(ValidationError::unauthorized(format!(
                            "relay shutdown notice signer does not match endpoint device for {}",
                            body.relay_peer_id
                        )));
                    }
                }
                Ok(())
            }
            EventBody::StorageRelationshipCreated(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::StorageLedgerUpdated(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::StorageManifestPublished(body) => {
                authorize_root_key(&event.signer_binding, signer_pk, &body.root_id, state)
            }
            EventBody::MessageSent(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.sender_persona_id,
                state,
            ),
            EventBody::ContentPublished(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.author_persona_id,
                state,
            ),
            EventBody::DisclosureRevoked(body) => {
                authorize_persona_key(
                    &event.signer_binding,
                    signer_pk,
                    &body.revoker_persona_id,
                    state,
                )?;
                // P79.1a L-3: defense-in-depth cross-check — the revoker must
                // be the original disclosure issuer. When the disclosure is in
                // local state, require `signer == original_issuer`. If the
                // artifact is not present in `disclosures_current` (cross-device
                // delivery where the receiver has not yet materialized the
                // issuance event), we pass through — the issuer-side replay will
                // catch violations, analogous to the GrantOfferRevoked and
                // BadgeRevoked pass-through for unknown artifacts.
                if let Some(disclosure) = state.disclosures_current.get(&body.artifact_id)
                    && disclosure.issuer_persona_id != body.revoker_persona_id
                {
                    return Err(ValidationError::unauthorized(
                        "only the original issuer can revoke this disclosure",
                    ));
                }
                Ok(())
            }
            EventBody::GrantOfferCreated(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.issuer_persona_id,
                state,
            ),
            EventBody::GrantOfferClaimed(body) => {
                authorize_persona_key(
                    &event.signer_binding,
                    signer_pk,
                    &body.recipient_persona_id,
                    state,
                )?;
                // C-1: When the offer is known locally, verify it is still Pending and
                // has not expired. If it is not in local state (cross-device claim path
                // where claimant's store does not hold the issuer's GrantOfferCreated
                // event), we pass through — the issuer-side replay will catch violations.
                if let Some(offer) = state.grant_offers_current.get(&body.offer_id) {
                    if offer.status != GrantOfferStatus::Pending {
                        return Err(ValidationError::state_violation(
                            "grant offer is not in Pending status",
                        ));
                    }
                    // P79.1a I-2: expiry is a "must be strictly before"
                    // check; uses the shared check_time_window helper.
                    check_time_window(
                        now_epoch_secs,
                        None,
                        Some(offer.expires_at),
                        "grant offer cannot have a future-only earliest window",
                        "grant offer has expired",
                    )?;
                }
                Ok(())
            }
            EventBody::GrantOfferRevoked(body) => {
                authorize_persona_key(
                    &event.signer_binding,
                    signer_pk,
                    &body.issuer_persona_id,
                    state,
                )?;
                // C-2: Verify the revoking persona is actually the offer's issuer.
                if let Some(offer) = state.grant_offers_current.get(&body.offer_id)
                    && offer.issuer_persona_id != body.issuer_persona_id
                {
                    return Err(ValidationError::unauthorized(
                        "grant offer revocation signer does not match original issuer",
                    ));
                }
                Ok(())
            }
            EventBody::BadgeIssued(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.issuer_persona_id,
                state,
            ),
            EventBody::BadgeRevoked(body) => {
                authorize_persona_key(
                    &event.signer_binding,
                    signer_pk,
                    &body.revoker_persona_id,
                    state,
                )?;
                // C-3: Verify the revoking persona is actually the badge's issuer.
                if let Some(badge) = state.badges_current.get(&body.badge_id)
                    && badge.issuer_persona_id != body.revoker_persona_id
                {
                    return Err(ValidationError::unauthorized(
                        "badge revocation signer does not match original issuer",
                    ));
                }
                Ok(())
            }
            EventBody::BadgeDisputed(body) => authorize_persona_key(
                &event.signer_binding,
                signer_pk,
                &body.disputer_persona_id,
                state,
            ),
            EventBody::CredentialDeposited(body) => {
                authorize_persona_key(&event.signer_binding, signer_pk, &body.issuer_id, state)
            }
            EventBody::CredentialRevoked(body) => {
                authorize_persona_key(&event.signer_binding, signer_pk, &body.revoker_id, state)?;
                // Verify a deposit exists for this grant and the revoker is the original issuer.
                // Multi-deposit issuer check: require ALL deposits sharing this grant_id to have been
                // issued by the revoker. If grant_id uniqueness drifts (current schema
                // does not enforce uniqueness at the grant_id level), a single owned
                // deposit would otherwise let the revoker revoke other issuers' deposits
                // under the same grant_id.
                let mut found_any = false;
                for deposit in state.credential_deposits_current.values() {
                    if deposit.grant_id == body.grant_id {
                        found_any = true;
                        if deposit.issuer_id != body.revoker_id {
                            return Err(ValidationError::unauthorized(
                                "credential revocation signer does not match original issuer",
                            ));
                        }
                    }
                }
                if !found_any {
                    return Err(ValidationError::unauthorized(
                        "no credential deposit found for grant",
                    ));
                }
                Ok(())
            }
        }
    }
}

impl Authorizer for IdentityAuthorizer {
    fn authorize_raw(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        self.authorize_inner(event, state, now_epoch_secs)
    }
    // `authorize` inherits the trait default, which wraps `authorize_raw`
    // with `sanitize_authorize_error` for public-facing error surfaces.
}

/// True iff `signer_binding.key_id` AND `signer_public_key` both match `key` —
/// the same two-part binding (key-id string + pubkey material) the root/device
/// authorization has always required. Both halves are checked so a forged
/// `key_id` against someone else's pubkey (or vice versa) cannot pass.
fn key_material_matches(
    key: &PublicKeyMaterial,
    signer_binding: &SignerBinding,
    signer_public_key: &PublicKey,
) -> bool {
    key.key_id == signer_binding.key_id && key.public_key == signer_public_key.0
}

/// Authorize a root-level operation (ADR 200 §2/§5 — **Model C**, root authority
/// is a *set of devices*, not a single key).
///
/// A root-level event is authorized when its signer is **either**:
/// - the root's founding `active_key` (the genesis / current root key); **or**
/// - any **active `presence`-class Device** enrolled under the root.
///
/// This is the device-set generalization of the original single-root-key rule:
/// the daemon root is the N=1 case (its sole authority is its `active_key` —
/// the daemon-Device), the operator root is N≥2 (first + backup YubiKeys), so a
/// lost key is recoverable from any surviving presence Device without the daemon
/// ever holding an operator key. `co-authority`-class devices are deliberately
/// NOT root-authoritative here (that is a team0+ lane with its own policy).
///
/// **Recovery↔takeover duality (intended, not a bug).** Every root-level op —
/// including `RootKeyRotated`, `RootRevoked`, and revoking a *sibling* Device —
/// is admitted from any active presence Device. This is *required* for C's core
/// guarantee: recovering from a lost/compromised founding key means a surviving
/// Device must be able to rotate it away and revoke it. The same capability lets
/// a single compromised presence Device take over the root — the irreducible
/// cost of 1-of-N. At dev0 the operator physically holds both their own keys
/// (each tap is a per-use presence proof), so this is accepted; the multi-human
/// threat is addressed at team0+ by the M-of-N guardian threshold (ADR 200 §6),
/// NOT by carving root-mutation ops out here (which would re-break recovery).
fn authorize_root_key(
    signer_binding: &SignerBinding,
    signer_public_key: &PublicKey,
    root_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let root = state
        .roots_current
        .get(root_id)
        .ok_or_else(|| ValidationError::not_found("root", root_id))?;
    if root.status != RootStatus::Active {
        return Err(ValidationError::state_violation(format!(
            "root {} is revoked",
            root_id
        )));
    }

    // Branch 1: the root's own founding key (covers the daemon root, N=1, and
    // every existing single-key root — unchanged behavior).
    if key_material_matches(&root.active_key, signer_binding, signer_public_key) {
        return Ok(());
    }

    // Branch 2 (Model C): an active presence-class Device enrolled under this
    // root. Membership requires BOTH key-id and pubkey-material match against a
    // device whose recorded custody class is `presence` (attestation-proven at
    // enroll time) and whose status is Active (revoked/frozen devices cannot
    // authorize).
    let is_active_presence_device = state.devices_current.values().any(|device| {
        device.root_id == root_id
            && device.status == DeviceStatus::Active
            && device.custody_class == CustodyClass::Presence
            && key_material_matches(&device.active_key, signer_binding, signer_public_key)
    });
    if is_active_presence_device {
        return Ok(());
    }

    Err(ValidationError::unauthorized(format!(
        "signer {} is neither the root key nor an active presence Device for root {}",
        signer_binding.key_id, root_id
    )))
}

fn authorize_device_key(
    signer_binding: &SignerBinding,
    signer_public_key: &PublicKey,
    device_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let device = state
        .devices_current
        .get(device_id)
        .ok_or_else(|| ValidationError::not_found("device", device_id))?;
    if device.active_key.key_id != signer_binding.key_id {
        return Err(ValidationError::unauthorized(format!(
            "signer key {} does not match active device key for {}",
            signer_binding.key_id, device_id
        )));
    }
    // Signer-pubkey binding: bind signer pubkey material to stored active device key.
    if device.active_key.public_key != signer_public_key.0 {
        return Err(ValidationError::unauthorized(format!(
            "signer public key does not match active device key material for {}",
            device_id
        )));
    }
    if device.status != DeviceStatus::Active {
        return Err(ValidationError::state_violation(format!(
            "device {} is not active",
            device_id
        )));
    }
    Ok(())
}

fn require_device_owned_by_root(
    device_id: &str,
    root_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let device = state
        .devices_current
        .get(device_id)
        .ok_or_else(|| ValidationError::not_found("device", device_id))?;
    if device.root_id != root_id {
        return Err(ValidationError::unauthorized(format!(
            "device {device_id} belongs to root {}, not {root_id}",
            device.root_id
        )));
    }
    Ok(())
}

fn require_persona_owned_by_root(
    persona_id: &str,
    root_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let persona = state
        .personas_current
        .get(persona_id)
        .ok_or_else(|| ValidationError::not_found("persona", persona_id))?;
    if persona.root_id != root_id {
        return Err(ValidationError::unauthorized(format!(
            "persona {persona_id} belongs to root {}, not {root_id}",
            persona.root_id
        )));
    }
    Ok(())
}

fn authorize_enrolled_guardian(
    signer_binding: &SignerBinding,
    signer_public_key: &PublicKey,
    guardian_id: &str,
    root_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let guardian = state
        .guardians_current
        .get(guardian_id)
        .ok_or_else(|| ValidationError::not_found("guardian", guardian_id))?;
    if guardian.root_id != root_id {
        return Err(ValidationError::unauthorized(format!(
            "guardian {guardian_id} is enrolled for root {}, not {root_id}",
            guardian.root_id
        )));
    }
    if signer_binding.key_id != guardian.public_key {
        return Err(ValidationError::unauthorized(format!(
            "signer key {} does not match enrolled guardian key for {guardian_id}",
            signer_binding.key_id
        )));
    }
    // Signer-pubkey binding: bind signer pubkey material to the enrolled guardian key.
    // For guardians the enrolled identifier is the public key itself, so
    // `signer_public_key.0` must equal `guardian.public_key` for the signature
    // to represent the enrolled guardian (not just a peer echoing the key id).
    if signer_public_key.0 != guardian.public_key {
        return Err(ValidationError::unauthorized(format!(
            "signer public key does not match enrolled guardian key material for {guardian_id}"
        )));
    }
    Ok(())
}

fn authorize_persona_key(
    signer_binding: &SignerBinding,
    signer_public_key: &PublicKey,
    persona_id: &str,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    let persona = state
        .personas_current
        .get(persona_id)
        .ok_or_else(|| ValidationError::not_found("persona", persona_id))?;
    if persona.active_key.key_id != signer_binding.key_id {
        return Err(ValidationError::unauthorized(format!(
            "signer key {} does not match active persona key for {}",
            signer_binding.key_id, persona_id
        )));
    }
    // Signer-pubkey binding: bind signer pubkey material to stored active persona key.
    if persona.active_key.public_key != signer_public_key.0 {
        return Err(ValidationError::unauthorized(format!(
            "signer public key does not match active persona key material for {}",
            persona_id
        )));
    }
    if persona.status != PersonaStatus::Active {
        return Err(ValidationError::state_violation(format!(
            "persona {} is not active",
            persona_id
        )));
    }
    Ok(())
}

/// Read-only predicate: is `public_key` the active signing key of an **Active
/// persona** rooted under an **Active** `root_id`?
///
/// This is the stable read interface the broker capability lane (BKR-4
/// grant-chain-walk) consumes to confirm that the persona which signed a
/// delegation block is still a live, root-anchored principal — *without*
/// touching the Model-C `verify_chain` (that is the identity lane's surface;
/// BKR walks the grant chain only). It composes the same `personas_current`
/// active-key + root-ownership + status checks `authorize_persona_key` /
/// `authorize_root_key` enforce, but as a boolean query rather than an
/// event-authorization decision.
///
/// **Match semantics.** Keyed on the public-key *material* (`PublicKeyMaterial.
/// public_key`, the cryptographic identity), not on the `key_id` label: a grant
/// block carries the signer's pubkey, not the enrolling persona's `key_id`, and
/// a pubkey is 1:1 with a persona's active key, so the pubkey alone is the
/// sound membership test. (Contrast `authorize_persona_key`, which binds *both*
/// halves because it is validating a presented signature, not testing set
/// membership.)
///
/// **Root status is load-bearing.** A persona under a *revoked* root is NOT
/// active here even if its own `status` is still `Active` — a revoked root has
/// no authority to delegate, so its personas must not read as valid. Returns
/// `false` for an unknown/revoked root, an unknown/revoked persona, or a pubkey
/// that is not any persona's active key under the root. Never panics; fail-closed.
pub fn is_active_persona_key_under_root(
    state: &MaterializedState,
    root_id: &str,
    public_key: &str,
) -> bool {
    // The root itself must be Active — a revoked root's personas carry no authority.
    let root_active = state
        .roots_current
        .get(root_id)
        .is_some_and(|r| r.status == RootStatus::Active);
    if !root_active {
        return false;
    }
    state.personas_current.values().any(|persona| {
        persona.root_id == root_id
            && persona.status == PersonaStatus::Active
            && persona.active_key.public_key == public_key
    })
}

/// P79.1a L-1: transform an internal authorize error into a public-facing
/// error message that does not echo subject-existence / freeze / key-mismatch
/// state to the caller. Internal callers continue to receive the detailed
/// messages (useful for daemon logs and test assertions), but any surface
/// that exposes authorize errors to an untrusted peer (e.g., future
/// relay-discovery responses) should run them through this sanitizer first.
///
/// Subject kind + programmatic error kind are preserved so callers can still
/// distinguish an Unauthorized decision from a StateViolation without
/// learning whether the subject exists or what its current status is.
pub fn sanitize_authorize_error(err: ValidationError) -> ValidationError {
    use core_types::ValidationErrorKind;
    let kind = err.kind;
    let generic = match kind {
        ValidationErrorKind::NotFound
        | ValidationErrorKind::Unauthorized
        | ValidationErrorKind::StateViolation => "unauthorized for the requested operation",
        _ => return err,
    };
    ValidationError {
        kind: ValidationErrorKind::Unauthorized,
        message: generic.to_string(),
    }
}

/// P79.1a I-2: shared time-window helper for branches that gate on a
/// caller-supplied `now` against an optional start (`not_before`) and/or
/// optional end (`not_after`) epoch. Returns the corresponding error
/// messages when the window is violated.
///
/// Semantics:
/// * `not_before.is_some()` → require `now >= not_before`, else
///   `before_msg` (StateViolation) — used for cooldown gates.
/// * `not_after.is_some()`  → require `now < not_after`, else
///   `after_msg` (StateViolation) — used for expiry gates.
fn check_time_window(
    now_epoch_secs: u64,
    not_before: Option<u64>,
    not_after: Option<u64>,
    before_msg: &'static str,
    after_msg: &'static str,
) -> Result<(), ValidationError> {
    if let Some(start) = not_before
        && now_epoch_secs < start
    {
        return Err(ValidationError::state_violation(before_msg));
    }
    if let Some(end) = not_after
        && now_epoch_secs >= end
    {
        return Err(ValidationError::state_violation(after_msg));
    }
    Ok(())
}

/// P79.1a I-1: audit-clarity cross-check — the signer subject referenced in
/// `signer_binding.signer.subject_id` should be coherent with the authority
/// that the event body implies. A mismatch is not a security vulnerability
/// (the signer's pubkey material + body subject together define the
/// authority), but an incoherent audit trail is confusing for auditors and
/// hides downstream bugs. We fail-closed so that malformed envelopes never
/// land in the log.
///
/// Coherence rules (non-exhaustive — only the clearly derivable authority
/// subject is checked; events whose body does not single out one subject
/// pass through):
/// * RootCreated / RootKeyRotated / RootRevoked / RecoveryPolicyCreated /
///   RecoveryRequested / GuardianEnrolled / DeviceAdded / PersonaCreated /
///   DeviceReplaced / Storage*: signer is the root principal →
///   `signer.subject_id == body.root_id`.
/// * DeviceKeyRotated / DeviceEncryptionKeyRotated / DeviceRevoked /
///   DeviceFrozen / RelayHintUpdated / EndpointRotated: signer is a device
///   → `signer.subject_id == body.device_id`.
/// * TrustAttested / TrustRevoked / MessageSent / ContentPublished /
///   DisclosureRevoked / GrantOffer* / BadgeIssued / BadgeRevoked /
///   BadgeDisputed / CredentialDeposited / CredentialRevoked: signer is the
///   persona principal → `signer.subject_id == body.<the relevant persona id>`.
///
/// RecoveryApproved / RecoveryContested / RecoveryRejected / RecoveryExecuted
/// use the request's root_id; we allow any subject kind on those branches
/// and defer to the body-specific checks. Same for RelayShutdownNotice (the
/// signer may be any device backing the endpoint).
fn signer_is_root_principal(binding: &SignerBinding, expected_id: &str) -> bool {
    matches!(
        binding.signer.kind,
        SubjectKind::Principal | SubjectKind::Root
    ) && binding.signer.subject_id == expected_id
}

fn signer_is_persona_principal(binding: &SignerBinding, expected_id: &str) -> bool {
    matches!(
        binding.signer.kind,
        SubjectKind::Principal | SubjectKind::Persona
    ) && binding.signer.subject_id == expected_id
}

fn check_signer_subject_coherence(
    binding: &SignerBinding,
    body: &EventBody,
) -> Result<(), ValidationError> {
    let mismatch = |expected_kind: SubjectKind, expected_id: &str| {
        ValidationError::new(format!(
            "signer subject {}:{} does not match body authority {}:{}",
            binding.signer.kind.as_str(),
            binding.signer.subject_id,
            expected_kind.as_str(),
            expected_id,
        ))
    };
    match body {
        EventBody::RootCreated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::RootKeyRotated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::RootRevoked(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::DeviceAdded(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::DeviceEnrolled(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::PersonaCreated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::RecoveryPolicyCreated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::RecoveryRequested(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::GuardianEnrolled(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::DeviceReplaced(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::StorageRelationshipCreated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::StorageLedgerUpdated(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        EventBody::StorageManifestPublished(b) => {
            if !signer_is_root_principal(binding, &b.root_id) {
                return Err(mismatch(SubjectKind::Principal, &b.root_id));
            }
        }
        // Events where the signer is a persona principal: the binding subject
        // must be the relevant persona id from the body.
        EventBody::TrustAttested(b) => {
            if !signer_is_persona_principal(binding, &b.attester_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.attester_persona_id));
            }
        }
        EventBody::TrustRevoked(b) => {
            if !signer_is_persona_principal(binding, &b.attester_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.attester_persona_id));
            }
        }
        EventBody::MessageSent(b) => {
            if !signer_is_persona_principal(binding, &b.sender_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.sender_persona_id));
            }
        }
        EventBody::ContentPublished(b) => {
            if !signer_is_persona_principal(binding, &b.author_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.author_persona_id));
            }
        }
        EventBody::DisclosureRevoked(b) => {
            if !signer_is_persona_principal(binding, &b.revoker_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.revoker_persona_id));
            }
        }
        EventBody::GrantOfferCreated(b) => {
            if !signer_is_persona_principal(binding, &b.issuer_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.issuer_persona_id));
            }
        }
        EventBody::GrantOfferClaimed(b) => {
            if !signer_is_persona_principal(binding, &b.recipient_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.recipient_persona_id));
            }
        }
        EventBody::GrantOfferRevoked(b) => {
            if !signer_is_persona_principal(binding, &b.issuer_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.issuer_persona_id));
            }
        }
        EventBody::BadgeIssued(b) => {
            if !signer_is_persona_principal(binding, &b.issuer_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.issuer_persona_id));
            }
        }
        EventBody::BadgeRevoked(b) => {
            if !signer_is_persona_principal(binding, &b.revoker_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.revoker_persona_id));
            }
        }
        EventBody::BadgeDisputed(b) => {
            if !signer_is_persona_principal(binding, &b.disputer_persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.disputer_persona_id));
            }
        }
        EventBody::CredentialDeposited(b) => {
            if !signer_is_persona_principal(binding, &b.issuer_id) {
                return Err(mismatch(SubjectKind::Principal, &b.issuer_id));
            }
        }
        EventBody::CredentialRevoked(b) => {
            if !signer_is_persona_principal(binding, &b.revoker_id) {
                return Err(mismatch(SubjectKind::Principal, &b.revoker_id));
            }
        }
        // Device-as-signer events: the binding subject must be the
        // relevant device id.
        EventBody::DeviceKeyRotated(b) => {
            if binding.signer.kind != SubjectKind::Device
                || binding.signer.subject_id != b.device_id
            {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        EventBody::DeviceEncryptionKeyRotated(b) => {
            if binding.signer.kind != SubjectKind::Device
                || binding.signer.subject_id != b.device_id
            {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        EventBody::RelayHintUpdated(b) => {
            if binding.signer.kind != SubjectKind::Device
                || binding.signer.subject_id != b.device_id
            {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        EventBody::EndpointRotated(b) => {
            if binding.signer.kind != SubjectKind::Device
                || binding.signer.subject_id != b.device_id
            {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        // Device-revoke / freeze / persona-revoke may be signed by either the
        // root OR the subject device/persona — we accept either and let the
        // per-branch authorize check enforce the rest.
        EventBody::DeviceRevoked(b) => {
            let matches_root = signer_is_root_principal(binding, &b.root_id);
            let matches_device = binding.signer.kind == SubjectKind::Device
                && binding.signer.subject_id == b.device_id;
            if !matches_root && !matches_device {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        EventBody::DeviceFrozen(b) => {
            let matches_root = signer_is_root_principal(binding, &b.root_id);
            let matches_device = binding.signer.kind == SubjectKind::Device
                && binding.signer.subject_id == b.device_id;
            if !matches_root && !matches_device {
                return Err(mismatch(SubjectKind::Device, &b.device_id));
            }
        }
        EventBody::PersonaRevoked(b) => {
            let matches_root = signer_is_root_principal(binding, &b.root_id);
            let matches_persona = signer_is_persona_principal(binding, &b.persona_id);
            if !matches_root && !matches_persona {
                return Err(mismatch(SubjectKind::Principal, &b.persona_id));
            }
        }
        EventBody::PersonaKeyRotated(b) => {
            if !signer_is_persona_principal(binding, &b.persona_id) {
                return Err(mismatch(SubjectKind::Principal, &b.persona_id));
            }
        }
        // GuardianKeyRotated: root OR guardian may sign; skip subject binding
        // check — the per-branch authorize is the authority.
        EventBody::GuardianKeyRotated(_) => {}
        // Recovery lifecycle events whose subject authority depends on the
        // request state — skipped here and enforced by the per-branch code.
        EventBody::RecoveryApproved(_)
        | EventBody::RecoveryContested(_)
        | EventBody::RecoveryRejected(_)
        | EventBody::RecoveryExecuted(_) => {}
        // RelayShutdownNotice: signer is the relay device — per-branch
        // enforcement already checks the endpoint binding.
        EventBody::RelayShutdownNotice(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{DOMAIN_EVENT, FixtureSigner, Signer as _};
    use core_event_types::{
        AttestationTier, CustodyClass, DeviceAddedEvent, DeviceFrozenEvent, DeviceRevokedEvent,
        EventBody, MessageSentEvent, PersonaCreatedEvent, PersonaRevokedEvent, PresenceFactor,
        RootCreatedEvent, RootKeyRotatedEvent, SignerBinding,
    };
    use core_events::EventEnvelope;
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};

    use crate::{DeviceRecord, PersonaRecord, RootRecord};

    fn make_key(key_id: &str) -> PublicKeyMaterial {
        // Signer-pubkey binding: derive the stored public_key from the FixtureSigner that
        // events are signed with — authorize now binds signer.public_key material
        // to the record's active_key.public_key, so the strings must match.
        let signer = FixtureSigner::new(key_id);
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: signer.public_key().0,
        }
    }

    fn make_enc_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    fn make_event(event_id: &str, body: EventBody, signer_binding: SignerBinding) -> EventEnvelope {
        let signer = FixtureSigner::new(signer_binding.key_id.clone());
        EventEnvelope::from_body(event_id, body, vec![], signer_binding, &signer).unwrap()
    }

    /// Two-root state: root-a owns device-a and persona-a, root-b owns device-b and persona-b.
    fn two_root_state() -> MaterializedState {
        let mut state = MaterializedState::default();
        state.roots_current.insert(
            "root-a".into(),
            RootRecord {
                root_id: "root-a".into(),
                display_name: "Root A".into(),
                active_key: make_key("key-root-a"),
                status: RootStatus::Active,
            },
        );
        state.roots_current.insert(
            "root-b".into(),
            RootRecord {
                root_id: "root-b".into(),
                display_name: "Root B".into(),
                active_key: make_key("key-root-b"),
                status: RootStatus::Active,
            },
        );
        state.devices_current.insert(
            "device-a".into(),
            DeviceRecord {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Device A".into(),
                active_key: make_key("key-device-a"),
                active_encryption_key: make_enc_key("device-a"),
                status: DeviceStatus::Active,
                replacement_device_id: None,
                custody_class: CustodyClass::Daemon,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::Unattended,
            },
        );
        state.devices_current.insert(
            "device-b".into(),
            DeviceRecord {
                root_id: "root-b".into(),
                device_id: "device-b".into(),
                label: "Device B".into(),
                active_key: make_key("key-device-b"),
                active_encryption_key: make_enc_key("device-b"),
                status: DeviceStatus::Active,
                replacement_device_id: None,
                custody_class: CustodyClass::Daemon,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::Unattended,
            },
        );
        state.personas_current.insert(
            "persona-a".into(),
            PersonaRecord {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Persona A".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                active_key: make_key("key-persona-a"),
                status: PersonaStatus::Active,
            },
        );
        state.personas_current.insert(
            "persona-b".into(),
            PersonaRecord {
                root_id: "root-b".into(),
                persona_id: "persona-b".into(),
                label: "Persona B".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                active_key: make_key("key-persona-b"),
                status: PersonaStatus::Active,
            },
        );
        state
    }

    // ── is_active_persona_key_under_root (BKR-4 read interface) ──

    #[test]
    fn active_persona_key_under_its_own_root_is_true() {
        let state = two_root_state();
        let key = make_key("key-persona-a").public_key;
        assert!(is_active_persona_key_under_root(&state, "root-a", &key));
    }

    #[test]
    fn persona_key_under_a_different_root_is_false() {
        // persona-a's key is NOT a persona key under root-b (no cross-root leak).
        let state = two_root_state();
        let key = make_key("key-persona-a").public_key;
        assert!(!is_active_persona_key_under_root(&state, "root-b", &key));
    }

    #[test]
    fn revoked_persona_key_is_false() {
        let mut state = two_root_state();
        state.personas_current.get_mut("persona-a").unwrap().status = PersonaStatus::Revoked;
        let key = make_key("key-persona-a").public_key;
        assert!(!is_active_persona_key_under_root(&state, "root-a", &key));
    }

    #[test]
    fn persona_under_revoked_root_is_false() {
        // Root status is load-bearing: a revoked root's still-Active persona
        // carries no authority and must not read as valid.
        let mut state = two_root_state();
        state.roots_current.get_mut("root-a").unwrap().status = RootStatus::Revoked;
        let key = make_key("key-persona-a").public_key;
        assert!(
            !is_active_persona_key_under_root(&state, "root-a", &key),
            "a persona under a revoked root must not read as active"
        );
    }

    #[test]
    fn unknown_root_and_unknown_key_are_false() {
        let state = two_root_state();
        let key = make_key("key-persona-a").public_key;
        assert!(!is_active_persona_key_under_root(&state, "root-zzz", &key));
        assert!(!is_active_persona_key_under_root(
            &state,
            "root-a",
            "not-a-real-pubkey"
        ));
    }

    #[test]
    fn root_key_and_device_key_are_not_persona_keys() {
        // The predicate is persona-scoped: a root key or a device key under the
        // root is NOT an active persona key.
        let state = two_root_state();
        let root_key = make_key("key-root-a").public_key;
        let device_key = make_key("key-device-a").public_key;
        assert!(!is_active_persona_key_under_root(
            &state, "root-a", &root_key
        ));
        assert!(!is_active_persona_key_under_root(
            &state,
            "root-a",
            &device_key
        ));
    }

    #[test]
    fn principal_binding_authorizes_root_level_operation() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-principal-root",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-new".into(),
                label: "New Device".into(),
                initial_key: make_key("key-device-new"),
                initial_encryption_key: make_enc_key("device-new"),
            }),
            SignerBinding::principal("root-a", "key-root-a"),
        );

        auth.authorize_raw(&event, &state, 0)
            .expect("canonical Principal root signer should authorize root-level event");
    }

    #[test]
    fn principal_binding_authorizes_persona_level_operation() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-principal-persona",
            EventBody::MessageSent(MessageSentEvent {
                message_id: "msg-principal".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "00".into(),
            }),
            SignerBinding::principal("persona-a", "key-persona-a"),
        );

        auth.authorize_raw(&event, &state, 0)
            .expect("canonical Principal child signer should authorize persona-level event");
    }

    // ── 16.1: Cross-root revoke/freeze must be rejected ──

    // --- Model C: root authority = founding key OR active presence Device ---

    /// Root "op" with a founding key plus two active `presence` Devices (the
    /// operator's first + backup YubiKeys) and one `daemon`-class Device.
    fn presence_root_state() -> MaterializedState {
        let mut state = MaterializedState::default();
        state.roots_current.insert(
            "op".into(),
            RootRecord {
                root_id: "op".into(),
                display_name: "Operator".into(),
                active_key: make_key("key-root-op"),
                status: RootStatus::Active,
            },
        );
        let mut add_device = |id: &str, key: &str, custody: CustodyClass, status: DeviceStatus| {
            state.devices_current.insert(
                id.into(),
                DeviceRecord {
                    root_id: "op".into(),
                    device_id: id.into(),
                    label: id.into(),
                    active_key: make_key(key),
                    active_encryption_key: make_enc_key(id),
                    status,
                    replacement_device_id: None,
                    custody_class: custody,
                    attestation_statement: if custody == CustodyClass::Presence {
                        Some("att".into())
                    } else {
                        None
                    },
                    attestation_tier: AttestationTier::None,
                    presence_factor: if custody == CustodyClass::Presence {
                        PresenceFactor::UserPresence
                    } else {
                        PresenceFactor::Unattended
                    },
                },
            );
        };
        add_device("d1", "key-d1", CustodyClass::Presence, DeviceStatus::Active);
        add_device("d2", "key-d2", CustodyClass::Presence, DeviceStatus::Active);
        add_device("dd", "key-dd", CustodyClass::Daemon, DeviceStatus::Active);
        state
    }

    fn persona_created_under_op(persona_id: &str, signed_by_key: &str) -> EventEnvelope {
        make_event(
            "evt-c",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "op".into(),
                persona_id: persona_id.into(),
                label: "P".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: make_key(&format!("{persona_id}-key")),
            }),
            // Root-level op: subject is the root; the *key* is whichever device
            // (or the founding key) signs for it.
            SignerBinding::root("op", signed_by_key),
        )
    }

    #[test]
    fn c_founding_root_key_authorizes_root_op() {
        // N=1 / regression: the root's own founding key still authorizes.
        let state = presence_root_state();
        let event = persona_created_under_op("p1", "key-root-op");
        assert!(IdentityAuthorizer.authorize_raw(&event, &state, 0).is_ok());
    }

    #[test]
    fn c_active_presence_device_authorizes_root_op() {
        // The crux of Model C: an enrolled presence Device that is NOT the
        // founding key may authorize a root-level op (so a lost first key is
        // recoverable from the backup).
        let state = presence_root_state();
        let event = persona_created_under_op("p1", "key-d2");
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_ok(),
            "an active presence Device must authorize root-level ops"
        );
    }

    #[test]
    fn c_daemon_class_device_denied_root_authority() {
        // Only `presence`-class Devices carry root authority; a `daemon`-class
        // Device (even active, under the root) must NOT.
        let state = presence_root_state();
        let event = persona_created_under_op("p1", "key-dd");
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_err(),
            "daemon-class device must not get root authority"
        );
    }

    #[test]
    fn c_revoked_presence_device_loses_root_authority() {
        let mut state = presence_root_state();
        state.devices_current.get_mut("d1").unwrap().status = DeviceStatus::Revoked;
        let event = persona_created_under_op("p1", "key-d1");
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_err(),
            "a revoked presence device must not authorize root-level ops"
        );
    }

    #[test]
    fn c_presence_device_of_other_root_denied() {
        // A presence Device enrolled under a *different* root must not authorize
        // ops on this root (cross-root).
        let mut state = presence_root_state();
        state.roots_current.insert(
            "other".into(),
            RootRecord {
                root_id: "other".into(),
                display_name: "Other".into(),
                active_key: make_key("key-root-other"),
                status: RootStatus::Active,
            },
        );
        state.devices_current.insert(
            "x1".into(),
            DeviceRecord {
                root_id: "other".into(),
                device_id: "x1".into(),
                label: "x1".into(),
                active_key: make_key("key-x1"),
                active_encryption_key: make_enc_key("x1"),
                status: DeviceStatus::Active,
                replacement_device_id: None,
                custody_class: CustodyClass::Presence,
                attestation_statement: Some("att".into()),
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
        );
        let event = persona_created_under_op("p1", "key-x1");
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_err(),
            "a presence device of another root must not authorize this root's ops"
        );
    }

    #[test]
    fn c_presence_device_may_rotate_root_key_for_recovery() {
        // Recovery↔takeover duality (INTENDED): a surviving presence Device must
        // be able to rotate the founding key away from a lost/compromised one.
        // The op is takeover-shaped but it IS the recovery primitive — denying
        // it would re-break Model C's "either survivor recovers". ALLOWED.
        let state = presence_root_state();
        let event = make_event(
            "evt-rkt",
            EventBody::RootKeyRotated(RootKeyRotatedEvent {
                root_id: "op".into(),
                previous_key_id: "key-root-op".into(),
                new_key: make_key("key-root-op-v2"),
            }),
            SignerBinding::root("op", "key-d1"),
        );
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_ok(),
            "a surviving presence Device must be able to rotate the root key (recovery)"
        );
    }

    #[test]
    fn c_presence_device_may_revoke_a_sibling_device_for_recovery() {
        // Recovery: d1 revokes the lost/compromised sibling d2. ALLOWED (the
        // 1-of-N model — any active presence Device can revoke another).
        let state = presence_root_state();
        let event = make_event(
            "evt-rev",
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: "op".into(),
                device_id: "d2".into(),
                reason: "lost".into(),
            }),
            SignerBinding::root("op", "key-d1"),
        );
        assert!(
            IdentityAuthorizer.authorize_raw(&event, &state, 0).is_ok(),
            "a presence Device must be able to revoke a sibling device (recovery)"
        );
    }

    #[test]
    fn cross_root_device_revoke_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        // root-a tries to revoke root-b's device
        let event = make_event(
            "evt-1",
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: "root-a".into(),
                device_id: "device-b".into(),
                reason: "malicious".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize_raw(&event, &state, 0);
        assert!(result.is_err(), "cross-root device revoke must fail");
        assert!(
            result.unwrap_err().to_string().contains("belongs to root"),
            "error should mention ownership mismatch"
        );
    }

    #[test]
    fn cross_root_device_freeze_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::DeviceFrozen(DeviceFrozenEvent {
                root_id: "root-a".into(),
                device_id: "device-b".into(),
                reason: "malicious".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize(&event, &state, 0);
        assert!(result.is_err(), "cross-root device freeze must fail");
    }

    #[test]
    fn cross_root_persona_revoke_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::PersonaRevoked(PersonaRevokedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-b".into(),
                reason: "malicious".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize(&event, &state, 0);
        assert!(result.is_err(), "cross-root persona revoke must fail");
    }

    #[test]
    fn same_root_device_revoke_allowed() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "legit".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        assert!(auth.authorize(&event, &state, 0).is_ok());
    }

    #[test]
    fn same_root_persona_revoke_allowed() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::PersonaRevoked(PersonaRevokedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                reason: "legit".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        assert!(auth.authorize(&event, &state, 0).is_ok());
    }

    // ── 16.2: Revoked root must lose authority ──

    #[test]
    fn revoked_root_cannot_add_device() {
        let mut state = two_root_state();
        state.roots_current.get_mut("root-a").unwrap().status = RootStatus::Revoked;
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::DeviceAdded(core_event_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-new".into(),
                label: "New".into(),
                initial_key: make_key("key-new"),
                initial_encryption_key: make_enc_key("new"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize_raw(&event, &state, 0);
        assert!(result.is_err(), "revoked root must not add devices");
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[test]
    fn revoked_root_cannot_create_persona() {
        let mut state = two_root_state();
        state.roots_current.get_mut("root-a").unwrap().status = RootStatus::Revoked;
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::PersonaCreated(core_event_types::PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-new".into(),
                label: "New".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: make_key("key-new"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize(&event, &state, 0);
        assert!(result.is_err(), "revoked root must not create personas");
    }

    #[test]
    fn revoked_root_cannot_revoke_own_device() {
        let mut state = two_root_state();
        state.roots_current.get_mut("root-a").unwrap().status = RootStatus::Revoked;
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "test".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize(&event, &state, 0);
        assert!(result.is_err(), "revoked root must not revoke devices");
    }

    #[test]
    fn active_root_retains_authority() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-c".into(),
                display_name: "Root C".into(),
                initial_key: make_key("key-root-c"),
            }),
            SignerBinding::root("root-c", "key-root-c"),
        );
        // RootCreated doesn't check auth (always Ok), just ensure no regression
        assert!(auth.authorize(&event, &state, 0).is_ok());
    }

    // ── GrantOfferClaimed offer status/expiry checks ──

    fn state_with_pending_offer(expires_at: u64) -> MaterializedState {
        let mut state = two_root_state();
        state.grant_offers_current.insert(
            "offer-1".into(),
            crate::GrantOfferRecord {
                offer_id: "offer-1".into(),
                issuer_persona_id: "persona-a".into(),
                ephemeral_public_key_hex: "aabbcc".into(),
                sealed_payload_hex: "ddeeff".into(),
                relay_hint: None,
                expires_at,
                conditions_json: String::new(),
                status: GrantOfferStatus::Pending,
                recipient_persona_id: None,
                claim_response_hex: None,
                claimed_at: None,
            },
        );
        state
    }

    fn make_claim_event(offer_id: &str, recipient: &str, key: &str) -> core_events::EventEnvelope {
        make_event(
            "evt-claim",
            EventBody::GrantOfferClaimed(core_event_types::GrantOfferClaimedEvent {
                offer_id: offer_id.into(),
                recipient_persona_id: recipient.into(),
                claim_response_hex: "cafebabe".into(),
                claimed_at: 1000,
            }),
            SignerBinding::persona(recipient, key),
        )
    }

    #[test]
    fn grant_claim_on_nonexistent_offer_passes_through() {
        // When the offer is not in local state (cross-device claim path), we allow
        // the event through — the issuer-side replay will catch violations.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_claim_event("no-such-offer", "persona-b", "key-persona-b");
        let result = auth.authorize(&event, &state, 999);
        assert!(
            result.is_ok(),
            "claim on unknown offer must pass through (cross-device path)"
        );
    }

    #[test]
    fn grant_claim_on_expired_offer_rejected() {
        let state = state_with_pending_offer(500); // expires_at = 500
        let auth = IdentityAuthorizer;
        let event = make_claim_event("offer-1", "persona-b", "key-persona-b");
        let result = auth.authorize_raw(&event, &state, 1000); // now = 1000 > 500
        assert!(result.is_err(), "claim on expired offer must fail");
        assert!(
            result.unwrap_err().to_string().contains("expired"),
            "error should mention expiry"
        );
    }

    #[test]
    fn grant_claim_on_claimed_offer_rejected() {
        let mut state = state_with_pending_offer(9999);
        state
            .grant_offers_current
            .get_mut("offer-1")
            .unwrap()
            .status = GrantOfferStatus::Claimed;
        let auth = IdentityAuthorizer;
        let event = make_claim_event("offer-1", "persona-b", "key-persona-b");
        let result = auth.authorize_raw(&event, &state, 100);
        assert!(result.is_err(), "claim on already-claimed offer must fail");
        assert!(
            result.unwrap_err().to_string().contains("Pending"),
            "error should mention status"
        );
    }

    #[test]
    fn grant_claim_on_revoked_offer_rejected() {
        let mut state = state_with_pending_offer(9999);
        state
            .grant_offers_current
            .get_mut("offer-1")
            .unwrap()
            .status = GrantOfferStatus::Revoked;
        let auth = IdentityAuthorizer;
        let event = make_claim_event("offer-1", "persona-b", "key-persona-b");
        let result = auth.authorize(&event, &state, 100);
        assert!(result.is_err(), "claim on revoked offer must fail");
    }

    #[test]
    fn grant_claim_valid_pending_offer_allowed() {
        let state = state_with_pending_offer(9999);
        let auth = IdentityAuthorizer;
        let event = make_claim_event("offer-1", "persona-b", "key-persona-b");
        assert!(
            auth.authorize(&event, &state, 100).is_ok(),
            "valid claim on pending non-expired offer must succeed"
        );
    }

    // ── GrantOfferRevoked issuer ownership check ──

    fn make_revoke_offer_event(
        offer_id: &str,
        issuer: &str,
        key: &str,
        reason: &str,
    ) -> core_events::EventEnvelope {
        make_event(
            "evt-revoke-offer",
            EventBody::GrantOfferRevoked(core_event_types::GrantOfferRevokedEvent {
                offer_id: offer_id.into(),
                issuer_persona_id: issuer.into(),
                reason: reason.into(),
            }),
            SignerBinding::persona(issuer, key),
        )
    }

    #[test]
    fn grant_offer_revoke_by_non_issuer_rejected() {
        let state = state_with_pending_offer(9999);
        let auth = IdentityAuthorizer;
        // persona-b tries to revoke an offer issued by persona-a
        let event = make_revoke_offer_event("offer-1", "persona-b", "key-persona-b", "theft");
        let result = auth.authorize_raw(&event, &state, 100);
        assert!(result.is_err(), "non-issuer offer revoke must fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not match original issuer"),
            "error should mention issuer mismatch"
        );
    }

    #[test]
    fn grant_offer_revoke_by_issuer_allowed() {
        let state = state_with_pending_offer(9999);
        let auth = IdentityAuthorizer;
        // persona-a is the issuer — should succeed
        let event =
            make_revoke_offer_event("offer-1", "persona-a", "key-persona-a", "changed mind");
        assert!(
            auth.authorize(&event, &state, 100).is_ok(),
            "issuer may revoke their own offer"
        );
    }

    // ── BadgeRevoked issuer ownership check ──

    fn state_with_badge() -> MaterializedState {
        let mut state = two_root_state();
        state.badges_current.insert(
            "badge-1".into(),
            crate::BadgeRecord {
                badge_id: "badge-1".into(),
                issuer_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                badge_type: "endorsement".into(),
                display_name: "Great work".into(),
                evidence: None,
                issued_at: 0,
                expires_at: None,
                revoked: false,
                revoked_reason: None,
            },
        );
        state
    }

    fn make_revoke_badge_event(
        badge_id: &str,
        revoker: &str,
        key: &str,
    ) -> core_events::EventEnvelope {
        make_event(
            "evt-revoke-badge",
            EventBody::BadgeRevoked(core_event_types::BadgeRevokedEvent {
                badge_id: badge_id.into(),
                revoker_persona_id: revoker.into(),
                reason: "test".into(),
            }),
            SignerBinding::persona(revoker, key),
        )
    }

    #[test]
    fn badge_revoke_by_non_issuer_rejected() {
        let state = state_with_badge();
        let auth = IdentityAuthorizer;
        // persona-b (recipient) tries to revoke a badge issued by persona-a
        let event = make_revoke_badge_event("badge-1", "persona-b", "key-persona-b");
        let result = auth.authorize_raw(&event, &state, 0);
        assert!(result.is_err(), "non-issuer badge revoke must fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not match original issuer"),
            "error should mention issuer mismatch"
        );
    }

    #[test]
    fn badge_revoke_by_issuer_allowed() {
        let state = state_with_badge();
        let auth = IdentityAuthorizer;
        // persona-a is the issuer — should succeed
        let event = make_revoke_badge_event("badge-1", "persona-a", "key-persona-a");
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "issuer may revoke their own badge"
        );
    }

    // ── Signer-pubkey binding: must bind to the stored active key ──
    //
    // These regressions protect against a peer-impersonation attack: a valid
    // signature over a well-formed envelope whose `signer_binding.key_id` claims
    // the victim's key id, but whose `signer` public key material is the
    // attacker's. Before the fix, authorize only compared key_id strings and
    // accepted the impersonation.

    use core_events::EventRef;
    use core_types::{CanonicalEncode, SchemaVersion};

    /// Forge an envelope where `signer_binding.key_id` names the victim's key id
    /// but `signer` (the public-key material) is the attacker's, and the
    /// signature is produced by the attacker's private key over the
    /// victim-bound canonical bytes. The envelope signature verifies against
    /// the attacker's pubkey (because the signature and signer-pubkey are
    /// both the attacker's), but the authorizer must reject the envelope on
    /// the pubkey-material binding check.
    fn forged_envelope(
        event_id: &str,
        body: EventBody,
        victim_key_id: &str,
        attacker_signer: &FixtureSigner,
        role: KeyRole,
    ) -> EventEnvelope {
        let subject = body.subject();
        let signer_binding = SignerBinding {
            signer: subject.clone(),
            key_id: victim_key_id.into(),
            role,
        };
        let payload = body.canonical_encode();
        let event_type = body.event_type();
        let refs: Vec<EventRef> = vec![];
        let signer_public_key = attacker_signer.public_key();
        // Mirror the canonical_signed_bytes layout from core-events so the
        // attacker's signature covers the victim-bound binding. If the layout
        // changes upstream, this helper will need to match.
        let canonical = {
            let mut out = String::new();
            out.push_str("schema_version=");
            out.push_str(&SchemaVersion::V0_1_0.to_string());
            out.push('\n');
            out.push_str("event_id=");
            out.push_str(event_id);
            out.push('\n');
            out.push_str("event_type=");
            out.push_str(event_type.as_str());
            out.push('\n');
            out.push_str("subject_kind=");
            out.push_str(subject.kind.as_str());
            out.push('\n');
            out.push_str("subject_id=");
            out.push_str(&subject.subject_id);
            out.push('\n');
            out.push_str("signer_kind=");
            out.push_str(signer_binding.signer.kind.as_str());
            out.push('\n');
            out.push_str("signer_id=");
            out.push_str(&signer_binding.signer.subject_id);
            out.push('\n');
            out.push_str("signer_key_id=");
            out.push_str(&signer_binding.key_id);
            out.push('\n');
            out.push_str("signer_role=");
            out.push_str(signer_binding.role.as_str());
            out.push('\n');
            out.push_str("ref_count=0\n");
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(b"payload=\n");
            bytes.extend_from_slice(&payload);
            bytes
        };
        let signature = core_crypto::sign_with_context(DOMAIN_EVENT, attacker_signer, &canonical);
        EventEnvelope {
            schema_version: SchemaVersion::V0_1_0,
            event_id: event_id.into(),
            event_type,
            subject,
            signer_binding,
            signer: signer_public_key,
            payload,
            refs,
            signature,
            body,
        }
    }

    #[test]
    fn forged_root_event_with_attacker_pubkey_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        // Attacker signs with their own key but claims root-a's key id.
        let attacker = FixtureSigner::new("attacker-root-forgery");
        let event = forged_envelope(
            "evt-forged-root",
            EventBody::RootRevoked(core_event_types::RootRevokedEvent {
                root_id: "root-a".into(),
                reason: "attack".into(),
            }),
            "key-root-a",
            &attacker,
            KeyRole::Root,
        );
        // Sanity: the attacker's signature verifies against their own pubkey —
        // i.e. the signature check alone would not catch this.
        assert!(
            core_crypto::verify_with_context(
                DOMAIN_EVENT,
                &core_crypto::FixtureVerifier,
                &event.signer,
                &event.signed_bytes(),
                &event.signature,
            ),
            "forged envelope must be signature-valid for the authorization check to be meaningful",
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("authorize must reject envelope whose signer pubkey ≠ stored active key");
        assert!(
            err.to_string().contains("presence Device"),
            "error should explain the signer is not a root-authority key/device: {err}"
        );
    }

    #[test]
    fn forged_persona_event_with_attacker_pubkey_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let attacker = FixtureSigner::new("attacker-persona-forgery");
        let event = forged_envelope(
            "evt-forged-persona",
            EventBody::MessageSent(core_event_types::MessageSentEvent {
                message_id: "msg-1".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "00".into(),
            }),
            "key-persona-a",
            &attacker,
            KeyRole::Persona,
        );
        assert!(core_crypto::verify_with_context(
            DOMAIN_EVENT,
            &core_crypto::FixtureVerifier,
            &event.signer,
            &event.signed_bytes(),
            &event.signature,
        ));
        let err = auth.authorize_raw(&event, &state, 0).expect_err(
            "authorize must reject persona envelope whose signer pubkey ≠ stored active key",
        );
        assert!(
            err.to_string().contains("public key"),
            "error should mention pubkey material mismatch: {err}"
        );
    }

    #[test]
    fn forged_device_event_with_attacker_pubkey_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let attacker = FixtureSigner::new("attacker-device-forgery");
        let event = forged_envelope(
            "evt-forged-device",
            EventBody::DeviceKeyRotated(core_event_types::DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a".into(),
                new_key: core_principals::PublicKeyMaterial {
                    key_id: "key-device-a-v2".into(),
                    algorithm: KeyAlgorithm::Ed25519,
                    public_key: "ed25519:attacker-new".into(),
                },
            }),
            "key-device-a",
            &attacker,
            KeyRole::Device,
        );
        assert!(core_crypto::verify_with_context(
            DOMAIN_EVENT,
            &core_crypto::FixtureVerifier,
            &event.signer,
            &event.signed_bytes(),
            &event.signature,
        ));
        let err = auth.authorize_raw(&event, &state, 0).expect_err(
            "authorize must reject device envelope whose signer pubkey ≠ stored active key",
        );
        assert!(
            err.to_string().contains("public key"),
            "error should mention pubkey material mismatch: {err}"
        );
    }

    #[test]
    fn forged_guardian_event_with_attacker_pubkey_rejected() {
        let mut state = two_root_state();
        // Enroll a guardian for root-a where the "key id" IS the public key.
        let enrolled_guardian_signer = FixtureSigner::new("real-guardian-key");
        let enrolled_pub = enrolled_guardian_signer.public_key().0;
        state.guardians_current.insert(
            "guardian-1".into(),
            crate::GuardianRecord {
                guardian_id: "guardian-1".into(),
                root_id: "root-a".into(),
                label: "G1".into(),
                public_key: enrolled_pub.clone(),
            },
        );
        // Add a recovery policy + request so the RecoveryApproved path has state.
        state.recovery_requests_current.insert(
            "req-1".into(),
            crate::RecoveryRequestRecord {
                request_id: "req-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
                approvals: Default::default(),
                contested_by: Default::default(),
                status: RecoveryRequestStatus::Requested,
                executed_scope: None,
                cooldown_until: None,
                contest_reason: None,
                rejection_reason: None,
            },
        );
        let auth = IdentityAuthorizer;
        // Attacker signs with their own key but claims the enrolled guardian's pubkey as key_id.
        let attacker = FixtureSigner::new("attacker-guardian-forgery");
        let event = forged_envelope(
            "evt-forged-guardian",
            EventBody::RecoveryApproved(core_event_types::RecoveryApprovedEvent {
                request_id: "req-1".into(),
                guardian_id: "guardian-1".into(),
            }),
            &enrolled_pub,
            &attacker,
            KeyRole::Guardian,
        );
        assert!(core_crypto::verify_with_context(
            DOMAIN_EVENT,
            &core_crypto::FixtureVerifier,
            &event.signer,
            &event.signed_bytes(),
            &event.signature,
        ));
        let err = auth.authorize_raw(&event, &state, 0).expect_err(
            "authorize must reject guardian envelope whose signer pubkey ≠ enrolled guardian key",
        );
        assert!(
            err.to_string().contains("public key"),
            "error should mention pubkey material mismatch: {err}"
        );
    }

    // ── DeviceReplaced must enforce cross-root ownership ──

    #[test]
    fn cross_root_device_replace_rejected() {
        // root-a tries to Replace device-b (owned by root-b) with device-a.
        // Before the fix, this passed because authorize only checked the signing
        // root's key; no ownership check was required.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-cross-replace",
            EventBody::DeviceReplaced(core_event_types::DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-b".into(),
                replacement_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("cross-root device replace must fail");
        assert!(
            err.to_string().contains("belongs to root"),
            "error should mention ownership mismatch: {err}"
        );
    }

    #[test]
    fn cross_root_device_replace_replacement_rejected() {
        // Mirror case: root-a claims authority over their own replaced_device_id
        // but names device-b (owned by root-b) as the replacement.
        let mut state = two_root_state();
        // Ensure device-a exists as an Active device under root-a (already does).
        // Add a second device under root-a we can legitimately replace.
        state.devices_current.insert(
            "device-a2".into(),
            DeviceRecord {
                root_id: "root-a".into(),
                device_id: "device-a2".into(),
                label: "Device A2".into(),
                active_key: make_key("key-device-a2"),
                active_encryption_key: make_enc_key("device-a2"),
                status: DeviceStatus::Active,
                replacement_device_id: None,
                custody_class: CustodyClass::Daemon,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::Unattended,
            },
        );
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-cross-replacement",
            EventBody::DeviceReplaced(core_event_types::DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-b".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("naming cross-root replacement must fail");
        assert!(
            err.to_string().contains("belongs to root"),
            "error should mention ownership mismatch: {err}"
        );
    }

    #[test]
    fn same_root_device_replace_allowed() {
        let mut state = two_root_state();
        state.devices_current.insert(
            "device-a2".into(),
            DeviceRecord {
                root_id: "root-a".into(),
                device_id: "device-a2".into(),
                label: "Device A2".into(),
                active_key: make_key("key-device-a2"),
                active_encryption_key: make_enc_key("device-a2"),
                status: DeviceStatus::Active,
                replacement_device_id: None,
                custody_class: CustodyClass::Daemon,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::Unattended,
            },
        );
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-replace-ok",
            EventBody::DeviceReplaced(core_event_types::DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-a2".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "same-root device replace should succeed"
        );
    }

    // ── CredentialRevoked must require ALL deposits with this grant_id ──
    // are issued by the revoker, not just the first-found one.

    #[test]
    fn credential_revoke_blocks_cross_issuer_grant_id_collision() {
        let mut state = two_root_state();
        // Two deposits sharing a grant_id. First one is issued by persona-a (the
        // revoker). Second is issued by persona-b.
        state.credential_deposits_current.insert(
            "deposit-1".into(),
            crate::CredentialDepositRecord {
                deposit_id: "deposit-1".into(),
                grant_id: "grant-shared".into(),
                credential_id: "cred-1".into(),
                issuer_id: "persona-a".into(),
                encrypted_blocks_json: "{}".into(),
                status: crate::CredentialDepositStatus::Active,
                created_at: 0,
                expires_at: None,
                revoked_at: None,
                revoked_reason: None,
            },
        );
        state.credential_deposits_current.insert(
            "deposit-2".into(),
            crate::CredentialDepositRecord {
                deposit_id: "deposit-2".into(),
                grant_id: "grant-shared".into(),
                credential_id: "cred-2".into(),
                issuer_id: "persona-b".into(),
                encrypted_blocks_json: "{}".into(),
                status: crate::CredentialDepositStatus::Active,
                created_at: 0,
                expires_at: None,
                revoked_at: None,
                revoked_reason: None,
            },
        );
        let auth = IdentityAuthorizer;
        // persona-a (issuer of deposit-1 only) tries to revoke — the second deposit
        // under the same grant_id was issued by persona-b, so the revocation must
        // be rejected.
        let event = make_event(
            "evt-cred-revoke",
            EventBody::CredentialRevoked(core_event_types::CredentialRevokedEvent {
                grant_id: "grant-shared".into(),
                revoker_id: "persona-a".into(),
                reason: "test".into(),
                revoked_at: 100,
            }),
            SignerBinding::persona("persona-a", "key-persona-a"),
        );
        let err = auth.authorize_raw(&event, &state, 100).expect_err(
            "credential revoke must reject cross-issuer grant_id collision (defense in depth)",
        );
        assert!(
            err.to_string().contains("does not match original issuer"),
            "error should mention issuer mismatch: {err}"
        );
    }

    // ── P79.1a M-5: DeviceKeyRotated / DeviceEncryptionKeyRotated body.root_id
    // must match the device's stored root_id (audit-trail consistency). ──

    #[test]
    fn device_key_rotated_root_id_mismatch_rejected() {
        // device-a is owned by root-a, but the body claims root_id=root-b.
        // Signed by device-a's current key (so authorize_device_key would pass)
        // — we rely on the new require_device_owned_by_root assertion to reject
        // the mismatched body.root_id.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-device-key-rotate-mismatch",
            EventBody::DeviceKeyRotated(core_event_types::DeviceKeyRotatedEvent {
                root_id: "root-b".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a".into(),
                new_key: make_key("key-device-a-v2"),
            }),
            SignerBinding::device("device-a", "key-device-a"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("DeviceKeyRotated must reject mismatched body.root_id");
        assert!(
            err.to_string().contains("belongs to root"),
            "error should mention ownership mismatch: {err}"
        );
    }

    #[test]
    fn device_encryption_key_rotated_root_id_mismatch_rejected() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-device-enc-rotate-mismatch",
            EventBody::DeviceEncryptionKeyRotated(
                core_event_types::DeviceEncryptionKeyRotatedEvent {
                    root_id: "root-b".into(),
                    device_id: "device-a".into(),
                    previous_encryption_key_id: "enc-device-a".into(),
                    new_encryption_key: make_enc_key("device-a-v2"),
                },
            ),
            SignerBinding::device("device-a", "key-device-a"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("DeviceEncryptionKeyRotated must reject mismatched body.root_id");
        assert!(
            err.to_string().contains("belongs to root"),
            "error should mention ownership mismatch: {err}"
        );
    }

    #[test]
    fn device_key_rotated_matching_root_id_allowed() {
        // Happy path: body.root_id matches device.root_id → accepted.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-device-key-rotate-ok",
            EventBody::DeviceKeyRotated(core_event_types::DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a".into(),
                new_key: make_key("key-device-a-v2"),
            }),
            SignerBinding::device("device-a", "key-device-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "matching body.root_id should be accepted",
        );
    }

    // ── P79.1a M-3: RelayShutdownNotice must match the known endpoint device ──

    fn state_with_relay_endpoint() -> MaterializedState {
        let mut state = two_root_state();
        state.endpoints_current.insert(
            "peer-relay".into(),
            core_principals::EndpointDescriptor {
                peer_id: "peer-relay".into(),
                device_id: "device-a".into(),
                transport_hint: "wss://relay.example".into(),
            },
        );
        state
    }

    #[test]
    fn relay_shutdown_notice_wrong_device_rejected() {
        // An endpoint is registered for peer-relay → device-a. But device-b
        // signs the notice for the same peer. Must be rejected.
        let state = state_with_relay_endpoint();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-relay-shutdown",
            EventBody::RelayShutdownNotice(core_event_types::RelayShutdownNoticeEvent {
                relay_peer_id: "peer-relay".into(),
                reason: "attacker".into(),
                deadline_epoch: 9999,
            }),
            SignerBinding::device("device-b", "key-device-b"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("shutdown notice from non-endpoint device must be rejected");
        assert!(
            err.to_string().contains("endpoint device"),
            "error should mention endpoint device mismatch: {err}"
        );
    }

    #[test]
    fn relay_shutdown_notice_correct_device_allowed() {
        // The endpoint device signs → accepted.
        let state = state_with_relay_endpoint();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-relay-shutdown-ok",
            EventBody::RelayShutdownNotice(core_event_types::RelayShutdownNoticeEvent {
                relay_peer_id: "peer-relay".into(),
                reason: "maintenance".into(),
                deadline_epoch: 9999,
            }),
            SignerBinding::device("device-a", "key-device-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "shutdown notice from correct endpoint device must be accepted",
        );
    }

    #[test]
    fn relay_shutdown_notice_unknown_endpoint_passes_through() {
        // No endpoint registered for peer-unknown → authorize defers to
        // consumer layer. This is the documented pass-through.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-relay-shutdown-unknown",
            EventBody::RelayShutdownNotice(core_event_types::RelayShutdownNoticeEvent {
                relay_peer_id: "peer-unknown".into(),
                reason: "no endpoint on file".into(),
                deadline_epoch: 9999,
            }),
            SignerBinding::device("device-a", "key-device-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "shutdown notice for unknown endpoint must pass through",
        );
    }

    // ── P79.1a M-4: RootCreated key-material collision rejected ──

    #[test]
    fn root_created_with_colliding_pubkey_rejected() {
        // state has root-a with key-root-a. A second RootCreated for root-c
        // that reuses root-a's pubkey must be rejected.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let existing_pubkey_material = state
            .roots_current
            .get("root-a")
            .unwrap()
            .active_key
            .clone();
        // Sign with root-a's key so the event passes the self-root invariant
        // (signer == initial_key) and the COLLISION guard is what rejects it —
        // otherwise the self-root check would fire first. (This models an attacker
        // who actually holds root-a's key; the collision guard stops the squat
        // regardless.)
        let event = make_event(
            "evt-collide-root",
            EventBody::RootCreated(core_event_types::RootCreatedEvent {
                root_id: "root-c".into(),
                display_name: "Colliding".into(),
                initial_key: core_principals::PublicKeyMaterial {
                    key_id: "key-root-a".into(),
                    algorithm: core_principals::KeyAlgorithm::Ed25519,
                    // Reuse root-a's public key material.
                    public_key: existing_pubkey_material.public_key.clone(),
                },
            }),
            SignerBinding::root("root-c", "key-root-a"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("RootCreated with colliding pubkey material must be rejected");
        assert!(
            err.to_string().contains("collides with existing root"),
            "error should mention collision: {err}"
        );
    }

    #[test]
    fn root_created_with_signer_mismatched_initial_key_rejected() {
        // ADR 200 self-root invariant: a RootCreated whose recorded `initial_key`
        // is key A but whose signing key is B (a valid B-signature) must be
        // rejected at the authority layer, so local materialized state can never
        // name an active_key an external verify_chain would reject. Pre-fix this
        // was accepted (RootCreated only ran the cross-root collision check).
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        // initial_key = key-root-c, but the event is signed by key-root-d.
        let event = make_event(
            "evt-root-signer-mismatch",
            EventBody::RootCreated(core_event_types::RootCreatedEvent {
                root_id: "root-c".into(),
                display_name: "Mismatch".into(),
                initial_key: make_key("key-root-c"),
            }),
            SignerBinding::root("root-c", "key-root-d"),
        );
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("RootCreated signed by a key other than initial_key must be rejected");
        assert!(
            err.to_string().contains("self-root invariant")
                || err
                    .to_string()
                    .contains("does not match the recorded initial_key"),
            "error should name the self-root invariant: {err}"
        );
    }

    #[test]
    fn root_created_with_fresh_pubkey_allowed() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-fresh-root",
            EventBody::RootCreated(core_event_types::RootCreatedEvent {
                root_id: "root-c".into(),
                display_name: "Fresh".into(),
                initial_key: make_key("key-root-c-fresh"),
            }),
            SignerBinding::root("root-c", "key-root-c-fresh"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "RootCreated with fresh pubkey must be accepted",
        );
    }

    // ── P79.1a L-2: TrustRevoked on unknown attestation passes through (documented) ──

    #[test]
    fn trust_revoked_on_unknown_attestation_passes_through() {
        // Document the pass-through: a persona revokes an attestation that
        // does not exist in local state. Accepted — materialize will no-op.
        // The DoS risk is bounded by the attacker having to sign with an
        // active persona key.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-trust-revoked-unknown",
            EventBody::TrustRevoked(core_event_types::TrustRevokedEvent {
                attestation_id: "does-not-exist".into(),
                attester_persona_id: "persona-a".into(),
            }),
            SignerBinding::persona("persona-a", "key-persona-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "unknown-attestation TrustRevoked must pass through",
        );
    }

    // ── P79.1a L-3: DisclosureRevoked authorize layer (documented pass-through) ──

    #[test]
    fn disclosure_revoked_authorize_layer_allows_revoker_persona() {
        // Authorize layer accepts DisclosureRevoked when the signer is an
        // active persona that matches `body.revoker_persona_id`. Cross-check
        // against the original issuer is deferred to the disclosure module
        // because the eventlog does not materialize disclosure artifacts.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-disclosure-revoked",
            EventBody::DisclosureRevoked(core_event_types::DisclosureRevokedEvent {
                revocation_id: "rev-1".into(),
                artifact_id: "artifact-1".into(),
                revoker_persona_id: "persona-a".into(),
                reason: "test".into(),
            }),
            SignerBinding::persona("persona-a", "key-persona-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "DisclosureRevoked by active persona must be accepted at authorize layer",
        );
    }

    #[test]
    fn disclosure_revoked_by_non_persona_signer_rejected() {
        // A root-role signer that still names `revoker_persona_id` in the body
        // must fail the coherence check (I-1) and / or the persona-key check.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-disclosure-revoked-wrong-role",
            EventBody::DisclosureRevoked(core_event_types::DisclosureRevokedEvent {
                revocation_id: "rev-1".into(),
                artifact_id: "artifact-1".into(),
                revoker_persona_id: "persona-a".into(),
                reason: "test".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_err(),
            "DisclosureRevoked signed by wrong role must be rejected",
        );
    }

    // ── P79.1a I-1: signer subject coherence ──

    #[test]
    fn signer_subject_mismatch_rejected() {
        // Body says persona-a sent the message, but signer_binding claims the
        // signer is persona-b. Even if persona-b's key would technically verify
        // the payload, the coherence check fails first — auditors should not
        // see "persona-b signed persona-a's message".
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-signer-mismatch",
            EventBody::MessageSent(core_event_types::MessageSentEvent {
                message_id: "msg-1".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "00".into(),
            }),
            SignerBinding::persona("persona-b", "key-persona-b"),
        );
        let err = auth
            .authorize(&event, &state, 0)
            .expect_err("mismatched signer subject must be rejected");
        assert!(
            err.to_string().contains("signer subject"),
            "error should mention signer-subject mismatch: {err}"
        );
    }

    #[test]
    fn signer_wrong_kind_rejected() {
        // Body is a DeviceKeyRotated (device-as-signer), but signer_binding
        // is a root. Coherence check must reject.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-signer-wrong-kind",
            EventBody::DeviceKeyRotated(core_event_types::DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a".into(),
                new_key: make_key("key-device-a-v2"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let err = auth
            .authorize(&event, &state, 0)
            .expect_err("wrong signer kind must be rejected");
        assert!(
            err.to_string().contains("signer subject"),
            "error should mention signer-subject mismatch: {err}"
        );
    }

    // ── P79.1a I-2: check_time_window helper semantics ──

    #[test]
    fn check_time_window_not_before_blocks() {
        // cooldown semantics: now < not_before → error.
        let err = check_time_window(50, Some(100), None, "before-window", "after-window")
            .expect_err("now < not_before must error");
        assert!(err.to_string().contains("before-window"));
    }

    #[test]
    fn check_time_window_not_before_at_boundary_allows() {
        // cooldown semantics: now >= not_before → ok.
        assert!(
            check_time_window(100, Some(100), None, "x", "y").is_ok(),
            "now == not_before must succeed",
        );
    }

    #[test]
    fn check_time_window_not_after_blocks() {
        // expiry semantics: now >= not_after → error.
        let err = check_time_window(200, None, Some(200), "before-window", "after-window")
            .expect_err("now >= not_after must error");
        assert!(err.to_string().contains("after-window"));
    }

    #[test]
    fn check_time_window_strictly_before_not_after_allows() {
        assert!(
            check_time_window(199, None, Some(200), "x", "y").is_ok(),
            "now < not_after must succeed",
        );
    }

    // ── P79.1a L-1: sanitize_authorize_error collapses state-revealing errors ──

    #[test]
    fn sanitize_collapses_not_found() {
        let err = ValidationError::not_found("device", "device-a");
        let sanitized = super::sanitize_authorize_error(err);
        assert_eq!(
            sanitized.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(!sanitized.message.contains("device-a"));
        assert!(!sanitized.message.contains("unknown"));
        assert!(sanitized.message.contains("unauthorized"));
    }

    #[test]
    fn sanitize_collapses_state_violation() {
        let err = ValidationError::state_violation("device device-a is not active");
        let sanitized = super::sanitize_authorize_error(err);
        assert_eq!(
            sanitized.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(!sanitized.message.contains("device-a"));
        assert!(!sanitized.message.contains("not active"));
    }

    #[test]
    fn sanitize_collapses_unauthorized_detail() {
        let err = ValidationError::unauthorized("signer key foo does not match active device key");
        let sanitized = super::sanitize_authorize_error(err);
        assert!(!sanitized.message.contains("signer key"));
        assert_eq!(
            sanitized.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
    }

    #[test]
    fn sanitize_preserves_non_authorize_kinds() {
        // InvalidFormat errors originate from body-level validation and are
        // not state-revealing; leave them alone.
        let err = ValidationError::invalid_format("bad hex");
        let sanitized = super::sanitize_authorize_error(err.clone());
        assert_eq!(sanitized, err);
    }

    #[test]
    fn check_time_window_both_bounds() {
        // now inside (not_before, not_after) window → ok.
        assert!(check_time_window(150, Some(100), Some(200), "x", "y").is_ok());
        // now before not_before → before_msg.
        assert!(
            check_time_window(50, Some(100), Some(200), "before", "after")
                .unwrap_err()
                .to_string()
                .contains("before")
        );
        // now at or after not_after → after_msg.
        assert!(
            check_time_window(200, Some(100), Some(200), "before", "after")
                .unwrap_err()
                .to_string()
                .contains("after")
        );
    }

    // ── P79.1a L-1: authorize sanitizes, authorize_raw returns raw errors ──

    #[test]
    fn authorize_sanitizes_not_found_to_generic_unauthorized() {
        // An event signed by a non-existent root causes a NotFound error
        // internally. The public `authorize` must return a generic Unauthorized
        // rather than revealing "root X does not exist".
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-unknown-root",
            EventBody::RootRevoked(core_event_types::RootRevokedEvent {
                root_id: "root-nonexistent".into(),
                reason: "test".into(),
            }),
            SignerBinding::root("root-nonexistent", "key-root-nonexistent"),
        );
        // authorize_raw returns the precise error.
        let raw_err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("unknown root must fail");
        assert_eq!(raw_err.kind, core_types::ValidationErrorKind::NotFound);
        assert!(raw_err.to_string().contains("root"));

        // authorize returns the sanitized generic message.
        let sanitized_err = auth
            .authorize(&event, &state, 0)
            .expect_err("authorize must also reject");
        assert_eq!(
            sanitized_err.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(sanitized_err.to_string().contains("unauthorized"));
        assert!(!sanitized_err.to_string().contains("root-nonexistent"));
    }

    #[test]
    fn authorize_sanitizes_state_violation_to_generic_unauthorized() {
        // A revoked root causes a StateViolation error internally. The public
        // `authorize` must return a generic Unauthorized.
        let mut state = two_root_state();
        state.roots_current.get_mut("root-a").unwrap().status = RootStatus::Revoked;
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-revoked-root",
            EventBody::PersonaCreated(core_event_types::PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-new".into(),
                label: "New".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: make_key("key-new"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        // Raw error is a StateViolation with "revoked" in the message.
        let raw_err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("revoked root must fail");
        assert_eq!(
            raw_err.kind,
            core_types::ValidationErrorKind::StateViolation
        );
        assert!(raw_err.to_string().contains("revoked"));

        // Public authorize returns a sanitized Unauthorized.
        let sanitized_err = auth
            .authorize(&event, &state, 0)
            .expect_err("authorize must also reject");
        assert_eq!(
            sanitized_err.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(!sanitized_err.to_string().contains("revoked"));
    }

    #[test]
    fn authorize_passes_through_ok() {
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_event(
            "evt-ok-root-revoke",
            EventBody::RootRevoked(core_event_types::RootRevokedEvent {
                root_id: "root-a".into(),
                reason: "self-revoke".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "Ok is not affected by sanitizer"
        );
        assert!(
            auth.authorize_raw(&event, &state, 0).is_ok(),
            "authorize_raw also passes Ok"
        );
    }

    #[test]
    fn authorize_sanitizes_unauthorized_detail_to_generic() {
        // A forged pubkey causes Unauthorized (specific message). The public
        // `authorize` must collapse it to the generic message.
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let attacker = FixtureSigner::new("attacker-sanitize-test");
        let event = forged_envelope(
            "evt-sanitize-test",
            EventBody::RootRevoked(core_event_types::RootRevokedEvent {
                root_id: "root-a".into(),
                reason: "attack".into(),
            }),
            "key-root-a",
            &attacker,
            KeyRole::Root,
        );
        let raw_err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("forged pubkey must fail");
        assert_eq!(raw_err.kind, core_types::ValidationErrorKind::Unauthorized);
        assert!(raw_err.to_string().contains("presence Device"));

        let sanitized_err = auth
            .authorize(&event, &state, 0)
            .expect_err("authorize must also reject");
        assert_eq!(
            sanitized_err.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(!sanitized_err.to_string().contains("presence Device"));
        assert!(sanitized_err.to_string().contains("unauthorized"));
    }

    // ── P79.1a L-3: DisclosureRevoked revoker == original issuer cross-check ──

    fn state_with_disclosure(artifact_id: &str, issuer_persona_id: &str) -> MaterializedState {
        let mut state = two_root_state();
        state.disclosures_current.insert(
            artifact_id.into(),
            crate::DisclosureRecord {
                artifact_id: artifact_id.into(),
                issuer_persona_id: issuer_persona_id.into(),
            },
        );
        state
    }

    fn make_disclosure_revoke_event(
        artifact_id: &str,
        revoker: &str,
        key: &str,
    ) -> core_events::EventEnvelope {
        make_event(
            "evt-disclosure-revoke",
            EventBody::DisclosureRevoked(core_event_types::DisclosureRevokedEvent {
                revocation_id: "rev-1".into(),
                artifact_id: artifact_id.into(),
                revoker_persona_id: revoker.into(),
                reason: "test".into(),
            }),
            SignerBinding::persona(revoker, key),
        )
    }

    #[test]
    fn disclosure_revoke_by_original_issuer_allowed() {
        // persona-a issued the disclosure and revokes it — must be accepted.
        let state = state_with_disclosure("artifact-1", "persona-a");
        let auth = IdentityAuthorizer;
        let event = make_disclosure_revoke_event("artifact-1", "persona-a", "key-persona-a");
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "original issuer may revoke their own disclosure"
        );
    }

    #[test]
    fn disclosure_revoke_by_non_issuer_rejected() {
        // persona-a issued the disclosure; persona-b tries to revoke it — must fail.
        let state = state_with_disclosure("artifact-1", "persona-a");
        let auth = IdentityAuthorizer;
        let event = make_disclosure_revoke_event("artifact-1", "persona-b", "key-persona-b");
        let err = auth
            .authorize_raw(&event, &state, 0)
            .expect_err("non-issuer disclosure revoke must fail");
        assert_eq!(err.kind, core_types::ValidationErrorKind::Unauthorized);
        assert!(
            err.to_string().contains("only the original issuer"),
            "error should mention original issuer restriction: {err}"
        );
        // Public authorize collapses to generic message.
        let sanitized = auth
            .authorize(&event, &state, 0)
            .expect_err("public authorize must also reject");
        assert_eq!(
            sanitized.kind,
            core_types::ValidationErrorKind::Unauthorized
        );
        assert!(!sanitized.to_string().contains("only the original issuer"));
    }

    #[test]
    fn disclosure_revoke_unknown_artifact_passes_through() {
        // Disclosure not in local state → pass through (cross-device delivery;
        // issuer-side replay catches violations).
        let state = two_root_state();
        let auth = IdentityAuthorizer;
        let event = make_disclosure_revoke_event("artifact-unknown", "persona-a", "key-persona-a");
        assert!(
            auth.authorize(&event, &state, 0).is_ok(),
            "unknown artifact must pass through at authorize layer",
        );
    }
}
