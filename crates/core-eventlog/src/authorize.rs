use core_events::EventEnvelope;
use core_types::{EventBody, KeyRole, SignerBinding, ValidationError};

use crate::{
    DeviceStatus, GrantOfferStatus, MaterializedState, PersonaStatus, RecoveryRequestStatus,
    RootStatus,
};

pub trait Authorizer {
    fn authorize(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllAuthorizer;

impl Authorizer for AllowAllAuthorizer {
    fn authorize(
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

impl Authorizer for IdentityAuthorizer {
    fn authorize(
        &self,
        event: &EventEnvelope,
        state: &MaterializedState,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        match &event.body {
            EventBody::RootCreated(_) => Ok(()),
            EventBody::RootKeyRotated(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::RootRevoked(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::DeviceAdded(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::PersonaCreated(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::DeviceKeyRotated(body) => {
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::DeviceEncryptionKeyRotated(body) => {
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::DeviceRevoked(body) => {
                if authorize_root_key(&event.signer_binding, &body.root_id, state).is_ok() {
                    require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::DeviceFrozen(body) => {
                if authorize_root_key(&event.signer_binding, &body.root_id, state).is_ok() {
                    require_device_owned_by_root(&body.device_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::DeviceReplaced(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::PersonaKeyRotated(body) => {
                authorize_persona_key(&event.signer_binding, &body.persona_id, state)
            }
            EventBody::PersonaRevoked(body) => {
                if authorize_root_key(&event.signer_binding, &body.root_id, state).is_ok() {
                    require_persona_owned_by_root(&body.persona_id, &body.root_id, state)?;
                    return Ok(());
                }
                authorize_persona_key(&event.signer_binding, &body.persona_id, state)
            }
            EventBody::TrustAttested(body) => {
                authorize_persona_key(&event.signer_binding, &body.attester_persona_id, state)
            }
            EventBody::TrustRevoked(body) => {
                authorize_persona_key(&event.signer_binding, &body.attester_persona_id, state)?;
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
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::RecoveryRequested(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::GuardianEnrolled(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
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
                authorize_root_key(&event.signer_binding, &request.root_id, state)
            }
            EventBody::RecoveryExecuted(body) => {
                let request = state
                    .recovery_requests_current
                    .get(&body.request_id)
                    .ok_or_else(|| {
                        ValidationError::not_found("recovery request", &body.request_id)
                    })?;
                if let Some(until) = request.cooldown_until
                    && now_epoch_secs < until
                {
                    return Err(ValidationError::state_violation(
                        "recovery request is in cooldown after contest",
                    ));
                }
                if request.status != RecoveryRequestStatus::Approved {
                    return Err(ValidationError::state_violation(
                        "recovery request must be approved before execution",
                    ));
                }
                authorize_root_key(&event.signer_binding, &request.root_id, state)
            }
            EventBody::RelayHintUpdated(body) => {
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::EndpointRotated(body) => {
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            // Shutdown notices are relay-operator actions; no identity authority required
            EventBody::RelayShutdownNotice(_) => Ok(()),
            EventBody::StorageRelationshipCreated(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::StorageLedgerUpdated(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::StorageManifestPublished(body) => {
                authorize_root_key(&event.signer_binding, &body.root_id, state)
            }
            EventBody::MessageSent(body) => {
                authorize_persona_key(&event.signer_binding, &body.sender_persona_id, state)
            }
            EventBody::ContentPublished(body) => {
                authorize_persona_key(&event.signer_binding, &body.author_persona_id, state)
            }
            EventBody::DisclosureRevoked(body) => {
                authorize_persona_key(&event.signer_binding, &body.revoker_persona_id, state)
            }
            EventBody::GrantOfferCreated(body) => {
                authorize_persona_key(&event.signer_binding, &body.issuer_persona_id, state)
            }
            EventBody::GrantOfferClaimed(body) => {
                authorize_persona_key(&event.signer_binding, &body.recipient_persona_id, state)?;
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
                    if now_epoch_secs >= offer.expires_at {
                        return Err(ValidationError::state_violation(
                            "grant offer has expired",
                        ));
                    }
                }
                Ok(())
            }
            EventBody::GrantOfferRevoked(body) => {
                authorize_persona_key(&event.signer_binding, &body.issuer_persona_id, state)?;
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
            EventBody::BadgeIssued(body) => {
                authorize_persona_key(&event.signer_binding, &body.issuer_persona_id, state)
            }
            EventBody::BadgeRevoked(body) => {
                authorize_persona_key(&event.signer_binding, &body.revoker_persona_id, state)?;
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
            EventBody::BadgeDisputed(body) => {
                authorize_persona_key(&event.signer_binding, &body.disputer_persona_id, state)
            }
            EventBody::CredentialDeposited(body) => {
                authorize_persona_key(&event.signer_binding, &body.issuer_id, state)
            }
            EventBody::CredentialRevoked(body) => {
                authorize_persona_key(&event.signer_binding, &body.revoker_id, state)?;
                // Verify a deposit exists for this grant and the revoker is the original issuer.
                let deposit = state
                    .credential_deposits_current
                    .values()
                    .find(|d| d.grant_id == body.grant_id);
                match deposit {
                    Some(d) if d.issuer_id != body.revoker_id => {
                        Err(ValidationError::unauthorized(
                            "credential revocation signer does not match original issuer",
                        ))
                    }
                    Some(_) => Ok(()),
                    None => Err(ValidationError::unauthorized(
                        "no credential deposit found for grant",
                    )),
                }
            }
            EventBody::LegacyOpaque { .. } => Ok(()),
        }
    }
}

fn authorize_root_key(
    signer_binding: &SignerBinding,
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
    if root.active_key.key_id != signer_binding.key_id {
        return Err(ValidationError::unauthorized(format!(
            "signer key {} does not match active root key for {}",
            signer_binding.key_id, root_id
        )));
    }
    Ok(())
}

fn authorize_device_key(
    signer_binding: &SignerBinding,
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
    Ok(())
}

fn authorize_persona_key(
    signer_binding: &SignerBinding,
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
    if persona.status != PersonaStatus::Active {
        return Err(ValidationError::state_violation(format!(
            "persona {} is not active",
            persona_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::FixtureSigner;
    use core_events::EventEnvelope;
    use core_types::{
        DeviceFrozenEvent, DeviceRevokedEvent, EventBody, KeyAlgorithm, PersonaRevokedEvent,
        PublicKeyMaterial, RootCreatedEvent, SignerBinding, SurvivalMode,
    };

    use crate::{DeviceRecord, PersonaRecord, RootRecord};

    fn make_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: format!("ed25519:{key_id}"),
        }
    }

    fn make_enc_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    fn make_event(
        event_id: &str,
        body: EventBody,
        signer_binding: SignerBinding,
    ) -> EventEnvelope {
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

    // ── 16.1: Cross-root revoke/freeze must be rejected ──

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
        let result = auth.authorize(&event, &state, 0);
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
            EventBody::DeviceAdded(core_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-new".into(),
                label: "New".into(),
                initial_key: make_key("key-new"),
                initial_encryption_key: make_enc_key("new"),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = auth.authorize(&event, &state, 0);
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
            EventBody::PersonaCreated(core_types::PersonaCreatedEvent {
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

    // ── C-1: GrantOfferClaimed offer status/expiry checks ──

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
            EventBody::GrantOfferClaimed(core_types::GrantOfferClaimedEvent {
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
        let result = auth.authorize(&event, &state, 1000); // now = 1000 > 500
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
        let result = auth.authorize(&event, &state, 100);
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

    // ── C-2: GrantOfferRevoked issuer ownership check ──

    fn make_revoke_offer_event(
        offer_id: &str,
        issuer: &str,
        key: &str,
        reason: &str,
    ) -> core_events::EventEnvelope {
        make_event(
            "evt-revoke-offer",
            EventBody::GrantOfferRevoked(core_types::GrantOfferRevokedEvent {
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
        let result = auth.authorize(&event, &state, 100);
        assert!(result.is_err(), "non-issuer offer revoke must fail");
        assert!(
            result.unwrap_err().to_string().contains("does not match original issuer"),
            "error should mention issuer mismatch"
        );
    }

    #[test]
    fn grant_offer_revoke_by_issuer_allowed() {
        let state = state_with_pending_offer(9999);
        let auth = IdentityAuthorizer;
        // persona-a is the issuer — should succeed
        let event = make_revoke_offer_event("offer-1", "persona-a", "key-persona-a", "changed mind");
        assert!(
            auth.authorize(&event, &state, 100).is_ok(),
            "issuer may revoke their own offer"
        );
    }

    // ── C-3: BadgeRevoked issuer ownership check ──

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
            EventBody::BadgeRevoked(core_types::BadgeRevokedEvent {
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
        let result = auth.authorize(&event, &state, 0);
        assert!(result.is_err(), "non-issuer badge revoke must fail");
        assert!(
            result.unwrap_err().to_string().contains("does not match original issuer"),
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
}
