use core_events::EventEnvelope;
use core_types::{EventBody, KeyRole, SignerBinding, ValidationError};

use crate::{DeviceStatus, MaterializedState, PersonaStatus, RecoveryRequestStatus};

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
                    return Ok(());
                }
                authorize_device_key(&event.signer_binding, &body.device_id, state)
            }
            EventBody::DeviceFrozen(body) => {
                if authorize_root_key(&event.signer_binding, &body.root_id, state).is_ok() {
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
