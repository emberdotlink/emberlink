use std::collections::{BTreeMap, BTreeSet};

use core_events::EventEnvelope;
use core_trust::derive_public_statements;
use core_types::{
    EndpointDescriptor, EventBody, FileManifest, TrustAttestation, Validate, ValidationError,
};

use crate::{
    DeviceRecord, DeviceStatus, GuardianRecord, MaterializedState, PersonaRecord, PersonaStatus,
    RecoveryPolicyRecord, RecoveryRequestRecord, RecoveryRequestStatus, RootRecord, RootStatus,
};

pub(crate) fn apply_event(
    state: &mut MaterializedState,
    event: &EventEnvelope,
) -> Result<(), ValidationError> {
    match &event.body {
        EventBody::RootCreated(body) => {
            if state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "root already exists: {}",
                    body.root_id
                )));
            }
            state.roots_current.insert(
                body.root_id.clone(),
                RootRecord {
                    root_id: body.root_id.clone(),
                    display_name: body.display_name.clone(),
                    active_key: body.initial_key.clone(),
                    status: RootStatus::Active,
                },
            );
            push_key_history(
                &mut state.root_key_history,
                &body.root_id,
                &body.initial_key.key_id,
            );
        }
        EventBody::RootKeyRotated(body) => {
            let root = state
                .roots_current
                .get_mut(&body.root_id)
                .ok_or_else(|| ValidationError::new(format!("unknown root: {}", body.root_id)))?;
            if root.active_key.key_id != body.previous_key_id {
                return Err(ValidationError::new(
                    "root rotation previous key does not match current state",
                ));
            }
            root.active_key = body.new_key.clone();
            push_key_history(
                &mut state.root_key_history,
                &body.root_id,
                &body.new_key.key_id,
            );
        }
        EventBody::RootRevoked(body) => {
            let root = state
                .roots_current
                .get_mut(&body.root_id)
                .ok_or_else(|| ValidationError::new(format!("unknown root: {}", body.root_id)))?;
            root.status = RootStatus::Revoked;
        }
        EventBody::DeviceAdded(body) => {
            if !state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "device references unknown root: {}",
                    body.root_id
                )));
            }
            if state.devices_current.contains_key(&body.device_id) {
                return Err(ValidationError::new(format!(
                    "device already exists: {}",
                    body.device_id
                )));
            }
            state.devices_current.insert(
                body.device_id.clone(),
                DeviceRecord {
                    root_id: body.root_id.clone(),
                    device_id: body.device_id.clone(),
                    label: body.label.clone(),
                    active_key: body.initial_key.clone(),
                    active_encryption_key: body.initial_encryption_key.clone(),
                    status: DeviceStatus::Active,
                    replacement_device_id: None,
                },
            );
            push_key_history(
                &mut state.device_key_history,
                &body.device_id,
                &body.initial_key.key_id,
            );
            push_key_history(
                &mut state.device_encryption_key_history,
                &body.device_id,
                &body.initial_encryption_key.key_id,
            );
        }
        EventBody::DeviceKeyRotated(body) => {
            let device = state
                .devices_current
                .get_mut(&body.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown device: {}", body.device_id))
                })?;
            if device.active_key.key_id != body.previous_key_id {
                return Err(ValidationError::new(
                    "device rotation previous key does not match current state",
                ));
            }
            device.active_key = body.new_key.clone();
            push_key_history(
                &mut state.device_key_history,
                &body.device_id,
                &body.new_key.key_id,
            );
        }
        EventBody::DeviceEncryptionKeyRotated(body) => {
            let device = state
                .devices_current
                .get_mut(&body.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown device: {}", body.device_id))
                })?;
            if device.active_encryption_key.key_id != body.previous_encryption_key_id {
                return Err(ValidationError::new(
                    "device encryption rotation previous key does not match current state",
                ));
            }
            device.active_encryption_key = body.new_encryption_key.clone();
            push_key_history(
                &mut state.device_encryption_key_history,
                &body.device_id,
                &body.new_encryption_key.key_id,
            );
        }
        EventBody::DeviceRevoked(body) => {
            let device = state
                .devices_current
                .get_mut(&body.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown device: {}", body.device_id))
                })?;
            device.status = DeviceStatus::Revoked;
        }
        EventBody::DeviceFrozen(body) => {
            let device = state
                .devices_current
                .get_mut(&body.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown device: {}", body.device_id))
                })?;
            device.status = DeviceStatus::Frozen;
        }
        EventBody::DeviceReplaced(body) => {
            if !state
                .devices_current
                .contains_key(&body.replacement_device_id)
            {
                return Err(ValidationError::new(format!(
                    "replacement device does not exist: {}",
                    body.replacement_device_id
                )));
            }
            let device = state
                .devices_current
                .get_mut(&body.replaced_device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "unknown replaced device: {}",
                        body.replaced_device_id
                    ))
                })?;
            device.status = DeviceStatus::Replaced;
            device.replacement_device_id = Some(body.replacement_device_id.clone());
        }
        EventBody::PersonaCreated(body) => {
            if !state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "persona references unknown root: {}",
                    body.root_id
                )));
            }
            if state.personas_current.contains_key(&body.persona_id) {
                return Err(ValidationError::new(format!(
                    "persona already exists: {}",
                    body.persona_id
                )));
            }
            state.personas_current.insert(
                body.persona_id.clone(),
                PersonaRecord {
                    root_id: body.root_id.clone(),
                    persona_id: body.persona_id.clone(),
                    label: body.label.clone(),
                    disclosure_profile: body.disclosure_profile.clone(),
                    survival_mode: body.survival_mode,
                    active_key: body.initial_key.clone(),
                    status: PersonaStatus::Active,
                },
            );
            push_key_history(
                &mut state.persona_key_history,
                &body.persona_id,
                &body.initial_key.key_id,
            );
        }
        EventBody::PersonaKeyRotated(body) => {
            let persona = state
                .personas_current
                .get_mut(&body.persona_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown persona: {}", body.persona_id))
                })?;
            if persona.active_key.key_id != body.previous_key_id {
                return Err(ValidationError::new(
                    "persona rotation previous key does not match current state",
                ));
            }
            persona.active_key = body.new_key.clone();
            push_key_history(
                &mut state.persona_key_history,
                &body.persona_id,
                &body.new_key.key_id,
            );
        }
        EventBody::PersonaRevoked(body) => {
            let persona = state
                .personas_current
                .get_mut(&body.persona_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown persona: {}", body.persona_id))
                })?;
            persona.status = PersonaStatus::Revoked;
        }
        EventBody::TrustAttested(body) => {
            if !state
                .personas_current
                .contains_key(&body.attester_persona_id)
            {
                return Err(ValidationError::new(format!(
                    "unknown attester persona: {}",
                    body.attester_persona_id
                )));
            }
            if !state
                .personas_current
                .contains_key(&body.subject_persona_id)
            {
                return Err(ValidationError::new(format!(
                    "unknown trust subject persona: {}",
                    body.subject_persona_id
                )));
            }
            state.trust_edges_current.insert(
                body.attestation_id.clone(),
                TrustAttestation {
                    id: body.attestation_id.clone(),
                    attester: body.attester_persona_id.clone(),
                    subject: body.subject_persona_id.clone(),
                    domain: body.domain.clone(),
                    score: body.score,
                    recipient_bound: body.recipient_bound.clone(),
                },
            );
            recompute_derived_trust(state);
        }
        EventBody::TrustRevoked(body) => {
            if let Some(existing) = state.trust_edges_current.get(&body.attestation_id)
                && existing.attester != body.attester_persona_id
            {
                return Err(ValidationError::new(
                    "trust revocation signer does not match original attester",
                ));
            }
            state.trust_edges_current.remove(&body.attestation_id);
            recompute_derived_trust(state);
        }
        EventBody::RecoveryPolicyCreated(body) => {
            state.recovery_policies_current.insert(
                body.root_id.clone(),
                RecoveryPolicyRecord {
                    root_id: body.root_id.clone(),
                    guardian_threshold: body.guardian_threshold,
                    cooldown_seconds: body.cooldown_seconds,
                },
            );
        }
        EventBody::GuardianEnrolled(body) => {
            state.guardians_current.insert(
                body.guardian_id.clone(),
                GuardianRecord {
                    guardian_id: body.guardian_id.clone(),
                    root_id: body.root_id.clone(),
                    label: body.guardian_label.clone(),
                    public_key: body.guardian_public_key.clone(),
                },
            );
        }
        EventBody::RecoveryRequested(body) => {
            if !state.devices_current.contains_key(&body.target_device_id) {
                return Err(ValidationError::new(format!(
                    "recovery target device does not exist: {}",
                    body.target_device_id
                )));
            }
            state.recovery_requests_current.insert(
                body.request_id.clone(),
                RecoveryRequestRecord {
                    request_id: body.request_id.clone(),
                    root_id: body.root_id.clone(),
                    target_device_id: body.target_device_id.clone(),
                    approvals: BTreeSet::new(),
                    contested_by: BTreeSet::new(),
                    status: RecoveryRequestStatus::Requested,
                    executed_scope: None,
                    cooldown_until: None,
                    contest_reason: None,
                    rejection_reason: None,
                },
            );
        }
        EventBody::RecoveryApproved(body) => {
            let request = state
                .recovery_requests_current
                .get_mut(&body.request_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown recovery request: {}", body.request_id))
                })?;
            if matches!(
                request.status,
                RecoveryRequestStatus::Contested
                    | RecoveryRequestStatus::Rejected
                    | RecoveryRequestStatus::Executed
            ) {
                return Err(ValidationError::new(
                    "cannot approve a contested, rejected, or executed recovery request",
                ));
            }
            request.approvals.insert(body.guardian_id.clone());
            let threshold = state
                .recovery_policies_current
                .get(&request.root_id)
                .map(|policy| policy.guardian_threshold)
                .unwrap_or(1);
            if request.approvals.len() >= threshold as usize {
                request.status = RecoveryRequestStatus::Approved;
            }
        }
        EventBody::RecoveryContested(body) => {
            let request = state
                .recovery_requests_current
                .get_mut(&body.request_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown recovery request: {}", body.request_id))
                })?;
            if matches!(
                request.status,
                RecoveryRequestStatus::Rejected | RecoveryRequestStatus::Executed
            ) {
                return Err(ValidationError::new(
                    "cannot contest a rejected or executed recovery request",
                ));
            }
            request.contested_by.insert(body.guardian_id.clone());
            request.status = RecoveryRequestStatus::Contested;
            let cooldown_secs = state
                .recovery_policies_current
                .get(&request.root_id)
                .map(|p| p.cooldown_seconds)
                .unwrap_or(0);
            request.cooldown_until = if cooldown_secs > 0 {
                Some(body.contested_at_epoch + cooldown_secs as u64)
            } else {
                None
            };
            request.contest_reason = Some(body.reason.clone());
        }
        EventBody::RecoveryRejected(body) => {
            let request = state
                .recovery_requests_current
                .get_mut(&body.request_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown recovery request: {}", body.request_id))
                })?;
            if request.status == RecoveryRequestStatus::Executed {
                return Err(ValidationError::new(
                    "cannot reject an executed recovery request",
                ));
            }
            request.status = RecoveryRequestStatus::Rejected;
            request.cooldown_until = None;
            request.rejection_reason = Some(body.reason.clone());
        }
        EventBody::RecoveryExecuted(body) => {
            let request = state
                .recovery_requests_current
                .get_mut(&body.request_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown recovery request: {}", body.request_id))
                })?;
            if request.cooldown_until.is_some() {
                return Err(ValidationError::new(
                    "recovery request is in cooldown after contest",
                ));
            }
            if request.status != RecoveryRequestStatus::Approved {
                return Err(ValidationError::new(
                    "recovery request must be approved before execution",
                ));
            }
            request.status = RecoveryRequestStatus::Executed;
            request.executed_scope = Some(body.executed_scope);
        }
        EventBody::RelayHintUpdated(body) => {
            let device = state.devices_current.get(&body.device_id).ok_or_else(|| {
                ValidationError::new(format!("unknown device: {}", body.device_id))
            })?;
            if device.status != DeviceStatus::Active {
                return Err(ValidationError::new(
                    "only active devices may advertise endpoint hints",
                ));
            }

            if let Some(existing) = state.endpoints_current.get(&body.peer_id)
                && existing.device_id != body.device_id
            {
                let existing_device =
                    state
                        .devices_current
                        .get(&existing.device_id)
                        .ok_or_else(|| {
                            ValidationError::new(format!(
                                "unknown existing endpoint device: {}",
                                existing.device_id
                            ))
                        })?;
                if existing_device.root_id != device.root_id {
                    return Err(ValidationError::new(
                        "endpoint peer id is already claimed by a different root",
                    ));
                }
            }

            state.endpoints_current.insert(
                body.peer_id.clone(),
                EndpointDescriptor {
                    peer_id: body.peer_id.clone(),
                    device_id: body.device_id.clone(),
                    transport_hint: body.transport_hint.clone(),
                },
            );
        }
        EventBody::EndpointRotated(body) => {
            let device = state.devices_current.get(&body.device_id).ok_or_else(|| {
                ValidationError::new(format!("unknown device: {}", body.device_id))
            })?;
            if device.status != DeviceStatus::Active {
                return Err(ValidationError::new(
                    "only active devices may rotate endpoint hints",
                ));
            }

            let endpoint = state
                .endpoints_current
                .get_mut(&body.peer_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown endpoint: {}", body.peer_id))
                })?;
            if endpoint.device_id != body.device_id {
                return Err(ValidationError::new(
                    "endpoint rotation device does not own current endpoint descriptor",
                ));
            }
            if endpoint.transport_hint != body.previous_transport_hint {
                return Err(ValidationError::new(
                    "endpoint rotation previous transport hint does not match current state",
                ));
            }
            endpoint.transport_hint = body.new_transport_hint.clone();
        }
        EventBody::StorageRelationshipCreated(body) => {
            if !state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "unknown root for storage relationship: {}",
                    body.root_id
                )));
            }
            state
                .storage_relationships_current
                .insert(body.relationship.id.clone(), body.relationship.clone());
        }
        EventBody::StorageLedgerUpdated(body) => {
            if !state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "unknown root for storage ledger update: {}",
                    body.root_id
                )));
            }
            if !state
                .storage_relationships_current
                .contains_key(&body.entry.relationship_id)
            {
                return Err(ValidationError::new(format!(
                    "unknown storage relationship for ledger update: {}",
                    body.entry.relationship_id
                )));
            }
            state
                .storage_balances_current
                .insert(body.entry.relationship_id.clone(), body.entry.clone());
        }
        EventBody::StorageManifestPublished(body) => {
            if !state.roots_current.contains_key(&body.root_id) {
                return Err(ValidationError::new(format!(
                    "unknown root for storage manifest: {}",
                    body.root_id
                )));
            }
        }
        EventBody::MessageSent(_) | EventBody::ContentPublished(_) => {}
        EventBody::DisclosureRevoked(_) => {}
        EventBody::RelayShutdownNotice(_) => {}
        EventBody::LegacyOpaque { .. } => {}
    }

    Ok(())
}

/// Returns true if the event type modifies materialized tables (roots, devices,
/// personas, trust, recovery, endpoints, storage relationships/ledger).
/// Events that are no-ops for materialization (messages, content, shutdown notices)
/// can skip the write_materialized_tables persistence step.
pub(crate) fn event_affects_materialized_state(event: &EventEnvelope) -> bool {
    !matches!(
        event.body,
        EventBody::MessageSent(_)
            | EventBody::ContentPublished(_)
            | EventBody::DisclosureRevoked(_)
            | EventBody::RelayShutdownNotice(_)
            | EventBody::StorageManifestPublished(_)
            | EventBody::LegacyOpaque { .. }
    )
}

pub(crate) fn push_key_history(
    history: &mut BTreeMap<String, Vec<String>>,
    entity_id: &str,
    key_id: &str,
) {
    let entries = history.entry(entity_id.to_string()).or_default();
    if !entries.iter().any(|existing| existing == key_id) {
        entries.push(key_id.to_string());
    }
}

pub(crate) fn recompute_derived_trust(state: &mut MaterializedState) {
    state.derived_trust_current = derive_public_statements(
        &state
            .trust_edges_current
            .values()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .map(|statement| (statement.id.clone(), statement))
    .collect();
}

pub(crate) fn apply_storage_event(
    manifests: &mut BTreeMap<String, FileManifest>,
    event: &EventEnvelope,
    state: &MaterializedState,
) -> Result<(), ValidationError> {
    if let EventBody::StorageManifestPublished(body) = &event.body {
        if !state.roots_current.contains_key(&body.root_id) {
            return Err(ValidationError::new(format!(
                "unknown root for storage manifest: {}",
                body.root_id
            )));
        }
        body.manifest.validate()?;
        for access in &body.manifest.authorized_devices {
            let device = state
                .devices_current
                .get(&access.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "storage manifest references unknown device: {}",
                        access.device_id
                    ))
                })?;
            if device.root_id != body.root_id {
                return Err(ValidationError::new(
                    "storage manifest authorized devices must belong to the publishing root",
                ));
            }
        }
        manifests.insert(body.manifest.id.clone(), body.manifest.clone());
    }
    Ok(())
}
