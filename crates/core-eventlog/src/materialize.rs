use std::collections::{BTreeMap, BTreeSet};

use core_events::EventEnvelope;
use core_trust::derive_public_statements;
use core_types::{
    EndpointDescriptor, EventBody, FileManifest, TrustAttestation, Validate, ValidationError,
};

use crate::{
    BadgeDisputeRecord, BadgeRecord, CredentialDepositRecord, CredentialDepositStatus,
    DeviceRecord, DeviceStatus, GrantOfferRecord, GrantOfferStatus, GuardianRecord,
    MaterializedState, PersonaRecord, PersonaStatus, RecoveryPolicyRecord, RecoveryRequestRecord,
    RecoveryRequestStatus, RootRecord, RootStatus,
};

pub fn apply_event(
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
            // Defense-in-depth: both devices must belong to the event's root_id.
            // authorize.rs only checks that the signer holds the root key for body.root_id;
            // without these ownership checks, a root could mark another root's device as
            // Replaced by a third root's device. See docs/the security review
            let replacement = state
                .devices_current
                .get(&body.replacement_device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "replacement device does not exist: {}",
                        body.replacement_device_id
                    ))
                })?;
            if replacement.root_id != body.root_id {
                return Err(ValidationError::new(format!(
                    "replacement device {} does not belong to root {}",
                    body.replacement_device_id, body.root_id
                )));
            }
            let replaced = state
                .devices_current
                .get(&body.replaced_device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "unknown replaced device: {}",
                        body.replaced_device_id
                    ))
                })?;
            if replaced.root_id != body.root_id {
                return Err(ValidationError::new(format!(
                    "replaced device {} does not belong to root {}",
                    body.replaced_device_id, body.root_id
                )));
            }
            // All checks passed — now mutate.
            let device = state
                .devices_current
                .get_mut(&body.replaced_device_id)
                .expect("replaced device existence already verified");
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
        EventBody::GuardianKeyRotated(body) => {
            let guardian = state
                .guardians_current
                .get_mut(&body.guardian_id)
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown guardian: {}", body.guardian_id))
                })?;
            if guardian.public_key != body.previous_key_id {
                return Err(ValidationError::new(
                    "guardian rotation previous key does not match current state",
                ));
            }
            guardian.public_key = body.new_guardian_public_key.clone();
        }
        EventBody::RecoveryRequested(body) => {
            // Defense-in-depth: reject duplicate request_id. Without this, a root can
            // replay RecoveryRequested with the same request_id to wipe accumulated
            // guardian approvals, cooldown, and contest state. authorize.rs does not
            // enforce uniqueness. See docs/the security review
            if state
                .recovery_requests_current
                .contains_key(&body.request_id)
            {
                return Err(ValidationError::new(format!(
                    "recovery request already exists: {}",
                    body.request_id
                )));
            }
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
        EventBody::GrantOfferCreated(body) => {
            state.grant_offers_current.insert(
                body.offer_id.clone(),
                GrantOfferRecord {
                    offer_id: body.offer_id.clone(),
                    issuer_persona_id: body.issuer_persona_id.clone(),
                    ephemeral_public_key_hex: body.ephemeral_public_key_hex.clone(),
                    sealed_payload_hex: body.sealed_payload_hex.clone(),
                    relay_hint: body.relay_hint.clone(),
                    expires_at: body.expires_at,
                    conditions_json: body.conditions_json.clone(),
                    status: GrantOfferStatus::Pending,
                    recipient_persona_id: None,
                    claim_response_hex: None,
                    claimed_at: None,
                },
            );
        }
        EventBody::GrantOfferClaimed(body) => {
            if let Some(offer) = state.grant_offers_current.get_mut(&body.offer_id) {
                offer.status = GrantOfferStatus::Claimed;
                offer.recipient_persona_id = Some(body.recipient_persona_id.clone());
                offer.claim_response_hex = Some(body.claim_response_hex.clone());
                offer.claimed_at = Some(body.claimed_at);
            }
        }
        EventBody::GrantOfferRevoked(body) => {
            if let Some(offer) = state.grant_offers_current.get_mut(&body.offer_id) {
                offer.status = GrantOfferStatus::Revoked;
            }
        }
        EventBody::BadgeIssued(body) => {
            state.badges_current.insert(
                body.badge_id.clone(),
                BadgeRecord {
                    badge_id: body.badge_id.clone(),
                    issuer_persona_id: body.issuer_persona_id.clone(),
                    recipient_persona_id: body.recipient_persona_id.clone(),
                    badge_type: body.badge_type.clone(),
                    display_name: body.display_name.clone(),
                    evidence: body.evidence.clone(),
                    issued_at: body.issued_at,
                    expires_at: body.expires_at,
                    revoked: false,
                    revoked_reason: None,
                },
            );
        }
        EventBody::BadgeRevoked(body) => {
            if let Some(badge) = state.badges_current.get_mut(&body.badge_id) {
                badge.revoked = true;
                badge.revoked_reason = Some(body.reason.clone());
            }
        }
        EventBody::BadgeDisputed(body) => {
            state.badge_disputes_current.insert(
                body.dispute_id.clone(),
                BadgeDisputeRecord {
                    dispute_id: body.dispute_id.clone(),
                    target_badge_id: body.target_badge_id.clone(),
                    disputer_persona_id: body.disputer_persona_id.clone(),
                    reason: body.reason.clone(),
                    evidence: body.evidence.clone(),
                },
            );
        }
        EventBody::CredentialDeposited(body) => {
            state.credential_deposits_current.insert(
                body.deposit_id.clone(),
                CredentialDepositRecord {
                    deposit_id: body.deposit_id.clone(),
                    grant_id: body.grant_id.clone(),
                    credential_id: body.credential_id.clone(),
                    issuer_id: body.issuer_id.clone(),
                    encrypted_blocks_json: body.encrypted_blocks_json.clone(),
                    status: CredentialDepositStatus::Active,
                    created_at: body.created_at,
                    expires_at: body.expires_at,
                    revoked_at: None,
                    revoked_reason: None,
                },
            );
        }
        EventBody::CredentialRevoked(body) => {
            // Find the deposit by grant_id and mark it revoked.
            for deposit in state.credential_deposits_current.values_mut() {
                if deposit.grant_id == body.grant_id {
                    deposit.status = CredentialDepositStatus::Revoked;
                    deposit.revoked_at = Some(body.revoked_at);
                    deposit.revoked_reason = Some(body.reason.clone());
                }
            }
        }
        EventBody::LegacyOpaque { .. } => {}
    }

    Ok(())
}

/// Returns true if the event type modifies materialized tables (roots, devices,
/// personas, trust, recovery, endpoints, storage relationships/ledger).
/// Events that are no-ops for materialization (messages, content, shutdown notices)
/// can skip the write_materialized_tables persistence step.
pub fn event_affects_materialized_state(event: &EventEnvelope) -> bool {
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

pub fn push_key_history(
    history: &mut BTreeMap<String, Vec<String>>,
    entity_id: &str,
    key_id: &str,
) {
    let entries = history.entry(entity_id.to_string()).or_default();
    if !entries.iter().any(|existing| existing == key_id) {
        entries.push(key_id.to_string());
    }
}

pub fn recompute_derived_trust(state: &mut MaterializedState) {
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

pub fn apply_storage_event(
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

#[cfg(test)]
mod tests {
    //! Adversarial regression tests for .1b materialize.rs review.
    //!
    //! These tests exercise `apply_event` directly against hand-crafted
    //! `MaterializedState` and `EventEnvelope` values to assert defense-in-depth
    //! invariants that are *not* enforced by `authorize.rs`. Integration-level
    //! authorize + materialize tests live in `authorize.rs` and `memory.rs`.
    use super::*;
    use core_crypto::FixtureSigner;
    use core_events::EventEnvelope;
    use core_types::{
        DeviceReplacedEvent, EventBody, KeyAlgorithm, PublicKeyMaterial, RecoveryRequestedEvent,
        SignerBinding,
    };

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

    fn make_event(event_id: &str, body: EventBody, signer_binding: SignerBinding) -> EventEnvelope {
        let signer = FixtureSigner::new(signer_binding.key_id.clone());
        EventEnvelope::from_body(event_id, body, vec![], signer_binding, &signer).unwrap()
    }

    fn two_root_state_with_three_devices() -> MaterializedState {
        let mut state = MaterializedState::default();
        for root in ["root-a", "root-b", "root-c"] {
            state.roots_current.insert(
                root.into(),
                RootRecord {
                    root_id: root.into(),
                    display_name: root.into(),
                    active_key: make_key(&format!("key-{root}")),
                    status: RootStatus::Active,
                },
            );
        }
        for (device, root) in [
            ("device-a", "root-a"),
            ("device-b", "root-b"),
            ("device-c", "root-c"),
        ] {
            state.devices_current.insert(
                device.into(),
                DeviceRecord {
                    root_id: root.into(),
                    device_id: device.into(),
                    label: device.into(),
                    active_key: make_key(&format!("key-{device}")),
                    active_encryption_key: make_enc_key(device),
                    status: DeviceStatus::Active,
                    replacement_device_id: None,
                },
            );
        }
        state
    }

    // ── .1b-: DeviceReplaced must verify both devices belong to the event's root ──

    #[test]
    fn device_replaced_rejects_cross_root_replaced_device() {
        let mut state = two_root_state_with_three_devices();
        // root-a tries to mark root-b's device-b as replaced by its own device-a.
        let event = make_event(
            "evt-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-b".into(), // owned by root-b!
                replacement_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = apply_event(&mut state, &event);
        assert!(result.is_err(), "cross-root replaced_device must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("device-b") && err.contains("root-a"),
            "error should mention ownership mismatch, got: {err}"
        );
        // State must be unchanged.
        assert_eq!(
            state.devices_current["device-b"].status,
            DeviceStatus::Active,
            "device-b must remain Active after rejected replacement"
        );
        assert!(
            state.devices_current["device-b"]
                .replacement_device_id
                .is_none(),
            "device-b must not record a replacement after rejection"
        );
    }

    #[test]
    fn device_replaced_rejects_cross_root_replacement_device() {
        let mut state = two_root_state_with_three_devices();
        // root-a says its own device-a is replaced by root-c's device-c.
        let event = make_event(
            "evt-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-c".into(), // owned by root-c!
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = apply_event(&mut state, &event);
        assert!(
            result.is_err(),
            "cross-root replacement_device must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("device-c") && err.contains("root-a"),
            "error should mention ownership mismatch, got: {err}"
        );
        assert_eq!(
            state.devices_current["device-a"].status,
            DeviceStatus::Active,
            "device-a must remain Active after rejected replacement"
        );
    }

    #[test]
    fn device_replaced_same_root_allowed() {
        let mut state = two_root_state_with_three_devices();
        // Add a second device under root-a.
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
            },
        );
        let event = make_event(
            "evt-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-a2".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &event).expect("same-root replacement must succeed");
        assert_eq!(
            state.devices_current["device-a"].status,
            DeviceStatus::Replaced
        );
        assert_eq!(
            state.devices_current["device-a"].replacement_device_id,
            Some("device-a2".into())
        );
    }

    // ── .1b-: RecoveryRequested must reject duplicate request_id ──

    fn state_with_recovery_context() -> MaterializedState {
        let mut state = two_root_state_with_three_devices();
        state.recovery_policies_current.insert(
            "root-a".into(),
            RecoveryPolicyRecord {
                root_id: "root-a".into(),
                guardian_threshold: 2,
                cooldown_seconds: 3600,
            },
        );
        state.guardians_current.insert(
            "guardian-1".into(),
            GuardianRecord {
                guardian_id: "guardian-1".into(),
                root_id: "root-a".into(),
                label: "G1".into(),
                public_key: "key-g1".into(),
            },
        );
        state
    }

    #[test]
    fn recovery_requested_rejects_duplicate_request_id() {
        let mut state = state_with_recovery_context();
        let event1 = make_event(
            "evt-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "req-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &event1).expect("first recovery request should succeed");

        // Simulate gathered approvals + contest state.
        let req = state
            .recovery_requests_current
            .get_mut("req-1")
            .expect("request should exist");
        req.approvals.insert("guardian-1".into());
        req.status = RecoveryRequestStatus::Contested;
        req.cooldown_until = Some(1000);
        req.contest_reason = Some("suspicious".into());

        // Replay RecoveryRequested with the same request_id.
        let event2 = make_event(
            "evt-2",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "req-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = apply_event(&mut state, &event2);
        assert!(
            result.is_err(),
            "duplicate RecoveryRequested must be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("already exists"),
            "error should mention duplicate"
        );

        // State must preserve the in-flight request — approvals, cooldown, contest reason intact.
        let preserved = &state.recovery_requests_current["req-1"];
        assert!(
            preserved.approvals.contains("guardian-1"),
            "approvals must not be wiped"
        );
        assert_eq!(preserved.status, RecoveryRequestStatus::Contested);
        assert_eq!(preserved.cooldown_until, Some(1000));
        assert_eq!(preserved.contest_reason, Some("suspicious".into()));
    }

    #[test]
    fn recovery_requested_unique_id_succeeds() {
        let mut state = state_with_recovery_context();
        let event1 = make_event(
            "evt-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "req-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &event1).expect("first request");

        let event2 = make_event(
            "evt-2",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "req-2".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &event2).expect("distinct request_id must succeed");
        assert_eq!(state.recovery_requests_current.len(), 2);
    }
}
