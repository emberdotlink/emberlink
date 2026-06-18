use std::collections::{BTreeMap, BTreeSet};

use core_event_types::{
    AttestationTier, CustodyClass, EventBody, EventRefRelation, FileManifest, PresenceFactor,
};
use core_events::{EventEnvelope, EventRef};
use core_grant_types::grant_conditions::{GrantCondition, MAX_CONDITION_DEPTH};
use core_principals::{EndpointDescriptor, TrustAttestation};
use core_trust::derive_public_statements;
use core_types::{Validate, ValidationError};

use crate::{
    BadgeDisputeRecord, BadgeRecord, CredentialDepositRecord, CredentialDepositStatus,
    DeviceRecord, DeviceStatus, GrantOfferRecord, GrantOfferStatus, GuardianRecord,
    MaterializedState, PersonaRecord, PersonaStatus, RecoveryPolicyRecord, RecoveryRequestRecord,
    RecoveryRequestStatus, RootRecord, RootStatus,
};

/// Enforce `prev_event_id` chaining and per-root monotonic sequence.
///
/// Finds the `Previous` ref (if present) and:
/// 1. Asserts `ref.target_event_id == current_head.event_id` (no fork).
/// 2. Asserts `ref.seq == current_head.seq + 1` (no skip, no replay).
///
/// Must be called BEFORE `apply_event` so the check runs against the current
/// head, not the post-mutation state.
///
/// Events with no `Previous` ref (e.g. genesis `RootCreated`) and events
/// whose `root_id` cannot be determined from the body alone are skipped.
pub fn check_chain(
    state: &MaterializedState,
    event: &EventEnvelope,
) -> Result<(), ValidationError> {
    let root_id = match event.body.root_id() {
        Some(id) => id,
        None => return Ok(()),
    };

    let prev_ref: Option<&EventRef> = event
        .refs
        .iter()
        .find(|r| r.relation == EventRefRelation::Previous);

    match (prev_ref, state.root_chain_heads.get(root_id)) {
        // No previous ref and no known head → genesis event, allow.
        (None, None) => Ok(()),
        // No previous ref but a head exists → event is missing a required chain ref.
        (None, Some((head_event_id, head_seq))) => Err(ValidationError::state_violation(format!(
            "out-of-order event: missing Previous ref for root {root_id}; \
             expected prev_event_id={head_event_id} seq={}",
            head_seq + 1,
        ))),
        // Previous ref but no head → references a non-existent predecessor.
        (Some(r), None) => Err(ValidationError::state_violation(format!(
            "out-of-order event: Previous ref points to {} but root {} has no chain head",
            r.target_event_id, root_id,
        ))),
        // Previous ref and known head → enforce both checks.
        (Some(r), Some((head_event_id, head_seq))) => {
            let expected_seq = head_seq + 1;
            if r.target_event_id != *head_event_id || r.seq != expected_seq {
                return Err(ValidationError::state_violation(format!(
                    "out-of-order event: expected prev_event_id={head_event_id} seq={expected_seq}, \
                     got prev_event_id={} seq={}",
                    r.target_event_id, r.seq,
                )));
            }
            Ok(())
        }
    }
}

/// Update the per-root chain head after an event has been accepted.
///
/// Must be called AFTER `apply_event` succeeds. For events with a `Previous`
/// ref the new `last_seq` is taken from `ref.seq`. For genesis events (no
/// Previous ref, no existing head) `last_seq` is set to `0`.
pub fn advance_chain_head(state: &mut MaterializedState, event: &EventEnvelope) {
    let root_id = match event.body.root_id() {
        Some(id) => id.to_owned(),
        None => return,
    };

    let seq = event
        .refs
        .iter()
        .find(|r| r.relation == EventRefRelation::Previous)
        .map(|r| r.seq)
        .unwrap_or(0);

    state
        .root_chain_heads
        .insert(root_id, (event.event_id.clone(), seq));
}

/// Compute the maximum nesting depth of a `serde_json::Value`.
///
/// Depth of a scalar (null, bool, number, string) is `0`. Each `Array` or
/// `Object` layer adds 1 to the deepest child. Used by `apply_event` to
/// reject signed-payload JSON whose nesting exceeds [`MAX_CONDITION_DEPTH`]
/// before any structured deserialization (which itself recurses) is attempted.
/// Defence in depth alongside `GrantCondition::validate_depth`.
pub(crate) fn json_max_depth(v: &serde_json::Value) -> u32 {
    match v {
        serde_json::Value::Array(arr) => {
            arr.iter().map(|x| 1 + json_max_depth(x)).max().unwrap_or(0)
        }
        serde_json::Value::Object(map) => map
            .values()
            .map(|x| 1 + json_max_depth(x))
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}

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
                    // A `DeviceAdded` device is one whose key the daemon holds
                    // (ADR 200 §1) — i.e. `daemon`-class, no attestation, no human
                    // presence gate (unattended).
                    custody_class: CustodyClass::Daemon,
                    attestation_statement: None,
                    attestation_tier: AttestationTier::None,
                    presence_factor: PresenceFactor::Unattended,
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
        EventBody::DeviceEnrolled(body) => {
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
            // Structural invariant (ADR 200 §3, two-axis): an attestation-backed
            // TIER (or co-authority custody) must carry its recorded statement.
            // The cryptographic chain verification against the binary-embedded
            // vendor roots happens in `verify_chain` (the independent verifier,
            // AC-1) — here the presence of the statement is the materialization-
            // level invariant. The `AttestationTier::None` dev0 floor carries none.
            let statement_required = body.attestation_tier.requires_statement()
                || body.custody_class == CustodyClass::CoAuthority;
            if statement_required
                && body
                    .attestation_statement
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                return Err(ValidationError::new(format!(
                    "custody class {} at attestation tier {} requires a recorded attestation statement",
                    body.custody_class.as_str(),
                    body.attestation_tier.as_str(),
                )));
            }
            state.devices_current.insert(
                body.device_id.clone(),
                DeviceRecord {
                    root_id: body.root_id.clone(),
                    device_id: body.device_id.clone(),
                    label: body.label.clone(),
                    active_key: body.device_key.clone(),
                    // ADR 206 §4 (presence-as-decryption): an enrolled `presence`
                    // Device carries a DISTINCT ECIES recipient key, never the
                    // signing key. macOS SE cannot enforce sign-vs-decrypt usage
                    // on one key (§4 AC-3), so reusing `device_key` here would
                    // collapse the very sign==decrypt separation the cut kills.
                    // Enrollment provisions a second `UserPresence` SE key for
                    // this slot; §4 seals scope KEKs to it.
                    active_encryption_key: body.encryption_key.clone(),
                    status: DeviceStatus::Active,
                    replacement_device_id: None,
                    custody_class: body.custody_class,
                    attestation_statement: body.attestation_statement.clone(),
                    attestation_tier: body.attestation_tier,
                    presence_factor: body.presence_factor,
                },
            );
            push_key_history(
                &mut state.device_key_history,
                &body.device_id,
                &body.device_key.key_id,
            );
            push_key_history(
                &mut state.device_encryption_key_history,
                &body.device_id,
                &body.encryption_key.key_id,
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
            // Replaced by a third root's device. See docs/security-reviews/materialize-rs-2026-04-22.md.
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
            // enforce uniqueness. See docs/security-reviews/materialize-rs-2026-04-22.md.
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
            // Validate conditions_json depth before materializing. The
            // per-field size cap (MAX_CONDITIONS_JSON_BYTES = 8 KiB) is
            // enforced by GrantOfferCreatedEvent::validate() at event ingress,
            // which is stricter than the 100 KiB target.
            // TODO: if conditions_json is ever moved to a separate
            // storage path that bypasses event validation, add an explicit
            // 100 KiB byte-length check here.
            if !body.conditions_json.is_empty() {
                // Traverse the raw JSON once before structured
                // deserialization to reject deeply-nested payloads early.
                // `serde_json::from_str::<Vec<GrantCondition>>` itself recurses
                // and could blow the stack on adversarial input; a flat
                // `Value` parse is bounded by serde_json's own depth guard
                // and gives us a cheap pre-check.
                let raw_value: serde_json::Value = serde_json::from_str(&body.conditions_json)
                    .map_err(|e| {
                        ValidationError::invalid_format(format!(
                            "grant offer conditions_json is not valid JSON: {e}"
                        ))
                    })?;
                let depth = json_max_depth(&raw_value);
                if depth > MAX_CONDITION_DEPTH {
                    return Err(ValidationError::invalid_format(format!(
                        "grant offer conditions_json rejected: JSON nesting depth \
                         {depth} exceeds maximum of {MAX_CONDITION_DEPTH}"
                    )));
                }
                let conditions: Vec<GrantCondition> =
                    serde_json::from_value(raw_value).map_err(|e| {
                        ValidationError::invalid_format(format!(
                            "grant offer conditions_json is not valid JSON: {e}"
                        ))
                    })?;
                for condition in &conditions {
                    condition.validate_depth().map_err(|e| {
                        ValidationError::invalid_format(format!(
                            "grant offer conditions_json rejected: {e}"
                        ))
                    })?;
                }
            }
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
    //! Adversarial regression tests for P79.1b materialize.rs review.
    //!
    //! These tests exercise `apply_event` directly against hand-crafted
    //! `MaterializedState` and `EventEnvelope` values to assert defense-in-depth
    //! invariants that are *not* enforced by `authorize.rs`. Integration-level
    //! authorize + materialize tests live in `authorize.rs` and `memory.rs`.
    use super::*;
    use core_crypto::FixtureSigner;
    use core_event_types::{
        DeviceEnrolledEvent, DeviceReplacedEvent, EventBody, EventSubject, KeyRole,
        RecoveryApprovedEvent, RecoveryContestedEvent, RecoveryExecutedEvent,
        RecoveryRejectedEvent, RecoveryRequestedEvent, RootCreatedEvent, SignerBinding,
        SubjectKind,
    };
    use core_events::{EventEnvelope, EventRef as CrateEventRef};
    use core_principals::{KeyAlgorithm, PublicKeyMaterial, RecoveryScope};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

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
                    custody_class: CustodyClass::Daemon,
                    attestation_statement: None,
                    attestation_tier: AttestationTier::None,
                    presence_factor: PresenceFactor::Unattended,
                },
            );
        }
        state
    }

    // ── P79.1b-P0: DeviceReplaced must verify both devices belong to the event's root ──

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
        assert!(
            result.is_err(),
            "cross-root replaced_device must be rejected"
        );
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
                custody_class: CustodyClass::Daemon,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::Unattended,
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

    // ── P79.1b-P0: RecoveryRequested must reject duplicate request_id ──

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

    // Anchor: core_recovery_proptest_lifecycle_landed
    #[derive(Clone, Debug)]
    enum RecoveryOp {
        Request {
            slot: u8,
            target_device_exists: bool,
        },
        Approve {
            slot: u8,
            guardian: u8,
        },
        Contest {
            slot: u8,
            guardian: u8,
            reason: u8,
            contested_at_epoch: u64,
        },
        Reject {
            slot: u8,
            reason: u8,
        },
        Execute {
            slot: u8,
            scope: RecoveryScope,
        },
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ExpectedRecoveryRequest {
        root_id: String,
        target_device_id: String,
        approvals: BTreeSet<String>,
        contested_by: BTreeSet<String>,
        status: RecoveryRequestStatus,
        executed_scope: Option<RecoveryScope>,
        cooldown_until: Option<u64>,
        contest_reason: Option<String>,
        rejection_reason: Option<String>,
    }

    fn arb_recovery_scope() -> impl Strategy<Value = RecoveryScope> {
        prop_oneof![
            Just(RecoveryScope::FreezeDevice),
            Just(RecoveryScope::RestorePersonaAccess),
        ]
    }

    fn arb_recovery_op() -> impl Strategy<Value = RecoveryOp> {
        prop_oneof![
            (0u8..4, any::<bool>()).prop_map(|(slot, target_device_exists)| {
                RecoveryOp::Request {
                    slot,
                    target_device_exists,
                }
            }),
            (0u8..4, 0u8..4).prop_map(|(slot, guardian)| RecoveryOp::Approve { slot, guardian }),
            (0u8..4, 0u8..4, 0u8..4, 0u64..10_000).prop_map(
                |(slot, guardian, reason, contested_at_epoch)| RecoveryOp::Contest {
                    slot,
                    guardian,
                    reason,
                    contested_at_epoch,
                },
            ),
            (0u8..4, 0u8..4).prop_map(|(slot, reason)| RecoveryOp::Reject { slot, reason }),
            (0u8..4, arb_recovery_scope())
                .prop_map(|(slot, scope)| RecoveryOp::Execute { slot, scope }),
        ]
    }

    fn request_id(slot: u8) -> String {
        format!("req-{slot}")
    }

    fn guardian_id(guardian: u8) -> String {
        format!("guardian-{}", guardian + 1)
    }

    fn reason_text(reason: u8) -> String {
        format!("reason-{reason}")
    }

    fn signer_for_guardian(guardian_id: &str) -> SignerBinding {
        SignerBinding {
            signer: EventSubject::new(SubjectKind::Guardian, guardian_id),
            role: KeyRole::Guardian,
            key_id: format!("key-{guardian_id}"),
        }
    }

    fn recovery_event(idx: usize, op: &RecoveryOp) -> EventEnvelope {
        let event_id = format!("evt-recovery-prop-{idx}");
        match op {
            RecoveryOp::Request {
                slot,
                target_device_exists,
            } => make_event(
                &event_id,
                EventBody::RecoveryRequested(RecoveryRequestedEvent {
                    request_id: request_id(*slot),
                    root_id: "root-a".into(),
                    target_device_id: if *target_device_exists {
                        "device-a".into()
                    } else {
                        "missing-device".into()
                    },
                }),
                SignerBinding::root("root-a", "key-root-a"),
            ),
            RecoveryOp::Approve { slot, guardian } => {
                let guardian_id = guardian_id(*guardian);
                make_event(
                    &event_id,
                    EventBody::RecoveryApproved(RecoveryApprovedEvent {
                        request_id: request_id(*slot),
                        guardian_id: guardian_id.clone(),
                    }),
                    signer_for_guardian(&guardian_id),
                )
            }
            RecoveryOp::Contest {
                slot,
                guardian,
                reason,
                contested_at_epoch,
            } => {
                let guardian_id = guardian_id(*guardian);
                make_event(
                    &event_id,
                    EventBody::RecoveryContested(RecoveryContestedEvent {
                        request_id: request_id(*slot),
                        guardian_id: guardian_id.clone(),
                        reason: reason_text(*reason),
                        contested_at_epoch: *contested_at_epoch,
                    }),
                    signer_for_guardian(&guardian_id),
                )
            }
            RecoveryOp::Reject { slot, reason } => make_event(
                &event_id,
                EventBody::RecoveryRejected(RecoveryRejectedEvent {
                    request_id: request_id(*slot),
                    rejected_by: "root-a".into(),
                    reason: reason_text(*reason),
                }),
                SignerBinding::root("root-a", "key-root-a"),
            ),
            RecoveryOp::Execute { slot, scope } => make_event(
                &event_id,
                EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                    request_id: request_id(*slot),
                    executed_scope: *scope,
                }),
                SignerBinding::root("root-a", "key-root-a"),
            ),
        }
    }

    fn apply_expected_recovery_op(
        expected: &mut BTreeMap<String, ExpectedRecoveryRequest>,
        op: &RecoveryOp,
    ) -> Result<(), ()> {
        match op {
            RecoveryOp::Request {
                slot,
                target_device_exists,
            } => {
                let request_id = request_id(*slot);
                if expected.contains_key(&request_id) || !target_device_exists {
                    return Err(());
                }
                expected.insert(
                    request_id,
                    ExpectedRecoveryRequest {
                        root_id: "root-a".into(),
                        target_device_id: "device-a".into(),
                        approvals: BTreeSet::new(),
                        contested_by: BTreeSet::new(),
                        status: RecoveryRequestStatus::Requested,
                        executed_scope: None,
                        cooldown_until: None,
                        contest_reason: None,
                        rejection_reason: None,
                    },
                );
                Ok(())
            }
            RecoveryOp::Approve { slot, guardian } => {
                let request = expected.get_mut(&request_id(*slot)).ok_or(())?;
                if matches!(
                    request.status,
                    RecoveryRequestStatus::Contested
                        | RecoveryRequestStatus::Rejected
                        | RecoveryRequestStatus::Executed
                ) {
                    return Err(());
                }
                request.approvals.insert(guardian_id(*guardian));
                if request.approvals.len() >= 2 {
                    request.status = RecoveryRequestStatus::Approved;
                }
                Ok(())
            }
            RecoveryOp::Contest {
                slot,
                guardian,
                reason,
                contested_at_epoch,
            } => {
                let request = expected.get_mut(&request_id(*slot)).ok_or(())?;
                if matches!(
                    request.status,
                    RecoveryRequestStatus::Rejected | RecoveryRequestStatus::Executed
                ) {
                    return Err(());
                }
                request.contested_by.insert(guardian_id(*guardian));
                request.status = RecoveryRequestStatus::Contested;
                request.cooldown_until = Some(*contested_at_epoch + 3600);
                request.contest_reason = Some(reason_text(*reason));
                Ok(())
            }
            RecoveryOp::Reject { slot, reason } => {
                let request = expected.get_mut(&request_id(*slot)).ok_or(())?;
                if request.status == RecoveryRequestStatus::Executed {
                    return Err(());
                }
                request.status = RecoveryRequestStatus::Rejected;
                request.cooldown_until = None;
                request.rejection_reason = Some(reason_text(*reason));
                Ok(())
            }
            RecoveryOp::Execute { slot, scope } => {
                let request = expected.get_mut(&request_id(*slot)).ok_or(())?;
                if request.cooldown_until.is_some()
                    || request.status != RecoveryRequestStatus::Approved
                {
                    return Err(());
                }
                request.status = RecoveryRequestStatus::Executed;
                request.executed_scope = Some(*scope);
                Ok(())
            }
        }
    }

    fn assert_recovery_state_matches_model(
        state: &MaterializedState,
        expected: &BTreeMap<String, ExpectedRecoveryRequest>,
    ) -> Result<(), TestCaseError> {
        prop_assert_eq!(state.recovery_requests_current.len(), expected.len());
        for (request_id, expected_request) in expected {
            let actual = state
                .recovery_requests_current
                .get(request_id)
                .ok_or_else(|| TestCaseError::fail(format!("missing request {request_id}")))?;
            prop_assert_eq!(&actual.root_id, &expected_request.root_id);
            prop_assert_eq!(&actual.target_device_id, &expected_request.target_device_id);
            prop_assert_eq!(&actual.approvals, &expected_request.approvals);
            prop_assert_eq!(&actual.contested_by, &expected_request.contested_by);
            prop_assert_eq!(&actual.status, &expected_request.status);
            prop_assert_eq!(&actual.executed_scope, &expected_request.executed_scope);
            prop_assert_eq!(&actual.cooldown_until, &expected_request.cooldown_until);
            prop_assert_eq!(&actual.contest_reason, &expected_request.contest_reason);
            prop_assert_eq!(&actual.rejection_reason, &expected_request.rejection_reason);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn recovery_lifecycle_sequences_match_expected_state_machine(
            ops in proptest::collection::vec(arb_recovery_op(), 1..64),
        ) {
            let mut state = state_with_recovery_context();
            let mut expected = BTreeMap::new();

            for (idx, op) in ops.iter().enumerate() {
                let mut next_expected = expected.clone();
                let expected_result = apply_expected_recovery_op(&mut next_expected, op);
                let before_requests = state.recovery_requests_current.clone();
                let event = recovery_event(idx, op);
                let actual_result = apply_event(&mut state, &event);

                prop_assert_eq!(
                    actual_result.is_ok(),
                    expected_result.is_ok(),
                    "apply_event/model parity failed for op {}: {:?}; actual={:?}",
                    idx,
                    op,
                    actual_result
                );

                if actual_result.is_ok() {
                    expected = next_expected;
                } else {
                    prop_assert_eq!(
                        &state.recovery_requests_current,
                        &before_requests,
                        "failed recovery op mutated materialized request state: {:?}",
                        op
                    );
                }

                assert_recovery_state_matches_model(&state, &expected)?;
            }
        }
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

    // ── Race-prone RecoveryApproved must not double-materialize ──

    #[test]
    fn recovery_approved_duplicate_from_same_guardian_is_idempotent() {
        // Adversarial: two concurrent `RecoveryApproved` events from the same
        // guardian for the same request. Both pass authorize (signer is the
        // enrolled guardian, request exists). Both call `apply_event`. The
        // second must be a no-op against approvals/threshold — i.e. only the
        // first materially changes state, the second sees the state already
        // contains its approval and does not double-count.
        //
        // This is the in-memory analog of the daemon-side BEGIN IMMEDIATE
        // protection (REVIEW2-F3, commit ed832de6): the materialize seam
        // must be safe under retransmission/replay.
        let mut state = state_with_recovery_context();

        // Lower threshold to 1 so a single approval flips status to Approved.
        state
            .recovery_policies_current
            .get_mut("root-a")
            .unwrap()
            .guardian_threshold = 1;

        // Stage a request.
        let req_event = make_event(
            "evt-req",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "req-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &req_event).expect("request setup");

        // First approval — should flip status to Approved.
        let approve1 = make_event(
            "evt-approve-1",
            EventBody::RecoveryApproved(core_event_types::RecoveryApprovedEvent {
                request_id: "req-1".into(),
                guardian_id: "guardian-1".into(),
            }),
            SignerBinding {
                signer: core_event_types::EventSubject::new(
                    core_event_types::SubjectKind::Guardian,
                    "guardian-1",
                ),
                role: core_event_types::KeyRole::Guardian,
                key_id: "key-g1".into(),
            },
        );
        apply_event(&mut state, &approve1).expect("first approval should materialize");
        let req_after_first = &state.recovery_requests_current["req-1"];
        assert_eq!(
            req_after_first.approvals.len(),
            1,
            "exactly one approval recorded after first event"
        );
        assert!(req_after_first.approvals.contains("guardian-1"));
        assert_eq!(req_after_first.status, RecoveryRequestStatus::Approved);

        // Second approval — same guardian, same request. Mirrors the
        // adversarial concurrent-replay scenario the daemon-side BEGIN
        // IMMEDIATE protects against. apply_event must NOT double-count or
        // otherwise corrupt state (BTreeSet insert is idempotent).
        let approve2 = make_event(
            "evt-approve-2",
            EventBody::RecoveryApproved(core_event_types::RecoveryApprovedEvent {
                request_id: "req-1".into(),
                guardian_id: "guardian-1".into(),
            }),
            SignerBinding {
                signer: core_event_types::EventSubject::new(
                    core_event_types::SubjectKind::Guardian,
                    "guardian-1",
                ),
                role: core_event_types::KeyRole::Guardian,
                key_id: "key-g1".into(),
            },
        );
        apply_event(&mut state, &approve2)
            .expect("second approval must not error — current materialize is idempotent");

        // State after the second event must be identical to state after the
        // first — exactly one logical approval, status still Approved, no
        // split-state side effects.
        let req_after_second = &state.recovery_requests_current["req-1"];
        assert_eq!(
            req_after_second.approvals.len(),
            1,
            "duplicate approval from same guardian must not double-count"
        );
        assert!(req_after_second.approvals.contains("guardian-1"));
        assert_eq!(req_after_second.status, RecoveryRequestStatus::Approved);
        assert!(req_after_second.contested_by.is_empty());
        assert!(req_after_second.cooldown_until.is_none());
    }

    // ── prev_event_id + monotonic sequence chaining ──

    fn make_event_with_refs(
        event_id: &str,
        body: EventBody,
        refs: Vec<CrateEventRef>,
        signer_binding: SignerBinding,
    ) -> EventEnvelope {
        let signer = FixtureSigner::new(signer_binding.key_id.clone());
        EventEnvelope::from_body(event_id, body, refs, signer_binding, &signer).unwrap()
    }

    /// Build a MaterializedState with root-a registered and a chain head set.
    fn state_with_chain_head(head_event_id: &str, head_seq: u64) -> MaterializedState {
        let mut state = MaterializedState::default();
        state.roots_current.insert(
            "root-a".into(),
            RootRecord {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                active_key: make_key("key-root-a"),
                status: RootStatus::Active,
            },
        );
        state
            .root_chain_heads
            .insert("root-a".into(), (head_event_id.to_owned(), head_seq));
        state
    }

    #[test]
    fn out_of_order_event_rejected_wrong_seq() {
        // Adversarial: valid signed event replayed with same prev_event_id but wrong seq.
        // Chain head: (evt-1, seq=1). New event claims prev=evt-1 seq=5 → should fail.
        let state = state_with_chain_head("evt-1", 1);
        let event = make_event_with_refs(
            "evt-bad",
            EventBody::DeviceAdded(core_event_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-x".into(),
                label: "X".into(),
                initial_key: make_key("key-device-x"),
                initial_encryption_key: make_enc_key("device-x"),
            }),
            vec![CrateEventRef::previous("evt-1", 5)],
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = check_chain(&state, &event);
        assert!(result.is_err(), "wrong seq must be rejected by check_chain");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("out-of-order"),
            "error must mention out-of-order, got: {msg}"
        );
    }

    #[test]
    fn out_of_order_event_rejected_skip_sequence() {
        // Skip-sequence: head seq=1, new event claims seq=3 (should be 2).
        let state = state_with_chain_head("evt-1", 1);
        let event = make_event_with_refs(
            "evt-skip",
            EventBody::DeviceAdded(core_event_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-skip".into(),
                label: "Skip".into(),
                initial_key: make_key("key-device-skip"),
                initial_encryption_key: make_enc_key("device-skip"),
            }),
            vec![CrateEventRef::previous("evt-1", 3)],
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = check_chain(&state, &event);
        assert!(result.is_err(), "skip-sequence (1→3) must be rejected");
    }

    #[test]
    fn out_of_order_event_rejected_wrong_prev_id() {
        // Wrong prev_event_id: correct seq but forked chain.
        // Head: (evt-1, 1). New event claims prev=evt-FORK seq=2.
        let state = state_with_chain_head("evt-1", 1);
        let event = make_event_with_refs(
            "evt-fork",
            EventBody::DeviceAdded(core_event_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-fork".into(),
                label: "Fork".into(),
                initial_key: make_key("key-device-fork"),
                initial_encryption_key: make_enc_key("device-fork"),
            }),
            vec![CrateEventRef::previous("evt-FORK", 2)],
            SignerBinding::root("root-a", "key-root-a"),
        );
        let result = check_chain(&state, &event);
        assert!(
            result.is_err(),
            "wrong prev_event_id must be rejected even with correct seq"
        );
    }

    #[test]
    fn chain_check_accepts_valid_next_event() {
        // Happy path: head=(evt-1, seq=1), new event has prev=evt-1 seq=2.
        let state = state_with_chain_head("evt-1", 1);
        let event = make_event_with_refs(
            "evt-2",
            EventBody::DeviceAdded(core_event_types::DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "A".into(),
                initial_key: make_key("key-device-a"),
                initial_encryption_key: make_enc_key("device-a"),
            }),
            vec![CrateEventRef::previous("evt-1", 2)],
            SignerBinding::root("root-a", "key-root-a"),
        );
        check_chain(&state, &event).expect("valid next event must pass check_chain");
    }

    #[test]
    fn genesis_event_accepted_without_previous_ref() {
        // First event for a root has no head yet and no Previous ref.
        let state = MaterializedState::default();
        let event = make_event(
            "evt-genesis",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "new-root".into(),
                display_name: "New Root".into(),
                initial_key: make_key("key-new-root"),
            }),
            SignerBinding::root("new-root", "key-new-root"),
        );
        check_chain(&state, &event).expect("genesis event must pass check_chain");
    }

    // ── ADR 206 §4: DeviceEnrolled records a DISTINCT §4 ECIES recipient key ──

    #[test]
    fn device_enrolled_records_distinct_encryption_key_not_the_signing_key() {
        // Regression guard for the concrete hole the slice-3 cut closes: the
        // `DeviceEnrolled` materialize arm used to set `active_encryption_key =
        // device_key` (reusing the signing key as the §4 ECIES recipient). It now
        // records the event's distinct `encryption_key`, and its key id enters the
        // device's encryption-key history.
        let mut state = MaterializedState::default();
        state.roots_current.insert(
            "root-a".into(),
            RootRecord {
                root_id: "root-a".into(),
                display_name: "root-a".into(),
                active_key: make_key("key-root-a"),
                status: RootStatus::Active,
            },
        );

        let signing = make_key("key-device-presence");
        let recipient = make_enc_key("device-presence");
        assert_ne!(
            signing.public_key, recipient.public_key,
            "fixture sanity: the two keys must differ"
        );

        let event = make_event(
            "evt-enroll",
            EventBody::DeviceEnrolled(DeviceEnrolledEvent {
                root_id: "root-a".into(),
                device_id: "device-presence".into(),
                label: "Operator Presence".into(),
                device_key: signing.clone(),
                encryption_key: recipient.clone(),
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            }),
            SignerBinding::root("root-a", "key-root-a"),
        );
        apply_event(&mut state, &event).expect("DeviceEnrolled must materialize");

        let dev = &state.devices_current["device-presence"];
        assert_eq!(dev.active_key.public_key, signing.public_key);
        assert_eq!(dev.active_encryption_key.public_key, recipient.public_key);
        assert_ne!(
            dev.active_encryption_key.public_key, dev.active_key.public_key,
            "the §4 ECIES recipient must NOT reuse the signing key (ADR 206 §4)"
        );
        // The encryption-key history records the recipient key id (mirrors DeviceAdded).
        assert_eq!(
            state.device_encryption_key_history["device-presence"],
            vec![recipient.key_id.clone()],
        );
    }
}
