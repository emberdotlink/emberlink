use std::collections::{HashMap, HashSet};

use core_crypto::{PublicKey, Signature, Verifier};
use core_event_types::{
    EndpointRotatedEvent, EventBody, RelayHintUpdatedEvent, RelayShutdownNoticeEvent,
};
use core_events::EventEnvelope;
use core_principals::{AdmissionToken, RelayEnvelope, SyncBatch};
use core_principals::{PeerCursor, RelayAdmission, RelayMode, SyncProfile, TrustThreshold};
use core_types::{Validate, ValidationError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct LightSyncContext {
    pub root_ids: HashSet<String>,
    pub persona_ids: HashSet<String>,
    pub device_ids: HashSet<String>,
    pub recovery_request_ids: HashSet<String>,
}

pub fn new_cursor(peer_id: impl Into<String>) -> PeerCursor {
    PeerCursor {
        peer_id: peer_id.into(),
        last_event_id: None,
    }
}

pub fn new_batch(id: impl Into<String>, event_ids: Vec<String>) -> SyncBatch {
    SyncBatch {
        id: id.into(),
        event_ids,
    }
}

pub fn relay_hint_updated_event(
    peer_id: impl Into<String>,
    device_id: impl Into<String>,
    transport_hint: impl Into<String>,
) -> EventBody {
    EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
        peer_id: peer_id.into(),
        device_id: device_id.into(),
        transport_hint: transport_hint.into(),
    })
}

pub fn endpoint_rotated_event(
    peer_id: impl Into<String>,
    device_id: impl Into<String>,
    previous_transport_hint: impl Into<String>,
    new_transport_hint: impl Into<String>,
) -> EventBody {
    EventBody::EndpointRotated(EndpointRotatedEvent {
        peer_id: peer_id.into(),
        device_id: device_id.into(),
        previous_transport_hint: previous_transport_hint.into(),
        new_transport_hint: new_transport_hint.into(),
    })
}

pub fn relay_shutdown_notice_event(
    relay_peer_id: impl Into<String>,
    reason: impl Into<String>,
    deadline_epoch: u64,
) -> EventBody {
    EventBody::RelayShutdownNotice(RelayShutdownNoticeEvent {
        relay_peer_id: relay_peer_id.into(),
        reason: reason.into(),
        deadline_epoch,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTransportRoute {
    pub bind_address: String,
    pub peer_id: String,
}

pub fn build_relay_transport_hint(
    bind_address: impl Into<String>,
    peer_id: impl Into<String>,
) -> String {
    format!("relay://{}/mailbox/{}", bind_address.into(), peer_id.into())
}

pub fn parse_relay_transport_hint(hint: &str) -> Result<RelayTransportRoute, ValidationError> {
    let remainder = hint
        .strip_prefix("relay://")
        .ok_or_else(|| ValidationError::new("transport hint must start with relay://"))?;
    let (bind_address, peer_id) = remainder
        .split_once("/mailbox/")
        .ok_or_else(|| ValidationError::new("transport hint must include /mailbox/<peer-id>"))?;
    if bind_address.trim().is_empty() {
        return Err(ValidationError::new(
            "transport hint bind address must not be empty",
        ));
    }
    if peer_id.trim().is_empty() {
        return Err(ValidationError::new(
            "transport hint peer id must not be empty",
        ));
    }
    Ok(RelayTransportRoute {
        bind_address: bind_address.to_string(),
        peer_id: peer_id.to_string(),
    })
}

pub fn plan_pull_batch(
    cursor: &PeerCursor,
    batch_id: impl Into<String>,
    remote_event_ids: &[String],
    local_has_event: impl Fn(&str) -> bool,
) -> SyncBatch {
    let start_index = cursor
        .last_event_id
        .as_ref()
        .and_then(|last| {
            remote_event_ids
                .iter()
                .position(|event_id| event_id == last)
        })
        .map(|index| index + 1)
        .unwrap_or(0);

    new_batch(
        batch_id,
        remote_event_ids[start_index..]
            .iter()
            .filter(|event_id| !local_has_event(event_id))
            .cloned()
            .collect(),
    )
}

pub fn advance_cursor(cursor: &PeerCursor, batch: &SyncBatch) -> PeerCursor {
    let mut next = cursor.clone();
    if let Some(last_event_id) = batch.event_ids.last() {
        next.last_event_id = Some(last_event_id.clone());
    }
    next
}

/// A portable invite payload for onboarding new users.
///
/// Contains the inviter's persona info, relay endpoint, and identity events
/// so the recipient can bootstrap a connection in a single step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableInvite {
    /// Display name of the inviter (human-readable).
    pub inviter_name: String,
    /// Persona ID the inviter wants to be contacted through.
    pub inviter_persona_id: String,
    /// Relay endpoint where the inviter can be reached.
    pub relay_bind_address: String,
    /// The inviter's identity events (root, device, persona creation + keys).
    pub identity_events: Vec<EventEnvelope>,
}

#[derive(Serialize, Deserialize)]
struct WireInvite {
    inviter_name: String,
    inviter_persona_id: String,
    relay_bind_address: String,
    identity_events: Vec<WireEvent>,
}

impl PortableInvite {
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireInvite {
            inviter_name: self.inviter_name.clone(),
            inviter_persona_id: self.inviter_persona_id.clone(),
            relay_bind_address: self.relay_bind_address.clone(),
            identity_events: self.identity_events.iter().map(wire_event_from).collect(),
        };
        rmp_serde::to_vec(&wire).expect("msgpack encode")
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ValidationError> {
        let wire: WireInvite = rmp_serde::from_slice(payload)
            .map_err(|err| ValidationError::new(format!("invite decode: {err}")))?;
        let mut identity_events = Vec::with_capacity(wire.identity_events.len());
        for w in wire.identity_events {
            identity_events.push(wire_event_to_envelope(w)?);
        }
        Ok(Self {
            inviter_name: wire.inviter_name,
            inviter_persona_id: wire.inviter_persona_id,
            relay_bind_address: wire.relay_bind_address,
            identity_events,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableSyncBatch {
    pub source_peer_id: String,
    pub profile: SyncProfile,
    pub batch: SyncBatch,
    pub cursor_event_id: Option<String>,
    pub events: Vec<EventEnvelope>,
}

// --- Msgpack wire format ---
//
// All three Portable types serialize to msgpack via intermediate "Wire" structs.
// This replaces the old hex-encoded text format, eliminating ~3-5x overhead.
// Canonical event body encoding (used for signatures) is not affected.

#[derive(Serialize, Deserialize)]
struct WireEventRef {
    relation: String,
    target_event_id: String,
}

#[derive(Serialize, Deserialize)]
struct WireEvent {
    event_id: String,
    schema_version: String,
    event_type: String,
    subject_kind: String,
    subject_id: String,
    signer_kind: String,
    signer_id: String,
    signer_role: String,
    signer_key_id: String,
    signer_public_key: String,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    signature: String,
    refs: Vec<WireEventRef>,
}

#[derive(Serialize, Deserialize)]
struct WireSyncBatch {
    source_peer_id: String,
    profile: String,
    batch_id: String,
    cursor_event_id: Option<String>,
    events: Vec<WireEvent>,
}

#[derive(Serialize, Deserialize)]
struct WireRelayEnvelope {
    id: String,
    #[serde(with = "serde_bytes")]
    opaque_payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct WireAdmissionToken {
    token_id: String,
    persona_id: String,
    issuer_persona_id: String,
    issued_at: u64,
    expires_at: u64,
    threshold_met: f32,
    issuer_signature_hex: String,
}

#[derive(Serialize, Deserialize)]
struct WireRelaySubmission {
    source_persona_id: Option<String>,
    target_peer_id: Option<String>,
    envelope: WireRelayEnvelope,
    admission_token: Option<WireAdmissionToken>,
}

fn wire_event_from(event: &EventEnvelope) -> WireEvent {
    WireEvent {
        event_id: event.event_id.clone(),
        schema_version: event.schema_version.to_string(),
        event_type: event.event_type.as_str().to_string(),
        subject_kind: event.subject.kind.as_str().to_string(),
        subject_id: event.subject.subject_id.clone(),
        signer_kind: event.signer_binding.signer.kind.as_str().to_string(),
        signer_id: event.signer_binding.signer.subject_id.clone(),
        signer_role: event.signer_binding.role.as_str().to_string(),
        signer_key_id: event.signer_binding.key_id.clone(),
        signer_public_key: event.signer.0.clone(),
        payload: event.payload.clone(),
        signature: event.signature.0.clone(),
        refs: event
            .refs
            .iter()
            .map(|r| WireEventRef {
                relation: r.relation.as_str().to_string(),
                target_event_id: r.target_event_id.clone(),
            })
            .collect(),
    }
}

fn wire_event_to_envelope(w: WireEvent) -> Result<EventEnvelope, ValidationError> {
    let schema_version = core_types::SchemaVersion::parse(&w.schema_version)
        .ok_or_else(|| ValidationError::new("invalid schema version"))?;
    let event_type = core_event_types::EventType::parse(&w.event_type)
        .ok_or_else(|| ValidationError::new("invalid event type"))?;
    let subject = core_event_types::EventSubject::new(
        core_event_types::SubjectKind::parse(&w.subject_kind)
            .ok_or_else(|| ValidationError::new("invalid subject kind"))?,
        w.subject_id,
    );
    let signer_binding = core_event_types::SignerBinding {
        signer: core_event_types::EventSubject::new(
            core_event_types::SubjectKind::parse(&w.signer_kind)
                .ok_or_else(|| ValidationError::new("invalid signer kind"))?,
            w.signer_id,
        ),
        role: core_event_types::KeyRole::parse(&w.signer_role)
            .ok_or_else(|| ValidationError::new("invalid signer role"))?,
        key_id: w.signer_key_id,
    };
    let refs = w
        .refs
        .into_iter()
        .map(|r| {
            Ok(core_events::EventRef {
                relation: core_event_types::EventRefRelation::parse(&r.relation)
                    .ok_or_else(|| ValidationError::new("invalid ref relation"))?,
                target_event_id: r.target_event_id,
                seq: 0,
            })
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;

    EventEnvelope::from_stored_parts(
        schema_version,
        w.event_id,
        event_type,
        subject,
        signer_binding,
        PublicKey(w.signer_public_key),
        w.payload,
        refs,
        Signature(w.signature),
    )
}

impl PortableSyncBatch {
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireSyncBatch {
            source_peer_id: self.source_peer_id.clone(),
            profile: self.profile.as_str().to_string(),
            batch_id: self.batch.id.clone(),
            cursor_event_id: self.cursor_event_id.clone(),
            events: self.events.iter().map(wire_event_from).collect(),
        };
        rmp_serde::to_vec(&wire).expect("msgpack encode")
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ValidationError> {
        let wire: WireSyncBatch = rmp_serde::from_slice(payload)
            .map_err(|err| ValidationError::new(format!("msgpack decode: {err}")))?;
        let profile = SyncProfile::parse(&wire.profile)
            .ok_or_else(|| ValidationError::new("invalid sync profile"))?;
        let mut events = Vec::with_capacity(wire.events.len());
        let mut event_ids = Vec::with_capacity(wire.events.len());
        for w in wire.events {
            event_ids.push(w.event_id.clone());
            events.push(wire_event_to_envelope(w)?);
        }
        Ok(Self {
            source_peer_id: wire.source_peer_id,
            profile,
            batch: SyncBatch {
                id: wire.batch_id,
                event_ids,
            },
            cursor_event_id: wire.cursor_event_id,
            events,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableRelayEnvelope {
    pub envelope: RelayEnvelope,
}

impl PortableRelayEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireRelayEnvelope {
            id: self.envelope.id.clone(),
            opaque_payload: self.envelope.opaque_payload.clone(),
        };
        rmp_serde::to_vec(&wire).expect("msgpack encode")
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ValidationError> {
        let wire: WireRelayEnvelope = rmp_serde::from_slice(payload)
            .map_err(|err| ValidationError::new(format!("msgpack decode: {err}")))?;
        Ok(Self {
            envelope: RelayEnvelope {
                id: wire.id,
                opaque_payload: wire.opaque_payload,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortableRelaySubmission {
    pub source_persona_id: Option<String>,
    pub target_peer_id: Option<String>,
    pub envelope: RelayEnvelope,
    pub admission_token: Option<AdmissionToken>,
}

impl PortableRelaySubmission {
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireRelaySubmission {
            source_persona_id: self.source_persona_id.clone(),
            target_peer_id: self.target_peer_id.clone(),
            envelope: WireRelayEnvelope {
                id: self.envelope.id.clone(),
                opaque_payload: self.envelope.opaque_payload.clone(),
            },
            admission_token: self.admission_token.as_ref().map(|t| WireAdmissionToken {
                token_id: t.token_id.clone(),
                persona_id: t.persona_id.clone(),
                issuer_persona_id: t.issuer_persona_id.clone(),
                issued_at: t.issued_at,
                expires_at: t.expires_at,
                threshold_met: t.threshold_met.value(),
                issuer_signature_hex: t.issuer_signature_hex.clone(),
            }),
        };
        rmp_serde::to_vec(&wire).expect("msgpack encode")
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ValidationError> {
        let wire: WireRelaySubmission = rmp_serde::from_slice(payload)
            .map_err(|err| ValidationError::new(format!("msgpack decode: {err}")))?;
        let admission_token = match wire.admission_token {
            Some(wt) => {
                let token = AdmissionToken {
                    token_id: wt.token_id,
                    persona_id: wt.persona_id,
                    issuer_persona_id: wt.issuer_persona_id,
                    issued_at: wt.issued_at,
                    expires_at: wt.expires_at,
                    threshold_met: TrustThreshold::new(wt.threshold_met)?,
                    issuer_signature_hex: wt.issuer_signature_hex,
                };
                token.validate()?;
                Some(token)
            }
            None => None,
        };
        Ok(Self {
            source_persona_id: wire.source_persona_id,
            target_peer_id: wire.target_peer_id,
            envelope: RelayEnvelope {
                id: wire.envelope.id,
                opaque_payload: wire.envelope.opaque_payload,
            },
            admission_token,
        })
    }
}

pub fn check_relay_submission_admission(
    mode: RelayMode,
    submission: &PortableRelaySubmission,
    threshold: Option<TrustThreshold>,
    allowlist: &[String],
    trusted_issuer_keys: &HashMap<String, String>,
    now_epoch_secs: u64,
    verifier: &impl Verifier,
) -> RelayAdmission {
    match mode {
        RelayMode::Open => RelayAdmission::Accept,
        RelayMode::NetworkScoped => {
            let Some(source_persona_id) = submission.source_persona_id.as_deref() else {
                return RelayAdmission::Reject {
                    reason: "network-scoped relay requires source persona metadata".to_string(),
                };
            };
            check_relay_admission(mode, source_persona_id, None, None, allowlist)
        }
        RelayMode::TrustGated => {
            let Some(source_persona_id) = submission.source_persona_id.as_deref() else {
                return RelayAdmission::Reject {
                    reason: "trust-gated relay requires source persona metadata".to_string(),
                };
            };
            let Some(required_threshold) = threshold else {
                return RelayAdmission::Reject {
                    reason: "trust-gated relay requires a configured threshold".to_string(),
                };
            };
            let Some(token) = submission.admission_token.as_ref() else {
                return RelayAdmission::Reject {
                    reason: "trust-gated relay requires an admission token".to_string(),
                };
            };
            verify_admission_token(
                token,
                source_persona_id,
                required_threshold,
                trusted_issuer_keys,
                now_epoch_secs,
                verifier,
            )
        }
    }
}

fn verify_admission_token(
    token: &AdmissionToken,
    expected_source_persona_id: &str,
    required_threshold: TrustThreshold,
    trusted_issuer_keys: &HashMap<String, String>,
    now_epoch_secs: u64,
    verifier: &impl Verifier,
) -> RelayAdmission {
    if let Err(err) = token.validate() {
        return RelayAdmission::Reject {
            reason: format!("invalid admission token: {}", err.message),
        };
    }
    if token.persona_id != expected_source_persona_id {
        return RelayAdmission::Reject {
            reason: "admission token persona does not match submission source".to_string(),
        };
    }
    if token.issued_at > now_epoch_secs {
        return RelayAdmission::Reject {
            reason: "admission token is not valid yet".to_string(),
        };
    }
    if token.expires_at <= now_epoch_secs {
        return RelayAdmission::Reject {
            reason: "admission token expired".to_string(),
        };
    }
    if token.threshold_met.value() < required_threshold.value() {
        return RelayAdmission::Reject {
            reason: format!(
                "admission token threshold {:.2} does not satisfy relay threshold {:.2}",
                token.threshold_met.value(),
                required_threshold.value()
            ),
        };
    }

    let Some(issuer_public_key) = trusted_issuer_keys.get(&token.issuer_persona_id) else {
        return RelayAdmission::Reject {
            reason: format!(
                "issuer {} is not in relay trust set",
                token.issuer_persona_id
            ),
        };
    };

    let signature = Signature(token.issuer_signature_hex.clone());
    let public_key = PublicKey(issuer_public_key.clone());
    if !verifier.verify(&public_key, &token.signing_payload(), &signature) {
        return RelayAdmission::Reject {
            reason: "admission token signature is invalid".to_string(),
        };
    }

    RelayAdmission::Accept
}

pub fn relevant_event_ids_for_context(
    events: &[EventEnvelope],
    context: &LightSyncContext,
) -> HashSet<String> {
    events
        .iter()
        .filter(|event| is_event_relevant_to_context(event, context))
        .map(|event| event.event_id.clone())
        .collect()
}

fn is_event_relevant_to_context(event: &EventEnvelope, context: &LightSyncContext) -> bool {
    match &event.body {
        EventBody::RootCreated(body) => context.root_ids.contains(&body.root_id),
        EventBody::RootKeyRotated(body) => context.root_ids.contains(&body.root_id),
        EventBody::RootRevoked(body) => context.root_ids.contains(&body.root_id),
        EventBody::RecoveryPolicyCreated(body) => context.root_ids.contains(&body.root_id),
        EventBody::GuardianEnrolled(body) => context.root_ids.contains(&body.root_id),
        EventBody::GuardianKeyRotated(body) => context.root_ids.contains(&body.root_id),
        EventBody::DeviceAdded(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceEnrolled(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceKeyRotated(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceEncryptionKeyRotated(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceRevoked(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceFrozen(body) => {
            context.root_ids.contains(&body.root_id) || context.device_ids.contains(&body.device_id)
        }
        EventBody::DeviceReplaced(body) => {
            context.root_ids.contains(&body.root_id)
                || context.device_ids.contains(&body.replaced_device_id)
                || context.device_ids.contains(&body.replacement_device_id)
        }
        EventBody::PersonaCreated(body) => {
            context.root_ids.contains(&body.root_id)
                || context.persona_ids.contains(&body.persona_id)
        }
        EventBody::PersonaKeyRotated(body) => {
            context.root_ids.contains(&body.root_id)
                || context.persona_ids.contains(&body.persona_id)
        }
        EventBody::PersonaRevoked(body) => {
            context.root_ids.contains(&body.root_id)
                || context.persona_ids.contains(&body.persona_id)
        }
        EventBody::TrustAttested(body) => {
            context.persona_ids.contains(&body.attester_persona_id)
                || context.persona_ids.contains(&body.subject_persona_id)
        }
        EventBody::TrustRevoked(body) => context.persona_ids.contains(&body.attester_persona_id),
        EventBody::RecoveryRequested(body) => {
            context.root_ids.contains(&body.root_id)
                || context.device_ids.contains(&body.target_device_id)
                || context.recovery_request_ids.contains(&body.request_id)
        }
        EventBody::RecoveryApproved(body) => {
            context.recovery_request_ids.contains(&body.request_id)
        }
        EventBody::RecoveryContested(body) => {
            context.recovery_request_ids.contains(&body.request_id)
        }
        EventBody::RecoveryRejected(body) => {
            context.recovery_request_ids.contains(&body.request_id)
        }
        EventBody::RecoveryExecuted(body) => {
            context.recovery_request_ids.contains(&body.request_id)
        }
        EventBody::RelayHintUpdated(body) => context.device_ids.contains(&body.device_id),
        EventBody::EndpointRotated(body) => context.device_ids.contains(&body.device_id),
        // Shutdown notices are broadcast-level; always relevant to light nodes
        EventBody::RelayShutdownNotice(_) => true,
        EventBody::StorageRelationshipCreated(body) => context.root_ids.contains(&body.root_id),
        EventBody::StorageLedgerUpdated(body) => context.root_ids.contains(&body.root_id),
        EventBody::StorageManifestPublished(body) => {
            context.root_ids.contains(&body.root_id)
                || body
                    .manifest
                    .authorized_devices
                    .iter()
                    .any(|access| context.device_ids.contains(&access.device_id))
        }
        EventBody::MessageSent(body) => {
            context.persona_ids.contains(&body.sender_persona_id)
                || context.persona_ids.contains(&body.recipient_persona_id)
        }
        EventBody::ContentPublished(body) => context.persona_ids.contains(&body.author_persona_id),
        EventBody::DisclosureRevoked(body) => {
            context.persona_ids.contains(&body.revoker_persona_id)
        }
        EventBody::GrantOfferCreated(body) => context.persona_ids.contains(&body.issuer_persona_id),
        EventBody::GrantOfferClaimed(body) => {
            context.persona_ids.contains(&body.recipient_persona_id)
        }
        EventBody::GrantOfferRevoked(body) => context.persona_ids.contains(&body.issuer_persona_id),
        EventBody::BadgeIssued(body) => {
            context.persona_ids.contains(&body.issuer_persona_id)
                || context.persona_ids.contains(&body.recipient_persona_id)
        }
        EventBody::BadgeRevoked(body) => context.persona_ids.contains(&body.revoker_persona_id),
        EventBody::BadgeDisputed(body) => context.persona_ids.contains(&body.disputer_persona_id),
        EventBody::CredentialDeposited(body) => context.persona_ids.contains(&body.issuer_id),
        EventBody::CredentialRevoked(body) => context.persona_ids.contains(&body.revoker_id),
    }
}

pub fn wrap_for_relay(id: impl Into<String>, opaque_payload: Vec<u8>) -> RelayEnvelope {
    RelayEnvelope {
        id: id.into(),
        opaque_payload,
    }
}

/// Check whether a relay should admit an envelope based on its operating mode.
/// See 007-sync-and-relays.md and 013-network-model.md for relay mode semantics.
///
/// - `Open`: always admits.
/// - `TrustGated`: admits if `source_trust_score` meets `threshold`.
/// - `NetworkScoped`: admits if `source_persona_id` is in the allowlist.
///
/// This is a relay-local policy check. The protocol envelope is identical
/// regardless of mode.
pub fn check_relay_admission(
    mode: RelayMode,
    source_persona_id: &str,
    source_trust_score: Option<f32>,
    threshold: Option<TrustThreshold>,
    allowlist: &[String],
) -> RelayAdmission {
    match mode {
        RelayMode::Open => RelayAdmission::Accept,
        RelayMode::TrustGated => {
            let threshold = match threshold {
                Some(t) => t,
                None => {
                    return RelayAdmission::Reject {
                        reason: "trust-gated relay requires a configured threshold".to_string(),
                    };
                }
            };
            match source_trust_score {
                Some(score) if threshold.is_met_by(score) => RelayAdmission::Accept,
                Some(score) => RelayAdmission::Reject {
                    reason: format!(
                        "trust score {score:.2} does not meet threshold {:.2}",
                        threshold.value()
                    ),
                },
                None => RelayAdmission::Reject {
                    reason: "no trust score available for source".to_string(),
                },
            }
        }
        RelayMode::NetworkScoped => {
            if allowlist.iter().any(|id| id == source_persona_id) {
                RelayAdmission::Accept
            } else {
                RelayAdmission::Reject {
                    reason: format!("persona {source_persona_id} is not in relay allowlist"),
                }
            }
        }
    }
}

/// Filter a batch of event IDs according to a sync profile.
///
/// For `Full` profile, all events are accepted.
/// For `Light` profile, only events whose IDs appear in `relevant_ids` pass.
///
/// In a real implementation, `relevant_ids` would be computed from the node's
/// trust context (own roots, personas, devices, trusted peers, active
/// recovery/storage relationships). For now this is a structural filter that
/// callers populate.
pub fn filter_batch_by_profile(
    batch: &SyncBatch,
    profile: SyncProfile,
    relevant_ids: &HashSet<String>,
) -> SyncBatch {
    match profile {
        SyncProfile::Full => batch.clone(),
        SyncProfile::Light => SyncBatch {
            id: batch.id.clone(),
            event_ids: batch
                .event_ids
                .iter()
                .filter(|id| relevant_ids.contains(id.as_str()))
                .cloned()
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{Ed25519Verifier, FixtureSigner, Signer as CryptoSigner};
    use core_event_types::{
        ChunkReference, ContentPublishedEvent, ContentVisibility, DeviceAddedEvent, EventType,
        FileManifest, ManifestDeviceAccess, MessageSentEvent, RootCreatedEvent, SignerBinding,
        StorageLedgerEntry, StorageLedgerUpdatedEvent, StorageManifestPublishedEvent,
        StorageRelationship, StorageRelationshipCreatedEvent,
    };
    use core_events::{EventEnvelope, EventRef};
    use core_principals::PublicKeyMaterial;

    fn test_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: core_principals::KeyAlgorithm::Ed25519,
            public_key: format!("ed25519:{key_id}"),
        }
    }

    fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: core_principals::KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    fn signed_admission_token(
        signer: &FixtureSigner,
        persona_id: &str,
        issuer_persona_id: &str,
        threshold: TrustThreshold,
        issued_at: u64,
        expires_at: u64,
    ) -> AdmissionToken {
        let unsigned = AdmissionToken {
            token_id: "token-1".into(),
            persona_id: persona_id.into(),
            issuer_persona_id: issuer_persona_id.into(),
            issued_at,
            expires_at,
            threshold_met: threshold,
            issuer_signature_hex: String::new(),
        };
        let signature = signer.sign(&unsigned.signing_payload());

        AdmissionToken {
            issuer_signature_hex: signature.0,
            ..unsigned
        }
    }

    #[test]
    fn portable_sync_batch_round_trips_envelopes() {
        let signer = FixtureSigner::new("portable-sync");
        let root_event = EventEnvelope::from_body(
            "evt-root-created",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Root A".into(),
                initial_key: test_key("root-a-v1"),
            }),
            Vec::new(),
            SignerBinding::root("root-a", "root-a-v1"),
            &signer,
        )
        .unwrap();
        let device_event = EventEnvelope::from_body(
            "evt-device-added",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("device-a-v1"),
                initial_encryption_key: test_encryption_key("device-a-v1"),
            }),
            vec![EventRef::previous("evt-root-created", 0)],
            SignerBinding::root("root-a", "root-a-v1"),
            &signer,
        )
        .unwrap();
        let batch = PortableSyncBatch {
            source_peer_id: "peer:/tmp/client-a.tsv".into(),
            profile: SyncProfile::Full,
            batch: SyncBatch {
                id: "sync-batch-1".into(),
                event_ids: vec!["evt-root-created".into(), "evt-device-added".into()],
            },
            cursor_event_id: Some("evt-device-added".into()),
            events: vec![root_event, device_event],
        };

        let decoded = PortableSyncBatch::decode(&batch.encode()).unwrap();

        assert_eq!(decoded, batch);
    }

    #[test]
    fn endpoint_event_builders_emit_typed_events() {
        let updated = relay_hint_updated_event(
            "peer-bridge-a",
            "device-root-a-01",
            "relay://127.0.0.1:9100/mailbox/peer-bridge-a",
        );
        let rotated = endpoint_rotated_event(
            "peer-bridge-a",
            "device-root-a-01",
            "relay://127.0.0.1:9100/mailbox/peer-bridge-a",
            "relay://127.0.0.1:9200/mailbox/peer-bridge-a",
        );

        assert_eq!(updated.event_type(), EventType::RelayHintUpdated);
        assert_eq!(rotated.event_type(), EventType::EndpointRotated);
        assert_eq!(
            updated.subject().kind,
            core_event_types::SubjectKind::Endpoint
        );
        assert_eq!(
            rotated.subject().kind,
            core_event_types::SubjectKind::Endpoint
        );
    }

    #[test]
    fn relay_transport_hint_round_trips_route_parts() {
        let hint = build_relay_transport_hint("127.0.0.1:9100", "peer-bridge-a");
        let route = parse_relay_transport_hint(&hint).unwrap();

        assert_eq!(hint, "relay://127.0.0.1:9100/mailbox/peer-bridge-a");
        assert_eq!(
            route,
            RelayTransportRoute {
                bind_address: "127.0.0.1:9100".into(),
                peer_id: "peer-bridge-a".into(),
            }
        );
    }

    #[test]
    fn relay_transport_hint_rejects_malformed_routes() {
        for invalid in [
            "http://127.0.0.1:9100/mailbox/peer-bridge-a",
            "relay:///mailbox/peer-bridge-a",
            "relay://127.0.0.1:9100",
            "relay://127.0.0.1:9100/mailbox/",
        ] {
            assert!(parse_relay_transport_hint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn portable_relay_envelope_round_trips_opaque_payload() {
        let envelope = PortableRelayEnvelope {
            envelope: wrap_for_relay("relay-envelope-1", vec![0x01, 0x02, 0xab, 0xcd]),
        };

        let decoded = PortableRelayEnvelope::decode(&envelope.encode()).unwrap();

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn portable_relay_submission_round_trips_source_and_token() {
        let issuer_signer = FixtureSigner::new("relay-issuer");
        let token = signed_admission_token(
            &issuer_signer,
            "persona-source",
            "persona-issuer",
            TrustThreshold::new(0.75).unwrap(),
            100,
            200,
        );
        let submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0x01, 0x02, 0xab, 0xcd]),
            admission_token: Some(token),
        };

        let decoded = PortableRelaySubmission::decode(&submission.encode()).unwrap();

        assert_eq!(decoded, submission);
    }

    #[test]
    fn open_relay_admits_anything() {
        let result = check_relay_admission(RelayMode::Open, "unknown-persona", None, None, &[]);
        assert_eq!(result, RelayAdmission::Accept);
    }

    #[test]
    fn trust_gated_relay_admits_above_threshold() {
        let threshold = TrustThreshold::new(0.5).unwrap();
        let result = check_relay_admission(
            RelayMode::TrustGated,
            "persona-1",
            Some(0.7),
            Some(threshold),
            &[],
        );
        assert_eq!(result, RelayAdmission::Accept);
    }

    #[test]
    fn trust_gated_relay_rejects_below_threshold() {
        let threshold = TrustThreshold::new(0.5).unwrap();
        let result = check_relay_admission(
            RelayMode::TrustGated,
            "persona-1",
            Some(0.3),
            Some(threshold),
            &[],
        );
        assert!(matches!(result, RelayAdmission::Reject { .. }));
    }

    #[test]
    fn trust_gated_relay_rejects_no_score() {
        let threshold = TrustThreshold::new(0.5).unwrap();
        let result = check_relay_admission(
            RelayMode::TrustGated,
            "persona-1",
            None,
            Some(threshold),
            &[],
        );
        assert!(matches!(result, RelayAdmission::Reject { .. }));
    }

    #[test]
    fn network_scoped_relay_admits_allowlisted() {
        let allowlist = vec!["persona-1".to_string(), "persona-2".to_string()];
        let result = check_relay_admission(
            RelayMode::NetworkScoped,
            "persona-1",
            None,
            None,
            &allowlist,
        );
        assert_eq!(result, RelayAdmission::Accept);
    }

    #[test]
    fn network_scoped_relay_rejects_unlisted() {
        let allowlist = vec!["persona-1".to_string()];
        let result = check_relay_admission(
            RelayMode::NetworkScoped,
            "persona-3",
            None,
            None,
            &allowlist,
        );
        assert!(matches!(result, RelayAdmission::Reject { .. }));
    }

    #[test]
    fn trust_gated_submission_accepts_valid_signed_token() {
        let issuer_signer = FixtureSigner::new("relay-issuer");
        let token = signed_admission_token(
            &issuer_signer,
            "persona-source",
            "persona-issuer",
            TrustThreshold::new(0.80).unwrap(),
            100,
            200,
        );
        let submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0xde, 0xad]),
            admission_token: Some(token),
        };
        let mut trusted_issuer_keys = HashMap::new();
        trusted_issuer_keys.insert(
            "persona-issuer".to_string(),
            issuer_signer.public_key().0.clone(),
        );

        let admission = check_relay_submission_admission(
            RelayMode::TrustGated,
            &submission,
            Some(TrustThreshold::new(0.75).unwrap()),
            &[],
            &trusted_issuer_keys,
            150,
            &Ed25519Verifier,
        );

        assert_eq!(admission, RelayAdmission::Accept);
    }

    #[test]
    fn trust_gated_submission_rejects_missing_or_invalid_token() {
        let issuer_signer = FixtureSigner::new("relay-issuer");
        let valid_token = signed_admission_token(
            &issuer_signer,
            "persona-source",
            "persona-issuer",
            TrustThreshold::new(0.80).unwrap(),
            100,
            200,
        );
        let missing_token_submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0xde, 0xad]),
            admission_token: None,
        };
        let invalid_signature_submission = PortableRelaySubmission {
            source_persona_id: Some("persona-source".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-2", vec![0xde, 0xad]),
            admission_token: Some(AdmissionToken {
                issuer_signature_hex: "ed25519sig:deadbeef".into(),
                ..valid_token
            }),
        };
        let mut trusted_issuer_keys = HashMap::new();
        trusted_issuer_keys.insert(
            "persona-issuer".to_string(),
            issuer_signer.public_key().0.clone(),
        );

        let missing_token = check_relay_submission_admission(
            RelayMode::TrustGated,
            &missing_token_submission,
            Some(TrustThreshold::new(0.75).unwrap()),
            &[],
            &trusted_issuer_keys,
            150,
            &Ed25519Verifier,
        );
        let invalid_signature = check_relay_submission_admission(
            RelayMode::TrustGated,
            &invalid_signature_submission,
            Some(TrustThreshold::new(0.75).unwrap()),
            &[],
            &trusted_issuer_keys,
            150,
            &Ed25519Verifier,
        );

        assert!(matches!(missing_token, RelayAdmission::Reject { .. }));
        assert!(matches!(invalid_signature, RelayAdmission::Reject { .. }));
    }

    #[test]
    fn network_scoped_submission_uses_source_persona_not_envelope_id() {
        let submission = PortableRelaySubmission {
            source_persona_id: Some("persona-allowed".into()),
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-looking-like-persona-blocked", vec![0xaa]),
            admission_token: None,
        };
        let allowlist = vec!["persona-allowed".to_string()];

        let admission = check_relay_submission_admission(
            RelayMode::NetworkScoped,
            &submission,
            None,
            &allowlist,
            &HashMap::new(),
            0,
            &Ed25519Verifier,
        );

        assert_eq!(admission, RelayAdmission::Accept);
    }

    #[test]
    fn light_profile_filters_batch() {
        let batch = new_batch(
            "batch-1",
            vec![
                "evt-1".to_string(),
                "evt-2".to_string(),
                "evt-3".to_string(),
            ],
        );
        let relevant: HashSet<String> = ["evt-1", "evt-3"].iter().map(|s| s.to_string()).collect();
        let filtered = filter_batch_by_profile(&batch, SyncProfile::Light, &relevant);
        assert_eq!(filtered.event_ids.len(), 2);
        assert!(filtered.event_ids.contains(&"evt-1".to_string()));
        assert!(filtered.event_ids.contains(&"evt-3".to_string()));
    }

    #[test]
    fn full_profile_keeps_all() {
        let batch = new_batch("batch-1", vec!["evt-1".to_string(), "evt-2".to_string()]);
        let empty: HashSet<String> = HashSet::new();
        let filtered = filter_batch_by_profile(&batch, SyncProfile::Full, &empty);
        assert_eq!(filtered.event_ids.len(), 2);
    }

    #[test]
    fn pull_batch_uses_cursor_and_skips_existing_local_events() {
        let cursor = PeerCursor {
            peer_id: "peer-b".into(),
            last_event_id: Some("evt-2".into()),
        };
        let remote = vec![
            "evt-1".to_string(),
            "evt-2".to_string(),
            "evt-3".to_string(),
            "evt-4".to_string(),
        ];
        let local: HashSet<String> = ["evt-3"].iter().map(|value| value.to_string()).collect();

        let batch = plan_pull_batch(&cursor, "batch-2", &remote, |id| local.contains(id));

        assert_eq!(batch.id, "batch-2");
        assert_eq!(batch.event_ids, vec!["evt-4".to_string()]);
    }

    #[test]
    fn advance_cursor_tracks_last_event_in_batch() {
        let cursor = new_cursor("peer-b");
        let batch = new_batch(
            "batch-1",
            vec![
                "evt-1".to_string(),
                "evt-2".to_string(),
                "evt-3".to_string(),
            ],
        );

        let next = advance_cursor(&cursor, &batch);

        assert_eq!(next.peer_id, "peer-b");
        assert_eq!(next.last_event_id.as_deref(), Some("evt-3"));
    }

    #[test]
    fn light_sync_context_marks_new_device_under_known_root_as_relevant() {
        let signer = FixtureSigner::new("key-root-a-v1");
        let root_event = EventEnvelope::from_body(
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &signer,
        )
        .unwrap();
        let device_event = EventEnvelope::from_body(
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &signer,
        )
        .unwrap();
        let unrelated_root_event = EventEnvelope::from_body(
            "evt-root-2",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Other".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            Vec::new(),
            SignerBinding::root("root-b", "key-root-b-v1"),
            &FixtureSigner::new("key-root-b-v1"),
        )
        .unwrap();

        let context = LightSyncContext {
            root_ids: ["root-a".to_string()].into_iter().collect(),
            ..LightSyncContext::default()
        };
        let relevant = relevant_event_ids_for_context(
            &[root_event, device_event, unrelated_root_event],
            &context,
        );

        assert!(relevant.contains("evt-root-1"));
        assert!(relevant.contains("evt-device-1"));
        assert!(!relevant.contains("evt-root-2"));
    }

    #[test]
    fn light_sync_context_marks_message_and_content_for_known_persona_as_relevant() {
        let signer = FixtureSigner::new("key-persona-a-v1");
        let message_event = EventEnvelope::from_body(
            "evt-message-1",
            EventBody::MessageSent(MessageSentEvent {
                message_id: "message-1".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "c0ffee".into(),
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &signer,
        )
        .unwrap();
        let content_event = EventEnvelope::from_body(
            "evt-content-1",
            EventBody::ContentPublished(ContentPublishedEvent {
                content_id: "content-1".into(),
                author_persona_id: "persona-a".into(),
                content_type: "post".into(),
                payload_hex: "deadbeef".into(),
                visibility: ContentVisibility::Public,
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &signer,
        )
        .unwrap();
        let unrelated_message = EventEnvelope::from_body(
            "evt-message-2",
            EventBody::MessageSent(MessageSentEvent {
                message_id: "message-2".into(),
                sender_persona_id: "persona-c".into(),
                recipient_persona_id: "persona-d".into(),
                ciphertext_hex: "bead".into(),
            }),
            Vec::new(),
            SignerBinding::persona("persona-c", "key-persona-c-v1"),
            &FixtureSigner::new("key-persona-c-v1"),
        )
        .unwrap();

        let context = LightSyncContext {
            persona_ids: ["persona-a".to_string()].into_iter().collect(),
            ..LightSyncContext::default()
        };
        let relevant = relevant_event_ids_for_context(
            &[message_event, content_event, unrelated_message],
            &context,
        );

        assert!(relevant.contains("evt-message-1"));
        assert!(relevant.contains("evt-content-1"));
        assert!(!relevant.contains("evt-message-2"));
    }

    #[test]
    fn light_sync_context_marks_storage_manifest_for_known_root_or_device_as_relevant() {
        let signer = FixtureSigner::new("key-root-a-v1");
        let relationship_event = EventEnvelope::from_body(
            "evt-storage-relationship-1",
            EventBody::StorageRelationshipCreated(StorageRelationshipCreatedEvent {
                root_id: "root-a".into(),
                relationship: StorageRelationship {
                    id: "storage-1".into(),
                    local_peer_id: "peer-a".into(),
                    remote_peer_id: "peer-b".into(),
                    approved: true,
                },
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &signer,
        )
        .unwrap();
        let ledger_event = EventEnvelope::from_body(
            "evt-storage-ledger-1",
            EventBody::StorageLedgerUpdated(StorageLedgerUpdatedEvent {
                root_id: "root-a".into(),
                entry: StorageLedgerEntry {
                    relationship_id: "storage-1".into(),
                    stored_bytes_delta: 524_288,
                },
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &signer,
        )
        .unwrap();
        let manifest_event = EventEnvelope::from_body(
            "evt-storage-1",
            EventBody::StorageManifestPublished(StorageManifestPublishedEvent {
                root_id: "root-a".into(),
                relationship_id: "storage-1".into(),
                manifest: FileManifest {
                    id: "manifest-1".into(),
                    encrypted_root_chunk_id: "bafy-root-1".into(),
                    chunks: vec![
                        ChunkReference {
                            manifest_id: "manifest-1".into(),
                            chunk_id: "bafy-root-1".into(),
                            ordinal: 0,
                            ciphertext_bytes: 4096,
                        },
                        ChunkReference {
                            manifest_id: "manifest-1".into(),
                            chunk_id: "bafy-root-1-chunk-0001".into(),
                            ordinal: 1,
                            ciphertext_bytes: 2048,
                        },
                    ],
                    authorized_devices: vec![ManifestDeviceAccess {
                        device_id: "device-a".into(),
                        wrapped_manifest_key_hex: "deadbeef".into(),
                    }],
                },
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &signer,
        )
        .unwrap();

        let root_context = LightSyncContext {
            root_ids: ["root-a".to_string()].into_iter().collect(),
            ..LightSyncContext::default()
        };
        let device_context = LightSyncContext {
            device_ids: ["device-a".to_string()].into_iter().collect(),
            ..LightSyncContext::default()
        };
        let unrelated_context = LightSyncContext {
            root_ids: ["root-b".to_string()].into_iter().collect(),
            ..LightSyncContext::default()
        };

        assert!(
            relevant_event_ids_for_context(std::slice::from_ref(&manifest_event), &root_context)
                .contains("evt-storage-1")
        );
        assert!(
            relevant_event_ids_for_context(
                std::slice::from_ref(&relationship_event),
                &root_context
            )
            .contains("evt-storage-relationship-1")
        );
        assert!(
            relevant_event_ids_for_context(std::slice::from_ref(&ledger_event), &root_context)
                .contains("evt-storage-ledger-1")
        );
        assert!(
            relevant_event_ids_for_context(std::slice::from_ref(&manifest_event), &device_context)
                .contains("evt-storage-1")
        );
        assert!(
            !relevant_event_ids_for_context(&[manifest_event], &unrelated_context)
                .contains("evt-storage-1")
        );
    }

    #[test]
    fn node_tier_default_behaviors() {
        use core_principals::{NodeTier, SyncProfile};

        assert_eq!(
            NodeTier::MobileLight.default_sync_profile(),
            SyncProfile::Light
        );
        assert_eq!(
            NodeTier::PersonalBridge.default_sync_profile(),
            SyncProfile::Full
        );

        assert!(!NodeTier::MobileLight.has_relay_duty());
        assert!(NodeTier::PersonalBridge.has_relay_duty());
        assert!(NodeTier::CommunityRelay.has_relay_duty());
        assert!(NodeTier::Bootstrap.has_relay_duty());

        assert_eq!(
            NodeTier::PersonalBridge.default_relay_mode(),
            Some(RelayMode::NetworkScoped)
        );
        assert_eq!(
            NodeTier::CommunityRelay.default_relay_mode(),
            Some(RelayMode::TrustGated)
        );
        assert_eq!(
            NodeTier::Bootstrap.default_relay_mode(),
            Some(RelayMode::Open)
        );
    }

    #[test]
    fn msgpack_relay_submission_round_trips_without_token() {
        let submission = PortableRelaySubmission {
            source_persona_id: None,
            target_peer_id: Some("peer:/tmp/client-b.tsv".into()),
            envelope: wrap_for_relay("relay-envelope-1", vec![0xde, 0xad]),
            admission_token: None,
        };

        let decoded = PortableRelaySubmission::decode(&submission.encode()).unwrap();
        assert_eq!(decoded, submission);
    }
}
