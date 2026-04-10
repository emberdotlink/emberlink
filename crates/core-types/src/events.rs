use crate::encoding::*;
use crate::{
    CanonicalEncode, FileManifest, PublicKeyMaterial, RecoveryScope, StorageLedgerEntry,
    StorageRelationship, SurvivalMode, Validate, ValidationError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Root,
    Persona,
    Device,
    Guardian,
    RecoveryRequest,
    TrustStatement,
    StorageRelationship,
    Endpoint,
    Unknown,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Persona => "persona",
            Self::Device => "device",
            Self::Guardian => "guardian",
            Self::RecoveryRequest => "recovery-request",
            Self::TrustStatement => "trust-statement",
            Self::StorageRelationship => "storage-relationship",
            Self::Endpoint => "endpoint",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root" => Some(Self::Root),
            "persona" => Some(Self::Persona),
            "device" => Some(Self::Device),
            "guardian" => Some(Self::Guardian),
            "recovery-request" => Some(Self::RecoveryRequest),
            "trust-statement" => Some(Self::TrustStatement),
            "storage-relationship" => Some(Self::StorageRelationship),
            "endpoint" => Some(Self::Endpoint),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSubject {
    pub kind: SubjectKind,
    pub subject_id: String,
}

impl EventSubject {
    pub fn new(kind: SubjectKind, subject_id: impl Into<String>) -> Self {
        Self {
            kind,
            subject_id: subject_id.into(),
        }
    }

    pub fn root(root_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Root, root_id)
    }

    pub fn persona(persona_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Persona, persona_id)
    }

    pub fn device(device_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Device, device_id)
    }

    pub fn endpoint(peer_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Endpoint, peer_id)
    }

    pub fn recovery_request(request_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::RecoveryRequest, request_id)
    }

    pub fn storage_relationship(relationship_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::StorageRelationship, relationship_id)
    }

    pub fn guardian(guardian_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Guardian, guardian_id)
    }

    pub fn unknown(subject_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Unknown, subject_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Root,
    Persona,
    Device,
    Guardian,
    Unknown,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Persona => "persona",
            Self::Device => "device",
            Self::Guardian => "guardian",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root" => Some(Self::Root),
            "persona" => Some(Self::Persona),
            "device" => Some(Self::Device),
            "guardian" => Some(Self::Guardian),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBinding {
    pub signer: EventSubject,
    pub key_id: String,
    pub role: KeyRole,
}

impl SignerBinding {
    pub fn root(root_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::root(root_id),
            key_id: key_id.into(),
            role: KeyRole::Root,
        }
    }

    pub fn persona(persona_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::persona(persona_id),
            key_id: key_id.into(),
            role: KeyRole::Persona,
        }
    }

    pub fn device(device_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::device(device_id),
            key_id: key_id.into(),
            role: KeyRole::Device,
        }
    }

    pub fn guardian(guardian_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::guardian(guardian_id),
            key_id: key_id.into(),
            role: KeyRole::Guardian,
        }
    }

    pub fn unknown(key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::unknown("legacy"),
            key_id: key_id.into(),
            role: KeyRole::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRefRelation {
    Previous,
    Authorization,
    Approval,
    RecoveryPolicy,
    Replacement,
    Related,
}

impl EventRefRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Previous => "previous",
            Self::Authorization => "authorization",
            Self::Approval => "approval",
            Self::RecoveryPolicy => "recovery-policy",
            Self::Replacement => "replacement",
            Self::Related => "related",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "previous" => Some(Self::Previous),
            "authorization" => Some(Self::Authorization),
            "approval" => Some(Self::Approval),
            "recovery-policy" => Some(Self::RecoveryPolicy),
            "replacement" => Some(Self::Replacement),
            "related" => Some(Self::Related),
            _ => None,
        }
    }
}

// --- Event structs ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootCreatedEvent {
    pub root_id: String,
    pub display_name: String,
    pub initial_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKeyRotatedEvent {
    pub root_id: String,
    pub previous_key_id: String,
    pub new_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRevokedEvent {
    pub root_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddedEvent {
    pub root_id: String,
    pub device_id: String,
    pub label: String,
    pub initial_key: PublicKeyMaterial,
    pub initial_encryption_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyRotatedEvent {
    pub root_id: String,
    pub device_id: String,
    pub previous_key_id: String,
    pub new_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEncryptionKeyRotatedEvent {
    pub root_id: String,
    pub device_id: String,
    pub previous_encryption_key_id: String,
    pub new_encryption_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevokedEvent {
    pub root_id: String,
    pub device_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFrozenEvent {
    pub root_id: String,
    pub device_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReplacedEvent {
    pub root_id: String,
    pub replaced_device_id: String,
    pub replacement_device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaCreatedEvent {
    pub root_id: String,
    pub persona_id: String,
    pub label: String,
    pub disclosure_profile: Option<String>,
    pub survival_mode: SurvivalMode,
    pub initial_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaKeyRotatedEvent {
    pub root_id: String,
    pub persona_id: String,
    pub previous_key_id: String,
    pub new_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaRevokedEvent {
    pub root_id: String,
    pub persona_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustAttestedEvent {
    pub attestation_id: String,
    pub attester_persona_id: String,
    pub subject_persona_id: String,
    pub domain: String,
    pub score: f32,
    pub recipient_bound: Option<String>,
}

impl Eq for TrustAttestedEvent {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRevokedEvent {
    pub attestation_id: String,
    pub attester_persona_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicyCreatedEvent {
    pub root_id: String,
    pub guardian_threshold: u8,
    pub cooldown_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianEnrolledEvent {
    pub root_id: String,
    pub guardian_id: String,
    pub guardian_label: String,
    pub guardian_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequestedEvent {
    pub request_id: String,
    pub root_id: String,
    pub target_device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryApprovedEvent {
    pub request_id: String,
    pub guardian_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryContestedEvent {
    pub request_id: String,
    pub guardian_id: String,
    pub reason: String,
    /// Wall-clock epoch seconds when the contest was raised.
    pub contested_at_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRejectedEvent {
    pub request_id: String,
    pub rejected_by: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExecutedEvent {
    pub request_id: String,
    pub executed_scope: RecoveryScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHintUpdatedEvent {
    pub peer_id: String,
    pub device_id: String,
    pub transport_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRotatedEvent {
    pub peer_id: String,
    pub device_id: String,
    pub previous_transport_hint: String,
    pub new_transport_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageManifestPublishedEvent {
    pub root_id: String,
    pub relationship_id: String,
    pub manifest: FileManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRelationshipCreatedEvent {
    pub root_id: String,
    pub relationship: StorageRelationship,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLedgerUpdatedEvent {
    pub root_id: String,
    pub entry: StorageLedgerEntry,
}

/// Visibility scope for published content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentVisibility {
    /// Visible to anyone who can reach the publisher's persona.
    Public,
    /// Visible only to personas with trust score above threshold.
    TrustGated,
    /// Visible only to explicitly listed recipient personas.
    Direct,
}

impl ContentVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::TrustGated => "trust_gated",
            Self::Direct => "direct",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "trust_gated" => Some(Self::TrustGated),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }
}

/// A persona-to-persona encrypted message routed through the relay network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSentEvent {
    pub message_id: String,
    pub sender_persona_id: String,
    pub recipient_persona_id: String,
    /// Hex-encoded ciphertext. Encrypted to the recipient's persona key.
    pub ciphertext_hex: String,
}

/// A relay operator's graceful shutdown notice, broadcast to all served
/// endpoints so clients can drain their mailbox and migrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayShutdownNoticeEvent {
    pub relay_peer_id: String,
    pub reason: String,
    pub deadline_epoch: u64,
}

/// Revocation of a previously issued disclosure artifact.
/// The revoker must be the persona that originally issued the artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRevokedEvent {
    pub revocation_id: String,
    pub artifact_id: String,
    pub revoker_persona_id: String,
    pub reason: String,
}

/// A content item published by a persona into the event graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentPublishedEvent {
    pub content_id: String,
    pub author_persona_id: String,
    pub content_type: String,
    /// For Public/TrustGated: cleartext or threshold-encrypted payload.
    /// For Direct: hex-encoded ciphertext per recipient (multi-recipient encryption
    /// is handled at the application layer; this carries the broadcast payload).
    pub payload_hex: String,
    pub visibility: ContentVisibility,
}

// --- EventBody enum ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBody {
    RootCreated(RootCreatedEvent),
    RootKeyRotated(RootKeyRotatedEvent),
    RootRevoked(RootRevokedEvent),
    DeviceAdded(DeviceAddedEvent),
    DeviceKeyRotated(DeviceKeyRotatedEvent),
    DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent),
    DeviceRevoked(DeviceRevokedEvent),
    DeviceFrozen(DeviceFrozenEvent),
    DeviceReplaced(DeviceReplacedEvent),
    PersonaCreated(PersonaCreatedEvent),
    PersonaKeyRotated(PersonaKeyRotatedEvent),
    PersonaRevoked(PersonaRevokedEvent),
    TrustAttested(TrustAttestedEvent),
    TrustRevoked(TrustRevokedEvent),
    RecoveryPolicyCreated(RecoveryPolicyCreatedEvent),
    GuardianEnrolled(GuardianEnrolledEvent),
    RecoveryRequested(RecoveryRequestedEvent),
    RecoveryApproved(RecoveryApprovedEvent),
    RecoveryContested(RecoveryContestedEvent),
    RecoveryRejected(RecoveryRejectedEvent),
    RecoveryExecuted(RecoveryExecutedEvent),
    RelayHintUpdated(RelayHintUpdatedEvent),
    EndpointRotated(EndpointRotatedEvent),
    StorageRelationshipCreated(StorageRelationshipCreatedEvent),
    StorageLedgerUpdated(StorageLedgerUpdatedEvent),
    StorageManifestPublished(StorageManifestPublishedEvent),
    RelayShutdownNotice(RelayShutdownNoticeEvent),
    MessageSent(MessageSentEvent),
    ContentPublished(ContentPublishedEvent),
    DisclosureRevoked(DisclosureRevokedEvent),
    LegacyOpaque {
        declared_type: EventType,
        subject: EventSubject,
        canonical_payload: Vec<u8>,
    },
}

impl EventBody {
    pub fn event_type(&self) -> EventType {
        match self {
            Self::RootCreated(_) => EventType::RootCreated,
            Self::RootKeyRotated(_) => EventType::RootKeyRotated,
            Self::RootRevoked(_) => EventType::RootRevoked,
            Self::DeviceAdded(_) => EventType::DeviceAdded,
            Self::DeviceKeyRotated(_) => EventType::DeviceKeyRotated,
            Self::DeviceEncryptionKeyRotated(_) => EventType::DeviceEncryptionKeyRotated,
            Self::DeviceRevoked(_) => EventType::DeviceRevoked,
            Self::DeviceFrozen(_) => EventType::DeviceFrozen,
            Self::DeviceReplaced(_) => EventType::DeviceReplaced,
            Self::PersonaCreated(_) => EventType::PersonaCreated,
            Self::PersonaKeyRotated(_) => EventType::PersonaKeyRotated,
            Self::PersonaRevoked(_) => EventType::PersonaRevoked,
            Self::TrustAttested(_) => EventType::TrustAttested,
            Self::TrustRevoked(_) => EventType::TrustRevoked,
            Self::RecoveryPolicyCreated(_) => EventType::RecoveryPolicyCreated,
            Self::GuardianEnrolled(_) => EventType::GuardianEnrolled,
            Self::RecoveryRequested(_) => EventType::RecoveryRequested,
            Self::RecoveryApproved(_) => EventType::RecoveryApproved,
            Self::RecoveryContested(_) => EventType::RecoveryContested,
            Self::RecoveryRejected(_) => EventType::RecoveryRejected,
            Self::RecoveryExecuted(_) => EventType::RecoveryExecuted,
            Self::RelayHintUpdated(_) => EventType::RelayHintUpdated,
            Self::EndpointRotated(_) => EventType::EndpointRotated,
            Self::StorageRelationshipCreated(_) => EventType::StorageRelationshipCreated,
            Self::StorageLedgerUpdated(_) => EventType::StorageLedgerUpdated,
            Self::StorageManifestPublished(_) => EventType::StorageManifestPublished,
            Self::RelayShutdownNotice(_) => EventType::RelayShutdownNotice,
            Self::MessageSent(_) => EventType::MessageSent,
            Self::ContentPublished(_) => EventType::ContentPublished,
            Self::DisclosureRevoked(_) => EventType::DisclosureRevoked,
            Self::LegacyOpaque { declared_type, .. } => *declared_type,
        }
    }

    pub fn subject(&self) -> EventSubject {
        match self {
            Self::RootCreated(body) => EventSubject::root(body.root_id.clone()),
            Self::RootKeyRotated(body) => EventSubject::root(body.root_id.clone()),
            Self::RootRevoked(body) => EventSubject::root(body.root_id.clone()),
            Self::DeviceAdded(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceKeyRotated(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceEncryptionKeyRotated(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceRevoked(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceFrozen(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceReplaced(body) => EventSubject::device(body.replaced_device_id.clone()),
            Self::PersonaCreated(body) => EventSubject::persona(body.persona_id.clone()),
            Self::PersonaKeyRotated(body) => EventSubject::persona(body.persona_id.clone()),
            Self::PersonaRevoked(body) => EventSubject::persona(body.persona_id.clone()),
            Self::TrustAttested(body) => EventSubject::persona(body.subject_persona_id.clone()),
            Self::TrustRevoked(body) => EventSubject::persona(body.attester_persona_id.clone()),
            Self::RecoveryPolicyCreated(body) => EventSubject::root(body.root_id.clone()),
            Self::GuardianEnrolled(body) => EventSubject::guardian(body.guardian_id.clone()),
            Self::RecoveryRequested(body) => {
                EventSubject::recovery_request(body.request_id.clone())
            }
            Self::RecoveryApproved(body) => EventSubject::recovery_request(body.request_id.clone()),
            Self::RecoveryContested(body) => {
                EventSubject::recovery_request(body.request_id.clone())
            }
            Self::RecoveryRejected(body) => EventSubject::recovery_request(body.request_id.clone()),
            Self::RecoveryExecuted(body) => EventSubject::recovery_request(body.request_id.clone()),
            Self::RelayHintUpdated(body) => EventSubject::endpoint(body.peer_id.clone()),
            Self::EndpointRotated(body) => EventSubject::endpoint(body.peer_id.clone()),
            Self::StorageRelationshipCreated(body) => {
                EventSubject::storage_relationship(body.relationship.id.clone())
            }
            Self::StorageLedgerUpdated(body) => {
                EventSubject::storage_relationship(body.entry.relationship_id.clone())
            }
            Self::StorageManifestPublished(body) => {
                EventSubject::storage_relationship(body.relationship_id.clone())
            }
            Self::RelayShutdownNotice(body) => EventSubject::endpoint(body.relay_peer_id.clone()),
            Self::MessageSent(body) => EventSubject::persona(body.sender_persona_id.clone()),
            Self::ContentPublished(body) => EventSubject::persona(body.author_persona_id.clone()),
            Self::DisclosureRevoked(body) => EventSubject::persona(body.revoker_persona_id.clone()),
            Self::LegacyOpaque { subject, .. } => subject.clone(),
        }
    }

    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        let (record_type, fields) = parse_canonical_record(payload)?;

        match record_type.as_str() {
            "root-created" => Ok(Self::RootCreated(RootCreatedEvent {
                root_id: required_field(&fields, "root_id")?,
                display_name: required_field(&fields, "display_name")?,
                initial_key: parse_public_key_material(
                    &fields,
                    "key_id",
                    "algorithm",
                    "public_key",
                )?,
            })),
            "root-key-rotated" => Ok(Self::RootKeyRotated(RootKeyRotatedEvent {
                root_id: required_field(&fields, "root_id")?,
                previous_key_id: required_field(&fields, "previous_key_id")?,
                new_key: parse_public_key_material(
                    &fields,
                    "new_key_id",
                    "algorithm",
                    "public_key",
                )?,
            })),
            "root-revoked" => Ok(Self::RootRevoked(RootRevokedEvent {
                root_id: required_field(&fields, "root_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "device-added" => Ok(Self::DeviceAdded(DeviceAddedEvent {
                root_id: required_field(&fields, "root_id")?,
                device_id: required_field(&fields, "device_id")?,
                label: required_field(&fields, "label")?,
                initial_key: parse_public_key_material(
                    &fields,
                    "key_id",
                    "algorithm",
                    "public_key",
                )?,
                initial_encryption_key: parse_public_key_material(
                    &fields,
                    "encryption_key_id",
                    "encryption_algorithm",
                    "encryption_public_key",
                )?,
            })),
            "device-key-rotated" => Ok(Self::DeviceKeyRotated(DeviceKeyRotatedEvent {
                root_id: required_field(&fields, "root_id")?,
                device_id: required_field(&fields, "device_id")?,
                previous_key_id: required_field(&fields, "previous_key_id")?,
                new_key: parse_public_key_material(
                    &fields,
                    "new_key_id",
                    "algorithm",
                    "public_key",
                )?,
            })),
            "device-encryption-key-rotated" => Ok(Self::DeviceEncryptionKeyRotated(
                DeviceEncryptionKeyRotatedEvent {
                    root_id: required_field(&fields, "root_id")?,
                    device_id: required_field(&fields, "device_id")?,
                    previous_encryption_key_id: required_field(
                        &fields,
                        "previous_encryption_key_id",
                    )?,
                    new_encryption_key: parse_public_key_material(
                        &fields,
                        "new_encryption_key_id",
                        "encryption_algorithm",
                        "encryption_public_key",
                    )?,
                },
            )),
            "device-revoked" => Ok(Self::DeviceRevoked(DeviceRevokedEvent {
                root_id: required_field(&fields, "root_id")?,
                device_id: required_field(&fields, "device_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "device-frozen" => Ok(Self::DeviceFrozen(DeviceFrozenEvent {
                root_id: required_field(&fields, "root_id")?,
                device_id: required_field(&fields, "device_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "device-replaced" => Ok(Self::DeviceReplaced(DeviceReplacedEvent {
                root_id: required_field(&fields, "root_id")?,
                replaced_device_id: required_field(&fields, "replaced_device_id")?,
                replacement_device_id: required_field(&fields, "replacement_device_id")?,
            })),
            "persona-created" => Ok(Self::PersonaCreated(PersonaCreatedEvent {
                root_id: required_field(&fields, "root_id")?,
                persona_id: required_field(&fields, "persona_id")?,
                label: required_field(&fields, "label")?,
                disclosure_profile: optional_non_empty_field(&fields, "disclosure_profile"),
                survival_mode: SurvivalMode::parse(&required_field(&fields, "survival_mode")?)
                    .ok_or_else(|| ValidationError::invalid_format("invalid survival mode"))?,
                initial_key: parse_public_key_material(
                    &fields,
                    "key_id",
                    "algorithm",
                    "public_key",
                )?,
            })),
            "persona-key-rotated" => Ok(Self::PersonaKeyRotated(PersonaKeyRotatedEvent {
                root_id: required_field(&fields, "root_id")?,
                persona_id: required_field(&fields, "persona_id")?,
                previous_key_id: required_field(&fields, "previous_key_id")?,
                new_key: parse_public_key_material(
                    &fields,
                    "new_key_id",
                    "algorithm",
                    "public_key",
                )?,
            })),
            "persona-revoked" => Ok(Self::PersonaRevoked(PersonaRevokedEvent {
                root_id: required_field(&fields, "root_id")?,
                persona_id: required_field(&fields, "persona_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "recovery-policy-created" => {
                Ok(Self::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                    root_id: required_field(&fields, "root_id")?,
                    guardian_threshold: required_field(&fields, "guardian_threshold")?
                        .parse::<u8>()
                        .map_err(|_| {
                            ValidationError::invalid_format("guardian threshold must be a valid u8")
                        })?,
                    cooldown_seconds: fields
                        .get("cooldown_seconds")
                        .and_then(|v| v.parse::<u32>().ok())
                        .unwrap_or(0),
                }))
            }
            "guardian-enrolled" => Ok(Self::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: required_field(&fields, "root_id")?,
                guardian_id: required_field(&fields, "guardian_id")?,
                guardian_label: required_field(&fields, "guardian_label")?,
                guardian_public_key: required_field(&fields, "guardian_public_key")?,
            })),
            "recovery-requested" => Ok(Self::RecoveryRequested(RecoveryRequestedEvent {
                request_id: required_field(&fields, "request_id")?,
                root_id: required_field(&fields, "root_id")?,
                target_device_id: required_field(&fields, "target_device_id")?,
            })),
            "recovery-approved" => Ok(Self::RecoveryApproved(RecoveryApprovedEvent {
                request_id: required_field(&fields, "request_id")?,
                guardian_id: required_field(&fields, "guardian_id")?,
            })),
            "recovery-contested" => Ok(Self::RecoveryContested(RecoveryContestedEvent {
                request_id: required_field(&fields, "request_id")?,
                guardian_id: required_field(&fields, "guardian_id")?,
                reason: required_field(&fields, "reason")?,
                contested_at_epoch: fields
                    .get("contested_at_epoch")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0),
            })),
            "recovery-rejected" => Ok(Self::RecoveryRejected(RecoveryRejectedEvent {
                request_id: required_field(&fields, "request_id")?,
                rejected_by: required_field(&fields, "rejected_by")?,
                reason: required_field(&fields, "reason")?,
            })),
            "recovery-executed" => Ok(Self::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: required_field(&fields, "request_id")?,
                executed_scope: RecoveryScope::parse(&required_field(&fields, "executed_scope")?)
                    .ok_or_else(|| {
                    ValidationError::invalid_format("invalid recovery scope")
                })?,
            })),
            "relay-hint-updated" => Ok(Self::RelayHintUpdated(RelayHintUpdatedEvent {
                peer_id: required_field(&fields, "peer_id")?,
                device_id: required_field(&fields, "device_id")?,
                transport_hint: required_field(&fields, "transport_hint")?,
            })),
            "endpoint-rotated" => Ok(Self::EndpointRotated(EndpointRotatedEvent {
                peer_id: required_field(&fields, "peer_id")?,
                device_id: required_field(&fields, "device_id")?,
                previous_transport_hint: required_field(&fields, "previous_transport_hint")?,
                new_transport_hint: required_field(&fields, "new_transport_hint")?,
            })),
            "relay-shutdown-notice" => Ok(Self::RelayShutdownNotice(RelayShutdownNoticeEvent {
                relay_peer_id: required_field(&fields, "relay_peer_id")?,
                reason: required_field(&fields, "reason")?,
                deadline_epoch: required_field(&fields, "deadline_epoch")?
                    .parse::<u64>()
                    .map_err(|_| {
                        ValidationError::invalid_format("deadline_epoch must be a valid u64")
                    })?,
            })),
            "storage-relationship-created" => Ok(Self::StorageRelationshipCreated(
                StorageRelationshipCreatedEvent {
                    root_id: required_field(&fields, "root_id")?,
                    relationship: StorageRelationship {
                        id: required_field(&fields, "relationship_id")?,
                        local_peer_id: required_field(&fields, "local_peer_id")?,
                        remote_peer_id: required_field(&fields, "remote_peer_id")?,
                        approved: required_field(&fields, "approved")? == "true",
                    },
                },
            )),
            "storage-ledger-updated" => Ok(Self::StorageLedgerUpdated(StorageLedgerUpdatedEvent {
                root_id: required_field(&fields, "root_id")?,
                entry: StorageLedgerEntry {
                    relationship_id: required_field(&fields, "relationship_id")?,
                    stored_bytes_delta: required_field(&fields, "stored_bytes_delta")?
                        .parse::<i64>()
                        .map_err(|err| {
                            ValidationError::invalid_format(format!(
                                "invalid storage ledger delta: {err}"
                            ))
                        })?,
                },
            })),
            "storage-manifest-published" => Ok(Self::StorageManifestPublished(
                StorageManifestPublishedEvent {
                    root_id: required_field(&fields, "root_id")?,
                    relationship_id: required_field(&fields, "relationship_id")?,
                    manifest: crate::storage::decode_file_manifest_canonical(&hex_to_bytes(
                        &required_field(&fields, "manifest_payload_hex")?,
                    )?)?,
                },
            )),
            "trust-attested" => Ok(Self::TrustAttested(TrustAttestedEvent {
                attestation_id: required_field(&fields, "attestation_id")?,
                attester_persona_id: required_field(&fields, "attester_persona_id")?,
                subject_persona_id: required_field(&fields, "subject_persona_id")?,
                domain: required_field(&fields, "domain")?,
                score: required_field(&fields, "score")?
                    .parse::<f32>()
                    .map_err(|err| {
                        ValidationError::invalid_format(format!("invalid trust score: {err}"))
                    })?,
                recipient_bound: optional_non_empty_field(&fields, "recipient_bound"),
            })),
            "trust-revoked" => Ok(Self::TrustRevoked(TrustRevokedEvent {
                attestation_id: required_field(&fields, "attestation_id")?,
                attester_persona_id: required_field(&fields, "attester_persona_id")?,
            })),
            "message-sent" => Ok(Self::MessageSent(MessageSentEvent {
                message_id: required_field(&fields, "message_id")?,
                sender_persona_id: required_field(&fields, "sender_persona_id")?,
                recipient_persona_id: required_field(&fields, "recipient_persona_id")?,
                ciphertext_hex: required_field(&fields, "ciphertext_hex")?,
            })),
            "content-published" => Ok(Self::ContentPublished(ContentPublishedEvent {
                content_id: required_field(&fields, "content_id")?,
                author_persona_id: required_field(&fields, "author_persona_id")?,
                content_type: required_field(&fields, "content_type")?,
                payload_hex: required_field(&fields, "payload_hex")?,
                visibility: ContentVisibility::parse(&required_field(&fields, "visibility")?)
                    .ok_or_else(|| ValidationError::invalid_format("invalid content visibility"))?,
            })),
            "disclosure-revoked" => Ok(Self::DisclosureRevoked(DisclosureRevokedEvent {
                revocation_id: required_field(&fields, "revocation_id")?,
                artifact_id: required_field(&fields, "artifact_id")?,
                revoker_persona_id: required_field(&fields, "revoker_persona_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "legacy-opaque" => Ok(Self::LegacyOpaque {
                declared_type: EventType::parse(&required_field(&fields, "declared_type")?)
                    .ok_or_else(|| {
                        ValidationError::invalid_format("invalid legacy declared type")
                    })?,
                subject: EventSubject::new(
                    SubjectKind::parse(&required_field(&fields, "subject_kind")?).ok_or_else(
                        || ValidationError::invalid_format("invalid legacy subject kind"),
                    )?,
                    required_field(&fields, "subject_id")?,
                ),
                canonical_payload: hex_to_bytes(&required_field(&fields, "payload_hex")?)?,
            }),
            _ => Err(ValidationError::invalid_format(format!(
                "unsupported canonical event body type: {record_type}"
            ))),
        }
    }
}

// --- EventType enum ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    RootCreated,
    RootKeyRotated,
    RootRevoked,
    DeviceAdded,
    DeviceKeyRotated,
    DeviceEncryptionKeyRotated,
    DeviceRevoked,
    DeviceFrozen,
    DeviceReplaced,
    PersonaCreated,
    PersonaKeyRotated,
    PersonaRevoked,
    LinkageAsserted,
    LinkageRevoked,
    TrustAttested,
    TrustRevoked,
    DerivedTrustPublished,
    DerivedTrustRevoked,
    RecoveryPolicyCreated,
    RecoveryPolicyUpdated,
    GuardianEnrolled,
    RecoveryRequested,
    RecoveryApproved,
    RecoveryContested,
    RecoveryRejected,
    RecoveryExecuted,
    FreezeExecuted,
    MessageSent,
    ContentPublished,
    StorageRelationshipCreated,
    StorageRelationshipUpdated,
    StorageManifestPublished,
    StorageLedgerUpdated,
    StorageRetentionNotice,
    RelayHintUpdated,
    EndpointRotated,
    RelayShutdownNotice,
    DisclosurePolicyUpdated,
    DisclosureRevoked,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootCreated => "root_created",
            Self::RootKeyRotated => "root_key_rotated",
            Self::RootRevoked => "root_revoked",
            Self::DeviceAdded => "device_added",
            Self::DeviceKeyRotated => "device_key_rotated",
            Self::DeviceEncryptionKeyRotated => "device_encryption_key_rotated",
            Self::DeviceRevoked => "device_revoked",
            Self::DeviceFrozen => "device_frozen",
            Self::DeviceReplaced => "device_replaced",
            Self::PersonaCreated => "persona_created",
            Self::PersonaKeyRotated => "persona_key_rotated",
            Self::PersonaRevoked => "persona_revoked",
            Self::LinkageAsserted => "linkage_asserted",
            Self::LinkageRevoked => "linkage_revoked",
            Self::TrustAttested => "trust_attested",
            Self::TrustRevoked => "trust_revoked",
            Self::DerivedTrustPublished => "derived_trust_published",
            Self::DerivedTrustRevoked => "derived_trust_revoked",
            Self::RecoveryPolicyCreated => "recovery_policy_created",
            Self::RecoveryPolicyUpdated => "recovery_policy_updated",
            Self::GuardianEnrolled => "guardian_enrolled",
            Self::RecoveryRequested => "recovery_requested",
            Self::RecoveryApproved => "recovery_approved",
            Self::RecoveryContested => "recovery_contested",
            Self::RecoveryRejected => "recovery_rejected",
            Self::RecoveryExecuted => "recovery_executed",
            Self::FreezeExecuted => "freeze_executed",
            Self::MessageSent => "message_sent",
            Self::ContentPublished => "content_published",
            Self::StorageRelationshipCreated => "storage_relationship_created",
            Self::StorageRelationshipUpdated => "storage_relationship_updated",
            Self::StorageManifestPublished => "storage_manifest_published",
            Self::StorageLedgerUpdated => "storage_ledger_updated",
            Self::StorageRetentionNotice => "storage_retention_notice",
            Self::RelayHintUpdated => "relay_hint_updated",
            Self::EndpointRotated => "endpoint_rotated",
            Self::RelayShutdownNotice => "relay_shutdown_notice",
            Self::DisclosurePolicyUpdated => "disclosure_policy_updated",
            Self::DisclosureRevoked => "disclosure_revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root_created" => Some(Self::RootCreated),
            "root_key_rotated" => Some(Self::RootKeyRotated),
            "root_revoked" => Some(Self::RootRevoked),
            "device_added" => Some(Self::DeviceAdded),
            "device_key_rotated" => Some(Self::DeviceKeyRotated),
            "device_encryption_key_rotated" => Some(Self::DeviceEncryptionKeyRotated),
            "device_revoked" => Some(Self::DeviceRevoked),
            "device_frozen" => Some(Self::DeviceFrozen),
            "device_replaced" => Some(Self::DeviceReplaced),
            "persona_created" => Some(Self::PersonaCreated),
            "persona_key_rotated" => Some(Self::PersonaKeyRotated),
            "persona_revoked" => Some(Self::PersonaRevoked),
            "linkage_asserted" => Some(Self::LinkageAsserted),
            "linkage_revoked" => Some(Self::LinkageRevoked),
            "trust_attested" => Some(Self::TrustAttested),
            "trust_revoked" => Some(Self::TrustRevoked),
            "derived_trust_published" => Some(Self::DerivedTrustPublished),
            "derived_trust_revoked" => Some(Self::DerivedTrustRevoked),
            "recovery_policy_created" => Some(Self::RecoveryPolicyCreated),
            "recovery_policy_updated" => Some(Self::RecoveryPolicyUpdated),
            "guardian_enrolled" => Some(Self::GuardianEnrolled),
            "recovery_requested" => Some(Self::RecoveryRequested),
            "recovery_approved" => Some(Self::RecoveryApproved),
            "recovery_contested" => Some(Self::RecoveryContested),
            "recovery_rejected" => Some(Self::RecoveryRejected),
            "recovery_executed" => Some(Self::RecoveryExecuted),
            "freeze_executed" => Some(Self::FreezeExecuted),
            "message_sent" => Some(Self::MessageSent),
            "content_published" => Some(Self::ContentPublished),
            "storage_relationship_created" => Some(Self::StorageRelationshipCreated),
            "storage_relationship_updated" => Some(Self::StorageRelationshipUpdated),
            "storage_manifest_published" => Some(Self::StorageManifestPublished),
            "storage_ledger_updated" => Some(Self::StorageLedgerUpdated),
            "storage_retention_notice" => Some(Self::StorageRetentionNotice),
            "relay_hint_updated" => Some(Self::RelayHintUpdated),
            "endpoint_rotated" => Some(Self::EndpointRotated),
            "relay_shutdown_notice" => Some(Self::RelayShutdownNotice),
            "disclosure_policy_updated" => Some(Self::DisclosurePolicyUpdated),
            "disclosure_revoked" => Some(Self::DisclosureRevoked),
            _ => None,
        }
    }
}

// --- Retention classification ---

/// Controls how long an event is retained before it becomes eligible for
/// compaction after a snapshot checkpoint. See design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionClass {
    /// Identity lifecycle events — never compacted.
    Permanent,
    /// Active protocol state — retained until superseded + grace period.
    LongLived,
    /// Routine operational events — compactable after next snapshot.
    Ephemeral,
}

impl RetentionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permanent => "permanent",
            Self::LongLived => "long_lived",
            Self::Ephemeral => "ephemeral",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "permanent" => Some(Self::Permanent),
            "long_lived" => Some(Self::LongLived),
            "ephemeral" => Some(Self::Ephemeral),
            _ => None,
        }
    }
}

impl EventType {
    /// Returns the retention class for this event type.
    pub fn retention_class(self) -> RetentionClass {
        match self {
            // Identity lifecycle — permanent record of what existed
            Self::RootCreated
            | Self::RootRevoked
            | Self::DeviceAdded
            | Self::DeviceRevoked
            | Self::PersonaCreated
            | Self::PersonaRevoked => RetentionClass::Permanent,

            // Key rotations — permanent because they establish signing authority chains
            Self::RootKeyRotated
            | Self::DeviceKeyRotated
            | Self::DeviceEncryptionKeyRotated
            | Self::PersonaKeyRotated => RetentionClass::Permanent,

            // Active protocol state — meaningful until superseded
            Self::TrustAttested
            | Self::TrustRevoked
            | Self::LinkageAsserted
            | Self::LinkageRevoked
            | Self::RecoveryPolicyCreated
            | Self::RecoveryPolicyUpdated
            | Self::GuardianEnrolled
            | Self::StorageRelationshipCreated
            | Self::StorageManifestPublished
            | Self::DisclosurePolicyUpdated
            | Self::DisclosureRevoked => RetentionClass::LongLived,

            // Recovery flow events — long-lived for audit trail
            Self::RecoveryRequested
            | Self::RecoveryApproved
            | Self::RecoveryContested
            | Self::RecoveryRejected
            | Self::RecoveryExecuted
            | Self::FreezeExecuted
            | Self::DeviceFrozen
            | Self::DeviceReplaced => RetentionClass::LongLived,

            // Routine operations — compactable after snapshot
            Self::DerivedTrustPublished
            | Self::DerivedTrustRevoked
            | Self::StorageRelationshipUpdated
            | Self::StorageLedgerUpdated
            | Self::StorageRetentionNotice
            | Self::RelayHintUpdated
            | Self::EndpointRotated
            | Self::RelayShutdownNotice
            | Self::MessageSent
            | Self::ContentPublished => RetentionClass::Ephemeral,
        }
    }
}

// --- Validate impls ---

impl Validate for EventSubject {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.subject_id, "subject id")
    }
}

impl Validate for SignerBinding {
    fn validate(&self) -> Result<(), ValidationError> {
        self.signer.validate()?;
        validate_non_empty(&self.key_id, "signer key id")
    }
}

impl Validate for RootCreatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.display_name, "display name")?;
        self.initial_key.validate()
    }
}

impl Validate for RootKeyRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.previous_key_id, "previous key id")?;
        self.new_key.validate()?;
        if self.previous_key_id == self.new_key.key_id {
            return Err(ValidationError::state_violation(
                "rotated root key must change key id",
            ));
        }
        Ok(())
    }
}

impl Validate for RootRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.reason, "revocation reason")
    }
}

impl Validate for DeviceAddedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.label, "device label")?;
        self.initial_key.validate()?;
        self.initial_encryption_key.validate()
    }
}

impl Validate for DeviceKeyRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.previous_key_id, "previous key id")?;
        self.new_key.validate()?;
        if self.previous_key_id == self.new_key.key_id {
            return Err(ValidationError::state_violation(
                "rotated device key must change key id",
            ));
        }
        Ok(())
    }
}

impl Validate for DeviceEncryptionKeyRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(
            &self.previous_encryption_key_id,
            "previous encryption key id",
        )?;
        self.new_encryption_key.validate()?;
        if self.previous_encryption_key_id == self.new_encryption_key.key_id {
            return Err(ValidationError::state_violation(
                "rotated device encryption key must change key id",
            ));
        }
        Ok(())
    }
}

impl Validate for DeviceRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.reason, "revocation reason")
    }
}

impl Validate for DeviceFrozenEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.reason, "freeze reason")
    }
}

impl Validate for DeviceReplacedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.replaced_device_id, "replaced device id")?;
        validate_non_empty(&self.replacement_device_id, "replacement device id")?;
        if self.replaced_device_id == self.replacement_device_id {
            return Err(ValidationError::state_violation(
                "replacement device must differ from replaced device",
            ));
        }
        Ok(())
    }
}

impl Validate for PersonaCreatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.persona_id, "persona id")?;
        validate_non_empty(&self.label, "persona label")?;
        self.initial_key.validate()
    }
}

impl Validate for PersonaKeyRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.persona_id, "persona id")?;
        validate_non_empty(&self.previous_key_id, "previous key id")?;
        self.new_key.validate()?;
        if self.previous_key_id == self.new_key.key_id {
            return Err(ValidationError::state_violation(
                "rotated persona key must change key id",
            ));
        }
        Ok(())
    }
}

impl Validate for PersonaRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.persona_id, "persona id")?;
        validate_non_empty(&self.reason, "revocation reason")
    }
}

impl Validate for RecoveryPolicyCreatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        if self.guardian_threshold == 0 {
            return Err(ValidationError::invalid_format(
                "guardian threshold must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl Validate for GuardianEnrolledEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.guardian_id, "guardian id")?;
        validate_non_empty(&self.guardian_label, "guardian label")?;
        validate_non_empty(&self.guardian_public_key, "guardian public key")
    }
}

impl Validate for RecoveryRequestedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")?;
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.target_device_id, "target device id")
    }
}

impl Validate for RecoveryApprovedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")?;
        validate_non_empty(&self.guardian_id, "guardian id")
    }
}

impl Validate for RecoveryContestedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")?;
        validate_non_empty(&self.guardian_id, "guardian id")?;
        validate_non_empty(&self.reason, "contest reason")
    }
}

impl Validate for RecoveryRejectedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")?;
        validate_non_empty(&self.rejected_by, "rejected by")?;
        validate_non_empty(&self.reason, "rejection reason")
    }
}

impl Validate for RecoveryExecutedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")
    }
}

impl Validate for TrustAttestedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.attestation_id, "attestation id")?;
        validate_non_empty(&self.attester_persona_id, "attester persona id")?;
        validate_non_empty(&self.subject_persona_id, "subject persona id")?;
        validate_non_empty(&self.domain, "trust domain")?;
        if !(0.0..=1.0).contains(&self.score) {
            return Err(ValidationError::invalid_format(
                "trust score must be in [0.0, 1.0]",
            ));
        }
        Ok(())
    }
}

impl Validate for TrustRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.attestation_id, "attestation id")?;
        validate_non_empty(&self.attester_persona_id, "attester persona id")
    }
}

impl Validate for RelayHintUpdatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.peer_id, "peer id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.transport_hint, "transport hint")
    }
}

impl Validate for EndpointRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.peer_id, "peer id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.previous_transport_hint, "previous transport hint")?;
        validate_non_empty(&self.new_transport_hint, "new transport hint")?;
        if self.previous_transport_hint == self.new_transport_hint {
            return Err(ValidationError::state_violation(
                "endpoint rotation must change transport hint",
            ));
        }
        Ok(())
    }
}

impl Validate for RelayShutdownNoticeEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.relay_peer_id, "relay peer id")?;
        validate_non_empty(&self.reason, "shutdown reason")
    }
}

impl Validate for MessageSentEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.message_id, "message id")?;
        validate_non_empty(&self.sender_persona_id, "sender persona id")?;
        validate_non_empty(&self.recipient_persona_id, "recipient persona id")?;
        validate_non_empty(&self.ciphertext_hex, "ciphertext")?;
        Ok(())
    }
}

impl Validate for ContentPublishedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.content_id, "content id")?;
        validate_non_empty(&self.author_persona_id, "author persona id")?;
        validate_non_empty(&self.content_type, "content type")?;
        validate_non_empty(&self.payload_hex, "payload")?;
        Ok(())
    }
}

impl Validate for DisclosureRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.revocation_id, "revocation id")?;
        validate_non_empty(&self.artifact_id, "artifact id")?;
        validate_non_empty(&self.revoker_persona_id, "revoker persona id")?;
        validate_non_empty(&self.reason, "reason")?;
        Ok(())
    }
}

impl Validate for StorageRelationshipCreatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "storage relationship root id")?;
        self.relationship.validate()
    }
}

impl Validate for StorageLedgerUpdatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "storage ledger root id")?;
        self.entry.validate()
    }
}

impl Validate for StorageManifestPublishedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "storage manifest root id")?;
        validate_non_empty(&self.relationship_id, "storage relationship id")?;
        self.manifest.validate()
    }
}

impl Validate for EventBody {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::RootCreated(body) => body.validate(),
            Self::RootKeyRotated(body) => body.validate(),
            Self::RootRevoked(body) => body.validate(),
            Self::DeviceAdded(body) => body.validate(),
            Self::DeviceKeyRotated(body) => body.validate(),
            Self::DeviceEncryptionKeyRotated(body) => body.validate(),
            Self::DeviceRevoked(body) => body.validate(),
            Self::DeviceFrozen(body) => body.validate(),
            Self::DeviceReplaced(body) => body.validate(),
            Self::PersonaCreated(body) => body.validate(),
            Self::PersonaKeyRotated(body) => body.validate(),
            Self::PersonaRevoked(body) => body.validate(),
            Self::TrustAttested(body) => body.validate(),
            Self::TrustRevoked(body) => body.validate(),
            Self::RecoveryPolicyCreated(body) => body.validate(),
            Self::GuardianEnrolled(body) => body.validate(),
            Self::RecoveryRequested(body) => body.validate(),
            Self::RecoveryApproved(body) => body.validate(),
            Self::RecoveryContested(body) => body.validate(),
            Self::RecoveryRejected(body) => body.validate(),
            Self::RecoveryExecuted(body) => body.validate(),
            Self::RelayHintUpdated(body) => body.validate(),
            Self::EndpointRotated(body) => body.validate(),
            Self::RelayShutdownNotice(body) => body.validate(),
            Self::StorageRelationshipCreated(body) => body.validate(),
            Self::StorageLedgerUpdated(body) => body.validate(),
            Self::StorageManifestPublished(body) => body.validate(),
            Self::MessageSent(body) => body.validate(),
            Self::ContentPublished(body) => body.validate(),
            Self::DisclosureRevoked(body) => body.validate(),
            Self::LegacyOpaque {
                subject,
                canonical_payload,
                ..
            } => {
                subject.validate()?;
                if canonical_payload.is_empty() {
                    return Err(ValidationError::empty_field("legacy payload"));
                }
                Ok(())
            }
        }
    }
}

// --- CanonicalEncode impls ---

impl CanonicalEncode for EventSubject {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "event-subject",
            &[
                ("kind", self.kind.as_str().to_string()),
                ("subject_id", self.subject_id.clone()),
            ],
        )
    }
}

impl CanonicalEncode for SignerBinding {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "signer-binding",
            &[
                ("signer_kind", self.signer.kind.as_str().to_string()),
                ("signer_id", self.signer.subject_id.clone()),
                ("key_id", self.key_id.clone()),
                ("role", self.role.as_str().to_string()),
            ],
        )
    }
}

impl CanonicalEncode for EventBody {
    fn canonical_encode(&self) -> Vec<u8> {
        match self {
            Self::RootCreated(body) => canonical_record(
                "root-created",
                &[
                    ("root_id", body.root_id.clone()),
                    ("display_name", body.display_name.clone()),
                    ("key_id", body.initial_key.key_id.clone()),
                    ("algorithm", body.initial_key.algorithm.as_str().to_string()),
                    ("public_key", body.initial_key.public_key.clone()),
                ],
            ),
            Self::RootKeyRotated(body) => canonical_record(
                "root-key-rotated",
                &[
                    ("root_id", body.root_id.clone()),
                    ("previous_key_id", body.previous_key_id.clone()),
                    ("new_key_id", body.new_key.key_id.clone()),
                    ("algorithm", body.new_key.algorithm.as_str().to_string()),
                    ("public_key", body.new_key.public_key.clone()),
                ],
            ),
            Self::RootRevoked(body) => canonical_record(
                "root-revoked",
                &[
                    ("root_id", body.root_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::DeviceAdded(body) => canonical_record(
                "device-added",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("label", body.label.clone()),
                    ("key_id", body.initial_key.key_id.clone()),
                    ("algorithm", body.initial_key.algorithm.as_str().to_string()),
                    ("public_key", body.initial_key.public_key.clone()),
                    (
                        "encryption_key_id",
                        body.initial_encryption_key.key_id.clone(),
                    ),
                    (
                        "encryption_algorithm",
                        body.initial_encryption_key.algorithm.as_str().to_string(),
                    ),
                    (
                        "encryption_public_key",
                        body.initial_encryption_key.public_key.clone(),
                    ),
                ],
            ),
            Self::DeviceKeyRotated(body) => canonical_record(
                "device-key-rotated",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("previous_key_id", body.previous_key_id.clone()),
                    ("new_key_id", body.new_key.key_id.clone()),
                    ("algorithm", body.new_key.algorithm.as_str().to_string()),
                    ("public_key", body.new_key.public_key.clone()),
                ],
            ),
            Self::DeviceEncryptionKeyRotated(body) => canonical_record(
                "device-encryption-key-rotated",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    (
                        "previous_encryption_key_id",
                        body.previous_encryption_key_id.clone(),
                    ),
                    (
                        "new_encryption_key_id",
                        body.new_encryption_key.key_id.clone(),
                    ),
                    (
                        "encryption_algorithm",
                        body.new_encryption_key.algorithm.as_str().to_string(),
                    ),
                    (
                        "encryption_public_key",
                        body.new_encryption_key.public_key.clone(),
                    ),
                ],
            ),
            Self::DeviceRevoked(body) => canonical_record(
                "device-revoked",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::DeviceFrozen(body) => canonical_record(
                "device-frozen",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::DeviceReplaced(body) => canonical_record(
                "device-replaced",
                &[
                    ("root_id", body.root_id.clone()),
                    ("replaced_device_id", body.replaced_device_id.clone()),
                    ("replacement_device_id", body.replacement_device_id.clone()),
                ],
            ),
            Self::PersonaCreated(body) => canonical_record(
                "persona-created",
                &[
                    ("root_id", body.root_id.clone()),
                    ("persona_id", body.persona_id.clone()),
                    ("label", body.label.clone()),
                    (
                        "disclosure_profile",
                        body.disclosure_profile.clone().unwrap_or_default(),
                    ),
                    ("survival_mode", body.survival_mode.as_str().to_string()),
                    ("key_id", body.initial_key.key_id.clone()),
                    ("algorithm", body.initial_key.algorithm.as_str().to_string()),
                    ("public_key", body.initial_key.public_key.clone()),
                ],
            ),
            Self::PersonaKeyRotated(body) => canonical_record(
                "persona-key-rotated",
                &[
                    ("root_id", body.root_id.clone()),
                    ("persona_id", body.persona_id.clone()),
                    ("previous_key_id", body.previous_key_id.clone()),
                    ("new_key_id", body.new_key.key_id.clone()),
                    ("algorithm", body.new_key.algorithm.as_str().to_string()),
                    ("public_key", body.new_key.public_key.clone()),
                ],
            ),
            Self::PersonaRevoked(body) => canonical_record(
                "persona-revoked",
                &[
                    ("root_id", body.root_id.clone()),
                    ("persona_id", body.persona_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::RecoveryPolicyCreated(body) => canonical_record(
                "recovery-policy-created",
                &[
                    ("cooldown_seconds", body.cooldown_seconds.to_string()),
                    ("guardian_threshold", body.guardian_threshold.to_string()),
                    ("root_id", body.root_id.clone()),
                ],
            ),
            Self::GuardianEnrolled(body) => canonical_record(
                "guardian-enrolled",
                &[
                    ("root_id", body.root_id.clone()),
                    ("guardian_id", body.guardian_id.clone()),
                    ("guardian_label", body.guardian_label.clone()),
                    ("guardian_public_key", body.guardian_public_key.clone()),
                ],
            ),
            Self::RecoveryRequested(body) => canonical_record(
                "recovery-requested",
                &[
                    ("request_id", body.request_id.clone()),
                    ("root_id", body.root_id.clone()),
                    ("target_device_id", body.target_device_id.clone()),
                ],
            ),
            Self::RecoveryApproved(body) => canonical_record(
                "recovery-approved",
                &[
                    ("request_id", body.request_id.clone()),
                    ("guardian_id", body.guardian_id.clone()),
                ],
            ),
            Self::RecoveryContested(body) => canonical_record(
                "recovery-contested",
                &[
                    ("contested_at_epoch", body.contested_at_epoch.to_string()),
                    ("guardian_id", body.guardian_id.clone()),
                    ("reason", body.reason.clone()),
                    ("request_id", body.request_id.clone()),
                ],
            ),
            Self::RecoveryRejected(body) => canonical_record(
                "recovery-rejected",
                &[
                    ("request_id", body.request_id.clone()),
                    ("rejected_by", body.rejected_by.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::RecoveryExecuted(body) => canonical_record(
                "recovery-executed",
                &[
                    ("request_id", body.request_id.clone()),
                    ("executed_scope", body.executed_scope.as_str().to_string()),
                ],
            ),
            Self::RelayHintUpdated(body) => canonical_record(
                "relay-hint-updated",
                &[
                    ("peer_id", body.peer_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("transport_hint", body.transport_hint.clone()),
                ],
            ),
            Self::EndpointRotated(body) => canonical_record(
                "endpoint-rotated",
                &[
                    ("peer_id", body.peer_id.clone()),
                    ("device_id", body.device_id.clone()),
                    (
                        "previous_transport_hint",
                        body.previous_transport_hint.clone(),
                    ),
                    ("new_transport_hint", body.new_transport_hint.clone()),
                ],
            ),
            Self::RelayShutdownNotice(body) => canonical_record(
                "relay-shutdown-notice",
                &[
                    ("deadline_epoch", body.deadline_epoch.to_string()),
                    ("reason", body.reason.clone()),
                    ("relay_peer_id", body.relay_peer_id.clone()),
                ],
            ),
            Self::StorageRelationshipCreated(body) => canonical_record(
                "storage-relationship-created",
                &[
                    ("root_id", body.root_id.clone()),
                    ("relationship_id", body.relationship.id.clone()),
                    ("local_peer_id", body.relationship.local_peer_id.clone()),
                    ("remote_peer_id", body.relationship.remote_peer_id.clone()),
                    ("approved", body.relationship.approved.to_string()),
                ],
            ),
            Self::StorageLedgerUpdated(body) => canonical_record(
                "storage-ledger-updated",
                &[
                    ("root_id", body.root_id.clone()),
                    ("relationship_id", body.entry.relationship_id.clone()),
                    (
                        "stored_bytes_delta",
                        body.entry.stored_bytes_delta.to_string(),
                    ),
                ],
            ),
            Self::StorageManifestPublished(body) => canonical_record(
                "storage-manifest-published",
                &[
                    ("root_id", body.root_id.clone()),
                    ("relationship_id", body.relationship_id.clone()),
                    (
                        "manifest_payload_hex",
                        bytes_to_hex(&body.manifest.canonical_encode()),
                    ),
                ],
            ),
            Self::TrustAttested(body) => canonical_record(
                "trust-attested",
                &[
                    ("attestation_id", body.attestation_id.clone()),
                    ("attester_persona_id", body.attester_persona_id.clone()),
                    ("subject_persona_id", body.subject_persona_id.clone()),
                    ("domain", body.domain.clone()),
                    ("score", format!("{:.6}", body.score)),
                    (
                        "recipient_bound",
                        body.recipient_bound.clone().unwrap_or_default(),
                    ),
                ],
            ),
            Self::TrustRevoked(body) => canonical_record(
                "trust-revoked",
                &[
                    ("attestation_id", body.attestation_id.clone()),
                    ("attester_persona_id", body.attester_persona_id.clone()),
                ],
            ),
            Self::MessageSent(body) => canonical_record(
                "message-sent",
                &[
                    ("message_id", body.message_id.clone()),
                    ("sender_persona_id", body.sender_persona_id.clone()),
                    ("recipient_persona_id", body.recipient_persona_id.clone()),
                    ("ciphertext_hex", body.ciphertext_hex.clone()),
                ],
            ),
            Self::ContentPublished(body) => canonical_record(
                "content-published",
                &[
                    ("content_id", body.content_id.clone()),
                    ("author_persona_id", body.author_persona_id.clone()),
                    ("content_type", body.content_type.clone()),
                    ("payload_hex", body.payload_hex.clone()),
                    ("visibility", body.visibility.as_str().to_string()),
                ],
            ),
            Self::DisclosureRevoked(body) => canonical_record(
                "disclosure-revoked",
                &[
                    ("revocation_id", body.revocation_id.clone()),
                    ("artifact_id", body.artifact_id.clone()),
                    ("revoker_persona_id", body.revoker_persona_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::LegacyOpaque {
                declared_type,
                subject,
                canonical_payload,
            } => canonical_record(
                "legacy-opaque",
                &[
                    ("declared_type", declared_type.as_str().to_string()),
                    ("subject_kind", subject.kind.as_str().to_string()),
                    ("subject_id", subject.subject_id.clone()),
                    ("payload_hex", bytes_to_hex(canonical_payload)),
                ],
            ),
        }
    }
}

// --- impl_typed_event_canonical_encode macro and invocations ---

macro_rules! impl_typed_event_canonical_encode {
    ($ty:ty, $variant:ident) => {
        impl CanonicalEncode for $ty {
            fn canonical_encode(&self) -> Vec<u8> {
                EventBody::$variant(self.clone()).canonical_encode()
            }
        }
    };
}

impl_typed_event_canonical_encode!(RootCreatedEvent, RootCreated);
impl_typed_event_canonical_encode!(RootKeyRotatedEvent, RootKeyRotated);
impl_typed_event_canonical_encode!(RootRevokedEvent, RootRevoked);
impl_typed_event_canonical_encode!(DeviceAddedEvent, DeviceAdded);
impl_typed_event_canonical_encode!(DeviceKeyRotatedEvent, DeviceKeyRotated);
impl_typed_event_canonical_encode!(DeviceEncryptionKeyRotatedEvent, DeviceEncryptionKeyRotated);
impl_typed_event_canonical_encode!(DeviceRevokedEvent, DeviceRevoked);
impl_typed_event_canonical_encode!(DeviceFrozenEvent, DeviceFrozen);
impl_typed_event_canonical_encode!(DeviceReplacedEvent, DeviceReplaced);
impl_typed_event_canonical_encode!(PersonaCreatedEvent, PersonaCreated);
impl_typed_event_canonical_encode!(PersonaKeyRotatedEvent, PersonaKeyRotated);
impl_typed_event_canonical_encode!(PersonaRevokedEvent, PersonaRevoked);
impl_typed_event_canonical_encode!(RecoveryPolicyCreatedEvent, RecoveryPolicyCreated);
impl_typed_event_canonical_encode!(GuardianEnrolledEvent, GuardianEnrolled);
impl_typed_event_canonical_encode!(RecoveryRequestedEvent, RecoveryRequested);
impl_typed_event_canonical_encode!(RecoveryApprovedEvent, RecoveryApproved);
impl_typed_event_canonical_encode!(RecoveryContestedEvent, RecoveryContested);
impl_typed_event_canonical_encode!(RecoveryRejectedEvent, RecoveryRejected);
impl_typed_event_canonical_encode!(RecoveryExecutedEvent, RecoveryExecuted);
impl_typed_event_canonical_encode!(RelayHintUpdatedEvent, RelayHintUpdated);
impl_typed_event_canonical_encode!(EndpointRotatedEvent, EndpointRotated);
impl_typed_event_canonical_encode!(StorageRelationshipCreatedEvent, StorageRelationshipCreated);
impl_typed_event_canonical_encode!(StorageLedgerUpdatedEvent, StorageLedgerUpdated);
impl_typed_event_canonical_encode!(StorageManifestPublishedEvent, StorageManifestPublished);
impl_typed_event_canonical_encode!(MessageSentEvent, MessageSent);
impl_typed_event_canonical_encode!(ContentPublishedEvent, ContentPublished);
impl_typed_event_canonical_encode!(DisclosureRevokedEvent, DisclosureRevoked);

#[cfg(test)]
mod retention_tests {
    use super::*;

    const ALL_EVENT_TYPES: &[EventType] = &[
        EventType::RootCreated,
        EventType::RootKeyRotated,
        EventType::RootRevoked,
        EventType::DeviceAdded,
        EventType::DeviceKeyRotated,
        EventType::DeviceEncryptionKeyRotated,
        EventType::DeviceRevoked,
        EventType::DeviceFrozen,
        EventType::DeviceReplaced,
        EventType::PersonaCreated,
        EventType::PersonaKeyRotated,
        EventType::PersonaRevoked,
        EventType::LinkageAsserted,
        EventType::LinkageRevoked,
        EventType::TrustAttested,
        EventType::TrustRevoked,
        EventType::DerivedTrustPublished,
        EventType::DerivedTrustRevoked,
        EventType::RecoveryPolicyCreated,
        EventType::RecoveryPolicyUpdated,
        EventType::GuardianEnrolled,
        EventType::RecoveryRequested,
        EventType::RecoveryApproved,
        EventType::RecoveryContested,
        EventType::RecoveryRejected,
        EventType::RecoveryExecuted,
        EventType::FreezeExecuted,
        EventType::MessageSent,
        EventType::ContentPublished,
        EventType::StorageRelationshipCreated,
        EventType::StorageRelationshipUpdated,
        EventType::StorageManifestPublished,
        EventType::StorageLedgerUpdated,
        EventType::StorageRetentionNotice,
        EventType::RelayHintUpdated,
        EventType::EndpointRotated,
        EventType::RelayShutdownNotice,
        EventType::DisclosurePolicyUpdated,
        EventType::DisclosureRevoked,
    ];

    #[test]
    fn every_event_type_has_retention_class() {
        for et in ALL_EVENT_TYPES {
            let _class = et.retention_class();
        }
    }

    #[test]
    fn identity_lifecycle_events_are_permanent() {
        let permanent = [
            EventType::RootCreated,
            EventType::RootRevoked,
            EventType::DeviceAdded,
            EventType::DeviceRevoked,
            EventType::PersonaCreated,
            EventType::PersonaRevoked,
            EventType::RootKeyRotated,
            EventType::DeviceKeyRotated,
            EventType::DeviceEncryptionKeyRotated,
            EventType::PersonaKeyRotated,
        ];
        for et in permanent {
            assert_eq!(
                et.retention_class(),
                RetentionClass::Permanent,
                "{:?} should be Permanent",
                et
            );
        }
    }

    #[test]
    fn routine_operations_are_ephemeral() {
        let ephemeral = [
            EventType::DerivedTrustPublished,
            EventType::DerivedTrustRevoked,
            EventType::StorageRelationshipUpdated,
            EventType::StorageLedgerUpdated,
            EventType::StorageRetentionNotice,
            EventType::RelayHintUpdated,
            EventType::EndpointRotated,
            EventType::RelayShutdownNotice,
            EventType::MessageSent,
            EventType::ContentPublished,
        ];
        for et in ephemeral {
            assert_eq!(
                et.retention_class(),
                RetentionClass::Ephemeral,
                "{:?} should be Ephemeral",
                et
            );
        }
    }

    #[test]
    fn retention_class_roundtrip() {
        for class in [
            RetentionClass::Permanent,
            RetentionClass::LongLived,
            RetentionClass::Ephemeral,
        ] {
            assert_eq!(RetentionClass::parse(class.as_str()), Some(class));
        }
    }

    #[test]
    fn retention_class_parse_rejects_unknown() {
        assert_eq!(RetentionClass::parse("unknown"), None);
        assert_eq!(RetentionClass::parse(""), None);
    }
}
