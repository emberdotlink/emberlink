use std::fmt;

pub const SCHEMA_VERSION: &str = "0.1.0";

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

pub trait CanonicalEncode {
    fn canonical_encode(&self) -> Vec<u8>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub message: String,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersion(pub u16, pub u16, pub u16);

impl SchemaVersion {
    pub const V0_1_0: Self = Self(0, 1, 0);
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRoot {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Persona {
    pub id: String,
    pub root_id: String,
    pub label: String,
    pub preset: VisibilityPreset,
    pub survival_mode: SurvivalMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkageAssertion {
    pub source_root_id: String,
    pub target_root_id: String,
    pub disclosed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMembership {
    pub root_id: String,
    pub device_id: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrustAttestation {
    pub id: String,
    pub attester: String,
    pub subject: String,
    pub domain: String,
    pub score: f32,
    pub recipient_bound: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DerivedTrustStatement {
    pub id: String,
    pub subject: String,
    pub domain: String,
    pub normalized_score: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustExplanation {
    pub summary: String,
    pub redacted_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub root_id: String,
    pub guardian_threshold: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub id: String,
    pub root_id: String,
    pub target_device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryApproval {
    pub request_id: String,
    pub guardian_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryContest {
    pub request_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExecution {
    pub request_id: String,
    pub executed_scope: RecoveryScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRelationship {
    pub id: String,
    pub local_peer_id: String,
    pub remote_peer_id: String,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLedgerEntry {
    pub relationship_id: String,
    pub stored_bytes_delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    pub id: String,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkReference {
    pub manifest_id: String,
    pub chunk_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionNotice {
    pub relationship_id: String,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCursor {
    pub peer_id: String,
    pub last_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEnvelope {
    pub id: String,
    pub opaque_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBatch {
    pub id: String,
    pub event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub peer_id: String,
    pub transport_hint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityPreset {
    Professional,
    Friends,
    Pseudonymous,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurvivalMode {
    Strict,
    LimitedPersonaContinuity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryScope {
    FreezeDevice,
    RestorePersonaAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    RootCreated,
    RootRevoked,
    DeviceAdded,
    DeviceRevoked,
    PersonaCreated,
    PersonaRevoked,
    LinkageAsserted,
    LinkageRevoked,
    TrustAttested,
    TrustRevoked,
    DerivedTrustPublished,
    DerivedTrustRevoked,
    RecoveryPolicyCreated,
    RecoveryPolicyUpdated,
    RecoveryRequested,
    RecoveryApproved,
    RecoveryContested,
    RecoveryRejected,
    RecoveryExecuted,
    FreezeExecuted,
    StorageRelationshipCreated,
    StorageRelationshipUpdated,
    StorageManifestPublished,
    StorageLedgerUpdated,
    StorageRetentionNotice,
    RelayHintUpdated,
    EndpointRotated,
    DisclosurePolicyUpdated,
}

impl Validate for IdentityRoot {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.id.is_empty() {
            return Err(ValidationError::new("root id must not be empty"));
        }
        Ok(())
    }
}

impl Validate for Persona {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.id.is_empty() || self.root_id.is_empty() {
            return Err(ValidationError::new("persona id and root id must not be empty"));
        }
        Ok(())
    }
}

impl CanonicalEncode for IdentityRoot {
    fn canonical_encode(&self) -> Vec<u8> {
        format!("IdentityRoot|{}|{}", self.id, self.display_name).into_bytes()
    }
}

impl CanonicalEncode for Persona {
    fn canonical_encode(&self) -> Vec<u8> {
        format!("Persona|{}|{}|{}", self.id, self.root_id, self.label).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_frozen_for_bootstrap() {
        assert_eq!(SCHEMA_VERSION, "0.1.0");
        assert_eq!(SchemaVersion::V0_1_0.to_string(), "0.1.0");
    }

    #[test]
    fn persona_requires_parent_root() {
        let persona = Persona {
            id: "persona-1".into(),
            root_id: String::new(),
            label: "friends".into(),
            preset: VisibilityPreset::Friends,
            survival_mode: SurvivalMode::Strict,
        };

        assert!(persona.validate().is_err());
    }
}

