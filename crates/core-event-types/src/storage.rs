use core_types::encoding::*;
use core_types::{CanonicalEncode, Validate, ValidationError};

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
pub struct ManifestDeviceAccess {
    pub device_id: String,
    pub wrapped_manifest_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    pub id: String,
    pub encrypted_root_chunk_id: String,
    pub chunks: Vec<ChunkReference>,
    pub authorized_devices: Vec<ManifestDeviceAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkReference {
    pub manifest_id: String,
    pub chunk_id: String,
    pub ordinal: u32,
    pub ciphertext_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionNotice {
    pub relationship_id: String,
    pub notice: String,
}

// --- BlockStore trait ---

/// Pluggable backend for encrypted block storage.
///
/// Blocks are opaque ciphertext keyed by content-addressed chunk IDs.
/// The protocol layer handles encryption, manifests, and access control;
/// BlockStore implementations only need to persist and retrieve bytes.
pub trait BlockStore {
    /// Store a block. Overwrites if chunk_id already exists.
    fn put_block(
        &self,
        chunk_id: &str,
        nonce_hex: &str,
        ciphertext: &[u8],
    ) -> Result<(), ValidationError>;

    /// Retrieve a block's nonce and ciphertext. Returns None if not found.
    fn get_block(&self, chunk_id: &str) -> Result<Option<(String, Vec<u8>)>, ValidationError>;

    /// Delete a block by chunk ID.
    fn delete_block(&self, chunk_id: &str) -> Result<(), ValidationError>;

    /// Check whether a block exists.
    fn has_block(&self, chunk_id: &str) -> Result<bool, ValidationError>;

    /// List all stored chunk IDs.
    fn list_block_ids(&self) -> Result<Vec<String>, ValidationError>;
}

// --- Vault types ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOwnerKind {
    Root,
    Persona,
}

impl VaultOwnerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Persona => "persona",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root" => Some(Self::Root),
            "persona" => Some(Self::Persona),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultNamespace {
    pub owner_kind: VaultOwnerKind,
    pub owner_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultObjectClass {
    RootRecoveryBundle,
    RootDeviceContinuityBundle,
    PersonaSecret,
    PersonaCredential,
    PersonaNote,
    PersonaDocument,
    PersonaAttachment,
    PersonaExportBundle,
    StructuredRecord,
}

impl VaultObjectClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootRecoveryBundle => "root-recovery-bundle",
            Self::RootDeviceContinuityBundle => "root-device-continuity-bundle",
            Self::PersonaSecret => "persona-secret",
            Self::PersonaCredential => "persona-credential",
            Self::PersonaNote => "persona-note",
            Self::PersonaDocument => "persona-document",
            Self::PersonaAttachment => "persona-attachment",
            Self::PersonaExportBundle => "persona-export-bundle",
            Self::StructuredRecord => "structured-record",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root-recovery-bundle" => Some(Self::RootRecoveryBundle),
            "root-device-continuity-bundle" => Some(Self::RootDeviceContinuityBundle),
            "persona-secret" => Some(Self::PersonaSecret),
            "persona-credential" => Some(Self::PersonaCredential),
            "persona-note" => Some(Self::PersonaNote),
            "persona-document" => Some(Self::PersonaDocument),
            "persona-attachment" => Some(Self::PersonaAttachment),
            "persona-export-bundle" => Some(Self::PersonaExportBundle),
            "structured-record" => Some(Self::StructuredRecord),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredEncoding {
    Json,
    Cbor,
}

impl StructuredEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Cbor => "cbor",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "cbor" => Some(Self::Cbor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredRecordMeta {
    pub schema_id: String,
    pub schema_version: String,
    pub encoding: StructuredEncoding,
    pub app_namespace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Catalog,
    StructuredRecord,
    BinaryBlob,
    PresentationArtifact,
}

impl PayloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::StructuredRecord => "structured-record",
            Self::BinaryBlob => "binary-blob",
            Self::PresentationArtifact => "presentation-artifact",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "catalog" => Some(Self::Catalog),
            "structured-record" => Some(Self::StructuredRecord),
            "binary-blob" => Some(Self::BinaryBlob),
            "presentation-artifact" => Some(Self::PresentationArtifact),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityPolicy {
    LocalOnly,
    ReplicatedToApprovedPeers,
    CriticalIdentity,
}

impl DurabilityPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local-only",
            Self::ReplicatedToApprovedPeers => "replicated-to-approved-peers",
            Self::CriticalIdentity => "critical-identity",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local-only" => Some(Self::LocalOnly),
            "replicated-to-approved-peers" => Some(Self::ReplicatedToApprovedPeers),
            "critical-identity" => Some(Self::CriticalIdentity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionPolicy {
    KeepLatest,
    KeepLastN(u16),
    KeepAll,
}

impl RetentionPolicy {
    pub fn policy_name(&self) -> &'static str {
        match self {
            Self::KeepLatest => "keep-latest",
            Self::KeepLastN(_) => "keep-last-n",
            Self::KeepAll => "keep-all",
        }
    }

    pub fn retain_count(&self) -> Option<u16> {
        match self {
            Self::KeepLastN(count) => Some(*count),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultObject {
    pub id: String,
    pub namespace: VaultNamespace,
    pub class: VaultObjectClass,
    pub latest_revision_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub durability: DurabilityPolicy,
    pub retention: RetentionPolicy,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRevision {
    pub id: String,
    pub object_id: String,
    pub manifest_id: String,
    pub payload_kind: PayloadKind,
    pub content_type: String,
    pub created_at: u64,
    pub created_by_device_id: String,
    pub parent_revision_id: Option<String>,
    pub structured_record: Option<StructuredRecordMeta>,
    pub claim: Option<ClaimMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationAudienceKind {
    Peer,
    Service,
}

impl PresentationAudienceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Service => "service",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "peer" => Some(Self::Peer),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationTemplate {
    pub id: String,
    pub namespace: VaultNamespace,
    pub source_object_id: String,
    pub schema_id: String,
    pub audience_kind: PresentationAudienceKind,
    pub field_paths: Vec<String>,
    pub expires_after_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationArtifact {
    pub id: String,
    pub source_object_id: String,
    pub source_revision_id: String,
    pub recipient_kind: PresentationAudienceKind,
    pub recipient_id: String,
    pub schema_id: String,
    pub manifest_id: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

// --- Claim types ---

/// The kind of claim being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimType {
    /// Self-asserted claim (e.g., "I am a software engineer").
    SelfAsserted,
    /// Peer-attested claim (e.g., "Alice worked at Acme Corp").
    PeerAttested,
    /// Service-issued claim (e.g., credential imported from external provider).
    ServiceIssued,
    /// Derived claim (e.g., "age >= 18" derived from a birthdate claim).
    Derived,
}

impl ClaimType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfAsserted => "self-asserted",
            Self::PeerAttested => "peer-attested",
            Self::ServiceIssued => "service-issued",
            Self::Derived => "derived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "self-asserted" => Some(Self::SelfAsserted),
            "peer-attested" => Some(Self::PeerAttested),
            "service-issued" => Some(Self::ServiceIssued),
            "derived" => Some(Self::Derived),
            _ => None,
        }
    }
}

/// Metadata that marks a vault structured record as a verifiable claim.
/// Stored alongside StructuredRecordMeta in vault revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMeta {
    /// What kind of claim this is.
    pub claim_type: ClaimType,
    /// The persona that issued this claim.
    pub issuer_persona_id: String,
    /// The persona this claim is about.
    pub subject_persona_id: String,
    /// Semantic type of the claim content (e.g., "employment", "membership").
    pub claim_schema: String,
    /// When this claim was issued (epoch seconds).
    pub issued_at: u64,
    /// When this claim expires, if ever (epoch seconds).
    pub expires_at: Option<u64>,
    /// For service-issued claims: identifier of the external service.
    pub external_issuer: Option<String>,
    /// For service-issued claims: the original credential ID from the external system.
    pub external_credential_id: Option<String>,
}

// --- Service binding types (local-only) ---

/// Describes an external service type that a persona can bind to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDescriptor {
    /// Adapter kind identifier (e.g., "oauth2", "activitypub", "passkey", "password").
    pub adapter_kind: String,
    /// Human-readable service name (e.g., "GitHub", "Mastodon").
    pub service_label: String,
    /// Service-specific endpoint or configuration.
    pub endpoint: String,
}

/// Local-only association between a persona and an external service account.
/// Never promoted to protocol state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    pub id: String,
    pub persona_id: String,
    pub descriptor: ServiceDescriptor,
    /// Opaque service-specific account identifier (e.g., username, handle).
    pub external_account_id: String,
    /// When this binding was created (epoch seconds).
    pub created_at: u64,
}

/// Result of presenting a credential to an external service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationResult {
    /// Service accepted the credential presentation.
    Accepted { response_payload: Option<String> },
    /// Service rejected the credential.
    Rejected { reason: String },
    /// Adapter-level error (network, format, etc.).
    Error { message: String },
}

/// Result of importing a credential from an external service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedClaim {
    /// The claim type (maps to ClaimType).
    pub claim_type: String,
    /// Structured payload in the protocol's native format.
    pub payload_json: String,
    /// External issuer identifier for provenance tracking.
    pub external_issuer: String,
    /// When the external credential was issued, if known.
    pub external_issued_at: Option<u64>,
    /// When the external credential expires, if known.
    pub external_expires_at: Option<u64>,
}

/// Pluggable adapter for bridging personas to external services.
///
/// Implementations handle format translation and API interaction.
/// They never hold private keys or modify protocol state.
pub trait ServiceAdapter {
    /// Present a signed disclosure artifact to the external service.
    fn present(
        &self,
        binding: &ServiceBinding,
        disclosure_payload: &[u8],
    ) -> Result<PresentationResult, ValidationError>;

    /// Import a credential from the external service into protocol-native format.
    fn import(&self, binding: &ServiceBinding) -> Result<Vec<ImportedClaim>, ValidationError>;

    /// Check whether the external service is reachable and the binding is still valid.
    fn verify_binding(&self, binding: &ServiceBinding) -> Result<bool, ValidationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCatalog {
    pub namespace: VaultNamespace,
    pub objects: Vec<VaultObject>,
    pub revisions: Vec<VaultRevision>,
}

// --- decode_canonical impls on types ---

impl VaultObject {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_vault_object_canonical(payload)
    }
}

impl VaultRevision {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_vault_revision_canonical(payload)
    }
}

impl PresentationTemplate {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_presentation_template_canonical(payload)
    }
}

impl PresentationArtifact {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_presentation_artifact_canonical(payload)
    }
}

impl VaultCatalog {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_vault_catalog_canonical(payload)
    }
}

impl FileManifest {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self, ValidationError> {
        decode_file_manifest_canonical(payload)
    }
}

// --- Validate impls ---

impl Validate for StorageRelationship {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "storage relationship id")?;
        validate_non_empty(&self.local_peer_id, "local peer id")?;
        validate_non_empty(&self.remote_peer_id, "remote peer id")?;
        if self.local_peer_id == self.remote_peer_id {
            return Err(ValidationError::new(
                "storage relationship peers must differ",
            ));
        }
        Ok(())
    }
}

impl Validate for StorageLedgerEntry {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.relationship_id, "storage relationship id")
    }
}

impl Validate for ManifestDeviceAccess {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.device_id, "manifest device id")?;
        validate_non_empty(&self.wrapped_manifest_key_hex, "wrapped manifest key")
    }
}

impl Validate for FileManifest {
    fn validate(&self) -> Result<(), ValidationError> {
        use std::collections::HashSet;

        validate_non_empty(&self.id, "file manifest id")?;
        validate_non_empty(&self.encrypted_root_chunk_id, "encrypted root chunk id")?;
        if self.chunks.is_empty() {
            return Err(ValidationError::new(
                "file manifest must contain at least one chunk reference",
            ));
        }
        let mut seen_chunk_ids = HashSet::new();
        let mut seen_ordinals = HashSet::new();
        let mut root_chunk_found = false;
        for chunk in &self.chunks {
            chunk.validate()?;
            if chunk.manifest_id != self.id {
                return Err(ValidationError::new(
                    "file manifest chunk references must point back to the manifest id",
                ));
            }
            if !seen_chunk_ids.insert(chunk.chunk_id.as_str()) {
                return Err(ValidationError::new(
                    "file manifest chunk ids must be unique",
                ));
            }
            if !seen_ordinals.insert(chunk.ordinal) {
                return Err(ValidationError::new(
                    "file manifest chunk ordinals must be unique",
                ));
            }
            if chunk.chunk_id == self.encrypted_root_chunk_id {
                if chunk.ordinal != 0 {
                    return Err(ValidationError::new(
                        "encrypted root chunk must be the first chunk in the manifest",
                    ));
                }
                root_chunk_found = true;
            }
        }
        if !root_chunk_found {
            return Err(ValidationError::new(
                "file manifest must include the encrypted root chunk at ordinal 0",
            ));
        }
        let mut seen_devices = HashSet::new();
        for access in &self.authorized_devices {
            access.validate()?;
            if !seen_devices.insert(access.device_id.as_str()) {
                return Err(ValidationError::new(
                    "file manifest device access entries must be unique",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for ChunkReference {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.manifest_id, "chunk manifest id")?;
        validate_non_empty(&self.chunk_id, "chunk id")?;
        if self.ciphertext_bytes == 0 {
            return Err(ValidationError::new(
                "chunk ciphertext size must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl Validate for RetentionNotice {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.relationship_id, "storage relationship id")?;
        validate_non_empty(&self.notice, "retention notice")
    }
}

impl Validate for VaultNamespace {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.owner_id, "vault owner id")
    }
}

impl Validate for StructuredRecordMeta {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.schema_id, "structured schema id")?;
        validate_non_empty(&self.schema_version, "structured schema version")?;
        validate_non_empty(&self.app_namespace, "structured app namespace")
    }
}

impl Validate for VaultObject {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "vault object id")?;
        self.namespace.validate()?;
        validate_non_empty(&self.latest_revision_id, "latest revision id")?;
        if self.updated_at < self.created_at {
            return Err(ValidationError::new(
                "vault object updated_at must be >= created_at",
            ));
        }
        match self.retention {
            RetentionPolicy::KeepLastN(0) => Err(ValidationError::new(
                "vault retention keep-last-n count must be greater than zero",
            )),
            _ => Ok(()),
        }
    }
}

impl Validate for VaultRevision {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "vault revision id")?;
        validate_non_empty(&self.object_id, "vault object id")?;
        validate_non_empty(&self.manifest_id, "vault manifest id")?;
        validate_non_empty(&self.content_type, "vault content type")?;
        validate_non_empty(&self.created_by_device_id, "vault creating device id")?;
        if self.payload_kind == PayloadKind::StructuredRecord && self.structured_record.is_none() {
            return Err(ValidationError::new(
                "structured-record payloads require structured record metadata",
            ));
        }
        if self.payload_kind != PayloadKind::StructuredRecord && self.structured_record.is_some() {
            return Err(ValidationError::new(
                "structured record metadata is only valid for structured-record payloads",
            ));
        }
        if let Some(structured) = &self.structured_record {
            structured.validate()?;
        }
        if let Some(claim) = &self.claim {
            claim.validate()?;
            if self.structured_record.is_none() {
                return Err(ValidationError::new(
                    "claim metadata requires structured record metadata",
                ));
            }
        }
        if self.parent_revision_id.as_deref() == Some(self.id.as_str()) {
            return Err(ValidationError::new(
                "vault revision cannot name itself as parent",
            ));
        }
        Ok(())
    }
}

impl Validate for PresentationTemplate {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "presentation template id")?;
        self.namespace.validate()?;
        validate_non_empty(&self.source_object_id, "presentation source object id")?;
        validate_non_empty(&self.schema_id, "presentation schema id")?;
        if self.field_paths.is_empty() {
            return Err(ValidationError::new(
                "presentation templates require at least one field path",
            ));
        }
        for field_path in &self.field_paths {
            validate_non_empty(field_path, "presentation field path")?;
        }
        Ok(())
    }
}

impl Validate for PresentationArtifact {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "presentation artifact id")?;
        validate_non_empty(&self.source_object_id, "presentation source object id")?;
        validate_non_empty(&self.source_revision_id, "presentation source revision id")?;
        validate_non_empty(&self.recipient_id, "presentation recipient id")?;
        validate_non_empty(&self.schema_id, "presentation schema id")?;
        validate_non_empty(&self.manifest_id, "presentation manifest id")?;
        if self.expires_at.is_some_and(|exp| exp <= self.issued_at) {
            return Err(ValidationError::new(
                "presentation expiry must be after issue time",
            ));
        }
        Ok(())
    }
}

impl Validate for ClaimMeta {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.issuer_persona_id, "claim issuer persona id")?;
        validate_non_empty(&self.subject_persona_id, "claim subject persona id")?;
        validate_non_empty(&self.claim_schema, "claim schema")?;
        if self.issued_at == 0 {
            return Err(ValidationError::new("claim issued_at must be non-zero"));
        }
        if self.expires_at.is_some_and(|exp| exp <= self.issued_at) {
            return Err(ValidationError::new(
                "claim expiry must be after issue time",
            ));
        }
        if self.claim_type == ClaimType::ServiceIssued && self.external_issuer.is_none() {
            return Err(ValidationError::new(
                "service-issued claims require an external issuer",
            ));
        }
        Ok(())
    }
}

impl Validate for ServiceDescriptor {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.adapter_kind, "service adapter kind")?;
        validate_non_empty(&self.service_label, "service label")
    }
}

impl Validate for ServiceBinding {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "service binding id")?;
        validate_non_empty(&self.persona_id, "service binding persona id")?;
        self.descriptor.validate()?;
        validate_non_empty(&self.external_account_id, "external account id")?;
        if self.created_at == 0 {
            return Err(ValidationError::new(
                "service binding created_at must be non-zero",
            ));
        }
        Ok(())
    }
}

impl Validate for PresentationResult {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Accepted { .. } => Ok(()),
            Self::Rejected { reason } => {
                validate_non_empty(reason, "presentation rejection reason")
            }
            Self::Error { message } => validate_non_empty(message, "presentation error message"),
        }
    }
}

impl Validate for ImportedClaim {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.claim_type, "imported claim type")?;
        validate_non_empty(&self.payload_json, "imported claim payload json")?;
        validate_non_empty(&self.external_issuer, "imported claim external issuer")?;
        let payload =
            serde_json::from_str::<serde_json::Value>(&self.payload_json).map_err(|err| {
                ValidationError::new(format!("imported claim payload must be valid json: {err}"))
            })?;
        if !payload.is_object() {
            return Err(ValidationError::new(
                "imported claim payload must be a json object",
            ));
        }
        if self
            .external_expires_at
            .zip(self.external_issued_at)
            .is_some_and(|(expires_at, issued_at)| expires_at <= issued_at)
        {
            return Err(ValidationError::new(
                "imported claim expiry must be after issue time",
            ));
        }
        Ok(())
    }
}

impl Validate for VaultCatalog {
    fn validate(&self) -> Result<(), ValidationError> {
        use std::collections::{BTreeMap, BTreeSet};

        self.namespace.validate()?;

        let mut object_ids = BTreeSet::new();
        let mut revision_ids = BTreeSet::new();
        let mut object_latest_revision = BTreeMap::new();

        for object in &self.objects {
            object.validate()?;
            if object.namespace != self.namespace {
                return Err(ValidationError::new(
                    "vault object namespace must match catalog namespace",
                ));
            }
            if !object_ids.insert(object.id.clone()) {
                return Err(ValidationError::new(format!(
                    "duplicate vault object id: {}",
                    object.id
                )));
            }
            object_latest_revision.insert(object.id.clone(), object.latest_revision_id.clone());
        }

        let mut revisions_by_id = BTreeMap::new();
        for revision in &self.revisions {
            revision.validate()?;
            if !object_ids.contains(&revision.object_id) {
                return Err(ValidationError::new(format!(
                    "vault revision references unknown object: {}",
                    revision.object_id
                )));
            }
            if !revision_ids.insert(revision.id.clone()) {
                return Err(ValidationError::new(format!(
                    "duplicate vault revision id: {}",
                    revision.id
                )));
            }
            revisions_by_id.insert(revision.id.clone(), revision);
        }

        for object in &self.objects {
            let latest = object_latest_revision
                .get(&object.id)
                .expect("object latest revision tracked");
            let revision = revisions_by_id.get(latest).ok_or_else(|| {
                ValidationError::new(format!(
                    "vault object latest revision is missing from catalog: {}",
                    latest
                ))
            })?;
            if revision.object_id != object.id {
                return Err(ValidationError::new(
                    "vault object latest revision does not belong to the object",
                ));
            }
        }

        for revision in &self.revisions {
            if let Some(parent_id) = &revision.parent_revision_id {
                let parent = revisions_by_id.get(parent_id).ok_or_else(|| {
                    ValidationError::new(format!(
                        "vault revision parent is missing from catalog: {}",
                        parent_id
                    ))
                })?;
                if parent.object_id != revision.object_id {
                    return Err(ValidationError::new(
                        "vault revision parent must belong to the same object",
                    ));
                }
            }
        }

        Ok(())
    }
}

// --- CanonicalEncode impls ---

/// Canonical byte encoding of a grant `Block`. These are the exact bytes the
/// previous block's `pubkey_next` (or the persona root key, for block 0) signs
/// to produce `SignedBlock.signature`.
///
/// The encoding is `"type=grant-block-v1\n"` followed by `serde_json::to_vec`
/// of the `Block`. `serde_json` serializes struct fields in declaration order
/// and `BTreeMap`/sorted keys deterministically; `Block` and its transitive
/// types contain no `HashMap`, so the encoding is canonical. All `Option`
/// fields use `skip_serializing_if = "Option::is_none"`, so absent fields
/// never appear as `null` and changing the option from None to Some does not
/// silently slide bytes around.
///
/// The `type=grant-block-v1` prefix namespaces this encoding — if the shape
/// changes incompatibly, bump to `v2` and verifiers reject mixed-version
/// chains at the signature layer.
impl CanonicalEncode for StorageRelationship {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "storage-relationship",
            &[
                ("id", self.id.clone()),
                ("local_peer_id", self.local_peer_id.clone()),
                ("remote_peer_id", self.remote_peer_id.clone()),
                ("approved", self.approved.to_string()),
            ],
        )
    }
}

impl CanonicalEncode for StorageLedgerEntry {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "storage-ledger-entry",
            &[
                ("relationship_id", self.relationship_id.clone()),
                ("stored_bytes_delta", self.stored_bytes_delta.to_string()),
            ],
        )
    }
}

impl CanonicalEncode for ManifestDeviceAccess {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "manifest-device-access",
            &[
                ("device_id", self.device_id.clone()),
                (
                    "wrapped_manifest_key_hex",
                    self.wrapped_manifest_key_hex.clone(),
                ),
            ],
        )
    }
}

impl CanonicalEncode for FileManifest {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut fields = vec![
            ("id".to_string(), self.id.clone()),
            (
                "encrypted_root_chunk_id".to_string(),
                self.encrypted_root_chunk_id.clone(),
            ),
            ("chunk_count".to_string(), self.chunks.len().to_string()),
            (
                "authorized_device_count".to_string(),
                self.authorized_devices.len().to_string(),
            ),
        ];

        let mut chunks = self.chunks.clone();
        chunks.sort_by(|left, right| {
            left.ordinal
                .cmp(&right.ordinal)
                .then_with(|| left.chunk_id.cmp(&right.chunk_id))
        });
        for (index, chunk) in chunks.iter().enumerate() {
            fields.push((format!("chunk_{index:04}_chunk_id"), chunk.chunk_id.clone()));
            fields.push((
                format!("chunk_{index:04}_ordinal"),
                chunk.ordinal.to_string(),
            ));
            fields.push((
                format!("chunk_{index:04}_ciphertext_bytes"),
                chunk.ciphertext_bytes.to_string(),
            ));
        }

        let mut authorized_devices = self.authorized_devices.clone();
        authorized_devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        for (index, access) in authorized_devices.iter().enumerate() {
            fields.push((
                format!("device_access_{index:04}_device_id"),
                access.device_id.clone(),
            ));
            fields.push((
                format!("device_access_{index:04}_wrapped_manifest_key_hex"),
                access.wrapped_manifest_key_hex.clone(),
            ));
        }

        let field_refs: Vec<(&str, String)> = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();

        canonical_record("file-manifest", &field_refs)
    }
}

impl CanonicalEncode for ChunkReference {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "chunk-reference",
            &[
                ("manifest_id", self.manifest_id.clone()),
                ("chunk_id", self.chunk_id.clone()),
                ("ordinal", self.ordinal.to_string()),
                ("ciphertext_bytes", self.ciphertext_bytes.to_string()),
            ],
        )
    }
}

impl CanonicalEncode for RetentionNotice {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "retention-notice",
            &[
                ("relationship_id", self.relationship_id.clone()),
                ("notice", self.notice.clone()),
            ],
        )
    }
}

impl CanonicalEncode for VaultNamespace {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "vault-namespace",
            &[
                ("owner_kind", self.owner_kind.as_str().to_string()),
                ("owner_id", self.owner_id.clone()),
            ],
        )
    }
}

impl CanonicalEncode for StructuredRecordMeta {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "structured-record-meta",
            &[
                ("schema_id", self.schema_id.clone()),
                ("schema_version", self.schema_version.clone()),
                ("encoding", self.encoding.as_str().to_string()),
                ("app_namespace", self.app_namespace.clone()),
            ],
        )
    }
}

impl CanonicalEncode for VaultObject {
    fn canonical_encode(&self) -> Vec<u8> {
        let retention_count = self
            .retention
            .retain_count()
            .map(|value| value.to_string())
            .unwrap_or_default();
        canonical_record(
            "vault-object",
            &[
                ("id", self.id.clone()),
                ("owner_kind", self.namespace.owner_kind.as_str().to_string()),
                ("owner_id", self.namespace.owner_id.clone()),
                ("class", self.class.as_str().to_string()),
                ("latest_revision_id", self.latest_revision_id.clone()),
                ("created_at", self.created_at.to_string()),
                ("updated_at", self.updated_at.to_string()),
                ("durability", self.durability.as_str().to_string()),
                ("retention_policy", self.retention.policy_name().to_string()),
                ("retention_count", retention_count),
                ("deleted", self.deleted.to_string()),
            ],
        )
    }
}

impl CanonicalEncode for VaultRevision {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut fields = vec![
            ("id".to_string(), self.id.clone()),
            ("object_id".to_string(), self.object_id.clone()),
            ("manifest_id".to_string(), self.manifest_id.clone()),
            (
                "payload_kind".to_string(),
                self.payload_kind.as_str().to_string(),
            ),
            ("content_type".to_string(), self.content_type.clone()),
            ("created_at".to_string(), self.created_at.to_string()),
            (
                "created_by_device_id".to_string(),
                self.created_by_device_id.clone(),
            ),
            (
                "parent_revision_id".to_string(),
                self.parent_revision_id.clone().unwrap_or_default(),
            ),
        ];
        if let Some(structured) = &self.structured_record {
            fields.push(("schema_id".to_string(), structured.schema_id.clone()));
            fields.push((
                "schema_version".to_string(),
                structured.schema_version.clone(),
            ));
            fields.push((
                "encoding".to_string(),
                structured.encoding.as_str().to_string(),
            ));
            fields.push((
                "app_namespace".to_string(),
                structured.app_namespace.clone(),
            ));
        }
        if let Some(claim) = &self.claim {
            fields.push((
                "claim_type".to_string(),
                claim.claim_type.as_str().to_string(),
            ));
            fields.push((
                "claim_issuer_persona_id".to_string(),
                claim.issuer_persona_id.clone(),
            ));
            fields.push((
                "claim_subject_persona_id".to_string(),
                claim.subject_persona_id.clone(),
            ));
            fields.push(("claim_schema".to_string(), claim.claim_schema.clone()));
            fields.push(("claim_issued_at".to_string(), claim.issued_at.to_string()));
            fields.push((
                "claim_expires_at".to_string(),
                claim.expires_at.map(|v| v.to_string()).unwrap_or_default(),
            ));
            fields.push((
                "claim_external_issuer".to_string(),
                claim.external_issuer.clone().unwrap_or_default(),
            ));
            fields.push((
                "claim_external_credential_id".to_string(),
                claim.external_credential_id.clone().unwrap_or_default(),
            ));
        }
        let field_refs: Vec<(&str, String)> = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        canonical_record("vault-revision", &field_refs)
    }
}

impl CanonicalEncode for PresentationTemplate {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut field_paths = self.field_paths.clone();
        field_paths.sort();
        let mut fields = vec![
            ("id".to_string(), self.id.clone()),
            (
                "owner_kind".to_string(),
                self.namespace.owner_kind.as_str().to_string(),
            ),
            ("owner_id".to_string(), self.namespace.owner_id.clone()),
            (
                "source_object_id".to_string(),
                self.source_object_id.clone(),
            ),
            ("schema_id".to_string(), self.schema_id.clone()),
            (
                "audience_kind".to_string(),
                self.audience_kind.as_str().to_string(),
            ),
            (
                "expires_after_secs".to_string(),
                self.expires_after_secs
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
        ];
        for (index, field_path) in field_paths.iter().enumerate() {
            fields.push((format!("field_path_{index:04}"), field_path.clone()));
        }
        let field_refs: Vec<(&str, String)> = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        canonical_record("presentation-template", &field_refs)
    }
}

impl CanonicalEncode for PresentationArtifact {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "presentation-artifact",
            &[
                ("id", self.id.clone()),
                ("source_object_id", self.source_object_id.clone()),
                ("source_revision_id", self.source_revision_id.clone()),
                ("recipient_kind", self.recipient_kind.as_str().to_string()),
                ("recipient_id", self.recipient_id.clone()),
                ("schema_id", self.schema_id.clone()),
                ("manifest_id", self.manifest_id.clone()),
                ("issued_at", self.issued_at.to_string()),
                (
                    "expires_at",
                    self.expires_at
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
            ],
        )
    }
}

impl CanonicalEncode for ClaimMeta {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "claim-meta",
            &[
                ("claim_type", self.claim_type.as_str().to_string()),
                ("issuer_persona_id", self.issuer_persona_id.clone()),
                ("subject_persona_id", self.subject_persona_id.clone()),
                ("claim_schema", self.claim_schema.clone()),
                ("issued_at", self.issued_at.to_string()),
                (
                    "expires_at",
                    self.expires_at.map(|v| v.to_string()).unwrap_or_default(),
                ),
                (
                    "external_issuer",
                    self.external_issuer.clone().unwrap_or_default(),
                ),
                (
                    "external_credential_id",
                    self.external_credential_id.clone().unwrap_or_default(),
                ),
            ],
        )
    }
}

impl CanonicalEncode for ServiceDescriptor {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "service-descriptor",
            &[
                ("adapter_kind", self.adapter_kind.clone()),
                ("service_label", self.service_label.clone()),
                ("endpoint", self.endpoint.clone()),
            ],
        )
    }
}

impl CanonicalEncode for ServiceBinding {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "service-binding",
            &[
                ("id", self.id.clone()),
                ("persona_id", self.persona_id.clone()),
                ("adapter_kind", self.descriptor.adapter_kind.clone()),
                ("service_label", self.descriptor.service_label.clone()),
                ("endpoint", self.descriptor.endpoint.clone()),
                ("external_account_id", self.external_account_id.clone()),
                ("created_at", self.created_at.to_string()),
            ],
        )
    }
}

impl CanonicalEncode for VaultCatalog {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut fields = vec![
            (
                "owner_kind".to_string(),
                self.namespace.owner_kind.as_str().to_string(),
            ),
            ("owner_id".to_string(), self.namespace.owner_id.clone()),
            ("object_count".to_string(), self.objects.len().to_string()),
            (
                "revision_count".to_string(),
                self.revisions.len().to_string(),
            ),
        ];

        let mut objects = self.objects.clone();
        objects.sort_by(|left, right| left.id.cmp(&right.id));
        for (index, object) in objects.iter().enumerate() {
            fields.push((
                format!("object_{index:04}_payload_hex"),
                bytes_to_hex(&object.canonical_encode()),
            ));
        }

        let mut revisions = self.revisions.clone();
        revisions.sort_by(|left, right| left.id.cmp(&right.id));
        for (index, revision) in revisions.iter().enumerate() {
            fields.push((
                format!("revision_{index:04}_payload_hex"),
                bytes_to_hex(&revision.canonical_encode()),
            ));
        }

        let field_refs: Vec<(&str, String)> = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        canonical_record("vault-catalog", &field_refs)
    }
}

// --- decode_*_canonical helper functions ---

pub(crate) fn decode_file_manifest_canonical(
    payload: &[u8],
) -> Result<FileManifest, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "file-manifest" {
        return Err(ValidationError::new(format!(
            "unsupported canonical file manifest type: {record_type}"
        )));
    }

    let manifest_id = required_field(&fields, "id")?;
    let chunk_count = required_field(&fields, "chunk_count")?
        .parse::<usize>()
        .map_err(|err| ValidationError::new(format!("invalid chunk count: {err}")))?;
    let mut chunks = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        chunks.push(ChunkReference {
            manifest_id: manifest_id.clone(),
            chunk_id: required_field(&fields, &format!("chunk_{index:04}_chunk_id"))?,
            ordinal: required_field(&fields, &format!("chunk_{index:04}_ordinal"))?
                .parse::<u32>()
                .map_err(|err| ValidationError::new(format!("invalid chunk ordinal: {err}")))?,
            ciphertext_bytes: required_field(
                &fields,
                &format!("chunk_{index:04}_ciphertext_bytes"),
            )?
            .parse::<u64>()
            .map_err(|err| {
                ValidationError::new(format!("invalid chunk ciphertext bytes: {err}"))
            })?,
        });
    }

    let authorized_device_count = required_field(&fields, "authorized_device_count")?
        .parse::<usize>()
        .map_err(|err| ValidationError::new(format!("invalid authorized device count: {err}")))?;
    let mut authorized_devices = Vec::with_capacity(authorized_device_count);
    for index in 0..authorized_device_count {
        authorized_devices.push(ManifestDeviceAccess {
            device_id: required_field(&fields, &format!("device_access_{index:04}_device_id"))?,
            wrapped_manifest_key_hex: required_field(
                &fields,
                &format!("device_access_{index:04}_wrapped_manifest_key_hex"),
            )?,
        });
    }

    Ok(FileManifest {
        id: manifest_id,
        encrypted_root_chunk_id: required_field(&fields, "encrypted_root_chunk_id")?,
        chunks,
        authorized_devices,
    })
}

fn decode_vault_object_canonical(payload: &[u8]) -> Result<VaultObject, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "vault-object" {
        return Err(ValidationError::new(format!(
            "unsupported canonical vault object type: {record_type}"
        )));
    }

    let retention_name = required_field(&fields, "retention_policy")?;
    let retention = match retention_name.as_str() {
        "keep-latest" => RetentionPolicy::KeepLatest,
        "keep-all" => RetentionPolicy::KeepAll,
        "keep-last-n" => RetentionPolicy::KeepLastN(
            required_field(&fields, "retention_count")?
                .parse::<u16>()
                .map_err(|err| {
                    ValidationError::new(format!("invalid vault retention count: {err}"))
                })?,
        ),
        _ => return Err(ValidationError::new("invalid vault retention policy")),
    };

    let object = VaultObject {
        id: required_field(&fields, "id")?,
        namespace: VaultNamespace {
            owner_kind: VaultOwnerKind::parse(&required_field(&fields, "owner_kind")?)
                .ok_or_else(|| ValidationError::new("invalid vault owner kind"))?,
            owner_id: required_field(&fields, "owner_id")?,
        },
        class: VaultObjectClass::parse(&required_field(&fields, "class")?)
            .ok_or_else(|| ValidationError::new("invalid vault object class"))?,
        latest_revision_id: required_field(&fields, "latest_revision_id")?,
        created_at: required_field(&fields, "created_at")?
            .parse::<u64>()
            .map_err(|err| ValidationError::new(format!("invalid vault created_at: {err}")))?,
        updated_at: required_field(&fields, "updated_at")?
            .parse::<u64>()
            .map_err(|err| ValidationError::new(format!("invalid vault updated_at: {err}")))?,
        durability: DurabilityPolicy::parse(&required_field(&fields, "durability")?)
            .ok_or_else(|| ValidationError::new("invalid vault durability policy"))?,
        retention,
        deleted: parse_bool_field(&fields, "deleted")?,
    };
    object.validate()?;
    Ok(object)
}

fn decode_vault_revision_canonical(payload: &[u8]) -> Result<VaultRevision, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "vault-revision" {
        return Err(ValidationError::new(format!(
            "unsupported canonical vault revision type: {record_type}"
        )));
    }

    let payload_kind = PayloadKind::parse(&required_field(&fields, "payload_kind")?)
        .ok_or_else(|| ValidationError::new("invalid vault payload kind"))?;
    let structured_record = match payload_kind {
        PayloadKind::StructuredRecord => Some(StructuredRecordMeta {
            schema_id: required_field(&fields, "schema_id")?,
            schema_version: required_field(&fields, "schema_version")?,
            encoding: StructuredEncoding::parse(&required_field(&fields, "encoding")?)
                .ok_or_else(|| ValidationError::new("invalid structured record encoding"))?,
            app_namespace: required_field(&fields, "app_namespace")?,
        }),
        _ => None,
    };

    let claim = optional_non_empty_field(&fields, "claim_type")
        .and_then(|ct| ClaimType::parse(&ct))
        .map(|claim_type| -> Result<ClaimMeta, ValidationError> {
            Ok(ClaimMeta {
                claim_type,
                issuer_persona_id: required_field(&fields, "claim_issuer_persona_id")?,
                subject_persona_id: required_field(&fields, "claim_subject_persona_id")?,
                claim_schema: required_field(&fields, "claim_schema")?,
                issued_at: required_field(&fields, "claim_issued_at")?
                    .parse::<u64>()
                    .map_err(|err| {
                        ValidationError::new(format!("invalid claim issued_at: {err}"))
                    })?,
                expires_at: optional_non_empty_field(&fields, "claim_expires_at")
                    .map(|v| {
                        v.parse::<u64>().map_err(|err| {
                            ValidationError::new(format!("invalid claim expires_at: {err}"))
                        })
                    })
                    .transpose()?,
                external_issuer: optional_non_empty_field(&fields, "claim_external_issuer"),
                external_credential_id: optional_non_empty_field(
                    &fields,
                    "claim_external_credential_id",
                ),
            })
        })
        .transpose()?;

    let revision = VaultRevision {
        id: required_field(&fields, "id")?,
        object_id: required_field(&fields, "object_id")?,
        manifest_id: required_field(&fields, "manifest_id")?,
        payload_kind,
        content_type: required_field(&fields, "content_type")?,
        created_at: required_field(&fields, "created_at")?
            .parse::<u64>()
            .map_err(|err| {
                ValidationError::new(format!("invalid vault revision created_at: {err}"))
            })?,
        created_by_device_id: required_field(&fields, "created_by_device_id")?,
        parent_revision_id: optional_non_empty_field(&fields, "parent_revision_id"),
        structured_record,
        claim,
    };
    revision.validate()?;
    Ok(revision)
}

fn decode_presentation_template_canonical(
    payload: &[u8],
) -> Result<PresentationTemplate, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "presentation-template" {
        return Err(ValidationError::new(format!(
            "unsupported canonical presentation template type: {record_type}"
        )));
    }

    let field_paths = fields
        .iter()
        .filter_map(|(field_name, field_value)| {
            field_name
                .starts_with("field_path_")
                .then_some(field_value.clone())
        })
        .collect();
    let template = PresentationTemplate {
        id: required_field(&fields, "id")?,
        namespace: VaultNamespace {
            owner_kind: VaultOwnerKind::parse(&required_field(&fields, "owner_kind")?)
                .ok_or_else(|| ValidationError::new("invalid presentation template owner kind"))?,
            owner_id: required_field(&fields, "owner_id")?,
        },
        source_object_id: required_field(&fields, "source_object_id")?,
        schema_id: required_field(&fields, "schema_id")?,
        audience_kind: PresentationAudienceKind::parse(&required_field(&fields, "audience_kind")?)
            .ok_or_else(|| ValidationError::new("invalid presentation audience kind"))?,
        field_paths,
        expires_after_secs: optional_non_empty_field(&fields, "expires_after_secs")
            .map(|value| {
                value.parse::<u64>().map_err(|err| {
                    ValidationError::new(format!("invalid presentation expires_after_secs: {err}"))
                })
            })
            .transpose()?,
    };
    template.validate()?;
    Ok(template)
}

fn decode_presentation_artifact_canonical(
    payload: &[u8],
) -> Result<PresentationArtifact, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "presentation-artifact" {
        return Err(ValidationError::new(format!(
            "unsupported canonical presentation artifact type: {record_type}"
        )));
    }

    let artifact = PresentationArtifact {
        id: required_field(&fields, "id")?,
        source_object_id: required_field(&fields, "source_object_id")?,
        source_revision_id: required_field(&fields, "source_revision_id")?,
        recipient_kind: PresentationAudienceKind::parse(&required_field(
            &fields,
            "recipient_kind",
        )?)
        .ok_or_else(|| ValidationError::new("invalid presentation recipient kind"))?,
        recipient_id: required_field(&fields, "recipient_id")?,
        schema_id: required_field(&fields, "schema_id")?,
        manifest_id: required_field(&fields, "manifest_id")?,
        issued_at: required_field(&fields, "issued_at")?
            .parse::<u64>()
            .map_err(|err| {
                ValidationError::new(format!("invalid presentation issued_at: {err}"))
            })?,
        expires_at: optional_non_empty_field(&fields, "expires_at")
            .map(|value| {
                value.parse::<u64>().map_err(|err| {
                    ValidationError::new(format!("invalid presentation expires_at: {err}"))
                })
            })
            .transpose()?,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn decode_vault_catalog_canonical(payload: &[u8]) -> Result<VaultCatalog, ValidationError> {
    let (record_type, fields) = parse_canonical_record(payload)?;
    if record_type != "vault-catalog" {
        return Err(ValidationError::new(format!(
            "unsupported canonical vault catalog type: {record_type}"
        )));
    }

    let namespace = VaultNamespace {
        owner_kind: VaultOwnerKind::parse(&required_field(&fields, "owner_kind")?)
            .ok_or_else(|| ValidationError::new("invalid vault owner kind"))?,
        owner_id: required_field(&fields, "owner_id")?,
    };
    let object_count = required_field(&fields, "object_count")?
        .parse::<usize>()
        .map_err(|err| ValidationError::new(format!("invalid vault object count: {err}")))?;
    let revision_count = required_field(&fields, "revision_count")?
        .parse::<usize>()
        .map_err(|err| ValidationError::new(format!("invalid vault revision count: {err}")))?;

    let mut objects = Vec::with_capacity(object_count);
    for index in 0..object_count {
        let payload_hex = required_field(&fields, &format!("object_{index:04}_payload_hex"))?;
        objects.push(VaultObject::decode_canonical(&hex_to_bytes(&payload_hex)?)?);
    }

    let mut revisions = Vec::with_capacity(revision_count);
    for index in 0..revision_count {
        let payload_hex = required_field(&fields, &format!("revision_{index:04}_payload_hex"))?;
        revisions.push(VaultRevision::decode_canonical(&hex_to_bytes(
            &payload_hex,
        )?)?);
    }

    let catalog = VaultCatalog {
        namespace,
        objects,
        revisions,
    };
    catalog.validate()?;
    Ok(catalog)
}
