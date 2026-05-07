use crate::encoding::*;
use crate::{CanonicalEncode, Validate, ValidationError};
use serde::{Deserialize, Serialize};

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

// --- Access grant types ---

/// UX-layer classification of a grant recipient.
/// Not a new transport primitive — layered on top of Peer/Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientProfile {
    Human,
    Agent,
    Service,
}

impl RecipientProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "human" => Some(Self::Human),
            "agent" => Some(Self::Agent),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

// ============================================================================
// Composite Grant — design
// ============================================================================
//
// A Grant is a signed, append-only chain of blocks (Biscuit-style), each
// carrying one or more IAM-shaped Statements. One envelope, one approval,
// one receipt, one revocation cascade. Per-statement budgets are the
// primitive's novel axis.

/// Lifecycle status of a grant. See design.
///
/// `Expired` and `Pending` are derived at query time from timestamps;
/// `Active`, `Paused`, `Revoked`, and `ExhaustedByBudget` are persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Active,
    /// Human-requested freeze. No metering accrues; not a terminal state.
    Paused,
    Revoked,
    Expired,
    Pending,
    /// Terminal state: at least one statement's budget has been exhausted
    /// such that no applicable-statement set has remaining capacity.
    ExhaustedByBudget,
}

impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Pending => "pending",
            Self::ExhaustedByBudget => "exhausted_by_budget",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            "pending" => Some(Self::Pending),
            "exhausted_by_budget" | "expired_by_budget" => Some(Self::ExhaustedByBudget),
            _ => None,
        }
    }

    /// Derive the effective status from stored status and timestamps.
    pub fn derive(stored_status: &str, not_before: Option<u64>, expires_at: Option<u64>, now: u64) -> Self {
        if stored_status == "revoked" {
            return Self::Revoked;
        }
        if stored_status == "exhausted_by_budget" || stored_status == "expired_by_budget" {
            return Self::ExhaustedByBudget;
        }
        if stored_status == "paused" {
            return Self::Paused;
        }
        if let Some(nb) = not_before
            && now < nb
        {
            return Self::Pending;
        }
        if let Some(exp) = expires_at
            && now > exp
        {
            return Self::Expired;
        }
        Self::Active
    }
}

/// Access duration model for a grant envelope. Orthogonal to the statements
/// inside — a Standing grant can still carry budget-capped statements that
/// self-expire on exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrantMode {
    /// One disclosure or approval, then done.
    #[default]
    OneShot,
    /// Short-lived, refreshable within existing scope.
    Renewable,
    /// Durable ongoing relationship until explicit revocation.
    Standing,
}

impl GrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OneShot => "one_shot",
            Self::Renewable => "renewable",
            Self::Standing => "standing",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "one_shot" => Some(Self::OneShot),
            "renewable" => Some(Self::Renewable),
            "standing" => Some(Self::Standing),
            _ => None,
        }
    }
}

// --- Unified Grant primitive (design) ---
//
// The four additive fields below generalize `AccessGrant` into the unified
// authority object for every resource an agent might consume. A "credential
// grant" is just a Grant with `resource_type = Credential`. A "token budget
// grant" is just a Grant with `resource_type = Session` and `budget.tokens`
// set. A "spending grant" is `Payment + budget.cents`. Same primitive, same
// UX, same audit log, same revocation semantics, same delegation rules.

/// Kind of resource an agent consumes through a grant.
///
/// See design §"The primitive: the unified Grant." Extensible — additional
/// variants will be added as new grant classes come online (attestation scope,
/// compute budgets, payment surfaces, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// Credential grants — the original shape of `AccessGrant`. An agent gets
    /// bounded use of a stored credential without the credential itself.
    #[default]
    Credential,
    /// Session grants — LLM/compute sessions metered by tokens, requests, or
    /// wall-clock seconds.
    Session,
    /// Payment grants — bounded spend authority (x402 and sibling surfaces).
    Payment,
    /// Compute grants — bounded workload / container / GPU time.
    Compute,
    /// Time grants — bounded human attention or calendar windows.
    Time,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Session => "session",
            Self::Payment => "payment",
            Self::Compute => "compute",
            Self::Time => "time",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "credential" => Some(Self::Credential),
            "session" => Some(Self::Session),
            "payment" => Some(Self::Payment),
            "compute" => Some(Self::Compute),
            "time" => Some(Self::Time),
            _ => None,
        }
    }
}

impl TryFrom<&str> for ResourceType {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
            .ok_or_else(|| ValidationError::invalid_format(format!("unknown resource_type: {value}")))
    }
}

/// Optional ceiling values attached to a grant. `None` on every field (or on
/// the whole `Option<Budget>`) means TTL-only — the existing pre-design
/// behavior. All counters are integer-valued to keep audit math exact; `cents`
/// is integer cents (no fractional currency).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// Integer cents. No float, no fractional currency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cents: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_secs: Option<u64>,
}

impl Budget {
    /// True when no ceiling is set on any axis. A `Budget` with
    /// `is_none_set() == true` is functionally equivalent to `Option::None`.
    pub fn is_none_set(&self) -> bool {
        self.tokens.is_none()
            && self.cents.is_none()
            && self.requests.is_none()
            && self.workload_hours.is_none()
            && self.wall_clock_secs.is_none()
    }
}

/// Running tally of consumption against a grant's `Budget`. Always present
/// (defaults to zeros); the absence of a budget does not imply the absence of
/// usage tracking — even TTL-only grants may accumulate usage for audit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub tokens: u64,
    /// Integer-cent display value. Derived from `cents_micro` at increment
    /// time so receipt JSON / audit rows stay human-readable; do NOT use
    /// for budget enforcement (sub-cent calls truncate to 0). The
    /// authoritative budget axis is `cents_micro`.
    #[serde(default)]
    pub cents: u64,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub workload_hours: u64,
    #[serde(default)]
    pub wall_clock_secs: u64,
    /// Epoch seconds when the usage tally was last updated. Zero on a freshly
    /// created grant that has never been exercised.
    #[serde(default)]
    pub last_updated: u64,
    /// Sub-cent precision accumulator (cents × 10⁶ = micro-cents).
    /// Authoritative for budget enforcement: `has_budget_remaining` and
    /// `emit_threshold_crossings` compare this against the budget cap
    /// scaled to the same unit. Without this, a single Haiku-4.5 call
    /// (~0.1¢ per call) rounds to 0¢ via integer division and the cap
    /// can never accumulate enough to trip — implementation-note-18.
    /// Defaults to 0 on legacy grants; the next `increment_statement_usage`
    /// call re-derives the displayed `cents` from this field, so
    /// pre-existing (non-zero `cents`, zero `cents_micro`) grants flush
    /// their legacy display value on first new metering — acceptable for
    /// v0 (no rollback ceremony).
    ///
    /// `skip_serializing_if` so a zero value is omitted from canonical
    /// encoding — preserves the grant-block-v1 signature bytes for any
    /// grant that hasn't yet accumulated sub-cent usage (the field is
    /// invisible to signers/verifiers until the meter touches it).
    /// Once a grant has been metered, the field appears in the canonical
    /// bytes and re-signing flows through the same persona key path —
    /// no version bump needed because the field is additive and zero-
    /// preserving for unaffected chains.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub cents_micro: u64,
}

/// Serde helper for `Usage::cents_micro` — `skip_serializing_if`
/// predicate that returns `true` when the field is its default zero.
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Agent attestation posture for a grant. First-class field today (design §
/// "Attestation-bound grants"); enforcement is Phase 2 + Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// MVS default: the daemon trusts the human at the keyboard but has no
    /// cryptographic binding to the agent binary. Local-dev only — not
    /// acceptable for shared team policies in Phase 2.
    #[default]
    UnattestedLocalDev,
    /// The agent is running inside an Ember-managed sandbox (design). The
    /// sandbox identifier is recorded in `sandbox_id`.
    SandboxContained,
    /// The agent binary hash and signer are recorded; verification is policy-
    /// gated.
    SignedBinary,
    /// The agent presents a SPIFFE identity.
    Spiffe,
    /// The agent runs inside a TEE and presents an attestation quote.
    Tee,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnattestedLocalDev => "unattested_local_dev",
            Self::SandboxContained => "sandbox_contained",
            Self::SignedBinary => "signed_binary",
            Self::Spiffe => "spiffe",
            Self::Tee => "tee",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unattested_local_dev" => Some(Self::UnattestedLocalDev),
            "sandbox_contained" => Some(Self::SandboxContained),
            "signed_binary" => Some(Self::SignedBinary),
            "spiffe" => Some(Self::Spiffe),
            "tee" => Some(Self::Tee),
            _ => None,
        }
    }
}

/// Attestation metadata bound to a grant. Every field except `status` is
/// optional — the shape is future-proof for SPIFFE/TEE enforcement without
/// blocking the local-dev demo path today.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBinding {
    #[serde(default)]
    pub status: AttestationStatus,
    /// Runtime label — `"claude_code"`, `"openclaw"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// sha256 hex of the agent binary, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_hash: Option<String>,
    /// ed25519 pubkey hex or DID of the signer, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    /// Base64 TEE attestation quote. Not parsed yet — stored opaquely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<String>,
}

// --- Statement -------------------------------------------------------------
//
// IAM-shaped clause. One grant block carries one or more. Evaluator is
// AND-all over *applicable* statements (action matches AND resource covers).
// Allow-only — Deny lives in policy.toml, not inside the grant. See design.

/// Stable identifier for a statement within a block. Unique within its block
/// but NOT globally unique — receipts reference (grant_id, block_index, sid).
pub type StatementId = String;

/// A positive enumeration of action verbs. Colon-delimited namespaces
/// (e.g. `github:pull_request:create`, `llm:generate`, `x402:pay`). No
/// NotAction variant exists — the shape designs that footgun out.
pub type Action = String;

/// Typed resource selector. Glob and Regex are distinct variants so the
/// issuer UI can warn on unbounded wildcards at issue time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceSelector {
    Exact { value: String },
    /// Shell-style glob, anchored on both ends. `*` matches any run of chars.
    Glob { pattern: String },
    /// Glob with a structured branch-path subtarget. `primary_glob` matches
    /// the resource (`owner/repo`), `subtarget_glob` is a secondary check
    /// applied by the resolver against an out-of-band field (e.g. the branch
    /// extracted from the request URI). `covers()` only validates the primary
    /// glob — subtarget enforcement is the resolver's job because the
    /// concrete subtarget value (branch name) is not part of `resource`.
    /// Issued from 4-segment legacy scopes like
    /// `github:push:owner/repo:feat/*` (P69E.5c).
    GlobWithSubtarget {
        primary_glob: String,
        subtarget_glob: String,
    },
    /// Regex anchored on both ends. Evaluation stub for now — issuers may
    /// declare but evaluator in core-policy is the authoritative matcher.
    Regex { pattern: String },
    /// Unconstrained. Issuer UI should require explicit confirmation.
    Any,
}

impl ResourceSelector {
    /// True iff this selector covers the given concrete resource string.
    ///
    /// For `GlobWithSubtarget` only the `primary_glob` is consulted —
    /// subtarget matching is the resolver's responsibility (it has access
    /// to the request URI / method that carries the branch). A primary
    /// match with a missing subtarget should produce
    /// `denied_subtarget_scope`, NOT `denied_no_applicable_statement`.
    pub fn covers(&self, resource: &str) -> bool {
        match self {
            Self::Exact { value } => value == resource,
            Self::Glob { pattern } => glob_matches(pattern, resource),
            Self::GlobWithSubtarget { primary_glob, .. } => {
                glob_matches(primary_glob, resource)
            }
            Self::Regex { .. } => false, // evaluator lives in core-policy
            Self::Any => true,
        }
    }

    /// Subtarget glob if this selector carries one. Used by the proxy
    /// resolver to route to `denied_subtarget_scope` instead of
    /// `denied_no_applicable_statement` on a primary-but-not-subtarget
    /// match.
    pub fn subtarget_glob(&self) -> Option<&str> {
        match self {
            Self::GlobWithSubtarget { subtarget_glob, .. } => Some(subtarget_glob.as_str()),
            _ => None,
        }
    }

    /// True iff this selector is structurally unbounded (`Any` or `*`).
    pub fn is_unbounded(&self) -> bool {
        matches!(self, Self::Any) || matches!(self, Self::Glob { pattern } if pattern == "*")
    }
}

/// Condition predicate. AND-all across a statement's Vec<Condition>. Every
/// condition names its `field` explicitly. Evaluator contract: if the named
/// field is ABSENT from the invocation context, the condition is treated as
/// "not applicable to this call" — NOT passing, NOT denying. Authors who
/// want "deny if absent" must invert via `NotOneOf` or design the field in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    Subpath { field: String, prefix: String },
    OneOf { field: String, values: Vec<String> },
    NotOneOf { field: String, values: Vec<String> },
    Range { field: String, min: Option<i64>, max: Option<i64> },
    Cidr { field: String, cidrs: Vec<String> },
    UrlPattern { field: String, pattern: String },
    Regex { field: String, pattern: String },
    TimeWindow { start_secs_of_day: u32, end_secs_of_day: u32 },
    MerchantAllowlist { merchants: Vec<String> },
}

/// HITL handoff shape. When a block carries an `approval` challenge it is in
/// `Pending` until the human completes the method. Shared across issuance,
/// extension, threshold crossings, and delegation — the single protocol
/// handle for design + design to plug into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub method: ApprovalMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    pub expires_in_secs: u32,
    pub poll_interval_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMethod {
    Notification,
    Passkey,
    YubiKey,
    Ciba,
    DeviceFlow,
}

/// One IAM-shaped clause inside a grant block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub sid: StatementId,
    pub resource_type: ResourceType,
    pub actions: Vec<Action>,
    pub resource: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl Statement {
    /// True iff this statement is applicable to a call with the given action
    /// verb and concrete resource string.
    pub fn applicable_to(&self, action: &str, resource: &str) -> bool {
        self.actions.iter().any(|a| a == action) && self.resource.covers(resource)
    }

    /// True iff this statement's budget still has capacity on every set axis.
    /// Returns true when `budget` is `None` (TTL-only).
    pub fn has_budget_remaining(&self) -> bool {
        let Some(b) = &self.budget else { return true };
        if let Some(cap) = b.tokens
            && self.usage.tokens >= cap
        {
            return false;
        }
        if let Some(cap) = b.cents {
            // implementation-note-18: budget enforcement runs on the
            // sub-cent `cents_micro` accumulator. Sub-cent calls (typical for
            // Haiku-4.5 pricing) round the integer `cents` field to 0 per
            // call, so a cents-only check would never trip. Compare against
            // the cap scaled to micro-cents (cap × 10⁶); fall back to the
            // legacy `cents` axis when cents_micro is unset (zero) so
            // pre-fix grants stored under the old representation still
            // exhaust correctly.
            let cap_micro = cap.saturating_mul(1_000_000);
            if self.usage.cents_micro > 0 {
                if self.usage.cents_micro >= cap_micro {
                    return false;
                }
            } else if self.usage.cents >= cap {
                return false;
            }
        }
        if let Some(cap) = b.requests
            && self.usage.requests >= cap
        {
            return false;
        }
        if let Some(cap) = b.workload_hours
            && self.usage.workload_hours >= cap
        {
            return false;
        }
        if let Some(cap) = b.wall_clock_secs
            && self.usage.wall_clock_secs >= cap
        {
            return false;
        }
        true
    }
}

/// Proposal-shape sibling of [`Statement`]. Carries the per-statement clauses
/// of a [`GrantProposal`] before it is approved into a runtime [`AccessGrant`].
/// No `sid` or `usage` — both are minted at grant-creation time, not at proposal.
///
/// Per design (composite-grant runtime) + design (Construct collapse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementProposal {
    pub resource_type: ResourceType,
    pub credential_name: String,
    pub actions: Vec<Action>,
    pub resource: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Proposal-shape sibling of [`AccessGrant`]. Submitted to emberd to start the
/// propose-then-approve flow; on approval, materializes into a runtime
/// [`AccessGrant`].
///
/// `skill_ref` is an advisory pointer to the originating Construct/skill
/// that asked for the grant; emberd does not enforce on it. Per design.
///
/// Per design (composite-grant runtime) + design (Construct collapse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantProposal {
    pub persona_id: String,
    pub statements: Vec<StatementProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// --- Block + SignedBlock --------------------------------------------------
//
// A grant is a signed, append-only chain of blocks (Biscuit-style). Block 0
// is the authority, issued under the persona's root key. Each subsequent
// block is an attenuation signed by the previous block's `pubkey_next`.
// Reorder or remove a block and the signature chain breaks.

/// Unsigned block content. Carries statements plus block-level metadata.
/// Canonical-encoded bytes of this struct are what the previous block's
/// `pubkey_next` signs to produce the next `SignedBlock.signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub statements: Vec<Statement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Persona that minted this block (block 0 = grant issuer; later blocks
    /// = delegators). String today; will become PersonaId newtype.
    pub issued_by: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalChallenge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Block plus its Biscuit-style signature. `pubkey_next` is the public key
/// that MUST sign the *next* appended block; the current block's bytes are
/// signed by the previous block's `pubkey_next` — or, for block 0, by the
/// persona's root key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlock {
    pub block: Block,
    /// Hex-encoded Ed25519 public key that will sign the NEXT appended block.
    pub pubkey_next: String,
    /// Hex-encoded Ed25519 signature over canonical-encoded `block` bytes.
    pub signature: String,
}

// --- Grant envelope -------------------------------------------------------

/// Local-only runtime object representing delegated authority. Never appears
/// in the protocol event log or crosses the disclosure boundary.
///
/// Per design, a grant is a signed chain of blocks. Block 0 is the authority
/// minted under the issuing persona; subsequent blocks are attenuations.
/// Every block carries typed `Statement`s with per-statement budgets and
/// conditions. Persona and attestation live on the envelope, not inside
/// statements — a grant is always under exactly one persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrant {
    pub id: String,
    pub version: u32,
    pub issuing_persona_id: String,
    pub recipient_kind: PresentationAudienceKind,
    pub recipient_id: String,
    pub recipient_profile: RecipientProfile,
    pub status: GrantStatus,
    pub mode: GrantMode,
    /// Append-only signed chain. First element is block 0 (the authority);
    /// subsequent elements are attenuations.
    pub blocks: Vec<SignedBlock>,
    /// Agent attestation posture. Envelope-level; design §"Attestation."
    pub attestation: AttestationBinding,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
    pub last_used_at: Option<u64>,
    pub label: Option<String>,
}

impl AccessGrant {
    /// Build a grant with a single block containing a single statement. Useful
    /// for tests and the simplest demo path (one credential, no budget).
    pub fn single_statement(
        id: impl Into<String>,
        persona: impl Into<String>,
        recipient_id: impl Into<String>,
        statement: Statement,
        pubkey_next: impl Into<String>,
        signature: impl Into<String>,
        issued_at: u64,
    ) -> Self {
        let persona = persona.into();
        let block = Block {
            statements: vec![statement],
            nbf: None,
            expires_at: None,
            issued_by: persona.clone(),
            issued_at,
            approval: None,
            note: None,
        };
        Self {
            id: id.into(),
            version: 1,
            issuing_persona_id: persona,
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: recipient_id.into(),
            recipient_profile: RecipientProfile::Human,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: pubkey_next.into(),
                signature: signature.into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: issued_at,
            updated_at: issued_at,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    /// Walk every (block_index, statement) pair across the whole chain, in
    /// chain order. Useful for the authorize walker and summary projections.
    pub fn statements(&self) -> impl Iterator<Item = (usize, &Statement)> {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(|(i, sb)| sb.block.statements.iter().map(move |s| (i, s)))
    }

    /// Total statement count across all blocks.
    pub fn statement_count(&self) -> usize {
        self.blocks.iter().map(|sb| sb.block.statements.len()).sum()
    }

    /// Effective grant expiry = earliest `expires_at` across all blocks.
    /// `None` means no block declared an expiry (open-ended).
    pub fn effective_expires_at(&self) -> Option<u64> {
        self.blocks.iter().filter_map(|sb| sb.block.expires_at).min()
    }

    /// Effective not-before = latest `nbf` across all blocks.
    pub fn effective_nbf(&self) -> Option<u64> {
        self.blocks.iter().filter_map(|sb| sb.block.nbf).max()
    }

    /// Derive the effective status from both the stored status field and
    /// the block-level timestamps. A grant stored as `Active` but whose
    /// `effective_expires_at` has passed is `Expired`; a grant whose
    /// `effective_nbf` is in the future is `Pending`. Terminal statuses
    /// (`Revoked`, `ExhaustedByBudget`, `Paused`) are never overridden by
    /// timestamps — only `Active` can be demoted by TTL or nbf.
    pub fn effective_status(&self, now_secs: u64) -> GrantStatus {
        GrantStatus::derive(
            self.status.as_str(),
            self.effective_nbf(),
            self.effective_expires_at(),
            now_secs,
        )
    }

    /// Distinct resource_types present across all statements, in first-seen
    /// order. Used by the dashboard to render the persona-chip badges.
    pub fn resource_types(&self) -> Vec<ResourceType> {
        let mut seen = Vec::new();
        for (_i, s) in self.statements() {
            if !seen.contains(&s.resource_type) {
                seen.push(s.resource_type);
            }
        }
        seen
    }

    /// Aggregate usage snapshot — the dimensional sum of every statement's
    /// usage. View-only; the event log is the authoritative source.
    pub fn aggregate_usage(&self) -> Usage {
        let mut u = Usage::default();
        for (_i, s) in self.statements() {
            u.tokens = u.tokens.saturating_add(s.usage.tokens);
            u.cents = u.cents.saturating_add(s.usage.cents);
            u.requests = u.requests.saturating_add(s.usage.requests);
            u.workload_hours = u.workload_hours.saturating_add(s.usage.workload_hours);
            u.wall_clock_secs = u.wall_clock_secs.saturating_add(s.usage.wall_clock_secs);
            if s.usage.last_updated > u.last_updated {
                u.last_updated = s.usage.last_updated;
            }
        }
        u
    }
}

/// Summary view for grant listings. Aggregates across statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantSummary {
    pub id: String,
    pub label: Option<String>,
    pub issuing_persona_id: String,
    pub recipient_kind: PresentationAudienceKind,
    pub recipient_id: String,
    pub recipient_profile: RecipientProfile,
    pub status: GrantStatus,
    pub mode: GrantMode,
    pub block_count: usize,
    pub statement_count: usize,
    pub resource_types: Vec<ResourceType>,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub aggregate_usage: Usage,
}

/// A lifecycle event in the grant audit history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantHistoryEntry {
    pub history_id: String,
    pub grant_id: String,
    pub version: u32,
    pub action: String,
    pub timestamp: u64,
    /// Canonical JSON snapshot of `AccessGrant.blocks` at the time of this
    /// event, when the action mutated the chain. `None` for lifecycle events
    /// that did not alter the blocks (e.g. `paused`, `last_used`).
    pub blocks_snapshot: Option<String>,
    pub note: Option<String>,
}

/// Full detail view of a grant including linked artifacts and history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantDetail {
    pub grant: AccessGrant,
    pub linked_artifact_count: usize,
    pub linked_artifact_ids: Vec<String>,
    pub history: Vec<AccessGrantHistoryEntry>,
}

// --- small helpers for ResourceSelector -----------------------------------

/// Minimal shell-style glob matcher. `*` matches any run of characters
/// (including empty); `?` matches exactly one character. Anchored on both
/// ends. Sufficient for Emberlink's MVS; richer patterns should use Regex.
fn glob_matches(pattern: &str, s: &str) -> bool {
    fn inner(p: &[u8], s: &[u8]) -> bool {
        let (mut pi, mut si) = (0usize, 0usize);
        let (mut star_pi, mut star_si) = (usize::MAX, 0usize);
        while si < s.len() {
            if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
                pi += 1;
                si += 1;
            } else if pi < p.len() && p[pi] == b'*' {
                star_pi = pi;
                star_si = si;
                pi += 1;
            } else if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_si += 1;
                si = star_si;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }
    inner(pattern.as_bytes(), s.as_bytes())
}

#[cfg(test)]
mod composite_grant_tests {
    use super::*;

    fn stmt_credential_github() -> Statement {
        Statement {
            sid: "GitHubPR".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:pull_request:create".into()],
            resource: ResourceSelector::Glob { pattern: "emberdotlink/*".into() },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
        }
    }

    fn stmt_session_tokens() -> Statement {
        Statement {
            sid: "ClaudeTokens".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Glob { pattern: "anthropic/*".into() },
            budget: Some(Budget {
                tokens: Some(20_000),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
        }
    }

    fn stmt_payment() -> Statement {
        Statement {
            sid: "InfraSpend".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["x402:pay".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(50),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![Condition::MerchantAllowlist {
                merchants: vec!["openai.com".into(), "anthropic.com".into()],
            }],
        }
    }

    #[test]
    fn resource_selector_glob_covers_expected() {
        let g = ResourceSelector::Glob { pattern: "emberdotlink/*".into() };
        assert!(g.covers("emberdotlink/sandbox"));
        assert!(g.covers("emberdotlink/anything-here"));
        assert!(!g.covers("other/repo"));
        assert!(!g.covers("emberdotlink"));
    }

    #[test]
    fn resource_selector_any_covers_everything() {
        let a = ResourceSelector::Any;
        assert!(a.covers(""));
        assert!(a.covers("literally anything"));
    }

    #[test]
    fn resource_selector_exact_is_exact() {
        let e = ResourceSelector::Exact { value: "emberdotlink/sandbox".into() };
        assert!(e.covers("emberdotlink/sandbox"));
        assert!(!e.covers("emberdotlink/sandbox-demo"));
    }

    #[test]
    fn statement_applicable_only_when_action_and_resource_match() {
        let s = stmt_credential_github();
        assert!(s.applicable_to("github:pull_request:create", "emberdotlink/sandbox"));
        assert!(!s.applicable_to("github:pull_request:merge", "emberdotlink/sandbox"));
        assert!(!s.applicable_to("github:pull_request:create", "other/repo"));
    }

    #[test]
    fn statement_has_budget_remaining_honors_every_axis() {
        let mut s = stmt_session_tokens();
        assert!(s.has_budget_remaining());
        s.usage.tokens = 19_999;
        assert!(s.has_budget_remaining());
        s.usage.tokens = 20_000;
        assert!(!s.has_budget_remaining());
    }

    #[test]
    fn composite_grant_bundles_three_resource_types_in_one_envelope() {
        let block = Block {
            statements: vec![stmt_credential_github(), stmt_session_tokens(), stmt_payment()],
            nbf: None,
            expires_at: Some(1_800),
            issued_by: "persona_work".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant_01".into(),
            version: 1,
            issuing_persona_id: "persona_work".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent_claude_code".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: Some("Work: coding agent".into()),
        };

        assert_eq!(grant.statement_count(), 3);
        assert_eq!(grant.resource_types().len(), 3);
        assert!(grant.resource_types().contains(&ResourceType::Credential));
        assert!(grant.resource_types().contains(&ResourceType::Session));
        assert!(grant.resource_types().contains(&ResourceType::Payment));
        assert_eq!(grant.effective_expires_at(), Some(1_800));
    }

    #[test]
    fn block_canonical_encode_is_deterministic_and_round_trips() {
        let block = Block {
            statements: vec![stmt_credential_github(), stmt_session_tokens(), stmt_payment()],
            nbf: None,
            expires_at: Some(1_800),
            issued_by: "persona_work".into(),
            issued_at: 42,
            approval: None,
            note: Some("hello".into()),
        };

        let encoded = block.canonical_encode();
        // Prefix namespaces the canonical encoding version.
        assert!(
            encoded.starts_with(b"type=grant-block-v1\n"),
            "canonical encoding must carry a version prefix"
        );

        // Stability: repeated encoding produces identical bytes.
        assert_eq!(block.canonical_encode(), encoded);

        // Round-trip: decode the JSON body back to a Block and re-encode —
        // bytes must be byte-identical. This catches any non-determinism
        // sneaking into the transitive serde graph (e.g. a future HashMap).
        let json_body = &encoded[b"type=grant-block-v1\n".len()..];
        let decoded: Block = serde_json::from_slice(json_body)
            .expect("canonical encoding round-trips through serde_json");
        assert_eq!(decoded.canonical_encode(), encoded);
        assert_eq!(decoded, block);
    }

    #[test]
    fn block_canonical_encode_differs_on_material_change() {
        let base = Block {
            statements: vec![stmt_credential_github()],
            nbf: None,
            expires_at: None,
            issued_by: "persona_a".into(),
            issued_at: 10,
            approval: None,
            note: None,
        };
        let mut tampered = base.clone();
        tampered.issued_at = 11;
        assert_ne!(base.canonical_encode(), tampered.canonical_encode());

        let mut mutated_stmt = base.clone();
        mutated_stmt.statements[0].sid = "DifferentSid".into();
        assert_ne!(base.canonical_encode(), mutated_stmt.canonical_encode());
    }

    #[test]
    fn block_canonical_encode_golden_bytes_v1() {
        // Canonical-version-1 stability baseline. A change to this hash value
        // indicates a serde_json behavior change — verify the new bytes match
        // the intended canonical format and bump `canonical_version` in the
        // prefix before updating this expected value. NEVER silently update
        // this test.
        //
        // If this hash changes:
        // 1. Determine WHY (serde_json upgrade, Block field addition, etc.)
        // 2. If the change is intentional, bump canonical_version in the
        //    `type=grant-block-v1` prefix (→ v2) and update this hash.
        // 3. If the change is unintentional, REVERT the serde_json upgrade
        //    or field change that caused it.
        let fixture_block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact { value: "obj-test".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: Some(1700000000),
            issued_by: "persona-test".into(),
            issued_at: 1699999000,
            approval: None,
            note: None,
        };
        use sha2::Digest as _;
        let encoded = fixture_block.canonical_encode();
        let hash = sha2::Sha256::digest(&encoded);
        let hex = hex::encode(hash);

        // CANONICAL-VERSION-1 BASELINE. If this value changes:
        // 1. Determine WHY (serde_json upgrade, Block field addition, etc.)
        // 2. If the change is intentional, bump canonical_version and update this hash
        // 3. If the change is unintentional, REVERT the serde_json upgrade or field change
        assert_eq!(
            hex,
            "cd399643d1e04ac2901bce8475557fdc111b947ad2655cacb73508e96293bfe5",
            "Block::canonical_encode produced unexpected bytes — see test comment"
        );
    }

    #[test]
    fn grant_status_derive_handles_all_persisted_states() {
        assert_eq!(GrantStatus::derive("revoked", None, None, 100), GrantStatus::Revoked);
        assert_eq!(
            GrantStatus::derive("exhausted_by_budget", None, None, 100),
            GrantStatus::ExhaustedByBudget
        );
        assert_eq!(
            GrantStatus::derive("expired_by_budget", None, None, 100),
            GrantStatus::ExhaustedByBudget
        );
        assert_eq!(GrantStatus::derive("paused", None, None, 100), GrantStatus::Paused);
        assert_eq!(GrantStatus::derive("active", None, Some(50), 100), GrantStatus::Expired);
        assert_eq!(GrantStatus::derive("active", Some(200), None, 100), GrantStatus::Pending);
        assert_eq!(GrantStatus::derive("active", None, None, 100), GrantStatus::Active);
    }

    #[test]
    fn effective_status_returns_expired_when_ttl_passed_despite_stored_active() {
        let block = Block {
            statements: vec![stmt_credential_github()],
            nbf: None,
            expires_at: Some(50),
            issued_by: "persona_work".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant_ttl_test".into(),
            version: 1,
            issuing_persona_id: "persona_work".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent_claude".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };

        // Stored status is Active, but the block expired at epoch 50.
        assert_eq!(grant.status, GrantStatus::Active);
        assert_eq!(grant.effective_status(100), GrantStatus::Expired);
        // Still active before expiry.
        assert_eq!(grant.effective_status(49), GrantStatus::Active);
    }
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

impl Validate for Statement {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.sid, "statement sid")?;
        if self.actions.is_empty() {
            return Err(ValidationError::new(
                "statement must declare at least one action",
            ));
        }
        for a in &self.actions {
            validate_non_empty(a, "statement action")?;
        }
        match &self.resource {
            ResourceSelector::Exact { value } => {
                validate_non_empty(value, "resource selector exact value")?;
            }
            ResourceSelector::Glob { pattern } => {
                validate_non_empty(pattern, "resource selector glob pattern")?;
            }
            ResourceSelector::GlobWithSubtarget { primary_glob, subtarget_glob } => {
                validate_non_empty(primary_glob, "resource selector primary glob pattern")?;
                validate_non_empty(subtarget_glob, "resource selector subtarget glob pattern")?;
            }
            ResourceSelector::Regex { pattern } => {
                validate_non_empty(pattern, "resource selector regex pattern")?;
            }
            ResourceSelector::Any => {}
        }
        Ok(())
    }
}

impl Validate for Block {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.issued_by, "block issued_by persona id")?;
        if self.statements.is_empty() {
            return Err(ValidationError::new(
                "block must contain at least one statement",
            ));
        }
        for s in &self.statements {
            s.validate()?;
        }
        if let (Some(nb), Some(exp)) = (self.nbf, self.expires_at)
            && exp <= nb
        {
            return Err(ValidationError::new(
                "block expires_at must be after nbf",
            ));
        }
        Ok(())
    }
}

impl Validate for SignedBlock {
    fn validate(&self) -> Result<(), ValidationError> {
        self.block.validate()?;
        validate_non_empty(&self.pubkey_next, "signed block pubkey_next")?;
        validate_non_empty(&self.signature, "signed block signature")?;
        Ok(())
    }
}

impl Validate for AccessGrant {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "access grant id")?;
        if self.version == 0 {
            return Err(ValidationError::new(
                "access grant version must be at least 1",
            ));
        }
        validate_non_empty(&self.issuing_persona_id, "access grant issuing persona id")?;
        validate_non_empty(&self.recipient_id, "access grant recipient id")?;
        if self.blocks.is_empty() {
            return Err(ValidationError::new(
                "access grant must have at least one signed block",
            ));
        }
        for b in &self.blocks {
            b.validate()?;
        }
        if self.created_at == 0 {
            return Err(ValidationError::new(
                "access grant created_at must be non-zero",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(ValidationError::new(
                "access grant updated_at must not precede created_at",
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
impl CanonicalEncode for Block {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"type=grant-block-v1\n");
        // serde_json emits deterministic bytes for this struct — no HashMap
        // anywhere in the transitive graph. If a future field change ever
        // introduces one, the `canonical_encode_round_trips` test (below,
        // under #[cfg(test)]) will catch the non-determinism.
        let json = serde_json::to_vec(self)
            .expect("Block serializes to JSON (no HashMap/non-UTF-8 keys in the graph)");
        out.extend_from_slice(&json);
        out
    }
}

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
