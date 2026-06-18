use crate::storage::{FileManifest, StorageLedgerEntry, StorageRelationship};
use core_principals::{PublicKeyMaterial, RecoveryScope, SurvivalMode, parse_public_key_material};
use core_types::encoding::*;
use core_types::size_limits::{
    MAX_BADGE_PAYLOAD_HEX_BYTES, MAX_CIPHERTEXT_HEX_BYTES, MAX_CONDITIONS_JSON_BYTES,
    MAX_LABEL_BYTES, MAX_PUBLIC_KEY_HEX_BYTES, MAX_REASON_BYTES, MAX_SEALED_PAYLOAD_HEX_BYTES,
    MAX_TRANSPORT_HINT_BYTES, validate_optional_size, validate_size,
};
use core_types::{CanonicalEncode, Validate, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Principal,
    /// Compatibility wire alias for a self-parented Principal.
    ///
    /// New event emission should use [`SubjectKind::Principal`]. Keep parsing
    /// this value so older signed envelopes continue to verify byte-for-byte.
    Root,
    /// Compatibility wire alias for a scoped Principal.
    ///
    /// Product/domain vocabulary may still say "Persona", but protocol signer
    /// and subject attribution should emit [`SubjectKind::Principal`].
    Persona,
    Device,
    Guardian,
    RecoveryRequest,
    TrustStatement,
    StorageRelationship,
    Endpoint,
    GrantOffer,
    Badge,
    CredentialDeposit,
    Unknown,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Root => "root",
            Self::Persona => "persona",
            Self::Device => "device",
            Self::Guardian => "guardian",
            Self::RecoveryRequest => "recovery-request",
            Self::TrustStatement => "trust-statement",
            Self::StorageRelationship => "storage-relationship",
            Self::Endpoint => "endpoint",
            Self::GrantOffer => "grant-offer",
            Self::Badge => "badge",
            Self::CredentialDeposit => "credential-deposit",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "principal" => Some(Self::Principal),
            "root" => Some(Self::Root),
            "persona" => Some(Self::Persona),
            "device" => Some(Self::Device),
            "guardian" => Some(Self::Guardian),
            "recovery-request" => Some(Self::RecoveryRequest),
            "trust-statement" => Some(Self::TrustStatement),
            "storage-relationship" => Some(Self::StorageRelationship),
            "endpoint" => Some(Self::Endpoint),
            "grant-offer" => Some(Self::GrantOffer),
            "badge" => Some(Self::Badge),
            "credential-deposit" => Some(Self::CredentialDeposit),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn is_principal_kind(self) -> bool {
        matches!(self, Self::Principal | Self::Root | Self::Persona)
    }

    pub fn is_legacy_principal_alias(self) -> bool {
        matches!(self, Self::Root | Self::Persona)
    }

    pub fn canonical_principal_kind(self) -> Self {
        if self.is_principal_kind() {
            Self::Principal
        } else {
            self
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

    /// Build a legacy root-subject alias. Prefer [`Self::principal`] for new
    /// protocol emission; this remains for parsing/back-compat test fixtures.
    pub fn root(root_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Root, root_id)
    }

    pub fn principal(principal_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Principal, principal_id)
    }

    /// Build a legacy persona-subject alias. Prefer [`Self::principal`] for
    /// signer/subject attribution; Persona remains product/domain vocabulary.
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

    pub fn grant_offer(offer_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::GrantOffer, offer_id)
    }

    pub fn badge(badge_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Badge, badge_id)
    }

    pub fn credential_deposit(deposit_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::CredentialDeposit, deposit_id)
    }

    pub fn unknown(subject_id: impl Into<String>) -> Self {
        Self::new(SubjectKind::Unknown, subject_id)
    }

    pub fn canonical_principal_alias(mut self) -> Self {
        self.kind = self.kind.canonical_principal_kind();
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Principal,
    /// Compatibility wire alias for Principal role at the self-parented root.
    /// New signatures should emit [`KeyRole::Principal`].
    Root,
    /// Compatibility wire alias for Principal role below the root. New
    /// signatures should emit [`KeyRole::Principal`].
    Persona,
    Device,
    Guardian,
    Unknown,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Root => "root",
            Self::Persona => "persona",
            Self::Device => "device",
            Self::Guardian => "guardian",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "principal" => Some(Self::Principal),
            "root" => Some(Self::Root),
            "persona" => Some(Self::Persona),
            "device" => Some(Self::Device),
            "guardian" => Some(Self::Guardian),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn is_principal_role(self) -> bool {
        matches!(self, Self::Principal | Self::Root | Self::Persona)
    }

    pub fn is_legacy_principal_alias(self) -> bool {
        matches!(self, Self::Root | Self::Persona)
    }

    pub fn canonical_principal_role(self) -> Self {
        if self.is_principal_role() {
            Self::Principal
        } else {
            self
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
    /// Build a legacy root-signer alias. Prefer [`Self::principal`] for new
    /// signatures; this remains so old call sites and fixtures can migrate
    /// without losing parse compatibility.
    pub fn root(root_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self {
            signer: EventSubject::root(root_id),
            key_id: key_id.into(),
            role: KeyRole::Root,
        }
    }

    pub fn principal(
        principal_id: impl Into<String>,
        signing_device_id: impl Into<String>,
    ) -> Self {
        Self {
            signer: EventSubject::principal(principal_id),
            key_id: signing_device_id.into(),
            role: KeyRole::Principal,
        }
    }

    /// Build a legacy persona-signer alias. Prefer [`Self::principal`] for new
    /// signatures; Persona is product/domain vocabulary, not a signer universe.
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

    pub fn canonical_principal_alias(mut self) -> Self {
        self.signer = self.signer.canonical_principal_alias();
        self.role = self.role.canonical_principal_role();
        self
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

/// Key-custody class of a Device (ADR 200 §Vocabulary). The class determines
/// whether a signature on the Device can satisfy Operator Presence. It is a
/// property of the **Device**, never the Persona.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyClass {
    /// Software key, host-resident, unattended — the emberd keychain key.
    /// Cannot satisfy Operator Presence.
    Daemon,
    /// Operator-held hardware key requiring per-use human presence, proven by a
    /// vendor-rooted hardware attestation recorded at enrollment. The ONLY class
    /// that satisfies Operator Presence.
    Presence,
    /// A separate authority (cloud KMS / HSM / second emberd) the daemon cannot
    /// reach. Satisfies a co-authority requirement, not human presence.
    CoAuthority,
    /// Per-spawn container cert key (the ADR 154 bridge-client mTLS key).
    Container,
    /// An off-host, operator-blessed **recovery recipient** (ADR 206 §6): a key
    /// whose private half lives provably off the host — e.g. a printed/exported
    /// `age` recovery code in a drawer, or an air-gapped key. Its sole role is to
    /// be a `KEK_s` recovery recipient so device loss never becomes identity loss
    /// (finding C3). Distinct from [`Self::CoAuthority`]: it carries NO reachable
    /// service and NO vendor attestation (the only proof is the operator-presence
    /// signature on its enrollment), and distinct from [`Self::Presence`]: it is
    /// NOT a live human-presence factor and is NEVER a root-authority signer (it
    /// is enrolled BY an existing presence authority and only ever *decrypts*).
    Recovery,
}

impl CustodyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Presence => "presence",
            Self::CoAuthority => "co-authority",
            Self::Container => "container",
            Self::Recovery => "recovery",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "daemon" => Some(Self::Daemon),
            "presence" => Some(Self::Presence),
            "co-authority" => Some(Self::CoAuthority),
            "container" => Some(Self::Container),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }

    /// Only `presence` satisfies Operator Presence (ADR 200 §3).
    pub fn satisfies_operator_presence(self) -> bool {
        matches!(self, Self::Presence)
    }

    /// Classes whose custody is proven by a recorded, externally-reproducible
    /// vendor/authority attestation statement (ADR 200 §3). A daemon-class key
    /// is the daemon itself (self-evident); a container key is the bridge CA's.
    ///
    /// NOTE (ADR 200 §3, two-axis model): for a `presence` Device the statement
    /// requirement is keyed on its [`AttestationTier`], not the custody class —
    /// a `presence` Device at `AttestationTier::None` (the dev0 floor) rests on
    /// the OOB anchor + the hardware presence gate and carries NO vendor chain.
    /// This method remains the requirement for `co-authority` custody (whose
    /// authority always records its own attestation).
    pub fn requires_attestation(self) -> bool {
        matches!(self, Self::CoAuthority)
    }
}

/// The strength of the externally-reproducible attestation recorded for an
/// enrolled Device (ADR 200 §3, the two-axis custody model). **Orthogonal** to
/// both [`CustodyClass`] and [`PresenceFactor`]: custody class says *what kind
/// of authority* a Device carries, the presence factor says *how the use-time
/// human gate is enforced*, and the attestation tier says *how strongly the
/// Device's custody is proven to an INDEPENDENT verifier*.
///
/// Evaluated strictly independently of [`CustodyClass::satisfies_operator_presence`]
/// — a higher tier NEVER upgrades a Device's custody class, and the tier NEVER
/// substitutes for the per-op presence signature (it is an assurance band the
/// authority gate layers on top, never a stand-in for a live tap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationTier {
    /// No externally-reproducible attestation. The dev0 floor: a presence key
    /// whose custody rests on the hardware presence gate (Property 1) + out-of-band
    /// enrollment confirmation (Property 2b), NOT a re-verifiable vendor chain.
    /// The only tier whose authority an independent verifier extends from the OOB
    /// anchor alone (no statement to re-run).
    None,
    /// Genuine-app/device attestation (e.g. Apple App Attest): proves a genuine
    /// signed build on genuine hardware emitted the enrollment, NOT that the
    /// signing key's custody is hardware-presence-gated. A team0 membership /
    /// anti-emulation **admission** signal ONLY — it MUST NEVER gate a G1 widening
    /// op (a runtime-compromised genuine app can mint the binding over any key).
    GenuineApp,
    /// Vendor-rooted hardware attestation over the SIGNING key itself (e.g. YubiKey
    /// PIV cert chain → pinned vendor root). The attested artifact IS the device
    /// key; a software key cannot produce a passing chain. The team0 / high-assurance
    /// tier; an independent verifier MUST re-run the statement before honoring it.
    VendorHw,
}

impl AttestationTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::GenuineApp => "genuine_app",
            Self::VendorHw => "vendor_hw",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "genuine_app" => Some(Self::GenuineApp),
            "vendor_hw" => Some(Self::VendorHw),
            _ => None,
        }
    }

    /// Whether this tier requires a recorded, externally-reproducible attestation
    /// statement (ADR 200 §3). `None` rests on the OOB anchor; the higher tiers
    /// MUST carry a statement the independent verifier re-runs before honoring it.
    pub fn requires_statement(self) -> bool {
        matches!(self, Self::GenuineApp | Self::VendorHw)
    }
}

/// How a Device's **use-time human-presence gate** is enforced (ADR 200 §3, the
/// presence axis — distinct from the [`AttestationTier`] attestation axis). This
/// is the property that anchors G1: a compromised daemon cannot synthesize the
/// human factor. ALL presence factors are enforced **per-signature** (no auth
/// reuse window); the variants differ only in how strong the factor is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceFactor {
    /// No human gate — an unattended key (a `daemon`/`co-authority` Device). Cannot
    /// satisfy Operator Presence.
    Unattended,
    /// The dev0 floor: a Secure-Enclave key gated by `.userPresence` (biometric
    /// **or** device passcode), per-signature. NIST SP 800-63B multi-factor
    /// cryptographic device — the SE key activated by something-you-know/are; the
    /// passcode is SEP-verified via out-of-process secure UI the app cannot supply,
    /// so a compromised non-root daemon cannot forge it. Portable to Macs without
    /// biometric hardware.
    UserPresence,
    /// Stronger, where the hardware supports it: a Secure-Enclave key gated by
    /// `.biometryCurrentSet` (biometry only, invalidated if the enrolled set
    /// changes — defeats evil-maid biometric enrollment). The human factor is
    /// hardware-unforgeable even by a root attacker. A high-assurance / team0 band
    /// may require this where available.
    Biometric,
    /// An external hardware token requiring a physical touch (e.g. YubiKey). The
    /// key never resides on the host at all.
    HardwareTouch,
}

impl PresenceFactor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unattended => "unattended",
            Self::UserPresence => "user_presence",
            Self::Biometric => "biometric",
            Self::HardwareTouch => "hardware_touch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unattended" => Some(Self::Unattended),
            "user_presence" => Some(Self::UserPresence),
            "biometric" => Some(Self::Biometric),
            "hardware_touch" => Some(Self::HardwareTouch),
            _ => None,
        }
    }

    /// Whether this factor is a genuine use-time human-presence gate (anything
    /// but `Unattended`). Required for a `presence`-class Device (ADR 200 §3).
    pub fn is_human_present(self) -> bool {
        !matches!(self, Self::Unattended)
    }
}

/// A Device is enrolled with a proven key-custody class (ADR 200 §1/§3). Unlike
/// [`DeviceAddedEvent`] (which adds a `daemon`-class device whose key the daemon
/// holds), enrollment records only the Device's **public** key plus the raw,
/// externally-reproducible vendor attestation statement that proves its custody
/// class. The daemon holds no private key for an enrolled `presence` Device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrolledEvent {
    pub root_id: String,
    pub device_id: String,
    pub label: String,
    /// The Device's signing public key (identity-binding: only this key's
    /// signatures verify). For dev0 `presence` this is an ECDSA-P256 key.
    pub device_key: PublicKeyMaterial,
    /// The Device's ECIES **recipient** public key — a key DISTINCT from
    /// `device_key`, recorded as the Device's `active_encryption_key` so ADR 206
    /// §4 presence-as-decryption can seal scope KEKs to it. macOS SE cannot
    /// enforce sign-vs-decrypt usage on one key (see ADR 206 §4 AC-3), so the
    /// signing key MUST NOT double as the §4 recipient; enrollment provisions a
    /// second SE key under `SeAccessPolicy::UserPresence` for this slot. Mirrors
    /// `DeviceAddedEvent.initial_encryption_key`; for dev0 `presence` this is an
    /// ECDH-P256 (ECIES) key.
    pub encryption_key: PublicKeyMaterial,
    pub custody_class: CustodyClass,
    /// The raw vendor-signed attestation statement (e.g. the YubiKey PIV
    /// attestation cert chain, base64-DER). Stored verbatim so any party can
    /// re-verify it against the binary-embedded vendor roots — never a
    /// daemon-computed boolean. Required when `attestation_tier.requires_statement()`
    /// (or for `co-authority` custody); absent for the `None`-tier dev0 floor.
    pub attestation_statement: Option<String>,
    /// The attestation strength this enrollment **claims** (ADR 200 §3, two-axis
    /// model). It is the *claimed* tier; an independent verifier ([`verify_chain`])
    /// honors a Device at the tier it can PROVE by re-running `attestation_statement`,
    /// never the claimed value — a claim above what the statement proves is refused,
    /// closing tier-laundering. `None` (the dev0 floor) needs no statement.
    pub attestation_tier: AttestationTier,
    /// How this Device's use-time human-presence gate is enforced (ADR 200 §3,
    /// the presence axis). For a `presence` Device this MUST be a human factor
    /// (`UserPresence` floor / `Biometric` / `HardwareTouch`), never `Unattended`.
    pub presence_factor: PresenceFactor,
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
pub struct GuardianKeyRotatedEvent {
    pub guardian_id: String,
    pub root_id: String,
    pub previous_key_id: String,
    pub new_guardian_public_key: String,
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

// --- Grant exchange events (ADR 027) ---

/// A grant offer created by an issuer, ready for a recipient to claim.
/// The sealed payload contains the proposed grant parameters encrypted
/// to the ephemeral key. The offer can be deposited at a relay for
/// async pickup or embedded directly in a QR code for offline exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOfferCreatedEvent {
    /// Unique offer identifier. Format: `offer-{ulid}`.
    pub offer_id: String,
    /// The persona that created this offer.
    pub issuer_persona_id: String,
    /// Hex-encoded ephemeral public key. The sealed payload is encrypted
    /// to this key; the recipient proves possession of the corresponding
    /// private key during claim.
    pub ephemeral_public_key_hex: String,
    /// Hex-encoded sealed grant payload. Contains the proposed grant
    /// parameters (scope, mode, capabilities, expiry) encrypted to
    /// the ephemeral key.
    pub sealed_payload_hex: String,
    /// Optional relay endpoint hint for async pickup. Omitted for
    /// offline/direct exchange.
    pub relay_hint: Option<String>,
    /// Expiry timestamp (epoch seconds). After this time, the offer
    /// is dead and relays may discard it.
    pub expires_at: u64,
    /// JSON-encoded grant conditions the claimant must satisfy (e.g., badge gates).
    /// Empty string or `"[]"` means unconditional.
    /// Deserialized via [`crate::grant_conditions::GrantCondition`].
    pub conditions_json: String,
}

/// A grant offer claimed by a recipient. Establishes the grant
/// relationship between issuer and recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOfferClaimedEvent {
    /// The offer being claimed.
    pub offer_id: String,
    /// The persona claiming the offer.
    pub recipient_persona_id: String,
    /// Hex-encoded claim response. Contains the recipient's persona
    /// public key and a signature proving possession of the private key.
    pub claim_response_hex: String,
    /// Epoch seconds when the claim was made.
    pub claimed_at: u64,
}

/// An unclaimed grant offer revoked by its issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOfferRevokedEvent {
    /// The offer being revoked.
    pub offer_id: String,
    /// The persona that issued (and is now revoking) this offer.
    pub issuer_persona_id: String,
    /// Reason for revocation.
    pub reason: String,
}

// --- Badge events (ADR 030) ---

/// Opaque evidence attached to a badge issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeEvidence {
    /// Freeform evidence type identifier (e.g. "proof-of-ride", "photo-hash").
    pub evidence_type: String,
    /// Hex-encoded opaque bytes — interpretation is up to the evidence_type.
    pub payload_hex: String,
}

/// A soulbound badge issued from one persona to another.
/// The badge_type is freeform, namespaced by convention (e.g. "subway:king:A").
/// Signature lives in the event envelope, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeIssuedEvent {
    pub badge_id: String,
    pub issuer_persona_id: String,
    pub recipient_persona_id: String,
    /// Freeform badge type, namespaced by convention (e.g. "subway:king:A").
    pub badge_type: String,
    pub display_name: String,
    pub evidence: Option<BadgeEvidence>,
    /// Epoch seconds when the badge was issued.
    pub issued_at: u64,
    /// Optional expiry (epoch seconds). None means the badge never expires.
    pub expires_at: Option<u64>,
}

/// Revocation of a previously issued badge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeRevokedEvent {
    pub badge_id: String,
    pub revoker_persona_id: String,
    pub reason: String,
}

/// A dispute attestation targeting a specific badge (ADR 030 counter-attestation).
/// Disputes are weighted by the viewer's trust graph — a dispute from a closer/more-trusted
/// identity reduces badge authority score more than a dispute from a distant identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeDisputedEvent {
    pub dispute_id: String,
    pub target_badge_id: String,
    pub disputer_persona_id: String,
    /// Freeform reason for the dispute.
    pub reason: String,
    /// Optional evidence supporting the dispute (hex-encoded).
    pub evidence: Option<String>,
}

// --- Credential delivery events (P29) ---

/// Maximum size of encrypted_blocks_json in bytes (1 MB).
pub const MAX_ENCRYPTED_BLOCKS_JSON_BYTES: usize = 1_048_576;

/// A credential deposited by a grant issuer for a recipient.
/// The encrypted blocks are stored for async pickup. The deposit_id
/// is a unique identifier for idempotent replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDepositedEvent {
    /// Unique deposit identifier. Format: `deposit-{ulid}`.
    pub deposit_id: String,
    /// The grant this deposit fulfills.
    pub grant_id: String,
    /// The credential being deposited.
    pub credential_id: String,
    /// The persona that issued the grant and is depositing the credential.
    pub issuer_id: String,
    /// JSON-encoded encrypted blocks. The relay stores this opaque blob;
    /// the recipient decrypts using their persona key.
    pub encrypted_blocks_json: String,
    /// Epoch seconds when this deposit was created.
    pub created_at: u64,
    /// Optional expiry (epoch seconds). None means the deposit never expires.
    pub expires_at: Option<u64>,
}

/// Revocation of a previously deposited credential.
/// The revoker must be the original issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRevokedEvent {
    /// The deposit being revoked (looked up by grant_id).
    pub grant_id: String,
    /// The persona that issued (and is now revoking) this credential.
    pub revoker_id: String,
    /// Reason for revocation.
    pub reason: String,
    /// Epoch seconds when the revocation occurred.
    pub revoked_at: u64,
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
    DeviceEnrolled(DeviceEnrolledEvent),
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
    GuardianKeyRotated(GuardianKeyRotatedEvent),
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
    GrantOfferCreated(GrantOfferCreatedEvent),
    GrantOfferClaimed(GrantOfferClaimedEvent),
    GrantOfferRevoked(GrantOfferRevokedEvent),
    BadgeIssued(BadgeIssuedEvent),
    BadgeRevoked(BadgeRevokedEvent),
    BadgeDisputed(BadgeDisputedEvent),
    CredentialDeposited(CredentialDepositedEvent),
    CredentialRevoked(CredentialRevokedEvent),
}

impl EventBody {
    pub fn event_type(&self) -> EventType {
        match self {
            Self::RootCreated(_) => EventType::RootCreated,
            Self::RootKeyRotated(_) => EventType::RootKeyRotated,
            Self::RootRevoked(_) => EventType::RootRevoked,
            Self::DeviceAdded(_) => EventType::DeviceAdded,
            Self::DeviceEnrolled(_) => EventType::DeviceEnrolled,
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
            Self::GuardianKeyRotated(_) => EventType::GuardianKeyRotated,
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
            Self::GrantOfferCreated(_) => EventType::GrantOfferCreated,
            Self::GrantOfferClaimed(_) => EventType::GrantOfferClaimed,
            Self::GrantOfferRevoked(_) => EventType::GrantOfferRevoked,
            Self::BadgeIssued(_) => EventType::BadgeIssued,
            Self::BadgeRevoked(_) => EventType::BadgeRevoked,
            Self::BadgeDisputed(_) => EventType::BadgeDisputed,
            Self::CredentialDeposited(_) => EventType::CredentialDeposited,
            Self::CredentialRevoked(_) => EventType::CredentialRevoked,
        }
    }

    pub fn subject(&self) -> EventSubject {
        match self {
            Self::RootCreated(body) => EventSubject::principal(body.root_id.clone()),
            Self::RootKeyRotated(body) => EventSubject::principal(body.root_id.clone()),
            Self::RootRevoked(body) => EventSubject::principal(body.root_id.clone()),
            Self::DeviceAdded(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceEnrolled(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceKeyRotated(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceEncryptionKeyRotated(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceRevoked(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceFrozen(body) => EventSubject::device(body.device_id.clone()),
            Self::DeviceReplaced(body) => EventSubject::device(body.replaced_device_id.clone()),
            Self::PersonaCreated(body) => EventSubject::principal(body.persona_id.clone()),
            Self::PersonaKeyRotated(body) => EventSubject::principal(body.persona_id.clone()),
            Self::PersonaRevoked(body) => EventSubject::principal(body.persona_id.clone()),
            Self::TrustAttested(body) => EventSubject::principal(body.subject_persona_id.clone()),
            Self::TrustRevoked(body) => EventSubject::principal(body.attester_persona_id.clone()),
            Self::RecoveryPolicyCreated(body) => EventSubject::principal(body.root_id.clone()),
            Self::GuardianEnrolled(body) => EventSubject::guardian(body.guardian_id.clone()),
            Self::GuardianKeyRotated(body) => EventSubject::guardian(body.guardian_id.clone()),
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
            Self::MessageSent(body) => EventSubject::principal(body.sender_persona_id.clone()),
            Self::ContentPublished(body) => EventSubject::principal(body.author_persona_id.clone()),
            Self::DisclosureRevoked(body) => {
                EventSubject::principal(body.revoker_persona_id.clone())
            }
            Self::GrantOfferCreated(body) => EventSubject::grant_offer(body.offer_id.clone()),
            Self::GrantOfferClaimed(body) => EventSubject::grant_offer(body.offer_id.clone()),
            Self::GrantOfferRevoked(body) => EventSubject::grant_offer(body.offer_id.clone()),
            Self::BadgeIssued(body) => EventSubject::badge(body.badge_id.clone()),
            Self::BadgeRevoked(body) => EventSubject::badge(body.badge_id.clone()),
            Self::BadgeDisputed(body) => EventSubject::badge(body.target_badge_id.clone()),
            Self::CredentialDeposited(body) => {
                EventSubject::credential_deposit(body.deposit_id.clone())
            }
            Self::CredentialRevoked(body) => {
                EventSubject::credential_deposit(body.grant_id.clone())
            }
        }
    }

    /// Returns the root_id for events that are directly owned by a root.
    /// Returns `None` for events whose root ownership can only be determined
    /// by joining against materialized state (e.g. guardian approvals).
    pub fn root_id(&self) -> Option<&str> {
        match self {
            Self::RootCreated(b) => Some(&b.root_id),
            Self::RootKeyRotated(b) => Some(&b.root_id),
            Self::RootRevoked(b) => Some(&b.root_id),
            Self::DeviceAdded(b) => Some(&b.root_id),
            Self::DeviceEnrolled(b) => Some(&b.root_id),
            Self::DeviceKeyRotated(b) => Some(&b.root_id),
            Self::DeviceEncryptionKeyRotated(b) => Some(&b.root_id),
            Self::DeviceRevoked(b) => Some(&b.root_id),
            Self::DeviceFrozen(b) => Some(&b.root_id),
            Self::DeviceReplaced(b) => Some(&b.root_id),
            Self::PersonaCreated(b) => Some(&b.root_id),
            Self::PersonaKeyRotated(b) => Some(&b.root_id),
            Self::PersonaRevoked(b) => Some(&b.root_id),
            Self::RecoveryPolicyCreated(b) => Some(&b.root_id),
            Self::GuardianEnrolled(b) => Some(&b.root_id),
            Self::GuardianKeyRotated(b) => Some(&b.root_id),
            Self::RecoveryRequested(b) => Some(&b.root_id),
            Self::StorageRelationshipCreated(b) => Some(&b.root_id),
            Self::StorageLedgerUpdated(b) => Some(&b.root_id),
            Self::StorageManifestPublished(b) => Some(&b.root_id),
            _ => None,
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
            "device-enrolled" => Ok(Self::DeviceEnrolled(DeviceEnrolledEvent {
                root_id: required_field(&fields, "root_id")?,
                device_id: required_field(&fields, "device_id")?,
                label: required_field(&fields, "label")?,
                device_key: parse_public_key_material(
                    &fields,
                    "key_id",
                    "algorithm",
                    "public_key",
                )?,
                encryption_key: parse_public_key_material(
                    &fields,
                    "encryption_key_id",
                    "encryption_algorithm",
                    "encryption_public_key",
                )?,
                custody_class: CustodyClass::parse(&required_field(&fields, "custody_class")?)
                    .ok_or_else(|| ValidationError::new("invalid custody_class"))?,
                attestation_statement: optional_non_empty_field(&fields, "attestation_statement"),
                attestation_tier: AttestationTier::parse(
                    optional_non_empty_field(&fields, "attestation_tier")
                        .as_deref()
                        .unwrap_or("none"),
                )
                .ok_or_else(|| ValidationError::new("invalid attestation_tier"))?,
                presence_factor: PresenceFactor::parse(
                    optional_non_empty_field(&fields, "presence_factor")
                        .as_deref()
                        .unwrap_or("unattended"),
                )
                .ok_or_else(|| ValidationError::new("invalid presence_factor"))?,
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
            "guardian-key-rotated" => Ok(Self::GuardianKeyRotated(GuardianKeyRotatedEvent {
                guardian_id: required_field(&fields, "guardian_id")?,
                root_id: required_field(&fields, "root_id")?,
                previous_key_id: required_field(&fields, "previous_key_id")?,
                new_guardian_public_key: required_field(&fields, "new_guardian_public_key")?,
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
            "trust-attested" => {
                // C43-EVENTS-H2-DECODE: `f32::from_str` happily accepts
                // `"NaN"`, `"inf"`, `"-inf"`, and `"-0"` — the exact bit
                // patterns EVENTS-H2 rejects on the emit path. An
                // attacker-controlled event stream (relay, backup, peer
                // sync) could re-inject those values via
                // `decode_canonical`. Re-apply the same numeric guards
                // here so the parse path is symmetric with `Validate
                // for TrustAttestedEvent`.
                let score = required_field(&fields, "score")?
                    .parse::<f32>()
                    .map_err(|err| {
                        ValidationError::invalid_format(format!("invalid trust score: {err}"))
                    })?;
                if score.is_nan() {
                    return Err(ValidationError::invalid_format(
                        "trust score must not be NaN",
                    ));
                }
                if score == 0.0 && score.is_sign_negative() {
                    return Err(ValidationError::invalid_format(
                        "trust score must not be negative zero",
                    ));
                }
                if !(0.0..=1.0).contains(&score) {
                    return Err(ValidationError::invalid_format(
                        "trust score must be in [0.0, 1.0]",
                    ));
                }
                Ok(Self::TrustAttested(TrustAttestedEvent {
                    attestation_id: required_field(&fields, "attestation_id")?,
                    attester_persona_id: required_field(&fields, "attester_persona_id")?,
                    subject_persona_id: required_field(&fields, "subject_persona_id")?,
                    domain: required_field(&fields, "domain")?,
                    score,
                    recipient_bound: optional_non_empty_field(&fields, "recipient_bound"),
                }))
            }
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
            "grant-offer-created" => Ok(Self::GrantOfferCreated(GrantOfferCreatedEvent {
                offer_id: required_field(&fields, "offer_id")?,
                issuer_persona_id: required_field(&fields, "issuer_persona_id")?,
                ephemeral_public_key_hex: required_field(&fields, "ephemeral_public_key_hex")?,
                sealed_payload_hex: required_field(&fields, "sealed_payload_hex")?,
                relay_hint: optional_non_empty_field(&fields, "relay_hint"),
                expires_at: required_field(&fields, "expires_at")?
                    .parse::<u64>()
                    .map_err(|_| {
                        ValidationError::invalid_format("expires_at must be a valid u64")
                    })?,
                conditions_json: optional_non_empty_field(&fields, "conditions_json")
                    .unwrap_or_default(),
            })),
            "grant-offer-claimed" => Ok(Self::GrantOfferClaimed(GrantOfferClaimedEvent {
                offer_id: required_field(&fields, "offer_id")?,
                recipient_persona_id: required_field(&fields, "recipient_persona_id")?,
                claim_response_hex: required_field(&fields, "claim_response_hex")?,
                claimed_at: required_field(&fields, "claimed_at")?
                    .parse::<u64>()
                    .map_err(|_| {
                        ValidationError::invalid_format("claimed_at must be a valid u64")
                    })?,
            })),
            "grant-offer-revoked" => Ok(Self::GrantOfferRevoked(GrantOfferRevokedEvent {
                offer_id: required_field(&fields, "offer_id")?,
                issuer_persona_id: required_field(&fields, "issuer_persona_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "badge-issued" => {
                let evidence = {
                    let etype = fields.get("evidence_type").cloned().unwrap_or_default();
                    let payload = fields
                        .get("evidence_payload_hex")
                        .cloned()
                        .unwrap_or_default();
                    if etype.is_empty() && payload.is_empty() {
                        None
                    } else {
                        Some(BadgeEvidence {
                            evidence_type: etype,
                            payload_hex: payload,
                        })
                    }
                };
                Ok(Self::BadgeIssued(BadgeIssuedEvent {
                    badge_id: required_field(&fields, "badge_id")?,
                    issuer_persona_id: required_field(&fields, "issuer_persona_id")?,
                    recipient_persona_id: required_field(&fields, "recipient_persona_id")?,
                    badge_type: required_field(&fields, "badge_type")?,
                    display_name: required_field(&fields, "display_name")?,
                    evidence,
                    issued_at: required_field(&fields, "issued_at")?
                        .parse::<u64>()
                        .map_err(|_| {
                            ValidationError::invalid_format("issued_at must be a valid u64")
                        })?,
                    expires_at: optional_non_empty_field(&fields, "expires_at")
                        .and_then(|v| v.parse::<u64>().ok()),
                }))
            }
            "badge-revoked" => Ok(Self::BadgeRevoked(BadgeRevokedEvent {
                badge_id: required_field(&fields, "badge_id")?,
                revoker_persona_id: required_field(&fields, "revoker_persona_id")?,
                reason: required_field(&fields, "reason")?,
            })),
            "badge-disputed" => Ok(Self::BadgeDisputed(BadgeDisputedEvent {
                dispute_id: required_field(&fields, "dispute_id")?,
                target_badge_id: required_field(&fields, "target_badge_id")?,
                disputer_persona_id: required_field(&fields, "disputer_persona_id")?,
                reason: required_field(&fields, "reason")?,
                evidence: optional_non_empty_field(&fields, "evidence"),
            })),
            "credential-deposited" => Ok(Self::CredentialDeposited(CredentialDepositedEvent {
                deposit_id: required_field(&fields, "deposit_id")?,
                grant_id: required_field(&fields, "grant_id")?,
                credential_id: required_field(&fields, "credential_id")?,
                issuer_id: required_field(&fields, "issuer_id")?,
                encrypted_blocks_json: required_field(&fields, "encrypted_blocks_json")?,
                created_at: required_field(&fields, "created_at")?
                    .parse::<u64>()
                    .map_err(|_| {
                        ValidationError::invalid_format("created_at must be a valid u64")
                    })?,
                expires_at: optional_non_empty_field(&fields, "expires_at")
                    .and_then(|v| v.parse::<u64>().ok()),
            })),
            "credential-revoked" => Ok(Self::CredentialRevoked(CredentialRevokedEvent {
                grant_id: required_field(&fields, "grant_id")?,
                revoker_id: required_field(&fields, "revoker_id")?,
                reason: required_field(&fields, "reason")?,
                revoked_at: required_field(&fields, "revoked_at")?
                    .parse::<u64>()
                    .map_err(|_| {
                        ValidationError::invalid_format("revoked_at must be a valid u64")
                    })?,
            })),
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
    DeviceEnrolled,
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
    GuardianKeyRotated,
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
    GrantOfferCreated,
    GrantOfferClaimed,
    GrantOfferRevoked,
    BadgeIssued,
    BadgeRevoked,
    BadgeDisputed,
    CredentialDeposited,
    CredentialRevoked,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootCreated => "root_created",
            Self::RootKeyRotated => "root_key_rotated",
            Self::RootRevoked => "root_revoked",
            Self::DeviceAdded => "device_added",
            Self::DeviceEnrolled => "device_enrolled",
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
            Self::GuardianKeyRotated => "guardian_key_rotated",
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
            Self::GrantOfferCreated => "grant_offer_created",
            Self::GrantOfferClaimed => "grant_offer_claimed",
            Self::GrantOfferRevoked => "grant_offer_revoked",
            Self::BadgeIssued => "badge_issued",
            Self::BadgeRevoked => "badge_revoked",
            Self::BadgeDisputed => "badge_disputed",
            Self::CredentialDeposited => "credential_deposited",
            Self::CredentialRevoked => "credential_revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "root_created" => Some(Self::RootCreated),
            "root_key_rotated" => Some(Self::RootKeyRotated),
            "root_revoked" => Some(Self::RootRevoked),
            "device_added" => Some(Self::DeviceAdded),
            "device_enrolled" => Some(Self::DeviceEnrolled),
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
            "guardian_key_rotated" => Some(Self::GuardianKeyRotated),
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
            "grant_offer_created" => Some(Self::GrantOfferCreated),
            "grant_offer_claimed" => Some(Self::GrantOfferClaimed),
            "grant_offer_revoked" => Some(Self::GrantOfferRevoked),
            "badge_issued" => Some(Self::BadgeIssued),
            "badge_revoked" => Some(Self::BadgeRevoked),
            "badge_disputed" => Some(Self::BadgeDisputed),
            "credential_deposited" => Some(Self::CredentialDeposited),
            "credential_revoked" => Some(Self::CredentialRevoked),
            _ => None,
        }
    }
}

// --- Retention classification ---

/// Controls how long an event is retained before it becomes eligible for
/// compaction after a snapshot checkpoint. See ADR 021.
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
            | Self::DeviceEnrolled
            | Self::DeviceRevoked
            | Self::PersonaCreated
            | Self::PersonaRevoked => RetentionClass::Permanent,

            // Key rotations — permanent because they establish signing authority chains
            Self::RootKeyRotated
            | Self::DeviceKeyRotated
            | Self::DeviceEncryptionKeyRotated
            | Self::PersonaKeyRotated
            | Self::GuardianKeyRotated => RetentionClass::Permanent,

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
            | Self::DisclosureRevoked
            | Self::GrantOfferCreated
            | Self::GrantOfferClaimed
            | Self::GrantOfferRevoked
            | Self::BadgeIssued
            | Self::BadgeRevoked
            | Self::BadgeDisputed
            | Self::CredentialDeposited
            | Self::CredentialRevoked => RetentionClass::LongLived,

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
        validate_size(&self.display_name, "display name", MAX_LABEL_BYTES)?;
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
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)
    }
}

impl Validate for DeviceAddedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.label, "device label")?;
        validate_size(&self.label, "device label", MAX_LABEL_BYTES)?;
        self.initial_key.validate()?;
        self.initial_encryption_key.validate()
    }
}

impl Validate for DeviceEnrolledEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.label, "device label")?;
        validate_size(&self.label, "device label", MAX_LABEL_BYTES)?;
        self.device_key.validate()?;
        self.encryption_key.validate()?;
        // ADR 200 §3 (two-axis model): the attestation STATEMENT requirement is
        // keyed on the attestation TIER, not the custody class. A `presence` Device
        // at `AttestationTier::None` (the dev0 floor) rests on the OOB anchor + the
        // hardware presence gate and carries NO vendor chain; the `genuine_app` /
        // `vendor_hw` tiers MUST carry the raw statement an independent verifier
        // re-runs. `co-authority` custody always records its authority's attestation.
        let statement_required = self.attestation_tier.requires_statement()
            || self.custody_class == CustodyClass::CoAuthority;
        if statement_required
            && self
                .attestation_statement
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            return Err(ValidationError::new(format!(
                "custody class {} at attestation tier {} requires a recorded attestation statement",
                self.custody_class.as_str(),
                self.attestation_tier.as_str(),
            )));
        }
        // An attestation tier above `None` describes a presence-Device assurance
        // band; it is meaningless on a non-presence Device.
        if self.attestation_tier != AttestationTier::None
            && self.custody_class != CustodyClass::Presence
        {
            return Err(ValidationError::new(
                "attestation tier above `none` is only valid for a presence Device",
            ));
        }
        // ADR 200 §3 (presence axis): a `presence` Device MUST carry a genuine
        // use-time human-presence factor; conversely a non-presence Device is
        // `unattended` (no human gate). Keeps the two axes coherent.
        match self.custody_class {
            CustodyClass::Presence if !self.presence_factor.is_human_present() => {
                return Err(ValidationError::new(
                    "a presence Device requires a human presence factor, not `unattended`",
                ));
            }
            CustodyClass::Presence => {}
            _ if self.presence_factor.is_human_present() => {
                return Err(ValidationError::new(format!(
                    "custody class {} must record an `unattended` presence factor",
                    self.custody_class.as_str(),
                )));
            }
            _ => {}
        }
        validate_optional_size(
            self.attestation_statement.as_deref(),
            "attestation statement",
            MAX_SEALED_PAYLOAD_HEX_BYTES,
        )
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
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)
    }
}

impl Validate for DeviceFrozenEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.reason, "freeze reason")?;
        validate_size(&self.reason, "freeze reason", MAX_REASON_BYTES)
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
        validate_size(&self.label, "persona label", MAX_LABEL_BYTES)?;
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
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)
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
        validate_size(&self.guardian_label, "guardian label", MAX_LABEL_BYTES)?;
        validate_non_empty(&self.guardian_public_key, "guardian public key")?;
        validate_size(
            &self.guardian_public_key,
            "guardian public key",
            MAX_PUBLIC_KEY_HEX_BYTES,
        )
    }
}

impl Validate for GuardianKeyRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.guardian_id, "guardian id")?;
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.previous_key_id, "previous key id")?;
        validate_size(
            &self.previous_key_id,
            "previous key id",
            MAX_PUBLIC_KEY_HEX_BYTES,
        )?;
        validate_non_empty(&self.new_guardian_public_key, "new guardian public key")?;
        validate_size(
            &self.new_guardian_public_key,
            "new guardian public key",
            MAX_PUBLIC_KEY_HEX_BYTES,
        )?;
        if self.previous_key_id == self.new_guardian_public_key {
            return Err(ValidationError::state_violation(
                "rotated guardian key must change key id",
            ));
        }
        Ok(())
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
        validate_non_empty(&self.reason, "contest reason")?;
        validate_size(&self.reason, "contest reason", MAX_REASON_BYTES)
    }
}

impl Validate for RecoveryRejectedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.request_id, "request id")?;
        validate_non_empty(&self.rejected_by, "rejected by")?;
        validate_non_empty(&self.reason, "rejection reason")?;
        validate_size(&self.reason, "rejection reason", MAX_REASON_BYTES)
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
        validate_size(&self.domain, "trust domain", MAX_LABEL_BYTES)?;
        // EVENTS-H2: reject NaN and negative zero so canonical encoding
        // `format!("{:.6}", score)` is deterministic. `+0.0 == -0.0` compares
        // equal but renders as `"0.000000"` vs `"-0.000000"`, which would
        // produce two distinct signed byte sequences for the same semantic
        // score. `Range::contains` already excludes NaN, but we check
        // explicitly so the error message is unambiguous.
        if self.score.is_nan() {
            return Err(ValidationError::invalid_format(
                "trust score must not be NaN",
            ));
        }
        if self.score == 0.0 && self.score.is_sign_negative() {
            return Err(ValidationError::invalid_format(
                "trust score must not be negative zero",
            ));
        }
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
        validate_non_empty(&self.transport_hint, "transport hint")?;
        validate_size(
            &self.transport_hint,
            "transport hint",
            MAX_TRANSPORT_HINT_BYTES,
        )
    }
}

impl Validate for EndpointRotatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.peer_id, "peer id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.previous_transport_hint, "previous transport hint")?;
        validate_size(
            &self.previous_transport_hint,
            "previous transport hint",
            MAX_TRANSPORT_HINT_BYTES,
        )?;
        validate_non_empty(&self.new_transport_hint, "new transport hint")?;
        validate_size(
            &self.new_transport_hint,
            "new transport hint",
            MAX_TRANSPORT_HINT_BYTES,
        )?;
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
        validate_non_empty(&self.reason, "shutdown reason")?;
        validate_size(&self.reason, "shutdown reason", MAX_REASON_BYTES)
    }
}

impl Validate for MessageSentEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.message_id, "message id")?;
        validate_non_empty(&self.sender_persona_id, "sender persona id")?;
        validate_non_empty(&self.recipient_persona_id, "recipient persona id")?;
        validate_non_empty(&self.ciphertext_hex, "ciphertext")?;
        validate_size(&self.ciphertext_hex, "ciphertext", MAX_CIPHERTEXT_HEX_BYTES)?;
        Ok(())
    }
}

impl Validate for ContentPublishedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.content_id, "content id")?;
        validate_non_empty(&self.author_persona_id, "author persona id")?;
        validate_non_empty(&self.content_type, "content type")?;
        validate_size(&self.content_type, "content type", MAX_LABEL_BYTES)?;
        validate_non_empty(&self.payload_hex, "payload")?;
        validate_size(&self.payload_hex, "payload", MAX_CIPHERTEXT_HEX_BYTES)?;
        Ok(())
    }
}

impl Validate for DisclosureRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.revocation_id, "revocation id")?;
        validate_non_empty(&self.artifact_id, "artifact id")?;
        validate_non_empty(&self.revoker_persona_id, "revoker persona id")?;
        validate_non_empty(&self.reason, "reason")?;
        validate_size(&self.reason, "reason", MAX_REASON_BYTES)?;
        Ok(())
    }
}

impl Validate for GrantOfferCreatedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.offer_id, "offer id")?;
        validate_non_empty(&self.issuer_persona_id, "issuer persona id")?;
        validate_non_empty(&self.ephemeral_public_key_hex, "ephemeral public key")?;
        validate_size(
            &self.ephemeral_public_key_hex,
            "ephemeral public key",
            MAX_PUBLIC_KEY_HEX_BYTES,
        )?;
        validate_non_empty(&self.sealed_payload_hex, "sealed payload")?;
        validate_size(
            &self.sealed_payload_hex,
            "sealed payload",
            MAX_SEALED_PAYLOAD_HEX_BYTES,
        )?;
        validate_size(
            &self.conditions_json,
            "conditions json",
            MAX_CONDITIONS_JSON_BYTES,
        )?;
        if self.expires_at == 0 {
            return Err(ValidationError::invalid_format(
                "grant offer must have a non-zero expiry",
            ));
        }
        // relay_hint must use a TLS-secured scheme (https:// or wss://) to
        // prevent SSRF via arbitrary or plaintext schemes when clients follow it.
        if let Some(hint) = &self.relay_hint
            && !hint.is_empty()
            && !hint.starts_with("https://")
            && !hint.starts_with("wss://")
        {
            return Err(ValidationError::invalid_format(
                "relay_hint must be an https:// or wss:// URL",
            ));
        }
        validate_optional_size(
            self.relay_hint.as_deref(),
            "relay hint",
            MAX_TRANSPORT_HINT_BYTES,
        )?;
        Ok(())
    }
}

impl Validate for GrantOfferClaimedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.offer_id, "offer id")?;
        validate_non_empty(&self.recipient_persona_id, "recipient persona id")?;
        validate_non_empty(&self.claim_response_hex, "claim response")?;
        validate_size(
            &self.claim_response_hex,
            "claim response",
            MAX_SEALED_PAYLOAD_HEX_BYTES,
        )?;
        if self.claimed_at == 0 {
            return Err(ValidationError::invalid_format(
                "claim timestamp must be non-zero",
            ));
        }
        Ok(())
    }
}

impl Validate for GrantOfferRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.offer_id, "offer id")?;
        validate_non_empty(&self.issuer_persona_id, "issuer persona id")?;
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)
    }
}

impl Validate for BadgeEvidence {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.evidence_type, "evidence type")?;
        validate_size(&self.evidence_type, "evidence type", MAX_LABEL_BYTES)?;
        validate_non_empty(&self.payload_hex, "evidence payload")?;
        validate_size(
            &self.payload_hex,
            "evidence payload",
            MAX_BADGE_PAYLOAD_HEX_BYTES,
        )
    }
}

impl Validate for BadgeIssuedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.badge_id, "badge id")?;
        validate_non_empty(&self.issuer_persona_id, "issuer persona id")?;
        validate_non_empty(&self.recipient_persona_id, "recipient persona id")?;
        validate_non_empty(&self.badge_type, "badge type")?;
        validate_size(&self.badge_type, "badge type", MAX_LABEL_BYTES)?;
        validate_non_empty(&self.display_name, "display name")?;
        validate_size(&self.display_name, "display name", MAX_LABEL_BYTES)?;
        if let Some(ref evidence) = self.evidence {
            evidence.validate()?;
        }
        if self.issued_at == 0 {
            return Err(ValidationError::invalid_format(
                "badge issued_at must be non-zero",
            ));
        }
        Ok(())
    }
}

impl Validate for BadgeRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.badge_id, "badge id")?;
        validate_non_empty(&self.revoker_persona_id, "revoker persona id")?;
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)
    }
}

impl Validate for BadgeDisputedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.dispute_id, "dispute id")?;
        validate_non_empty(&self.target_badge_id, "target badge id")?;
        validate_non_empty(&self.disputer_persona_id, "disputer persona id")?;
        validate_non_empty(&self.reason, "dispute reason")?;
        validate_size(&self.reason, "dispute reason", MAX_REASON_BYTES)?;
        validate_optional_size(
            self.evidence.as_deref(),
            "dispute evidence",
            MAX_BADGE_PAYLOAD_HEX_BYTES,
        )
    }
}

impl Validate for CredentialDepositedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.deposit_id, "deposit id")?;
        validate_non_empty(&self.grant_id, "grant id")?;
        validate_non_empty(&self.credential_id, "credential id")?;
        validate_non_empty(&self.issuer_id, "issuer id")?;
        validate_non_empty(&self.encrypted_blocks_json, "encrypted blocks json")?;
        if self.encrypted_blocks_json.len() > MAX_ENCRYPTED_BLOCKS_JSON_BYTES {
            return Err(ValidationError::invalid_format(format!(
                "encrypted_blocks_json exceeds maximum size of {} bytes",
                MAX_ENCRYPTED_BLOCKS_JSON_BYTES
            )));
        }
        if self.created_at == 0 {
            return Err(ValidationError::invalid_format(
                "credential deposit created_at must be non-zero",
            ));
        }
        Ok(())
    }
}

impl Validate for CredentialRevokedEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.grant_id, "grant id")?;
        validate_non_empty(&self.revoker_id, "revoker id")?;
        validate_non_empty(&self.reason, "revocation reason")?;
        validate_size(&self.reason, "revocation reason", MAX_REASON_BYTES)?;
        if self.revoked_at == 0 {
            return Err(ValidationError::invalid_format(
                "credential revocation revoked_at must be non-zero",
            ));
        }
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
            Self::DeviceEnrolled(body) => body.validate(),
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
            Self::GuardianKeyRotated(body) => body.validate(),
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
            Self::GrantOfferCreated(body) => body.validate(),
            Self::GrantOfferClaimed(body) => body.validate(),
            Self::GrantOfferRevoked(body) => body.validate(),
            Self::BadgeIssued(body) => body.validate(),
            Self::BadgeRevoked(body) => body.validate(),
            Self::BadgeDisputed(body) => body.validate(),
            Self::CredentialDeposited(body) => body.validate(),
            Self::CredentialRevoked(body) => body.validate(),
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
            Self::DeviceEnrolled(body) => canonical_record(
                "device-enrolled",
                &[
                    ("root_id", body.root_id.clone()),
                    ("device_id", body.device_id.clone()),
                    ("label", body.label.clone()),
                    ("key_id", body.device_key.key_id.clone()),
                    ("algorithm", body.device_key.algorithm.as_str().to_string()),
                    ("public_key", body.device_key.public_key.clone()),
                    ("encryption_key_id", body.encryption_key.key_id.clone()),
                    (
                        "encryption_algorithm",
                        body.encryption_key.algorithm.as_str().to_string(),
                    ),
                    (
                        "encryption_public_key",
                        body.encryption_key.public_key.clone(),
                    ),
                    ("custody_class", body.custody_class.as_str().to_string()),
                    (
                        "attestation_statement",
                        body.attestation_statement.clone().unwrap_or_default(),
                    ),
                    (
                        "attestation_tier",
                        body.attestation_tier.as_str().to_string(),
                    ),
                    ("presence_factor", body.presence_factor.as_str().to_string()),
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
            Self::GuardianKeyRotated(body) => canonical_record(
                "guardian-key-rotated",
                &[
                    ("guardian_id", body.guardian_id.clone()),
                    ("root_id", body.root_id.clone()),
                    ("previous_key_id", body.previous_key_id.clone()),
                    (
                        "new_guardian_public_key",
                        body.new_guardian_public_key.clone(),
                    ),
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
            Self::GrantOfferCreated(body) => canonical_record(
                "grant-offer-created",
                &[
                    ("offer_id", body.offer_id.clone()),
                    ("issuer_persona_id", body.issuer_persona_id.clone()),
                    (
                        "ephemeral_public_key_hex",
                        body.ephemeral_public_key_hex.clone(),
                    ),
                    ("sealed_payload_hex", body.sealed_payload_hex.clone()),
                    ("relay_hint", body.relay_hint.clone().unwrap_or_default()),
                    ("expires_at", body.expires_at.to_string()),
                    ("conditions_json", body.conditions_json.clone()),
                ],
            ),
            Self::GrantOfferClaimed(body) => canonical_record(
                "grant-offer-claimed",
                &[
                    ("offer_id", body.offer_id.clone()),
                    ("recipient_persona_id", body.recipient_persona_id.clone()),
                    ("claim_response_hex", body.claim_response_hex.clone()),
                    ("claimed_at", body.claimed_at.to_string()),
                ],
            ),
            Self::GrantOfferRevoked(body) => canonical_record(
                "grant-offer-revoked",
                &[
                    ("offer_id", body.offer_id.clone()),
                    ("issuer_persona_id", body.issuer_persona_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::BadgeIssued(body) => {
                let (ev_type, ev_payload) = match &body.evidence {
                    Some(e) => (e.evidence_type.clone(), e.payload_hex.clone()),
                    None => (String::new(), String::new()),
                };
                canonical_record(
                    "badge-issued",
                    &[
                        ("badge_id", body.badge_id.clone()),
                        ("issuer_persona_id", body.issuer_persona_id.clone()),
                        ("recipient_persona_id", body.recipient_persona_id.clone()),
                        ("badge_type", body.badge_type.clone()),
                        ("display_name", body.display_name.clone()),
                        ("evidence_type", ev_type),
                        ("evidence_payload_hex", ev_payload),
                        ("issued_at", body.issued_at.to_string()),
                        (
                            "expires_at",
                            body.expires_at.map(|v| v.to_string()).unwrap_or_default(),
                        ),
                    ],
                )
            }
            Self::BadgeRevoked(body) => canonical_record(
                "badge-revoked",
                &[
                    ("badge_id", body.badge_id.clone()),
                    ("revoker_persona_id", body.revoker_persona_id.clone()),
                    ("reason", body.reason.clone()),
                ],
            ),
            Self::BadgeDisputed(body) => canonical_record(
                "badge-disputed",
                &[
                    ("dispute_id", body.dispute_id.clone()),
                    ("target_badge_id", body.target_badge_id.clone()),
                    ("disputer_persona_id", body.disputer_persona_id.clone()),
                    ("reason", body.reason.clone()),
                    ("evidence", body.evidence.clone().unwrap_or_default()),
                ],
            ),
            Self::CredentialDeposited(body) => canonical_record(
                "credential-deposited",
                &[
                    ("deposit_id", body.deposit_id.clone()),
                    ("grant_id", body.grant_id.clone()),
                    ("credential_id", body.credential_id.clone()),
                    ("issuer_id", body.issuer_id.clone()),
                    ("encrypted_blocks_json", body.encrypted_blocks_json.clone()),
                    ("created_at", body.created_at.to_string()),
                    (
                        "expires_at",
                        body.expires_at.map(|v| v.to_string()).unwrap_or_default(),
                    ),
                ],
            ),
            Self::CredentialRevoked(body) => canonical_record(
                "credential-revoked",
                &[
                    ("grant_id", body.grant_id.clone()),
                    ("revoker_id", body.revoker_id.clone()),
                    ("reason", body.reason.clone()),
                    ("revoked_at", body.revoked_at.to_string()),
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
impl_typed_event_canonical_encode!(DeviceEnrolledEvent, DeviceEnrolled);
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
impl_typed_event_canonical_encode!(GuardianKeyRotatedEvent, GuardianKeyRotated);
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
impl_typed_event_canonical_encode!(GrantOfferCreatedEvent, GrantOfferCreated);
impl_typed_event_canonical_encode!(GrantOfferClaimedEvent, GrantOfferClaimed);
impl_typed_event_canonical_encode!(GrantOfferRevokedEvent, GrantOfferRevoked);
impl_typed_event_canonical_encode!(BadgeIssuedEvent, BadgeIssued);
impl_typed_event_canonical_encode!(BadgeRevokedEvent, BadgeRevoked);
impl_typed_event_canonical_encode!(BadgeDisputedEvent, BadgeDisputed);
impl_typed_event_canonical_encode!(CredentialDepositedEvent, CredentialDeposited);
impl_typed_event_canonical_encode!(CredentialRevokedEvent, CredentialRevoked);

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
        EventType::GuardianKeyRotated,
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
        EventType::GrantOfferCreated,
        EventType::GrantOfferClaimed,
        EventType::GrantOfferRevoked,
        EventType::BadgeIssued,
        EventType::BadgeRevoked,
        EventType::BadgeDisputed,
        EventType::CredentialDeposited,
        EventType::CredentialRevoked,
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
            EventType::GuardianKeyRotated,
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

#[cfg(test)]
mod credential_validation_tests {
    use super::*;

    fn valid_credential_deposited() -> CredentialDepositedEvent {
        CredentialDepositedEvent {
            deposit_id: "deposit-001".into(),
            grant_id: "grant-001".into(),
            credential_id: "cred-001".into(),
            issuer_id: "persona-001".into(),
            encrypted_blocks_json: r#"{"blocks":[]}"#.into(),
            created_at: 1_700_000_000,
            expires_at: None,
        }
    }

    #[test]
    fn valid_credential_deposited_passes() {
        assert!(valid_credential_deposited().validate().is_ok());
    }

    #[test]
    fn oversized_encrypted_blocks_json_rejected() {
        let mut event = valid_credential_deposited();
        event.encrypted_blocks_json = "x".repeat(MAX_ENCRYPTED_BLOCKS_JSON_BYTES + 1);
        let err = event.validate().unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "expected size error, got: {err}"
        );
    }
}

#[cfg(test)]
mod size_limit_tests {
    //! Per-field caps and envelope-level backstop coverage for EVENTS-H1.
    //! Each oversized-field test mirrors the attack shape from
    //! `docs/security-reviews/events-rs-2026-04-23.md` H-1.
    use super::*;
    use core_types::size_limits::{
        MAX_BADGE_PAYLOAD_HEX_BYTES, MAX_CIPHERTEXT_HEX_BYTES, MAX_CONDITIONS_JSON_BYTES,
        MAX_REASON_BYTES, MAX_SEALED_PAYLOAD_HEX_BYTES, MAX_TRANSPORT_HINT_BYTES,
    };

    fn assert_size_error(err: &ValidationError) {
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "expected size cap error, got: {err}"
        );
    }

    fn valid_message_sent() -> MessageSentEvent {
        MessageSentEvent {
            message_id: "msg-001".into(),
            sender_persona_id: "persona-a".into(),
            recipient_persona_id: "persona-b".into(),
            ciphertext_hex: "deadbeef".into(),
        }
    }

    #[test]
    fn principal_signer_binding_is_canonical() {
        let binding = SignerBinding::principal("principal-1", "device-1");
        assert_eq!(binding.signer.kind, SubjectKind::Principal);
        assert_eq!(binding.signer.subject_id, "principal-1");
        assert_eq!(binding.key_id, "device-1");
        assert_eq!(binding.role, KeyRole::Principal);
        assert_eq!(
            SubjectKind::parse("principal"),
            Some(SubjectKind::Principal)
        );
        assert_eq!(KeyRole::parse("principal"), Some(KeyRole::Principal));

        let encoded = String::from_utf8(binding.canonical_encode()).unwrap();
        assert!(encoded.contains("signer_kind=principal"));
        assert!(encoded.contains("role=principal"));
    }

    #[test]
    fn legacy_root_and_persona_aliases_normalize_to_principal() {
        let root = SignerBinding::root("root-1", "device-root").canonical_principal_alias();
        assert_eq!(root.signer.kind, SubjectKind::Principal);
        assert_eq!(root.signer.subject_id, "root-1");
        assert_eq!(root.key_id, "device-root");
        assert_eq!(root.role, KeyRole::Principal);

        let persona =
            SignerBinding::persona("persona-1", "device-persona").canonical_principal_alias();
        assert_eq!(persona.signer.kind, SubjectKind::Principal);
        assert_eq!(persona.signer.subject_id, "persona-1");
        assert_eq!(persona.key_id, "device-persona");
        assert_eq!(persona.role, KeyRole::Principal);

        assert!(SubjectKind::Root.is_legacy_principal_alias());
        assert!(SubjectKind::Persona.is_legacy_principal_alias());
        assert_eq!(
            SubjectKind::parse("root")
                .unwrap()
                .canonical_principal_kind(),
            SubjectKind::Principal
        );
        assert_eq!(
            KeyRole::parse("persona")
                .unwrap()
                .canonical_principal_role(),
            KeyRole::Principal
        );
    }

    #[test]
    fn identity_subjects_emit_principal_kind() {
        let root = EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-1".into(),
            display_name: "Root".into(),
            initial_key: PublicKeyMaterial {
                key_id: "root-device".into(),
                algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:root-device".into(),
            },
        });
        assert_eq!(root.subject(), EventSubject::principal("root-1"));

        let persona = EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-1".into(),
            persona_id: "persona-1".into(),
            label: "Runtime".into(),
            disclosure_profile: None,
            survival_mode: SurvivalMode::Strict,
            initial_key: PublicKeyMaterial {
                key_id: "persona-device".into(),
                algorithm: core_principals::KeyAlgorithm::DevEd25519Like,
                public_key: "devpub:persona-device".into(),
            },
        });
        assert_eq!(persona.subject(), EventSubject::principal("persona-1"));

        let message = EventBody::MessageSent(valid_message_sent());
        assert_eq!(message.subject(), EventSubject::principal("persona-a"));
    }

    #[test]
    fn message_sent_valid_passes() {
        assert!(valid_message_sent().validate().is_ok());
    }

    #[test]
    fn oversized_ciphertext_hex_rejected() {
        let mut event = valid_message_sent();
        event.ciphertext_hex = "a".repeat(MAX_CIPHERTEXT_HEX_BYTES + 1);
        assert_size_error(&event.validate().unwrap_err());
    }

    fn valid_grant_offer() -> GrantOfferCreatedEvent {
        GrantOfferCreatedEvent {
            offer_id: "offer-001".into(),
            issuer_persona_id: "persona-issuer".into(),
            ephemeral_public_key_hex: "deadbeef".into(),
            sealed_payload_hex: "cafebabe".into(),
            relay_hint: None,
            expires_at: 1_800_000_000,
            conditions_json: String::new(),
        }
    }

    #[test]
    fn grant_offer_valid_passes() {
        assert!(valid_grant_offer().validate().is_ok());
    }

    #[test]
    fn oversized_sealed_payload_rejected() {
        let mut event = valid_grant_offer();
        event.sealed_payload_hex = "a".repeat(MAX_SEALED_PAYLOAD_HEX_BYTES + 1);
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_conditions_json_rejected() {
        let mut event = valid_grant_offer();
        event.conditions_json = "a".repeat(MAX_CONDITIONS_JSON_BYTES + 1);
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_relay_hint_rejected() {
        let mut event = valid_grant_offer();
        let mut hint = String::from("https://");
        hint.push_str(&"a".repeat(MAX_TRANSPORT_HINT_BYTES + 1));
        event.relay_hint = Some(hint);
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_persona_revocation_reason_rejected() {
        let event = PersonaRevokedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            reason: "x".repeat(MAX_REASON_BYTES + 1),
        };
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_badge_evidence_payload_rejected() {
        let evidence = BadgeEvidence {
            evidence_type: "proof-of-ride".into(),
            payload_hex: "a".repeat(MAX_BADGE_PAYLOAD_HEX_BYTES + 1),
        };
        assert_size_error(&evidence.validate().unwrap_err());
    }

    #[test]
    fn oversized_dispute_evidence_rejected() {
        let event = BadgeDisputedEvent {
            dispute_id: "dispute-a".into(),
            target_badge_id: "badge-a".into(),
            disputer_persona_id: "persona-a".into(),
            reason: "spurious".into(),
            evidence: Some("a".repeat(MAX_BADGE_PAYLOAD_HEX_BYTES + 1)),
        };
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_transport_hint_rejected() {
        let event = RelayHintUpdatedEvent {
            peer_id: "peer-a".into(),
            device_id: "device-a".into(),
            transport_hint: "a".repeat(MAX_TRANSPORT_HINT_BYTES + 1),
        };
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn oversized_relay_shutdown_reason_rejected() {
        let event = RelayShutdownNoticeEvent {
            relay_peer_id: "peer-a".into(),
            reason: "x".repeat(MAX_REASON_BYTES + 1),
            deadline_epoch: 1_800_000_000,
        };
        assert_size_error(&event.validate().unwrap_err());
    }

    #[test]
    fn at_limit_payloads_pass() {
        // Per-field caps must accept exactly-at-limit values; off-by-one
        // bugs would silently break legitimate payloads.
        let mut msg = valid_message_sent();
        msg.ciphertext_hex = "a".repeat(MAX_CIPHERTEXT_HEX_BYTES);
        assert!(msg.validate().is_ok());

        let mut offer = valid_grant_offer();
        offer.sealed_payload_hex = "a".repeat(MAX_SEALED_PAYLOAD_HEX_BYTES);
        offer.conditions_json = "a".repeat(MAX_CONDITIONS_JSON_BYTES);
        assert!(offer.validate().is_ok());
    }
}

#[cfg(test)]
mod trust_score_canonical_tests {
    //! EVENTS-H2: `TrustAttestedEvent.score` canonical encoding must be
    //! deterministic. `format!("{:.6}", score)` renders `+0.0` as
    //! `"0.000000"` and `-0.0` as `"-0.000000"`, even though the two
    //! values compare equal. We close the divergence by rejecting NaN
    //! and negative-zero at the validation boundary so the existing
    //! decimal encoding stays stable and existing signatures remain
    //! verifiable.
    use super::*;

    fn valid_trust_attested(score: f32) -> TrustAttestedEvent {
        TrustAttestedEvent {
            attestation_id: "att-001".into(),
            attester_persona_id: "persona-attester".into(),
            subject_persona_id: "persona-subject".into(),
            domain: "example".into(),
            score,
            recipient_bound: None,
        }
    }

    #[test]
    fn test_trust_attested_score_canonical_bit_exactness() {
        // `+0.0 == -0.0` in IEEE-754 but they render to distinct strings
        // under `format!("{:.6}", ...)`. Without the EVENTS-H2 guard an
        // attacker could produce two valid signed attestations for the
        // same semantic score. The fix: validation rejects negative
        // zero, so only the positive-zero form can ever reach the
        // canonical encoder.
        let pos_zero = valid_trust_attested(0.0f32);
        let neg_zero = valid_trust_attested(-0.0f32);

        // Sanity: the two scores compare equal but have different bits.
        assert_eq!(pos_zero.score, neg_zero.score);
        assert_ne!(pos_zero.score.to_bits(), neg_zero.score.to_bits());

        // The positive-zero form must pass validation.
        pos_zero
            .validate()
            .expect("positive zero score is a valid attestation");

        // The negative-zero form must be rejected at the validation
        // boundary so it can never be signed.
        let err = neg_zero
            .validate()
            .expect_err("negative zero score must be rejected");
        assert!(
            err.to_string().contains("negative zero"),
            "expected negative-zero rejection, got: {err}"
        );

        // NaN must also be rejected (explicit check; `Range::contains`
        // already excludes NaN but the error message would be
        // misleading without the dedicated guard).
        let nan_body = valid_trust_attested(f32::NAN);
        let err = nan_body.validate().expect_err("NaN score must be rejected");
        assert!(
            err.to_string().contains("NaN"),
            "expected NaN rejection, got: {err}"
        );

        // Out-of-range values (negative, >1.0, infinity) still rejected.
        assert!(valid_trust_attested(-0.5f32).validate().is_err());
        assert!(valid_trust_attested(1.5f32).validate().is_err());
        assert!(valid_trust_attested(f32::INFINITY).validate().is_err());
        assert!(valid_trust_attested(f32::NEG_INFINITY).validate().is_err());
    }

    #[test]
    fn test_trust_attested_score_canonical_roundtrip_positive_zero() {
        // With `-0.0` rejected at validation, the canonical-encode /
        // parse path must roundtrip cleanly for `+0.0`. The bytes
        // produced before and after a parse-reencode pass must match.
        let body = EventBody::TrustAttested(valid_trust_attested(0.0f32));
        let encoded = body.canonical_encode();
        let reparsed = EventBody::decode_canonical(&encoded)
            .expect("positive-zero attestation must roundtrip");
        let reencoded = reparsed.canonical_encode();
        assert_eq!(
            encoded, reencoded,
            "canonical encoding must be idempotent for +0.0 score"
        );
    }

    /// Build a canonical `trust-attested` payload with a caller-chosen
    /// raw `score` string, bypassing the emit-path validation. The
    /// emit path would refuse these values (EVENTS-H2), but an
    /// attacker-controlled relay, backup, or peer stream can forge
    /// the bytes directly. This helper lets us assert that
    /// `decode_canonical` rejects them (C43-EVENTS-H2-DECODE).
    fn hostile_trust_attested_payload(score_literal: &str) -> Vec<u8> {
        format!(
            "type=trust-attested\n\
             attestation_id=att-001\n\
             attester_persona_id=persona-attester\n\
             subject_persona_id=persona-subject\n\
             domain=example\n\
             score={score_literal}\n\
             recipient_bound=\n"
        )
        .into_bytes()
    }

    #[test]
    fn decode_canonical_rejects_nan_score() {
        // `f32::from_str("NaN")` succeeds, so the pre-C43 decode path
        // would happily produce a `TrustAttestedEvent { score: NaN }`
        // from attacker bytes.
        let payload = hostile_trust_attested_payload("NaN");
        let err = EventBody::decode_canonical(&payload)
            .expect_err("NaN score must be rejected at decode");
        assert!(
            err.to_string().contains("NaN"),
            "expected NaN rejection, got: {err}"
        );
    }

    #[test]
    fn decode_canonical_rejects_negative_zero_score() {
        // `"-0"` parses to the IEEE-754 negative-zero bit pattern, the
        // exact case EVENTS-H2 closes because `format!("{:.6}", -0.0)`
        // renders `"-0.000000"` and breaks canonical determinism.
        let payload = hostile_trust_attested_payload("-0");
        let err = EventBody::decode_canonical(&payload)
            .expect_err("negative-zero score must be rejected at decode");
        assert!(
            err.to_string().contains("negative zero"),
            "expected negative-zero rejection, got: {err}"
        );
    }

    #[test]
    fn decode_canonical_rejects_infinity_score() {
        // `"inf"` and `"-inf"` both parse as `f32` and fall outside
        // `[0.0, 1.0]`; decode must reject them even though the raw
        // string form is valid for `f32::from_str`.
        let pos_inf = hostile_trust_attested_payload("inf");
        let err = EventBody::decode_canonical(&pos_inf)
            .expect_err("positive infinity score must be rejected at decode");
        assert!(
            err.to_string().contains("[0.0, 1.0]"),
            "expected range rejection for +inf, got: {err}"
        );

        let neg_inf = hostile_trust_attested_payload("-inf");
        let err = EventBody::decode_canonical(&neg_inf)
            .expect_err("negative infinity score must be rejected at decode");
        assert!(
            err.to_string().contains("[0.0, 1.0]"),
            "expected range rejection for -inf, got: {err}"
        );
    }

    #[test]
    fn decode_canonical_rejects_nan_inf_negzero() {
        // C43-EVENTS-H2-DECODE consolidated regression: every divergent
        // float bit pattern that EVENTS-H2 closes on the emit path must
        // also be rejected on the decode path. `f32::from_str` accepts
        // all four forms below, so without explicit guards an
        // attacker-controlled relay/backup/sync stream could re-inject
        // NaN, ±inf, or -0 into a `TrustAttestedEvent` and break
        // canonical determinism (which would let two distinct signed
        // payloads carry the "same" semantic score).
        //
        // Decode must `Err` for each of these literal `score` field
        // values; producing `Ok(TrustAttested(...))` would be a
        // security regression.
        for literal in ["NaN", "inf", "-inf", "-0"] {
            let payload = hostile_trust_attested_payload(literal);
            let result = EventBody::decode_canonical(&payload);
            assert!(
                result.is_err(),
                "decode_canonical must reject score={literal}, got Ok"
            );
        }
    }
}

#[cfg(test)]
mod attestation_axes_tests {
    use super::*;
    use core_principals::KeyAlgorithm;

    fn dev_key() -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: "k-d2".into(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: "p256:04aa".into(),
        }
    }

    // The §4 ECIES recipient key — DISTINCT from `dev_key` (sign != decrypt).
    fn enc_key() -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: "k-d2-ecies".into(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: "p256:04bb".into(),
        }
    }

    fn enrolled(
        custody: CustodyClass,
        tier: AttestationTier,
        factor: PresenceFactor,
        statement: Option<&str>,
    ) -> DeviceEnrolledEvent {
        DeviceEnrolledEvent {
            root_id: "root-1".into(),
            device_id: "d2".into(),
            label: "Backup".into(),
            device_key: dev_key(),
            encryption_key: enc_key(),
            custody_class: custody,
            attestation_statement: statement.map(str::to_string),
            attestation_tier: tier,
            presence_factor: factor,
        }
    }

    #[test]
    fn presence_tier_none_is_enrollable_without_a_statement() {
        // The dev0 floor: a `.userPresence` SE key, custody proven by OOB + the
        // hardware gate, carries NO vendor statement.
        let e = enrolled(
            CustodyClass::Presence,
            AttestationTier::None,
            PresenceFactor::UserPresence,
            None,
        );
        assert!(
            e.validate().is_ok(),
            "tier=None presence must be enrollable"
        );
    }

    #[test]
    fn presence_vendor_hw_requires_a_statement() {
        let missing = enrolled(
            CustodyClass::Presence,
            AttestationTier::VendorHw,
            PresenceFactor::HardwareTouch,
            None,
        );
        assert!(
            missing.validate().is_err(),
            "tier=VendorHw must require a recorded statement"
        );
        let present = enrolled(
            CustodyClass::Presence,
            AttestationTier::VendorHw,
            PresenceFactor::HardwareTouch,
            Some("vendor-chain"),
        );
        assert!(present.validate().is_ok(), "with a statement it is valid");
    }

    #[test]
    fn presence_device_must_carry_a_human_factor() {
        let e = enrolled(
            CustodyClass::Presence,
            AttestationTier::None,
            PresenceFactor::Unattended,
            None,
        );
        assert!(
            e.validate().is_err(),
            "a presence Device cannot be `unattended`"
        );
    }

    #[test]
    fn tier_above_none_is_rejected_on_non_presence_custody() {
        // CoAuthority custody carries a statement but the attestation TIER axis is
        // presence-specific — a vendor_hw tier on co-authority is incoherent.
        let e = enrolled(
            CustodyClass::CoAuthority,
            AttestationTier::VendorHw,
            PresenceFactor::Unattended,
            Some("vendor-chain"),
        );
        assert!(
            e.validate().is_err(),
            "attestation tier above None is presence-only"
        );
    }

    #[test]
    fn canonical_roundtrip_preserves_both_axes() {
        let body = EventBody::DeviceEnrolled(enrolled(
            CustodyClass::Presence,
            AttestationTier::VendorHw,
            PresenceFactor::Biometric,
            Some("vendor-chain"),
        ));
        let encoded = body.canonical_encode();
        let reparsed =
            EventBody::decode_canonical(&encoded).expect("device-enrolled must roundtrip");
        match &reparsed {
            EventBody::DeviceEnrolled(b) => {
                assert_eq!(b.attestation_tier, AttestationTier::VendorHw);
                assert_eq!(b.presence_factor, PresenceFactor::Biometric);
            }
            other => panic!("wrong body: {other:?}"),
        }
        assert_eq!(
            encoded,
            reparsed.canonical_encode(),
            "canonical encoding must be idempotent across the new axes"
        );
    }
}
