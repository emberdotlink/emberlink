use std::collections::{BTreeMap, BTreeSet};

use core_event_types::{
    AttestationTier, CustodyClass, PresenceFactor, StorageLedgerEntry, StorageRelationship,
};

use core_principals::{
    EndpointDescriptor, PublicKeyMaterial, RecoveryScope, SurvivalMode, TrustAttestation,
};

use core_principals::DerivedTrustStatement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
    Frozen,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonaStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryRequestStatus {
    Requested,
    Approved,
    Contested,
    Rejected,
    Executed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecord {
    pub root_id: String,
    pub display_name: String,
    pub active_key: PublicKeyMaterial,
    pub status: RootStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub root_id: String,
    pub device_id: String,
    pub label: String,
    pub active_key: PublicKeyMaterial,
    pub active_encryption_key: PublicKeyMaterial,
    pub status: DeviceStatus,
    pub replacement_device_id: Option<String>,
    /// Key-custody class (ADR 200 §1). Devices added via `DeviceAdded` are
    /// `daemon`-class (the daemon holds their key); `presence`/`co-authority`
    /// devices arrive via `DeviceEnrolled` with a recorded attestation.
    pub custody_class: CustodyClass,
    /// Raw vendor/authority attestation statement proving the custody class,
    /// re-verifiable against the binary-embedded roots. `None` for `daemon`-class
    /// and for the `AttestationTier::None` dev0 floor.
    pub attestation_statement: Option<String>,
    /// The **claimed** attestation strength (ADR 200 §3, two-axis model). This is
    /// the recorded claim; authority decisions read the tier PROVEN by
    /// [`crate::verify_chain`] (which re-runs the statement), never this field
    /// blind — it is metadata for re-verification, not a trusted boolean.
    pub attestation_tier: AttestationTier,
    /// How the Device's use-time human-presence gate is enforced (ADR 200 §3,
    /// presence axis). `Unattended` for `daemon`/`co-authority` custody.
    pub presence_factor: PresenceFactor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaRecord {
    pub root_id: String,
    pub persona_id: String,
    pub label: String,
    pub disclosure_profile: Option<String>,
    pub survival_mode: SurvivalMode,
    pub active_key: PublicKeyMaterial,
    pub status: PersonaStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicyRecord {
    pub root_id: String,
    pub guardian_threshold: u8,
    pub cooldown_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianRecord {
    pub guardian_id: String,
    pub root_id: String,
    pub label: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequestRecord {
    pub request_id: String,
    pub root_id: String,
    pub target_device_id: String,
    pub approvals: BTreeSet<String>,
    pub contested_by: BTreeSet<String>,
    pub status: RecoveryRequestStatus,
    pub executed_scope: Option<RecoveryScope>,
    /// Epoch seconds until which execution is blocked. `None` means no cooldown.
    pub cooldown_until: Option<u64>,
    pub contest_reason: Option<String>,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeRecord {
    pub badge_id: String,
    pub issuer_persona_id: String,
    pub recipient_persona_id: String,
    pub badge_type: String,
    pub display_name: String,
    pub evidence: Option<core_event_types::BadgeEvidence>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub revoked_reason: Option<String>,
}

/// A dispute attestation targeting a specific badge (ADR 030 counter-attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadgeDisputeRecord {
    pub dispute_id: String,
    pub target_badge_id: String,
    pub disputer_persona_id: String,
    pub reason: String,
    pub evidence: Option<String>,
}

/// Status of a credential deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialDepositStatus {
    Active,
    Revoked,
}

/// A credential deposit record for materialized state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDepositRecord {
    pub deposit_id: String,
    pub grant_id: String,
    pub credential_id: String,
    pub issuer_id: String,
    pub encrypted_blocks_json: String,
    pub status: CredentialDepositStatus,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
}

/// A disclosure artifact record. Populated by the persona layer when a
/// disclosure is issued; used by authorize.rs for the L-3 revoker == issuer
/// cross-check (P79.1a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRecord {
    /// Unique artifact identifier (matches `DisclosureRevokedEvent.artifact_id`).
    pub artifact_id: String,
    /// The persona that originally issued this disclosure.
    pub issuer_persona_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantOfferStatus {
    Pending,
    Claimed,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOfferRecord {
    pub offer_id: String,
    pub issuer_persona_id: String,
    pub ephemeral_public_key_hex: String,
    pub sealed_payload_hex: String,
    pub relay_hint: Option<String>,
    pub expires_at: u64,
    /// JSON-encoded grant conditions. Empty string or `"[]"` = unconditional.
    pub conditions_json: String,
    pub status: GrantOfferStatus,
    /// Set when status transitions to `Claimed`.
    pub recipient_persona_id: Option<String>,
    pub claim_response_hex: Option<String>,
    pub claimed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MaterializedState {
    pub roots_current: BTreeMap<String, RootRecord>,
    pub devices_current: BTreeMap<String, DeviceRecord>,
    pub personas_current: BTreeMap<String, PersonaRecord>,
    pub trust_edges_current: BTreeMap<String, TrustAttestation>,
    pub derived_trust_current: BTreeMap<String, DerivedTrustStatement>,
    pub recovery_policies_current: BTreeMap<String, RecoveryPolicyRecord>,
    pub guardians_current: BTreeMap<String, GuardianRecord>,
    pub recovery_requests_current: BTreeMap<String, RecoveryRequestRecord>,
    pub storage_relationships_current: BTreeMap<String, StorageRelationship>,
    pub storage_balances_current: BTreeMap<String, StorageLedgerEntry>,
    pub endpoints_current: BTreeMap<String, EndpointDescriptor>,
    pub grant_offers_current: BTreeMap<String, GrantOfferRecord>,
    pub badges_current: BTreeMap<String, BadgeRecord>,
    pub badge_disputes_current: BTreeMap<String, BadgeDisputeRecord>,
    pub credential_deposits_current: BTreeMap<String, CredentialDepositRecord>,
    /// Disclosure artifacts indexed by `artifact_id`. Populated by the persona
    /// layer; used by `authorize.rs` for the L-3 revoker-==issuer cross-check.
    pub disclosures_current: BTreeMap<String, DisclosureRecord>,
    pub root_key_history: BTreeMap<String, Vec<String>>,
    pub device_key_history: BTreeMap<String, Vec<String>>,
    pub device_encryption_key_history: BTreeMap<String, Vec<String>>,
    pub persona_key_history: BTreeMap<String, Vec<String>>,
    /// Per-root chain head: maps root_id → (last_event_id, last_seq).
    /// `last_seq` is the sequence number of the most recently accepted event
    /// for that root. Used to enforce monotonic `prev_event_id` chaining.
    pub root_chain_heads: BTreeMap<String, (String, u64)>,
}

impl MaterializedState {
    pub fn root(&self, root_id: &str) -> Option<&RootRecord> {
        self.roots_current.get(root_id)
    }

    pub fn device(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices_current.get(device_id)
    }

    pub fn persona(&self, persona_id: &str) -> Option<&PersonaRecord> {
        self.personas_current.get(persona_id)
    }

    pub fn endpoint(&self, peer_id: &str) -> Option<&EndpointDescriptor> {
        self.endpoints_current.get(peer_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBatchRecord {
    pub batch_id: String,
    pub peer_id: String,
    pub last_event_id: Option<String>,
}
