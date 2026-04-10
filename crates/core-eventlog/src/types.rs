use std::collections::{BTreeMap, BTreeSet};

use core_types::{
    DerivedTrustStatement, EndpointDescriptor, PublicKeyMaterial, RecoveryScope, StorageLedgerEntry,
    StorageRelationship, SurvivalMode, TrustAttestation,
};

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
    pub root_key_history: BTreeMap<String, Vec<String>>,
    pub device_key_history: BTreeMap<String, Vec<String>>,
    pub device_encryption_key_history: BTreeMap<String, Vec<String>>,
    pub persona_key_history: BTreeMap<String, Vec<String>>,
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
