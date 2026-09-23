use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

pub const ACTION_REQUEST_SCHEMA: &str = "ember.action-request/v1";
pub const ACTION_REF_TEXT: &str =
    "packet-fixture.local/packet-fixture/diagnostic:authority_status:v2";
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRef {
    pub plugin_address: String,
    pub action_key: String,
    pub action_version: String,
}

impl ActionRef {
    pub fn diagnostic() -> Self {
        Self {
            plugin_address: "packet-fixture.local/packet-fixture/diagnostic".into(),
            action_key: "authority_status".into(),
            action_version: "v2".into(),
        }
    }

    pub fn parse(text: &str) -> Result<Self, Refusal> {
        (text == ACTION_REF_TEXT)
            .then(Self::diagnostic)
            .ok_or_else(|| Refusal::new("unknown_definition"))
    }

    pub fn identity(&self) -> String {
        format!("{}:{}", self.plugin_address, self.action_key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInput {
    pub challenge: String,
}

impl DiagnosticInput {
    pub fn validate(&self) -> Result<(), Refusal> {
        let count = self.challenge.chars().count();
        if !(1..=64).contains(&count) {
            return Err(Refusal::new("invalid_input"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticFacts {
    pub challenge: String,
    pub journal_health: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Need {
    pub need_item_id: String,
    pub permission: String,
    pub target: String,
    pub material_class: String,
    pub provider: String,
    pub protocol: String,
    pub destination: String,
    pub operation_class: String,
    pub request_count: u64,
    pub byte_count: u64,
    pub rate: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantUseCeiling {
    pub grant_use_id: String,
    pub need_item_id: String,
    pub request_count_ceiling: u64,
    pub byte_budget: u64,
    pub rate_ceiling: u64,
    pub remaining_use_ceiling: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantUse {
    pub grant_id: String,
    pub grant_use_id: String,
    pub delegation_id: String,
    pub session_id: String,
    pub target: String,
    pub permission: String,
    pub material_class: String,
    pub provider: String,
    pub protocol: String,
    pub destination: String,
    pub operation_class: String,
    pub request_count_ceiling: u64,
    pub byte_budget: u64,
    pub rate_ceiling: u64,
    pub remaining_uses: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

impl GrantUse {
    pub fn ceiling(&self, need_item_id: String) -> GrantUseCeiling {
        GrantUseCeiling {
            grant_use_id: self.grant_use_id.clone(),
            need_item_id,
            request_count_ceiling: self.request_count_ceiling,
            byte_budget: self.byte_budget,
            rate_ceiling: self.rate_ceiling,
            remaining_use_ceiling: self.remaining_uses,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    NotApplicable,
    Unqualified,
    Provisional,
    Qualified,
    Disqualified,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationAxis {
    pub state: CoverageState,
    pub record_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCoverage {
    pub actor_lane: QualificationAxis,
    pub credential_lane: QualificationAxis,
    pub federation: QualificationAxis,
    pub production_cluster: QualificationAxis,
}

impl QualificationCoverage {
    pub fn diagnostic() -> Self {
        let absent = || QualificationAxis {
            state: CoverageState::NotApplicable,
            record_digest: None,
        };
        Self {
            actor_lane: absent(),
            credential_lane: absent(),
            federation: absent(),
            production_cluster: absent(),
        }
    }

    pub fn validate_diagnostic(&self) -> Result<(), Refusal> {
        let valid = [
            &self.actor_lane,
            &self.credential_lane,
            &self.federation,
            &self.production_cluster,
        ]
        .into_iter()
        .all(|axis| axis.state == CoverageState::NotApplicable && axis.record_digest.is_none());
        if valid {
            Ok(())
        } else {
            Err(Refusal::new("qualification_mismatch"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub session_id: String,
    pub persona_id: String,
    pub execution_binding_digest: String,
    pub expected_uid: u32,
    pub expected_pid: Option<u32>,
    pub expected_pid_version: Option<u64>,
    pub challenge: String,
    pub grant: GrantUse,
    pub endpoint: String,
    pub state: SessionState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Opening,
    Active,
    Closing,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchContext {
    pub project_root: String,
    pub worktree: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub schema: String,
    pub submission_id: String,
    pub action_ref: ActionRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_digest: Option<String>,
    pub input: DiagnosticInput,
}

impl ActionRequest {
    pub fn required_definition_digest(&self) -> Result<&str, Refusal> {
        self.definition_digest
            .as_deref()
            .filter(|digest| !digest.is_empty())
            .ok_or_else(|| Refusal::new("definition_digest_required"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPermit {
    pub permit_kind: String,
    pub authority_fingerprint: String,
    pub authority_epoch: u64,
    pub installation_id: String,
    pub proxy_instance_id: Option<String>,
    pub session_id: String,
    pub operation_id: Option<String>,
    pub execution_ordinal_first: Option<u64>,
    pub execution_ordinal_count: Option<u64>,
    pub execution_binding_digest: String,
    pub assurance_profile_id: String,
    pub assurance_profile_digest: String,
    pub qualification_coverage_digest: String,
    pub action_definition_id: String,
    pub action_definition_version: String,
    pub action_definition_digest: String,
    pub canonicalizer_id: String,
    pub canonicalizer_digest: String,
    pub canonical_typed_input_digest: String,
    pub need_item_id_list: Vec<String>,
    pub grant_use_id_and_ceiling_list: Vec<GrantUseCeiling>,
    pub credential_slot: Option<String>,
    pub credential_revision: Option<u64>,
    pub execution_lane: String,
    pub recipient_key_fingerprint: Option<String>,
    pub provider_route_id: Option<String>,
    pub route_qualification_version: Option<u64>,
    pub release_manifest_digest: Option<String>,
    pub profile_artifact_digest: Option<String>,
    pub target: String,
    pub protocol: String,
    pub destination: String,
    pub operation_class: String,
    pub request_count_ceiling: u64,
    pub byte_budget: u64,
    pub rate_ceiling: u64,
    pub remaining_use_ceiling: u64,
    pub expiry: u64,
    pub offline_bound: bool,
    pub consequence_class: String,
    pub capability: String,
    pub nonce: String,
    pub issuance: u64,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Success,
    ExecutionFailure,
    EffectUnknown,
    CancelledBeforeEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationSnapshot {
    pub permit: ActionPermit,
    pub persona_id: String,
    pub delegation_id: String,
    pub grant_id: String,
    pub need: Need,
    pub grant_use: GrantUse,
    pub registry_sequence: u64,
    pub definition_resolved_at: u64,
    pub qualification_coverage: QualificationCoverage,
    pub canonical_request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub operation_id: String,
    pub operation_key: String,
    pub submission_binding_key: String,
    pub submission_id: String,
    pub session_id: String,
    pub execution_binding_digest: String,
    pub action_ref: ActionRef,
    pub definition_digest: String,
    pub typed_input_digest: String,
    pub authorization: AuthorizationSnapshot,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub status: OperationStatus,
    pub facts: Option<DiagnosticFacts>,
    pub receipt_id: Option<String>,
    pub failure_code: Option<String>,
    pub cleanup_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionBinding {
    pub canonical_request_digest: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIndexRow {
    pub receipt_id: String,
    pub operation_id: String,
    pub action_ref: ActionRef,
    pub definition_digest: String,
    pub terminal_status: OperationStatus,
    pub started_at: u64,
    pub completed_at: u64,
    pub signed_receipt_digest: String,
    pub terminal_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredReceipt {
    pub row: ReceiptIndexRow,
    pub canonical_bytes: String,
    pub fact_digests: Vec<String>,
    pub checkpoint_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResponse {
    pub action_ref: ActionRef,
    pub definition_digest: String,
    pub facts: DiagnosticFacts,
    pub operation_id: String,
    pub receipt_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializationRecord {
    pub operation_id: String,
    pub root_intent_digest: String,
    pub release_manifest_digest: String,
    pub release_qualification_digest: String,
    pub continuity_digest: String,
    pub initialized_at: u64,
    pub receipt_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentAuthorityState {
    pub schema: String,
    pub generation: u64,
    pub authority_fingerprint: String,
    pub authority_epoch: u64,
    pub installation_id: String,
    pub release_manifest_digest: String,
    /// Digest of the reviewed `emberd` bootstrap artifact. Clients authenticate
    /// the control endpoint's serving process against this value, so a
    /// same-UID impostor socket cannot masquerade as the installed authority.
    pub daemon_executable_digest: String,
    pub operator_uid: u32,
    pub initialized_at: u64,
    pub registry_bytes: String,
    pub registry_sequence: u64,
    pub qualification_coverage: QualificationCoverage,
    pub initialization: InitializationRecord,
    pub qualification_grant: crate::initialization::QualificationGrantRecord,
    pub caller_eligibility: crate::initialization::CallerEligibilityRecord,
    pub harness_profile_authorization: crate::initialization::HarnessProfileAuthorization,
    pub trusted_project: crate::initialization::TrustedProjectAuthorization,
    pub route: crate::initialization::RouteAuthorization,
    pub devices: crate::device::DeviceState,
    pub sessions: BTreeMap<String, SessionRecord>,
    pub submissions: BTreeMap<String, SubmissionBinding>,
    pub operations: BTreeMap<String, OperationRecord>,
    pub receipts: BTreeMap<String, StoredReceipt>,
    pub used_permit_nonces: BTreeMap<String, String>,
    pub sequence: u64,
    pub checkpoint_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refusal {
    pub code: &'static str,
}

impl Refusal {
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for Refusal {}
