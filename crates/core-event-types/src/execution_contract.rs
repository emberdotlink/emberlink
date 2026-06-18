use serde::{Deserialize, Serialize};

use crate::ActionRef;

const EXECUTION_CONTRACT_SCHEMA_V1: &str = "execution_contract.v1";

fn default_schema_version() -> String {
    EXECUTION_CONTRACT_SCHEMA_V1.to_string()
}

/// Authority-side execution contract per ADR 183 / ADR 184.
///
/// Callers may construct this envelope before authority has minted a stable
/// `contract_id`; the authority side fills that field during resolve/approve
/// and then threads the contract forward to runner-local translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContract {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    pub action_ref: ActionRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Coordination-layer join handle supplied by an orchestrator such as
    /// Forge. Authority space echoes it into receipts but does not grant from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ref: Option<String>,
    #[serde(default)]
    pub materialization_policy: MaterializationPolicy,
    #[serde(default)]
    pub runner_policy: RunnerPolicy,
    #[serde(default)]
    pub topology_policy: TopologyPolicy,
    #[serde(default)]
    pub interaction_class: InteractionClass,
    #[serde(default)]
    pub lease_policy: LeasePolicy,
    #[serde(default)]
    pub audit_policy: AuditPolicy,
}

impl ExecutionContract {
    pub fn new(action_ref: ActionRef) -> Self {
        Self {
            schema_version: default_schema_version(),
            contract_id: None,
            action_ref,
            workspace_ref: None,
            subject_ref: None,
            coordination_ref: None,
            caller_ref: None,
            authority_ref: None,
            materialization_policy: MaterializationPolicy::default(),
            runner_policy: RunnerPolicy::default(),
            topology_policy: TopologyPolicy::default(),
            interaction_class: InteractionClass::default(),
            lease_policy: LeasePolicy::default(),
            audit_policy: AuditPolicy::default(),
        }
    }

    pub fn with_contract_id(mut self, contract_id: impl Into<String>) -> Self {
        self.contract_id = Some(contract_id.into());
        self
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != EXECUTION_CONTRACT_SCHEMA_V1 {
            return Err("schema_version must equal execution_contract.v1");
        }
        self.action_ref.validate()?;
        self.runner_policy.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationPolicy {
    #[serde(default)]
    pub exposure: MaterialExposure,
    #[serde(default)]
    pub revocation: RevocationStrategy,
}

impl Default for MaterializationPolicy {
    fn default() -> Self {
        Self {
            exposure: MaterialExposure::BrokeredEnv,
            revocation: RevocationStrategy::OnExit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaterialExposure {
    #[default]
    BrokeredEnv,
    BrokeredFile,
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStrategy {
    #[default]
    OnExit,
    OnRelease,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerPolicy {
    #[serde(default = "default_runner_classes")]
    pub allowed: Vec<RunnerClass>,
    #[serde(default = "default_runner_preferences")]
    pub preferred: Vec<RunnerClass>,
}

fn default_runner_classes() -> Vec<RunnerClass> {
    vec![RunnerClass::LocalTrusted]
}

fn default_runner_preferences() -> Vec<RunnerClass> {
    vec![RunnerClass::LocalTrusted]
}

impl Default for RunnerPolicy {
    fn default() -> Self {
        Self {
            allowed: default_runner_classes(),
            preferred: default_runner_preferences(),
        }
    }
}

impl RunnerPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.allowed.is_empty() {
            return Err("runner_policy.allowed must not be empty");
        }
        for class in &self.preferred {
            if !self.allowed.contains(class) {
                return Err("runner_policy.preferred must be a subset of runner_policy.allowed");
            }
        }
        if has_duplicate_runner_classes(&self.allowed) {
            return Err("runner_policy.allowed must not contain duplicates");
        }
        if has_duplicate_runner_classes(&self.preferred) {
            return Err("runner_policy.preferred must not contain duplicates");
        }
        Ok(())
    }
}

fn has_duplicate_runner_classes(classes: &[RunnerClass]) -> bool {
    let mut seen = Vec::with_capacity(classes.len());
    for class in classes {
        if seen.contains(class) {
            return true;
        }
        seen.push(*class);
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerClass {
    LocalTrusted,
    IsolatedLocal,
    InternalOnly,
    TeeRequired,
    VendorBound,
    CheapTrustless,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TopologyPolicy {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub preferred: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InteractionClass {
    #[default]
    InlineInteractive,
    SynchronousHeavy,
    AsynchronousBatch,
    LongRunningJob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePolicy {
    #[serde(default = "default_single_use")]
    pub single_use: bool,
}

fn default_single_use() -> bool {
    true
}

impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            single_use: default_single_use(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPolicy {
    #[serde(default = "default_receipt_required")]
    pub receipt_required: bool,
    #[serde(default = "default_audit_evidence")]
    pub evidence: Vec<String>,
}

fn default_receipt_required() -> bool {
    true
}

fn default_audit_evidence() -> Vec<String> {
    vec!["execution_receipt".to_string()]
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            receipt_required: default_receipt_required(),
            evidence: default_audit_evidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_contract_defaults_to_authority_side_safe_shape() {
        let contract = ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pull_requests.list",
            "v1",
        ));

        assert_eq!(contract.schema_version, EXECUTION_CONTRACT_SCHEMA_V1);
        assert_eq!(
            contract.runner_policy.allowed,
            vec![RunnerClass::LocalTrusted]
        );
        assert_eq!(
            contract.runner_policy.preferred,
            vec![RunnerClass::LocalTrusted]
        );
        assert_eq!(
            contract.materialization_policy.exposure,
            MaterialExposure::BrokeredEnv
        );
        assert_eq!(
            contract.materialization_policy.revocation,
            RevocationStrategy::OnExit
        );
        assert!(contract.audit_policy.receipt_required);
        assert!(contract.lease_policy.single_use);
        contract.validate().expect("contract should validate");
    }

    #[test]
    fn execution_contract_validate_refuses_empty_allowed_runner_policy() {
        let mut contract = ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pull_requests.list",
            "v1",
        ));
        contract.runner_policy.allowed.clear();

        let err = contract.validate().expect_err("runner policy must fail");
        assert_eq!(err, "runner_policy.allowed must not be empty");
    }

    #[test]
    fn execution_contract_validate_refuses_preferred_outside_allowed() {
        let mut contract = ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pull_requests.list",
            "v1",
        ));
        contract.runner_policy.allowed = vec![RunnerClass::LocalTrusted];
        contract.runner_policy.preferred = vec![RunnerClass::TeeRequired];

        let err = contract.validate().expect_err("runner policy must fail");
        assert_eq!(
            err,
            "runner_policy.preferred must be a subset of runner_policy.allowed"
        );
    }

    #[test]
    fn execution_contract_round_trips_coordination_ref() {
        let mut contract = ExecutionContract::new(ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pull_requests.list",
            "v1",
        ));
        contract.subject_ref = Some("forge:run:run-123".to_string());
        contract.coordination_ref = Some("forge:workflow_event:event-123".to_string());

        let value = serde_json::to_value(&contract).expect("serialize contract");
        assert_eq!(value["subject_ref"], "forge:run:run-123");
        assert_eq!(value["coordination_ref"], "forge:workflow_event:event-123");

        let round_trip: ExecutionContract =
            serde_json::from_value(value).expect("deserialize contract");
        assert_eq!(round_trip.subject_ref, contract.subject_ref);
        assert_eq!(round_trip.coordination_ref, contract.coordination_ref);
    }
}
