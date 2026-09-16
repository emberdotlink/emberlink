use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const ACTION_REQUEST_SCHEMA: &str = "ember.action-request/v1";
pub const OPERATION_RESULT_SCHEMA: &str = "ember.operation-result/v1";

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub(crate) String);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

opaque_id!(OperationId);
opaque_id!(PersonaId);
opaque_id!(GrantId);
opaque_id!(SessionId);
opaque_id!(DelegationId);
opaque_id!(ProcessBindingId);
opaque_id!(ProviderInstanceId);
opaque_id!(ProviderGeneration);
opaque_id!(MaterializationId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub schema: String,
    pub pack: PackRef,
    pub action: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_id: Option<SubmissionId>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRef {
    pub address: String,
    pub version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRefPublicationInput {
    pub repository: RepositoryResource,
    pub artifact: ArtifactRef,
    pub expected_old_oid: GitOid,
    pub new_oid: GitOid,
    pub destination_ref: GitRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPullRequestCreateInput {
    pub repository: RepositoryResource,
    pub head_ref: GitRef,
    pub base_ref: GitRef,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRepositoryFactsInput {
    pub repository: RepositoryResource,
    pub head_ref: GitRef,
    pub base_ref: GitRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum ActionFacts {
    #[serde(rename = "ember.github.pull-request-created/v1")]
    GithubPullRequestCreated {
        repository: RepositoryResource,
        number: u64,
        html_url: String,
        head_ref: GitRef,
        base_ref: GitRef,
    },
    #[serde(rename = "ember.github.repository-facts/v1")]
    GithubRepositoryFacts {
        repository: RepositoryResource,
        repository_head: GitOid,
        fork_heads: Vec<GithubForkHeadFact>,
        prs: Vec<GithubPullRequestFact>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubForkHeadFact {
    pub number: u64,
    pub repository: RepositoryResource,
    pub base_ref: GitRef,
    pub head_ref: GitRef,
    pub head_sha: GitOid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPullRequestFact {
    pub number: u64,
    pub state: String,
    pub merge_sha: Option<GitOid>,
    pub base_ref: GitRef,
    pub head_ref: GitRef,
    pub head_sha: GitOid,
    pub changed_files_count: u64,
    pub changed_files: Vec<String>,
    pub checks: Vec<GithubCheckFact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubCheckFact {
    pub database_id: u64,
    pub name: String,
    pub head_sha: GitOid,
    pub status: String,
    pub conclusion: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RepositoryResource(String);

impl RepositoryResource {
    pub fn owner(&self) -> &str {
        self.0
            .strip_prefix("github:")
            .and_then(|value| value.split_once('/'))
            .map(|(owner, _)| owner)
            .expect("validated repository resource")
    }

    pub fn repository(&self) -> &str {
        self.0
            .strip_prefix("github:")
            .and_then(|value| value.split_once('/'))
            .map(|(_, repository)| repository)
            .expect("validated repository resource")
    }

    pub fn full_name(&self) -> &str {
        self.0
            .strip_prefix("github:")
            .expect("validated repository resource")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepositoryResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RepositoryResource {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let full_name = value
            .strip_prefix("github:")
            .ok_or(ModelError::InvalidRepositoryResource)?;
        let (owner, repository) = full_name
            .split_once('/')
            .ok_or(ModelError::InvalidRepositoryResource)?;
        if repository.contains('/')
            || owner.is_empty()
            || repository.is_empty()
            || owner.len() > 39
            || repository.len() > 100
            || repository.ends_with(".git")
            || !owner.bytes().all(is_repository_byte)
            || !repository.bytes().all(is_repository_byte)
        {
            return Err(ModelError::InvalidRepositoryResource);
        }
        Ok(Self(format!(
            "github:{}/{}",
            owner.to_ascii_lowercase(),
            repository.to_ascii_lowercase()
        )))
    }
}

impl<'de> Deserialize<'de> for RepositoryResource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn is_repository_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.')
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactRef(String);

impl ArtifactRef {
    pub fn from_digest(digest: &[u8; 32]) -> Self {
        Self(format!("artifact:sha256:{}", hex::encode(digest)))
    }

    pub fn digest_hex(&self) -> &str {
        self.0
            .strip_prefix("artifact:sha256:")
            .expect("validated artifact reference")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ArtifactRef {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let digest = value
            .strip_prefix("artifact:sha256:")
            .ok_or(ModelError::InvalidArtifactRef)?;
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ModelError::InvalidArtifactRef);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ArtifactRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GitOid(String);

impl GitOid {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.bytes().all(|byte| byte == b'0')
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GitOid {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !matches!(value.len(), 40 | 64)
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ModelError::InvalidGitOid);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for GitOid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GitRef(String);

impl GitRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GitRef {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !(value.starts_with("refs/heads/") || value.starts_with("refs/tags/"))
            || value.len() > 255
            || value.ends_with('/')
            || value.ends_with('.')
            || value.contains("..")
            || value.contains("@{")
            || value.contains("//")
            || value.bytes().any(|byte| {
                byte <= b' '
                    || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' | 0x7f)
            })
        {
            return Err(ModelError::InvalidGitRef);
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for GitRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Need {
    pub provider: String,
    pub repository: RepositoryResource,
    pub destination_ref: Option<GitRef>,
    pub permissions: BTreeMap<String, PermissionLevel>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalStatus {
    Success,
    ExecutionFailure,
    Refusal,
    CompletedButUnsettled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_digest: Option<String>,
    pub stderr_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvidence {
    pub provider_instance: ProviderInstanceId,
    pub generation: ProviderGeneration,
    pub app_slug: String,
    pub app_id: u64,
    pub installation_id: u64,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, PermissionLevel>,
    pub expires_at_unix: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerEvidence {
    pub adapter: String,
    pub executable_digest_sha256: Option<String>,
    pub credential_helper_digest_sha256: Option<String>,
    pub artifact_digest_sha256: Option<String>,
    pub process: Option<ProcessOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_peer_served_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_peer_rejected_count: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCommitment {
    pub first_hash: String,
    pub last_hash: String,
    pub fact_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalFact {
    pub operation_id: OperationId,
    pub sequence: u64,
    pub at_unix: i64,
    pub kind: String,
    pub data: Value,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("repository resource must be canonical github:owner/repository")]
    InvalidRepositoryResource,
    #[error("artifact reference is invalid")]
    InvalidArtifactRef,
    #[error("Git object ID must be lowercase hexadecimal SHA-1 or SHA-256")]
    InvalidGitOid,
    #[error("destination must be a canonical heads or tags ref")]
    InvalidGitRef,
    #[error("operation result schema is invalid")]
    InvalidOperationResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_repository_resource_without_accepting_urls() {
        let resource = "github:EmberDotLink/Ember"
            .parse::<RepositoryResource>()
            .unwrap();
        assert_eq!(resource.as_str(), "github:emberdotlink/ember");
        assert!(
            "https://github.com/emberdotlink/ember"
                .parse::<RepositoryResource>()
                .is_err()
        );
        assert!(
            "github:emberdotlink/ember.git"
                .parse::<RepositoryResource>()
                .is_err()
        );
    }

    #[test]
    fn artifact_references_reject_noncanonical_prefix_length_case_and_hex() {
        for value in [
            format!("sha256:{}", "a".repeat(64)),
            format!("artifact:sha512:{}", "a".repeat(64)),
            format!("artifact:sha256:{}", "a".repeat(63)),
            format!("artifact:sha256:{}", "a".repeat(65)),
            format!("artifact:sha256:A{}", "a".repeat(63)),
            format!("artifact:sha256:g{}", "a".repeat(63)),
        ] {
            assert!(
                matches!(
                    value.parse::<ArtifactRef>(),
                    Err(ModelError::InvalidArtifactRef)
                ),
                "{value} was accepted"
            );
        }
    }

    #[test]
    fn git_oids_reject_invalid_length_case_and_hex() {
        for value in [
            "a".repeat(39),
            "a".repeat(41),
            "a".repeat(63),
            "a".repeat(65),
            format!("sha1:{}", "a".repeat(35)),
            format!("A{}", "a".repeat(39)),
            format!("G{}", "a".repeat(39)),
            format!("A{}", "a".repeat(63)),
            format!("g{}", "a".repeat(39)),
            format!("g{}", "a".repeat(63)),
        ] {
            assert!(
                matches!(value.parse::<GitOid>(), Err(ModelError::InvalidGitOid)),
                "{value} was accepted"
            );
        }
    }

    #[test]
    fn runner_peer_counts_are_optional_on_legacy_evidence() {
        let legacy = serde_json::json!({
            "adapter": "git.publish-ref/v1",
            "executable_digest_sha256": null,
            "credential_helper_digest_sha256": null,
            "artifact_digest_sha256": null,
            "process": null,
        });

        let evidence: RunnerEvidence = serde_json::from_value(legacy.clone()).unwrap();

        assert_eq!(evidence.credential_peer_served_count, None);
        assert_eq!(evidence.credential_peer_rejected_count, None);
        assert_eq!(serde_json::to_value(evidence).unwrap(), legacy);
    }

    #[test]
    fn rejects_git_ref_grammar_hazards() {
        assert!("refs/heads/role/workstream".parse::<GitRef>().is_ok());
        for value in [
            "main",
            "refs/heads/../../main",
            "refs/heads/a:b",
            "refs/heads/a@{b",
            "refs/heads/a//b",
            "refs/remotes/origin/main",
        ] {
            assert!(value.parse::<GitRef>().is_err(), "{value}");
        }
    }

    #[test]
    fn request_wire_rejects_authority_and_execution_mirror_fields() {
        for field in [
            "binary",
            "cwd",
            "socket",
            "uid",
            "gid",
            "provider_instance",
            "scope",
            "permissions",
            "environment",
            "artifact_path",
        ] {
            let mut value = serde_json::json!({
                "schema": ACTION_REQUEST_SCHEMA,
                "pack": {"address": "ember.pack/github", "version": 1},
                "action": "git.publish-ref/v1",
                "input": {}
            });
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!("attacker"));
            assert!(
                serde_json::from_value::<ActionRequest>(value).is_err(),
                "{field} was accepted"
            );
        }
    }
}

/// Caller-supplied idempotency identity. It is independent of transport
/// sessions and binds exactly one canonical request digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SubmissionId([u8; 32]);

impl SubmissionId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the exact RFC 8785 request bytes bound to a submission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn of(canonical_request: &[u8]) -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::digest(canonical_request).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvidenceId([u8; 32]);
impl EvidenceId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityObjectId([u8; 32]);
impl AuthorityObjectId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Position in the single monotonic authority journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JournalSequence(std::num::NonZeroU64);
impl JournalSequence {
    pub const fn new(value: u64) -> Option<Self> {
        match std::num::NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
/// Version of the deterministic rules used to rebuild a projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProjectionVersion(std::num::NonZeroU32);
impl ProjectionVersion {
    pub const V1: Self = Self(std::num::NonZeroU32::MIN);
    pub const fn new(value: u32) -> Option<Self> {
        match std::num::NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// The complete public semantic role set for authority evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceRole {
    AuthorityReceipt,
    AuditFact,
    AuthorityRollup,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventClassification {
    Evidence(EvidenceRole),
    DerivedNoRecord,
    NoRecordUntilObserved,
}

/// Closed event vocabulary; adding an event requires an exhaustive
/// classification decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EventKind {
    GrantIssued = 0,
    GrantWidened = 1,
    GrantRenewed = 2,
    DelegationCreated = 3,
    GrantRevoked = 4,
    DelegationRevoked = 5,
    DescendantInvalidated = 6,
    AuthorityExpiryElapsed = 7,
    AuthorityExpiryObserved = 8,
    SessionCreated = 9,
    SessionEnded = 10,
    PresenceIntentIssued = 11,
    OrphanPresenceIntentDiscarded = 12,
    CustodyUnlockBegan = 13,
    CustodyUnlockCompleted = 14,
    ControlRequestAttempted = 15,
    ControlRequestDecided = 16,
    OperationAdmitted = 17,
    ActionResolved = 18,
    PackResolved = 19,
    ArtifactVerified = 20,
    CredentialMaterialized = 21,
    CredentialBorrowed = 22,
    RunnerExecutionOutcome = 23,
    ProviderSettlement = 24,
    UpstreamRevocation = 25,
    StartupRecoverySettlement = 26,
    OperationTerminal = 27,
    IdempotentReplay = 28,
    SubmissionConflict = 29,
    JournalDegraded = 30,
    FailStopEntered = 31,
    OperationAuthorityRevoked = 32,
    OperatorRollupView = 33,
    CredentialEnrolled = 34,
    CredentialRotated = 35,
    CredentialDeleted = 36,
    CredentialEnrollPresenceRefused = 37,
    CredentialEnrollOccupied = 38,
    CredentialEnrollReplayRefused = 39,
    CredentialRotatePresenceRefused = 40,
    CredentialRotateEmpty = 41,
    CredentialRotateMismatch = 42,
    CredentialRotateReplayRefused = 43,
    CredentialDeletePresenceRefused = 44,
    CredentialDeleteEmpty = 45,
    CredentialDeleteMismatch = 46,
    CredentialDeleteReplayRefused = 47,
}

impl EventKind {
    pub const fn classification(self) -> EventClassification {
        use EventClassification::{DerivedNoRecord, Evidence, NoRecordUntilObserved};
        use EvidenceRole::{AuditFact, AuthorityReceipt, AuthorityRollup};
        match self {
            Self::GrantIssued
            | Self::GrantWidened
            | Self::GrantRenewed
            | Self::DelegationCreated
            | Self::GrantRevoked
            | Self::DelegationRevoked
            | Self::CredentialEnrolled
            | Self::CredentialRotated
            | Self::CredentialDeleted => Evidence(AuthorityReceipt),
            Self::DescendantInvalidated => DerivedNoRecord,
            Self::AuthorityExpiryElapsed => NoRecordUntilObserved,
            Self::OperatorRollupView => Evidence(AuthorityRollup),
            Self::AuthorityExpiryObserved
            | Self::SessionCreated
            | Self::SessionEnded
            | Self::PresenceIntentIssued
            | Self::OrphanPresenceIntentDiscarded
            | Self::CustodyUnlockBegan
            | Self::CustodyUnlockCompleted
            | Self::ControlRequestAttempted
            | Self::ControlRequestDecided
            | Self::OperationAdmitted
            | Self::ActionResolved
            | Self::PackResolved
            | Self::ArtifactVerified
            | Self::CredentialMaterialized
            | Self::CredentialBorrowed
            | Self::RunnerExecutionOutcome
            | Self::ProviderSettlement
            | Self::UpstreamRevocation
            | Self::StartupRecoverySettlement
            | Self::OperationTerminal
            | Self::IdempotentReplay
            | Self::SubmissionConflict
            | Self::JournalDegraded
            | Self::FailStopEntered
            | Self::OperationAuthorityRevoked
            | Self::CredentialEnrollPresenceRefused
            | Self::CredentialEnrollOccupied
            | Self::CredentialEnrollReplayRefused
            | Self::CredentialRotatePresenceRefused
            | Self::CredentialRotateEmpty
            | Self::CredentialRotateMismatch
            | Self::CredentialRotateReplayRefused
            | Self::CredentialDeletePresenceRefused
            | Self::CredentialDeleteEmpty
            | Self::CredentialDeleteMismatch
            | Self::CredentialDeleteReplayRefused => Evidence(AuditFact),
        }
    }
    pub const fn requires_operation(self) -> bool {
        matches!(
            self,
            Self::OperationAdmitted
                | Self::ActionResolved
                | Self::PackResolved
                | Self::ArtifactVerified
                | Self::CredentialMaterialized
                | Self::CredentialBorrowed
                | Self::RunnerExecutionOutcome
                | Self::ProviderSettlement
                | Self::UpstreamRevocation
                | Self::StartupRecoverySettlement
                | Self::OperationTerminal
                | Self::IdempotentReplay
                | Self::SubmissionConflict
                | Self::OperationAuthorityRevoked
        )
    }
    pub const fn requires_materialization(self) -> bool {
        matches!(
            self,
            Self::CredentialMaterialized
                | Self::CredentialBorrowed
                | Self::ProviderSettlement
                | Self::UpstreamRevocation
                | Self::StartupRecoverySettlement
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityTransitionKind {
    GrantIssue = 0,
    GrantWiden = 1,
    GrantRenew = 2,
    DelegationCreate = 3,
    GrantRevoke = 4,
    DelegationRevoke = 5,
    CredentialEnroll = 6,
    CredentialRotate = 7,
    CredentialDelete = 8,
}

impl AuthorityTransitionKind {
    pub const fn event_kind(self) -> EventKind {
        match self {
            Self::GrantIssue => EventKind::GrantIssued,
            Self::GrantWiden => EventKind::GrantWidened,
            Self::GrantRenew => EventKind::GrantRenewed,
            Self::DelegationCreate => EventKind::DelegationCreated,
            Self::GrantRevoke => EventKind::GrantRevoked,
            Self::DelegationRevoke => EventKind::DelegationRevoked,
            Self::CredentialEnroll => EventKind::CredentialEnrolled,
            Self::CredentialRotate => EventKind::CredentialRotated,
            Self::CredentialDelete => EventKind::CredentialDeleted,
        }
    }
    pub const fn signature_domain(self) -> crate::identity::SignatureDomain {
        match self {
            Self::GrantRevoke | Self::DelegationRevoke => {
                crate::identity::SignatureDomain::OperationalDeescalation
            }
            Self::GrantIssue
            | Self::GrantWiden
            | Self::GrantRenew
            | Self::DelegationCreate
            | Self::CredentialEnroll
            | Self::CredentialRotate
            | Self::CredentialDelete => crate::identity::SignatureDomain::AuthorityTransition,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityReceiptBody {
    evidence_id: EvidenceId,
    sequence: JournalSequence,
    authority_object_id: AuthorityObjectId,
    transition: AuthorityTransitionKind,
}

impl AuthorityReceiptBody {
    pub const fn new(
        evidence_id: EvidenceId,
        sequence: JournalSequence,
        authority_object_id: AuthorityObjectId,
        transition: AuthorityTransitionKind,
    ) -> Self {
        Self {
            evidence_id,
            sequence,
            authority_object_id,
            transition,
        }
    }

    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    pub const fn authority_object_id(&self) -> AuthorityObjectId {
        self.authority_object_id
    }

    pub const fn transition(&self) -> AuthorityTransitionKind {
        self.transition
    }
}

/// Root-verifiable evidence for one committed authority transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityReceipt {
    body: AuthorityReceiptBody,
    signature: crate::identity::EvidenceSignature,
}

impl AuthorityReceipt {
    pub(crate) const fn from_signed(
        body: AuthorityReceiptBody,
        signature: crate::identity::EvidenceSignature,
    ) -> Self {
        Self { body, signature }
    }

    pub const fn body(&self) -> &AuthorityReceiptBody {
        &self.body
    }

    pub const fn signature(&self) -> &crate::identity::EvidenceSignature {
        &self.signature
    }
}

/// Causal identity retained by operation-linked audit facts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationEvidenceRef {
    operation_id: OperationId,
    materialization_id: Option<MaterializationId>,
}

impl OperationEvidenceRef {
    pub const fn operation(operation_id: OperationId) -> Self {
        Self {
            operation_id,
            materialization_id: None,
        }
    }

    pub const fn materialization(
        operation_id: OperationId,
        materialization_id: MaterializationId,
    ) -> Self {
        Self {
            operation_id,
            materialization_id: Some(materialization_id),
        }
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn materialization_id(&self) -> Option<&MaterializationId> {
        self.materialization_id.as_ref()
    }
}

/// Daemon-witnessed evidence of an observation or use.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuditFact {
    evidence_id: EvidenceId,
    sequence: JournalSequence,
    event: EventKind,
    operation: Option<OperationEvidenceRef>,
}

impl AuditFact {
    pub fn new(
        evidence_id: EvidenceId,
        sequence: JournalSequence,
        event: EventKind,
        operation: Option<OperationEvidenceRef>,
    ) -> Result<Self, AuditFactError> {
        if event.classification() != EventClassification::Evidence(EvidenceRole::AuditFact) {
            return Err(AuditFactError::WrongEvidenceRole);
        }
        if event.requires_materialization()
            && operation
                .as_ref()
                .and_then(OperationEvidenceRef::materialization_id)
                .is_none()
        {
            return Err(AuditFactError::MissingMaterializationIdentity);
        }
        if event.requires_operation() && operation.is_none() {
            return Err(AuditFactError::MissingOperationIdentity);
        }
        if !event.requires_operation() && operation.is_some() {
            return Err(AuditFactError::UnexpectedOperationIdentity);
        }
        Ok(Self {
            evidence_id,
            sequence,
            event,
            operation,
        })
    }

    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    pub const fn event(&self) -> EventKind {
        self.event
    }

    pub const fn operation(&self) -> Option<&OperationEvidenceRef> {
        self.operation.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AuditFactError {
    #[error("event does not classify as AuditFact")]
    WrongEvidenceRole,
    #[error("operation-linked fact is missing its operation identity")]
    MissingOperationIdentity,
    #[error("fact requires the original materialization identity")]
    MissingMaterializationIdentity,
    #[error("system fact cannot carry an operation identity")]
    UnexpectedOperationIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionBoundary {
    CancelledBeforeEffect,
    EffectCompleted { succeeded: bool },
    EffectUnknown,
}

/// Immutable statement of what Ember durably knew at the action boundary.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOutcome {
    operation_id: OperationId,
    submission_id: SubmissionId,
    request_digest: RequestDigest,
    sequence: JournalSequence,
    materialization_id: Option<MaterializationId>,
    boundary: ActionBoundary,
}

impl OperationOutcome {
    pub const fn new(
        operation_id: OperationId,
        submission_id: SubmissionId,
        request_digest: RequestDigest,
        sequence: JournalSequence,
        materialization_id: Option<MaterializationId>,
        boundary: ActionBoundary,
    ) -> Self {
        Self {
            operation_id,
            submission_id,
            request_digest,
            sequence,
            materialization_id,
            boundary,
        }
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn submission_id(&self) -> SubmissionId {
        self.submission_id
    }

    pub const fn request_digest(&self) -> RequestDigest {
        self.request_digest
    }

    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    pub fn materialization_id(&self) -> Option<&MaterializationId> {
        self.materialization_id.as_ref()
    }

    pub const fn boundary(&self) -> ActionBoundary {
        self.boundary
    }
}

/// Non-evidence transport and persistence record for one terminal operation.
///
/// The enclosed [`OperationOutcome`] is immutable. The remaining fields report
/// execution metadata and are not authority evidence or an admission input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResult {
    pub schema: String,
    pub outcome: OperationOutcome,
    pub persona_id: PersonaId,
    pub session_id: SessionId,
    pub process_binding_id: ProcessBindingId,
    pub grant_id: Option<GrantId>,
    pub delegation_path: Vec<DelegationId>,
    pub status: TerminalStatus,
    pub action: Option<String>,
    pub approved_input: Option<Value>,
    pub resource: Option<RepositoryResource>,
    pub need: Option<Need>,
    pub provider: Option<ProviderEvidence>,
    pub runner: Option<RunnerEvidence>,
    pub facts: Option<ActionFacts>,
    pub upstream_revoked: bool,
    pub audit: AuditCommitment,
    pub started_at_unix: i64,
    pub completed_at_unix: i64,
    pub message: String,
}

impl OperationResult {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema != OPERATION_RESULT_SCHEMA {
            return Err(ModelError::InvalidOperationResult);
        }
        Ok(())
    }
}

/// Current settlement projection for an immutable operation outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SettlementState {
    NotRequired,
    Pending,
    RecoveryPending,
    Settled,
}

/// Explicit derived view of an immutable operation outcome. E1 constructs the
/// vocabulary from already-derived fields; E2 owns evidence projection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationView {
    operation_id: OperationId,
    outcome_sequence: JournalSequence,
    through_sequence: JournalSequence,
    projection_version: ProjectionVersion,
    settlement: SettlementState,
    authority_revoked_after_boundary: bool,
}

impl OperationView {
    pub fn initial(outcome: &OperationOutcome) -> Self {
        Self {
            operation_id: outcome.operation_id.clone(),
            outcome_sequence: outcome.sequence,
            through_sequence: outcome.sequence,
            projection_version: ProjectionVersion::V1,
            settlement: match outcome.boundary {
                ActionBoundary::CancelledBeforeEffect => SettlementState::NotRequired,
                ActionBoundary::EffectCompleted { .. } => SettlementState::Pending,
                ActionBoundary::EffectUnknown => SettlementState::RecoveryPending,
            },
            authority_revoked_after_boundary: false,
        }
    }

    pub fn from_derived_fields(
        outcome: &OperationOutcome,
        through_sequence: JournalSequence,
        projection_version: ProjectionVersion,
        settlement: SettlementState,
        authority_revoked_after_boundary: bool,
    ) -> Option<Self> {
        if through_sequence < outcome.sequence {
            return None;
        }
        Some(Self {
            operation_id: outcome.operation_id.clone(),
            outcome_sequence: outcome.sequence,
            through_sequence,
            projection_version,
            settlement,
            authority_revoked_after_boundary,
        })
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub const fn outcome_sequence(&self) -> JournalSequence {
        self.outcome_sequence
    }

    pub const fn through_sequence(&self) -> JournalSequence {
        self.through_sequence
    }

    pub const fn projection_version(&self) -> ProjectionVersion {
        self.projection_version
    }

    pub const fn settlement(&self) -> SettlementState {
        self.settlement
    }

    pub const fn authority_revoked_after_boundary(&self) -> bool {
        self.authority_revoked_after_boundary
    }
}

/// Existing durable binding for one caller-supplied submission identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionBinding {
    submission_id: SubmissionId,
    request_digest: RequestDigest,
    operation_id: OperationId,
}

impl SubmissionBinding {
    pub const fn new(
        submission_id: SubmissionId,
        request_digest: RequestDigest,
        operation_id: OperationId,
    ) -> Self {
        Self {
            submission_id,
            request_digest,
            operation_id,
        }
    }

    pub const fn submission_id(&self) -> SubmissionId {
        self.submission_id
    }

    pub const fn request_digest(&self) -> RequestDigest {
        self.request_digest
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionResolution {
    Admit,
    Existing(OperationId),
    Conflict { existing_operation_id: OperationId },
}

pub fn resolve_submission(
    submission_id: SubmissionId,
    request_digest: RequestDigest,
    existing: Option<&SubmissionBinding>,
) -> SubmissionResolution {
    let Some(existing) = existing else {
        return SubmissionResolution::Admit;
    };
    if existing.submission_id != submission_id {
        return SubmissionResolution::Conflict {
            existing_operation_id: existing.operation_id.clone(),
        };
    }
    if existing.request_digest == request_digest {
        SubmissionResolution::Existing(existing.operation_id.clone())
    } else {
        SubmissionResolution::Conflict {
            existing_operation_id: existing.operation_id.clone(),
        }
    }
}

/// Deterministic rebuildable projection; never primary evidence or an
/// admission input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityRollup {
    projection_version: ProjectionVersion,
    through_sequence: JournalSequence,
    authority_receipt_count: u64,
    audit_fact_count: u64,
    primary_evidence_digest: [u8; 32],
}

impl AuthorityRollup {
    pub const fn new(
        projection_version: ProjectionVersion,
        through_sequence: JournalSequence,
        authority_receipt_count: u64,
        audit_fact_count: u64,
        primary_evidence_digest: [u8; 32],
    ) -> Self {
        Self {
            projection_version,
            through_sequence,
            authority_receipt_count,
            audit_fact_count,
            primary_evidence_digest,
        }
    }
    pub const fn projection_version(&self) -> ProjectionVersion {
        self.projection_version
    }
    pub const fn through_sequence(&self) -> JournalSequence {
        self.through_sequence
    }
    pub const fn authority_receipt_count(&self) -> u64 {
        self.authority_receipt_count
    }
    pub const fn audit_fact_count(&self) -> u64 {
        self.audit_fact_count
    }
    pub const fn primary_evidence_digest(&self) -> &[u8; 32] {
        &self.primary_evidence_digest
    }
}

#[cfg(test)]
mod e1_tests {
    use super::*;

    fn sequence(value: u64) -> JournalSequence {
        JournalSequence::new(value).unwrap()
    }

    #[test]
    fn event_roles_are_closed_and_exhaustively_classified() {
        fn role(role: EvidenceRole) -> u8 {
            match role {
                EvidenceRole::AuthorityReceipt => 1,
                EvidenceRole::AuditFact => 2,
                EvidenceRole::AuthorityRollup => 3,
            }
        }
        fn classification(kind: EventKind) -> EventClassification {
            match kind {
                EventKind::GrantIssued
                | EventKind::GrantWidened
                | EventKind::GrantRenewed
                | EventKind::DelegationCreated
                | EventKind::GrantRevoked
                | EventKind::DelegationRevoked
                | EventKind::DescendantInvalidated
                | EventKind::AuthorityExpiryElapsed
                | EventKind::AuthorityExpiryObserved
                | EventKind::SessionCreated
                | EventKind::SessionEnded
                | EventKind::PresenceIntentIssued
                | EventKind::OrphanPresenceIntentDiscarded
                | EventKind::CustodyUnlockBegan
                | EventKind::CustodyUnlockCompleted
                | EventKind::ControlRequestAttempted
                | EventKind::ControlRequestDecided
                | EventKind::OperationAdmitted
                | EventKind::ActionResolved
                | EventKind::PackResolved
                | EventKind::ArtifactVerified
                | EventKind::CredentialMaterialized
                | EventKind::CredentialBorrowed
                | EventKind::RunnerExecutionOutcome
                | EventKind::ProviderSettlement
                | EventKind::UpstreamRevocation
                | EventKind::StartupRecoverySettlement
                | EventKind::OperationTerminal
                | EventKind::IdempotentReplay
                | EventKind::SubmissionConflict
                | EventKind::JournalDegraded
                | EventKind::FailStopEntered
                | EventKind::OperationAuthorityRevoked
                | EventKind::OperatorRollupView
                | EventKind::CredentialEnrolled
                | EventKind::CredentialRotated
                | EventKind::CredentialDeleted
                | EventKind::CredentialEnrollPresenceRefused
                | EventKind::CredentialEnrollOccupied
                | EventKind::CredentialEnrollReplayRefused
                | EventKind::CredentialRotatePresenceRefused
                | EventKind::CredentialRotateEmpty
                | EventKind::CredentialRotateMismatch
                | EventKind::CredentialRotateReplayRefused
                | EventKind::CredentialDeletePresenceRefused
                | EventKind::CredentialDeleteEmpty
                | EventKind::CredentialDeleteMismatch
                | EventKind::CredentialDeleteReplayRefused => kind.classification(),
            }
        }
        assert_eq!(role(EvidenceRole::AuthorityReceipt), 1);
        assert_eq!(role(EvidenceRole::AuditFact), 2);
        assert_eq!(role(EvidenceRole::AuthorityRollup), 3);
        assert_eq!(
            classification(EventKind::DescendantInvalidated),
            EventClassification::DerivedNoRecord
        );
        assert_eq!(
            classification(EventKind::AuthorityExpiryElapsed),
            EventClassification::NoRecordUntilObserved
        );
        assert_eq!(
            classification(EventKind::OperationAdmitted),
            EventClassification::Evidence(EvidenceRole::AuditFact)
        );
        assert_eq!(EventKind::GrantIssued as u8, 0);
        assert_eq!(EventKind::OperationAdmitted as u8, 17);
        assert_eq!(EventKind::OperatorRollupView as u8, 33);
        assert_eq!(EventKind::CredentialEnrolled as u8, 34);
        assert_eq!(EventKind::CredentialEnrollPresenceRefused as u8, 37);
        assert_eq!(EventKind::CredentialDeleteReplayRefused as u8, 47);
        assert_eq!(EventKind::CredentialDeleted as u8, 36);
    }

    #[test]
    fn submission_resolution_is_unknown_identical_or_conflict() {
        for value in 0_u8..64 {
            let submission = SubmissionId::from_bytes([value; 32]);
            let digest = RequestDigest::of(&[value]);
            let operation = OperationId::new();
            assert_eq!(
                resolve_submission(submission, digest, None),
                SubmissionResolution::Admit
            );
            let binding = SubmissionBinding::new(submission, digest, operation.clone());
            assert_eq!(
                resolve_submission(submission, digest, Some(&binding)),
                SubmissionResolution::Existing(operation.clone())
            );
            assert_eq!(
                resolve_submission(
                    submission,
                    RequestDigest::of(&[value.wrapping_add(1)]),
                    Some(&binding),
                ),
                SubmissionResolution::Conflict {
                    existing_operation_id: operation.clone(),
                }
            );
            assert_eq!(
                resolve_submission(
                    SubmissionId::from_bytes([value.wrapping_add(1); 32]),
                    digest,
                    Some(&binding),
                ),
                SubmissionResolution::Conflict {
                    existing_operation_id: operation,
                }
            );
        }
    }

    #[test]
    fn materialization_fact_requires_materialization_even_without_operation() {
        assert_eq!(
            AuditFact::new(
                EvidenceId::from_bytes([3; 32]),
                sequence(1),
                EventKind::CredentialMaterialized,
                None,
            ),
            Err(AuditFactError::MissingMaterializationIdentity)
        );
    }

    #[test]
    fn explicit_derived_fields_construct_views_without_mutating_outcomes() {
        let outcome = OperationOutcome::new(
            OperationId::new(),
            SubmissionId::from_bytes([2; 32]),
            RequestDigest::of(b"request"),
            sequence(2),
            None,
            ActionBoundary::EffectCompleted { succeeded: true },
        );
        let immutable = outcome.clone();
        let view = OperationView::from_derived_fields(
            &outcome,
            sequence(3),
            ProjectionVersion::V1,
            SettlementState::Settled,
            true,
        )
        .unwrap();
        assert_eq!(view.operation_id(), outcome.operation_id());
        assert_eq!(view.outcome_sequence(), sequence(2));
        assert_eq!(view.through_sequence(), sequence(3));
        assert_eq!(view.projection_version(), ProjectionVersion::V1);
        assert_eq!(view.settlement(), SettlementState::Settled);
        assert!(view.authority_revoked_after_boundary());
        assert_eq!(outcome, immutable);
        assert!(
            OperationView::from_derived_fields(
                &outcome,
                sequence(1),
                ProjectionVersion::V1,
                SettlementState::Pending,
                false,
            )
            .is_none()
        );

        let rollup = AuthorityRollup::new(ProjectionVersion::V1, sequence(3), 4, 5, [6; 32]);
        assert_eq!(rollup.projection_version(), ProjectionVersion::V1);
        assert_eq!(rollup.through_sequence(), sequence(3));
        assert_eq!(rollup.authority_receipt_count(), 4);
        assert_eq!(rollup.audit_fact_count(), 5);
        assert_eq!(rollup.primary_evidence_digest(), &[6; 32]);
    }
}
