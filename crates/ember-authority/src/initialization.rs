use std::{collections::BTreeSet, fs, path::PathBuf};

use core_crypto::{PublicKey, Signature, Verifier as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    action_definition::ActionDefinitionRegistry,
    audit::{now_unix, sha256},
    device::{
        DeviceCustody, DeviceCustodyEvidence, DeviceState, authority_fingerprint,
        device_set_digest, signing_key_fingerprint,
    },
    model::Refusal,
};

const MAX_MEMBERS: usize = 64;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigestEntry {
    pub artifact_id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSource {
    pub artifact_id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBaseReleaseManifest {
    pub manifest_version: String,
    pub release_signer_key_fingerprint: String,
    pub release_signer_authorization_chain_digest: String,
    pub release_signing_trust_root_fingerprint: String,
    pub release_signing_trust_root_version: u64,
    pub bootstrap_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub executable_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub profile_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub deny_by_default_policy_digest: String,
    pub activation_qualification_plan_digest: String,
    pub initial_qualification_publisher_trust_root_digest: String,
    pub initial_qualification_harness_profile_authorization_set_digest: String,
    pub initial_qualification_grant_set_digest: String,
    pub initial_qualification_action_definition_set_digest: String,
    pub initial_trusted_project_authorization_set_digest: String,
    pub initial_qualification_route_set_digest: String,
    pub initial_qualification_caller_eligibility_digest: String,
    pub initial_qualification_coverage_set_digest: String,
    pub issuance: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBaseReleaseManifestEnvelope {
    pub release_manifest: ProductBaseReleaseManifest,
    pub release_manifest_digest: String,
    pub release_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseVerificationAnchor {
    pub trust_root_fingerprint: String,
    pub version: u64,
    pub signer_public_key: String,
    pub signer_authorization_chain_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootInitializationIntent {
    pub productbase_release_manifest_digest: String,
    pub bootstrap_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub root_verification_public_key: String,
    pub initial_principal_id: String,
    pub initial_qualification_persona_id: String,
    pub initial_qualification_grant_set_digest: String,
    pub initial_qualification_harness_profile_authorization_set_digest: String,
    pub initial_qualification_caller_eligibility_digest: String,
    pub deny_by_default_policy_digest: String,
    pub recovery_manifest_digest: String,
    pub initial_device_set_digest: String,
    pub initial_qualification_publisher_trust_root_digest: String,
    pub initial_qualification_action_definition_set_digest: String,
    pub initial_trusted_project_authorization_set_digest: String,
    pub initial_qualification_route_set_digest: String,
    pub release_signing_trust_root_fingerprint: String,
    pub release_signing_trust_root_version: u64,
    pub initial_release_qualification_record_digest: String,
    pub initial_qualification_coverage_set_digest: String,
    pub prior_root_continuity_record_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationQualificationPlan {
    pub qualification_principal_id: String,
    pub qualification_persona_id: String,
    pub qualification_harness_profile_artifact_digest: String,
    pub qualification_harness_profile_authorization_set_digest: String,
    pub qualification_grant_set_digest: String,
    pub qualification_action_definition_set_digest: String,
    pub qualification_trusted_project_authorization_set_digest: String,
    pub qualification_route_set_digest: String,
    pub caller_eligibility_digest: String,
    pub maintenance_window_expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationGrantRecord {
    pub grant_id: String,
    pub principal_id: String,
    pub persona_id: String,
    pub action_definition_digest: String,
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
    pub offline_bound: bool,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessProfileAuthorization {
    pub profile_id: String,
    pub artifact_digest: String,
    pub executable_digest: String,
    pub launch_scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerEligibilityRecord {
    pub principal_id: String,
    pub persona_id: String,
    pub operator_uid: u32,
    pub profile_artifact_digest: String,
    pub executable_digest: String,
    /// Release-signed loaded-code identity: `cdhash:<40 hex>` on macOS or
    /// `sha256:<64 hex>` on Linux.
    pub executable_identity: String,
    pub trusted_project_digest: String,
    pub maintenance_window_expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherTrustRoot {
    pub publisher_id: String,
    pub signer_key_id: String,
    pub public_key: String,
    pub not_after: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialActionDefinitionRecord {
    pub action_definition_digest: String,
    pub signed_bundle: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProjectAuthorization {
    pub project_root_digest: String,
    pub worktree_digest: String,
    pub profile_artifact_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAuthorization {
    pub route_id: String,
    pub action_definition_digest: String,
    pub runner_class: String,
    pub delivery_lane: String,
    pub credential_slot: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyByDefaultPolicy {
    pub schema: String,
    pub default_decision: String,
    pub credential_delivery: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryManifest {
    pub schema: String,
    pub mode: String,
    pub reconstruction_quorum: u64,
    pub recipient_fingerprints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialQualificationCoverageSet {
    pub schema: String,
    pub deployment_class: String,
    pub initialization: String,
    pub session_action_receipt: String,
    pub recovery: String,
    pub production_credentials: String,
    pub federation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlReleaseQualificationRecord {
    pub manifest_version: String,
    pub manifest_digest: String,
    pub executable_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub profile_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub rollback_manifest_digest: Option<String>,
    pub activation_qualification_plan_digest: String,
    pub release_signing_trust_root_fingerprint: String,
    pub release_signing_trust_root_version: u64,
    pub qualification_state: String,
    pub record_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootContinuityRecord {
    pub schema: String,
    pub generation: u64,
    pub authority_fingerprint: String,
    pub prior_record_digest: String,
    pub protected_tip_digest: String,
    pub slot_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialRecords {
    pub qualification_grants: Vec<QualificationGrantRecord>,
    pub harness_profile_authorizations: Vec<HarnessProfileAuthorization>,
    pub caller_eligibility: Vec<CallerEligibilityRecord>,
    pub publisher_trust_roots: Vec<PublisherTrustRoot>,
    pub action_definitions: Vec<InitialActionDefinitionRecord>,
    pub trusted_projects: Vec<TrustedProjectAuthorization>,
    pub routes: Vec<RouteAuthorization>,
    pub policy: DenyByDefaultPolicy,
    pub recovery_manifest: RecoveryManifest,
    pub coverage: InitialQualificationCoverageSet,
    pub release_qualification: AuthorityControlReleaseQualificationRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialRecordDigests {
    pub grant_set: String,
    pub profile_set: String,
    pub caller_set: String,
    pub publisher_set: String,
    pub definition_set: String,
    pub project_set: String,
    pub route_set: String,
    pub policy: String,
    pub recovery: String,
    pub coverage: String,
    pub release_qualification: String,
}

impl InitialRecords {
    pub fn digests(&self) -> Result<InitialRecordDigests, Refusal> {
        Ok(InitialRecordDigests {
            grant_set: digest(&encode_set(
                "ember/initial-qualification-grant-set/v1",
                &self.qualification_grants,
                encode_grant,
            )?),
            profile_set: digest(&encode_set(
                "ember/initial-qualification-harness-profile-authorization-set/v1",
                &self.harness_profile_authorizations,
                encode_profile,
            )?),
            caller_set: digest(&encode_set(
                "ember/initial-qualification-caller-eligibility-set/v1",
                &self.caller_eligibility,
                encode_caller,
            )?),
            publisher_set: digest(&encode_set(
                "ember/initial-qualification-publisher-trust-root-set/v1",
                &self.publisher_trust_roots,
                encode_publisher,
            )?),
            definition_set: digest(&encode_set(
                "ember/initial-qualification-action-definition-set/v1",
                &self.action_definitions,
                encode_definition,
            )?),
            project_set: digest(&encode_set(
                "ember/initial-trusted-project-authorization-set/v1",
                &self.trusted_projects,
                encode_project,
            )?),
            route_set: digest(&encode_set(
                "ember/initial-qualification-route-set/v1",
                &self.routes,
                encode_route,
            )?),
            policy: digest(&encode_policy(&self.policy)?),
            recovery: digest(&encode_recovery(&self.recovery_manifest)?),
            coverage: digest(&encode_coverage(&self.coverage)?),
            release_qualification: digest(&encode_release_qualification(
                &self.release_qualification,
            )?),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentInitialRecords {
    pub qualification_grants: Vec<QualificationGrantRecord>,
    pub harness_profile_authorizations: Vec<HarnessProfileAuthorization>,
    pub caller_eligibility: Vec<CallerEligibilityRecord>,
    pub publisher_trust_roots: Vec<PublisherTrustRoot>,
    pub action_definitions: Vec<InitialActionDefinitionRecord>,
    pub trusted_projects: Vec<TrustedProjectAuthorization>,
    pub routes: Vec<RouteAuthorization>,
    pub policy: DenyByDefaultPolicy,
    pub recovery_manifest: RecoveryManifest,
    pub coverage: InitialQualificationCoverageSet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevelopmentInitialRecordDigests {
    pub grant_set: String,
    pub profile_set: String,
    pub caller_set: String,
    pub publisher_set: String,
    pub definition_set: String,
    pub project_set: String,
    pub route_set: String,
    pub policy: String,
    pub recovery: String,
    pub coverage: String,
}

impl DevelopmentInitialRecords {
    pub fn digests(&self) -> Result<DevelopmentInitialRecordDigests, Refusal> {
        Ok(DevelopmentInitialRecordDigests {
            grant_set: digest(&encode_set(
                "ember/development-qualification-grant-set/v1",
                &self.qualification_grants,
                encode_grant,
            )?),
            profile_set: digest(&encode_set(
                "ember/development-harness-profile-authorization-set/v1",
                &self.harness_profile_authorizations,
                encode_profile,
            )?),
            caller_set: digest(&encode_set(
                "ember/development-caller-eligibility-set/v1",
                &self.caller_eligibility,
                encode_caller,
            )?),
            publisher_set: digest(&encode_set(
                "ember/development-publisher-trust-root-set/v1",
                &self.publisher_trust_roots,
                encode_publisher,
            )?),
            definition_set: digest(&encode_set(
                "ember/development-action-definition-set/v1",
                &self.action_definitions,
                encode_definition,
            )?),
            project_set: digest(&encode_set(
                "ember/development-trusted-project-authorization-set/v1",
                &self.trusted_projects,
                encode_project,
            )?),
            route_set: digest(&encode_set(
                "ember/development-qualification-route-set/v1",
                &self.routes,
                encode_route,
            )?),
            policy: digest(&encode_policy(&self.policy)?),
            recovery: digest(&encode_recovery(&self.recovery_manifest)?),
            coverage: digest(&encode_coverage(&self.coverage)?),
        })
    }
}

pub fn digest_encoded(bytes: &[u8]) -> String {
    digest(bytes)
}

#[derive(Clone, Debug)]
pub struct InitializationRequest {
    pub intent: RootInitializationIntent,
    pub intent_signature: String,
    pub release: ProductBaseReleaseManifestEnvelope,
    pub activation_plan: ActivationQualificationPlan,
    pub records: InitialRecords,
    pub devices: DeviceState,
    pub custody_evidence: DeviceCustodyEvidence,
    pub prior_continuity: RootContinuityRecord,
    pub artifacts: Vec<ArtifactSource>,
}

pub struct ValidatedInitialization {
    pub authority_fingerprint: String,
    pub release_manifest_digest: String,
    pub daemon_executable_digest: String,
    pub registry_bytes: String,
    pub operator_uid: u32,
    pub qualification_grant: QualificationGrantRecord,
    pub caller_eligibility: CallerEligibilityRecord,
    pub harness_profile_authorization: HarnessProfileAuthorization,
    pub trusted_project: TrustedProjectAuthorization,
    pub route: RouteAuthorization,
    pub root_intent_digest: String,
    pub release_qualification_digest: String,
    pub continuity_digest: String,
}

impl InitializationRequest {
    pub fn validate(
        &self,
        anchor: &ReleaseVerificationAnchor,
        now: u64,
    ) -> Result<ValidatedInitialization, Refusal> {
        validate_anchor(&self.release, anchor, now)?;
        validate_artifacts(&self.release.release_manifest, &self.artifacts)?;
        let custody = DeviceCustody::restore(&self.devices)?;
        DeviceCustody::verify_custody_evidence(&self.devices, &self.custody_evidence)?;
        let authority_fingerprint = authority_fingerprint(&custody.root_public_key().0)?;
        let intent_bytes = encode_root_intent(&self.intent)?;
        if !core_crypto::Ed25519Verifier.verify(
            &custody.root_public_key(),
            &intent_bytes,
            &Signature(self.intent_signature.clone()),
        ) {
            return Err(Refusal::new("root_intent_signature_invalid"));
        }

        let manifest = &self.release.release_manifest;
        let plan_digest = digest(&encode_activation_plan(&self.activation_plan)?);
        let grant_set_digest = digest(&encode_set(
            "ember/initial-qualification-grant-set/v1",
            &self.records.qualification_grants,
            encode_grant,
        )?);
        let profile_set_digest = digest(&encode_set(
            "ember/initial-qualification-harness-profile-authorization-set/v1",
            &self.records.harness_profile_authorizations,
            encode_profile,
        )?);
        let caller_set_digest = digest(&encode_set(
            "ember/initial-qualification-caller-eligibility-set/v1",
            &self.records.caller_eligibility,
            encode_caller,
        )?);
        let publisher_set_digest = digest(&encode_set(
            "ember/initial-qualification-publisher-trust-root-set/v1",
            &self.records.publisher_trust_roots,
            encode_publisher,
        )?);
        let definition_set_digest = digest(&encode_set(
            "ember/initial-qualification-action-definition-set/v1",
            &self.records.action_definitions,
            encode_definition,
        )?);
        let project_set_digest = digest(&encode_set(
            "ember/initial-trusted-project-authorization-set/v1",
            &self.records.trusted_projects,
            encode_project,
        )?);
        let route_set_digest = digest(&encode_set(
            "ember/initial-qualification-route-set/v1",
            &self.records.routes,
            encode_route,
        )?);
        let policy_digest = digest(&encode_policy(&self.records.policy)?);
        let recovery_digest = digest(&encode_recovery(&self.records.recovery_manifest)?);
        let coverage_digest = digest(&encode_coverage(&self.records.coverage)?);
        let release_qualification_digest = digest(&encode_release_qualification(
            &self.records.release_qualification,
        )?);
        let root_device_set_digest = device_set_digest(&self.devices)?;
        let continuity_digest = digest(&encode_continuity(&self.prior_continuity)?);

        if self.records.action_definitions.len() > 1 {
            // This tranche installs exactly one closed diagnostic identity.
            // Any second definition therefore conflicts with that immutable
            // identity; do not collapse equivocation into a cardinality error.
            return Err(Refusal::new("identity_collision"));
        }
        let singleton = [
            self.records.qualification_grants.len(),
            self.records.harness_profile_authorizations.len(),
            self.records.caller_eligibility.len(),
            self.records.publisher_trust_roots.len(),
            self.records.action_definitions.len(),
            self.records.trusted_projects.len(),
            self.records.routes.len(),
        ];
        if singleton != [1; 7] {
            return Err(Refusal::new("initialization_set_invalid"));
        }
        let grant = &self.records.qualification_grants[0];
        let profile = &self.records.harness_profile_authorizations[0];
        let caller = &self.records.caller_eligibility[0];
        let publisher = &self.records.publisher_trust_roots[0];
        let definition = &self.records.action_definitions[0];
        let project = &self.records.trusted_projects[0];
        let route = &self.records.routes[0];

        if manifest.activation_qualification_plan_digest != plan_digest
            || manifest.initial_qualification_grant_set_digest != grant_set_digest
            || manifest.initial_qualification_harness_profile_authorization_set_digest
                != profile_set_digest
            || manifest.initial_qualification_caller_eligibility_digest != caller_set_digest
            || manifest.initial_qualification_publisher_trust_root_digest != publisher_set_digest
            || manifest.initial_qualification_action_definition_set_digest != definition_set_digest
            || manifest.initial_trusted_project_authorization_set_digest != project_set_digest
            || manifest.initial_qualification_route_set_digest != route_set_digest
            || manifest.deny_by_default_policy_digest != policy_digest
            || manifest.initial_qualification_coverage_set_digest != coverage_digest
            || self.intent.productbase_release_manifest_digest
                != self.release.release_manifest_digest
            || self.intent.bootstrap_artifact_digest_list != manifest.bootstrap_artifact_digest_list
            || self.intent.root_verification_public_key != custody.root_public_key().0
            || self.intent.initial_principal_id != self.activation_plan.qualification_principal_id
            || self.intent.initial_qualification_persona_id
                != self.activation_plan.qualification_persona_id
            || self.intent.initial_qualification_grant_set_digest != grant_set_digest
            || self
                .intent
                .initial_qualification_harness_profile_authorization_set_digest
                != profile_set_digest
            || self.intent.initial_qualification_caller_eligibility_digest != caller_set_digest
            || self.intent.deny_by_default_policy_digest != policy_digest
            || self.intent.recovery_manifest_digest != recovery_digest
            || self.intent.initial_device_set_digest != root_device_set_digest
            || self
                .intent
                .initial_qualification_publisher_trust_root_digest
                != publisher_set_digest
            || self
                .intent
                .initial_qualification_action_definition_set_digest
                != definition_set_digest
            || self.intent.initial_trusted_project_authorization_set_digest != project_set_digest
            || self.intent.initial_qualification_route_set_digest != route_set_digest
            || self.intent.release_signing_trust_root_fingerprint
                != manifest.release_signing_trust_root_fingerprint
            || self.intent.release_signing_trust_root_version
                != manifest.release_signing_trust_root_version
            || self.intent.initial_release_qualification_record_digest
                != release_qualification_digest
            || self.intent.initial_qualification_coverage_set_digest != coverage_digest
            || self.intent.prior_root_continuity_record_digest != continuity_digest
            || self
                .activation_plan
                .qualification_harness_profile_authorization_set_digest
                != profile_set_digest
            || self.activation_plan.qualification_grant_set_digest != grant_set_digest
            || self
                .activation_plan
                .qualification_action_definition_set_digest
                != definition_set_digest
            || self
                .activation_plan
                .qualification_trusted_project_authorization_set_digest
                != project_set_digest
            || self.activation_plan.qualification_route_set_digest != route_set_digest
            || self.activation_plan.caller_eligibility_digest != caller_set_digest
        {
            return Err(Refusal::new("initialization_digest_mismatch"));
        }

        validate_semantics(
            &authority_fingerprint,
            now,
            &self.activation_plan,
            grant,
            profile,
            caller,
            publisher,
            definition,
            project,
            route,
            &self.records,
            &self.prior_continuity,
            &self.release,
        )?;
        let registry_bytes = ActionDefinitionRegistry::initialize(publisher, definition)?;
        Ok(ValidatedInitialization {
            authority_fingerprint,
            release_manifest_digest: self.release.release_manifest_digest.clone(),
            daemon_executable_digest: self
                .release
                .release_manifest
                .bootstrap_artifact_digest_list
                .iter()
                .find(|entry| entry.artifact_id == "bootstrap:emberd")
                .map(|entry| entry.digest.clone())
                .ok_or_else(|| Refusal::new("release_artifact_invalid"))?,
            registry_bytes,
            operator_uid: caller.operator_uid,
            qualification_grant: grant.clone(),
            caller_eligibility: caller.clone(),
            harness_profile_authorization: profile.clone(),
            trusted_project: project.clone(),
            route: route.clone(),
            root_intent_digest: digest(&intent_bytes),
            release_qualification_digest,
            continuity_digest,
        })
    }
}

fn validate_anchor(
    release: &ProductBaseReleaseManifestEnvelope,
    anchor: &ReleaseVerificationAnchor,
    now: u64,
) -> Result<(), Refusal> {
    let manifest = &release.release_manifest;
    let bytes = encode_release_manifest(manifest)?;
    let manifest_digest = digest(&bytes);
    let signer_fingerprint = signing_key_fingerprint(&anchor.signer_public_key, "release-signing")?;
    if manifest.manifest_version != "productbase-s4/v1"
        || release.release_manifest_digest != manifest_digest
        || manifest.release_signer_key_fingerprint != signer_fingerprint
        || manifest.release_signer_authorization_chain_digest
            != anchor.signer_authorization_chain_digest
        || manifest.release_signing_trust_root_fingerprint != anchor.trust_root_fingerprint
        || manifest.release_signing_trust_root_version != anchor.version
        || now < manifest.issuance
        || now >= manifest.expiry
        || !core_crypto::Ed25519Verifier.verify(
            &PublicKey(anchor.signer_public_key.clone()),
            &bytes,
            &Signature(release.release_signature.clone()),
        )
    {
        return Err(Refusal::new("release_manifest_invalid"));
    }
    Ok(())
}

fn validate_artifacts(
    manifest: &ProductBaseReleaseManifest,
    sources: &[ArtifactSource],
) -> Result<(), Refusal> {
    let mut signed = Vec::new();
    signed.extend(manifest.bootstrap_artifact_digest_list.iter().cloned());
    signed.extend(manifest.executable_artifact_digest_list.iter().cloned());
    signed.extend(manifest.profile_artifact_digest_list.iter().cloned());
    validate_artifact_list(&manifest.bootstrap_artifact_digest_list)?;
    validate_artifact_list(&manifest.executable_artifact_digest_list)?;
    validate_artifact_list(&manifest.profile_artifact_digest_list)?;
    let signed_ids: BTreeSet<_> = signed
        .iter()
        .map(|entry| entry.artifact_id.as_str())
        .collect();
    let source_ids: BTreeSet<_> = sources
        .iter()
        .map(|source| source.artifact_id.as_str())
        .collect();
    if signed_ids != source_ids || source_ids.len() != sources.len() {
        return Err(Refusal::new("release_artifact_invalid"));
    }
    for source in sources {
        let metadata =
            fs::metadata(&source.path).map_err(|_| Refusal::new("release_artifact_invalid"))?;
        if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(Refusal::new("release_artifact_invalid"));
        }
        let bytes = fs::read(&source.path).map_err(|_| Refusal::new("release_artifact_invalid"))?;
        let actual = sha256(&bytes);
        if signed
            .iter()
            .filter(|entry| entry.artifact_id == source.artifact_id)
            .any(|entry| entry.digest != actual)
        {
            return Err(Refusal::new("release_artifact_invalid"));
        }
    }
    Ok(())
}

fn validate_artifact_list(entries: &[ArtifactDigestEntry]) -> Result<(), Refusal> {
    if entries.len() > MAX_MEMBERS {
        return Err(Refusal::new("initialization_set_invalid"));
    }
    let ids: Vec<_> = entries
        .iter()
        .map(|entry| entry.artifact_id.as_str())
        .collect();
    if !is_strictly_sorted(&ids)
        || entries
            .iter()
            .any(|entry| validate_digest(&entry.digest).is_err())
    {
        return Err(Refusal::new("release_artifact_invalid"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_semantics(
    authority_fingerprint: &str,
    now: u64,
    plan: &ActivationQualificationPlan,
    grant: &QualificationGrantRecord,
    profile: &HarnessProfileAuthorization,
    caller: &CallerEligibilityRecord,
    publisher: &PublisherTrustRoot,
    definition: &InitialActionDefinitionRecord,
    project: &TrustedProjectAuthorization,
    route: &RouteAuthorization,
    records: &InitialRecords,
    continuity: &RootContinuityRecord,
    release: &ProductBaseReleaseManifestEnvelope,
) -> Result<(), Refusal> {
    if plan.qualification_principal_id != grant.principal_id
        || plan.qualification_principal_id != caller.principal_id
        || plan.qualification_persona_id != grant.persona_id
        || plan.qualification_persona_id != caller.persona_id
        || plan.qualification_harness_profile_artifact_digest != profile.artifact_digest
        || profile.artifact_digest != caller.profile_artifact_digest
        || profile.artifact_digest != project.profile_artifact_digest
        || caller.trusted_project_digest != digest(&encode_project(project)?)
        || !valid_executable_identity(&caller.executable_identity)
        || plan.maintenance_window_expiry != caller.maintenance_window_expiry
        || now >= plan.maintenance_window_expiry
        || now >= grant.expiry
        || now >= publisher.not_after
        || grant.action_definition_digest != definition.action_definition_digest
        || route.action_definition_digest != definition.action_definition_digest
        || route.runner_class != "builtin"
        || route.delivery_lane != "sealed-exec"
        || route.credential_slot.is_some()
        || grant.permission != "authority.status.read"
        || grant.material_class != "non_secret"
        || grant.provider != "ember.local"
        || grant.protocol != "ember.local"
        || grant.destination != "authority-journal"
        || grant.operation_class != "diagnostic.read"
        || grant.request_count_ceiling != 1
        || grant.rate_ceiling != 1
        || grant.byte_budget != 65_536
        || grant.offline_bound
        || records.policy.schema != "ember.deny-by-default-policy/v1"
        || records.policy.default_decision != "deny"
        || records.policy.credential_delivery != "forbidden"
        || records.recovery_manifest.schema != "ember.recovery-manifest/v1"
        || records.recovery_manifest.mode != "qualification-no-recovery"
        || records.recovery_manifest.reconstruction_quorum != 0
        || !records.recovery_manifest.recipient_fingerprints.is_empty()
        || records.coverage.schema != "ember.initial-qualification-coverage-set/v1"
        || records.coverage.deployment_class != "disposable-qualification"
        || records.coverage.initialization != "unqualified"
        || records.coverage.session_action_receipt != "unqualified"
        || records.coverage.recovery != "not_applicable"
        || records.coverage.production_credentials != "not_applicable"
        || records.coverage.federation != "not_applicable"
        || records.release_qualification.manifest_version
            != release.release_manifest.manifest_version
        || records.release_qualification.manifest_digest != release.release_manifest_digest
        || records
            .release_qualification
            .executable_artifact_digest_list
            != release.release_manifest.executable_artifact_digest_list
        || records.release_qualification.profile_artifact_digest_list
            != release.release_manifest.profile_artifact_digest_list
        || records
            .release_qualification
            .rollback_manifest_digest
            .is_some()
        || records
            .release_qualification
            .activation_qualification_plan_digest
            != release
                .release_manifest
                .activation_qualification_plan_digest
        || records
            .release_qualification
            .release_signing_trust_root_fingerprint
            != release
                .release_manifest
                .release_signing_trust_root_fingerprint
        || records
            .release_qualification
            .release_signing_trust_root_version
            != release.release_manifest.release_signing_trust_root_version
        || records.release_qualification.qualification_state != "provisional"
        || records.release_qualification.record_revision != 1
        || continuity.schema != "ember.root-continuity-record/v1"
        || continuity.generation != 0
        || continuity.authority_fingerprint != authority_fingerprint
        || continuity.prior_record_digest != ZERO_DIGEST
        || continuity.protected_tip_digest != ZERO_DIGEST
        || continuity.slot_id.is_empty()
        || publisher.publisher_id.is_empty()
        || publisher.signer_key_id.is_empty()
        || publisher.public_key.is_empty()
        || !release
            .release_manifest
            .executable_artifact_digest_list
            .iter()
            .any(|entry| entry.digest == caller.executable_digest)
        || !release
            .release_manifest
            .profile_artifact_digest_list
            .iter()
            .any(|entry| entry.digest == profile.artifact_digest)
    {
        return Err(Refusal::new("initialization_invalid"));
    }
    Ok(())
}

pub fn encode_release_manifest(value: &ProductBaseReleaseManifest) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/productbase-release-manifest/v1")?;
    e.string(&value.manifest_version)?
        .digest(&value.release_signer_key_fingerprint)?
        .digest(&value.release_signer_authorization_chain_digest)?
        .digest(&value.release_signing_trust_root_fingerprint)?
        .u64(value.release_signing_trust_root_version)
        .list(&value.bootstrap_artifact_digest_list, encode_artifact)?
        .list(&value.executable_artifact_digest_list, encode_artifact)?
        .list(&value.profile_artifact_digest_list, encode_artifact)?
        .digest(&value.deny_by_default_policy_digest)?
        .digest(&value.activation_qualification_plan_digest)?
        .digest(&value.initial_qualification_publisher_trust_root_digest)?
        .digest(&value.initial_qualification_harness_profile_authorization_set_digest)?
        .digest(&value.initial_qualification_grant_set_digest)?
        .digest(&value.initial_qualification_action_definition_set_digest)?
        .digest(&value.initial_trusted_project_authorization_set_digest)?
        .digest(&value.initial_qualification_route_set_digest)?
        .digest(&value.initial_qualification_caller_eligibility_digest)?
        .digest(&value.initial_qualification_coverage_set_digest)?
        .u64(value.issuance)
        .u64(value.expiry);
    Ok(e.finish())
}

pub fn encode_root_intent(value: &RootInitializationIntent) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/root-initialization-intent/v1")?;
    e.digest(&value.productbase_release_manifest_digest)?
        .list(&value.bootstrap_artifact_digest_list, encode_artifact)?
        .string(&value.root_verification_public_key)?
        .string(&value.initial_principal_id)?
        .string(&value.initial_qualification_persona_id)?
        .digest(&value.initial_qualification_grant_set_digest)?
        .digest(&value.initial_qualification_harness_profile_authorization_set_digest)?
        .digest(&value.initial_qualification_caller_eligibility_digest)?
        .digest(&value.deny_by_default_policy_digest)?
        .digest(&value.recovery_manifest_digest)?
        .digest(&value.initial_device_set_digest)?
        .digest(&value.initial_qualification_publisher_trust_root_digest)?
        .digest(&value.initial_qualification_action_definition_set_digest)?
        .digest(&value.initial_trusted_project_authorization_set_digest)?
        .digest(&value.initial_qualification_route_set_digest)?
        .digest(&value.release_signing_trust_root_fingerprint)?
        .u64(value.release_signing_trust_root_version)
        .digest(&value.initial_release_qualification_record_digest)?
        .digest(&value.initial_qualification_coverage_set_digest)?
        .digest(&value.prior_root_continuity_record_digest)?;
    Ok(e.finish())
}

pub fn encode_activation_plan(value: &ActivationQualificationPlan) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/activation-qualification-plan/v1")?;
    e.string(&value.qualification_principal_id)?
        .string(&value.qualification_persona_id)?
        .digest(&value.qualification_harness_profile_artifact_digest)?
        .digest(&value.qualification_harness_profile_authorization_set_digest)?
        .digest(&value.qualification_grant_set_digest)?
        .digest(&value.qualification_action_definition_set_digest)?
        .digest(&value.qualification_trusted_project_authorization_set_digest)?
        .digest(&value.qualification_route_set_digest)?
        .digest(&value.caller_eligibility_digest)?
        .u64(value.maintenance_window_expiry);
    Ok(e.finish())
}

fn encode_artifact(value: &ArtifactDigestEntry) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/artifact-digest-entry/v1")?;
    e.string(&value.artifact_id)?.digest(&value.digest)?;
    Ok(e.finish())
}

fn encode_grant(value: &QualificationGrantRecord) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/qualification-grant/v1")?;
    e.string(&value.grant_id)?
        .string(&value.principal_id)?
        .string(&value.persona_id)?
        .digest(&value.action_definition_digest)?
        .string(&value.target)?
        .string(&value.permission)?
        .string(&value.material_class)?
        .string(&value.provider)?
        .string(&value.protocol)?
        .string(&value.destination)?
        .string(&value.operation_class)?
        .u64(value.request_count_ceiling)
        .u64(value.byte_budget)
        .u64(value.rate_ceiling)
        .u64(value.expiry);
    Ok(e.finish())
}

fn encode_profile(value: &HarnessProfileAuthorization) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/harness-profile-authorization/v1")?;
    e.string(&value.profile_id)?
        .digest(&value.artifact_digest)?
        .digest(&value.executable_digest)?
        .string(&value.launch_scope)?;
    Ok(e.finish())
}

fn valid_executable_identity(value: &str) -> bool {
    let (prefix, width) = if cfg!(target_os = "macos") {
        ("cdhash:", 40)
    } else if cfg!(target_os = "linux") {
        ("sha256:", 64)
    } else {
        return false;
    };
    value
        .strip_prefix(prefix)
        .is_some_and(|hex| hex.len() == width && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn encode_caller(value: &CallerEligibilityRecord) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/caller-eligibility/v1")?;
    e.string(&value.principal_id)?
        .string(&value.persona_id)?
        .u64(value.operator_uid.into())
        .digest(&value.profile_artifact_digest)?
        .digest(&value.executable_digest)?
        .string(&value.executable_identity)?
        .digest(&value.trusted_project_digest)?
        .u64(value.maintenance_window_expiry);
    Ok(e.finish())
}

fn encode_publisher(value: &PublisherTrustRoot) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/publisher-trust-root/v1")?;
    e.string(&value.publisher_id)?
        .string(&value.signer_key_id)?
        .string(&value.public_key)?
        .u64(value.not_after);
    Ok(e.finish())
}

fn encode_definition(value: &InitialActionDefinitionRecord) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/initial-action-definition/v1")?;
    e.digest(&value.action_definition_digest)?
        .bytes(value.signed_bundle.as_bytes())?;
    Ok(e.finish())
}

pub fn encode_project(value: &TrustedProjectAuthorization) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/trusted-project-authorization/v1")?;
    e.digest(&value.project_root_digest)?
        .digest(&value.worktree_digest)?
        .digest(&value.profile_artifact_digest)?;
    Ok(e.finish())
}

fn encode_route(value: &RouteAuthorization) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/qualification-route/v1")?;
    e.string(&value.route_id)?
        .digest(&value.action_definition_digest)?
        .string(&value.runner_class)?
        .string(&value.delivery_lane)?
        .optional_string(value.credential_slot.as_deref())?;
    Ok(e.finish())
}

pub fn encode_policy(value: &DenyByDefaultPolicy) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/deny-by-default-policy/v1")?;
    e.string(&value.schema)?
        .string(&value.default_decision)?
        .string(&value.credential_delivery)?;
    Ok(e.finish())
}

pub fn encode_recovery(value: &RecoveryManifest) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/recovery-manifest/v1")?;
    e.string(&value.schema)?
        .string(&value.mode)?
        .u64(value.reconstruction_quorum)
        .list(&value.recipient_fingerprints, |entry| {
            let mut item = Encoder::new("ember/recovery-recipient-entry/v1")?;
            item.digest(entry)?;
            Ok(item.finish())
        })?;
    Ok(e.finish())
}

pub fn encode_coverage(value: &InitialQualificationCoverageSet) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/initial-qualification-coverage-set/v1")?;
    e.string(&value.schema)?
        .string(&value.deployment_class)?
        .string(&value.initialization)?
        .string(&value.session_action_receipt)?
        .string(&value.recovery)?
        .string(&value.production_credentials)?
        .string(&value.federation)?;
    Ok(e.finish())
}

pub fn encode_release_qualification(
    value: &AuthorityControlReleaseQualificationRecord,
) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/authority-control-release-qualification-record/v1")?;
    e.string(&value.manifest_version)?
        .digest(&value.manifest_digest)?
        .list(&value.executable_artifact_digest_list, encode_artifact)?
        .list(&value.profile_artifact_digest_list, encode_artifact)?
        .optional_digest(value.rollback_manifest_digest.as_deref())?
        .digest(&value.activation_qualification_plan_digest)?
        .digest(&value.release_signing_trust_root_fingerprint)?
        .u64(value.release_signing_trust_root_version)
        .string(&value.qualification_state)?
        .u64(value.record_revision);
    Ok(e.finish())
}

pub fn encode_continuity(value: &RootContinuityRecord) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new("ember/root-continuity-record/v1")?;
    e.string(&value.schema)?
        .u64(value.generation)
        .digest(&value.authority_fingerprint)?
        .digest(&value.prior_record_digest)?
        .digest(&value.protected_tip_digest)?
        .string(&value.slot_id)?;
    Ok(e.finish())
}

fn encode_set<T>(
    domain: &str,
    values: &[T],
    encode: impl Fn(&T) -> Result<Vec<u8>, Refusal>,
) -> Result<Vec<u8>, Refusal> {
    if values.len() > MAX_MEMBERS {
        return Err(Refusal::new("initialization_set_invalid"));
    }
    let mut members = Vec::with_capacity(values.len());
    for value in values {
        members.push(encode(value)?);
    }
    let mut sorted = members.clone();
    sorted.sort();
    if members != sorted || members.windows(2).any(|window| window[0] == window[1]) {
        return Err(Refusal::new("initialization_set_invalid"));
    }
    let mut e = Encoder::new(domain)?;
    e.list(&members, |member| Ok(member.clone()))?;
    Ok(e.finish())
}

fn is_strictly_sorted(values: &[&str]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn validate_digest(value: &str) -> Result<(), Refusal> {
    let raw = value
        .strip_prefix("sha256:")
        .ok_or_else(|| Refusal::new("canonical_digest_invalid"))?;
    let decoded = hex::decode(raw).map_err(|_| Refusal::new("canonical_digest_invalid"))?;
    if decoded.len() != 32 || raw != raw.to_ascii_lowercase() {
        return Err(Refusal::new("canonical_digest_invalid"));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new(domain: &str) -> Result<Self, Refusal> {
        let mut value = Self { bytes: Vec::new() };
        value.bytes(domain.as_bytes())?;
        Ok(value)
    }

    fn bytes(&mut self, value: &[u8]) -> Result<&mut Self, Refusal> {
        if value.len() > 1_048_576 {
            return Err(Refusal::new("canonical_value_too_large"));
        }
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(self)
    }

    fn string(&mut self, value: &str) -> Result<&mut Self, Refusal> {
        if value.len() > 4096 {
            return Err(Refusal::new("canonical_value_too_large"));
        }
        self.bytes(value.as_bytes())
    }

    fn digest(&mut self, value: &str) -> Result<&mut Self, Refusal> {
        validate_digest(value)?;
        self.string(value)
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn optional_string(&mut self, value: Option<&str>) -> Result<&mut Self, Refusal> {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.string(value)
            }
            None => {
                self.bytes.push(0);
                Ok(self)
            }
        }
    }

    fn optional_digest(&mut self, value: Option<&str>) -> Result<&mut Self, Refusal> {
        match value {
            Some(value) => {
                self.bytes.push(1);
                self.digest(value)
            }
            None => {
                self.bytes.push(0);
                Ok(self)
            }
        }
    }

    fn list<T>(
        &mut self,
        values: &[T],
        encode: impl Fn(&T) -> Result<Vec<u8>, Refusal>,
    ) -> Result<&mut Self, Refusal> {
        if values.len() > MAX_MEMBERS {
            return Err(Refusal::new("canonical_list_too_large"));
        }
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.bytes(&encode(value)?)?;
        }
        Ok(self)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn default_now() -> u64 {
    now_unix()
}
