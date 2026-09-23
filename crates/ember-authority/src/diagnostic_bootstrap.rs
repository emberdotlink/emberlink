use core_crypto::{PublicKey, Signature, Signer as _, Verifier as _};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _},
    os::unix::{fs::MetadataExt as _, fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use crate::{
    action_definition::{ActionDefinitionRegistry, sign_diagnostic_bundle},
    audit::sha256,
    canonical::LenEncoder,
    device::{
        DeviceCustody, DeviceCustodyEvidence, DeviceState, authority_fingerprint,
        device_set_digest, signing_key_fingerprint,
    },
    identity::{executable_identity_from_file, process_executable_identity, process_pid_version},
    initialization::{
        ArtifactDigestEntry, CallerEligibilityRecord, DenyByDefaultPolicy,
        DevelopmentInitialRecords, HarnessProfileAuthorization, InitialQualificationCoverageSet,
        QualificationGrantRecord, RecoveryManifest, RootContinuityRecord, RouteAuthorization,
        TrustedProjectAuthorization, digest_encoded, encode_continuity, encode_project,
    },
    model::{InitializationEvidence, ProductClassification, Refusal},
};

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PROFILE_BYTES: &[u8] = br#"{"profile":"productbase-development-diagnostic/v1"}"#;
const MANIFEST_DOMAIN: &str = "ember/development-initialization-manifest/v1";
const ATTESTATION_DOMAIN: &[u8] = b"ember/development-bootstrap-attestation/v1\0";
const INTENT_DOMAIN: &str = "ember/development-root-initialization-intent/v1";
const QUALIFICATION_DOMAIN: &str = "ember/development-qualification-record/v1";
const PUBLISHER_ID: &str = "publisher:packet-fixture";
const SIGNER_KEY_ID: &str = "publisher:ember-development-diagnostic:ephemeral";
const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentInitializationManifest {
    pub schema: String,
    pub bootstrap_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub executable_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub profile_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub deny_by_default_policy_digest: String,
    pub recovery_manifest_digest: String,
    pub qualification_grant_set_digest: String,
    pub harness_profile_authorization_set_digest: String,
    pub caller_eligibility_digest: String,
    pub publisher_trust_root_digest: String,
    pub action_definition_set_digest: String,
    pub trusted_project_authorization_set_digest: String,
    pub route_set_digest: String,
    pub qualification_coverage_set_digest: String,
    pub development_qualification_record_digest: String,
    pub prior_root_continuity_record_digest: String,
    pub issuance: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentBootstrapAttestation {
    pub development_manifest_digest: String,
    pub attestation_public_key: String,
    pub attestation_key_fingerprint: String,
    pub attestation_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentRootInitializationIntent {
    pub development_manifest_digest: String,
    pub development_bootstrap_attestation_digest: String,
    pub root_verification_public_key: String,
    pub initial_principal_id: String,
    pub initial_persona_id: String,
    pub qualification_grant_set_digest: String,
    pub harness_profile_authorization_set_digest: String,
    pub caller_eligibility_digest: String,
    pub publisher_trust_root_digest: String,
    pub action_definition_set_digest: String,
    pub trusted_project_authorization_set_digest: String,
    pub route_set_digest: String,
    pub deny_by_default_policy_digest: String,
    pub recovery_manifest_digest: String,
    pub initial_device_set_digest: String,
    pub qualification_coverage_set_digest: String,
    pub development_qualification_record_digest: String,
    pub prior_root_continuity_record_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentQualificationRecord {
    pub schema: String,
    pub classification: ProductClassification,
    pub attestation_key_fingerprint: String,
    pub executable_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub profile_artifact_digest_list: Vec<ArtifactDigestEntry>,
    pub qualification_grant_set_digest: String,
    pub caller_eligibility_digest: String,
    pub action_definition_set_digest: String,
    pub trusted_project_authorization_set_digest: String,
    pub route_set_digest: String,
    pub qualification_coverage_set_digest: String,
}

#[derive(Debug)]
struct OpenedArtifact {
    artifact_id: String,
    path: PathBuf,
    file: File,
    digest: String,
    executable_identity: String,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentInitializationProof {
    pub manifest: DevelopmentInitializationManifest,
    pub bootstrap_attestation: DevelopmentBootstrapAttestation,
    pub intent: DevelopmentRootInitializationIntent,
    pub intent_signature: String,
    pub qualification_record: DevelopmentQualificationRecord,
    pub records: DevelopmentInitialRecords,
    pub prior_continuity: RootContinuityRecord,
}

#[derive(Debug)]
pub struct DevelopmentInitializationRequest {
    pub manifest: DevelopmentInitializationManifest,
    pub bootstrap_attestation: DevelopmentBootstrapAttestation,
    pub intent: DevelopmentRootInitializationIntent,
    pub intent_signature: String,
    pub qualification_record: DevelopmentQualificationRecord,
    pub records: DevelopmentInitialRecords,
    pub devices: DeviceState,
    pub custody_evidence: DeviceCustodyEvidence,
    pub prior_continuity: RootContinuityRecord,
    artifacts: Vec<OpenedArtifact>,
}

pub struct ValidatedDevelopmentInitialization {
    pub authority_fingerprint: String,
    pub daemon_executable_digest: String,
    pub daemon_executable_identity: String,
    pub registry_bytes: String,
    pub operator_uid: u32,
    pub qualification_grant: QualificationGrantRecord,
    pub caller_eligibility: CallerEligibilityRecord,
    pub harness_profile_authorization: HarnessProfileAuthorization,
    pub trusted_project: TrustedProjectAuthorization,
    pub route: RouteAuthorization,
    pub root_intent_digest: String,
    pub evidence: InitializationEvidence,
    pub continuity_digest: String,
    pub classification: ProductClassification,
}

pub fn build_request(
    project_root: &Path,
    cli_path: &Path,
    daemon_path: &Path,
    now: u64,
) -> Result<DevelopmentInitializationRequest, Refusal> {
    if !project_root.is_absolute() {
        return Err(Refusal::new("project_root_untrusted"));
    }
    let canonical_project =
        fs::canonicalize(project_root).map_err(|_| Refusal::new("project_root_untrusted"))?;
    if canonical_project != project_root || !canonical_project.is_dir() {
        return Err(Refusal::new("project_root_untrusted"));
    }
    let project_root = canonical_project;
    let cli = open_artifact("executable:ember", cli_path)?;
    let daemon = open_artifact("bootstrap:emberd", daemon_path)?;
    let pid = std::process::id();
    let pid_version =
        process_pid_version(pid).map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    let loaded_cli_identity = process_executable_identity(pid, pid_version)
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    if loaded_cli_identity != cli.executable_identity {
        return Err(Refusal::new("bootstrap_artifact_invalid"));
    }
    let expiry = now.saturating_add(7_200);
    let devices = DeviceCustody::generate()?;
    let custody = DeviceCustody::restore(&devices)?;
    let custody_evidence = DeviceCustody::custody_evidence(&devices, "qualification-software")?;
    let authority = authority_fingerprint(&custody.root_public_key().0)?;

    let mut publisher_seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *publisher_seed);
    let publisher_key = SigningKey::from_bytes(&publisher_seed);
    let (publisher, definition) =
        sign_diagnostic_bundle(PUBLISHER_ID, SIGNER_KEY_ID, expiry, now, &publisher_key)?;
    drop(publisher_key);
    publisher_seed.fill(0);

    let profile_artifact = ArtifactDigestEntry {
        artifact_id: "profile:productbase-development-diagnostic".into(),
        digest: sha256(PROFILE_BYTES),
    };
    let executable = ArtifactDigestEntry {
        artifact_id: cli.artifact_id.clone(),
        digest: cli.digest.clone(),
    };
    let bootstrap = ArtifactDigestEntry {
        artifact_id: daemon.artifact_id.clone(),
        digest: daemon.digest.clone(),
    };
    let project_text = project_root
        .to_str()
        .ok_or_else(|| Refusal::new("project_root_untrusted"))?;
    let project = TrustedProjectAuthorization {
        project_root_digest: sha256(project_text.as_bytes()),
        worktree_digest: sha256(project_text.as_bytes()),
        profile_artifact_digest: profile_artifact.digest.clone(),
    };
    let project_digest = digest_encoded(&encode_project(&project)?);
    let grant = QualificationGrantRecord {
        grant_id: "grant:productbase-development-diagnostic".into(),
        principal_id: "principal:operator".into(),
        persona_id: "persona:operator:local".into(),
        action_definition_digest: definition.action_definition_digest.clone(),
        target: "pb-r2-ok".into(),
        permission: "authority.status.read".into(),
        material_class: "non_secret".into(),
        provider: "ember.local".into(),
        protocol: "ember.local".into(),
        destination: "authority-journal".into(),
        operation_class: "diagnostic.read".into(),
        request_count_ceiling: 1,
        byte_budget: 65_536,
        rate_ceiling: 1,
        offline_bound: false,
        expiry,
    };
    let profile = HarnessProfileAuthorization {
        profile_id: "productbase-development-diagnostic".into(),
        artifact_digest: profile_artifact.digest.clone(),
        executable_digest: executable.digest.clone(),
        launch_scope: "provisional".into(),
    };
    let caller = CallerEligibilityRecord {
        principal_id: grant.principal_id.clone(),
        persona_id: grant.persona_id.clone(),
        operator_uid: crate::effective_uid(),
        profile_artifact_digest: profile.artifact_digest.clone(),
        executable_digest: executable.digest.clone(),
        executable_identity: cli.executable_identity.clone(),
        trusted_project_digest: project_digest,
        maintenance_window_expiry: expiry,
    };
    let records = DevelopmentInitialRecords {
        qualification_grants: vec![grant],
        harness_profile_authorizations: vec![profile],
        caller_eligibility: vec![caller],
        publisher_trust_roots: vec![publisher],
        action_definitions: vec![definition],
        trusted_projects: vec![project],
        routes: vec![RouteAuthorization {
            route_id: "route:development-diagnostic:sealed-exec".into(),
            action_definition_digest: String::new(),
            runner_class: "builtin".into(),
            delivery_lane: "sealed-exec".into(),
            credential_slot: None,
        }],
        policy: DenyByDefaultPolicy {
            schema: "ember.deny-by-default-policy/v1".into(),
            default_decision: "deny".into(),
            credential_delivery: "forbidden".into(),
        },
        recovery_manifest: RecoveryManifest {
            schema: "ember.recovery-manifest/v1".into(),
            mode: "qualification-no-recovery".into(),
            reconstruction_quorum: 0,
            recipient_fingerprints: vec![],
        },
        coverage: InitialQualificationCoverageSet {
            schema: "ember.initial-qualification-coverage-set/v1".into(),
            deployment_class: "disposable-qualification".into(),
            initialization: "provisional".into(),
            session_action_receipt: "provisional".into(),
            recovery: "not_applicable".into(),
            production_credentials: "forbidden".into(),
            federation: "not_applicable".into(),
        },
    };
    let mut records = records;
    records.routes[0].action_definition_digest = records.action_definitions[0]
        .action_definition_digest
        .clone();
    let digests = records.digests()?;
    let classification = ProductClassification::development_diagnostic();

    let mut attestation_seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *attestation_seed);
    let attestation_key = SigningKey::from_bytes(&attestation_seed);
    let attestation_public_key = format!(
        "ed25519:{}",
        hex::encode(attestation_key.verifying_key().to_bytes())
    );
    let attestation_key_fingerprint =
        signing_key_fingerprint(&attestation_public_key, "development-bootstrap-attestation")?;
    let qualification_record = DevelopmentQualificationRecord {
        schema: "ember.development-qualification-record/v1".into(),
        classification: classification.clone(),
        attestation_key_fingerprint: attestation_key_fingerprint.clone(),
        executable_artifact_digest_list: vec![executable.clone()],
        profile_artifact_digest_list: vec![profile_artifact.clone()],
        qualification_grant_set_digest: digests.grant_set.clone(),
        caller_eligibility_digest: digests.caller_set.clone(),
        action_definition_set_digest: digests.definition_set.clone(),
        trusted_project_authorization_set_digest: digests.project_set.clone(),
        route_set_digest: digests.route_set.clone(),
        qualification_coverage_set_digest: digests.coverage.clone(),
    };
    let qualification_record_digest =
        digest_encoded(&encode_development_qualification(&qualification_record)?);
    let continuity = RootContinuityRecord {
        schema: "ember.root-continuity-record/v1".into(),
        generation: 0,
        authority_fingerprint: authority,
        prior_record_digest: ZERO_DIGEST.into(),
        protected_tip_digest: ZERO_DIGEST.into(),
        slot_id: "qualification-slot-0".into(),
    };
    let continuity_digest = digest_encoded(&encode_continuity(&continuity)?);
    let manifest = DevelopmentInitializationManifest {
        schema: "ember.development-initialization-manifest/v1".into(),
        bootstrap_artifact_digest_list: vec![bootstrap],
        executable_artifact_digest_list: vec![executable],
        profile_artifact_digest_list: vec![profile_artifact],
        deny_by_default_policy_digest: digests.policy.clone(),
        recovery_manifest_digest: digests.recovery.clone(),
        qualification_grant_set_digest: digests.grant_set.clone(),
        harness_profile_authorization_set_digest: digests.profile_set.clone(),
        caller_eligibility_digest: digests.caller_set.clone(),
        publisher_trust_root_digest: digests.publisher_set.clone(),
        action_definition_set_digest: digests.definition_set.clone(),
        trusted_project_authorization_set_digest: digests.project_set.clone(),
        route_set_digest: digests.route_set.clone(),
        qualification_coverage_set_digest: digests.coverage.clone(),
        development_qualification_record_digest: qualification_record_digest.clone(),
        prior_root_continuity_record_digest: continuity_digest.clone(),
        issuance: now,
        expiry,
    };
    let manifest_bytes = encode_development_manifest(&manifest)?;
    let manifest_digest = digest_encoded(&manifest_bytes);
    let mut attestation_preimage = ATTESTATION_DOMAIN.to_vec();
    attestation_preimage.extend_from_slice(&manifest_bytes);
    let bootstrap_attestation = DevelopmentBootstrapAttestation {
        development_manifest_digest: manifest_digest.clone(),
        attestation_public_key,
        attestation_key_fingerprint,
        attestation_signature: format!(
            "ed25519sig:{}",
            hex::encode(attestation_key.sign(&attestation_preimage).to_bytes())
        ),
    };
    drop(attestation_key);
    attestation_seed.fill(0);
    let attestation_digest = sha256(
        &serde_jcs::to_vec(&bootstrap_attestation)
            .map_err(|_| Refusal::new("development_attestation_invalid"))?,
    );
    let intent = DevelopmentRootInitializationIntent {
        development_manifest_digest: manifest_digest,
        development_bootstrap_attestation_digest: attestation_digest,
        root_verification_public_key: custody.root_public_key().0,
        initial_principal_id: records.qualification_grants[0].principal_id.clone(),
        initial_persona_id: records.qualification_grants[0].persona_id.clone(),
        qualification_grant_set_digest: digests.grant_set,
        harness_profile_authorization_set_digest: digests.profile_set,
        caller_eligibility_digest: digests.caller_set,
        publisher_trust_root_digest: digests.publisher_set,
        action_definition_set_digest: digests.definition_set,
        trusted_project_authorization_set_digest: digests.project_set,
        route_set_digest: digests.route_set,
        deny_by_default_policy_digest: digests.policy,
        recovery_manifest_digest: digests.recovery,
        initial_device_set_digest: device_set_digest(&devices)?,
        qualification_coverage_set_digest: digests.coverage,
        development_qualification_record_digest: qualification_record_digest,
        prior_root_continuity_record_digest: continuity_digest,
    };
    let intent_signature = custody
        .root_signer()?
        .sign(&encode_development_intent(&intent)?)
        .0;
    Ok(DevelopmentInitializationRequest {
        manifest,
        bootstrap_attestation,
        intent,
        intent_signature,
        qualification_record,
        records,
        devices,
        custody_evidence,
        prior_continuity: continuity,
        artifacts: vec![daemon, cli],
    })
}

impl DevelopmentInitializationRequest {
    pub fn proof(&self) -> DevelopmentInitializationProof {
        DevelopmentInitializationProof {
            manifest: self.manifest.clone(),
            bootstrap_attestation: self.bootstrap_attestation.clone(),
            intent: self.intent.clone(),
            intent_signature: self.intent_signature.clone(),
            qualification_record: self.qualification_record.clone(),
            records: self.records.clone(),
            prior_continuity: self.prior_continuity.clone(),
        }
    }

    pub fn validate(&self, now: u64) -> Result<ValidatedDevelopmentInitialization, Refusal> {
        let classification = ProductClassification::development_diagnostic();
        let manifest_bytes = encode_development_manifest(&self.manifest)?;
        let manifest_digest = digest_encoded(&manifest_bytes);
        if self.manifest.schema != "ember.development-initialization-manifest/v1"
            || self.manifest.issuance > now
            || now >= self.manifest.expiry
            || self.bootstrap_attestation.development_manifest_digest != manifest_digest
            || self.qualification_record.schema != "ember.development-qualification-record/v1"
            || self.qualification_record.classification != classification
        {
            return Err(Refusal::new("development_manifest_invalid"));
        }
        let attestation_fingerprint = signing_key_fingerprint(
            &self.bootstrap_attestation.attestation_public_key,
            "development-bootstrap-attestation",
        )?;
        let mut attestation_preimage = ATTESTATION_DOMAIN.to_vec();
        attestation_preimage.extend_from_slice(&manifest_bytes);
        if attestation_fingerprint != self.bootstrap_attestation.attestation_key_fingerprint
            || attestation_fingerprint != self.qualification_record.attestation_key_fingerprint
            || !core_crypto::Ed25519Verifier.verify(
                &PublicKey(self.bootstrap_attestation.attestation_public_key.clone()),
                &attestation_preimage,
                &Signature(self.bootstrap_attestation.attestation_signature.clone()),
            )
        {
            return Err(Refusal::new("development_attestation_invalid"));
        }
        validate_artifacts(self)?;
        let digests = self.records.digests()?;
        let qualification_digest = digest_encoded(&encode_development_qualification(
            &self.qualification_record,
        )?);
        let continuity_digest = digest_encoded(&encode_continuity(&self.prior_continuity)?);
        let attestation_digest = sha256(
            &serde_jcs::to_vec(&self.bootstrap_attestation)
                .map_err(|_| Refusal::new("development_attestation_invalid"))?,
        );
        let custody = DeviceCustody::restore(&self.devices)?;
        DeviceCustody::verify_custody_evidence(&self.devices, &self.custody_evidence)?;
        let authority = authority_fingerprint(&custody.root_public_key().0)?;
        let intent_bytes = encode_development_intent(&self.intent)?;
        if self.intent.root_verification_public_key != custody.root_public_key().0
            || self.intent.initial_device_set_digest != device_set_digest(&self.devices)?
            || !core_crypto::Ed25519Verifier.verify(
                &custody.root_public_key(),
                &intent_bytes,
                &Signature(self.intent_signature.clone()),
            )
        {
            return Err(Refusal::new("root_intent_signature_invalid"));
        }
        let intent_matches = self.intent.development_manifest_digest == manifest_digest
            && self.intent.development_bootstrap_attestation_digest == attestation_digest
            && self.intent.qualification_grant_set_digest == digests.grant_set
            && self.intent.harness_profile_authorization_set_digest == digests.profile_set
            && self.intent.caller_eligibility_digest == digests.caller_set
            && self.intent.publisher_trust_root_digest == digests.publisher_set
            && self.intent.action_definition_set_digest == digests.definition_set
            && self.intent.trusted_project_authorization_set_digest == digests.project_set
            && self.intent.route_set_digest == digests.route_set
            && self.intent.deny_by_default_policy_digest == digests.policy
            && self.intent.recovery_manifest_digest == digests.recovery
            && self.intent.qualification_coverage_set_digest == digests.coverage
            && self.intent.development_qualification_record_digest == qualification_digest
            && self.intent.prior_root_continuity_record_digest == continuity_digest;
        let manifest_matches = self.manifest.deny_by_default_policy_digest == digests.policy
            && self.manifest.recovery_manifest_digest == digests.recovery
            && self.manifest.qualification_grant_set_digest == digests.grant_set
            && self.manifest.harness_profile_authorization_set_digest == digests.profile_set
            && self.manifest.caller_eligibility_digest == digests.caller_set
            && self.manifest.publisher_trust_root_digest == digests.publisher_set
            && self.manifest.action_definition_set_digest == digests.definition_set
            && self.manifest.trusted_project_authorization_set_digest == digests.project_set
            && self.manifest.route_set_digest == digests.route_set
            && self.manifest.qualification_coverage_set_digest == digests.coverage
            && self.manifest.development_qualification_record_digest == qualification_digest
            && self.manifest.prior_root_continuity_record_digest == continuity_digest;
        if !intent_matches || !manifest_matches {
            return Err(Refusal::new("development_manifest_invalid"));
        }
        let grant = exactly_one(&self.records.qualification_grants)?;
        let profile = exactly_one(&self.records.harness_profile_authorizations)?;
        let caller = exactly_one(&self.records.caller_eligibility)?;
        let publisher = exactly_one(&self.records.publisher_trust_roots)?;
        let definition = exactly_one(&self.records.action_definitions)?;
        let project = exactly_one(&self.records.trusted_projects)?;
        let route = exactly_one(&self.records.routes)?;
        if self.intent.initial_principal_id != grant.principal_id
            || self.intent.initial_persona_id != grant.persona_id
            || caller.principal_id != grant.principal_id
            || caller.persona_id != grant.persona_id
            || caller.operator_uid != crate::effective_uid()
            || caller.profile_artifact_digest != profile.artifact_digest
            || caller.executable_digest != profile.executable_digest
            || grant.action_definition_digest != definition.action_definition_digest
            || route.action_definition_digest != definition.action_definition_digest
            || route.credential_slot.is_some()
            || self.records.policy.default_decision != "deny"
            || self.records.policy.credential_delivery != "forbidden"
            || grant.material_class != "non_secret"
            || self.records.coverage.deployment_class != "disposable-qualification"
            || self.records.coverage.production_credentials != "forbidden"
            || self.prior_continuity.generation != 0
            || self.prior_continuity.authority_fingerprint != authority
        {
            return Err(Refusal::new("development_initialization_invalid"));
        }
        let registry_bytes = ActionDefinitionRegistry::initialize(publisher, definition)?;
        let daemon = self
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == "bootstrap:emberd")
            .ok_or_else(|| Refusal::new("bootstrap_artifact_invalid"))?;
        Ok(ValidatedDevelopmentInitialization {
            authority_fingerprint: authority,
            daemon_executable_digest: daemon.digest.clone(),
            daemon_executable_identity: daemon.executable_identity.clone(),
            registry_bytes,
            operator_uid: caller.operator_uid,
            qualification_grant: grant.clone(),
            caller_eligibility: caller.clone(),
            harness_profile_authorization: profile.clone(),
            trusted_project: project.clone(),
            route: route.clone(),
            root_intent_digest: digest_encoded(&intent_bytes),
            evidence: InitializationEvidence::Development {
                qualification_manifest_digest: manifest_digest,
                qualification_bootstrap_attestation_digest: attestation_digest,
                qualification_record_digest: qualification_digest,
            },
            continuity_digest,
            classification,
        })
    }
}

pub fn verify_persisted_development(
    state: &crate::model::PersistentAuthorityState,
) -> Result<(), Refusal> {
    let proof = state
        .development_initialization
        .as_ref()
        .ok_or_else(|| Refusal::new("development_initialization_invalid"))?;
    let manifest_bytes = encode_development_manifest(&proof.manifest)?;
    let manifest_digest = digest_encoded(&manifest_bytes);
    let attestation_bytes = serde_jcs::to_vec(&proof.bootstrap_attestation)
        .map_err(|_| Refusal::new("development_attestation_invalid"))?;
    let attestation_digest = sha256(&attestation_bytes);
    let qualification_digest = digest_encoded(&encode_development_qualification(
        &proof.qualification_record,
    )?);
    let continuity_digest = digest_encoded(&encode_continuity(&proof.prior_continuity)?);
    let InitializationEvidence::Development {
        qualification_manifest_digest,
        qualification_bootstrap_attestation_digest,
        qualification_record_digest,
    } = &state.initialization.evidence
    else {
        return Err(Refusal::new("development_initialization_invalid"));
    };
    if state.classification != ProductClassification::development_diagnostic()
        || proof.qualification_record.classification != state.classification
        || manifest_digest != *qualification_manifest_digest
        || attestation_digest != *qualification_bootstrap_attestation_digest
        || qualification_digest != *qualification_record_digest
        || continuity_digest != state.initialization.continuity_digest
        || digest_encoded(&encode_development_intent(&proof.intent)?)
            != state.initialization.root_intent_digest
    {
        return Err(Refusal::new("development_initialization_invalid"));
    }
    let attestation_fingerprint = signing_key_fingerprint(
        &proof.bootstrap_attestation.attestation_public_key,
        "development-bootstrap-attestation",
    )?;
    let mut attestation_preimage = ATTESTATION_DOMAIN.to_vec();
    attestation_preimage.extend_from_slice(&manifest_bytes);
    if proof.bootstrap_attestation.development_manifest_digest != manifest_digest
        || proof.bootstrap_attestation.attestation_key_fingerprint != attestation_fingerprint
        || proof.qualification_record.attestation_key_fingerprint != attestation_fingerprint
        || !core_crypto::Ed25519Verifier.verify(
            &PublicKey(proof.bootstrap_attestation.attestation_public_key.clone()),
            &attestation_preimage,
            &Signature(proof.bootstrap_attestation.attestation_signature.clone()),
        )
    {
        return Err(Refusal::new("development_attestation_invalid"));
    }
    let custody = DeviceCustody::restore(&state.devices)?;
    let authority = authority_fingerprint(&custody.root_public_key().0)?;
    let intent_bytes = encode_development_intent(&proof.intent)?;
    if proof.intent.root_verification_public_key != custody.root_public_key().0
        || proof.intent.initial_device_set_digest != device_set_digest(&state.devices)?
        || !core_crypto::Ed25519Verifier.verify(
            &custody.root_public_key(),
            &intent_bytes,
            &Signature(proof.intent_signature.clone()),
        )
        || authority != state.authority_fingerprint
        || proof.prior_continuity.authority_fingerprint != authority
        || proof.prior_continuity.generation != 0
    {
        return Err(Refusal::new("root_intent_signature_invalid"));
    }
    let digests = proof.records.digests()?;
    let intent_matches = proof.intent.development_manifest_digest == manifest_digest
        && proof.intent.development_bootstrap_attestation_digest == attestation_digest
        && proof.intent.qualification_grant_set_digest == digests.grant_set
        && proof.intent.harness_profile_authorization_set_digest == digests.profile_set
        && proof.intent.caller_eligibility_digest == digests.caller_set
        && proof.intent.publisher_trust_root_digest == digests.publisher_set
        && proof.intent.action_definition_set_digest == digests.definition_set
        && proof.intent.trusted_project_authorization_set_digest == digests.project_set
        && proof.intent.route_set_digest == digests.route_set
        && proof.intent.deny_by_default_policy_digest == digests.policy
        && proof.intent.recovery_manifest_digest == digests.recovery
        && proof.intent.qualification_coverage_set_digest == digests.coverage
        && proof.intent.development_qualification_record_digest == qualification_digest
        && proof.intent.prior_root_continuity_record_digest == continuity_digest;
    let manifest_matches = proof.manifest.qualification_grant_set_digest == digests.grant_set
        && proof.manifest.harness_profile_authorization_set_digest == digests.profile_set
        && proof.manifest.caller_eligibility_digest == digests.caller_set
        && proof.manifest.publisher_trust_root_digest == digests.publisher_set
        && proof.manifest.action_definition_set_digest == digests.definition_set
        && proof.manifest.trusted_project_authorization_set_digest == digests.project_set
        && proof.manifest.route_set_digest == digests.route_set
        && proof.manifest.deny_by_default_policy_digest == digests.policy
        && proof.manifest.recovery_manifest_digest == digests.recovery
        && proof.manifest.qualification_coverage_set_digest == digests.coverage
        && proof.manifest.development_qualification_record_digest == qualification_digest
        && proof.manifest.prior_root_continuity_record_digest == continuity_digest;
    if !intent_matches || !manifest_matches {
        return Err(Refusal::new("development_manifest_invalid"));
    }
    let grant = exactly_one(&proof.records.qualification_grants)?;
    let profile = exactly_one(&proof.records.harness_profile_authorizations)?;
    let caller = exactly_one(&proof.records.caller_eligibility)?;
    let publisher = exactly_one(&proof.records.publisher_trust_roots)?;
    let definition = exactly_one(&proof.records.action_definitions)?;
    let project = exactly_one(&proof.records.trusted_projects)?;
    let route = exactly_one(&proof.records.routes)?;
    let registry_bytes = ActionDefinitionRegistry::initialize(publisher, definition)?;
    let bootstrap_digest = exactly_one(&proof.manifest.bootstrap_artifact_digest_list)?;
    if grant != &state.qualification_grant
        || profile != &state.harness_profile_authorization
        || caller != &state.caller_eligibility
        || project != &state.trusted_project
        || route != &state.route
        || registry_bytes != state.registry_bytes
        || bootstrap_digest.artifact_id != "bootstrap:emberd"
        || bootstrap_digest.digest != state.daemon_executable_digest
        || proof.qualification_record.executable_artifact_digest_list
            != proof.manifest.executable_artifact_digest_list
        || proof.qualification_record.profile_artifact_digest_list
            != proof.manifest.profile_artifact_digest_list
    {
        return Err(Refusal::new("development_initialization_invalid"));
    }
    Ok(())
}

pub fn validate_new_state_root(root: &Path) -> Result<(), Refusal> {
    match fs::symlink_metadata(root) {
        Ok(_) => return Err(Refusal::new("already_initialized")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Refusal::new("state_root_untrusted")),
    }
    for path in continuity_paths(root)? {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(Refusal::new("continuity_unavailable")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Refusal::new("state_root_untrusted")),
        }
    }
    validate_state_root(root, false, true)
}
fn continuity_paths(root: &Path) -> Result<[PathBuf; 3], Refusal> {
    let parent = root
        .parent()
        .ok_or_else(|| Refusal::new("state_root_untrusted"))?;
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| Refusal::new("state_root_untrusted"))?;
    Ok([
        parent.join(format!("{name}.continuity.json")),
        parent.join(format!("{name}.continuity.next.json")),
        parent.join(format!("{name}.high-water.json")),
    ])
}

pub fn validate_existing_state_root(root: &Path) -> Result<(), Refusal> {
    validate_state_root(root, true, false)
}

pub fn validate_development_state_root(root: &Path) -> Result<(), Refusal> {
    validate_state_root(root, true, true)
}

fn validate_state_root(root: &Path, present: bool, exact_parent: bool) -> Result<(), Refusal> {
    if !root.is_absolute() {
        return Err(Refusal::new("state_root_untrusted"));
    }
    let parent = root
        .parent()
        .ok_or_else(|| Refusal::new("state_root_untrusted"))?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| Refusal::new("state_root_untrusted"))?;
    if canonical_parent != parent {
        return Err(Refusal::new("state_root_untrusted"));
    }
    if exact_parent {
        validate_disposable_parent(parent)?;
    } else {
        validate_owned_parent(parent)?;
    }
    if present {
        let metadata =
            fs::symlink_metadata(root).map_err(|_| Refusal::new("state_root_unavailable"))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || fs::canonicalize(root).ok().as_deref() != Some(root)
        {
            return Err(Refusal::new("state_root_untrusted"));
        }
        validate_private_directory(root)?;
    }
    let expected_uid = crate::effective_uid();
    let mut ancestor = parent.parent();
    while let Some(path) = ancestor {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| Refusal::new("state_root_untrusted"))?;
        let mode = metadata.mode();
        let owner_ok = metadata.uid() == expected_uid || metadata.uid() == 0;
        let writable_ok =
            mode & 0o022 == 0 || (metadata.uid() == 0 && mode & libc::S_ISVTX as u32 != 0);
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || !owner_ok
            || !writable_ok
        {
            return Err(Refusal::new("state_root_untrusted"));
        }
        ancestor = path.parent();
    }
    Ok(())
}

fn validate_owned_parent(path: &Path) -> Result<(), Refusal> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal::new("state_root_untrusted"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Refusal::new("state_root_untrusted"));
    }
    Ok(())
}

fn validate_disposable_parent(path: &Path) -> Result<(), Refusal> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal::new("state_root_untrusted"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(Refusal::new("state_root_untrusted"));
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), Refusal> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Refusal::new("state_root_untrusted"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(Refusal::new("state_root_untrusted"));
    }
    Ok(())
}

fn open_artifact(artifact_id: &str, path: &Path) -> Result<OpenedArtifact, Refusal> {
    let source =
        fs::symlink_metadata(path).map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    if source.file_type().is_symlink() || !source.file_type().is_file() {
        return Err(Refusal::new("bootstrap_artifact_invalid"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    if !metadata.is_file()
        || metadata.len() > ARTIFACT_LIMIT
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Refusal::new("bootstrap_artifact_invalid"));
    }
    let digest = digest_file(&file)?;
    let executable_identity = executable_identity_from_file(&file)
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    Ok(OpenedArtifact {
        artifact_id: artifact_id.into(),
        path: path.to_owned(),
        file,
        digest,
        executable_identity,
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

fn validate_artifacts(request: &DevelopmentInitializationRequest) -> Result<(), Refusal> {
    if request.artifacts.len() != 2
        || request.manifest.bootstrap_artifact_digest_list.len() != 1
        || request.manifest.executable_artifact_digest_list.len() != 1
        || request.manifest.profile_artifact_digest_list
            != [ArtifactDigestEntry {
                artifact_id: "profile:productbase-development-diagnostic".into(),
                digest: sha256(PROFILE_BYTES),
            }]
    {
        return Err(Refusal::new("bootstrap_artifact_invalid"));
    }
    for artifact in &request.artifacts {
        let current = fs::symlink_metadata(&artifact.path)
            .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
        let current_digest = digest_file(&artifact.file)?;
        let current_identity = executable_identity_from_file(&artifact.file)
            .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
        if current.file_type().is_symlink()
            || !current.file_type().is_file()
            || current.dev() != artifact.dev
            || current.ino() != artifact.ino
            || current.uid() != artifact.uid
            || current.mode() != artifact.mode
            || current_digest != artifact.digest
            || current_identity != artifact.executable_identity
        {
            return Err(Refusal::new("bootstrap_artifact_invalid"));
        }
        let expected = if artifact.artifact_id == "bootstrap:emberd" {
            &request.manifest.bootstrap_artifact_digest_list
        } else if artifact.artifact_id == "executable:ember" {
            &request.manifest.executable_artifact_digest_list
        } else {
            return Err(Refusal::new("bootstrap_artifact_invalid"));
        };
        if expected.as_slice()
            != [ArtifactDigestEntry {
                artifact_id: artifact.artifact_id.clone(),
                digest: artifact.digest.clone(),
            }]
        {
            return Err(Refusal::new("bootstrap_artifact_invalid"));
        }
    }
    Ok(())
}

fn digest_file(file: &File) -> Result<String, Refusal> {
    let mut reader = file
        .try_clone()
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    reader
        .rewind()
        .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| Refusal::new("bootstrap_artifact_invalid"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn exactly_one<T>(values: &[T]) -> Result<&T, Refusal> {
    match values {
        [value] => Ok(value),
        _ => Err(Refusal::new("development_initialization_invalid")),
    }
}

fn encode_artifact(value: &ArtifactDigestEntry) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new("ember/development-artifact-digest-entry/v1")?;
    encoder.string(&value.artifact_id)?.digest(&value.digest)?;
    Ok(encoder.finish())
}

pub fn encode_development_manifest(
    value: &DevelopmentInitializationManifest,
) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new(MANIFEST_DOMAIN)?;
    encoder
        .string(&value.schema)?
        .list(&value.bootstrap_artifact_digest_list, encode_artifact)?
        .list(&value.executable_artifact_digest_list, encode_artifact)?
        .list(&value.profile_artifact_digest_list, encode_artifact)?
        .digest(&value.deny_by_default_policy_digest)?
        .digest(&value.recovery_manifest_digest)?
        .digest(&value.qualification_grant_set_digest)?
        .digest(&value.harness_profile_authorization_set_digest)?
        .digest(&value.caller_eligibility_digest)?
        .digest(&value.publisher_trust_root_digest)?
        .digest(&value.action_definition_set_digest)?
        .digest(&value.trusted_project_authorization_set_digest)?
        .digest(&value.route_set_digest)?
        .digest(&value.qualification_coverage_set_digest)?
        .digest(&value.development_qualification_record_digest)?
        .digest(&value.prior_root_continuity_record_digest)?
        .u64(value.issuance)
        .u64(value.expiry);
    Ok(encoder.finish())
}

pub fn encode_development_intent(
    value: &DevelopmentRootInitializationIntent,
) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new(INTENT_DOMAIN)?;
    encoder
        .digest(&value.development_manifest_digest)?
        .digest(&value.development_bootstrap_attestation_digest)?
        .string(&value.root_verification_public_key)?
        .string(&value.initial_principal_id)?
        .string(&value.initial_persona_id)?
        .digest(&value.qualification_grant_set_digest)?
        .digest(&value.harness_profile_authorization_set_digest)?
        .digest(&value.caller_eligibility_digest)?
        .digest(&value.publisher_trust_root_digest)?
        .digest(&value.action_definition_set_digest)?
        .digest(&value.trusted_project_authorization_set_digest)?
        .digest(&value.route_set_digest)?
        .digest(&value.deny_by_default_policy_digest)?
        .digest(&value.recovery_manifest_digest)?
        .digest(&value.initial_device_set_digest)?
        .digest(&value.qualification_coverage_set_digest)?
        .digest(&value.development_qualification_record_digest)?
        .digest(&value.prior_root_continuity_record_digest)?;
    Ok(encoder.finish())
}

pub fn encode_development_qualification(
    value: &DevelopmentQualificationRecord,
) -> Result<Vec<u8>, Refusal> {
    let mut encoder = LenEncoder::new(QUALIFICATION_DOMAIN)?;
    encoder
        .string(&value.schema)?
        .string(&value.classification.schema)?
        .string(&value.classification.qualification_mode)?
        .string(&value.classification.qualification_state)?
        .string(&value.classification.deployment_class)?
        .bool(value.classification.development_only)
        .string(&value.classification.production_classification)?
        .string(&value.classification.secret_classification)?
        .string(&value.classification.release_provenance)?
        .string(&value.classification.credential_use)?
        .digest(&value.attestation_key_fingerprint)?
        .list(&value.executable_artifact_digest_list, encode_artifact)?
        .list(&value.profile_artifact_digest_list, encode_artifact)?
        .digest(&value.qualification_grant_set_digest)?
        .digest(&value.caller_eligibility_digest)?
        .digest(&value.action_definition_set_digest)?
        .digest(&value.trusted_project_authorization_set_digest)?
        .digest(&value.route_set_digest)?
        .digest(&value.qualification_coverage_set_digest)?;
    Ok(encoder.finish())
}
