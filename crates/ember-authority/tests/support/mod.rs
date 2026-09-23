use core_crypto::Signer as _;
use ed25519_dalek::{Signer as _, SigningKey};
use ember_authority::{
    action_definition::{PUBLISHER_ID, PUBLISHER_NOT_AFTER, PUBLISHER_PUBLIC_KEY, SIGNER_KEY_ID},
    audit::{now_unix, sha256},
    control::AuthorityControl,
    device::{DeviceCustody, authority_fingerprint, device_set_digest, signing_key_fingerprint},
    initialization::{
        ActivationQualificationPlan, ArtifactDigestEntry, ArtifactSource,
        AuthorityControlReleaseQualificationRecord, CallerEligibilityRecord, DenyByDefaultPolicy,
        HarnessProfileAuthorization, InitialActionDefinitionRecord,
        InitialQualificationCoverageSet, InitialRecords, InitializationRequest,
        ProductBaseReleaseManifest, ProductBaseReleaseManifestEnvelope, PublisherTrustRoot,
        QualificationGrantRecord, RecoveryManifest, ReleaseVerificationAnchor,
        RootContinuityRecord, RootInitializationIntent, RouteAuthorization,
        TrustedProjectAuthorization, digest_encoded, encode_activation_plan, encode_continuity,
        encode_project, encode_release_manifest, encode_root_intent,
    },
    model::{DEFINITION_DIGEST, signed_bundle_bytes},
};
use std::{fs, path::Path};
use tempfile::TempDir;

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const RELEASE_SEED: [u8; 32] = [7; 32];

pub fn authority(target: &str) -> (TempDir, AuthorityControl) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("authority");
    let request = request(directory.path(), target);
    let anchor = anchor();
    let (control, _) =
        AuthorityControl::initialize_at(&root, request, &anchor, now_unix()).unwrap();
    (directory, control)
}

pub fn request(directory: &Path, target: &str) -> InitializationRequest {
    let bootstrap_path = directory.join("bootstrap.bin");
    let executable_path = directory.join("ember.bin");
    fs::write(&bootstrap_path, b"reviewed emberd fixture").unwrap();
    fs::write(&executable_path, b"reviewed ember fixture").unwrap();
    request_for_runtime(directory, target, bootstrap_path, executable_path)
}

pub fn request_for_runtime(
    directory: &Path,
    target: &str,
    bootstrap_path: std::path::PathBuf,
    executable_path: std::path::PathBuf,
) -> InitializationRequest {
    let now = now_unix();
    let expiry = now.saturating_add(3_600);
    let devices = AuthorityControl::generate_devices().unwrap();
    let custody = DeviceCustody::restore(&devices).unwrap();
    let custody_evidence =
        DeviceCustody::custody_evidence(&devices, "qualification-software").unwrap();
    let authority = authority_fingerprint(&custody.root_public_key().0).unwrap();
    let profile_path = directory.join("profile.json");
    fs::write(&profile_path, b"{\"profile\":\"productbase-s4\"}").unwrap();
    let bootstrap = ArtifactDigestEntry {
        artifact_id: "bootstrap:emberd".into(),
        digest: sha256(&fs::read(&bootstrap_path).unwrap()),
    };
    let executable = ArtifactDigestEntry {
        artifact_id: "executable:ember".into(),
        digest: sha256(&fs::read(&executable_path).unwrap()),
    };
    let profile_artifact = ArtifactDigestEntry {
        artifact_id: "profile:productbase-s4".into(),
        digest: sha256(&fs::read(&profile_path).unwrap()),
    };

    let project = TrustedProjectAuthorization {
        project_root_digest: sha256(b"productbase-s4-project-root"),
        worktree_digest: sha256(b"productbase-s4-worktree"),
        profile_artifact_digest: profile_artifact.digest.clone(),
    };
    let project_digest = digest_encoded(&encode_project(&project).unwrap());
    let grant = QualificationGrantRecord {
        grant_id: "grant:productbase-s4-diagnostic".into(),
        principal_id: "principal:operator".into(),
        persona_id: format!("persona:operator:{}", ember_authority::effective_uid()),
        action_definition_digest: DEFINITION_DIGEST.into(),
        target: target.into(),
        permission: "authority.status.read".into(),
        material_class: "non_secret".into(),
        provider: "ember.local".into(),
        protocol: "local".into(),
        destination: "daemon".into(),
        operation_class: "read_only_diagnostic".into(),
        request_count_ceiling: 1,
        byte_budget: 65_536,
        rate_ceiling: 1,
        expiry,
    };
    let profile = HarnessProfileAuthorization {
        profile_id: "productbase-s4-diagnostic".into(),
        artifact_digest: profile_artifact.digest.clone(),
        executable_digest: executable.digest.clone(),
        launch_scope: "qualification-only".into(),
    };
    let caller = CallerEligibilityRecord {
        principal_id: grant.principal_id.clone(),
        persona_id: grant.persona_id.clone(),
        operator_uid: ember_authority::effective_uid(),
        profile_artifact_digest: profile.artifact_digest.clone(),
        executable_digest: executable.digest.clone(),
        trusted_project_digest: project_digest,
        maintenance_window_expiry: expiry,
    };
    let mut records = InitialRecords {
        qualification_grants: vec![grant],
        harness_profile_authorizations: vec![profile.clone()],
        caller_eligibility: vec![caller],
        publisher_trust_roots: vec![PublisherTrustRoot {
            publisher_id: PUBLISHER_ID.into(),
            signer_key_id: SIGNER_KEY_ID.into(),
            public_key: PUBLISHER_PUBLIC_KEY.into(),
            not_after: PUBLISHER_NOT_AFTER,
        }],
        action_definitions: vec![InitialActionDefinitionRecord {
            action_definition_digest: DEFINITION_DIGEST.into(),
            signed_bundle: signed_bundle_bytes(),
        }],
        trusted_projects: vec![project],
        routes: vec![RouteAuthorization {
            route_id: "route:diagnostic:sealed-exec".into(),
            action_definition_digest: DEFINITION_DIGEST.into(),
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
            initialization: "unqualified".into(),
            session_action_receipt: "unqualified".into(),
            recovery: "not_applicable".into(),
            production_credentials: "not_applicable".into(),
            federation: "not_applicable".into(),
        },
        release_qualification: AuthorityControlReleaseQualificationRecord {
            manifest_version: "productbase-s4/v1".into(),
            manifest_digest: ZERO_DIGEST.into(),
            executable_artifact_digest_list: vec![executable.clone()],
            profile_artifact_digest_list: vec![profile_artifact.clone()],
            rollback_manifest_digest: None,
            activation_qualification_plan_digest: ZERO_DIGEST.into(),
            release_signing_trust_root_fingerprint: release_trust_root(),
            release_signing_trust_root_version: 1,
            qualification_state: "qualification-only".into(),
            record_revision: 1,
        },
    };
    let preliminary = records.digests().unwrap();
    let plan = ActivationQualificationPlan {
        qualification_principal_id: "principal:operator".into(),
        qualification_persona_id: format!("persona:operator:{}", ember_authority::effective_uid()),
        qualification_harness_profile_artifact_digest: profile.artifact_digest.clone(),
        qualification_harness_profile_authorization_set_digest: preliminary.profile_set.clone(),
        qualification_grant_set_digest: preliminary.grant_set.clone(),
        qualification_action_definition_set_digest: preliminary.definition_set.clone(),
        qualification_trusted_project_authorization_set_digest: preliminary.project_set.clone(),
        qualification_route_set_digest: preliminary.route_set.clone(),
        caller_eligibility_digest: preliminary.caller_set.clone(),
        maintenance_window_expiry: expiry,
    };
    let plan_digest = digest_encoded(&encode_activation_plan(&plan).unwrap());
    let release_key = SigningKey::from_bytes(&RELEASE_SEED);
    let release_public_key = format!(
        "ed25519:{}",
        hex::encode(release_key.verifying_key().to_bytes())
    );
    let manifest = ProductBaseReleaseManifest {
        manifest_version: "productbase-s4/v1".into(),
        release_signer_key_fingerprint: signing_key_fingerprint(
            &release_public_key,
            "release-signing",
        )
        .unwrap(),
        release_signer_authorization_chain_digest: sha256(b"release-signer-authorization-chain"),
        release_signing_trust_root_fingerprint: release_trust_root(),
        release_signing_trust_root_version: 1,
        bootstrap_artifact_digest_list: vec![bootstrap.clone()],
        executable_artifact_digest_list: vec![executable.clone()],
        profile_artifact_digest_list: vec![profile_artifact.clone()],
        deny_by_default_policy_digest: preliminary.policy.clone(),
        activation_qualification_plan_digest: plan_digest.clone(),
        initial_qualification_publisher_trust_root_digest: preliminary.publisher_set.clone(),
        initial_qualification_harness_profile_authorization_set_digest: preliminary
            .profile_set
            .clone(),
        initial_qualification_grant_set_digest: preliminary.grant_set.clone(),
        initial_qualification_action_definition_set_digest: preliminary.definition_set.clone(),
        initial_trusted_project_authorization_set_digest: preliminary.project_set.clone(),
        initial_qualification_route_set_digest: preliminary.route_set.clone(),
        initial_qualification_caller_eligibility_digest: preliminary.caller_set.clone(),
        initial_qualification_coverage_set_digest: preliminary.coverage.clone(),
        issuance: now.saturating_sub(1),
        expiry: now.saturating_add(7_200),
    };
    let manifest_bytes = encode_release_manifest(&manifest).unwrap();
    let manifest_digest = digest_encoded(&manifest_bytes);
    let release_signature = format!(
        "ed25519sig:{}",
        hex::encode(release_key.sign(&manifest_bytes).to_bytes())
    );
    let release = ProductBaseReleaseManifestEnvelope {
        release_manifest: manifest.clone(),
        release_manifest_digest: manifest_digest.clone(),
        release_signature,
    };
    records.release_qualification.manifest_digest = manifest_digest.clone();
    records
        .release_qualification
        .activation_qualification_plan_digest = plan_digest;
    let digests = records.digests().unwrap();
    let continuity = RootContinuityRecord {
        schema: "ember.root-continuity-record/v1".into(),
        generation: 0,
        authority_fingerprint: authority,
        prior_record_digest: ZERO_DIGEST.into(),
        protected_tip_digest: ZERO_DIGEST.into(),
        slot_id: "qualification-slot-0".into(),
    };
    let intent = RootInitializationIntent {
        productbase_release_manifest_digest: manifest_digest,
        bootstrap_artifact_digest_list: vec![bootstrap],
        root_verification_public_key: custody.root_public_key().0,
        initial_principal_id: plan.qualification_principal_id.clone(),
        initial_qualification_persona_id: plan.qualification_persona_id.clone(),
        initial_qualification_grant_set_digest: digests.grant_set,
        initial_qualification_harness_profile_authorization_set_digest: digests.profile_set,
        initial_qualification_caller_eligibility_digest: digests.caller_set,
        deny_by_default_policy_digest: digests.policy,
        recovery_manifest_digest: digests.recovery,
        initial_device_set_digest: device_set_digest(&devices).unwrap(),
        initial_qualification_publisher_trust_root_digest: digests.publisher_set,
        initial_qualification_action_definition_set_digest: digests.definition_set,
        initial_trusted_project_authorization_set_digest: digests.project_set,
        initial_qualification_route_set_digest: digests.route_set,
        release_signing_trust_root_fingerprint: release_trust_root(),
        release_signing_trust_root_version: 1,
        initial_release_qualification_record_digest: digests.release_qualification,
        initial_qualification_coverage_set_digest: digests.coverage,
        prior_root_continuity_record_digest: digest_encoded(
            &encode_continuity(&continuity).unwrap(),
        ),
    };
    let intent_signature = custody
        .root_signer()
        .unwrap()
        .sign(&encode_root_intent(&intent).unwrap())
        .0;
    InitializationRequest {
        intent,
        intent_signature,
        release,
        activation_plan: plan,
        records,
        devices,
        custody_evidence,
        prior_continuity: continuity,
        artifacts: vec![
            ArtifactSource {
                artifact_id: "bootstrap:emberd".into(),
                path: bootstrap_path,
            },
            ArtifactSource {
                artifact_id: "executable:ember".into(),
                path: executable_path,
            },
            ArtifactSource {
                artifact_id: "profile:productbase-s4".into(),
                path: profile_path,
            },
        ],
    }
}

pub fn anchor() -> ReleaseVerificationAnchor {
    let release_key = SigningKey::from_bytes(&RELEASE_SEED);
    ReleaseVerificationAnchor {
        trust_root_fingerprint: release_trust_root(),
        version: 1,
        signer_public_key: format!(
            "ed25519:{}",
            hex::encode(release_key.verifying_key().to_bytes())
        ),
        signer_authorization_chain_digest: sha256(b"release-signer-authorization-chain"),
    }
}

fn release_trust_root() -> String {
    sha256(b"productbase-s4-release-trust-root")
}
