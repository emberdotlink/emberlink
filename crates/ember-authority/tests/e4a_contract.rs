use std::{num::NonZeroU32, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use ember_authority::{
    audit::{
        CommitFault, EvidenceJournal, EvidenceSigner, JournalError, JournalIdentity,
        JournalSealKey, JournalSecurity, JournalTransaction, OperationalEvidenceSigner,
        OperationalVerifier, PrimaryEvidence, encode_authority_receipt, issue_authority_receipt,
    },
    catalog::{
        CatalogAuthority, CatalogError, CatalogTransitionKind, CommitmentBinding,
        CredentialCatalog, CredentialExpectation, CredentialId, CredentialMaterial,
        CredentialTransitionEvidence, CustodyProfile, DeleteCredential, EnrollCredential,
        GithubAppSubject, Kind, MATERIAL_COMMITMENT_DOMAIN, MaterialCommitmentCapability,
        MaterialKeyReference, RevisionCommitment, RevisionId, RotateCredential,
    },
    identity::{
        CertificateSignature, DeviceCertificateId, DeviceId, EvidencePublicKey,
        EvidenceSignatureBytes, IdentityError, SignerGeneration, SignerGenerationBody,
        SignerGenerationId, SignerKeyId, SignerPurpose, SigningAlgorithm, ValidityInterval,
        VaultId,
    },
    model::{
        AuthorityObjectId, AuthorityReceiptBody, AuthorityTransitionKind, EventKind, EvidenceId,
        JournalSequence,
    },
    principal::{PresenceOperation, PresenceVerifier},
    runtime_presence::{RUNTIME_PRESENCE_INTENT_SCHEMA, RuntimePresenceIntent},
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::Signer as _,
};
use rand_core::OsRng;
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use zeroize::Zeroizing;

const STATE_KEY: &str = "authority-credential-catalog";

#[derive(Clone)]
struct OperationalTestSigner {
    id: SignerGenerationId,
    key: Ed25519SigningKey,
}

impl OperationalTestSigner {
    fn new(seed: u8) -> Self {
        Self {
            id: SignerGenerationId::from_bytes([seed; 32]),
            key: Ed25519SigningKey::from_bytes(&[seed.wrapping_add(1); 32]),
        }
    }

    fn verifier(&self) -> OperationalVerifier {
        let mut verifier = OperationalVerifier::default();
        verifier.trust(self.id, self.key.verifying_key().to_bytes());
        verifier
    }
}

impl OperationalEvidenceSigner for OperationalTestSigner {
    fn generation_id(&self) -> SignerGenerationId {
        self.id
    }

    fn sign_bound_message(&self, message: &[u8]) -> Result<[u8; 64], JournalError> {
        Ok(self.key.sign(message).to_bytes())
    }
}

struct AuthorityTestSigner {
    key: P256SigningKey,
    public: EvidencePublicKey,
}

impl AuthorityTestSigner {
    fn new(seed: u8) -> Self {
        let key = P256SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
        let public =
            EvidencePublicKey::P256(key.verifying_key().to_sec1_point(true).as_bytes().to_vec());
        Self { key, public }
    }
}

impl EvidenceSigner for AuthorityTestSigner {
    fn public_key(&self) -> &EvidencePublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<EvidenceSignatureBytes, IdentityError> {
        let signature: P256Signature = self.key.sign(message);
        Ok(EvidenceSignatureBytes::P256Der(
            signature.normalize_s().to_der().as_bytes().to_vec(),
        ))
    }
}

fn sequence(value: u64) -> JournalSequence {
    JournalSequence::new(value).unwrap()
}

fn authority_generation(signer: &AuthorityTestSigner) -> SignerGeneration {
    SignerGeneration {
        body: SignerGenerationBody {
            generation_id: SignerGenerationId::from_bytes([0x31; 32]),
            vault_id: VaultId::from_bytes([0x32; 32]),
            device_certificate_id: DeviceCertificateId::from_bytes([0x33; 32]),
            key_id: SignerKeyId::from_bytes([0x34; 32]),
            generation: NonZeroU32::MIN,
            purpose: SignerPurpose::AuthorityTransition,
            algorithm: SigningAlgorithm::EcdsaP256Sha256,
            public_key: signer.public.clone(),
            validity: ValidityInterval::new(sequence(1), sequence(10_000)).unwrap(),
            predecessor: None,
        },
        signature: CertificateSignature {
            issuer_key_id: SignerKeyId::from_bytes([0x35; 32]),
            signature: EvidenceSignatureBytes::P256Der(vec![0x30, 0]),
        },
    }
}

fn open_journal(root: impl AsRef<Path>) -> Arc<EvidenceJournal> {
    let root = root.as_ref();
    let high_water = root.join("high-water");
    std::fs::create_dir_all(&high_water).unwrap();
    std::fs::set_permissions(&high_water, std::fs::Permissions::from_mode(0o700)).unwrap();
    let signer = OperationalTestSigner::new(1);
    Arc::new(
        EvidenceJournal::open(
            root.join("journal"),
            JournalIdentity::new(
                VaultId::from_bytes([0x11; 32]),
                DeviceId::from_bytes([0x22; 32]),
            ),
            JournalSecurity::new(
                high_water.join("journal.json"),
                JournalSealKey::from_bytes([0xE4; 32]),
                Arc::new(signer.clone()),
                signer.verifier(),
            ),
        )
        .unwrap(),
    )
}

fn private_key_pem() -> Vec<u8> {
    let key = RsaPrivateKey::new(&mut OsRng, 2_048).unwrap();
    key.to_pkcs8_pem(Default::default())
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn credential_material() -> CredentialMaterial {
    CredentialMaterial::new(Kind::GithubAppPrivateKey, private_key_pem()).unwrap()
}

fn subject() -> GithubAppSubject {
    GithubAppSubject::new(1234, 5678).unwrap()
}

struct TestCommitments {
    key: [u8; 32],
    bindings: Vec<CommitmentBinding>,
}

impl TestCommitments {
    fn new() -> Self {
        Self {
            key: [0xA5; 32],
            bindings: Vec::new(),
        }
    }

    fn digest(&self, binding: &CommitmentBinding, material: &[u8]) -> RevisionCommitment {
        let mut digest = Sha256::new();
        digest.update(MATERIAL_COMMITMENT_DOMAIN);
        digest.update(self.key);
        digest.update(binding.credential_id().as_bytes());
        digest.update(binding.revision_id().as_bytes());
        digest.update([binding.kind() as u8]);
        digest.update(binding.subject().app_id().to_be_bytes());
        digest.update(binding.subject().installation_id().to_be_bytes());
        digest.update([binding.custody_profile() as u8]);
        digest.update(binding.key_reference().as_bytes());
        digest.update((material.len() as u64).to_be_bytes());
        digest.update(material);
        RevisionCommitment::from_bytes(digest.finalize().into())
    }
}

impl MaterialCommitmentCapability for TestCommitments {
    fn commit(
        &mut self,
        binding: &CommitmentBinding,
        material: &[u8],
    ) -> Result<RevisionCommitment, CatalogError> {
        let commitment = self.digest(binding, material);
        self.bindings.push(binding.clone());
        Ok(commitment)
    }
}

struct FixedCommitment(RevisionCommitment);

impl MaterialCommitmentCapability for FixedCommitment {
    fn commit(
        &mut self,
        _binding: &CommitmentBinding,
        _material: &[u8],
    ) -> Result<RevisionCommitment, CatalogError> {
        Ok(self.0)
    }
}

struct ExactPresence {
    operation: PresenceOperation,
    unused: bool,
}

impl ExactPresence {
    fn fresh(operation: PresenceOperation) -> Self {
        Self {
            operation,
            unused: true,
        }
    }
}

impl PresenceVerifier for ExactPresence {
    fn verify_presence(&mut self, operation: &PresenceOperation) -> bool {
        let accepted = self.unused && self.operation == *operation;
        self.unused = false;
        accepted
    }
}

fn prepare_enrollment(commitments: &mut TestCommitments) -> EnrollCredential {
    EnrollCredential::prepare(
        Kind::GithubAppPrivateKey,
        subject(),
        CustodyProfile::MacosDeviceBoundUserPresenceV1,
        MaterialKeyReference::new(),
        credential_material(),
        commitments,
    )
    .unwrap()
}

#[test]
fn credential_material_rejects_invalid_kind_payload_before_preparation() {
    assert!(matches!(
        CredentialMaterial::new(Kind::GithubAppPrivateKey, b"not a private key".to_vec()),
        Err(CatalogError::InvalidPreparedMaterial)
    ));
}

fn state_value(journal: &EvidenceJournal) -> Value {
    serde_json::from_slice(
        journal
            .verified_snapshot()
            .unwrap()
            .state(STATE_KEY)
            .unwrap(),
    )
    .unwrap()
}

fn journal_state(journal: &EvidenceJournal) -> Option<Vec<u8>> {
    journal
        .verified_snapshot()
        .unwrap()
        .state(STATE_KEY)
        .map(ToOwned::to_owned)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_material_absent(root: &Path, journal: &EvidenceJournal, material: &[u8]) {
    let durable_state = journal
        .verified_snapshot()
        .unwrap()
        .state(STATE_KEY)
        .unwrap()
        .to_vec();
    assert!(!contains_subslice(&durable_state, material));

    let journal_bytes = std::fs::read(root.join("journal").join("authority-journal.json")).unwrap();
    assert!(!contains_subslice(&journal_bytes, material));
    let disk: Value = serde_json::from_slice(&journal_bytes).unwrap();
    for record in disk["records"].as_array().unwrap() {
        let canonical_evidence = record["canonical_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|byte| byte.as_u64().unwrap() as u8)
            .collect::<Vec<_>>();
        assert!(!contains_subslice(&canonical_evidence, material));
    }
}

fn runtime_intent(operation: &PresenceOperation) -> RuntimePresenceIntent {
    let (transition, credential) = match operation {
        PresenceOperation::EnrollCredential {
            credential_id,
            revision_id,
            kind: Kind::GithubAppPrivateKey,
            subject,
            custody_profile: CustodyProfile::MacosDeviceBoundUserPresenceV1,
            commitment,
            key_reference,
        } => (
            "enroll_credential",
            json!({
                "transition": "enroll_credential",
                "credential_id": hex::encode(credential_id.as_bytes()),
                "current_revision_id": null,
                "current_commitment": null,
                "new_revision_id": hex::encode(revision_id.as_bytes()),
                "new_commitment": hex::encode(commitment.as_bytes()),
                "kind": "github_app_private_key",
                "app_id": subject.app_id(),
                "installation_id": subject.installation_id(),
                "custody_profile": "macos_device_bound_user_presence_v1",
                "material_key_reference": hex::encode(key_reference.as_bytes()),
            }),
        ),
        PresenceOperation::RotateCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            new_revision_id,
            new_commitment,
            kind: Kind::GithubAppPrivateKey,
            subject,
            custody_profile: CustodyProfile::MacosDeviceBoundUserPresenceV1,
            key_reference,
        } => (
            "rotate_credential",
            json!({
                "transition": "rotate_credential",
                "credential_id": hex::encode(credential_id.as_bytes()),
                "current_revision_id": hex::encode(current_revision_id.as_bytes()),
                "current_commitment": hex::encode(current_commitment.as_bytes()),
                "new_revision_id": hex::encode(new_revision_id.as_bytes()),
                "new_commitment": hex::encode(new_commitment.as_bytes()),
                "kind": "github_app_private_key",
                "app_id": subject.app_id(),
                "installation_id": subject.installation_id(),
                "custody_profile": "macos_device_bound_user_presence_v1",
                "material_key_reference": hex::encode(key_reference.as_bytes()),
            }),
        ),
        PresenceOperation::DeleteCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            kind: Kind::GithubAppPrivateKey,
            subject,
            custody_profile: CustodyProfile::MacosDeviceBoundUserPresenceV1,
        } => (
            "delete_credential",
            json!({
                "transition": "delete_credential",
                "credential_id": hex::encode(credential_id.as_bytes()),
                "current_revision_id": hex::encode(current_revision_id.as_bytes()),
                "new_revision_id": null,
                "new_commitment": null,
                "current_commitment": hex::encode(current_commitment.as_bytes()),
                "kind": "github_app_private_key",
                "app_id": subject.app_id(),
                "installation_id": subject.installation_id(),
                "custody_profile": "macos_device_bound_user_presence_v1",
                "material_key_reference": null,
            }),
        ),
        _ => panic!("expected a Credential presence operation"),
    };
    let founder_display = json!({
        "operation": transition,
        "session_id": "",
        "requested_ttl_seconds": 0,
        "grants": [],
        "credential": credential,
    });
    let founder_display_sha256 =
        hex::encode(Sha256::digest(serde_jcs::to_vec(&founder_display).unwrap()));
    let operation_wire = json!({
        "operation": transition,
        "session_id": "",
        "grant_ids": [],
        "delegation_ids": [],
        "requested_ttl_seconds": 0,
        "credential": founder_display["credential"].clone(),
    });
    let wire = json!({
        "schema": RUNTIME_PRESENCE_INTENT_SCHEMA,
        "authority": {
            "installation_identity_sha256": "11".repeat(32),
            "accepted_authority_state_sha256": "22".repeat(32),
            "daemon_identity_sha256": "33".repeat(32),
        },
        "operation": operation_wire,
        "founder_display": founder_display,
        "founder_display_sha256": founder_display_sha256,
        "nonce": "44".repeat(32),
        "issued_at_unix": 1_000,
        "expires_at_unix": 1_030,
    });
    RuntimePresenceIntent::from_canonical_bytes(&serde_jcs::to_vec(&wire).unwrap()).unwrap()
}

fn assert_display_matches_operation(intent: &RuntimePresenceIntent, operation: &PresenceOperation) {
    let display = intent.founder_display();
    assert!(display.session_id().is_empty());
    assert_eq!(display.requested_ttl_seconds(), 0);
    assert!(display.grants().is_empty());
    let credential = display.credential().unwrap();
    assert_eq!(display.operation(), credential.transition());
    assert_eq!(credential.kind(), "github_app_private_key");
    assert_eq!(
        credential.custody_profile(),
        "macos_device_bound_user_presence_v1"
    );

    match operation {
        PresenceOperation::EnrollCredential {
            credential_id,
            revision_id,
            subject,
            commitment,
            key_reference,
            ..
        } => {
            assert_eq!(credential.transition(), "enroll_credential");
            assert_eq!(
                credential.credential_id(),
                hex::encode(credential_id.as_bytes())
            );
            assert_eq!(credential.current_revision_id(), None);
            assert_eq!(credential.current_commitment(), None);
            assert_eq!(
                credential.new_revision_id(),
                Some(hex::encode(revision_id.as_bytes()).as_str())
            );
            assert_eq!(
                credential.new_commitment(),
                Some(hex::encode(commitment.as_bytes()).as_str())
            );
            assert_eq!(
                credential.material_key_reference(),
                Some(hex::encode(key_reference.as_bytes()).as_str())
            );
            assert_eq!(credential.app_id(), subject.app_id());
            assert_eq!(credential.installation_id(), subject.installation_id());
        }
        PresenceOperation::RotateCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            new_revision_id,
            new_commitment,
            subject,
            key_reference,
            ..
        } => {
            assert_eq!(credential.transition(), "rotate_credential");
            assert_eq!(
                credential.credential_id(),
                hex::encode(credential_id.as_bytes())
            );
            assert_eq!(
                credential.current_revision_id(),
                Some(hex::encode(current_revision_id.as_bytes()).as_str())
            );
            assert_eq!(
                credential.current_commitment(),
                Some(hex::encode(current_commitment.as_bytes()).as_str())
            );
            assert_eq!(
                credential.new_revision_id(),
                Some(hex::encode(new_revision_id.as_bytes()).as_str())
            );
            assert_eq!(
                credential.new_commitment(),
                Some(hex::encode(new_commitment.as_bytes()).as_str())
            );
            assert_eq!(
                credential.material_key_reference(),
                Some(hex::encode(key_reference.as_bytes()).as_str())
            );
            assert_eq!(credential.app_id(), subject.app_id());
            assert_eq!(credential.installation_id(), subject.installation_id());
        }
        PresenceOperation::DeleteCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            subject,
            ..
        } => {
            assert_eq!(credential.transition(), "delete_credential");
            assert_eq!(
                credential.credential_id(),
                hex::encode(credential_id.as_bytes())
            );
            assert_eq!(
                credential.current_revision_id(),
                Some(hex::encode(current_revision_id.as_bytes()).as_str())
            );
            assert_eq!(
                credential.current_commitment(),
                Some(hex::encode(current_commitment.as_bytes()).as_str())
            );
            assert_eq!(credential.new_revision_id(), None);
            assert_eq!(credential.new_commitment(), None);
            assert_eq!(credential.material_key_reference(), None);
            assert_eq!(credential.app_id(), subject.app_id());
            assert_eq!(credential.installation_id(), subject.installation_id());
        }
        _ => panic!("expected a Credential presence operation"),
    }
}

#[test]
fn public_founder_display_and_reason_bind_every_credential_transition_field() {
    let credential_id = CredentialId::from_bytes([0x11; 32]);
    let current_revision_id = RevisionId::from_bytes([0x22; 32]);
    let current_commitment = RevisionCommitment::from_bytes([0x33; 32]);
    let new_revision_id = RevisionId::from_bytes([0x44; 32]);
    let new_commitment = RevisionCommitment::from_bytes([0x55; 32]);
    let key_reference = MaterialKeyReference::from_bytes([0x66; 32]);
    let subject = GithubAppSubject::new(1234, 5678).unwrap();
    let profile = CustodyProfile::MacosDeviceBoundUserPresenceV1;

    let enrollment = PresenceOperation::EnrollCredential {
        credential_id,
        revision_id: current_revision_id,
        kind: Kind::GithubAppPrivateKey,
        subject: subject.clone(),
        custody_profile: profile,
        commitment: current_commitment,
        key_reference,
    };
    let intent = runtime_intent(&enrollment);
    assert_display_matches_operation(&intent, &enrollment);
    assert_eq!(
        intent.founder_presence_reason().unwrap(),
        format!(
            "Ember authority (0s): transition=enroll_credential credential_id={} \
             current_revision_id=none current_commitment=none new_revision_id={} \
             new_commitment={} kind=github_app_private_key app_id=1234 \
             installation_id=5678 custody_profile=macos_device_bound_user_presence_v1 \
             material_key_reference={}",
            hex::encode(credential_id.as_bytes()),
            hex::encode(current_revision_id.as_bytes()),
            hex::encode(current_commitment.as_bytes()),
            hex::encode(key_reference.as_bytes()),
        )
    );

    let rotation = PresenceOperation::RotateCredential {
        credential_id,
        current_revision_id,
        current_commitment,
        new_revision_id,
        new_commitment,
        kind: Kind::GithubAppPrivateKey,
        subject: subject.clone(),
        custody_profile: profile,
        key_reference,
    };
    let intent = runtime_intent(&rotation);
    assert_display_matches_operation(&intent, &rotation);
    assert_eq!(
        intent.founder_presence_reason().unwrap(),
        format!(
            "Ember authority (0s): transition=rotate_credential credential_id={} \
             current_revision_id={} current_commitment={} new_revision_id={} \
             new_commitment={} kind=github_app_private_key app_id=1234 \
             installation_id=5678 custody_profile=macos_device_bound_user_presence_v1 \
             material_key_reference={}",
            hex::encode(credential_id.as_bytes()),
            hex::encode(current_revision_id.as_bytes()),
            hex::encode(current_commitment.as_bytes()),
            hex::encode(new_revision_id.as_bytes()),
            hex::encode(new_commitment.as_bytes()),
            hex::encode(key_reference.as_bytes()),
        )
    );

    let deletion = PresenceOperation::DeleteCredential {
        credential_id,
        current_revision_id: new_revision_id,
        current_commitment: new_commitment,
        kind: Kind::GithubAppPrivateKey,
        subject,
        custody_profile: profile,
    };
    let intent = runtime_intent(&deletion);
    assert_display_matches_operation(&intent, &deletion);
    assert_eq!(
        intent.founder_presence_reason().unwrap(),
        format!(
            "Ember authority (0s): transition=delete_credential credential_id={} \
             current_revision_id={} current_commitment={} new_revision_id=none \
             new_commitment=none kind=github_app_private_key app_id=1234 \
             installation_id=5678 custody_profile=macos_device_bound_user_presence_v1 \
             material_key_reference=none",
            hex::encode(credential_id.as_bytes()),
            hex::encode(new_revision_id.as_bytes()),
            hex::encode(new_commitment.as_bytes()),
        )
    );
}

#[test]
fn lifecycle_is_one_slot_forward_only_receipted_and_commitment_verifiable() {
    let directory = tempdir().unwrap();
    let journal = open_journal(directory.path());
    let signer = AuthorityTestSigner::new(7);
    let generation = authority_generation(&signer);
    let authority = CatalogAuthority::new(&generation, &signer);
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    let mut commitments = TestCommitments::new();

    let enrollment = prepare_enrollment(&mut commitments);
    let mut presence = ExactPresence::fresh(enrollment.presence_operation());
    let enrolled = catalog
        .enroll(&enrollment, Some(&mut presence), &authority)
        .unwrap();
    let first = enrolled.credential().clone();
    assert_eq!(
        enrolled.authority_receipt().body().transition(),
        AuthorityTransitionKind::CredentialEnroll
    );
    assert_eq!(
        journal.verified_snapshot().unwrap().records()[0].event_code(),
        EventKind::CredentialEnrolled as u8
    );

    let rotation_material = Zeroizing::new(private_key_pem());
    let rotation = RotateCredential::prepare(
        first.clone(),
        MaterialKeyReference::new(),
        CredentialMaterial::new(
            Kind::GithubAppPrivateKey,
            rotation_material.as_slice().to_vec(),
        )
        .unwrap(),
        &mut commitments,
    )
    .unwrap();
    let mut presence = ExactPresence::fresh(rotation.presence_operation());
    let rotated = catalog
        .rotate(&rotation, Some(&mut presence), &authority)
        .unwrap();
    assert_eq!(rotated.ordinal().get(), 2);
    assert_eq!(
        rotated.authority_receipt().body().transition(),
        AuthorityTransitionKind::CredentialRotate
    );
    assert_eq!(rotated.credential().credential_id(), first.credential_id());
    assert_ne!(rotated.credential().revision_id(), first.revision_id());
    let state = state_value(&journal);
    assert_eq!(state["active"]["revisions"].as_array().unwrap().len(), 2);
    assert_eq!(state["active"]["destroyed"].as_array().unwrap().len(), 1);
    assert_eq!(
        state["active"]["revisions"][0]["commitment"],
        serde_json::to_value(first.commitment()).unwrap()
    );
    assert_material_absent(directory.path(), &journal, rotation_material.as_slice());

    let deletion = DeleteCredential::new(rotated.credential().clone()).unwrap();
    let mut presence = ExactPresence::fresh(deletion.presence_operation());
    let deleted = catalog
        .delete(&deletion, Some(&mut presence), &authority)
        .unwrap();
    assert_eq!(
        deleted.authority_receipt().body().transition(),
        AuthorityTransitionKind::CredentialDelete
    );
    assert_eq!(
        deleted.retained_commitment(),
        rotated.credential().commitment()
    );
    let state = state_value(&journal);
    assert!(state["active"].is_null());
    assert_eq!(
        state["tombstones"][0]["revisions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        state["tombstones"][0]["destroyed"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(state["tombstones"][0].get("current_material").is_none());
    assert_eq!(
        commitments.digest(
            commitments.bindings.last().unwrap(),
            rotation_material.as_slice(),
        ),
        deleted.retained_commitment(),
    );
    assert_material_absent(directory.path(), &journal, rotation_material.as_slice());

    let replacement = prepare_enrollment(&mut commitments);
    let mut presence = ExactPresence::fresh(replacement.presence_operation());
    let replacement = catalog
        .enroll(&replacement, Some(&mut presence), &authority)
        .unwrap();
    assert_ne!(
        replacement.credential().credential_id(),
        deleted.credential_id()
    );
    assert_ne!(
        replacement.credential().revision_id(),
        deleted.revision_id()
    );
    assert_material_absent(directory.path(), &journal, rotation_material.as_slice());
}

#[test]
fn duplicate_commitments_are_rejected_across_active_and_tombstone_history() {
    let directory = tempdir().unwrap();
    let journal = open_journal(directory.path());
    let signer = AuthorityTestSigner::new(7);
    let generation = authority_generation(&signer);
    let authority = CatalogAuthority::new(&generation, &signer);
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    let commitment = RevisionCommitment::from_bytes([0xA7; 32]);
    let mut commitments = FixedCommitment(commitment);

    let enrollment = EnrollCredential::prepare(
        Kind::GithubAppPrivateKey,
        subject(),
        CustodyProfile::MacosDeviceBoundUserPresenceV1,
        MaterialKeyReference::new(),
        credential_material(),
        &mut commitments,
    )
    .unwrap();
    let mut presence = ExactPresence::fresh(enrollment.presence_operation());
    let enrolled = catalog
        .enroll(&enrollment, Some(&mut presence), &authority)
        .unwrap();

    let rotation = RotateCredential::prepare(
        enrolled.credential().clone(),
        MaterialKeyReference::new(),
        credential_material(),
        &mut commitments,
    )
    .unwrap();
    let before_rotation = journal_state(&journal);
    let records_before_rotation = journal.verified_snapshot().unwrap().records().len();
    let mut presence = ExactPresence::fresh(rotation.presence_operation());
    assert!(matches!(
        catalog.rotate(&rotation, Some(&mut presence), &authority),
        Err(CatalogError::InvalidDurableState)
    ));
    assert_eq!(journal_state(&journal), before_rotation);
    assert_eq!(
        journal.verified_snapshot().unwrap().records().len(),
        records_before_rotation
    );

    let deletion = DeleteCredential::new(enrolled.credential().clone()).unwrap();
    let mut presence = ExactPresence::fresh(deletion.presence_operation());
    catalog
        .delete(&deletion, Some(&mut presence), &authority)
        .unwrap();

    let replacement = EnrollCredential::prepare(
        Kind::GithubAppPrivateKey,
        subject(),
        CustodyProfile::MacosDeviceBoundUserPresenceV1,
        MaterialKeyReference::new(),
        credential_material(),
        &mut commitments,
    )
    .unwrap();
    let before_reenrollment = journal_state(&journal);
    let records_before_reenrollment = journal.verified_snapshot().unwrap().records().len();
    let mut presence = ExactPresence::fresh(replacement.presence_operation());
    assert!(matches!(
        catalog.enroll(&replacement, Some(&mut presence), &authority),
        Err(CatalogError::InvalidDurableState)
    ));
    assert_eq!(journal_state(&journal), before_reenrollment);
    assert_eq!(
        journal.verified_snapshot().unwrap().records().len(),
        records_before_reenrollment
    );
}

#[test]
fn refusals_append_audit_facts_without_mutating_catalog_state() {
    let directory = tempdir().unwrap();
    let journal = open_journal(directory.path());
    let signer = AuthorityTestSigner::new(7);
    let generation = authority_generation(&signer);
    let authority = CatalogAuthority::new(&generation, &signer);
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    let mut commitments = TestCommitments::new();

    let enrollment = prepare_enrollment(&mut commitments);
    assert!(matches!(
        catalog.enroll(&enrollment, None, &authority),
        Err(CatalogError::PresenceRequired)
    ));
    assert_eq!(
        journal.verified_snapshot().unwrap().records()[0].event_code(),
        EventKind::CredentialEnrollPresenceRefused as u8
    );
    assert!(journal_state(&journal).is_none());

    let mut presence = ExactPresence::fresh(enrollment.presence_operation());
    let enrolled = catalog
        .enroll(&enrollment, Some(&mut presence), &authority)
        .unwrap();
    let unchanged = journal_state(&journal);

    let occupied = prepare_enrollment(&mut commitments);
    let mut presence = ExactPresence::fresh(occupied.presence_operation());
    assert!(matches!(
        catalog.enroll(&occupied, Some(&mut presence), &authority),
        Err(CatalogError::Occupied)
    ));
    assert_eq!(journal_state(&journal), unchanged);
    assert_eq!(
        journal
            .verified_snapshot()
            .unwrap()
            .records()
            .last()
            .unwrap()
            .event_code(),
        EventKind::CredentialEnrollOccupied as u8
    );

    let mut replayed = ExactPresence::fresh(enrollment.presence_operation());
    assert!(matches!(
        catalog.enroll(&enrollment, Some(&mut replayed), &authority),
        Err(CatalogError::AlreadyApplied)
    ));
    assert_eq!(journal_state(&journal), unchanged);
    assert_eq!(
        journal
            .verified_snapshot()
            .unwrap()
            .records()
            .last()
            .unwrap()
            .event_code(),
        EventKind::CredentialEnrollReplayRefused as u8
    );

    let wrong = CredentialExpectation::new(
        enrolled.credential().credential_id(),
        enrolled.credential().revision_id(),
        enrolled.credential().kind(),
        GithubAppSubject::new(4321, 8765).unwrap(),
        enrolled.credential().custody_profile(),
        enrolled.credential().commitment(),
    );
    let rotate = RotateCredential::prepare(
        wrong,
        MaterialKeyReference::new(),
        credential_material(),
        &mut commitments,
    )
    .unwrap();
    let mut presence = ExactPresence::fresh(rotate.presence_operation());
    assert!(matches!(
        catalog.rotate(&rotate, Some(&mut presence), &authority),
        Err(CatalogError::SubjectMismatch)
    ));
    assert_eq!(journal_state(&journal), unchanged);
    assert_eq!(
        journal
            .verified_snapshot()
            .unwrap()
            .records()
            .last()
            .unwrap()
            .event_code(),
        EventKind::CredentialRotateMismatch as u8
    );
}

#[test]
fn empty_and_exact_tuple_mismatches_fail_closed() {
    let directory = tempdir().unwrap();
    let journal = open_journal(directory.path());
    let signer = AuthorityTestSigner::new(7);
    let generation = authority_generation(&signer);
    let authority = CatalogAuthority::new(&generation, &signer);
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    let mut commitments = TestCommitments::new();

    let fake = CredentialExpectation::new(
        CredentialId::new(),
        RevisionId::new(),
        Kind::GithubAppPrivateKey,
        subject(),
        CustodyProfile::MacosDeviceBoundUserPresenceV1,
        RevisionCommitment::from_bytes([9; 32]),
    );
    let empty_delete = DeleteCredential::new(fake.clone()).unwrap();
    let mut presence = ExactPresence::fresh(empty_delete.presence_operation());
    assert!(matches!(
        catalog.delete(&empty_delete, Some(&mut presence), &authority),
        Err(CatalogError::Empty)
    ));
    assert!(journal_state(&journal).is_none());
    assert_eq!(
        journal
            .verified_snapshot()
            .unwrap()
            .records()
            .last()
            .unwrap()
            .event_code(),
        EventKind::CredentialDeleteEmpty as u8
    );

    let enrollment = prepare_enrollment(&mut commitments);
    let mut presence = ExactPresence::fresh(enrollment.presence_operation());
    let enrolled = catalog
        .enroll(&enrollment, Some(&mut presence), &authority)
        .unwrap();
    let current = enrolled.credential().clone();
    let unchanged = journal_state(&journal);

    let cases = [
        (
            CredentialExpectation::new(
                CredentialId::new(),
                current.revision_id(),
                current.kind(),
                current.subject().clone(),
                current.custody_profile(),
                current.commitment(),
            ),
            0_u8,
        ),
        (
            CredentialExpectation::new(
                current.credential_id(),
                RevisionId::new(),
                current.kind(),
                current.subject().clone(),
                current.custody_profile(),
                current.commitment(),
            ),
            1_u8,
        ),
        (
            CredentialExpectation::new(
                current.credential_id(),
                current.revision_id(),
                current.kind(),
                current.subject().clone(),
                current.custody_profile(),
                RevisionCommitment::from_bytes([0xAA; 32]),
            ),
            2_u8,
        ),
    ];
    for (expected, expected_error) in cases {
        let delete = DeleteCredential::new(expected).unwrap();
        let mut presence = ExactPresence::fresh(delete.presence_operation());
        let error = catalog
            .delete(&delete, Some(&mut presence), &authority)
            .unwrap_err();
        assert!(match expected_error {
            0 => matches!(error, CatalogError::CredentialMismatch),
            1 => matches!(error, CatalogError::RevisionMismatch),
            2 => matches!(error, CatalogError::CommitmentMismatch),
            _ => unreachable!(),
        });
        assert_eq!(journal_state(&journal), unchanged);
        assert_eq!(
            journal
                .verified_snapshot()
                .unwrap()
                .records()
                .last()
                .unwrap()
                .event_code(),
            EventKind::CredentialDeleteMismatch as u8
        );
    }
}

#[test]
fn commit_faults_never_expose_torn_catalog_and_receipt_state() {
    let faults = [
        CommitFault::BeforeRecord,
        CommitFault::AfterRecordBeforeCheckpoint,
        CommitFault::AfterCheckpointBeforeJournalReplace,
        CommitFault::AfterJournalReplaceBeforeStatus,
        CommitFault::AfterDurableCommitBeforeResponse,
    ];
    for fault in faults {
        let root = tempdir().unwrap();
        let journal = open_journal(root.path());
        let signer = AuthorityTestSigner::new(7);
        let generation = authority_generation(&signer);
        let authority = CatalogAuthority::new(&generation, &signer);
        let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
        let mut commitments = TestCommitments::new();
        let enrollment = prepare_enrollment(&mut commitments);
        let mut presence = ExactPresence::fresh(enrollment.presence_operation());
        let _ = catalog.enroll_with_fault(&enrollment, Some(&mut presence), &authority, fault);
        let snapshot = journal.verified_snapshot().unwrap();
        assert_eq!(
            snapshot.state(STATE_KEY).is_some(),
            !snapshot.records().is_empty()
        );
        if let Some(state) = snapshot.state(STATE_KEY) {
            let parsed: Value = serde_json::from_slice(state).unwrap();
            assert!(!parsed["active"].is_null());
            assert_eq!(snapshot.records().len(), 1);
            assert_eq!(
                snapshot.records()[0].event_code(),
                EventKind::CredentialEnrolled as u8
            );
        }
    }
}

#[test]
fn refusal_fault_is_reported_only_when_its_audit_fact_is_durable() {
    let signer = AuthorityTestSigner::new(7);
    let generation = authority_generation(&signer);
    let authority = CatalogAuthority::new(&generation, &signer);

    let root = tempdir().unwrap();
    let journal = open_journal(root.path());
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    let mut commitments = TestCommitments::new();
    let enrollment = prepare_enrollment(&mut commitments);
    assert!(matches!(
        catalog.enroll_with_fault(&enrollment, None, &authority, CommitFault::BeforeRecord),
        Err(CatalogError::Journal(JournalError::InjectedInterruption))
    ));
    assert!(journal.verified_snapshot().unwrap().records().is_empty());

    let root = tempdir().unwrap();
    let journal = open_journal(root.path());
    let catalog = CredentialCatalog::open(Arc::clone(&journal)).unwrap();
    assert!(matches!(
        catalog.enroll_with_fault(
            &enrollment,
            None,
            &authority,
            CommitFault::AfterDurableCommitBeforeResponse
        ),
        Err(CatalogError::Journal(JournalError::ResponseLost(_)))
    ));
    let snapshot = journal.verified_snapshot().unwrap();
    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(
        snapshot.records()[0].event_code(),
        EventKind::CredentialEnrollPresenceRefused as u8
    );
    assert!(snapshot.state(STATE_KEY).is_none());
}

fn inject_state(journal: &EvidenceJournal, bytes: Vec<u8>, signer: &AuthorityTestSigner) {
    let receipt = issue_authority_receipt(
        &authority_generation(signer),
        AuthorityReceiptBody::new(
            EvidenceId::from_bytes([0x41; 32]),
            sequence(1),
            AuthorityObjectId::from_bytes([0x42; 32]),
            AuthorityTransitionKind::CredentialEnroll,
        ),
        signer,
    )
    .unwrap();
    let mut transaction = JournalTransaction::new([0x43; 32]);
    transaction.put_state(STATE_KEY, bytes);
    transaction.push_evidence(PrimaryEvidence::authority_receipt(&receipt), None);
    journal.commit(transaction).unwrap();
}

#[test]
fn noncanonical_unknown_and_invalid_durable_state_are_rejected() {
    let signer = AuthorityTestSigner::new(7);
    let root = tempdir().unwrap();
    let journal = open_journal(root.path());
    inject_state(&journal, b"{ \"active\": null, \"schema\": \"ember.authority-credential-catalog/v1\", \"tombstones\": [] }".to_vec(), &signer);
    assert!(matches!(
        CredentialCatalog::open(journal),
        Err(CatalogError::NonCanonicalDurableState)
    ));

    let root = tempdir().unwrap();
    let journal = open_journal(root.path());
    inject_state(&journal, serde_jcs::to_vec(&json!({"schema":"ember.authority-credential-catalog/v1","active":null,"tombstones":[],"unexpected":true})).unwrap(), &signer);
    assert!(matches!(
        CredentialCatalog::open(journal),
        Err(CatalogError::InvalidDurableState)
    ));

    let root = tempdir().unwrap();
    let journal = open_journal(root.path());
    inject_state(&journal, serde_jcs::to_vec(&json!({"schema":"ember.authority-credential-catalog/v999","active":null,"tombstones":[]})).unwrap(), &signer);
    assert!(matches!(
        CredentialCatalog::open(journal),
        Err(CatalogError::InvalidDurableState)
    ));
}

#[test]
fn keyed_commitment_rejects_every_binding_substitution() {
    let mut commitments = TestCommitments::new();
    let retained_material = Zeroizing::new(private_key_pem());
    let enrollment = EnrollCredential::prepare(
        Kind::GithubAppPrivateKey,
        subject(),
        CustodyProfile::MacosDeviceBoundUserPresenceV1,
        MaterialKeyReference::new(),
        CredentialMaterial::new(
            Kind::GithubAppPrivateKey,
            retained_material.as_slice().to_vec(),
        )
        .unwrap(),
        &mut commitments,
    )
    .unwrap();
    let binding = commitments.bindings[0].clone();
    let commitment = enrollment.commitment();
    assert_eq!(
        commitments.digest(&binding, retained_material.as_slice()),
        commitment,
    );
    let substitutions = [
        CommitmentBinding::new(
            CredentialId::new(),
            binding.revision_id(),
            binding.kind(),
            binding.subject().clone(),
            binding.custody_profile(),
            binding.key_reference(),
        )
        .unwrap(),
        CommitmentBinding::new(
            binding.credential_id(),
            RevisionId::new(),
            binding.kind(),
            binding.subject().clone(),
            binding.custody_profile(),
            binding.key_reference(),
        )
        .unwrap(),
        CommitmentBinding::new(
            binding.credential_id(),
            binding.revision_id(),
            binding.kind(),
            GithubAppSubject::new(9, 10).unwrap(),
            binding.custody_profile(),
            binding.key_reference(),
        )
        .unwrap(),
        CommitmentBinding::new(
            binding.credential_id(),
            binding.revision_id(),
            binding.kind(),
            binding.subject().clone(),
            binding.custody_profile(),
            MaterialKeyReference::new(),
        )
        .unwrap(),
    ];
    for changed in substitutions {
        assert_ne!(
            commitments.digest(&changed, retained_material.as_slice()),
            commitment,
        );
    }
}

#[test]
fn canonical_transition_and_lifecycle_receipt_fixtures_are_stable() {
    let transition_bytes = serde_jcs::to_vec(&json!({
        "schema": "ember.authority-credential-catalog/v1",
        "kind": "enroll",
        "mutation_id": vec![0x11_u8; 32],
        "evidence_id": vec![0x22_u8; 32],
        "sequence": 1,
        "credential_id": vec![0x33_u8; 32],
        "revision_id": vec![0x44_u8; 32],
        "ordinal": 1,
        "credential_kind": "github_app_private_key",
        "subject": {"app_id": 1234, "installation_id": 5678},
        "custody_profile": "macos_device_bound_user_presence_v1",
        "commitment": vec![0x55_u8; 32],
        "occurred_at_unix": 1_700_000_000_u64,
    }))
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&transition_bytes)),
        "4808bb6c9fe4a3cb3cb1108f52a65c1d184b4e44a59e176c0365cf53dd21daf3"
    );
    let transition = CredentialTransitionEvidence::from_canonical(&transition_bytes).unwrap();
    assert_eq!(transition.kind(), CatalogTransitionKind::Enroll);
    assert_eq!(transition.sequence(), 1);
    assert_eq!(transition.canonical_bytes().unwrap(), transition_bytes);
    assert_eq!(
        hex::encode(transition.authority_object_id().unwrap().as_bytes()),
        "9a7525de42603cffeb85fe2bf3bee1d2077b881e248593bde065c64e17b3a504"
    );

    let fixtures = [
        (
            AuthorityReceiptBody::new(
                EvidenceId::from_bytes([0x11; 32]),
                sequence(1),
                AuthorityObjectId::from_bytes([0x44; 32]),
                AuthorityTransitionKind::CredentialEnroll,
            ),
            "1e98f2f696dcdef99dbe5f3e2a5d8e906f7ce5501828f2e95bca7a59edbf54e2",
        ),
        (
            AuthorityReceiptBody::new(
                EvidenceId::from_bytes([0x22; 32]),
                sequence(2),
                AuthorityObjectId::from_bytes([0x55; 32]),
                AuthorityTransitionKind::CredentialRotate,
            ),
            "beaff2d86b75bc477b359631bbf9f39800dbb55f727b1ffec5b02e0e8f4dc870",
        ),
        (
            AuthorityReceiptBody::new(
                EvidenceId::from_bytes([0x33; 32]),
                sequence(3),
                AuthorityObjectId::from_bytes([0x66; 32]),
                AuthorityTransitionKind::CredentialDelete,
            ),
            "3eb0b45efc37ee9b8ae2d20120d2756453fe40ac9325fc1d3f08815e9ed88264",
        ),
    ];
    for (body, expected_digest) in fixtures {
        assert_eq!(
            hex::encode(Sha256::digest(encode_authority_receipt(&body))),
            expected_digest
        );
    }
}
