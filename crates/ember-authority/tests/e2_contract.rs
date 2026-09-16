use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
};

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use ember_authority::{
    audit::{
        CommitFault, EvidenceJournal, EvidenceLinks, ExportScope, JournalError, JournalIdentity,
        JournalSealKey, JournalSecurity, JournalTransaction, OperationalEvidenceSigner,
        OperationalVerifier, PayloadEnvelope, PayloadKeyId, PrimaryEvidence, SequenceRange,
        canonical_checkpoint_predecessor, encode_authority_rollup, encode_operation_view,
        issue_authority_receipt, verify_export,
    },
    identity::{
        CertificateSignature, DeviceCertificateId, DeviceId, EvidencePublicKey,
        EvidenceSignatureBytes, IdentityError, SignerGeneration, SignerGenerationBody,
        SignerGenerationId, SignerKeyId, SignerPurpose, SigningAlgorithm, ValidityInterval,
        VaultId,
    },
    model::{
        ActionBoundary, AuditFact, AuthorityObjectId, AuthorityReceiptBody,
        AuthorityTransitionKind, DelegationId, EventKind, EvidenceId, GrantId, JournalSequence,
        Need, OperationEvidenceRef, OperationId, OperationOutcome, PermissionLevel, PersonaId,
        ProcessBindingId, ProjectionVersion, ProviderEvidence, ProviderGeneration,
        ProviderInstanceId, RepositoryResource, RequestDigest, SessionId, SubmissionId,
    },
    recovery::{RecoveryContext, RecoveryJournal, RecoveryPhase, StartupRecoveryStatus},
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use tempfile::tempdir;

fn open_journal(
    root: impl AsRef<Path>,
    signer: &OperationalTestSigner,
) -> Result<EvidenceJournal, JournalError> {
    let root = root.as_ref();
    let high_water_root = root.join("high-water");
    std::fs::create_dir_all(&high_water_root)?;
    std::fs::set_permissions(&high_water_root, std::fs::Permissions::from_mode(0o700))?;
    EvidenceJournal::open(
        root.join("journal"),
        identity(),
        JournalSecurity::new(
            high_water_root.join("journal.json"),
            JournalSealKey::from_bytes([0xE2; 32]),
            Arc::new(signer.clone()),
            signer.verifier(),
        ),
    )
}

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

#[derive(Clone)]
struct FailingOperationalSigner {
    inner: OperationalTestSigner,
    calls: Arc<AtomicUsize>,
    fail_on: usize,
}

impl FailingOperationalSigner {
    fn verifier(&self) -> OperationalVerifier {
        self.inner.verifier()
    }
}

impl OperationalEvidenceSigner for FailingOperationalSigner {
    fn generation_id(&self) -> SignerGenerationId {
        self.inner.generation_id()
    }

    fn sign_bound_message(&self, message: &[u8]) -> Result<[u8; 64], JournalError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on {
            return Err(JournalError::Storage("injected signer failure".to_owned()));
        }
        self.inner.sign_bound_message(message)
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

impl ember_authority::audit::EvidenceSigner for AuthorityTestSigner {
    fn public_key(&self) -> &EvidencePublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<EvidenceSignatureBytes, IdentityError> {
        let signature: P256Signature = self.key.sign(message);
        let signature = signature.normalize_s();
        Ok(EvidenceSignatureBytes::P256Der(
            signature.to_der().as_bytes().to_vec(),
        ))
    }
}

fn identity() -> JournalIdentity {
    JournalIdentity::new(
        VaultId::from_bytes([0x11; 32]),
        DeviceId::from_bytes([0x22; 32]),
    )
}

fn sequence(value: u64) -> JournalSequence {
    JournalSequence::new(value).unwrap()
}

fn audit_evidence(sequence_value: u64, event: EventKind, links: EvidenceLinks) -> PrimaryEvidence {
    let operation = match (&links.operation_id, &links.materialization_id) {
        (Some(operation), Some(materialization)) => Some(OperationEvidenceRef::materialization(
            operation.clone(),
            materialization.clone(),
        )),
        (Some(operation), None) => Some(OperationEvidenceRef::operation(operation.clone())),
        (None, _) => None,
    };
    let fact = AuditFact::new(
        EvidenceId::from_bytes([sequence_value as u8; 32]),
        sequence(sequence_value),
        event,
        operation,
    )
    .unwrap();
    PrimaryEvidence::audit_fact(&fact, links).unwrap()
}

fn operation_links(operation_id: OperationId) -> EvidenceLinks {
    EvidenceLinks {
        operation_id: Some(operation_id),
        ..EvidenceLinks::default()
    }
}

fn commit_fact(
    journal: &EvidenceJournal,
    sequence_value: u64,
    event: EventKind,
    links: EvidenceLinks,
) {
    let mut transaction = JournalTransaction::new([sequence_value as u8; 32]);
    transaction.push_evidence(audit_evidence(sequence_value, event, links), None);
    journal.commit(transaction).unwrap();
}

fn authority_receipt(sequence_value: u64) -> ember_authority::model::AuthorityReceipt {
    let signer = AuthorityTestSigner::new(7);
    let generation = SignerGeneration {
        body: SignerGenerationBody {
            generation_id: SignerGenerationId::from_bytes([0x31; 32]),
            vault_id: VaultId::from_bytes([0x32; 32]),
            device_certificate_id: DeviceCertificateId::from_bytes([0x33; 32]),
            key_id: SignerKeyId::from_bytes([0x34; 32]),
            generation: NonZeroU32::MIN,
            purpose: SignerPurpose::AuthorityTransition,
            algorithm: SigningAlgorithm::EcdsaP256Sha256,
            public_key: signer.public.clone(),
            validity: ValidityInterval::new(sequence(1), sequence(100)).unwrap(),
            predecessor: None,
        },
        signature: CertificateSignature {
            issuer_key_id: SignerKeyId::from_bytes([0x35; 32]),
            signature: EvidenceSignatureBytes::P256Der(vec![0x30, 0]),
        },
    };
    issue_authority_receipt(
        &generation,
        AuthorityReceiptBody::new(
            EvidenceId::from_bytes([0x36; 32]),
            sequence(sequence_value),
            AuthorityObjectId::from_bytes([0x37; 32]),
            AuthorityTransitionKind::GrantIssue,
        ),
        &signer,
    )
    .unwrap()
}

#[test]
fn every_successful_batch_has_one_durable_checkpoint_and_atomic_state() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(1);
    let journal = open_journal(directory.path(), &signer).unwrap();

    let operation = OperationId::new();
    let mut first = JournalTransaction::new([1; 32]);
    first.push_evidence(
        audit_evidence(
            1,
            EventKind::OperationAdmitted,
            operation_links(operation.clone()),
        ),
        None,
    );
    first.put_state("operation/status", b"admitted".to_vec());
    let receipt = journal.commit(first).unwrap();
    assert_eq!((receipt.first_sequence, receipt.last_sequence), (1, 1));

    let first_snapshot = journal.verified_snapshot().unwrap();
    assert_eq!(first_snapshot.records().len(), 1);
    assert_eq!(first_snapshot.checkpoints().len(), 1);
    assert_eq!(
        first_snapshot.state("operation/status"),
        Some(&b"admitted"[..])
    );
    let expected_predecessor =
        canonical_checkpoint_predecessor(first_snapshot.checkpoints()).unwrap();

    let mut second = JournalTransaction::new([2; 32]);
    second.push_evidence(
        audit_evidence(2, EventKind::OperationTerminal, operation_links(operation)),
        None,
    );
    second.put_state("operation/status", b"terminal".to_vec());
    journal.commit(second).unwrap();

    let reopened = open_journal(directory.path(), &signer).unwrap();
    let snapshot = reopened.verified_snapshot().unwrap();
    assert_eq!(snapshot.records().len(), 2);
    assert_eq!(snapshot.checkpoints().len(), 2);
    assert_eq!(
        snapshot.checkpoints()[1].previous_checkpoint(),
        &expected_predecessor
    );
    assert_eq!(snapshot.state("operation/status"), Some(&b"terminal"[..]));
    assert!(
        snapshot
            .checkpoints()
            .iter()
            .all(|checkpoint| { checkpoint.first_sequence() <= checkpoint.last_sequence() })
    );
}

#[test]
fn concurrent_writers_prepare_against_the_sequence_reserved_under_the_global_lock() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(0x21);
    let first_writer = open_journal(directory.path(), &signer).unwrap();
    let second_writer = open_journal(directory.path(), &signer).unwrap();
    let barrier = Barrier::new(2);
    let first_operation = OperationId::new();
    let second_operation = OperationId::new();

    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            first_writer
                .commit_with_sequence(|sequence_value| {
                    let mut transaction = JournalTransaction::new([0x31; 32]);
                    transaction.push_evidence(
                        audit_evidence(
                            sequence_value,
                            EventKind::OperationAdmitted,
                            operation_links(first_operation),
                        ),
                        None,
                    );
                    Ok(transaction)
                })
                .unwrap()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            second_writer
                .commit_with_sequence(|sequence_value| {
                    let mut transaction = JournalTransaction::new([0x32; 32]);
                    transaction.push_evidence(
                        audit_evidence(
                            sequence_value,
                            EventKind::OperationAdmitted,
                            operation_links(second_operation),
                        ),
                        None,
                    );
                    Ok(transaction)
                })
                .unwrap()
        });
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_ne!(first.first_sequence(), second.first_sequence());
    });

    let snapshot = first_writer.verified_snapshot().unwrap();
    assert_eq!(snapshot.records().len(), 2);
    assert_eq!(snapshot.checkpoints().len(), 2);
    assert_eq!(
        snapshot
            .records()
            .iter()
            .map(|record| record.sequence())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn crashes_before_durable_replace_leave_no_record_checkpoint_or_state() {
    for fault in [
        CommitFault::BeforeRecord,
        CommitFault::AfterRecordBeforeCheckpoint,
        CommitFault::AfterCheckpointBeforeJournalReplace,
    ] {
        let directory = tempdir().unwrap();
        let signer = OperationalTestSigner::new(2);
        let journal = open_journal(directory.path(), &signer).unwrap();
        let mut transaction = JournalTransaction::new([4; 32]);
        transaction.push_evidence(
            audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
            None,
        );
        transaction.put_state("must-not-commit", vec![1]);
        assert!(matches!(
            journal.commit_with_fault(transaction, fault),
            Err(JournalError::InjectedInterruption)
        ));
        let reopened = open_journal(directory.path(), &signer).unwrap();
        let snapshot = reopened.verified_snapshot().unwrap();
        assert!(snapshot.records().is_empty());
        assert!(snapshot.checkpoints().is_empty());
        assert_eq!(snapshot.state("must-not-commit"), None);
    }
}

#[test]
fn status_signing_failure_occurs_before_the_journal_becomes_durable() {
    let directory = tempdir().unwrap();
    let high_water_root = directory.path().join("high-water");
    std::fs::create_dir_all(&high_water_root).unwrap();
    std::fs::set_permissions(&high_water_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let signer = FailingOperationalSigner {
        inner: OperationalTestSigner::new(0xA0),
        calls: Arc::new(AtomicUsize::new(0)),
        fail_on: 3,
    };
    let journal = EvidenceJournal::open(
        directory.path().join("journal"),
        identity(),
        JournalSecurity::new(
            high_water_root.join("journal.json"),
            JournalSealKey::from_bytes([0xE2; 32]),
            Arc::new(signer.clone()),
            signer.verifier(),
        ),
    )
    .unwrap();
    let mut transaction = JournalTransaction::new([0xA1; 32]);
    transaction.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        journal.commit(transaction),
        Err(JournalError::Storage(reason)) if reason == "injected signer failure"
    ));
    let snapshot = journal.verified_snapshot().unwrap();
    assert!(snapshot.records().is_empty());
    assert!(snapshot.checkpoints().is_empty());
}

#[test]
fn crash_after_journal_replace_repairs_status_without_losing_the_commit() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(15);
    let journal = open_journal(directory.path(), &signer).unwrap();
    let mut transaction = JournalTransaction::new([17; 32]);
    transaction.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        journal.commit_with_fault(transaction, CommitFault::AfterJournalReplaceBeforeStatus),
        Err(JournalError::InjectedInterruption)
    ));
    drop(journal);

    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(!reopened.health().unwrap().permits_new_authority_decision());
    let snapshot = reopened.recover_startup().unwrap();
    assert!(reopened.health().unwrap().permits_new_authority_decision());
    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.checkpoints().len(), 1);
    assert_eq!(snapshot.checkpoints()[0].last_sequence(), 1);
}

#[test]
fn response_loss_never_hides_a_durable_checkpointed_commit() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(3);
    let journal = open_journal(directory.path(), &signer).unwrap();
    let mut transaction = JournalTransaction::new([5; 32]);
    transaction.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        None,
    );
    let lost =
        journal.commit_with_fault(transaction, CommitFault::AfterDurableCommitBeforeResponse);
    assert!(matches!(lost, Err(JournalError::ResponseLost(_))));

    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(!reopened.health().unwrap().permits_new_authority_decision());
    let snapshot = reopened.recover_startup().unwrap();
    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.checkpoints().len(), 1);
    assert_eq!(snapshot.checkpoints()[0].last_sequence(), 1);
}

#[test]
fn operation_session_and_grant_rollups_rebuild_byte_identically() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(4);
    let journal = open_journal(directory.path(), &signer).unwrap();
    let operation = OperationId::new();
    let session = SessionId::new();
    let grant = GrantId::new();

    commit_fact(
        &journal,
        1,
        EventKind::SessionCreated,
        EvidenceLinks {
            session_id: Some(session.clone()),
            ..EvidenceLinks::default()
        },
    );
    commit_fact(
        &journal,
        2,
        EventKind::OperationAdmitted,
        EvidenceLinks {
            operation_id: Some(operation.clone()),
            session_id: Some(session.clone()),
            grant_id: Some(grant.clone()),
            materialization_id: None,
        },
    );
    commit_fact(
        &journal,
        3,
        EventKind::OperationTerminal,
        EvidenceLinks {
            operation_id: Some(operation.clone()),
            session_id: Some(session.clone()),
            grant_id: Some(grant.clone()),
            materialization_id: None,
        },
    );
    commit_fact(
        &journal,
        4,
        EventKind::SessionEnded,
        EvidenceLinks {
            session_id: Some(session.clone()),
            ..EvidenceLinks::default()
        },
    );

    let outcome = OperationOutcome::new(
        operation,
        SubmissionId::from_bytes([0x50; 32]),
        RequestDigest::from_bytes([0x51; 32]),
        sequence(3),
        None,
        ActionBoundary::EffectCompleted { succeeded: true },
    );
    let snapshot = journal.verified_snapshot().unwrap();
    let operation_a = encode_operation_view(
        &snapshot
            .rebuild_operation_view(&outcome, ProjectionVersion::V1)
            .unwrap(),
    );
    let operation_b = encode_operation_view(
        &snapshot
            .rebuild_operation_view(&outcome, ProjectionVersion::V1)
            .unwrap(),
    );
    assert_eq!(operation_a, operation_b);
    assert_eq!(
        serde_jcs::to_vec(&snapshot.rebuild_session_lifetime(&session, ProjectionVersion::V1))
            .unwrap(),
        serde_jcs::to_vec(&snapshot.rebuild_session_lifetime(&session, ProjectionVersion::V1))
            .unwrap()
    );
    assert_eq!(
        serde_jcs::to_vec(&snapshot.rebuild_grant_lineage(&grant, ProjectionVersion::V1)).unwrap(),
        serde_jcs::to_vec(&snapshot.rebuild_grant_lineage(&grant, ProjectionVersion::V1)).unwrap()
    );
    assert_eq!(
        encode_authority_rollup(
            &snapshot
                .rebuild_authority_rollup(ProjectionVersion::V1)
                .unwrap()
        ),
        encode_authority_rollup(
            &snapshot
                .rebuild_authority_rollup(ProjectionVersion::V1)
                .unwrap()
        )
    );
}

fn three_record_export_fixture() -> (
    tempfile::TempDir,
    OperationalTestSigner,
    OperationalVerifier,
    ember_authority::audit::EvidenceExport,
) {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(5);
    let verifier = signer.verifier();
    let journal = open_journal(directory.path(), &signer).unwrap();
    let operation = OperationId::new();
    let mut transaction = JournalTransaction::new([6; 32]);
    transaction.push_evidence(
        audit_evidence(
            1,
            EventKind::OperationAdmitted,
            operation_links(operation.clone()),
        ),
        None,
    );
    transaction.push_evidence(
        audit_evidence(
            2,
            EventKind::ActionResolved,
            operation_links(operation.clone()),
        ),
        None,
    );
    transaction.push_evidence(
        audit_evidence(3, EventKind::OperationTerminal, operation_links(operation)),
        None,
    );
    journal.commit(transaction).unwrap();
    let export = journal
        .verified_snapshot()
        .unwrap()
        .export(
            ExportScope::exact(vec![SequenceRange::new(1, 3).unwrap()]).unwrap(),
            false,
            ProjectionVersion::V1,
            &signer,
        )
        .unwrap();
    (directory, signer, verifier, export)
}

#[test]
fn exact_range_exports_require_explicit_gaps() {
    let (directory, signer, verifier, full) = three_record_export_fixture();
    verify_export(&full, identity(), &verifier).unwrap();
    let journal = open_journal(directory.path(), &signer).unwrap();
    let gapped = journal
        .verified_snapshot()
        .unwrap()
        .export(
            ExportScope::with_gaps(
                vec![SequenceRange::new(1, 3).unwrap()],
                vec![SequenceRange::new(2, 2).unwrap()],
            )
            .unwrap(),
            false,
            ProjectionVersion::V1,
            &signer,
        )
        .unwrap();
    assert_eq!(gapped.records.len(), 2);
    verify_export(&gapped, identity(), &verifier).unwrap();

    let mut omitted_without_gap = full;
    omitted_without_gap.records.remove(1);
    assert!(verify_export(&omitted_without_gap, identity(), &verifier).is_err());
}

#[test]
fn export_verifier_rejects_mutate_omit_reorder_and_substitute_matrix() {
    let (_directory, _signer, verifier, export) = three_record_export_fixture();

    let mut mutated = serde_json::to_value(&export).unwrap();
    mutated["records"][0]["event"] = serde_json::json!(255);
    let mutated = serde_json::from_value(mutated).unwrap();
    assert!(verify_export(&mutated, identity(), &verifier).is_err());

    let mut omitted = export.clone();
    omitted.records.remove(1);
    assert!(verify_export(&omitted, identity(), &verifier).is_err());

    let mut reordered = export.clone();
    reordered.records.swap(0, 2);
    assert!(verify_export(&reordered, identity(), &verifier).is_err());

    let mut substituted = serde_json::to_value(&export).unwrap();
    substituted["records"][1] = substituted["records"][0].clone();
    let substituted = serde_json::from_value(substituted).unwrap();
    assert!(verify_export(&substituted, identity(), &verifier).is_err());
}

#[test]
fn checkpoint_signature_cannot_substitute_for_export_manifest_signature() {
    let (_directory, _signer, verifier, export) = three_record_export_fixture();
    let mut substituted = serde_json::to_value(export).unwrap();
    substituted["manifest"]["signature"] =
        substituted["checkpoints"][0]["checkpoint"]["signature"].clone();
    let substituted = serde_json::from_value(substituted).unwrap();
    assert!(matches!(
        verify_export(&substituted, identity(), &verifier),
        Err(JournalError::InvalidSignature)
    ));
}

#[test]
fn payload_key_redaction_preserves_commitment_and_removes_disclosure() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(6);
    let verifier = signer.verifier();
    let journal = open_journal(directory.path(), &signer).unwrap();
    let key_id = PayloadKeyId::from_bytes([0x41; 32]);
    let key = [0x42; 32];
    let secret = b"sensitive-provider-observation";
    let payload = PayloadEnvelope::seal(key_id, &key, secret).unwrap();
    let commitment = *payload.commitment();
    let independently_keyed =
        PayloadEnvelope::seal(PayloadKeyId::from_bytes([0x43; 32]), &[0x44; 32], secret).unwrap();
    assert_ne!(commitment, *independently_keyed.commitment());

    let mut first = JournalTransaction::new([7; 32]);
    first.install_payload_key(key_id, key);
    first.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        Some(payload),
    );
    journal.commit(first).unwrap();
    assert_eq!(
        journal
            .verified_snapshot()
            .unwrap()
            .payload_plaintext(1)
            .unwrap(),
        secret
    );

    let receipt = authority_receipt(2);
    let mut redact = JournalTransaction::new([8; 32]);
    redact.push_evidence(PrimaryEvidence::authority_receipt(&receipt), None);
    redact.redact_payload_key(key_id);
    journal.commit(redact).unwrap();

    let snapshot = journal.verified_snapshot().unwrap();
    assert!(matches!(
        snapshot.payload_plaintext(1),
        Err(JournalError::PayloadRedacted)
    ));
    assert_eq!(
        snapshot.records()[0].payload_commitment(),
        Some(&commitment)
    );
    let export = snapshot
        .export(
            ExportScope::exact(vec![SequenceRange::new(1, 3).unwrap()]).unwrap(),
            false,
            ProjectionVersion::V1,
            &signer,
        )
        .unwrap();
    assert!(export.records[0].payload().is_none());
    assert_eq!(export.records[0].payload_commitment(), Some(&commitment));
    assert!(
        export
            .manifest
            .redactions()
            .iter()
            .any(|redaction| redaction.sequence == 1 && redaction.commitment == commitment)
    );
    verify_export(&export, identity(), &verifier).unwrap();
}

fn recovery_context(operation_id: OperationId) -> RecoveryContext {
    RecoveryContext {
        operation_id,
        session_id: SessionId::new(),
        persona_id: PersonaId::new(),
        process_binding_id: ProcessBindingId::new(),
        grant_id: GrantId::new(),
        delegation_path: vec![DelegationId::new()],
        action: "git.push".to_owned(),
        approved_input: serde_json::json!({"ref": "refs/heads/main"}),
        need: Need {
            provider: "github-app".to_owned(),
            repository: RepositoryResource::from_str("github:emberdotlink/ember").unwrap(),
            destination_ref: None,
            permissions: BTreeMap::from([("contents".to_owned(), PermissionLevel::Write)]),
        },
        provider: None,
    }
}

fn provider_evidence(
    provider_instance: ProviderInstanceId,
    generation: ProviderGeneration,
    expiry: i64,
) -> ProviderEvidence {
    ProviderEvidence {
        provider_instance,
        generation,
        app_slug: "ember".to_owned(),
        app_id: 1,
        installation_id: 2,
        repositories: vec!["emberdotlink/ember".to_owned()],
        permissions: BTreeMap::from([("contents".to_owned(), PermissionLevel::Write)]),
        expires_at_unix: expiry,
    }
}

#[test]
fn degraded_startup_preserves_unknown_intents_and_keeps_verified_reads() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(9);
    let evidence_root = directory.path().join("evidence");
    let recovery_root = directory.path().join("recovery");
    let journal = open_journal(&evidence_root, &signer).unwrap();
    journal
        .enter_degraded(0, "checkpoint verification failed")
        .unwrap();
    let recovery = RecoveryJournal::open(&recovery_root, [9; 32]).unwrap();
    let provider = ProviderInstanceId::new();
    let generation = ProviderGeneration::new();
    let operation = OperationId::new();
    let materialization = recovery
        .begin_mint(&recovery_context(operation.clone()), &provider, &generation)
        .unwrap();
    drop(recovery);

    let recovery = RecoveryJournal::open(&recovery_root, [9; 32]).unwrap();
    let status = StartupRecoveryStatus::inspect(&journal, &recovery, 1_000).unwrap();
    assert!(status.verified_reads_available());
    assert!(!status.new_authority_decisions_available());
    assert!(!status.new_provider_operations_available());
    assert_eq!(status.unknown_intents().len(), 1);
    assert_eq!(status.unknown_intents()[0].operation_id, operation);
    assert_eq!(
        status.unknown_intents()[0].materialization_id,
        materialization
    );
    assert_eq!(
        status.unknown_intents()[0].phase,
        RecoveryPhase::MintIntentUnknown
    );
    assert!(status.provider_generation_blocked(&provider, &generation));
}

#[test]
fn restart_retains_encrypted_materialization_and_safe_expiry() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(10);
    let evidence_root = directory.path().join("evidence");
    let recovery_root = directory.path().join("recovery");
    let journal = open_journal(&evidence_root, &signer).unwrap();
    let provider = ProviderInstanceId::new();
    let generation = ProviderGeneration::new();
    let materialization;
    {
        let recovery = RecoveryJournal::open(&recovery_root, [10; 32]).unwrap();
        materialization = recovery
            .begin_mint(
                &recovery_context(OperationId::new()),
                &provider,
                &generation,
            )
            .unwrap();
        recovery
            .record_token(
                &materialization,
                provider_evidence(provider.clone(), generation.clone(), 1_300),
                "bearer-value-must-never-reach-disk",
            )
            .unwrap();
    }

    for entry in std::fs::read_dir(&recovery_root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) == Some("entry") {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(b"bearer-value-must-never-reach-disk".len())
                    .any(|window| window == b"bearer-value-must-never-reach-disk")
            );
        }
    }

    let recovery = RecoveryJournal::open(&recovery_root, [10; 32]).unwrap();
    let unknown = StartupRecoveryStatus::inspect(&journal, &recovery, 1_200).unwrap();
    assert_eq!(
        unknown.unknown_intents()[0].phase,
        RecoveryPhase::MaterializedUnknown
    );
    assert!(unknown.provider_generation_blocked(&provider, &generation));
    let expired = StartupRecoveryStatus::inspect(&journal, &recovery, 1_300).unwrap();
    assert_eq!(
        expired.unknown_intents()[0].phase,
        RecoveryPhase::SafeExpiryReached
    );
    assert!(!expired.provider_generation_blocked(&provider, &generation));
    assert_eq!(
        expired.unknown_intents()[0].materialization_id,
        materialization
    );
}

#[test]
fn checkpoint_aligned_tail_rollback_is_caught_by_durable_high_water() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(11);
    let journal = open_journal(directory.path(), &signer).unwrap();
    commit_fact(
        &journal,
        1,
        EventKind::SessionCreated,
        EvidenceLinks::default(),
    );
    commit_fact(
        &journal,
        2,
        EventKind::SessionEnded,
        EvidenceLinks::default(),
    );
    drop(journal);

    let path = directory.path().join("journal/authority-journal.json");
    let mut disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    disk["records"].as_array_mut().unwrap().pop();
    disk["checkpoints"].as_array_mut().unwrap().pop();
    std::fs::write(&path, serde_jcs::to_vec(&disk).unwrap()).unwrap();

    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(matches!(
        reopened.health().unwrap(),
        ember_authority::audit::JournalHealth::Degraded {
            last_verified_sequence: 2,
            ..
        }
    ));
    let mut transaction = JournalTransaction::new([12; 32]);
    transaction.push_evidence(
        audit_evidence(2, EventKind::SessionEnded, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        reopened.commit(transaction),
        Err(JournalError::Degraded)
    ));
}

#[test]
fn degradation_is_fail_stop_across_restart() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(0xDD);
    {
        let journal = open_journal(directory.path(), &signer).unwrap();
        journal
            .enter_degraded(0, "operator repair required")
            .unwrap();
    }
    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(matches!(
        reopened.health().unwrap(),
        ember_authority::audit::JournalHealth::Degraded { reason, .. }
            if reason == "operator repair required"
    ));
    assert!(matches!(
        reopened.recover_startup(),
        Err(JournalError::Degraded)
    ));
    assert!(reopened.verified_snapshot().unwrap().records().is_empty());
}

#[test]
fn persisted_degraded_state_stops_an_already_open_writer() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(0xDE);
    let writer = open_journal(directory.path(), &signer).unwrap();
    let degrading_peer = open_journal(directory.path(), &signer).unwrap();
    degrading_peer
        .enter_degraded(0, "cross-process fail-stop")
        .unwrap();
    assert!(matches!(
        writer.health().unwrap(),
        ember_authority::audit::JournalHealth::Degraded { reason, .. }
            if reason == "cross-process fail-stop"
    ));

    let mut transaction = JournalTransaction::new([0xDE; 32]);
    transaction.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        writer.commit(transaction),
        Err(JournalError::Degraded)
    ));
    assert!(writer.verified_snapshot().unwrap().records().is_empty());
}

#[test]
fn checkpoint_signature_binds_private_state_and_payload_key_maps() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(12);
    let journal = open_journal(directory.path(), &signer).unwrap();
    let key_id = PayloadKeyId::from_bytes([0x61; 32]);
    let key = [0x62; 32];
    let mut transaction = JournalTransaction::new([13; 32]);
    transaction.install_payload_key(key_id, key);
    transaction.put_state("operation/example", b"terminal".to_vec());
    transaction.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        Some(PayloadEnvelope::seal(key_id, &key, b"observation").unwrap()),
    );
    journal.commit(transaction).unwrap();
    drop(journal);

    let path = directory.path().join("journal/authority-journal.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

    let mut state_tampered = original.clone();
    state_tampered["state"]["operation/example"] = serde_json::json!([0]);
    std::fs::write(&path, serde_jcs::to_vec(&state_tampered).unwrap()).unwrap();
    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(matches!(
        reopened.verified_snapshot(),
        Err(JournalError::CheckpointRoot)
    ));
    std::fs::write(&path, serde_jcs::to_vec(&original).unwrap()).unwrap();
    let mut envelope_tampered = original;
    let byte = envelope_tampered["records"][0]["payload"]["ciphertext"][0]
        .as_u64()
        .unwrap();
    envelope_tampered["records"][0]["payload"]["ciphertext"][0] = serde_json::json!(byte ^ 1);
    std::fs::write(&path, serde_jcs::to_vec(&envelope_tampered).unwrap()).unwrap();
    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(matches!(
        reopened.verified_snapshot(),
        Err(JournalError::PayloadCommitmentMismatch)
    ));
}

#[test]
fn payload_key_mutations_cannot_resurrect_or_replace_keys() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(13);
    let journal = open_journal(directory.path(), &signer).unwrap();
    let key_id = PayloadKeyId::from_bytes([0x71; 32]);
    let key = [0x72; 32];
    let mut transaction = JournalTransaction::new([14; 32]);
    transaction.install_payload_key(key_id, key);
    transaction.redact_payload_key(key_id);
    transaction.push_evidence(
        PrimaryEvidence::authority_receipt(&authority_receipt(1)),
        None,
    );
    assert!(matches!(
        journal.commit(transaction),
        Err(JournalError::ConflictingPayloadKeyMutation)
    ));

    let mut initial = JournalTransaction::new([17; 32]);
    initial.install_payload_key(key_id, key);
    initial.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        Some(PayloadEnvelope::seal(key_id, &key, b"first").unwrap()),
    );
    journal.commit(initial).unwrap();

    let mut replacement = JournalTransaction::new([18; 32]);
    replacement.install_payload_key(key_id, [0x75; 32]);
    replacement.push_evidence(
        audit_evidence(2, EventKind::SessionEnded, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        journal.commit(replacement),
        Err(JournalError::DuplicatePayloadKey)
    ));

    let mut redact = JournalTransaction::new([19; 32]);
    redact.push_evidence(
        PrimaryEvidence::authority_receipt(&authority_receipt(2)),
        None,
    );
    redact.redact_payload_key(key_id);
    journal.commit(redact).unwrap();

    let mut resurrection = JournalTransaction::new([20; 32]);
    resurrection.install_payload_key(key_id, key);
    resurrection.push_evidence(
        audit_evidence(4, EventKind::SessionEnded, EvidenceLinks::default()),
        None,
    );
    assert!(matches!(
        journal.commit(resurrection),
        Err(JournalError::DuplicatePayloadKey)
    ));
    assert!(matches!(
        journal.verified_snapshot().unwrap().payload_plaintext(1),
        Err(JournalError::PayloadRedacted)
    ));

    drop(journal);
    let path = directory.path().join("journal/authority-journal.json");
    let mut disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    disk["redacted_payload_keys"] = serde_json::json!([]);
    std::fs::write(&path, serde_jcs::to_vec(&disk).unwrap()).unwrap();
    let reopened = open_journal(directory.path(), &signer).unwrap();
    assert!(matches!(
        reopened.verified_snapshot(),
        Err(JournalError::InvalidRedactionMarker)
    ));
}

#[test]
fn gapped_export_hides_redaction_metadata_and_record_preimages() {
    let directory = tempdir().unwrap();
    let signer = OperationalTestSigner::new(14);
    let verifier = signer.verifier();
    let journal = open_journal(directory.path(), &signer).unwrap();
    let key_id = PayloadKeyId::from_bytes([0x73; 32]);
    let key = [0x74; 32];
    let mut initial = JournalTransaction::new([15; 32]);
    initial.install_payload_key(key_id, key);
    initial.push_evidence(
        audit_evidence(1, EventKind::SessionCreated, EvidenceLinks::default()),
        Some(PayloadEnvelope::seal(key_id, &key, b"secret").unwrap()),
    );
    journal.commit(initial).unwrap();
    let mut redact = JournalTransaction::new([16; 32]);
    redact.push_evidence(
        PrimaryEvidence::authority_receipt(&authority_receipt(2)),
        None,
    );
    redact.redact_payload_key(key_id);
    journal.commit(redact).unwrap();

    let snapshot = journal.verified_snapshot().unwrap();
    let omitted_record_hash = *snapshot.records()[0].record_hash();
    let export = snapshot
        .export(
            ExportScope::with_gaps(
                vec![SequenceRange::new(1, 3).unwrap()],
                vec![SequenceRange::new(1, 1).unwrap()],
            )
            .unwrap(),
            true,
            ProjectionVersion::V1,
            &signer,
        )
        .unwrap();
    assert!(export.manifest.redactions().is_empty());
    assert!(export.records.iter().all(|record| record.sequence() != 1));
    let omitted_leaf = export.checkpoints[0]
        .leaves
        .iter()
        .find(|leaf| leaf.sequence == 1)
        .unwrap();
    assert_ne!(omitted_leaf.digest, omitted_record_hash);
    verify_export(&export, identity(), &verifier).unwrap();
}
