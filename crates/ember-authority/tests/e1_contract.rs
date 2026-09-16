use std::num::NonZeroU32;

use ember_authority::{
    audit::{signature_message, verify_signature},
    identity::{
        CompromiseCutoff, DeviceCertificateId, EvidencePublicKey, EvidenceSignatureBytes,
        SignatureDomain, SignerGenerationBody, SignerGenerationId, SignerKeyId, SignerPurpose,
        SigningAlgorithm, ValidityInterval, VaultId, validate_successor_generation,
    },
    model::{
        ActionBoundary, EventClassification, EventKind, EvidenceRole, JournalSequence, OperationId,
        OperationOutcome, OperationView, ProjectionVersion, RequestDigest, SettlementState,
        SubmissionBinding, SubmissionId, SubmissionResolution, resolve_submission,
    },
};

fn sequence(value: u64) -> JournalSequence {
    JournalSequence::new(value).unwrap()
}

#[test]
fn closed_event_vocabulary_has_exactly_three_evidence_roles() {
    fn exhaustive(role: EvidenceRole) -> u8 {
        match role {
            EvidenceRole::AuthorityReceipt => 1,
            EvidenceRole::AuditFact => 2,
            EvidenceRole::AuthorityRollup => 3,
        }
    }
    assert_eq!(exhaustive(EvidenceRole::AuthorityReceipt), 1);
    assert_eq!(
        EventKind::GrantIssued.classification(),
        EventClassification::Evidence(EvidenceRole::AuthorityReceipt)
    );
    assert_eq!(
        EventKind::OperationTerminal.classification(),
        EventClassification::Evidence(EvidenceRole::AuditFact)
    );
    assert_eq!(
        EventKind::OperatorRollupView.classification(),
        EventClassification::Evidence(EvidenceRole::AuthorityRollup)
    );
}

#[test]
fn submission_resolution_is_unknown_identical_or_conflict() {
    let submission = SubmissionId::from_bytes([1; 32]);
    let digest = RequestDigest::of(b"canonical request");
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
        resolve_submission(submission, RequestDigest::of(b"different"), Some(&binding)),
        SubmissionResolution::Conflict {
            existing_operation_id: operation
        }
    );
}

#[test]
fn explicit_derived_fields_construct_view_without_mutating_outcome() {
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
    assert_eq!(view.through_sequence(), sequence(3));
    assert_eq!(view.settlement(), SettlementState::Settled);
    assert!(view.authority_revoked_after_boundary());
    assert_eq!(outcome, immutable);
}

#[test]
fn successor_rotation_is_exact_and_cutoff_is_generation_bound() {
    let validity = ValidityInterval::new(sequence(1), sequence(10)).unwrap();
    let predecessor = SignerGenerationBody {
        generation_id: SignerGenerationId::from_bytes([1; 32]),
        vault_id: VaultId::from_bytes([2; 32]),
        device_certificate_id: DeviceCertificateId::from_bytes([3; 32]),
        key_id: SignerKeyId::from_bytes([4; 32]),
        generation: NonZeroU32::new(1).unwrap(),
        purpose: SignerPurpose::AuthorityTransition,
        algorithm: SigningAlgorithm::EcdsaP256Sha256,
        public_key: EvidencePublicKey::P256(vec![2; 33]),
        validity,
        predecessor: None,
    };
    let successor = SignerGenerationBody {
        generation_id: SignerGenerationId::from_bytes([5; 32]),
        key_id: SignerKeyId::from_bytes([6; 32]),
        generation: NonZeroU32::new(2).unwrap(),
        public_key: EvidencePublicKey::P256(vec![3; 33]),
        validity: ValidityInterval::new(sequence(11), sequence(20)).unwrap(),
        predecessor: Some(predecessor.generation_id),
        ..predecessor.clone()
    };
    validate_successor_generation(&predecessor, &successor).unwrap();

    let cutoff = CompromiseCutoff::new(predecessor.generation_id, sequence(2));
    assert_eq!(cutoff.generation_id, predecessor.generation_id);
    assert_eq!(cutoff.first_untrusted, sequence(2));
}

#[test]
fn p256_evidence_verification_rejects_malleated_high_s() {
    use p256::ecdsa::signature::Signer as _;

    let signing_key = p256::ecdsa::SigningKey::from_bytes((&[0x31_u8; 32]).into()).unwrap();
    let public_key = EvidencePublicKey::P256(
        signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
    );
    let payload = b"durable-evidence";
    let domain = SignatureDomain::AuthorityTransition;
    let message = signature_message(domain, payload);
    let low: p256::ecdsa::Signature = signing_key.sign(&message);
    let (r, s) = low.split_scalars();
    let high_s = -*s.as_ref();
    let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();

    assert!(
        verify_signature(
            domain,
            &public_key,
            payload,
            &EvidenceSignatureBytes::P256Der(low.to_der().as_bytes().to_vec()),
        )
        .is_ok()
    );
    assert!(
        verify_signature(
            domain,
            &public_key,
            payload,
            &EvidenceSignatureBytes::P256Der(high.to_der().as_bytes().to_vec()),
        )
        .is_err()
    );
}
