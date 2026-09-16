//! One-slot authority Credential catalog.
//!
//! This module owns the durable catalog state machine and its journal seam.
//! Operator material is held only in zeroizing memory while deriving a keyed
//! commitment. Only the opaque material-key reference and commitment can enter
//! durable state; superseding or deleting a Revision removes that reference
//! while retaining its keyed commitment.

use std::{
    collections::BTreeSet,
    num::NonZeroU64,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, RngCore as _};
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey as _, pkcs8::DecodePrivateKey as _,
    traits::PublicKeyParts as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    audit::{
        CommitFault, CommitReceipt, EvidenceJournal, EvidenceSigner, JournalError,
        JournalTransaction, PrimaryEvidence, VerifiedSnapshot, issue_authority_receipt,
    },
    identity::{IdentityError, SignerGeneration},
    model::{
        AuditFact, AuthorityObjectId, AuthorityReceipt, AuthorityReceiptBody,
        AuthorityTransitionKind, EventKind, EvidenceId, JournalSequence,
    },
};

pub const CREDENTIAL_CATALOG_SCHEMA: &str = "ember.authority-credential-catalog/v1";
const CATALOG_STATE_KEY: &str = "authority-credential-catalog";
pub const MAX_GITHUB_APP_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const TRANSITION_DOMAIN: &[u8] = b"ember.credential-catalog.transition/v1\0";

macro_rules! opaque_random_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn new() -> Self {
                Self(random_bytes())
            }

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            fn is_valid(self) -> bool {
                self.0 != [0; 32]
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

opaque_random_id!(CredentialId);
opaque_random_id!(RevisionId);
opaque_random_id!(MaterialKeyReference);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    GithubAppPrivateKey,
}

impl Kind {
    fn validate_material(self, material: &[u8]) -> Result<(), CatalogError> {
        match self {
            Self::GithubAppPrivateKey => validate_github_app_private_key(material),
        }
    }
}

/// Operator-supplied Credential material accepted by the catalog seam.
///
/// Construction consumes the caller's allocation, validates it once for its
/// declared [`Kind`], and keeps it zeroizing until preparation has derived its
/// keyed commitment through [`MaterialCommitmentCapability`]. The bytes have
/// no public accessor and never enter durable state, intent/display/proof,
/// evidence, diagnostics, or logs.
pub struct CredentialMaterial {
    kind: Kind,
    bytes: Zeroizing<Vec<u8>>,
}

impl CredentialMaterial {
    pub fn new(kind: Kind, bytes: Vec<u8>) -> Result<Self, CatalogError> {
        let bytes = Zeroizing::new(bytes);
        kind.validate_material(bytes.as_slice())?;
        Ok(Self { kind, bytes })
    }

    const fn kind(&self) -> Kind {
        self.kind
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyProfile {
    MacosDeviceBoundUserPresenceV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RevisionCommitment([u8; 32]);

impl RevisionCommitment {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn is_valid(self) -> bool {
        self.0 != [0; 32]
    }
}

/// Versioned domain every custody implementation must bind into commitments.
pub const MATERIAL_COMMITMENT_DOMAIN: &[u8] = b"ember.credential-revision.material-commitment/v1\0";

/// Full non-secret immutable Revision tuple bound by custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentBinding {
    credential_id: CredentialId,
    revision_id: RevisionId,
    kind: Kind,
    subject: GithubAppSubject,
    custody_profile: CustodyProfile,
    key_reference: MaterialKeyReference,
}

impl CommitmentBinding {
    pub fn new(
        credential_id: CredentialId,
        revision_id: RevisionId,
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
        key_reference: MaterialKeyReference,
    ) -> Result<Self, CatalogError> {
        subject.validate()?;
        if !credential_id.is_valid() || !revision_id.is_valid() || !key_reference.is_valid() {
            return Err(CatalogError::InvalidPreparedMaterial);
        }
        Ok(Self {
            credential_id,
            revision_id,
            kind,
            subject,
            custody_profile,
            key_reference,
        })
    }

    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    pub const fn kind(&self) -> Kind {
        self.kind
    }

    pub const fn subject(&self) -> &GithubAppSubject {
        &self.subject
    }

    pub const fn custody_profile(&self) -> CustodyProfile {
        self.custody_profile
    }

    pub const fn key_reference(&self) -> MaterialKeyReference {
        self.key_reference
    }
}

/// Non-enumerating capability seam implemented by custody. Implementations
/// must include [`MATERIAL_COMMITMENT_DOMAIN`] and every [`CommitmentBinding`]
/// field in their keyed construction. Credential material crosses this seam
/// transiently only while constructing the commitment; it is never persisted
/// and never enters intent/display/proof, evidence, diagnostics, or logs.
pub trait MaterialCommitmentCapability {
    fn commit(
        &mut self,
        binding: &CommitmentBinding,
        material: &[u8],
    ) -> Result<RevisionCommitment, CatalogError>;
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubAppSubject {
    app_id: u64,
    installation_id: u64,
}

impl GithubAppSubject {
    pub fn new(app_id: u64, installation_id: u64) -> Result<Self, CatalogError> {
        let subject = Self {
            app_id,
            installation_id,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    fn validate(&self) -> Result<(), CatalogError> {
        if self.app_id == 0 || self.installation_id == 0 {
            return Err(CatalogError::InvalidSubject);
        }
        Ok(())
    }
}

/// Exact identity and immutable attributes expected by rotate or delete.
///
/// Requiring the complete current tuple makes stale and replayed authority
/// decisions fail closed rather than silently following the current pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialExpectation {
    credential_id: CredentialId,
    revision_id: RevisionId,
    kind: Kind,
    subject: GithubAppSubject,
    commitment: RevisionCommitment,
    custody_profile: CustodyProfile,
}

impl CredentialExpectation {
    pub fn new(
        credential_id: CredentialId,
        revision_id: RevisionId,
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
        commitment: RevisionCommitment,
    ) -> Self {
        Self {
            credential_id,
            revision_id,
            kind,
            subject,
            custody_profile,
            commitment,
        }
    }

    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    pub const fn kind(&self) -> Kind {
        self.kind
    }

    pub const fn commitment(&self) -> RevisionCommitment {
        self.commitment
    }

    pub const fn subject(&self) -> &GithubAppSubject {
        &self.subject
    }

    pub const fn custody_profile(&self) -> CustodyProfile {
        self.custody_profile
    }
}

/// Opaque custody descriptor prepared before a journal mutation.
///
/// The descriptor contains no secret bytes. A custody-held capability binds
/// material to the full immutable Revision tuple while retaining the only
/// verification key outside this module.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedMaterial {
    credential_id: CredentialId,
    revision_id: RevisionId,
    key_reference: MaterialKeyReference,
    commitment: RevisionCommitment,
}

impl PreparedMaterial {
    fn new(
        scope: CredentialScope<'_>,
        revision_id: RevisionId,
        key_reference: MaterialKeyReference,
        material: CredentialMaterial,
        commitments: &mut dyn MaterialCommitmentCapability,
    ) -> Result<Self, CatalogError> {
        if material.kind() != scope.kind {
            return Err(CatalogError::KindMismatch);
        }
        if !key_reference.is_valid() {
            return Err(CatalogError::InvalidPreparedMaterial);
        }
        let binding = CommitmentBinding {
            credential_id: scope.credential_id,
            revision_id,
            kind: scope.kind,
            subject: scope.subject.clone(),
            custody_profile: scope.custody_profile,
            key_reference,
        };
        let commitment = commitments.commit(&binding, material.as_bytes())?;
        if !commitment.is_valid() {
            return Err(CatalogError::InvalidPreparedMaterial);
        }
        Ok(Self {
            credential_id: scope.credential_id,
            revision_id,
            key_reference,
            commitment,
        })
    }
}

#[derive(Clone, Debug)]
pub struct EnrollCredential {
    mutation_id: [u8; 32],
    evidence_id: [u8; 32],
    kind: Kind,
    subject: GithubAppSubject,
    custody_profile: CustodyProfile,
    material: PreparedMaterial,
}

impl EnrollCredential {
    pub fn prepare(
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
        key_reference: MaterialKeyReference,
        material: CredentialMaterial,
        commitments: &mut dyn MaterialCommitmentCapability,
    ) -> Result<Self, CatalogError> {
        subject.validate()?;
        let credential_id = CredentialId::new();
        let revision_id = RevisionId::new();
        let material = PreparedMaterial::new(
            CredentialScope::new(credential_id, kind, &subject, custody_profile),
            revision_id,
            key_reference,
            material,
            commitments,
        )?;
        Ok(Self {
            mutation_id: random_bytes(),
            evidence_id: random_bytes(),
            kind,
            subject,
            custody_profile,
            material,
        })
    }

    pub const fn credential_id(&self) -> CredentialId {
        self.material.credential_id
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.material.revision_id
    }

    pub const fn commitment(&self) -> RevisionCommitment {
        self.material.commitment
    }

    pub fn presence_operation(&self) -> crate::principal::PresenceOperation {
        crate::principal::PresenceOperation::EnrollCredential {
            credential_id: self.material.credential_id,
            revision_id: self.material.revision_id,
            kind: self.kind,
            subject: self.subject.clone(),
            custody_profile: self.custody_profile,
            commitment: self.material.commitment,
            key_reference: self.material.key_reference,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RotateCredential {
    mutation_id: [u8; 32],
    evidence_id: [u8; 32],
    expected: CredentialExpectation,
    material: PreparedMaterial,
}

impl RotateCredential {
    pub fn prepare(
        expected: CredentialExpectation,
        key_reference: MaterialKeyReference,
        material: CredentialMaterial,
        commitments: &mut dyn MaterialCommitmentCapability,
    ) -> Result<Self, CatalogError> {
        expected.subject.validate()?;
        if !expected.credential_id.is_valid()
            || !expected.revision_id.is_valid()
            || !expected.commitment.is_valid()
        {
            return Err(CatalogError::InvalidPreparedMaterial);
        }
        let revision_id = RevisionId::new();
        let material = PreparedMaterial::new(
            CredentialScope::new(
                expected.credential_id,
                expected.kind,
                &expected.subject,
                expected.custody_profile,
            ),
            revision_id,
            key_reference,
            material,
            commitments,
        )?;
        Ok(Self {
            mutation_id: random_bytes(),
            evidence_id: random_bytes(),
            material,
            expected,
        })
    }

    pub const fn credential_id(&self) -> CredentialId {
        self.material.credential_id
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.material.revision_id
    }

    pub const fn commitment(&self) -> RevisionCommitment {
        self.material.commitment
    }

    pub fn presence_operation(&self) -> crate::principal::PresenceOperation {
        crate::principal::PresenceOperation::RotateCredential {
            credential_id: self.expected.credential_id,
            current_revision_id: self.expected.revision_id,
            current_commitment: self.expected.commitment,
            new_revision_id: self.material.revision_id,
            new_commitment: self.material.commitment,
            kind: self.expected.kind,
            subject: self.expected.subject.clone(),
            custody_profile: self.expected.custody_profile,
            key_reference: self.material.key_reference,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeleteCredential {
    mutation_id: [u8; 32],
    evidence_id: [u8; 32],
    expected: CredentialExpectation,
}

impl DeleteCredential {
    pub fn new(expected: CredentialExpectation) -> Result<Self, CatalogError> {
        expected.subject.validate()?;
        if !expected.credential_id.is_valid()
            || !expected.revision_id.is_valid()
            || !expected.commitment.is_valid()
        {
            return Err(CatalogError::InvalidPreparedMaterial);
        }
        Ok(Self {
            mutation_id: random_bytes(),
            evidence_id: random_bytes(),
            expected,
        })
    }

    pub fn presence_operation(&self) -> crate::principal::PresenceOperation {
        crate::principal::PresenceOperation::DeleteCredential {
            credential_id: self.expected.credential_id,
            current_revision_id: self.expected.revision_id,
            current_commitment: self.expected.commitment,
            kind: self.expected.kind,
            subject: self.expected.subject.clone(),
            custody_profile: self.expected.custody_profile,
        }
    }
}

/// Authority-transition signing capability used after the catalog consumes a
/// fresh verifier for the exact operation.
pub struct CatalogAuthority<'a> {
    generation: &'a SignerGeneration,
    signer: &'a dyn EvidenceSigner,
}

impl<'a> CatalogAuthority<'a> {
    pub fn new(generation: &'a SignerGeneration, signer: &'a dyn EvidenceSigner) -> Self {
        Self { generation, signer }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialTransition {
    credential: CredentialExpectation,
    ordinal: NonZeroU64,
    evidence: CredentialTransitionEvidence,
    receipt: AuthorityReceipt,
    commit: CommitReceipt,
}

impl CredentialTransition {
    pub const fn credential(&self) -> &CredentialExpectation {
        &self.credential
    }

    pub const fn ordinal(&self) -> NonZeroU64 {
        self.ordinal
    }

    pub const fn evidence(&self) -> &CredentialTransitionEvidence {
        &self.evidence
    }

    pub const fn authority_receipt(&self) -> &AuthorityReceipt {
        &self.receipt
    }

    pub const fn commit_receipt(&self) -> &CommitReceipt {
        &self.commit
    }
}

#[derive(Clone, Debug)]
pub struct CredentialDeletion {
    credential_id: CredentialId,
    revision_id: RevisionId,
    retained_commitment: RevisionCommitment,
    evidence: CredentialTransitionEvidence,
    receipt: AuthorityReceipt,
    commit: CommitReceipt,
}

impl CredentialDeletion {
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    pub const fn revision_id(&self) -> RevisionId {
        self.revision_id
    }

    pub const fn retained_commitment(&self) -> RevisionCommitment {
        self.retained_commitment
    }

    pub const fn evidence(&self) -> &CredentialTransitionEvidence {
        &self.evidence
    }

    pub const fn authority_receipt(&self) -> &AuthorityReceipt {
        &self.receipt
    }

    pub const fn commit_receipt(&self) -> &CommitReceipt {
        &self.commit
    }
}

/// Deep one-slot catalog module. Every method consumes fresh exact-operation
/// presence, then revalidates canonical durable state under the journal lock.
///
/// Session and execution identities intentionally have no catalog interface:
///
/// ```compile_fail
/// use ember_authority::{catalog::CredentialCatalog, model::SessionId};
/// fn catalog_from_session(session: &SessionId) -> &CredentialCatalog {
///     session.catalog()
/// }
/// ```
pub struct CredentialCatalog {
    journal: Arc<EvidenceJournal>,
}

impl CredentialCatalog {
    pub fn open(journal: Arc<EvidenceJournal>) -> Result<Self, CatalogError> {
        let snapshot = journal.verified_snapshot()?;
        load_state(&snapshot)?;
        Ok(Self { journal })
    }

    fn record_refusal(
        &self,
        event: EventKind,
        fault: CommitFault,
    ) -> Result<CommitReceipt, CatalogError> {
        self.journal.commit_with_verified_snapshot_and_fault(
            |sequence, snapshot| {
                load_state(snapshot)?;
                refusal_transaction(sequence, event)
            },
            fault,
        )
    }

    pub fn enroll(
        &self,
        request: &EnrollCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
    ) -> Result<CredentialTransition, CatalogError> {
        self.enroll_with_fault(request, presence, authority, CommitFault::None)
    }

    #[doc(hidden)]
    pub fn enroll_with_fault(
        &self,
        request: &EnrollCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
        fault: CommitFault,
    ) -> Result<CredentialTransition, CatalogError> {
        if !presence_is_valid(presence, &request.presence_operation()) {
            self.record_refusal(EventKind::CredentialEnrollPresenceRefused, fault)?;
            return Err(CatalogError::PresenceRequired);
        }
        let now = unix_now()?;
        let mut issued = None;
        let mut resulting = None;
        let mut evidence = None;
        let mut refusal = None;
        let commit = self.journal.commit_with_verified_snapshot_and_fault(
            |sequence, snapshot| {
                let mut state = load_state(snapshot)?;
                if is_replay(&state, request.mutation_id) {
                    refusal = Some(CatalogError::AlreadyApplied);
                    return refusal_transaction(sequence, EventKind::CredentialEnrollReplayRefused);
                }
                if state.active.is_some() {
                    refusal = Some(CatalogError::Occupied);
                    return refusal_transaction(sequence, EventKind::CredentialEnrollOccupied);
                }
                let timestamp = state
                    .tombstones
                    .last()
                    .map_or(now, |tombstone| now.max(tombstone.deleted_at_unix));
                let revision = Revision {
                    id: request.material.revision_id,
                    ordinal: 1,
                    commitment: request.material.commitment,
                    created_at_unix: timestamp,
                    transition: TransitionLink::pending(
                        request.mutation_id,
                        request.evidence_id,
                        sequence,
                        CatalogTransitionKind::Enroll,
                    )?,
                };
                let mut credential = Credential {
                    id: request.material.credential_id,
                    kind: request.kind,
                    subject: request.subject.clone(),
                    custody_profile: request.custody_profile,
                    enrolled_at_unix: timestamp,
                    updated_at_unix: timestamp,
                    current: revision.id,
                    revisions: vec![revision],
                    current_material: DurableMaterialReference::from_prepared(&request.material),
                    destroyed: Vec::new(),
                };
                complete_current_transition(&mut credential)?;
                evidence = Some(transition_object(
                    &credential.revisions[0].transition,
                    &credential.revisions[0],
                    CredentialScope::active(&credential),
                    credential.enrolled_at_unix,
                ));
                let receipt = make_receipt(
                    authority,
                    request.evidence_id,
                    sequence,
                    credential.revisions[0].transition.authority_object_id,
                    AuthorityTransitionKind::CredentialEnroll,
                )?;
                resulting = Some(expectation_from(&credential));
                issued = Some(receipt.clone());
                state.active = Some(credential);
                state.validate()?;
                transaction(request.mutation_id, state, receipt)
            },
            fault,
        )?;
        if let Some(error) = refusal {
            return Err(error);
        }
        Ok(CredentialTransition {
            credential: resulting.ok_or(CatalogError::InvariantViolation)?,
            ordinal: NonZeroU64::MIN,
            evidence: evidence.ok_or(CatalogError::InvariantViolation)?,
            receipt: issued.ok_or(CatalogError::InvariantViolation)?,
            commit,
        })
    }

    pub fn rotate(
        &self,
        request: &RotateCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
    ) -> Result<CredentialTransition, CatalogError> {
        self.rotate_with_fault(request, presence, authority, CommitFault::None)
    }

    #[doc(hidden)]
    pub fn rotate_with_fault(
        &self,
        request: &RotateCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
        fault: CommitFault,
    ) -> Result<CredentialTransition, CatalogError> {
        if !presence_is_valid(presence, &request.presence_operation()) {
            self.record_refusal(EventKind::CredentialRotatePresenceRefused, fault)?;
            return Err(CatalogError::PresenceRequired);
        }
        let now = unix_now()?;
        let mut issued = None;
        let mut resulting = None;
        let mut ordinal = None;
        let mut evidence = None;
        let mut refusal = None;
        let commit = self.journal.commit_with_verified_snapshot_and_fault(
            |sequence, snapshot| {
                let mut state = load_state(snapshot)?;
                if is_replay(&state, request.mutation_id) {
                    refusal = Some(CatalogError::AlreadyApplied);
                    return refusal_transaction(sequence, EventKind::CredentialRotateReplayRefused);
                }
                let Some(credential) = state.active.as_mut() else {
                    refusal = Some(CatalogError::Empty);
                    return refusal_transaction(sequence, EventKind::CredentialRotateEmpty);
                };
                if let Err(error) = validate_expectation(credential, &request.expected) {
                    refusal = Some(error);
                    return refusal_transaction(sequence, EventKind::CredentialRotateMismatch);
                }
                if request.material.credential_id != credential.id {
                    refusal = Some(CatalogError::CredentialMismatch);
                    return refusal_transaction(sequence, EventKind::CredentialRotateMismatch);
                }
                let next_ordinal = credential
                    .revisions
                    .last()
                    .and_then(|revision| revision.ordinal.checked_add(1))
                    .ok_or(CatalogError::OrdinalOverflow)?;
                let timestamp = now.max(credential.updated_at_unix);
                credential.destroyed.push(DestroyedRevision {
                    revision_id: credential.current,
                    destroyed_at_unix: timestamp,
                });
                credential.current_material =
                    DurableMaterialReference::from_prepared(&request.material);
                credential.current = request.material.revision_id;
                credential.updated_at_unix = timestamp;
                credential.revisions.push(Revision {
                    id: request.material.revision_id,
                    ordinal: next_ordinal,
                    commitment: request.material.commitment,
                    created_at_unix: timestamp,
                    transition: TransitionLink::pending(
                        request.mutation_id,
                        request.evidence_id,
                        sequence,
                        CatalogTransitionKind::Rotate,
                    )?,
                });
                complete_current_transition(credential)?;
                let current_revision = credential
                    .revisions
                    .last()
                    .ok_or(CatalogError::InvariantViolation)?;
                evidence = Some(transition_object(
                    &current_revision.transition,
                    current_revision,
                    CredentialScope::active(credential),
                    credential.updated_at_unix,
                ));
                let receipt = make_receipt(
                    authority,
                    request.evidence_id,
                    sequence,
                    current_revision.transition.authority_object_id,
                    AuthorityTransitionKind::CredentialRotate,
                )?;
                ordinal = NonZeroU64::new(next_ordinal);
                resulting = Some(expectation_from(credential));
                issued = Some(receipt.clone());
                state.validate()?;
                transaction(request.mutation_id, state, receipt)
            },
            fault,
        )?;
        if let Some(error) = refusal {
            return Err(error);
        }
        Ok(CredentialTransition {
            credential: resulting.ok_or(CatalogError::InvariantViolation)?,
            ordinal: ordinal.ok_or(CatalogError::InvariantViolation)?,
            evidence: evidence.ok_or(CatalogError::InvariantViolation)?,
            receipt: issued.ok_or(CatalogError::InvariantViolation)?,
            commit,
        })
    }

    pub fn delete(
        &self,
        request: &DeleteCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
    ) -> Result<CredentialDeletion, CatalogError> {
        self.delete_with_fault(request, presence, authority, CommitFault::None)
    }

    #[doc(hidden)]
    pub fn delete_with_fault(
        &self,
        request: &DeleteCredential,
        presence: Option<&mut dyn crate::principal::PresenceVerifier>,
        authority: &CatalogAuthority<'_>,
        fault: CommitFault,
    ) -> Result<CredentialDeletion, CatalogError> {
        if !presence_is_valid(presence, &request.presence_operation()) {
            self.record_refusal(EventKind::CredentialDeletePresenceRefused, fault)?;
            return Err(CatalogError::PresenceRequired);
        }
        let now = unix_now()?;
        let mut issued = None;
        let mut deleted = None;
        let mut evidence = None;
        let mut refusal = None;
        let commit = self.journal.commit_with_verified_snapshot_and_fault(
            |sequence, snapshot| {
                let mut state = load_state(snapshot)?;
                if is_replay(&state, request.mutation_id) {
                    refusal = Some(CatalogError::AlreadyApplied);
                    return refusal_transaction(sequence, EventKind::CredentialDeleteReplayRefused);
                }
                let Some(credential) = state.active.take() else {
                    refusal = Some(CatalogError::Empty);
                    return refusal_transaction(sequence, EventKind::CredentialDeleteEmpty);
                };
                if let Err(error) = validate_expectation(&credential, &request.expected) {
                    refusal = Some(error);
                    return refusal_transaction(sequence, EventKind::CredentialDeleteMismatch);
                }
                let timestamp = now.max(credential.updated_at_unix);
                let (current_revision_id, current_commitment) = credential
                    .revisions
                    .last()
                    .map(|revision| (revision.id, revision.commitment))
                    .ok_or(CatalogError::InvariantViolation)?;
                let mut destroyed = credential.destroyed;
                destroyed.push(DestroyedRevision {
                    revision_id: credential.current,
                    destroyed_at_unix: timestamp,
                });
                let mut tombstone = Tombstone {
                    credential_id: credential.id,
                    kind: credential.kind,
                    subject: credential.subject,
                    custody_profile: credential.custody_profile,
                    enrolled_at_unix: credential.enrolled_at_unix,
                    deleted_at_unix: timestamp,
                    revisions: credential.revisions,
                    destroyed,
                    deletion: TransitionLink::pending(
                        request.mutation_id,
                        request.evidence_id,
                        sequence,
                        CatalogTransitionKind::Delete,
                    )?,
                };
                complete_delete_transition(&mut tombstone)?;
                let current_revision = tombstone
                    .revisions
                    .last()
                    .ok_or(CatalogError::InvariantViolation)?;
                evidence = Some(transition_object(
                    &tombstone.deletion,
                    current_revision,
                    CredentialScope::tombstone(&tombstone),
                    tombstone.deleted_at_unix,
                ));
                let receipt = make_receipt(
                    authority,
                    request.evidence_id,
                    sequence,
                    tombstone.deletion.authority_object_id,
                    AuthorityTransitionKind::CredentialDelete,
                )?;
                deleted = Some((
                    tombstone.credential_id,
                    current_revision_id,
                    current_commitment,
                ));
                issued = Some(receipt.clone());
                state.tombstones.push(tombstone);
                state.validate()?;
                transaction(request.mutation_id, state, receipt)
            },
            fault,
        )?;
        if let Some(error) = refusal {
            return Err(error);
        }
        let (credential_id, revision_id, retained_commitment) =
            deleted.ok_or(CatalogError::InvariantViolation)?;
        Ok(CredentialDeletion {
            credential_id,
            revision_id,
            retained_commitment,
            evidence: evidence.ok_or(CatalogError::InvariantViolation)?,
            receipt: issued.ok_or(CatalogError::InvariantViolation)?,
            commit,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogState {
    schema: String,
    active: Option<Credential>,
    tombstones: Vec<Tombstone>,
}

impl Default for CatalogState {
    fn default() -> Self {
        Self {
            schema: CREDENTIAL_CATALOG_SCHEMA.to_owned(),
            active: None,
            tombstones: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    id: CredentialId,
    kind: Kind,
    subject: GithubAppSubject,
    custody_profile: CustodyProfile,
    enrolled_at_unix: u64,
    updated_at_unix: u64,
    current: RevisionId,
    revisions: Vec<Revision>,
    current_material: DurableMaterialReference,
    destroyed: Vec<DestroyedRevision>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    id: RevisionId,
    ordinal: u64,
    commitment: RevisionCommitment,
    created_at_unix: u64,
    transition: TransitionLink,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableMaterialReference {
    credential_id: CredentialId,
    revision_id: RevisionId,
    key_reference: MaterialKeyReference,
    commitment: RevisionCommitment,
}

impl DurableMaterialReference {
    fn from_prepared(prepared: &PreparedMaterial) -> Self {
        Self {
            credential_id: prepared.credential_id,
            revision_id: prepared.revision_id,
            key_reference: prepared.key_reference,
            commitment: prepared.commitment,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DestroyedRevision {
    revision_id: RevisionId,
    destroyed_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    credential_id: CredentialId,
    kind: Kind,
    subject: GithubAppSubject,
    custody_profile: CustodyProfile,
    enrolled_at_unix: u64,
    deleted_at_unix: u64,
    revisions: Vec<Revision>,
    destroyed: Vec<DestroyedRevision>,
    deletion: TransitionLink,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogTransitionKind {
    Enroll,
    Rotate,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionLink {
    mutation_id: [u8; 32],
    evidence_id: [u8; 32],
    sequence: u64,
    kind: CatalogTransitionKind,
    authority_object_id: [u8; 32],
}

impl TransitionLink {
    fn pending(
        mutation_id: [u8; 32],
        evidence_id: [u8; 32],
        sequence: u64,
        kind: CatalogTransitionKind,
    ) -> Result<Self, CatalogError> {
        if sequence == 0 || mutation_id == [0; 32] || evidence_id == [0; 32] {
            return Err(CatalogError::InvariantViolation);
        }
        Ok(Self {
            mutation_id,
            evidence_id,
            sequence,
            kind,
            authority_object_id: [0; 32],
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTransitionEvidence {
    schema: String,
    kind: CatalogTransitionKind,
    mutation_id: [u8; 32],
    evidence_id: [u8; 32],
    sequence: u64,
    credential_id: CredentialId,
    revision_id: RevisionId,
    ordinal: u64,
    credential_kind: Kind,
    subject: GithubAppSubject,
    custody_profile: CustodyProfile,
    commitment: RevisionCommitment,
    occurred_at_unix: u64,
}

impl CredentialTransitionEvidence {
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, CatalogError> {
        let evidence: Self =
            serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidTransitionEvidence)?;
        if evidence.schema != CREDENTIAL_CATALOG_SCHEMA
            || evidence.mutation_id == [0; 32]
            || evidence.evidence_id == [0; 32]
            || evidence.sequence == 0
            || !evidence.credential_id.is_valid()
            || !evidence.revision_id.is_valid()
            || evidence.ordinal == 0
            || !evidence.commitment.is_valid()
            || evidence.occurred_at_unix == 0
        {
            return Err(CatalogError::InvalidTransitionEvidence);
        }
        evidence.subject.validate()?;
        if serde_jcs::to_vec(&evidence).map_err(|_| CatalogError::InvalidTransitionEvidence)?
            != bytes
        {
            return Err(CatalogError::NonCanonicalTransitionEvidence);
        }
        Ok(evidence)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CatalogError> {
        serde_jcs::to_vec(self).map_err(|_| CatalogError::InvalidTransitionEvidence)
    }

    pub fn authority_object_id(&self) -> Result<AuthorityObjectId, CatalogError> {
        Ok(AuthorityObjectId::from_bytes(transition_object_id(self)?))
    }

    pub const fn kind(&self) -> CatalogTransitionKind {
        self.kind
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl CatalogState {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.schema != CREDENTIAL_CATALOG_SCHEMA {
            return Err(CatalogError::InvalidDurableState);
        }
        let mut credential_ids = BTreeSet::new();
        let mut revision_ids = BTreeSet::new();
        let mut commitments = BTreeSet::new();
        let mut last_sequence = 0;
        for tombstone in &self.tombstones {
            validate_tombstone(
                tombstone,
                &mut credential_ids,
                &mut revision_ids,
                &mut commitments,
                &mut last_sequence,
            )?;
        }
        if let Some(credential) = &self.active {
            validate_credential(
                credential,
                &mut credential_ids,
                &mut revision_ids,
                &mut commitments,
                &mut last_sequence,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct CredentialScope<'a> {
    credential_id: CredentialId,
    kind: Kind,
    subject: &'a GithubAppSubject,
    custody_profile: CustodyProfile,
}

impl<'a> CredentialScope<'a> {
    const fn new(
        credential_id: CredentialId,
        kind: Kind,
        subject: &'a GithubAppSubject,
        custody_profile: CustodyProfile,
    ) -> Self {
        Self {
            credential_id,
            kind,
            subject,
            custody_profile,
        }
    }

    fn active(credential: &'a Credential) -> Self {
        Self {
            credential_id: credential.id,
            kind: credential.kind,
            subject: &credential.subject,
            custody_profile: credential.custody_profile,
        }
    }

    fn tombstone(tombstone: &'a Tombstone) -> Self {
        Self {
            credential_id: tombstone.credential_id,
            kind: tombstone.kind,
            subject: &tombstone.subject,
            custody_profile: tombstone.custody_profile,
        }
    }
}

fn validate_credential(
    credential: &Credential,
    credential_ids: &mut BTreeSet<CredentialId>,
    revision_ids: &mut BTreeSet<RevisionId>,
    commitments: &mut BTreeSet<RevisionCommitment>,
    last_sequence: &mut u64,
) -> Result<(), CatalogError> {
    credential.subject.validate()?;
    if !credential.id.is_valid()
        || !credential_ids.insert(credential.id)
        || credential.enrolled_at_unix == 0
        || credential.updated_at_unix < credential.enrolled_at_unix
        || credential.revisions.is_empty()
        || credential.current_material.credential_id != credential.id
        || credential.current_material.revision_id != credential.current
        || !credential.current_material.key_reference.is_valid()
        || !credential.current_material.commitment.is_valid()
    {
        return Err(CatalogError::InvalidDurableState);
    }
    validate_revisions(
        CredentialScope::active(credential),
        credential.enrolled_at_unix,
        &credential.revisions,
        revision_ids,
        commitments,
        last_sequence,
    )?;
    let current = credential
        .revisions
        .last()
        .ok_or(CatalogError::InvalidDurableState)?;
    if credential.current != current.id
        || credential.updated_at_unix != current.created_at_unix
        || credential.current_material.commitment != current.commitment
    {
        return Err(CatalogError::InvalidDurableState);
    }
    validate_destroyed(
        &credential.revisions[..credential.revisions.len() - 1],
        &credential.destroyed,
        credential.updated_at_unix,
    )
}

fn validate_tombstone(
    tombstone: &Tombstone,
    credential_ids: &mut BTreeSet<CredentialId>,
    revision_ids: &mut BTreeSet<RevisionId>,
    commitments: &mut BTreeSet<RevisionCommitment>,
    last_sequence: &mut u64,
) -> Result<(), CatalogError> {
    tombstone.subject.validate()?;
    if !tombstone.credential_id.is_valid()
        || !credential_ids.insert(tombstone.credential_id)
        || tombstone.enrolled_at_unix == 0
        || tombstone.deleted_at_unix < tombstone.enrolled_at_unix
        || tombstone.revisions.is_empty()
        || tombstone.deletion.kind != CatalogTransitionKind::Delete
        || tombstone.deletion.sequence <= *last_sequence
    {
        return Err(CatalogError::InvalidDurableState);
    }
    validate_revisions(
        CredentialScope::tombstone(tombstone),
        tombstone.enrolled_at_unix,
        &tombstone.revisions,
        revision_ids,
        commitments,
        last_sequence,
    )?;
    if tombstone.deletion.sequence <= *last_sequence {
        return Err(CatalogError::InvalidDurableState);
    }
    validate_transition_object(
        &tombstone.deletion,
        tombstone
            .revisions
            .last()
            .ok_or(CatalogError::InvalidDurableState)?,
        CredentialScope::tombstone(tombstone),
        tombstone.deleted_at_unix,
    )?;
    *last_sequence = tombstone.deletion.sequence;
    validate_destroyed(
        &tombstone.revisions,
        &tombstone.destroyed,
        tombstone.deleted_at_unix,
    )
}

fn validate_revisions(
    scope: CredentialScope<'_>,
    enrolled_at_unix: u64,
    revisions: &[Revision],
    revision_ids: &mut BTreeSet<RevisionId>,
    commitments: &mut BTreeSet<RevisionCommitment>,
    last_sequence: &mut u64,
) -> Result<(), CatalogError> {
    let mut previous_time = enrolled_at_unix;
    for (index, revision) in revisions.iter().enumerate() {
        let ordinal = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(CatalogError::InvalidDurableState)?;
        let expected_kind = if index == 0 {
            CatalogTransitionKind::Enroll
        } else {
            CatalogTransitionKind::Rotate
        };
        if !revision.id.is_valid()
            || !revision_ids.insert(revision.id)
            || revision.ordinal != ordinal
            || !revision.commitment.is_valid()
            || !commitments.insert(revision.commitment)
            || revision.created_at_unix < previous_time
            || revision.transition.kind != expected_kind
            || revision.transition.sequence <= *last_sequence
        {
            return Err(CatalogError::InvalidDurableState);
        }
        validate_transition_object(
            &revision.transition,
            revision,
            scope,
            revision.created_at_unix,
        )?;
        *last_sequence = revision.transition.sequence;
        previous_time = revision.created_at_unix;
    }
    Ok(())
}

fn validate_destroyed(
    revisions: &[Revision],
    destroyed: &[DestroyedRevision],
    upper_time: u64,
) -> Result<(), CatalogError> {
    if revisions.len() != destroyed.len() {
        return Err(CatalogError::InvalidDurableState);
    }
    for (revision, marker) in revisions.iter().zip(destroyed) {
        if marker.revision_id != revision.id
            || marker.destroyed_at_unix < revision.created_at_unix
            || marker.destroyed_at_unix > upper_time
        {
            return Err(CatalogError::InvalidDurableState);
        }
    }
    Ok(())
}

fn complete_current_transition(credential: &mut Credential) -> Result<(), CatalogError> {
    let revision = credential
        .revisions
        .last()
        .ok_or(CatalogError::InvariantViolation)?;
    let object = transition_object(
        &revision.transition,
        revision,
        CredentialScope::active(credential),
        revision.created_at_unix,
    );
    let object_id = transition_object_id(&object)?;
    credential
        .revisions
        .last_mut()
        .ok_or(CatalogError::InvariantViolation)?
        .transition
        .authority_object_id = object_id;
    Ok(())
}

fn complete_delete_transition(tombstone: &mut Tombstone) -> Result<(), CatalogError> {
    let revision = tombstone
        .revisions
        .last()
        .ok_or(CatalogError::InvariantViolation)?;
    let object = transition_object(
        &tombstone.deletion,
        revision,
        CredentialScope::tombstone(tombstone),
        tombstone.deleted_at_unix,
    );
    tombstone.deletion.authority_object_id = transition_object_id(&object)?;
    Ok(())
}

fn validate_transition_object(
    link: &TransitionLink,
    revision: &Revision,
    scope: CredentialScope<'_>,
    occurred_at_unix: u64,
) -> Result<(), CatalogError> {
    if link.mutation_id == [0; 32]
        || link.evidence_id == [0; 32]
        || link.sequence == 0
        || link.authority_object_id == [0; 32]
        || transition_object_id(&transition_object(link, revision, scope, occurred_at_unix))?
            != link.authority_object_id
    {
        return Err(CatalogError::InvalidDurableState);
    }
    Ok(())
}

fn transition_object(
    link: &TransitionLink,
    revision: &Revision,
    scope: CredentialScope<'_>,
    occurred_at_unix: u64,
) -> CredentialTransitionEvidence {
    CredentialTransitionEvidence {
        schema: CREDENTIAL_CATALOG_SCHEMA.to_owned(),
        kind: link.kind,
        mutation_id: link.mutation_id,
        evidence_id: link.evidence_id,
        sequence: link.sequence,
        credential_id: scope.credential_id,
        revision_id: revision.id,
        ordinal: revision.ordinal,
        credential_kind: scope.kind,
        subject: scope.subject.clone(),
        custody_profile: scope.custody_profile,
        commitment: revision.commitment,
        occurred_at_unix,
    }
}

fn transition_object_id(object: &CredentialTransitionEvidence) -> Result<[u8; 32], CatalogError> {
    let canonical = serde_jcs::to_vec(object).map_err(|_| CatalogError::InvalidDurableState)?;
    let mut digest = Sha256::new();
    digest.update(TRANSITION_DOMAIN);
    digest.update((canonical.len() as u64).to_be_bytes());
    digest.update(canonical);
    Ok(digest.finalize().into())
}

fn expectation_from(credential: &Credential) -> CredentialExpectation {
    let revision = credential
        .revisions
        .last()
        .expect("validated active Credential has a current Revision");
    CredentialExpectation::new(
        credential.id,
        revision.id,
        credential.kind,
        credential.subject.clone(),
        credential.custody_profile,
        revision.commitment,
    )
}

fn presence_is_valid(
    presence: Option<&mut dyn crate::principal::PresenceVerifier>,
    operation: &crate::principal::PresenceOperation,
) -> bool {
    presence.is_some_and(|verifier| verifier.verify_presence(operation))
}

fn validate_expectation(
    credential: &Credential,
    expected: &CredentialExpectation,
) -> Result<(), CatalogError> {
    if credential.id != expected.credential_id {
        return Err(CatalogError::CredentialMismatch);
    }
    if credential.kind != expected.kind {
        return Err(CatalogError::KindMismatch);
    }
    if credential.subject != expected.subject {
        return Err(CatalogError::SubjectMismatch);
    }
    if credential.custody_profile != expected.custody_profile {
        return Err(CatalogError::CustodyMismatch);
    }
    if credential.current != expected.revision_id {
        return Err(CatalogError::RevisionMismatch);
    }
    let current = credential
        .revisions
        .last()
        .ok_or(CatalogError::InvalidDurableState)?;
    if current.commitment != expected.commitment {
        return Err(CatalogError::CommitmentMismatch);
    }
    Ok(())
}

fn is_replay(state: &CatalogState, mutation_id: [u8; 32]) -> bool {
    state
        .active
        .iter()
        .flat_map(|credential| &credential.revisions)
        .any(|revision| revision.transition.mutation_id == mutation_id)
        || state.tombstones.iter().any(|tombstone| {
            tombstone.deletion.mutation_id == mutation_id
                || tombstone
                    .revisions
                    .iter()
                    .any(|revision| revision.transition.mutation_id == mutation_id)
        })
}

fn make_receipt(
    authority: &CatalogAuthority<'_>,
    evidence_id: [u8; 32],
    sequence: u64,
    authority_object_id: [u8; 32],
    transition: AuthorityTransitionKind,
) -> Result<AuthorityReceipt, CatalogError> {
    let sequence = JournalSequence::new(sequence).ok_or(CatalogError::InvariantViolation)?;
    Ok(issue_authority_receipt(
        authority.generation,
        AuthorityReceiptBody::new(
            EvidenceId::from_bytes(evidence_id),
            sequence,
            AuthorityObjectId::from_bytes(authority_object_id),
            transition,
        ),
        authority.signer,
    )?)
}

fn refusal_transaction(
    sequence: u64,
    event: EventKind,
) -> Result<JournalTransaction, CatalogError> {
    let sequence = JournalSequence::new(sequence).ok_or(CatalogError::InvariantViolation)?;
    let fact = AuditFact::new(
        EvidenceId::from_bytes(random_bytes()),
        sequence,
        event,
        None,
    )
    .map_err(|_| CatalogError::InvariantViolation)?;
    let evidence = PrimaryEvidence::audit_fact(&fact, Default::default())?;
    let mut transaction = JournalTransaction::new(random_bytes());
    transaction.push_evidence(evidence, None);
    Ok(transaction)
}

fn transaction(
    transaction_id: [u8; 32],
    state: CatalogState,
    receipt: AuthorityReceipt,
) -> Result<JournalTransaction, CatalogError> {
    let canonical = serde_jcs::to_vec(&state).map_err(|_| CatalogError::InvalidDurableState)?;
    let mut transaction = JournalTransaction::new(transaction_id);
    transaction.put_state(CATALOG_STATE_KEY, canonical);
    transaction.push_evidence(PrimaryEvidence::authority_receipt(&receipt), None);
    Ok(transaction)
}

fn load_state(snapshot: &VerifiedSnapshot) -> Result<CatalogState, CatalogError> {
    let Some(bytes) = snapshot.state(CATALOG_STATE_KEY) else {
        return Ok(CatalogState::default());
    };
    let state: CatalogState =
        serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidDurableState)?;
    let canonical = serde_jcs::to_vec(&state).map_err(|_| CatalogError::InvalidDurableState)?;
    if canonical != bytes {
        return Err(CatalogError::NonCanonicalDurableState);
    }
    state.validate()?;
    validate_receipt_links(&state, snapshot)?;
    Ok(state)
}

fn validate_receipt_links(
    state: &CatalogState,
    snapshot: &VerifiedSnapshot,
) -> Result<(), CatalogError> {
    let validate = |link: &TransitionLink| -> Result<(), CatalogError> {
        let sequence =
            JournalSequence::new(link.sequence).ok_or(CatalogError::InvalidDurableState)?;
        let record_index =
            usize::try_from(link.sequence - 1).map_err(|_| CatalogError::InvalidDurableState)?;
        let transition = match link.kind {
            CatalogTransitionKind::Enroll => AuthorityTransitionKind::CredentialEnroll,
            CatalogTransitionKind::Rotate => AuthorityTransitionKind::CredentialRotate,
            CatalogTransitionKind::Delete => AuthorityTransitionKind::CredentialDelete,
        };
        let body = AuthorityReceiptBody::new(
            EvidenceId::from_bytes(link.evidence_id),
            sequence,
            AuthorityObjectId::from_bytes(link.authority_object_id),
            transition,
        );
        if !snapshot
            .records()
            .get(record_index)
            .is_some_and(|record| record.matches_authority_receipt_body(&body))
        {
            return Err(CatalogError::InvalidDurableState);
        }
        Ok(())
    };

    for tombstone in &state.tombstones {
        for revision in &tombstone.revisions {
            validate(&revision.transition)?;
        }
        validate(&tombstone.deletion)?;
    }
    if let Some(credential) = &state.active {
        for revision in &credential.revisions {
            validate(&revision.transition)?;
        }
    }
    Ok(())
}

fn random_bytes() -> [u8; 32] {
    loop {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if bytes != [0; 32] {
            return bytes;
        }
    }
}

fn validate_github_app_private_key(material: &[u8]) -> Result<(), CatalogError> {
    if material.is_empty() || material.len() > MAX_GITHUB_APP_PRIVATE_KEY_BYTES {
        return Err(CatalogError::InvalidPreparedMaterial);
    }
    let text = std::str::from_utf8(material).map_err(|_| CatalogError::InvalidPreparedMaterial)?;
    let trimmed = text.trim();
    let footer = if trimmed.starts_with(concat!("-----BEGIN RSA ", "PRIVATE KEY-----")) {
        concat!("-----END RSA ", "PRIVATE KEY-----")
    } else if trimmed.starts_with(concat!("-----BEGIN ", "PRIVATE KEY-----")) {
        concat!("-----END ", "PRIVATE KEY-----")
    } else {
        return Err(CatalogError::InvalidPreparedMaterial);
    };
    if !trimmed.ends_with(footer)
        || trimmed.matches("-----BEGIN ").count() != 1
        || trimmed.matches("-----END ").count() != 1
    {
        return Err(CatalogError::InvalidPreparedMaterial);
    }
    let key = RsaPrivateKey::from_pkcs8_pem(trimmed)
        .ok()
        .or_else(|| RsaPrivateKey::from_pkcs1_pem(trimmed).ok())
        .ok_or(CatalogError::InvalidPreparedMaterial)?;
    key.validate()
        .map_err(|_| CatalogError::InvalidPreparedMaterial)?;
    if key.n().bits() < 2048 || key.e().bits() < 17 {
        return Err(CatalogError::InvalidPreparedMaterial);
    }
    Ok(())
}

fn unix_now() -> Result<u64, CatalogError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().max(1))
        .map_err(|_| CatalogError::Clock)
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("fresh operator presence for the exact Credential transition is required")]
    PresenceRequired,
    #[error("the sole Credential slot is occupied")]
    Occupied,
    #[error("the sole Credential slot is empty")]
    Empty,
    #[error("the Credential identity does not match the current slot")]
    CredentialMismatch,
    #[error("the Revision identity does not match the current pointer")]
    RevisionMismatch,
    #[error("the Credential Kind does not match")]
    KindMismatch,
    #[error("the provider subject does not match")]
    SubjectMismatch,
    #[error("the Credential custody profile does not match")]
    CustodyMismatch,
    #[error("the Revision commitment does not match")]
    CommitmentMismatch,
    #[error("the exact catalog mutation was already committed")]
    AlreadyApplied,
    #[error("the GitHub App subject is invalid")]
    InvalidSubject,
    #[error("the prepared custody material descriptor is invalid")]
    InvalidPreparedMaterial,
    #[error("the durable Credential catalog is invalid")]
    InvalidDurableState,
    #[error("the durable Credential catalog is not canonical RFC 8785 JSON")]
    NonCanonicalDurableState,
    #[error("Credential transition evidence is invalid")]
    InvalidTransitionEvidence,
    #[error("Credential transition evidence is not canonical RFC 8785 JSON")]
    NonCanonicalTransitionEvidence,
    #[error("the Revision ordinal overflowed")]
    OrdinalOverflow,
    #[error("the system clock is before the Unix epoch")]
    Clock,
    #[error("the Credential catalog invariant was violated")]
    InvariantViolation,
    #[error("authority evidence issuance failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("authority journal operation failed: {0}")]
    Journal(#[from] JournalError),
}
