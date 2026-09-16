use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::model::OperationId;

const DIRECTORY_MODE: u32 = 0o700;
const MUTABLE_FILE_MODE: u32 = 0o600;

fn read_regular_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != crate::effective_uid()
        || metadata.mode() & 0o177 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stored value is not an owner-private regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn atomic_replace(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    create_only: bool,
) -> Result<(), JournalError> {
    let parent = path.parent().ok_or(JournalError::InvalidJournalRoot)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".journal-write-")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    if create_only {
        temporary
            .persist_noclobber(path)
            .map_err(|error| JournalError::Io(error.error))?;
    } else {
        temporary
            .persist(path)
            .map_err(|error| JournalError::Io(error.error))?;
    }
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Schema written by the single monotonic authority journal.
pub const AUTHORITY_JOURNAL_SCHEMA: &str = "ember.authority-journal/v1";
/// Schema of a signed commitment over one durable transaction.
pub const AUDIT_CHECKPOINT_SCHEMA: &str = "ember.audit-checkpoint/v1";
/// Schema of an exact-scope evidence export.
pub const EXPORT_MANIFEST_SCHEMA: &str = "ember.export-manifest/v1";
/// Version of the file durability contract. Every successful replacement
/// performs file `fsync`, atomic rename, and parent-directory `fsync`.
pub const FULL_DURABILITY_V1: &str = "fsync-file+atomic-rename+fsync-directory/v1";
/// The sole predecessor of the first Checkpoint. Writer and verifier call
/// [`canonical_checkpoint_predecessor`] rather than maintaining separate seeds.
pub const CHECKPOINT_GENESIS: [u8; 32] = [0; 32];

const JOURNAL_FILE: &str = "authority-journal.json";
const JOURNAL_LOCK: &str = "authority-journal.lock";
const JOURNAL_STATUS_SCHEMA: &str = "ember.authority-journal-status/v2";
const CHECKPOINT_DOMAIN: &[u8] = b"ember.audit-checkpoint.signature/v1\0";
const EXPORT_DOMAIN: &[u8] = b"ember.export-manifest.signature/v1\0";
const HIGH_WATER_DOMAIN: &[u8] = b"ember.authority-journal.high-water.signature/v1\0";
const RECORD_DOMAIN: &[u8] = b"ember.authority-journal.record/v1\0";
const RECORD_LEAF_DOMAIN: &[u8] = b"ember.authority-journal.record-leaf/v1\0";
const CHECKPOINT_HASH_DOMAIN: &[u8] = b"ember.audit-checkpoint.hash/v1\0";
const PAYLOAD_COMMITMENT_DOMAIN: &[u8] = b"ember.evidence-payload.commitment/v1\0";
const PAYLOAD_KEY_AAD_DOMAIN: &[u8] = b"ember.authority-journal.payload-key/v1\0";

/// Stable journal identity. Checkpoints and exports cannot cross a vault or
/// device boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalIdentity {
    vault_id: [u8; 32],
    device_id: [u8; 32],
}

impl JournalIdentity {
    /// Constructs an identity from the vault and device that own the journal.
    pub const fn new(
        vault_id: crate::identity::VaultId,
        device_id: crate::identity::DeviceId,
    ) -> Self {
        Self {
            vault_id: *vault_id.as_bytes(),
            device_id: *device_id.as_bytes(),
        }
    }

    /// Returns the vault identifier bytes bound into every signed anchor.
    pub const fn vault_id(&self) -> &[u8; 32] {
        &self.vault_id
    }

    /// Returns the device identifier bytes bound into every signed anchor.
    pub const fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }
}

/// Cryptographically separate operational-evidence purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalEvidenceDomain {
    /// Signature domain for one transaction checkpoint.
    AuditCheckpoint,
    /// Signature domain for one exact-scope export manifest.
    ExportManifest,
    /// Signature domain for the rollback-resistant high-water anchor.
    JournalHighWater,
}

impl OperationalEvidenceDomain {
    fn separator(self) -> &'static [u8] {
        match self {
            Self::AuditCheckpoint => CHECKPOINT_DOMAIN,
            Self::ExportManifest => EXPORT_DOMAIN,
            Self::JournalHighWater => HIGH_WATER_DOMAIN,
        }
    }
}

/// Daemon-held Ed25519 signer boundary. Callers provide the complete
/// domain-bound message assembled by this module.
pub trait OperationalEvidenceSigner: Send + Sync {
    /// Returns the installed signer-generation identifier.
    fn generation_id(&self) -> crate::identity::SignerGenerationId;
    /// Signs an already domain-bound canonical message.
    fn sign_bound_message(&self, message: &[u8]) -> Result<[u8; 64], JournalError>;
}

/// Owner-private Ed25519 operational-evidence capability provisioned at install.
pub struct Ed25519OperationalEvidenceSigner {
    generation_id: crate::identity::SignerGenerationId,
    key: SigningKey,
}

impl Ed25519OperationalEvidenceSigner {
    /// Creates an operational signer from an installed 32-byte Ed25519 seed.
    pub fn from_seed(generation_id: crate::identity::SignerGenerationId, seed: [u8; 32]) -> Self {
        Self {
            generation_id,
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Creates a verifier that trusts only this signer generation.
    pub fn verifier(&self) -> OperationalVerifier {
        let mut verifier = OperationalVerifier::default();
        verifier.trust(self.generation_id, self.key.verifying_key().to_bytes());
        verifier
    }

    /// Returns this signer's Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl OperationalEvidenceSigner for Ed25519OperationalEvidenceSigner {
    fn generation_id(&self) -> crate::identity::SignerGenerationId {
        self.generation_id
    }

    fn sign_bound_message(&self, message: &[u8]) -> Result<[u8; 64], JournalError> {
        Ok(self.key.sign(message).to_bytes())
    }
}
/// Owner-private wrapping key for journal payload keys. The wrapping key is
/// provisioned separately from payload keys and is never serialized with the
/// journal.
pub struct JournalSealKey(Zeroizing<[u8; 32]>);

impl JournalSealKey {
    /// Wraps the installed 32-byte payload-key sealing key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Security capabilities and rollback anchor for one journal.
///
/// `high_water_path` must live outside `journal_root`; restoring or replacing
/// the journal directory therefore cannot also restore its signed monotonic
/// high-water anchor.
pub struct JournalSecurity {
    high_water_path: PathBuf,
    seal_key: Arc<JournalSealKey>,
    signer: Arc<dyn OperationalEvidenceSigner>,
    verifier: OperationalVerifier,
}

impl JournalSecurity {
    /// Binds the journal to its external high-water path, seal key, signer,
    /// and trusted operational verifier.
    pub fn new(
        high_water_path: impl Into<PathBuf>,
        seal_key: JournalSealKey,
        signer: Arc<dyn OperationalEvidenceSigner>,
        verifier: OperationalVerifier,
    ) -> Self {
        Self {
            high_water_path: high_water_path.into(),
            seal_key: Arc::new(seal_key),
            signer,
            verifier,
        }
    }
}

#[cfg(test)]
pub(crate) type TestEvidenceContext = (
    std::sync::Arc<EvidenceJournal>,
    std::sync::Arc<dyn OperationalEvidenceSigner>,
    OperationalVerifier,
);

#[cfg(test)]
pub(crate) fn test_evidence_context(
    root: impl AsRef<Path>,
) -> Result<TestEvidenceContext, JournalError> {
    let root = root.as_ref();
    let anchor_directory = root.join("test-high-water");
    fs::create_dir_all(&anchor_directory)?;
    fs::set_permissions(
        &anchor_directory,
        fs::Permissions::from_mode(DIRECTORY_MODE),
    )?;
    let signer = std::sync::Arc::new(Ed25519OperationalEvidenceSigner::from_seed(
        crate::identity::SignerGenerationId::from_bytes([0xA5; 32]),
        [0x5A; 32],
    ));
    let verifier = signer.verifier();
    let security = JournalSecurity::new(
        anchor_directory.join("journal.json"),
        JournalSealKey::from_bytes([0xA6; 32]),
        signer.clone(),
        verifier.clone(),
    );
    let journal = std::sync::Arc::new(EvidenceJournal::open(
        root.join("evidence"),
        JournalIdentity::new(
            crate::identity::VaultId::from_bytes([0x51; 32]),
            crate::identity::DeviceId::from_bytes([0x52; 32]),
        ),
        security,
    )?);
    Ok((journal, signer, verifier))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Signature bytes and signer generation attached to an operational artifact.
pub struct OperationalSignature {
    generation_id: [u8; 32],
    bytes: Vec<u8>,
}

impl OperationalSignature {
    /// Returns the signer-generation identifier.
    pub const fn generation_id(&self) -> &[u8; 32] {
        &self.generation_id
    }

    /// Returns the canonical signature bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Causal coordinates used only to build deterministic operator projections.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLinks {
    /// Operation causally associated with the evidence, if any.
    pub operation_id: Option<OperationId>,
    /// Session causally associated with the evidence, if any.
    pub session_id: Option<crate::model::SessionId>,
    /// Grant causally associated with the evidence, if any.
    pub grant_id: Option<crate::model::GrantId>,
    /// Materialization causally associated with the evidence, if any.
    pub materialization_id: Option<crate::model::MaterializationId>,
}

/// One E1 primary-evidence object prepared for the canonical journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimaryEvidence {
    role: PrimaryRole,
    sequence: u64,
    event: u8,
    canonical: Vec<u8>,
    links: EvidenceLinks,
}

impl PrimaryEvidence {
    /// Canonicalizes a signed authority receipt for journal admission.
    pub fn authority_receipt(receipt: &crate::model::AuthorityReceipt) -> Self {
        let sequence = receipt.body().sequence().get();
        Self {
            role: PrimaryRole::AuthorityReceipt,
            sequence,
            event: receipt.body().transition().event_kind() as u8,
            canonical: encode_signed_authority_receipt(receipt),
            links: EvidenceLinks::default(),
        }
    }

    /// Canonicalizes a daemon-witnessed fact after validating its causal links.
    pub fn audit_fact(
        fact: &crate::model::AuditFact,
        links: EvidenceLinks,
    ) -> Result<Self, JournalError> {
        let expected_operation = fact.operation().map(|value| value.operation_id());
        if expected_operation != links.operation_id.as_ref()
            || fact
                .operation()
                .and_then(crate::model::OperationEvidenceRef::materialization_id)
                != links.materialization_id.as_ref()
        {
            return Err(JournalError::EvidenceLinkMismatch);
        }
        Ok(Self {
            role: PrimaryRole::AuditFact,
            sequence: fact.sequence().get(),
            event: fact.event() as u8,
            canonical: encode_audit_fact(fact),
            links,
        })
    }

    /// Returns the sequence assigned by the E1 evidence object.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PrimaryRole {
    AuthorityReceipt,
    AuditFact,
    RedactionMarker,
}

/// Identifier of an erasable evidence-payload key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PayloadKeyId([u8; 32]);

impl PayloadKeyId {
    /// Constructs a key identifier from canonical bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Encrypted optional payload. Its plaintext commitment remains after the key
/// is destroyed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadEnvelope {
    key_id: PayloadKeyId,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    commitment: [u8; 32],
}

impl PayloadEnvelope {
    /// Encrypts a payload and binds its key identifier and permanent commitment.
    pub fn seal(
        key_id: PayloadKeyId,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Self, JournalError> {
        let commitment = payload_commitment(key, plaintext);
        let aad = payload_aad(key_id, commitment);
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::PayloadEncryption)?;
        Ok(Self {
            key_id,
            nonce,
            ciphertext,
            commitment,
        })
    }

    /// Decrypts the payload and verifies its permanent plaintext commitment.
    pub fn open(&self, key: &[u8; 32]) -> Result<Vec<u8>, JournalError> {
        let aad = payload_aad(self.key_id, self.commitment);
        let plaintext = XChaCha20Poly1305::new(key.into())
            .decrypt(
                XNonce::from_slice(&self.nonce),
                chacha20poly1305::aead::Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::PayloadUnavailable)?;
        if payload_commitment(key, &plaintext) != self.commitment {
            return Err(JournalError::PayloadCommitmentMismatch);
        }
        Ok(plaintext)
    }

    /// Returns the payload key identifier.
    pub const fn key_id(&self) -> PayloadKeyId {
        self.key_id
    }

    /// Returns the permanent keyed plaintext commitment.
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

/// One immutable canonical journal entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    sequence: u64,
    transaction_id: [u8; 32],
    role: PrimaryRole,
    event: u8,
    canonical_evidence: Vec<u8>,
    links: EvidenceLinks,
    payload: Option<PayloadEnvelope>,
    payload_envelope_hash: Option<[u8; 32]>,
    payload_commitment: Option<[u8; 32]>,
    record_blind: [u8; 32],
    record_hash: [u8; 32],
}

impl JournalRecord {
    /// Returns this record's global journal sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the stable E1 event-kind discriminant.
    pub const fn event_code(&self) -> u8 {
        self.event
    }

    /// Returns the causal projection coordinates.
    pub fn links(&self) -> &EvidenceLinks {
        &self.links
    }

    /// Returns the canonical record hash committed by its Checkpoint.
    pub const fn record_hash(&self) -> &[u8; 32] {
        &self.record_hash
    }

    fn leaf_digest(&self) -> [u8; 32] {
        record_leaf(self.record_hash, self.record_blind)
    }

    /// Returns the encrypted optional payload, when still disclosed.
    pub const fn payload(&self) -> Option<&PayloadEnvelope> {
        self.payload.as_ref()
    }

    /// Returns the permanent payload commitment, when this record has a payload.
    pub const fn payload_commitment(&self) -> Option<&[u8; 32]> {
        self.payload_commitment.as_ref()
    }

    /// Reports whether this record is E1 primary evidence rather than a redaction marker.
    pub fn is_primary_evidence(&self) -> bool {
        self.role != PrimaryRole::RedactionMarker
    }

    /// Checks that this record is the canonical signed form of the supplied
    /// authority-receipt body without exposing or reparsing signer material.
    pub(crate) fn matches_authority_receipt_body(
        &self,
        body: &crate::model::AuthorityReceiptBody,
    ) -> bool {
        if self.role != PrimaryRole::AuthorityReceipt
            || self.sequence != body.sequence().get()
            || self.event != body.transition().event_kind() as u8
        {
            return false;
        }
        let expected: [u8; 32] = Sha256::digest(encode_authority_receipt(body)).into();
        let schema = b"ember.authority-receipt.v1";
        let digest_offset = 1 + 8 + schema.len() + 1 + 8;
        self.canonical_evidence
            .get(..digest_offset)
            .is_some_and(|prefix| {
                prefix[0] == 0
                    && prefix[1..9] == (schema.len() as u64).to_be_bytes()
                    && prefix[9..9 + schema.len()] == *schema
                    && prefix[9 + schema.len()] == 1
                    && prefix[10 + schema.len()..18 + schema.len()] == 32_u64.to_be_bytes()
            })
            && self
                .canonical_evidence
                .get(digest_offset..digest_offset + expected.len())
                == Some(expected.as_slice())
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RecordHashInput<'a> {
    sequence: u64,
    transaction_id: &'a [u8; 32],
    role: PrimaryRole,
    event: u8,
    canonical_evidence: &'a [u8],
    links: &'a EvidenceLinks,
    payload_commitment: &'a Option<[u8; 32]>,
    payload_envelope_hash: &'a Option<[u8; 32]>,
}

/// Signed commitment to one complete durable journal transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    schema: String,
    identity: JournalIdentity,
    first_sequence: u64,
    last_sequence: u64,
    records_root: [u8; 32],
    state_root: [u8; 32],
    payload_keys_root: [u8; 32],
    previous_checkpoint: [u8; 32],
    schema_set: BTreeSet<String>,
    signature: OperationalSignature,
}

impl Checkpoint {
    /// Returns the first journal sequence committed by this transaction.
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Returns the final journal sequence committed by this transaction.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the hash of the immediately preceding Checkpoint, or genesis.
    pub const fn previous_checkpoint(&self) -> &[u8; 32] {
        &self.previous_checkpoint
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointBody<'a> {
    schema: &'a str,
    identity: JournalIdentity,
    first_sequence: u64,
    last_sequence: u64,
    records_root: &'a [u8; 32],
    state_root: &'a [u8; 32],
    payload_keys_root: &'a [u8; 32],
    previous_checkpoint: &'a [u8; 32],
    schema_set: &'a BTreeSet<String>,
    signer_generation: &'a [u8; 32],
}

/// The canonical predecessor query shared by append and verification.
pub fn canonical_checkpoint_predecessor(
    checkpoints: &[Checkpoint],
) -> Result<[u8; 32], JournalError> {
    match checkpoints.last() {
        Some(checkpoint) => checkpoint_hash(checkpoint),
        None => Ok(CHECKPOINT_GENESIS),
    }
}

fn checkpoint_hash(checkpoint: &Checkpoint) -> Result<[u8; 32], JournalError> {
    let body = CheckpointBody {
        schema: &checkpoint.schema,
        identity: checkpoint.identity,
        first_sequence: checkpoint.first_sequence,
        last_sequence: checkpoint.last_sequence,
        records_root: &checkpoint.records_root,
        previous_checkpoint: &checkpoint.previous_checkpoint,
        schema_set: &checkpoint.schema_set,
        signer_generation: &checkpoint.signature.generation_id,
        state_root: &checkpoint.state_root,
        payload_keys_root: &checkpoint.payload_keys_root,
    };
    Ok(domain_hash(CHECKPOINT_HASH_DOMAIN, &canonical(&body)?))
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, JournalError> {
    serde_jcs::to_vec(value).map_err(JournalError::Canonicalize)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

fn payload_commitment(key: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PAYLOAD_COMMITMENT_DOMAIN);
    digest.update(((key.len() + plaintext.len()) as u64).to_be_bytes());
    digest.update(key);
    digest.update(plaintext);
    digest.finalize().into()
}

fn map_root<V: Serialize>(
    domain: &[u8],
    values: &BTreeMap<String, V>,
) -> Result<[u8; 32], JournalError> {
    Ok(domain_hash(domain, &canonical(values)?))
}

fn payload_aad(key_id: PayloadKeyId, commitment: [u8; 32]) -> [u8; 64] {
    let mut aad = [0_u8; 64];
    aad[..32].copy_from_slice(key_id.as_bytes());
    aad[32..].copy_from_slice(&commitment);
    aad
}
fn payload_key_aad(identity: JournalIdentity, key_id: PayloadKeyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        PAYLOAD_KEY_AAD_DOMAIN.len() + identity.vault_id.len() + identity.device_id.len() + 32,
    );
    aad.extend_from_slice(PAYLOAD_KEY_AAD_DOMAIN);
    aad.extend_from_slice(&identity.vault_id);
    aad.extend_from_slice(&identity.device_id);
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SealedPayloadKey {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl SealedPayloadKey {
    fn seal(
        identity: JournalIdentity,
        key_id: PayloadKeyId,
        key: &[u8; 32],
        seal_key: &JournalSealKey,
    ) -> Result<Self, JournalError> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = payload_key_aad(identity, key_id);
        let ciphertext = XChaCha20Poly1305::new((&*seal_key.0).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: key,
                    aad: &aad,
                },
            )
            .map_err(|_| JournalError::PayloadEncryption)?;
        Ok(Self { nonce, ciphertext })
    }

    fn open(
        &self,
        identity: JournalIdentity,
        key_id: PayloadKeyId,
        seal_key: &JournalSealKey,
    ) -> Result<Zeroizing<[u8; 32]>, JournalError> {
        let aad = payload_key_aad(identity, key_id);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new((&*seal_key.0).into())
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| JournalError::PayloadUnavailable)?,
        );
        let key = <[u8; 32]>::try_from(plaintext.as_slice())
            .map_err(|_| JournalError::PayloadUnavailable)?;
        Ok(Zeroizing::new(key))
    }
}

/// Fail-stop journal posture shared by authority, provider, and read gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalHealth {
    /// Journal is verified and may admit new authority/provider work.
    Ready {
        /// Final sequence committed by a durable Checkpoint.
        last_durable_sequence: u64,
    },
    /// Journal is fail-stop; verified evidence reads remain available.
    Degraded {
        /// Final sequence successfully verified before degradation.
        last_verified_sequence: u64,
        /// Stable operator-facing reason for the fail-stop posture.
        reason: String,
    },
}

impl JournalHealth {
    /// Reports whether already verified evidence may be read.
    pub const fn permits_verified_read(&self) -> bool {
        true
    }

    /// Reports whether a new authority decision may be admitted.
    pub const fn permits_new_authority_decision(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// Reports whether new provider work may be admitted.
    pub const fn permits_provider_operation(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RedactionMarker {
    key_id: PayloadKeyId,
    authorization_sequence: u64,
    affected: Vec<RedactedPayload>,
}

/// Commitment retained after destruction of an encrypted payload key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedPayload {
    /// Sequence of the payload-bearing evidence record.
    pub sequence: u64,
    /// Permanent keyed commitment to the erased plaintext.
    pub commitment: [u8; 32],
}

/// Prepared evidence and state mutations that share one durable Checkpoint.
pub struct JournalTransaction {
    transaction_id: [u8; 32],
    evidence: Vec<(PrimaryEvidence, Option<PayloadEnvelope>)>,
    state: BTreeMap<String, Option<Vec<u8>>>,
    install_payload_keys: BTreeMap<PayloadKeyId, Zeroizing<[u8; 32]>>,
    redact_payload_keys: BTreeSet<PayloadKeyId>,
}

impl JournalTransaction {
    /// Starts a transaction with a caller-derived stable identifier.
    pub fn new(transaction_id: [u8; 32]) -> Self {
        Self {
            transaction_id,
            evidence: Vec::new(),
            state: BTreeMap::new(),
            install_payload_keys: BTreeMap::new(),
            redact_payload_keys: BTreeSet::new(),
        }
    }

    /// Adds one E1 evidence object and its optional encrypted payload.
    pub fn push_evidence(&mut self, evidence: PrimaryEvidence, payload: Option<PayloadEnvelope>) {
        self.evidence.push((evidence, payload));
    }

    /// State and its primary evidence are persisted by the same atomic file
    /// replacement. State values never enter an Export.
    pub fn put_state(&mut self, key: impl Into<String>, canonical_value: Vec<u8>) {
        self.state.insert(key.into(), Some(canonical_value));
    }

    /// Deletes a state projection in the same commit as its primary evidence.
    pub fn delete_state(&mut self, key: impl Into<String>) {
        self.state.insert(key.into(), None);
    }

    /// Installs one fresh per-payload encryption key.
    pub fn install_payload_key(&mut self, key_id: PayloadKeyId, key: [u8; 32]) {
        self.install_payload_keys
            .insert(key_id, Zeroizing::new(key));
    }

    /// Key destruction must share a transaction with an authority receipt. The
    /// journal appends a commitment-preserving marker in the same Checkpoint.
    pub fn redact_payload_key(&mut self, key_id: PayloadKeyId) {
        self.redact_payload_keys.insert(key_id);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum CommitFault {
    None,
    BeforeRecord,
    AfterRecordBeforeCheckpoint,
    AfterCheckpointBeforeJournalReplace,
    AfterJournalReplaceBeforeStatus,
    AfterDurableCommitBeforeResponse,
}

/// Durable acknowledgement for one completely checkpointed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// First sequence committed by the transaction.
    pub first_sequence: u64,
    /// Final sequence committed by the transaction.
    pub last_sequence: u64,
    /// Hash of the transaction's signed Checkpoint.
    pub checkpoint_hash: [u8; 32],
}

impl CommitReceipt {
    /// Returns the first sequence committed by the transaction.
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Returns the final sequence committed by the transaction.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Returns the hash of the transaction's signed Checkpoint.
    pub const fn checkpoint_hash(&self) -> &[u8; 32] {
        &self.checkpoint_hash
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskJournal {
    schema: String,
    durability: String,
    identity: JournalIdentity,
    records: Vec<JournalRecord>,
    checkpoints: Vec<Checkpoint>,
    state: BTreeMap<String, Vec<u8>>,
    payload_keys: BTreeMap<String, SealedPayloadKey>,
    redacted_payload_keys: BTreeSet<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PayloadKeyState<'a> {
    active: &'a BTreeMap<String, SealedPayloadKey>,
    redacted: &'a BTreeSet<String>,
}

fn payload_key_state_root(disk: &DiskJournal) -> Result<[u8; 32], JournalError> {
    let state = PayloadKeyState {
        active: &disk.payload_keys,
        redacted: &disk.redacted_payload_keys,
    };
    Ok(domain_hash(
        b"ember.authority-journal.payload-key-state-root/v1\0",
        &canonical(&state)?,
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DegradedRecoveryPolicy {
    OperatorRepair,
    StartupVerification,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskJournalStatus {
    schema: String,
    identity: JournalIdentity,
    high_water_sequence: u64,
    checkpoint_hash: [u8; 32],
    degraded_reason: Option<String>,
    degraded_recovery: Option<DegradedRecoveryPolicy>,
    signature: OperationalSignature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JournalStatusBody<'a> {
    schema: &'a str,
    identity: JournalIdentity,
    high_water_sequence: u64,
    checkpoint_hash: &'a [u8; 32],
    degraded_reason: &'a Option<String>,
    degraded_recovery: &'a Option<DegradedRecoveryPolicy>,
    signer_generation: &'a [u8; 32],
}

/// Canonical single-sequence journal for all authority receipts and audit
/// facts. A transaction is successful only after its Checkpoint signature,
/// journal replacement, file sync, rename, and directory sync complete.
pub struct EvidenceJournal {
    root: PathBuf,
    identity: JournalIdentity,
    high_water_path: PathBuf,
    seal_key: Arc<JournalSealKey>,
    signer: Arc<dyn OperationalEvidenceSigner>,
    verifier: OperationalVerifier,
    health: Mutex<JournalHealth>,
}

impl EvidenceJournal {
    /// Opens or initializes the canonical journal and checks its durable anchor.
    pub fn open(
        root: impl AsRef<Path>,
        identity: JournalIdentity,
        security: JournalSecurity,
    ) -> Result<Self, JournalError> {
        let root = prepare_journal_root(root.as_ref())?;
        let high_water_path = prepare_high_water_path(&root, &security.high_water_path)?;
        let journal = Self {
            root,
            identity,
            high_water_path,
            seal_key: security.seal_key,
            signer: security.signer,
            verifier: security.verifier,
            health: Mutex::new(JournalHealth::Ready {
                last_durable_sequence: 0,
            }),
        };
        let lock = journal.open_global_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let path = journal.journal_path();
        match read_regular_file(&path) {
            Ok(bytes) => {
                let disk: DiskJournal = match serde_json::from_slice(&bytes) {
                    Ok(disk) => disk,
                    Err(error) => {
                        journal.set_degraded(0, format!("journal decoding failed: {error}"))?;
                        return Ok(journal);
                    }
                };
                if let Err(error) = journal.validate_header(&disk) {
                    journal.set_degraded(0, error.to_string())?;
                    return Ok(journal);
                }
                let sequence = disk
                    .checkpoints
                    .last()
                    .map_or(0, |checkpoint| checkpoint.last_sequence);
                let checkpoint_hash = canonical_checkpoint_predecessor(&disk.checkpoints)?;
                match journal.read_status() {
                    Ok(status) => {
                        if let Err(error) = journal.verify_status(&status) {
                            journal.set_degraded(0, error.to_string())?;
                        } else if let Some(reason) = status.degraded_reason {
                            journal.set_degraded(status.high_water_sequence, reason)?;
                        } else if sequence < status.high_water_sequence
                            || (sequence == status.high_water_sequence
                                && checkpoint_hash != status.checkpoint_hash)
                        {
                            journal.persist_degraded(
                                status.high_water_sequence,
                                "journal is behind its durable high-water mark".to_owned(),
                                DegradedRecoveryPolicy::OperatorRepair,
                            )?;
                        } else {
                            *journal
                                .health
                                .lock()
                                .map_err(|_| JournalError::LockPoisoned)? = if sequence == 0 {
                                JournalHealth::Ready {
                                    last_durable_sequence: 0,
                                }
                            } else {
                                JournalHealth::Degraded {
                                    last_verified_sequence: status.high_water_sequence,
                                    reason: "startup verification required".to_owned(),
                                }
                            };
                        }
                    }
                    Err(JournalError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                        journal.set_degraded(
                            0,
                            "journal durable high-water anchor is missing".to_owned(),
                        )?;
                    }
                    Err(error) => {
                        journal.set_degraded(0, error.to_string())?;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let disk = DiskJournal {
                    schema: AUTHORITY_JOURNAL_SCHEMA.to_owned(),
                    durability: FULL_DURABILITY_V1.to_owned(),
                    identity,
                    records: Vec::new(),
                    checkpoints: Vec::new(),
                    state: BTreeMap::new(),
                    payload_keys: BTreeMap::new(),
                    redacted_payload_keys: BTreeSet::new(),
                };
                atomic_replace(&path, &canonical(&disk)?, MUTABLE_FILE_MODE, true)?;
                let status = journal.sign_status(0, CHECKPOINT_GENESIS, None, None)?;
                journal.write_status(&status, true)?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(journal)
    }

    /// Returns the local health after consulting the signed durable marker.
    ///
    /// Multiple daemon components may hold handles for the same journal root.
    /// A degraded marker written by any handle is therefore authoritative for
    /// every other live handle, not merely after process restart.
    pub fn health(&self) -> Result<JournalHealth, JournalError> {
        let status = match self.read_status() {
            Ok(status) => status,
            Err(error) => {
                self.set_degraded(0, error.to_string())?;
                return Err(error);
            }
        };
        if let Err(error) = self.verify_status(&status) {
            self.set_degraded(status.high_water_sequence, error.to_string())?;
            return Err(error);
        }
        if let Some(reason) = status.degraded_reason {
            self.set_degraded(status.high_water_sequence, reason)?;
        }
        Ok(self
            .health
            .lock()
            .map_err(|_| JournalError::LockPoisoned)?
            .clone())
    }

    /// Commits a fully prepared transaction.
    pub fn commit(&self, transaction: JournalTransaction) -> Result<CommitReceipt, JournalError> {
        self.commit_snapshot_with_fault(|_, _| Ok(transaction), CommitFault::None)
    }

    /// Reserves the next sequence under the exclusive journal lock, prepares
    /// the transaction against that reservation, and durably commits it before
    /// releasing the lock.
    pub fn commit_with_sequence(
        &self,
        prepare: impl FnOnce(u64) -> Result<JournalTransaction, JournalError>,
    ) -> Result<CommitReceipt, JournalError> {
        self.commit_snapshot_with_fault(|sequence, _| prepare(sequence), CommitFault::None)
    }

    /// Validates and prepares a transaction from the fully verified committed
    /// state while holding the journal's exclusive lock.
    ///
    /// The closure's error type is retained so a deep state-machine module can
    /// report a typed refusal without weakening the journal transaction seam.
    pub fn commit_with_verified_snapshot<E>(
        &self,
        prepare: impl FnOnce(u64, &VerifiedSnapshot) -> Result<JournalTransaction, E>,
    ) -> Result<CommitReceipt, E>
    where
        E: From<JournalError>,
    {
        self.commit_with_verified_snapshot_and_fault(prepare, CommitFault::None)
    }

    #[doc(hidden)]
    pub fn commit_with_verified_snapshot_and_fault<E>(
        &self,
        prepare: impl FnOnce(u64, &VerifiedSnapshot) -> Result<JournalTransaction, E>,
        fault: CommitFault,
    ) -> Result<CommitReceipt, E>
    where
        E: From<JournalError>,
    {
        let mut refusal = None;
        let result = self.commit_snapshot_with_fault(
            |sequence, snapshot| match prepare(sequence, snapshot) {
                Ok(transaction) => Ok(transaction),
                Err(error) => {
                    refusal = Some(error);
                    Err(JournalError::TransactionPreparationRefused)
                }
            },
            fault,
        );
        match refusal {
            Some(error) => Err(error),
            None => result.map_err(E::from),
        }
    }

    #[doc(hidden)]
    pub fn commit_with_fault(
        &self,
        transaction: JournalTransaction,
        fault: CommitFault,
    ) -> Result<CommitReceipt, JournalError> {
        self.commit_snapshot_with_fault(|_, _| Ok(transaction), fault)
    }

    fn commit_snapshot_with_fault(
        &self,
        prepare: impl FnOnce(u64, &VerifiedSnapshot) -> Result<JournalTransaction, JournalError>,
        fault: CommitFault,
    ) -> Result<CommitReceipt, JournalError> {
        if !self.health()?.permits_new_authority_decision() {
            return Err(JournalError::Degraded);
        }
        if fault == CommitFault::BeforeRecord {
            return Err(JournalError::InjectedInterruption);
        }
        let lock = self.open_global_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let mut disk = self.read_disk()?;
        self.validate_header(&disk)?;
        let status = match self.read_status() {
            Ok(status) => status,
            Err(error) => {
                self.set_degraded(0, error.to_string())?;
                return Err(error);
            }
        };
        if let Err(error) = self.verify_status(&status).and_then(|()| {
            verify_disk_and_high_water(&disk, &status, &self.verifier, self.identity)
        }) {
            self.set_degraded(status.high_water_sequence, error.to_string())?;
            return Err(error);
        }
        if status.degraded_reason.is_some() || !self.health()?.permits_new_authority_decision() {
            self.set_degraded(
                status.high_water_sequence,
                status
                    .degraded_reason
                    .unwrap_or_else(|| "journal is degraded".to_owned()),
            )?;
            return Err(JournalError::Degraded);
        }
        let first_sequence = disk.records.last().map_or(1, |record| {
            record
                .sequence
                .checked_add(1)
                .expect("validated journal sequence cannot overflow")
        });
        let snapshot = snapshot_from_disk(disk.clone(), Arc::clone(&self.seal_key));
        let transaction = prepare(first_sequence, &snapshot)?;
        if transaction.install_payload_keys.keys().any(|key_id| {
            let key = hex::encode(key_id.as_bytes());
            disk.payload_keys.contains_key(&key) || disk.redacted_payload_keys.contains(&key)
        }) {
            return Err(JournalError::DuplicatePayloadKey);
        }
        if transaction.evidence.is_empty() && transaction.redact_payload_keys.is_empty() {
            return Err(JournalError::UnanchoredTransaction);
        }
        if transaction
            .redact_payload_keys
            .iter()
            .any(|key_id| transaction.install_payload_keys.contains_key(key_id))
        {
            return Err(JournalError::ConflictingPayloadKeyMutation);
        }
        let mut expected_sequence = first_sequence;
        let mut transaction_records =
            Vec::with_capacity(transaction.evidence.len() + transaction.redact_payload_keys.len());

        for (evidence, payload) in transaction.evidence {
            if evidence.sequence != expected_sequence {
                return Err(JournalError::NonCanonicalSequence {
                    expected: expected_sequence,
                    actual: evidence.sequence,
                });
            }
            if let Some(payload) = payload.as_ref() {
                if let Some(key) = transaction.install_payload_keys.get(&payload.key_id) {
                    payload.open(key)?;
                } else {
                    let sealed = disk
                        .payload_keys
                        .get(&hex::encode(payload.key_id.as_bytes()))
                        .ok_or(JournalError::UnknownPayloadKey)?;
                    let key = sealed.open(self.identity, payload.key_id, self.seal_key.as_ref())?;
                    payload.open(&key)?;
                }
            }
            let mut record = JournalRecord {
                sequence: expected_sequence,
                transaction_id: transaction.transaction_id,
                role: evidence.role,
                event: evidence.event,
                canonical_evidence: evidence.canonical,
                links: evidence.links,
                payload_commitment: payload.as_ref().map(|payload| payload.commitment),
                payload_envelope_hash: payload
                    .as_ref()
                    .map(canonical)
                    .transpose()?
                    .map(|bytes| Sha256::digest(bytes).into()),
                payload,
                record_blind: random_record_blind(),
                record_hash: [0; 32],
            };
            record.record_hash = record_hash(&record)?;
            transaction_records.push(record);
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceOverflow)?;
        }

        let authorization_sequence = transaction_records
            .iter()
            .find(|record| record.role == PrimaryRole::AuthorityReceipt)
            .map(|record| record.sequence);
        for key_id in transaction.redact_payload_keys {
            let Some(authorization_sequence) = authorization_sequence else {
                return Err(JournalError::RedactionRequiresAuthorityReceipt);
            };
            let key = hex::encode(key_id.as_bytes());
            if !disk.payload_keys.contains_key(&key)
                && !transaction.install_payload_keys.contains_key(&key_id)
            {
                return Err(JournalError::UnknownPayloadKey);
            }
            let mut affected = disk
                .records
                .iter()
                .chain(transaction_records.iter())
                .filter_map(|record| {
                    record
                        .payload
                        .as_ref()
                        .filter(|payload| payload.key_id == key_id)
                        .map(|payload| RedactedPayload {
                            sequence: record.sequence,
                            commitment: payload.commitment,
                        })
                })
                .collect::<Vec<_>>();
            affected.sort_by_key(|payload| payload.sequence);
            if affected.is_empty() {
                return Err(JournalError::UnknownPayloadKey);
            }
            let marker = RedactionMarker {
                key_id,
                authorization_sequence,
                affected,
            };
            let mut record = JournalRecord {
                sequence: expected_sequence,
                transaction_id: transaction.transaction_id,
                role: PrimaryRole::RedactionMarker,
                event: 0,
                canonical_evidence: canonical(&marker)?,
                links: EvidenceLinks::default(),
                payload: None,
                payload_commitment: None,
                payload_envelope_hash: None,
                record_blind: random_record_blind(),
                record_hash: [0; 32],
            };
            record.record_hash = record_hash(&record)?;
            transaction_records.push(record);
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceOverflow)?;
            disk.payload_keys.remove(&key);
            disk.redacted_payload_keys.insert(key);
        }
        for (key, value) in transaction.state {
            match value {
                Some(value) => {
                    disk.state.insert(key, value);
                }
                None => {
                    disk.state.remove(&key);
                }
            }
        }
        for (key_id, key) in transaction.install_payload_keys {
            let sealed =
                SealedPayloadKey::seal(self.identity, key_id, &key, self.seal_key.as_ref())?;
            disk.payload_keys
                .insert(hex::encode(key_id.as_bytes()), sealed);
        }

        if fault == CommitFault::AfterRecordBeforeCheckpoint {
            return Err(JournalError::InjectedInterruption);
        }
        let last_sequence = transaction_records
            .last()
            .ok_or(JournalError::UnanchoredTransaction)?
            .sequence;
        let records_root = records_root(&transaction_records);
        let state_root = map_root(b"ember.authority-journal.state-root/v1\0", &disk.state)?;
        let payload_keys_root = payload_key_state_root(&disk)?;
        let previous_checkpoint = canonical_checkpoint_predecessor(&disk.checkpoints)?;
        let schema_set = transaction_records
            .iter()
            .map(|record| match record.role {
                PrimaryRole::AuthorityReceipt => "ember.authority-receipt/v1",
                PrimaryRole::AuditFact => "ember.audit-fact/v1",
                PrimaryRole::RedactionMarker => "ember.evidence-redaction-marker/v1",
            })
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let generation_id = *self.signer.generation_id().as_bytes();
        let body = CheckpointBody {
            schema: AUDIT_CHECKPOINT_SCHEMA,
            identity: self.identity,
            first_sequence,
            last_sequence,
            records_root: &records_root,
            previous_checkpoint: &previous_checkpoint,
            schema_set: &schema_set,
            signer_generation: &generation_id,
            state_root: &state_root,
            payload_keys_root: &payload_keys_root,
        };
        let body_bytes = canonical(&body)?;
        let signature = self.signer.sign_bound_message(&operational_message(
            OperationalEvidenceDomain::AuditCheckpoint,
            &body_bytes,
        ))?;
        let checkpoint = Checkpoint {
            schema: AUDIT_CHECKPOINT_SCHEMA.to_owned(),
            identity: self.identity,
            first_sequence,
            last_sequence,
            records_root,
            previous_checkpoint,
            schema_set,
            state_root,
            payload_keys_root,
            signature: OperationalSignature {
                generation_id,
                bytes: signature.to_vec(),
            },
        };
        let checkpoint_hash = checkpoint_hash(&checkpoint)?;
        let next_status = self.sign_status(last_sequence, checkpoint_hash, None, None)?;
        if fault == CommitFault::AfterCheckpointBeforeJournalReplace {
            return Err(JournalError::InjectedInterruption);
        }
        disk.records.extend(transaction_records);
        disk.checkpoints.push(checkpoint);
        let bytes = canonical(&disk)?;
        if let Err(error) = atomic_replace(&self.journal_path(), &bytes, MUTABLE_FILE_MODE, false) {
            self.persist_startup_recoverable_degraded(
                first_sequence.saturating_sub(1),
                error.to_string(),
            )?;
            return Err(error);
        }
        if fault == CommitFault::AfterJournalReplaceBeforeStatus {
            self.set_degraded(
                first_sequence.saturating_sub(1),
                "journal replace completed before durable high-water update".to_owned(),
            )?;
            return Err(JournalError::InjectedInterruption);
        }
        let status = next_status;
        if let Err(error) = self.write_status(&status, false) {
            let _ = self.persist_startup_recoverable_degraded(
                first_sequence.saturating_sub(1),
                format!("durable high-water update failed: {error}"),
            );
            return Err(error);
        }
        *self.health.lock().map_err(|_| JournalError::LockPoisoned)? = JournalHealth::Ready {
            last_durable_sequence: last_sequence,
        };
        let receipt = CommitReceipt {
            first_sequence,
            last_sequence,
            checkpoint_hash,
        };
        if fault == CommitFault::AfterDurableCommitBeforeResponse {
            return Err(JournalError::ResponseLost(receipt));
        }
        Ok(receipt)
    }

    /// Persists a signed fail-stop marker before publishing degraded health.
    pub fn enter_degraded(
        &self,
        last_verified_sequence: u64,
        reason: impl Into<String>,
    ) -> Result<(), JournalError> {
        self.persist_degraded(
            last_verified_sequence,
            reason.into(),
            DegradedRecoveryPolicy::OperatorRepair,
        )
    }

    fn persist_startup_recoverable_degraded(
        &self,
        last_verified_sequence: u64,
        reason: String,
    ) -> Result<(), JournalError> {
        self.persist_degraded(
            last_verified_sequence,
            reason,
            DegradedRecoveryPolicy::StartupVerification,
        )
    }

    fn persist_degraded(
        &self,
        last_verified_sequence: u64,
        reason: String,
        recovery: DegradedRecoveryPolicy,
    ) -> Result<(), JournalError> {
        self.set_degraded(last_verified_sequence, reason.clone())?;
        let status = self.read_status()?;
        self.verify_status(&status)?;
        let status = self.sign_status(
            status.high_water_sequence,
            status.checkpoint_hash,
            Some(reason),
            Some(recovery),
        )?;
        self.write_status(&status, false)
    }

    fn set_degraded(
        &self,
        last_verified_sequence: u64,
        reason: String,
    ) -> Result<(), JournalError> {
        *self.health.lock().map_err(|_| JournalError::LockPoisoned)? = JournalHealth::Degraded {
            last_verified_sequence,
            reason,
        };
        Ok(())
    }

    fn sign_status(
        &self,
        high_water_sequence: u64,
        checkpoint_hash: [u8; 32],
        degraded_reason: Option<String>,
        degraded_recovery: Option<DegradedRecoveryPolicy>,
    ) -> Result<DiskJournalStatus, JournalError> {
        let generation_id = *self.signer.generation_id().as_bytes();
        let body = JournalStatusBody {
            schema: JOURNAL_STATUS_SCHEMA,
            identity: self.identity,
            high_water_sequence,
            checkpoint_hash: &checkpoint_hash,
            degraded_reason: &degraded_reason,
            degraded_recovery: &degraded_recovery,
            signer_generation: &generation_id,
        };
        let signature = self.signer.sign_bound_message(&operational_message(
            OperationalEvidenceDomain::JournalHighWater,
            &canonical(&body)?,
        ))?;
        Ok(DiskJournalStatus {
            schema: JOURNAL_STATUS_SCHEMA.to_owned(),
            identity: self.identity,
            high_water_sequence,
            checkpoint_hash,
            degraded_reason,
            degraded_recovery,
            signature: OperationalSignature {
                generation_id,
                bytes: signature.to_vec(),
            },
        })
    }

    fn verify_status(&self, status: &DiskJournalStatus) -> Result<(), JournalError> {
        if status.schema != JOURNAL_STATUS_SCHEMA || status.identity != self.identity {
            return Err(JournalError::InvalidHighWaterAnchor);
        }
        if status.degraded_reason.is_some() != status.degraded_recovery.is_some() {
            return Err(JournalError::InvalidHighWaterAnchor);
        }
        if status.high_water_sequence == 0 && status.checkpoint_hash != CHECKPOINT_GENESIS {
            return Err(JournalError::InvalidHighWaterAnchor);
        }
        let body = JournalStatusBody {
            schema: &status.schema,
            identity: status.identity,
            high_water_sequence: status.high_water_sequence,
            checkpoint_hash: &status.checkpoint_hash,
            degraded_reason: &status.degraded_reason,
            degraded_recovery: &status.degraded_recovery,
            signer_generation: &status.signature.generation_id,
        };
        self.verifier.verify(
            OperationalEvidenceDomain::JournalHighWater,
            &status.signature.generation_id,
            &canonical(&body)?,
            &status.signature.bytes,
        )
    }

    fn read_status(&self) -> Result<DiskJournalStatus, JournalError> {
        serde_json::from_slice(&read_regular_file(&self.high_water_path)?)
            .map_err(JournalError::Decode)
    }

    fn write_status(&self, status: &DiskJournalStatus, create: bool) -> Result<(), JournalError> {
        atomic_replace(
            &self.high_water_path,
            &canonical(status)?,
            MUTABLE_FILE_MODE,
            create,
        )
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }

    fn open_global_lock(&self) -> Result<File, JournalError> {
        Ok(OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(MUTABLE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(self.root.join(JOURNAL_LOCK))?)
    }

    fn read_disk(&self) -> Result<DiskJournal, JournalError> {
        let bytes = read_regular_file(&self.journal_path())?;
        let disk = serde_json::from_slice(&bytes).map_err(JournalError::Decode)?;
        self.validate_header(&disk)?;
        Ok(disk)
    }

    fn validate_header(&self, disk: &DiskJournal) -> Result<(), JournalError> {
        if disk.schema != AUTHORITY_JOURNAL_SCHEMA
            || disk.durability != FULL_DURABILITY_V1
            || disk.identity != self.identity
        {
            return Err(JournalError::InvalidJournalHeader);
        }
        Ok(())
    }
}

fn prepare_journal_root(path: &Path) -> Result<PathBuf, JournalError> {
    if !path.is_absolute() {
        return Err(JournalError::InvalidJournalRoot);
    }
    fs::create_dir_all(path)?;
    let path = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != crate::effective_uid() {
        return Err(JournalError::InvalidJournalRoot);
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE))?;
    sync_directory(&path)?;
    Ok(path)
}

fn prepare_high_water_path(root: &Path, path: &Path) -> Result<PathBuf, JournalError> {
    if !path.is_absolute() {
        return Err(JournalError::InvalidHighWaterPath);
    }
    let parent = path.parent().ok_or(JournalError::InvalidHighWaterPath)?;
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(root) {
        return Err(JournalError::InvalidHighWaterPath);
    }
    let parent_metadata = fs::symlink_metadata(&parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != crate::effective_uid()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(JournalError::InvalidHighWaterPath);
    }
    let file_name = path.file_name().ok_or(JournalError::InvalidHighWaterPath)?;
    let path = parent.join(file_name);
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (!metadata.file_type().is_file()
            || metadata.uid() != crate::effective_uid()
            || metadata.mode() & 0o177 != 0
            || metadata.nlink() != 1)
    {
        return Err(JournalError::InvalidHighWaterPath);
    }
    Ok(path)
}

fn random_record_blind() -> [u8; 32] {
    let mut blind = [0_u8; 32];
    OsRng.fill_bytes(&mut blind);
    blind
}

fn record_leaf(record_hash: [u8; 32], blind: [u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    input[..32].copy_from_slice(&record_hash);
    input[32..].copy_from_slice(&blind);
    domain_hash(RECORD_LEAF_DOMAIN, &input)
}

fn record_hash(record: &JournalRecord) -> Result<[u8; 32], JournalError> {
    let input = RecordHashInput {
        sequence: record.sequence,
        transaction_id: &record.transaction_id,
        role: record.role,
        event: record.event,
        canonical_evidence: &record.canonical_evidence,
        links: &record.links,
        payload_commitment: &record.payload_commitment,
        payload_envelope_hash: &record.payload_envelope_hash,
    };
    Ok(domain_hash(RECORD_DOMAIN, &canonical(&input)?))
}

fn records_root(records: &[JournalRecord]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ember.audit-checkpoint.records-root/v1\0");
    digest.update((records.len() as u64).to_be_bytes());
    for record in records {
        digest.update(record.sequence.to_be_bytes());
        digest.update(record.leaf_digest());
    }
    digest.finalize().into()
}

fn operational_message(domain: OperationalEvidenceDomain, payload: &[u8]) -> Vec<u8> {
    let separator = domain.separator();
    let mut message = Vec::with_capacity(separator.len() + 8 + payload.len());
    message.extend_from_slice(separator);
    message.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

/// Explicit trust set for operational-evidence signer generations.
#[derive(Clone, Debug, Default)]
pub struct OperationalVerifier {
    keys: BTreeMap<[u8; 32], [u8; 32]>,
}

impl OperationalVerifier {
    /// Adds one explicitly trusted operational signer generation.
    pub fn trust(
        &mut self,
        generation_id: crate::identity::SignerGenerationId,
        public_key: [u8; 32],
    ) {
        self.keys.insert(*generation_id.as_bytes(), public_key);
    }

    fn verify(
        &self,
        domain: OperationalEvidenceDomain,
        generation_id: &[u8; 32],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), JournalError> {
        let key = self
            .keys
            .get(generation_id)
            .ok_or(JournalError::UntrustedSigner)?;
        let key = VerifyingKey::from_bytes(key).map_err(|_| JournalError::InvalidSignature)?;
        let signature =
            Signature::from_slice(signature).map_err(|_| JournalError::InvalidSignature)?;
        key.verify_strict(&operational_message(domain, payload), &signature)
            .map_err(|_| JournalError::InvalidSignature)
    }
}

/// Fully verified immutable view of journal evidence and committed state.
#[derive(Clone)]
pub struct VerifiedSnapshot {
    identity: JournalIdentity,
    records: Vec<JournalRecord>,
    checkpoints: Vec<Checkpoint>,
    state: BTreeMap<String, Vec<u8>>,
    payload_keys: BTreeMap<String, SealedPayloadKey>,
    seal_key: Arc<JournalSealKey>,
}

impl EvidenceJournal {
    /// Reads remain available in degraded mode, but no bytes escape until the
    /// complete record and Checkpoint chain verifies.
    pub fn verified_snapshot(&self) -> Result<VerifiedSnapshot, JournalError> {
        let lock = self.open_global_lock()?;
        FileExt::lock_shared(&lock)?;
        let disk = self.read_disk()?;
        let status = self.read_status()?;
        if let Err(error) = self.verify_status(&status).and_then(|()| {
            verify_disk_and_high_water(&disk, &status, &self.verifier, self.identity)
        }) {
            let last = disk
                .checkpoints
                .last()
                .map_or(0, |checkpoint| checkpoint.last_sequence);
            self.set_degraded(last, error.to_string())?;
            return Err(error);
        }
        Ok(snapshot_from_disk(disk, Arc::clone(&self.seal_key)))
    }

    /// Re-verifies all durable evidence at daemon startup. An unsigned crash
    /// gap may advance the high-water anchor after verification, but a signed
    /// degraded marker remains fail-stop until an operator-authorized repair.
    pub fn recover_startup(&self) -> Result<VerifiedSnapshot, JournalError> {
        let lock = self.open_global_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let disk = self.read_disk()?;
        let status = self.read_status()?;
        if let Err(error) = self.verify_status(&status).and_then(|()| {
            verify_disk_and_high_water(&disk, &status, &self.verifier, self.identity)
        }) {
            let last = disk
                .checkpoints
                .last()
                .map_or(0, |checkpoint| checkpoint.last_sequence);
            self.set_degraded(last, error.to_string())?;
            return Err(error);
        }
        if let Some(reason) = status.degraded_reason
            && status.degraded_recovery != Some(DegradedRecoveryPolicy::StartupVerification)
        {
            self.set_degraded(status.high_water_sequence, reason)?;
            return Err(JournalError::Degraded);
        }
        let last_durable_sequence = disk
            .checkpoints
            .last()
            .map_or(0, |checkpoint| checkpoint.last_sequence);
        let checkpoint_hash = canonical_checkpoint_predecessor(&disk.checkpoints)?;
        let status = self.sign_status(last_durable_sequence, checkpoint_hash, None, None)?;
        self.write_status(&status, false)?;
        *self.health.lock().map_err(|_| JournalError::LockPoisoned)? = JournalHealth::Ready {
            last_durable_sequence,
        };
        Ok(snapshot_from_disk(disk, Arc::clone(&self.seal_key)))
    }
}

fn verify_disk_and_high_water(
    disk: &DiskJournal,
    status: &DiskJournalStatus,
    verifier: &OperationalVerifier,
    expected_identity: JournalIdentity,
) -> Result<(), JournalError> {
    if status.schema != JOURNAL_STATUS_SCHEMA || status.identity != expected_identity {
        return Err(JournalError::InvalidJournalHeader);
    }
    verify_disk(disk, verifier)?;
    let sequence = disk
        .checkpoints
        .last()
        .map_or(0, |checkpoint| checkpoint.last_sequence);
    let checkpoint_hash = canonical_checkpoint_predecessor(&disk.checkpoints)?;
    if sequence < status.high_water_sequence
        || (sequence == status.high_water_sequence && checkpoint_hash != status.checkpoint_hash)
    {
        return Err(JournalError::BehindDurableHighWater);
    }
    Ok(())
}

fn snapshot_from_disk(disk: DiskJournal, seal_key: Arc<JournalSealKey>) -> VerifiedSnapshot {
    VerifiedSnapshot {
        identity: disk.identity,
        records: disk.records,
        checkpoints: disk.checkpoints,
        state: disk.state,
        payload_keys: disk.payload_keys,
        seal_key,
    }
}

fn verify_disk(disk: &DiskJournal, verifier: &OperationalVerifier) -> Result<(), JournalError> {
    if disk.schema != AUTHORITY_JOURNAL_SCHEMA || disk.durability != FULL_DURABILITY_V1 {
        return Err(JournalError::InvalidJournalHeader);
    }
    for (index, record) in disk.records.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| JournalError::SequenceOverflow)?
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if record.sequence != expected || record_hash(record)? != record.record_hash {
            return Err(JournalError::RecordTampered(record.sequence));
        }
        if let Some(payload) = &record.payload {
            if record.payload_commitment != Some(*payload.commitment())
                || record.payload_envelope_hash != Some(Sha256::digest(canonical(payload)?).into())
            {
                return Err(JournalError::PayloadCommitmentMismatch);
            }
        } else if record.payload_commitment.is_some() || record.payload_envelope_hash.is_some() {
            return Err(JournalError::PayloadCommitmentMismatch);
        }
    }

    let mut payloads_by_key = BTreeMap::<PayloadKeyId, Vec<RedactedPayload>>::new();
    let mut authority_records = BTreeSet::<([u8; 32], u64)>::new();
    for record in &disk.records {
        if let Some(payload) = &record.payload {
            payloads_by_key
                .entry(payload.key_id)
                .or_default()
                .push(RedactedPayload {
                    sequence: record.sequence,
                    commitment: payload.commitment,
                });
        }
        if record.role == PrimaryRole::AuthorityReceipt {
            authority_records.insert((record.transaction_id, record.sequence));
        }
    }
    let mut marker_keys = BTreeSet::new();
    for record in disk
        .records
        .iter()
        .filter(|record| record.role == PrimaryRole::RedactionMarker)
    {
        let marker: RedactionMarker =
            serde_json::from_slice(&record.canonical_evidence).map_err(JournalError::Decode)?;
        if canonical(&marker)? != record.canonical_evidence
            || !marker_keys.insert(hex::encode(marker.key_id.as_bytes()))
            || !authority_records.contains(&(record.transaction_id, marker.authorization_sequence))
            || marker.authorization_sequence >= record.sequence
            || payloads_by_key.get(&marker.key_id) != Some(&marker.affected)
        {
            return Err(JournalError::InvalidRedactionMarker);
        }
    }
    if marker_keys != disk.redacted_payload_keys
        || disk
            .payload_keys
            .keys()
            .any(|key| disk.redacted_payload_keys.contains(key))
    {
        return Err(JournalError::InvalidRedactionMarker);
    }

    let mut record_offset = 0_usize;
    for (checkpoint_index, checkpoint) in disk.checkpoints.iter().enumerate() {
        let previous = canonical_checkpoint_predecessor(&disk.checkpoints[..checkpoint_index])?;
        if checkpoint.schema != AUDIT_CHECKPOINT_SCHEMA
            || checkpoint.identity != disk.identity
            || checkpoint.first_sequence
                != u64::try_from(record_offset)
                    .map_err(|_| JournalError::SequenceOverflow)?
                    .checked_add(1)
                    .ok_or(JournalError::SequenceOverflow)?
            || checkpoint.last_sequence < checkpoint.first_sequence
            || checkpoint.previous_checkpoint != previous
        {
            return Err(JournalError::CheckpointChain);
        }
        let count = checkpoint
            .last_sequence
            .checked_sub(checkpoint.first_sequence)
            .and_then(|value| value.checked_add(1))
            .ok_or(JournalError::CheckpointChain)?;
        let end = record_offset
            .checked_add(usize::try_from(count).map_err(|_| JournalError::SequenceOverflow)?)
            .ok_or(JournalError::SequenceOverflow)?;
        let records = disk
            .records
            .get(record_offset..end)
            .ok_or(JournalError::CheckpointChain)?;
        if records_root(records) != checkpoint.records_root {
            return Err(JournalError::CheckpointRoot);
        }
        let body = CheckpointBody {
            schema: &checkpoint.schema,
            identity: checkpoint.identity,
            first_sequence: checkpoint.first_sequence,
            last_sequence: checkpoint.last_sequence,
            records_root: &checkpoint.records_root,
            previous_checkpoint: &checkpoint.previous_checkpoint,
            schema_set: &checkpoint.schema_set,
            signer_generation: &checkpoint.signature.generation_id,
            state_root: &checkpoint.state_root,
            payload_keys_root: &checkpoint.payload_keys_root,
        };
        verifier.verify(
            OperationalEvidenceDomain::AuditCheckpoint,
            &checkpoint.signature.generation_id,
            &canonical(&body)?,
            &checkpoint.signature.bytes,
        )?;
        record_offset = end;
    }
    if record_offset != disk.records.len() {
        return Err(JournalError::UncheckpointedTail);
    }
    if let Some(checkpoint) = disk.checkpoints.last() {
        if checkpoint.state_root
            != map_root(b"ember.authority-journal.state-root/v1\0", &disk.state)?
            || checkpoint.payload_keys_root != payload_key_state_root(disk)?
        {
            return Err(JournalError::CheckpointRoot);
        }
    } else if !disk.state.is_empty()
        || !disk.payload_keys.is_empty()
        || !disk.redacted_payload_keys.is_empty()
    {
        return Err(JournalError::UncheckpointedTail);
    }
    Ok(())
}

impl VerifiedSnapshot {
    /// Returns the vault/device identity proven by this snapshot.
    pub const fn identity(&self) -> JournalIdentity {
        self.identity
    }

    /// Returns all verified journal records in canonical sequence order.
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    /// Returns one signed Checkpoint per committed transaction.
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// Reads committed primary state that was atomically bound to evidence.
    pub fn state(&self, key: &str) -> Option<&[u8]> {
        self.state.get(key).map(Vec::as_slice)
    }

    /// Decrypts a disclosed optional payload after commitment verification.
    pub fn payload_plaintext(&self, sequence: u64) -> Result<Vec<u8>, JournalError> {
        let record = self
            .records
            .iter()
            .find(|record| record.sequence == sequence)
            .ok_or(JournalError::PayloadUnavailable)?;
        let payload = record
            .payload
            .as_ref()
            .ok_or(JournalError::PayloadUnavailable)?;
        if record.payload_commitment.as_ref() != Some(payload.commitment()) {
            return Err(JournalError::PayloadCommitmentMismatch);
        }
        let sealed = self
            .payload_keys
            .get(&hex::encode(payload.key_id.as_bytes()))
            .ok_or(JournalError::PayloadRedacted)?;
        let key = sealed.open(self.identity, payload.key_id, self.seal_key.as_ref())?;
        payload.open(&key)
    }

    /// Deterministically rebuilds the versioned aggregate authority rollup.
    pub fn rebuild_authority_rollup(
        &self,
        projection_version: crate::model::ProjectionVersion,
    ) -> Result<crate::model::AuthorityRollup, JournalError> {
        let through = self
            .records
            .last()
            .map(|record| record.sequence)
            .ok_or(JournalError::EmptyJournal)?;
        let mut receipt_count = 0_u64;
        let mut fact_count = 0_u64;
        let mut digest = Sha256::new();
        digest.update(b"ember.authority-rollup.primary/v1\0");
        for record in &self.records {
            match record.role {
                PrimaryRole::AuthorityReceipt => receipt_count += 1,
                PrimaryRole::AuditFact => fact_count += 1,
                PrimaryRole::RedactionMarker => continue,
            }
            digest.update(record.sequence.to_be_bytes());
            digest.update(record.record_hash);
        }
        Ok(crate::model::AuthorityRollup::new(
            projection_version,
            crate::model::JournalSequence::new(through).ok_or(JournalError::SequenceOverflow)?,
            receipt_count,
            fact_count,
            digest.finalize().into(),
        ))
    }

    /// Deterministically rebuilds an operation projection through its latest fact.
    pub fn rebuild_operation_view(
        &self,
        outcome: &crate::model::OperationOutcome,
        projection_version: crate::model::ProjectionVersion,
    ) -> Result<crate::model::OperationView, JournalError> {
        let mut view = crate::model::OperationView::initial(outcome);
        let mut settlement = view.settlement();
        let mut revoked = false;
        let mut through = outcome.sequence().get();
        for record in self.records.iter().filter(|record| {
            record.links.operation_id.as_ref() == Some(outcome.operation_id())
                && record.sequence >= outcome.sequence().get()
        }) {
            through = record.sequence;
            if record.event == crate::model::EventKind::ProviderSettlement as u8
                || record.event == crate::model::EventKind::UpstreamRevocation as u8
                || record.event == crate::model::EventKind::StartupRecoverySettlement as u8
            {
                settlement = crate::model::SettlementState::Settled;
            }
            if record.event == crate::model::EventKind::OperationAuthorityRevoked as u8 {
                revoked = true;
            }
        }
        view = crate::model::OperationView::from_derived_fields(
            outcome,
            crate::model::JournalSequence::new(through).ok_or(JournalError::SequenceOverflow)?,
            projection_version,
            settlement,
            revoked,
        )
        .ok_or(JournalError::Projection)?;
        Ok(view)
    }

    /// Deterministically rebuilds one session's lifetime projection.
    pub fn rebuild_session_lifetime(
        &self,
        session_id: &crate::model::SessionId,
        projection_version: crate::model::ProjectionVersion,
    ) -> SessionLifetimeRollup {
        let mut operations = BTreeSet::new();
        let mut fact_count = 0_u64;
        let mut created = false;
        let mut ended = false;
        let mut through = 0_u64;
        for record in self
            .records
            .iter()
            .filter(|record| record.links.session_id.as_ref() == Some(session_id))
        {
            through = record.sequence;
            if record.role == PrimaryRole::AuditFact {
                fact_count += 1;
            }
            if record.event == crate::model::EventKind::SessionCreated as u8 {
                created = true;
            } else if record.event == crate::model::EventKind::SessionEnded as u8 {
                ended = true;
            } else if record.event == crate::model::EventKind::OperationAdmitted as u8
                && let Some(operation) = record.links.operation_id.as_ref()
            {
                operations.insert(operation.clone());
            }
        }
        SessionLifetimeRollup {
            projection_version: projection_version.get(),
            session_id: session_id.clone(),
            through_sequence: through,
            created,
            ended,
            admitted_operations: operations.into_iter().collect(),
            audit_fact_count: fact_count,
        }
    }

    /// Deterministically rebuilds one grant's lineage projection.
    pub fn rebuild_grant_lineage(
        &self,
        grant_id: &crate::model::GrantId,
        projection_version: crate::model::ProjectionVersion,
    ) -> GrantLineageRollup {
        let mut operations = BTreeSet::new();
        let mut receipt_count = 0_u64;
        let mut revoked = false;
        let mut through = 0_u64;
        for record in self
            .records
            .iter()
            .filter(|record| record.links.grant_id.as_ref() == Some(grant_id))
        {
            through = record.sequence;
            if record.role == PrimaryRole::AuthorityReceipt {
                receipt_count += 1;
            }
            if record.event == crate::model::EventKind::GrantRevoked as u8 {
                revoked = true;
            }
            if let Some(operation) = record.links.operation_id.as_ref() {
                operations.insert(operation.clone());
            }
        }
        GrantLineageRollup {
            projection_version: projection_version.get(),
            grant_id: grant_id.clone(),
            through_sequence: through,
            receipt_count,
            revoked,
            operations: operations.into_iter().collect(),
        }
    }
}

/// Deterministic projection of all journal facts linked to one session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLifetimeRollup {
    projection_version: u32,
    session_id: crate::model::SessionId,
    through_sequence: u64,
    created: bool,
    ended: bool,
    admitted_operations: Vec<OperationId>,
    audit_fact_count: u64,
}

/// Deterministic projection of all journal evidence linked to one grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantLineageRollup {
    projection_version: u32,
    grant_id: crate::model::GrantId,
    through_sequence: u64,
    receipt_count: u64,
    revoked: bool,
    operations: Vec<OperationId>,
}

/// Inclusive nonempty journal sequence range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceRange {
    /// First included sequence.
    pub first: u64,
    /// Final included sequence.
    pub last: u64,
}

impl SequenceRange {
    /// Constructs a nonzero inclusive range with `first <= last`.
    pub fn new(first: u64, last: u64) -> Result<Self, JournalError> {
        if first == 0 || first > last {
            Err(JournalError::InvalidExportScope)
        } else {
            Ok(Self { first, last })
        }
    }

    const fn contains(self, sequence: u64) -> bool {
        sequence >= self.first && sequence <= self.last
    }
}

/// Exact export ranges plus explicitly withheld subranges.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportScope {
    /// Claimed sequence ranges.
    pub ranges: Vec<SequenceRange>,
    /// Explicitly withheld subranges within `ranges`.
    pub gaps: Vec<SequenceRange>,
}

impl ExportScope {
    /// Constructs a scope that discloses every record in its ranges.
    pub fn exact(ranges: Vec<SequenceRange>) -> Result<Self, JournalError> {
        let scope = Self {
            ranges,
            gaps: Vec::new(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Constructs a scope with explicit, nonoverlapping withheld subranges.
    pub fn with_gaps(
        ranges: Vec<SequenceRange>,
        gaps: Vec<SequenceRange>,
    ) -> Result<Self, JournalError> {
        let scope = Self { ranges, gaps };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), JournalError> {
        validate_nonoverlapping(&self.ranges)?;
        validate_nonoverlapping(&self.gaps)?;
        if self.ranges.is_empty()
            || self.gaps.iter().any(|gap| {
                !self
                    .ranges
                    .iter()
                    .any(|range| range.first <= gap.first && range.last >= gap.last)
            })
        {
            return Err(JournalError::InvalidExportScope);
        }
        Ok(())
    }

    fn contains(&self, sequence: u64) -> bool {
        self.ranges.iter().any(|range| range.contains(sequence))
    }

    fn is_gap(&self, sequence: u64) -> bool {
        self.gaps.iter().any(|range| range.contains(sequence))
    }
}

fn validate_nonoverlapping(ranges: &[SequenceRange]) -> Result<(), JournalError> {
    let mut previous = None;
    for range in ranges {
        if range.first == 0
            || range.first > range.last
            || previous.is_some_and(|last| range.first <= last)
        {
            return Err(JournalError::InvalidExportScope);
        }
        previous = Some(range.last);
    }
    Ok(())
}

/// Merkle-leaf digest for one sequence withheld from an export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceDigest {
    /// Journal sequence committed by the digest.
    pub sequence: u64,
    /// Blinded record-leaf digest.
    pub digest: [u8; 32],
}

/// Signed Checkpoint plus all leaf digests needed for exact-range proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportCheckpoint {
    /// Original canonical journal Checkpoint.
    pub checkpoint: Checkpoint,
    /// Every leaf hash is present so an exact subrange can prove inclusion
    /// without disclosing records outside the manifest scope.
    pub leaves: Vec<SequenceDigest>,
}

/// Signed exact-scope claim over an evidence export archive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    schema: String,
    identity: JournalIdentity,
    scope: ExportScope,
    checkpoint_hashes: Vec<[u8; 32]>,
    disclosed_payload_sequences: Vec<u64>,
    redactions: Vec<RedactedPayload>,
    projection_version: u32,
    archive_digest: [u8; 32],
    signature: OperationalSignature,
}

impl ExportManifest {
    /// Returns the exact claimed and withheld sequence ranges.
    pub fn scope(&self) -> &ExportScope {
        &self.scope
    }

    /// Returns commitment-preserving redaction claims relevant to the scope.
    pub fn redactions(&self) -> &[RedactedPayload] {
        &self.redactions
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExportManifestBody<'a> {
    schema: &'a str,
    identity: JournalIdentity,
    scope: &'a ExportScope,
    checkpoint_hashes: &'a [[u8; 32]],
    disclosed_payload_sequences: &'a [u64],
    redactions: &'a [RedactedPayload],
    projection_version: u32,
    archive_digest: &'a [u8; 32],
    signer_generation: &'a [u8; 32],
}

/// Self-contained exact-range evidence archive and signed manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExport {
    /// Signed manifest binding scope, archive, signer, and projection version.
    pub manifest: ExportManifest,
    /// Disclosed records, excluding every explicit gap.
    pub records: Vec<JournalRecord>,
    /// Checkpoint proof bundles from genesis through the claimed range.
    pub checkpoints: Vec<ExportCheckpoint>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExportArchive<'a> {
    records: &'a [JournalRecord],
    checkpoints: &'a [ExportCheckpoint],
}

impl VerifiedSnapshot {
    /// Produces a signed exact-range export with optional encrypted payload disclosure.
    pub fn export(
        &self,
        scope: ExportScope,
        disclose_encrypted_payloads: bool,
        projection_version: crate::model::ProjectionVersion,
        signer: &(impl OperationalEvidenceSigner + ?Sized),
    ) -> Result<EvidenceExport, JournalError> {
        scope.validate()?;
        let last = self.records.last().map_or(0, |record| record.sequence);
        if scope.ranges.iter().any(|range| range.last > last) {
            return Err(JournalError::MissingClaimedRecord);
        }
        let mut records = self
            .records
            .iter()
            .filter(|record| scope.contains(record.sequence) && !scope.is_gap(record.sequence))
            .cloned()
            .collect::<Vec<_>>();
        let mut disclosed_payload_sequences = Vec::new();
        for record in &mut records {
            let disclose = disclose_encrypted_payloads
                && record.payload.as_ref().is_some_and(|payload| {
                    self.payload_keys
                        .contains_key(&hex::encode(payload.key_id().as_bytes()))
                });
            if disclose {
                disclosed_payload_sequences.push(record.sequence);
            } else {
                record.payload = None;
            }
        }

        let maximum = scope
            .ranges
            .last()
            .ok_or(JournalError::InvalidExportScope)?
            .last;
        let mut offset = 0_usize;
        let mut checkpoints = Vec::new();
        for checkpoint in self
            .checkpoints
            .iter()
            .take_while(|checkpoint| checkpoint.first_sequence <= maximum)
        {
            let count = checkpoint
                .last_sequence
                .checked_sub(checkpoint.first_sequence)
                .and_then(|value| value.checked_add(1))
                .ok_or(JournalError::CheckpointChain)?;
            let end = offset
                .checked_add(usize::try_from(count).map_err(|_| JournalError::SequenceOverflow)?)
                .ok_or(JournalError::SequenceOverflow)?;
            let leaves = self
                .records
                .get(offset..end)
                .ok_or(JournalError::CheckpointChain)?
                .iter()
                .map(|record| SequenceDigest {
                    sequence: record.sequence,
                    digest: record.leaf_digest(),
                })
                .collect();
            checkpoints.push(ExportCheckpoint {
                checkpoint: checkpoint.clone(),
                leaves,
            });
            offset = end;
        }
        let checkpoint_hashes = checkpoints
            .iter()
            .map(|bundle| checkpoint_hash(&bundle.checkpoint))
            .collect::<Result<Vec<_>, _>>()?;
        let redactions = self.export_redactions(&scope)?;
        let archive_digest = domain_hash(
            b"ember.evidence-export.archive/v1\0",
            &canonical(&ExportArchive {
                records: &records,
                checkpoints: &checkpoints,
            })?,
        );
        let generation_id = *signer.generation_id().as_bytes();
        let body = ExportManifestBody {
            schema: EXPORT_MANIFEST_SCHEMA,
            identity: self.identity,
            scope: &scope,
            checkpoint_hashes: &checkpoint_hashes,
            disclosed_payload_sequences: &disclosed_payload_sequences,
            redactions: &redactions,
            projection_version: projection_version.get(),
            archive_digest: &archive_digest,
            signer_generation: &generation_id,
        };
        let bytes = canonical(&body)?;
        let signature = signer.sign_bound_message(&operational_message(
            OperationalEvidenceDomain::ExportManifest,
            &bytes,
        ))?;
        Ok(EvidenceExport {
            manifest: ExportManifest {
                schema: EXPORT_MANIFEST_SCHEMA.to_owned(),
                identity: self.identity,
                scope,
                checkpoint_hashes,
                disclosed_payload_sequences,
                redactions,
                projection_version: projection_version.get(),
                archive_digest,
                signature: OperationalSignature {
                    generation_id,
                    bytes: signature.to_vec(),
                },
            },
            records,
            checkpoints,
        })
    }

    fn export_redactions(&self, scope: &ExportScope) -> Result<Vec<RedactedPayload>, JournalError> {
        let mut redactions = Vec::new();
        for record in self
            .records
            .iter()
            .filter(|record| record.role == PrimaryRole::RedactionMarker)
        {
            let marker: RedactionMarker =
                serde_json::from_slice(&record.canonical_evidence).map_err(JournalError::Decode)?;
            redactions.extend(marker.affected.into_iter().filter(|payload| {
                scope.contains(payload.sequence) && !scope.is_gap(payload.sequence)
            }));
        }
        redactions.sort_by_key(|payload| payload.sequence);
        redactions.dedup_by_key(|payload| payload.sequence);
        Ok(redactions)
    }
}

/// Verifies an export's identity, exact scope, Checkpoint proofs, redactions,
/// archive digest, projection version, and domain-separated signature.
pub fn verify_export(
    export: &EvidenceExport,
    expected_identity: JournalIdentity,
    verifier: &OperationalVerifier,
) -> Result<(), JournalError> {
    export.manifest.scope.validate()?;
    if export.manifest.schema != EXPORT_MANIFEST_SCHEMA
        || export.manifest.projection_version != crate::model::ProjectionVersion::V1.get()
    {
        return Err(JournalError::InvalidExportManifest);
    }
    if export.manifest.identity != expected_identity {
        return Err(JournalError::UnexpectedIdentity);
    }
    let archive_digest = domain_hash(
        b"ember.evidence-export.archive/v1\0",
        &canonical(&ExportArchive {
            records: &export.records,
            checkpoints: &export.checkpoints,
        })?,
    );
    if archive_digest != export.manifest.archive_digest {
        return Err(JournalError::ArchiveDigest);
    }
    let body = ExportManifestBody {
        schema: &export.manifest.schema,
        identity: export.manifest.identity,
        scope: &export.manifest.scope,
        checkpoint_hashes: &export.manifest.checkpoint_hashes,
        disclosed_payload_sequences: &export.manifest.disclosed_payload_sequences,
        redactions: &export.manifest.redactions,
        projection_version: export.manifest.projection_version,
        archive_digest: &export.manifest.archive_digest,
        signer_generation: &export.manifest.signature.generation_id,
    };
    verifier.verify(
        OperationalEvidenceDomain::ExportManifest,
        &export.manifest.signature.generation_id,
        &canonical(&body)?,
        &export.manifest.signature.bytes,
    )?;

    let hashes = export
        .checkpoints
        .iter()
        .map(|bundle| checkpoint_hash(&bundle.checkpoint))
        .collect::<Result<Vec<_>, _>>()?;
    if hashes != export.manifest.checkpoint_hashes {
        return Err(JournalError::CheckpointChain);
    }
    let mut previous = CHECKPOINT_GENESIS;
    let mut expected_first = 1_u64;
    let mut leaves = BTreeMap::new();
    for bundle in &export.checkpoints {
        let checkpoint = &bundle.checkpoint;
        if checkpoint.schema != AUDIT_CHECKPOINT_SCHEMA
            || checkpoint.identity != export.manifest.identity
            || checkpoint.first_sequence != expected_first
            || checkpoint.previous_checkpoint != previous
            || bundle.leaves.first().map(|leaf| leaf.sequence) != Some(checkpoint.first_sequence)
            || bundle.leaves.last().map(|leaf| leaf.sequence) != Some(checkpoint.last_sequence)
        {
            return Err(JournalError::CheckpointChain);
        }
        let mut root = Sha256::new();
        root.update(b"ember.audit-checkpoint.records-root/v1\0");
        root.update((bundle.leaves.len() as u64).to_be_bytes());
        for (index, leaf) in bundle.leaves.iter().enumerate() {
            let expected = checkpoint
                .first_sequence
                .checked_add(u64::try_from(index).map_err(|_| JournalError::SequenceOverflow)?)
                .ok_or(JournalError::SequenceOverflow)?;
            if leaf.sequence != expected || leaves.insert(leaf.sequence, leaf.digest).is_some() {
                return Err(JournalError::CheckpointChain);
            }
            root.update(leaf.sequence.to_be_bytes());
            root.update(leaf.digest);
        }
        let computed: [u8; 32] = root.finalize().into();
        if computed != checkpoint.records_root {
            return Err(JournalError::CheckpointRoot);
        }
        let checkpoint_body = CheckpointBody {
            schema: &checkpoint.schema,
            identity: checkpoint.identity,
            first_sequence: checkpoint.first_sequence,
            last_sequence: checkpoint.last_sequence,
            records_root: &checkpoint.records_root,
            previous_checkpoint: &checkpoint.previous_checkpoint,
            schema_set: &checkpoint.schema_set,
            signer_generation: &checkpoint.signature.generation_id,
            state_root: &checkpoint.state_root,
            payload_keys_root: &checkpoint.payload_keys_root,
        };
        verifier.verify(
            OperationalEvidenceDomain::AuditCheckpoint,
            &checkpoint.signature.generation_id,
            &canonical(&checkpoint_body)?,
            &checkpoint.signature.bytes,
        )?;
        previous = checkpoint_hash(checkpoint)?;
        expected_first = checkpoint
            .last_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
    }

    let mut disclosed = BTreeSet::new();
    let mut disclosed_payloads = Vec::new();
    let mut payload_commitments = BTreeMap::new();
    for record in &export.records {
        if !export.manifest.scope.contains(record.sequence) {
            return Err(JournalError::OutsideScopeRecord(record.sequence));
        }
        if export.manifest.scope.is_gap(record.sequence)
            || !disclosed.insert(record.sequence)
            || record_hash(record)? != record.record_hash
            || leaves.get(&record.sequence) != Some(&record.leaf_digest())
        {
            return Err(JournalError::RecordTampered(record.sequence));
        }
        if let Some(commitment) = record.payload_commitment {
            payload_commitments.insert(record.sequence, commitment);
        }
        if let Some(payload) = &record.payload {
            if record.payload_commitment.as_ref() != Some(payload.commitment())
                || record.payload_envelope_hash != Some(Sha256::digest(canonical(payload)?).into())
            {
                return Err(JournalError::PayloadCommitmentMismatch);
            }
            disclosed_payloads.push(record.sequence);
        }
    }
    for range in &export.manifest.scope.ranges {
        for sequence in range.first..=range.last {
            if !export.manifest.scope.is_gap(sequence) && !disclosed.contains(&sequence) {
                return Err(JournalError::MissingClaimedRecord);
            }
            if !leaves.contains_key(&sequence) {
                return Err(JournalError::CheckpointChain);
            }
        }
    }
    if disclosed_payloads != export.manifest.disclosed_payload_sequences {
        return Err(JournalError::PayloadDisclosureMismatch);
    }
    let mut previous_redaction = None;
    for redaction in &export.manifest.redactions {
        if !export.manifest.scope.contains(redaction.sequence)
            || export.manifest.scope.is_gap(redaction.sequence)
            || previous_redaction.is_some_and(|sequence| redaction.sequence <= sequence)
            || payload_commitments.get(&redaction.sequence) != Some(&redaction.commitment)
            || disclosed_payloads
                .binary_search(&redaction.sequence)
                .is_ok()
        {
            return Err(JournalError::ExportRedactionMismatch);
        }
        previous_redaction = Some(redaction.sequence);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("authority journal root is invalid")]
    InvalidJournalRoot,
    #[error("durable journal high-water path is not separately protected")]
    InvalidHighWaterPath,
    #[error("durable journal high-water anchor is invalid")]
    InvalidHighWaterAnchor,
    #[error("authority journal schema, durability, or identity is invalid")]
    InvalidJournalHeader,
    #[error("journal sequence overflow")]
    SequenceOverflow,
    #[error("primary evidence sequence {actual} does not equal canonical sequence {expected}")]
    NonCanonicalSequence { expected: u64, actual: u64 },
    #[error("audit fact event kind is not part of the closed E1 vocabulary")]
    InvalidEventKind,
    #[error("primary evidence causal links disagree with the E1 evidence")]
    EvidenceLinkMismatch,
    #[error("prepared primary evidence is invalid: {0}")]
    InvalidPreparedEvidence(String),
    #[error("transaction preparation was refused by its state machine")]
    #[doc(hidden)]
    TransactionPreparationRefused,
    #[error("transaction has no journal record and cannot be checkpointed")]
    UnanchoredTransaction,
    #[error("payload key is not installed")]
    UnknownPayloadKey,
    #[error("payload encryption failed")]
    PayloadEncryption,
    #[error("payload is unavailable")]
    PayloadUnavailable,
    #[error("payload key was destroyed")]
    PayloadRedacted,
    #[error("decrypted payload does not match its permanent commitment")]
    PayloadCommitmentMismatch,
    #[error("a payload key cannot be installed and redacted in the same transaction")]
    ConflictingPayloadKeyMutation,
    #[error("payload key is already installed")]
    DuplicatePayloadKey,
    #[error("payload-key destruction requires an authority receipt in the same transaction")]
    RedactionRequiresAuthorityReceipt,
    #[error("redaction marker, authority binding, or payload tombstone is invalid")]
    InvalidRedactionMarker,
    #[error("journal is degraded and refuses new authority/provider work")]
    Degraded,
    #[error("journal is behind or inconsistent with its durable high-water anchor")]
    BehindDurableHighWater,
    #[error("record {0} failed sequence or commitment verification")]
    RecordTampered(u64),
    #[error("Checkpoint predecessor or range chain is invalid")]
    CheckpointChain,
    #[error("Checkpoint records root is invalid")]
    CheckpointRoot,
    #[error("journal has primary evidence outside a signed Checkpoint")]
    UncheckpointedTail,
    #[error("operational evidence signer generation is not trusted")]
    UntrustedSigner,
    #[error("operational evidence signature is invalid or cross-domain")]
    InvalidSignature,
    #[error("journal is empty")]
    EmptyJournal,
    #[error("projection inputs are inconsistent")]
    Projection,
    #[error("Export scope is invalid or non-canonical")]
    InvalidExportScope,
    #[error("Export manifest schema or projection version is unsupported")]
    InvalidExportManifest,
    #[error("Export belongs to a different journal identity")]
    UnexpectedIdentity,
    #[error("Export contains record {0} outside its exact scope")]
    OutsideScopeRecord(u64),
    #[error("Export omits a record inside a claimed non-gap range")]
    MissingClaimedRecord,
    #[error("Export archive digest is invalid")]
    ArchiveDigest,
    #[error("Export payload disclosure claim does not match its records")]
    PayloadDisclosureMismatch,
    #[error("Export redaction claim does not match a disclosed payload commitment")]
    ExportRedactionMismatch,
    #[error("injected interruption before durable Checkpoint")]
    InjectedInterruption,
    #[error("commit is durable but its response was lost")]
    ResponseLost(CommitReceipt),
    #[error("journal mutex is poisoned")]
    LockPoisoned,
    #[error("canonical JSON encoding failed: {0}")]
    Canonicalize(serde_json::Error),
    #[error("stored JSON decoding failed: {0}")]
    Decode(serde_json::Error),
    #[error("journal storage failed: {0}")]
    Storage(String),
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
}

fn field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn record(schema: &'static str, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    field(&mut out, 0, schema.as_bytes());
    out
}

fn key_field(out: &mut Vec<u8>, tag: u8, key: &crate::identity::EvidencePublicKey) {
    let (algorithm, bytes): (u8, &[u8]) = match key {
        crate::identity::EvidencePublicKey::Ed25519(bytes) => (1, bytes),
        crate::identity::EvidencePublicKey::P256(bytes) => (2, bytes),
    };
    out.push(tag);
    out.extend_from_slice(&((9 + bytes.len()) as u64).to_be_bytes());
    out.push(algorithm);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn signature_field(
    out: &mut Vec<u8>,
    tag: u8,
    signature: &crate::identity::EvidenceSignatureBytes,
) {
    let (algorithm, bytes): (u8, &[u8]) = match signature {
        crate::identity::EvidenceSignatureBytes::Ed25519(bytes) => (1, bytes),
        crate::identity::EvidenceSignatureBytes::P256Der(bytes) => (2, bytes),
    };
    out.push(tag);
    out.extend_from_slice(&((9 + bytes.len()) as u64).to_be_bytes());
    out.push(algorithm);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn validity_bytes(value: crate::identity::ValidityInterval) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&value.first.get().to_be_bytes());
    out[8..].copy_from_slice(&value.last.get().to_be_bytes());
    out
}

/// Injective canonical encoding of an Operator certificate body.
pub fn encode_operator_certificate(body: &crate::identity::OperatorCertificateBody) -> Vec<u8> {
    let mut out = record("ember.operator-certificate.v1", 288);
    field(&mut out, 1, body.certificate_id.as_bytes());
    field(&mut out, 2, body.root_id.as_bytes());
    field(&mut out, 3, body.operator_id.as_bytes());
    field(&mut out, 4, body.key_id.as_bytes());
    field(&mut out, 5, &[body.algorithm as u8]);
    key_field(&mut out, 6, &body.public_key);
    field(&mut out, 7, &validity_bytes(body.validity));
    out
}
/// Injective canonical encoding of a device certificate body.
pub fn encode_device_certificate(body: &crate::identity::DeviceCertificateBody) -> Vec<u8> {
    let mut out = record("ember.device-certificate.v1", 288);
    field(&mut out, 1, body.certificate_id.as_bytes());
    field(&mut out, 2, body.operator_certificate_id.as_bytes());
    field(&mut out, 3, body.device_id.as_bytes());
    field(&mut out, 4, body.key_id.as_bytes());
    field(&mut out, 5, &[body.algorithm as u8]);
    key_field(&mut out, 6, &body.public_key);
    field(&mut out, 7, &validity_bytes(body.validity));
    out
}
/// Injective canonical encoding of a signer generation.
pub fn encode_signer_generation(body: &crate::identity::SignerGenerationBody) -> Vec<u8> {
    let mut out = record("ember.signer-generation.v1", 320);
    field(&mut out, 1, body.generation_id.as_bytes());
    field(&mut out, 2, body.vault_id.as_bytes());
    field(&mut out, 3, body.device_certificate_id.as_bytes());
    field(&mut out, 4, body.key_id.as_bytes());
    field(&mut out, 5, &body.generation.get().to_be_bytes());
    field(&mut out, 6, &[body.purpose as u8]);
    field(&mut out, 7, &[body.algorithm as u8]);
    key_field(&mut out, 8, &body.public_key);
    field(&mut out, 9, &validity_bytes(body.validity));
    if let Some(predecessor) = body.predecessor {
        field(&mut out, 10, predecessor.as_bytes());
    }
    out
}

/// Injective canonical encoding of an authority-receipt body.
pub fn encode_authority_receipt(body: &crate::model::AuthorityReceiptBody) -> Vec<u8> {
    let mut out = record("ember.authority-receipt-body.v1", 176);
    field(&mut out, 1, body.evidence_id().as_bytes());
    field(&mut out, 2, &body.sequence().get().to_be_bytes());
    field(&mut out, 3, body.authority_object_id().as_bytes());
    field(&mut out, 4, &[body.transition() as u8]);
    out
}

/// Injective canonical encoding of a complete signed authority receipt.
pub fn encode_signed_authority_receipt(receipt: &crate::model::AuthorityReceipt) -> Vec<u8> {
    let body_digest: [u8; 32] = Sha256::digest(encode_authority_receipt(receipt.body())).into();
    let signature = receipt.signature();
    let mut out = record("ember.authority-receipt.v1", 224);
    field(&mut out, 1, &body_digest);
    field(&mut out, 2, signature.generation_id.as_bytes());
    field(&mut out, 3, &signature.sequence.get().to_be_bytes());
    field(&mut out, 4, &[signature.domain as u8]);
    signature_field(&mut out, 5, &signature.signature);
    out
}

/// Injective canonical encoding of a daemon-witnessed audit fact.
pub fn encode_audit_fact(fact: &crate::model::AuditFact) -> Vec<u8> {
    let mut out = record("ember.audit-fact.v1", 224);
    field(&mut out, 1, fact.evidence_id().as_bytes());
    field(&mut out, 2, &fact.sequence().get().to_be_bytes());
    field(&mut out, 3, &[fact.event() as u8]);
    if let Some(operation) = fact.operation() {
        field(&mut out, 4, operation.operation_id().as_str().as_bytes());
        if let Some(materialization_id) = operation.materialization_id() {
            field(&mut out, 5, materialization_id.as_str().as_bytes());
        }
    }
    out
}

fn signature_domain_separator(domain: crate::identity::SignatureDomain) -> &'static [u8] {
    match domain {
        crate::identity::SignatureDomain::OperatorCertificate => {
            b"ember/e1/operator-certificate/v1"
        }
        crate::identity::SignatureDomain::DeviceCertificate => b"ember/e1/device-certificate/v1",
        crate::identity::SignatureDomain::SignerGeneration => b"ember/e1/signer-generation/v1",
        crate::identity::SignatureDomain::AuthorityTransition => {
            b"ember/e1/authority-transition/v1"
        }
        crate::identity::SignatureDomain::OperationalDeescalation => {
            b"ember/e1/operational-deescalation/v1"
        }
    }
}

/// Canonical domain-separated bytes presented to an evidence signer.
pub fn signature_message(domain: crate::identity::SignatureDomain, payload: &[u8]) -> Vec<u8> {
    let separator = signature_domain_separator(domain);
    let mut message = Vec::with_capacity(separator.len() + 8 + payload.len());
    message.extend_from_slice(separator);
    message.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

pub(crate) fn validate_public_key(
    key: &crate::identity::EvidencePublicKey,
) -> Result<(), crate::identity::IdentityError> {
    match key {
        crate::identity::EvidencePublicKey::Ed25519(bytes) => VerifyingKey::from_bytes(bytes)
            .map(|_| ())
            .map_err(|_| crate::identity::IdentityError::InvalidSignature),
        crate::identity::EvidencePublicKey::P256(bytes) => {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(|_| ())
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)
        }
    }
}

/// Canonical encoding of the immutable terminal operation outcome.
pub fn encode_operation_outcome(outcome: &crate::model::OperationOutcome) -> Vec<u8> {
    let mut out = record("ember.operation-outcome.v1", 224);
    field(&mut out, 1, outcome.operation_id().as_str().as_bytes());
    field(&mut out, 2, outcome.submission_id().as_bytes());
    field(&mut out, 3, outcome.request_digest().as_bytes());
    field(&mut out, 4, &outcome.sequence().get().to_be_bytes());
    if let Some(materialization_id) = outcome.materialization_id() {
        field(&mut out, 5, materialization_id.as_str().as_bytes());
    }
    match outcome.boundary() {
        crate::model::ActionBoundary::CancelledBeforeEffect => field(&mut out, 6, &[0]),
        crate::model::ActionBoundary::EffectCompleted { succeeded } => {
            field(&mut out, 6, &[1, u8::from(succeeded)]);
        }
        crate::model::ActionBoundary::EffectUnknown => field(&mut out, 6, &[2]),
    }
    out
}

/// Canonical encoding of a deterministic current-operation projection.
pub fn encode_operation_view(view: &crate::model::OperationView) -> Vec<u8> {
    let mut out = record("ember.operation-view.v1", 176);
    field(&mut out, 1, view.operation_id().as_str().as_bytes());
    field(&mut out, 2, &view.outcome_sequence().get().to_be_bytes());
    field(&mut out, 3, &view.through_sequence().get().to_be_bytes());
    field(&mut out, 4, &view.projection_version().get().to_be_bytes());
    let settlement = match view.settlement() {
        crate::model::SettlementState::NotRequired => 0,
        crate::model::SettlementState::Pending => 1,
        crate::model::SettlementState::RecoveryPending => 2,
        crate::model::SettlementState::Settled => 3,
    };
    field(&mut out, 5, &[settlement]);
    field(
        &mut out,
        6,
        &[u8::from(view.authority_revoked_after_boundary())],
    );
    out
}

/// Canonical encoding of a rebuildable authority rollup.
pub fn encode_authority_rollup(rollup: &crate::model::AuthorityRollup) -> Vec<u8> {
    let mut out = record("ember.authority-rollup.v1", 144);
    field(
        &mut out,
        1,
        &rollup.projection_version().get().to_be_bytes(),
    );
    field(&mut out, 2, &rollup.through_sequence().get().to_be_bytes());
    field(&mut out, 3, &rollup.authority_receipt_count().to_be_bytes());
    field(&mut out, 4, &rollup.audit_fact_count().to_be_bytes());
    field(&mut out, 5, rollup.primary_evidence_digest());
    out
}

/// Canonical encoding of a durable submission-to-request-to-operation binding.
pub fn encode_submission_binding(binding: &crate::model::SubmissionBinding) -> Vec<u8> {
    let mut out = record("ember.submission-binding.v1", 176);
    field(&mut out, 1, binding.submission_id().as_bytes());
    field(&mut out, 2, binding.request_digest().as_bytes());
    field(&mut out, 3, binding.operation_id().as_str().as_bytes());
    out
}

/// Minimal boundary implemented by an in-process or hardware evidence signer.
///
/// Implementations retain key custody and return algorithm-tagged signature
/// bytes. Issuance verifies the returned signature before constructing a
/// certificate or receipt.
pub trait EvidenceSigner {
    fn public_key(&self) -> &crate::identity::EvidencePublicKey;
    fn sign(
        &self,
        message: &[u8],
    ) -> Result<crate::identity::EvidenceSignatureBytes, crate::identity::IdentityError>;
}

fn issue_signature(
    domain: crate::identity::SignatureDomain,
    issuer_key_id: crate::identity::SignerKeyId,
    issuer: &crate::identity::EvidencePublicKey,
    payload: &[u8],
    signer: &(impl EvidenceSigner + ?Sized),
) -> Result<crate::identity::CertificateSignature, crate::identity::IdentityError> {
    if signer.public_key() != issuer {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    let signature = signer.sign(&signature_message(domain, payload))?;
    if signature.algorithm() != issuer.algorithm() {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    verify_signature(domain, issuer, payload, &signature)?;
    Ok(crate::identity::CertificateSignature {
        issuer_key_id,
        signature,
    })
}

/// Issue an Operator certificate under the named installation root.
pub fn issue_operator_certificate(
    root: &crate::identity::InstallationRoot,
    body: crate::identity::OperatorCertificateBody,
    signer: &(impl EvidenceSigner + ?Sized),
) -> Result<crate::identity::OperatorCertificate, crate::identity::IdentityError> {
    if body.root_id != root.id
        || root.validity.first > root.validity.last
        || body.validity.first > body.validity.last
        || body.validity.first < root.validity.first
        || body.validity.last > root.validity.last
        || root.algorithm != root.public_key.algorithm()
        || body.algorithm != body.public_key.algorithm()
    {
        return Err(crate::identity::IdentityError::BrokenChain);
    }
    validate_public_key(&body.public_key)?;
    let signature = issue_signature(
        crate::identity::SignatureDomain::OperatorCertificate,
        root.key_id,
        &root.public_key,
        &encode_operator_certificate(&body),
        signer,
    )?;
    Ok(crate::identity::OperatorCertificate { body, signature })
}

/// Issue a device certificate without exceeding its Operator certificate.
pub fn issue_device_certificate(
    operator: &crate::identity::OperatorCertificate,
    body: crate::identity::DeviceCertificateBody,
    signer: &(impl EvidenceSigner + ?Sized),
) -> Result<crate::identity::DeviceCertificate, crate::identity::IdentityError> {
    if body.operator_certificate_id != operator.body.certificate_id
        || operator.body.validity.first > operator.body.validity.last
        || body.validity.first > body.validity.last
        || body.validity.first < operator.body.validity.first
        || body.validity.last > operator.body.validity.last
        || body.algorithm != body.public_key.algorithm()
    {
        return Err(crate::identity::IdentityError::BrokenChain);
    }
    validate_public_key(&body.public_key)?;
    let signature = issue_signature(
        crate::identity::SignatureDomain::DeviceCertificate,
        operator.body.key_id,
        &operator.body.public_key,
        &encode_device_certificate(&body),
        signer,
    )?;
    Ok(crate::identity::DeviceCertificate { body, signature })
}

/// Issue a first or exact-successor signer generation under a device.
pub fn issue_signer_generation(
    device: &crate::identity::DeviceCertificate,
    predecessor: Option<&crate::identity::SignerGenerationBody>,
    body: crate::identity::SignerGenerationBody,
    signer: &(impl EvidenceSigner + ?Sized),
) -> Result<crate::identity::SignerGeneration, crate::identity::IdentityError> {
    if body.device_certificate_id != device.body.certificate_id
        || device.body.validity.first > device.body.validity.last
        || body.validity.first > body.validity.last
        || body.validity.first < device.body.validity.first
        || body.validity.last > device.body.validity.last
        || body.algorithm != body.public_key.algorithm()
        || body.algorithm != body.purpose.required_algorithm()
    {
        return Err(crate::identity::IdentityError::BrokenChain);
    }
    validate_public_key(&body.public_key)?;
    match predecessor {
        None if body.generation.get() == 1 && body.predecessor.is_none() => {}
        Some(predecessor) => {
            crate::identity::validate_successor_generation(predecessor, &body)?;
        }
        None => return Err(crate::identity::IdentityError::InvalidSuccessor),
    }
    let signature = issue_signature(
        crate::identity::SignatureDomain::SignerGeneration,
        device.body.key_id,
        &device.body.public_key,
        &encode_signer_generation(&body),
        signer,
    )?;
    Ok(crate::identity::SignerGeneration { body, signature })
}

/// Issue one generation-, sequence-, purpose-, and domain-bound authority receipt.
pub fn issue_authority_receipt(
    generation: &crate::identity::SignerGeneration,
    body: crate::model::AuthorityReceiptBody,
    signer: &(impl EvidenceSigner + ?Sized),
) -> Result<crate::model::AuthorityReceipt, crate::identity::IdentityError> {
    let domain = body.transition().signature_domain();
    if body.sequence() < generation.body.validity.first
        || body.sequence() > generation.body.validity.last
        || !generation.body.purpose.permits(domain)
        || generation.body.algorithm != generation.body.public_key.algorithm()
        || generation.body.algorithm != signer.public_key().algorithm()
        || signer.public_key() != &generation.body.public_key
    {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    let payload = encode_authority_receipt(&body);
    let mut bound_payload = Vec::with_capacity(40 + payload.len());
    bound_payload.extend_from_slice(generation.body.generation_id.as_bytes());
    bound_payload.extend_from_slice(&body.sequence().get().to_be_bytes());
    bound_payload.extend_from_slice(&payload);
    let signature = signer.sign(&signature_message(domain, &bound_payload))?;
    verify_signature(
        domain,
        &generation.body.public_key,
        &bound_payload,
        &signature,
    )?;
    let evidence_signature = crate::identity::EvidenceSignature {
        generation_id: generation.body.generation_id,
        sequence: body.sequence(),
        domain,
        signature,
    };
    Ok(crate::model::AuthorityReceipt::from_signed(
        body,
        evidence_signature,
    ))
}

/// Algorithm-bound verification. P-256 signatures must be strict DER and use
/// the unique low-S representation; malleable high-S evidence is rejected.
pub fn verify_signature(
    domain: crate::identity::SignatureDomain,
    public_key: &crate::identity::EvidencePublicKey,
    payload: &[u8],
    signature: &crate::identity::EvidenceSignatureBytes,
) -> Result<(), crate::identity::IdentityError> {
    let message = signature_message(domain, payload);
    match (public_key, signature) {
        (
            crate::identity::EvidencePublicKey::Ed25519(key),
            crate::identity::EvidenceSignatureBytes::Ed25519(bytes),
        ) => {
            let key = VerifyingKey::from_bytes(key)
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)?;
            let signature = Signature::from_bytes(bytes);
            key.verify_strict(&message, &signature)
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)
        }
        (
            crate::identity::EvidencePublicKey::P256(key),
            crate::identity::EvidenceSignatureBytes::P256Der(bytes),
        ) => {
            use p256::ecdsa::signature::Verifier as _;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)?;
            let signature = p256::ecdsa::Signature::from_der(bytes)
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)?;
            if signature.normalize_s() != signature {
                return Err(crate::identity::IdentityError::InvalidSignature);
            }
            key.verify(&message, &signature)
                .map_err(|_| crate::identity::IdentityError::InvalidSignature)
        }
        _ => Err(crate::identity::IdentityError::InvalidSignature),
    }
}

/// Verify one canonical certificate body under its declared issuer and domain.
pub fn verify_certificate_signature(
    domain: crate::identity::SignatureDomain,
    issuer_key_id: crate::identity::SignerKeyId,
    issuer: &crate::identity::EvidencePublicKey,
    payload: &[u8],
    signature: &crate::identity::CertificateSignature,
) -> Result<(), crate::identity::IdentityError> {
    if signature.issuer_key_id != issuer_key_id {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    verify_signature(domain, issuer, payload, &signature.signature)
}

/// Verify evidence under an authenticated signer-generation capability.
pub fn verify_evidence_signature<'a>(
    trusted: crate::identity::TrustedSignerGeneration<'a>,
    expected_domain: crate::identity::SignatureDomain,
    payload: &[u8],
    signature: &'a crate::identity::EvidenceSignature,
) -> Result<crate::identity::VerifiedEvidence<'a>, crate::identity::IdentityError> {
    let generation = trusted.generation();
    if signature.generation_id != generation.body.generation_id
        || signature.domain != expected_domain
        || !generation.body.purpose.permits(expected_domain)
        || signature.signature.algorithm() != generation.body.algorithm
        || !generation.body.validity.contains(signature.sequence)
    {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    let mut bound_payload = Vec::with_capacity(40 + payload.len());
    bound_payload.extend_from_slice(signature.generation_id.as_bytes());
    bound_payload.extend_from_slice(&signature.sequence.get().to_be_bytes());
    bound_payload.extend_from_slice(payload);
    verify_signature(
        expected_domain,
        &generation.body.public_key,
        &bound_payload,
        &signature.signature,
    )?;
    Ok(crate::identity::VerifiedEvidence::new(
        signature,
        trusted,
        Sha256::digest(payload).into(),
    ))
}

/// Verify an authority receipt's sequence, transition domain, and signature.
pub fn verify_authority_receipt<'a>(
    trusted: crate::identity::TrustedSignerGeneration<'a>,
    receipt: &'a crate::model::AuthorityReceipt,
) -> Result<crate::identity::VerifiedEvidence<'a>, crate::identity::IdentityError> {
    if receipt.signature().sequence != receipt.body().sequence() {
        return Err(crate::identity::IdentityError::InvalidSignature);
    }
    verify_evidence_signature(
        trusted,
        receipt.body().transition().signature_domain(),
        &encode_authority_receipt(receipt.body()),
        receipt.signature(),
    )
}

#[cfg(test)]
mod e1_tests {
    use super::*;
    use crate::{
        identity::{
            CertificateSignature, CompromiseCutoff, DeviceCertificate, DeviceCertificateBody,
            DeviceCertificateId, DeviceId, EvidencePublicKey, EvidenceSignature,
            EvidenceSignatureBytes, InstallationRoot, InstallationRootId, OperatorCertificate,
            OperatorCertificateBody, OperatorCertificateId, OperatorId, SignatureDomain,
            SignerGeneration, SignerGenerationBody, SignerGenerationId, SignerKeyId, SignerPurpose,
            SigningAlgorithm, ValidityInterval, VaultId, verify_identity_chain,
        },
        model::{
            AuditFact, AuthorityObjectId, AuthorityReceiptBody, AuthorityTransitionKind, EventKind,
            EvidenceId, JournalSequence, OperationEvidenceRef, OperationId,
        },
    };
    use p256::ecdsa::signature::Signer as _;

    fn sequence(value: u64) -> JournalSequence {
        JournalSequence::new(value).unwrap()
    }
    struct P256TestSigner<'a> {
        key: &'a p256::ecdsa::SigningKey,
        public_key: EvidencePublicKey,
    }

    impl EvidenceSigner for P256TestSigner<'_> {
        fn public_key(&self) -> &EvidencePublicKey {
            &self.public_key
        }

        fn sign(
            &self,
            message: &[u8],
        ) -> Result<EvidenceSignatureBytes, crate::identity::IdentityError> {
            let signature: p256::ecdsa::Signature = self.key.sign(message);
            let signature = signature.normalize_s();
            Ok(EvidenceSignatureBytes::P256Der(
                signature.to_der().as_bytes().to_vec(),
            ))
        }
    }

    fn signed_certificate(
        issuer: &ed25519_dalek::SigningKey,
        issuer_key_id: SignerKeyId,
        domain: SignatureDomain,
        payload: &[u8],
    ) -> CertificateSignature {
        CertificateSignature {
            issuer_key_id,
            signature: EvidenceSignatureBytes::Ed25519(
                issuer.sign(&signature_message(domain, payload)).to_bytes(),
            ),
        }
    }

    fn p256_signature(
        key: &p256::ecdsa::SigningKey,
        generation_id: SignerGenerationId,
        sequence: JournalSequence,
        domain: SignatureDomain,
        payload: &[u8],
    ) -> EvidenceSignature {
        let mut bound = Vec::with_capacity(40 + payload.len());
        bound.extend_from_slice(generation_id.as_bytes());
        bound.extend_from_slice(&sequence.get().to_be_bytes());
        bound.extend_from_slice(payload);
        let signature: p256::ecdsa::Signature = key.sign(&signature_message(domain, &bound));
        let signature = signature.normalize_s();
        EvidenceSignature {
            generation_id,
            sequence,
            domain,
            signature: EvidenceSignatureBytes::P256Der(signature.to_der().as_bytes().to_vec()),
        }
    }

    #[test]
    fn audit_fact_encoding_is_exact_and_injective() {
        let operation_id = OperationId::new();
        let fact = AuditFact::new(
            EvidenceId::from_bytes([9; 32]),
            sequence(1),
            EventKind::OperationAdmitted,
            Some(OperationEvidenceRef::operation(operation_id.clone())),
        )
        .unwrap();
        let mut expected = record("ember.audit-fact.v1", 224);
        field(&mut expected, 1, &[9; 32]);
        field(&mut expected, 2, &1_u64.to_be_bytes());
        field(&mut expected, 3, &[EventKind::OperationAdmitted as u8]);
        field(&mut expected, 4, operation_id.as_str().as_bytes());
        assert_eq!(encode_audit_fact(&fact), expected);

        let distinct = AuditFact::new(
            EvidenceId::from_bytes([9; 32]),
            sequence(1),
            EventKind::OperationTerminal,
            Some(OperationEvidenceRef::operation(operation_id)),
        )
        .unwrap();
        assert_ne!(encode_audit_fact(&fact), encode_audit_fact(&distinct));
    }

    #[test]
    fn rooted_chain_domain_and_compromise_cutoff_are_enforced() {
        let validity = ValidityInterval::new(sequence(1), sequence(10)).unwrap();
        let root_key = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
        let operator_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let device_key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let evidence_key = p256::ecdsa::SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let root = InstallationRoot {
            id: InstallationRootId::from_bytes([13; 32]),
            key_id: SignerKeyId::from_bytes([20; 32]),
            algorithm: SigningAlgorithm::Ed25519,
            public_key: EvidencePublicKey::Ed25519(root_key.verifying_key().to_bytes()),
            validity,
        };
        let operator_body = OperatorCertificateBody {
            certificate_id: OperatorCertificateId::from_bytes([21; 32]),
            root_id: root.id,
            operator_id: OperatorId::from_bytes([14; 32]),
            key_id: SignerKeyId::from_bytes([22; 32]),
            algorithm: SigningAlgorithm::Ed25519,
            public_key: EvidencePublicKey::Ed25519(operator_key.verifying_key().to_bytes()),
            validity,
        };
        let operator = OperatorCertificate {
            signature: signed_certificate(
                &root_key,
                root.key_id,
                SignatureDomain::OperatorCertificate,
                &encode_operator_certificate(&operator_body),
            ),
            body: operator_body,
        };
        let device_body = DeviceCertificateBody {
            certificate_id: DeviceCertificateId::from_bytes([23; 32]),
            operator_certificate_id: operator.body.certificate_id,
            device_id: DeviceId::from_bytes([15; 32]),
            key_id: SignerKeyId::from_bytes([24; 32]),
            algorithm: SigningAlgorithm::Ed25519,
            public_key: EvidencePublicKey::Ed25519(device_key.verifying_key().to_bytes()),
            validity,
        };
        let device = DeviceCertificate {
            signature: signed_certificate(
                &operator_key,
                operator.body.key_id,
                SignatureDomain::DeviceCertificate,
                &encode_device_certificate(&device_body),
            ),
            body: device_body,
        };
        let generation_body = SignerGenerationBody {
            generation_id: SignerGenerationId::from_bytes([16; 32]),
            vault_id: VaultId::from_bytes([17; 32]),
            device_certificate_id: device.body.certificate_id,
            key_id: SignerKeyId::from_bytes([25; 32]),
            generation: std::num::NonZeroU32::new(1).unwrap(),
            purpose: SignerPurpose::AuthorityTransition,
            algorithm: SigningAlgorithm::EcdsaP256Sha256,
            public_key: EvidencePublicKey::P256(
                evidence_key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .to_vec(),
            ),
            validity,
            predecessor: None,
        };
        let generation = SignerGeneration {
            signature: signed_certificate(
                &device_key,
                device.body.key_id,
                SignatureDomain::SignerGeneration,
                &encode_signer_generation(&generation_body),
            ),
            body: generation_body,
        };
        let invalid_root = InstallationRoot {
            validity: ValidityInterval {
                first: sequence(2),
                last: sequence(1),
            },
            ..root.clone()
        };
        assert!(matches!(
            verify_identity_chain(
                &invalid_root,
                &operator,
                &device,
                None,
                &generation,
                sequence(1),
            ),
            Err(crate::identity::IdentityError::InvalidValidity)
        ));
        let trusted =
            verify_identity_chain(&root, &operator, &device, None, &generation, sequence(1))
                .unwrap();
        let receipt_body = AuthorityReceiptBody::new(
            EvidenceId::from_bytes([18; 32]),
            sequence(1),
            AuthorityObjectId::from_bytes([19; 32]),
            AuthorityTransitionKind::GrantIssue,
        );
        let receipt_signer = P256TestSigner {
            key: &evidence_key,
            public_key: generation.body.public_key.clone(),
        };
        let receipt = issue_authority_receipt(&generation, receipt_body, &receipt_signer).unwrap();
        verify_authority_receipt(trusted, &receipt).unwrap();
        let payload = b"authority transition";
        let before = p256_signature(
            &evidence_key,
            generation.body.generation_id,
            sequence(1),
            SignatureDomain::AuthorityTransition,
            payload,
        );
        let cutoff_signature = p256_signature(
            &evidence_key,
            generation.body.generation_id,
            sequence(2),
            SignatureDomain::AuthorityTransition,
            payload,
        );
        let verified_before = verify_evidence_signature(
            trusted,
            SignatureDomain::AuthorityTransition,
            payload,
            &before,
        )
        .unwrap();
        let expected_digest: [u8; 32] = Sha256::digest(payload).into();
        assert_eq!(verified_before.evidence_digest(), &expected_digest);
        let verified_at_cutoff = verify_evidence_signature(
            trusted,
            SignatureDomain::AuthorityTransition,
            payload,
            &cutoff_signature,
        )
        .unwrap();
        assert!(
            verify_evidence_signature(
                trusted,
                SignatureDomain::OperationalDeescalation,
                payload,
                &before,
            )
            .is_err()
        );
        let cutoff = CompromiseCutoff::new(generation.body.generation_id, sequence(2));
        assert!(cutoff.permits(verified_before));
        assert!(!cutoff.permits(verified_at_cutoff));
    }

    #[test]
    fn p256_verification_rejects_noncanonical_high_s() {
        let key = p256::ecdsa::SigningKey::from_bytes((&[0x31; 32]).into()).unwrap();
        let public_key =
            EvidencePublicKey::P256(key.verifying_key().to_sec1_point(true).as_bytes().to_vec());
        let payload = b"evidence";
        let domain = SignatureDomain::AuthorityTransition;
        let signature: p256::ecdsa::Signature = key.sign(&signature_message(domain, payload));
        let signature = signature.normalize_s();
        let (r, s) = signature.split_scalars();
        let high_s = -*s.as_ref();
        let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();
        assert!(
            verify_signature(
                domain,
                &public_key,
                payload,
                &EvidenceSignatureBytes::P256Der(signature.to_der().as_bytes().to_vec()),
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
}
