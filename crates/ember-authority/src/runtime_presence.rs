//! Fresh founder-presence proofs for top-level Session Grant attachment.
//!
//! The daemon owns only durable one-time intents and public verification. The
//! logged-in CLI displays the exact Grant batch and signs the canonical intent
//! through [`crate::presence`]'s fixed Secure Enclave key path. Acceptance
//! yields an in-memory, one-call verifier; there is deliberately no unlock
//! window or reusable presence credential.

use crate::presence::{PresenceError, sign_founder_presence_message};
use crate::principal::{GrantSummary, PresenceOperation, PresenceVerifier};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

pub const RUNTIME_PRESENCE_INTENT_SCHEMA: &str = "ember.founder-presence.runtime-intent/v2";
pub const RUNTIME_PRESENCE_PROOF_SCHEMA: &str = "ember.founder-presence.runtime-proof/v2";
pub const ATTACH_SELECTED_GRANTS_OPERATION: &str = "attach_selected_grants";
pub const ENROLL_CREDENTIAL_OPERATION: &str = "enroll_credential";
pub const ROTATE_CREDENTIAL_OPERATION: &str = "rotate_credential";
pub const DELETE_CREDENTIAL_OPERATION: &str = "delete_credential";
pub const MAX_RUNTIME_INTENT_LIFETIME: Duration = Duration::from_secs(300);

const RUNTIME_LEDGER_SCHEMA: &str = "ember.founder-presence.runtime-nonce-ledger/v1";
const RUNTIME_LEDGER_FILE: &str = "runtime-nonce-ledger.json";
const RUNTIME_LOCK_FILE: &str = ".runtime-nonce-ledger.lock";
#[cfg(unix)]
const RUNTIME_LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const RUNTIME_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const NONCE_BYTES: usize = 32;
const NONCE_HEX_LEN: usize = NONCE_BYTES * 2;
const SHA256_HEX_LEN: usize = 64;
const PUBLIC_KEY_BYTES: usize = 65;
const MAX_LEDGER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WIRE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_GRANTS_PER_BATCH: usize = 4096;
const MAX_SUMMARY_BYTES: usize = 64 * 1024;
const MAX_PROMPT_SUMMARY_BYTES: usize = 384;
const MAX_FOUNDER_PRESENCE_REASON_BYTES: usize = 512;
const MAX_CREDENTIAL_PRESENCE_REASON_BYTES: usize = 1_024;

/// Digests of the exact installation, accepted authority state, and daemon
/// identity that issued an intent. Raw identity material does not cross the
/// presence seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityBinding {
    installation_identity_sha256: String,
    accepted_authority_state_sha256: String,
    daemon_identity_sha256: String,
}

impl RuntimeAuthorityBinding {
    pub fn from_exact_bytes(
        installation_identity: &[u8],
        accepted_authority_state: &[u8],
        daemon_identity: &[u8],
    ) -> Result<Self, RuntimePresenceError> {
        if installation_identity.is_empty()
            || accepted_authority_state.is_empty()
            || daemon_identity.is_empty()
            || installation_identity.len() > MAX_IDENTITY_BYTES
            || accepted_authority_state.len() > MAX_IDENTITY_BYTES
            || daemon_identity.len() > MAX_IDENTITY_BYTES
        {
            return Err(RuntimePresenceError::InvalidAuthorityBinding);
        }
        Ok(Self {
            installation_identity_sha256: sha256_hex(installation_identity),
            accepted_authority_state_sha256: sha256_hex(accepted_authority_state),
            daemon_identity_sha256: sha256_hex(daemon_identity),
        })
    }

    pub fn installation_identity_sha256(&self) -> &str {
        &self.installation_identity_sha256
    }

    pub fn accepted_authority_state_sha256(&self) -> &str {
        &self.accepted_authority_state_sha256
    }

    pub fn daemon_identity_sha256(&self) -> &str {
        &self.daemon_identity_sha256
    }
}

/// One full, founder-displayable Grant entry in the exact approved order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FounderGrantDisplay {
    grant_id: String,
    delegation_id: String,
    full_summary: String,
    /// Read-only recovery field emitted by the short-lived v3 installation.
    /// Fresh v2 intents never serialize it, and strict validation rejects it.
    #[serde(
        default,
        rename = "prompt_summary",
        skip_serializing_if = "Option::is_none"
    )]
    transient_prompt_summary: Option<String>,
}

impl FounderGrantDisplay {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn delegation_id(&self) -> &str {
        &self.delegation_id
    }

    pub fn full_summary(&self) -> &str {
        &self.full_summary
    }
}

/// Full non-secret Credential transition tuple displayed to the founder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FounderCredentialDisplay {
    transition: String,
    credential_id: String,
    current_revision_id: Option<String>,
    current_commitment: Option<String>,
    new_revision_id: Option<String>,
    new_commitment: Option<String>,
    kind: String,
    app_id: u64,
    installation_id: u64,
    custody_profile: String,
    material_key_reference: Option<String>,
}

impl FounderCredentialDisplay {
    pub fn transition(&self) -> &str {
        &self.transition
    }
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    pub fn current_revision_id(&self) -> Option<&str> {
        self.current_revision_id.as_deref()
    }
    pub fn current_commitment(&self) -> Option<&str> {
        self.current_commitment.as_deref()
    }
    pub fn new_revision_id(&self) -> Option<&str> {
        self.new_revision_id.as_deref()
    }
    pub fn new_commitment(&self) -> Option<&str> {
        self.new_commitment.as_deref()
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }
    pub fn custody_profile(&self) -> &str {
        &self.custody_profile
    }
    pub fn material_key_reference(&self) -> Option<&str> {
        self.material_key_reference.as_deref()
    }
}

/// Exact payload the CLI must display before asking the fixed key to sign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FounderPresenceDisplay {
    operation: String,
    session_id: String,
    requested_ttl_seconds: u64,
    grants: Vec<FounderGrantDisplay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<FounderCredentialDisplay>,
}

impl FounderPresenceDisplay {
    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn requested_ttl_seconds(&self) -> u64 {
        self.requested_ttl_seconds
    }

    pub fn grants(&self) -> &[FounderGrantDisplay] {
        &self.grants
    }

    pub const fn credential(&self) -> Option<&FounderCredentialDisplay> {
        self.credential.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeOperationWire {
    operation: String,
    session_id: String,
    grant_ids: Vec<String>,
    delegation_ids: Vec<String>,
    requested_ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<FounderCredentialDisplay>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeIntentWire {
    schema: String,
    authority: RuntimeAuthorityBinding,
    operation: RuntimeOperationWire,
    founder_display: FounderPresenceDisplay,
    founder_display_sha256: String,
    nonce: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProofWire {
    schema: String,
    intent: RuntimeIntentWire,
    signature_der_hex: String,
}

/// Strict, canonical runtime intent wire object. It contains no secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePresenceIntent {
    wire: RuntimeIntentWire,
    canonical_json: Vec<u8>,
}

impl RuntimePresenceIntent {
    /// Parses only the current strict schema and RFC 8785 canonical JSON.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RuntimePresenceError> {
        let wire = parse_canonical_intent(bytes)?;
        validate_intent_static(&wire)?;
        Ok(Self {
            wire,
            canonical_json: bytes.to_vec(),
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn authority(&self) -> &RuntimeAuthorityBinding {
        &self.wire.authority
    }

    pub fn founder_display(&self) -> &FounderPresenceDisplay {
        &self.wire.founder_display
    }

    pub fn founder_display_sha256(&self) -> &str {
        &self.wire.founder_display_sha256
    }

    /// Human-readable authorization reason derived from the exact signed
    /// display payload. Credential transitions include the complete non-secret
    /// current/new tuple that the one-call proof authorizes.
    pub fn founder_presence_reason(&self) -> Result<String, RuntimePresenceError> {
        let display = self.founder_display();
        let mut reason = format!("Ember authority ({}s): ", display.requested_ttl_seconds);
        match (display.grants.as_slice(), display.credential.as_ref()) {
            ([], None) | ([_, ..], Some(_)) => {
                return Err(RuntimePresenceError::InvalidOperation);
            }
            ([], Some(credential)) => {
                use std::fmt::Write as _;

                write!(
                    reason,
                    "transition={} credential_id={} current_revision_id={} \
                     current_commitment={} new_revision_id={} new_commitment={} \
                     kind={} app_id={} installation_id={} custody_profile={} \
                     material_key_reference={}",
                    credential.transition,
                    credential.credential_id,
                    credential.current_revision_id.as_deref().unwrap_or("none"),
                    credential.current_commitment.as_deref().unwrap_or("none"),
                    credential.new_revision_id.as_deref().unwrap_or("none"),
                    credential.new_commitment.as_deref().unwrap_or("none"),
                    credential.kind,
                    credential.app_id,
                    credential.installation_id,
                    credential.custody_profile,
                    credential
                        .material_key_reference
                        .as_deref()
                        .unwrap_or("none"),
                )
                .map_err(|_| RuntimePresenceError::InvalidOperation)?;
                if reason.len() > MAX_CREDENTIAL_PRESENCE_REASON_BYTES {
                    return Err(RuntimePresenceError::PresenceReasonTooLarge);
                }
            }
            (grants, None) => {
                for (index, grant) in grants.iter().enumerate() {
                    if index > 0 {
                        reason.push('\n');
                    }
                    let prompt_summary = grant
                        .full_summary
                        .lines()
                        .next()
                        .filter(|summary| !summary.is_empty())
                        .ok_or(RuntimePresenceError::InvalidOperation)?;
                    reason.push_str(prompt_summary);
                    if reason.len() > MAX_FOUNDER_PRESENCE_REASON_BYTES {
                        return Err(RuntimePresenceError::PresenceReasonTooLarge);
                    }
                }
            }
        }
        Ok(reason)
    }

    pub fn nonce(&self) -> &str {
        &self.wire.nonce
    }

    pub fn issued_at_unix(&self) -> u64 {
        self.wire.issued_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.wire.expires_at_unix
    }
}

/// Strict canonical proof bytes suitable for transport back to the daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRuntimePresenceProof {
    canonical_json: Vec<u8>,
}

impl SignedRuntimePresenceProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.canonical_json
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeNonceState {
    PendingAudit,
    Issued,
    Consumed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeNonceRecordWire {
    intent: RuntimeIntentWire,
    state: RuntimeNonceState,
    consumed_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLedgerWire {
    schema: String,
    records: BTreeMap<String, RuntimeNonceRecordWire>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    consumed_nonces: BTreeMap<String, u64>,
}

impl Default for RuntimeLedgerWire {
    fn default() -> Self {
        Self {
            schema: RUNTIME_LEDGER_SCHEMA.to_owned(),
            records: BTreeMap::new(),
            consumed_nonces: BTreeMap::new(),
        }
    }
}

/// Owner-private durable issue/consume ledger for runtime presence nonces.
///
/// This ledger is physically and schematically separate from installation
/// acceptance, so runtime attempts cannot alter the accepted-install pointer.
#[derive(Debug)]
pub struct RuntimePresenceStore {
    root_path: PathBuf,
    #[cfg(unix)]
    root: File,
}

impl RuntimePresenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RuntimePresenceError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(RuntimePresenceError::InvalidStorePath);
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(RuntimePresenceError::InsecureStore);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(unix)]
                fs::DirBuilder::new().mode(0o700).create(path)?;
                #[cfg(not(unix))]
                return Err(RuntimePresenceError::UnsupportedPlatform);
            }
            Err(error) => return Err(error.into()),
        }

        #[cfg(unix)]
        {
            let root = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(path)?;
            validate_private_directory(&root)?;
            Ok(Self {
                root_path: path.to_owned(),
                root,
            })
        }
        #[cfg(not(unix))]
        {
            Err(RuntimePresenceError::UnsupportedPlatform)
        }
    }

    pub fn path(&self) -> &Path {
        &self.root_path
    }

    /// Consumes a parseable proof's nonce before checking canonical encoding,
    /// freshness, bindings, or signature. Success returns a verifier usable for
    /// exactly one equality check against the approved operation.
    pub fn accept(
        &self,
        proof: &[u8],
        expected_authority: &RuntimeAuthorityBinding,
        expected_operation: &PresenceOperation,
        enrolled_public_key_sec1: &[u8],
    ) -> Result<VerifiedPresence, RuntimePresenceError> {
        self.accept_at(
            proof,
            expected_authority,
            expected_operation,
            enrolled_public_key_sec1,
            unix_now()?,
        )
    }

    fn accept_at(
        &self,
        proof: &[u8],
        expected_authority: &RuntimeAuthorityBinding,
        expected_operation: &PresenceOperation,
        enrolled_public_key_sec1: &[u8],
        now: u64,
    ) -> Result<VerifiedPresence, RuntimePresenceError> {
        if proof.is_empty() || proof.len() > MAX_WIRE_BYTES {
            return Err(RuntimePresenceError::MalformedProof);
        }
        // Unknown fields are not parseable under this schema and therefore have
        // no trusted nonce to consume. Every successfully parsed object does.
        let proof_wire: RuntimeProofWire =
            serde_json::from_slice(proof).map_err(|_| RuntimePresenceError::MalformedProof)?;
        let stored_intent = self.consume_nonce(&proof_wire.intent.nonce, now)?;

        let canonical_proof =
            serde_jcs::to_vec(&proof_wire).map_err(|_| RuntimePresenceError::MalformedProof)?;
        if canonical_proof != proof {
            return Err(RuntimePresenceError::NonCanonicalEncoding);
        }
        validate_proof_fresh(&proof_wire, now)?;
        if stored_intent != proof_wire.intent {
            return Err(RuntimePresenceError::IntentMismatch);
        }
        validate_authority(expected_authority)?;
        if proof_wire.intent.authority != *expected_authority {
            return Err(RuntimePresenceError::AuthorityBindingMismatch);
        }
        let (expected_wire, expected_display) = encode_operation(expected_operation)?;
        if proof_wire.intent.operation != expected_wire
            || proof_wire.intent.founder_display != expected_display
            || proof_wire.intent.founder_display_sha256 != display_sha256(&expected_display)?
        {
            return Err(RuntimePresenceError::OperationBindingMismatch);
        }
        verify_signature(&proof_wire, enrolled_public_key_sec1)?;
        Ok(VerifiedPresence {
            operation: expected_operation.clone(),
            unused: true,
        })
    }

    fn consume_nonce(
        &self,
        nonce: &str,
        now: u64,
    ) -> Result<RuntimeIntentWire, RuntimePresenceError> {
        let _lock = self.exclusive_lock()?;
        let mut ledger = self.load_ledger()?;
        let record = match ledger.records.remove(nonce) {
            Some(record) => record,
            None if ledger.consumed_nonces.contains_key(nonce) => {
                return Err(RuntimePresenceError::Replay);
            }
            None => return Err(RuntimePresenceError::UnknownNonce),
        };
        if record.state != RuntimeNonceState::Issued {
            return Err(RuntimePresenceError::Replay);
        }
        let intent = record.intent;
        ledger.consumed_nonces.insert(nonce.to_owned(), now);
        self.persist_ledger(&ledger)?;
        Ok(intent)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn exclusive_lock(&self) -> Result<File, RuntimePresenceError> {
        let lock = openat_file(
            self.root.as_raw_fd(),
            RUNTIME_LOCK_FILE,
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular_file(&lock, None)?;
        let deadline = std::time::Instant::now() + RUNTIME_LOCK_ACQUIRE_TIMEOUT;
        loop {
            // SAFETY: lock owns a live descriptor; closing it releases flock.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(lock);
            }
            let error = io::Error::last_os_error();
            let retryable = error.raw_os_error().is_some_and(|code| {
                code == libc::EWOULDBLOCK || code == libc::EAGAIN || code == libc::EINTR
            });
            if !retryable {
                return Err(error.into());
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimePresenceError::LockTimeout);
            }
            std::thread::sleep(RUNTIME_LOCK_RETRY_INTERVAL.min(remaining));
        }
    }

    #[cfg(unix)]
    fn load_ledger_wire(&self) -> Result<RuntimeLedgerWire, RuntimePresenceError> {
        let mut file = match openat_file(
            self.root.as_raw_fd(),
            RUNTIME_LEDGER_FILE,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(RuntimeLedgerWire::default());
            }
            Err(error) => return Err(error.into()),
        };
        validate_private_regular_file(&file, Some(MAX_LEDGER_BYTES))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(RuntimePresenceError::CorruptStore);
        }
        let ledger: RuntimeLedgerWire =
            serde_json::from_slice(&bytes).map_err(|_| RuntimePresenceError::CorruptStore)?;
        if serde_jcs::to_vec(&ledger).map_err(|_| RuntimePresenceError::CorruptStore)? != bytes {
            return Err(RuntimePresenceError::CorruptStore);
        }
        Ok(ledger)
    }

    #[cfg(unix)]
    fn load_ledger(&self) -> Result<RuntimeLedgerWire, RuntimePresenceError> {
        let ledger = self.load_ledger_wire()?;
        validate_ledger(&ledger)?;
        Ok(ledger)
    }

    #[cfg(unix)]
    fn persist_ledger(&self, ledger: &RuntimeLedgerWire) -> Result<(), RuntimePresenceError> {
        let bytes = serde_jcs::to_vec(ledger).map_err(|_| RuntimePresenceError::Serialization)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(RuntimePresenceError::StoreCapacity);
        }
        let mut random = [0u8; 12];
        OsRng.fill_bytes(&mut random);
        let temp_name = format!(".runtime-nonce-ledger.tmp.{}", hex::encode(random));
        let mut temp = openat_file(
            self.root.as_raw_fd(),
            &temp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular_file(&temp, None)?;
        let result = (|| -> Result<(), RuntimePresenceError> {
            temp.write_all(&bytes)?;
            temp.sync_all()?;
            renameat_file(self.root.as_raw_fd(), &temp_name, RUNTIME_LEDGER_FILE)?;
            self.root.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat_file(self.root.as_raw_fd(), &temp_name);
        }
        result
    }

    #[cfg(not(unix))]
    fn exclusive_lock(&self) -> Result<File, RuntimePresenceError> {
        Err(RuntimePresenceError::UnsupportedPlatform)
    }

    #[cfg(not(unix))]
    fn load_ledger(&self) -> Result<RuntimeLedgerWire, RuntimePresenceError> {
        Err(RuntimePresenceError::UnsupportedPlatform)
    }

    #[cfg(not(unix))]
    fn persist_ledger(&self, _ledger: &RuntimeLedgerWire) -> Result<(), RuntimePresenceError> {
        Err(RuntimePresenceError::UnsupportedPlatform)
    }
}

/// Signs the exact canonical intent with the existing fixed founder key.
/// `crate::presence` creates a fresh `LAContext` for every invocation.
pub fn sign_runtime_presence_intent(
    intent: &RuntimePresenceIntent,
    enrolled_public_key_sec1: &[u8],
) -> Result<SignedRuntimePresenceProof, RuntimePresenceError> {
    validate_intent_fresh(&intent.wire, unix_now()?)?;
    if canonical_intent_bytes(&intent.wire)? != intent.canonical_json {
        return Err(RuntimePresenceError::NonCanonicalEncoding);
    }
    let reason = intent.founder_presence_reason()?;
    let signature_der =
        sign_founder_presence_message(&intent.canonical_json, enrolled_public_key_sec1, &reason)?;
    let proof = RuntimeProofWire {
        schema: RUNTIME_PRESENCE_PROOF_SCHEMA.to_owned(),
        intent: intent.wire.clone(),
        signature_der_hex: hex::encode(signature_der),
    };
    Ok(SignedRuntimePresenceProof {
        canonical_json: serde_jcs::to_vec(&proof)
            .map_err(|_| RuntimePresenceError::Serialization)?,
    })
}

/// Opaque authority token that can approve exactly one matching operation call.
#[derive(Debug)]
pub struct VerifiedPresence {
    operation: PresenceOperation,
    unused: bool,
}

impl PresenceVerifier for VerifiedPresence {
    fn verify_presence(&mut self, operation: &PresenceOperation) -> bool {
        let unused = self.unused;
        self.unused = false;
        unused && self.operation == *operation
    }
}

fn encode_operation(
    operation: &PresenceOperation,
) -> Result<(RuntimeOperationWire, FounderPresenceDisplay), RuntimePresenceError> {
    match operation {
        PresenceOperation::AttachSelectedGrants {
            session,
            grants,
            delegation_ids,
            requested_ttl_seconds,
        } => {
            if grants.is_empty()
                || grants.len() > MAX_GRANTS_PER_BATCH
                || grants.len() != delegation_ids.len()
                || *requested_ttl_seconds == 0
            {
                return Err(RuntimePresenceError::InvalidOperation);
            }
            let mut seen_grants = BTreeSet::new();
            let mut seen_delegations = BTreeSet::new();
            let mut grant_ids = Vec::with_capacity(grants.len());
            let mut delegation_id_strings = Vec::with_capacity(grants.len());
            let mut display_grants = Vec::with_capacity(grants.len());
            for (summary, delegation_id) in grants.iter().zip(delegation_ids) {
                let grant_id = grant_summary_id(summary)?;
                if !seen_grants.insert(grant_id.clone())
                    || !seen_delegations.insert(delegation_id.as_str())
                {
                    return Err(RuntimePresenceError::DuplicateGrant);
                }
                let prompt_summary = summary.founder_presence_summary();
                if prompt_summary.is_empty()
                    || prompt_summary.len() > MAX_PROMPT_SUMMARY_BYTES
                    || prompt_summary
                        .bytes()
                        .any(|byte| matches!(byte, b'\n' | b'\r'))
                {
                    return Err(RuntimePresenceError::InvalidOperation);
                }
                let full_summary = format!("{prompt_summary}\nFull Grant: {summary}");
                if full_summary.len() > MAX_SUMMARY_BYTES {
                    return Err(RuntimePresenceError::InvalidOperation);
                }
                grant_ids.push(grant_id.clone());
                delegation_id_strings.push(delegation_id.as_str().to_owned());
                display_grants.push(FounderGrantDisplay {
                    grant_id,
                    delegation_id: delegation_id.as_str().to_owned(),
                    full_summary,
                    transient_prompt_summary: None,
                });
            }
            Ok((
                RuntimeOperationWire {
                    operation: ATTACH_SELECTED_GRANTS_OPERATION.to_owned(),
                    session_id: session.as_str().to_owned(),
                    grant_ids,
                    delegation_ids: delegation_id_strings,
                    requested_ttl_seconds: *requested_ttl_seconds,
                    credential: None,
                },
                FounderPresenceDisplay {
                    operation: ATTACH_SELECTED_GRANTS_OPERATION.to_owned(),
                    session_id: session.as_str().to_owned(),
                    requested_ttl_seconds: *requested_ttl_seconds,
                    grants: display_grants,
                    credential: None,
                },
            ))
        }
        PresenceOperation::EnrollCredential {
            credential_id,
            revision_id,
            kind,
            subject,
            custody_profile,
            commitment,
            key_reference,
        } => credential_operation(
            ENROLL_CREDENTIAL_OPERATION,
            FounderCredentialDisplay {
                transition: ENROLL_CREDENTIAL_OPERATION.to_owned(),
                credential_id: hex::encode(credential_id.as_bytes()),
                current_revision_id: None,
                current_commitment: None,
                new_revision_id: Some(hex::encode(revision_id.as_bytes())),
                new_commitment: Some(hex::encode(commitment.as_bytes())),
                kind: kind_name(*kind).to_owned(),
                app_id: subject.app_id(),
                installation_id: subject.installation_id(),
                custody_profile: custody_profile_name(*custody_profile).to_owned(),
                material_key_reference: Some(hex::encode(key_reference.as_bytes())),
            },
        ),
        PresenceOperation::RotateCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            new_revision_id,
            new_commitment,
            kind,
            subject,
            custody_profile,
            key_reference,
        } => credential_operation(
            ROTATE_CREDENTIAL_OPERATION,
            FounderCredentialDisplay {
                transition: ROTATE_CREDENTIAL_OPERATION.to_owned(),
                credential_id: hex::encode(credential_id.as_bytes()),
                current_revision_id: Some(hex::encode(current_revision_id.as_bytes())),
                current_commitment: Some(hex::encode(current_commitment.as_bytes())),
                new_revision_id: Some(hex::encode(new_revision_id.as_bytes())),
                new_commitment: Some(hex::encode(new_commitment.as_bytes())),
                kind: kind_name(*kind).to_owned(),
                app_id: subject.app_id(),
                installation_id: subject.installation_id(),
                custody_profile: custody_profile_name(*custody_profile).to_owned(),
                material_key_reference: Some(hex::encode(key_reference.as_bytes())),
            },
        ),
        PresenceOperation::DeleteCredential {
            credential_id,
            current_revision_id,
            current_commitment,
            kind,
            subject,
            custody_profile,
        } => credential_operation(
            DELETE_CREDENTIAL_OPERATION,
            FounderCredentialDisplay {
                transition: DELETE_CREDENTIAL_OPERATION.to_owned(),
                credential_id: hex::encode(credential_id.as_bytes()),
                current_revision_id: Some(hex::encode(current_revision_id.as_bytes())),
                current_commitment: Some(hex::encode(current_commitment.as_bytes())),
                new_revision_id: None,
                new_commitment: None,
                kind: kind_name(*kind).to_owned(),
                app_id: subject.app_id(),
                installation_id: subject.installation_id(),
                custody_profile: custody_profile_name(*custody_profile).to_owned(),
                material_key_reference: None,
            },
        ),
        PresenceOperation::InstallPersona | PresenceOperation::InstallGrant { .. } => {
            Err(RuntimePresenceError::UnsupportedOperation)
        }
    }
}

fn credential_operation(
    operation: &str,
    credential: FounderCredentialDisplay,
) -> Result<(RuntimeOperationWire, FounderPresenceDisplay), RuntimePresenceError> {
    Ok((
        RuntimeOperationWire {
            operation: operation.to_owned(),
            session_id: String::new(),
            grant_ids: Vec::new(),
            delegation_ids: Vec::new(),
            requested_ttl_seconds: 0,
            credential: Some(credential.clone()),
        },
        FounderPresenceDisplay {
            operation: operation.to_owned(),
            session_id: String::new(),
            requested_ttl_seconds: 0,
            grants: Vec::new(),
            credential: Some(credential),
        },
    ))
}

const fn kind_name(kind: crate::catalog::Kind) -> &'static str {
    match kind {
        crate::catalog::Kind::GithubAppPrivateKey => "github_app_private_key",
    }
}

const fn custody_profile_name(profile: crate::catalog::CustodyProfile) -> &'static str {
    match profile {
        crate::catalog::CustodyProfile::MacosDeviceBoundUserPresenceV1 => {
            "macos_device_bound_user_presence_v1"
        }
    }
}

fn grant_summary_id(summary: &GrantSummary) -> Result<String, RuntimePresenceError> {
    let value = serde_json::to_value(summary).map_err(|_| RuntimePresenceError::Serialization)?;
    value
        .get("grant_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(RuntimePresenceError::InvalidOperation)
}

fn parse_canonical_intent(bytes: &[u8]) -> Result<RuntimeIntentWire, RuntimePresenceError> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err(RuntimePresenceError::MalformedIntent);
    }
    let wire: RuntimeIntentWire =
        serde_json::from_slice(bytes).map_err(|_| RuntimePresenceError::MalformedIntent)?;
    if canonical_intent_bytes(&wire)? != bytes {
        return Err(RuntimePresenceError::NonCanonicalEncoding);
    }
    Ok(wire)
}

fn canonical_intent_bytes(intent: &RuntimeIntentWire) -> Result<Vec<u8>, RuntimePresenceError> {
    serde_jcs::to_vec(intent).map_err(|_| RuntimePresenceError::Serialization)
}

fn validate_intent_static(intent: &RuntimeIntentWire) -> Result<(), RuntimePresenceError> {
    if intent.schema != RUNTIME_PRESENCE_INTENT_SCHEMA {
        return Err(RuntimePresenceError::UnexpectedSchema);
    }
    validate_authority(&intent.authority)?;
    if !is_lower_hex(&intent.nonce, NONCE_HEX_LEN)
        || !is_lower_hex(&intent.founder_display_sha256, SHA256_HEX_LEN)
        || intent.operation.operation != intent.founder_display.operation
    {
        return Err(RuntimePresenceError::InvalidOperation);
    }
    if intent.operation.operation == ATTACH_SELECTED_GRANTS_OPERATION {
        validate_grant_intent(intent)?;
    } else {
        validate_credential_intent(intent)?;
    }
    if intent.founder_display_sha256 != display_sha256(&intent.founder_display)? {
        return Err(RuntimePresenceError::DisplayBindingMismatch);
    }
    let lifetime = intent
        .expires_at_unix
        .checked_sub(intent.issued_at_unix)
        .ok_or(RuntimePresenceError::InvalidTimestamp)?;
    if lifetime == 0 || lifetime > MAX_RUNTIME_INTENT_LIFETIME.as_secs() {
        return Err(RuntimePresenceError::InvalidTimestamp);
    }
    Ok(())
}

fn validate_grant_intent(intent: &RuntimeIntentWire) -> Result<(), RuntimePresenceError> {
    if intent.operation.credential.is_some()
        || intent.founder_display.credential.is_some()
        || intent.operation.session_id.is_empty()
        || intent.operation.session_id != intent.founder_display.session_id
        || intent.operation.requested_ttl_seconds == 0
        || intent.operation.requested_ttl_seconds != intent.founder_display.requested_ttl_seconds
        || intent.operation.grant_ids.is_empty()
        || intent.operation.grant_ids.len() > MAX_GRANTS_PER_BATCH
        || intent.operation.grant_ids.len() != intent.operation.delegation_ids.len()
        || intent.operation.grant_ids.len() != intent.founder_display.grants.len()
    {
        return Err(RuntimePresenceError::InvalidOperation);
    }
    let mut seen_grants = BTreeSet::new();
    let mut seen_delegations = BTreeSet::new();
    for ((grant_id, delegation_id), display) in intent
        .operation
        .grant_ids
        .iter()
        .zip(&intent.operation.delegation_ids)
        .zip(&intent.founder_display.grants)
    {
        if grant_id.is_empty()
            || delegation_id.is_empty()
            || !seen_grants.insert(grant_id)
            || !seen_delegations.insert(delegation_id)
            || display.grant_id != *grant_id
            || display.delegation_id != *delegation_id
            || display.transient_prompt_summary.is_some()
            || display.full_summary.is_empty()
            || display.full_summary.len() > MAX_SUMMARY_BYTES
        {
            return Err(RuntimePresenceError::InvalidOperation);
        }
    }
    Ok(())
}

fn validate_credential_intent(intent: &RuntimeIntentWire) -> Result<(), RuntimePresenceError> {
    let Some(operation) = intent.operation.credential.as_ref() else {
        return Err(RuntimePresenceError::InvalidOperation);
    };
    let Some(display) = intent.founder_display.credential.as_ref() else {
        return Err(RuntimePresenceError::InvalidOperation);
    };
    let name = intent.operation.operation.as_str();
    let shape_matches = match name {
        ENROLL_CREDENTIAL_OPERATION => {
            operation.current_revision_id.is_none()
                && operation.current_commitment.is_none()
                && operation.new_revision_id.is_some()
                && operation.new_commitment.is_some()
                && operation.material_key_reference.is_some()
        }
        ROTATE_CREDENTIAL_OPERATION => {
            operation.current_revision_id.is_some()
                && operation.current_commitment.is_some()
                && operation.new_revision_id.is_some()
                && operation.new_commitment.is_some()
                && operation.material_key_reference.is_some()
        }
        DELETE_CREDENTIAL_OPERATION => {
            operation.current_revision_id.is_some()
                && operation.current_commitment.is_some()
                && operation.new_revision_id.is_none()
                && operation.new_commitment.is_none()
                && operation.material_key_reference.is_none()
        }
        _ => false,
    };
    let hex_field = |value: &Option<String>| {
        value
            .as_deref()
            .is_none_or(|value| is_lower_hex(value, SHA256_HEX_LEN))
    };
    if !shape_matches
        || operation != display
        || operation.transition != name
        || !intent.operation.session_id.is_empty()
        || intent.operation.requested_ttl_seconds != 0
        || !intent.operation.grant_ids.is_empty()
        || !intent.operation.delegation_ids.is_empty()
        || !intent.founder_display.session_id.is_empty()
        || intent.founder_display.requested_ttl_seconds != 0
        || !intent.founder_display.grants.is_empty()
        || !is_lower_hex(&operation.credential_id, SHA256_HEX_LEN)
        || !hex_field(&operation.current_revision_id)
        || !hex_field(&operation.current_commitment)
        || !hex_field(&operation.new_revision_id)
        || !hex_field(&operation.new_commitment)
        || !hex_field(&operation.material_key_reference)
        || operation.kind != "github_app_private_key"
        || operation.custody_profile != "macos_device_bound_user_presence_v1"
        || operation.app_id == 0
        || operation.installation_id == 0
    {
        return Err(RuntimePresenceError::InvalidOperation);
    }
    Ok(())
}

fn validate_intent_fresh(intent: &RuntimeIntentWire, now: u64) -> Result<(), RuntimePresenceError> {
    validate_intent_static(intent)?;
    if intent.issued_at_unix > now {
        return Err(RuntimePresenceError::FutureProof);
    }
    if now >= intent.expires_at_unix {
        return Err(RuntimePresenceError::ExpiredProof);
    }
    Ok(())
}

fn validate_proof_fresh(proof: &RuntimeProofWire, now: u64) -> Result<(), RuntimePresenceError> {
    if proof.schema != RUNTIME_PRESENCE_PROOF_SCHEMA {
        return Err(RuntimePresenceError::UnexpectedSchema);
    }
    if decode_lower_hex(&proof.signature_der_hex).is_none() {
        return Err(RuntimePresenceError::InvalidSignature);
    }
    validate_intent_fresh(&proof.intent, now)
}

fn validate_authority(authority: &RuntimeAuthorityBinding) -> Result<(), RuntimePresenceError> {
    if !is_lower_hex(&authority.installation_identity_sha256, SHA256_HEX_LEN)
        || !is_lower_hex(&authority.accepted_authority_state_sha256, SHA256_HEX_LEN)
        || !is_lower_hex(&authority.daemon_identity_sha256, SHA256_HEX_LEN)
    {
        return Err(RuntimePresenceError::InvalidAuthorityBinding);
    }
    Ok(())
}

fn display_sha256(display: &FounderPresenceDisplay) -> Result<String, RuntimePresenceError> {
    let bytes = serde_jcs::to_vec(display).map_err(|_| RuntimePresenceError::Serialization)?;
    Ok(sha256_hex(&bytes))
}

fn verify_signature(
    proof: &RuntimeProofWire,
    enrolled_public_key_sec1: &[u8],
) -> Result<(), RuntimePresenceError> {
    let key = parse_public_key(enrolled_public_key_sec1)?;
    let signature_bytes =
        decode_lower_hex(&proof.signature_der_hex).ok_or(RuntimePresenceError::InvalidSignature)?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|_| RuntimePresenceError::InvalidSignature)?;
    key.verify(&canonical_intent_bytes(&proof.intent)?, &signature)
        .map_err(|_| RuntimePresenceError::InvalidSignature)
}

fn validate_ledger(ledger: &RuntimeLedgerWire) -> Result<(), RuntimePresenceError> {
    if ledger.schema != RUNTIME_LEDGER_SCHEMA {
        return Err(RuntimePresenceError::CorruptStore);
    }
    for (nonce, record) in &ledger.records {
        if nonce != &record.intent.nonce || !is_lower_hex(nonce, NONCE_HEX_LEN) {
            return Err(RuntimePresenceError::CorruptStore);
        }
        validate_intent_static(&record.intent).map_err(|_| RuntimePresenceError::CorruptStore)?;
        match (record.state, record.consumed_at_unix) {
            (RuntimeNonceState::Issued | RuntimeNonceState::PendingAudit, None) => {}
            (RuntimeNonceState::Consumed, Some(consumed))
                if consumed >= record.intent.issued_at_unix => {}
            _ => return Err(RuntimePresenceError::CorruptStore),
        }
    }
    for (nonce, consumed_at) in &ledger.consumed_nonces {
        if !is_lower_hex(nonce, NONCE_HEX_LEN) || *consumed_at == 0 {
            return Err(RuntimePresenceError::CorruptStore);
        }
    }
    Ok(())
}

fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey, RuntimePresenceError> {
    if bytes.len() != PUBLIC_KEY_BYTES || bytes.first() != Some(&0x04) {
        return Err(RuntimePresenceError::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| RuntimePresenceError::InvalidPublicKey)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) || !is_lower_hex(value, value.len()) {
        return None;
    }
    hex::decode(value).ok()
}

fn unix_now() -> Result<u64, RuntimePresenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| RuntimePresenceError::Clock)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn validate_private_directory(directory: &File) -> Result<(), RuntimePresenceError> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() == 0
    {
        return Err(RuntimePresenceError::InsecureStore);
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn validate_private_regular_file(
    file: &File,
    max_len: Option<u64>,
) -> Result<(), RuntimePresenceError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o177 != 0
        || metadata.nlink() != 1
        || max_len.is_some_and(|limit| metadata.len() > limit)
    {
        return Err(RuntimePresenceError::InsecureStore);
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn openat_file(root: RawFd, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    // SAFETY: root and name are valid for this call; a successful descriptor is
    // transferred exactly once into File.
    let fd = unsafe { libc::openat(root, name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn renameat_file(root: RawFd, from: &str, to: &str) -> io::Result<()> {
    let from = std::ffi::CString::new(from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid source name"))?;
    let to = std::ffi::CString::new(to)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid target name"))?;
    // SAFETY: both names are valid and relative to the live root descriptor.
    if unsafe { libc::renameat(root, from.as_ptr(), root, to.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn unlinkat_file(root: RawFd, name: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    // SAFETY: name is valid and relative to the live root descriptor.
    if unsafe { libc::unlinkat(root, name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum RuntimePresenceError {
    #[error("runtime founder presence requires a supported Unix store")]
    UnsupportedPlatform,
    #[error("runtime presence store path must be absolute")]
    InvalidStorePath,
    #[error("runtime presence store is not owner-private and symlink-safe")]
    InsecureStore,
    #[error("runtime presence ledger is corrupt or non-canonical")]
    CorruptStore,
    #[error("runtime presence ledger capacity exceeded")]
    StoreCapacity,
    #[error("runtime presence store lock acquisition timed out")]
    LockTimeout,
    #[error("intent validity must be whole seconds in 1..=300")]
    InvalidValidity,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("invalid intent timestamps")]
    InvalidTimestamp,
    #[error("intent was issued in the future")]
    FutureProof,
    #[error("intent is expired")]
    ExpiredProof,
    #[error("intent encoding is malformed")]
    MalformedIntent,
    #[error("proof encoding is malformed")]
    MalformedProof,
    #[error("wire encoding is not RFC 8785 canonical JSON")]
    NonCanonicalEncoding,
    #[error("unexpected runtime presence schema")]
    UnexpectedSchema,
    #[error("runtime presence operation is unsupported")]
    UnsupportedOperation,
    #[error("runtime presence operation is invalid")]
    InvalidOperation,
    #[error("runtime presence reason is too large for a reviewable founder prompt")]
    PresenceReasonTooLarge,
    #[error("selected Grant attachment contains a duplicate Grant")]
    DuplicateGrant,
    #[error("installation, accepted-state, or daemon identity binding is invalid")]
    InvalidAuthorityBinding,
    #[error("proof authority binding differs from the expected runtime authority")]
    AuthorityBindingMismatch,
    #[error("proof operation, Grant order, or summary differs from the expected operation")]
    OperationBindingMismatch,
    #[error("founder display payload digest does not match")]
    DisplayBindingMismatch,
    #[error("proof intent does not match the durably issued nonce")]
    IntentMismatch,
    #[error("runtime presence nonce was not issued by this store")]
    UnknownNonce,
    #[error("runtime presence nonce has already been consumed")]
    Replay,
    #[error("enrolled key is not an uncompressed P-256 public point")]
    InvalidPublicKey,
    #[error("P-256 runtime presence signature is invalid")]
    InvalidSignature,
    #[error("canonical serialization failed")]
    Serialization,
    #[error(transparent)]
    FounderPresence(#[from] PresenceError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{
        CredentialId, CustodyProfile, GithubAppSubject, Kind, MaterialKeyReference,
        RevisionCommitment, RevisionId,
    };
    use crate::model::{DelegationId, PackRef, PermissionLevel, RepositoryResource, SessionId};
    use crate::principal::{
        ExecutableDigest, GrantInstallation, GrantSelection, PersonaAuthority, ProcessOrigin,
    };
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use std::str::FromStr as _;

    struct Present;

    impl PresenceVerifier for Present {
        fn verify_presence(&mut self, _operation: &PresenceOperation) -> bool {
            true
        }
    }

    fn operation() -> PresenceOperation {
        let mut authority = PersonaAuthority::new();
        let persona = authority
            .management()
            .install_persona(&mut Present)
            .unwrap();
        let mut permissions = BTreeMap::new();
        permissions.insert("contents".to_owned(), PermissionLevel::Write);
        let installation = |version| {
            GrantInstallation::new(
                persona.clone(),
                PackRef {
                    address: "ember.test".to_owned(),
                    version,
                },
                "git.publish-ref/v1",
                "github",
                RepositoryResource::from_str("github:acme/widgets").unwrap(),
                Some("refs/heads/ws/".to_owned()),
                permissions.clone(),
                1,
                10_000,
            )
            .unwrap()
        };
        let first = authority
            .management()
            .install_grant(&mut Present, installation(1))
            .unwrap();
        let second = authority
            .management()
            .install_grant(&mut Present, installation(2))
            .unwrap();
        PresenceOperation::AttachSelectedGrants {
            session: SessionId::new(),
            grants: vec![
                authority.grant_summary(&first).unwrap(),
                authority.grant_summary(&second).unwrap(),
            ],
            delegation_ids: vec![DelegationId::new(), DelegationId::new()],
            requested_ttl_seconds: 300,
        }
    }

    fn binding() -> RuntimeAuthorityBinding {
        RuntimeAuthorityBinding::from_exact_bytes(b"install-a", b"state-a", b"daemon-a").unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn software_proof(intent: &RuntimePresenceIntent, key: &SigningKey) -> Vec<u8> {
        let signature: Signature = key.sign(intent.canonical_bytes());
        serde_jcs::to_vec(&RuntimeProofWire {
            schema: RUNTIME_PRESENCE_PROOF_SCHEMA.to_owned(),
            intent: intent.wire.clone(),

            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap()
    }

    fn open_store() -> (tempfile::TempDir, RuntimePresenceStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = RuntimePresenceStore::open(temp.path().join("runtime-presence")).unwrap();
        (temp, store)
    }

    const TEST_CONSUMED_NONCE_RETENTION_SECONDS: u64 = 10 * 60;

    impl RuntimePresenceStore {
        fn issue_at(
            &self,
            authority: &RuntimeAuthorityBinding,
            operation: &PresenceOperation,
            valid_for: Duration,
            now: u64,
        ) -> Result<RuntimePresenceIntent, RuntimePresenceError> {
            validate_authority(authority)?;
            if valid_for.is_zero()
                || valid_for > MAX_RUNTIME_INTENT_LIFETIME
                || valid_for.subsec_nanos() != 0
            {
                return Err(RuntimePresenceError::InvalidValidity);
            }
            let expires_at_unix = now
                .checked_add(valid_for.as_secs())
                .ok_or(RuntimePresenceError::InvalidTimestamp)?;
            let (operation_wire, founder_display) = encode_operation(operation)?;
            let founder_display_sha256 = display_sha256(&founder_display)?;

            let _lock = self.exclusive_lock()?;
            let mut ledger = self.load_ledger_for_issue_test(now)?;
            let consumed = ledger
                .records
                .iter()
                .filter_map(|(nonce, record)| {
                    (record.state == RuntimeNonceState::Consumed)
                        .then_some((nonce.clone(), record.consumed_at_unix.unwrap_or(now)))
                })
                .collect::<Vec<_>>();
            for (nonce, consumed_at) in consumed {
                ledger.records.remove(&nonce);
                ledger.consumed_nonces.insert(nonce, consumed_at);
            }
            ledger
                .records
                .retain(|_, record| record.intent.expires_at_unix >= now);
            ledger.consumed_nonces.retain(|_, consumed_at| {
                now.saturating_sub(*consumed_at) <= TEST_CONSUMED_NONCE_RETENTION_SECONDS
            });
            let nonce = loop {
                let mut random = [0u8; NONCE_BYTES];
                OsRng.fill_bytes(&mut random);
                let candidate = hex::encode(random);
                if !ledger.records.contains_key(&candidate) {
                    break candidate;
                }
            };
            let wire = RuntimeIntentWire {
                schema: RUNTIME_PRESENCE_INTENT_SCHEMA.to_owned(),
                authority: authority.clone(),
                operation: operation_wire,
                founder_display,
                founder_display_sha256,
                nonce: nonce.clone(),
                issued_at_unix: now,
                expires_at_unix,
            };
            validate_intent_static(&wire)?;
            let canonical_json = canonical_intent_bytes(&wire)?;
            if canonical_json.len() > MAX_WIRE_BYTES {
                return Err(RuntimePresenceError::InvalidOperation);
            }
            ledger.records.insert(
                nonce,
                RuntimeNonceRecordWire {
                    intent: wire.clone(),
                    state: RuntimeNonceState::Issued,
                    consumed_at_unix: None,
                },
            );
            self.persist_ledger(&ledger)?;
            Ok(RuntimePresenceIntent {
                wire,
                canonical_json,
            })
        }

        #[cfg(unix)]
        fn load_ledger_for_issue_test(
            &self,
            now: u64,
        ) -> Result<RuntimeLedgerWire, RuntimePresenceError> {
            let mut ledger = self.load_ledger_wire()?;
            prune_expired_foreign_intents_test(&mut ledger, now);
            validate_ledger(&ledger)?;
            Ok(ledger)
        }

        #[cfg(not(unix))]
        fn load_ledger_for_issue_test(
            &self,
            _now: u64,
        ) -> Result<RuntimeLedgerWire, RuntimePresenceError> {
            Err(RuntimePresenceError::UnsupportedPlatform)
        }
    }

    fn prune_expired_foreign_intents_test(ledger: &mut RuntimeLedgerWire, now: u64) {
        ledger.records.retain(|nonce, record| {
            let lifetime = record
                .intent
                .expires_at_unix
                .checked_sub(record.intent.issued_at_unix);
            let safely_prunable = record.intent.schema != RUNTIME_PRESENCE_INTENT_SCHEMA
                && is_versioned_runtime_intent_schema_test(&record.intent.schema)
                && nonce == &record.intent.nonce
                && is_lower_hex(nonce, NONCE_HEX_LEN)
                && record.state == RuntimeNonceState::Issued
                && record.consumed_at_unix.is_none()
                && record.intent.expires_at_unix <= now
                && lifetime.is_some_and(|seconds| {
                    seconds > 0 && seconds <= MAX_RUNTIME_INTENT_LIFETIME.as_secs()
                });
            !safely_prunable
        });
    }

    fn is_versioned_runtime_intent_schema_test(schema: &str) -> bool {
        schema
            .strip_prefix("ember.founder-presence.runtime-intent/v")
            .is_some_and(|version| {
                !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
            })
    }

    #[test]
    fn founder_presence_reason_frontloads_exact_grant_scope() {
        let (_temp, store) = open_store();
        let intent = store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();

        let reason = intent.founder_presence_reason().unwrap();
        assert!(reason.starts_with("Ember authority (300s): github:acme/widgets"));
        assert!(reason.contains("action=git.publish-ref/v1"));
        assert!(reason.contains("destination=refs/heads/ws/"));
        assert!(reason.contains("permissions=contents:write"));
        assert!(reason.len() <= MAX_FOUNDER_PRESENCE_REASON_BYTES);
        assert!(
            intent.founder_display().grants()[0]
                .full_summary()
                .contains("\nFull Grant: Grant ")
        );
    }

    #[test]
    fn grant_and_credential_reason_bounds_are_distinct() {
        assert_eq!(MAX_FOUNDER_PRESENCE_REASON_BYTES, 512);
        assert_eq!(MAX_CREDENTIAL_PRESENCE_REASON_BYTES, 1_024);

        let (_temp, store) = open_store();
        let mut intent = store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();
        let prefix_len = "Ember authority (300s): ".len();
        let first_len = 240;
        let second_len = MAX_FOUNDER_PRESENCE_REASON_BYTES - prefix_len - first_len - 1;
        intent.wire.founder_display.grants[0].full_summary =
            format!("{}\nFull Grant: first", "x".repeat(first_len));
        intent.wire.founder_display.grants[1].full_summary =
            format!("{}\nFull Grant: second", "y".repeat(second_len));
        assert_eq!(
            intent.founder_presence_reason().unwrap().len(),
            MAX_FOUNDER_PRESENCE_REASON_BYTES
        );

        intent.wire.founder_display.grants[1]
            .full_summary
            .insert(0, 'y');
        assert!(matches!(
            intent.founder_presence_reason(),
            Err(RuntimePresenceError::PresenceReasonTooLarge)
        ));
    }

    #[test]
    fn credential_transition_reasons_are_the_exact_displayed_tuples() {
        let (_temp, store) = open_store();
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
        let enrollment = store
            .issue_at(&binding(), &enrollment, Duration::from_secs(30), 1_000)
            .unwrap();
        assert_eq!(
            enrollment.founder_presence_reason().unwrap(),
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
        let rotation = store
            .issue_at(&binding(), &rotation, Duration::from_secs(30), 1_010)
            .unwrap();
        let rotation_reason = rotation.founder_presence_reason().unwrap();
        assert_eq!(
            rotation_reason,
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
        assert!(rotation_reason.len() > MAX_FOUNDER_PRESENCE_REASON_BYTES);
        assert!(rotation_reason.len() <= MAX_CREDENTIAL_PRESENCE_REASON_BYTES);

        let deletion = PresenceOperation::DeleteCredential {
            credential_id,
            current_revision_id: new_revision_id,
            current_commitment: new_commitment,
            kind: Kind::GithubAppPrivateKey,
            subject,
            custody_profile: profile,
        };
        let deletion = store
            .issue_at(&binding(), &deletion, Duration::from_secs(30), 1_020)
            .unwrap();
        assert_eq!(
            deletion.founder_presence_reason().unwrap(),
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
    fn founder_presence_reason_refuses_an_empty_display() {
        let (_temp, store) = open_store();
        let mut intent = store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();
        intent.wire.founder_display.grants.clear();
        assert!(matches!(
            intent.founder_presence_reason(),
            Err(RuntimePresenceError::InvalidOperation)
        ));
    }

    #[test]
    fn issue_prunes_expired_intent_from_previous_runtime_schema() {
        let (_temp, store) = open_store();
        store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();
        let ledger = store.load_ledger().unwrap();
        let mut installed_v3 = serde_json::to_value(&ledger).unwrap();
        let intent = installed_v3["records"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()
            .get_mut("intent")
            .unwrap();
        intent["schema"] = serde_json::json!("ember.founder-presence.runtime-intent/v3");
        intent["founder_display"]["grants"][0]["prompt_summary"] =
            serde_json::json!("Ember authority (30s): github:acme/widgets");
        fs::write(
            store.path().join(RUNTIME_LEDGER_FILE),
            serde_jcs::to_vec(&installed_v3).unwrap(),
        )
        .unwrap();

        store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 2_000)
            .unwrap();
    }
    #[test]
    fn issue_refuses_active_intent_from_unknown_runtime_schema() {
        let (_temp, store) = open_store();
        store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();
        let mut ledger = store.load_ledger().unwrap();
        ledger.records.values_mut().next().unwrap().intent.schema =
            "ember.founder-presence.runtime-intent/v3".to_owned();
        ledger
            .records
            .values_mut()
            .next()
            .unwrap()
            .intent
            .founder_display
            .grants[0]
            .transient_prompt_summary =
            Some("Ember authority (30s): github:acme/widgets".to_owned());
        store.persist_ledger(&ledger).unwrap();

        assert!(matches!(
            store.issue_at(&binding(), &operation(), Duration::from_secs(30), 1_010),
            Err(RuntimePresenceError::CorruptStore)
        ));
    }

    #[test]
    fn current_schema_rejects_transient_prompt_summary_field() {
        let (_temp, store) = open_store();
        store
            .issue_at(&binding(), &operation(), Duration::from_secs(30), 1_000)
            .unwrap();
        let mut ledger = store.load_ledger().unwrap();
        ledger
            .records
            .values_mut()
            .next()
            .unwrap()
            .intent
            .founder_display
            .grants[0]
            .transient_prompt_summary =
            Some("Ember authority (30s): github:acme/widgets".to_owned());
        store.persist_ledger(&ledger).unwrap();

        assert!(matches!(
            store.load_ledger(),
            Err(RuntimePresenceError::CorruptStore)
        ));
    }

    #[test]
    fn ledger_consumes_acceptance_once_and_verifier_is_one_use() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let intent = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 1_000)
            .unwrap();
        let signer = key(7);
        let public = signer.verifying_key().to_sec1_point(false);
        let proof = software_proof(&intent, &signer);
        let mut verified = store
            .accept_at(&proof, &binding, &operation, public.as_bytes(), 1_001)
            .unwrap();

        assert!(verified.verify_presence(&operation));
        assert!(!verified.verify_presence(&operation));
        assert!(matches!(
            store.accept_at(&proof, &binding, &operation, public.as_bytes(), 1_002),
            Err(RuntimePresenceError::Replay)
        ));
    }

    #[test]
    fn accepted_attachment_uses_grant_ceiling_while_installing_bounded_lifetime() {
        let (_temp, store) = open_store();
        let binding = binding();
        let mut authority = PersonaAuthority::new();
        let persona = authority
            .management()
            .install_persona(&mut Present)
            .unwrap();
        let grant = authority
            .management()
            .install_grant(
                &mut Present,
                GrantInstallation::new(
                    persona.clone(),
                    PackRef {
                        address: "ember.test".to_owned(),
                        version: 1,
                    },
                    "git.publish-ref/v1",
                    "github",
                    RepositoryResource::from_str("github:acme/widgets").unwrap(),
                    Some("refs/heads/ws/".to_owned()),
                    BTreeMap::from([("contents".to_owned(), PermissionLevel::Write)]),
                    1,
                    10_000,
                )
                .unwrap(),
            )
            .unwrap();
        let executable = ExecutableDigest::from_sha256([7; 32]);
        let (session, challenge) = authority.sessions().create(&persona, executable).unwrap();
        authority
            .sessions()
            .bind_origin(
                &session,
                &challenge,
                ProcessOrigin::new(42, 9, 501, 20, executable).unwrap(),
            )
            .unwrap();
        let selection = GrantSelection::whole(grant);
        let delegation = DelegationId::new();
        let requested_ttl = Duration::from_secs(300);
        let operation = PresenceOperation::AttachSelectedGrants {
            session: session.clone(),
            grants: authority
                .selected_grant_summaries(std::slice::from_ref(&selection))
                .unwrap(),
            delegation_ids: vec![delegation.clone()],
            requested_ttl_seconds: requested_ttl.as_secs(),
        };
        let intent = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 1_000)
            .unwrap();
        let signer = key(23);
        let public = signer.verifying_key().to_sec1_point(false);
        let proof = software_proof(&intent, &signer);
        let mut verified = store
            .accept_at(&proof, &binding, &operation, public.as_bytes(), 1_001)
            .unwrap();

        assert_eq!(
            authority
                .management()
                .attach_selected_grants(
                    &mut verified,
                    &session,
                    vec![(delegation.clone(), selection)],
                    1_001,
                    requested_ttl,
                )
                .unwrap(),
            vec![delegation]
        );
    }

    #[test]
    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn contended_runtime_lock_returns_with_bounded_timeout() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let intent = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 1_000)
            .unwrap();
        let signer = key(19);
        let public = signer
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let proof = software_proof(&intent, &signer);
        let holder = openat_file(
            store.root.as_raw_fd(),
            RUNTIME_LOCK_FILE,
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .unwrap();
        // SAFETY: holder owns a live descriptor for the duration of the test.
        assert_eq!(
            unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let path = store.path().to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let store = RuntimePresenceStore::open(path).unwrap();
            let started = std::time::Instant::now();
            let result = store.accept_at(&proof, &binding, &operation, &public, 1_001);
            sender.send((result, started.elapsed())).unwrap();
        });

        let observed = receiver.recv_timeout(RUNTIME_LOCK_ACQUIRE_TIMEOUT + Duration::from_secs(1));
        drop(holder);
        contender.join().unwrap();
        let (result, elapsed) = observed.expect("contended operation must return by its deadline");
        assert!(matches!(result, Err(RuntimePresenceError::LockTimeout)));
        assert!(
            elapsed <= RUNTIME_LOCK_ACQUIRE_TIMEOUT + Duration::from_secs(1),
            "lock acquisition took {elapsed:?}"
        );
    }

    #[test]
    fn mismatch_consumes_verifier_and_parseable_failures_consume_nonce() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let signer = key(9);
        let public = signer.verifying_key().to_sec1_point(false);

        let first = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 2_000)
            .unwrap();
        let first_proof = software_proof(&first, &signer);
        let mut verified = store
            .accept_at(&first_proof, &binding, &operation, public.as_bytes(), 2_001)
            .unwrap();
        assert!(!verified.verify_presence(&PresenceOperation::InstallPersona));
        assert!(!verified.verify_presence(&operation));

        let second = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 2_010)
            .unwrap();
        let mut noncanonical = software_proof(&second, &signer);
        noncanonical.push(b' ');
        assert!(matches!(
            store.accept_at(
                &noncanonical,
                &binding,
                &operation,
                public.as_bytes(),
                2_011
            ),
            Err(RuntimePresenceError::NonCanonicalEncoding)
        ));
        assert!(matches!(
            store.accept_at(
                &software_proof(&second, &signer),
                &binding,
                &operation,
                public.as_bytes(),
                2_012,
            ),
            Err(RuntimePresenceError::Replay)
        ));
    }

    #[test]
    fn unknown_fields_fail_closed_under_the_strict_schema() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let signer = key(10);
        let public = signer.verifying_key().to_sec1_point(false);
        let intent = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 2_100)
            .unwrap();
        let canonical = software_proof(&intent, &signer);
        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let with_unknown = serde_jcs::to_vec(&value).unwrap();
        assert!(matches!(
            store.accept_at(
                &with_unknown,
                &binding,
                &operation,
                public.as_bytes(),
                2_101,
            ),
            Err(RuntimePresenceError::MalformedProof)
        ));
        let mut verified = store
            .accept_at(&canonical, &binding, &operation, public.as_bytes(), 2_102)
            .unwrap();
        assert!(verified.verify_presence(&operation));
    }

    #[test]
    fn expired_wrong_identity_and_wrong_key_fail_closed_and_consume() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let signer = key(11);
        let public = signer.verifying_key().to_sec1_point(false);

        let expired = store
            .issue_at(&binding, &operation, Duration::from_secs(5), 3_000)
            .unwrap();
        let expired_proof = software_proof(&expired, &signer);
        assert!(matches!(
            store.accept_at(
                &expired_proof,
                &binding,
                &operation,
                public.as_bytes(),
                3_005
            ),
            Err(RuntimePresenceError::ExpiredProof)
        ));
        assert!(matches!(
            store.accept_at(
                &expired_proof,
                &binding,
                &operation,
                public.as_bytes(),
                3_006
            ),
            Err(RuntimePresenceError::Replay)
        ));

        let wrong_identity = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 3_010)
            .unwrap();
        let wrong_identity_proof = software_proof(&wrong_identity, &signer);
        let other_binding =
            RuntimeAuthorityBinding::from_exact_bytes(b"install-b", b"state-a", b"daemon-a")
                .unwrap();
        assert!(matches!(
            store.accept_at(
                &wrong_identity_proof,
                &other_binding,
                &operation,
                public.as_bytes(),
                3_011,
            ),
            Err(RuntimePresenceError::AuthorityBindingMismatch)
        ));
        assert!(matches!(
            store.accept_at(
                &wrong_identity_proof,
                &binding,
                &operation,
                public.as_bytes(),
                3_012,
            ),
            Err(RuntimePresenceError::Replay)
        ));

        let wrong_key = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 3_020)
            .unwrap();
        let wrong_key_proof = software_proof(&wrong_key, &signer);
        let other_key = key(12);
        let other_public = other_key.verifying_key().to_sec1_point(false);
        assert!(matches!(
            store.accept_at(
                &wrong_key_proof,
                &binding,
                &operation,
                other_public.as_bytes(),
                3_021,
            ),
            Err(RuntimePresenceError::InvalidSignature)
        ));
        assert!(matches!(
            store.accept_at(
                &wrong_key_proof,
                &binding,
                &operation,
                public.as_bytes(),
                3_022,
            ),
            Err(RuntimePresenceError::Replay)
        ));
    }

    #[test]
    fn changed_or_reordered_batch_and_display_fail_closed() {
        let (_temp, store) = open_store();
        let binding = binding();
        let operation = operation();
        let signer = key(13);
        let public = signer.verifying_key().to_sec1_point(false);

        let reordered = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 4_000)
            .unwrap();
        let reordered_proof = software_proof(&reordered, &signer);
        let mut reordered_operation = operation.clone();
        let PresenceOperation::AttachSelectedGrants { grants, .. } = &mut reordered_operation
        else {
            unreachable!()
        };
        grants.reverse();
        assert!(matches!(
            store.accept_at(
                &reordered_proof,
                &binding,
                &reordered_operation,
                public.as_bytes(),
                4_001,
            ),
            Err(RuntimePresenceError::OperationBindingMismatch)
        ));

        let changed_id = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 4_005)
            .unwrap();
        let mut changed_id_wire = changed_id.wire.clone();
        changed_id_wire.operation.grant_ids[0] = "changed-grant-id".to_owned();
        changed_id_wire.founder_display.grants[0].grant_id = "changed-grant-id".to_owned();
        changed_id_wire.founder_display_sha256 =
            display_sha256(&changed_id_wire.founder_display).unwrap();
        let signature: Signature = signer.sign(&canonical_intent_bytes(&changed_id_wire).unwrap());
        let changed_id_proof = serde_jcs::to_vec(&RuntimeProofWire {
            schema: RUNTIME_PRESENCE_PROOF_SCHEMA.to_owned(),
            intent: changed_id_wire,
            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap();
        assert!(matches!(
            store.accept_at(
                &changed_id_proof,
                &binding,
                &operation,
                public.as_bytes(),
                4_006,
            ),
            Err(RuntimePresenceError::IntentMismatch)
        ));
        let changed_delegation = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 4_007)
            .unwrap();
        let mut changed_delegation_wire = changed_delegation.wire.clone();
        let replacement = DelegationId::new().to_string();
        changed_delegation_wire.operation.delegation_ids[0] = replacement.clone();
        changed_delegation_wire.founder_display.grants[0].delegation_id = replacement;
        changed_delegation_wire.founder_display_sha256 =
            display_sha256(&changed_delegation_wire.founder_display).unwrap();
        let signature: Signature =
            signer.sign(&canonical_intent_bytes(&changed_delegation_wire).unwrap());
        let changed_delegation_proof = serde_jcs::to_vec(&RuntimeProofWire {
            schema: RUNTIME_PRESENCE_PROOF_SCHEMA.to_owned(),
            intent: changed_delegation_wire,
            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap();
        assert!(matches!(
            store.accept_at(
                &changed_delegation_proof,
                &binding,
                &operation,
                public.as_bytes(),
                4_008,
            ),
            Err(RuntimePresenceError::IntentMismatch)
        ));

        let altered_display = store
            .issue_at(&binding, &operation, Duration::from_secs(30), 4_010)
            .unwrap();
        let mut altered_wire = altered_display.wire.clone();
        altered_wire.founder_display.grants[0]
            .full_summary
            .push_str(" changed");
        altered_wire.founder_display_sha256 =
            display_sha256(&altered_wire.founder_display).unwrap();
        let signature: Signature = signer.sign(&canonical_intent_bytes(&altered_wire).unwrap());
        let altered_proof = serde_jcs::to_vec(&RuntimeProofWire {
            schema: RUNTIME_PRESENCE_PROOF_SCHEMA.to_owned(),
            intent: altered_wire,
            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap();
        assert!(matches!(
            store.accept_at(
                &altered_proof,
                &binding,
                &operation,
                public.as_bytes(),
                4_011,
            ),
            Err(RuntimePresenceError::IntentMismatch)
        ));
    }
}
