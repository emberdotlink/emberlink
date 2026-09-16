//! Founder-presence authorization for authority-state installation.
//!
//! Production signing has one path: a fixed-label persistent P-256 key in the
//! macOS Secure Enclave. Each signature uses a new `LAContext`; callers never
//! receive a private-key handle, authentication context, or unlock window.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

use crate::sha256_hex;

pub const FOUNDER_PRESENCE_KEY_LABEL: &str =
    "link.ember.authority-install.founder-presence.p256.v1";
pub const INSTALLATION_INTENT_SCHEMA: &str = "ember.founder-presence.install-intent/v1";
pub const INSTALLATION_PROOF_SCHEMA: &str = "ember.founder-presence.install-proof/v1";
pub const INSTALL_AUTHORITY_STATE_OPERATION: &str = "install_authority_state";
pub const MAX_INTENT_LIFETIME: Duration = Duration::from_secs(300);

const NONCE_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 65;
const SHA256_HEX_LEN: usize = 64;
const NONCE_HEX_LEN: usize = NONCE_BYTES * 2;
const LEDGER_SCHEMA: &str = "ember.founder-presence.nonce-ledger/v2";
const LEDGER_FILE: &str = "nonce-ledger.json";
const LOCK_FILE: &str = ".nonce-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresencePolicy {
    /// Security.framework `PrivateKeyUsage | UserPresence`.
    UserPresence,
    /// Security.framework `PrivateKeyUsage | BiometryCurrentSet`.
    BiometryCurrentSet,
}

/// Public result of enrollment. It contains no private-key material or handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FounderKeyEnrollment {
    public_key_sec1: [u8; PUBLIC_KEY_BYTES],
    policy: PresencePolicy,
}

impl FounderKeyEnrollment {
    pub fn public_key_sec1(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key_sec1
    }

    pub fn policy(&self) -> PresencePolicy {
        self.policy
    }
}

/// Intent returned only after its random nonce is durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedInstallationIntent {
    wire: IntentWire,
}

impl IssuedInstallationIntent {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PresenceError> {
        canonical_intent_bytes(&self.wire)
    }

    pub fn nonce(&self) -> &str {
        &self.wire.nonce
    }

    pub fn installed_state_sha256(&self) -> &str {
        &self.wire.installed_state_sha256
    }

    pub fn issued_at_unix(&self) -> u64 {
        self.wire.issued_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.wire.expires_at_unix
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, PresenceError> {
        let wire: IntentWire =
            serde_json::from_slice(bytes).map_err(|_| PresenceError::MalformedProof)?;
        if canonical_intent_bytes(&wire)? != bytes {
            return Err(PresenceError::NonCanonicalEncoding);
        }
        validate_intent_static(&wire)?;
        Ok(Self { wire })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInstallationProof {
    canonical_json: Vec<u8>,
}

impl SignedInstallationProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.canonical_json
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    schema: String,
    operation: String,
    installed_state_sha256: String,
    nonce: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofWire {
    schema: String,
    intent: IntentWire,
    signature_der_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerWire {
    schema: String,
    records: BTreeMap<String, NonceRecordWire>,
    current_installation: Option<CurrentInstallationWire>,
}

impl Default for LedgerWire {
    fn default() -> Self {
        Self {
            schema: LEDGER_SCHEMA.to_owned(),
            records: BTreeMap::new(),
            current_installation: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NonceRecordWire {
    intent: IntentWire,
    state: NonceState,
    consumed_at_unix: Option<u64>,
    acceptance: Option<AcceptanceWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceWire {
    proof_sha256: String,
    enrolled_public_key_sha256: String,
    accepted_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CurrentInstallationWire {
    nonce: String,
    proof_sha256: String,
    installed_state_sha256: String,
    daemon_config_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NonceState {
    Issued,
    Consumed,
    Accepted,
}

/// Owner-private durable nonce issue/consume/acceptance-tombstone store.
///
/// The root descriptor remains open. Children use `openat(O_NOFOLLOW)`, a
/// private regular-file lock, atomic `renameat`, and file+directory `fsync`.
#[derive(Debug)]
pub struct NonceStore {
    root_path: PathBuf,
    #[cfg(unix)]
    root: File,
}

impl NonceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PresenceError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(PresenceError::InvalidStorePath);
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(PresenceError::InsecureStore);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(unix)]
                fs::DirBuilder::new().mode(0o700).create(path)?;
                #[cfg(not(unix))]
                return Err(PresenceError::UnsupportedPlatform);
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
            Err(PresenceError::UnsupportedPlatform)
        }
    }

    pub fn path(&self) -> &Path {
        &self.root_path
    }

    /// Durably issues a random 256-bit nonce bound to the SHA-256 digest of
    /// the exact installed-state bytes and to the fixed install operation.
    pub fn issue_installation_intent(
        &self,
        installed_state: &[u8],
        valid_for: Duration,
    ) -> Result<IssuedInstallationIntent, PresenceError> {
        self.issue_at(installed_state, valid_for, unix_now()?)
    }

    /// Fresh-install boundary: parse a canonical proof, durably consume its
    /// nonce, enforce strict timestamps and bindings, verify the enrolled key's
    /// signature, then persist an accepted tombstone bound to the exact proof and
    /// enrolled key. Any parseable failed attempt leaves the nonce consumed.
    pub fn accept_fresh_install(
        &self,
        proof: &[u8],
        installed_state: &[u8],
        daemon_config: &[u8],
        enrolled_public_key_sec1: &[u8],
    ) -> Result<(), PresenceError> {
        self.accept_fresh_install_at(
            proof,
            installed_state,
            daemon_config,
            enrolled_public_key_sec1,
            unix_now()?,
        )
    }

    /// Restart boundary: verifies the exact installed-state, daemon-config, and
    /// proof bytes against the sole current durable installation pointer. Expiry
    /// is intentionally not re-applied; freshness was enforced once at acceptance.
    /// Substituting a different proof, key, nonce, state, or config fails closed.
    pub fn verify_accepted_state(
        &self,
        proof: &[u8],
        installed_state: &[u8],
        daemon_config: &[u8],
        enrolled_public_key_sec1: &[u8],
    ) -> Result<(), PresenceError> {
        let proof_wire = parse_canonical_proof(proof)?;
        validate_proof_static(&proof_wire)?;
        // Keep the ledger lock through signature verification so a concurrent
        // acceptance cannot supersede this installation between lookup and return.
        let _lock = self.exclusive_lock()?;
        let ledger = self.load_ledger()?;
        let acceptance = Self::load_accepted(
            &ledger,
            &proof_wire.intent.nonce,
            &proof_wire.intent,
            daemon_config,
        )?;
        if acceptance.proof_sha256 != sha256_hex(proof)
            || acceptance.enrolled_public_key_sha256 != sha256_hex(enrolled_public_key_sec1)
        {
            return Err(PresenceError::AcceptedBindingMismatch);
        }
        verify_proof_signature(&proof_wire, installed_state, enrolled_public_key_sec1)
    }

    fn issue_at(
        &self,
        installed_state: &[u8],
        valid_for: Duration,
        now: u64,
    ) -> Result<IssuedInstallationIntent, PresenceError> {
        if valid_for.is_zero() || valid_for > MAX_INTENT_LIFETIME || valid_for.subsec_nanos() != 0 {
            return Err(PresenceError::InvalidValidity);
        }
        let expires_at_unix = now
            .checked_add(valid_for.as_secs())
            .ok_or(PresenceError::InvalidTimestamp)?;
        let _lock = self.exclusive_lock()?;
        let mut ledger = self.load_ledger()?;
        let nonce = loop {
            let mut random = [0u8; NONCE_BYTES];
            OsRng.fill_bytes(&mut random);
            let candidate = hex::encode(random);
            if !ledger.records.contains_key(&candidate) {
                break candidate;
            }
        };
        let intent = IntentWire {
            schema: INSTALLATION_INTENT_SCHEMA.to_owned(),
            operation: INSTALL_AUTHORITY_STATE_OPERATION.to_owned(),
            installed_state_sha256: sha256_hex(installed_state),
            nonce: nonce.clone(),
            issued_at_unix: now,
            expires_at_unix,
        };
        ledger.records.insert(
            nonce,
            NonceRecordWire {
                intent: intent.clone(),
                state: NonceState::Issued,
                consumed_at_unix: None,
                acceptance: None,
            },
        );
        self.persist_ledger(&ledger)?;
        Ok(IssuedInstallationIntent { wire: intent })
    }

    fn accept_fresh_install_at(
        &self,
        proof: &[u8],
        installed_state: &[u8],
        daemon_config: &[u8],
        enrolled_public_key_sec1: &[u8],
        now: u64,
    ) -> Result<(), PresenceError> {
        let proof_wire = parse_canonical_proof(proof)?;
        let stored_intent = self.consume_nonce(&proof_wire.intent.nonce, now)?;
        validate_proof_fresh(&proof_wire, now)?;
        if stored_intent != proof_wire.intent {
            return Err(PresenceError::IntentMismatch);
        }
        verify_proof_signature(&proof_wire, installed_state, enrolled_public_key_sec1)?;
        self.mark_accepted(
            &proof_wire.intent,
            sha256_hex(proof),
            sha256_hex(enrolled_public_key_sec1),
            sha256_hex(daemon_config),
            now,
        )
    }

    fn consume_nonce(&self, nonce: &str, now: u64) -> Result<IntentWire, PresenceError> {
        let _lock = self.exclusive_lock()?;
        let mut ledger = self.load_ledger()?;
        let record = ledger
            .records
            .get_mut(nonce)
            .ok_or(PresenceError::UnknownNonce)?;
        if record.state != NonceState::Issued {
            return Err(PresenceError::Replay);
        }
        record.state = NonceState::Consumed;
        record.consumed_at_unix = Some(now);
        let intent = record.intent.clone();
        self.persist_ledger(&ledger)?;
        Ok(intent)
    }

    fn mark_accepted(
        &self,
        intent: &IntentWire,
        proof_sha256: String,
        enrolled_public_key_sha256: String,
        daemon_config_sha256: String,
        now: u64,
    ) -> Result<(), PresenceError> {
        let _lock = self.exclusive_lock()?;
        let mut ledger = self.load_ledger()?;
        let record = ledger
            .records
            .get_mut(&intent.nonce)
            .ok_or(PresenceError::UnknownNonce)?;
        if record.state != NonceState::Consumed || record.intent != *intent {
            return Err(PresenceError::Replay);
        }
        record.state = NonceState::Accepted;
        record.acceptance = Some(AcceptanceWire {
            proof_sha256: proof_sha256.clone(),
            enrolled_public_key_sha256,
            accepted_at_unix: now,
        });
        ledger.current_installation = Some(CurrentInstallationWire {
            nonce: intent.nonce.clone(),
            proof_sha256,
            installed_state_sha256: intent.installed_state_sha256.clone(),
            daemon_config_sha256,
        });
        self.persist_ledger(&ledger)
    }

    fn load_accepted(
        ledger: &LedgerWire,
        nonce: &str,
        intent: &IntentWire,
        daemon_config: &[u8],
    ) -> Result<AcceptanceWire, PresenceError> {
        let current = ledger
            .current_installation
            .as_ref()
            .ok_or(PresenceError::NotAccepted)?;
        if current.nonce != nonce {
            return Err(PresenceError::NotAccepted);
        }
        let record = ledger
            .records
            .get(nonce)
            .ok_or(PresenceError::UnknownNonce)?;
        let acceptance = record
            .acceptance
            .as_ref()
            .ok_or(PresenceError::NotAccepted)?;
        if record.state != NonceState::Accepted || record.intent != *intent {
            return Err(PresenceError::NotAccepted);
        }
        if current.proof_sha256 != acceptance.proof_sha256
            || current.installed_state_sha256 != intent.installed_state_sha256
            || current.daemon_config_sha256 != sha256_hex(daemon_config)
        {
            return Err(PresenceError::AcceptedBindingMismatch);
        }
        Ok(acceptance.clone())
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn exclusive_lock(&self) -> Result<File, PresenceError> {
        let lock = openat_file(
            self.root.as_raw_fd(),
            LOCK_FILE,
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular_file(&lock, None)?;
        // SAFETY: lock owns a live descriptor; closing it releases flock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(lock)
    }

    #[cfg(unix)]
    fn load_ledger(&self) -> Result<LedgerWire, PresenceError> {
        let mut file = match openat_file(
            self.root.as_raw_fd(),
            LEDGER_FILE,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LedgerWire::default());
            }
            Err(error) => return Err(error.into()),
        };
        validate_private_regular_file(&file, Some(MAX_LEDGER_BYTES))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_LEDGER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(PresenceError::CorruptStore);
        }
        let ledger: LedgerWire =
            serde_json::from_slice(&bytes).map_err(|_| PresenceError::CorruptStore)?;
        validate_ledger(&ledger)?;
        if serde_jcs::to_vec(&ledger).map_err(|_| PresenceError::CorruptStore)? != bytes {
            return Err(PresenceError::CorruptStore);
        }
        Ok(ledger)
    }

    #[cfg(unix)]
    fn persist_ledger(&self, ledger: &LedgerWire) -> Result<(), PresenceError> {
        let bytes = serde_jcs::to_vec(ledger).map_err(|_| PresenceError::Serialization)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(PresenceError::StoreCapacity);
        }
        let mut random = [0u8; 12];
        OsRng.fill_bytes(&mut random);
        let temp_name = format!(".nonce-ledger.tmp.{}", hex::encode(random));
        let mut temp = openat_file(
            self.root.as_raw_fd(),
            &temp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular_file(&temp, None)?;
        let result = (|| -> Result<(), PresenceError> {
            temp.write_all(&bytes)?;
            temp.sync_all()?;
            renameat_file(self.root.as_raw_fd(), &temp_name, LEDGER_FILE)?;
            self.root.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat_file(self.root.as_raw_fd(), &temp_name);
        }
        result
    }

    #[cfg(not(unix))]
    fn exclusive_lock(&self) -> Result<File, PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }

    #[cfg(not(unix))]
    fn load_ledger(&self) -> Result<LedgerWire, PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }

    #[cfg(not(unix))]
    fn persist_ledger(&self, _ledger: &LedgerWire) -> Result<(), PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }
}

/// Creates the fixed-label persistent P-256 Secure Enclave key with the chosen
/// access control. No release API can construct a software signing key.
pub fn enroll_founder_presence_key(
    policy: PresencePolicy,
) -> Result<FounderKeyEnrollment, PresenceError> {
    platform::enroll(policy)
}

/// Confirms that the fixed-label key is Secure-Enclave-backed and matches the
/// enrolled public trust anchor exactly.
pub fn lookup_founder_presence_key(enrolled_public_key_sec1: &[u8]) -> Result<(), PresenceError> {
    parse_public_key(enrolled_public_key_sec1)?;
    platform::lookup(enrolled_public_key_sec1)
}
/// Signs exact canonical founder-presence bytes with the fixed enrolled key.
///
/// This crate-private seam lets other strict presence protocols reuse the sole
/// production key lookup and fresh-`LAContext` signing path without exposing a
/// key handle or authentication context.
pub(crate) fn sign_founder_presence_message(
    message: &[u8],
    enrolled_public_key_sec1: &[u8],
    reason: &str,
) -> Result<Vec<u8>, PresenceError> {
    parse_public_key(enrolled_public_key_sec1)?;
    platform::sign(message, enrolled_public_key_sec1, reason)
}

/// Signs one issued install intent. The consent reason names authority-state
/// installation and includes the first twelve hex digits of its SHA-256 digest.
pub fn sign_installation_intent(
    intent: &IssuedInstallationIntent,
    enrolled_public_key_sec1: &[u8],
) -> Result<SignedInstallationProof, PresenceError> {
    let now = unix_now()?;
    validate_intent_fresh(&intent.wire, now)?;
    parse_public_key(enrolled_public_key_sec1)?;
    let signed_bytes = canonical_intent_bytes(&intent.wire)?;
    let reason = format!(
        "Install Ember authority state (SHA-256 {})",
        &intent.wire.installed_state_sha256[..12]
    );
    let signature_der = platform::sign(&signed_bytes, enrolled_public_key_sec1, &reason)?;
    let proof = ProofWire {
        schema: INSTALLATION_PROOF_SCHEMA.to_owned(),
        intent: intent.wire.clone(),
        signature_der_hex: hex::encode(signature_der),
    };
    Ok(SignedInstallationProof {
        canonical_json: serde_jcs::to_vec(&proof).map_err(|_| PresenceError::Serialization)?,
    })
}

fn verify_proof_signature(
    proof: &ProofWire,
    installed_state: &[u8],
    enrolled_public_key_sec1: &[u8],
) -> Result<(), PresenceError> {
    if sha256_hex(installed_state) != proof.intent.installed_state_sha256 {
        return Err(PresenceError::DigestMismatch);
    }
    let key = parse_public_key(enrolled_public_key_sec1)?;
    let signature_bytes =
        decode_lower_hex(&proof.signature_der_hex).ok_or(PresenceError::InvalidSignature)?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|_| PresenceError::InvalidSignature)?;
    key.verify(&canonical_intent_bytes(&proof.intent)?, &signature)
        .map_err(|_| PresenceError::InvalidSignature)
}

fn parse_canonical_proof(bytes: &[u8]) -> Result<ProofWire, PresenceError> {
    if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
        return Err(PresenceError::MalformedProof);
    }
    let proof: ProofWire =
        serde_json::from_slice(bytes).map_err(|_| PresenceError::MalformedProof)?;
    if serde_jcs::to_vec(&proof).map_err(|_| PresenceError::MalformedProof)? != bytes {
        return Err(PresenceError::NonCanonicalEncoding);
    }
    Ok(proof)
}

fn validate_proof_static(proof: &ProofWire) -> Result<(), PresenceError> {
    if proof.schema != INSTALLATION_PROOF_SCHEMA {
        return Err(PresenceError::UnexpectedSchema);
    }
    validate_intent_static(&proof.intent)?;
    if decode_lower_hex(&proof.signature_der_hex).is_none() {
        return Err(PresenceError::InvalidSignature);
    }
    Ok(())
}

fn validate_proof_fresh(proof: &ProofWire, now: u64) -> Result<(), PresenceError> {
    validate_proof_static(proof)?;
    validate_intent_fresh(&proof.intent, now)
}

fn validate_intent_static(intent: &IntentWire) -> Result<(), PresenceError> {
    if intent.schema != INSTALLATION_INTENT_SCHEMA {
        return Err(PresenceError::UnexpectedSchema);
    }
    if intent.operation != INSTALL_AUTHORITY_STATE_OPERATION {
        return Err(PresenceError::UnexpectedOperation);
    }
    if !is_lower_hex(&intent.installed_state_sha256, SHA256_HEX_LEN)
        || !is_lower_hex(&intent.nonce, NONCE_HEX_LEN)
    {
        return Err(PresenceError::MalformedProof);
    }
    let lifetime = intent
        .expires_at_unix
        .checked_sub(intent.issued_at_unix)
        .ok_or(PresenceError::InvalidTimestamp)?;
    if lifetime == 0 || lifetime > MAX_INTENT_LIFETIME.as_secs() {
        return Err(PresenceError::InvalidTimestamp);
    }
    Ok(())
}

fn validate_intent_fresh(intent: &IntentWire, now: u64) -> Result<(), PresenceError> {
    validate_intent_static(intent)?;
    if intent.issued_at_unix > now {
        return Err(PresenceError::FutureProof);
    }
    if now >= intent.expires_at_unix {
        return Err(PresenceError::ExpiredProof);
    }
    Ok(())
}

fn validate_ledger(ledger: &LedgerWire) -> Result<(), PresenceError> {
    if ledger.schema != LEDGER_SCHEMA {
        return Err(PresenceError::CorruptStore);
    }
    for (nonce, record) in &ledger.records {
        if nonce != &record.intent.nonce || !is_lower_hex(nonce, NONCE_HEX_LEN) {
            return Err(PresenceError::CorruptStore);
        }
        validate_intent_static(&record.intent).map_err(|_| PresenceError::CorruptStore)?;
        match (record.state, record.consumed_at_unix, &record.acceptance) {
            (NonceState::Issued, None, None) => {}
            (NonceState::Consumed, Some(_), None) => {}
            (NonceState::Accepted, Some(consumed), Some(acceptance))
                if acceptance.accepted_at_unix >= record.intent.issued_at_unix
                    && acceptance.accepted_at_unix < record.intent.expires_at_unix
                    && acceptance.accepted_at_unix >= consumed
                    && is_lower_hex(&acceptance.proof_sha256, SHA256_HEX_LEN)
                    && is_lower_hex(&acceptance.enrolled_public_key_sha256, SHA256_HEX_LEN) => {}
            _ => return Err(PresenceError::CorruptStore),
        }
    }
    let accepted_records = ledger
        .records
        .values()
        .filter(|record| record.state == NonceState::Accepted)
        .count();
    match &ledger.current_installation {
        None if accepted_records == 0 => {}
        Some(current)
            if is_lower_hex(&current.nonce, NONCE_HEX_LEN)
                && is_lower_hex(&current.proof_sha256, SHA256_HEX_LEN)
                && is_lower_hex(&current.installed_state_sha256, SHA256_HEX_LEN)
                && is_lower_hex(&current.daemon_config_sha256, SHA256_HEX_LEN) =>
        {
            let record = ledger
                .records
                .get(&current.nonce)
                .ok_or(PresenceError::CorruptStore)?;
            let acceptance = record
                .acceptance
                .as_ref()
                .ok_or(PresenceError::CorruptStore)?;
            if record.state != NonceState::Accepted
                || current.proof_sha256 != acceptance.proof_sha256
                || current.installed_state_sha256 != record.intent.installed_state_sha256
            {
                return Err(PresenceError::CorruptStore);
            }
        }
        _ => return Err(PresenceError::CorruptStore),
    }
    Ok(())
}

fn canonical_intent_bytes(intent: &IntentWire) -> Result<Vec<u8>, PresenceError> {
    serde_jcs::to_vec(intent).map_err(|_| PresenceError::Serialization)
}

fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey, PresenceError> {
    if bytes.len() != PUBLIC_KEY_BYTES || bytes.first() != Some(&0x04) {
        return Err(PresenceError::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| PresenceError::InvalidPublicKey)
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

fn unix_now() -> Result<u64, PresenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| PresenceError::Clock)
}

#[cfg(unix)]
fn validate_private_directory(directory: &File) -> Result<(), PresenceError> {
    let metadata = directory.metadata()?;
    let euid = crate::effective_uid();
    if !metadata.file_type().is_dir()
        || metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o700 != 0o700
    {
        return Err(PresenceError::InsecureStore);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_regular_file(file: &File, max_len: Option<u64>) -> Result<(), PresenceError> {
    let metadata = file.metadata()?;
    let euid = crate::effective_uid();
    if !metadata.file_type().is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || max_len.is_some_and(|limit| metadata.len() > limit)
    {
        return Err(PresenceError::InsecureStore);
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn openat_file(root: RawFd, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    use std::ffi::CString;
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: name is a live NUL-terminated CString, and the variadic mode
    // argument uses the C integer promotion required by openat.
    let fd = unsafe { libc::openat(root, name.as_ptr(), flags, mode as libc::c_int) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn renameat_file(root: RawFd, from: &str, to: &str) -> io::Result<()> {
    use std::ffi::CString;
    let from = CString::new(from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    let to = CString::new(to)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: from and to are live NUL-terminated CStrings for the duration of
    // renameat; integer descriptors are passed by value.
    if unsafe { libc::renameat(root, from.as_ptr(), root, to.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn unlinkat_file(root: RawFd, name: &str) -> io::Result<()> {
    use std::ffi::CString;
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: name is a live NUL-terminated CString for the duration of
    // unlinkat; the integer descriptor is passed by value.
    if unsafe { libc::unlinkat(root, name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod platform {
    use super::*;
    use core_foundation::base::{CFType, TCFType as _, ToVoid as _};
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_local_authentication::LAContext;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework::passwords_options::AccessControlOptions;
    use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};
    use std::os::raw::c_void;

    pub(super) fn enroll(policy: PresencePolicy) -> Result<FounderKeyEnrollment, PresenceError> {
        let presence = match policy {
            PresencePolicy::UserPresence => AccessControlOptions::USER_PRESENCE,
            PresencePolicy::BiometryCurrentSet => AccessControlOptions::BIOMETRY_CURRENT_SET,
        };
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            (AccessControlOptions::PRIVATE_KEY_USAGE | presence).bits(),
        )
        .map_err(|error| PresenceError::KeyEnrollment(error.to_string()))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(FOUNDER_PRESENCE_KEY_LABEL)
            .set_access_control(access)
            .set_location(Location::DataProtectionKeychain);
        let key = SecKey::new(&options)
            .map_err(|error| PresenceError::KeyEnrollment(error.to_string()))?;
        if !is_secure_enclave_key(&key) {
            let _ = key.delete();
            return Err(PresenceError::BackendAuthenticity);
        }
        Ok(FounderKeyEnrollment {
            public_key_sec1: public_key_bytes(&key)?,
            policy,
        })
    }

    pub(super) fn lookup(expected_public_key: &[u8]) -> Result<(), PresenceError> {
        find_expected_key(
            expected_public_key,
            "Locate enrolled Ember founder-presence key",
        )
        .map(|_| ())
    }

    pub(super) fn sign(
        message: &[u8],
        expected_public_key: &[u8],
        reason: &str,
    ) -> Result<Vec<u8>, PresenceError> {
        find_expected_key(expected_public_key, reason)?
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|error| PresenceError::PresenceUnavailable(error.to_string()))
    }

    fn find_expected_key(
        expected_public_key: &[u8],
        reason: &str,
    ) -> Result<SecKey, PresenceError> {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(FOUNDER_PRESENCE_KEY_LABEL)
            .load_refs(true)
            .limit(Limit::All)
            .ignore_legacy_keychains();
        attach_authentication_context(&mut query, reason);
        let results = query
            .search()
            .map_err(|error| PresenceError::KeyLookup(error.to_string()))?;
        let mut found = None;
        for result in results {
            let SearchResult::Ref(Reference::Key(key)) = result else {
                continue;
            };
            if is_secure_enclave_key(&key)
                && public_key_bytes(&key)?.as_slice() == expected_public_key
            {
                if found.is_some() {
                    return Err(PresenceError::BackendAuthenticity);
                }
                found = Some(key);
            }
        }
        found.ok_or(PresenceError::BackendAuthenticity)
    }

    fn public_key_bytes(key: &SecKey) -> Result<[u8; PUBLIC_KEY_BYTES], PresenceError> {
        let bytes = key
            .public_key()
            .ok_or(PresenceError::BackendAuthenticity)?
            .external_representation()
            .ok_or(PresenceError::BackendAuthenticity)?
            .to_vec();
        parse_public_key(&bytes)?;
        bytes
            .try_into()
            .map_err(|_| PresenceError::BackendAuthenticity)
    }

    fn is_secure_enclave_key(key: &SecKey) -> bool {
        if key.external_representation().is_some() {
            return false;
        }
        let attributes = key.attributes();
        // SAFETY: Security.framework exports this immutable, non-null CFString
        // constant for the lifetime of the process.
        let token_attribute = unsafe { kSecAttrTokenID };
        let Some(token) = attributes.find(token_attribute.to_void()) else {
            return false;
        };
        // SAFETY: attributes retains this non-null CF value while actual is in
        // use; get-rule wrapping borrows rather than consumes the reference.
        let actual = unsafe { CFType::wrap_under_get_rule((*token).cast()) };
        // SAFETY: Security.framework exports this immutable, non-null CFString
        // constant for the lifetime of the process.
        let enclave_token = unsafe { kSecAttrTokenIDSecureEnclave };
        // SAFETY: the Security.framework constant is a non-null CFString with
        // process lifetime; get-rule wrapping does not consume it.
        let expected = unsafe { CFType::wrap_under_get_rule(enclave_token.cast()) };
        actual == expected
    }

    /// Hands exactly one +1 retain to security-framework's create-rule sink.
    fn attach_authentication_context(query: &mut ItemSearchOptions, reason: &str) {
        // SAFETY: LAContext is available on supported macOS targets, and +new
        // returns a retained, initialized LAContext.
        let context: Retained<LAContext> = unsafe { LAContext::new() };
        let reason = NSString::from_str(reason);
        // SAFETY: context and reason are valid Objective-C objects, and the
        // property setter borrows both for the duration of the message.
        unsafe {
            context.setLocalizedReason(&reason);
        }
        let raw = Retained::into_raw(context);
        // SAFETY: into_raw yields exactly one +1 LAContext reference; this
        // create-rule sink consumes that retain, and raw is not used again.
        unsafe {
            #[allow(deprecated)]
            query.authentication_context(raw.cast::<c_void>());
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    pub(super) fn enroll(_policy: PresencePolicy) -> Result<FounderKeyEnrollment, PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }

    pub(super) fn lookup(_expected_public_key: &[u8]) -> Result<(), PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }

    pub(super) fn sign(
        _message: &[u8],
        _expected_public_key: &[u8],
        _reason: &str,
    ) -> Result<Vec<u8>, PresenceError> {
        Err(PresenceError::UnsupportedPlatform)
    }
}

#[derive(Debug, Error)]
pub enum PresenceError {
    #[error("founder presence requires macOS Secure Enclave")]
    UnsupportedPlatform,
    #[error("nonce store path must be absolute")]
    InvalidStorePath,
    #[error("nonce store is not owner-private and symlink-safe")]
    InsecureStore,
    #[error("nonce store is corrupt or non-canonical")]
    CorruptStore,
    #[error("nonce store capacity exceeded")]
    StoreCapacity,
    #[error("intent validity must be whole seconds in 1..=300")]
    InvalidValidity,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("invalid intent timestamps")]
    InvalidTimestamp,
    #[error("proof was issued in the future")]
    FutureProof,
    #[error("proof is expired")]
    ExpiredProof,
    #[error("proof encoding is malformed")]
    MalformedProof,
    #[error("proof is not RFC 8785 canonical JSON")]
    NonCanonicalEncoding,
    #[error("unexpected proof or intent schema")]
    UnexpectedSchema,
    #[error("proof operation is not install_authority_state")]
    UnexpectedOperation,
    #[error("proof intent does not match the issued nonce")]
    IntentMismatch,
    #[error("installed-state digest does not match")]
    DigestMismatch,
    #[error("nonce was not issued by this store")]
    UnknownNonce,
    #[error("nonce has already been consumed")]
    Replay,
    #[error("nonce has no accepted installation record")]
    NotAccepted,
    #[error("accepted proof, key, state, config, or current-installation binding does not match")]
    AcceptedBindingMismatch,
    #[error("enrolled key is not an uncompressed P-256 public point")]
    InvalidPublicKey,
    #[error("P-256 proof signature is invalid")]
    InvalidSignature,
    #[error("canonical serialization failed")]
    Serialization,
    #[error("Secure Enclave enrollment failed: {0}")]
    KeyEnrollment(String),
    #[error("Secure Enclave lookup failed: {0}")]
    KeyLookup(String),
    #[error("keychain item is not the enrolled Secure Enclave key")]
    BackendAuthenticity,
    #[error("OS-mediated founder presence unavailable: {0}")]
    PresenceUnavailable(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};

    const CONFIG: &[u8] = b"exact daemon config";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn proof(intent: &IssuedInstallationIntent, key: &SigningKey) -> Vec<u8> {
        let signature: Signature = key.sign(&intent.canonical_bytes().unwrap());
        serde_jcs::to_vec(&ProofWire {
            schema: INSTALLATION_PROOF_SCHEMA.to_owned(),
            intent: intent.wire.clone(),
            signature_der_hex: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap()
    }

    fn open_test_store(name: &str) -> (tempfile::TempDir, NonceStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(temp.path().join(name)).unwrap();
        (temp, store)
    }

    #[test]
    fn accepts_once_and_restart_verifies_exact_state_and_config() {
        let (_temp, store) = open_test_store("nonce");
        let state = b"exact installed state";
        let intent = store
            .issue_at(state, Duration::from_secs(30), 1_000)
            .unwrap();
        let key = key(7);
        let proof = proof(&intent, &key);
        let public = key.verifying_key().to_sec1_point(false);
        store
            .accept_fresh_install_at(&proof, state, CONFIG, public.as_bytes(), 1_001)
            .unwrap();
        assert!(matches!(
            store.accept_fresh_install_at(&proof, state, CONFIG, public.as_bytes(), 1_002),
            Err(PresenceError::Replay)
        ));
        store
            .verify_accepted_state(&proof, state, CONFIG, public.as_bytes())
            .unwrap();
        assert!(matches!(
            store.verify_accepted_state(&proof, b"changed", CONFIG, public.as_bytes()),
            Err(PresenceError::DigestMismatch)
        ));
        assert!(matches!(
            store.verify_accepted_state(&proof, state, b"changed config", public.as_bytes()),
            Err(PresenceError::AcceptedBindingMismatch)
        ));
    }

    #[test]
    fn newer_acceptance_supersedes_the_prior_installation_atomically() {
        let (_temp, store) = open_test_store("supersede");
        let signer = key(12);
        let public = signer.verifying_key().to_sec1_point(false);
        let old_state = b"old state";
        let old_config = b"old config";
        let old_intent = store
            .issue_at(old_state, Duration::from_secs(30), 2_000)
            .unwrap();
        let old_proof = proof(&old_intent, &signer);
        store
            .accept_fresh_install_at(&old_proof, old_state, old_config, public.as_bytes(), 2_001)
            .unwrap();

        let new_state = b"new state";
        let new_config = b"new config";
        let new_intent = store
            .issue_at(new_state, Duration::from_secs(30), 2_002)
            .unwrap();
        let new_proof = proof(&new_intent, &signer);
        store
            .accept_fresh_install_at(&new_proof, new_state, new_config, public.as_bytes(), 2_003)
            .unwrap();

        assert!(matches!(
            store.verify_accepted_state(&old_proof, old_state, old_config, public.as_bytes(),),
            Err(PresenceError::NotAccepted)
        ));
        assert!(matches!(
            store.verify_accepted_state(&new_proof, old_state, new_config, public.as_bytes(),),
            Err(PresenceError::DigestMismatch)
        ));
        assert!(matches!(
            store.verify_accepted_state(&new_proof, new_state, old_config, public.as_bytes(),),
            Err(PresenceError::AcceptedBindingMismatch)
        ));
        store
            .verify_accepted_state(&new_proof, new_state, new_config, public.as_bytes())
            .unwrap();
    }

    #[test]
    fn rejects_wrong_digest_operation_key_nonce_and_time() {
        let signer = key(8);
        let wrong_key = key(9);
        let public = signer.verifying_key().to_sec1_point(false);

        let (_temp, store) = open_test_store("digest");
        let intent = store
            .issue_at(b"right", Duration::from_secs(30), 2_000)
            .unwrap();
        assert!(matches!(
            store.accept_fresh_install_at(
                &proof(&intent, &signer),
                b"wrong",
                CONFIG,
                public.as_bytes(),
                2_001,
            ),
            Err(PresenceError::DigestMismatch)
        ));

        let (_temp, store) = open_test_store("key");
        let intent = store
            .issue_at(b"state", Duration::from_secs(30), 2_000)
            .unwrap();
        assert!(matches!(
            store.accept_fresh_install_at(
                &proof(&intent, &signer),
                b"state",
                CONFIG,
                wrong_key.verifying_key().to_sec1_point(false).as_bytes(),
                2_001,
            ),
            Err(PresenceError::InvalidSignature)
        ));

        let (_temp, store) = open_test_store("operation");
        let intent = store
            .issue_at(b"state", Duration::from_secs(30), 2_000)
            .unwrap();
        let mut wire: ProofWire = serde_json::from_slice(&proof(&intent, &signer)).unwrap();
        wire.intent.operation = "wrong".into();
        assert!(matches!(
            store.accept_fresh_install_at(
                &serde_jcs::to_vec(&wire).unwrap(),
                b"state",
                CONFIG,
                public.as_bytes(),
                2_001,
            ),
            Err(PresenceError::UnexpectedOperation)
        ));

        let (_temp, store) = open_test_store("nonce-mismatch");
        let intent = store
            .issue_at(b"state", Duration::from_secs(30), 2_000)
            .unwrap();
        let mut wire: ProofWire = serde_json::from_slice(&proof(&intent, &signer)).unwrap();
        wire.intent.nonce = "ab".repeat(NONCE_BYTES);
        assert!(matches!(
            store.accept_fresh_install_at(
                &serde_jcs::to_vec(&wire).unwrap(),
                b"state",
                CONFIG,
                public.as_bytes(),
                2_001,
            ),
            Err(PresenceError::UnknownNonce)
        ));

        for (name, now, expected_future) in [("expired", 2_030, false), ("future", 1_999, true)] {
            let (_temp, store) = open_test_store(name);
            let intent = store
                .issue_at(b"state", Duration::from_secs(30), 2_000)
                .unwrap();
            let result = store.accept_fresh_install_at(
                &proof(&intent, &signer),
                b"state",
                CONFIG,
                public.as_bytes(),
                now,
            );
            assert!(if expected_future {
                matches!(result, Err(PresenceError::FutureProof))
            } else {
                matches!(result, Err(PresenceError::ExpiredProof))
            });
        }
    }

    #[test]
    fn rejects_malformed_noncanonical_and_unknown_fields() {
        let (_temp, store) = open_test_store("parse");
        let public = key(10).verifying_key().to_sec1_point(false);
        assert!(matches!(
            store.accept_fresh_install_at(b"{", b"state", CONFIG, public.as_bytes(), 1),
            Err(PresenceError::MalformedProof)
        ));
        let intent = store
            .issue_at(b"unknown", Duration::from_secs(30), 1)
            .unwrap();
        let unknown_proof = proof(&intent, &key(10));
        let mut unknown: serde_json::Value = serde_json::from_slice(&unknown_proof).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(matches!(
            store.accept_fresh_install_at(
                &serde_jcs::to_vec(&unknown).unwrap(),
                b"unknown",
                CONFIG,
                public.as_bytes(),
                2,
            ),
            Err(PresenceError::MalformedProof)
        ));

        let intent = store
            .issue_at(b"state", Duration::from_secs(30), 1)
            .unwrap();
        let mut noncanonical = proof(&intent, &key(10));
        noncanonical.push(b'\n');
        assert!(matches!(
            store.accept_fresh_install_at(&noncanonical, b"state", CONFIG, public.as_bytes(), 2),
            Err(PresenceError::NonCanonicalEncoding)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_store_root() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        symlink(target, &link).unwrap();
        assert!(matches!(
            NonceStore::open(link),
            Err(PresenceError::InsecureStore)
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_signing_is_explicitly_unsupported() {
        let (_temp, store) = open_test_store("unsupported");
        let intent = store
            .issue_at(b"state", Duration::from_secs(30), unix_now().unwrap())
            .unwrap();
        let key = key(11);
        assert!(matches!(
            sign_installation_intent(&intent, key.verifying_key().to_sec1_point(false).as_bytes(),),
            Err(PresenceError::UnsupportedPlatform)
        ));
    }
}
