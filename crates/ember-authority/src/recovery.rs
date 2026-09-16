use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    },
    path::Path,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::model::{
    DelegationId, GrantId, MaterializationId, Need, OperationId, PersonaId, ProcessBindingId,
    ProviderEvidence, ProviderGeneration, ProviderInstanceId, SessionId,
};

const FILE_MAGIC: &[u8; 8] = b"EMBRREC3";
const NONCE_LEN: usize = 24;
const ENTRY_SUFFIX: &str = ".entry";
const MAX_RECOVERY_ENTRY_BYTES: u64 = 2 * 1024 * 1024;

/// Secret text whose allocation is erased when it leaves scope.
///
/// The wrapper deliberately has no `Clone` or `Debug` implementation.
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Non-secret evidence required to close an interrupted accepted operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContext {
    /// Accepted operation whose provider side effect requires recovery.
    pub operation_id: OperationId,
    /// Persona under whose authority the operation was accepted.
    pub persona_id: PersonaId,
    /// Presence-bound session that admitted the operation.
    pub session_id: SessionId,
    /// Exact admitted process binding.
    pub process_binding_id: ProcessBindingId,
    /// Grant authorizing the provider operation.
    pub grant_id: GrantId,
    /// Delegation lineage used by the authority decision.
    pub delegation_path: Vec<DelegationId>,
    /// Canonical provider action name.
    pub action: String,
    /// Validated action input that can be replayed only for recovery evidence.
    pub approved_input: serde_json::Value,
    /// Exact provider requirement selected by the authority decision.
    pub need: Need,
    /// Present only after the adapter returned a credential and the durable
    /// intent was promoted to a non-secret materialization observation.
    pub provider: Option<ProviderEvidence>,
}

/// A durable mint intent or token materialization which has not yet been
/// durably settled.
#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RecoveryEntry {
    Intent {
        context: RecoveryContext,
        materialization_id: MaterializationId,
        provider_instance: ProviderInstanceId,
        generation: ProviderGeneration,
    },
    MaterializedUnknown {
        context: RecoveryContext,
        materialization_id: MaterializationId,
        provider_instance: ProviderInstanceId,
        generation: ProviderGeneration,
        token: SecretString,
    },
}

impl RecoveryEntry {
    pub(crate) fn context(&self) -> &RecoveryContext {
        match self {
            Self::Intent { context, .. } | Self::MaterializedUnknown { context, .. } => context,
        }
    }

    pub(crate) fn materialization_id(&self) -> &MaterializationId {
        match self {
            Self::Intent {
                materialization_id, ..
            }
            | Self::MaterializedUnknown {
                materialization_id, ..
            } => materialization_id,
        }
    }

    pub(crate) fn provider_instance(&self) -> &ProviderInstanceId {
        match self {
            Self::Intent {
                provider_instance, ..
            }
            | Self::MaterializedUnknown {
                provider_instance, ..
            } => provider_instance,
        }
    }

    pub(crate) fn generation(&self) -> &ProviderGeneration {
        match self {
            Self::Intent { generation, .. } | Self::MaterializedUnknown { generation, .. } => {
                generation
            }
        }
    }

    pub(crate) fn token(&self) -> Option<&str> {
        match self {
            Self::Intent { .. } => None,
            Self::MaterializedUnknown { token, .. } => Some(token.expose()),
        }
    }

    pub(crate) fn is_intent(&self) -> bool {
        matches!(self, Self::Intent { .. })
    }
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum BorrowedRecoveryEntry<'a> {
    Intent {
        context: &'a RecoveryContext,
        materialization_id: &'a MaterializationId,
        provider_instance: &'a ProviderInstanceId,
        generation: &'a ProviderGeneration,
    },
    MaterializedUnknown {
        context: &'a RecoveryContext,
        materialization_id: &'a MaterializationId,
        provider_instance: &'a ProviderInstanceId,
        generation: &'a ProviderGeneration,
        token: &'a str,
    },
}

/// Encrypted, crash-durable journal for provider recovery state.
///
/// Mint intents and token materializations survive restart so startup can
/// revoke a returned bearer before clearing the exact provider generation.
/// The validated root descriptor remains pinned for every filesystem action.
pub struct RecoveryJournal {
    #[cfg(test)]
    directory: std::path::PathBuf,
    root: File,
    cipher: XChaCha20Poly1305,
}

impl RecoveryJournal {
    /// Opens or creates a descriptor-pinned owner-private recovery journal.
    pub fn open(directory: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, RecoveryError> {
        let directory = directory.as_ref().to_path_buf();
        if !directory.is_absolute() {
            return Err(RecoveryError::InsecureDirectory);
        }
        let created = match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                validate_private_directory_metadata(&metadata)?;
                false
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)?;
        validate_private_directory(&root)?;
        if created
            && let Some(parent) = directory
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)?.sync_all()?;
        }
        root.sync_all()?;
        let key = Zeroizing::new(key);
        let cipher = XChaCha20Poly1305::new((&*key).into());
        Ok(Self {
            #[cfg(test)]
            directory,
            root,
            cipher,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_test_fixture(
        directory: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<Self, RecoveryError> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = directory.as_ref();
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Self::open(directory, key)
    }

    /// Seals a mint intent before the adapter may be called. The intent alone
    /// is sufficient to quarantine this exact provider generation after a
    /// crash, even though no token is available for revocation.
    pub fn begin_mint(
        &self,
        context: &RecoveryContext,
        provider_instance: &ProviderInstanceId,
        generation: &ProviderGeneration,
    ) -> Result<MaterializationId, RecoveryError> {
        let materialization_id = MaterializationId::new();
        let mut intent_context = context.clone();
        intent_context.provider = None;
        self.write_entry(
            &materialization_id,
            &BorrowedRecoveryEntry::Intent {
                context: &intent_context,
                materialization_id: &materialization_id,
                provider_instance,
                generation,
            },
            false,
        )?;
        Ok(materialization_id)
    }

    /// Atomically promotes a prewritten intent to an encrypted token-bearing
    /// recovery entry before the returned bearer can be used.
    pub fn record_token(
        &self,
        materialization_id: &MaterializationId,
        provider: ProviderEvidence,
        token: &str,
    ) -> Result<(), RecoveryError> {
        let name = entry_name(materialization_id);
        let entry = self.read_entry(&name)?;
        let RecoveryEntry::Intent {
            mut context,
            materialization_id: recorded_id,
            provider_instance,
            generation,
        } = entry
        else {
            return Err(RecoveryError::InvalidTransition);
        };
        if recorded_id != *materialization_id {
            return Err(RecoveryError::MaterializationMismatch);
        }
        context.provider = Some(provider);
        self.write_entry(
            materialization_id,
            &BorrowedRecoveryEntry::MaterializedUnknown {
                context: &context,
                materialization_id,
                provider_instance: &provider_instance,
                generation: &generation,
                token,
            },
            true,
        )
    }

    /// Returns all unresolved entries in stable materialization-id order.
    pub(crate) fn unresolved(&self) -> Result<Vec<RecoveryEntry>, RecoveryError> {
        let mut names = directory_names(&self.root)?;
        names.retain(|name| name.ends_with(ENTRY_SUFFIX));
        names.sort();
        names.iter().map(|name| self.read_entry(name)).collect()
    }

    /// Removes a settled entry and fsyncs its parent directory so it does not
    /// reappear after a successful return and restart.
    pub fn settle(&self, materialization_id: &MaterializationId) -> Result<(), RecoveryError> {
        let name = entry_name(materialization_id);
        match unlinkat_file(self.root.as_raw_fd(), &name) {
            Ok(()) => {
                self.root.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(RecoveryError::UnknownMaterialization)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn write_entry(
        &self,
        materialization_id: &MaterializationId,
        entry: &impl Serialize,
        replace: bool,
    ) -> Result<(), RecoveryError> {
        let plaintext = serde_json::to_vec(entry)?;
        let mut plaintext = Zeroizing::new(plaintext);
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                chacha20poly1305::aead::Payload {
                    msg: plaintext.as_slice(),
                    aad: materialization_id.as_str().as_bytes(),
                },
            )
            .map_err(|_| RecoveryError::Encryption)?;
        plaintext.as_mut_slice().fill(0);

        let (temporary_name, mut temporary) = self.create_temporary(materialization_id)?;
        let destination = entry_name(materialization_id);
        let result = (|| {
            temporary.write_all(FILE_MAGIC)?;
            temporary.write_all(&nonce_bytes)?;
            temporary.write_all(&ciphertext)?;
            temporary.sync_all()?;
            if replace {
                renameat_file(self.root.as_raw_fd(), &temporary_name, &destination)?;
            } else {
                linkat_file(self.root.as_raw_fd(), &temporary_name, &destination)?;
                unlinkat_file(self.root.as_raw_fd(), &temporary_name)?;
            }
            self.root.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat_file(self.root.as_raw_fd(), &temporary_name);
        }
        result.map_err(RecoveryError::Io)
    }

    fn create_temporary(
        &self,
        materialization_id: &MaterializationId,
    ) -> Result<(String, File), RecoveryError> {
        loop {
            let mut random = [0_u8; 16];
            OsRng.fill_bytes(&mut random);
            let name = format!(
                ".{}.{}.tmp",
                materialization_id.as_str(),
                hex::encode(random)
            );
            match openat_file(
                self.root.as_raw_fd(),
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            ) {
                Ok(file) => {
                    if let Err(error) = validate_private_regular_file(&file) {
                        let _ = unlinkat_file(self.root.as_raw_fd(), &name);
                        return Err(error);
                    }
                    return Ok((name, file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read_entry(&self, file_name: &str) -> Result<RecoveryEntry, RecoveryError> {
        let id = file_name
            .strip_suffix(ENTRY_SUFFIX)
            .filter(|value| !value.is_empty())
            .ok_or(RecoveryError::InvalidEntryName)?;
        let file = openat_file(
            self.root.as_raw_fd(),
            file_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )?;
        validate_private_regular_file(&file)?;
        if file.metadata()?.len() > MAX_RECOVERY_ENTRY_BYTES {
            return Err(RecoveryError::EntryTooLarge {
                maximum: MAX_RECOVERY_ENTRY_BYTES,
            });
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_RECOVERY_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECOVERY_ENTRY_BYTES {
            return Err(RecoveryError::EntryTooLarge {
                maximum: MAX_RECOVERY_ENTRY_BYTES,
            });
        }
        if bytes.len() < FILE_MAGIC.len() + NONCE_LEN {
            return Err(RecoveryError::InvalidEnvelope);
        }
        if &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(RecoveryError::InvalidEnvelope);
        }
        let nonce_start = FILE_MAGIC.len();
        let ciphertext_start = nonce_start + NONCE_LEN;
        let plaintext = self
            .cipher
            .decrypt(
                XNonce::from_slice(&bytes[nonce_start..ciphertext_start]),
                chacha20poly1305::aead::Payload {
                    msg: &bytes[ciphertext_start..],
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| RecoveryError::Authentication)?;
        let plaintext = Zeroizing::new(plaintext);
        let entry: RecoveryEntry = serde_json::from_slice(plaintext.as_slice())?;
        if entry.materialization_id().as_str() != id {
            return Err(RecoveryError::MaterializationMismatch);
        }
        Ok(entry)
    }

    #[cfg(test)]
    fn entry_path(&self, materialization_id: &MaterializationId) -> std::path::PathBuf {
        self.directory.join(entry_name(materialization_id))
    }
}

fn entry_name(materialization_id: &MaterializationId) -> String {
    format!("{}{}", materialization_id.as_str(), ENTRY_SUFFIX)
}

fn validate_private_directory_metadata(metadata: &fs::Metadata) -> Result<(), RecoveryError> {
    let euid = crate::effective_uid();
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o700 != 0o700
    {
        return Err(RecoveryError::InsecureDirectory);
    }
    Ok(())
}

fn validate_private_directory(directory: &File) -> Result<(), RecoveryError> {
    validate_private_directory_metadata(&directory.metadata()?)
}

fn validate_private_regular_file(file: &File) -> Result<(), RecoveryError> {
    let euid = crate::effective_uid();
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(RecoveryError::InsecureEntry);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn openat_file(root: RawFd, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: `name` is NUL-terminated and `root` remains an open directory.
    let fd = unsafe { libc::openat(root, name.as_ptr(), flags, mode as libc::c_int) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(unsafe_code)]
fn renameat_file(root: RawFd, from: &str, to: &str) -> io::Result<()> {
    let from = CString::new(from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    let to = CString::new(to)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: names are NUL-terminated and both directory descriptors remain open.
    if unsafe { libc::renameat(root, from.as_ptr(), root, to.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn linkat_file(root: RawFd, from: &str, to: &str) -> io::Result<()> {
    let from = CString::new(from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    let to = CString::new(to)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: names are NUL-terminated and both directory descriptors remain open.
    if unsafe { libc::linkat(root, from.as_ptr(), root, to.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn unlinkat_file(root: RawFd, name: &str) -> io::Result<()> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in filename"))?;
    // SAFETY: `name` is NUL-terminated and `root` remains an open directory.
    if unsafe { libc::unlinkat(root, name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the pointer was returned by `fdopendir` and is owned here.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[allow(unsafe_code)]
fn directory_names(root: &File) -> Result<Vec<String>, RecoveryError> {
    // SAFETY: `root` is a live pinned directory descriptor and `"."` is a
    // static NUL-terminated path. Opening it creates an independent directory
    // stream offset instead of sharing the root descriptor's offset via dup.
    let duplicate = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: `duplicate` is an owned directory descriptor.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: `fdopendir` did not take ownership on failure.
        unsafe {
            libc::close(duplicate);
        }
        return Err(io::Error::last_os_error().into());
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        set_errno(0);
        // SAFETY: the directory stream is valid and exclusively used here.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        // SAFETY: `readdir` returned a live dirent with a NUL-terminated name.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(bytes) {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

#[allow(unsafe_code)]
fn set_errno(value: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe {
        *libc::__error() = value;
    }
    let _ = value;
}

/// Restart classification retains prewritten Unknown intents verbatim. Safe
/// expiry is an observation; callers must journal that settlement before
/// deleting the recovery row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryPhase {
    /// A durable mint was prewritten, but no provider response is known.
    MintIntentUnknown,
    /// A bearer returned and remains potentially live.
    MaterializedUnknown,
    /// The provider's recorded hard expiry has elapsed.
    SafeExpiryReached,
}

/// Non-secret startup view of one unresolved provider intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownIntent {
    /// Operation that initiated provider work.
    pub operation_id: OperationId,
    /// Stable materialization identity prewritten before mint.
    pub materialization_id: MaterializationId,
    /// Exact provider instance that may have acted.
    pub provider_instance: ProviderInstanceId,
    /// Exact provider generation that may have acted.
    pub generation: ProviderGeneration,
    /// Conservative restart classification.
    pub phase: RecoveryPhase,
    /// Recorded provider hard expiry, when a bearer was observed.
    pub safe_expiry_unix: Option<i64>,
}

/// Combined journal-health and unresolved-intent startup gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupRecoveryStatus {
    journal_health: crate::audit::JournalHealth,
    unknown_intents: Vec<UnknownIntent>,
}

impl StartupRecoveryStatus {
    /// Recovers journal health and classifies every durable unresolved intent.
    pub fn inspect(
        journal: &crate::audit::EvidenceJournal,
        recovery: &RecoveryJournal,
        now_unix: i64,
    ) -> Result<Self, RecoveryError> {
        let unknown_intents = recovery
            .unresolved()?
            .into_iter()
            .map(|entry| {
                let context = entry.context();
                let safe_expiry_unix = context
                    .provider
                    .as_ref()
                    .map(|provider| provider.expires_at_unix);
                let phase = match &entry {
                    RecoveryEntry::Intent { .. } => RecoveryPhase::MintIntentUnknown,
                    RecoveryEntry::MaterializedUnknown { .. }
                        if safe_expiry_unix.is_some_and(|expiry| now_unix >= expiry) =>
                    {
                        RecoveryPhase::SafeExpiryReached
                    }
                    RecoveryEntry::MaterializedUnknown { .. } => RecoveryPhase::MaterializedUnknown,
                };
                UnknownIntent {
                    operation_id: context.operation_id.clone(),
                    materialization_id: entry.materialization_id().clone(),
                    provider_instance: entry.provider_instance().clone(),
                    generation: entry.generation().clone(),
                    phase,
                    safe_expiry_unix,
                }
            })
            .collect();
        let journal_health = journal
            .health()
            .map_err(|error| RecoveryError::JournalHealth(error.to_string()))?;
        Ok(Self {
            journal_health,
            unknown_intents,
        })
    }

    /// Returns every unresolved intent in deterministic journal order.
    pub fn unknown_intents(&self) -> &[UnknownIntent] {
        &self.unknown_intents
    }

    /// Reports whether verified evidence reads remain available.
    pub const fn verified_reads_available(&self) -> bool {
        self.journal_health.permits_verified_read()
    }

    /// Reports whether the journal permits new authority decisions.
    pub const fn new_authority_decisions_available(&self) -> bool {
        self.journal_health.permits_new_authority_decision()
    }

    /// Reports whether the journal permits new provider operations globally.
    pub const fn new_provider_operations_available(&self) -> bool {
        self.journal_health.permits_provider_operation()
    }

    /// Reports whether an unresolved intent blocks this exact provider generation.
    pub fn provider_generation_blocked(
        &self,
        provider_instance: &ProviderInstanceId,
        generation: &ProviderGeneration,
    ) -> bool {
        self.unknown_intents.iter().any(|intent| {
            &intent.provider_instance == provider_instance
                && &intent.generation == generation
                && intent.phase != RecoveryPhase::SafeExpiryReached
        })
    }
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("recovery journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("recovery journal root is symlinked, wrong-owner, wrong-type, or unsafe")]
    InsecureDirectory,
    #[error("recovery journal entry is wrong-owner, wrong-type, linked, or unsafe")]
    InsecureEntry,
    #[error("recovery journal entry exceeds the {maximum}-byte limit")]
    EntryTooLarge { maximum: u64 },
    #[error("recovery journal serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("recovery entry encryption failed")]
    Encryption,
    #[error("recovery entry authentication failed")]
    Authentication,
    #[error("recovery entry envelope is invalid")]
    InvalidEnvelope,
    #[error("authority journal health is unavailable: {0}")]
    JournalHealth(String),
    #[error("recovery entry filename is invalid")]
    InvalidEntryName,
    #[error("recovery entry materialization id does not match its filename")]
    MaterializationMismatch,
    #[error("recovery entry is not a sealed mint intent")]
    InvalidTransition,
    #[error("materialization is not unresolved")]
    UnknownMaterialization,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink},
        str::FromStr,
    };

    use tempfile::tempdir;

    use super::*;

    fn context(operation_id: OperationId) -> RecoveryContext {
        let repository =
            crate::model::RepositoryResource::from_str("github:ember/example").unwrap();
        RecoveryContext {
            operation_id,
            persona_id: PersonaId::new(),
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            grant_id: GrantId::new(),
            action: "git.publish-ref/v1".to_owned(),
            delegation_path: vec![DelegationId::new()],
            approved_input: serde_json::json!({"test": true}),
            need: Need {
                provider: "github".to_owned(),
                repository,
                destination_ref: None,
                permissions: BTreeMap::from([(
                    "contents".to_owned(),
                    crate::model::PermissionLevel::Write,
                )]),
            },
            provider: None,
        }
    }

    #[test]
    fn open_rejects_a_symlinked_root() {
        let parent = tempdir().unwrap();
        let target = parent.path().join("target");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        let link = parent.path().join("journal");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            RecoveryJournal::open(&link, [1_u8; 32]),
            Err(RecoveryError::InsecureDirectory)
        ));
    }

    #[test]
    fn open_rejects_an_existing_root_with_unsafe_mode_without_chmod() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            RecoveryJournal::open(directory.path(), [2_u8; 32]),
            Err(RecoveryError::InsecureDirectory)
        ));
        assert_eq!(
            fs::symlink_metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn writes_remain_pinned_to_the_opened_root_descriptor() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("journal");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let journal = RecoveryJournal::open(&root, [3_u8; 32]).unwrap();
        let displaced = parent.path().join("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();

        let materialization = journal
            .begin_mint(
                &context(OperationId::new()),
                &ProviderInstanceId::new(),
                &ProviderGeneration::new(),
            )
            .unwrap();

        assert!(displaced.join(entry_name(&materialization)).is_file());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    fn evidence(
        provider_instance: &ProviderInstanceId,
        generation: &ProviderGeneration,
    ) -> ProviderEvidence {
        ProviderEvidence {
            provider_instance: provider_instance.clone(),
            generation: generation.clone(),
            app_slug: "ember-app".to_owned(),
            app_id: 41,
            installation_id: 73,
            repositories: vec!["ember/example".to_owned()],
            permissions: BTreeMap::from([(
                "contents".to_owned(),
                crate::model::PermissionLevel::Write,
            )]),
            expires_at_unix: 1_300,
        }
    }

    #[test]
    fn sealed_intent_promotes_without_exposing_bearer_material() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [7_u8; 32]).unwrap();
        let provider = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let token = "github-token-that-must-not-appear-on-disk";
        let recovery_context = context(OperationId::new());

        let materialization = journal
            .begin_mint(&recovery_context, &provider, &generation)
            .unwrap();
        let unresolved = journal.unresolved().unwrap();
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].is_intent());
        assert_eq!(unresolved[0].materialization_id(), &materialization);
        assert_eq!(unresolved[0].provider_instance(), &provider);
        assert_eq!(unresolved[0].generation(), &generation);
        assert_eq!(unresolved[0].token(), None);

        journal
            .record_token(&materialization, evidence(&provider, &generation), token)
            .unwrap();
        let stored = fs::read(journal.entry_path(&materialization)).unwrap();
        assert!(
            !stored
                .windows(token.len())
                .any(|window| window == token.as_bytes())
        );
        let unresolved = journal.unresolved().unwrap();
        assert!(!unresolved[0].is_intent());
        assert_eq!(unresolved[0].token(), Some(token));
        assert!(unresolved[0].context().provider.is_some());
        drop(journal);
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [7_u8; 32]).unwrap();
        let unresolved = journal.unresolved().unwrap();
        assert_eq!(unresolved[0].token(), Some(token));

        journal.settle(&materialization).unwrap();
        let reopened = RecoveryJournal::open_test_fixture(directory.path(), [7_u8; 32]).unwrap();
        assert!(reopened.unresolved().unwrap().is_empty());
    }

    #[test]
    fn intent_survives_restart_before_adapter_mint() {
        let directory = tempdir().unwrap();
        let provider = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let materialization = RecoveryJournal::open_test_fixture(directory.path(), [5_u8; 32])
            .unwrap()
            .begin_mint(&context(OperationId::new()), &provider, &generation)
            .unwrap();

        let reopened = RecoveryJournal::open_test_fixture(directory.path(), [5_u8; 32]).unwrap();
        let entries = reopened.unresolved().unwrap();
        assert_eq!(entries[0].materialization_id(), &materialization);
        assert!(entries[0].is_intent());
    }

    #[test]
    fn filename_is_authenticated() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [8_u8; 32]).unwrap();
        let materialization = journal
            .begin_mint(
                &context(OperationId::new()),
                &ProviderInstanceId::new(),
                &ProviderGeneration::new(),
            )
            .unwrap();
        let original = journal.entry_path(&materialization);
        let renamed =
            directory
                .path()
                .join(format!("{}{}", MaterializationId::new(), ENTRY_SUFFIX));
        fs::rename(original, renamed).unwrap();

        assert!(matches!(
            journal.unresolved(),
            Err(RecoveryError::Authentication)
        ));
    }

    #[test]
    fn entry_at_size_limit_is_read_before_authentication_refusal() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [9_u8; 32]).unwrap();
        let materialization = journal
            .begin_mint(
                &context(OperationId::new()),
                &ProviderInstanceId::new(),
                &ProviderGeneration::new(),
            )
            .unwrap();
        let mut at_limit = vec![0_u8; MAX_RECOVERY_ENTRY_BYTES as usize];
        at_limit[..FILE_MAGIC.len()].copy_from_slice(FILE_MAGIC);
        fs::write(journal.entry_path(&materialization), at_limit).unwrap();

        assert!(matches!(
            journal.unresolved(),
            Err(RecoveryError::Authentication)
        ));
    }

    #[test]
    fn oversized_entry_is_refused_with_typed_error() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [10_u8; 32]).unwrap();
        let materialization = journal
            .begin_mint(
                &context(OperationId::new()),
                &ProviderInstanceId::new(),
                &ProviderGeneration::new(),
            )
            .unwrap();
        fs::write(
            journal.entry_path(&materialization),
            vec![0_u8; MAX_RECOVERY_ENTRY_BYTES as usize + 1],
        )
        .unwrap();

        assert!(matches!(
            journal.unresolved(),
            Err(RecoveryError::EntryTooLarge {
                maximum: MAX_RECOVERY_ENTRY_BYTES
            })
        ));
    }
    #[test]
    fn predecessor_journal_schema_has_no_import_path() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [4_u8; 32]).unwrap();
        let materialization = journal
            .begin_mint(
                &context(OperationId::new()),
                &ProviderInstanceId::new(),
                &ProviderGeneration::new(),
            )
            .unwrap();
        let path = journal.entry_path(&materialization);
        let mut bytes = fs::read(&path).unwrap();
        bytes[..8].copy_from_slice(b"EMBRREC2");
        fs::write(path, bytes).unwrap();

        assert!(matches!(
            journal.unresolved(),
            Err(RecoveryError::InvalidEnvelope)
        ));
    }
}
