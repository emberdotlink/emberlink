//! Founder-authorized staged authority installation.
//!
//! Installation publishes a dormant, credential-free state. Credential
//! enrollment and custody are separate authority transitions.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    daemon::ACTIVATION_MARKER_FILE,
    identity::{self, reviewed_executable_fingerprint},
    installed_state::{
        ACTIVATION_MARKER_SCHEMA, ActivationMarkerWire, AuthorityStateWire, DAEMON_CONFIG_SCHEMA,
        DaemonConfigWire, DaemonCustodyWire, INSTALLED_AUTHORITY_STATE_SCHEMA,
        INSTALLED_STATE_ACTIVATION, InstalledAuthorityWire, InstalledStateError,
        OperationalEvidenceWire, SocketWire, StorageWire, TrustRootWire, decode_install_request,
        validate_launch_policy_shape, validate_personas,
    },
    pack::{SignedProviderPack, github_pack_v2},
    presence::{IssuedInstallationIntent, MAX_INTENT_LIFETIME, NonceStore, PresencePolicy},
    same_file_version, sha256_hex,
};

pub use crate::installed_state::{
    FounderKeyInput, FounderPolicyInput, INSTALL_REQUEST_SCHEMA, INSTALL_RESULT_SCHEMA,
    InstallRequest, InstallResult, LaunchPolicyWire, LauncherIdentityWire, PersonaWire,
    ReviewedExecutableWire, ReviewedExecutablesWire, SessionExecutableIdentityWire,
};

const PACK_PUBLISHER: &str = "ember.authority.founder";
const PACK_KEY_ID: &str = "founder-provider-pack-v2";
const REQUEST_MAX_BYTES: u64 = 1024 * 1024;
const INSTALL_LOCK_FILE: &str = ".authority-install.lock";

impl From<FounderPolicyInput> for PresencePolicy {
    fn from(value: FounderPolicyInput) -> Self {
        match value {
            FounderPolicyInput::UserPresence => Self::UserPresence,
            FounderPolicyInput::BiometryCurrentSet => Self::BiometryCurrentSet,
        }
    }
}

#[derive(Clone, Debug)]
struct InstallPaths {
    root: PathBuf,
    daemon_config: PathBuf,
    state: PathBuf,
    proof: PathBuf,
    founder_key: PathBuf,
    signed_pack: PathBuf,
    marker: PathBuf,
    nonce_store: PathBuf,
    recovery_key: PathBuf,
    operational_evidence_key: PathBuf,
    audit_payload_seal_key: PathBuf,
    artifact_root: PathBuf,
    audit_root: PathBuf,
    audit_high_water: PathBuf,
    recovery_root: PathBuf,
}

impl InstallPaths {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            daemon_config: root.join("emberd.json"),
            state: root.join("installed-authority-state.json"),
            proof: root.join("installed-authority-proof.json"),
            founder_key: root.join("founder-presence-public-key"),
            signed_pack: root.join("github-provider-pack-v2.json"),
            marker: root.join(ACTIVATION_MARKER_FILE),
            nonce_store: root.join("presence-nonces"),
            recovery_key: root.join("recovery-key"),
            operational_evidence_key: root.join("operational-evidence-ed25519-key"),
            audit_payload_seal_key: root.join("audit-payload-seal-key"),
            artifact_root: root.join("artifacts"),
            audit_root: root.join("audit"),
            audit_high_water: root.join("audit-high-water.json"),
            recovery_root: root.join("recovery"),
        }
    }

    fn outputs(&self) -> [&Path; 8] {
        [
            &self.daemon_config,
            &self.state,
            &self.proof,
            &self.founder_key,
            &self.signed_pack,
            &self.recovery_key,
            &self.operational_evidence_key,
            &self.audit_payload_seal_key,
        ]
    }
}

struct PreparedInstall {
    paths: InstallPaths,
    config_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    pack_bytes: Vec<u8>,
    recovery_key: [u8; 32],
    operational_evidence_key: [u8; 32],
    audit_payload_seal_key: [u8; 32],
    client_gid: u32,
    config_sha256: String,
    state_sha256: String,
}

impl Drop for PreparedInstall {
    fn drop(&mut self) {
        self.recovery_key.zeroize();
        self.operational_evidence_key.zeroize();
        self.audit_payload_seal_key.zeroize();
    }
}

struct InstallLock {
    _file: File,
}

impl InstallLock {
    fn acquire(root: &Path, owner_uid: u32) -> Result<Self, InstallError> {
        let path = root.join(INSTALL_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(InstallError::InsecurePath(path));
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(InstallError::InstallInProgress);
            }
            Err(fs::TryLockError::Error(error)) => return Err(InstallError::Io(error)),
        }
        Ok(Self { _file: file })
    }
}

/// Reads and validates the owner-private strict-JCS installation request.
pub fn read_install_request(path: impl AsRef<Path>) -> Result<InstallRequest, InstallError> {
    let request_path = path.as_ref();
    let owner_uid = secure_file_owner(request_path)?;
    let request_bytes = read_bounded_request(request_path, owner_uid)?;
    let request = match decode_install_request(&request_bytes) {
        Ok(request) => request,
        Err(InstalledStateError::NonCanonical) => {
            return Err(InstallError::NonCanonicalRequest);
        }
        Err(error) => return Err(error.into()),
    };
    if request.daemon_uid != owner_uid {
        return Err(InstallError::WrongOwner);
    }
    Ok(request)
}

/// Daemon-retained files and nonce intent awaiting a CLI-produced founder
/// presence proof. The installed state remains dormant and carries no
/// Credential or custody source.
pub struct PendingFounderInstall {
    prepared: PreparedInstall,
    owner_uid: u32,
    _install_lock: InstallLock,
    nonce_store: NonceStore,
    intent: IssuedInstallationIntent,
    founder_public_key: [u8; 65],
}

impl PendingFounderInstall {
    pub fn intent(&self) -> &IssuedInstallationIntent {
        &self.intent
    }

    pub fn accept_founder_proof(self, proof: &[u8]) -> Result<InstallResult, InstallError> {
        self.nonce_store.accept_fresh_install(
            proof,
            &self.prepared.state_bytes,
            &self.prepared.config_bytes,
            &self.founder_public_key,
        )?;
        publish(
            &self.prepared,
            proof,
            &self.founder_public_key,
            self.owner_uid,
        )?;
        Ok(InstallResult {
            schema: INSTALL_RESULT_SCHEMA.to_owned(),
            state_directory: self.prepared.paths.root.clone(),
            daemon_config_path: self.prepared.paths.daemon_config.clone(),
            installed_state_path: self.prepared.paths.state.clone(),
            installation_proof_path: self.prepared.paths.proof.clone(),
            founder_public_key_path: self.prepared.paths.founder_key.clone(),
            signed_pack_path: self.prepared.paths.signed_pack.clone(),
            activation_marker_path: self.prepared.paths.marker.clone(),
            daemon_config_sha256: self.prepared.config_sha256.clone(),
            installed_state_sha256: self.prepared.state_sha256.clone(),
        })
    }
}

/// Prepares a founder-authorized dormant installation. Credential enrollment is
/// an independent catalog transition and is never sourced from installed state.
pub fn daemon_prepare_dormant_install(
    request: InstallRequest,
    founder_public_key: [u8; 65],
) -> Result<PendingFounderInstall, InstallError> {
    let daemon_uid = crate::effective_uid();
    validate_daemon_install_request(&request, daemon_uid)?;
    let install_lock = InstallLock::acquire(&request.state_directory, daemon_uid)?;
    reject_active_install(&InstallPaths::new(&request.state_directory), daemon_uid)?;
    let prepared = prepare(&request, daemon_uid)?;
    let nonce_store = NonceStore::open(&prepared.paths.nonce_store)?;
    let intent =
        nonce_store.issue_installation_intent(&prepared.state_bytes, MAX_INTENT_LIFETIME)?;
    Ok(PendingFounderInstall {
        prepared,
        owner_uid: daemon_uid,
        _install_lock: install_lock,
        nonce_store,
        intent,
        founder_public_key,
    })
}

/// Validates every daemon-owned request invariant before the install transport
/// exposes a founder-presence ceremony.
pub(crate) fn validate_daemon_install_request(
    request: &InstallRequest,
    daemon_uid: u32,
) -> Result<(), InstallError> {
    let expected_state_directory = crate::authority_state_directory(daemon_uid)?;
    require_canonical_state_directory(request, &expected_state_directory)?;
    let owner_uid = secure_directory_owner(&request.state_directory)?;
    if owner_uid != daemon_uid {
        return Err(InstallError::WrongOwner);
    }
    validate_request(request, owner_uid)
}

fn require_canonical_state_directory(
    request: &InstallRequest,
    expected: &Path,
) -> Result<(), InstallError> {
    if request.state_directory != expected {
        return Err(InstallError::NonCanonicalStateDirectory {
            expected: expected.to_owned(),
            actual: request.state_directory.clone(),
        });
    }
    Ok(())
}

fn validate_request(request: &InstallRequest, owner_uid: u32) -> Result<(), InstallError> {
    if request.schema != INSTALL_REQUEST_SCHEMA
        || request.daemon_uid != owner_uid
        || request.daemon_uid == 0
        || request
            .launch_policy
            .launchers
            .iter()
            .any(|launcher| launcher.uid == request.daemon_uid)
        || request
            .launch_policy
            .session_executables
            .iter()
            .any(|session| session.uid == request.daemon_uid)
        || request.launch_policy.session_executables.is_empty()
    {
        return Err(InstallError::InvalidRequest);
    }
    validate_clean_absolute(&request.state_directory)?;
    if request.state_directory.canonicalize()? != request.state_directory {
        return Err(InstallError::PathTraversal(request.state_directory.clone()));
    }
    validate_process_owner(&request.state_directory, owner_uid)?;
    let paths = InstallPaths::new(&request.state_directory);
    reject_active_install(&paths, owner_uid)?;
    for path in paths.outputs() {
        reject_insecure_existing(path, owner_uid)?;
    }

    validate_personas(&request.personas)?;
    let persona_ids: BTreeSet<_> = request
        .personas
        .iter()
        .map(|persona| persona.persona_id.as_str())
        .collect();
    validate_launch_policy_shape(&request.launch_policy, Some(&persona_ids))?;
    if request.personas.iter().any(|persona| {
        !request
            .launch_policy
            .session_executables
            .iter()
            .any(|session| session.persona_id == persona.persona_id)
    }) {
        return Err(InstallError::InvalidRequest);
    }

    validate_reviewed_executable_uniqueness(request)?;

    content_executable_wire(&request.reviewed_executables.git, owner_uid)?;
    content_executable_wire(&request.reviewed_executables.askpass, owner_uid)?;
    for launcher in &request.launch_policy.launchers {
        identity_executable_wire(&launcher.executable, owner_uid)?;
    }
    for session in &request.launch_policy.session_executables {
        identity_executable_wire(&session.executable, owner_uid)?;
    }
    if let FounderKeyInput::Lookup { public_key_path } = &request.founder_key {
        validate_clean_absolute(public_key_path)?;
        if public_key_path.starts_with(&request.state_directory)
            || public_key_path.canonicalize()? != *public_key_path
        {
            return Err(InstallError::InvalidFounderPublicKey);
        }
    }
    Ok(())
}

fn validate_reviewed_executable_uniqueness(request: &InstallRequest) -> Result<(), InstallError> {
    let mut paths = BTreeSet::new();
    for executable in [
        &request.reviewed_executables.git,
        &request.reviewed_executables.askpass,
    ] {
        if !paths.insert(executable.path.as_path()) {
            return Err(InstallError::DuplicateIdentity);
        }
    }
    for launcher in &request.launch_policy.launchers {
        if !paths.insert(launcher.executable.path.as_path()) {
            return Err(InstallError::DuplicateIdentity);
        }
    }
    for session in &request.launch_policy.session_executables {
        if !paths.insert(session.executable.path.as_path()) {
            return Err(InstallError::DuplicateIdentity);
        }
    }
    Ok(())
}

fn prepare(request: &InstallRequest, owner_uid: u32) -> Result<PreparedInstall, InstallError> {
    let paths = InstallPaths::new(&request.state_directory);
    for directory in [
        &paths.artifact_root,
        &paths.audit_root,
        &paths.recovery_root,
        &paths.nonce_store,
    ] {
        ensure_private_directory(directory, owner_uid)?;
    }
    let git = content_executable_wire(&request.reviewed_executables.git, owner_uid)?;
    let askpass = content_executable_wire(&request.reviewed_executables.askpass, owner_uid)?;
    let launch_policy = crate::installed_state::LaunchPolicyWire {
        client_gid: request.launch_policy.client_gid,
        launchers: request
            .launch_policy
            .launchers
            .iter()
            .map(|launcher| {
                Ok(crate::installed_state::LauncherIdentityWire {
                    uid: launcher.uid,
                    gid: launcher.gid,
                    executable: identity_executable_wire(&launcher.executable, owner_uid)?,
                })
            })
            .collect::<Result<_, InstallError>>()?,
        session_executables: request
            .launch_policy
            .session_executables
            .iter()
            .map(|session| {
                Ok(crate::installed_state::SessionExecutableIdentityWire {
                    persona_id: session.persona_id.clone(),
                    uid: session.uid,
                    gid: session.gid,
                    executable: identity_executable_wire(&session.executable, owner_uid)?,
                })
            })
            .collect::<Result<_, InstallError>>()?,
    };

    let pack_signer = SigningKey::generate(&mut OsRng);
    let signed_pack =
        SignedProviderPack::sign(github_pack_v2(PACK_PUBLISHER), PACK_KEY_ID, &pack_signer)?;
    let pack_bytes = serde_jcs::to_vec(&signed_pack)?;
    let operational_signer = SigningKey::generate(&mut OsRng);
    let operational_evidence_key = operational_signer.to_bytes();
    let mut audit_payload_seal_key = [0_u8; 32];
    OsRng.fill_bytes(&mut audit_payload_seal_key);
    let operational_generation_id = random_nonzero_32();
    let operational_vault_id = random_nonzero_32();
    let operational_device_id = random_nonzero_32();
    // Provider-pack trust is installation-scoped. Per-operation authority
    // lifetime is enforced by fresh Grant/Delegation admission, not by
    // stretching an installed Grant bundle into a trust-root lifetime.
    let trust_not_before = 0;
    let trust_not_after = i64::MAX;
    let config = DaemonConfigWire {
        schema: DAEMON_CONFIG_SCHEMA.to_owned(),
        daemon_uid: request.daemon_uid,
        socket: SocketWire {
            path: paths.root.join("emberd.sock"),
            mode: 0o660,
            max_header_bytes: 1024 * 1024,
            max_artifact_bytes: 512 * 1024 * 1024,
            io_timeout_seconds: 30,
        },
        storage: StorageWire {
            artifact_root: paths.artifact_root.clone(),
            audit_root: paths.audit_root.clone(),
            recovery_root: paths.recovery_root.clone(),
            audit_high_water_path: paths.audit_high_water.clone(),
        },
        custody: DaemonCustodyWire {
            recovery_key_path: paths.recovery_key.clone(),
        },
        operational_evidence: OperationalEvidenceWire {
            private_key_path: paths.operational_evidence_key.clone(),
            payload_seal_key_path: paths.audit_payload_seal_key.clone(),
            generation_id_hex: hex::encode(operational_generation_id),
            public_key_hex: hex::encode(operational_signer.verifying_key().to_bytes()),
            vault_id_hex: hex::encode(operational_vault_id),
            device_id_hex: hex::encode(operational_device_id),
        },
        trust_roots: vec![TrustRootWire {
            key_id: PACK_KEY_ID.to_owned(),
            publisher: PACK_PUBLISHER.to_owned(),
            verifying_key_hex: hex::encode(pack_signer.verifying_key().to_bytes()),
            not_before_unix: trust_not_before,
            not_after_unix: trust_not_after,
            revoked: false,
        }],
        signed_pack_paths: vec![paths.signed_pack.clone()],
        reviewed_executables: ReviewedExecutablesWire { git, askpass },
        launch_policy,
        installed_authority: InstalledAuthorityWire {
            state_path: paths.state.clone(),
            proof_path: paths.proof.clone(),
            enrolled_public_key_path: paths.founder_key.clone(),
            nonce_store_root: paths.nonce_store.clone(),
        },
    };
    config.validate()?;
    // These bytes, not a later reserialization, are the installed configuration.
    let config_bytes = serde_jcs::to_vec(&config)?;
    let config_sha256 = sha256_hex(&config_bytes);
    let state = AuthorityStateWire {
        schema: INSTALLED_AUTHORITY_STATE_SCHEMA.to_owned(),
        activation: INSTALLED_STATE_ACTIVATION.to_owned(),
        daemon_config_sha256: config_sha256.clone(),
        personas: request.personas.clone(),
    };
    state.validate()?;
    let state_bytes = serde_jcs::to_vec(&state)?;
    let state_sha256 = sha256_hex(&state_bytes);
    let mut recovery_key = [0_u8; 32];
    OsRng.fill_bytes(&mut recovery_key);
    Ok(PreparedInstall {
        paths,
        config_bytes,
        state_bytes,
        pack_bytes,
        client_gid: request.launch_policy.client_gid,
        operational_evidence_key,
        audit_payload_seal_key,
        recovery_key,
        config_sha256,
        state_sha256,
    })
}

fn random_nonzero_32() -> [u8; 32] {
    loop {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if bytes != [0_u8; 32] {
            return bytes;
        }
    }
}

fn publish(
    prepared: &PreparedInstall,
    proof: &[u8],
    public_key: &[u8; 65],
    owner_uid: u32,
) -> Result<(), InstallError> {
    let mut rollback = UnactivatedPublication::new(prepared, owner_uid);
    let result = (|| {
        // Installed state is intentionally dormant until a catalog transition
        // and its AuthorityReceipt commit together in the EvidenceJournal.
        atomic_replace(&prepared.paths.signed_pack, &prepared.pack_bytes, owner_uid)?;
        atomic_replace(
            &prepared.paths.recovery_key,
            &prepared.recovery_key,
            owner_uid,
        )?;
        atomic_replace(
            &prepared.paths.operational_evidence_key,
            &prepared.operational_evidence_key,
            owner_uid,
        )?;
        atomic_replace(
            &prepared.paths.audit_payload_seal_key,
            &prepared.audit_payload_seal_key,
            owner_uid,
        )?;
        atomic_replace(&prepared.paths.founder_key, public_key, owner_uid)?;
        atomic_replace(&prepared.paths.proof, proof, owner_uid)?;
        atomic_replace(&prepared.paths.state, &prepared.state_bytes, owner_uid)?;
        atomic_replace(
            &prepared.paths.daemon_config,
            &prepared.config_bytes,
            owner_uid,
        )?;
        identity::set_socket_owner(&prepared.paths.root, owner_uid, prepared.client_gid)?;
        fs::set_permissions(&prepared.paths.root, fs::Permissions::from_mode(0o710))?;
        sync_directory(&prepared.paths.root)?;
        let marker = serde_jcs::to_vec(&ActivationMarkerWire {
            schema: ACTIVATION_MARKER_SCHEMA.to_owned(),
            daemon_config_sha256: prepared.config_sha256.clone(),
            installed_state_sha256: prepared.state_sha256.clone(),
        })?;
        // Commit point: the marker becomes visible only after every referenced
        // byte, directory entry, and key has reached durable storage.
        atomic_create(&prepared.paths.marker, &marker)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            rollback.disarm();
            Ok(())
        }
        Err(error) => {
            rollback.rollback()?;
            Err(error)
        }
    }
}

struct UnactivatedPublication<'a> {
    prepared: &'a PreparedInstall,
    owner_uid: u32,
    armed: bool,
}

impl<'a> UnactivatedPublication<'a> {
    fn new(prepared: &'a PreparedInstall, owner_uid: u32) -> Self {
        Self {
            prepared,
            owner_uid,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn rollback(&mut self) -> Result<(), InstallError> {
        let root_result = match fs::symlink_metadata(&self.prepared.paths.root) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == self.owner_uid =>
            {
                fs::set_permissions(&self.prepared.paths.root, fs::Permissions::from_mode(0o700))
                    .map_err(InstallError::from)
            }
            Ok(_) => Err(InstallError::InsecurePath(self.prepared.paths.root.clone())),
            Err(error) => Err(error.into()),
        };
        let sync_result = sync_directory(&self.prepared.paths.root).map_err(InstallError::from);
        if root_result.is_ok() && sync_result.is_ok() {
            self.armed = false;
        }
        root_result?;
        sync_result
    }
}

impl Drop for UnactivatedPublication<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.rollback();
        }
    }
}

fn reject_active_install(paths: &InstallPaths, owner_uid: u32) -> Result<(), InstallError> {
    match fs::symlink_metadata(&paths.marker) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o077 != 0
            {
                Err(InstallError::InsecurePath(paths.marker.clone()))
            } else {
                Err(InstallError::AlreadyActive)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_clean_absolute(path: &Path) -> Result<(), InstallError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(InstallError::PathTraversal(path.to_owned()));
    }
    Ok(())
}

fn secure_directory_owner(path: &Path) -> Result<u32, InstallError> {
    validate_clean_absolute(path)?;
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || !matches!(mode, 0o700 | 0o710)
    {
        return Err(InstallError::InsecurePath(path.to_owned()));
    }
    Ok(metadata.uid())
}

fn secure_file_owner(path: &Path) -> Result<u32, InstallError> {
    validate_clean_absolute(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
    {
        return Err(InstallError::InsecurePath(path.to_owned()));
    }
    let owner = metadata.uid();
    validate_private_parent(path, owner)?;
    Ok(owner)
}

fn validate_private_parent(path: &Path, owner_uid: u32) -> Result<(), InstallError> {
    let parent = path
        .parent()
        .ok_or_else(|| InstallError::PathTraversal(path.to_owned()))?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(InstallError::InsecurePath(parent.to_owned()));
    }
    Ok(())
}

fn validate_process_owner(directory: &Path, owner_uid: u32) -> Result<(), InstallError> {
    let probe = tempfile::Builder::new()
        .prefix(".ember-owner-check-")
        .tempfile_in(directory)?;
    if probe.as_file().metadata()?.uid() != owner_uid {
        return Err(InstallError::WrongOwner);
    }
    Ok(())
}

fn validate_reviewed_executable(path: &Path, owner_uid: u32) -> Result<(), InstallError> {
    validate_clean_absolute(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || (metadata.uid() != 0 && metadata.uid() != owner_uid)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || path.canonicalize()? != path
    {
        return Err(InstallError::InsecurePath(path.to_owned()));
    }
    Ok(())
}

fn require_same_executable_version(
    path: &Path,
    before: &fs::Metadata,
    after: &fs::Metadata,
) -> Result<(), InstallError> {
    if !same_file_version(before, after) {
        return Err(InstallError::ExecutableChanged(path.to_owned()));
    }
    Ok(())
}

fn identity_executable_wire(
    reviewed: &ReviewedExecutableWire,
    owner_uid: u32,
) -> Result<ReviewedExecutableWire, InstallError> {
    validate_reviewed_executable(&reviewed.path, owner_uid)?;
    let before = fs::symlink_metadata(&reviewed.path)?;
    let digest = reviewed_executable_fingerprint(&reviewed.path)?;
    let after = fs::symlink_metadata(&reviewed.path)?;
    require_same_executable_version(&reviewed.path, &before, &after)?;
    if hex::encode(digest) != reviewed.digest_sha256 {
        return Err(InstallError::ExecutableFingerprintMismatch(
            reviewed.path.clone(),
        ));
    }
    Ok(reviewed.clone())
}

fn content_executable_wire(
    reviewed: &ReviewedExecutableWire,
    owner_uid: u32,
) -> Result<ReviewedExecutableWire, InstallError> {
    validate_reviewed_executable(&reviewed.path, owner_uid)?;
    let before = fs::symlink_metadata(&reviewed.path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&reviewed.path)?;
    let opened = file.metadata()?;
    require_same_executable_version(&reviewed.path, &before, &opened)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    require_same_executable_version(&reviewed.path, &opened, &after)?;
    if hex::encode(digest.finalize()) != reviewed.digest_sha256 {
        return Err(InstallError::ExecutableFingerprintMismatch(
            reviewed.path.clone(),
        ));
    }
    Ok(reviewed.clone())
}

fn ensure_private_directory(path: &Path, owner_uid: u32) -> Result<(), InstallError> {
    validate_clean_absolute(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o077 != 0
            {
                return Err(InstallError::InsecurePath(path.to_owned()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
            sync_directory(
                path.parent()
                    .ok_or_else(|| InstallError::PathTraversal(path.to_owned()))?,
            )?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(InstallError::InsecurePath(path.to_owned()));
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn reject_insecure_existing(path: &Path, owner_uid: u32) -> Result<(), InstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o077 != 0
            {
                return Err(InstallError::InsecurePath(path.to_owned()));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_request(path: &Path, owner_uid: u32) -> Result<Vec<u8>, InstallError> {
    read_owner_private_file(path, owner_uid, REQUEST_MAX_BYTES, || {
        InstallError::RequestTooLarge
    })
}

fn read_owner_private_file(
    path: &Path,
    owner_uid: u32,
    max_bytes: u64,
    too_large: fn() -> InstallError,
) -> Result<Vec<u8>, InstallError> {
    if secure_file_owner(path)? != owner_uid {
        return Err(InstallError::WrongOwner);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let initial_capacity =
        usize::try_from(metadata.len().min(max_bytes)).map_err(|_| too_large())?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(too_large());
    }
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8], owner_uid: u32) -> Result<(), InstallError> {
    reject_insecure_existing(path, owner_uid)?;
    let parent = path
        .parent()
        .ok_or_else(|| InstallError::PathTraversal(path.to_owned()))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".ember-install-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let parent = path
        .parent()
        .ok_or_else(|| InstallError::PathTraversal(path.to_owned()))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".ember-activation-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    if let Err(error) = temporary.persist_noclobber(path) {
        return if error.error.kind() == io::ErrorKind::AlreadyExists {
            Err(InstallError::AlreadyActive)
        } else {
            Err(error.error.into())
        };
    }
    if let Err(error) = sync_directory(parent) {
        fs::remove_file(path)?;
        sync_directory(parent)?;
        return Err(error.into());
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("installation request is invalid")]
    InvalidRequest,
    #[error("installation request is not strict RFC 8785 JSON")]
    NonCanonicalRequest,
    #[error("an active authority installation already exists")]
    AlreadyActive,
    #[error("another authority installation is already in progress")]
    InstallInProgress,
    #[error("request owner does not match the daemon state owner")]
    WrongOwner,
    #[error("state directory must be {expected}, not {actual}")]
    NonCanonicalStateDirectory { expected: PathBuf, actual: PathBuf },
    #[error("path is not clean and absolute: {0}")]
    PathTraversal(PathBuf),
    #[error("path is symlinked, wrong-owner, wrong-type, or not private: {0}")]
    InsecurePath(PathBuf),
    #[error("Grant action, provider, resource, destination, or permissions are invalid")]
    AuthorityScopeMismatch,
    #[error("duplicate Persona, Grant, or launch-policy identity")]
    DuplicateIdentity,
    #[error("founder public key input is invalid")]
    InvalidFounderPublicKey,
    #[error("a reviewed executable changed while it was hashed: {0}")]
    ExecutableChanged(PathBuf),
    #[error("reviewed executable fingerprint does not match measured identity: {0}")]
    ExecutableFingerprintMismatch(PathBuf),
    #[error("installation request exceeds one MiB")]
    RequestTooLarge,
    #[error("filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("JSON encoding is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("provider pack is invalid: {0}")]
    Pack(#[from] crate::pack::PackError),
    #[error("founder-presence authorization failed: {0}")]
    Presence(#[from] crate::presence::PresenceError),
}

impl From<InstalledStateError> for InstallError {
    fn from(error: InstalledStateError) -> Self {
        match error {
            InstalledStateError::NonCanonical => Self::NonCanonicalRequest,
            InstalledStateError::Json(error) => Self::Json(error),
            InstalledStateError::WrongSchema | InstalledStateError::InvalidState => {
                Self::InvalidRequest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as _};
    use serde_json::{Value, json};
    use std::time::Duration;
    use uuid::Uuid;

    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        state: PathBuf,
        executables: Vec<PathBuf>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let canonical_root = root.path().canonicalize().unwrap();
            let state = canonical_root.join("state");
            fs::DirBuilder::new().mode(0o700).create(&state).unwrap();

            let mut executables = Vec::new();
            for name in [
                "git",
                "askpass",
                "workbench-launcher",
                "planner-session",
                "builder-session",
                "reconciler-session",
            ] {
                let path = canonical_root.join(name);
                #[cfg(target_os = "macos")]
                fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
                #[cfg(not(target_os = "macos"))]
                fs::write(&path, format!("#!/bin/sh\n# {name}\n")).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
                executables.push(path);
            }
            Self {
                _root: root,
                root: canonical_root,
                state,
                executables,
            }
        }

        fn content_executable(&self, index: usize) -> ReviewedExecutableWire {
            let path = self.executables[index].clone();
            ReviewedExecutableWire {
                digest_sha256: sha256_hex(&fs::read(&path).unwrap()),
                path,
            }
        }

        fn identity_executable(&self, index: usize) -> ReviewedExecutableWire {
            let path = self.executables[index].clone();
            ReviewedExecutableWire {
                digest_sha256: hex::encode(reviewed_executable_fingerprint(&path).unwrap()),
                path,
            }
        }

        fn request(&self) -> InstallRequest {
            let planner = Uuid::from_u128(11).to_string();
            let builder = Uuid::from_u128(12).to_string();
            let reconciler = Uuid::from_u128(13).to_string();
            InstallRequest {
                schema: INSTALL_REQUEST_SCHEMA.to_owned(),
                state_directory: self.state.clone(),
                daemon_uid: fs::symlink_metadata(&self.state).unwrap().uid(),
                personas: vec![
                    PersonaWire {
                        persona_id: planner.clone(),
                        name: "workbench-planner".to_owned(),
                    },
                    PersonaWire {
                        persona_id: builder.clone(),
                        name: "workbench-builder".to_owned(),
                    },
                    PersonaWire {
                        persona_id: reconciler.clone(),
                        name: "workbench-reconciler".to_owned(),
                    },
                ],
                launch_policy: {
                    let founder_uid = fs::symlink_metadata(&self.state)
                        .unwrap()
                        .uid()
                        .checked_add(1)
                        .unwrap();
                    LaunchPolicyWire {
                        client_gid: 20,
                        launchers: vec![LauncherIdentityWire {
                            uid: founder_uid,
                            gid: 20,
                            executable: self.identity_executable(2),
                        }],
                        session_executables: vec![
                            SessionExecutableIdentityWire {
                                persona_id: planner,
                                uid: founder_uid,
                                gid: 20,
                                executable: self.identity_executable(3),
                            },
                            SessionExecutableIdentityWire {
                                persona_id: builder,
                                uid: founder_uid,
                                gid: 20,
                                executable: self.identity_executable(4),
                            },
                            SessionExecutableIdentityWire {
                                persona_id: reconciler,
                                uid: founder_uid,
                                gid: 20,
                                executable: self.identity_executable(5),
                            },
                        ],
                    }
                },
                reviewed_executables: ReviewedExecutablesWire {
                    git: self.content_executable(0),
                    askpass: self.content_executable(1),
                },
                founder_key: FounderKeyInput::Enroll {
                    policy: FounderPolicyInput::UserPresence,
                },
            }
        }
    }

    #[test]
    fn production_installer_rejects_a_noncanonical_state_directory() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let actual = request.state_directory.clone();
        let expected = fixture.root.join("canonical-state");

        assert!(matches!(
            require_canonical_state_directory(&request, &expected),
            Err(InstallError::NonCanonicalStateDirectory {
                expected: required,
                actual: rejected,
            }) if required == expected && rejected == actual
        ));
    }

    #[test]
    fn state_binds_exact_strict_jcs_config_bytes() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let owner = secure_directory_owner(&fixture.state).unwrap();
        validate_request(&request, owner).unwrap();
        let prepared = prepare(&request, owner).unwrap();
        let config: Value = serde_json::from_slice(&prepared.config_bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&config).unwrap(), prepared.config_bytes);
        assert_eq!(config["daemon_uid"], request.daemon_uid);
        let state: Value = serde_json::from_slice(&prepared.state_bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&state).unwrap(), prepared.state_bytes);
        assert_eq!(
            state["daemon_config_sha256"],
            sha256_hex(&prepared.config_bytes)
        );
        assert_eq!(prepared.state_sha256, sha256_hex(&prepared.state_bytes));
        assert!(state.get("github").is_none());
        assert!(state.get("github_private_key_custody").is_none());
        assert_eq!(
            config["custody"],
            json!({
                "recovery_key_path": fixture.state.join("recovery-key"),
            })
        );
        assert_eq!(state["personas"].as_array().unwrap().len(), 3);
        assert!(state.get("grants").is_none());
        assert!(state.get("roles").is_none());
        assert!(state.get("process_bindings").is_none());
        assert!(config["launch_policy"]["launchers"].is_array());
        assert_eq!(
            config["launch_policy"]["session_executables"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn accepted_presence_proof_supersedes_the_previous_proof() {
        let fixture = Fixture::new();
        let store = NonceStore::open(fixture.state.join("presence-records")).unwrap();
        let signing_key = P256SigningKey::from_slice(&[9_u8; 32]).unwrap();
        let public = signing_key.verifying_key().to_sec1_point(false);
        let accept = |state: &[u8], config: &[u8]| {
            let intent = store
                .issue_installation_intent(state, Duration::from_secs(300))
                .unwrap();
            let intent_bytes = intent.canonical_bytes().unwrap();
            let intent_value: Value = serde_json::from_slice(&intent_bytes).unwrap();
            let signature: p256::ecdsa::Signature = signing_key.sign(&intent_bytes);
            let proof = serde_jcs::to_vec(&json!({
                "schema": crate::presence::INSTALLATION_PROOF_SCHEMA,
                "intent": intent_value,
                "signature_der_hex": hex::encode(signature.to_der().as_bytes()),
            }))
            .unwrap();
            store
                .accept_fresh_install(&proof, state, config, public.as_bytes())
                .unwrap();
            proof
        };
        let old_proof = accept(b"old-state", b"old-config");
        let new_proof = accept(b"new-state", b"new-config");
        assert!(
            store
                .verify_accepted_state(&old_proof, b"old-state", b"old-config", public.as_bytes())
                .is_err()
        );
        store
            .verify_accepted_state(&new_proof, b"new-state", b"new-config", public.as_bytes())
            .unwrap();
    }

    #[test]
    fn install_lock_is_exclusive_and_reusable() {
        let fixture = Fixture::new();
        let owner = secure_directory_owner(&fixture.state).unwrap();
        let first = InstallLock::acquire(&fixture.state, owner).unwrap();
        assert!(matches!(
            InstallLock::acquire(&fixture.state, owner),
            Err(InstallError::InstallInProgress)
        ));
        drop(first);
        InstallLock::acquire(&fixture.state, owner).unwrap();
    }

    #[test]
    fn completed_install_is_classified_as_already_active_with_shared_root_mode() {
        let fixture = Fixture::new();
        let marker = fixture.state.join(ACTIVATION_MARKER_FILE);
        fs::write(&marker, b"{}").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o710)).unwrap();

        let owner = secure_directory_owner(&fixture.state).unwrap();
        assert!(matches!(
            validate_request(&fixture.request(), owner),
            Err(InstallError::AlreadyActive)
        ));
    }

    #[test]
    fn failed_publish_after_shared_key_publication_is_retry_safe() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let owner = secure_directory_owner(&fixture.state).unwrap();
        validate_request(&request, owner).unwrap();
        let mut prepared = prepare(&request, owner).unwrap();
        prepared.client_gid = fs::symlink_metadata(&fixture.state).unwrap().gid();
        fs::create_dir(&prepared.paths.recovery_key).unwrap();

        assert!(matches!(
            publish(&prepared, b"proof", &[4_u8; 65], owner),
            Err(InstallError::InsecurePath(path)) if path == prepared.paths.recovery_key
        ));
        assert_eq!(
            fs::symlink_metadata(&fixture.state).unwrap().mode() & 0o7777,
            0o700
        );

        fs::remove_dir(&prepared.paths.recovery_key).unwrap();
        publish(&prepared, b"proof", &[4_u8; 65], owner).unwrap();
        assert!(prepared.paths.marker.is_file());
        assert_eq!(
            fs::symlink_metadata(&fixture.state).unwrap().mode() & 0o7777,
            0o710
        );
    }

    #[test]
    fn rejects_daemon_uid_shared_with_launcher_or_session() {
        let fixture = Fixture::new();
        let owner = secure_directory_owner(&fixture.state).unwrap();

        let mut request = fixture.request();
        request.launch_policy.launchers[0].uid = request.daemon_uid;
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::InvalidRequest)
        ));

        let mut request = fixture.request();
        request.launch_policy.session_executables[0].uid = request.daemon_uid;
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::InvalidRequest)
        ));
    }

    #[test]
    fn rejects_schema_and_filesystem_failures() {
        let fixture = Fixture::new();
        let owner = secure_directory_owner(&fixture.state).unwrap();
        let mut request = fixture.request();
        request.schema = "ember.authority-install-request/v0".to_owned();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::InvalidRequest)
        ));

        let mut request = fixture.request();
        request.state_directory = fixture.state.join("..").join("state");
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::PathTraversal(_))
        ));

        let target = fixture.state.join("target");
        fs::write(&target, b"x").unwrap();
        let symlink = fixture.state.join("emberd.json");
        std::os::unix::fs::symlink(&target, &symlink).unwrap();
        assert!(matches!(
            validate_request(&fixture.request(), owner),
            Err(InstallError::InsecurePath(path)) if path == symlink
        ));

        let insecure_directory = Fixture::new();
        fs::set_permissions(&insecure_directory.state, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            secure_directory_owner(&insecure_directory.state),
            Err(InstallError::InsecurePath(path)) if path == insecure_directory.state
        ));
    }

    #[test]
    fn founder_key_inside_state_directory_is_refused() {
        let fixture = Fixture::new();
        let owner = secure_directory_owner(&fixture.state).unwrap();
        let mut request = fixture.request();
        request.founder_key = FounderKeyInput::Lookup {
            public_key_path: fixture.state.join("founder-public-key"),
        };

        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::InvalidFounderPublicKey)
        ));
    }

    #[test]
    fn reviewed_executable_paths_are_unique_across_all_categories() {
        let fixture = Fixture::new();
        let owner = secure_directory_owner(&fixture.state).unwrap();

        let mut request = fixture.request();
        request.reviewed_executables.askpass = request.reviewed_executables.git.clone();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::DuplicateIdentity)
        ));

        let mut request = fixture.request();
        request.launch_policy.launchers[0].executable = request.reviewed_executables.git.clone();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::DuplicateIdentity)
        ));

        let mut request = fixture.request();
        request.launch_policy.session_executables[0].executable =
            request.reviewed_executables.askpass.clone();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::DuplicateIdentity)
        ));

        let mut request = fixture.request();
        request.launch_policy.session_executables[0].executable =
            request.launch_policy.launchers[0].executable.clone();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::DuplicateIdentity)
        ));

        let mut request = fixture.request();
        request.launch_policy.session_executables[1].executable =
            request.launch_policy.session_executables[0]
                .executable
                .clone();
        assert!(matches!(
            validate_request(&request, owner),
            Err(InstallError::DuplicateIdentity)
        ));
    }

    #[test]
    fn changed_executable_version_is_refused() {
        let fixture = Fixture::new();
        let path = &fixture.executables[0];
        let before = fs::symlink_metadata(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        let after = fs::symlink_metadata(path).unwrap();

        assert!(matches!(
            require_same_executable_version(path, &before, &after),
            Err(InstallError::ExecutableChanged(rejected)) if rejected == *path
        ));
    }

    #[test]
    fn strict_request_rejects_unknown_fields() {
        let fixture = Fixture::new();
        let request = serde_json::to_value(fixture.request()).unwrap();

        let mut unknown_top_level = request.clone();
        unknown_top_level["unexpected"] = json!(true);
        assert!(serde_json::from_value::<InstallRequest>(unknown_top_level).is_err());

        let mut unknown_executable = request;
        unknown_executable["reviewed_executables"]["unexpected"] = json!("/tmp/unexpected");
        assert!(serde_json::from_value::<InstallRequest>(unknown_executable).is_err());
    }

    #[test]
    fn oversized_request_file_is_refused() {
        let fixture = Fixture::new();
        let request_path = fixture.root.join("oversized-request.json");
        fs::write(&request_path, vec![b'x'; REQUEST_MAX_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o400)).unwrap();
        let owner = fs::symlink_metadata(&request_path).unwrap().uid();

        assert!(matches!(
            read_bounded_request(&request_path, owner),
            Err(InstallError::RequestTooLarge)
        ));
    }

    #[test]
    fn request_file_requires_strict_jcs_and_known_schema() {
        let fixture = Fixture::new();
        let request_path = fixture.root.join("request.json");
        let request_value = serde_json::to_value(fixture.request()).unwrap();
        let mut unknown = request_value.as_object().unwrap().clone();
        unknown.insert("unknown".to_owned(), Value::Bool(true));
        fs::write(&request_path, serde_jcs::to_vec(&unknown).unwrap()).unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            read_install_request(&request_path),
            Err(InstallError::Json(_))
        ));

        let mut v1 = request_value.clone();
        v1["schema"] = json!("ember.authority-install-request/v1");
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&request_path, serde_jcs::to_vec(&v1).unwrap()).unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            read_install_request(&request_path),
            Err(InstallError::InvalidRequest)
        ));

        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &request_path,
            serde_json::to_vec_pretty(&request_value).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            read_install_request(&request_path),
            Err(InstallError::NonCanonicalRequest)
        ));

        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&request_path, b"{").unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            read_install_request(&request_path),
            Err(InstallError::Json(_))
        ));
    }
}
