use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    time::Instant,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    control::ControlRuntime,
    host::{ABSOLUTE_MAX_ARTIFACT_BYTES, ABSOLUTE_MAX_HEADER_BYTES, HostRuntime},
    identity,
    installed_state::{self, DaemonConfigWire},
    presence::NonceStore,
    session_supervisor::SessionSupervisor,
};

#[cfg(target_os = "macos")]
use crate::macos_console_session::{ConsoleSessionActivity, ConsoleSessionMonitor};

pub const ACTIVATION_MARKER_FILE: &str = "authority-active.json";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub struct ConfiguredDaemon {
    runtime: HostRuntime,
    control: ControlRuntime,
    supervisor: SessionSupervisor,
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: SocketIdentity,
    _instance_lock: InstanceLock,
    #[cfg(target_os = "macos")]
    console: ConsoleSessionMonitor,
}

struct InstanceLock {
    _file: File,
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl ConfiguredDaemon {
    pub fn load(
        config_path: impl AsRef<Path>,
        daemon_uid: u32,
        trusted_state_directory: impl AsRef<Path>,
        _now_unix: i64,
    ) -> Result<Self, DaemonError> {
        if daemon_uid == 0 {
            return Err(DaemonError::InvalidDaemonIdentity);
        }
        let root = trusted_state_directory.as_ref();
        validate_runtime_directory(root, daemon_uid, None)?;
        if config_path.as_ref() != root.join("emberd.json") {
            return Err(DaemonError::InvalidConfiguration);
        }

        let config_bytes = read_secure_file(config_path.as_ref(), daemon_uid, MAX_CONFIG_BYTES)?;
        let config = installed_state::decode_daemon_config(&config_bytes)?;
        if config.daemon_uid != daemon_uid
            || config.launch_policy.client_gid != crate::effective_gid()
        {
            return Err(DaemonError::InvalidDaemonIdentity);
        }
        validate_runtime_directory(root, daemon_uid, Some(config.launch_policy.client_gid))?;
        validate_fixed_paths(&config, root)?;
        let _instance_lock = acquire_instance_lock(root, daemon_uid)?;
        if config.socket.max_header_bytes > ABSOLUTE_MAX_HEADER_BYTES
            || config.socket.max_artifact_bytes > ABSOLUTE_MAX_ARTIFACT_BYTES
        {
            return Err(DaemonError::InvalidConfiguration);
        }

        let state_bytes = read_secure_file(
            &config.installed_authority.state_path,
            daemon_uid,
            MAX_CONFIG_BYTES,
        )?;
        let state = installed_state::decode_authority_state(&state_bytes)?;
        if hex::encode(Sha256::digest(&config_bytes)) != state.daemon_config_sha256 {
            return Err(DaemonError::InvalidConfiguration);
        }
        let marker = installed_state::decode_activation_marker(&read_secure_file(
            &root.join(ACTIVATION_MARKER_FILE),
            daemon_uid,
            16 * 1024,
        )?)?;
        if marker.daemon_config_sha256 != state.daemon_config_sha256
            || marker.installed_state_sha256 != hex::encode(Sha256::digest(&state_bytes))
        {
            return Err(DaemonError::InvalidConfiguration);
        }

        let installation_proof = read_secure_file(
            &config.installed_authority.proof_path,
            daemon_uid,
            64 * 1024,
        )?;
        let founder_key = read_secure_file(
            &config.installed_authority.enrolled_public_key_path,
            daemon_uid,
            65,
        )?;
        if founder_key.len() != 65 {
            return Err(DaemonError::InvalidConfiguration);
        }
        NonceStore::open(&config.installed_authority.nonce_store_root)?.verify_accepted_state(
            &installation_proof,
            &state_bytes,
            &config_bytes,
            &founder_key,
        )?;

        // The installed-state schema intentionally carries no Credential or
        // custody path. Until catalog custody is attached by its owning
        // transition, startup remains fail-closed and cannot materialize a
        // provider credential from an obsolete installed-state source.
        Err(DaemonError::DormantCredentialCatalog)
    }

    /// Handles control only on the public listener. Session action frames are
    /// accepted exclusively by SessionSupervisor.
    pub fn serve_once(&mut self) -> Result<(), DaemonError> {
        #[cfg(target_os = "macos")]
        if !matches!(
            self.console.check(),
            Ok(ConsoleSessionActivity::FounderActive)
        ) {
            self.control.relock()?;
        }
        #[cfg(not(target_os = "macos"))]
        self.control.relock()?;

        #[cfg(target_os = "macos")]
        let mut authorize_action = || {
            if matches!(
                self.console.check(),
                Ok(ConsoleSessionActivity::FounderActive)
            ) {
                true
            } else {
                let _ = self.control.relock();
                false
            }
        };
        #[cfg(not(target_os = "macos"))]
        let mut authorize_action = || false;
        self.supervisor
            .tick(&mut self.runtime, &mut authorize_action)?;
        match self.listener.accept() {
            Ok((stream, _)) => {
                let accepted_at = Instant::now();
                stream.set_nonblocking(false)?;
                match identity::peer_identity(&stream) {
                    Ok(peer) => {
                        if let Err(error) = self.control.handle_connection(
                            stream,
                            peer,
                            &mut self.runtime,
                            &mut self.supervisor,
                            accepted_at,
                        ) {
                            if error.is_fatal() {
                                return Err(error.into());
                            }
                            eprintln!("emberd: refused control connection: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("emberd: refused unidentified control peer: {error}");
                    }
                }
            }
            Err(error) if transient_accept_error(&error) => {}
            Err(error) => return Err(error.into()),
        }

        Ok(())
    }
}

fn transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    ) || matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EMFILE || code == libc::ENFILE
    )
}

impl Drop for ConfiguredDaemon {
    fn drop(&mut self) {
        remove_socket_if_owned(&self.socket_path, self.socket_identity);
    }
}

fn validate_fixed_paths(config: &DaemonConfigWire, root: &Path) -> Result<(), DaemonError> {
    if config.socket.path != root.join("emberd.sock")
        || config.installed_authority.state_path != root.join("installed-authority-state.json")
        || config.installed_authority.proof_path != root.join("installed-authority-proof.json")
        || config.installed_authority.enrolled_public_key_path
            != root.join("founder-presence-public-key")
        || config.installed_authority.nonce_store_root != root.join("presence-nonces")
    {
        return Err(DaemonError::InvalidConfiguration);
    }
    Ok(())
}

fn acquire_instance_lock(root: &Path, daemon_uid: u32) -> Result<InstanceLock, DaemonError> {
    let path = root.join("emberd.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !valid_instance_lock_metadata(&metadata, daemon_uid) {
        return Err(DaemonError::InsecureFile);
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(DaemonError::AlreadyRunning),
        Err(fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let locked_metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !valid_instance_lock_metadata(&locked_metadata, daemon_uid)
        || locked_metadata.dev() != path_metadata.dev()
        || locked_metadata.ino() != path_metadata.ino()
    {
        return Err(DaemonError::InsecureFile);
    }
    Ok(InstanceLock { _file: file })
}

fn valid_instance_lock_metadata(metadata: &fs::Metadata, daemon_uid: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == daemon_uid
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
}

#[cfg(test)]
fn bind_socket(
    path: &Path,
    mode: u32,
    daemon_uid: u32,
    client_gid: u32,
    _instance_lock: &InstanceLock,
) -> Result<(UnixListener, SocketIdentity), DaemonError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != daemon_uid
                || metadata.gid() != client_gid
                || metadata.mode() & 0o777 != mode
            {
                return Err(DaemonError::SocketExists);
            }
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) => SocketIdentity::from_metadata(&metadata),
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(error.into());
        }
    };
    let configured = (|| -> io::Result<SocketIdentity> {
        identity::set_socket_owner(path, daemon_uid, client_gid)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != daemon_uid
            || metadata.gid() != client_gid
            || metadata.mode() & 0o777 != mode
            || !created.same_inode(&metadata)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid control socket owner, group, mode, or identity",
            ));
        }
        listener.set_nonblocking(true)?;
        Ok(SocketIdentity::from_metadata(&metadata))
    })();
    match configured {
        Ok(identity) => Ok((listener, identity)),
        Err(error) => {
            remove_socket_if_same_inode(path, created);
            Err(error.into())
        }
    }
}

impl SocketIdentity {
    #[cfg(test)]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
        }
    }

    fn same_inode(self, metadata: &fs::Metadata) -> bool {
        metadata.dev() == self.device && metadata.ino() == self.inode
    }

    fn matches(self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket()
            && self.same_inode(metadata)
            && metadata.uid() == self.uid
            && metadata.gid() == self.gid
            && metadata.mode() & 0o777 == self.mode
    }
}

#[cfg(test)]
fn remove_socket_if_same_inode(path: &Path, identity: SocketIdentity) {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && identity.same_inode(&metadata)
    {
        let _ = fs::remove_file(path);
    }
}

fn remove_socket_if_owned(path: &Path, identity: SocketIdentity) {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && identity.matches(&metadata)
    {
        let _ = fs::remove_file(path);
    }
}

fn read_secure_file(
    path: &Path,
    owner_uid: u32,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, DaemonError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > max_bytes
    {
        return Err(DaemonError::InsecureFile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(DaemonError::InsecureFile);
    }
    Ok(bytes)
}

fn validate_runtime_directory(
    path: &Path,
    owner_uid: u32,
    client_gid: Option<u32>,
) -> Result<(), DaemonError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != 0o710
        || client_gid.is_some_and(|gid| metadata.gid() != gid)
    {
        return Err(DaemonError::InsecureFile);
    }
    Ok(())
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct DaemonInstalledStateError(installed_state::InstalledStateError);

#[derive(Debug, Error)]
#[error(transparent)]
pub struct DaemonSupervisorError(crate::session_supervisor::SupervisorError);

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("invalid daemon configuration")]
    InvalidConfiguration,
    #[error("the authority Credential catalog is dormant")]
    DormantCredentialCatalog,
    #[error("daemon must run as its configured dedicated non-root identity")]
    InvalidDaemonIdentity,
    #[error("owner-private file is insecure")]
    InsecureFile,
    #[error("daemon path is insecure")]
    InsecurePath,
    #[error("control socket already exists")]
    SocketExists,
    #[error("authority daemon is already running")]
    AlreadyRunning,
    #[error("startup recovery is unresolved")]
    UnresolvedRecovery,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Installed(DaemonInstalledStateError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Pack(#[from] crate::pack::PackError),
    #[error(transparent)]
    Presence(#[from] crate::presence::PresenceError),
    #[error(transparent)]
    RuntimePresence(#[from] crate::runtime_presence::RuntimePresenceError),
    #[error(transparent)]
    Custody(#[from] crate::custody::CustodyError),
    #[error(transparent)]
    Provider(#[from] crate::provider::ProviderError),
    #[error(transparent)]
    Git(#[from] crate::git::GitRunnerError),
    #[error(transparent)]
    Runner(#[from] crate::runner::RunnerError),
    #[error(transparent)]
    Authority(#[from] crate::principal::AuthorityError),
    #[error(transparent)]
    Artifact(#[from] crate::artifact::ArtifactError),
    #[error(transparent)]
    Journal(#[from] crate::audit::JournalError),
    #[error(transparent)]
    Recovery(#[from] crate::recovery::RecoveryError),
    #[error(transparent)]
    Host(#[from] crate::host::HostError),
    #[error(transparent)]
    Submit(#[from] crate::SubmitError),
    #[error(transparent)]
    Control(#[from] crate::control::ControlError),
    #[error(transparent)]
    Supervisor(DaemonSupervisorError),
}

impl From<installed_state::InstalledStateError> for DaemonError {
    fn from(source: installed_state::InstalledStateError) -> Self {
        Self::Installed(DaemonInstalledStateError(source))
    }
}

impl From<crate::session_supervisor::SupervisorError> for DaemonError {
    fn from(source: crate::session_supervisor::SupervisorError) -> Self {
        Self::Supervisor(DaemonSupervisorError(source))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::Shutdown,
        os::unix::net::UnixStream,
        sync::Arc,
        time::Duration,
    };

    use crate::{
        AuthorityKernel,
        artifact::ArtifactStore,
        audit::test_evidence_context,
        control::{
            CONTROL_REQUEST_SCHEMA, ControlOperation, ControlRequest, ControlResponse,
            ControlResult, GithubCoordinates, LauncherPolicy, LockableGithubProvider,
        },
        custody::{
            CUSTODY_KEY_LABEL, CustodyContext, CustodyPurpose, DOUBLE_ENVELOPE_SCHEMA,
            DaemonWrapKey, INNER_ENVELOPE_ALGORITHM, OUTER_ENVELOPE_ALGORITHM,
        },
        identity,
        model::OperationId,
        pack::PackRegistry,
        principal::{ExecutableDigest, PersonaAuthority},
        provider::ProviderRegistry,
        recovery::RecoveryJournal,
        runner::RunnerRegistry,
    };

    use super::*;

    fn test_daemon(root: &Path) -> ConfiguredDaemon {
        let metadata = fs::metadata(root).unwrap();
        let daemon_uid = metadata.uid();
        let client_gid = metadata.gid();
        let (journal, _, _) = test_evidence_context(root.join("audit")).unwrap();
        let mut kernel = AuthorityKernel::new(
            PersonaAuthority::new(),
            PackRegistry::default(),
            ProviderRegistry::default(),
            ArtifactStore::new(root.join("artifacts"), 1024).unwrap(),
            journal.clone(),
            RecoveryJournal::open(root.join("recovery"), [8_u8; 32]).unwrap(),
            RunnerRegistry::default(),
        );
        kernel.recover_startup(1).unwrap();
        let runtime = HostRuntime::new(kernel, 1024, 1024, Duration::from_secs(1)).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let launchers = vec![LauncherPolicy {
            euid: daemon_uid,
            egid: client_gid,
            executable_digest: ExecutableDigest::from_sha256(
                identity::reviewed_executable_fingerprint(&executable).unwrap(),
            ),
        }];
        let custody_context = CustodyContext::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            CustodyPurpose::GithubAppPrivateKey,
        )
        .unwrap();
        let public_key = p256::ecdsa::SigningKey::from_slice(&[7_u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false);
        let sealed_envelope = serde_jcs::to_vec(&serde_json::json!({
            "schema": DOUBLE_ENVELOPE_SCHEMA,
            "outer_algorithm": OUTER_ENVELOPE_ALGORITHM,
            "inner_algorithm": INNER_ENVELOPE_ALGORITHM,
            "key_label": CUSTODY_KEY_LABEL,
            "context": &custody_context,
            "inner_envelope_sha256": "00".repeat(32),
            "public_key_sec1_hex": hex::encode(public_key.as_bytes()),
            "ciphertext_hex": hex::encode(vec![3_u8; 32 * 1024]),
        }))
        .unwrap();
        let control = ControlRuntime::new(
            Duration::from_secs(1),
            journal,
            launchers,
            sealed_envelope,
            custody_context,
            DaemonWrapKey::generate(),
            GithubCoordinates {
                app_slug: "test".to_owned(),
                app_id: 1,
                installation_id: 2,
            },
            Arc::new(LockableGithubProvider::locked(
                crate::provider::GithubTokenRevoker::new(),
            )),
        )
        .unwrap();
        let supervisor =
            SessionSupervisor::new(root.join("sessions"), daemon_uid, client_gid).unwrap();
        let socket_path = root.join("emberd.sock");
        let instance_lock = acquire_instance_lock(root, daemon_uid).unwrap();
        let (listener, socket_identity) =
            bind_socket(&socket_path, 0o660, daemon_uid, client_gid, &instance_lock).unwrap();
        ConfiguredDaemon {
            runtime,
            control,
            supervisor,
            listener,
            socket_path,
            socket_identity,
            _instance_lock: instance_lock,
            #[cfg(target_os = "macos")]
            console: ConsoleSessionMonitor::new(daemon_uid),
        }
    }

    #[test]
    fn root_daemon_identity_is_refused_before_state_access() {
        let result = ConfiguredDaemon::load("/missing/emberd.json", 0, "/missing", 1);
        assert!(matches!(result, Err(DaemonError::InvalidDaemonIdentity)));
    }

    #[test]
    fn malformed_control_peer_does_not_terminate_daemon() {
        let temp = tempfile::tempdir().unwrap();
        let mut daemon = test_daemon(temp.path());
        let socket = daemon.socket_path.clone();

        let mut malformed = UnixStream::connect(&socket).unwrap();
        malformed.write_all(b"x").unwrap();
        malformed.shutdown(Shutdown::Write).unwrap();
        daemon.serve_once().unwrap();

        let request = serde_jcs::to_vec(&ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: OperationId::new().to_string(),
            operation: ControlOperation::Status,
        })
        .unwrap();
        let mut valid = UnixStream::connect(&socket).unwrap();
        valid
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        valid.write_all(&request).unwrap();
        valid.shutdown(Shutdown::Write).unwrap();
        daemon.serve_once().unwrap();

        let mut prefix = [0_u8; 4];
        valid.read_exact(&mut prefix).unwrap();
        let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        valid.read_exact(&mut payload).unwrap();
        let response: ControlResponse = serde_json::from_slice(&payload).unwrap();
        assert!(matches!(
            response.result,
            ControlResult::Success { ok: true, .. }
        ));
    }

    #[test]
    fn control_transaction_has_an_absolute_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let mut daemon = test_daemon(temp.path());
        let mut client = UnixStream::connect(&daemon.socket_path).unwrap();
        client.write_all(&8_u32.to_be_bytes()).unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..8 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let _ = client.shutdown(Shutdown::Write);
        });

        let started = std::time::Instant::now();
        daemon.serve_once().unwrap();
        let elapsed = started.elapsed();
        writer.join().unwrap();

        assert!(
            elapsed < Duration::from_millis(1_500),
            "drip-fed control transaction held the daemon for {elapsed:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn large_control_response_survives_nonblocking_listener() {
        let temp = tempfile::tempdir().unwrap();
        let mut daemon = test_daemon(temp.path());
        let request = serde_jcs::to_vec(&ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: OperationId::new().to_string(),
            operation: ControlOperation::CustodyUnlockBegin,
        })
        .unwrap();
        let mut client = UnixStream::connect(&daemon.socket_path).unwrap();
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let response = std::thread::spawn(move || {
            let mut prefix = [0_u8; 4];
            client.read_exact(&mut prefix).unwrap();
            let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            client.read_exact(&mut payload).unwrap();
            serde_json::from_slice::<ControlResponse>(&payload).unwrap()
        });
        daemon.serve_once().unwrap();

        assert!(matches!(
            response.join().unwrap().result,
            ControlResult::Success { ok: true, .. }
        ));
    }
    #[test]
    fn instance_lock_serializes_socket_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = fs::metadata(temp.path()).unwrap();
        let daemon_uid = metadata.uid();

        let lock = acquire_instance_lock(temp.path(), daemon_uid).unwrap();
        assert!(matches!(
            acquire_instance_lock(temp.path(), daemon_uid),
            Err(DaemonError::AlreadyRunning)
        ));
        drop(lock);
        acquire_instance_lock(temp.path(), daemon_uid).unwrap();
    }

    #[test]
    fn stale_control_socket_is_replaced_but_live_instance_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = fs::metadata(temp.path()).unwrap();
        let daemon_uid = metadata.uid();
        let client_gid = metadata.gid();
        let path = temp.path().join("emberd.sock");

        let first_lock = acquire_instance_lock(temp.path(), daemon_uid).unwrap();
        let (stale, _) = bind_socket(&path, 0o660, daemon_uid, client_gid, &first_lock).unwrap();
        drop(stale);
        assert!(matches!(
            acquire_instance_lock(temp.path(), daemon_uid),
            Err(DaemonError::AlreadyRunning)
        ));
        drop(first_lock);

        let rebound_lock = acquire_instance_lock(temp.path(), daemon_uid).unwrap();
        let (rebound, _) =
            bind_socket(&path, 0o660, daemon_uid, client_gid, &rebound_lock).unwrap();
        UnixStream::connect(&path).unwrap();
        drop(rebound);
    }

    #[test]
    fn socket_recovery_rejects_unrecognized_paths() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = fs::metadata(temp.path()).unwrap();
        let daemon_uid = metadata.uid();
        let client_gid = metadata.gid();
        let lock = acquire_instance_lock(temp.path(), daemon_uid).unwrap();
        let path = temp.path().join("emberd.sock");

        fs::write(&path, b"not a socket").unwrap();
        assert!(matches!(
            bind_socket(&path, 0o660, daemon_uid, client_gid, &lock),
            Err(DaemonError::SocketExists)
        ));
        fs::remove_file(&path).unwrap();

        std::os::unix::fs::symlink(temp.path(), &path).unwrap();
        assert!(matches!(
            bind_socket(&path, 0o660, daemon_uid, client_gid, &lock),
            Err(DaemonError::SocketExists)
        ));
        fs::remove_file(&path).unwrap();

        let (stale, _) = bind_socket(&path, 0o660, daemon_uid, client_gid, &lock).unwrap();
        drop(stale);
        assert!(matches!(
            bind_socket(&path, 0o600, daemon_uid, client_gid, &lock),
            Err(DaemonError::SocketExists)
        ));
    }

    #[test]
    fn socket_cleanup_refuses_a_replacement_inode() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = fs::metadata(temp.path()).unwrap();
        let daemon_uid = metadata.uid();
        let client_gid = metadata.gid();
        let lock = acquire_instance_lock(temp.path(), daemon_uid).unwrap();
        let path = temp.path().join("emberd.sock");

        let (original, original_identity) =
            bind_socket(&path, 0o660, daemon_uid, client_gid, &lock).unwrap();
        drop(original);
        remove_socket_if_owned(&path, original_identity);
        assert!(!path.exists());
        let replacement = UnixListener::bind(&path).unwrap();
        remove_socket_if_owned(&path, original_identity);
        assert!(path.exists());
        drop(replacement);
    }
}
