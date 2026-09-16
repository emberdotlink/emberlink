use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    host::{HostError, HostRuntime, PeerIdentity},
    host_client::{
        SESSION_ACTIVATION_REQUEST_SCHEMA, SESSION_ACTIVATION_RESPONSE_SCHEMA,
        SessionActivationRequest, SessionActivationResponse,
    },
    identity,
    model::{ProcessBindingId, SessionId},
    principal::{ExecutableDigest, ProcessRegistrationChallenge},
};

#[cfg(target_os = "macos")]
use crate::macos_process::{ExitObservation, ProcessExitWatcher, peer_process_instance};

#[cfg(test)]
const MAX_SUPERVISED_SESSIONS: usize = 256;
const MAX_ACTIVATION_BYTES: u64 = 64 * 1024;
const PENDING_SESSION_TTL: Duration = Duration::from_secs(5 * 60);
#[cfg(not(test))]
const ACTIVATION_IO_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const ACTIVATION_IO_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub(crate) struct SessionEndpointPolicy {
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) executable_digest: ExecutableDigest,
}

struct PendingSession {
    policy: SessionEndpointPolicy,
    registered_at: Instant,
    endpoint: PathBuf,
    listener: UnixListener,
}

struct ActiveSession {
    binding: ProcessBindingId,
    endpoint: PathBuf,
    #[cfg(not(target_os = "macos"))]
    pid: u32,
    #[cfg(not(target_os = "macos"))]
    pid_version: u64,
    listener: UnixListener,
    #[cfg(target_os = "macos")]
    exit_observer: ProcessExitWatcher,
}

pub(crate) struct ActivatedEndpoint {
    pub(crate) session_id: SessionId,
    pub(crate) process_binding_id: ProcessBindingId,
    pub(crate) socket_path: PathBuf,
}

/// Owns every action listener and exact process-exit watcher. The public daemon
/// listener is deliberately absent from this type.
pub(crate) struct SessionSupervisor {
    root: PathBuf,
    daemon_uid: u32,
    client_gid: u32,
    pending: BTreeMap<SessionId, PendingSession>,
    active: BTreeMap<SessionId, ActiveSession>,
}

impl SessionSupervisor {
    pub(crate) fn new(
        root: impl AsRef<Path>,
        daemon_uid: u32,
        client_gid: u32,
    ) -> Result<Self, SupervisorError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(SupervisorError::InvalidRoot);
        }
        match fs::symlink_metadata(root) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || metadata.uid() != daemon_uid
                    || metadata.permissions().mode() & 0o022 != 0
                {
                    return Err(SupervisorError::InvalidRoot);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(root)?;
                fs::set_permissions(root, fs::Permissions::from_mode(0o711))?;
                let metadata = fs::symlink_metadata(root)?;
                if metadata.uid() != daemon_uid {
                    return Err(SupervisorError::InvalidRoot);
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            root: root.to_owned(),
            daemon_uid,
            client_gid,
            pending: BTreeMap::new(),
            active: BTreeMap::new(),
        })
    }
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn active_count(&self) -> usize {
        self.active.len()
    }

    #[cfg(test)]
    pub(crate) fn register_pending(
        &mut self,
        session: SessionId,
        policy: SessionEndpointPolicy,
    ) -> Result<PathBuf, SupervisorError> {
        if self.pending.contains_key(&session) || self.active.contains_key(&session) {
            return Err(SupervisorError::DuplicateSession);
        }
        if self.pending.len() + self.active.len() >= MAX_SUPERVISED_SESSIONS {
            return Err(SupervisorError::Capacity);
        }
        let session_uuid =
            Uuid::parse_str(session.as_str()).map_err(|_| SupervisorError::InvalidSession)?;
        let endpoint = self.root.join(format!(
            "activate-{}",
            URL_SAFE_NO_PAD.encode(session_uuid.as_bytes())
        ));
        let listener = bind_owner_socket(&endpoint, self.daemon_uid, self.client_gid)?;
        self.pending.insert(
            session,
            PendingSession {
                policy,
                registered_at: Instant::now(),
                endpoint: endpoint.clone(),
                listener,
            },
        );
        Ok(endpoint)
    }

    /// Activates only the exact reviewed Session process that owns this control
    /// connection. Kernel-derived peer identity replaces cross-UID PID reports.
    pub(crate) fn bind_and_activate(
        &mut self,
        runtime: &mut HostRuntime,
        session: &SessionId,
        challenge: ProcessRegistrationChallenge,
        peer: &PeerIdentity,
        control_stream: &UnixStream,
    ) -> Result<ActivatedEndpoint, SupervisorError> {
        if !self.pending_peer_matches(session, peer)? {
            return Err(SupervisorError::ProcessPolicy);
        }
        #[cfg(target_os = "macos")]
        let exit_observer = self.prepare_exit_observer(control_stream, peer)?;
        #[cfg(not(target_os = "macos"))]
        let _ = control_stream;

        let binding = match runtime.bind_session_origin(session, &challenge, peer) {
            Ok(binding) => binding,
            Err(error) => {
                if error.is_reclaimed_session_bind_failure() {
                    self.pending.remove(session);
                }
                return Err(error.into());
            }
        };
        let binding_uuid = parse_binding_uuid_or_rollback(&binding, || {
            self.rollback_failed_activation(runtime, session, &binding)
        })?;
        let endpoint = self
            .root
            .join(URL_SAFE_NO_PAD.encode(binding_uuid.as_bytes()));
        let listener = match bind_owner_socket(&endpoint, self.daemon_uid, self.client_gid) {
            Ok(listener) => listener,
            Err(error) => {
                self.rollback_failed_activation(runtime, session, &binding)?;
                return Err(error);
            }
        };
        let active = ActiveSession {
            binding: binding.clone(),
            endpoint: endpoint.clone(),
            listener,
            #[cfg(not(target_os = "macos"))]
            pid: peer.pid(),
            #[cfg(not(target_os = "macos"))]
            pid_version: peer.pid_version(),
            #[cfg(target_os = "macos")]
            exit_observer,
        };
        let pending = self
            .pending
            .remove(session)
            .ok_or(SupervisorError::UnknownSession)?;
        unlink_socket(&pending.endpoint).map_err(|_| SupervisorError::CleanupInvariant)?;
        self.active.insert(session.clone(), active);
        Ok(ActivatedEndpoint {
            session_id: session.clone(),
            process_binding_id: binding,
            socket_path: endpoint,
        })
    }

    fn pending_peer_matches(
        &self,
        session: &SessionId,
        peer: &PeerIdentity,
    ) -> Result<bool, SupervisorError> {
        let pending = self
            .pending
            .get(session)
            .ok_or(SupervisorError::UnknownSession)?;
        Ok(peer.euid() == pending.policy.euid
            && peer.egid() == pending.policy.egid
            && peer.executable_digest() == pending.policy.executable_digest)
    }

    #[cfg(test)]
    pub(crate) fn end_session(
        &mut self,
        runtime: &mut HostRuntime,
        session: &SessionId,
    ) -> Result<(), SupervisorError> {
        if !self.pending.contains_key(session) && !self.active.contains_key(session) {
            return Err(SupervisorError::UnknownSession);
        }
        match runtime.end_session(session) {
            Ok(()) => {}
            Err(error) if !self.active.contains_key(session) && error.is_unknown_session() => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(pending) = self.pending.remove(session) {
            unlink_socket(&pending.endpoint).map_err(|_| SupervisorError::CleanupInvariant)?;
        }
        self.remove_active_endpoint(session)
    }

    /// Nonblocking liveness and action dispatch pass. Process exit is terminal:
    /// the exact binding is ended before its owner-bound endpoint is unlinked.
    pub(crate) fn tick(
        &mut self,
        runtime: &mut HostRuntime,
        authorize: &mut impl FnMut() -> bool,
    ) -> Result<(), SupervisorError> {
        let expired = self
            .pending
            .iter()
            .filter(|&(_, pending)| pending.registered_at.elapsed() >= PENDING_SESSION_TTL)
            .map(|(session, _)| session.clone())
            .collect::<Vec<_>>();
        for session in expired {
            match runtime.end_session(&session) {
                Ok(()) => self.remove_pending_endpoint(&session)?,
                Err(error) if error.is_unknown_session() => {
                    self.remove_pending_endpoint(&session)?;
                }
                Err(error) if error.is_permanent_session_cleanup_failure() => {
                    return Err(SupervisorError::CleanupInvariant);
                }
                Err(error) => {
                    eprintln!("emberd: failed to expire pending Session: {error}");
                }
            }
        }
        let mut activations = Vec::new();
        for (session, pending) in &self.pending {
            match pending.listener.accept() {
                Ok((stream, _)) => activations.push((session.clone(), stream)),
                Err(error) if transient_accept_error(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for (session, mut stream) in activations {
            if stream.set_nonblocking(false).is_err()
                || stream
                    .set_read_timeout(Some(ACTIVATION_IO_TIMEOUT))
                    .is_err()
                || stream
                    .set_write_timeout(Some(ACTIVATION_IO_TIMEOUT))
                    .is_err()
            {
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
            let peer = match identity::peer_identity(&stream) {
                Ok(peer) if self.pending_peer_matches(&session, &peer).unwrap_or(false) => peer,
                _ => {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
            };
            let request = match read_activation(&mut stream) {
                Ok(request)
                    if request.schema == SESSION_ACTIVATION_REQUEST_SCHEMA
                        && request.session_id == session =>
                {
                    request
                }
                _ => {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
            };
            let mut challenge_bytes = Zeroizing::new([0_u8; 32]);
            let challenge_valid =
                hex::decode_to_slice(&request.challenge_hex, &mut *challenge_bytes).is_ok();
            if !challenge_valid {
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
            let challenge = ProcessRegistrationChallenge::from_bytes(*challenge_bytes);
            challenge_bytes.zeroize();
            let activation = self.bind_and_activate(runtime, &session, challenge, &peer, &stream);
            match activation {
                Ok(endpoint) => {
                    let response = SessionActivationResponse {
                        schema: SESSION_ACTIVATION_RESPONSE_SCHEMA.to_owned(),
                        socket_path: endpoint.socket_path,
                        session_id: endpoint.session_id,
                        process_binding_id: endpoint.process_binding_id,
                    };
                    let Ok(bytes) = serde_jcs::to_vec(&response) else {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    };
                    if stream.write_all(&bytes).is_err()
                        || stream.shutdown(Shutdown::Write).is_err()
                    {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
                Err(error) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    if matches!(error, SupervisorError::CleanupInvariant) {
                        return Err(error);
                    }
                }
            }
        }

        let mut exited = Vec::new();
        for (session, active) in &mut self.active {
            #[cfg(target_os = "macos")]
            let process_exited = match active
                .exit_observer
                .observe_exit()
                .map_err(|_| SupervisorError::ProcessWatcher)?
            {
                ExitObservation::Running => false,
                ExitObservation::Exited => true,
            };
            #[cfg(not(target_os = "macos"))]
            let process_exited = process_exited(active.pid, active.pid_version)?;
            if process_exited {
                exited.push(session.clone());
            }
        }
        for session in exited {
            let Some(active) = self.active.get(&session) else {
                continue;
            };
            if let Err(error) = runtime.end_session_origin(&active.binding) {
                if error.is_permanent_session_cleanup_failure() {
                    return Err(SupervisorError::CleanupInvariant);
                }
                eprintln!("emberd: failed to end exited Session binding: {error}");
                continue;
            }
            self.remove_active_endpoint(&session)?;
        }

        for (session, active) in &self.active {
            let (stream, _) = match active.listener.accept() {
                Ok(value) => value,
                Err(error) if transient_accept_error(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            stream.set_nonblocking(false)?;
            let result = match identity::peer_identity(&stream) {
                Ok(peer) => runtime.handle_session_connection(
                    stream,
                    peer,
                    session,
                    &active.binding,
                    &mut *authorize,
                ),
                Err(_) => HostRuntime::reject_unidentified(stream),
            };
            if let Err(error) = result {
                eprintln!("emberd: refused Session connection: {error}");
            }
        }
        Ok(())
    }

    fn rollback_failed_activation(
        &mut self,
        runtime: &mut HostRuntime,
        session: &SessionId,
        binding: &ProcessBindingId,
    ) -> Result<(), SupervisorError> {
        self.remove_pending_endpoint(session)?;
        runtime
            .end_session_origin(binding)
            .map_err(|_| SupervisorError::CleanupInvariant)
    }
    fn remove_pending_endpoint(&mut self, session: &SessionId) -> Result<(), SupervisorError> {
        let Some(pending) = self.pending.remove(session) else {
            return Ok(());
        };
        unlink_socket(&pending.endpoint).map_err(|_| SupervisorError::CleanupInvariant)
    }

    fn remove_active_endpoint(&mut self, session: &SessionId) -> Result<(), SupervisorError> {
        let Some(active) = self.active.remove(session) else {
            return Ok(());
        };
        unlink_socket(&active.endpoint).map_err(|_| SupervisorError::CleanupInvariant)
    }

    #[cfg(target_os = "macos")]
    fn prepare_exit_observer(
        &self,
        control_stream: &UnixStream,
        peer: &PeerIdentity,
    ) -> Result<ProcessExitWatcher, SupervisorError> {
        let process =
            peer_process_instance(control_stream).map_err(|_| SupervisorError::ProcessIdentity)?;
        if process.pid() != peer.pid() || process.pid_version() != peer.pid_version() {
            return Err(SupervisorError::ProcessIdentity);
        }
        ProcessExitWatcher::register(process).map_err(|_| SupervisorError::ProcessWatcher)
    }
}
#[cfg(not(target_os = "macos"))]
fn process_exited(pid: u32, expected_pid_version: u64) -> Result<bool, SupervisorError> {
    match identity::process_pid_version(pid) {
        Ok(actual_pid_version) => Ok(actual_pid_version != expected_pid_version),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(SupervisorError::ProcessIdentity),
    }
}

impl Drop for SessionSupervisor {
    fn drop(&mut self) {
        for endpoint in self
            .pending
            .values()
            .map(|pending| &pending.endpoint)
            .chain(self.active.values().map(|active| &active.endpoint))
        {
            if let Err(error) = unlink_socket(endpoint) {
                eprintln!("emberd: Session endpoint cleanup invariant failed: {error}");
                std::process::abort();
            }
        }
    }
}

#[allow(unsafe_code)]
fn bind_owner_socket(
    path: &Path,
    daemon_uid: u32,
    client_gid: u32,
) -> Result<UnixListener, SupervisorError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(SupervisorError::EndpointExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    if let Err(error) = (|| {
        identity::set_socket_owner(path, daemon_uid, client_gid)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != daemon_uid
            || metadata.gid() != client_gid
            || metadata.mode() & 0o777 != 0o660
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid Session socket owner, group, or mode",
            ));
        }
        listener.set_nonblocking(true)
    })() {
        cleanup_failed_bind(path)?;
        return Err(error.into());
    }
    Ok(listener)
}

fn cleanup_failed_bind(path: &Path) -> Result<(), SupervisorError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SupervisorError::CleanupInvariant),
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

fn unlink_socket(path: &Path) -> Result<(), SupervisorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(SupervisorError::EndpointChanged),
    }
}

fn parse_binding_uuid_or_rollback(
    binding: &ProcessBindingId,
    rollback: impl FnOnce() -> Result<(), SupervisorError>,
) -> Result<Uuid, SupervisorError> {
    match Uuid::parse_str(binding.as_str()) {
        Ok(binding_uuid) => Ok(binding_uuid),
        Err(_) => {
            rollback()?;
            Err(SupervisorError::InvalidBinding)
        }
    }
}

fn read_activation(stream: &mut UnixStream) -> Result<SessionActivationRequest, SupervisorError> {
    let mut bytes = Zeroizing::new(Vec::new());
    stream
        .take(MAX_ACTIVATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_ACTIVATION_BYTES as usize {
        return Err(SupervisorError::ActivationProtocol);
    }
    serde_json::from_slice(&bytes).map_err(|_| SupervisorError::ActivationProtocol)
}

#[derive(Debug, Error)]
pub(crate) enum SupervisorError {
    #[error("invalid Session endpoint root")]
    InvalidRoot,
    #[error("invalid process binding identifier")]
    InvalidBinding,
    #[cfg(test)]
    #[error("invalid Session identifier")]
    InvalidSession,
    #[cfg(test)]
    #[error("Session is already supervised")]
    DuplicateSession,
    #[error("Session is not supervised")]
    UnknownSession,
    #[cfg(test)]
    #[error("Session supervisor capacity exceeded")]
    Capacity,
    #[error("reported process identity is unavailable")]
    ProcessIdentity,
    #[error("reported process does not match reviewed Session policy")]
    ProcessPolicy,
    #[error("reported process watcher registration failed")]
    ProcessWatcher,
    #[error("Session endpoint already exists")]
    EndpointExists,
    #[error("Session endpoint changed unexpectedly")]
    EndpointChanged,
    #[error("Session cleanup invariant failed; daemon must stop")]
    CleanupInvariant,
    #[error("Session activation protocol is invalid")]
    ActivationProtocol,
    #[error("platform does not support exact process supervision")]
    #[cfg(not(unix))]
    UnsupportedPlatform,
    #[error("authority host transition failed")]
    Host(#[from] HostError),
    #[error("Session endpoint I/O failed")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixListener,
    };
    #[cfg(target_os = "macos")]
    use std::{io::Write as _, net::Shutdown, os::unix::net::UnixStream, process::Command};

    use super::*;
    use crate::{
        artifact::ArtifactStore, audit::test_evidence_context, kernel::AuthorityKernel,
        model::PersonaId, pack::PackRegistry, principal::PersonaAuthority,
        provider::ProviderRegistry, recovery::RecoveryJournal, runner::RunnerRegistry,
    };

    fn daemon_uid(root: &Path) -> u32 {
        fs::symlink_metadata(root).unwrap().uid()
    }

    fn daemon_gid(root: &Path) -> u32 {
        fs::symlink_metadata(root).unwrap().gid()
    }

    fn policy(digest: ExecutableDigest) -> SessionEndpointPolicy {
        SessionEndpointPolicy {
            euid: 501,
            egid: 20,
            executable_digest: digest,
        }
    }

    fn host_runtime(root: &Path) -> (HostRuntime, PersonaId) {
        let persona = PersonaId::new();
        let mut authority = PersonaAuthority::new();
        authority.restore_persona(persona.clone()).unwrap();
        let (journal, _, _) = test_evidence_context(root.join("audit")).unwrap();
        let mut kernel = AuthorityKernel::new(
            authority,
            PackRegistry::default(),
            ProviderRegistry::default(),
            ArtifactStore::new(root.join("artifacts"), 1024).unwrap(),
            journal,
            RecoveryJournal::open(root.join("recovery"), [8_u8; 32]).unwrap(),
            RunnerRegistry::default(),
        );
        kernel.recover_startup(1).unwrap();
        (
            HostRuntime::new(kernel, 1024, 1024, std::time::Duration::from_secs(1)).unwrap(),
            persona,
        )
    }

    #[cfg(target_os = "macos")]
    fn current_peer() -> PeerIdentity {
        let (stream, _peer) = UnixStream::pair().unwrap();
        identity::peer_identity(&stream).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn runtime_with_session(
        root: &Path,
        digest: ExecutableDigest,
    ) -> (HostRuntime, SessionId, ProcessRegistrationChallenge) {
        let (mut runtime, persona) = host_runtime(root);
        let (session, challenge) = runtime.create_session(&persona, digest).unwrap();
        (runtime, session, challenge)
    }

    #[test]
    fn pending_registration_is_unique_and_does_not_replace_policy() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let session = SessionId::new();
        let original = ExecutableDigest::from_sha256([1_u8; 32]);
        supervisor
            .register_pending(session.clone(), policy(original))
            .unwrap();

        assert!(matches!(
            supervisor.register_pending(
                session.clone(),
                policy(ExecutableDigest::from_sha256([2_u8; 32]))
            ),
            Err(SupervisorError::DuplicateSession)
        ));
        assert_eq!(supervisor.pending_count(), 1);
        assert_eq!(
            supervisor
                .pending
                .get(&session)
                .unwrap()
                .policy
                .executable_digest,
            original
        );
    }

    #[test]
    fn pending_sessions_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let endpoint_policy = policy(ExecutableDigest::from_sha256([9_u8; 32]));
        for _ in 0..MAX_SUPERVISED_SESSIONS {
            supervisor
                .register_pending(SessionId::new(), endpoint_policy.clone())
                .unwrap();
        }

        assert!(matches!(
            supervisor.register_pending(SessionId::new(), endpoint_policy),
            Err(SupervisorError::Capacity)
        ));
    }

    #[test]
    fn expired_pending_session_is_ended_and_removed() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let (mut runtime, persona) = host_runtime(temp.path());
        let digest = ExecutableDigest::from_sha256([9_u8; 32]);
        let (session, _) = runtime.create_session(&persona, digest).unwrap();
        supervisor
            .register_pending(session.clone(), policy(digest))
            .unwrap();
        supervisor.pending.get_mut(&session).unwrap().registered_at =
            Instant::now() - PENDING_SESSION_TTL;

        supervisor.tick(&mut runtime, &mut || true).unwrap();

        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }
    #[test]
    fn already_reclaimed_pending_session_is_removed_during_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let session = SessionId::new();
        supervisor
            .register_pending(
                session.clone(),
                policy(ExecutableDigest::from_sha256([4_u8; 32])),
            )
            .unwrap();
        supervisor.pending.get_mut(&session).unwrap().registered_at =
            Instant::now() - PENDING_SESSION_TTL;
        let (mut runtime, _) = host_runtime(temp.path());

        supervisor.tick(&mut runtime, &mut || true).unwrap();

        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bind_failure_with_failed_origin_rollback_is_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint_root = temp.path().join("endpoints");
        let mut supervisor = SessionSupervisor::new(
            &endpoint_root,
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let (control_stream, _client) = UnixStream::pair().unwrap();
        let peer = identity::peer_identity(&control_stream).unwrap();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let activation = supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        fs::remove_file(activation).unwrap();
        fs::remove_dir(&endpoint_root).unwrap();
        fs::write(&endpoint_root, b"not-a-directory").unwrap();
        runtime.fail_next_end_session_origin();

        assert!(matches!(
            supervisor
                .bind_and_activate(&mut runtime, &session, challenge, &peer, &control_stream,),
            Err(SupervisorError::CleanupInvariant)
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn process_liveness_uses_pid_version_without_rehashing() {
        let pid = std::process::id();
        let pid_version = identity::process_pid_version(pid).unwrap();

        assert!(!process_exited(pid, pid_version).unwrap());
        assert!(process_exited(pid, pid_version.wrapping_add(1)).unwrap());
    }

    #[test]
    fn ending_an_unknown_session_is_refused_without_state_change() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let (mut runtime, _) = host_runtime(temp.path());

        assert!(matches!(
            supervisor.end_session(&mut runtime, &SessionId::new()),
            Err(SupervisorError::UnknownSession)
        ));
        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[test]
    fn already_reclaimed_pending_session_can_be_ended_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            daemon_gid(temp.path()),
        )
        .unwrap();
        let session = SessionId::new();
        supervisor
            .register_pending(
                session.clone(),
                policy(ExecutableDigest::from_sha256([4_u8; 32])),
            )
            .unwrap();
        let (mut runtime, _) = host_runtime(temp.path());

        supervisor.end_session(&mut runtime, &session).unwrap();

        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[test]
    fn a_replaced_endpoint_is_not_silently_unlinked() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = temp.path().join("session.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        drop(listener);
        fs::remove_file(&endpoint).unwrap();
        fs::write(&endpoint, b"replacement").unwrap();

        assert!(matches!(
            unlink_socket(&endpoint),
            Err(SupervisorError::EndpointChanged)
        ));
        assert_eq!(fs::read(&endpoint).unwrap(), b"replacement");
    }
    #[test]
    fn failed_bind_cleanup_that_cannot_remove_the_endpoint_is_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = temp.path().join("endpoint");
        fs::create_dir(&endpoint).unwrap();

        assert!(matches!(
            cleanup_failed_bind(&endpoint),
            Err(SupervisorError::CleanupInvariant)
        ));
    }

    #[test]
    fn invalid_binding_parse_runs_activation_rollback() {
        let invalid = ProcessBindingId("not-a-uuid".to_owned());
        let mut rolled_back = false;

        let result = parse_binding_uuid_or_rollback(&invalid, || {
            rolled_back = true;
            Ok(())
        });

        assert!(matches!(result, Err(SupervisorError::InvalidBinding)));
        assert!(rolled_back);
    }

    #[test]
    fn invalid_binding_parse_escalates_failed_rollback() {
        let invalid = ProcessBindingId("not-a-uuid".to_owned());

        assert!(matches!(
            parse_binding_uuid_or_rollback(&invalid, || Err(SupervisorError::CleanupInvariant)),
            Err(SupervisorError::CleanupInvariant)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pre_bind_policy_mismatch_retains_pending_registration() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mismatched_digest =
            if peer.executable_digest() == ExecutableDigest::from_sha256([0_u8; 32]) {
                ExecutableDigest::from_sha256([1_u8; 32])
            } else {
                ExecutableDigest::from_sha256([0_u8; 32])
            };
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: mismatched_digest,
                },
            )
            .unwrap();

        assert!(matches!(
            supervisor.bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            ),
            Err(SupervisorError::ProcessPolicy)
        ));
        assert_eq!(supervisor.pending_count(), 1);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reclaimed_bind_failure_removes_pending_registration() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        drop(challenge);
        let challenge = ProcessRegistrationChallenge::from_bytes([0_u8; 32]);
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();

        assert!(
            supervisor
                .bind_and_activate(
                    &mut runtime,
                    &session,
                    challenge,
                    &peer,
                    &UnixStream::pair().unwrap().0,
                )
                .is_err()
        );
        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn activation_uses_kernel_derived_control_peer_without_ancestry_report() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();

        let endpoint = supervisor
            .bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            )
            .unwrap();

        assert!(endpoint.socket_path.exists());
        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn stalled_activation_peer_is_bounded_and_does_not_consume_session() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, _) = runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        let activation = supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let _stalled = UnixStream::connect(activation).unwrap();

        let started = Instant::now();
        supervisor.tick(&mut runtime, &mut || true).unwrap();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(supervisor.pending_count(), 1);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn activation_peer_policy_is_checked_before_challenge_consumption() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        let activation = supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: ExecutableDigest::from_sha256([0_u8; 32]),
                },
            )
            .unwrap();
        let mut client = UnixStream::connect(activation).unwrap();
        let request = SessionActivationRequest {
            schema: SESSION_ACTIVATION_REQUEST_SCHEMA.to_owned(),
            session_id: session.clone(),
            challenge_hex: hex::encode(challenge.expose_to_launcher()),
        };
        client
            .write_all(&serde_jcs::to_vec(&request).unwrap())
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        supervisor.tick(&mut runtime, &mut || true).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
        assert_eq!(supervisor.pending_count(), 1);
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn token_derived_exit_watcher_ends_child_session() {
        let temp = tempfile::tempdir().unwrap();
        let control_path = temp.path().join("child-control.sock");
        let control_listener = UnixListener::bind(&control_path).unwrap();
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(30)",
            ])
            .arg(&control_path)
            .spawn()
            .unwrap();
        let (control_stream, _) = control_listener.accept().unwrap();
        let peer = identity::peer_identity(&control_stream).unwrap();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let endpoint = supervisor
            .bind_and_activate(&mut runtime, &session, challenge, &peer, &control_stream)
            .unwrap();

        child.kill().unwrap();
        child.wait().unwrap();
        supervisor.tick(&mut runtime, &mut || false).unwrap();

        assert_eq!(supervisor.active_count(), 0);
        assert!(!endpoint.socket_path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exited_session_is_retained_when_binding_cleanup_fails() {
        let temp = tempfile::tempdir().unwrap();
        let control_path = temp.path().join("retry-control.sock");
        let control_listener = UnixListener::bind(&control_path).unwrap();
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(30)",
            ])
            .arg(&control_path)
            .spawn()
            .unwrap();
        let (control_stream, _) = control_listener.accept().unwrap();
        let peer = identity::peer_identity(&control_stream).unwrap();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let endpoint = supervisor
            .bind_and_activate(&mut runtime, &session, challenge, &peer, &control_stream)
            .unwrap();
        runtime.fail_next_end_session_origin();

        child.kill().unwrap();
        child.wait().unwrap();
        supervisor.tick(&mut runtime, &mut || false).unwrap();

        assert_eq!(supervisor.active_count(), 1);
        assert!(endpoint.socket_path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn post_binding_endpoint_failure_terminally_removes_pending_registration() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let endpoint_root = temp.path().join("endpoints");
        let mut supervisor =
            SessionSupervisor::new(&endpoint_root, daemon_uid(temp.path()), peer.egid()).unwrap();
        let activation = supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        fs::remove_file(activation).unwrap();
        fs::remove_dir(&endpoint_root).unwrap();

        assert!(matches!(
            supervisor.bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            ),
            Err(SupervisorError::Io(_))
        ));
        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 0);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn endpoint_failure_with_failed_binding_rollback_is_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let endpoint_root = temp.path().join("e");
        let mut supervisor =
            SessionSupervisor::new(&endpoint_root, daemon_uid(temp.path()), peer.egid()).unwrap();
        let activation = supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        fs::remove_file(activation).unwrap();
        fs::remove_dir(&endpoint_root).unwrap();
        runtime.fail_next_end_session_origin();

        assert!(matches!(
            supervisor.bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            ),
            Err(SupervisorError::CleanupInvariant)
        ));
        assert_eq!(supervisor.pending_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exact_current_origin_activation_and_end_owns_socket_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();

        let endpoint = supervisor
            .bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            )
            .unwrap();
        let metadata = fs::symlink_metadata(&endpoint.socket_path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        assert_eq!(metadata.uid(), daemon_uid(temp.path()));
        assert_eq!(metadata.gid(), peer.egid());
        assert_eq!(supervisor.pending_count(), 0);
        assert_eq!(supervisor.active_count(), 1);

        supervisor.end_session(&mut runtime, &session).unwrap();
        assert!(!endpoint.socket_path.exists());
        assert_eq!(supervisor.active_count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn active_authority_desync_is_not_tolerated_as_pending_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let endpoint = supervisor
            .bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            )
            .unwrap();
        runtime.end_session(&session).unwrap();

        assert!(matches!(
            supervisor.end_session(&mut runtime, &session),
            Err(SupervisorError::Host(error)) if error.is_unknown_session()
        ));
        assert_eq!(supervisor.active_count(), 1);
        assert!(endpoint.socket_path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn endpoint_cleanup_failure_after_session_end_is_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let endpoint = supervisor
            .bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            )
            .unwrap();
        fs::remove_file(&endpoint.socket_path).unwrap();
        fs::write(&endpoint.socket_path, b"replacement").unwrap();

        assert!(matches!(
            supervisor.end_session(&mut runtime, &session),
            Err(SupervisorError::CleanupInvariant)
        ));
        assert_eq!(supervisor.active_count(), 0);
        assert_eq!(fs::read(&endpoint.socket_path).unwrap(), b"replacement");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn malformed_session_peer_does_not_terminate_supervisor() {
        let temp = tempfile::tempdir().unwrap();
        let peer = current_peer();
        let (mut runtime, session, challenge) =
            runtime_with_session(temp.path(), peer.executable_digest());
        let mut supervisor = SessionSupervisor::new(
            temp.path().join("endpoints"),
            daemon_uid(temp.path()),
            peer.egid(),
        )
        .unwrap();
        supervisor
            .register_pending(
                session.clone(),
                SessionEndpointPolicy {
                    euid: peer.euid(),
                    egid: peer.egid(),
                    executable_digest: peer.executable_digest(),
                },
            )
            .unwrap();
        let endpoint = supervisor
            .bind_and_activate(
                &mut runtime,
                &session,
                challenge,
                &peer,
                &UnixStream::pair().unwrap().0,
            )
            .unwrap();

        let mut malformed = UnixStream::connect(endpoint.socket_path).unwrap();
        malformed.write_all(b"x").unwrap();
        malformed.shutdown(Shutdown::Write).unwrap();
        supervisor.tick(&mut runtime, &mut || true).unwrap();

        assert_eq!(supervisor.active_count(), 1);
    }
}
