//! Split-privilege installation transport.
//!
//! The per-user daemon owns staged inputs and durable state. The logged-in CLI
//! performs only founder-presence key enrollment or lookup and signs the exact
//! installation intent; no Credential material crosses this process seam.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    authority_state_directory, effective_uid,
    host::{DeadlineReader, DeadlineWriter, PeerIdentity, deadline_after},
    identity,
    install::{
        FounderKeyInput, InstallError, InstallResult, daemon_prepare_dormant_install,
        read_install_request, validate_daemon_install_request,
    },
    presence::{
        IssuedInstallationIntent, PresenceError, enroll_founder_presence_key,
        lookup_founder_presence_key, sign_installation_intent,
    },
    principal::ExecutableDigest,
};

pub const INSTALL_SOCKET_FILE: &str = "install.sock";
const FOUNDER_REQUEST_SCHEMA: &str = "ember.install-founder-request/v2";
const FOUNDER_RESPONSE_SCHEMA: &str = "ember.install-founder-response/v2";
const INTENT_SCHEMA: &str = "ember.install-intent/v2";
const PROOF_SCHEMA: &str = "ember.install-proof/v2";
const RESULT_SCHEMA: &str = "ember.install-result-message/v2";
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const INSTALL_IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FounderRequestWire {
    schema: String,
    founder_key: FounderKeyInput,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FounderResponseWire {
    schema: String,
    founder_public_key_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentMessageWire {
    schema: String,
    intent_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofMessageWire {
    schema: String,
    proof_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultMessageWire {
    schema: String,
    result: InstallResult,
}

/// Runs the daemon-owned half of one dormant installation and exits after one
/// founder client. Credential enrollment is intentionally a later catalog
/// transition.
pub fn serve_daemon_install(request_path: &Path) -> Result<InstallResult, InstallTransportError> {
    let daemon_uid = effective_uid();
    let request = read_install_request(request_path)?;
    validate_daemon_install_request(&request, daemon_uid)?;
    let founder = request
        .launch_policy
        .launchers
        .first()
        .ok_or(InstallTransportError::InvalidPeer)?;
    let founder_uid = founder.uid;
    let founder_gid = founder.gid;
    let founder_executable_digest =
        ExecutableDigest::from_sha256_hex(&founder.executable.digest_sha256)
            .map_err(|_| InstallTransportError::InsecureInput)?;
    let client_gid = request.launch_policy.client_gid;
    let founder_key = request.founder_key.clone();
    let root = request.state_directory.clone();
    let socket_path = root.join(INSTALL_SOCKET_FILE);

    let (listener, mut socket_guard) =
        bind_install_socket(&root, &socket_path, daemon_uid, client_gid)?;
    let (mut stream, _) = listener.accept()?;
    let io_deadline = deadline_after(INSTALL_IO_TIMEOUT)?;
    let peer = identity::peer_identity(&stream)?;
    if !founder_peer_is_authorized(&peer, founder_uid, founder_gid, founder_executable_digest) {
        return Err(InstallTransportError::InvalidPeer);
    }

    write_frame(
        &mut stream,
        &FounderRequestWire {
            schema: FOUNDER_REQUEST_SCHEMA.to_owned(),
            founder_key,
        },
        io_deadline,
    )?;
    let founder: FounderResponseWire = read_frame(&mut stream, io_deadline)?;
    require_schema(&founder.schema, FOUNDER_RESPONSE_SCHEMA)?;
    let founder_public_key: [u8; 65] = decode_base64(&founder.founder_public_key_base64)?
        .try_into()
        .map_err(|_| InstallTransportError::MalformedFrame)?;
    let prepared = daemon_prepare_dormant_install(request, founder_public_key)?;

    write_frame(
        &mut stream,
        &IntentMessageWire {
            schema: INTENT_SCHEMA.to_owned(),
            intent_base64: BASE64.encode(prepared.intent().canonical_bytes()?),
        },
        io_deadline,
    )?;
    let proof: ProofMessageWire = read_frame(&mut stream, io_deadline)?;
    require_schema(&proof.schema, PROOF_SCHEMA)?;
    let proof = Zeroizing::new(decode_base64(&proof.proof_base64)?);
    let result = prepared.accept_founder_proof(&proof)?;
    socket_guard.mark_activated();
    write_frame(
        &mut stream,
        &ResultMessageWire {
            schema: RESULT_SCHEMA.to_owned(),
            result: result.clone(),
        },
        io_deadline,
    )?;
    Ok(result)
}

/// Runs the logged-in founder half. It enrolls or looks up the fixed
/// founder-presence key, signs the daemon-issued installation intent, and
/// receives no Credential material.
pub fn perform_cli_install(socket_path: &Path) -> Result<InstallResult, InstallTransportError> {
    let caller_uid = effective_uid();
    let expected_executable_digest = current_executable_digest()?;
    let socket_before = validate_install_socket_path(socket_path, caller_uid)?;
    let mut stream = UnixStream::connect(socket_path)?;
    let io_deadline = deadline_after(INSTALL_IO_TIMEOUT)?;
    let socket_after = validate_install_socket_path(socket_path, caller_uid)?;
    if socket_before != socket_after {
        return Err(InstallTransportError::InsecureSocket);
    }
    let peer = identity::peer_identity(&stream)?;
    if !daemon_peer_is_authorized(&peer, socket_before, expected_executable_digest) {
        return Err(InstallTransportError::InvalidPeer);
    }

    let request: FounderRequestWire = read_frame(&mut stream, io_deadline)?;
    require_schema(&request.schema, FOUNDER_REQUEST_SCHEMA)?;
    let founder_public_key = founder_public_key(&request.founder_key)?;
    write_frame(
        &mut stream,
        &FounderResponseWire {
            schema: FOUNDER_RESPONSE_SCHEMA.to_owned(),
            founder_public_key_base64: BASE64.encode(&founder_public_key),
        },
        io_deadline,
    )?;

    let intent: IntentMessageWire = read_frame(&mut stream, io_deadline)?;
    require_schema(&intent.schema, INTENT_SCHEMA)?;
    let intent_bytes = decode_base64(&intent.intent_base64)?;
    let intent = IssuedInstallationIntent::from_canonical(&intent_bytes)?;
    let proof = sign_installation_intent(&intent, &founder_public_key)?;
    write_frame(
        &mut stream,
        &ProofMessageWire {
            schema: PROOF_SCHEMA.to_owned(),
            proof_base64: BASE64.encode(proof.as_bytes()),
        },
        io_deadline,
    )?;

    let result: ResultMessageWire = read_frame(&mut stream, io_deadline)?;
    require_schema(&result.schema, RESULT_SCHEMA)?;
    Ok(result.result)
}

fn founder_public_key(
    input: &FounderKeyInput,
) -> Result<Zeroizing<Vec<u8>>, InstallTransportError> {
    match input {
        FounderKeyInput::Enroll { policy } => {
            let enrollment = enroll_founder_presence_key((*policy).into())?;
            Ok(Zeroizing::new(enrollment.public_key_sec1().to_vec()))
        }
        FounderKeyInput::Lookup { public_key_path } => {
            let public_key = read_founder_private_file(public_key_path, 65)?;
            lookup_founder_presence_key(&public_key)?;
            Ok(public_key)
        }
    }
}

fn bind_install_socket(
    root: &Path,
    socket_path: &Path,
    daemon_uid: u32,
    client_gid: u32,
) -> Result<(UnixListener, SocketGuard), InstallTransportError> {
    bind_install_socket_with(root, socket_path, daemon_uid, client_gid, |socket_path| {
        identity::set_socket_owner(socket_path, daemon_uid, client_gid)?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
        Ok(())
    })
}

fn bind_install_socket_with(
    root: &Path,
    socket_path: &Path,
    daemon_uid: u32,
    client_gid: u32,
    setup_socket: impl FnOnce(&Path) -> Result<(), InstallTransportError>,
) -> Result<(UnixListener, SocketGuard), InstallTransportError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.uid() != daemon_uid
        || root_metadata.mode() & 0o7777 != 0o700
    {
        return Err(InstallTransportError::InsecureSocket);
    }
    match fs::symlink_metadata(socket_path) {
        Ok(_) => return Err(InstallTransportError::InsecureSocket),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let guard = SocketGuard::new(socket_path.to_owned(), root.to_owned());
    identity::set_socket_owner(root, daemon_uid, client_gid)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o710))?;
    let listener = UnixListener::bind(socket_path)?;
    let bound = socket_node_identity(socket_path)?;
    setup_socket(socket_path)?;
    let configured = fs::symlink_metadata(socket_path)?;
    let configured_node = socket_node_identity(socket_path)?;
    let configured_root = fs::symlink_metadata(root)?;
    if bound != configured_node
        || configured.uid() != daemon_uid
        || configured.gid() != client_gid
        || configured.mode() & 0o7777 != 0o660
        || configured_root.uid() != daemon_uid
        || configured_root.gid() != client_gid
        || configured_root.mode() & 0o7777 != 0o710
    {
        return Err(InstallTransportError::InsecureSocket);
    }
    Ok((listener, guard))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstallSocketIdentity {
    node: SocketNodeIdentity,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketNodeIdentity {
    device: u64,
    inode: u64,
}

fn socket_node_identity(path: &Path) -> Result<SocketNodeIdentity, InstallTransportError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(InstallTransportError::InsecureSocket);
    }
    Ok(SocketNodeIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_install_socket_path(
    path: &Path,
    caller_uid: u32,
) -> Result<InstallSocketIdentity, InstallTransportError> {
    let socket = match fs::symlink_metadata(path) {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(InstallTransportError::InsecureSocket);
        }
        Err(error) => return Err(error.into()),
    };
    if !socket.file_type().is_socket()
        || socket.mode() & 0o7777 != 0o660
        || socket.uid() == caller_uid
    {
        return Err(InstallTransportError::InsecureSocket);
    }
    let expected = authority_state_directory(socket.uid())?.join(INSTALL_SOCKET_FILE);
    if path != expected {
        return Err(InstallTransportError::InsecureSocket);
    }
    let parent = path.parent().ok_or(InstallTransportError::InsecureSocket)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != socket.uid()
        || metadata.gid() != socket.gid()
        || metadata.mode() & 0o7777 != 0o710
    {
        return Err(InstallTransportError::InsecureSocket);
    }
    Ok(InstallSocketIdentity {
        node: socket_node_identity(path)?,
        uid: socket.uid(),
        gid: socket.gid(),
    })
}

fn current_executable_digest() -> Result<ExecutableDigest, InstallTransportError> {
    let (probe, _peer) = UnixStream::pair()?;
    Ok(identity::peer_identity(&probe)?.executable_digest())
}

fn founder_peer_is_authorized(
    peer: &PeerIdentity,
    founder_uid: u32,
    founder_gid: u32,
    founder_executable_digest: ExecutableDigest,
) -> bool {
    peer.euid() == founder_uid
        && peer.egid() == founder_gid
        && peer.executable_digest() == founder_executable_digest
}

fn daemon_peer_is_authorized(
    peer: &PeerIdentity,
    socket: InstallSocketIdentity,
    expected_executable_digest: ExecutableDigest,
) -> bool {
    peer.euid() == socket.uid
        && peer.euid() != effective_uid()
        && peer.executable_digest() == expected_executable_digest
}

fn read_founder_private_file(
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, InstallTransportError> {
    let owner_uid = effective_uid();
    validate_private_path(path, owner_uid, max_bytes)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = validate_open_private_file(&file, owner_uid, max_bytes)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(InstallTransportError::FrameTooLarge);
    }
    Ok(bytes)
}

fn validate_private_path(
    path: &Path,
    owner_uid: u32,
    max_bytes: u64,
) -> Result<(), InstallTransportError> {
    if !path.is_absolute() {
        return Err(InstallTransportError::InsecureInput);
    }
    let parent = path.parent().ok_or(InstallTransportError::InsecureInput)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != owner_uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(InstallTransportError::InsecureInput);
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(InstallTransportError::InsecureInput);
    }
    Ok(())
}

fn validate_open_private_file(
    file: &File,
    owner_uid: u32,
    max_bytes: u64,
) -> Result<fs::Metadata, InstallTransportError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() > max_bytes
    {
        return Err(InstallTransportError::InsecureInput);
    }
    Ok(metadata)
}

fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<(), InstallTransportError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| InstallTransportError::MalformedFrame)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(InstallTransportError::FrameTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| InstallTransportError::FrameTooLarge)?;
    let mut writer = DeadlineWriter::until(stream, deadline)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<T: DeserializeOwned + Serialize>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T, InstallTransportError> {
    let mut reader = DeadlineReader::until(stream, deadline)?;
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(InstallTransportError::FrameTooLarge);
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    let value =
        serde_json::from_slice(&bytes).map_err(|_| InstallTransportError::MalformedFrame)?;
    if serde_jcs::to_vec(&value).map_err(|_| InstallTransportError::MalformedFrame)? != bytes {
        bytes.zeroize();
        return Err(InstallTransportError::NonCanonicalFrame);
    }
    bytes.zeroize();
    Ok(value)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, InstallTransportError> {
    BASE64
        .decode(value)
        .map_err(|_| InstallTransportError::MalformedFrame)
}

fn require_schema(actual: &str, expected: &str) -> Result<(), InstallTransportError> {
    if actual == expected {
        Ok(())
    } else {
        Err(InstallTransportError::UnexpectedMessage)
    }
}

struct SocketGuard {
    socket: PathBuf,
    root: PathBuf,
    activated: bool,
}

impl SocketGuard {
    fn new(socket: PathBuf, root: PathBuf) -> Self {
        Self {
            socket,
            root,
            activated: false,
        }
    }

    fn mark_activated(&mut self) {
        self.activated = true;
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        if !self.activated {
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
    }
}

#[derive(Debug, Error)]
pub enum InstallTransportError {
    #[error("installation peer identity is not authorized")]
    InvalidPeer,
    #[error("installation socket path, ownership, or mode is insecure")]
    InsecureSocket,
    #[error("installation input path, ownership, or mode is insecure")]
    InsecureInput,
    #[error("installation protocol frame exceeds its fixed limit")]
    FrameTooLarge,
    #[error("installation protocol frame is malformed")]
    MalformedFrame,
    #[error("installation protocol frame is not strict RFC 8785 JSON")]
    NonCanonicalFrame,
    #[error("installation protocol message schema or order is invalid")]
    UnexpectedMessage,
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error(transparent)]
    Presence(#[from] PresenceError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::symlink, net::UnixStream};

    fn write_raw(stream: &mut UnixStream, bytes: &[u8]) {
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(bytes).unwrap();
    }

    fn peer(uid: u32, gid: u32, digest: [u8; 32]) -> PeerIdentity {
        PeerIdentity::observed(1, 1, uid, gid, PathBuf::from("/tmp/peer"), digest).unwrap()
    }

    #[test]
    fn rejects_noncanonical_protocol_frame() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let bytes = br#"{ "schema":"ember.install-founder-response/v2","founder_public_key_base64":"AA==" }"#;
        write_raw(&mut writer, bytes);
        let error = read_frame::<FounderResponseWire>(
            &mut reader,
            deadline_after(INSTALL_IO_TIMEOUT).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallTransportError::NonCanonicalFrame));
    }

    #[test]
    fn rejects_unknown_protocol_field() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let bytes = br#"{"founder_public_key_base64":"AA==","schema":"ember.install-founder-response/v2","unexpected":true}"#;
        write_raw(&mut writer, bytes);
        let error = read_frame::<FounderResponseWire>(
            &mut reader,
            deadline_after(INSTALL_IO_TIMEOUT).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallTransportError::MalformedFrame));
    }

    #[test]
    fn rejects_oversized_protocol_frame_before_payload_read() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .unwrap();
        let error = read_frame::<FounderResponseWire>(
            &mut reader,
            deadline_after(INSTALL_IO_TIMEOUT).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallTransportError::FrameTooLarge));
    }

    #[test]
    fn partial_install_frame_is_bounded_by_one_absolute_deadline() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&16_u32.to_be_bytes()).unwrap();
        writer.write_all(b"{").unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        let started = Instant::now();

        let error = read_frame::<FounderResponseWire>(&mut reader, deadline).unwrap_err();

        assert!(matches!(error, InstallTransportError::Io(_)));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn rejects_non_system_install_socket() {
        let path = tempfile::tempdir()
            .unwrap()
            .path()
            .join(INSTALL_SOCKET_FILE);
        let error = validate_install_socket_path(&path, effective_uid()).unwrap_err();
        assert!(matches!(error, InstallTransportError::InsecureSocket));
    }

    #[test]
    fn install_peers_require_split_uids_and_exact_reviewed_executables() {
        let caller_uid = effective_uid();
        let daemon_uid = caller_uid.checked_add(1).unwrap();
        let digest = ExecutableDigest::from_sha256([7; 32]);
        let socket = InstallSocketIdentity {
            node: SocketNodeIdentity {
                device: 1,
                inode: 2,
            },
            uid: daemon_uid,
            gid: 42,
        };
        let daemon = peer(daemon_uid, 99, [7; 32]);
        assert!(daemon_peer_is_authorized(&daemon, socket, digest));
        assert!(!daemon_peer_is_authorized(
            &peer(caller_uid, 99, [7; 32]),
            InstallSocketIdentity {
                uid: caller_uid,
                ..socket
            },
            digest,
        ));
        assert!(!daemon_peer_is_authorized(
            &peer(daemon_uid, 99, [8; 32]),
            socket,
            digest,
        ));

        let founder = peer(caller_uid, 20, [7; 32]);
        assert!(founder_peer_is_authorized(&founder, caller_uid, 20, digest));
        assert!(!founder_peer_is_authorized(
            &peer(caller_uid, 20, [8; 32]),
            caller_uid,
            20,
            digest,
        ));
    }

    #[test]
    fn founder_key_file_must_be_owner_private_and_not_symlinked() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = directory.path().join("founder-public-key");
        fs::write(&key, [7_u8; 65]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            read_founder_private_file(&key, 65).unwrap().as_slice(),
            &[7_u8; 65]
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o440)).unwrap();
        let error = read_founder_private_file(&key, 65).unwrap_err();
        assert!(matches!(error, InstallTransportError::InsecureInput));

        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        let alias = directory.path().join("founder-public-key-alias");
        symlink(&key, &alias).unwrap();
        let error = read_founder_private_file(&alias, 65).unwrap_err();
        assert!(matches!(error, InstallTransportError::InsecureInput));
    }
    #[test]
    fn failed_install_restores_private_root_and_removes_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join(INSTALL_SOCKET_FILE);
        File::create(&socket).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710)).unwrap();
        {
            let _guard = SocketGuard::new(socket.clone(), directory.path().to_owned());
        }
        assert!(!socket.exists());
        assert_eq!(
            fs::metadata(directory.path()).unwrap().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn post_bind_setup_failure_removes_socket_and_restores_private_root() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::symlink_metadata(directory.path()).unwrap();
        let socket = directory.path().join(INSTALL_SOCKET_FILE);

        let error = match bind_install_socket_with(
            directory.path(),
            &socket,
            metadata.uid(),
            metadata.gid(),
            |_| {
                Err(InstallTransportError::Io(io::Error::other(
                    "injected post-bind setup failure",
                )))
            },
        ) {
            Ok(_) => panic!("injected post-bind setup failure unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(error, InstallTransportError::Io(_)));
        assert!(!socket.exists());
        assert_eq!(
            fs::symlink_metadata(directory.path()).unwrap().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn post_bind_verifies_configured_socket_identity() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::symlink_metadata(directory.path()).unwrap();
        let socket = directory.path().join(INSTALL_SOCKET_FILE);

        let error = match bind_install_socket_with(
            directory.path(),
            &socket,
            metadata.uid(),
            metadata.gid(),
            |path| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                Ok(())
            },
        ) {
            Ok(_) => panic!("insecure post-bind socket unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(error, InstallTransportError::InsecureSocket));
        assert!(!socket.exists());
        assert_eq!(
            fs::symlink_metadata(directory.path()).unwrap().mode() & 0o7777,
            0o700
        );
    }
}
