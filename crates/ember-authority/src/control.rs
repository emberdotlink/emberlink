use crate::{
    audit::{EvidenceJournal, EvidenceLinks, JournalError, JournalTransaction, PrimaryEvidence},
    custody::{
        CUSTODY_UNLOCK_CHALLENGE_BYTES, CustodyContext, DaemonWrapKey, DoubleEnvelope,
        SealedUnlockChallenge, daemon_open_inner, daemon_seal_unlock_challenge,
    },
    host::{DeadlineReader, DeadlineWriter, HostRuntime, PeerIdentity, deadline_from},
    identity,
    model::{
        AuditFact, DelegationId, EventKind, EvidenceId, GrantId, JournalSequence,
        OperationEvidenceRef, OperationId,
    },
    principal::ExecutableDigest,
    provider::{
        AdapterError, AdapterMint, GithubAppAdapter, GithubTokenRevoker, MintRequest,
        ProviderAdapter,
    },
    session_supervisor::SessionSupervisor,
    sha256_hex,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const CONTROL_REQUEST_SCHEMA: &str = "ember.control-request/v2";
pub const CONTROL_RESPONSE_SCHEMA: &str = "ember.control-response/v1";
pub const MAX_CONTROL_FRAME_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub schema: String,
    pub request_id: String,
    pub operation: ControlOperation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlOperation {
    Status,
    CustodyUnlockBegin,
    CustodyUnlockComplete {
        unlock_id: String,
        decrypted_challenge_base64: String,
        relayed_inner_base64: String,
    },
    GrantRevoke {
        grant_id: String,
    },
    DelegationRevoke {
        delegation_id: String,
    },
}
impl ControlOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::CustodyUnlockBegin => "custody_unlock_begin",
            Self::CustodyUnlockComplete { .. } => "custody_unlock_complete",
            Self::GrantRevoke { .. } => "grant_revoke",
            Self::DelegationRevoke { .. } => "delegation_revoke",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub schema: String,
    pub request_id: String,
    pub result: ControlResult,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ControlResult {
    Success { ok: bool, result: Value },
    Error { ok: bool, error: ControlWireError },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlWireError {
    pub code: String,
    pub message: String,
}

#[derive(Clone)]
pub(crate) struct LauncherPolicy {
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) executable_digest: ExecutableDigest,
}
#[derive(Clone)]
pub(crate) struct GithubCoordinates {
    pub(crate) app_slug: String,
    pub(crate) app_id: u64,
    pub(crate) installation_id: u64,
}

pub(crate) struct LockableGithubProvider {
    adapter: Mutex<Option<GithubAppAdapter>>,
    revoker: GithubTokenRevoker,
}
impl LockableGithubProvider {
    pub(crate) fn locked(revoker: GithubTokenRevoker) -> Self {
        Self {
            adapter: Mutex::new(None),
            revoker,
        }
    }
    pub(crate) fn is_locked(&self) -> bool {
        self.adapter.lock().map_or(true, |v| v.is_none())
    }
    pub(crate) fn unlock(&self, adapter: GithubAppAdapter) -> Result<(), ControlError> {
        *self
            .adapter
            .lock()
            .map_err(|_| ControlError::ProviderState)? = Some(adapter);
        Ok(())
    }
    pub(crate) fn lock(&self) -> Result<(), ControlError> {
        *self
            .adapter
            .lock()
            .map_err(|_| ControlError::ProviderState)? = None;
        Ok(())
    }
}
impl ProviderAdapter for LockableGithubProvider {
    fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
        self.adapter
            .lock()
            .map_err(|_| AdapterError::new("provider custody is unavailable"))?
            .as_ref()
            .ok_or_else(|| AdapterError::new("provider custody is locked"))?
            .mint(request)
    }
    fn revoke(&self, token: &str) -> Result<(), AdapterError> {
        self.revoker.revoke(token)
    }
}

struct DispatchSuccess {
    value: Value,
    rollback: Option<MutationRollback>,
}

impl DispatchSuccess {
    fn read_only(value: Value) -> Self {
        Self {
            value,
            rollback: None,
        }
    }

    fn mutated(value: Value, rollback: MutationRollback) -> Self {
        Self {
            value,
            rollback: Some(rollback),
        }
    }
}

fn control_decision_data(
    request_id: &OperationId,
    operation: &str,
    result: &Result<DispatchSuccess, ControlError>,
) -> Value {
    json!({
        "request_id": request_id.as_str(),
        "operation": operation,
        "allowed": result.is_ok(),
        "code": result.as_ref().err().map(ControlError::code),
    })
}

enum MutationRollback {
    CustodyUnlock,
    DiscardCustodyUnlock(Uuid),
}

impl MutationRollback {
    fn apply(
        self,
        control: &ControlRuntime,
        _runtime: &mut HostRuntime,
    ) -> Result<(), ControlError> {
        match self {
            Self::CustodyUnlock => control.provider.lock(),
            Self::DiscardCustodyUnlock(unlock_id) => {
                let mut pending = control
                    .pending_custody_unlock
                    .lock()
                    .map_err(|_| ControlError::ProviderState)?;
                if pending
                    .as_ref()
                    .is_some_and(|attempt| attempt.unlock_id == unlock_id)
                {
                    *pending = None;
                }
                Ok(())
            }
        }
    }
}

fn apply_rollback_or_fail_stop(
    rollback: MutationRollback,
    control: &ControlRuntime,
    runtime: &mut HostRuntime,
) -> Result<(), ControlError> {
    rollback
        .apply(control, runtime)
        .map_err(|_| ControlError::RollbackFailed)
}

const CUSTODY_UNLOCK_PENDING_TTL: Duration = Duration::from_secs(120);

struct PendingCustodyUnlock {
    unlock_id: Uuid,
    challenge: Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>,
    expires_at: Instant,
    peer_pid: u32,
    peer_pid_version: u64,
    peer_euid: u32,
    peer_egid: u32,
    peer_executable_digest: ExecutableDigest,
}

impl PendingCustodyUnlock {
    fn new(
        unlock_id: Uuid,
        challenge: Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>,
        peer: &PeerIdentity,
    ) -> Self {
        Self {
            unlock_id,
            challenge,
            expires_at: Instant::now() + CUSTODY_UNLOCK_PENDING_TTL,
            peer_pid: peer.pid(),
            peer_pid_version: peer.pid_version(),
            peer_euid: peer.euid(),
            peer_egid: peer.egid(),
            peer_executable_digest: peer.executable_digest(),
        }
    }

    fn matches_peer(&self, peer: &PeerIdentity) -> bool {
        self.peer_pid == peer.pid()
            && self.peer_pid_version == peer.pid_version()
            && self.peer_euid == peer.euid()
            && self.peer_egid == peer.egid()
            && self.peer_executable_digest == peer.executable_digest()
    }
}
pub(crate) struct ControlRuntime {
    io_timeout: Duration,
    journal: Arc<EvidenceJournal>,
    launchers: Vec<LauncherPolicy>,
    sealed_envelope: Vec<u8>,
    custody_context: CustodyContext,
    daemon_wrap_key: DaemonWrapKey,
    github: GithubCoordinates,
    provider: Arc<LockableGithubProvider>,
    pending_custody_unlock: Mutex<Option<PendingCustodyUnlock>>,
    #[cfg(test)]
    audit_fail_after: Mutex<Option<usize>>,
}

impl ControlRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        io_timeout: Duration,
        journal: Arc<EvidenceJournal>,
        launchers: Vec<LauncherPolicy>,
        sealed_envelope: Vec<u8>,
        custody_context: CustodyContext,
        daemon_wrap_key: DaemonWrapKey,
        github: GithubCoordinates,
        provider: Arc<LockableGithubProvider>,
    ) -> Result<Self, ControlError> {
        let runtime = Self {
            io_timeout,
            journal,
            launchers,
            sealed_envelope,
            custody_context,
            daemon_wrap_key,
            github,
            provider,
            pending_custody_unlock: Mutex::new(None),
            #[cfg(test)]
            audit_fail_after: Mutex::new(None),
        };
        Ok(runtime)
    }
    pub(crate) fn relock(&self) -> Result<(), ControlError> {
        self.provider.lock()
    }
    fn append_audit(
        &self,
        operation_id: &OperationId,
        at_unix: i64,
        kind: &'static str,
        data: Value,
    ) -> Result<(), ()> {
        #[cfg(test)]
        {
            let mut fail_after = self.audit_fail_after.lock().map_err(|_| ())?;
            if let Some(remaining) = fail_after.as_mut() {
                if *remaining == 0 {
                    return Err(());
                }
                *remaining -= 1;
            }
        }
        self.journal
            .commit_with_sequence(|sequence| {
                let event = match kind {
                    "control.attempt" => EventKind::OperationAdmitted,
                    "control.decision" | "control.presence_orphan_discard" => {
                        EventKind::ControlRequestDecided
                    }
                    _ => {
                        return Err(JournalError::InvalidPreparedEvidence(
                            "unknown control audit kind".to_owned(),
                        ));
                    }
                };
                let mut digest = sha2::Sha256::new();
                use sha2::Digest as _;
                digest.update(b"ember.control-journal.transaction/v1\0");
                digest.update(operation_id.as_str().as_bytes());
                digest.update(sequence.to_be_bytes());
                let operation = event
                    .requires_operation()
                    .then(|| OperationEvidenceRef::operation(operation_id.clone()));
                let fact = AuditFact::new(
                    EvidenceId::from_bytes(digest.clone().finalize().into()),
                    JournalSequence::new(sequence).ok_or(JournalError::SequenceOverflow)?,
                    event,
                    operation,
                )
                .map_err(|error| JournalError::InvalidPreparedEvidence(error.to_string()))?;
                let mut transaction = JournalTransaction::new(digest.finalize().into());
                transaction.push_evidence(
                    PrimaryEvidence::audit_fact(
                        &fact,
                        EvidenceLinks {
                            operation_id: event.requires_operation().then(|| operation_id.clone()),
                            ..EvidenceLinks::default()
                        },
                    )?,
                    None,
                );
                let attribution = serde_json::json!({
                    "at_unix": at_unix,
                    "data": data,
                    "kind": kind,
                    "operation_id": operation_id.as_str(),
                });
                transaction.put_state(
                    format!("control/audit/{sequence:020}"),
                    serde_jcs::to_vec(&attribution).map_err(JournalError::Canonicalize)?,
                );
                Ok(transaction)
            })
            .map(|_| ())
            .map_err(|_| ())
    }

    #[cfg(test)]
    fn fail_audit_after(&self, successful_appends: usize) {
        if let Ok(mut fail_after) = self.audit_fail_after.lock() {
            *fail_after = Some(successful_appends);
        }
    }

    pub(crate) fn handle_connection(
        &self,
        mut stream: UnixStream,
        peer: PeerIdentity,
        runtime: &mut HostRuntime,
        supervisor: &mut SessionSupervisor,
        accepted_at: Instant,
    ) -> Result<(), ControlError> {
        let transaction_deadline = deadline_from(accepted_at, self.io_timeout)?;
        let request = {
            let mut reader = DeadlineReader::until(&mut stream, transaction_deadline)?;
            read_request(&mut reader)?
        };
        let request_id = parse_operation_id(&request.request_id)?;
        let audit_operation_id = OperationId::new();
        let name = request.operation.name();
        let mutation = !matches!(&request.operation, ControlOperation::Status);
        let decision_at_unix = unix_now()?;
        if mutation
            && self
                .append_audit(
                    &audit_operation_id,
                    decision_at_unix,
                    "control.attempt",
                    json!({
                        "request_id": request_id.as_str(),
                        "operation": name,
                        "peer_pid": peer.pid(),
                        "peer_pid_version": peer.pid_version(),
                        "peer_euid": peer.euid(),
                        "peer_egid": peer.egid(),
                        "peer_executable_digest": peer.executable_digest().to_sha256_hex(),
                    }),
                )
                .is_err()
        {
            return write_error(
                &mut stream,
                transaction_deadline,
                request_id.as_str(),
                "audit_unavailable",
                "control attempt could not be recorded",
            );
        }
        let result = peer
            .revalidate(&stream)
            .map_err(|_| ControlError::PeerChanged)
            .and_then(|current| self.dispatch(request.operation, &current, runtime, supervisor));
        let decided_at_unix = unix_now()?;
        let mut decision = control_decision_data(&request_id, name, &result);
        let Value::Object(decision_fields) = &mut decision else {
            return Err(ControlError::Malformed);
        };
        decision_fields.insert(
            "peer".to_owned(),
            json!({
                "pid": peer.pid(),
                "pid_version": peer.pid_version(),
                "euid": peer.euid(),
                "egid": peer.egid(),
                "executable_digest": peer.executable_digest().to_sha256_hex(),
            }),
        );
        if mutation
            && self
                .append_audit(
                    &audit_operation_id,
                    decided_at_unix,
                    "control.decision",
                    decision,
                )
                .is_err()
        {
            match result {
                Ok(success) => {
                    if let Some(rollback) = success.rollback {
                        apply_rollback_or_fail_stop(rollback, self, runtime)?;
                    }
                }
                Err(error) if error.is_fatal() => return Err(error),
                Err(_) => {}
            }
            return write_error(
                &mut stream,
                transaction_deadline,
                request_id.as_str(),
                "audit_unavailable",
                "control decision could not be recorded",
            );
        }
        match result {
            Ok(success) => write_success(
                &mut stream,
                transaction_deadline,
                request_id.as_str(),
                success.value,
            ),
            Err(error) if error.is_fatal() => Err(error),
            Err(error) => write_error(
                &mut stream,
                transaction_deadline,
                request_id.as_str(),
                error.code(),
                error.public_message(),
            ),
        }
    }
    fn dispatch(
        &self,
        operation: ControlOperation,
        peer: &PeerIdentity,
        runtime: &mut HostRuntime,
        supervisor: &mut SessionSupervisor,
    ) -> Result<DispatchSuccess, ControlError> {
        match operation {
            ControlOperation::Status => Ok(DispatchSuccess::read_only(
                json!({"custody":if self.provider.is_locked(){"locked"}else{"unlocked"},"pending_sessions":supervisor.pending_count(),"active_sessions":supervisor.active_count()}),
            )),
            ControlOperation::CustodyUnlockBegin => {
                self.require_launcher(peer)?;
                {
                    let mut pending = self
                        .pending_custody_unlock
                        .lock()
                        .map_err(|_| ControlError::ProviderState)?;
                    if let Some(attempt) = pending.as_ref() {
                        if Instant::now() >= attempt.expires_at {
                            *pending = None;
                        } else if !attempt.matches_peer(peer) {
                            return Err(ControlError::CustodyUnlockPending);
                        }
                    }
                }
                let envelope =
                    DoubleEnvelope::decode(&self.sealed_envelope, &self.custody_context)?;
                let SealedUnlockChallenge {
                    unlock_id,
                    challenge,
                    ciphertext: encrypted_challenge,
                } = daemon_seal_unlock_challenge(&envelope, &self.custody_context)?;
                *self
                    .pending_custody_unlock
                    .lock()
                    .map_err(|_| ControlError::ProviderState)? =
                    Some(PendingCustodyUnlock::new(unlock_id, challenge, peer));
                Ok(DispatchSuccess::mutated(
                    json!({
                        "sealed_envelope_base64": BASE64.encode(&self.sealed_envelope),
                        "custody_context": &self.custody_context,
                        "unlock_id": unlock_id.to_string(),
                        "encrypted_challenge_base64": BASE64.encode(encrypted_challenge),
                    }),
                    MutationRollback::DiscardCustodyUnlock(unlock_id),
                ))
            }
            ControlOperation::CustodyUnlockComplete {
                unlock_id,
                decrypted_challenge_base64,
                relayed_inner_base64,
            } => {
                self.require_launcher(peer)?;
                let presented_unlock_id =
                    Uuid::parse_str(&unlock_id).map_err(|_| ControlError::InvalidRequest)?;
                if presented_unlock_id.is_nil() || unlock_id != presented_unlock_id.to_string() {
                    return Err(ControlError::InvalidRequest);
                }
                let pending = {
                    let mut pending = self
                        .pending_custody_unlock
                        .lock()
                        .map_err(|_| ControlError::ProviderState)?;
                    let attempt = pending.as_ref().ok_or(ControlError::InvalidRequest)?;
                    if Instant::now() >= attempt.expires_at {
                        *pending = None;
                        return Err(ControlError::InvalidRequest);
                    }
                    if presented_unlock_id != attempt.unlock_id {
                        return Err(ControlError::InvalidRequest);
                    }
                    pending.take().ok_or(ControlError::InvalidRequest)?
                };
                if !pending.matches_peer(peer) {
                    return Err(ControlError::InvalidRequest);
                }
                let decrypted_challenge_base64 = Zeroizing::new(decrypted_challenge_base64);
                let presented_challenge = decode_base64_challenge(&decrypted_challenge_base64)?;
                if !challenges_match(&pending.challenge, &presented_challenge) {
                    return Err(ControlError::InvalidRequest);
                }
                let envelope =
                    DoubleEnvelope::decode(&self.sealed_envelope, &self.custody_context)?;
                let relayed_inner_base64 = Zeroizing::new(relayed_inner_base64);
                let relayed_inner = Zeroizing::new(decode_base64(relayed_inner_base64.as_str())?);
                if sha256_hex(relayed_inner.as_slice()) != envelope.inner_envelope_sha256() {
                    return Err(crate::custody::CustodyError::MixedEnvelope.into());
                }
                let private_key =
                    daemon_open_inner(relayed_inner, &self.daemon_wrap_key, &self.custody_context)?;
                let adapter = GithubAppAdapter::new(
                    self.github.app_slug.clone(),
                    self.github.app_id,
                    self.github.installation_id,
                    &private_key,
                )?;
                self.provider.unlock(adapter)?;
                drop(private_key);
                Ok(DispatchSuccess::mutated(
                    json!({"custody":"unlocked"}),
                    MutationRollback::CustodyUnlock,
                ))
            }
            ControlOperation::GrantRevoke { grant_id } => {
                self.require_launcher(peer)?;
                runtime
                    .revoke_grant(&parse_grant_id(&grant_id)?)
                    .map_err(|_| ControlError::Authority)?;
                Ok(DispatchSuccess::read_only(json!({"revoked":true})))
            }
            ControlOperation::DelegationRevoke { delegation_id } => {
                self.require_launcher(peer)?;
                runtime
                    .revoke_delegation(&parse_delegation_id(&delegation_id)?)
                    .map_err(|_| ControlError::Authority)?;
                Ok(DispatchSuccess::read_only(json!({"revoked":true})))
            }
        }
    }
    fn require_launcher(&self, peer: &PeerIdentity) -> Result<(), ControlError> {
        self.launchers
            .iter()
            .any(|p| {
                p.euid == peer.euid()
                    && p.egid == peer.egid()
                    && p.executable_digest == peer.executable_digest()
            })
            .then_some(())
            .ok_or(ControlError::LauncherAdmission)
    }
}

pub struct ControlClient {
    socket: PathBuf,
    io_timeout: Duration,
    expected_executable_digest: ExecutableDigest,
}
impl ControlClient {
    /// Creates a client that accepts only the caller's platform-reviewed
    /// executable identity.
    ///
    /// The shipped authority CLI and daemon are modes of the same binary. A
    /// listener from any other executable is rejected before request bytes are
    /// sent, even when it runs as the same user.
    pub fn new(socket: impl Into<PathBuf>) -> Result<Self, ControlError> {
        let (probe, _peer) = UnixStream::pair()?;
        let current =
            identity::peer_identity(&probe).map_err(|_| ControlError::DaemonAuthentication)?;
        Ok(Self {
            socket: socket.into(),
            io_timeout: Duration::from_secs(30),
            expected_executable_digest: current.executable_digest(),
        })
    }
    pub fn request(&self, operation: ControlOperation) -> Result<ControlResponse, ControlError> {
        let request = ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: uuid::Uuid::new_v4().to_string(),
            operation,
        };
        let bytes = serde_jcs::to_vec(&request).map_err(|_| ControlError::Encoding)?;
        if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME_BYTES as usize {
            return Err(ControlError::FrameSize);
        }
        let socket_before = control_socket_identity(&self.socket)?;
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(self.io_timeout))?;
        stream.set_write_timeout(Some(self.io_timeout))?;
        let socket_after = control_socket_identity(&self.socket)?;
        if socket_before != socket_after {
            return Err(ControlError::DaemonAuthentication);
        }
        self.authenticate_daemon(&stream, socket_before)?;
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let response = read_frame(&mut stream)?;
        let value: Value =
            serde_json::from_slice(&response).map_err(|_| ControlError::Malformed)?;
        if serde_jcs::to_vec(&value).map_err(|_| ControlError::Malformed)? != response {
            return Err(ControlError::NonCanonical);
        }
        let response: ControlResponse =
            serde_json::from_value(value).map_err(|_| ControlError::Malformed)?;
        if response.schema != CONTROL_RESPONSE_SCHEMA || response.request_id != request.request_id {
            return Err(ControlError::Schema);
        }
        Ok(response)
    }

    fn authenticate_daemon(
        &self,
        stream: &UnixStream,
        socket: ControlSocketIdentity,
    ) -> Result<(), ControlError> {
        let observed =
            identity::peer_identity(stream).map_err(|_| ControlError::DaemonAuthentication)?;
        if observed.euid() != socket.uid
            || observed.egid() != socket.gid
            || observed.executable_digest() != self.expected_executable_digest
        {
            return Err(ControlError::DaemonAuthentication);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ControlSocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}

fn control_socket_identity(path: &Path) -> Result<ControlSocketIdentity, ControlError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.mode() & 0o777 != 0o660 {
        return Err(ControlError::DaemonAuthentication);
    }
    Ok(ControlSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}
fn read_request(stream: &mut impl Read) -> Result<ControlRequest, ControlError> {
    let bytes = Zeroizing::new(read_frame(stream)?);
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(ControlError::TrailingFrame);
    }
    let request: ControlRequest =
        serde_json::from_slice(&bytes).map_err(|_| ControlError::Malformed)?;
    let canonical =
        Zeroizing::new(serde_jcs::to_vec(&request).map_err(|_| ControlError::Malformed)?);
    if canonical.as_slice() != bytes.as_slice() {
        return Err(ControlError::NonCanonical);
    }
    if request.schema != CONTROL_REQUEST_SCHEMA {
        return Err(ControlError::Schema);
    }
    parse_operation_id(&request.request_id)?;
    Ok(request)
}
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ControlError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length);
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlError::FrameSize);
    }
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_success(
    stream: &mut UnixStream,
    deadline: Instant,
    id: &str,
    result: Value,
) -> Result<(), ControlError> {
    let mut writer = DeadlineWriter::until(stream, deadline)?;
    write_response(
        &mut writer,
        &ControlResponse {
            schema: CONTROL_RESPONSE_SCHEMA.to_owned(),
            request_id: id.to_owned(),
            result: ControlResult::Success { ok: true, result },
        },
    )
}
fn write_error(
    stream: &mut UnixStream,
    deadline: Instant,
    id: &str,
    code: &str,
    message: &str,
) -> Result<(), ControlError> {
    let mut writer = DeadlineWriter::until(stream, deadline)?;
    write_response(
        &mut writer,
        &ControlResponse {
            schema: CONTROL_RESPONSE_SCHEMA.to_owned(),
            request_id: id.to_owned(),
            result: ControlResult::Error {
                ok: false,
                error: ControlWireError {
                    code: code.to_owned(),
                    message: message.to_owned(),
                },
            },
        },
    )
}
fn write_response(s: &mut impl Write, r: &ControlResponse) -> Result<(), ControlError> {
    let bytes = serde_jcs::to_vec(r).map_err(|_| ControlError::Encoding)?;
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::Encoding)?;
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlError::FrameSize);
    }
    s.write_all(&length.to_be_bytes())?;
    s.write_all(&bytes)?;
    s.flush()?;
    Ok(())
}
fn validate_uuid(v: &str) -> Result<(), ControlError> {
    let id = uuid::Uuid::parse_str(v).map_err(|_| ControlError::InvalidRequest)?;
    if id.is_nil() || id.to_string() != v {
        return Err(ControlError::InvalidRequest);
    }
    Ok(())
}
fn parse_operation_id(v: &str) -> Result<OperationId, ControlError> {
    validate_uuid(v)?;
    Ok(OperationId(v.to_owned()))
}
fn parse_grant_id(v: &str) -> Result<GrantId, ControlError> {
    validate_uuid(v)?;
    Ok(GrantId(v.to_owned()))
}
fn parse_delegation_id(v: &str) -> Result<DelegationId, ControlError> {
    validate_uuid(v)?;
    Ok(DelegationId(v.to_owned()))
}
fn decode_base64(v: &str) -> Result<Vec<u8>, ControlError> {
    let bytes = BASE64.decode(v).map_err(|_| ControlError::InvalidRequest)?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME_BYTES as usize {
        return Err(ControlError::FrameSize);
    }
    Ok(bytes)
}

fn decode_base64_challenge(
    value: &str,
) -> Result<Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>, ControlError> {
    let decoded = Zeroizing::new(
        BASE64
            .decode(value)
            .map_err(|_| ControlError::InvalidRequest)?,
    );
    if decoded.len() != CUSTODY_UNLOCK_CHALLENGE_BYTES {
        return Err(ControlError::InvalidRequest);
    }
    let mut challenge = Zeroizing::new([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]);
    challenge.copy_from_slice(&decoded);
    Ok(challenge)
}

fn challenges_match(
    expected: &[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES],
    presented: &[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES],
) -> bool {
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
fn unix_now() -> Result<i64, ControlError> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ControlError::Clock)?;
    i64::try_from(d.as_secs()).map_err(|_| ControlError::Clock)
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control transport failed")]
    Io(#[from] io::Error),
    #[error("invalid frame size")]
    FrameSize,
    #[error("malformed control frame")]
    Malformed,
    #[error("noncanonical control frame")]
    NonCanonical,
    #[error("unsupported control schema")]
    Schema,
    #[error("trailing control frame")]
    TrailingFrame,
    #[error("invalid control request")]
    InvalidRequest,
    #[error("custody unlock already pending")]
    CustodyUnlockPending,
    #[error("launcher refused")]
    LauncherAdmission,
    #[error("control peer changed after connect")]
    PeerChanged,
    #[error("control daemon identity does not match the authority CLI")]
    DaemonAuthentication,
    #[error("mutation rollback failed; daemon must stop")]
    RollbackFailed,
    #[error("authority refused")]
    Authority,
    #[error("provider state unavailable")]
    ProviderState,
    #[error("response encoding failed")]
    Encoding,
    #[error("clock unavailable")]
    Clock,
    #[error("custody refused")]
    Custody(#[from] crate::custody::CustodyError),
    #[error("provider refused")]
    Provider(#[from] AdapterError),
}
impl ControlError {
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(self, Self::RollbackFailed)
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Io(_) | Self::Encoding | Self::Clock | Self::ProviderState => {
                "service_unavailable"
            }
            Self::FrameSize => "frame_too_large",
            Self::Malformed | Self::NonCanonical | Self::TrailingFrame | Self::InvalidRequest => {
                "invalid_request"
            }
            Self::CustodyUnlockPending => "custody_unlock_pending",
            Self::PeerChanged | Self::DaemonAuthentication => "admission_refused",
            Self::Schema => "unsupported_schema",
            Self::LauncherAdmission => "launcher_refused",
            Self::RollbackFailed => "session_refused",
            Self::Authority => "authority_refused",
            Self::Custody(_) | Self::Provider(_) => "custody_refused",
        }
    }
    fn public_message(&self) -> &'static str {
        match self.code() {
            "service_unavailable" => "control service is unavailable",
            "frame_too_large" => "control frame exceeds the byte limit",
            "invalid_request" => "control request is invalid",
            "unsupported_schema" => "control schema is unsupported",
            "custody_unlock_pending" => "another custody unlock is already pending",
            "launcher_refused" => "launcher admission was refused",
            "session_policy_refused" => "reviewed Session policy was refused",
            "session_refused" => "Session transition was refused",
            "authority_refused" => "authority transition was refused",
            "custody_refused" => "custody unlock was refused",
            _ => "control request was refused",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead as _, BufReader, Write as _},
        os::unix::{
            fs::{MetadataExt as _, PermissionsExt as _},
            net::{UnixListener, UnixStream},
        },
        path::Path,
        process::{Command, Stdio},
        thread,
    };

    use super::*;
    use crate::{
        artifact::ArtifactStore,
        audit::test_evidence_context,
        custody::{
            CUSTODY_KEY_LABEL, CustodyError, CustodyPurpose, DOUBLE_ENVELOPE_SCHEMA,
            INNER_ENVELOPE_ALGORITHM, OUTER_ENVELOPE_ALGORITHM,
        },
        kernel::AuthorityKernel,
        pack::PackRegistry,
        principal::PersonaAuthority,
        provider::ProviderRegistry,
        recovery::RecoveryJournal,
        runner::RunnerRegistry,
    };

    fn read_test_request(
        payload: &[u8],
        declared_length: u32,
        trailing: &[u8],
    ) -> Result<ControlRequest, ControlError> {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&declared_length.to_be_bytes()).unwrap();
        writer.write_all(payload).unwrap();
        writer.write_all(trailing).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        read_request(&mut reader)
    }

    fn canonical_status_request() -> Vec<u8> {
        serde_jcs::to_vec(&ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: uuid::Uuid::new_v4().to_string(),
            operation: ControlOperation::Status,
        })
        .unwrap()
    }

    fn control_runtime(root: &Path, launchers: Vec<LauncherPolicy>) -> ControlRuntime {
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
        let sealed_envelope = serde_jcs::to_vec(&json!({
            "schema": DOUBLE_ENVELOPE_SCHEMA,
            "outer_algorithm": OUTER_ENVELOPE_ALGORITHM,
            "inner_algorithm": INNER_ENVELOPE_ALGORITHM,
            "key_label": CUSTODY_KEY_LABEL,
            "context": &custody_context,
            "inner_envelope_sha256": sha256_hex(b"captured-inner"),
            "public_key_sec1_hex": hex::encode(public_key.as_bytes()),
            "ciphertext_hex": "00",
        }))
        .unwrap();
        let (journal, _, _) = test_evidence_context(root.join("control-audit")).unwrap();
        journal.recover_startup().unwrap();
        ControlRuntime::new(
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
            Arc::new(LockableGithubProvider::locked(GithubTokenRevoker::new())),
        )
        .unwrap()
    }

    fn host_runtime(root: &Path) -> HostRuntime {
        host_runtime_with_authority(root, PersonaAuthority::new())
    }

    fn host_runtime_with_authority(root: &Path, authority: PersonaAuthority) -> HostRuntime {
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
        HostRuntime::new(kernel, 1024, 1024, Duration::from_secs(1)).unwrap()
    }

    fn peer(euid: u32, egid: u32, digest: u8) -> PeerIdentity {
        peer_process(1, 1, euid, egid, digest)
    }

    fn peer_process(pid: u32, pid_version: u64, euid: u32, egid: u32, digest: u8) -> PeerIdentity {
        PeerIdentity::observed(
            pid,
            pid_version,
            euid,
            egid,
            PathBuf::from("/test/launcher"),
            [digest; 32],
        )
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn begin_unlock(
        runtime: &ControlRuntime,
        peer: &PeerIdentity,
        host: &mut HostRuntime,
        supervisor: &mut SessionSupervisor,
    ) -> (String, Zeroizing<[u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]>) {
        let success = runtime
            .dispatch(ControlOperation::CustodyUnlockBegin, peer, host, supervisor)
            .unwrap();
        let unlock_id = success
            .value
            .get("unlock_id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let pending = match runtime.pending_custody_unlock.lock() {
            Ok(pending) => pending,
            Err(_) => panic!("pending custody mutex poisoned"),
        };
        let pending = pending.as_ref().unwrap();
        assert_eq!(pending.unlock_id.to_string(), unlock_id);
        let mut challenge = Zeroizing::new([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]);
        challenge.copy_from_slice(&*pending.challenge);
        (unlock_id, challenge)
    }

    #[test]
    fn request_framing_rejects_malformed_oversized_trailing_and_noncanonical_frames() {
        assert!(matches!(
            read_test_request(b"{", 1, &[]),
            Err(ControlError::Malformed)
        ));
        assert!(matches!(
            read_test_request(&[], MAX_CONTROL_FRAME_BYTES + 1, &[]),
            Err(ControlError::FrameSize)
        ));

        let canonical = canonical_status_request();
        assert!(matches!(
            read_test_request(&canonical, canonical.len() as u32, b"x"),
            Err(ControlError::TrailingFrame)
        ));

        let mut noncanonical = vec![b' '];
        noncanonical.extend_from_slice(&canonical);
        assert!(matches!(
            read_test_request(&noncanonical, noncanonical.len() as u32, &[]),
            Err(ControlError::NonCanonical)
        ));
    }
    #[test]
    fn stalled_control_response_write_obeys_the_transaction_deadline() {
        let (_client, mut server) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        let started = Instant::now();

        let error = write_success(
            &mut server,
            deadline,
            OperationId::new().as_str(),
            json!({"payload": "x".repeat(900 * 1024)}),
        )
        .unwrap_err();

        assert!(matches!(error, ControlError::Io(_)));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn launcher_admission_binds_euid_egid_and_executable_digest() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: 501,
                egid: 20,
                executable_digest: ExecutableDigest::from_sha256([9_u8; 32]),
            }],
        );

        assert!(runtime.require_launcher(&peer(501, 20, 9)).is_ok());
        for refused in [peer(502, 20, 9), peer(501, 21, 9), peer(501, 20, 10)] {
            assert!(matches!(
                runtime.require_launcher(&refused),
                Err(ControlError::LauncherAdmission)
            ));
        }

        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let refused = peer(502, 20, 9);
        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockBegin,
                &refused,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::LauncherAdmission)
        ));
        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: Uuid::new_v4().to_string(),
                    decrypted_challenge_base64: BASE64
                        .encode([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]),
                    relayed_inner_base64: "not-base64".to_owned(),
                },
                &refused,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::LauncherAdmission)
        ));
    }

    #[test]
    fn custody_unlock_complete_without_begin_fails_before_inner_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer(501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();

        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: Uuid::new_v4().to_string(),
                    decrypted_challenge_base64: BASE64
                        .encode([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]),
                    relayed_inner_base64: "not-base64".to_owned(),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::InvalidRequest)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_wrong_challenge_consumes_attempt_before_inner_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer(501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let (unlock_id, challenge) = begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);
        let mut wrong_challenge = Zeroizing::new([0_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES]);
        wrong_challenge.copy_from_slice(&*challenge);
        wrong_challenge[0] ^= 1;

        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: unlock_id.clone(),
                    decrypted_challenge_base64: BASE64.encode(wrong_challenge.as_slice()),
                    relayed_inner_base64: "not-base64".to_owned(),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::InvalidRequest)
        ));
        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id,
                    decrypted_challenge_base64: BASE64.encode(challenge.as_slice()),
                    relayed_inner_base64: BASE64.encode(b"captured-inner"),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::InvalidRequest)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_replay_fails_after_matching_attempt_reaches_inner_parser() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer(501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let (unlock_id, challenge) = begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);
        let complete = || ControlOperation::CustodyUnlockComplete {
            unlock_id: unlock_id.clone(),
            decrypted_challenge_base64: BASE64.encode(challenge.as_slice()),
            relayed_inner_base64: BASE64.encode(b"captured-inner"),
        };

        assert!(matches!(
            runtime.dispatch(complete(), &admitted, &mut host, &mut supervisor,),
            Err(ControlError::Custody(CustodyError::MalformedEnvelope))
        ));
        assert!(matches!(
            runtime.dispatch(complete(), &admitted, &mut host, &mut supervisor,),
            Err(ControlError::InvalidRequest)
        ));
    }

    #[test]
    fn custody_unlock_rejects_inner_not_committed_by_persisted_envelope() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer(501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let unlock_id = Uuid::new_v4();
        let challenge = [7_u8; CUSTODY_UNLOCK_CHALLENGE_BYTES];
        let mut pending = match runtime.pending_custody_unlock.lock() {
            Ok(pending) => pending,
            Err(_) => panic!("pending custody mutex poisoned"),
        };
        *pending = Some(PendingCustodyUnlock::new(
            unlock_id,
            Zeroizing::new(challenge),
            &admitted,
        ));
        drop(pending);

        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: unlock_id.to_string(),
                    decrypted_challenge_base64: BASE64.encode(challenge),
                    relayed_inner_base64: BASE64.encode(b"substituted-inner"),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::Custody(CustodyError::MixedEnvelope))
        ));
        assert!(runtime.provider.is_locked());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_peer_mismatch_consumes_attempt_for_all_process_coordinates() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer_process(1, 1, 501, 20, 9);
        let mismatches = [
            peer_process(2, 1, 501, 20, 9),
            peer_process(1, 2, 501, 20, 9),
            peer_process(1, 1, 502, 20, 9),
            peer_process(1, 1, 501, 21, 9),
            peer_process(1, 1, 501, 20, 10),
        ];
        let mut launchers = vec![LauncherPolicy {
            euid: admitted.euid(),
            egid: admitted.egid(),
            executable_digest: admitted.executable_digest(),
        }];
        launchers.extend(mismatches.iter().map(|candidate| LauncherPolicy {
            euid: candidate.euid(),
            egid: candidate.egid(),
            executable_digest: candidate.executable_digest(),
        }));
        let runtime = control_runtime(temp.path(), launchers);
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();

        for mismatch in mismatches {
            let (unlock_id, challenge) =
                begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);
            assert!(matches!(
                runtime.dispatch(
                    ControlOperation::CustodyUnlockComplete {
                        unlock_id: unlock_id.clone(),
                        decrypted_challenge_base64: BASE64.encode(challenge.as_slice()),
                        relayed_inner_base64: BASE64.encode(b"captured-inner"),
                    },
                    &mismatch,
                    &mut host,
                    &mut supervisor,
                ),
                Err(ControlError::InvalidRequest)
            ));
            assert!(matches!(
                runtime.dispatch(
                    ControlOperation::CustodyUnlockComplete {
                        unlock_id,
                        decrypted_challenge_base64: BASE64.encode(challenge.as_slice()),
                        relayed_inner_base64: BASE64.encode(b"captured-inner"),
                    },
                    &admitted,
                    &mut host,
                    &mut supervisor,
                ),
                Err(ControlError::InvalidRequest)
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_stale_completion_preserves_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer(501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let (old_id, old_challenge) = begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);
        let (new_id, new_challenge) = begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);

        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: old_id,
                    decrypted_challenge_base64: BASE64.encode(old_challenge.as_slice()),
                    relayed_inner_base64: BASE64.encode(b"captured-inner"),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::InvalidRequest)
        ));
        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id: new_id,
                    decrypted_challenge_base64: BASE64.encode(new_challenge.as_slice()),
                    relayed_inner_base64: BASE64.encode(b"captured-inner"),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::Custody(CustodyError::MalformedEnvelope))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_other_peer_cannot_replace_pending_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let admitted = peer_process(1, 1, 501, 20, 9);
        let rival = peer_process(2, 1, 501, 20, 9);
        let runtime = control_runtime(
            temp.path(),
            vec![
                LauncherPolicy {
                    euid: admitted.euid(),
                    egid: admitted.egid(),
                    executable_digest: admitted.executable_digest(),
                },
                LauncherPolicy {
                    euid: rival.euid(),
                    egid: rival.egid(),
                    executable_digest: rival.executable_digest(),
                },
            ],
        );
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let (unlock_id, challenge) = begin_unlock(&runtime, &admitted, &mut host, &mut supervisor);

        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockBegin,
                &rival,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::CustodyUnlockPending)
        ));
        assert!(matches!(
            runtime.dispatch(
                ControlOperation::CustodyUnlockComplete {
                    unlock_id,
                    decrypted_challenge_base64: BASE64.encode(challenge.as_slice()),
                    relayed_inner_base64: BASE64.encode(b"captured-inner"),
                },
                &admitted,
                &mut host,
                &mut supervisor,
            ),
            Err(ControlError::Custody(CustodyError::MalformedEnvelope))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn custody_unlock_begin_is_disarmed_when_decision_audit_fails() {
        let temp = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let pid_version = crate::identity::process_pid_version(pid).unwrap();
        let admitted = crate::identity::observed_process(pid, pid_version).unwrap();
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: admitted.euid(),
                egid: admitted.egid(),
                executable_digest: admitted.executable_digest(),
            }],
        );
        runtime.fail_audit_after(1);
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let request = serde_jcs::to_vec(&ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: OperationId::new().to_string(),
            operation: ControlOperation::CustodyUnlockBegin,
        })
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        client.write_all(&request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        runtime
            .handle_connection(server, admitted, &mut host, &mut supervisor, Instant::now())
            .unwrap();
        let response: ControlResponse =
            serde_json::from_slice(&read_frame(&mut client).unwrap()).unwrap();

        assert!(matches!(
            response.result,
            ControlResult::Error {
                error: ControlWireError { ref code, .. },
                ..
            } if code == "audit_unavailable"
        ));
        assert!(runtime.pending_custody_unlock.lock().unwrap().is_none());
    }

    #[test]
    fn deescalation_operations_require_launcher_admission() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = control_runtime(
            temp.path(),
            vec![LauncherPolicy {
                euid: 501,
                egid: 20,
                executable_digest: ExecutableDigest::from_sha256([9_u8; 32]),
            }],
        );
        let refused = peer(502, 20, 9);
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();

        for operation in [
            ControlOperation::GrantRevoke {
                grant_id: GrantId::new().to_string(),
            },
            ControlOperation::DelegationRevoke {
                delegation_id: DelegationId::new().to_string(),
            },
        ] {
            assert!(matches!(
                runtime.dispatch(operation, &refused, &mut host, &mut supervisor,),
                Err(ControlError::LauncherAdmission)
            ));
        }
    }

    #[test]
    fn control_client_accepts_the_current_authority_executable() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let daemon = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream).unwrap();
            write_response(
                &mut stream,
                &ControlResponse {
                    schema: CONTROL_RESPONSE_SCHEMA.to_owned(),
                    request_id: request.request_id,
                    result: ControlResult::Success {
                        ok: true,
                        result: json!({"status":"ready"}),
                    },
                },
            )
            .unwrap();
        });

        let response = ControlClient::new(&socket)
            .unwrap()
            .request(ControlOperation::Status)
            .unwrap();
        assert!(matches!(
            response.result,
            ControlResult::Success {
                ok: true,
                result
            } if result == json!({"status":"ready"})
        ));
        daemon.join().unwrap();
    }

    #[test]
    fn control_client_rejects_a_replaced_listener_before_sending_request() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let script = r#"
import os
import socket
import sys

listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o660)
listener.listen(1)
print("ready", flush=True)
connection, _ = listener.accept()
print(len(connection.recv(1)), flush=True)
"#;
        let mut child = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(script)
            .arg(&socket)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");

        let client = ControlClient::new(&socket).unwrap();
        assert!(matches!(
            client.request(ControlOperation::Status),
            Err(ControlError::DaemonAuthentication)
        ));

        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "0\n");
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn caller_request_id_cannot_select_control_audit_stream() {
        let temp = tempfile::tempdir().unwrap();
        let audit_root = temp.path().join("control-audit");
        let runtime = control_runtime(temp.path(), Vec::new());
        let mut host = host_runtime(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let mut supervisor =
            SessionSupervisor::new(temp.path().join("sessions"), metadata.uid(), metadata.gid())
                .unwrap();
        let request_id = OperationId::new();
        let request = serde_jcs::to_vec(&ControlRequest {
            schema: CONTROL_REQUEST_SCHEMA.to_owned(),
            request_id: request_id.to_string(),
            operation: ControlOperation::GrantRevoke {
                grant_id: GrantId::new().to_string(),
            },
        })
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        client.write_all(&request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        runtime
            .handle_connection(
                server,
                peer(501, 20, 9),
                &mut host,
                &mut supervisor,
                Instant::now(),
            )
            .unwrap();

        let (journal, _, _) = test_evidence_context(&audit_root).unwrap();
        let snapshot = journal.verified_snapshot().unwrap();
        assert!(!snapshot.records().is_empty());
        assert!(
            snapshot
                .records()
                .iter()
                .all(|record| { record.links().operation_id.as_ref() != Some(&request_id) })
        );
    }
}
