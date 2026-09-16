use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    AuthorityKernel,
    artifact::{ArtifactError, ImportedArtifact},
    host_client::{
        SESSION_REQUEST_SCHEMA, SessionErrorResponse, SessionRequest, SessionResultResponse,
        SessionWireError,
    },
    identity,
    model::{
        ACTION_REQUEST_SCHEMA, DelegationId, GrantId, OperationResult, ProcessBindingId, SessionId,
    },
    principal::{ExecutableDigest, ProcessOrigin, ProcessRegistrationChallenge, ReconnectProof},
};
pub const ABSOLUTE_MAX_HEADER_BYTES: u32 = 1024 * 1024;
pub const ABSOLUTE_MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const SESSION_INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_ARTIFACT_INGRESS_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024;

pub(crate) struct DeadlineReader<'a> {
    inner: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    pub(crate) fn new(inner: &'a mut UnixStream, timeout: Duration) -> io::Result<Self> {
        Self::until(inner, deadline_after(timeout)?)
    }

    pub(crate) fn until(inner: &'a mut UnixStream, deadline: Instant) -> io::Result<Self> {
        deadline_remaining(deadline, "read")?;
        Ok(Self { inner, deadline })
    }

    pub(crate) fn reset(&mut self, timeout: Duration) -> io::Result<()> {
        self.deadline = deadline_after(timeout)?;
        Ok(())
    }

    pub(crate) fn stream(&self) -> &UnixStream {
        self.inner
    }

    fn remaining(&self) -> io::Result<Duration> {
        deadline_remaining(self.deadline, "read")
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.set_read_timeout(Some(self.remaining()?))?;
        self.inner.read(buffer)
    }
}

pub(crate) struct DeadlineWriter<'a> {
    inner: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineWriter<'a> {
    pub(crate) fn new(inner: &'a mut UnixStream, timeout: Duration) -> io::Result<Self> {
        Self::until(inner, deadline_after(timeout)?)
    }

    pub(crate) fn until(inner: &'a mut UnixStream, deadline: Instant) -> io::Result<Self> {
        deadline_remaining(deadline, "write")?;
        Ok(Self { inner, deadline })
    }

    fn remaining(&self) -> io::Result<Duration> {
        deadline_remaining(self.deadline, "write")
    }
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.set_write_timeout(Some(self.remaining()?))?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.set_write_timeout(Some(self.remaining()?))?;
        self.inner.flush()
    }
}

pub(crate) fn deadline_after(timeout: Duration) -> io::Result<Instant> {
    deadline_from(Instant::now(), timeout)
}

pub(crate) fn deadline_from(start: Instant, timeout: Duration) -> io::Result<Instant> {
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deadline must be positive",
        ));
    }
    start
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))
}

fn deadline_remaining(deadline: Instant, phase: &str) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, format!("{phase} deadline elapsed")))
}

fn artifact_ingress_timeout(base: Duration, artifact_length: u64) -> io::Result<Duration> {
    let transfer_seconds = artifact_length.div_ceil(MIN_ARTIFACT_INGRESS_BYTES_PER_SECOND);
    base.checked_add(Duration::from_secs(transfer_seconds))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "artifact deadline overflow"))
}

/// Identity measured from the accepted Unix socket by the daemon platform
/// adapter. None of these values are deserializable from the execution wire.
pub struct PeerIdentity {
    pid: u32,
    pid_version: u64,
    euid: u32,
    egid: u32,
    executable_path: PathBuf,
    executable_digest: ExecutableDigest,
}

impl PeerIdentity {
    pub(crate) fn observed(
        pid: u32,
        pid_version: u64,
        euid: u32,
        egid: u32,
        executable_path: PathBuf,
        executable_digest: [u8; 32],
    ) -> Result<Self, HostError> {
        if pid == 0 || pid_version == 0 || !executable_path.is_absolute() {
            return Err(HostError::PeerIdentity);
        }
        Ok(Self {
            pid,
            pid_version,
            euid,
            egid,
            executable_path,
            executable_digest: ExecutableDigest::from_sha256(executable_digest),
        })
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn pid_version(&self) -> u64 {
        self.pid_version
    }

    pub fn euid(&self) -> u32 {
        self.euid
    }

    pub(crate) fn egid(&self) -> u32 {
        self.egid
    }

    pub fn executable_digest(&self) -> ExecutableDigest {
        self.executable_digest
    }

    pub(crate) fn revalidate(&self, stream: &UnixStream) -> Result<Self, HostError> {
        let observed = identity::peer_identity(stream).map_err(|_| HostError::PeerIdentity)?;
        if observed.pid != self.pid
            || observed.pid_version != self.pid_version
            || observed.euid != self.euid
            || observed.egid != self.egid
            || observed.executable_path != self.executable_path
            || observed.executable_digest != self.executable_digest
        {
            return Err(HostError::PeerIdentity);
        }
        Ok(observed)
    }

    fn process_origin(&self) -> Result<ProcessOrigin, HostError> {
        ProcessOrigin::new(
            self.pid,
            self.pid_version,
            self.euid,
            self.egid,
            self.executable_digest,
        )
        .map_err(|_| HostError::PeerIdentity)
    }
}

/// Session-scoped action runtime. Listener creation and Session endpoint
/// lifecycle remain daemon responsibilities; the public control socket must
/// never dispatch connections here.
pub struct HostRuntime {
    kernel: AuthorityKernel,
    max_header_bytes: u32,
    max_artifact_bytes: u64,
    io_timeout: Duration,
    #[cfg(test)]
    fail_end_session_origin_once: bool,
    #[cfg(test)]
    fail_artifact_ingress_deadline_once: bool,
}

impl HostRuntime {
    pub fn new(
        kernel: AuthorityKernel,
        max_header_bytes: u32,
        max_artifact_bytes: u64,
        io_timeout: Duration,
    ) -> Result<Self, HostError> {
        if max_header_bytes == 0
            || max_header_bytes > ABSOLUTE_MAX_HEADER_BYTES
            || max_artifact_bytes > ABSOLUTE_MAX_ARTIFACT_BYTES
            || io_timeout.is_zero()
        {
            return Err(HostError::InvalidRuntimeConfiguration);
        }
        Ok(Self {
            kernel,
            max_header_bytes,
            max_artifact_bytes,
            io_timeout,
            #[cfg(test)]
            fail_end_session_origin_once: false,
            #[cfg(test)]
            fail_artifact_ingress_deadline_once: false,
        })
    }
    #[cfg(test)]
    pub(crate) fn create_session(
        &mut self,
        persona: &crate::model::PersonaId,
        reviewed_executable: ExecutableDigest,
    ) -> Result<(SessionId, ProcessRegistrationChallenge), HostError> {
        Ok(self.kernel.create_session(persona, reviewed_executable)?)
    }

    pub(crate) fn bind_session_origin(
        &mut self,
        session: &SessionId,
        challenge: &ProcessRegistrationChallenge,
        observed: &PeerIdentity,
    ) -> Result<ProcessBindingId, HostError> {
        Ok(self
            .kernel
            .bind_session_origin(session, challenge, observed.process_origin()?)?)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_end_session_origin(&mut self) {
        self.fail_end_session_origin_once = true;
    }

    #[cfg(test)]
    fn fail_next_artifact_ingress_deadline(&mut self) {
        self.fail_artifact_ingress_deadline_once = true;
    }

    pub(crate) fn end_session_origin(
        &mut self,
        binding: &ProcessBindingId,
    ) -> Result<(), HostError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_end_session_origin_once) {
            return Err(HostError::PeerIdentity);
        }
        Ok(self.kernel.end_session_origin(binding)?)
    }
    pub(crate) fn end_session(&mut self, session: &SessionId) -> Result<(), HostError> {
        Ok(self.kernel.end_session(session)?)
    }

    pub(crate) fn revoke_grant(&mut self, grant: &GrantId) -> Result<(), HostError> {
        Ok(self.kernel.revoke_grant(grant)?)
    }
    pub(crate) fn revoke_delegation(&mut self, delegation: &DelegationId) -> Result<(), HostError> {
        Ok(self.kernel.revoke_delegation(delegation)?)
    }

    /// Processes exactly one action request on an accepted Session-scoped
    /// endpoint and writes exactly one response. The caller must have derived
    /// `peer` from this accepted socket and supplied the immutable selectors
    /// pinned to the endpoint when it was created.
    pub fn handle_session_connection(
        &mut self,
        mut stream: UnixStream,
        peer: PeerIdentity,
        expected_session: &SessionId,
        expected_process_binding: &ProcessBindingId,
        mut authorize: impl FnMut() -> bool,
    ) -> Result<(), HostError> {
        let transaction = {
            let mut reader = DeadlineReader::new(&mut stream, SESSION_INITIAL_READ_TIMEOUT)?;
            match self.transact(
                &mut reader,
                &peer,
                expected_session,
                expected_process_binding,
                &mut authorize,
            ) {
                Ok(transaction) => transaction,
                Err(error) => TransactionResult {
                    outcome: Err(error),
                    cleanup_error: None,
                    reconnect_proof: None,
                },
            }
        };

        let mut writer = DeadlineWriter::new(&mut stream, self.io_timeout)?;
        respond_transaction(transaction, |outcome, reconnect_proof| match outcome {
            Ok(result) => write_result(&mut writer, &result, reconnect_proof),
            Err(error) => write_error(
                &mut writer,
                error.code(),
                error.public_message(),
                reconnect_proof,
            ),
        })
    }

    /// Sends a sanitized rejection when platform identity derivation fails.
    pub fn reject_unidentified(mut stream: UnixStream) -> Result<(), HostError> {
        write_error(
            &mut stream,
            "peer_identity_unavailable",
            "peer identity is unavailable",
            None,
        )
    }

    fn transact(
        &mut self,
        stream: &mut DeadlineReader<'_>,
        peer: &PeerIdentity,
        expected_session: &SessionId,
        expected_process_binding: &ProcessBindingId,
        authorize: &mut impl FnMut() -> bool,
    ) -> Result<TransactionResult<OperationResult>, RequestError> {
        let header_length = read_u32(stream).map_err(|_| RequestError::MalformedFrame)?;
        stream
            .reset(self.io_timeout)
            .map_err(|_| RequestError::MalformedFrame)?;
        if header_length == 0 || header_length > self.max_header_bytes {
            return Err(RequestError::OversizeHeader);
        }
        let mut header = Zeroizing::new(vec![0_u8; header_length as usize]);
        stream
            .read_exact(&mut header)
            .map_err(|_| RequestError::MalformedFrame)?;
        let mut envelope: SessionRequest =
            serde_json::from_slice(&header).map_err(|_| RequestError::MalformedRequest)?;
        if envelope.schema != SESSION_REQUEST_SCHEMA
            || envelope.request.schema != ACTION_REQUEST_SCHEMA
        {
            return Err(RequestError::UnknownSchema);
        }
        if envelope.artifact_length > self.max_artifact_bytes {
            return Err(RequestError::OversizeArtifact);
        }
        validate_action_input(&envelope.request.input)?;
        if !matches!(
            envelope.request.submission_id,
            Some(submission_id) if submission_id.as_bytes().iter().any(|byte| *byte != 0)
        ) {
            return Err(RequestError::MalformedRequest);
        }
        let reconnect_proof = envelope.reconnect_proof.map(ReconnectProof::from_bytes);
        let origin = peer
            .revalidate(stream.stream())
            .and_then(|observed| observed.process_origin())
            .map_err(|_| RequestError::SessionAdmission)?;
        let (context, issued_reconnect_proof) = self
            .kernel
            .connect_session(
                expected_session,
                expected_process_binding,
                &origin,
                reconnect_proof.as_ref(),
            )
            .map_err(|_| RequestError::SessionAdmission)?;
        let issued_reconnect_proof = issued_reconnect_proof.map(|proof| proof.expose_to_launcher());
        if !authorize() {
            return Ok(TransactionResult {
                outcome: Err(RequestError::SessionAdmission),
                cleanup_error: None,
                reconnect_proof: issued_reconnect_proof,
            });
        }

        let artifact = if envelope.request.action == crate::pack::GITHUB_PUBLISH_REF_ACTION {
            #[cfg(test)]
            let ingress_timeout = if std::mem::take(&mut self.fail_artifact_ingress_deadline_once) {
                Err(io::Error::other("injected artifact deadline failure"))
            } else {
                artifact_ingress_timeout(self.io_timeout, envelope.artifact_length)
            };
            #[cfg(not(test))]
            let ingress_timeout =
                artifact_ingress_timeout(self.io_timeout, envelope.artifact_length);
            let ingress_timeout = match ingress_timeout {
                Ok(timeout) => timeout,
                Err(_) => {
                    return Ok(artifact_ingress_refusal(issued_reconnect_proof));
                }
            };
            if stream.reset(ingress_timeout).is_err() {
                return Ok(artifact_ingress_refusal(issued_reconnect_proof));
            }
            match self
                .kernel
                .import_artifact(ExactReader::new(stream, envelope.artifact_length))
            {
                Ok(artifact) => Some(artifact),
                Err(_) => {
                    return Ok(artifact_ingress_refusal(issued_reconnect_proof));
                }
            }
        } else {
            if envelope.artifact_length != 0 {
                return Ok(TransactionResult {
                    outcome: Err(RequestError::ForbiddenInput),
                    cleanup_error: None,
                    reconnect_proof: issued_reconnect_proof,
                });
            }
            None
        };

        let outcome = (|| {
            // A request is one frame, not a stream of frames. Clients half-close
            // their write side after the declared artifact so trailing bytes and
            // delayed frame concatenation fail closed.
            let mut trailing = [0_u8; 1];
            match stream.read(&mut trailing) {
                Ok(0) => {}
                Ok(_) => return Err(RequestError::TrailingFrame),
                Err(_) => return Err(RequestError::MalformedFrame),
            }

            if let Some(artifact) = artifact.as_ref() {
                let input = envelope
                    .request
                    .input
                    .as_object_mut()
                    .ok_or(RequestError::ForbiddenInput)?;
                if input
                    .insert(
                        "artifact".to_owned(),
                        Value::String(artifact.artifact_ref().to_string()),
                    )
                    .is_some()
                {
                    return Err(RequestError::ForbiddenInput);
                }
            }
            let current_origin = peer
                .revalidate(stream.stream())
                .and_then(|observed| observed.process_origin())
                .map_err(|_| RequestError::SessionAdmission)?;
            if current_origin != origin || !authorize() {
                return Err(RequestError::SessionAdmission);
            }
            let wire = serde_json::to_vec(&envelope.request)
                .map_err(|_| RequestError::MalformedRequest)?;
            self.kernel
                .submit(
                    &context,
                    &wire,
                    unix_now().map_err(|_| RequestError::Clock)?,
                )
                .map_err(|_| RequestError::Operation)
        })();

        let mut transaction = finalize_artifact(artifact.as_ref(), outcome, |artifact| {
            self.kernel.cleanup_artifact(artifact)
        });
        transaction.reconnect_proof = issued_reconnect_proof;
        Ok(transaction)
    }
}

struct TransactionResult<T> {
    outcome: Result<T, RequestError>,
    cleanup_error: Option<ArtifactError>,
    reconnect_proof: Option<[u8; 32]>,
}

fn artifact_ingress_refusal<T>(reconnect_proof: Option<[u8; 32]>) -> TransactionResult<T> {
    TransactionResult {
        outcome: Err(RequestError::ArtifactIngress),
        cleanup_error: None,
        reconnect_proof,
    }
}

fn finalize_artifact<T>(
    artifact: Option<&ImportedArtifact>,
    outcome: Result<T, RequestError>,
    cleanup: impl FnOnce(&ImportedArtifact) -> Result<(), ArtifactError>,
) -> TransactionResult<T> {
    let cleanup_error = artifact.and_then(|artifact| cleanup(artifact).err());
    TransactionResult {
        outcome,
        cleanup_error,
        reconnect_proof: None,
    }
}

fn respond_transaction<T>(
    mut transaction: TransactionResult<T>,
    respond: impl FnOnce(Result<T, RequestError>, Option<[u8; 32]>) -> Result<(), HostError>,
) -> Result<(), HostError> {
    let mut reconnect_proof = transaction.reconnect_proof;
    let response = respond(transaction.outcome, reconnect_proof);
    if let Some(proof) = reconnect_proof.as_mut() {
        proof.zeroize();
    }
    if let Some(proof) = transaction.reconnect_proof.as_mut() {
        proof.zeroize();
    }
    response?;
    match transaction.cleanup_error {
        Some(error) => Err(HostError::ArtifactCleanup(error)),
        None => Ok(()),
    }
}

fn validate_action_input(value: &Value) -> Result<(), RequestError> {
    let object = value.as_object().ok_or(RequestError::ForbiddenInput)?;
    validate_value(object.values())?;
    for key in object.keys() {
        if is_forbidden_key(key) {
            return Err(RequestError::ForbiddenInput);
        }
    }
    Ok(())
}

fn validate_value<'a>(values: impl IntoIterator<Item = &'a Value>) -> Result<(), RequestError> {
    for value in values {
        match value {
            Value::String(text) if text.starts_with("artifact:sha256:") => {
                return Err(RequestError::ForbiddenInput);
            }
            Value::Object(object) => {
                if object.keys().any(|key| is_forbidden_key(key)) {
                    return Err(RequestError::ForbiddenInput);
                }
                validate_value(object.values())?;
            }
            Value::Array(values) => validate_value(values.iter())?,
            _ => {}
        }
    }
    Ok(())
}

fn is_forbidden_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    normalized.ends_with("path")
        || matches!(
            normalized.as_str(),
            "artifact"
                | "artifactref"
                | "authority"
                | "authorityscope"
                | "role"
                | "persona"
                | "personaid"
                | "executable"
                | "executabledigest"
                | "executablesha256"
                | "runner"
                | "helper"
                | "cwd"
                | "workingdirectory"
                | "socket"
                | "pid"
                | "pidversion"
                | "uid"
                | "gid"
                | "principal"
                | "principalid"
                | "binding"
                | "bindingid"
                | "processbinding"
                | "processbindingid"
                | "grant"
                | "grantid"
                | "delegation"
                | "delegationid"
                | "session"
                | "sessionid"
                | "lease"
                | "leaseid"
                | "provider"
                | "providerinstance"
                | "providerinstanceid"
                | "scope"
                | "scopes"
                | "permission"
                | "permissions"
                | "environment"
                | "env"
                | "delivery"
                | "deliverylane"
                | "deliverypolicy"
        )
}

struct ExactReader<'a, R> {
    inner: &'a mut R,
    remaining: u64,
}

impl<'a, R> ExactReader<'a, R> {
    fn new(inner: &'a mut R, remaining: u64) -> Self {
        Self { inner, remaining }
    }
}

impl<R: Read> Read for ExactReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = self.inner.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "artifact ended before its declared length",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn write_result(
    stream: &mut impl Write,
    result: &OperationResult,
    mut reconnect_proof: Option<[u8; 32]>,
) -> Result<(), HostError> {
    let response = SessionResultResponse::new(result.clone(), reconnect_proof);
    let written = write_response(stream, &response);
    drop(response);
    if let Some(proof) = reconnect_proof.as_mut() {
        proof.zeroize();
    }
    written
}

fn write_error(
    stream: &mut impl Write,
    code: &str,
    message: &str,
    mut reconnect_proof: Option<[u8; 32]>,
) -> Result<(), HostError> {
    let response = SessionErrorResponse::new(
        SessionWireError::new(code.to_owned(), message.to_owned()),
        reconnect_proof,
    );
    let written = write_response(stream, &response);
    drop(response);
    if let Some(proof) = reconnect_proof.as_mut() {
        proof.zeroize();
    }
    written
}

fn write_response(stream: &mut impl Write, response: &impl Serialize) -> Result<(), HostError> {
    let bytes =
        Zeroizing::new(serde_jcs::to_vec(response).map_err(|_| HostError::ResponseEncoding)?);
    let length = u32::try_from(bytes.len()).map_err(|_| HostError::ResponseEncoding)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn unix_now() -> Result<i64, HostError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Clock)?;
    i64::try_from(duration.as_secs()).map_err(|_| HostError::Clock)
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("invalid host runtime configuration")]
    InvalidRuntimeConfiguration,
    #[error("peer identity unavailable")]
    PeerIdentity,
    #[error("host clock unavailable")]
    Clock,
    #[error("response encoding failed")]
    ResponseEncoding,
    #[error("request artifact cleanup failed: {0}")]
    ArtifactCleanup(#[source] ArtifactError),
    #[error("authority lifecycle transition failed")]
    Authority(#[from] crate::SubmitError),
    #[error("host transport I/O failed")]
    Io(#[from] io::Error),
}
impl HostError {
    pub(crate) fn is_permanent_session_cleanup_failure(&self) -> bool {
        matches!(
            self,
            Self::Authority(crate::SubmitError::Authority(
                crate::principal::AuthorityError::UnknownSession
                    | crate::principal::AuthorityError::UnknownProcessBinding
            ))
        )
    }

    pub(crate) fn is_unknown_session(&self) -> bool {
        matches!(
            self,
            Self::Authority(crate::SubmitError::Authority(
                crate::principal::AuthorityError::UnknownSession
            ))
        )
    }

    pub(crate) fn is_reclaimed_session_bind_failure(&self) -> bool {
        matches!(
            self,
            Self::Authority(crate::SubmitError::Authority(
                crate::principal::AuthorityError::ProcessRegistrationChallengeMismatch
                    | crate::principal::AuthorityError::ExecutableDigestMismatch
                    | crate::principal::AuthorityError::ProcessBindingCapacityExceeded
            ))
        )
    }
}

#[derive(Debug)]
enum RequestError {
    MalformedFrame,
    OversizeHeader,
    MalformedRequest,
    UnknownSchema,
    OversizeArtifact,
    ForbiddenInput,
    ArtifactIngress,
    TrailingFrame,
    Clock,
    SessionAdmission,
    Operation,
}

impl RequestError {
    fn code(&self) -> &'static str {
        match self {
            Self::MalformedFrame => "malformed_frame",
            Self::OversizeHeader => "header_too_large",
            Self::MalformedRequest => "malformed_request",
            Self::UnknownSchema => "unknown_schema",
            Self::OversizeArtifact => "artifact_too_large",
            Self::ForbiddenInput => "forbidden_input",
            Self::ArtifactIngress => "artifact_ingress_failed",
            Self::TrailingFrame => "trailing_frame",
            Self::Clock => "clock_unavailable",
            Self::SessionAdmission => "session_refused",
            Self::Operation => "operation_failed",
        }
    }

    fn public_message(&self) -> &'static str {
        match self {
            Self::MalformedFrame => "request frame is malformed",
            Self::OversizeHeader => "request header exceeds the configured limit",
            Self::MalformedRequest => "request header is invalid",
            Self::UnknownSchema => "request schema is unsupported",
            Self::OversizeArtifact => "artifact exceeds the configured limit",
            Self::ForbiddenInput => "request input contains a daemon-owned coordinate",
            Self::ArtifactIngress => "artifact ingress failed",
            Self::TrailingFrame => "request contains trailing bytes",
            Self::Clock => "daemon clock is unavailable",
            Self::SessionAdmission => "session admission was refused",
            Self::Operation => "operation failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io::{Cursor, Read as _, Write as _},
        net::Shutdown,
        os::unix::net::UnixStream,
        thread,
    };

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        artifact::ArtifactStore,
        audit::test_evidence_context,
        host_client::SESSION_RESPONSE_SCHEMA,
        model::{
            ActionBoundary, AuditCommitment, JournalSequence, OPERATION_RESULT_SCHEMA, OperationId,
            OperationOutcome, PersonaId, RequestDigest, SubmissionId, TerminalStatus,
        },
        pack::{GITHUB_PUBLISH_REF_ACTION, GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION, PackRegistry},
        principal::PersonaAuthority,
        provider::ProviderRegistry,
        recovery::RecoveryJournal,
        runner::RunnerRegistry,
    };

    const TEST_MAX_HEADER_BYTES: u32 = 4096;
    const TEST_MAX_ARTIFACT_BYTES: u64 = 16;

    struct SessionHostFixture {
        _root: tempfile::TempDir,
        runtime: HostRuntime,
        session: SessionId,
        process_binding: ProcessBindingId,
        revalidate_peer: bool,
    }

    impl SessionHostFixture {
        fn before_peer_revalidation() -> Self {
            Self::new(false)
        }

        fn bound_session() -> Self {
            Self::new(true)
        }

        fn new(bind_session: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let persona = PersonaId::new();
            let mut authority = PersonaAuthority::new();
            authority.restore_persona(persona.clone()).unwrap();
            let (journal, _, _) = test_evidence_context(root.path().join("audit")).unwrap();
            let mut kernel = AuthorityKernel::new(
                authority,
                PackRegistry::default(),
                ProviderRegistry::default(),
                ArtifactStore::new(root.path().join("artifacts"), TEST_MAX_ARTIFACT_BYTES).unwrap(),
                journal,
                RecoveryJournal::open(root.path().join("recovery"), [6_u8; 32]).unwrap(),
                RunnerRegistry::default(),
            );
            kernel.recover_startup(1).unwrap();
            let bound = if bind_session {
                let (probe, _client) = UnixStream::pair().unwrap();
                let peer = identity::peer_identity(&probe).unwrap();
                let (session, challenge) = kernel
                    .create_session(&persona, peer.executable_digest())
                    .unwrap();
                Some((session, challenge, peer))
            } else {
                None
            };
            let mut runtime = HostRuntime::new(
                kernel,
                TEST_MAX_HEADER_BYTES,
                TEST_MAX_ARTIFACT_BYTES,
                Duration::from_secs(1),
            )
            .unwrap();

            let (session, process_binding) = if let Some((session, challenge, peer)) = bound {
                let process_binding = runtime
                    .bind_session_origin(&session, &challenge, &peer)
                    .unwrap();
                (session, process_binding)
            } else {
                (SessionId::new(), ProcessBindingId::new())
            };

            Self {
                _root: root,
                runtime,
                session,
                process_binding,
                revalidate_peer: bind_session,
            }
        }

        fn envelope(&self, action: &str, input: Value, artifact_length: u64) -> Value {
            let submission_id = [5_u8; 32];
            json!({
                "schema": SESSION_REQUEST_SCHEMA,
                "request": {
                    "schema": ACTION_REQUEST_SCHEMA,
                    "pack": {"address": "ember.pack/github", "version": 2},
                    "action": action,
                    "input": input,
                    "submission_id": submission_id,
                },
                "artifact_length": artifact_length,
            })
        }

        fn publish_envelope(&self, input: Value, artifact_length: u64) -> Value {
            self.envelope(GITHUB_PUBLISH_REF_ACTION, input, artifact_length)
        }

        fn exchange(&mut self, wire: &[u8]) -> Value {
            let (server, mut client) = UnixStream::pair().unwrap();
            let peer = if self.revalidate_peer {
                identity::peer_identity(&server).unwrap()
            } else {
                PeerIdentity::observed(
                    42,
                    1,
                    501,
                    20,
                    PathBuf::from("/reviewed/host-wire-test"),
                    [9_u8; 32],
                )
                .unwrap()
            };
            client.write_all(wire).unwrap();
            client.shutdown(Shutdown::Write).unwrap();

            self.runtime
                .handle_session_connection(
                    server,
                    peer,
                    &self.session,
                    &self.process_binding,
                    || true,
                )
                .unwrap();

            let response_length = read_u32(&mut client).unwrap();
            let mut response = vec![0_u8; response_length as usize];
            client.read_exact(&mut response).unwrap();
            let mut trailing = Vec::new();
            client.read_to_end(&mut trailing).unwrap();
            assert!(
                trailing.is_empty(),
                "host wrote more than one response frame"
            );
            serde_json::from_slice(&response).unwrap()
        }
    }

    fn valid_publish_input() -> Value {
        json!({
            "repository": "github:acme/planning",
            "expected_old_oid": "0".repeat(40),
            "new_oid": "a".repeat(40),
            "destination_ref": "refs/heads/ws/test/planner-1",
        })
    }

    fn frame(envelope: &Value) -> Vec<u8> {
        let header = serde_json::to_vec(envelope).unwrap();
        let mut wire = Vec::with_capacity(4 + header.len());
        wire.extend_from_slice(&(header.len() as u32).to_be_bytes());
        wire.extend_from_slice(&header);
        wire
    }

    fn assert_wire_error(response: &Value, code: &str, message: &str) {
        assert_eq!(
            response.get("schema").and_then(Value::as_str),
            Some(SESSION_RESPONSE_SCHEMA)
        );
        assert_eq!(
            response
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str),
            Some(code)
        );
        assert_eq!(
            response
                .get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
            Some(message)
        );
        assert!(response.get("result").is_none());
        assert!(response.get("receipt").is_none());
    }

    fn fixed_id<T: serde::de::DeserializeOwned>(value: &str) -> T {
        serde_json::from_value(Value::String(value.to_owned())).unwrap()
    }

    fn canonical_response_result() -> OperationResult {
        OperationResult {
            schema: OPERATION_RESULT_SCHEMA.to_owned(),
            outcome: OperationOutcome::new(
                fixed_id::<OperationId>("00000000-0000-0000-0000-000000000001"),
                SubmissionId::from_bytes([0x11; 32]),
                RequestDigest::from_bytes([
                    237, 87, 64, 218, 198, 102, 109, 155, 158, 226, 224, 70, 253, 30, 211, 13, 209,
                    90, 48, 62, 212, 239, 86, 234, 161, 93, 225, 56, 167, 101, 35, 169,
                ]),
                JournalSequence::new(1).unwrap(),
                None,
                ActionBoundary::CancelledBeforeEffect,
            ),
            persona_id: fixed_id::<PersonaId>("00000000-0000-0000-0000-000000000002"),
            session_id: fixed_id::<SessionId>("00000000-0000-0000-0000-000000000003"),
            process_binding_id: fixed_id::<ProcessBindingId>(
                "00000000-0000-0000-0000-000000000004",
            ),
            grant_id: None,
            delegation_path: Vec::new(),
            status: TerminalStatus::Refusal,
            action: None,
            approved_input: None,
            resource: None,
            need: None,
            provider: None,
            runner: None,
            facts: None,
            upstream_revoked: false,
            audit: AuditCommitment {
                first_hash: "a".repeat(64),
                last_hash: "b".repeat(64),
                fact_count: 1,
            },
            started_at_unix: 1_800_000_000,
            completed_at_unix: 1_800_000_001,
            message: "authority admission refused".to_owned(),
        }
    }

    fn response_payload(frame: &[u8]) -> &[u8] {
        let announced = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 4 + announced);
        let payload = &frame[4..];
        assert!(
            !payload.contains(&b'\n'),
            "daemon framing must not contain the adapter stdout newline"
        );
        payload
    }

    #[test]
    fn result_response_frame_uses_exact_canonical_bytes_without_newline() {
        let mut frame = Vec::new();
        write_result(&mut frame, &canonical_response_result(), Some([0x44; 32])).unwrap();

        let expected = r#"{"reconnect_proof":[68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68,68],"result":{"action":null,"approved_input":null,"audit":{"fact_count":1,"first_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","last_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"completed_at_unix":1800000001,"delegation_path":[],"facts":null,"grant_id":null,"message":"authority admission refused","need":null,"outcome":{"boundary":"cancelled-before-effect","materialization_id":null,"operation_id":"00000000-0000-0000-0000-000000000001","request_digest":[237,87,64,218,198,102,109,155,158,226,224,70,253,30,211,13,209,90,48,62,212,239,86,234,161,93,225,56,167,101,35,169],"sequence":1,"submission_id":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17]},"persona_id":"00000000-0000-0000-0000-000000000002","process_binding_id":"00000000-0000-0000-0000-000000000004","provider":null,"resource":null,"runner":null,"schema":"ember.operation-result/v1","session_id":"00000000-0000-0000-0000-000000000003","started_at_unix":1800000000,"status":"refusal","upstream_revoked":false},"schema":"ember.session-response/v1"}"#;
        assert_eq!(response_payload(&frame), expected.as_bytes());
    }

    #[test]
    fn error_response_frame_uses_exact_canonical_bytes_without_newline() {
        let mut frame = Vec::new();
        write_error(
            &mut frame,
            "authority_gap",
            "authority admission refused",
            Some([0x55; 32]),
        )
        .unwrap();

        let expected = r#"{"error":{"code":"authority_gap","message":"authority admission refused"},"reconnect_proof":[85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85],"schema":"ember.session-response/v1"}"#;
        assert_eq!(response_payload(&frame), expected.as_bytes());
    }

    #[test]
    fn zero_and_oversize_headers_are_rejected_before_body_read() {
        let mut fixture = SessionHostFixture::before_peer_revalidation();

        for announced_length in [0, TEST_MAX_HEADER_BYTES + 1] {
            let response = fixture.exchange(&announced_length.to_be_bytes());
            assert_wire_error(
                &response,
                "header_too_large",
                "request header exceeds the configured limit",
            );
        }
    }

    #[test]
    fn host_and_action_request_schemas_are_pinned_independently() {
        let mut fixture = SessionHostFixture::before_peer_revalidation();
        let mut wrong_host_schema = fixture.publish_envelope(valid_publish_input(), 0);
        wrong_host_schema["schema"] = Value::String("ember.host-request/v2".to_owned());
        let mut wrong_action_schema = fixture.publish_envelope(valid_publish_input(), 0);
        wrong_action_schema["request"]["schema"] =
            Value::String("ember.action-request/v2".to_owned());

        for envelope in [wrong_host_schema, wrong_action_schema] {
            let response = fixture.exchange(&frame(&envelope));
            assert_wire_error(&response, "unknown_schema", "request schema is unsupported");
        }
    }

    #[test]
    fn publish_artifact_length_is_bounded_before_ingress() {
        let mut fixture = SessionHostFixture::before_peer_revalidation();
        let envelope = fixture.publish_envelope(valid_publish_input(), TEST_MAX_ARTIFACT_BYTES + 1);

        let response = fixture.exchange(&frame(&envelope));

        assert_wire_error(
            &response,
            "artifact_too_large",
            "artifact exceeds the configured limit",
        );
    }

    #[test]
    fn non_publish_actions_reject_artifact_bytes() {
        let mut fixture = SessionHostFixture::bound_session();
        let envelope = fixture.envelope(
            GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
            json!({
                "repository": "github:acme/planning",
                "head_ref": "refs/heads/ws/test/planner-1",
                "base_ref": "refs/heads/main",
            }),
            1,
        );
        let mut wire = frame(&envelope);
        wire.push(b'x');

        let response = fixture.exchange(&wire);

        assert_wire_error(
            &response,
            "forbidden_input",
            "request input contains a daemon-owned coordinate",
        );
    }

    #[test]
    fn bytes_after_the_declared_request_frame_are_rejected() {
        let mut fixture = SessionHostFixture::bound_session();
        let mut wire = frame(&fixture.publish_envelope(valid_publish_input(), 0));
        wire.extend_from_slice(b"second-frame");

        let response = fixture.exchange(&wire);

        assert_wire_error(
            &response,
            "trailing_frame",
            "request contains trailing bytes",
        );
    }

    #[test]
    fn daemon_owned_keys_and_artifact_references_are_rejected_at_any_depth() {
        let forbidden_inputs = [
            json!({"cwd": "/attacker-controlled"}),
            json!({"metadata": {"runner_path": "/attacker-controlled"}}),
            json!({
                "items": [
                    {"label": format!("artifact:sha256:{}", "b".repeat(64))}
                ]
            }),
        ];
        let mut fixture = SessionHostFixture::before_peer_revalidation();

        for input in forbidden_inputs {
            let envelope = fixture.publish_envelope(input, 0);
            let response = fixture.exchange(&frame(&envelope));
            assert_wire_error(
                &response,
                "forbidden_input",
                "request input contains a daemon-owned coordinate",
            );
        }
    }

    #[test]
    fn deadline_reader_bounds_drip_fed_session_input() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            for _ in 0..20 {
                if writer.write_all(&[0]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let mut reader = DeadlineReader::new(&mut reader, Duration::from_millis(100)).unwrap();
        let error = reader.read_exact(&mut [0; 64]).unwrap_err();
        let elapsed = started.elapsed();
        writer.join().unwrap();

        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(
            elapsed < Duration::from_millis(500),
            "drip-fed session input exceeded its absolute deadline: {elapsed:?}"
        );
    }

    #[test]
    fn deadline_writer_refuses_work_after_its_absolute_deadline() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let mut writer = DeadlineWriter::new(&mut writer, Duration::from_millis(1)).unwrap();
        thread::sleep(Duration::from_millis(10));

        let error = writer.write_all(&[0]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn artifact_ingress_has_a_size_aware_absolute_deadline() {
        let base = Duration::from_secs(30);
        assert_eq!(artifact_ingress_timeout(base, 0).unwrap(), base);
        assert_eq!(
            artifact_ingress_timeout(base, 1).unwrap(),
            Duration::from_secs(31)
        );
        assert_eq!(
            artifact_ingress_timeout(base, MIN_ARTIFACT_INGRESS_BYTES_PER_SECOND).unwrap(),
            Duration::from_secs(31)
        );
        assert_eq!(
            artifact_ingress_timeout(base, MIN_ARTIFACT_INGRESS_BYTES_PER_SECOND + 1).unwrap(),
            Duration::from_secs(32)
        );
    }

    #[test]
    fn artifact_deadline_failure_returns_the_issued_reconnect_proof() {
        let mut fixture = SessionHostFixture::bound_session();
        fixture.runtime.fail_next_artifact_ingress_deadline();
        let wire = frame(&fixture.publish_envelope(valid_publish_input(), 1));
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let peer = identity::peer_identity(&server).unwrap();
        client.write_all(&wire).unwrap();
        let mut reader = DeadlineReader::new(&mut server, SESSION_INITIAL_READ_TIMEOUT).unwrap();

        let transaction = fixture
            .runtime
            .transact(
                &mut reader,
                &peer,
                &fixture.session,
                &fixture.process_binding,
                &mut || true,
            )
            .unwrap();

        assert!(matches!(
            transaction.outcome,
            Err(RequestError::ArtifactIngress)
        ));
        let mut proof = transaction
            .reconnect_proof
            .expect("admitted request must return its reconnect proof");
        assert!(proof.iter().any(|byte| *byte != 0));
        proof.zeroize();
    }

    #[test]
    fn successful_artifact_transaction_removes_request_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"publication")).unwrap();
        let object = directory.path().join(artifact.artifact_ref().digest_hex());

        let transaction =
            finalize_artifact(Some(&artifact), Ok(TerminalStatus::Success), |artifact| {
                store.remove_scoped(artifact)
            });

        assert_eq!(transaction.outcome.unwrap(), TerminalStatus::Success);
        assert!(transaction.cleanup_error.is_none());
        assert!(!object.exists());
    }

    #[test]
    fn refused_artifact_transaction_still_removes_request_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"refused")).unwrap();
        let object = directory.path().join(artifact.artifact_ref().digest_hex());
        let transaction =
            finalize_artifact(Some(&artifact), Ok(TerminalStatus::Refusal), |artifact| {
                store.remove_scoped(artifact)
            });

        assert_eq!(transaction.outcome.unwrap(), TerminalStatus::Refusal);
        assert!(transaction.cleanup_error.is_none());
        assert!(!object.exists());
    }

    #[test]
    fn errored_artifact_transaction_still_removes_request_object() {
        let directory = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(directory.path(), 1024).unwrap();
        let artifact = store.import_scoped(Cursor::new(b"failed")).unwrap();
        let object = directory.path().join(artifact.artifact_ref().digest_hex());
        let outcome: Result<(), RequestError> = Err(RequestError::Operation);

        let transaction = finalize_artifact(Some(&artifact), outcome, |artifact| {
            store.remove_scoped(artifact)
        });

        assert!(matches!(transaction.outcome, Err(RequestError::Operation)));
        assert!(transaction.cleanup_error.is_none());
        assert!(!object.exists());
    }

    #[test]
    fn transaction_without_artifact_does_not_invoke_cleanup() {
        let touched = Cell::new(false);

        let transaction = finalize_artifact(
            None,
            Ok("terminal result"),
            |_| -> Result<(), ArtifactError> {
                touched.set(true);
                Ok(())
            },
        );

        assert_eq!(transaction.outcome.unwrap(), "terminal result");
        assert!(transaction.cleanup_error.is_none());
        assert!(!touched.get());
    }

    #[test]
    fn cleanup_failure_is_returned_after_terminal_result_is_written() {
        let written = Cell::new(None);
        let transaction = TransactionResult {
            outcome: Ok("terminal result"),
            cleanup_error: Some(ArtifactError::StoredObjectIdentityChanged),
            reconnect_proof: None,
        };

        let result = respond_transaction(transaction, |outcome, reconnect_proof| {
            assert!(reconnect_proof.is_none());
            written.set(Some(outcome.unwrap()));
            Ok(())
        });

        assert_eq!(written.get(), Some("terminal result"));
        assert!(matches!(result, Err(HostError::ArtifactCleanup(_))));
    }
}
