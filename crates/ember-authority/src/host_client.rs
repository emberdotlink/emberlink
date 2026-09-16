use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    host::{ABSOLUTE_MAX_ARTIFACT_BYTES, ABSOLUTE_MAX_HEADER_BYTES},
    identity,
    model::{
        ACTION_REQUEST_SCHEMA, ActionFacts, ActionRequest, ArtifactRef, GitOid, GitRef,
        GitRefPublicationInput, GithubPullRequestCreateInput, GithubRepositoryFactsInput,
        OPERATION_RESULT_SCHEMA, OperationResult, ProcessBindingId, RepositoryResource,
        RequestDigest, SessionId, TerminalStatus,
    },
    pack::{
        GITHUB_PACK_ADDRESS, GITHUB_PACK_VERSION, GITHUB_PUBLISH_REF_ACTION,
        GITHUB_PULL_REQUEST_CREATE_ACTION, GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
    },
    principal::ExecutableDigest,
};

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACTIVATION_BYTES: u64 = 64 * 1024;
const HOST_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const SESSION_BOOTSTRAP_SCHEMA: &str = "ember.session-bootstrap/v1";
pub const SESSION_ENDPOINT_SCHEMA: &str = "ember.session-endpoint/v1";
pub const SESSION_ACTION_REQUEST_SCHEMA: &str = "ember.session-action-request/v1";
pub const SESSION_REQUEST_SCHEMA: &str = "ember.session-request/v1";
pub const SESSION_RESPONSE_SCHEMA: &str = "ember.session-response/v1";
pub(crate) const SESSION_ACTIVATION_REQUEST_SCHEMA: &str = "ember.session-activation-request/v1";
pub(crate) const SESSION_ACTIVATION_RESPONSE_SCHEMA: &str = "ember.session-activation-response/v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionRequest {
    pub(crate) schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reconnect_proof: Option<[u8; 32]>,
    pub(crate) request: ActionRequest,
    pub(crate) artifact_length: u64,
}

impl Drop for SessionRequest {
    fn drop(&mut self) {
        if let Some(proof) = self.reconnect_proof.as_mut() {
            proof.zeroize();
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionActivationRequest {
    pub(crate) schema: String,
    pub(crate) session_id: SessionId,
    pub(crate) challenge_hex: String,
}

impl Drop for SessionActivationRequest {
    fn drop(&mut self) {
        self.challenge_hex.zeroize();
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionActivationResponse {
    pub(crate) schema: String,
    pub(crate) socket_path: PathBuf,
    pub(crate) session_id: SessionId,
    pub(crate) process_binding_id: ProcessBindingId,
}

/// Exact daemon process coordinates measured by the trusted launcher.
///
/// The inherited bootstrap pins these coordinates before either activation or
/// action bytes are sent, so a listener substituted at the same path is inert.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonProcessIdentityWire {
    pub(crate) pid: u32,
    pub(crate) pid_version: u64,
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) executable_digest_sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBootstrapWire {
    pub(crate) schema: String,
    pub(crate) activation_socket_path: PathBuf,
    pub(crate) session_id: SessionId,
    pub(crate) challenge_hex: String,
    pub(crate) daemon_process: DaemonProcessIdentityWire,
}

impl Drop for SessionBootstrapWire {
    fn drop(&mut self) {
        self.challenge_hex.zeroize();
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionEndpointWire {
    schema: String,
    socket_path: PathBuf,
    session_id: SessionId,
    process_binding_id: ProcessBindingId,
    daemon_process: DaemonProcessIdentityWire,
}

/// Canonical action envelope written to an inherited Session adapter.
///
/// Authority selection is intentionally absent: Ember derives admission from
/// the request, installed pack, authenticated process, and live Session state.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionActionRequest {
    schema: String,
    request: ActionRequest,
    artifact_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect_proof: Option<[u8; 32]>,
}

impl SessionActionRequest {
    /// Creates one canonical action envelope.
    pub fn new(
        request: ActionRequest,
        artifact_length: u64,
        reconnect_proof: Option<[u8; 32]>,
    ) -> Self {
        Self {
            schema: SESSION_ACTION_REQUEST_SCHEMA.to_owned(),
            request,
            artifact_length,
            reconnect_proof,
        }
    }

    /// Returns the envelope schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the typed action request.
    pub fn request(&self) -> &ActionRequest {
        &self.request
    }

    /// Returns the exact number of artifact bytes following this envelope.
    pub const fn artifact_length(&self) -> u64 {
        self.artifact_length
    }

    /// Returns the reconnect proof carried by this request, when present.
    pub const fn reconnect_proof(&self) -> Option<&[u8; 32]> {
        self.reconnect_proof.as_ref()
    }
}

impl Drop for SessionActionRequest {
    fn drop(&mut self) {
        if let Some(proof) = self.reconnect_proof.as_mut() {
            proof.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterRole {
    Planner,
    Builder,
    Reconciler,
}

impl AdapterRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Builder => "builder",
            Self::Reconciler => "reconciler",
        }
    }

    fn accepts_repository(self, repository: &RepositoryResource) -> bool {
        let product_repository = repository.as_str() == "github:emberdotlink/ember";
        match self {
            Self::Planner => !product_repository,
            Self::Builder => product_repository,
            Self::Reconciler => true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationIntent {
    repository: RepositoryResource,
    expected_old_oid: GitOid,
    new_oid: GitOid,
    destination_ref: GitRef,
}

enum ValidatedIntent {
    Publication(PublicationIntent),
    PullRequest(GithubPullRequestCreateInput),
    Reconcile(GithubRepositoryFactsInput),
}

impl ValidatedIntent {
    fn repository(&self) -> &RepositoryResource {
        match self {
            Self::Publication(value) => &value.repository,
            Self::PullRequest(value) => &value.repository,
            Self::Reconcile(value) => &value.repository,
        }
    }

    fn action(&self) -> &'static str {
        match self {
            Self::Publication(_) => GITHUB_PUBLISH_REF_ACTION,
            Self::PullRequest(_) => GITHUB_PULL_REQUEST_CREATE_ACTION,
            Self::Reconcile(_) => GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
        }
    }
}

#[derive(Clone, Copy)]
struct RequestContext<'a> {
    role: AdapterRole,
    endpoint: &'a SessionEndpointWire,
}

/// Canonical bounded error returned through a Session response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionWireError {
    code: String,
    message: String,
}

impl SessionWireError {
    /// Creates an error from its stable code and human-readable message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Returns the stable error code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the human-readable error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Canonical successful Session response envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResultResponse {
    schema: String,
    result: OperationResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect_proof: Option<[u8; 32]>,
}

impl SessionResultResponse {
    /// Creates one canonical successful response.
    pub fn new(result: OperationResult, reconnect_proof: Option<[u8; 32]>) -> Self {
        Self {
            schema: SESSION_RESPONSE_SCHEMA.to_owned(),
            result,
            reconnect_proof,
        }
    }

    /// Returns the response schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the immutable operation result.
    pub const fn result(&self) -> &OperationResult {
        &self.result
    }

    /// Returns the rotated reconnect proof, when present.
    pub const fn reconnect_proof(&self) -> Option<&[u8; 32]> {
        self.reconnect_proof.as_ref()
    }
}

impl Drop for SessionResultResponse {
    fn drop(&mut self) {
        if let Some(proof) = self.reconnect_proof.as_mut() {
            proof.zeroize();
        }
    }
}

/// Canonical refused Session response envelope.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionErrorResponse {
    schema: String,
    error: SessionWireError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconnect_proof: Option<[u8; 32]>,
}

impl SessionErrorResponse {
    /// Creates one canonical refused response.
    pub fn new(error: SessionWireError, reconnect_proof: Option<[u8; 32]>) -> Self {
        Self {
            schema: SESSION_RESPONSE_SCHEMA.to_owned(),
            error,
            reconnect_proof,
        }
    }

    /// Returns the response schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the bounded wire error.
    pub const fn error(&self) -> &SessionWireError {
        &self.error
    }

    /// Returns the rotated reconnect proof, when present.
    pub const fn reconnect_proof(&self) -> Option<&[u8; 32]> {
        self.reconnect_proof.as_ref()
    }
}

impl Drop for SessionErrorResponse {
    fn drop(&mut self) {
        if let Some(proof) = self.reconnect_proof.as_mut() {
            proof.zeroize();
        }
    }
}

#[derive(Debug, Error)]
pub enum HostClientError {
    #[error("inherited Session endpoint is invalid")]
    InvalidSessionEndpoint,
    #[error("inherited Session activation failed")]
    SessionActivation,
    #[error("Session action request contains forbidden authority selectors")]
    AuthoritySelector,
    #[error("host request framing is invalid")]
    InvalidRequestFrame,
    #[error("host request is not an allowed typed publication intent")]
    InvalidRequest,
    #[error("host request targets the wrong role adapter")]
    WrongRole,
    #[error("host request contains trailing bytes")]
    TrailingRequestBytes,
    #[error("host daemon is unavailable")]
    DaemonUnavailable,
    #[error("host daemon process identity does not match the inherited Session")]
    DaemonAuthentication,
    #[error("host daemon transport failed")]
    Transport,
    #[error("host daemon transport timed out")]
    DaemonTimeout,
    #[error("host daemon response framing is invalid")]
    InvalidResponseFrame,
    #[error("host daemon response is malformed")]
    InvalidResponse,
    #[error("host daemon operation result or request binding is invalid")]
    ResultValidation,
    #[error("host daemon refused the request")]
    DaemonError,
    #[error("host operation did not succeed")]
    OperationFailure,
}

pub fn run_inherited(role: AdapterRole, endpoint_bytes: &[u8]) -> Result<(), HostClientError> {
    let endpoint = activate_inherited_session(endpoint_bytes)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_inherited_with_io(role, &endpoint, &mut stdin.lock(), &mut stdout.lock())
}

fn run_inherited_with_io(
    role: AdapterRole,
    endpoint: &SessionEndpointWire,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), HostClientError> {
    let context = RequestContext { role, endpoint };
    let mut handled = false;
    while let Some(action) = read_session_action_header(input)? {
        handled = true;
        let request = bind_session_action(endpoint, &action)?;
        run_request_with_io(context, request, input, output)?;
    }
    if handled {
        Ok(())
    } else {
        Err(HostClientError::InvalidRequestFrame)
    }
}
#[derive(Serialize)]
struct BorrowedSessionRequest<'a> {
    schema: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconnect_proof: Option<&'a [u8; 32]>,
    request: &'a ActionRequest,
    artifact_length: u64,
}

fn bind_session_action<'a>(
    _endpoint: &SessionEndpointWire,
    action: &'a SessionActionRequest,
) -> Result<BorrowedSessionRequest<'a>, HostClientError> {
    Ok(BorrowedSessionRequest {
        schema: SESSION_REQUEST_SCHEMA,
        reconnect_proof: action.reconnect_proof.as_ref(),
        request: &action.request,
        artifact_length: action.artifact_length,
    })
}

fn run_request_with_io(
    context: RequestContext<'_>,
    request: BorrowedSessionRequest<'_>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), HostClientError> {
    let RequestContext { role, endpoint } = context;
    let intent = validate_request(role, &request)?;
    if !matches!(
        request.request.submission_id,
        Some(submission_id) if submission_id.as_bytes().iter().any(|byte| *byte != 0)
    ) {
        return Err(HostClientError::InvalidRequest);
    }
    let mut canonical_action = request.request.clone();
    canonical_action.input = canonical_request_input(&intent)?;
    let request = BorrowedSessionRequest {
        schema: request.schema,
        reconnect_proof: request.reconnect_proof,
        request: &canonical_action,
        artifact_length: request.artifact_length,
    };
    let request_bytes = Zeroizing::new(
        serde_jcs::to_vec(&request).map_err(|_| HostClientError::InvalidRequestFrame)?,
    );
    let request_length =
        u32::try_from(request_bytes.len()).map_err(|_| HostClientError::InvalidRequestFrame)?;
    let prefix = request_length.to_be_bytes();

    let mut daemon = UnixStream::connect(&endpoint.socket_path)
        .map_err(|_| HostClientError::DaemonUnavailable)?;
    daemon
        .set_read_timeout(Some(HOST_IO_TIMEOUT))
        .and_then(|_| daemon.set_write_timeout(Some(HOST_IO_TIMEOUT)))
        .map_err(|_| HostClientError::Transport)?;
    authenticate_daemon_peer(&daemon, &endpoint.daemon_process)?;
    daemon
        .write_all(&prefix)
        .and_then(|_| daemon.write_all(&request_bytes))
        .map_err(transport_error)?;
    let artifact_digest = copy_exact(input, &mut daemon, request.artifact_length)?;

    daemon
        .shutdown(Shutdown::Write)
        .map_err(|_| HostClientError::Transport)?;
    let response_bytes = read_response(&mut daemon)?;

    let outcome = validate_response(
        &response_bytes,
        endpoint,
        &request,
        &intent,
        artifact_digest,
    )?;
    output
        .write_all(&response_bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .map_err(|_| HostClientError::Transport)?;
    match outcome {
        ResponseOutcome::Success => Ok(()),
        ResponseOutcome::DaemonError => Err(HostClientError::DaemonError),
        ResponseOutcome::OperationFailure => Err(HostClientError::OperationFailure),
    }
}

fn activate_inherited_session(bytes: &[u8]) -> Result<SessionEndpointWire, HostClientError> {
    let mut bootstrap: SessionBootstrapWire =
        serde_json::from_slice(bytes).map_err(|_| HostClientError::InvalidSessionEndpoint)?;
    let trusted_root = crate::authority_state_directory(crate::effective_uid())
        .map_err(|_| HostClientError::InvalidSessionEndpoint)?;
    let mut challenge = [0_u8; 32];
    let bootstrap_valid = bootstrap.schema == SESSION_BOOTSTRAP_SCHEMA
        && clean_path_below(&bootstrap.activation_socket_path, &trusted_root)
        && uuid::Uuid::parse_str(bootstrap.session_id.as_str()).is_ok()
        && hex::decode_to_slice(&bootstrap.challenge_hex, &mut challenge).is_ok()
        && valid_daemon_process_identity(&bootstrap.daemon_process);
    challenge.zeroize();
    if !bootstrap_valid {
        return Err(HostClientError::InvalidSessionEndpoint);
    }
    let request_wire = SessionActivationRequest {
        schema: SESSION_ACTIVATION_REQUEST_SCHEMA.to_owned(),
        session_id: bootstrap.session_id.clone(),
        challenge_hex: std::mem::take(&mut bootstrap.challenge_hex),
    };
    let request = Zeroizing::new(
        serde_jcs::to_vec(&request_wire).map_err(|_| HostClientError::SessionActivation)?,
    );

    let mut stream = UnixStream::connect(&bootstrap.activation_socket_path)
        .map_err(|_| HostClientError::SessionActivation)?;
    stream
        .set_read_timeout(Some(HOST_IO_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(HOST_IO_TIMEOUT)))
        .map_err(|_| HostClientError::SessionActivation)?;
    authenticate_daemon_peer(&stream, &bootstrap.daemon_process)?;
    stream
        .write_all(&request)
        .and_then(|_| stream.shutdown(Shutdown::Write))
        .map_err(|_| HostClientError::SessionActivation)?;
    let mut response = Vec::new();
    stream
        .take(MAX_ACTIVATION_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|_| HostClientError::SessionActivation)?;
    if response.is_empty() || response.len() > MAX_ACTIVATION_BYTES as usize {
        return Err(HostClientError::SessionActivation);
    }
    let activated: SessionActivationResponse =
        serde_json::from_slice(&response).map_err(|_| HostClientError::SessionActivation)?;
    if activated.schema != SESSION_ACTIVATION_RESPONSE_SCHEMA
        || activated.session_id != bootstrap.session_id
    {
        return Err(HostClientError::SessionActivation);
    }
    validate_session_endpoint(SessionEndpointWire {
        schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
        socket_path: activated.socket_path,
        session_id: activated.session_id,
        process_binding_id: activated.process_binding_id,
        daemon_process: bootstrap.daemon_process.clone(),
    })
}

#[cfg(test)]
fn decode_session_endpoint(bytes: &[u8]) -> Result<SessionEndpointWire, HostClientError> {
    let endpoint: SessionEndpointWire =
        serde_json::from_slice(bytes).map_err(|_| HostClientError::InvalidSessionEndpoint)?;
    validate_session_endpoint(endpoint)
}

fn validate_session_endpoint(
    endpoint: SessionEndpointWire,
) -> Result<SessionEndpointWire, HostClientError> {
    let trusted_root = crate::authority_state_directory(crate::effective_uid())
        .map_err(|_| HostClientError::InvalidSessionEndpoint)?;
    if endpoint.schema != SESSION_ENDPOINT_SCHEMA
        || !clean_path_below(&endpoint.socket_path, &trusted_root)
        || uuid::Uuid::parse_str(endpoint.session_id.as_str()).is_err()
        || uuid::Uuid::parse_str(endpoint.process_binding_id.as_str()).is_err()
        || !valid_daemon_process_identity(&endpoint.daemon_process)
    {
        return Err(HostClientError::InvalidSessionEndpoint);
    }
    Ok(endpoint)
}

fn valid_daemon_process_identity(expected: &DaemonProcessIdentityWire) -> bool {
    expected.pid != 0
        && expected.pid_version != 0
        && ExecutableDigest::from_sha256_hex(&expected.executable_digest_sha256).is_ok()
}

fn authenticate_daemon_peer(
    stream: &UnixStream,
    expected: &DaemonProcessIdentityWire,
) -> Result<(), HostClientError> {
    let expected_digest = ExecutableDigest::from_sha256_hex(&expected.executable_digest_sha256)
        .map_err(|_| HostClientError::DaemonAuthentication)?;
    let observed =
        identity::peer_identity(stream).map_err(|_| HostClientError::DaemonAuthentication)?;
    if observed.pid() != expected.pid
        || observed.pid_version() != expected.pid_version
        || observed.euid() != expected.euid
        || observed.egid() != expected.egid
        || observed.executable_digest() != expected_digest
    {
        return Err(HostClientError::DaemonAuthentication);
    }
    Ok(())
}

fn clean_path_below(path: &Path, trusted_root: &Path) -> bool {
    path.is_absolute()
        && path.starts_with(trusted_root)
        && path != trusted_root
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

fn read_session_action_header(
    input: &mut impl Read,
) -> Result<Option<SessionActionRequest>, HostClientError> {
    let mut prefix = [0_u8; 4];
    if input
        .read(&mut prefix[..1])
        .map_err(|_| HostClientError::InvalidRequestFrame)?
        == 0
    {
        return Ok(None);
    }
    input
        .read_exact(&mut prefix[1..])
        .map_err(|_| HostClientError::InvalidRequestFrame)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > ABSOLUTE_MAX_HEADER_BYTES as usize {
        return Err(HostClientError::InvalidRequestFrame);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    input
        .read_exact(&mut bytes)
        .map_err(|_| HostClientError::InvalidRequestFrame)?;
    let mut request: SessionActionRequest =
        serde_json::from_slice(&bytes).map_err(|_| HostClientError::InvalidRequest)?;
    if request.schema != SESSION_ACTION_REQUEST_SCHEMA
        || !matches!(
            request.request.submission_id,
            Some(submission_id) if submission_id.as_bytes().iter().any(|byte| *byte != 0)
        )
        || request.artifact_length > ABSOLUTE_MAX_ARTIFACT_BYTES
    {
        if let Some(proof) = request.reconnect_proof.as_mut() {
            proof.zeroize();
        }
        return Err(HostClientError::InvalidRequest);
    }
    Ok(Some(request))
}

fn validate_request(
    role: AdapterRole,
    envelope: &BorrowedSessionRequest<'_>,
) -> Result<ValidatedIntent, HostClientError> {
    if envelope.schema != SESSION_REQUEST_SCHEMA
        || envelope.request.schema != ACTION_REQUEST_SCHEMA
        || envelope.request.pack.address != GITHUB_PACK_ADDRESS
        || envelope.request.pack.version != GITHUB_PACK_VERSION
        || envelope.artifact_length > ABSOLUTE_MAX_ARTIFACT_BYTES
    {
        return Err(HostClientError::InvalidRequest);
    }
    let intent = match envelope.request.action.as_str() {
        GITHUB_PUBLISH_REF_ACTION
            if role != AdapterRole::Reconciler && envelope.artifact_length != 0 =>
        {
            let value: PublicationIntent = serde_json::from_value(envelope.request.input.clone())
                .map_err(|_| HostClientError::InvalidRequest)?;
            if value.new_oid.is_zero() {
                return Err(HostClientError::InvalidRequest);
            }
            validate_role_ref(role, value.destination_ref.as_str())?;
            ValidatedIntent::Publication(value)
        }
        GITHUB_PULL_REQUEST_CREATE_ACTION
            if role != AdapterRole::Reconciler && envelope.artifact_length == 0 =>
        {
            let value: GithubPullRequestCreateInput =
                serde_json::from_value(envelope.request.input.clone())
                    .map_err(|_| HostClientError::InvalidRequest)?;
            validate_role_ref(role, value.head_ref.as_str())?;
            validate_pr_fields(
                &value.head_ref,
                &value.base_ref,
                Some((&value.title, &value.body)),
            )?;
            ValidatedIntent::PullRequest(value)
        }
        GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION
            if role == AdapterRole::Reconciler && envelope.artifact_length == 0 =>
        {
            let value: GithubRepositoryFactsInput =
                serde_json::from_value(envelope.request.input.clone())
                    .map_err(|_| HostClientError::InvalidRequest)?;
            validate_pr_fields(&value.head_ref, &value.base_ref, None)?;
            ValidatedIntent::Reconcile(value)
        }
        _ => return Err(HostClientError::WrongRole),
    };
    if !role.accepts_repository(intent.repository()) {
        return Err(HostClientError::WrongRole);
    }
    Ok(intent)
}

fn validate_pr_fields(
    head_ref: &GitRef,
    base_ref: &GitRef,
    pull_request: Option<(&str, &str)>,
) -> Result<(), HostClientError> {
    if base_ref.as_str() != "refs/heads/main" {
        return Err(HostClientError::InvalidRequest);
    }
    let branch = role_branch(head_ref.as_str())?;
    if let Some((title, body)) = pull_request
        && (title != format!("wb: {} {}", branch.0, branch.1) || !body.is_empty())
    {
        return Err(HostClientError::InvalidRequest);
    }
    Ok(())
}

fn role_branch(destination_ref: &str) -> Result<(&str, &str), HostClientError> {
    let branch = destination_ref
        .strip_prefix("refs/heads/ws/")
        .ok_or(HostClientError::InvalidRequest)?;
    let (slug, leaf) = branch
        .split_once('/')
        .ok_or(HostClientError::InvalidRequest)?;
    if leaf.contains('/') || !valid_slug(slug) {
        return Err(HostClientError::InvalidRequest);
    }
    let (recorded_role, ordinal) = leaf
        .rsplit_once('-')
        .ok_or(HostClientError::InvalidRequest)?;
    if !matches!(recorded_role, "planner" | "builder")
        || ordinal.is_empty()
        || ordinal.starts_with('0')
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(HostClientError::InvalidRequest);
    }
    Ok((slug, leaf))
}

fn validate_role_ref(role: AdapterRole, destination_ref: &str) -> Result<(), HostClientError> {
    let (_, leaf) = role_branch(destination_ref)?;
    let (recorded_role, _) = leaf
        .rsplit_once('-')
        .ok_or(HostClientError::InvalidRequest)?;
    if role == AdapterRole::Reconciler || recorded_role == role.as_str() {
        Ok(())
    } else {
        Err(HostClientError::WrongRole)
    }
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && !matches!(slug, "main" | "master" | "head" | "git")
        && slug.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn copy_exact(
    input: &mut impl Read,
    output: &mut impl Write,
    mut remaining: u64,
) -> Result<[u8; 32], HostClientError> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut digest = Sha256::new();
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| HostClientError::InvalidRequestFrame)?;
        let read = input
            .read(&mut buffer[..wanted])
            .map_err(|_| HostClientError::InvalidRequestFrame)?;
        if read == 0 {
            return Err(HostClientError::InvalidRequestFrame);
        }
        output.write_all(&buffer[..read]).map_err(transport_error)?;
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(digest.finalize().into())
}

fn read_response(daemon: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, HostClientError> {
    let mut prefix = [0_u8; 4];
    daemon
        .read_exact(&mut prefix)
        .map_err(response_frame_error)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_RESPONSE_BYTES {
        return Err(HostClientError::InvalidResponseFrame);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    daemon
        .read_exact(&mut bytes)
        .map_err(response_frame_error)?;
    let mut trailing = [0_u8; 1];
    if daemon.read(&mut trailing).map_err(response_frame_error)? != 0 {
        return Err(HostClientError::InvalidResponseFrame);
    }
    Ok(bytes)
}

fn transport_error(error: io::Error) -> HostClientError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        HostClientError::DaemonTimeout
    } else {
        HostClientError::Transport
    }
}

fn response_frame_error(error: io::Error) -> HostClientError {
    match transport_error(error) {
        HostClientError::DaemonTimeout => HostClientError::DaemonTimeout,
        _ => HostClientError::InvalidResponseFrame,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseOutcome {
    Success,
    DaemonError,
    OperationFailure,
}

fn validate_response(
    bytes: &[u8],
    endpoint: &SessionEndpointWire,
    request: &BorrowedSessionRequest<'_>,
    intent: &ValidatedIntent,
    artifact_digest: [u8; 32],
) -> Result<ResponseOutcome, HostClientError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| HostClientError::InvalidResponse)?;
    let canonical =
        Zeroizing::new(serde_jcs::to_vec(&value).map_err(|_| HostClientError::InvalidResponse)?);
    if canonical.as_slice() != bytes {
        return Err(HostClientError::InvalidResponse);
    }
    let object = value.as_object().ok_or(HostClientError::InvalidResponse)?;
    match (object.contains_key("result"), object.contains_key("error")) {
        (true, false) => {
            let mut response: SessionResultResponse =
                serde_json::from_value(value).map_err(|_| HostClientError::InvalidResponse)?;
            let outcome = if response.schema != SESSION_RESPONSE_SCHEMA {
                Err(HostClientError::InvalidResponse)
            } else {
                validate_result_binding(
                    &response.result,
                    endpoint,
                    request,
                    intent,
                    artifact_digest,
                )
            };
            if let Some(proof) = response.reconnect_proof.as_mut() {
                proof.zeroize();
            }
            outcome
        }
        (false, true) => {
            let mut response: SessionErrorResponse =
                serde_json::from_value(value).map_err(|_| HostClientError::InvalidResponse)?;
            let outcome = if response.schema != SESSION_RESPONSE_SCHEMA
                || response.error.code.is_empty()
                || response.error.message.is_empty()
            {
                Err(HostClientError::InvalidResponse)
            } else {
                Ok(ResponseOutcome::DaemonError)
            };
            if let Some(proof) = response.reconnect_proof.as_mut() {
                proof.zeroize();
            }
            outcome
        }
        _ => Err(HostClientError::InvalidResponse),
    }
}

fn validate_result_binding(
    result: &OperationResult,
    endpoint: &SessionEndpointWire,
    request: &BorrowedSessionRequest<'_>,
    intent: &ValidatedIntent,
    artifact_digest: [u8; 32],
) -> Result<ResponseOutcome, HostClientError> {
    let expected_artifact = match intent {
        ValidatedIntent::Publication(_) => Some(ArtifactRef::from_digest(&artifact_digest)),
        _ => None,
    };
    let expected_input = approved_input(intent, expected_artifact.as_ref())?;
    let submission_id = request
        .request
        .submission_id
        .ok_or(HostClientError::ResultValidation)?;
    let mut canonical_request = request.request.clone();
    canonical_request.input = expected_input.clone();
    let canonical_request =
        serde_jcs::to_vec(&canonical_request).map_err(|_| HostClientError::ResultValidation)?;
    let request_digest = RequestDigest::of(&canonical_request);
    if result.schema != OPERATION_RESULT_SCHEMA
        || result.validate().is_err()
        || result.session_id != endpoint.session_id
        || result.process_binding_id != endpoint.process_binding_id
        || result.outcome.submission_id() != submission_id
        || result.outcome.request_digest() != request_digest
    {
        return Err(HostClientError::ResultValidation);
    }
    if let Some(action) = &result.action
        && action != intent.action()
    {
        return Err(HostClientError::ResultValidation);
    }
    if let Some(resource) = &result.resource
        && resource != intent.repository()
    {
        return Err(HostClientError::ResultValidation);
    }
    if let Some(value) = &result.approved_input
        && value != &expected_input
    {
        return Err(HostClientError::ResultValidation);
    }
    if let Some(facts) = &result.facts {
        validate_facts(intent, facts)?;
    }
    if result.status != TerminalStatus::Success {
        return Ok(ResponseOutcome::OperationFailure);
    }
    let runner = result
        .runner
        .as_ref()
        .ok_or(HostClientError::ResultValidation)?;
    let process = runner
        .process
        .as_ref()
        .ok_or(HostClientError::ResultValidation)?;
    let expected_adapter = match intent {
        ValidatedIntent::Publication(_) => GITHUB_PUBLISH_REF_ACTION,
        _ => "github.api/v1",
    };
    let artifact_digest = expected_artifact
        .as_ref()
        .map(|artifact| artifact.digest_hex().to_owned());
    if result.action.as_deref() != Some(intent.action())
        || result.resource.as_ref() != Some(intent.repository())
        || result.approved_input.as_ref() != Some(&expected_input)
        || runner.adapter != expected_adapter
        || runner.artifact_digest_sha256 != artifact_digest
        || process.exit_code != Some(0)
        || process.signal.is_some()
        || !result.upstream_revoked
    {
        return Err(HostClientError::ResultValidation);
    }
    match intent {
        ValidatedIntent::Publication(_) if result.facts.is_none() => {}
        ValidatedIntent::PullRequest(_) | ValidatedIntent::Reconcile(_)
            if result
                .facts
                .as_ref()
                .is_some_and(|facts| validate_facts(intent, facts).is_ok()) => {}
        _ => return Err(HostClientError::ResultValidation),
    }
    Ok(ResponseOutcome::Success)
}

fn canonical_request_input(intent: &ValidatedIntent) -> Result<Value, HostClientError> {
    match intent {
        ValidatedIntent::Publication(value) => serde_json::to_value(value),
        ValidatedIntent::PullRequest(value) => serde_json::to_value(value),
        ValidatedIntent::Reconcile(value) => serde_json::to_value(value),
    }
    .map_err(|_| HostClientError::InvalidRequest)
}

fn approved_input(
    intent: &ValidatedIntent,
    artifact: Option<&ArtifactRef>,
) -> Result<Value, HostClientError> {
    match intent {
        ValidatedIntent::Publication(value) => serde_json::to_value(GitRefPublicationInput {
            repository: value.repository.clone(),
            artifact: artifact.cloned().ok_or(HostClientError::ResultValidation)?,
            expected_old_oid: value.expected_old_oid.clone(),
            new_oid: value.new_oid.clone(),
            destination_ref: value.destination_ref.clone(),
        }),
        ValidatedIntent::PullRequest(value) => serde_json::to_value(value),
        ValidatedIntent::Reconcile(value) => serde_json::to_value(value),
    }
    .map_err(|_| HostClientError::ResultValidation)
}

fn validate_facts(intent: &ValidatedIntent, facts: &ActionFacts) -> Result<(), HostClientError> {
    match (intent, facts) {
        (
            ValidatedIntent::PullRequest(input),
            ActionFacts::GithubPullRequestCreated {
                repository,
                number,
                html_url,
                head_ref,
                base_ref,
            },
        ) if repository == &input.repository
            && *number != 0
            && valid_fact_string(html_url, 4096)
            && head_ref == &input.head_ref
            && base_ref == &input.base_ref =>
        {
            Ok(())
        }
        (
            ValidatedIntent::Reconcile(input),
            ActionFacts::GithubRepositoryFacts {
                repository,
                fork_heads,
                prs,
                ..
            },
        ) if repository == &input.repository
            && fork_heads.len() <= 10_000
            && prs.len() <= 10_000
            && fork_heads.iter().all(|fork| {
                fork.number != 0
                    && fork.head_ref == input.head_ref
                    && fork.base_ref == input.base_ref
            })
            && prs.iter().all(|pr| {
                pr.number != 0
                    && pr.head_ref == input.head_ref
                    && pr.base_ref == input.base_ref
                    && pr.changed_files_count == pr.changed_files.len() as u64
                    && pr.changed_files.len() <= 10_000
                    && pr
                        .changed_files
                        .iter()
                        .all(|path| valid_fact_string(path, 1024))
                    && pr.checks.len() <= 10_000
                    && pr.checks.iter().all(|check| {
                        check.database_id != 0
                            && check.head_sha == pr.head_sha
                            && valid_fact_string(&check.name, 4096)
                    })
            }) =>
        {
            Ok(())
        }
        _ => Err(HostClientError::ResultValidation),
    }
}

fn valid_fact_string(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|value| {
            value.is_control()
                || (0x200b..=0x200f).contains(&(value as u32))
                || (0x202a..=0x202e).contains(&(value as u32))
                || (0x2060..=0x206f).contains(&(value as u32))
                || (0xfeff..=0xfeff).contains(&(value as u32))
                || (0xfff9..=0xfffb).contains(&(value as u32))
                || (0xe0000..=0xe0fff).contains(&(value as u32))
        })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read as _, Write as _},
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    use super::*;
    use crate::model::{
        ActionBoundary, ActionFacts, AuditCommitment, DelegationId, GithubPullRequestCreateInput,
        GrantId, JournalSequence, OPERATION_RESULT_SCHEMA, OperationId, OperationOutcome,
        OperationResult, PersonaId, ProcessBindingId, ProcessOutcome, RequestDigest,
        RunnerEvidence, SessionId, SubmissionId,
    };
    use serde_json::json;

    fn authority_state_root() -> std::path::PathBuf {
        crate::authority_state_directory(crate::effective_uid()).unwrap()
    }

    fn current_process_identity() -> DaemonProcessIdentityWire {
        let (server, _client) = UnixStream::pair().unwrap();
        let peer = identity::peer_identity(&server).unwrap();
        DaemonProcessIdentityWire {
            pid: peer.pid(),
            pid_version: peer.pid_version(),
            euid: peer.euid(),
            egid: peer.egid(),
            executable_digest_sha256: peer.executable_digest().to_sha256_hex(),
        }
    }

    #[test]
    fn transport_timeout_remains_distinct_from_malformed_response() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "deadline");
        assert!(matches!(
            response_frame_error(timeout),
            HostClientError::DaemonTimeout
        ));
        let truncated = io::Error::new(io::ErrorKind::UnexpectedEof, "truncated");
        assert!(matches!(
            response_frame_error(truncated),
            HostClientError::InvalidResponseFrame
        ));
    }

    fn request(input: Value) -> SessionRequest {
        serde_json::from_value(json!({
            "schema": SESSION_REQUEST_SCHEMA,
            "request": {
                "schema": ACTION_REQUEST_SCHEMA,
                "submission_id": SubmissionId::from_bytes([8_u8; 32]),
                "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
                "action": GITHUB_PUBLISH_REF_ACTION,
                "input": input
            },
            "artifact_length": 42
        }))
        .unwrap()
    }

    fn validate_owned_request(
        role: AdapterRole,
        request: &SessionRequest,
    ) -> Result<ValidatedIntent, HostClientError> {
        validate_request(
            role,
            &BorrowedSessionRequest {
                schema: &request.schema,
                reconnect_proof: request.reconnect_proof.as_ref(),
                request: &request.request,
                artifact_length: request.artifact_length,
            },
        )
    }

    fn canonical_builder_action_fixture() -> &'static [u8] {
        br#"{"artifact_length":0,"reconnect_proof":[34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34,34],"request":{"action":"github.pull-request.create/v1","input":{"base_ref":"refs/heads/main","body":"","head_ref":"refs/heads/ws/demo/builder-1","repository":"github:emberdotlink/ember","title":"wb: demo builder-1"},"pack":{"address":"ember.pack/github","version":2},"schema":"ember.action-request/v1","submission_id":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17]},"schema":"ember.session-action-request/v1"}"#
    }

    fn run_adapter_with_response(response: &[u8]) -> (Result<(), HostClientError>, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("session.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let response = response.to_vec();
        let daemon = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request).unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(stream.read(&mut trailing).unwrap(), 0);
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let action = canonical_builder_action_fixture();
        let mut input = Vec::with_capacity(4 + action.len());
        input.extend_from_slice(&(action.len() as u32).to_be_bytes());
        input.extend_from_slice(action);
        let endpoint = SessionEndpointWire {
            schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
            socket_path,
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            daemon_process: current_process_identity(),
        };
        let mut output = Vec::new();
        let result = run_inherited_with_io(
            AdapterRole::Builder,
            &endpoint,
            &mut Cursor::new(input),
            &mut output,
        );
        daemon.join().unwrap();
        (result, output)
    }

    #[test]
    fn canonical_pull_request_fixture_passes_real_intent_validation() {
        let fixture = canonical_builder_action_fixture();
        let action: SessionActionRequest = serde_json::from_slice(fixture).unwrap();
        assert_eq!(serde_jcs::to_vec(&action).unwrap(), fixture);

        let request = BorrowedSessionRequest {
            schema: SESSION_REQUEST_SCHEMA,
            reconnect_proof: action.reconnect_proof.as_ref(),
            request: &action.request,
            artifact_length: action.artifact_length,
        };
        let intent = validate_request(AdapterRole::Builder, &request).unwrap();
        assert!(matches!(intent, ValidatedIntent::PullRequest(_)));
    }

    #[test]
    fn adapter_rejects_noncanonical_and_duplicate_key_response_frames() {
        let mut noncanonical = br#"{"error":{"code":"authority_gap","message":"authority admission refused"},"schema":"ember.session-response/v1"}"#.to_vec();
        noncanonical.push(b'\n');
        let duplicate = br#"{"error":{"code":"authority_gap","message":"authority admission refused"},"schema":"ember.session-response/v1","schema":"ember.session-response/v1"}"#;

        for response in [noncanonical.as_slice(), duplicate.as_slice()] {
            let (result, output) = run_adapter_with_response(response);
            assert!(matches!(result, Err(HostClientError::InvalidResponse)));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn adapter_refuses_a_replaced_session_listener_before_sending_request() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("session.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let daemon = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let mut daemon_process = current_process_identity();
        let replacement = if daemon_process.executable_digest_sha256.starts_with('0') {
            "1"
        } else {
            "0"
        };
        daemon_process
            .executable_digest_sha256
            .replace_range(..1, replacement);
        let endpoint = SessionEndpointWire {
            schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
            socket_path,
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            daemon_process,
        };
        let action = canonical_builder_action_fixture();
        let mut input = Vec::with_capacity(4 + action.len());
        input.extend_from_slice(&(action.len() as u32).to_be_bytes());
        input.extend_from_slice(action);
        let mut output = Vec::new();

        let result = run_inherited_with_io(
            AdapterRole::Builder,
            &endpoint,
            &mut Cursor::new(input),
            &mut output,
        );

        assert!(matches!(result, Err(HostClientError::DaemonAuthentication)));
        assert!(output.is_empty());
        daemon.join().unwrap();
    }

    #[test]
    fn inherited_action_cannot_select_authority() {
        let endpoint = SessionEndpointWire {
            schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
            socket_path: authority_state_root()
                .join("session-endpoints")
                .join("bound.sock"),
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            daemon_process: current_process_identity(),
        };
        let external = request(planner_intent());
        let action = SessionActionRequest {
            schema: SESSION_ACTION_REQUEST_SCHEMA.to_owned(),
            request: external.request.clone(),
            reconnect_proof: Some([7_u8; 32]),
            artifact_length: external.artifact_length,
        };

        let bound = bind_session_action(&endpoint, &action).unwrap();
        assert_eq!(bound.reconnect_proof, Some(&[7_u8; 32]));
        let value = serde_json::to_value(&bound).unwrap();
        assert_eq!(action.reconnect_proof(), Some(&[7_u8; 32]));
        assert!(value.get("grant_id").is_none());
        assert!(value.get("delegation_id").is_none());
        assert!(value.get("process_binding_id").is_none());
        assert!(value.get("session_id").is_none());
    }

    #[test]
    fn inherited_endpoint_is_absolute_authority_state_and_selector_free() {
        let mut endpoint = json!({
            "schema": SESSION_ENDPOINT_SCHEMA,
            "socket_path": authority_state_root()
                .join("session-endpoints")
                .join("bound.sock"),
            "session_id": SessionId::new(),
            "process_binding_id": ProcessBindingId::new(),
            "daemon_process": current_process_identity(),
        });
        assert!(decode_session_endpoint(&serde_jcs::to_vec(&endpoint).unwrap()).is_ok());

        endpoint["socket_path"] = json!("/tmp/substitute.sock");
        assert!(matches!(
            decode_session_endpoint(&serde_jcs::to_vec(&endpoint).unwrap()),
            Err(HostClientError::InvalidSessionEndpoint)
        ));

        endpoint["socket_path"] = json!(
            authority_state_root()
                .join("session-endpoints")
                .join("bound.sock")
        );
        endpoint["grants"] = json!([]);
        assert!(matches!(
            decode_session_endpoint(&serde_jcs::to_vec(&endpoint).unwrap()),
            Err(HostClientError::InvalidSessionEndpoint)
        ));
    }

    #[test]
    fn inherited_bootstrap_rejects_unpinned_activation_and_authority_selectors() {
        let mut bootstrap = json!({
            "schema": SESSION_BOOTSTRAP_SCHEMA,
            "activation_socket_path": authority_state_root()
                .join("session-endpoints")
                .join("activation.sock"),
            "session_id": SessionId::new(),
            "challenge_hex": "01".repeat(32),
            "daemon_process": current_process_identity(),
        });

        bootstrap["activation_socket_path"] = json!("/tmp/substitute.sock");
        assert!(matches!(
            activate_inherited_session(&serde_jcs::to_vec(&bootstrap).unwrap()),
            Err(HostClientError::InvalidSessionEndpoint)
        ));

        bootstrap["activation_socket_path"] = json!(
            authority_state_root()
                .join("session-endpoints")
                .join("activation.sock")
        );
        bootstrap["grant_id"] = json!(GrantId::new());
        assert!(matches!(
            activate_inherited_session(&serde_jcs::to_vec(&bootstrap).unwrap()),
            Err(HostClientError::InvalidSessionEndpoint)
        ));
    }

    fn planner_intent() -> Value {
        json!({
            "repository": "github:acme/planning",
            "expected_old_oid": "0".repeat(40),
            "new_oid": "1".repeat(40),
            "destination_ref": "refs/heads/ws/demo/planner-1"
        })
    }

    #[test]
    fn session_request_serializes_no_authority_or_control_selectors() {
        let mut envelope = request(planner_intent());
        envelope.reconnect_proof = Some([7_u8; 32]);

        let value = serde_json::to_value(&envelope).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        assert_eq!(object["reconnect_proof"], json!(vec![7_u8; 32]));
        assert!(object["request"].is_object());
        assert_eq!(object["artifact_length"], json!(42));
        for forbidden in [
            "grant_id",
            "grants",
            "delegation_id",
            "delegations",
            "session_id",
            "process_binding_id",
            "credential",
            "token",
            "control",
        ] {
            assert!(object.get(forbidden).is_none());
        }
    }

    #[test]
    fn session_request_rejects_caller_authority_and_control_selectors() {
        for (key, value) in [
            ("session_id", json!(SessionId::new())),
            ("process_binding_id", json!(ProcessBindingId::new())),
            ("grant_id", json!(GrantId::new())),
            ("delegation_id", json!(DelegationId::new())),
            ("delegation_ids", json!([DelegationId::new()])),
            ("role", json!("planner")),
            ("persona_id", json!(PersonaId::new())),
            ("uid", json!(501)),
            ("executable", json!("/tmp/attacker")),
            ("authority_scope", json!(["repository:admin"])),
            ("credential", json!("secret")),
            ("token", json!("secret")),
            ("control", json!("revoke")),
        ] {
            let mut envelope = serde_json::to_value(request(planner_intent())).unwrap();
            envelope
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), value);
            assert!(serde_json::from_value::<SessionRequest>(envelope).is_err());
        }
    }

    #[test]
    fn role_executables_accept_only_their_role_ref() {
        assert!(validate_owned_request(AdapterRole::Planner, &request(planner_intent())).is_ok());
        assert!(matches!(
            validate_owned_request(AdapterRole::Builder, &request(planner_intent())),
            Err(HostClientError::WrongRole)
        ));
    }

    #[test]
    fn role_executables_accept_cas_republication() {
        let mut input = planner_intent();
        input["expected_old_oid"] = Value::String("2".repeat(40));

        assert!(validate_owned_request(AdapterRole::Planner, &request(input)).is_ok());
    }

    #[test]
    fn adapter_rejects_artifact_and_execution_coordinates_in_intent() {
        for (key, value) in [
            (
                "artifact",
                json!(format!("artifact:sha256:{}", "a".repeat(64))),
            ),
            ("socket", json!("/tmp/attacker.sock")),
            ("cwd", json!("/tmp/attacker")),
            ("provider_instance", json!("attacker")),
            ("environment", json!({"TOKEN": "attacker"})),
            ("role", json!("planner")),
            ("persona_id", json!(PersonaId::new())),
            ("grant_id", json!("attacker-grant")),
            ("uid", json!(501)),
            ("executable", json!("/tmp/attacker")),
            ("authority_scope", json!(["repository:admin"])),
        ] {
            let mut input = planner_intent();
            input.as_object_mut().unwrap().insert(key.to_owned(), value);
            assert!(matches!(
                validate_owned_request(AdapterRole::Planner, &request(input)),
                Err(HostClientError::InvalidRequest)
            ));
        }
    }

    #[test]
    fn real_host_transport_forwards_and_validates_an_immutable_result() {
        let directory = tempfile::tempdir().unwrap();
        let session_socket_path = directory.path().join("session.sock");
        let listener = UnixListener::bind(&session_socket_path).unwrap();

        let input_value = json!({
            "repository": "github:Acme/Planning",
            "head_ref": "refs/heads/ws/demo/planner-1",
            "base_ref": "refs/heads/main",
            "title": "wb: demo planner-1",
            "body": ""
        });
        let submission_id = crate::model::SubmissionId::from_bytes([7_u8; 32]);
        let envelope = json!({
            "schema": SESSION_ACTION_REQUEST_SCHEMA,
            "request": {
                "schema": ACTION_REQUEST_SCHEMA,
                "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
                "action": GITHUB_PULL_REQUEST_CREATE_ACTION,
                "input": input_value,
                "submission_id": submission_id,
            },
            "artifact_length": 0
        });
        let request_bytes = serde_json::to_vec(&envelope).unwrap();
        let mut input_bytes = Vec::with_capacity(4 + request_bytes.len());
        input_bytes.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
        input_bytes.extend_from_slice(&request_bytes);

        let response_input = serde_json::to_value(
            serde_json::from_value::<GithubPullRequestCreateInput>(input_value.clone()).unwrap(),
        )
        .unwrap();
        let session_id = SessionId::new();
        let process_binding_id = ProcessBindingId::new();
        let response_session_id = session_id.clone();
        let response_process_binding_id = process_binding_id.clone();
        let daemon = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request).unwrap();
            let request: SessionRequest = serde_json::from_slice(&request).unwrap();
            assert_eq!(request.request.input["repository"], "github:acme/planning");
            let request_digest = RequestDigest::of(&serde_jcs::to_vec(&request.request).unwrap());
            let mut trailing = [0_u8; 1];
            assert_eq!(stream.read(&mut trailing).unwrap(), 0);

            let typed: GithubPullRequestCreateInput =
                serde_json::from_value(response_input.clone()).unwrap();
            let facts = ActionFacts::GithubPullRequestCreated {
                repository: typed.repository.clone(),
                number: 17,
                html_url: "https://github.com/acme/planning/pull/17".to_owned(),
                head_ref: typed.head_ref,
                base_ref: typed.base_ref,
            };
            let result = OperationResult {
                schema: OPERATION_RESULT_SCHEMA.to_owned(),
                outcome: OperationOutcome::new(
                    OperationId::new(),
                    submission_id,
                    request_digest,
                    JournalSequence::new(1).unwrap(),
                    None,
                    ActionBoundary::EffectCompleted { succeeded: true },
                ),
                persona_id: PersonaId::new(),
                session_id: response_session_id.clone(),
                process_binding_id: response_process_binding_id.clone(),
                grant_id: Some(GrantId::new()),
                delegation_path: vec![DelegationId::new()],
                status: TerminalStatus::Success,
                action: Some(GITHUB_PULL_REQUEST_CREATE_ACTION.to_owned()),
                approved_input: Some(response_input),
                resource: Some(typed.repository),
                need: None,
                provider: None,
                runner: Some(RunnerEvidence {
                    adapter: "github.api/v1".to_owned(),
                    executable_digest_sha256: None,
                    credential_helper_digest_sha256: None,
                    artifact_digest_sha256: None,
                    process: Some(ProcessOutcome {
                        exit_code: Some(0),
                        signal: None,
                        stdout_digest: None,
                        stderr_digest: None,
                    }),
                    credential_peer_served_count: None,
                    credential_peer_rejected_count: None,
                }),
                facts: Some(facts),
                upstream_revoked: true,
                audit: AuditCommitment {
                    first_hash: "b".repeat(64),
                    last_hash: "c".repeat(64),
                    fact_count: 1,
                },
                started_at_unix: 1,
                completed_at_unix: 2,
                message: "GitHub API action succeeded".to_owned(),
            };
            let endpoint = SessionEndpointWire {
                schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
                socket_path: PathBuf::from("/unused"),
                session_id: response_session_id,
                process_binding_id: response_process_binding_id,
                daemon_process: current_process_identity(),
            };
            let borrowed_request = BorrowedSessionRequest {
                schema: request.schema.as_str(),
                reconnect_proof: request.reconnect_proof.as_ref(),
                request: &request.request,
                artifact_length: request.artifact_length,
            };
            let intent = validate_request(AdapterRole::Planner, &borrowed_request).unwrap();
            let assert_rejected = |forged_result: &OperationResult| {
                assert!(matches!(
                    validate_result_binding(
                        forged_result,
                        &endpoint,
                        &borrowed_request,
                        &intent,
                        [0_u8; 32],
                    ),
                    Err(HostClientError::ResultValidation)
                ));
            };
            let mut forged_result = result.clone();
            forged_result.process_binding_id = ProcessBindingId::new();
            assert_rejected(&forged_result);
            let mut forged_result = result.clone();
            forged_result.session_id = SessionId::new();
            assert_rejected(&forged_result);
            let response = serde_jcs::to_vec(&SessionResultResponse {
                schema: SESSION_RESPONSE_SCHEMA.to_owned(),
                result,
                reconnect_proof: Some([9_u8; 32]),
            })
            .unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
            response
        });

        let mut output = Vec::new();
        let endpoint = SessionEndpointWire {
            schema: SESSION_ENDPOINT_SCHEMA.to_owned(),
            socket_path: session_socket_path,
            session_id,
            process_binding_id,
            daemon_process: current_process_identity(),
        };
        run_inherited_with_io(
            AdapterRole::Planner,
            &endpoint,
            &mut Cursor::new(input_bytes),
            &mut output,
        )
        .unwrap();
        let response = daemon.join().unwrap();
        assert_eq!(output, [response, b"\n".to_vec()].concat());
    }
}
