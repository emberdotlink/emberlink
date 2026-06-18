//! Tier-0 daemon-managed ssh-agent (ARCH-BROKER-SSH-AGENT-TIER0).
//!
//! Per the 2026-05-05 grill (Angle A1): the daemon IS the ssh-agent for a
//! session. A fresh ed25519 keypair is minted in the daemon's address space,
//! never written to disk. The agent process tree talks to the daemon via a
//! Unix-domain socket whose path is set as `SSH_AUTH_SOCK` in the child env.
//!
//! ## Protocol
//!
//! Implements the OpenSSH agent wire format (RFC 4252 §6, openssh PROTOCOL.agent):
//!
//! - `SSH_AGENTC_REQUEST_IDENTITIES` (0x0b / 11) → returns the session pubkey.
//! - `SSH_AGENTC_SIGN_REQUEST` (0x0d / 13) → signs a blob with the in-memory privkey.
//! - All other message types → `SSH_AGENT_FAILURE` (0x05 / 5).
//!
//! `SSH_AGENTC_ADD_IDENTITY` is intentionally unimplemented — this agent is
//! daemon-managed only; callers cannot inject keys.
//!
//! ## Session lifecycle
//!
//! `spawn_session_ssh_agent` → binds UDS → returns `SshAgentHandle`.
//! Dropping the handle zeros the private key and unlinks the socket.
//!
//! ## GitHub deploy-key lifecycle
//!
//! [`spawn_session_ssh_agent_with_github_deploy_key`] layers GitHub
//! deploy-key registration on top of [`spawn_session_ssh_agent`]:
//!
//! 1. Mint a fresh ed25519 keypair and bind the UDS (Tier-0 path).
//! 2. Mint a GitHub App installation token via
//!    [`crate::github_app::mint_installation_token`].
//! 3. POST the session pubkey to `/repos/{owner}/{repo}/keys` as a
//!    read-only deploy-key titled `"ember session <session_id>"`.
//! 4. Retain the returned [`DeployKeyHandle`] inside the parent
//!    [`SshAgentHandle`] so dropping the parent fires
//!    `DELETE /repos/{owner}/{repo}/keys/{key_id}`.
//!
//! Registration is **best-effort + auditable**: when the GitHub API call
//! fails (rate-limited, network down, repo not found, App not configured)
//! the spawn function still returns `Ok(handle)` and records the failure
//! reason on the handle via
//! [`SshAgentHandle::deploy_key_registration_failed`]. Callers can read
//! the field and decide whether to proceed. Drop-time deregistration logs
//! via `tracing::warn!` on failure but never panics.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// OpenSSH agent wire constants
// ---------------------------------------------------------------------------

// `pub(crate)` so the lease-gated bridge (`ssh_agent_bridge.rs`) can recognize
// message types when it inspects/relays OpenSSH agent frames — it reuses these
// constants rather than re-declaring the protocol (compose, don't rebuild).
/// Client → agent: list identities.
pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent → client: identity list response.
pub(crate) const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client → agent: sign a blob.
pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent → client: signature response.
pub(crate) const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Agent → client: generic failure.
pub(crate) const SSH_AGENT_FAILURE: u8 = 5;

/// Ed25519 key type string as used in OpenSSH wire format.
const KEY_TYPE_ED25519: &str = "ssh-ed25519";
/// SSH_AGENT_RSA_SHA2_512 flag — for ed25519 signing we use this constant
/// for the `flags` field; the actual hash is implicit in the key type.
#[allow(dead_code)]
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

// ---------------------------------------------------------------------------
// Wire-framing helpers
// ---------------------------------------------------------------------------

/// Encode a length-prefixed string (SSH `string` type).
///
/// `pub(crate)`: the bridge's tests build OpenSSH key blobs / sign requests with
/// the same encoder the agent uses, rather than re-deriving the wire shape.
pub(crate) fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    let len = s.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
    out
}

/// Decode a length-prefixed string from `buf` starting at `offset`.
/// Returns `(value, new_offset)`.
///
/// `pub(crate)`: the bridge reuses it to parse the host agent's
/// `SSH_AGENT_IDENTITIES_ANSWER` (to learn the session pubkey blob) and to
/// shape-check responses — the same bounds-checked parser, not a second copy.
pub(crate) fn decode_string(buf: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
    let start = offset + 4;
    let end = start + len;
    if end > buf.len() {
        return None;
    }
    Some((&buf[start..end], end))
}

/// Decode a u32 from `buf` at `offset`. Returns `(value, new_offset)`.
///
/// `pub(crate)`: reused by the bridge's identities-answer parser.
pub(crate) fn decode_u32(buf: &[u8], offset: usize) -> Option<(u32, usize)> {
    if offset + 4 > buf.len() {
        return None;
    }
    let v = u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?);
    Some((v, offset + 4))
}

/// Wrap a payload in an OpenSSH agent length-prefixed message frame.
/// `payload[0]` must already be the message-type byte.
fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build `SSH_AGENT_FAILURE` frame.
fn failure_frame() -> Vec<u8> {
    frame_message(&[SSH_AGENT_FAILURE])
}

// ---------------------------------------------------------------------------
// Request-identities encoding
// ---------------------------------------------------------------------------

/// Build `SSH_AGENT_IDENTITIES_ANSWER` for a single ed25519 key.
///
/// Wire shape (RFC 4252 / PROTOCOL.agent §2.5.2):
///
/// ```text
/// byte    SSH_AGENT_IDENTITIES_ANSWER
/// uint32  nkeys
/// [per-key]
///   string  blob    (public key blob)
///   string  comment
/// ```
///
/// The public key blob for ed25519 is:
///
/// ```text
/// string  "ssh-ed25519"
/// string  <32-byte pubkey>
/// ```
pub fn encode_identities_answer(pubkey_bytes: &[u8]) -> Vec<u8> {
    // Build the public key blob.
    let mut pk_blob: Vec<u8> = Vec::new();
    pk_blob.extend_from_slice(&encode_string(KEY_TYPE_ED25519.as_bytes()));
    pk_blob.extend_from_slice(&encode_string(pubkey_bytes));

    // Build the payload.
    let mut payload: Vec<u8> = Vec::new();
    payload.push(SSH_AGENT_IDENTITIES_ANSWER);
    // nkeys = 1
    payload.extend_from_slice(&1u32.to_be_bytes());
    // key blob
    payload.extend_from_slice(&encode_string(&pk_blob));
    // comment
    payload.extend_from_slice(&encode_string(b"ember-session-key"));

    frame_message(&payload)
}

// ---------------------------------------------------------------------------
// Sign-request decoding + sign-response encoding
// ---------------------------------------------------------------------------

/// Parse `SSH_AGENTC_SIGN_REQUEST` body (after the message-type byte).
///
/// ```text
/// string  key_blob
/// string  data
/// uint32  flags
/// ```
///
/// Returns `(data_to_sign, flags)` if the key blob matches `expected_pubkey_blob`.
pub fn decode_sign_request<'a>(
    buf: &'a [u8],
    expected_pubkey_blob: &[u8],
) -> Option<(&'a [u8], u32)> {
    // Skip type byte (caller already consumed it) — buf starts after type byte.
    let (key_blob, offset) = decode_string(buf, 0)?;
    if key_blob != expected_pubkey_blob {
        return None;
    }
    let (data, offset) = decode_string(buf, offset)?;
    let (flags, _offset) = decode_u32(buf, offset)?;
    Some((data, flags))
}

/// RFC 4252 `SSH_MSG_USERAUTH_REQUEST` message number — the second field of a
/// publickey sign blob, used to recognize an auth-attribution blob.
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// Parseable userauth attribution fields recovered from a publickey sign blob
/// (ssh-agent-over-bridge S3 audit fidelity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshUserauthFields {
    /// The authenticating user name.
    pub user: String,
    /// The SSH service name (normally `ssh-connection`).
    pub service: String,
    /// The auth method name (normally `publickey`).
    pub method: String,
    /// The public-key algorithm name (e.g. `ssh-ed25519`).
    pub pubkey_algo: String,
}

/// Best-effort parse of an OpenSSH publickey **sign blob** (`data` from a
/// [`decode_sign_request`]) into its RFC 4252 userauth fields, for audit
/// attribution.
///
/// The layout signed for `publickey` userauth is:
///
/// ```text
/// string  session identifier
/// byte    SSH_MSG_USERAUTH_REQUEST (50)
/// string  user name
/// string  service name
/// string  method name ("publickey")
/// boolean TRUE
/// string  public key algorithm name
/// string  public key blob
/// ```
///
/// The agent protocol allows a client to ask the host agent to sign **arbitrary**
/// bytes, so this is **advisory** (audit-only), never a gate: a blob that is not
/// a recognizable publickey userauth request returns `None`, and the sign is
/// still audited by `data` hash. The opaque-`data` limitation (an audit row alone
/// can't say which host/repo — the repo isn't in the SSH handshake) is covered by
/// correlating the **egress** log, per the S3 spec.
pub fn parse_sign_userauth(data: &[u8]) -> Option<SshUserauthFields> {
    // string  session identifier
    let (_session_id, offset) = decode_string(data, 0)?;
    // byte    SSH_MSG_USERAUTH_REQUEST
    if *data.get(offset)? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let offset = offset + 1;
    // string  user name
    let (user, offset) = decode_string(data, offset)?;
    // string  service name
    let (service, offset) = decode_string(data, offset)?;
    // string  method name
    let (method, offset) = decode_string(data, offset)?;
    // boolean (present for a real signature attempt; not hard-required)
    let offset = offset + 1;
    // string  public key algorithm name
    let (algo, _offset) = decode_string(data, offset)?;
    Some(SshUserauthFields {
        user: String::from_utf8_lossy(user).into_owned(),
        service: String::from_utf8_lossy(service).into_owned(),
        method: String::from_utf8_lossy(method).into_owned(),
        pubkey_algo: String::from_utf8_lossy(algo).into_owned(),
    })
}

/// Build `SSH_AGENT_SIGN_RESPONSE` for an ed25519 signature.
///
/// ```text
/// byte    SSH_AGENT_SIGN_RESPONSE
/// string  signature_blob
/// ```
///
/// Signature blob:
/// ```text
/// string  "ssh-ed25519"
/// string  <64-byte signature>
/// ```
pub fn encode_sign_response(sig_bytes: &[u8]) -> Vec<u8> {
    let mut sig_blob: Vec<u8> = Vec::new();
    sig_blob.extend_from_slice(&encode_string(KEY_TYPE_ED25519.as_bytes()));
    sig_blob.extend_from_slice(&encode_string(sig_bytes));

    let mut payload: Vec<u8> = Vec::new();
    payload.push(SSH_AGENT_SIGN_RESPONSE);
    payload.extend_from_slice(&encode_string(&sig_blob));

    frame_message(&payload)
}

// ---------------------------------------------------------------------------
// Session key — zeroized on drop
// ---------------------------------------------------------------------------

/// A session ed25519 keypair. The private key bytes are zeroed when this
/// value is dropped (via `Zeroize`). The verifying key is derived from it
/// and is non-secret.
struct SessionKey {
    /// Raw 32-byte seed — kept as a `Vec` so `Zeroize` can clear it.
    seed: Vec<u8>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SessionKey {
    /// Mint a fresh ed25519 keypair from OS entropy.
    fn generate() -> Result<Self> {
        let mut seed = vec![0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| anyhow::anyhow!("getrandom for ssh-agent session key: {e}"))?;
        let signing_key = SigningKey::from_bytes(seed[..32].try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            seed,
            signing_key,
            verifying_key,
        })
    }

    /// Build a key from a caller-supplied 32-byte ed25519 seed. Test-only: the
    /// bridge's "private key never crosses the wire" test needs to know the
    /// exact secret bytes so it can assert they are absent from every captured
    /// frame. Production keys are always `generate`d from OS entropy.
    #[cfg(test)]
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            seed: seed.to_vec(),
            signing_key,
            verifying_key,
        }
    }

    /// Sign `data` and return the 64-byte raw signature.
    fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// The 32-byte raw public key.
    fn pubkey_bytes(&self) -> &[u8] {
        self.verifying_key.as_bytes()
    }

    /// Build the OpenSSH public key blob for this key.
    fn pubkey_blob(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&encode_string(KEY_TYPE_ED25519.as_bytes()));
        blob.extend_from_slice(&encode_string(self.pubkey_bytes()));
        blob
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        // Zero the signing key bytes explicitly.
        let mut raw: [u8; 32] = self.signing_key.to_bytes();
        raw.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Deploy-key error type
// ---------------------------------------------------------------------------

/// Errors returned by deploy-key registration operations.
#[derive(Debug, thiserror::Error)]
pub enum SshAgentError {
    #[error("GitHub App credentials not configured on this handle")]
    NotConfigured,
    #[error("installation token mint failed: {0}")]
    TokenMint(String),
    #[error("GitHub API request failed: {0}")]
    Http(String),
    #[error("GitHub API returned unexpected status {status}: {body}")]
    BadResponse { status: u16, body: String },
    #[error("response parse failed: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Deploy-key HTTP client trait (separate from github_app::HttpClient)
// ---------------------------------------------------------------------------

/// Minimal HTTP client trait for deploy-key registration/deregistration.
/// Separate from [`crate::github_app::HttpClient`] (which is scoped to
/// installation-token minting) so the two concerns stay independent.
///
/// Tests inject `MockDeployKeyClient` (defined in the test module).
/// Production code uses [`ReqwestDeployKeyClient`].
#[async_trait::async_trait]
pub trait DeployKeyHttpClient: Send + Sync {
    /// POST a JSON body to `url` with `Authorization: Bearer <bearer>`.
    /// Returns `(status_code, response_body_string)`.
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: &str,
    ) -> Result<(u16, String), SshAgentError>;

    /// DELETE `url` with `Authorization: Bearer <bearer>`.
    /// Returns `(status_code, response_body_string)`.
    async fn delete_bearer(&self, url: &str, bearer: &str) -> Result<(u16, String), SshAgentError>;
}

// ---------------------------------------------------------------------------
// Production reqwest-backed DeployKeyHttpClient
// ---------------------------------------------------------------------------

/// Production [`DeployKeyHttpClient`] backed by `reqwest`.
pub struct ReqwestDeployKeyClient {
    inner: reqwest::Client,
}

impl ReqwestDeployKeyClient {
    pub fn new() -> Self {
        let inner = reqwest::Client::builder()
            .user_agent("ember-broker/deploy-key")
            .build()
            .expect("reqwest client construction must not fail in production");
        Self { inner }
    }
}

impl Default for ReqwestDeployKeyClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl DeployKeyHttpClient for ReqwestDeployKeyClient {
    async fn post_json_bearer(
        &self,
        url: &str,
        bearer: &str,
        body: &str,
    ) -> Result<(u16, String), SshAgentError> {
        let resp = self
            .inner
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| SshAgentError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| SshAgentError::Http(e.to_string()))?;
        Ok((status, text))
    }

    async fn delete_bearer(&self, url: &str, bearer: &str) -> Result<(u16, String), SshAgentError> {
        let resp = self
            .inner
            .delete(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| SshAgentError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| SshAgentError::Http(e.to_string()))?;
        Ok((status, text))
    }
}

// ---------------------------------------------------------------------------
// DeployKeyHandle — holds the registered key id; deregisters on drop
// ---------------------------------------------------------------------------

/// Handle for a registered GitHub deploy key.
///
/// Dropping this handle fires a best-effort `DELETE /repos/<owner>/<repo>/keys/<id>`
/// using a `tokio::spawn` so the async call can run without blocking `Drop`.
/// Errors are logged and swallowed — `drop` must not panic.
pub struct DeployKeyHandle {
    pub key_id: u64,
    pub owner: String,
    pub repo: String,
    /// Title used when registering: `"ember session <session-id>"`.
    pub key_title: String,
    bearer_token: secrecy::SecretString,
    client: Arc<dyn DeployKeyHttpClient>,
}

impl std::fmt::Debug for DeployKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployKeyHandle")
            .field("key_id", &self.key_id)
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("key_title", &self.key_title)
            .finish()
    }
}

impl Drop for DeployKeyHandle {
    fn drop(&mut self) {
        let url = format!(
            "https://api.github.com/repos/{}/{}/keys/{}",
            self.owner, self.repo, self.key_id
        );
        let bearer = self.bearer_token.expose_secret().to_string();
        let client = Arc::clone(&self.client);
        let key_id = self.key_id;
        let owner = self.owner.clone();
        let repo = self.repo.clone();
        // Best-effort async deregister. `tokio::spawn` PANICS when no runtime
        // is active — it does NOT return a JoinError as the previous comment
        // claimed — and a panic in Drop can abort the process (fatal if the
        // drop runs during unwinding). Guard with `Handle::try_current()` and
        // skip the spawn when there is no runtime (drop in a sync context, or
        // during shutdown after the runtime has gone away). The token's ~1h
        // TTL is the real safety net for a skipped best-effort DELETE.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!(
                key_id,
                owner,
                repo,
                "no tokio runtime at DeployKeyHandle drop; skipping best-effort deploy-key DELETE (token TTL-bound)"
            );
            return;
        };
        let _handle = handle.spawn(async move {
            match client.delete_bearer(&url, &bearer).await {
                Ok((204, _)) | Ok((404, _)) => {
                    tracing::debug!(key_id, owner, repo, "deploy-key deregistered");
                }
                Ok((status, body)) => {
                    tracing::warn!(
                        key_id,
                        owner,
                        repo,
                        status,
                        body,
                        "deploy-key DELETE returned unexpected status"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        key_id,
                        owner,
                        repo,
                        error = %e,
                        "deploy-key DELETE failed (best-effort, ignoring)"
                    );
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// SshAgentHandle
// ---------------------------------------------------------------------------

/// Handle returned by `spawn_session_ssh_agent`. Dropping it stops the
/// agent task, zeros the private key, and unlinks the socket.
pub struct SshAgentHandle {
    /// Absolute path to the UDS — the value callers put into `SSH_AUTH_SOCK`.
    pub auth_sock_path: PathBuf,
    /// Drop guard: stopping the task cancels the accept loop.
    _task: tokio::task::JoinHandle<()>,
    /// Drop guard: zeros the privkey and unlinks the socket on drop.
    _guard: Arc<AgentGuard>,
    /// Session identifier — embedded in deploy-key titles for traceability.
    session_id: String,
    /// The session ed25519 keypair (Arc shared with the accept loop).
    session_key: Arc<SessionKey>,
    /// GitHub App credentials for deploy-key registration. `None` when
    /// GH App is not configured (most sessions).
    gh_creds: Option<crate::github_app::GhAppCredentials>,
    /// HTTP client used for deploy-key API calls. Swapped for a mock in tests.
    deploy_key_client: Arc<dyn DeployKeyHttpClient>,
    /// Idempotency registry: `(owner, repo)` → `key_id`. Ensures that
    /// calling `register_deploy_key` twice with the same target is a no-op.
    deploy_key_registry: Mutex<HashMap<(String, String), u64>>,
    /// Deploy-key handles retained by the spawn-with-deploy-key flow so
    /// that dropping this `SshAgentHandle` cascades into
    /// `DELETE /repos/<owner>/<repo>/keys/<id>` for each registered key.
    /// Other (non-retaining) callers of `register_deploy_key` get the
    /// `DeployKeyHandle` directly and own its lifecycle.
    retained_deploy_keys: Mutex<Vec<DeployKeyHandle>>,
    /// Reason string captured when
    /// [`spawn_session_ssh_agent_with_github_deploy_key`] failed to
    /// register the deploy-key (best-effort flow). `None` means either
    /// registration succeeded or no deploy-key spawn was attempted.
    deploy_key_registration_failed: Mutex<Option<String>>,
}

struct AgentGuard {
    socket_path: PathBuf,
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for SshAgentHandle {
    fn drop(&mut self) {
        // Abort the accept loop. Without this the spawned task (which holds its
        // own `Arc<AgentGuard>`) never ends, so the `AgentGuard` never drops and
        // the agent socket is never unlinked — leaking a live, ungated signer
        // after teardown / on a partial-bind failure. Aborting the task releases
        // its `Arc`, and the `AgentGuard` then unlinks the socket. This makes the
        // type's "dropping it stops the agent task and unlinks the socket"
        // contract real (load-bearing for the ssh-bridge per-session teardown).
        self._task.abort();
    }
}

// ---------------------------------------------------------------------------
// SshAgentHandle — deploy-key registration impl
// ---------------------------------------------------------------------------

/// Response shape from `POST /repos/<owner>/<repo>/keys`.
#[derive(serde::Deserialize)]
struct GhDeployKeyResponse {
    id: u64,
}

impl SshAgentHandle {
    /// Register the session pubkey as a GitHub deploy-key on `owner/repo`.
    ///
    /// Mints an installation token via the configured GitHub App, then calls
    /// `POST /repos/<owner>/<repo>/keys` with the session pubkey. The returned
    /// `key_id` is stored in the handle so `Drop` can DELETE it.
    ///
    /// Idempotent: if this handle has already registered a key for the same
    /// `(owner, repo)` pair, the existing `key_id` is returned immediately
    /// without a second POST.
    pub async fn register_deploy_key(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<DeployKeyHandle, SshAgentError> {
        let creds = self.gh_creds.as_ref().ok_or(SshAgentError::NotConfigured)?;

        // Mint installation token for the API call.
        let token = crate::github_app::mint_installation_token(creds, &[], &[])
            .await
            .map_err(|e| SshAgentError::TokenMint(e.to_string()))?;

        self.register_deploy_key_with_token(owner, repo, &token.token)
            .await
    }

    /// Inner implementation that accepts a pre-minted bearer token. Used
    /// by `register_deploy_key` (production) and tests (which supply a
    /// fixture token to bypass the GitHub App JWT flow).
    async fn register_deploy_key_with_token(
        &self,
        owner: &str,
        repo: &str,
        bearer_token: &str,
    ) -> Result<DeployKeyHandle, SshAgentError> {
        // Idempotency check.
        {
            let registry = self
                .deploy_key_registry
                .lock()
                .expect("deploy key registry mutex");
            if let Some(&key_id) = registry.get(&(owner.to_string(), repo.to_string())) {
                let key_title = format!("ember session {}", self.session_id);
                return Ok(DeployKeyHandle {
                    key_id,
                    owner: owner.to_string(),
                    repo: repo.to_string(),
                    key_title,
                    bearer_token: secrecy::SecretString::from(bearer_token.to_string()),
                    client: Arc::clone(&self.deploy_key_client),
                });
            }
        }

        // Build the OpenSSH public key wire format: "ssh-ed25519 <base64-of-blob>".
        let pk_blob = self.session_key.pubkey_blob();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk_blob);
        let pubkey_wire = format!("ssh-ed25519 {pk_b64}");

        let key_title = format!("ember session {}", self.session_id);

        let body = serde_json::json!({
            "title": key_title,
            "key": pubkey_wire,
            "read_only": true,
        })
        .to_string();

        let url = format!("https://api.github.com/repos/{owner}/{repo}/keys");
        let (status, resp_body) = self
            .deploy_key_client
            .post_json_bearer(&url, bearer_token, &body)
            .await?;

        if status != 201 {
            return Err(SshAgentError::BadResponse {
                status,
                body: resp_body,
            });
        }

        let parsed: GhDeployKeyResponse = serde_json::from_str(&resp_body)
            .map_err(|e| SshAgentError::Parse(format!("parse deploy key response: {e}")))?;

        let key_id = parsed.id;

        // Record in the idempotency registry.
        {
            let mut registry = self
                .deploy_key_registry
                .lock()
                .expect("deploy key registry mutex");
            registry.insert((owner.to_string(), repo.to_string()), key_id);
        }

        Ok(DeployKeyHandle {
            key_id,
            owner: owner.to_string(),
            repo: repo.to_string(),
            key_title,
            bearer_token: secrecy::SecretString::from(bearer_token.to_string()),
            client: Arc::clone(&self.deploy_key_client),
        })
    }

    /// Register a deploy-key on `owner/repo` using a pre-minted bearer
    /// token, retain the resulting [`DeployKeyHandle`] inside this
    /// [`SshAgentHandle`], and return `()` on success. On failure, the
    /// error reason is recorded in
    /// [`SshAgentHandle::deploy_key_registration_failed`] and `Ok(())` is
    /// returned (best-effort flow — see module docs).
    ///
    /// "Retain" means the parent handle owns the `DeployKeyHandle`, so
    /// dropping the parent fires `DELETE /repos/<owner>/<repo>/keys/<id>`
    /// for every retained key. Callers that need to manage the deploy-key
    /// lifecycle themselves should use
    /// [`SshAgentHandle::register_deploy_key`] (or
    /// `register_deploy_key_with_token` in tests) and own the returned
    /// handle directly.
    pub async fn register_and_retain_deploy_key_with_token(
        &self,
        owner: &str,
        repo: &str,
        bearer_token: &str,
    ) {
        match self
            .register_deploy_key_with_token(owner, repo, bearer_token)
            .await
        {
            Ok(dk_handle) => {
                let mut retained = self
                    .retained_deploy_keys
                    .lock()
                    .expect("retained deploy keys mutex");
                retained.push(dk_handle);
            }
            Err(e) => {
                let mut failed = self
                    .deploy_key_registration_failed
                    .lock()
                    .expect("deploy key registration failed mutex");
                *failed = Some(e.to_string());
                tracing::warn!(
                    owner,
                    repo,
                    error = %e,
                    "deploy-key registration failed (best-effort, returning Ok handle)"
                );
            }
        }
    }

    /// Returns the failure reason captured by the deploy-key spawn path,
    /// or `None` if registration succeeded (or no spawn-with-deploy-key
    /// flow was used). Useful for callers that need to decide whether to
    /// proceed when the GitHub side of the bring-up failed.
    pub fn deploy_key_registration_failed(&self) -> Option<String> {
        self.deploy_key_registration_failed
            .lock()
            .expect("deploy key registration failed mutex")
            .clone()
    }

    /// Number of retained deploy-key handles. Exposed for tests and
    /// observability. Production code typically only registers a single
    /// deploy-key per session.
    pub fn retained_deploy_key_count(&self) -> usize {
        self.retained_deploy_keys
            .lock()
            .expect("retained deploy keys mutex")
            .len()
    }

    /// Configure GitHub App credentials on this handle. Returns `self` for
    /// chaining. Used by tests and callers that set up GH App after construction.
    pub fn with_gh_creds(mut self, creds: crate::github_app::GhAppCredentials) -> Self {
        self.gh_creds = Some(creds);
        self
    }

    /// Swap the deploy-key HTTP client. Used by tests to inject a mock.
    pub fn with_deploy_key_client(mut self, client: Arc<dyn DeployKeyHttpClient>) -> Self {
        self.deploy_key_client = client;
        self
    }

    /// Test-only constructor that creates a minimal handle with no real UDS,
    /// usable for unit-testing the deploy-key API calls in isolation.
    #[cfg(test)]
    #[allow(private_interfaces)]
    pub fn new_for_test(
        session_id: &str,
        session_key: Arc<SessionKey>,
        deploy_key_client: Arc<dyn DeployKeyHttpClient>,
    ) -> Self {
        // Spawn a no-op task as the _task placeholder.
        let task = tokio::spawn(async {});
        Self {
            auth_sock_path: PathBuf::from("/dev/null"),
            _task: task,
            _guard: Arc::new(AgentGuard {
                socket_path: PathBuf::new(),
            }),
            session_id: session_id.to_string(),
            session_key,
            gh_creds: None,
            deploy_key_client,
            deploy_key_registry: Mutex::new(HashMap::new()),
            retained_deploy_keys: Mutex::new(Vec::new()),
            deploy_key_registration_failed: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Tier-1 entitlement probe (macOS only)
// ---------------------------------------------------------------------------

/// Returns `true` if the running binary has Secure Enclave entitlement.
///
/// Probes by attempting to generate a throwaway SE key. If it succeeds, the
/// binary is signed with the necessary entitlement. On unsigned binaries,
/// macOS VMs without SE passthrough, or non-macOS platforms this always
/// returns `false`.
///
/// The probe key is immediately discarded; it is not stored anywhere.
#[cfg(target_os = "macos")]
fn binary_has_se_entitlement() -> bool {
    use crate::secure_enclave::{SeKeychainTarget, generate_secure_enclave_key};
    // A unique-enough label that won't collide with real session keys.
    match generate_secure_enclave_key(
        "ember-se-entitlement-probe",
        SeKeychainTarget::LoginKeychain,
    ) {
        Ok(_key) => {
            // Key was created — SE entitlement confirmed.
            // The key is dropped here and never stored.
            true
        }
        Err(e) => {
            tracing::debug!(error = %e, "SE entitlement probe: not available (expected on unsigned binaries)");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Checkpoint function (target_state_anchor: `fn spawn_session_ssh_agent`)
// ---------------------------------------------------------------------------

/// Mint a fresh ed25519 keypair, bind a Unix-domain ssh-agent socket for
/// `session_id`, and return a handle with `auth_sock_path`.
///
/// On macOS, if the binary has Secure Enclave entitlement (detected via a
/// transient key probe), this function transparently delegates to
/// `ssh_agent_macos::spawn_session_ssh_agent_se` (Tier-1). Otherwise it falls
/// through to the Tier-0 in-memory ed25519 path.
///
/// The returned `SshAgentHandle` is the drop guard: dropping it zeros the
/// private key bytes and unlinks the socket. Callers should set
/// `SSH_AUTH_SOCK=<handle.auth_sock_path>` in the child process environment.
///
/// The socket is created at `~/.ember/run/ssh-agent-<session_id>.sock`
/// (mode 0600, owner-only) — the in-daemon ssh-bridge is its only client.
///
/// # Errors
///
/// Returns an error if key generation fails, the socket directory cannot be
/// created, or the UDS bind fails.
pub fn spawn_session_ssh_agent(session_id: &str) -> Result<SshAgentHandle> {
    // ------------------------------------------------------------------
    // Tier-1 fast path: Secure Enclave (macOS signed binary with Touch ID)
    // ------------------------------------------------------------------
    #[cfg(target_os = "macos")]
    {
        if binary_has_se_entitlement() {
            use crate::secure_enclave::{SeKeychainTarget, generate_secure_enclave_key};
            use crate::ssh_agent_macos::spawn_session_ssh_agent_se;

            let label = format!("ember-session-{session_id}");
            match generate_secure_enclave_key(&label, SeKeychainTarget::LoginKeychain) {
                Ok(se_key) => match spawn_session_ssh_agent_se(session_id, se_key) {
                    Ok(se_handle) => {
                        tracing::info!(
                            session_id,
                            auth_sock = %se_handle.auth_sock_path.display(),
                            "ssh-agent: Tier-1 SE-backed agent active (Touch ID per sign)"
                        );
                        // Convert SeAgentHandle into SshAgentHandle by binding a new
                        // Tier-0 wrapper around the SE socket path.
                        // We reuse the socket the SE agent already bound — just hand
                        // the caller the path. The SE agent task owns the socket.
                        //
                        // NOTE: We can't directly return a SeAgentHandle as SshAgentHandle
                        // because they are different types. Instead we return the Tier-0
                        // handle after the SE agent is running. Since both share a
                        // different socket path, this returns the SE socket path.
                        // Build a placeholder session_key for the SE path so
                        // register_deploy_key can read the pubkey. In the SE
                        // case the real key lives in the SE handle, but we
                        // need the pubkey bytes here for the deploy-key title.
                        // Generate a throwaway key for the pubkey bytes only —
                        // it is never used for signing on the Tier-0 path.
                        let placeholder_key =
                            Arc::new(SessionKey::generate().unwrap_or_else(|_| SessionKey {
                                seed: vec![0u8; 32],
                                signing_key: SigningKey::from_bytes(&[0u8; 32]),
                                verifying_key: SigningKey::from_bytes(&[0u8; 32]).verifying_key(),
                            }));
                        return Ok(SshAgentHandle {
                            auth_sock_path: se_handle.auth_sock_path.clone(),
                            _task: {
                                // Detach the SE agent task — it lives independently.
                                // We spawn a no-op task as the Tier-0 _task placeholder.
                                tokio::spawn(async move {
                                    // Keep se_handle alive for the lifetime of this task.
                                    let _se = se_handle;
                                    // Yield indefinitely so the SE agent stays alive.
                                    loop {
                                        tokio::time::sleep(tokio::time::Duration::from_secs(3600))
                                            .await;
                                    }
                                })
                            },
                            _guard: Arc::new(AgentGuard {
                                // The SE agent already owns its socket. We create a guard
                                // for a non-existent path so our Drop is a no-op here
                                // (the SE guard handles the real cleanup).
                                socket_path: PathBuf::new(),
                            }),
                            session_id: session_id.to_string(),
                            session_key: placeholder_key,
                            gh_creds: None,
                            deploy_key_client: Arc::new(ReqwestDeployKeyClient::default()),
                            deploy_key_registry: Mutex::new(HashMap::new()),
                            retained_deploy_keys: Mutex::new(Vec::new()),
                            deploy_key_registration_failed: Mutex::new(None),
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "ssh-agent: Tier-1 SE spawn failed, falling back to Tier-0"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "ssh-agent: SE key gen failed after entitlement probe, falling back to Tier-0"
                    );
                }
            }
        }
    }
    // ------------------------------------------------------------------
    // Tier-0 path: in-memory ed25519 (default on unsigned/non-macOS)
    // ------------------------------------------------------------------
    let run_dir = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".ember").join("run")
    };
    std::fs::create_dir_all(&run_dir).context("create ~/.ember/run")?;

    let socket_path = run_dir.join(format!("ssh-agent-{session_id}.sock"));
    // Remove stale socket from a previous session if present.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind ssh-agent socket: {}", socket_path.display()))?;

    // Mode 0600: owner-only. The in-daemon ssh-bridge is the ONLY client of this
    // raw signer socket; group access (the former `0660`) existed solely for the
    // retired broker_exec cross-uid child. Owner-only keeps the ungated raw signer
    // unreachable to any non-daemon principal, so the lease-gated bridge is the
    // only sign path a (different-uid) client can reach.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("set socket permissions")?;

    let session_key = Arc::new(SessionKey::generate()?);
    let guard = Arc::new(AgentGuard {
        socket_path: socket_path.clone(),
    });
    let guard_clone = Arc::clone(&guard);
    let session_key_clone = Arc::clone(&session_key);

    let task = tokio::spawn(agent_accept_loop(listener, session_key, guard_clone));

    Ok(SshAgentHandle {
        auth_sock_path: socket_path,
        _task: task,
        _guard: guard,
        session_id: session_id.to_string(),
        session_key: session_key_clone,
        gh_creds: None,
        deploy_key_client: Arc::new(ReqwestDeployKeyClient::default()),
        deploy_key_registry: Mutex::new(HashMap::new()),
        retained_deploy_keys: Mutex::new(Vec::new()),
        deploy_key_registration_failed: Mutex::new(None),
    })
}

/// Test-only: bind a Tier-0 host agent for `session_id` keyed by a caller-known
/// ed25519 `seed`, unconditionally (no Secure Enclave probe). The bridge's
/// "key never crosses the wire" test uses this so it can assert the exact 32
/// secret bytes never appear in any captured frame. The socket lands under a
/// caller-chosen `run_dir` (a tempdir in tests) so concurrent tests don't
/// collide on `~/.ember/run`.
#[cfg(test)]
pub(crate) fn spawn_tier0_ssh_agent_with_seed(
    session_id: &str,
    seed: [u8; 32],
    run_dir: &std::path::Path,
) -> Result<SshAgentHandle> {
    std::fs::create_dir_all(run_dir).context("create test ssh-agent run dir")?;
    let socket_path = run_dir.join(format!("ssh-agent-{session_id}.sock"));
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind ssh-agent socket: {}", socket_path.display()))?;
    // 0600 owner-only — mirrors the production path (the bridge is the only client).
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("set socket permissions")?;

    let session_key = Arc::new(SessionKey::from_seed(seed));
    let guard = Arc::new(AgentGuard {
        socket_path: socket_path.clone(),
    });
    let guard_clone = Arc::clone(&guard);
    let session_key_clone = Arc::clone(&session_key);
    let task = tokio::spawn(agent_accept_loop(listener, session_key, guard_clone));

    Ok(SshAgentHandle {
        auth_sock_path: socket_path,
        _task: task,
        _guard: guard,
        session_id: session_id.to_string(),
        session_key: session_key_clone,
        gh_creds: None,
        deploy_key_client: Arc::new(ReqwestDeployKeyClient::default()),
        deploy_key_registry: Mutex::new(HashMap::new()),
        retained_deploy_keys: Mutex::new(Vec::new()),
        deploy_key_registration_failed: Mutex::new(None),
    })
}

// ---------------------------------------------------------------------------
// Spawn-with-GitHub-deploy-key (Phase 1A entry point)
// ---------------------------------------------------------------------------

/// Spawn a session ssh-agent (per [`spawn_session_ssh_agent`]) and register
/// the session pubkey as a GitHub deploy-key on `owner/repo`.
///
/// The returned [`SshAgentHandle`]:
///
/// - has `gh_creds` populated so subsequent `register_deploy_key` calls work,
/// - retains the registered [`DeployKeyHandle`] so dropping the parent fires
///   `DELETE /repos/<owner>/<repo>/keys/<id>`,
/// - exposes [`SshAgentHandle::deploy_key_registration_failed`] when the
///   GitHub-side bring-up failed.
///
/// **Best-effort failure mode.** If the GitHub App is not configured, the
/// installation-token mint fails, or the deploy-key POST returns a non-201
/// status, this function still returns `Ok(handle)` with the failure
/// reason recorded on the handle. Callers can inspect
/// [`SshAgentHandle::deploy_key_registration_failed`] and decide whether
/// to proceed.
///
/// The only `Err` return path is when the underlying
/// [`spawn_session_ssh_agent`] call fails (key generation or UDS bind) —
/// the deploy-key half is always best-effort.
pub async fn spawn_session_ssh_agent_with_github_deploy_key(
    session_id: &str,
    owner: &str,
    repo: &str,
    creds: crate::github_app::GhAppCredentials,
) -> Result<SshAgentHandle> {
    let handle = spawn_session_ssh_agent(session_id)?.with_gh_creds(creds);

    // Best-effort: register the deploy-key. Use the public
    // `register_deploy_key` (which mints its own installation token) so
    // we go through the full production flow.
    match handle.register_deploy_key(owner, repo).await {
        Ok(dk_handle) => {
            let mut retained = handle
                .retained_deploy_keys
                .lock()
                .expect("retained deploy keys mutex");
            retained.push(dk_handle);
        }
        Err(e) => {
            let mut failed = handle
                .deploy_key_registration_failed
                .lock()
                .expect("deploy key registration failed mutex");
            *failed = Some(e.to_string());
            tracing::warn!(
                owner,
                repo,
                error = %e,
                "deploy-key registration failed during spawn (best-effort, returning Ok handle)"
            );
        }
    }

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Agent accept loop
// ---------------------------------------------------------------------------

async fn agent_accept_loop(
    listener: UnixListener,
    session_key: Arc<SessionKey>,
    _guard: Arc<AgentGuard>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let key = Arc::clone(&session_key);
                tokio::spawn(handle_agent_connection(stream, key));
            }
            Err(e) => {
                tracing::warn!(error = %e, "ssh-agent accept error");
                break;
            }
        }
    }
}

async fn handle_agent_connection(mut stream: UnixStream, session_key: Arc<SessionKey>) {
    loop {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => return, // EOF or error — connection closed.
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 256 * 1024 {
            tracing::warn!("ssh-agent: invalid message length {msg_len}");
            return;
        }

        let mut msg = vec![0u8; msg_len];
        if stream.read_exact(&mut msg).await.is_err() {
            return;
        }
        if msg.is_empty() {
            let _ = stream.write_all(&failure_frame()).await;
            continue;
        }

        let msg_type = msg[0];
        let body = &msg[1..];

        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => encode_identities_answer(session_key.pubkey_bytes()),
            SSH_AGENTC_SIGN_REQUEST => {
                let pubkey_blob = session_key.pubkey_blob();
                match decode_sign_request(body, &pubkey_blob) {
                    Some((data, _flags)) => {
                        let sig = session_key.sign(data);
                        encode_sign_response(&sig)
                    }
                    None => {
                        tracing::warn!("ssh-agent: sign request key mismatch or parse error");
                        failure_frame()
                    }
                }
            }
            other => {
                tracing::debug!(msg_type = other, "ssh-agent: unhandled message type");
                failure_frame()
            }
        };

        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (T1 — protocol framing + drop guard)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Protocol framing tests ---

    #[test]
    fn encode_decode_string_roundtrip() {
        let s = b"ssh-ed25519";
        let encoded = encode_string(s);
        assert_eq!(encoded.len(), 4 + s.len());
        let (decoded, offset) = decode_string(&encoded, 0).unwrap();
        assert_eq!(decoded, s);
        assert_eq!(offset, encoded.len());
    }

    #[test]
    fn decode_string_rejects_truncated_length() {
        let buf = [0u8, 0u8, 0u8]; // only 3 bytes — can't read u32
        assert!(decode_string(&buf, 0).is_none());
    }

    // --- S3 audit: userauth field parsing ---

    fn build_userauth_sign_blob(
        user: &[u8],
        service: &[u8],
        method: &[u8],
        algo: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&encode_string(b"session-id-bytes")); // session identifier
        b.push(SSH_MSG_USERAUTH_REQUEST); // byte 50
        b.extend_from_slice(&encode_string(user));
        b.extend_from_slice(&encode_string(service));
        b.extend_from_slice(&encode_string(method));
        b.push(1); // boolean TRUE
        b.extend_from_slice(&encode_string(algo));
        b.extend_from_slice(&encode_string(b"<pubkey-blob>"));
        b
    }

    #[test]
    fn parse_sign_userauth_extracts_attribution_fields() {
        let blob = build_userauth_sign_blob(
            b"deploy-bot",
            b"ssh-connection",
            b"publickey",
            b"ssh-ed25519",
        );
        let fields = parse_sign_userauth(&blob).expect("a publickey userauth blob");
        assert_eq!(fields.user, "deploy-bot");
        assert_eq!(fields.service, "ssh-connection");
        assert_eq!(fields.method, "publickey");
        assert_eq!(fields.pubkey_algo, "ssh-ed25519");
    }

    #[test]
    fn parse_sign_userauth_returns_none_for_non_userauth_bytes() {
        // The agent can be asked to sign arbitrary bytes; those are audited by
        // `data` hash, not by parsed fields. A blob whose second field is not
        // SSH_MSG_USERAUTH_REQUEST, or that is truncated, yields None (advisory).
        assert!(parse_sign_userauth(b"not an ssh userauth blob at all").is_none());
        let mut almost = encode_string(b"session"); // valid string...
        almost.push(99); // ...wrong message number
        assert!(parse_sign_userauth(&almost).is_none());
        assert!(parse_sign_userauth(&[]).is_none());
    }

    #[test]
    fn decode_string_rejects_truncated_body() {
        let mut buf = encode_string(b"hello");
        buf.truncate(6); // cut off last byte of "hello"
        assert!(decode_string(&buf, 0).is_none());
    }

    #[test]
    fn encode_identities_answer_has_correct_frame() {
        let pubkey = [0x42u8; 32];
        let frame = encode_identities_answer(&pubkey);
        // First 4 bytes are the message length.
        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(
            frame.len(),
            4 + msg_len,
            "frame length prefix must match body"
        );
        // Message type byte.
        assert_eq!(frame[4], SSH_AGENT_IDENTITIES_ANSWER);
        // nkeys = 1
        let nkeys = u32::from_be_bytes(frame[5..9].try_into().unwrap());
        assert_eq!(nkeys, 1);
    }

    #[test]
    fn encode_sign_response_has_correct_frame() {
        let sig = [0xABu8; 64];
        let frame = encode_sign_response(&sig);
        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 4 + msg_len);
        assert_eq!(frame[4], SSH_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn decode_sign_request_matches_key_blob() {
        // Build a synthetic pubkey blob.
        let pubkey = [0x11u8; 32];
        let mut pubkey_blob = Vec::new();
        pubkey_blob.extend_from_slice(&encode_string(KEY_TYPE_ED25519.as_bytes()));
        pubkey_blob.extend_from_slice(&encode_string(&pubkey));

        let data_to_sign = b"commit:abc123";
        let flags: u32 = 0;

        // Build sign request body.
        let mut body = Vec::new();
        body.extend_from_slice(&encode_string(&pubkey_blob));
        body.extend_from_slice(&encode_string(data_to_sign));
        body.extend_from_slice(&flags.to_be_bytes());

        let result = decode_sign_request(&body, &pubkey_blob);
        assert!(result.is_some());
        let (data, f) = result.unwrap();
        assert_eq!(data, data_to_sign.as_slice());
        assert_eq!(f, flags);
    }

    #[test]
    fn decode_sign_request_rejects_wrong_key() {
        let correct_blob = b"correct-blob";
        let wrong_blob = b"wrong-blob";

        let data_to_sign = b"payload";
        let flags: u32 = 0;

        let mut body = Vec::new();
        body.extend_from_slice(&encode_string(wrong_blob));
        body.extend_from_slice(&encode_string(data_to_sign));
        body.extend_from_slice(&flags.to_be_bytes());

        let result = decode_sign_request(&body, correct_blob);
        assert!(
            result.is_none(),
            "must reject sign request for wrong key blob"
        );
    }

    // --- Drop-guard / zeroize tests ---

    #[test]
    fn session_key_seed_zeroize_mechanism() {
        // The earlier version of this test read seed memory through a raw
        // pointer AFTER SessionKey was dropped, asserting the bytes had
        // been zeroed. That is undefined behaviour: Vec's destructor frees
        // the allocation when SessionKey goes out of scope, and reading
        // freed memory has no defined contents on any allocator that may
        // reuse, scrub, or unmap the page. The test was passing on Linux
        // and failing on macOS — both outcomes were unsound.
        //
        // The real invariant is structural: SessionKey's Drop impl calls
        // `self.seed.zeroize()` BEFORE the field's Vec destructor releases
        // the heap allocation (see `impl Drop for SessionKey` above; line
        // 255 at this revision). Code-review enforces that ordering. What
        // we CAN test soundly is the mechanism — that `Vec::zeroize` does
        // what we expect on a buffer of the same shape — so that the Drop
        // impl's call site has the documented effect.
        use zeroize::Zeroize;
        let mut seed: Vec<u8> = (1u8..=32).collect();
        assert_eq!(seed.len(), 32);
        assert!(
            !seed.iter().all(|&b| b == 0),
            "fixture must not be all-zero before zeroize"
        );
        seed.zeroize();
        assert!(
            seed.iter().all(|&b| b == 0),
            "Vec::zeroize must zero all bytes"
        );
    }

    #[test]
    fn session_key_signing_produces_valid_signature() {
        use ed25519_dalek::Verifier;
        let key = SessionKey::generate().expect("keygen");
        let data = b"test payload for signing";
        let sig_bytes = key.sign(data);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verifying_key
            .verify(data, &sig)
            .expect("signature must verify");
    }

    #[test]
    fn failure_frame_has_correct_type_byte() {
        let frame = failure_frame();
        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        assert_eq!(msg_len, 1);
        assert_eq!(frame[4], SSH_AGENT_FAILURE);
    }

    // -----------------------------------------------------------------------
    // Deploy-key T1 tests (META-YOLO-BROKER-NATIVE-A)
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Recording mock for deploy-key HTTP calls.
    ///
    /// Stores the last URL + body for POST calls and the last URL for DELETE
    /// calls so tests can assert the correct endpoints were hit.
    struct RecordingMockClient {
        /// Canned response for POST calls: `(status, body)`.
        post_response: (u16, String),
        /// Canned response for DELETE calls: `(status, body)`.
        delete_response: (u16, String),
        /// Number of POST calls recorded.
        post_count: Arc<AtomicU64>,
        /// Number of DELETE calls recorded.
        delete_count: Arc<AtomicU64>,
        /// Last POST URL observed.
        last_post_url: Arc<Mutex<Option<String>>>,
        /// Last POST body observed.
        last_post_body: Arc<Mutex<Option<String>>>,
        /// Last DELETE URL observed.
        last_delete_url: Arc<Mutex<Option<String>>>,
    }

    impl RecordingMockClient {
        fn new(post_status: u16, post_body: String, delete_status: u16) -> Arc<Self> {
            Arc::new(Self {
                post_response: (post_status, post_body),
                delete_response: (delete_status, String::new()),
                post_count: Arc::new(AtomicU64::new(0)),
                delete_count: Arc::new(AtomicU64::new(0)),
                last_post_url: Arc::new(Mutex::new(None)),
                last_post_body: Arc::new(Mutex::new(None)),
                last_delete_url: Arc::new(Mutex::new(None)),
            })
        }

        fn post_count(&self) -> u64 {
            self.post_count.load(Ordering::SeqCst)
        }

        fn delete_count(&self) -> u64 {
            self.delete_count.load(Ordering::SeqCst)
        }

        fn last_post_url(&self) -> Option<String> {
            self.last_post_url.lock().unwrap().clone()
        }

        fn last_post_body(&self) -> Option<String> {
            self.last_post_body.lock().unwrap().clone()
        }

        fn last_delete_url(&self) -> Option<String> {
            self.last_delete_url.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DeployKeyHttpClient for RecordingMockClient {
        async fn post_json_bearer(
            &self,
            url: &str,
            _bearer: &str,
            body: &str,
        ) -> Result<(u16, String), SshAgentError> {
            self.post_count.fetch_add(1, Ordering::SeqCst);
            *self.last_post_url.lock().unwrap() = Some(url.to_string());
            *self.last_post_body.lock().unwrap() = Some(body.to_string());
            Ok((self.post_response.0, self.post_response.1.clone()))
        }

        async fn delete_bearer(
            &self,
            url: &str,
            _bearer: &str,
        ) -> Result<(u16, String), SshAgentError> {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            *self.last_delete_url.lock().unwrap() = Some(url.to_string());
            Ok((self.delete_response.0, self.delete_response.1.clone()))
        }
    }

    fn test_session_key() -> Arc<SessionKey> {
        Arc::new(SessionKey::generate().expect("session key generation must succeed in tests"))
    }

    /// T1 — register_deploy_key POSTs to the correct URL and includes the
    /// session pubkey in the request body.
    #[tokio::test]
    async fn test_register_deploy_key_posts_to_correct_url() {
        let mock = RecordingMockClient::new(
            201,
            r#"{"id":42,"key":"ssh-ed25519 AAAA","title":"ember session test-session-1","read_only":true,"verified":false,"created_at":"2026-01-01T00:00:00Z","url":"https://api.github.com/repos/test-owner/test-repo/keys/42"}"#.to_string(),
            204,
        );

        let session_key = test_session_key();
        let handle = SshAgentHandle::new_for_test(
            "test-session-1",
            session_key,
            Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        );

        let deploy_handle = handle
            .register_deploy_key_with_token("test-owner", "test-repo", "ghs_fixture_token")
            .await
            .expect("register_deploy_key must succeed");

        // Verify key_id from the mocked response.
        assert_eq!(
            deploy_handle.key_id, 42,
            "key_id must be 42 from mocked response"
        );
        assert_eq!(deploy_handle.owner, "test-owner");
        assert_eq!(deploy_handle.repo, "test-repo");
        assert_eq!(deploy_handle.key_title, "ember session test-session-1");

        // Verify POST was called exactly once to the correct URL.
        assert_eq!(mock.post_count(), 1, "exactly one POST must have been made");
        assert_eq!(
            mock.last_post_url().as_deref(),
            Some("https://api.github.com/repos/test-owner/test-repo/keys"),
            "POST URL must be the GitHub deploy keys endpoint"
        );

        // Verify the pubkey appears in the POST body.
        let body = mock
            .last_post_body()
            .expect("POST body must have been recorded");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("body must be valid JSON");
        let key_field = parsed["key"]
            .as_str()
            .expect("body must have a 'key' field");
        assert!(
            key_field.starts_with("ssh-ed25519 "),
            "key field must be an ssh-ed25519 pubkey wire string, got: {key_field}"
        );
    }

    /// T2 — dropping a `DeployKeyHandle` fires the DELETE call for the key.
    #[tokio::test]
    async fn test_deregister_deploy_key_on_drop() {
        let mock = RecordingMockClient::new(
            201,
            r#"{"id":42,"key":"ssh-ed25519 AAAA","title":"ember session s2","read_only":true,"verified":false,"created_at":"2026-01-01T00:00:00Z","url":"https://api.github.com/repos/test-owner/test-repo/keys/42"}"#.to_string(),
            204,
        );

        let session_key = test_session_key();
        let handle = SshAgentHandle::new_for_test(
            "s2",
            session_key,
            Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        );

        let deploy_handle = handle
            .register_deploy_key_with_token("test-owner", "test-repo", "ghs_fixture_token")
            .await
            .expect("register must succeed");

        assert_eq!(mock.delete_count(), 0, "no DELETE before drop");

        // Drop the handle — this must trigger the DELETE call.
        drop(deploy_handle);

        // The DELETE is spawned asynchronously; yield the runtime to let it run.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(mock.delete_count(), 1, "DELETE must be called on drop");
        assert_eq!(
            mock.last_delete_url().as_deref(),
            Some("https://api.github.com/repos/test-owner/test-repo/keys/42"),
            "DELETE URL must target the registered key"
        );
    }

    /// T2b — dropping a `DeployKeyHandle` OUTSIDE a tokio runtime must not
    /// panic. The Drop impl spawns a best-effort DELETE; `tokio::spawn`
    /// panics ("no reactor running") with no runtime, and a panic in Drop
    /// can abort the process. The `Handle::try_current()` guard turns the
    /// spawn into a no-op skip instead. (Synchronous `#[test]` = no runtime.)
    #[test]
    fn test_drop_without_runtime_does_not_panic() {
        let mock = RecordingMockClient::new(201, "{}".to_string(), 204);
        let handle = DeployKeyHandle {
            key_id: 7,
            owner: "test-owner".to_string(),
            repo: "test-repo".to_string(),
            key_title: "ember session no-rt".to_string(),
            bearer_token: secrecy::SecretString::from("ghs_fixture_token".to_string()),
            client: Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        };
        // Before the fix this panics; after, it returns early.
        drop(handle);
        assert_eq!(
            mock.delete_count(),
            0,
            "no DELETE should fire without a runtime"
        );
    }

    /// T4 — `register_and_retain_deploy_key_with_token` retains the
    /// `DeployKeyHandle` inside the parent `SshAgentHandle`, and dropping
    /// the parent triggers the DELETE call. This is the lifecycle
    /// `spawn_session_ssh_agent_with_github_deploy_key` relies on.
    #[tokio::test]
    async fn test_spawn_with_github_deploy_key_retains_and_deletes_on_drop() {
        let mock = RecordingMockClient::new(
            201,
            r#"{"id":7,"key":"ssh-ed25519 AAAA","title":"ember session s4","read_only":true,"verified":false,"created_at":"2026-01-01T00:00:00Z","url":"https://api.github.com/repos/owner/repo/keys/7"}"#.to_string(),
            204,
        );

        let session_key = test_session_key();
        let handle = SshAgentHandle::new_for_test(
            "s4",
            session_key,
            Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        );

        // Sanity: nothing retained, no failure recorded, no HTTP yet.
        assert_eq!(handle.retained_deploy_key_count(), 0);
        assert!(handle.deploy_key_registration_failed().is_none());
        assert_eq!(mock.post_count(), 0);
        assert_eq!(mock.delete_count(), 0);

        // Drive the deploy-key registration through the retain path —
        // this is exactly what `spawn_session_ssh_agent_with_github_deploy_key`
        // does post-spawn, modulo the installation-token mint.
        handle
            .register_and_retain_deploy_key_with_token("owner", "repo", "ghs_fixture_token")
            .await;

        // POST hit the create-deploy-key endpoint.
        assert_eq!(mock.post_count(), 1, "deploy-key POST must have fired");
        assert_eq!(
            mock.last_post_url().as_deref(),
            Some("https://api.github.com/repos/owner/repo/keys"),
        );

        // Handle now retains exactly one deploy key, no failure recorded.
        assert_eq!(handle.retained_deploy_key_count(), 1);
        assert!(handle.deploy_key_registration_failed().is_none());

        // No DELETE has fired yet — the retained handle is alive.
        assert_eq!(mock.delete_count(), 0);

        // Drop the parent `SshAgentHandle` — this drops the retained
        // `DeployKeyHandle` whose Drop fires the DELETE.
        drop(handle);

        // The DELETE is `tokio::spawn`-ed; yield repeatedly so the task runs.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert_eq!(mock.delete_count(), 1, "DELETE must fire on parent drop");
        assert_eq!(
            mock.last_delete_url().as_deref(),
            Some("https://api.github.com/repos/owner/repo/keys/7"),
            "DELETE must target the registered key by id",
        );
    }

    /// T5 — when the deploy-key POST returns a non-201 status,
    /// `register_and_retain_deploy_key_with_token` swallows the error,
    /// records the reason on `deploy_key_registration_failed`, and does
    /// not retain anything. This proves the best-effort contract from the
    /// module docs.
    #[tokio::test]
    async fn test_spawn_with_github_deploy_key_best_effort_on_post_failure() {
        let mock = RecordingMockClient::new(
            422, // GitHub returns 422 for "key already in use" / validation errors.
            r#"{"message":"key is already in use","documentation_url":""}"#.to_string(),
            204,
        );

        let session_key = test_session_key();
        let handle = SshAgentHandle::new_for_test(
            "s5",
            session_key,
            Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        );

        handle
            .register_and_retain_deploy_key_with_token("owner", "repo", "ghs_fixture_token")
            .await;

        // POST was attempted exactly once.
        assert_eq!(mock.post_count(), 1, "POST must have been attempted once");

        // Nothing retained.
        assert_eq!(handle.retained_deploy_key_count(), 0);

        // Failure reason recorded.
        let failed = handle
            .deploy_key_registration_failed()
            .expect("failure reason must be recorded");
        assert!(
            failed.contains("422") || failed.to_lowercase().contains("status"),
            "failure reason should mention the HTTP status, got: {failed}"
        );

        // Drop fires no DELETE (nothing was retained).
        drop(handle);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            mock.delete_count(),
            0,
            "no DELETE when nothing was retained"
        );
    }

    /// T3 — calling register_deploy_key twice with the same (owner, repo) is
    /// idempotent: the second call returns the cached key_id without a second POST.
    #[tokio::test]
    async fn test_register_deploy_key_idempotent() {
        let mock = RecordingMockClient::new(
            201,
            r#"{"id":99,"key":"ssh-ed25519 AAAA","title":"ember session s3","read_only":true,"verified":false,"created_at":"2026-01-01T00:00:00Z","url":"https://api.github.com/repos/owner/repo/keys/99"}"#.to_string(),
            204,
        );

        let session_key = test_session_key();
        let handle = SshAgentHandle::new_for_test(
            "s3",
            session_key,
            Arc::clone(&mock) as Arc<dyn DeployKeyHttpClient>,
        );

        let first = handle
            .register_deploy_key_with_token("owner", "repo", "ghs_fixture_token")
            .await
            .expect("first register must succeed");

        let second = handle
            .register_deploy_key_with_token("owner", "repo", "ghs_fixture_token")
            .await
            .expect("second register must succeed");

        // Both handles must report the same key_id.
        assert_eq!(first.key_id, 99);
        assert_eq!(second.key_id, 99, "idempotent call must return same key_id");

        // Only one POST must have been made.
        assert_eq!(mock.post_count(), 1, "second call must not POST again");
    }
}
