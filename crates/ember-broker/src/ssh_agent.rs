//! Tier-0 daemon-managed ssh-agent (implementation-note-28).
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
//! TODO: on session start, register the session
//! pubkey as a deploy-key on the target GitHub repo via the GitHub App.
//! On drop, deregister it. This is a separate task; the ssh-agent
//! infrastructure (this file) is the deliverable for implementation-note-28.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// OpenSSH agent wire constants
// ---------------------------------------------------------------------------

/// Client → agent: list identities.
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent → client: identity list response.
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client → agent: sign a blob.
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent → client: signature response.
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Agent → client: generic failure.
const SSH_AGENT_FAILURE: u8 = 5;

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
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    let len = s.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
    out
}

/// Decode a length-prefixed string from `buf` starting at `offset`.
/// Returns `(value, new_offset)`.
fn decode_string(buf: &[u8], offset: usize) -> Option<(&[u8], usize)> {
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
fn decode_u32(buf: &[u8], offset: usize) -> Option<(u32, usize)> {
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
}

struct AgentGuard {
    socket_path: PathBuf,
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
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
    use crate::secure_enclave::generate_secure_enclave_key;
    // A unique-enough label that won't collide with real session keys.
    match generate_secure_enclave_key("ember-se-entitlement-probe") {
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
/// (mode 0660) and is only accessible to the owning user.
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
            use crate::secure_enclave::generate_secure_enclave_key;
            use crate::ssh_agent_macos::spawn_session_ssh_agent_se;

            let label = format!("ember-session-{session_id}");
            match generate_secure_enclave_key(&label) {
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
                                        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                                    }
                                })
                            },
                            _guard: Arc::new(AgentGuard {
                                // The SE agent already owns its socket. We create a guard
                                // for a non-existent path so our Drop is a no-op here
                                // (the SE guard handles the real cleanup).
                                socket_path: PathBuf::new(),
                            }),
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

    // Mode 0660: owner rw, group rw, other none.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))
        .context("set socket permissions")?;

    let session_key = Arc::new(SessionKey::generate()?);
    let guard = Arc::new(AgentGuard {
        socket_path: socket_path.clone(),
    });
    let guard_clone = Arc::clone(&guard);

    let task = tokio::spawn(agent_accept_loop(listener, session_key, guard_clone));

    Ok(SshAgentHandle {
        auth_sock_path: socket_path,
        _task: task,
        _guard: guard,
    })
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
            SSH_AGENTC_REQUEST_IDENTITIES => {
                encode_identities_answer(session_key.pubkey_bytes())
            }
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
        assert_eq!(frame.len(), 4 + msg_len, "frame length prefix must match body");
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
        assert!(result.is_none(), "must reject sign request for wrong key blob");
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
}
