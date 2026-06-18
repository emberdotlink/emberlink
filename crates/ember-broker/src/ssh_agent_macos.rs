//! Tier-1 macOS ssh-agent: Secure Enclave-backed P-256 ECDSA session key.
//!
//! Same OpenSSH wire protocol as `ssh_agent.rs` (Tier-0), but the session key
//! is a P-256 ECDSA key backed by the Secure Enclave. Each
//! `SSH_AGENTC_SIGN_REQUEST` invocation triggers a Touch ID prompt via
//! `SecKeyCreateSignature`.
//!
//! ## Key type on the wire
//!
//! The SE supports P-256 ECDSA but not ed25519. Per OpenSSH convention, this
//! agent advertises `ecdsa-sha2-nistp256` identities. The signature blob uses
//! the `ecdsa-sha2-nistp256` type prefix.
//!
//! ## Entitlement gate
//!
//! SE key creation requires a signed binary with the Secure Enclave entitlement.
//! On unsigned binaries, `secure_enclave::generate_secure_enclave_key` returns
//! `SeError::NotSupported`, and the caller falls back to Tier-0.
//!
//! This module compiles only on `target_os = "macos"`.

#![cfg(target_os = "macos")]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::secure_enclave::{SeKeyHandle, SignKeyHandle, se_sign_with_touch_id_reason};

// ---------------------------------------------------------------------------
// OpenSSH agent wire constants (duplicated from ssh_agent.rs to keep modules
// self-contained; the Tier-0 file is not pub-reexported)
// ---------------------------------------------------------------------------

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_FAILURE: u8 = 5;

/// P-256 key type string as used in OpenSSH wire format.
const KEY_TYPE_ECDSA_P256: &str = "ecdsa-sha2-nistp256";
/// Curve name for the nistp256 identifier field in the public key blob.
const CURVE_NISTP256: &str = "nistp256";

// ---------------------------------------------------------------------------
// Wire-framing helpers (P-256 variants)
// ---------------------------------------------------------------------------

fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
    out
}

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

fn decode_u32(buf: &[u8], offset: usize) -> Option<(u32, usize)> {
    if offset + 4 > buf.len() {
        return None;
    }
    let v = u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?);
    Some((v, offset + 4))
}

fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn failure_frame() -> Vec<u8> {
    frame_message(&[SSH_AGENT_FAILURE])
}

// ---------------------------------------------------------------------------
// P-256 public key blob encoding
// ---------------------------------------------------------------------------

/// Build the OpenSSH public key blob for an `ecdsa-sha2-nistp256` key.
///
/// Wire shape (RFC 5656 §3.1):
/// ```text
/// string  "ecdsa-sha2-nistp256"
/// string  "nistp256"
/// string  <65-byte uncompressed point: 0x04 || X || Y>
/// ```
pub fn encode_ecdsa_p256_pubkey_blob(pubkey_uncompressed: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&encode_string(KEY_TYPE_ECDSA_P256.as_bytes()));
    blob.extend_from_slice(&encode_string(CURVE_NISTP256.as_bytes()));
    blob.extend_from_slice(&encode_string(pubkey_uncompressed));
    blob
}

/// Build `SSH_AGENT_IDENTITIES_ANSWER` for a single P-256 key.
pub fn encode_identities_answer_p256(pubkey_uncompressed: &[u8]) -> Vec<u8> {
    let pk_blob = encode_ecdsa_p256_pubkey_blob(pubkey_uncompressed);

    let mut payload = Vec::new();
    payload.push(SSH_AGENT_IDENTITIES_ANSWER);
    payload.extend_from_slice(&1u32.to_be_bytes()); // nkeys = 1
    payload.extend_from_slice(&encode_string(&pk_blob));
    payload.extend_from_slice(&encode_string(b"ember-se-session-key"));

    frame_message(&payload)
}

/// Parse `SSH_AGENTC_SIGN_REQUEST` body (after the message-type byte).
///
/// Returns `(data_to_sign, flags)` if the key blob matches `expected_pubkey_blob`.
pub fn decode_sign_request_p256<'a>(
    buf: &'a [u8],
    expected_pubkey_blob: &[u8],
) -> Option<(&'a [u8], u32)> {
    let (key_blob, offset) = decode_string(buf, 0)?;
    if key_blob != expected_pubkey_blob {
        return None;
    }
    let (data, offset) = decode_string(buf, offset)?;
    let (flags, _) = decode_u32(buf, offset)?;
    Some((data, flags))
}

/// Build `SSH_AGENT_SIGN_RESPONSE` for an ECDSA-P256 DER signature.
///
/// Signature blob (RFC 5656 §3.1.2):
/// ```text
/// string  "ecdsa-sha2-nistp256"
/// string  <DER-encoded ECDSA signature>
/// ```
pub fn encode_sign_response_p256(der_sig: &[u8]) -> Vec<u8> {
    let mut sig_blob = Vec::new();
    sig_blob.extend_from_slice(&encode_string(KEY_TYPE_ECDSA_P256.as_bytes()));
    sig_blob.extend_from_slice(&encode_string(der_sig));

    let mut payload = Vec::new();
    payload.push(SSH_AGENT_SIGN_RESPONSE);
    payload.extend_from_slice(&encode_string(&sig_blob));

    frame_message(&payload)
}

// ---------------------------------------------------------------------------
// Session SE key wrapper
// ---------------------------------------------------------------------------

/// Wraps a `SeKeyHandle` with the cached public key bytes and blob, so we
/// avoid re-exporting on every request.
struct SeSessionKey {
    /// SSH-agent keys are sign-only; carry the sign role in the type so the
    /// signing call sites are role-checked (ADR 206 AC-3).
    handle: SignKeyHandle,
    /// Uncompressed P-256 point (65 bytes).
    pubkey_uncompressed: Vec<u8>,
    /// Pre-built OpenSSH public key blob.
    pubkey_blob: Vec<u8>,
}

impl SeSessionKey {
    fn new(handle: SeKeyHandle) -> Result<Self, crate::secure_enclave::SeError> {
        let handle = SignKeyHandle::from_provisioned(handle);
        let pubkey_uncompressed = handle.public_key_bytes()?;
        let pubkey_blob = encode_ecdsa_p256_pubkey_blob(&pubkey_uncompressed);
        Ok(Self {
            handle,
            pubkey_uncompressed,
            pubkey_blob,
        })
    }
}

// ---------------------------------------------------------------------------
// Handle + guard
// ---------------------------------------------------------------------------

/// Drop guard that unlinks the UDS socket on drop.
struct SeAgentGuard {
    socket_path: PathBuf,
}

impl Drop for SeAgentGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Handle returned by `spawn_session_ssh_agent_se`.
pub struct SeAgentHandle {
    /// Absolute path to the UDS (`SSH_AUTH_SOCK` value).
    pub auth_sock_path: PathBuf,
    _task: tokio::task::JoinHandle<()>,
    _guard: Arc<SeAgentGuard>,
}

// ---------------------------------------------------------------------------
// Anchor: spawn_session_ssh_agent_se
// ---------------------------------------------------------------------------

/// Spawn a Secure Enclave-backed ssh-agent for `session_id`.
///
/// Binds a Unix-domain socket at `~/.ember/run/ssh-agent-se-<session_id>.sock`
/// and serves the OpenSSH agent protocol with a P-256 Secure Enclave key.
/// Each `SSH_AGENTC_SIGN_REQUEST` triggers a Touch ID prompt.
///
/// Returns `Err` if SE key generation fails (unsigned binary, no hardware,
/// macOS VM without SE passthrough). The caller should fall back to
/// `spawn_session_ssh_agent` (Tier-0) in that case.
pub fn spawn_session_ssh_agent_se(
    session_id: &str,
    se_handle: SeKeyHandle,
) -> Result<SeAgentHandle> {
    let run_dir = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".ember").join("run")
    };
    std::fs::create_dir_all(&run_dir).context("create ~/.ember/run")?;

    let socket_path = run_dir.join(format!("ssh-agent-se-{session_id}.sock"));
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind SE ssh-agent socket: {}", socket_path.display()))?;

    // 0600 owner-only — the in-daemon ssh-bridge is the sole client of this raw
    // signer socket (group access was for the retired broker_exec cross-uid child).
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("set SE socket permissions")?;

    let session_key =
        SeSessionKey::new(se_handle).map_err(|e| anyhow::anyhow!("SE session key init: {e}"))?;
    let session_key = Arc::new(session_key);

    let guard = Arc::new(SeAgentGuard {
        socket_path: socket_path.clone(),
    });
    let guard_clone = Arc::clone(&guard);

    let task = tokio::spawn(se_agent_accept_loop(listener, session_key, guard_clone));

    Ok(SeAgentHandle {
        auth_sock_path: socket_path,
        _task: task,
        _guard: guard,
    })
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

async fn se_agent_accept_loop(
    listener: UnixListener,
    session_key: Arc<SeSessionKey>,
    _guard: Arc<SeAgentGuard>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let key = Arc::clone(&session_key);
                tokio::spawn(handle_se_agent_connection(stream, key));
            }
            Err(e) => {
                tracing::warn!(error = %e, "SE ssh-agent accept error");
                break;
            }
        }
    }
}

async fn handle_se_agent_connection(mut stream: UnixStream, session_key: Arc<SeSessionKey>) {
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => return,
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 256 * 1024 {
            tracing::warn!("SE ssh-agent: invalid message length {msg_len}");
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
                encode_identities_answer_p256(&session_key.pubkey_uncompressed)
            }
            SSH_AGENTC_SIGN_REQUEST => {
                match decode_sign_request_p256(body, &session_key.pubkey_blob) {
                    Some((data, _flags)) => {
                        // This call triggers Touch ID on a signed binary.
                        match se_sign_with_touch_id_reason(
                            &session_key.handle,
                            data,
                            "approve Ember SSH signing",
                        ) {
                            Ok(der_sig) => encode_sign_response_p256(&der_sig),
                            Err(e) => {
                                tracing::warn!(error = %e, "SE ssh-agent: sign failed");
                                failure_frame()
                            }
                        }
                    }
                    None => {
                        tracing::warn!("SE ssh-agent: sign request key mismatch or parse error");
                        failure_frame()
                    }
                }
            }
            other => {
                tracing::debug!(msg_type = other, "SE ssh-agent: unhandled message type");
                failure_frame()
            }
        };

        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (T1 — mockable; no real SE, no Touch ID)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_enclave::{new_stub_key, se_sign_with_touch_id};

    #[test]
    fn encode_ecdsa_p256_pubkey_blob_structure() {
        let pubkey = [0x04u8]
            .iter()
            .chain([0xAAu8; 32].iter())
            .chain([0xBBu8; 32].iter())
            .copied()
            .collect::<Vec<u8>>();
        let blob = encode_ecdsa_p256_pubkey_blob(&pubkey);

        // Must start with length-prefixed "ecdsa-sha2-nistp256"
        let (key_type, offset) = decode_string(&blob, 0).expect("key_type");
        assert_eq!(key_type, KEY_TYPE_ECDSA_P256.as_bytes());
        // Then "nistp256"
        let (curve, offset) = decode_string(&blob, offset).expect("curve");
        assert_eq!(curve, CURVE_NISTP256.as_bytes());
        // Then the public key
        let (pk, _) = decode_string(&blob, offset).expect("pk");
        assert_eq!(pk, pubkey.as_slice());
    }

    #[test]
    fn encode_identities_answer_p256_frame_structure() {
        let pubkey = vec![0x04u8; 65];
        let frame = encode_identities_answer_p256(&pubkey);

        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(
            frame.len(),
            4 + msg_len,
            "frame length prefix must match body"
        );
        assert_eq!(frame[4], SSH_AGENT_IDENTITIES_ANSWER);

        let nkeys = u32::from_be_bytes(frame[5..9].try_into().unwrap());
        assert_eq!(nkeys, 1);
    }

    #[test]
    fn encode_sign_response_p256_frame_structure() {
        let der_sig = vec![0x30u8, 0x44, 0x02, 0x20];
        let frame = encode_sign_response_p256(&der_sig);
        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 4 + msg_len);
        assert_eq!(frame[4], SSH_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn decode_sign_request_p256_roundtrip() {
        let pubkey = vec![0x04u8; 65];
        let blob = encode_ecdsa_p256_pubkey_blob(&pubkey);
        let data = b"data to be signed by Touch ID";
        let flags: u32 = 0;

        let mut body = Vec::new();
        body.extend_from_slice(&encode_string(&blob));
        body.extend_from_slice(&encode_string(data));
        body.extend_from_slice(&flags.to_be_bytes());

        let result = decode_sign_request_p256(&body, &blob);
        assert!(result.is_some());
        let (got_data, got_flags) = result.unwrap();
        assert_eq!(got_data, data.as_slice());
        assert_eq!(got_flags, flags);
    }

    #[test]
    fn decode_sign_request_p256_rejects_wrong_key() {
        let correct_blob = b"correct-blob-p256";
        let wrong_blob = b"wrong-blob-p256";
        let data = b"payload";

        let mut body = Vec::new();
        body.extend_from_slice(&encode_string(wrong_blob));
        body.extend_from_slice(&encode_string(data));
        body.extend_from_slice(&0u32.to_be_bytes());

        assert!(decode_sign_request_p256(&body, correct_blob).is_none());
    }

    #[test]
    fn se_session_key_pubkey_bytes_shape() {
        let stub = new_stub_key("session-test");
        let session = SeSessionKey::new(stub).expect("SeSessionKey::new with stub");
        // Uncompressed P-256: 0x04 || 32-byte X || 32-byte Y = 65 bytes
        assert_eq!(session.pubkey_uncompressed.len(), 65);
        assert_eq!(session.pubkey_uncompressed[0], 0x04);
        // Blob must embed the key type
        let (key_type, _) = decode_string(&session.pubkey_blob, 0).expect("key type in blob");
        assert_eq!(key_type, KEY_TYPE_ECDSA_P256.as_bytes());
    }

    #[test]
    fn stub_sign_and_encode_response_is_valid_frame() {
        let stub = new_stub_key("sign-test");
        let session = SeSessionKey::new(stub).expect("SeSessionKey::new");
        let data = b"sign me via stub touch-id";
        let der_sig = se_sign_with_touch_id(&session.handle, data).expect("stub sign");
        let frame = encode_sign_response_p256(&der_sig);
        // Frame must have correct length prefix
        let msg_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 4 + msg_len);
        assert_eq!(frame[4], SSH_AGENT_SIGN_RESPONSE);
    }
}
