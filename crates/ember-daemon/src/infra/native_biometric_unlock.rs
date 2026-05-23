use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use core_crypto::presence::{
    DaemonSignedHandle, PresenceProofRequest, bind_presence_challenge, verify_presence_handle,
};
use once_cell::sync::Lazy;
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const REQUEST_TTL: Duration = Duration::from_secs(60);
const TRUSTED_PUBKEY_FILE: &str = "presence/native-touchid-p256.pub";
const CHALLENGE_DOMAIN: &[u8] = b"emberlink/v1/native-vault-unlock";

#[derive(Debug, Clone, Serialize)]
pub struct UnlockBeginResponse {
    pub request_id: String,
    pub challenge_hex: String,
    pub expires_at_unix_ms: u64,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_request: Option<PresenceProofRequest>,
}

#[derive(Debug, Clone)]
struct PendingRequest {
    challenge: [u8; 32],
    expires_at_unix_ms: u64,
    presence_scope_key: String,
    expected_presence_challenge: [u8; 32],
    expected_presence_persona: String,
}

#[derive(Debug, Clone)]
pub struct CompletedUnlock {
    pub presence_scope_key: String,
}

static PENDING_REQUESTS: Lazy<Mutex<HashMap<String, PendingRequest>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const LOCAL_UNLOCK_SPIFFE_URI: &str = "spiffe://emberd/operator/local-cli";
const LOCAL_UNLOCK_PERSONA_ID: &str = "operator-local";

pub fn begin(
    data_dir: &Path,
    reason: &str,
    presence_scope_key: &str,
) -> Result<UnlockBeginResponse, String> {
    begin_with_presence_proof(
        data_dir,
        reason,
        "vault_unlock",
        presence_scope_key,
        None,
    )
}

pub fn begin_with_presence_proof(
    data_dir: &Path,
    reason: &str,
    target_method: &str,
    presence_scope_key: &str,
    prompt_url: Option<String>,
) -> Result<UnlockBeginResponse, String> {
    let request_id = Uuid::new_v4().to_string();
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| format!("OS RNG failure: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(request_id.as_bytes());
    hasher.update(nonce);
    let challenge: [u8; 32] = hasher.finalize().into();
    let expires_at_unix_ms = now_unix_ms() + REQUEST_TTL.as_millis() as u64;
    let prompt_url = prompt_url.map(|base| {
        let trimmed = base.trim_end_matches('/');
        format!("{trimmed}/{}", request_id)
    });
    let presence_request = PresenceProofRequest {
        workflow_id: request_id.clone(),
        action_key: target_method.to_string(),
        spiffe_uri: LOCAL_UNLOCK_SPIFFE_URI.to_string(),
        nonce_hex: hex::encode(nonce),
        persona_id: LOCAL_UNLOCK_PERSONA_ID.to_string(),
        prompt_id: Some(request_id.clone()),
        reason: Some(reason.to_string()),
        caller_persona: None,
        ttl_ms: None,
    };
    let expected_presence_challenge = bind_presence_challenge(
        &presence_request.workflow_id,
        &presence_request.action_key,
        &presence_request.spiffe_uri,
        &nonce,
    );

    prune_expired_requests(now_unix_ms());
    PENDING_REQUESTS
        .lock()
        .map_err(|_| "pending native-unlock registry poisoned".to_string())?
        .insert(
            request_id.clone(),
            PendingRequest {
                challenge,
                expires_at_unix_ms,
                presence_scope_key: presence_scope_key.to_string(),
                expected_presence_challenge,
                expected_presence_persona: LOCAL_UNLOCK_PERSONA_ID.to_string(),
            },
        );

    let _ = std::fs::create_dir_all(trusted_pubkey_path(data_dir).parent().unwrap_or(data_dir));

    Ok(UnlockBeginResponse {
        request_id,
        challenge_hex: hex::encode(challenge),
        expires_at_unix_ms,
        reason: reason.to_string(),
        prompt_url,
        presence_request: Some(presence_request),
    })
}

pub fn complete(
    data_dir: &Path,
    request_id: &str,
    public_key_hex: &str,
    signature_der_hex: &str,
) -> Result<CompletedUnlock, String> {
    let now = now_unix_ms();
    let pending = take_pending_request(request_id)?
        .ok_or_else(|| "native biometric unlock request missing or already consumed".to_string())?;
    if pending.expires_at_unix_ms < now {
        return Err("native biometric unlock request expired".to_string());
    }

    let provided_pubkey = decode_pubkey(public_key_hex)?;
    let stored_pubkey = load_trusted_pubkey(data_dir)?;
    let effective_pubkey = match stored_pubkey {
        Some(ref trusted) if trusted != &provided_pubkey => {
            return Err(
                "native biometric unlock key mismatch; rerun managed install or rotate the trusted host key explicitly"
                    .to_string(),
            )
        }
        Some(trusted) => trusted,
        None => provided_pubkey,
    };

    let signature_bytes =
        hex::decode(signature_der_hex).map_err(|e| format!("signature hex decode: {e}"))?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|e| format!("signature decode: {e}"))?;
    let digest = Sha256::digest(pending.challenge);
    effective_pubkey
        .verify_prehash(&digest, &signature)
        .map_err(|e| format!("native biometric signature verify failed: {e}"))?;

    if stored_pubkey.is_none() {
        store_trusted_pubkey(data_dir, public_key_hex)?;
    }
    Ok(CompletedUnlock {
        presence_scope_key: pending.presence_scope_key,
    })
}

pub fn complete_with_daemon_handle(
    request_id: &str,
    handle: &DaemonSignedHandle,
    verifying_key: &ed25519_dalek::VerifyingKey,
    now_unix_ms: u64,
) -> Result<CompletedUnlock, String> {
    let pending = take_pending_request(request_id)?
        .ok_or_else(|| "native biometric unlock request missing or already consumed".to_string())?;
    if pending.expires_at_unix_ms < now_unix_ms {
        return Err("native biometric unlock request expired".to_string());
    }
    verify_presence_handle(handle, verifying_key, now_unix_ms)
        .map_err(|e| format!("presence proof handle verify failed: {e}"))?;
    if handle.persona_id != pending.expected_presence_persona {
        return Err(format!(
            "presence proof persona mismatch; expected {} got {}",
            pending.expected_presence_persona, handle.persona_id
        ));
    }
    if handle.challenge_hash != pending.expected_presence_challenge {
        return Err("presence proof challenge mismatch for pending unlock request".to_string());
    }
    Ok(CompletedUnlock {
        presence_scope_key: pending.presence_scope_key,
    })
}

fn take_pending_request(request_id: &str) -> Result<Option<PendingRequest>, String> {
    PENDING_REQUESTS
        .lock()
        .map_err(|_| "pending native-unlock registry poisoned".to_string())
        .map(|mut requests| requests.remove(request_id))
}

fn prune_expired_requests(now_unix_ms: u64) {
    if let Ok(mut requests) = PENDING_REQUESTS.lock() {
        requests.retain(|_, pending| pending.expires_at_unix_ms >= now_unix_ms);
    }
}

fn trusted_pubkey_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TRUSTED_PUBKEY_FILE)
}

fn load_trusted_pubkey(data_dir: &Path) -> Result<Option<VerifyingKey>, String> {
    let path = trusted_pubkey_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("read trusted native unlock pubkey {}: {e}", path.display()))?;
    decode_pubkey(contents.trim()).map(Some)
}

fn store_trusted_pubkey(data_dir: &Path, public_key_hex: &str) -> Result<(), String> {
    let path = trusted_pubkey_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create native unlock pubkey dir {}: {e}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&tmp_path, format!("{}\n", public_key_hex.trim())).map_err(|e| {
        format!(
            "write trusted native unlock pubkey {}: {e}",
            tmp_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, &path).map_err(|e| {
        format!(
            "rename trusted native unlock pubkey {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn decode_pubkey(public_key_hex: &str) -> Result<VerifyingKey, String> {
    let pubkey_bytes =
        hex::decode(public_key_hex).map_err(|e| format!("pubkey hex decode: {e}"))?;
    VerifyingKey::from_sec1_bytes(&pubkey_bytes).map_err(|e| format!("pubkey SEC1 decode: {e}"))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
pub fn clear_for_tests() {
    if let Ok(mut requests) = PENDING_REQUESTS.lock() {
        requests.clear();
    }
}

#[cfg(test)]
mod tests {
    // Parent-mod re-export is consumed only by the macOS-gated test
    // below; suppress the unused-import lint on non-macOS so the Linux
    // build (headless host) doesn't warn on every build.
    #[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn begin_and_complete_round_trip_with_stub_signature() {
        use ember_broker::secure_enclave::{
            SeAccessPolicy, SeKeychainTarget, find_secure_enclave_key,
            generate_secure_enclave_key_with_policy, se_pubkey_bytes, se_register_stub_key,
            se_sign_with_touch_id,
        };
        use tempfile::tempdir;

        clear_for_tests();
        let dir = tempdir().unwrap();
        let label = "sh.emberlink.test.native-unlock";
        let handle = generate_secure_enclave_key_with_policy(
            label,
            SeKeychainTarget::SystemKeychain,
            SeAccessPolicy::BiometricCurrentSet,
        )
        .unwrap_or_else(|_| ember_broker::secure_enclave::new_stub_key(label));
        se_register_stub_key(label, &handle);
        let reopened = find_secure_enclave_key(label).unwrap_or(handle);

        let first_begin = begin(dir.path(), "Unlock the daemon vault", "class:vault").unwrap();
        let pubkey_hex = hex::encode(se_pubkey_bytes(&reopened).unwrap());
        let challenge = hex::decode(&first_begin.challenge_hex).unwrap();
        let signature_hex = hex::encode(se_sign_with_touch_id(&reopened, &challenge).unwrap());

        let completed = complete(
            dir.path(),
            &first_begin.request_id,
            &pubkey_hex,
            &signature_hex,
        )
        .unwrap();
        assert_eq!(completed.presence_scope_key, "class:vault");
        assert!(trusted_pubkey_path(dir.path()).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn complete_rejects_mismatched_pubkey_after_enrollment() {
        use ember_broker::secure_enclave::{new_stub_key, se_pubkey_bytes, se_register_stub_key};
        use tempfile::tempdir;

        clear_for_tests();
        let dir = tempdir().unwrap();

        let first = new_stub_key("stub-one");
        se_register_stub_key("stub-one", &first);
        let first_begin = begin(dir.path(), "Unlock the daemon vault", "class:vault").unwrap();
        let challenge = hex::decode(&first_begin.challenge_hex).unwrap();
        let first_sig = hex::encode(
            ember_broker::secure_enclave::se_sign_with_touch_id(&first, &challenge).unwrap(),
        );
        let first_pub = hex::encode(se_pubkey_bytes(&first).unwrap());
        let _ = complete(dir.path(), &first_begin.request_id, &first_pub, &first_sig).unwrap();

        let second = new_stub_key("stub-two");
        se_register_stub_key("stub-two", &second);
        let begin2 = begin(dir.path(), "Unlock the daemon vault", "class:vault").unwrap();
        let challenge2 = hex::decode(&begin2.challenge_hex).unwrap();
        let second_sig = hex::encode(
            ember_broker::secure_enclave::se_sign_with_touch_id(&second, &challenge2).unwrap(),
        );
        let second_pub = hex::encode(se_pubkey_bytes(&second).unwrap());
        let err = complete(dir.path(), &begin2.request_id, &second_pub, &second_sig).unwrap_err();
        assert!(err.contains("key mismatch"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn complete_returns_bound_non_vault_scope() {
        use ember_broker::secure_enclave::{new_stub_key, se_pubkey_bytes, se_register_stub_key};
        use tempfile::tempdir;

        clear_for_tests();
        let dir = tempdir().unwrap();
        let handle = new_stub_key("stub-session-runtime");
        se_register_stub_key("stub-session-runtime", &handle);

        let begin = begin(
            dir.path(),
            "Start a new Ember session",
            "class:session-runtime",
        )
        .unwrap();
        let challenge = hex::decode(&begin.challenge_hex).unwrap();
        let signature = hex::encode(
            ember_broker::secure_enclave::se_sign_with_touch_id(&handle, &challenge).unwrap(),
        );
        let pubkey = hex::encode(se_pubkey_bytes(&handle).unwrap());

        let completed = complete(dir.path(), &begin.request_id, &pubkey, &signature).unwrap();
        assert_eq!(completed.presence_scope_key, "class:session-runtime");
    }

    #[test]
    fn begin_with_presence_proof_embeds_presence_request_and_prompt_url() {
        clear_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let begin = begin_with_presence_proof(
            dir.path(),
            "Unlock your Ember vault.",
            "vault_unlock",
            "class:vault",
            Some("http://localhost:3141/prompts".to_string()),
        )
        .unwrap();
        let request = begin
            .presence_request
            .expect("presence request included in begin response");
        assert_eq!(request.workflow_id, begin.request_id);
        assert_eq!(request.action_key, "vault_unlock");
        assert_eq!(request.persona_id, LOCAL_UNLOCK_PERSONA_ID);
        assert_eq!(
            request.prompt_id.as_deref(),
            Some(begin.request_id.as_str())
        );
        assert_eq!(request.reason.as_deref(), Some("Unlock your Ember vault."));
        let expected_prompt_url = format!("http://localhost:3141/prompts/{}", begin.request_id);
        assert_eq!(
            begin.prompt_url.as_deref(),
            Some(expected_prompt_url.as_str())
        );
    }

    #[test]
    fn complete_with_daemon_handle_round_trips() {
        clear_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let begin = begin_with_presence_proof(
            dir.path(),
            "Unlock your Ember vault.",
            "vault_unlock",
            "class:vault",
            None,
        )
        .unwrap();
        let request = begin
            .presence_request
            .clone()
            .expect("presence request included in begin response");
        let nonce = hex::decode(&request.nonce_hex).expect("presence nonce hex");
        let challenge_hash = bind_presence_challenge(
            &request.workflow_id,
            &request.action_key,
            &request.spiffe_uri,
            &nonce,
        );
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let issued_at = now_unix_ms();
        let handle = core_crypto::presence::sign_presence_handle(
            challenge_hash,
            &request.persona_id,
            issued_at,
            30_000,
            &signing_key,
        );
        let completed = complete_with_daemon_handle(
            &begin.request_id,
            &handle,
            &signing_key.verifying_key(),
            issued_at,
        )
        .expect("daemon signed handle should satisfy pending unlock request");
        assert_eq!(completed.presence_scope_key, "class:vault");
    }
}
