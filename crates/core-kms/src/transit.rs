//! In-memory Vault Transit keyring — AES-256-GCM encrypt/decrypt.
//!
//! Implements the minimal Transit subset used by SOPS and Pulumi:
//! - key creation (`POST /v1/transit/keys/<key>`)
//! - key metadata (`GET /v1/transit/keys/<key>`)
//! - encrypt (`POST /v1/transit/encrypt/<key>`)
//! - decrypt (`POST /v1/transit/decrypt/<key>`)
//!
//! Keys are memory-only for now; envelope wrapping (storing the KEK in the
//! `ember vault` row at `kms/<name>`) is a follow-up per ADR 100.
//!
//! Wire format matches HashiCorp Vault Transit so SOPS (`hc_vault_transit_uri`)
//! and Pulumi (`hashivault://` secrets provider) can use ember-kms without
//! modification.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// Errors from Transit operations.
#[derive(Debug, Error)]
pub enum TransitError {
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("malformed ciphertext: expected 'vault:v1:<base64>' prefix")]
    MalformedCiphertext,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("aes-gcm error")]
    AesGcm,
    #[error("plaintext field is not valid base64")]
    InvalidPlaintext,
}

/// A single AES-256-GCM wrapping key with its name and creation timestamp.
struct TransitKey {
    name: String,
    key_material: SecretBox<Vec<u8>>,
    created_at: u64,
}

impl TransitKey {
    fn new(name: impl Into<String>) -> Self {
        let cipher_key = Aes256Gcm::generate_key(&mut OsRng);
        let key_bytes: Vec<u8> = cipher_key.to_vec();
        Self {
            name: name.into(),
            key_material: SecretBox::new(Box::new(key_bytes)),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn cipher(&self) -> Result<Aes256Gcm, TransitError> {
        let bytes = self.key_material.expose_secret().as_slice();
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(bytes);
        Ok(Aes256Gcm::new(key))
    }

    /// Encrypt `plaintext_bytes` → `vault:v1:<base64(nonce || ciphertext)>`
    fn encrypt_bytes(&self, plaintext_bytes: &[u8]) -> Result<String, TransitError> {
        let cipher = self.cipher()?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext_bytes)
            .map_err(|_| TransitError::AesGcm)?;
        // Pack: nonce (12 bytes) || ciphertext
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        let encoded = BASE64.encode(&blob);
        Ok(format!("vault:v1:{encoded}"))
    }

    /// Decrypt `vault:v1:<base64>` → plaintext bytes.
    fn decrypt_vault_ciphertext(&self, vault_ct: &str) -> Result<Vec<u8>, TransitError> {
        let b64 = vault_ct
            .strip_prefix("vault:v1:")
            .ok_or(TransitError::MalformedCiphertext)?;
        let blob = BASE64.decode(b64)?;
        if blob.len() < 12 {
            return Err(TransitError::AesGcm);
        }
        let (nonce_bytes, ct_bytes) = blob.split_at(12);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let cipher = self.cipher()?;
        cipher
            .decrypt(nonce, ct_bytes)
            .map_err(|_| TransitError::AesGcm)
    }
}

/// Key metadata returned by `GET /v1/transit/keys/<key>`.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub name: String,
    /// Reports `aes256-gcm96` to satisfy SOPS type-check.
    #[serde(rename = "type")]
    pub key_type: String,
    pub creation_time: u64,
    /// Always `1` in v1 (key rotation deferred per ADR 100).
    pub latest_version: u32,
    pub min_decryption_version: u32,
}

/// Shared in-memory keyring.
#[derive(Clone, Default)]
pub struct TransitKeyring {
    inner: Arc<RwLock<HashMap<String, TransitKey>>>,
}

impl TransitKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new key by `name`. Returns `KeyAlreadyExists` if it exists.
    pub fn create_key(&self, name: &str) -> Result<KeyInfo, TransitError> {
        let mut map = self.inner.write().expect("keyring lock poisoned");
        if map.contains_key(name) {
            return Err(TransitError::KeyAlreadyExists(name.to_owned()));
        }
        let key = TransitKey::new(name);
        let info = key_to_info(&key);
        map.insert(name.to_owned(), key);
        Ok(info)
    }

    /// Return metadata for `name`, or `KeyNotFound`.
    pub fn key_info(&self, name: &str) -> Result<KeyInfo, TransitError> {
        let map = self.inner.read().expect("keyring lock poisoned");
        map.get(name)
            .map(key_to_info)
            .ok_or_else(|| TransitError::KeyNotFound(name.to_owned()))
    }

    /// Encrypt base64-encoded `plaintext` under key `name`.
    ///
    /// `plaintext` is the base64-encoded DEK supplied by SOPS / Pulumi.
    /// Returns `vault:v1:<base64>` ciphertext.
    pub fn encrypt(&self, name: &str, plaintext_b64: &str) -> Result<String, TransitError> {
        let plaintext_bytes = BASE64
            .decode(plaintext_b64)
            .map_err(|_| TransitError::InvalidPlaintext)?;
        let map = self.inner.read().expect("keyring lock poisoned");
        let key = map
            .get(name)
            .ok_or_else(|| TransitError::KeyNotFound(name.to_owned()))?;
        key.encrypt_bytes(&plaintext_bytes)
    }

    /// Decrypt `vault:v1:<base64>` ciphertext under key `name`.
    ///
    /// Returns the base64-encoded plaintext DEK.
    pub fn decrypt(&self, name: &str, vault_ct: &str) -> Result<String, TransitError> {
        let map = self.inner.read().expect("keyring lock poisoned");
        let key = map
            .get(name)
            .ok_or_else(|| TransitError::KeyNotFound(name.to_owned()))?;
        let plaintext_bytes = key.decrypt_vault_ciphertext(vault_ct)?;
        Ok(BASE64.encode(&plaintext_bytes))
    }

    /// Return the number of keys in the ring (for testing).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().expect("keyring lock poisoned").len()
    }

    /// Return true if no keys have been registered (for testing).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner.read().expect("keyring lock poisoned").is_empty()
    }
}

fn key_to_info(key: &TransitKey) -> KeyInfo {
    KeyInfo {
        name: key.name.clone(),
        key_type: "aes256-gcm96".to_owned(),
        creation_time: key.created_at,
        latest_version: 1,
        min_decryption_version: 1,
    }
}

// ---------------------------------------------------------------------------
// Request / response shapes (Vault Transit wire format)
// ---------------------------------------------------------------------------

/// `POST /v1/transit/encrypt/<key>` request body.
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,
}

/// `POST /v1/transit/decrypt/<key>` request body.
#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
}

/// Vault-envelope outer wrapper `{"request_id": "...", "data": {...}}`.
#[derive(Debug, Serialize)]
pub struct VaultResponse<T: Serialize> {
    pub request_id: String,
    pub data: T,
}

impl<T: Serialize> VaultResponse<T> {
    pub fn new(data: T) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            data,
        }
    }
}

/// `data` object for an encrypt response.
#[derive(Debug, Serialize)]
pub struct EncryptData {
    pub ciphertext: String,
}

/// `data` object for a decrypt response.
#[derive(Debug, Serialize)]
pub struct DecryptData {
    pub plaintext: String,
}

/// `data` object for a key-info response.
#[derive(Debug, Serialize)]
pub struct KeyData {
    #[serde(flatten)]
    pub info: KeyInfo,
}

/// Warn on auth failures with context so they appear in daemon logs.
pub fn warn_auth_failure(context: &str) {
    warn!(context, "ember-kms auth failure");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring() -> TransitKeyring {
        TransitKeyring::new()
    }

    fn some_plaintext_b64() -> String {
        BASE64.encode(b"super-secret-dek-material-32bytes!")
    }

    // -----------------------------------------------------------------------
    // Key lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_create() {
        let kr = keyring();
        let info = kr.create_key("my-key").expect("create key");
        assert_eq!(info.name, "my-key");
        assert_eq!(info.key_type, "aes256-gcm96");
        assert_eq!(info.latest_version, 1);
        assert_eq!(kr.len(), 1);
    }

    #[test]
    fn key_list_after_create() {
        let kr = keyring();
        kr.create_key("alpha").expect("create alpha");
        kr.create_key("beta").expect("create beta");
        assert_eq!(kr.len(), 2);

        let info_a = kr.key_info("alpha").expect("alpha info");
        assert_eq!(info_a.name, "alpha");
        let info_b = kr.key_info("beta").expect("beta info");
        assert_eq!(info_b.name, "beta");
    }

    #[test]
    fn key_create_duplicate_returns_error() {
        let kr = keyring();
        kr.create_key("dup").expect("first create");
        let err = kr.create_key("dup").expect_err("second create should fail");
        assert!(matches!(err, TransitError::KeyAlreadyExists(_)));
    }

    // -----------------------------------------------------------------------
    // Encrypt / decrypt tests
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_roundtrip() {
        let kr = keyring();
        kr.create_key("roundtrip").expect("create");
        let pt = some_plaintext_b64();
        let ct = kr.encrypt("roundtrip", &pt).expect("encrypt");
        assert!(
            ct.starts_with("vault:v1:"),
            "ciphertext must have vault:v1: prefix"
        );
        let recovered = kr.decrypt("roundtrip", &ct).expect("decrypt");
        assert_eq!(recovered, pt, "recovered plaintext must match original");
    }

    #[test]
    fn keyless_encrypt_returns_not_found() {
        let kr = keyring();
        let err = kr
            .encrypt("nonexistent", &some_plaintext_b64())
            .expect_err("should fail");
        assert!(matches!(err, TransitError::KeyNotFound(_)));
    }

    #[test]
    fn keyless_decrypt_returns_not_found() {
        let kr = keyring();
        let err = kr
            .decrypt("nonexistent", "vault:v1:abc")
            .expect_err("should fail");
        assert!(matches!(err, TransitError::KeyNotFound(_)));
    }

    #[test]
    fn decrypt_malformed_prefix_returns_error() {
        let kr = keyring();
        kr.create_key("prefix-test").expect("create");
        let err = kr
            .decrypt("prefix-test", "notavault:v1:abc")
            .expect_err("should fail on bad prefix");
        assert!(matches!(err, TransitError::MalformedCiphertext));
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let kr = keyring();
        kr.create_key("key-a").expect("create key-a");
        kr.create_key("key-b").expect("create key-b");
        let pt = some_plaintext_b64();
        let ct = kr.encrypt("key-a", &pt).expect("encrypt with key-a");
        // Attempting to decrypt with key-b should fail (aes-gcm auth tag mismatch).
        let err = kr
            .decrypt("key-b", &ct)
            .expect_err("decrypt with wrong key should fail");
        assert!(matches!(
            err,
            TransitError::AesGcm | TransitError::Base64(_)
        ));
    }
}
