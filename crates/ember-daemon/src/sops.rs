//! SOPS DEK-unwrap (Path 1, -B-collapsed).
//!
//! Phase 1 of implementation-note-73 — pure DEK-unwrap function. The age private
//! key is consumed inside this function (Zeroizing buffer); never crosses
//! the IPC boundary in plaintext form. Phase 2 wires the daemon RPC +
//! receipt emission + rate-limit; Phase 3 ships the orch-only
//! sops-as-bot.sh wrapper.

use anyhow::{Context, Result};
use std::io::Read;
use zeroize::Zeroizing;

/// Unwrap a SOPS-encrypted DEK using a persona's age private key.
///
/// **Pre:** `age_private_key` is the UTF-8 `AGE-SECRET-KEY-1...` string
/// (typically read from the daemon vault into a `Zeroizing<Vec<u8>>` by
/// the caller). `encrypted_dek_blob` is the ciphertext output of
/// `age::Encryptor::with_recipients` (one or more recipients).
///
/// **Post:** Returns plaintext DEK in `Zeroizing<Vec<u8>>` (zeroized on drop).
/// The age private key is parsed locally and dropped at the end of the
/// function — never leaves this scope.
///
/// **Errors:** invalid UTF-8 in key, unparseable age identity, malformed
/// blob, no matching recipient.
#[cfg(feature = "age")]
pub fn unwrap_dek_userspace(
    age_private_key: &[u8],
    encrypted_dek_blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key_str = std::str::from_utf8(age_private_key)
        .context("age private key not valid UTF-8")?;
    let identity: age::x25519::Identity = key_str
        .trim()
        .parse()
        .map_err(|e: &'static str| anyhow::anyhow!("parse age identity: {e}"))?;
    let decryptor = age::Decryptor::new(encrypted_dek_blob)
        .context("create age decryptor")?;
    let recipients_decryptor = match decryptor {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            anyhow::bail!("encrypted blob uses passphrase mode; expected recipients mode")
        }
    };
    let mut reader = recipients_decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("decrypt DEK with persona key")?;
    let mut plaintext: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .context("read decrypted DEK")?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(not(feature = "age"))]
pub fn unwrap_dek_userspace(
    _age_private_key: &[u8],
    _encrypted_dek_blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!("age feature not enabled; build with --features age")
}

// SOPS-MODULE-SCAFFOLD — implementation-note-95. Real impl lands in implementation-note-76.
//
// These three stubs reserve the public surface that implementation-note-96
// will route to and that implementation-note-97 will implement. Until
// then, every call returns NotImplementedError so the SOPS Go-fork
// (implementation-note-77) can develop against the real RPC shape.

use crate::infra::store::StoreError;

/// Stub — returns the persona's age public key as an `age1...` recipient string.
/// Real impl in implementation-note-76.
pub fn sops_pubkey(persona_id: &str) -> Result<String, StoreError> {
    let _ = persona_id;
    Err(StoreError::InvalidInput(
        "sops_pubkey: not implemented (implementation-note-76)".into(),
    ))
}

/// Stub — wraps a DEK to a persona's public key (no private key required).
/// Real impl in implementation-note-76.
pub fn sops_wrap_dek(persona_id: &str, dek: &[u8]) -> Result<Vec<u8>, StoreError> {
    let _ = (persona_id, dek);
    Err(StoreError::InvalidInput(
        "sops_wrap_dek: not implemented (implementation-note-76)".into(),
    ))
}

/// Stub — unwraps an encrypted DEK using the persona's age private key
/// fetched from vault internally. Private key never leaves vault process.
/// Real impl in implementation-note-76.
pub fn sops_unwrap_in_vault(
    persona_id: &str,
    encrypted_dek: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let _ = (persona_id, encrypted_dek);
    Err(StoreError::InvalidInput(
        "sops_unwrap_in_vault: not implemented (implementation-note-76)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "age")]
    fn roundtrip_encrypts_then_unwraps() {
        use std::io::Write;

        let keypair = crate::age::generate_age_keypair().unwrap();
        let pub_key: age::x25519::Recipient = keypair.public_key.parse().unwrap();

        let plaintext = b"super-secret-dek-bytes-1234567890";
        let encryptor = age::Encryptor::with_recipients(vec![
            Box::new(pub_key) as Box<dyn age::Recipient + Send>,
        ])
        .unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();

        let result = unwrap_dek_userspace(keypair.private_key.as_bytes(), &ciphertext).unwrap();
        assert_eq!(&result[..], plaintext.as_slice());
    }

    #[test]
    #[cfg(feature = "age")]
    fn wrong_key_returns_error() {
        use std::io::Write;

        let key_a = crate::age::generate_age_keypair().unwrap();
        let pub_a: age::x25519::Recipient = key_a.public_key.parse().unwrap();

        let encryptor = age::Encryptor::with_recipients(vec![
            Box::new(pub_a) as Box<dyn age::Recipient + Send>,
        ])
        .unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();

        let key_b = crate::age::generate_age_keypair().unwrap();
        assert!(unwrap_dek_userspace(key_b.private_key.as_bytes(), &ciphertext).is_err());
    }

    #[test]
    #[cfg(feature = "age")]
    fn malformed_blob_returns_error() {
        let keypair = crate::age::generate_age_keypair().unwrap();
        assert!(unwrap_dek_userspace(keypair.private_key.as_bytes(), b"not-an-age-blob").is_err());
    }
}
