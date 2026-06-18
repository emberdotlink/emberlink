//! CLASSIFICATION: PUBLIC
//!
//! ADR 216 — Daemon Wrap Key (DWK).
//!
//! The DWK is a random 256-bit symmetric key stored in `daemon.db`
//! (uid=450, mode 0600). It forms the inner envelope of the
//! double-envelope SE custody model: at rest, every SE-custodied key
//! is `SE_ECIES_encrypt( DWK_encrypt(raw_key) )`. The CLI peels the
//! outer SE layer (Aqua/501) and relays the opaque inner blob; the
//! daemon peels the DWK layer. Raw key material never enters uid=501
//! address space.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead, aead::Payload};
use zeroize::Zeroizing;

use crate::infra::store::{DaemonStore, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwkPurpose {
    VaultMek,
    LeaseKek,
}

impl DwkPurpose {
    fn aad_tag(&self) -> &'static [u8] {
        match self {
            DwkPurpose::VaultMek => b"dwk:vault_mek:sh.emberlink.daemon.vault-mek",
            DwkPurpose::LeaseKek => b"dwk:lease_kek:sh.emberlink.daemon.lease-kek",
        }
    }
}

pub struct DaemonWrapKey {
    key: Zeroizing<[u8; 32]>,
}

impl DaemonWrapKey {
    pub fn load_or_generate(store: &DaemonStore) -> Result<Self, StoreError> {
        if let Some(bytes) = store.read_daemon_wrap_key()? {
            if bytes.len() != 32 {
                return Err(StoreError::InvalidInput(format!(
                    "daemon_wrap_key: stored DWK is {} bytes, expected 32",
                    bytes.len()
                )));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            return Ok(Self { key });
        }

        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).expect("OS entropy failure");
        store.write_daemon_wrap_key(key.as_ref())?;
        tracing::info!("daemon_wrap_key: provisioned fresh DWK in daemon.db");
        Ok(Self { key })
    }

    pub fn wrap(&self, plaintext: &[u8], purpose: DwkPurpose) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| format!("DWK cipher init: {e}"))?;
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: purpose.aad_tag(),
                },
            )
            .map_err(|e| format!("DWK wrap: {e}"))?;
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn unwrap(&self, blob: &[u8], purpose: DwkPurpose) -> Result<Zeroizing<Vec<u8>>, String> {
        if blob.len() < 24 + 16 {
            return Err(format!(
                "DWK unwrap: blob too short ({} bytes, minimum 40)",
                blob.len()
            ));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| format!("DWK cipher init: {e}"))?;
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: purpose.aad_tag(),
                },
            )
            .map_err(|e| format!("DWK unwrap: AEAD verification failed: {e}"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dwk() -> DaemonWrapKey {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).unwrap();
        DaemonWrapKey { key }
    }

    #[test]
    fn round_trip_vault_mek() {
        let dwk = test_dwk();
        let plaintext = b"test-vault-mek-32-bytes-exactly!";
        let blob = dwk.wrap(plaintext, DwkPurpose::VaultMek).unwrap();
        let recovered = dwk.unwrap(&blob, DwkPurpose::VaultMek).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn round_trip_lease_kek() {
        let dwk = test_dwk();
        let plaintext = b"test-lease-kek-material-here!!!";
        let blob = dwk.wrap(plaintext, DwkPurpose::LeaseKek).unwrap();
        let recovered = dwk.unwrap(&blob, DwkPurpose::LeaseKek).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn wrong_purpose_fails() {
        let dwk = test_dwk();
        let plaintext = b"cross-purpose-test-material!!!!!";
        let blob = dwk.wrap(plaintext, DwkPurpose::VaultMek).unwrap();
        let err = dwk.unwrap(&blob, DwkPurpose::LeaseKek).unwrap_err();
        assert!(err.contains("AEAD verification failed"), "{err}");
    }

    #[test]
    fn tampered_blob_fails() {
        let dwk = test_dwk();
        let plaintext = b"tamper-test-material-32-bytes!!!";
        let mut blob = dwk.wrap(plaintext, DwkPurpose::VaultMek).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let err = dwk.unwrap(&blob, DwkPurpose::VaultMek).unwrap_err();
        assert!(err.contains("AEAD verification failed"), "{err}");
    }

    #[test]
    fn too_short_blob_fails() {
        let dwk = test_dwk();
        let err = dwk.unwrap(&[0u8; 39], DwkPurpose::VaultMek).unwrap_err();
        assert!(err.contains("too short"), "{err}");
    }
}
