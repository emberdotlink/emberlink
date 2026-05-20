//! Dev IdentityRoot key generation + Keychain stash.
//!
//! Per design Phase 4, phase 1 of `ember dev install`: mint an Ed25519
//! keypair, write the private key to macOS Keychain at label
//! `sh.emberlink.dev-identity-root`, print the public-key fingerprint.
//!

use ed25519_dalek::{SigningKey, VerifyingKey};

pub const KEYCHAIN_LABEL: &str = "sh.emberlink.dev-identity-root";
const KEYCHAIN_SERVICE: &str = "sh.emberlink";

pub struct DevIdentityRootHandle {
    pub fingerprint: String,
    pub public_key: VerifyingKey,
}

/// Compute a 32-char hex fingerprint of a public key (blake3 of the raw bytes,
/// first 16 bytes as hex).
pub fn fingerprint_of(public: &VerifyingKey) -> String {
    let hash = blake3::hash(public.as_bytes());
    hex::encode(&hash.as_bytes()[..16])
}

/// Generate a fresh dev IdentityRoot keypair and stash the private key in
/// Keychain. If a keypair already exists at the canonical label, load it
/// instead of overwriting (idempotent).
pub fn ensure_dev_identity_root() -> Result<DevIdentityRootHandle, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| format!("failed to open keyring entry: {e}"))?;

    match entry.get_password() {
        Ok(hex_seed) => {
            // Existing key: decode and return.
            let seed_bytes = hex::decode(&hex_seed)
                .map_err(|e| format!(
                    "keyring entry contains invalid hex; delete the '{}' keychain item and re-run: {e}",
                    KEYCHAIN_LABEL
                ))?;
            if seed_bytes.len() != 32 {
                return Err(format!(
                    "keyring entry has wrong seed length {} (expected 32); \
                     delete the '{KEYCHAIN_LABEL}' keychain item and re-run",
                    seed_bytes.len()
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let signing_key = SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key();
            Ok(DevIdentityRootHandle {
                fingerprint: fingerprint_of(&public_key),
                public_key,
            })
        }
        Err(keyring::Error::NoEntry) => {
            // No existing key: generate fresh.
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| {
                format!("OS entropy failure generating dev IdentityRoot keypair: {e}")
            })?;
            let signing_key = SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key();

            let hex_seed = hex::encode(seed);
            entry
                .set_password(&hex_seed)
                .map_err(|e| format!("failed to stash dev IdentityRoot key in Keychain: {e}"))?;

            Ok(DevIdentityRootHandle {
                fingerprint: fingerprint_of(&public_key),
                public_key,
            })
        }
        Err(e) => Err(format!("keyring error loading dev IdentityRoot key: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn fingerprint_is_deterministic() {
        let mut seed = [0u8; 32];
        seed[0] = 42;
        let key = SigningKey::from_bytes(&seed);
        let vk = key.verifying_key();
        let fp1 = fingerprint_of(&vk);
        let fp2 = fingerprint_of(&vk);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let mut seed_a = [0u8; 32];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 32];
        seed_b[0] = 2;
        let vk_a = SigningKey::from_bytes(&seed_a).verifying_key();
        let vk_b = SigningKey::from_bytes(&seed_b).verifying_key();
        assert_ne!(fingerprint_of(&vk_a), fingerprint_of(&vk_b));
    }

    #[test]
    fn fingerprint_is_32_hex_chars() {
        let seed = [7u8; 32];
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let fp = fingerprint_of(&vk);
        assert_eq!(fp.len(), 32, "fingerprint must be 32 hex chars");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be hex"
        );
    }
}
