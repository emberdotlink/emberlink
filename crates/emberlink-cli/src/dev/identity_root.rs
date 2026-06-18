//! Dev IdentityRoot key generation + Keychain stash.
//!
//! Per ADR 157 Phase 4, phase 1 of `ember dev install`: mint an Ed25519
//! keypair, write the private key to macOS Keychain.
//!
//! ## Keychain layout — transitional (ADR 200 amendment 2026-06-15)
//!
//! The v0.1-v0.2 `sh.emberlink.dev-identity-root` slot is being
//! retired in favor of a unified Principal-rooted layout (one root
//! Principal + workstation Durable Persona + operator-role Durable
//! Persona) per ADR 200 §"Amendment 2026-06-15 — IdentityRoot /
//! Persona collapse into recursive Principal (v0.3.0)". The
//! target-state slot for the workstation manifest-signing seed is
//! [`crate::trust::principal_keychain::WORKSTATION_PERSONA_KEYCHAIN_LABEL`]
//! (`sh.emberlink.persona.workstation.seed`).
//!
//! This module's readers honor the target-state label first and fall
//! back to the legacy slot, so existing operator installs whose seed
//! still lives at `sh.emberlink.dev-identity-root` keep working until
//! [`crate::trust::principal_keychain::migrate_dual_ir_to_root_principal`]
//! runs and consolidates the layout. The `ensure_*` writers write to
//! the target slot only — new code never extends the dual-IR
//! vocabulary as target architecture.
//!
//! Anchor: `identity_root_persona_keychain_consolidation_landed`.
//!
//! CLASSIFICATION: PUBLIC

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::trust::principal_keychain::LEGACY_DEV_IR_KEYCHAIN_LABEL;

/// **Transitional** legacy macOS Keychain label for the v0.1-v0.2 dev
/// IdentityRoot. Restated here for backwards-compat with callers that
/// import the symbol (the canonical home is
/// [`crate::trust::principal_keychain::LEGACY_DEV_IR_KEYCHAIN_LABEL`]).
/// New writers MUST NOT use this label —
/// [`crate::trust::principal_keychain::WORKSTATION_PERSONA_KEYCHAIN_LABEL`]
/// is the target-state slot.
/// Anchor: `identity_root_persona_keychain_consolidation_landed`.
pub const KEYCHAIN_LABEL: &str = LEGACY_DEV_IR_KEYCHAIN_LABEL;

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

fn keyring_entry() -> Result<keyring_core::Entry, String> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_LABEL)
        .map_err(|e| format!("failed to open keyring entry: {e}"))?;
    Ok(entry)
}

fn decode_signing_key(hex_seed: &str) -> Result<SigningKey, String> {
    let seed_bytes = hex::decode(hex_seed).map_err(|e| {
        format!(
            "keyring entry contains invalid hex; delete the '{}' keychain item and re-run: {e}",
            KEYCHAIN_LABEL
        )
    })?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "keyring entry has wrong seed length {} (expected 32); \
             delete the '{KEYCHAIN_LABEL}' keychain item and re-run",
            seed_bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    Ok(SigningKey::from_bytes(&seed))
}

fn read_existing_signing_key() -> Result<Option<SigningKey>, String> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(hex_seed) => Ok(Some(decode_signing_key(&hex_seed)?)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keyring error loading dev IdentityRoot key: {e}")),
    }
}

/// Load the dev IdentityRoot signing key from Keychain, generating and stashing
/// it first when the canonical entry is absent.
pub fn ensure_dev_identity_root_signing_key() -> Result<SigningKey, String> {
    let entry = keyring_entry()?;

    match entry.get_password() {
        Ok(hex_seed) => decode_signing_key(&hex_seed),
        Err(keyring_core::Error::NoEntry) => {
            // No existing key: generate fresh.
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| {
                format!("OS entropy failure generating dev IdentityRoot keypair: {e}")
            })?;
            let signing_key = SigningKey::from_bytes(&seed);

            let hex_seed = hex::encode(seed);
            entry
                .set_password(&hex_seed)
                .map_err(|e| format!("failed to stash dev IdentityRoot key in Keychain: {e}"))?;

            Ok(signing_key)
        }
        Err(e) => Err(format!("keyring error loading dev IdentityRoot key: {e}")),
    }
}

/// Read the existing dev IdentityRoot from Keychain without generating a new
/// key when the canonical entry is absent.
pub fn read_existing_dev_identity_root() -> Result<Option<DevIdentityRootHandle>, String> {
    match read_existing_signing_key()? {
        Some(signing_key) => {
            let public_key = signing_key.verifying_key();
            Ok(Some(DevIdentityRootHandle {
                fingerprint: fingerprint_of(&public_key),
                public_key,
            }))
        }
        None => Ok(None),
    }
}

/// Read the existing dev IdentityRoot signing key from Keychain without
/// generating a new key when the canonical entry is absent.
pub fn read_existing_dev_identity_root_signing_key() -> Result<Option<SigningKey>, String> {
    read_existing_signing_key()
}

/// Read the existing dev IdentityRoot pubkey as canonical 64-char lower-hex
/// — the exact wire shape `ember_daemon::binary_manifest::parse_trust_roots`
/// expects in the `EMBER_TRUST_ROOTS` env var.
///
/// Returns `Ok(None)` when no dev IdentityRoot is stashed in Keychain; the
/// caller threads `None` through as an empty trust-roots string to preserve
/// the legacy plist shape.
pub fn read_existing_dev_identity_root_pubkey_hex() -> Result<Option<String>, String> {
    Ok(read_existing_dev_identity_root()?.map(|handle| hex::encode(handle.public_key.to_bytes())))
}

/// Generate a fresh dev IdentityRoot keypair and stash the private key in
/// Keychain. If a keypair already exists at the canonical label, load it
/// instead of overwriting (idempotent).
pub fn ensure_dev_identity_root() -> Result<DevIdentityRootHandle, String> {
    let signing_key = ensure_dev_identity_root_signing_key()?;
    let public_key = signing_key.verifying_key();
    Ok(DevIdentityRootHandle {
        fingerprint: fingerprint_of(&public_key),
        public_key,
    })
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

    #[test]
    fn decode_signing_key_rejects_invalid_hex() {
        let err = decode_signing_key("not-hex").expect_err("invalid hex must fail");
        assert!(err.contains("invalid hex"), "unexpected error: {err}");
    }

    #[test]
    fn decode_signing_key_rejects_wrong_seed_length() {
        let err = decode_signing_key("aa").expect_err("short seed must fail");
        assert!(err.contains("wrong seed length"), "unexpected error: {err}");
    }

    #[test]
    fn decode_signing_key_round_trips_seed_bytes() {
        let seed = [0x5au8; 32];
        let encoded = hex::encode(seed);
        let signing_key = decode_signing_key(&encoded).expect("seed decode must succeed");
        assert_eq!(signing_key.to_bytes(), seed);
    }
}
