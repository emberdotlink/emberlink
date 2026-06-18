//! SE wrap/unwrap primitives for double-envelope custody (ADR 216).
//!
//! The CLI relay uses these to peel/apply the **outer** SE layer of the
//! double-envelope custody model. The outer envelope is an SE-ECIES blob
//! wrapping the DWK-encrypted inner blob; the CLI runs in the Aqua/501
//! session domain where SE operations succeed.
//!
//! The SE key lives in the daemon process's DPK (Data Protection
//! Keychain) under label [`VAULT_MEK_SE_LABEL`].
//!
//! ## What was removed (ADR 216 S4)
//!
//! `ensure_vault_mek_se` — the function that provisioned the SE key and
//! was called by the now-deleted `se_unseal_with_presence`. The DE path
//! provisions the SE key through the CLI relay, not the daemon.

#![cfg(target_os = "macos")]

use ember_broker::secure_enclave::{EciesKeyLabel, se_unwrap, se_wrap};
use zeroize::Zeroizing;

use crate::infra::vault::VaultError;

pub const VAULT_MEK_SE_LABEL: &str = "sh.emberlink.daemon.vault-mek";

// ADR 216 S4: `ensure_vault_mek_se` deleted — the DE path provisions
// the SE key through the CLI relay, not the daemon. The `VAULT_MEK_SE_LABEL`
// const is kept because the DWK AAD and CLI relay reference it.

/// SE-wrap a 32-byte interactive key. Returns the opaque ECIES blob.
pub fn wrap_interactive_key(label: &EciesKeyLabel, key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    se_wrap(label, key).map_err(|e| VaultError::Crypto(format!("vault MEK SE wrap failed: {e}")))
}

/// SE-unwrap a wrapped interactive key blob back to 32 bytes.
///
/// The returned key is in a `Zeroizing` wrapper; the caller copies it
/// into the vault's `[u8; 32]` slot and the wrapper zeroizes the
/// intermediate `Vec` on drop.
pub fn unwrap_interactive_key(label: &EciesKeyLabel, blob: &[u8]) -> Result<[u8; 32], VaultError> {
    let plaintext = Zeroizing::new(
        se_unwrap(label, blob)
            .map_err(|e| VaultError::Crypto(format!("vault MEK SE unwrap failed: {e}")))?,
    );
    if plaintext.len() != 32 {
        return Err(VaultError::Crypto(format!(
            "vault MEK SE unwrap produced {} bytes (expected 32)",
            plaintext.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Test-only: create a stub SE label for vault MEK tests. Bypasses real
/// SE key creation (which requires a signed binary). Same pattern as
/// `set_lease_kek_for_test` in store.rs.
#[cfg(test)]
pub(crate) fn stub_vault_mek_label() -> EciesKeyLabel {
    use ember_broker::secure_enclave::{new_stub_key, se_register_stub_key};
    let handle = new_stub_key(VAULT_MEK_SE_LABEL);
    se_register_stub_key(VAULT_MEK_SE_LABEL, &handle);
    EciesKeyLabel::from_provisioned(VAULT_MEK_SE_LABEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let label = stub_vault_mek_label();

        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();

        let blob = wrap_interactive_key(&label, &key).expect("wrap");
        let recovered = unwrap_interactive_key(&label, &blob).expect("unwrap");
        assert_eq!(recovered, key);
    }

    #[test]
    fn unwrap_rejects_wrong_length() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let label = stub_vault_mek_label();

        let short_key = [42u8; 16];
        let blob = se_wrap(&label, &short_key).expect("wrap short");
        let err = unwrap_interactive_key(&label, &blob).expect_err("must reject");
        match err {
            VaultError::Crypto(msg) => assert!(msg.contains("16 bytes"), "{msg}"),
            other => panic!("expected Crypto error, got: {other:?}"),
        }
    }

    #[test]
    fn label_constant_is_stable() {
        assert_eq!(VAULT_MEK_SE_LABEL, "sh.emberlink.daemon.vault-mek");
    }
}
