//! macOS System.keychain MEK passphrase reader.
//!
//! The installer stores the vault master-encryption-key passphrase as a
//! generic-password item. The daemon reads it through `securityd` at startup,
//! validates UTF-8, and returns it in a zeroizing buffer. Missing or denied
//! keychain access is reported as an installation diagnostic.

#![cfg(target_os = "macos")]

use std::path::Path;

use zeroize::Zeroizing;

use crate::infra::vault::VaultError;

/// macOS keychain service identifier for the vault-MEK item. Shared
/// between the install writer and the daemon reader.
///
/// Uses the product's reverse-DNS namespace.
pub const VAULT_MEK_SERVICE: &str = "sh.emberlink.daemon";

/// macOS keychain account identifier for the vault-MEK item.
pub const VAULT_MEK_ACCOUNT: &str = "vault-mek";

/// Canonical path to the system keychain. The only macOS keychain that
/// is brokered by `securityd` cross-session and cross-uid for items with
/// permissive partition lists. Apple's own system daemons (`apsd`,
/// `mDNSResponder`, `cfprefsd`, etc.) use the same pattern for their
/// bootstrap credentials.
pub const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

/// Legacy SE-key label retained for the SSH-agent T1 path, which still
/// generates session-scoped SE keys in the calling process's DPK. The
/// vault-MEK lane no longer uses this label.
pub const SE_KEY_LABEL: &str = "sh.emberlink.daemon.vault-mek";

/// Read the MEK passphrase from `/Library/Keychains/System.keychain`,
/// validate UTF-8, and return it wrapped in `Zeroizing` so the buffer is
/// zeroed on drop.
///
/// `data_dir` is currently unused — the function signature is preserved
/// for the caller (`vault.rs::resolve_passphrase`) so the System.keychain
/// migration is a single-site change. A future revision may use
/// `data_dir` for a stamp file marking "install has completed."
///
/// # Errors
///
/// - [`VaultError::Io`] if the keychain can't be opened, the item isn't
///   present (operator hasn't run install), or the calling daemon
///   doesn't have read access to the item (partition-list mismatch).
/// - [`VaultError::Crypto`] if the keychain item contents are not valid
///   UTF-8 (would indicate the item was tampered with — install writes a
///   64-char ASCII hex passphrase).
pub fn get_mek_passphrase(_data_dir: &Path) -> Result<Zeroizing<String>, VaultError> {
    use security_framework::os::macos::keychain::SecKeychain;

    let keychain = SecKeychain::open(SYSTEM_KEYCHAIN_PATH).map_err(|e| {
        tracing::warn!(
            path = SYSTEM_KEYCHAIN_PATH,
            error = %e,
            "SecKeychain::open failed"
        );
        VaultError::Io(format!(
            "opening System.keychain at {SYSTEM_KEYCHAIN_PATH}: {e}"
        ))
    })?;

    let (password_bytes, _item) = keychain
        .find_generic_password(VAULT_MEK_SERVICE, VAULT_MEK_ACCOUNT)
        .map_err(|e| {
            tracing::warn!(
                service = VAULT_MEK_SERVICE,
                account = VAULT_MEK_ACCOUNT,
                error = %e,
                "MEK keychain item lookup failed"
            );
            VaultError::Io(format!(
                "MEK keychain item not found or not accessible \
                 (service={VAULT_MEK_SERVICE} account={VAULT_MEK_ACCOUNT}): \
                 {e} — run `ember daemon install` to provision"
            ))
        })?;

    // SecKeychainItemPassword derefs to &[u8]. Copy into a Zeroizing<Vec>
    // immediately so the bytes are scrubbed on drop even if the UTF-8
    // conversion fails.
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(password_bytes.to_vec());

    std::str::from_utf8(&plaintext)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|e| {
            tracing::warn!(error = %e, "MEK passphrase was not valid UTF-8");
            VaultError::Crypto("MEK passphrase was not valid UTF-8 (see daemon log)".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T1 — constants the install path and daemon reader share. Drift
    /// here breaks the contract silently. The string values are wired
    /// into operator-facing error messages (`security find-generic-password
    /// -a vault-mek -s sh.emberlink.daemon`) so they're locked.
    #[test]
    fn vault_mek_keychain_constants_stable() {
        assert_eq!(VAULT_MEK_SERVICE, "sh.emberlink.daemon");
        assert_eq!(VAULT_MEK_ACCOUNT, "vault-mek");
        assert_eq!(SYSTEM_KEYCHAIN_PATH, "/Library/Keychains/System.keychain");
    }

    /// T1 — missing keychain item produces an `Io` error pointing at
    /// `ember daemon install`. This is the operator-facing "you forgot
    /// to install" diagnostic; the error text is part of the UX contract.
    ///
    /// The test relies on the assumption that the dev runner does NOT
    /// have a `vault-mek` item in System.keychain (which would only be
    /// the case if the operator runs `ember daemon install` on the same
    /// machine the tests execute on). If you hit a false pass / failure,
    /// run `sudo security delete-generic-password -a vault-mek
    /// -s sh.emberlink.daemon /Library/Keychains/System.keychain` to
    /// clear state and re-run.
    #[test]
    fn missing_keychain_item_returns_install_hint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err =
            get_mek_passphrase(tmp.path()).expect_err("must fail when keychain item is absent");
        match err {
            VaultError::Io(msg) => {
                assert!(
                    msg.contains("ember daemon install"),
                    "expected install hint in error message, got: {msg}"
                );
            }
            other => panic!("expected VaultError::Io with install hint, got: {other:?}"),
        }
    }
}
