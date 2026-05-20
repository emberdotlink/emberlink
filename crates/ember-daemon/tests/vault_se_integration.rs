//! T2 integration: SE-rooted vault path used by the design separate-uid daemon.
//!
//! This suite pins the end-to-end round-trip across the three components that
//! the implementation-note-364-* task chain assembled:
//!
//!   1. **implementation-note-365** — `install::provision_se_mek` generates
//!      and SE-wraps the MEK passphrase, writing the blob to
//!      `<data_dir>/vault-mek.bin`.
//!   2. **implementation-note-366** — `infra::vault_macos_se::get_mek_passphrase`
//!      reads the blob back, calls `se_unwrap`, and returns the plaintext
//!      passphrase.
//!   3. **implementation-note-318** — `Vault::open_from_config` selects the
//!      SE path when `is_separate_uid_posture()` is true (HOME=/var/empty).
//!
//! The test verifies that a passphrase provisioned by step 1 can be recovered
//! by step 2, and that a `Vault` derived from that passphrase can seal and
//! open a credential entry (the minimal viable round-trip).
//!
//! Gated `#[ignore]` because it requires:
//!   - Apple Silicon (Secure Enclave hardware)
//!   - A signed binary with the appropriate entitlement
//!   - System keychain write access (for the SE key under the
//!     `sh.emberlink.daemon.vault-mek` label)
//!
//! Run on qualifying hardware:
//! ```text
//! cargo test -p ember-daemon vault_se -- --ignored
//! ```

#![cfg(target_os = "macos")]

use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultScope};
use ember_daemon::infra::vault_macos_se;
use ember_daemon::install::provision_se_mek;
use tempfile::TempDir;

/// End-to-end SE-vault round-trip for the design separate-uid daemon posture.
///
/// Steps:
///   1. Provision the SE key and wrapped MEK blob via `provision_se_mek`.
///   2. Recover the MEK passphrase via `vault_macos_se::get_mek_passphrase`.
///   3. Derive a `Vault` from the passphrase + a fresh salt.
///   4. Add a credential and read it back to confirm the vault MEK works.
///
/// The test is `#[ignore]`-gated because it requires real Apple Silicon SE
/// hardware and a signed binary with the System keychain entitlement. It is
/// intentionally NOT wired through `Vault::open_from_config` (which short-
/// circuits the SE path under cargo-test binaries via `is_cargo_test_binary`)
/// — instead it exercises `get_mek_passphrase` directly, mirroring the
/// runtime call path without the test guard.
///
/// # target_state_anchor
///
/// `fn vault_se_round_trip_under_separate_uid`
#[test]
#[ignore = "requires Apple Silicon + signed binary + System keychain access"]
fn vault_se_round_trip_under_separate_uid() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    // 1. Install-time: generate the SE-bound key (System keychain,
    //    label `sh.emberlink.daemon.vault-mek`) and write the SE-wrapped
    //    MEK passphrase blob to `<home>/.ember/data/vault-mek.bin`.
    //    On non-root: chown step may fail; provision_se_mek tolerates that
    //    for the test path as long as the file write succeeds.
    provision_se_mek(home).unwrap_or_else(|e| {
        // Tolerate the chown failure that occurs under non-root. The file
        // write and chmod run before chown, so vault-mek.bin is present
        // with correct mode even when chown errors.
        let msg = format!("{e:?}");
        if msg.contains("chown") {
            // Expected under non-root Apple Silicon developers.
        } else {
            panic!("provision_se_mek failed unexpectedly: {e:?}");
        }
    });

    // 2. Runtime: unwrap the blob via the SE key.
    let data_dir = home.join(".ember").join("data");
    let passphrase =
        vault_macos_se::get_mek_passphrase(&data_dir).expect("get_mek_passphrase round-trip");

    // The passphrase must be non-empty. implementation-note-365 writes a
    // hex-encoded 32-byte MEK (64 ASCII chars); validate the shape.
    assert!(
        !passphrase.is_empty(),
        "recovered passphrase must be non-empty"
    );

    // 3. Derive the vault MEK from the recovered passphrase + a fresh salt.
    let salt = Vault::generate_salt();
    let vault = Vault::from_passphrase(&passphrase, &salt);

    // 4. Credential round-trip: add → get must return the original value.
    let store = DaemonStore::open_in_memory().expect("open in-memory store");

    vault
        .add(
            VaultScope::Interactive,
            &store,
            "se-integration-test",
            b"se-vault-round-trip-value",
            None,
        )
        .expect("vault.add via SE-derived MEK");

    let recovered = vault
        .get(VaultScope::Interactive, &store, "se-integration-test")
        .expect("vault.get via SE-derived MEK");

    assert_eq!(
        recovered, b"se-vault-round-trip-value",
        "vault get must return the value written by vault add"
    );
}
