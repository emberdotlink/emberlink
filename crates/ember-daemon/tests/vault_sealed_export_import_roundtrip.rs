//! Vault sealed-MEK export → wipe → import round-trip integration test.
//!
//! Walks the operator recovery scenario at the substrate layer:
//!
//! 1. Stand up a fresh `Vault` from a known MEK and a fresh `DaemonStore`.
//! 2. Write a credential through `Vault::add` — the at-rest ciphertext
//!    lands in `store`, sealed under the MEK.
//! 3. `export_mek_sealed` wraps the MEK under an argon2id-KEK derived
//!    from a recovery passphrase — the operator-handle that gets carried
//!    forward to the recovery machine.
//! 4. Drop the live `Vault` — simulates losing the in-memory MEK (e.g.
//!    keychain entry purged, fresh-machine state).
//! 5. `import_mek_sealed` recovers the MEK bytes from the sealed blob
//!    using the same passphrase + expected fingerprint commitment.
//! 6. Re-instantiate the vault via `Vault::new(recovered)` and
//!    successfully decrypt the credential written in step 2.
//!
//! This is Slice C4 of META-AP-DAEMON-MEK-PERSISTENCE-C-VAULT-EXPORT-
//! IMPORT-SEALED. C1 (the sealed-blob format + `export_mek_sealed` /
//! `import_mek_sealed` substrate) shipped as PR #4139. C2/C3 (the RPC +
//! `ember vault export --sealed` / `--import --sealed` CLI surfaces)
//! are not yet on origin/main, so this test drives the substrate API
//! directly — when the CLI lands, a sibling T3 test can exercise the
//! same scenario end-to-end through `ember`.
//!
//! Anchor: vault_sealed_export_import_landed

use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{
    Vault, VaultScope, export_mek_sealed, import_mek_sealed, mek_fingerprint_hex,
};

/// Operator-flow round-trip:
///   add credential → export sealed MEK → drop Vault → import sealed
///   MEK → re-instantiate Vault → get credential.
///
/// The store persists across the "wipe" boundary — credential ciphertext
/// lives in SQLite, the MEK lives only in the `Vault` value. Losing the
/// MEK is what the sealed export/import recovers from.
///
/// Anchor: vault_sealed_export_import_landed
#[test]
fn vault_sealed_export_import_landed_operator_flow() {
    // --- Pre-state -------------------------------------------------------
    // A fresh 32-byte MEK + the fingerprint commitment that would be
    // recorded in `vault_meta.mek_fingerprint` on the live vault.
    let mut mek = [0u8; 32];
    getrandom::fill(&mut mek).expect("OS entropy failure");
    let fingerprint = mek_fingerprint_hex(&mek);

    let store = DaemonStore::open_in_memory().expect("open store");

    // Recovery passphrase that the operator carries to the fresh machine.
    let passphrase = "correct horse battery staple";

    // --- Step 1 + 2: add a credential through the live vault. -----------
    {
        let live_vault = Vault::new(mek);
        live_vault
            .add(
                VaultScope::Interactive,
                &store,
                "recovery-test-cred",
                b"secret-payload",
                None,
            )
            .expect("add credential");

        // Sanity: the live vault can read its own credential.
        let same_session = live_vault
            .get(VaultScope::Interactive, &store, "recovery-test-cred")
            .expect("get within live session");
        assert_eq!(same_session.as_slice(), b"secret-payload");
    }

    // --- Step 3: export the sealed MEK blob. ----------------------------
    let blob = export_mek_sealed(&mek, passphrase, &fingerprint).expect("export sealed MEK");
    // Sanity: the blob is non-trivial (header + salt + nonce + fp + ct
    // tag is structurally >100 bytes) and starts with the EMVS magic.
    assert!(
        blob.len() > 100,
        "sealed blob suspiciously small: {} bytes",
        blob.len()
    );
    assert_eq!(&blob[..4], b"EMVS", "expected EMVS magic at offset 0");

    // --- Step 4: wipe the live MEK. -------------------------------------
    // Zero the local copy too — the only path back to the credential is
    // through the sealed blob.
    let mek_copy = mek;
    mek.fill(0);
    assert_eq!(mek, [0u8; 32], "local MEK copy is wiped");

    // --- Step 5: import the sealed blob on the "fresh machine". ---------
    let recovered = import_mek_sealed(&blob, passphrase, &fingerprint).expect("import sealed MEK");
    assert_eq!(
        recovered.len(),
        32,
        "recovered MEK should be 32 bytes, got {}",
        recovered.len()
    );
    assert_eq!(
        recovered.as_slice(),
        &mek_copy,
        "recovered MEK bytes must match the original"
    );

    // --- Step 6: re-instantiate Vault from the recovered MEK and read
    //             the credential that was sealed under the original MEK.
    let mut recovered_mek = [0u8; 32];
    recovered_mek.copy_from_slice(&recovered);
    let restored_vault = Vault::new(recovered_mek);

    let plaintext = restored_vault
        .get(VaultScope::Interactive, &store, "recovery-test-cred")
        .expect("get credential after sealed-MEK import");
    assert_eq!(
        plaintext.as_slice(),
        b"secret-payload",
        "credential plaintext must round-trip after sealed-MEK import"
    );
}

/// Wrong passphrase on import refuses with `SealedBlobAeadFailure` —
/// the recovery passphrase is the only authorization for the sealed
/// blob, so a near-miss must not silently unwrap an arbitrary 32-byte
/// value and then fail downstream (the embedded fingerprint is the
/// second commitment but the AEAD tag is the first line of defence).
///
/// Anchor: vault_sealed_export_import_landed
#[test]
fn vault_sealed_export_import_landed_wrong_passphrase_refused() {
    let mut mek = [0u8; 32];
    getrandom::fill(&mut mek).expect("OS entropy failure");
    let fingerprint = mek_fingerprint_hex(&mek);

    let blob =
        export_mek_sealed(&mek, "correct passphrase", &fingerprint).expect("export sealed MEK");

    let err = import_mek_sealed(&blob, "wrong passphrase", &fingerprint)
        .expect_err("import with wrong passphrase must fail");
    // Don't depend on the exact `VaultError` variant name in error
    // formatting beyond a sanity check — the substrate-level unit tests
    // in `crates/ember-daemon/src/infra/vault.rs::tests` already pin
    // the variant. The contract this integration test cares about is
    // "wrong passphrase → import refused", and the operator never sees
    // an MEK they could plug into a Vault.
    let msg = format!("{err}");
    assert!(
        !msg.is_empty(),
        "import error must surface a non-empty message"
    );
}
