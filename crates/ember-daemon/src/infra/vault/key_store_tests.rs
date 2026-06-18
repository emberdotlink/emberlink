use super::*;

// --- P63.A VaultKeyStore tests ---

#[test]
fn vault_key_store_passphrase_variant_constructs() {
    // Shape-only test: confirms `VaultKeyStore::Passphrase(Argon2Salt)`
    // constructs and the salt round-trips through the variant. We
    // deliberately don't run `open_with_key_store` here because the
    // Passphrase lane reads/clears `EMBER_VAULT_PASSPHRASE`, which
    // races with the existing `open_from_config_roundtrip` test
    // under cargo's default parallel test runner. The actual unlock
    // path is exercised end-to-end by `open_from_config_roundtrip`
    // since both share `Vault::from_passphrase`.
    let salt_bytes: [u8; 16] = [3u8; 16];
    let key_store = VaultKeyStore::Passphrase(Argon2Salt::from(salt_bytes));
    match key_store {
        VaultKeyStore::Passphrase(s) => assert_eq!(s.as_bytes(), &salt_bytes),
        _ => panic!("expected Passphrase variant"),
    }
}

#[test]
fn vault_key_store_env_passphrase_variant_constructs() {
    // Shape-only test: `EnvPassphrase` is a unit variant so the test is
    // trivial, but locking the variant into the test surface guards
    // against accidental rename/removal during P63.A-SE-WIRE follow-up.
    let key_store = VaultKeyStore::EnvPassphrase;
    match key_store {
        VaultKeyStore::EnvPassphrase => {}
        _ => panic!("expected EnvPassphrase variant"),
    }
}

#[test]
fn vault_key_store_presence_scope_kek_installs_and_round_trips() {
    // ADR 206 §4: opening via PresenceScopeKek installs the supplied (already
    // cross-uid-unwrapped) scope KEK as the interactive key — no passphrase,
    // no keyring. Authority material sealed under it round-trips, and a
    // different KEK cannot open it (the §4 tap is load-bearing).
    let tmp = tempfile::tempdir().unwrap();
    let config = DaemonConfig::for_test(tmp.path());

    let kek = [7u8; 32];
    let vault = Vault::open_with_key_store(
        &config,
        &VaultKeyStore::PresenceScopeKek(PresenceUnwrappedKek(Zeroizing::new(kek))),
    )
    .expect("§4 presence-scope-KEK lane opens");

    let aad = b"persona-secret:test";
    let sealed = vault
        .seal(
            ValueClass::AuthorityBearing,
            aad,
            b"ed25519-secret:deadbeef",
        )
        .expect("seal");
    let opened = vault
        .open(ValueClass::AuthorityBearing, aad, &sealed)
        .expect("open round-trips");
    assert_eq!(opened.as_slice(), b"ed25519-secret:deadbeef");

    // Key-binding of the sealed blob to the interactive key (here the §4 KEK)
    // is the same DEK-wrapped-under-interactive-key property the passphrase
    // lane uses, already covered by the vault crypto tests. Re-sourcing the
    // interactive key from a DIFFERENT §4 KEK on an EXISTING data dir is the
    // documented clean break (the headless-MEK blob was wrapped under the
    // first KEK and won't unwrap) — exercised at the migration layer, not here.
}

#[test]
fn rotate_mek_refused_on_presence_vault_before_snapshot() {
    // ADR 206 §4 / ADR 211 AC-4 — `rotate_mek` is a passphrase/MEK primitive.
    // On a presence-backed (KEK_s) vault its pre-rotation snapshot would seal the
    // live KEK_s under the passphrase (a passphrase-recoverable scope-KEK leak)
    // and the per-row rewrap would downgrade AuthorityBearing custody to a MEK.
    // The entry guard must refuse BEFORE any side effect — in particular before
    // the snapshot file is written.
    let tmp = tempfile::tempdir().unwrap();
    let config = DaemonConfig::for_test(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();

    let kek = [7u8; 32];
    let vault = Vault::open_with_key_store(
        &config,
        &VaultKeyStore::PresenceScopeKek(PresenceUnwrappedKek(Zeroizing::new(kek))),
    )
    .expect("§4 presence-scope-KEK lane opens");

    let result = vault.rotate_mek(&store, tmp.path(), RotationMode::Rekey, "passphrase", None);
    assert!(
        matches!(result, Err(VaultError::AuthorityCustodyRotationUnsupported)),
        "presence-backed vault must refuse MEK rotation; got {:?}",
        result.as_ref().err()
    );

    // The refusal happened before `write_pre_rotation_snapshot`: no KEK_s was
    // sealed under the passphrase onto disk.
    let leaked_snapshot = std::fs::read_dir(tmp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("vault-mek-snapshot-")
    });
    assert!(
        !leaked_snapshot,
        "a refused presence-vault rotation must not write a KEK_s snapshot file"
    );
}

#[test]
fn presence_unwrapped_kek_debug_is_redacted() {
    // The raw KEK must never appear in a log line / error chain.
    let kek = PresenceUnwrappedKek(Zeroizing::new([0xAB; 32]));
    let rendered = format!("{kek:?}");
    assert_eq!(rendered, "PresenceUnwrappedKek(<redacted>)");
    assert!(!rendered.contains("ab") && !rendered.contains("171"));
}

#[cfg(target_os = "macos")]
#[test]
fn vault_key_store_secure_enclave_opens_with_stub_key() {
    // The SecureEnclave variant is now wired: register a stub SE key,
    // wrap a test interactive key under it, and assert the vault opens
    // successfully via `open_with_key_store`.
    use ember_broker::secure_enclave::{new_stub_key, se_register_stub_key};

    let label_str = "ember-vault-mek-test-ks";
    let handle = new_stub_key(label_str);
    se_register_stub_key(label_str, &handle);
    let label = ember_broker::secure_enclave::EciesKeyLabel::from_provisioned(label_str);

    // Generate a test interactive key and SE-wrap it under the stub.
    let mut interactive_key = [0u8; 32];
    getrandom::fill(&mut interactive_key).unwrap();
    let blob = crate::infra::vault_macos_se::wrap_interactive_key(&label, &interactive_key)
        .expect("stub SE wrap");

    let tmp = tempfile::tempdir().unwrap();
    let config = DaemonConfig::for_test(tmp.path());

    let key_store = VaultKeyStore::SecureEnclave(SEWrappedKey {
        key_label: label_str.to_string(),
        blob,
    });

    let vault = Vault::open_with_key_store(&config, &key_store)
        .expect("SecureEnclave key store must open with a stub-wrapped key");

    // Verify the vault's interactive key matches the one we wrapped.
    assert_eq!(
        *vault.interactive_key.borrow(),
        interactive_key,
        "SE-unwrapped interactive key must match the original"
    );
}

#[test]
fn argon2_salt_round_trips_bytes() {
    let bytes: [u8; 16] = [7u8; 16];
    let salt = Argon2Salt::from(bytes);
    assert_eq!(salt.as_bytes(), &bytes);
}
