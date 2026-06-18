use super::*;
use crate::infra::config::{DaemonConfig, KeyringConfig};
use crate::infra::store::DaemonStore;

fn test_key() -> [u8; 32] {
    [42u8; 32]
}

fn other_key() -> [u8; 32] {
    [99u8; 32]
}

/// VAULT-MEK-HARDENING-V030 C5: a roundtrip through `add` → `get`
/// succeeds when the row carries per-row AAD bound to the row's
/// UUID. The shape of the test is intentionally minimal — the
/// existing `add_list_get_roundtrip` test exercises the happy path
/// for any AAD scheme; this one names the property explicitly so
/// the wire format is locked.
#[test]
fn aad_roundtrip() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    let info = vault
        .add(
            VaultScope::Interactive,
            &store,
            "aad-test/key",
            b"some-secret-value",
            None,
        )
        .unwrap();
    assert!(info.id.starts_with("cred-"));

    // Same Vault decrypts cleanly via the AAD-aware get path.
    let value = vault
        .get(VaultScope::Interactive, &store, "aad-test/key")
        .unwrap();
    assert_eq!(value.as_slice(), b"some-secret-value");
}

/// ADR 198 D2 — envelope-only. A credentials row that pre-dates the
/// S6a migration (NULL `wrapped_dek` / `dek_nonce`) must NOT be
/// silently decrypted under the MEK. `Vault::get` returns a clear
/// error pointing at the migration one-shot — there is no dual-path
/// direct-MEK fallback (the ADR explicitly forbids it). The test
/// synthesises a pre-envelope row directly via SQL so the
/// not-enveloped branch is exercised deterministically.
#[test]
fn pre_envelope_row_errors_clearly() {
    use chacha20poly1305::aead::Aead;

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    // Hand-roll a direct-MEK ciphertext with NULL wrapped_dek, as a
    // pre-S6a daemon's `add` would have produced.
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(
        vault.interactive_key.borrow().as_slice(),
    )
    .unwrap();
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).unwrap();
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, b"legacy-plaintext".as_ref()).unwrap();

    let id = format!("cred-{}", uuid::Uuid::new_v4());
    let created_at = chrono::Utc::now().to_rfc3339();
    store
        .conn()
        .execute(
            "INSERT INTO credentials (id, name, nonce, ciphertext, created_at, metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            rusqlite::params![
                id,
                "legacy-row",
                nonce_bytes.as_slice(),
                ciphertext.as_slice(),
                created_at,
            ],
        )
        .unwrap();

    // Reading a NULL-wrapped_dek row returns a clear error, not a
    // silent decrypt.
    let err = vault
        .get(VaultScope::Interactive, &store, "legacy-row")
        .unwrap_err();
    match err {
        VaultError::Crypto(msg) => {
            assert!(
                msg.contains("not enveloped"),
                "expected a 'not enveloped' error, got: {msg}"
            );
        }
        other => panic!("expected VaultError::Crypto(not enveloped), got {other:?}"),
    }
}

/// ADR 198 D1 — round-trip add → get under the MEK→DEK envelope. The
/// payload is encrypted under a per-row DEK and the DEK is wrapped
/// under the scope MEK; `get` unwraps the DEK then decrypts. Verifies
/// the row carries non-NULL `wrapped_dek` + `dek_nonce` and that a
/// different MEK cannot read it.
#[test]
fn envelope_add_get_roundtrip() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    let info = vault
        .add(
            VaultScope::Interactive,
            &store,
            "envelope-test/key",
            b"enveloped-secret",
            None,
        )
        .unwrap();

    // The row carries both envelope columns.
    let (wrapped, dek_nonce): (Option<Vec<u8>>, Option<Vec<u8>>) = store
        .conn()
        .query_row(
            "SELECT wrapped_dek, dek_nonce FROM credentials WHERE id = ?1",
            rusqlite::params![info.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(wrapped.expect("wrapped_dek").len(), 32 + 16);
    assert_eq!(dek_nonce.expect("dek_nonce").len(), 24);

    // Same MEK reads it back.
    let value = vault
        .get(VaultScope::Interactive, &store, "envelope-test/key")
        .unwrap();
    assert_eq!(value.as_slice(), b"enveloped-secret");

    // A different MEK cannot unwrap the DEK.
    let wrong = Vault::new(other_key());
    let err = wrong
        .get(VaultScope::Interactive, &store, "envelope-test/key")
        .unwrap_err();
    assert!(matches!(err, VaultError::Crypto(_)));
}

/// ADR 198 D1 (scope+row-bound DEK-wrap AAD hardening) — T1(a). An
/// Interactive-wrapped DEK FAILS AEAD authentication when unwrapped as
/// Headless EVEN WHEN the two scope MEKs are set EQUAL. This proves the
/// cross-scope confused-deputy defense no longer rests solely on the MEK
/// split: with `new_split(k, k)` the interactive and headless MEKs are
/// byte-identical, so a constant-AAD v1 wrap would unwrap cleanly across
/// scopes. The v2 AAD folds the scope label into the wrap, so the AEAD
/// tag itself rejects the cross-scope unwrap.
#[test]
fn dek_wrap_aad_scope_bound_even_with_equal_meks() {
    let k = test_key();
    // Equal interactive and headless MEKs — the MEK split provides NO
    // separation here; only the AAD does.
    let vault = Vault::new_split(k, k);
    assert_eq!(
        *vault.key_for_scope(VaultScope::Interactive),
        *vault.key_for_scope(VaultScope::Headless),
        "test premise: the two scope MEKs are byte-equal"
    );

    // Generate a DEK and wrap it under the INTERACTIVE scope, then
    // attempt to unwrap under the HEADLESS scope. Same MEK bytes, same
    // row id — only the scope label differs.
    let mut dek = Zeroizing::new([0u8; 32]);
    getrandom::fill(dek.as_mut_slice()).unwrap();
    let row_uuid = *Uuid::new_v4().as_bytes();

    let (dek_nonce, wrapped) = wrap_dek(
        &vault.key_for_scope(VaultScope::Interactive),
        &dek,
        VaultScope::Interactive,
        &row_uuid,
    )
    .unwrap();

    // Unwrap as Headless (equal MEK) — must FAIL on the AAD scope
    // mismatch, not succeed.
    let err = unwrap_dek(
        &vault.key_for_scope(VaultScope::Headless),
        &dek_nonce,
        &wrapped,
        VaultScope::Headless,
        &row_uuid,
    )
    .unwrap_err();
    assert!(
        matches!(&err, VaultError::Crypto(m) if m.contains("dek unwrap failed")),
        "expected an AEAD unwrap failure on scope mismatch, got: {err:?}"
    );

    // Sanity: unwrapping under the SAME scope (Interactive) still works,
    // so the failure above is specifically the scope binding, not a
    // broken roundtrip.
    let recovered = unwrap_dek(
        &vault.key_for_scope(VaultScope::Interactive),
        &dek_nonce,
        &wrapped,
        VaultScope::Interactive,
        &row_uuid,
    )
    .unwrap();
    assert_eq!(recovered.as_slice(), dek.as_slice());
}

/// ADR 198 D1 (scope+row-bound DEK-wrap AAD hardening) — T1(b). A
/// whole-row cross-scope splice fails on the wrap-AAD scope mismatch.
/// The attacker moves a row's `wrapped_dek` + `dek_nonce` + `ciphertext`
/// together into ANOTHER scope's namespace (here: lift an Interactive
/// row's sealed material into the Headless `__headless/` namespace under
/// a fresh Headless row id). Reading it back under the Headless scope
/// must fail — the DEK was wrapped with the Interactive scope label and
/// the original row's UUID, so the Headless unwrap rebuilds a different
/// AAD and the AEAD tag rejects it. Uses EQUAL MEKs so the splice is
/// defeated by the AAD alone, not by a key mismatch.
#[test]
fn dek_wrap_aad_defeats_whole_row_cross_scope_splice() {
    let store = DaemonStore::open_in_memory().unwrap();
    let k = test_key();
    let vault = Vault::new_split(k, k);

    // Write a legitimate Interactive row.
    let info = vault
        .add(
            VaultScope::Interactive,
            &store,
            "splice-source/key",
            b"interactive-secret",
            None,
        )
        .unwrap();

    // Read the Interactive row's sealed material verbatim.
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (nonce, ciphertext, wrapped_dek, dek_nonce): Row = store
        .conn()
        .query_row(
            "SELECT nonce, ciphertext, wrapped_dek, dek_nonce \
                 FROM credentials WHERE id = ?1",
            rusqlite::params![info.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();

    // Splice the WHOLE sealed payload (nonce + ciphertext + wrapped_dek
    // + dek_nonce) into a NEW row in the Headless namespace under a fresh
    // Headless row id. This models an attacker with DB write access
    // relocating an Interactive secret into the Headless scope to read it
    // back through the Headless lane (equal MEK in this test).
    let spliced_id = format!("cred-{}", Uuid::new_v4());
    let headless_name = storage_name_for_scope(VaultScope::Headless, "spliced/key");
    let created_at = chrono::Utc::now().to_rfc3339();
    store
        .conn()
        .execute(
            "INSERT INTO credentials \
                 (id, name, nonce, ciphertext, created_at, metadata, wrapped_dek, dek_nonce) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            rusqlite::params![
                spliced_id,
                headless_name,
                nonce,
                ciphertext,
                created_at,
                wrapped_dek,
                dek_nonce
            ],
        )
        .unwrap();

    // Reading the spliced row under the Headless scope must fail: the
    // DEK was wrapped with the Interactive scope label AND the original
    // row's UUID; the Headless `get` rebuilds the AAD from the Headless
    // label and the spliced row's NEW UUID, so the AEAD tag rejects it.
    let err = vault
        .get(VaultScope::Headless, &store, "spliced/key")
        .unwrap_err();
    assert!(
        matches!(&err, VaultError::Crypto(m) if m.contains("dek unwrap failed")),
        "expected the cross-scope whole-row splice to fail on the \
             wrap-AAD mismatch, got: {err:?}"
    );
}

/// ADR 198 Part B — `Vault::seal`/`Vault::open` round-trip through the
/// MEK→DEK envelope: a per-blob DEK seals the payload and the DEK is
/// wrapped under the Interactive MEK with the purpose-bound AAD. A wrong
/// MEK, a wrong `aad_id`, and a tampered ciphertext all fail.
#[test]
fn enveloped_seal_open_roundtrip_and_binding() {
    let vault = Vault::new(test_key());
    let aad_id = b"persona-secret:persona-xyz";

    let env = vault
        .seal(ValueClass::AuthorityBearing, aad_id, b"a-secret-key")
        .unwrap();
    // The MEK does not directly encrypt the payload — there is a wrapped
    // DEK (32-byte key + 16-byte tag) and a separate dek_nonce.
    assert_eq!(env.payload_nonce.len(), 24);
    assert_eq!(env.dek_nonce.len(), 24);
    assert_eq!(env.wrapped_dek.len(), 32 + 16);

    // Correct MEK + correct aad_id opens it.
    assert_eq!(
        vault
            .open(ValueClass::AuthorityBearing, aad_id, &env)
            .unwrap()
            .as_slice(),
        b"a-secret-key"
    );

    // Wrong MEK fails.
    let wrong = Vault::new(other_key());
    assert!(matches!(
        wrong.open(ValueClass::AuthorityBearing, aad_id, &env),
        Err(VaultError::Crypto(_))
    ));

    // Wrong aad_id (different purpose/owner) fails — the wrap AAD binds
    // the blob to its purpose.
    assert!(matches!(
        vault.open(
            ValueClass::AuthorityBearing,
            b"persona-secret:persona-OTHER",
            &env
        ),
        Err(VaultError::Crypto(_))
    ));

    // Tampered ciphertext fails the payload AEAD.
    let mut tampered = env.clone();
    tampered.ciphertext[0] ^= 0xff;
    assert!(matches!(
        vault.open(ValueClass::AuthorityBearing, aad_id, &tampered),
        Err(VaultError::Crypto(_))
    ));
}

/// ADR 198 Part B — `SealedEnvelope` on-disk blob round-trips, and a
/// corrupt/legacy blob is rejected with a clear framing error (no silent
/// mis-parse).
#[test]
fn sealed_envelope_blob_roundtrip_and_framing() {
    let vault = Vault::new(test_key());
    let env = vault
        .seal(
            ValueClass::DaemonOperational,
            b"bridge-ca-module-key",
            b"the-module-key",
        )
        .unwrap();
    let blob = env.to_blob();
    let parsed = SealedEnvelope::from_blob(&blob).unwrap();
    assert_eq!(parsed, env);
    // And it still opens after the round-trip.
    assert_eq!(
        vault
            .open(
                ValueClass::DaemonOperational,
                b"bridge-ca-module-key",
                &parsed
            )
            .unwrap()
            .as_slice(),
        b"the-module-key"
    );

    // A bare [nonce||ct] legacy-shaped blob (wrong leading magic) is
    // rejected, not mis-parsed.
    let legacy = vec![0u8; 24 + 48];
    assert!(matches!(
        SealedEnvelope::from_blob(&legacy),
        Err(VaultError::Crypto(_))
    ));
    // Truncated blob is rejected.
    assert!(matches!(
        SealedEnvelope::from_blob(&blob[..10]),
        Err(VaultError::Crypto(_))
    ));
    // A blob claiming a wrapped_dek length past the end is rejected.
    let mut bad_len = blob.clone();
    bad_len[49] = 0xff;
    bad_len[50] = 0xff;
    bad_len[51] = 0xff;
    bad_len[52] = 0x7f;
    assert!(matches!(
        SealedEnvelope::from_blob(&bad_len),
        Err(VaultError::Crypto(_))
    ));
}

/// ADR 198 D3 — canary verifies under the correct MEK (including on
/// an empty vault with zero credential rows) and fails under a wrong
/// MEK.
#[test]
fn canary_verify_correct_and_wrong_mek_empty_vault() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    // Provision the canary on an EMPTY vault (no credential rows).
    let salt = [7u8; 16];
    vault.provision_envelope_meta(&store, &salt).unwrap();

    // Correct MEK verifies.
    vault.verify_canary(&store).unwrap();

    // Wrong MEK fails loud.
    let wrong = Vault::new(other_key());
    let err = wrong.verify_canary(&store).unwrap_err();
    assert!(
        matches!(&err, VaultError::Crypto(m) if m.contains("canary")),
        "expected a canary crypto failure, got: {err:?}"
    );

    // Salt + params are recorded in vault_meta.
    assert_eq!(store.read_vault_salt().unwrap().as_deref(), Some(&salt[..]));
    assert!(store.read_vault_argon2_params().unwrap().is_some());
}

/// ADR 198 D3 — `verify_canary` is a no-op (Ok) when no canary is
/// stored (transitional pre-migration vault), so a vault that never
/// provisioned a canary still opens under the advisory fingerprint.
#[test]
fn canary_absent_is_ok() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());
    // No provision call — vault_meta has no canary.
    vault.verify_canary(&store).unwrap();
}

/// VAULT-MEK-HARDENING-V030 C4: when `vault.params` contains values
/// that do not match the compile-time-pinned Argon2 parameters,
/// `Vault::open_from_config` refuses to proceed with
/// `VaultError::Crypto("argon2 params mismatch...")`. The file is
/// the trust anchor for "this vault was sealed under the pinned
/// KDF" — a mismatch means either a future param-rotation campaign
/// is needed or the file was tampered with.
#[test]
fn vault_refuses_open_on_argon2_params_mismatch() {
    // Hold the process-wide test lock — env::set_var on a process-
    // global env var races with peer tests under cargo's parallel
    // runner. The lock serializes them.
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "c4-mismatch-test") };

    let config = DaemonConfig::for_test(tmp.path());

    // Write a vault.params with the wrong t-cost (1 instead of 2).
    let bad_params = r#"[argon2]
m = 19456
t = 1
p = 1
alg = "Argon2id"
ver = "V0x13"
"#;
    std::fs::write(tmp.path().join("vault.params"), bad_params).unwrap();

    // Use `open_with_key_store(EnvPassphrase)` to exercise the passphrase
    // path (open_from_config now goes through SE custody which has no Argon2).
    let result = Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase);
    // SAFETY: test-only.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };

    match result {
        Err(VaultError::Crypto(msg)) => {
            assert!(
                msg.contains("argon2 params mismatch"),
                "expected 'argon2 params mismatch' in error, got: {msg}"
            );
        }
        other => panic!(
            "expected VaultError::Crypto with 'argon2 params mismatch', got: {other:?}",
            other = other.map(|_| "Ok(Vault)").map_err(|e| e.to_string())
        ),
    }
}

/// VAULT-MEK-HARDENING-V030 C4 partner: a fresh vault (no
/// `vault.params` on disk) lays one down on first open with the
/// pinned params, and a subsequent open against the same data_dir
/// succeeds (the params file now exists and matches).
#[test]
fn vault_writes_params_file_on_first_open() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "c4-first-open") };

    let config = DaemonConfig::for_test(tmp.path());

    // No vault.params exists yet.
    let params_path = tmp.path().join("vault.params");
    assert!(!params_path.exists(), "precondition: vault.params absent");

    // Use `open_with_key_store(EnvPassphrase)` to exercise the passphrase
    // path (open_from_config now goes through SE custody which has no params file).
    let _v = Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase)
        .expect("first open should succeed");
    assert!(
        params_path.exists(),
        "first open must write vault.params alongside vault.salt"
    );

    // SAFETY: test-only.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };

    // The file content must parse and match the pinned params.
    let contents = std::fs::read_to_string(&params_path).unwrap();
    assert!(contents.contains("m = 19456"));
    assert!(contents.contains("t = 2"));
    assert!(contents.contains("p = 1"));
    assert!(contents.contains("Argon2id"));
    assert!(contents.contains("V0x13"));
}

/// VAULT-MEK-HARDENING-V030 C1: `Vault` must implement
/// `ZeroizeOnDrop` so the MEK is wiped from memory when the Vault is
/// dropped (explicit lock, daemon shutdown, or any Rc going to zero
/// references). Compile-time trait assertion: the function body
/// compiles iff `Vault: ZeroizeOnDrop`.
#[test]
fn vault_is_zeroize() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Vault>();
}

/// ADR 198 D6 — `zero_scope` actually wipes one scope's MEK in place
/// (no longer a no-op stub). After wiping Interactive, the key is the
/// all-zero checkpoint so every Interactive op refuses `HeadlessOnly`,
/// while the independent Headless lane keeps serving (the ADR 139
/// demand-pinned posture). Wiping Headless then breaks that lane's
/// AEAD too.
#[test]
fn zero_scope_wipes_one_scope_in_place() {
    let store = DaemonStore::open_in_memory().unwrap();
    // Distinct, cryptographically-independent scope keys.
    let vault = Vault::new_split([7u8; 32], [9u8; 32]);

    vault
        .add(VaultScope::Interactive, &store, "i-secret", b"i-val", None)
        .unwrap();
    vault
        .add(VaultScope::Headless, &store, "h-secret", b"h-val", None)
        .unwrap();
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "i-secret")
            .unwrap()
            .as_slice(),
        b"i-val"
    );

    // Wipe the Interactive scope.
    vault.zero_scope(VaultScope::Interactive).unwrap();

    // The Interactive key is now the all-zero checkpoint → interactive
    // ops refuse, structurally (`can't > won't`).
    assert!(
        matches!(
            vault.get(VaultScope::Interactive, &store, "i-secret"),
            Err(VaultError::HeadlessOnly)
        ),
        "interactive get must refuse after zero_scope(Interactive)"
    );
    assert!(
        matches!(
            vault.add(VaultScope::Interactive, &store, "i2", b"x", None),
            Err(VaultError::HeadlessOnly)
        ),
        "interactive add must refuse after zero_scope(Interactive)"
    );

    // The Headless lane is untouched and still serves.
    assert_eq!(
        vault
            .get(VaultScope::Headless, &store, "h-secret")
            .unwrap()
            .as_slice(),
        b"h-val"
    );

    // Wiping Headless too zeros that lane — its DEK no longer unwraps.
    vault.zero_scope(VaultScope::Headless).unwrap();
    assert!(
        vault.get(VaultScope::Headless, &store, "h-secret").is_err(),
        "headless get must fail after zero_scope(Headless) zeros the MEK"
    );
}

// ─── ADR 198 D3/D5 — vault MEK rotation (rotate_mek) ───

/// `rekey` re-wraps the Interactive lane under a new salt-derived MEK and
/// preserves every at-rest payload. Proves: the new vault reads all data
/// + canary; the old vault is stale; a full reopen from (passphrase, new
/// DB salt) + the relocated DB headless-MEK wrap reads everything.
#[test]
fn rekey_rewraps_and_preserves_at_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [3u8; 16];
    let pass = "rotation-rekey-pass";
    let interactive = derive_interactive_key(pass, &salt);
    let headless = [9u8; 32];
    let vault = Vault::new_split(interactive, headless);
    vault.provision_envelope_meta(&store, &salt).unwrap();

    vault
        .add(VaultScope::Interactive, &store, "i-cred", b"i-secret", None)
        .unwrap();
    vault
        .add(VaultScope::Headless, &store, "h-cred", b"h-secret", None)
        .unwrap();
    assert!(vault.verify_canary(&store).is_ok());

    let outcome = vault
        .rotate_mek(&store, tmp.path(), RotationMode::Rekey, pass, None)
        .unwrap();
    assert_eq!(outcome.prev_key_epoch, 0);
    assert_eq!(outcome.new_key_epoch, 1);
    assert_ne!(
        outcome.prev_scope_fingerprint,
        outcome.new_scope_fingerprint
    );
    // Only the Interactive cred re-wraps on rekey (Headless value unchanged).
    assert_eq!(outcome.rewrap_count, 1);
    assert!(!outcome.snapshot_path.is_empty());

    let new_vault = outcome.new_vault;
    assert_eq!(
        new_vault
            .get(VaultScope::Interactive, &store, "i-cred")
            .unwrap()
            .as_slice(),
        b"i-secret"
    );
    assert_eq!(
        new_vault
            .get(VaultScope::Headless, &store, "h-cred")
            .unwrap()
            .as_slice(),
        b"h-secret"
    );
    assert!(new_vault.verify_canary(&store).is_ok());

    // The OLD vault is stale: its Interactive MEK can no longer unwrap the
    // re-wrapped interactive cred, and the canary was re-sealed.
    assert!(
        vault
            .get(VaultScope::Interactive, &store, "i-cred")
            .is_err()
    );
    assert!(vault.verify_canary(&store).is_err());

    // Full reopen from the persisted state: re-derive Interactive from the
    // passphrase + the NEW DB salt, load the relocated headless-MEK wrap.
    let new_salt: [u8; 16] = store
        .read_vault_salt()
        .unwrap()
        .expect("salt persisted to DB after rekey")
        .try_into()
        .unwrap();
    assert_ne!(new_salt, salt, "rekey generates a fresh salt");
    let reopened_interactive = derive_interactive_key(pass, &new_salt);
    let (h_nonce, h_wrapped) = store
        .read_headless_mek_wrap()
        .unwrap()
        .expect("headless-mek wrap relocated to DB");
    let reopened_headless =
        unwrap_headless_mek(&reopened_interactive, &h_nonce, &h_wrapped, "test reopen").unwrap();
    let reopened = Vault::new_split(reopened_interactive, reopened_headless);
    assert_eq!(
        reopened
            .get(VaultScope::Interactive, &store, "i-cred")
            .unwrap()
            .as_slice(),
        b"i-secret"
    );
    assert_eq!(
        reopened
            .get(VaultScope::Headless, &store, "h-cred")
            .unwrap()
            .as_slice(),
        b"h-secret"
    );
    assert!(reopened.verify_canary(&store).is_ok());
}

/// `rotate_headless` re-wraps ONLY the Headless lane; the Interactive lane
/// (creds + canary + salt) is untouched.
#[test]
fn rotate_headless_rewraps_headless_lane_only() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [5u8; 16];
    let pass = "rotation-headless-pass";
    let interactive = derive_interactive_key(pass, &salt);
    let vault = Vault::new_split(interactive, [9u8; 32]);
    vault.provision_envelope_meta(&store, &salt).unwrap();
    vault
        .add(VaultScope::Interactive, &store, "i-cred", b"i-secret", None)
        .unwrap();
    vault
        .add(VaultScope::Headless, &store, "h-cred", b"h-secret", None)
        .unwrap();

    let outcome = vault
        .rotate_mek(&store, tmp.path(), RotationMode::RotateHeadless, pass, None)
        .unwrap();
    assert_eq!(outcome.new_key_epoch, 1);
    assert_eq!(outcome.rewrap_count, 1, "only the headless cred re-wraps");
    assert_ne!(
        outcome.prev_scope_fingerprint,
        outcome.new_scope_fingerprint
    );
    // Salt is unchanged on rotate_headless.
    let db_salt: [u8; 16] = store
        .read_vault_salt()
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(db_salt, salt, "rotate_headless leaves the Interactive salt");

    let new_vault = outcome.new_vault;
    assert_eq!(
        new_vault
            .get(VaultScope::Headless, &store, "h-cred")
            .unwrap()
            .as_slice(),
        b"h-secret"
    );
    // Interactive lane unchanged — readable under BOTH old and new vault.
    assert_eq!(
        new_vault
            .get(VaultScope::Interactive, &store, "i-cred")
            .unwrap()
            .as_slice(),
        b"i-secret"
    );
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "i-cred")
            .unwrap()
            .as_slice(),
        b"i-secret"
    );
    assert!(vault.verify_canary(&store).is_ok());
    // Old Headless MEK can no longer read the re-wrapped headless cred.
    assert!(vault.get(VaultScope::Headless, &store, "h-cred").is_err());
}

/// A headless-only Vault cannot rotate (rotation always re-protects under
/// the Interactive MEK, which it lacks).
#[test]
fn rotate_mek_refuses_headless_only_vault() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new_headless_only([9u8; 32]);
    assert!(matches!(
        vault.rotate_mek(&store, tmp.path(), RotationMode::Rekey, "p", None),
        Err(VaultError::HeadlessOnly)
    ));
}

#[test]
fn ac4_authority_bearing_refuses_mek_backed_vault() {
    let mek_backed = Vault::new_split(test_key(), other_key());
    assert!(matches!(
        mek_backed.seal(ValueClass::AuthorityBearing, b"authority", b"secret"),
        Err(VaultError::AuthorityBearingRequiresPresence)
    ));

    let harness = Vault::new(test_key());
    let env = harness
        .seal(ValueClass::AuthorityBearing, b"authority", b"secret")
        .expect("test harness constructor stands in for presence-backed authority");
    assert!(matches!(
        mek_backed.open(ValueClass::AuthorityBearing, b"authority", &env),
        Err(VaultError::AuthorityBearingRequiresPresence)
    ));
}

/// ADR 206 §4 / ADR 211: production MEK-backed vaults no longer create
/// AuthorityBearing persona secrets. Persona authority must arrive through the
/// presence-unwrapped `KEK_s` lane, so there is no MEK-rotation rewrap path for
/// persona roots.
#[test]
fn mek_backed_vault_refuses_persona_secret_creation() {
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [7u8; 16];
    let pass = "rotation-persona-pass";
    let interactive = derive_interactive_key(pass, &salt);
    let vault = std::rc::Rc::new(Vault::new_split(interactive, [9u8; 32]));
    store.set_vault(std::rc::Rc::clone(&vault));
    vault.provision_envelope_meta(&store, &salt).unwrap();

    let err = store
        .create_persona("rotate-me")
        .expect_err("MEK-backed vault must refuse AuthorityBearing persona material");
    match err {
        StoreError::Vault(msg) => assert!(
            msg.contains("presence-unwrapped scope KEK"),
            "expected presence-KEK refusal, got: {msg}"
        ),
        other => panic!("expected Vault refusal, got {other:?}"),
    }
}

/// ADR 206 §4 / ADR 211 AC-4 — `rotate_mek` re-wraps persona-secret DEKs one
/// layer below the `seal`/`open` ValueClass gate (`rewrap_personas_in_tx`).
/// Without a guard there, a Rekey/ChangePassphrase on a presence-backed (KEK_s)
/// vault would re-wrap a persona root onto a passphrase-MEK destination,
/// minting a MEK-reachable copy of the persona root and silently voiding the
/// flip. The rotation must fail closed (tx rolls back; the persona row is
/// untouched) whenever AuthorityBearing persona rows are present.
#[test]
fn rotate_refuses_to_downgrade_authority_bearing_persona_to_mek() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [5u8; 16];
    // Test-harness source stands in for a presence-backed (KEK_s) vault — the
    // only non-MEK source that may carry AuthorityBearing in a unit test (same
    // stand-in `ac4_authority_bearing_refuses_mek_backed_vault` uses).
    let vault = std::rc::Rc::new(Vault::new(test_key()));
    store.set_vault(std::rc::Rc::clone(&vault));
    vault.provision_envelope_meta(&store, &salt).unwrap();

    let persona = store.create_persona("authority-bearing-persona").unwrap();
    let wrap_cols = |store: &DaemonStore| -> (Vec<u8>, Vec<u8>) {
        store
            .conn()
            .query_row(
                "SELECT private_key_dek_nonce, private_key_wrapped_dek FROM personas WHERE id = ?1",
                [&persona.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    };
    let before = wrap_cols(&store);

    // Rekey derives a passphrase-MEK destination vault. Re-wrapping the persona
    // root onto it is the AC-4 downgrade and must be refused. (`RotationOutcome`
    // is not `Debug`, so match on the result rather than `expect_err`.)
    let result = vault.rotate_mek(&store, tmp.path(), RotationMode::Rekey, "rekey-pass", None);
    assert!(
        matches!(result, Err(VaultError::AuthorityBearingRequiresPresence)),
        "rotation must refuse to downgrade AuthorityBearing persona custody to a MEK; got {:?}",
        result.as_ref().err()
    );

    // The persona wrap columns are byte-identical (tx rolled back) — no
    // MEK-reachable copy was written — and the original presence-backed custody
    // still opens the root.
    assert_eq!(
        before,
        wrap_cols(&store),
        "a refused rotation must not mutate the persona secret wrap"
    );
    assert!(
        store.persona_root_keypair(&persona.id).is_ok(),
        "persona root still opens under the original presence-backed custody"
    );
}

/// ADR 206 §4 — the bridge-CA module key is DaemonOperational, wrapped under
/// the HEADLESS key. `RotateHeadless` re-wraps it under the new headless key
/// (the module-key VALUE is preserved); a Rekey (interactive-only) leaves it
/// untouched (covered by `rekey_leaves_headless_bridge_ca_undisturbed`).
#[test]
fn rotate_headless_rewraps_bridge_ca_module_key() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [11u8; 16];
    let pass = "rotation-bridge-pass";
    let interactive = derive_interactive_key(pass, &salt);
    let vault = Vault::new_split(interactive, [9u8; 32]);
    vault.provision_envelope_meta(&store, &salt).unwrap();

    // Seal a fake bridge-CA module key under the headless (DaemonOperational)
    // key and store it DB-side (mirrors a provisioned bridge CA).
    let module_key = [7u8; 32];
    let env = vault
        .seal(
            ValueClass::DaemonOperational,
            b"bridge-ca-module-key",
            &module_key,
        )
        .unwrap();
    store.write_bridge_ca_wrap(&env.to_blob()).unwrap();

    let outcome = vault
        .rotate_mek(&store, tmp.path(), RotationMode::RotateHeadless, pass, None)
        .unwrap();
    let new_vault = outcome.new_vault;

    // The DB wrap was re-written; the new vault opens it to the SAME key.
    let new_blob = store
        .read_bridge_ca_wrap()
        .unwrap()
        .expect("bridge-ca wrap re-written during headless rotation");
    let new_env = SealedEnvelope::from_blob(&new_blob).unwrap();
    assert_eq!(
        new_vault
            .open(
                ValueClass::DaemonOperational,
                b"bridge-ca-module-key",
                &new_env
            )
            .unwrap()
            .as_slice(),
        module_key.as_slice()
    );
    // The stale old vault (old headless key) cannot open the re-wrapped blob.
    assert!(
        vault
            .open(
                ValueClass::DaemonOperational,
                b"bridge-ca-module-key",
                &new_env
            )
            .is_err()
    );
}

/// ADR 206 §4 — a Rekey (interactive passphrase rotation) leaves the
/// headless-keyed bridge-CA module key untouched: the autonomous bridge CA
/// is not disturbed by an operator passphrase change. The original blob
/// still opens under the (unchanged) headless key after the rotation.
#[test]
fn rekey_leaves_headless_bridge_ca_undisturbed() {
    let tmp = tempfile::tempdir().unwrap();
    let store = DaemonStore::open_in_memory().unwrap();
    let salt = [11u8; 16];
    let pass = "rotation-bridge-pass";
    let interactive = derive_interactive_key(pass, &salt);
    let vault = Vault::new_split(interactive, [9u8; 32]);
    vault.provision_envelope_meta(&store, &salt).unwrap();

    let module_key = [7u8; 32];
    let env = vault
        .seal(
            ValueClass::DaemonOperational,
            b"bridge-ca-module-key",
            &module_key,
        )
        .unwrap();
    store.write_bridge_ca_wrap(&env.to_blob()).unwrap();
    let original_blob = env.to_blob();

    let outcome = vault
        .rotate_mek(&store, tmp.path(), RotationMode::Rekey, pass, None)
        .unwrap();
    let new_vault = outcome.new_vault;

    // The bridge-CA wrap is unchanged (headless key did not rotate).
    let after_blob = store
        .read_bridge_ca_wrap()
        .unwrap()
        .expect("bridge-ca wrap row present");
    assert_eq!(
        after_blob, original_blob,
        "Rekey must not re-wrap the headless-keyed bridge CA"
    );
    // The new vault (same headless key) opens the original blob.
    let new_env = SealedEnvelope::from_blob(&after_blob).unwrap();
    assert_eq!(
        new_vault
            .open(
                ValueClass::DaemonOperational,
                b"bridge-ca-module-key",
                &new_env
            )
            .unwrap()
            .as_slice(),
        module_key.as_slice()
    );
}

/// Vault::replace per KEYCHAIN-CONSOLIDATE-CLI adversarial-review
/// HIGH-3: atomic swap via a single SQLite transaction; no
/// observable "no key" window between DELETE and INSERT.
#[test]
fn replace_overwrites_existing_atomically() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());
    vault
        .add(
            VaultScope::Interactive,
            &store,
            "rotation-target",
            b"old",
            None,
        )
        .unwrap();
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "rotation-target")
            .unwrap()
            .as_slice(),
        b"old"
    );
    assert!(
        vault
            .replace(
                VaultScope::Interactive,
                &store,
                "rotation-target",
                b"new",
                None
            )
            .is_ok()
    );
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "rotation-target")
            .unwrap()
            .as_slice(),
        b"new"
    );
    // List should still show exactly one row (replace, not append).
    let names: Vec<String> = vault
        .list(VaultScope::Interactive, &store)
        .unwrap()
        .iter()
        .map(|c| c.name.clone())
        .collect();
    assert_eq!(names, vec!["rotation-target".to_string()]);
}

#[test]
fn replace_succeeds_on_absent_name() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());
    assert!(
        vault
            .replace(
                VaultScope::Interactive,
                &store,
                "fresh-name",
                b"value",
                None
            )
            .is_ok()
    );
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "fresh-name")
            .unwrap()
            .as_slice(),
        b"value"
    );
}

#[test]
fn replace_validates_name_grammar() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());
    let outcome = vault.replace(VaultScope::Interactive, &store, "Invalid-Name", b"x", None);
    match outcome {
        Err(VaultError::InvalidName(_)) => (),
        other => panic!(
            "expected VaultError::InvalidName for uppercase name, got {other:?}",
            other = other.err()
        ),
    }
}

#[test]
fn add_list_get_roundtrip() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    let info = vault
        .add(
            VaultScope::Interactive,
            &store,
            "my-api-key",
            b"supersecret",
            None,
        )
        .unwrap();
    assert_eq!(info.name, "my-api-key");
    assert!(info.id.starts_with("cred-"));

    let list = vault.list(VaultScope::Interactive, &store).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "my-api-key");

    let value = vault
        .get(VaultScope::Interactive, &store, "my-api-key")
        .unwrap();
    assert_eq!(value.as_slice(), b"supersecret");
}

#[test]
fn biometric_requirement_defaults_false_for_existing_shape() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    let info = vault
        .add(
            VaultScope::Interactive,
            &store,
            "ordinary/key",
            b"ordinary-secret",
            None,
        )
        .unwrap();
    assert!(!info.presence_policy.requires_fresh_presence());
    assert!(
        !vault
            .credential_presence_policy(VaultScope::Interactive, &store, "ordinary/key")
            .unwrap()
            .requires_fresh_presence()
    );

    let list = vault.list(VaultScope::Interactive, &store).unwrap();
    assert_eq!(list.len(), 1);
    assert!(!list[0].presence_policy.requires_fresh_presence());
    assert_eq!(
        vault
            .get(VaultScope::Interactive, &store, "ordinary/key")
            .unwrap()
            .as_slice(),
        b"ordinary-secret"
    );
}

#[test]
fn direct_db_biometric_sentinel_blocks_cached_read_until_fresh_gate() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(
            VaultScope::Interactive,
            &store,
            "biometric/key",
            b"protected-secret",
            None,
        )
        .unwrap();
    // Directly stamp the row with the unified per-resource policy, mirroring
    // the legacy `requires_biometric = 1` direct-DB checkpoint the test
    // originally exercised. Asserts the same invariant: a row with
    // `PerAccessFresh` blocks a cached-unlock read and accepts a fresh-
    // presence read.
    store
        .conn()
        .execute(
            "UPDATE credentials SET presence_policy = 'per_access_fresh' WHERE name = ?1",
            rusqlite::params!["biometric/key"],
        )
        .unwrap();

    assert!(
        vault
            .credential_presence_policy(VaultScope::Interactive, &store, "biometric/key")
            .unwrap()
            .requires_fresh_presence()
    );
    assert!(matches!(
        vault.get(VaultScope::Interactive, &store, "biometric/key"),
        Err(VaultError::PresenceRequired)
    ));
    assert_eq!(
        vault
            .get_with_read_gate(
                VaultScope::Interactive,
                &store,
                "biometric/key",
                VaultReadGate::FreshPresence,
            )
            .unwrap()
            .as_slice(),
        b"protected-secret"
    );
}

#[test]
fn replace_sets_and_preserves_biometric_requirement() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(VaultScope::Interactive, &store, "replace/key", b"old", None)
        .unwrap();
    vault
        .replace_with_presence_policy(
            VaultScope::Interactive,
            &store,
            "replace/key",
            b"new",
            None,
            crate::auth::presence_gate::PresencePolicy::PerAccessFresh,
        )
        .unwrap();
    assert!(matches!(
        vault.get(VaultScope::Interactive, &store, "replace/key"),
        Err(VaultError::PresenceRequired)
    ));

    vault
        .replace(
            VaultScope::Interactive,
            &store,
            "replace/key",
            b"newer",
            None,
        )
        .unwrap();
    assert!(matches!(
        vault.get(VaultScope::Interactive, &store, "replace/key"),
        Err(VaultError::PresenceRequired)
    ));
    assert_eq!(
        vault
            .get_with_read_gate(
                VaultScope::Interactive,
                &store,
                "replace/key",
                VaultReadGate::FreshPresence,
            )
            .unwrap()
            .as_slice(),
        b"newer"
    );
}

#[test]
fn headless_scope_isolated_from_interactive_namespace() {
    let store = DaemonStore::open_in_memory().unwrap();
    let interactive_vault = Vault::new(test_key());
    let headless_vault = Vault::new(other_key());

    interactive_vault
        .add(
            VaultScope::Interactive,
            &store,
            "provider/token",
            b"interactive-secret",
            None,
        )
        .unwrap();
    headless_vault
        .add(
            VaultScope::Headless,
            &store,
            "provider/token",
            b"headless-secret",
            None,
        )
        .unwrap();

    let interactive = interactive_vault
        .get(VaultScope::Interactive, &store, "provider/token")
        .unwrap();
    let headless = headless_vault
        .get(VaultScope::Headless, &store, "provider/token")
        .unwrap();
    assert_eq!(interactive.as_slice(), b"interactive-secret");
    assert_eq!(headless.as_slice(), b"headless-secret");

    let interactive_names = interactive_vault
        .list(VaultScope::Interactive, &store)
        .unwrap()
        .into_iter()
        .map(|info| info.name)
        .collect::<Vec<_>>();
    let headless_names = headless_vault
        .list(VaultScope::Headless, &store)
        .unwrap()
        .into_iter()
        .map(|info| info.name)
        .collect::<Vec<_>>();
    assert_eq!(interactive_names, vec!["provider/token".to_string()]);
    assert_eq!(headless_names, vec!["provider/token".to_string()]);
}

#[test]
fn duplicate_name_returns_error() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(VaultScope::Interactive, &store, "token", b"value1", None)
        .unwrap();
    let result = vault.add(VaultScope::Interactive, &store, "token", b"value2", None);
    assert!(result.is_err());
}

#[test]
fn get_nonexistent_returns_not_found() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    let result = vault.get(VaultScope::Interactive, &store, "does-not-exist");
    assert!(matches!(result, Err(VaultError::NotFound)));
}

#[test]
fn remove_then_get_returns_not_found() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(VaultScope::Interactive, &store, "ephemeral", b"data", None)
        .unwrap();
    vault
        .remove(VaultScope::Interactive, &store, "ephemeral")
        .unwrap();

    let result = vault.get(VaultScope::Interactive, &store, "ephemeral");
    assert!(matches!(result, Err(VaultError::NotFound)));
}

#[test]
fn wrong_key_cannot_decrypt() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(
            VaultScope::Interactive,
            &store,
            "secret",
            b"confidential",
            None,
        )
        .unwrap();

    let wrong_vault = Vault::new(other_key());
    let result = wrong_vault.get(VaultScope::Interactive, &store, "secret");
    assert!(matches!(result, Err(VaultError::Crypto(_))));
}

#[test]
fn list_does_not_include_values() {
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new(test_key());

    vault
        .add(
            VaultScope::Interactive,
            &store,
            "key1",
            b"secret1",
            Some("tag=prod"),
        )
        .unwrap();
    vault
        .add(VaultScope::Interactive, &store, "key2", b"secret2", None)
        .unwrap();

    let list = vault.list(VaultScope::Interactive, &store).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].metadata.as_deref(), Some("tag=prod"));
    assert_eq!(list[1].metadata, None);
}

#[test]
fn open_from_config_roundtrip() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: test-only — process-global env mutation gated by PROCESS_TEST_LOCK above.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

    let config = DaemonConfig::for_test(tmp.path());

    let store = DaemonStore::open_in_memory().unwrap();

    // First vault: write a credential (migrated from open_from_config to
    // open_with_key_store per ADR 216 S4).
    let vault1 =
        Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase).expect("open vault 1");
    vault1
        .add(
            VaultScope::Interactive,
            &store,
            "round-trip-key",
            b"secret-value",
            None,
        )
        .unwrap();

    // Re-set the env var: open_with_key_store removes it after first read.
    // SAFETY: test-only, single-threaded, no other threads reading env vars.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

    // Second vault from same config: must decrypt successfully.
    let vault2 =
        Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase).expect("open vault 2");
    let value = vault2
        .get(VaultScope::Interactive, &store, "round-trip-key")
        .unwrap();
    assert_eq!(value.as_slice(), b"secret-value");

    let list = vault2.list(VaultScope::Interactive, &store).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "round-trip-key");

    // SAFETY: test-only, single-threaded, no other threads reading env vars.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
}

// VAULT-SCOPE-MEK-SPLIT-CRYPTOGRAPHIC (B1) anchor: the production
// `open_from_config` path now generates an independent Headless MEK,
// AEAD-wraps it under the Interactive MEK, and persists it to
// `<data_dir>/vault.headless-mek.wrapped`. The two lanes hold
// cryptographically distinct keys after open.
#[test]
fn vault_open_generates_independent_headless_mek_with_wrap_file() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: test-only env, gated by PROCESS_TEST_LOCK.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "split-mek-test-passphrase") };

    let config = DaemonConfig::for_test(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let vault =
        Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase).expect("open vault");

    // Checkpoint #1: the wrap file exists post-open.
    let wrap_path = tmp.path().join(HEADLESS_MEK_WRAP_FILE);
    assert!(
        wrap_path.exists(),
        "headless MEK wrap file must be created on first vault open at {}",
        wrap_path.display()
    );

    // Checkpoint #2: the two keys differ. The Interactive MEK is
    // Argon2id-derived; the Headless MEK is fresh OS entropy. Their
    // collision probability is 2^-256.
    assert_ne!(
        *vault.interactive_key.borrow(),
        *vault.headless_key.borrow(),
        "Interactive and Headless MEKs must be cryptographically independent"
    );

    // Checkpoint #3: a Headless-scope row can be sealed and opened
    // round-trip with the same vault (smoke). The cross-scope
    // tamper case is the next test.
    let store = DaemonStore::open_in_memory().unwrap();
    vault
        .add(
            VaultScope::Headless,
            &store,
            "headless-only-key",
            b"headless-only-value",
            None,
        )
        .expect("seal headless row");
    let got = vault
        .get(VaultScope::Headless, &store, "headless-only-key")
        .expect("open headless row");
    assert_eq!(got.as_slice(), b"headless-only-value");

    // SAFETY: test-only env cleanup.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
}

// VAULT-SCOPE-MEK-SPLIT-CRYPTOGRAPHIC (B1) + adversarial CRIT-1 fix
// checkpoint — `Vault::new_headless_only` refuses Interactive-lane
// operations at the API boundary. Pre-fix, `current_headless_vault`
// built `Vault::new(mek)` (single-key, both lanes equal to the
// headless MEK); calling `seal()` / `add(Interactive, ...)` on it
// would silently route headless-MEK through the Interactive lane.
// Now structurally impossible: every Interactive op gates on
// `is_headless_only()`.
#[test]
fn headless_only_vault_refuses_interactive_lane_operations() {
    let headless = Vault::new_headless_only([0x77u8; 32]);
    let store = DaemonStore::open_in_memory().unwrap();

    // AuthorityBearing seal/open refuse on a headless-only vault — there is
    // no §4/interactive key to seal authority under (ADR 206 §4: the
    // autonomous key may never be an authority recipient).
    match headless.seal(ValueClass::AuthorityBearing, b"test-blob", b"payload") {
        Err(VaultError::HeadlessOnly) => {}
        other => panic!("expected HeadlessOnly on AuthorityBearing seal, got {other:?}"),
    }
    let dummy_env = SealedEnvelope {
        payload_nonce: vec![0u8; 24],
        ciphertext: vec![0u8; 32],
        dek_nonce: vec![0u8; 24],
        wrapped_dek: vec![0u8; 48],
    };
    match headless.open(ValueClass::AuthorityBearing, b"test-blob", &dummy_env) {
        Err(VaultError::HeadlessOnly) => {}
        other => panic!("expected HeadlessOnly on AuthorityBearing open, got {other:?}"),
    }

    // DaemonOperational seal SUCCEEDS on a headless-only vault — it routes to
    // the autonomous headless key, which is always available. It round-trips
    // under the same class.
    let op_env = headless
        .seal(ValueClass::DaemonOperational, b"test-blob", b"payload")
        .expect("DaemonOperational seal must work on a headless-only vault");
    assert_eq!(
        headless
            .open(ValueClass::DaemonOperational, b"test-blob", &op_env)
            .expect("DaemonOperational open round-trips on a headless-only vault")
            .as_slice(),
        b"payload"
    );

    // add(Interactive, …) refuses; add(Headless, …) proceeds.
    let interactive_add = headless.add(VaultScope::Interactive, &store, "foo", b"v", None);
    assert!(
        matches!(interactive_add, Err(VaultError::HeadlessOnly)),
        "expected HeadlessOnly on add(Interactive)"
    );
    assert!(
        headless
            .add(VaultScope::Headless, &store, "headless-row", b"v", None)
            .is_ok(),
        "headless add must proceed"
    );

    // get(Interactive, …) refuses; get(Headless, …) proceeds.
    let interactive_get = headless.get(VaultScope::Interactive, &store, "foo");
    assert!(
        matches!(interactive_get, Err(VaultError::HeadlessOnly)),
        "expected HeadlessOnly on get(Interactive)"
    );
    assert!(
        headless
            .get(VaultScope::Headless, &store, "headless-row")
            .is_ok(),
        "headless get must proceed"
    );

    // replace(Interactive, …) refuses.
    let interactive_replace = headless.replace(VaultScope::Interactive, &store, "foo", b"v", None);
    assert!(
        matches!(interactive_replace, Err(VaultError::HeadlessOnly)),
        "expected HeadlessOnly on replace(Interactive)"
    );
}

// B1 anchor: a row sealed under the Headless MEK CANNOT be
// decrypted by an attacker holding only the Interactive MEK. This
// is the load-bearing threat model ADR 139 §"Split MEK topology"
// locks in — pre-B1 the test would have decrypted successfully
// because both lanes shared one key.
#[test]
fn headless_row_undecryptable_with_interactive_key_only() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::infra::vault_macos_se::stub_vault_mek_label();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: gated by PROCESS_TEST_LOCK.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "cross-scope-tamper-test") };

    let config = DaemonConfig::for_test(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let vault =
        Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase).expect("open vault");

    vault
        .add(
            VaultScope::Headless,
            &store,
            "isolation-target",
            b"sensitive-headless-bytes",
            None,
        )
        .expect("seal headless row");

    // Construct an attacker-controlled Vault that holds ONLY the
    // Interactive MEK in both lanes (the pre-B1 shape). It must
    // NOT be able to decrypt the headless row.
    let interactive_only = Vault::new(*vault.interactive_key.borrow());
    let result = interactive_only.get(VaultScope::Headless, &store, "isolation-target");
    match result {
        Err(VaultError::Crypto(_)) => {
            // expected: AEAD verification fails because the
            // ciphertext was sealed under the Headless MEK.
        }
        Ok(plaintext) => panic!(
            "cryptographic split breached: Interactive-only attacker recovered {} bytes from \
                 a Headless-scope row",
            plaintext.len()
        ),
        Err(other) => {
            panic!("expected Crypto error from cross-scope decrypt attempt, got {other:?}")
        }
    }

    // SAFETY: test-only env cleanup.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
}

/// ADR 211 §3 AC-3 (B1 guard rail) — the attested-device / automation unlock
/// path decrypts INFRA ONLY and refuses the authority lane. This is the
/// end-to-end acceptance the buildout flagged as unowned: the existing headless
/// tests each cover a piece (Interactive-lane refusal, internal `wrap_dek`
/// scope-AAD binding, cross-scope row undecryptability) but none asserts BOTH
/// halves — infra-yes AND authority-no — through the exact
/// `Vault::new_headless_only` construction that `credential_store/local.rs`
/// builds from `AttestedDevice::load_active`.
///
/// Authority-to-act is an operator-presence-minted lease-key (held in daemon
/// memory today; future SE custody per ADR 211 §4). When it is ever sealed it
/// MUST be classed `AuthorityBearing`; this test proves the automation vault's
/// `AuthorityBearing` lane is structurally sealed shut (seal AND open refuse),
/// and that the `ValueClass` -> scope routing is cryptographically bound at the
/// public `seal`/`open` boundary, not merely guarded by the checkpoint gate.
///
/// Scope boundary (kept honest): this is a vault-machinery test. It does NOT —
/// and a vault-level test cannot — catch a CALLER that MISLABELS a lease-key as
/// `DaemonOperational`; the vault faithfully routes whatever class it is handed.
/// That routing-discipline obligation lives at the seal call-site (`lease.rs` /
/// §4 when lease material is first sealed) and is guarded by the doc-comment on
/// `ValueClass`, not here.
#[test]
fn automation_unlock_decrypts_infra_only_never_lease_key() {
    // The vault the automation / attested-device unlock path constructs: the
    // headless MEK is live, the Interactive lane is the all-zero checkpoint.
    let automation = Vault::new_headless_only([0x55u8; 32]);

    // (1) INFRA reachable: a DaemonOperational (bridge-CA-module-key-shaped)
    //     blob seals and round-trips on the automation path.
    let infra = automation
        .seal(
            ValueClass::DaemonOperational,
            b"bridge-ca-module-key",
            b"infra-key-bytes",
        )
        .expect("infra (DaemonOperational) seal must work on the automation vault");
    assert_eq!(
        automation
            .open(
                ValueClass::DaemonOperational,
                b"bridge-ca-module-key",
                &infra
            )
            .expect("infra blob round-trips on the automation vault")
            .as_slice(),
        b"infra-key-bytes",
    );

    // (2) AUTHORITY fails CLOSED on the automation path, BOTH directions. A
    //     lease-key classed `AuthorityBearing` routes to the Interactive lane,
    //     whose key is the all-zero checkpoint on a headless-only vault ->
    //     HeadlessOnly, refused before any DEK is generated (seal) or any
    //     unwrap is attempted (open).
    assert!(
        matches!(
            automation.seal(
                ValueClass::AuthorityBearing,
                b"lease-key",
                b"authority-bytes"
            ),
            Err(VaultError::HeadlessOnly)
        ),
        "automation vault must REFUSE to seal a lease-key (AuthorityBearing)",
    );
    let dummy = SealedEnvelope {
        payload_nonce: vec![0u8; 24],
        ciphertext: vec![0u8; 32],
        dek_nonce: vec![0u8; 24],
        wrapped_dek: vec![0u8; 48],
    };
    assert!(
        matches!(
            automation.open(ValueClass::AuthorityBearing, b"lease-key", &dummy),
            Err(VaultError::HeadlessOnly)
        ),
        "automation vault must REFUSE to open a lease-key (AuthorityBearing)",
    );

    // (3) Defense in depth — the `ValueClass` -> scope routing is folded into
    //     the AEAD wrap AAD at the public seal/open boundary, so it is the
    //     BACKSTOP after the authority-key source gate admits the AuthorityBearing
    //     lane. Proven on a presence-scope-KEK-classified split vault (both lanes
    //     live, so no HeadlessOnly short-circuit) with the two MEKs deliberately
    //     EQUAL — the MEK split therefore provides NO separation, only the
    //     class-bound AAD does. A blob sealed as DaemonOperational fails the AEAD
    //     tag when opened as AuthorityBearing.
    //     (`dek_wrap_aad_scope_bound_even_with_equal_meks` proves this at the
    //     internal `wrap_dek` layer; this asserts it end-to-end through the
    //     public `seal`/`open` ValueClass API.)
    let split = Vault::new_split_with_authority_source(
        [0x55u8; 32],
        [0x55u8; 32],
        AuthorityKeySource::PresenceScopeKek,
    );
    let op_blob = split
        .seal(
            ValueClass::DaemonOperational,
            b"shared-id",
            b"operational-bytes",
        )
        .expect("operational seal under the split vault's headless lane");
    assert!(
        matches!(
            split.open(ValueClass::AuthorityBearing, b"shared-id", &op_blob),
            Err(VaultError::Crypto(_))
        ),
        "cross-class open must fail the AEAD tag even when the scope MEKs are equal",
    );
}

// --- 69G.1 keyring resolution tests ---

#[test]
fn vault_config_field_takes_precedence_over_env() {
    // SAFETY: test-only env var manipulation.
    unsafe {
        std::env::set_var("EMBER_KEYRING_SERVICE", "env-service");
        std::env::set_var("EMBER_KEYRING_ACCOUNT", "env-account");
    }

    let config = KeyringConfig {
        service: Some("config-service".to_string()),
        account: Some("config-account".to_string()),
    };

    assert_eq!(resolve_keyring_service(&config), "config-service");
    assert_eq!(resolve_keyring_account(&config), "config-account");

    unsafe {
        std::env::remove_var("EMBER_KEYRING_SERVICE");
        std::env::remove_var("EMBER_KEYRING_ACCOUNT");
    }
}

#[test]
fn vault_env_var_override_when_config_field_none() {
    // SAFETY: test-only env var manipulation.
    unsafe {
        std::env::set_var("EMBER_KEYRING_SERVICE", "env-service");
        std::env::set_var("EMBER_KEYRING_ACCOUNT", "env-account");
    }

    let config = KeyringConfig {
        service: None,
        account: None,
    };

    assert_eq!(resolve_keyring_service(&config), "env-service");
    assert_eq!(resolve_keyring_account(&config), "env-account");

    unsafe {
        std::env::remove_var("EMBER_KEYRING_SERVICE");
        std::env::remove_var("EMBER_KEYRING_ACCOUNT");
    }
}

#[test]
fn vault_falls_back_to_compile_time_default_when_both_unset() {
    // SAFETY: test-only env var manipulation. Remove any interference from environment.
    unsafe {
        std::env::remove_var("EMBER_KEYRING_SERVICE");
        std::env::remove_var("EMBER_KEYRING_ACCOUNT");
    }

    let config = KeyringConfig {
        service: None,
        account: None,
    };

    assert_eq!(resolve_keyring_service(&config), DEFAULT_KEYRING_SERVICE);
    assert_eq!(resolve_keyring_account(&config), DEFAULT_KEYRING_ACCOUNT);
}

// --- 69G.2 startup banner tests ---

#[test]
fn startup_banner_logs_keyring_identity() {
    // Smoke test: log_vault_identity must not panic with a typical config.
    let tmp = tempfile::tempdir().unwrap();
    let mut config = DaemonConfig::for_test(tmp.path());
    config.keyring = KeyringConfig {
        service: Some("test-service".to_string()),
        account: Some("test-account".to_string()),
    };
    // No panic = pass.
    log_vault_identity(&config, None);
}

#[test]
fn startup_banner_warns_on_default_service_with_custom_config() {
    // When config.keyring.service is None and EMBER_KEYRING_SERVICE is not set,
    // the fallback is the production default. If a non-default config path was
    // given, log_vault_identity should emit a WARN (we test no-panic here; the
    // tracing_test subscriber is not set up in this unit test, so we just verify
    // the code path executes without error).
    let tmp = tempfile::tempdir().unwrap();
    let custom_config = tmp.path().join("custom.toml");
    std::fs::write(&custom_config, "").unwrap();

    let mut config = DaemonConfig::for_test(tmp.path());
    config.keyring = KeyringConfig::default(); // no service override

    unsafe {
        std::env::remove_var("EMBER_KEYRING_SERVICE");
    }

    // Should not panic; warn path exercised.
    log_vault_identity(&config, Some(&custom_config));
}

#[test]
fn startup_banner_does_not_warn_on_default_config() {
    // When the config path IS the default path, no WARN should fire.
    let tmp = tempfile::tempdir().unwrap();
    let mut config = DaemonConfig::for_test(tmp.path());
    config.keyring = KeyringConfig::default();

    unsafe {
        std::env::remove_var("EMBER_KEYRING_SERVICE");
    }

    let default_path = DaemonConfig::default_config_path();
    // No panic regardless of whether the file exists.
    log_vault_identity(&config, Some(&default_path));
}

// --- production-checkpoint tests ---
//
// The helper is parameterized on home_dir so tests can point at a tempdir
// and never touch the real `$HOME`. The real production service string is
// also passed in as a parameter so the test doesn't depend on the global
// `DEFAULT_KEYRING_SERVICE` constant value.

#[test]
fn sentinel_absent_production_service_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    // No checkpoint file created.
    let result = check_production_sentinel("ember-daemon", "ember-daemon", tmp.path());
    match result {
        Err(VaultError::ProductionSentinelMissing(msg)) => {
            assert!(msg.contains(".ember-production"));
            assert!(msg.contains("ember-daemon"));
            assert!(msg.contains("touch ~/.ember-production"));
        }
        other => panic!("expected ProductionSentinelMissing, got {other:?}"),
    }
}

#[test]
fn sentinel_absent_custom_service_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    // No checkpoint; operator has opted out via custom service name.
    check_production_sentinel("ember-daemon-test", "ember-daemon", tmp.path())
        .expect("custom service should bypass checkpoint");
    check_production_sentinel("ember-daemon-qa", "ember-daemon", tmp.path())
        .expect("qa service should bypass checkpoint");
}

#[test]
fn sentinel_present_production_service_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".ember-production"), b"").unwrap();
    check_production_sentinel("ember-daemon", "ember-daemon", tmp.path())
        .expect("checkpoint present should allow production service");
}

#[test]
fn sentinel_check_uses_correct_filename() {
    // A near-miss filename must not satisfy the check.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("ember-production"), b"").unwrap();
    std::fs::write(tmp.path().join(".ember_production"), b"").unwrap();
    let result = check_production_sentinel("ember-daemon", "ember-daemon", tmp.path());
    assert!(
        matches!(result, Err(VaultError::ProductionSentinelMissing(_))),
        "near-miss filenames must not satisfy checkpoint"
    );
}

// --- EMBER_VAULT_PASSPHRASE cleared after first read ---

#[test]
fn env_var_removed_after_open_from_config() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-test-passphrase") };

    let config = DaemonConfig::for_test(tmp.path());

    // Use `open_with_key_store(EnvPassphrase)` to exercise the passphrase
    // path (open_from_config now goes through SE custody which does not
    // read or clear the env var).
    let _vault = Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase)
        .expect("open vault via env passphrase");

    assert!(
        std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
        "EMBER_VAULT_PASSPHRASE must be absent from the environment after open_with_key_store(EnvPassphrase)"
    );
}

// ADR 216 S4: bootstrap_open_from_config_leaves_presence_locked RETIRED
// (open_bootstrap_from_config is a stub that returns Err; the vault now
// opens via the double-envelope RPC).

#[test]
fn env_var_removed_after_resolve_passphrase_no_provision() {
    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-no-provision") };

    let result = resolve_passphrase_no_provision("svc", "acct");
    assert!(result.is_ok());
    // N6: resolve_passphrase_no_provision now returns Option<Zeroizing<String>>.
    // Compare via Deref-into-&str to keep the assertion side independent of
    // the wrapper type.
    let got = result.unwrap();
    assert_eq!(got.as_ref().map(|s| s.as_str()), Some("sec14-no-provision"));

    assert!(
        std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
        "EMBER_VAULT_PASSPHRASE must be absent after resolve_passphrase_no_provision"
    );
}

// ADR 216 S4: bootstrap_auto_unseal_leaves_presence_locked and
// reopen_after_bootstrap_uses_se_unseal RETIRED (same reason as above).

// --- macOS user-presence gate routing ---
//
// The shim itself (`vault_macos`) carries unit tests for the
// `apply_user_presence` predicate and the SE-safety guard. These tests
// assert the routing INSIDE `resolve_passphrase` selects the right
// backend per service name, without touching the real Keychain.
//
// The "first call prompts, subsequent calls cached" property requires a
// live Keychain and is exercised by the gated integration test in
// `tests/sec7_user_presence.rs` (env-flag opt-in).

#[cfg(target_os = "macos")]
#[test]
fn sec7_macos_apply_user_presence_only_for_production_default() {
    // Production default: gate ON. Anything else: gate OFF (qember demo
    // flow uses `ember-daemon-qa` and MUST NOT prompt).
    assert!(crate::infra::vault_macos::apply_user_presence(
        DEFAULT_KEYRING_SERVICE,
        DEFAULT_KEYRING_SERVICE
    ));
    assert!(!crate::infra::vault_macos::apply_user_presence(
        "ember-daemon-qa",
        DEFAULT_KEYRING_SERVICE
    ));
    assert!(!crate::infra::vault_macos::apply_user_presence(
        "ember-daemon-test",
        DEFAULT_KEYRING_SERVICE
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn sec7_qa_service_name_skips_user_presence() {
    // Pure predicate check — proves the QA service name documented in
    // qember.sh ("ember-daemon-qa") routes around the SE-backed shim,
    // so qember demo flows don't fire a biometric prompt every iteration.
    // Avoids env-var manipulation (which races with parallel tests) by
    // exercising the routing decision directly.
    assert!(
        !crate::infra::vault_macos::apply_user_presence("ember-daemon-qa", DEFAULT_KEYRING_SERVICE),
        "qember.sh QA service must NOT trigger the user-presence gate \
             (would break demo flows)"
    );
}

// ADR 216 S4: separate_uid_bootstrap_route_uses_system_keychain_only_without_env_override
// RETIRED (should_use_macos_system_keychain_mek deleted — SE path retired).

// --- salt file permissions ---

#[cfg(unix)]
#[test]
fn salt_file_created_with_0o600_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
    unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec17-perms-test") };

    let config = DaemonConfig::for_test(tmp.path());

    // Use `open_with_key_store(EnvPassphrase)` to exercise the passphrase
    // path (open_from_config now goes through SE custody which does not
    // create a salt file).
    let _vault = Vault::open_with_key_store(&config, &VaultKeyStore::EnvPassphrase)
        .expect("open vault for sec17 via env passphrase");

    let salt_path = tmp.path().join("vault.salt");
    let mode = std::fs::metadata(&salt_path)
        .expect("salt file must exist")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "vault.salt must be 0o600, got {:#o}",
        mode & 0o777
    );

    // SAFETY: test-only.
    unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
}

// --- VAULT-MACOS-BIOMETRIC-MIGRATE: migrate_mek_acl ---

// Serial lock: tests that mutate EMBER_VAULT_TEST_KEYRING_PRESENT must not
// run concurrently — cargo test threads share the process environment.
static MIGRATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_migrate_mek_acl_no_entry_returns_error() {
    // When no MEK entry exists (cfg!(test) gate returns Ok(None)),
    // migrate_mek_acl should return an error rather than silently succeeding.
    //
    // Hold the lock for the whole test so the idempotent test's
    // set_var("EMBER_VAULT_TEST_KEYRING_PRESENT") does not race with our
    // remove_var below.
    let _guard = MIGRATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };
    // Use a non-production service so the biometric path is NOT taken on macOS —
    // we want the system_keyring code path to exercise the Ok(None) branch.
    let result = migrate_mek_acl("ember-daemon-test", "vault");
    assert!(
        result.is_err(),
        "migrate_mek_acl must fail when no MEK entry exists; got: {result:?}"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no MEK entry"),
        "error should mention missing entry; got: {err_msg}"
    );
}

#[test]
fn test_migrate_mek_acl_idempotent_non_mac_service() {
    // For a non-production / QA service on any platform, or for non-macOS,
    // migrate_mek_acl returns system_keyring → system_keyring (idempotent).
    // Simulate a keyring entry being present.
    let _guard = MIGRATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };
    let result = migrate_mek_acl("ember-daemon-qa", "vault");
    unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };

    let result = result.expect("migrate_mek_acl must succeed for qa service with entry present");
    assert_eq!(
        result.before_acl_kind, "system_keyring",
        "qa service: before_acl_kind must be system_keyring"
    );
    assert_eq!(
        result.after_acl_kind, "system_keyring",
        "qa service: after_acl_kind must be system_keyring"
    );
    assert_eq!(result.service, "ember-daemon-qa");
    assert_eq!(result.account, "vault");
}
