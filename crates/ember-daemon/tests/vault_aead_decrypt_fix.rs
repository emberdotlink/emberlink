//! Vault round-trip contract tests — pin the post-fix vault flow to the
//! observable behavior `ember vault add` + `ember vault get` depend on.
//!
//! Pre-launch, we accept that an existing-vault user with key drift wipes
//! `<data_dir>/vault.salt` and reseeds. These tests therefore exercise the
//! **fresh-vault** contract only: open → add → close → re-open → get must
//! always round-trip cleanly under a stable passphrase + persistent salt.
//! They use `EMBER_VAULT_PASSPHRASE` to short-circuit the keyring lookup,
//! keeping the suite portable to Linux/CI runners.
//!
//! marker: vault-aead-decrypt-fix

use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultError, VaultScope};
use tempfile::TempDir;

/// Helper: build a `DaemonConfig` whose `data_dir` points at a fresh tempdir
/// so each test owns its own `vault.salt`.
fn config_with_data_dir(tmp: &TempDir) -> DaemonConfig {
    DaemonConfig::for_test(tmp.path())
}

/// End-to-end round-trip: open a vault, write a credential, drop the vault,
/// re-open from the same `DaemonConfig`, read the credential back. The test
/// gate in `resolve_passphrase` returns a deterministic passphrase under
/// `cargo test`, so the same `data_dir` (= same salt) deterministically
/// yields the same master key across opens — no env-var manipulation needed.
#[test]
fn vault_open_add_get_round_trips_across_sessions() {
    let tmp = TempDir::new().expect("tempdir");
    let config = config_with_data_dir(&tmp);

    let store1 = DaemonStore::open_in_memory().expect("store 1");

    // Session 1: create the vault, write a credential.
    {
        let vault1 = Vault::open_from_config(&config).expect("open vault 1");
        vault1
            .add(
                VaultScope::Interactive,
                &store1,
                "decrypt-fix-key",
                b"super-secret-value",
                None,
            )
            .expect("add credential");

        let same_session = vault1
            .get(VaultScope::Interactive, &store1, "decrypt-fix-key")
            .expect("get within session 1");
        assert_eq!(same_session, b"super-secret-value");
    }

    // Session 2: re-open with the SAME config (same salt file persisted on
    // disk). The store from session 1 still holds the encrypted credential.
    let vault2 = Vault::open_from_config(&config).expect("open vault 2");
    let across_sessions = vault2
        .get(VaultScope::Interactive, &store1, "decrypt-fix-key")
        .expect("get across session boundary");
    assert_eq!(across_sessions, b"super-secret-value");
}

/// Once initialized, the same `data_dir` (= same persistent `vault.salt`)
/// + same passphrase must always yield the same master key. Every `get`
/// across re-opens must succeed — no AEAD failure on a stable vault.
#[test]
fn vault_key_stable_across_opens_with_persistent_salt() {
    let tmp = TempDir::new().expect("tempdir");
    let config = config_with_data_dir(&tmp);
    let store = DaemonStore::open_in_memory().expect("store");

    // First open: salt file is created.
    {
        let vault1 = Vault::open_from_config(&config).expect("open 1");
        vault1
            .add(
                VaultScope::Interactive,
                &store,
                "stable-key",
                b"stable-value",
                None,
            )
            .expect("add");
    }

    // Subsequent opens: same salt + same deterministic test passphrase = same
    // master key. Every `get` must succeed — no AEAD failure.
    for i in 0..5 {
        let v = Vault::open_from_config(&config).expect("re-open");
        let value = v
            .get(VaultScope::Interactive, &store, "stable-key")
            .unwrap_or_else(|e| panic!("get on re-open #{i} failed: {e:?}"));
        assert_eq!(
            value, b"stable-value",
            "re-open #{i} returned wrong plaintext"
        );
    }
}

/// Multiple credentials stored across multiple opens must all decrypt
/// successfully. This catches the operator's exact symptom: `vault list` works
/// (3 entries: pulumi/..., tailscale/api-token, tailscale/tailnet) but every
/// `vault get` returns `aead::Error`.
#[test]
fn multi_credential_multi_session_all_decrypt() {
    let tmp = TempDir::new().expect("tempdir");
    let config = config_with_data_dir(&tmp);
    let store = DaemonStore::open_in_memory().expect("store");

    // Add three credentials under three different opens.
    {
        let v = Vault::open_from_config(&config).expect("open 1");
        v.add(
            VaultScope::Interactive,
            &store,
            "pulumi/operator/team-zero-dev/team-zero-dev",
            b"pulumi-pass",
            None,
        )
        .expect("add pulumi");
    }
    {
        let v = Vault::open_from_config(&config).expect("open 2");
        v.add(
            VaultScope::Interactive,
            &store,
            "tailscale/api-token",
            b"ts-token",
            None,
        )
        .expect("add tailscale token");
    }
    {
        let v = Vault::open_from_config(&config).expect("open 3");
        v.add(
            VaultScope::Interactive,
            &store,
            "tailscale/tailnet",
            b"tailnet-name",
            None,
        )
        .expect("add tailnet");
    }

    // List sees all three (mirrors the operator's working `vault list`).
    let list_vault = Vault::open_from_config(&config).expect("open for list");
    let listed = list_vault
        .list(VaultScope::Interactive, &store)
        .expect("list");
    assert_eq!(
        listed.len(),
        3,
        "all three entries must be present in index"
    );

    // Get every entry under a fresh vault open — every read must succeed.
    let names_and_expected = [
        (
            "pulumi/operator/team-zero-dev/team-zero-dev",
            &b"pulumi-pass"[..],
        ),
        ("tailscale/api-token", &b"ts-token"[..]),
        ("tailscale/tailnet", &b"tailnet-name"[..]),
    ];
    for (name, expected) in names_and_expected {
        let v = Vault::open_from_config(&config).expect("open for get");
        let got = v
            .get(VaultScope::Interactive, &store, name)
            .unwrap_or_else(|e| panic!("AEAD decrypt failed on {name:?}: {e:?}"));
        assert_eq!(got, expected, "wrong plaintext for {name:?}");
    }
}

/// Direct check: `Vault::get` on a credential sealed with key K1 must surface
/// `VaultError::Crypto(...)` (NOT `Ok` and NOT a panic) when re-opened under
/// key K2. This is the AEAD authentication-tag-mismatch path that the bug
/// report's `aead::Error` corresponds to. The CLI maps this to a non-zero
/// exit code in `crates/emberlink-cli/src/bin/ember.rs:1781-1789` —
/// confirming that branch is the only `Err(_)` arm of `vault get`.
#[test]
fn aead_decrypt_failure_surfaces_as_vault_error_crypto() {
    let store = DaemonStore::open_in_memory().expect("store");
    let v_seal = Vault::new([1u8; 32]);
    v_seal
        .add(VaultScope::Interactive, &store, "cred", b"plaintext", None)
        .expect("seal");

    let v_open_wrong_key = Vault::new([2u8; 32]);
    let err = v_open_wrong_key
        .get(VaultScope::Interactive, &store, "cred")
        .expect_err("must fail with AEAD error under wrong key");

    match err {
        VaultError::Crypto(_) => { /* expected */ }
        other => panic!("expected VaultError::Crypto, got {other:?}"),
    }
}
