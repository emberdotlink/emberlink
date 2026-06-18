//! Vault round-trip contract tests — pin the post-fix vault flow to the
//! observable behavior `ember vault add` + `ember vault get` depend on.
//!
//! Pre-launch, we accept that an existing-vault user with key drift wipes
//! `<data_dir>/vault.salt` and reseeds. These tests therefore exercise the
//! **fresh-vault** contract only: open → add → close → re-open → get must
//! always round-trip cleanly under a stable key.
//!
//! ADR 216 S4: migrated from `Vault::open_from_config` (retired) to
//! `Vault::new([key])` with a deterministic test key.
//!
//! marker: vault-aead-decrypt-fix

use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultError, VaultScope};

const TEST_KEY: [u8; 32] = [0xAB; 32];

/// End-to-end round-trip: open a vault, write a credential, drop the vault,
/// re-open from the same key, read the credential back.
#[test]
fn vault_open_add_get_round_trips_across_sessions() {
    let store = DaemonStore::open_in_memory().expect("store");

    // Session 1: create the vault, write a credential.
    {
        let vault1 = Vault::new(TEST_KEY);
        vault1
            .add(
                VaultScope::Interactive,
                &store,
                "decrypt-fix-key",
                b"super-secret-value",
                None,
            )
            .expect("add credential");

        let same_session = vault1
            .get(VaultScope::Interactive, &store, "decrypt-fix-key")
            .expect("get within session 1");
        assert_eq!(same_session.as_slice(), b"super-secret-value");
    }

    // Session 2: re-open with the same key.
    let vault2 = Vault::new(TEST_KEY);
    let across_sessions = vault2
        .get(VaultScope::Interactive, &store, "decrypt-fix-key")
        .expect("get across session boundary");
    assert_eq!(across_sessions.as_slice(), b"super-secret-value");
}

/// The same key must always yield identical decryptions. Every `get`
/// across re-opens must succeed — no AEAD failure on a stable vault.
#[test]
fn vault_key_stable_across_opens() {
    let store = DaemonStore::open_in_memory().expect("store");

    // First open: add a credential.
    {
        let vault1 = Vault::new(TEST_KEY);
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

    // Subsequent opens: same key = same master key. Every `get` must succeed.
    for i in 0..5 {
        let v = Vault::new(TEST_KEY);
        let value = v
            .get(VaultScope::Interactive, &store, "stable-key")
            .unwrap_or_else(|e| panic!("get on re-open #{i} failed: {e:?}"));
        assert_eq!(
            value.as_slice(),
            b"stable-value",
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
    let store = DaemonStore::open_in_memory().expect("store");

    // Add three credentials under three different opens.
    {
        let v = Vault::new(TEST_KEY);
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
        let v = Vault::new(TEST_KEY);
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
        let v = Vault::new(TEST_KEY);
        v.add(
            VaultScope::Interactive,
            &store,
            "tailscale/tailnet",
            b"tailnet-name",
            None,
        )
        .expect("add tailnet");
    }

    // List sees all three.
    let list_vault = Vault::new(TEST_KEY);
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
        let v = Vault::new(TEST_KEY);
        let got = v
            .get(VaultScope::Interactive, &store, name)
            .unwrap_or_else(|e| panic!("AEAD decrypt failed on {name:?}: {e:?}"));
        assert_eq!(got.as_slice(), expected, "wrong plaintext for {name:?}");
    }
}

/// Direct check: `Vault::get` on a credential sealed with key K1 must surface
/// `VaultError::Crypto(...)` (NOT `Ok` and NOT a panic) when re-opened under
/// key K2. This is the AEAD authentication-tag-mismatch path.
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
