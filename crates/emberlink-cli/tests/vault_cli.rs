//! Integration tests for `ember vault list/get/put/export/import`
//! (ARCH-CRED-STORE-E-CLI-EXTENSIONS).
//!
//! The argv-parsing surface lives in `bin/ember.rs`; the round-trip
//! semantics live in `emberlink_cli::vault_io`. These tests exercise:
//!
//! - `mask_credential_for_display` — `****<last4>` default-mask so the
//!   `ember vault get` output is never raw on a screen-recorded terminal.
//! - `encode_export_envelope` + `decode_import_envelope` — the
//!   age-armored JSON envelope round-trip that backs `export` / `import`.
//! - `put_then_list_then_get_round_trip` — direct exercise of the
//!   `Vault` adapter (the same trait surface the binary calls into) so
//!   the CLI's dispatch shape is validated end-to-end without spawning
//!   a daemon process or touching the real keychain.
//! - `put_refuses_value_argv_form` — the `--value <secret>` argv form
//!   is refused at the dispatch layer; clap-level parse still succeeds
//!   so the binary can emit a structured `refuse_value_in_argv` error
//!   pointing at `--stdin` / `--file`. We pin the parse layer here.
//! - `import_aborts_atomically_on_decrypt_failure` — the atomic-import
//!   contract: a single bad entry must abort BEFORE any vault write
//!   lands so the live vault never sees a partial restore.
//!
//! No real keychain is touched — `Vault::new([42; 32])` is the
//! in-process test posture (matches the broker_cli.rs / integration.rs
//! pattern). `DaemonStore::open_in_memory()` keeps SQLite scoped.

use std::rc::Rc;

use core_crypto::{LocalKeyPair, generate_local_encryption_key_pair};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultScope};
use emberlink_cli::vault_io::{
    VaultExportEnvelope, decode_import_envelope, encode_export_envelope,
    mask_credential_for_display,
};

fn fresh_vault_and_store() -> (Vault, Rc<DaemonStore>) {
    let store = Rc::new(DaemonStore::open_in_memory().expect("in-memory store"));
    let vault = Vault::new([42u8; 32]);
    (vault, store)
}

/// Generate a fresh age x25519 keypair for use as the operator's
/// export/import recipient. Tests never read the real
/// `~/.config/emberlink/recipient.age` file.
fn fresh_age_keypair() -> LocalKeyPair {
    generate_local_encryption_key_pair("test-vault", "vault-cli-tests")
}

#[test]
fn mask_credential_for_display_keeps_only_last_four() {
    // Long values reveal the last four chars only.
    assert_eq!(
        mask_credential_for_display(b"sk-anthropic-XYZQ"),
        "****XYZQ"
    );
    // 5+ chars: last 4 visible.
    assert_eq!(mask_credential_for_display(b"abcde"), "****bcde");
    // <=4 chars: nothing revealed.
    assert_eq!(mask_credential_for_display(b"abcd"), "****");
    assert_eq!(mask_credential_for_display(b"a"), "****");
    assert_eq!(mask_credential_for_display(b""), "****");
}

#[test]
fn put_then_list_then_get_round_trip() {
    let (vault, store) = fresh_vault_and_store();

    // Put — same path the `ember vault put` dispatch invokes.
    vault
        .add(
            VaultScope::Interactive,
            &store,
            "azure/tenant-id",
            b"tnt-123-XYZQ",
            None,
        )
        .expect("put succeeded");

    // List should reflect the new entry.
    let creds = vault
        .list(VaultScope::Interactive, &store)
        .expect("list succeeded");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name, "azure/tenant-id");

    // Get returns the raw bytes; default CLI behaviour masks them.
    let raw = vault
        .get(VaultScope::Interactive, &store, "azure/tenant-id")
        .expect("get succeeded");
    assert_eq!(raw.as_slice(), b"tnt-123-XYZQ");
    assert_eq!(mask_credential_for_display(&raw), "****XYZQ");
}

/// `ember vault put --value <secret>` argv form is refused at runtime
/// dispatch (the binary calls `refuse_value_in_argv`). Clap-level parse
/// still succeeds so the dispatch can emit a structured error pointing
/// at `--stdin` / `--file`. We pin the parse layer here without
/// process-exiting; the runtime refuse path is exercised by the binary
/// itself in qember.sh smoke tests.
#[test]
fn put_refuses_value_argv_form() {
    use clap::{Parser, Subcommand};

    /// Local mirror of the binary's `VaultPut` shape — only the
    /// surface this test pins. Keeping it inline avoids leaking the
    /// binary's `VaultPutArgs` into the public lib surface.
    #[derive(Debug, Parser)]
    struct Toy {
        #[command(subcommand)]
        action: ToyVault,
    }

    #[derive(Debug, Subcommand)]
    enum ToyVault {
        Put(emberlink_cli::vault_io::testing::VaultPutArgsMirror),
    }

    let parsed = Toy::try_parse_from([
        "test",
        "put",
        "--name",
        "azure/tenant-id",
        "--value",
        "leaky",
    ])
    .expect("clap should accept --value at parse-time");

    let ToyVault::Put(args) = parsed.action;
    assert_eq!(args.name, "azure/tenant-id");
    assert_eq!(
        args.value.as_deref(),
        Some("leaky"),
        "value field captured at parse-time so dispatch can refuse it",
    );
}

#[test]
fn export_import_round_trip() {
    let (vault, store) = fresh_vault_and_store();
    let kp = fresh_age_keypair();

    // Populate three entries.
    let entries = [
        ("azure/tenant-id", b"tnt-123-XYZQ".to_vec()),
        ("github/pat", b"ghp_abcdEFGH1234".to_vec()),
        ("anthropic/api-key", b"sk-anthropic-aaaa-bbbb".to_vec()),
    ];
    for (name, value) in &entries {
        vault
            .add(VaultScope::Interactive, &store, name, value, None)
            .expect("put");
    }
    assert_eq!(
        vault.list(VaultScope::Interactive, &store).unwrap().len(),
        3
    );

    // Read them back via `vault.list(VaultScope::Interactive, )` + `vault.get(VaultScope::Interactive, )`, exactly the
    // path the binary's `run_vault_export` follows.
    let creds = vault.list(VaultScope::Interactive, &store).unwrap();
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
    for c in &creds {
        let v = vault.get(VaultScope::Interactive, &store, &c.name).unwrap();
        pairs.push((c.name.clone(), v.to_vec()));
    }
    let envelope = encode_export_envelope(&kp.public_key, &pairs, "2026-05-10T00:00:00Z".into())
        .expect("encode envelope");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.recipient, kp.public_key);
    assert_eq!(envelope.entries.len(), 3);
    // Each entry name is plaintext (operators inspect what's stored)…
    for (entry, (orig_name, _)) in envelope.entries.iter().zip(pairs.iter()) {
        assert_eq!(&entry.name, orig_name);
        // …and each value is sealed under age — armored output must
        // start with the AGE header so import can recognise it.
        assert!(
            entry
                .value_age_armored
                .starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
            "expected armored AGE header, got {:?}",
            &entry.value_age_armored[..40.min(entry.value_age_armored.len())]
        );
    }

    // Serialize to JSON and parse back — same wire shape the
    // `--output <path>` flag would persist to disk.
    let json = serde_json::to_string_pretty(&envelope).unwrap();
    let parsed: VaultExportEnvelope = serde_json::from_str(&json).unwrap();

    // Wipe the live vault to simulate restoring on a fresh host.
    for (name, _) in &entries {
        vault.remove(VaultScope::Interactive, &store, name).unwrap();
    }
    assert!(
        vault
            .list(VaultScope::Interactive, &store)
            .unwrap()
            .is_empty()
    );

    // Decrypt every entry first (atomic-import contract); only on full
    // success do we `put` them back.
    let decrypted =
        decode_import_envelope(&kp.private_key, &parsed).expect("decode envelope succeeded");
    assert_eq!(decrypted.len(), 3);
    for (name, value) in decrypted {
        vault
            .add(VaultScope::Interactive, &store, &name, &value, None)
            .expect("re-put");
    }

    // Verify all three round-tripped byte-for-byte.
    for (name, expected) in &entries {
        let got = vault.get(VaultScope::Interactive, &store, name).unwrap();
        assert_eq!(got.as_slice(), expected, "{name} did not round-trip");
    }
}

/// Atomic-import contract — a single bad entry MUST abort
/// `decode_import_envelope` before any plaintext is returned, so the
/// caller never `put`s a partial restore. The function returns
/// `VaultIoError::Decrypt` on the first failure; the live vault stays
/// untouched.
#[test]
fn import_aborts_atomically_on_decrypt_failure() {
    let kp = fresh_age_keypair();
    // Build a valid 1-entry envelope, then tamper a second entry's
    // armored payload so it fails to decrypt.
    let pairs = vec![("good/key".to_string(), b"good-value-XYZQ".to_vec())];
    let mut envelope =
        encode_export_envelope(&kp.public_key, &pairs, "2026-05-10T00:00:00Z".into()).unwrap();
    // Inject a bogus armored entry — the AGE header is plausible but
    // the body is garbage so decrypt fails on this entry's turn.
    envelope
        .entries
        .push(emberlink_cli::vault_io::VaultExportEntry {
            name: "bad/key".to_string(),
            value_age_armored:
                "-----BEGIN AGE ENCRYPTED FILE-----\nINVALID\n-----END AGE ENCRYPTED FILE-----\n"
                    .to_string(),
        });

    let err = decode_import_envelope(&kp.private_key, &envelope)
        .expect_err("tampered armored entry must fail before any plaintext is returned");
    let msg = err.to_string();
    assert!(
        msg.contains("bad/key"),
        "error must name the offending entry; got {msg}"
    );
}
