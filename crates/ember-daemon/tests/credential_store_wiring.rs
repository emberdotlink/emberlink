//! ARCH-CRED-STORE-D-WIRING (ADR 137 sub-piece D) — T2 wiring test.
//!
//! This test pins the daemon-startup contract for the pluggable
//! `CredentialStore` backend selector. Sub-pieces A, B, C all shipped on
//! `main` (trait + `LocalEncryptedStore`, `HashiVaultStore`, the per-broker
//! `<provider>_config_from_store` sweep). Sub-piece D wires the runtime so
//! the store-first / env-fallback path actually fires at startup. Without
//! this test the wiring is silently inert.
//!
//! Three shapes are exercised:
//!
//! 1. **Config parsing.** `[credential_store] backend = "local"` round-trips
//!    through `DaemonConfig::load` and surfaces in `config.credential_store`.
//!    The default (no section) yields `None`, which the daemon treats as
//!    `"local"` for back-compat.
//! 2. **HashiCorp Vault config parsing.** `backend = "hashicorp-vault"` plus
//!    addr / mount / auth fields round-trip and the at-ref helper resolves
//!    `@<path>` token references off the filesystem the same way
//!    `runtime.rs` does at startup.
//! 3. **Empty-store fallback contract.** A live `LocalEncryptedStore` over an
//!    in-memory daemon-store + fixture vault returns `Ok(None)` from
//!    `azure_config_from_store` when no `azure/*` keys are present — exactly
//!    the shape `runtime.rs` relies on to fall through to the env-file
//!    loader. (Real round-trip storage is exercised by `azure_config`'s own
//!    `cfg(test)` suite via `MockCredentialStore`; this test pins the
//!    integration boundary the runtime touches.)
//!
//! Real `backend = "hashicorp-vault"` exercise lives in sub-piece F
//! (testcontainers Vault) — out of scope for this wiring T2.

use std::io::Write as _;
use std::rc::Rc;
use std::sync::Arc;

use ember_daemon::broker::azure_config::azure_config_from_store;
use ember_daemon::infra::config::{DaemonConfig, resolve_at_ref};
use ember_daemon::infra::credential_store::{CredentialStore, LocalEncryptedStore};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use tempfile::NamedTempFile;

/// `[credential_store]` absent from `config.toml` → `None`. This is the
/// back-compat path: existing operators have no `[credential_store]`
/// section, the daemon treats them as `backend = "local"` without
/// complaint.
#[test]
fn config_without_credential_store_section_yields_none() {
    let toml_str = "[daemon]\nlog_level = \"info\"\n";
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(toml_str.as_bytes()).unwrap();

    let cfg = DaemonConfig::load(f.path()).expect("config loads");
    assert!(
        cfg.credential_store.is_none(),
        "expected credential_store=None when section absent"
    );
}

/// `[credential_store] backend = "local"` is the explicit local-backend
/// opt-in — round-trips through TOML parsing exactly as `runtime.rs` reads
/// it. The defaults for `mount` and `unavailable_policy` show up so a
/// hashicorp-vault flip only requires switching `backend` + `addr`.
#[test]
fn config_with_local_backend_round_trips_through_toml() {
    let toml_str = "[daemon]\nlog_level = \"info\"\n\n[credential_store]\nbackend = \"local\"\n";
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(toml_str.as_bytes()).unwrap();

    let cfg = DaemonConfig::load(f.path()).expect("config loads");
    let cs = cfg.credential_store.expect("section parsed");
    assert_eq!(cs.backend, "local");
    assert_eq!(cs.mount, "secret");
    assert_eq!(cs.unavailable_policy, "fail-hard");
    assert!(cs.addr.is_none());
}

/// `[credential_store] backend = "hashicorp-vault"` round-trips through
/// TOML parsing with all the auth / unavailable_policy / cache_ttl fields
/// the runtime reads at startup. Pins the wire-format contract so a
/// future field rename surfaces here loudly.
#[test]
fn config_with_hashicorp_vault_backend_round_trips() {
    let toml_str = r#"[daemon]
log_level = "info"

[credential_store]
backend = "hashicorp-vault"
addr = "https://vault.example.com:8200"
mount = "kv"
auth = "approle"
role_id = "role-xyz"
secret_id = "@/run/secrets/vault-secret-id"
unavailable_policy = "fall-back-to-cache"
cache_ttl_secs = 90
"#;
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(toml_str.as_bytes()).unwrap();

    let cfg = DaemonConfig::load(f.path()).expect("config loads");
    let cs = cfg.credential_store.expect("section parsed");
    assert_eq!(cs.backend, "hashicorp-vault");
    assert_eq!(cs.addr.as_deref(), Some("https://vault.example.com:8200"));
    assert_eq!(cs.mount, "kv");
    assert_eq!(cs.auth.as_deref(), Some("approle"));
    assert_eq!(cs.role_id.as_deref(), Some("role-xyz"));
    assert_eq!(
        cs.secret_id.as_deref(),
        Some("@/run/secrets/vault-secret-id"),
        "@-ref preserved verbatim — resolve_at_ref runs at construction time"
    );
    assert_eq!(cs.unavailable_policy, "fall-back-to-cache");
    assert_eq!(cs.cache_ttl_secs, Some(90));
}

/// `resolve_at_ref` reads from a file when its argument starts with `@`,
/// passes through literal strings unchanged, and trims trailing newlines.
/// This is the helper `runtime.rs` calls when constructing the Vault
/// `Token` / `AppRole` auth method off a `[credential_store]` config
/// section's `token` / `secret_id` field.
#[test]
fn resolve_at_ref_reads_token_from_file_in_runtime_shape() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hvs.real-token-from-file\n").unwrap();

    let arg_literal = "hvs.literal-inline-token";
    assert_eq!(
        resolve_at_ref(arg_literal).unwrap(),
        "hvs.literal-inline-token"
    );

    let arg_at_ref = format!("@{}", f.path().display());
    let resolved = resolve_at_ref(&arg_at_ref).unwrap();
    assert_eq!(
        resolved, "hvs.real-token-from-file",
        "trailing newline trimmed; rest of file preserved verbatim"
    );
}

/// Empty-store fallback contract: when `backend = "local"` is configured
/// but the operator hasn't migrated any provider credentials into the
/// store yet, `<provider>_config_from_store` MUST return `Ok(None)` so
/// the runtime's broker-registration loop falls through to the env-file
/// loader cleanly. This is the dev-host case — env file is the source of
/// truth, the trait surface must not error on a cold store.
///
/// Mirrors the exact construction `runtime.rs` performs for the local
/// arm: `LocalEncryptedStore::new(Rc<DaemonStore>)` with the live vault
/// attached through the store's shared slot.
/// If this assertion holds, the daemon's startup loop will fall back to
/// the env file for every provider without surfacing a synthetic error.
#[tokio::test(flavor = "current_thread")]
async fn local_backend_empty_store_yields_none_for_provider_lookup() {
    let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
    store.set_vault(Rc::new(Vault::new([0xEFu8; 32])));
    let cs: Arc<dyn CredentialStore> = Arc::new(LocalEncryptedStore::new(Rc::clone(&store)));

    let resolved = azure_config_from_store(&*cs)
        .await
        .expect("empty-store read succeeds");
    assert!(
        resolved.is_none(),
        "empty store must surface as None so the runtime falls back to the env-file loader"
    );
}
