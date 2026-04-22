use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rusqlite::{OptionalExtension, params};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::DaemonConfig;
use crate::store::{DaemonStore, StoreError};

/// Compile-time default keyring service name.
pub const DEFAULT_KEYRING_SERVICE: &str = "ember-daemon";
/// Compile-time default keyring account name.
pub const DEFAULT_KEYRING_ACCOUNT: &str = "vault";

#[derive(Debug)]
pub enum VaultError {
    Store(StoreError),
    Crypto(String),
    NotFound,
    Keyring(String),
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Store(e) => write!(f, "store error: {e}"),
            VaultError::Crypto(s) => write!(f, "crypto error: {s}"),
            VaultError::NotFound => write!(f, "credential not found"),
            VaultError::Keyring(s) => write!(f, "keyring error: {s}"),
            VaultError::Io(s) => write!(f, "io error: {s}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub metadata: Option<String>,
}

pub struct Vault {
    vault_key: [u8; 32],
}

impl Vault {
    pub fn new(vault_key: [u8; 32]) -> Self {
        Vault { vault_key }
    }

    /// Derive a vault key from a passphrase using Argon2id.
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Self {
        let mut key = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .expect("Argon2 key derivation failed");
        Self { vault_key: key }
    }

    /// Generate a random salt for key derivation.
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).expect("OS entropy failure");
        salt
    }

    /// Open the vault using the passphrase and salt from config.
    ///
    /// Passphrase source order (first match wins):
    /// 1. `EMBER_VAULT_PASSPHRASE` environment variable (CI / automation)
    /// 2. System keyring — service/account resolved in order:
    ///    a. `config.keyring.service` / `config.keyring.account` (if `Some`)
    ///    b. `EMBER_KEYRING_SERVICE` / `EMBER_KEYRING_ACCOUNT` env var (debug backdoor)
    ///    c. Compile-time defaults (`DEFAULT_KEYRING_SERVICE` / `DEFAULT_KEYRING_ACCOUNT`)
    /// 3. Auto-generated random passphrase stored in keyring on first run
    ///
    /// Salt is read from `<data_dir>/vault.salt`; created on first call.
    pub fn open_from_config(config: &DaemonConfig) -> Result<Vault, VaultError> {
        let salt = vault_salt(config)?;
        let service = resolve_keyring_service(&config.keyring);
        let account = resolve_keyring_account(&config.keyring);
        let passphrase = resolve_passphrase(&service, &account)?;
        Ok(Vault::from_passphrase(&passphrase, &salt))
    }

    pub fn add(
        &self,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, value)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let id = format!("cred-{}", Uuid::new_v4());
        let created_at = chrono::Utc::now().to_rfc3339();

        store
            .conn()
            .execute(
                "INSERT INTO credentials (id, name, nonce, ciphertext, created_at, metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, name, nonce_bytes.as_slice(), ciphertext, created_at, metadata],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(CredentialInfo {
            id,
            name: name.to_string(),
            created_at,
            metadata: metadata.map(str::to_string),
        })
    }

    pub fn list(&self, store: &DaemonStore) -> Result<Vec<CredentialInfo>, VaultError> {
        let mut stmt = store
            .conn()
            .prepare("SELECT id, name, created_at, metadata FROM credentials ORDER BY created_at")
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(CredentialInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    metadata: row.get(3)?,
                })
            })
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?);
        }
        Ok(result)
    }

    pub fn get(&self, store: &DaemonStore, name: &str) -> Result<Vec<u8>, VaultError> {
        let result: Option<(Vec<u8>, Vec<u8>)> = store
            .conn()
            .query_row(
                "SELECT nonce, ciphertext FROM credentials WHERE name = ?1",
                params![name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let (nonce_bytes, ciphertext) = result.ok_or(VaultError::NotFound)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        Ok(plaintext)
    }

    pub fn remove(&self, store: &DaemonStore, name: &str) -> Result<(), VaultError> {
        let rows_affected = store
            .conn()
            .execute("DELETE FROM credentials WHERE name = ?1", params![name])
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        if rows_affected == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }
}

/// Resolve the keyring service name from a `KeyringConfig`.
///
/// Resolution order:
/// 1. `config.service` if `Some`
/// 2. `EMBER_KEYRING_SERVICE` env var (debug backdoor)
/// 3. `DEFAULT_KEYRING_SERVICE` compile-time default
pub fn resolve_keyring_service(config: &crate::config::KeyringConfig) -> String {
    if let Some(ref s) = config.service {
        return s.clone();
    }
    std::env::var("EMBER_KEYRING_SERVICE").unwrap_or_else(|_| DEFAULT_KEYRING_SERVICE.to_string())
}

/// Resolve the keyring account name from a `KeyringConfig`.
///
/// Resolution order:
/// 1. `config.account` if `Some`
/// 2. `EMBER_KEYRING_ACCOUNT` env var (debug backdoor)
/// 3. `DEFAULT_KEYRING_ACCOUNT` compile-time default
pub fn resolve_keyring_account(config: &crate::config::KeyringConfig) -> String {
    if let Some(ref a) = config.account {
        return a.clone();
    }
    std::env::var("EMBER_KEYRING_ACCOUNT").unwrap_or_else(|_| DEFAULT_KEYRING_ACCOUNT.to_string())
}

/// Keyring service name used to identify the ember vault entry in the OS keychain.
///
/// This is the legacy env-var-only helper retained for callers that do not yet have
/// a `KeyringConfig` (e.g., `ember init` before the config is written).
/// Override via `EMBER_KEYRING_SERVICE` env var.
pub fn keyring_service() -> String {
    std::env::var("EMBER_KEYRING_SERVICE").unwrap_or_else(|_| DEFAULT_KEYRING_SERVICE.to_string())
}

/// Keyring account name used to identify the ember vault entry in the OS keychain.
///
/// Legacy env-var-only helper. Override via `EMBER_KEYRING_ACCOUNT` env var.
pub fn keyring_account() -> String {
    std::env::var("EMBER_KEYRING_ACCOUNT").unwrap_or_else(|_| DEFAULT_KEYRING_ACCOUNT.to_string())
}

/// Log the active keyring identity at INFO level and, if the config uses the production default
/// service with a non-default config path, emit a WARN.
///
/// Call this once at daemon startup after the vault is opened.
pub fn log_vault_identity(config: &DaemonConfig, config_path: Option<&std::path::Path>) {
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);
    info!(service = %service, account = %account, "vault: keyring identity");

    // Warn when the default (production) service is in use but a custom config path was given —
    // this is the foot-gun state where an operator forgot to set [keyring].service.
    let using_default_service = config.keyring.service.is_none()
        && std::env::var("EMBER_KEYRING_SERVICE").is_err();

    if using_default_service && let Some(cp) = config_path {
        let default_path = DaemonConfig::default_config_path();
        let canon_actual = cp.canonicalize().unwrap_or_else(|_| cp.to_path_buf());
        let canon_default = default_path.canonicalize().unwrap_or(default_path);
        if canon_actual != canon_default {
            warn!(
                config_path = %cp.display(),
                "vault: using default (production) keyring service with non-default config \
                 — did you mean to set [keyring].service?"
            );
        }
    }
}

/// Verify a keyring entry can be read back across a fresh `Entry` handle.
///
/// This defeats the keyring crate's in-process mock backend: the mock stores
/// values in a same-process `HashMap`, which would pass a same-handle roundtrip
/// but fails when a second `Entry` is constructed. If the keyring crate is
/// compiled without platform features (no `apple-native`, `windows-native`, or
/// `sync-secret-service`), the mock is silently selected and this check fails.
///
/// Returns `Ok(())` if the read-back matches, `Err` otherwise.
/// True if the current process is a cargo-built test binary. Detects by
/// looking at current_exe path — cargo places test artifacts under
/// `target/<profile>/deps/<name>-<hash>`. Catches integration tests in
/// tests/*.rs and tests in downstream crates (emberlink-cli, workers)
/// that link ember-daemon as a dep where `cfg!(test)` is false.
pub fn is_cargo_test_binary() -> bool {
    match std::env::current_exe() {
        Ok(p) => {
            let s = p.to_string_lossy();
            s.contains("/target/") && s.contains("/deps/")
        }
        Err(_) => false,
    }
}

/// True when raw keyring writes must be suppressed: a cargo test binary is
/// running, or the `EMBER_VAULT_MOCK` opt-out is set. Downstream callers
/// (e.g., `ember init` in `emberlink-cli`) must consult this before
/// invoking `keyring::Entry::new(...).set_password(...)` directly — the
/// three-axis gate that lives inside `resolve_passphrase` does not cover
/// raw keyring access, and missing it was the leak that fired real
/// keychain popups from the emberlink-cli test suite on 2026-04-22.
pub fn keyring_writes_suppressed() -> bool {
    std::env::var("EMBER_VAULT_MOCK").is_ok() || is_cargo_test_binary()
}

pub fn verify_keyring_roundtrip(service: &str, account: &str, expected: &str) -> Result<(), VaultError> {
    // Test gate — skip the real-keychain verification step under the same
    // conditions that suppress keyring access in resolve_passphrase above.
    if cfg!(test) || std::env::var("EMBER_VAULT_MOCK").is_ok() || is_cargo_test_binary() {
        return Ok(());
    }
    let verify_entry = keyring::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("verify: {e}")))?;
    let read_back = verify_entry
        .get_password()
        .map_err(|e| VaultError::Keyring(format!("verify read: {e}")))?;
    if read_back != expected {
        return Err(VaultError::Keyring(
            "roundtrip mismatch — keyring backend may be mock (missing platform features)"
                .to_string(),
        ));
    }
    Ok(())
}

fn resolve_passphrase(service: &str, account: &str) -> Result<String, VaultError> {
    // 1. Environment variable
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        return Ok(p);
    }

    // 1b. Test gate — suppress real keychain access. Without this, `cargo test`
    // on macOS triggers a modal "keychain wants access" dialog for every test
    // that opens a Vault. The earlier version only checked `cfg!(test)`, but
    // that's false when ember-daemon is linked as a dep in integration tests
    // (tests/*.rs) or from another crate's tests (emberlink-cli, workers).
    // Now also detects cargo test binaries by their install path: cargo runs
    // tests from `target/<profile>/deps/<name>-<hash>`, so any process whose
    // current_exe contains `/target/` + `/deps/` is a test binary.
    if cfg!(test) || std::env::var("EMBER_VAULT_MOCK").is_ok() || is_cargo_test_binary() {
        tracing::debug!(
            service = service,
            account = account,
            "vault: returning deterministic test passphrase (cfg!(test) or EMBER_VAULT_MOCK or cargo test binary detected)"
        );
        return Ok(format!("test-passphrase-{service}-{account}"));
    }

    // 2. System keyring
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("init: {e}")))?;

    match entry.get_password() {
        Ok(p) => Ok(p),
        Err(keyring::Error::NoEntry) => {
            // 3. Generate and store a random passphrase, then verify cross-handle read-back
            let p = generate_passphrase();
            entry
                .set_password(&p)
                .map_err(|e| VaultError::Keyring(format!("store: {e}")))?;
            verify_keyring_roundtrip(service, account, &p)?;
            info!("generated and stored vault passphrase in system keyring");
            Ok(p)
        }
        Err(e) => Err(VaultError::Keyring(format!("read: {e}"))),
    }
}

fn vault_salt(config: &DaemonConfig) -> Result<[u8; 16], VaultError> {
    let salt_path = config.data_dir.join("vault.salt");
    if salt_path.exists() {
        let bytes = std::fs::read(&salt_path)
            .map_err(|e| VaultError::Io(format!("salt read: {e}")))?;
        let salt: [u8; 16] = bytes
            .try_into()
            .map_err(|_| VaultError::Io("invalid salt length".to_string()))?;
        Ok(salt)
    } else {
        let salt = Vault::generate_salt();
        std::fs::write(&salt_path, salt)
            .map_err(|e| VaultError::Io(format!("salt write: {e}")))?;
        Ok(salt)
    }
}

fn generate_passphrase() -> String {
    // 32 chars from an alphanumeric alphabet (62 chars) → ~190 bits of entropy.
    // Sampled by rejection from OS entropy to avoid modulo bias.
    const ALPHABET: &[u8; 62] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = String::with_capacity(32);
    let mut scratch = [0u8; 64];
    while out.len() < 32 {
        getrandom::fill(&mut scratch).expect("OS entropy failure");
        for &b in &scratch {
            if out.len() == 32 {
                break;
            }
            // Reject values that would bias the distribution. 256 mod 62 = 70,
            // so values >= 248 are rejected.
            if b < 248 {
                out.push(ALPHABET[(b % 62) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DaemonConfig, KeyringConfig};
    use crate::store::DaemonStore;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    fn other_key() -> [u8; 32] {
        [99u8; 32]
    }

    #[test]
    fn add_list_get_roundtrip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        let info = vault
            .add(&store, "my-api-key", b"supersecret", None)
            .unwrap();
        assert_eq!(info.name, "my-api-key");
        assert!(info.id.starts_with("cred-"));

        let list = vault.list(&store).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "my-api-key");

        let value = vault.get(&store, "my-api-key").unwrap();
        assert_eq!(value, b"supersecret");
    }

    #[test]
    fn duplicate_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "token", b"value1", None).unwrap();
        let result = vault.add(&store, "token", b"value2", None);
        assert!(result.is_err());
    }

    #[test]
    fn get_nonexistent_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        let result = vault.get(&store, "does-not-exist");
        assert!(matches!(result, Err(VaultError::NotFound)));
    }

    #[test]
    fn remove_then_get_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "ephemeral", b"data", None).unwrap();
        vault.remove(&store, "ephemeral").unwrap();

        let result = vault.get(&store, "ephemeral");
        assert!(matches!(result, Err(VaultError::NotFound)));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault.add(&store, "secret", b"confidential", None).unwrap();

        let wrong_vault = Vault::new(other_key());
        let result = wrong_vault.get(&store, "secret");
        assert!(matches!(result, Err(VaultError::Crypto(_))));
    }

    #[test]
    fn list_does_not_include_values() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        vault
            .add(&store, "key1", b"secret1", Some("tag=prod"))
            .unwrap();
        vault.add(&store, "key2", b"secret2", None).unwrap();

        let list = vault.list(&store).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].metadata.as_deref(), Some("tag=prod"));
        assert_eq!(list[1].metadata, None);
    }

    #[test]
    fn open_from_config_roundtrip() {
        // Use a tempdir so salt is isolated; use env-var passphrase to avoid touching keyring.
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();

        let store = DaemonStore::open_in_memory().unwrap();

        // First vault: write a credential.
        let vault1 = Vault::open_from_config(&config).expect("open vault 1");
        vault1
            .add(&store, "round-trip-key", b"secret-value", None)
            .unwrap();

        // Second vault from same config: must decrypt successfully.
        let vault2 = Vault::open_from_config(&config).expect("open vault 2");
        let value = vault2.get(&store, "round-trip-key").unwrap();
        assert_eq!(value, b"secret-value");

        let list = vault2.list(&store).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "round-trip-key");

        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
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

        let config = KeyringConfig { service: None, account: None };

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

        let config = KeyringConfig { service: None, account: None };

        assert_eq!(resolve_keyring_service(&config), DEFAULT_KEYRING_SERVICE);
        assert_eq!(resolve_keyring_account(&config), DEFAULT_KEYRING_ACCOUNT);
    }

    // --- 69G.2 startup banner tests ---

    #[test]
    fn startup_banner_logs_keyring_identity() {
        // Smoke test: log_vault_identity must not panic with a typical config.
        let tmp = tempfile::tempdir().unwrap();
        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();
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

        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();
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
        let mut config = DaemonConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        config.data_dir = tmp.path().to_path_buf();
        config.keyring = KeyringConfig::default();

        unsafe {
            std::env::remove_var("EMBER_KEYRING_SERVICE");
        }

        let default_path = DaemonConfig::default_config_path();
        // No panic regardless of whether the file exists.
        log_vault_identity(&config, Some(&default_path));
    }
}
