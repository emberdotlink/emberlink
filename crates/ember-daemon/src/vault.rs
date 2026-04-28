//! Vault MEK + sealed-credentials store.
//!
//! ## security check (Tier 1): start-of-session unlock
//!
//! `Vault::open_from_config` reads the MEK passphrase via the SE-backed
//! `vault_macos` shim on macOS — first read prompts for Touch ID. See
//! `vault_macos.rs` for the shim contract.
//!
//! ## security check (Tier 2): per-op user presence + idle re-lock
//!
//! After Tier 1 unlocks the vault, the daemon stays "session-permissive"
//! for read-class operations (vault_get, vault_list, status) but
//! per-operation `require_user_presence` gates fire on high-risk write
//! ops (vault_add, vault_remove, grant create, persona key export). The
//! gate state machine lives in `crate::presence` (not here, because the
//! gate is dispatch-level, not vault-level). The daemon supervisor calls
//! `presence::mark_unlocked()` after a successful Tier 1 unlock so
//! subsequent high-risk ops don't double-prompt within the idle window.
//!
//! See `project design notes` (cross-ref) and the
//! security check task brief for the full layer-cake design.

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
    /// Daemon was about to open the production keyring service without an
    /// opt-in checkpoint (`$HOME/.ember-production`). Refuses to proceed so that
    /// stray dev/QA daemon starts do not fire real keychain prompts.
    ProductionSentinelMissing(String),
    /// Credential name does not conform to the design path grammar.
    /// Only fired by `vault_add` for NEW entries; existing non-conformant
    /// entries are grandfathered (per design §5.4).
    InvalidName(VaultNameError),
}

/// Reasons a credential name fails the design path grammar.
///
/// Grammar (per task brief implementation-note-33):
///   - Lowercase ASCII letters `a-z`
///   - Digits `0-9`
///   - Hyphens `-`
///   - Forward slashes `/` for path segments
///   - Each segment: `^[a-z][a-z0-9-]*$`
///   - 1..=4 path segments
///   - 1..=128 total chars
///
/// Existing entries in the vault that don't conform stay untouched (no
/// migration). Only `vault.add` of NEW entries is validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultNameError {
    /// Empty string or all whitespace.
    Empty,
    /// Total length > 128 chars.
    TooLong { len: usize },
    /// Contains a character outside `[a-z0-9/-]`.
    BadCharacter(char),
    /// A segment fails the per-segment regex (`^[a-z][a-z0-9-]*$`):
    /// must start with a lowercase letter, no leading/trailing hyphen,
    /// no double-hyphen, no empty segment.
    BadSegment(String),
    /// Path has zero segments after splitting on `/`.
    TooFewSegments,
    /// Path has more than 4 segments.
    TooManySegments { count: usize },
}

impl std::fmt::Display for VaultNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultNameError::Empty => write!(f, "credential name is empty"),
            VaultNameError::TooLong { len } => write!(
                f,
                "credential name too long: {len} chars (max 128)"
            ),
            VaultNameError::BadCharacter(c) => write!(
                f,
                "credential name contains invalid character {c:?}: only lowercase \
                 ASCII letters, digits, hyphens, and forward slashes are allowed"
            ),
            VaultNameError::BadSegment(seg) => write!(
                f,
                "credential name segment {seg:?} is invalid: each segment must \
                 match ^[a-z][a-z0-9-]*$ (start with letter; no leading/trailing \
                 hyphen; no empty segments)"
            ),
            VaultNameError::TooFewSegments => write!(
                f,
                "credential name has no segments (min depth 1)"
            ),
            VaultNameError::TooManySegments { count } => write!(
                f,
                "credential name has {count} segments (max depth 4)"
            ),
        }
    }
}

impl std::error::Error for VaultNameError {}

/// Validate a credential name against the design path grammar.
///
/// Existing entries in the vault that don't conform stay untouched (no
/// migration); only `vault.add` of NEW entries is gated by this check.
pub fn validate_credential_name(name: &str) -> Result<(), VaultNameError> {
    // 1. Empty check (covers all-whitespace too — whitespace is a BadCharacter
    //    later, but we reject the empty case up front for a clearer error).
    if name.is_empty() {
        return Err(VaultNameError::Empty);
    }

    // 2. Length cap.
    if name.len() > 128 {
        return Err(VaultNameError::TooLong { len: name.len() });
    }

    // 3. Charset gate — only [a-z0-9/-] allowed. Catches uppercase, dot,
    //    underscore, space, '@', and any non-ASCII before per-segment work.
    for c in name.chars() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/';
        if !ok {
            return Err(VaultNameError::BadCharacter(c));
        }
    }

    // 4. Split on '/' and check segment count + each segment.
    //    Note: `"foo/"` → ["foo", ""], and `"foo//bar"` → ["foo", "", "bar"].
    //    Empty segments are caught by the per-segment regex below.
    let segments: Vec<&str> = name.split('/').collect();

    if segments.is_empty() {
        // Defensive — `str::split` on a non-empty string always yields ≥1 item,
        // so this branch is unreachable in practice. Kept for symmetry.
        return Err(VaultNameError::TooFewSegments);
    }
    if segments.len() > 4 {
        return Err(VaultNameError::TooManySegments {
            count: segments.len(),
        });
    }

    // 5. Per-segment regex: ^[a-z][a-z0-9-]*$. Manual check (no regex dep).
    for seg in &segments {
        if !is_valid_segment(seg) {
            return Err(VaultNameError::BadSegment((*seg).to_string()));
        }
    }

    Ok(())
}

/// Per-segment grammar: must start with `[a-z]`, body `[a-z0-9-]*`.
/// Empty segment fails (no leading char). The leading-char rule rules out
/// leading hyphens and digits in the segment, which is the property the
/// task brief calls out for "rejects leading hyphen or slash".
fn is_valid_segment(seg: &str) -> bool {
    let mut chars = seg.chars();
    match chars.next() {
        None => return false,
        Some(c) if !c.is_ascii_lowercase() => return false,
        Some(_) => {}
    }
    for c in chars {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        if !ok {
            return false;
        }
    }
    true
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Store(e) => write!(f, "store error: {e}"),
            VaultError::Crypto(s) => write!(f, "crypto error: {s}"),
            VaultError::NotFound => write!(f, "credential not found"),
            VaultError::Keyring(s) => write!(f, "keyring error: {s}"),
            VaultError::Io(s) => write!(f, "io error: {s}"),
            VaultError::ProductionSentinelMissing(s) => write!(f, "{s}"),
            VaultError::InvalidName(e) => write!(f, "invalid credential name: {e}"),
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

/// Newtype wrapper around the 16-byte Argon2id salt used to derive the vault
/// MEK from a passphrase. Carried inside `VaultKeyStore::Passphrase` so that
/// the key-store enum is self-describing — the caller doesn't need to plumb
/// the salt separately when they hand the variant off to `Vault::open_with_key_store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Salt(pub [u8; 16]);

impl Argon2Salt {
    /// Borrow the underlying 16 bytes for Argon2 derivation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for Argon2Salt {
    fn from(bytes: [u8; 16]) -> Self {
        Argon2Salt(bytes)
    }
}

/// SE-wrapped master key handle. macOS-only.
///
/// **STUB.** The real implementation will (a) generate a random Vault DEK,
/// (b) wrap it with a SE-resident Ed25519/EC key created via
/// `SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)`, and (c) store the
/// wrapped blob in the daemon's data directory. Unwrapping prompts the user
/// for biometric/passcode and never exposes the SE-resident key material to
/// userland. Wire-up is deferred to **.A-SE-WIRE** so the enum shape can
/// land first and unblock .B (presence attestation) without bringing in
/// the full SecKey API surface.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct SEWrappedKey {
    /// Stable label for the SE-resident wrapping key in the keychain. The
    /// real implementation will use this as the `kSecAttrLabel` so the same
    /// key is rediscoverable across daemon restarts.
    pub key_label: String,
}

/// Source of the vault MEK at unlock time.
///
/// Three lanes today:
/// - **`Passphrase`** — the established lane. Argon2id over the configured
///   passphrase; salt is carried inside the variant so callers don't have to
///   plumb it separately.
/// - **`SecureEnclave`** *(macOS only, stub)* — placeholder for the SE-wrapped
///   master-key lane. Currently returns `VaultError::Crypto("not yet
///   implemented; use Passphrase variant — see .A-SE-WIRE")` from
///   `Vault::open_with_key_store`. Shape is locked here so .B (presence
///   attestation) can build on it without the actual SE wiring landing yet.
/// - **`EnvPassphrase`** — the CI / headless escape hatch. The vault MEK is
///   derived from `$EMBER_VAULT_PASSPHRASE`. The salt still has to come from
///   somewhere — `Vault::open_with_key_store` resolves it from disk via
///   `vault_salt(&config)` at the call site.
#[derive(Debug, Clone)]
pub enum VaultKeyStore {
    /// Passphrase-derived key (Argon2id over the env/configured passphrase).
    Passphrase(Argon2Salt),
    /// SE-wrapped master key. macOS only.
    #[cfg(target_os = "macos")]
    SecureEnclave(SEWrappedKey),
    /// Env passphrase escape hatch (CI/headless).
    EnvPassphrase,
}

#[derive(Clone)]
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

        // Belt-and-suspenders: refuse to open the production keyring service
        // unless the operator has explicitly opted in with
        // `$HOME/.ember-production`. Dev/QA daemons that point at a custom
        // service name (via config or env override) bypass this check. Skipped
        // entirely under cargo-test binaries — the passphrase branch below is
        // also gated there, so the real keychain is never touched in tests.
        if !is_cargo_test_binary() {
            let home = dirs_next::home_dir().ok_or_else(|| {
                VaultError::ProductionSentinelMissing(
                    "refusing to open vault: home directory not resolvable (no $HOME)"
                        .to_string(),
                )
            })?;
            check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home)?;
        }

        let passphrase = resolve_passphrase(&service, &account)?;
        // security check: a successful unlock (Tier 1, possibly via the
        // macOS user-presence prompt) flips the in-process session state
        // to Unlocked so per-op `require_user_presence` gates don't
        // double-prompt within the idle window.
        crate::presence::mark_unlocked();
        Ok(Vault::from_passphrase(&passphrase, &salt))
    }

    /// Open the vault using a `VaultKeyStore` to select the unlock lane.
    ///
    /// Branches on the enum:
    /// - `Passphrase(salt)` — derive via Argon2id from the resolved passphrase
    ///   (env → keyring → auto-generate, same source order as `open_from_config`)
    ///   and the carried salt.
    /// - `EnvPassphrase` — require `EMBER_VAULT_PASSPHRASE`; salt is loaded
    ///   from `<data_dir>/vault.salt` (created on first call).
    /// - `SecureEnclave(_)` *(macOS only)* — **STUB.** Returns
    ///   `VaultError::Crypto("not yet implemented; use Passphrase variant")`.
    ///   Wire-up is tracked under **.A-SE-WIRE**.
    ///
    /// Both passphrase lanes flip the security check presence gate to
    /// Unlocked on success so per-op `require_user_presence` checks don't
    /// double-prompt within the idle window.
    pub fn open_with_key_store(
        config: &DaemonConfig,
        key_store: &VaultKeyStore,
    ) -> Result<Vault, VaultError> {
        match key_store {
            VaultKeyStore::Passphrase(salt) => {
                // Same resolution + checkpoint + presence-mark sequence as
                // `open_from_config`, but the salt is taken from the enum
                // variant rather than re-resolved from disk. The caller is
                // responsible for ensuring the salt matches the one originally
                // used to seal the vault — typically by populating the variant
                // via `vault_salt(config)`.
                let service = resolve_keyring_service(&config.keyring);
                let account = resolve_keyring_account(&config.keyring);

                if !is_cargo_test_binary() {
                    let home = dirs_next::home_dir().ok_or_else(|| {
                        VaultError::ProductionSentinelMissing(
                            "refusing to open vault: home directory not resolvable (no $HOME)"
                                .to_string(),
                        )
                    })?;
                    check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home)?;
                }

                let passphrase = resolve_passphrase(&service, &account)?;
                crate::presence::mark_unlocked();
                Ok(Vault::from_passphrase(&passphrase, salt.as_bytes()))
            }
            VaultKeyStore::EnvPassphrase => {
                // Headless / CI lane — refuse to fall back to the keyring; if
                // the env var is missing, the caller asked for the wrong lane.
                let passphrase = match std::env::var("EMBER_VAULT_PASSPHRASE") {
                    Ok(p) => {
                        // Same single-threaded-startup zeroize as
                        // `resolve_passphrase`'s env branch.
                        // Safety: single-threaded init path; no other threads
                        // are reading env at this point.
                        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
                        p
                    }
                    Err(_) => {
                        return Err(VaultError::Keyring(
                            "VaultKeyStore::EnvPassphrase selected but \
                             EMBER_VAULT_PASSPHRASE is not set"
                                .to_string(),
                        ));
                    }
                };
                let salt = vault_salt(config)?;
                crate::presence::mark_unlocked();
                Ok(Vault::from_passphrase(&passphrase, &salt))
            }
            #[cfg(target_os = "macos")]
            VaultKeyStore::SecureEnclave(_wrapped) => {
                // STUB: real implementation will unwrap `_wrapped.key_label`
                // via SecKeyCopyMatching + SecKeyCreateDecryptedData (which
                // forces the LocalAuthentication prompt and never exposes the
                // SE-resident key to userland). Tracked under
                // .A-SE-WIRE; the enum shape lands first so .B can
                // build on it without dragging in the full SecKey API.
                Err(VaultError::Crypto(
                    "VaultKeyStore::SecureEnclave is not yet implemented; \
                     use VaultKeyStore::Passphrase variant — see .A-SE-WIRE"
                        .to_string(),
                ))
            }
        }
    }

    /// Seal raw bytes under the vault master key and return
    /// `(nonce, ciphertext)` suitable for storing side-by-side in two
    /// BLOB columns. Used by persona-secret at-rest encryption (F-05).
    ///
    /// The nonce is a fresh 24-byte XChaCha20 nonce drawn from OS entropy
    /// per call — never reused across seals.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Open a `(nonce, ciphertext)` pair produced by `seal`. Returns the
    /// plaintext bytes on success, `VaultError::Crypto` on AEAD failure.
    pub fn open(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
        if nonce_bytes.len() != 24 {
            return Err(VaultError::Crypto(format!(
                "invalid nonce length: {}",
                nonce_bytes.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let nonce = XNonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| VaultError::Crypto(e.to_string()))
    }

    pub fn add(
        &self,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        // design path-grammar gate — applies to NEW entries only.
        // Existing rows with non-conformant names continue to function via
        // `get`/`list`/`remove`; this check fires only on insert.
        validate_credential_name(name).map_err(VaultError::InvalidName)?;

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

/// Outcome of `try_auto_unseal_from_keyring` — the daemon/CLI startup helper
/// that opens the vault from a keyring-stored passphrase. Designed as an enum
/// (rather than `Result<Option<Vault>, _>`) so callers can branch on the
/// "no keyring entry yet" case without flattening it into the error path.
pub enum AutoUnsealOutcome {
    /// Keyring lookup succeeded and the vault is unsealed. Attach to the store.
    Unsealed(Vault),
    /// Keyring had no entry for the configured service/account. Treat as
    /// non-fatal: the daemon should still start so the operator can run
    /// `ember init` (or equivalent) to provision one.
    NoKeyringEntry,
    /// Keyring lookup itself failed (platform error, checkpoint missing, etc.).
    /// Caller may surface as a startup warning but should keep running.
    Error(VaultError),
}

/// Best-effort vault auto-unseal from the system keyring.
///
/// This is the documented startup path for both the daemon (`runtime.rs`)
/// and the in-process CLI subcommands (`bin/ember.rs::open_store`) that
/// touch personas without going through the socket. Wraps
/// `Vault::open_from_config` and reshapes its return so a missing keyring
/// entry is `NoKeyringEntry` rather than an opaque error.
///
/// Why a separate helper:
/// - `Vault::open_from_config` auto-generates a passphrase on first call
///   when none exists, which is correct for `ember init` but wrong for
///   "auto-unseal on every daemon start" — we don't want a daemon restart
///   to silently mint a fresh vault key after the keyring was wiped.
///   `try_auto_unseal_from_keyring` only succeeds if the keyring already
///   has an entry (or `EMBER_VAULT_PASSPHRASE` is set, or we're in a test
///   harness with the mock gate enabled).
/// - Centralising the auto-unseal contract here means the daemon and the
///   CLI direct-store paths have one shared trust boundary instead of
///   each re-implementing keyring lookup.
///
/// Always-attempted: there is no relay/hosted/first-party mode flag in
/// `DaemonConfig` today (implementation-note-31 task instructions explicitly note this).
/// If one is added later, gate auto-unseal on first-party mode here.
pub fn try_auto_unseal_from_keyring(config: &DaemonConfig) -> AutoUnsealOutcome {
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);

    // Production checkpoint — same belt-and-suspenders as `open_from_config`.
    // Skip in cargo-test binaries (the passphrase branch below is also gated
    // there, so the real keychain is never touched in tests).
    if !is_cargo_test_binary() {
        let home = match dirs_next::home_dir() {
            Some(h) => h,
            None => {
                return AutoUnsealOutcome::Error(VaultError::ProductionSentinelMissing(
                    "refusing to open vault: home directory not resolvable (no $HOME)"
                        .to_string(),
                ));
            }
        };
        if let Err(e) = check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home) {
            return AutoUnsealOutcome::Error(e);
        }
    }

    // Salt resolution can fail on IO. Treat as a hard error — we cannot
    // derive the vault key without the salt.
    let salt = match vault_salt(config) {
        Ok(s) => s,
        Err(e) => return AutoUnsealOutcome::Error(e),
    };

    // Resolve the passphrase WITHOUT auto-generating one. Distinguishes
    // "keyring miss" (NoKeyringEntry) from "platform error" (Error).
    match resolve_passphrase_no_provision(&service, &account) {
        Ok(Some(passphrase)) => {
            // security check: same Tier-1 → Tier-2 hand-off as
            // `open_from_config` — flip the gate to Unlocked so per-op
            // `require_user_presence` checks succeed within the idle
            // window without re-prompting.
            crate::presence::mark_unlocked();
            AutoUnsealOutcome::Unsealed(Vault::from_passphrase(&passphrase, &salt))
        }
        Ok(None) => AutoUnsealOutcome::NoKeyringEntry,
        Err(e) => AutoUnsealOutcome::Error(e),
    }
}

/// Like `resolve_passphrase` but never provisions a new keyring entry.
/// Returns `Ok(None)` when the keyring has no entry — the signal callers
/// use to distinguish "needs init" from "failed".
///
/// Test/mock gate is preserved: under `cfg!(test)` / `EMBER_VAULT_MOCK` /
/// cargo test binary, returns the deterministic test passphrase so the
/// real keychain is never touched.
fn resolve_passphrase_no_provision(
    service: &str,
    account: &str,
) -> Result<Option<String>, VaultError> {
    // 1. Environment variable — capture then immediately zeroize from the
    // process environment so it cannot be read from /proc/<pid>/environ
    // by a second party after this point. Done before any background threads
    // are running (called during daemon startup), so the signal/thread race
    // in remove_var is acceptable.
    // Safety: single-threaded startup path; no other threads are reading env.
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
        return Ok(Some(p));
    }

    // 2. Test gate — same three-axis check as `resolve_passphrase`.
    if cfg!(test) || std::env::var("EMBER_VAULT_MOCK").is_ok() || is_cargo_test_binary() {
        // In test mode, only return a passphrase if the test has explicitly
        // signaled "keyring entry exists" via `EMBER_VAULT_TEST_KEYRING_PRESENT=1`.
        // Otherwise return None so tests can exercise the NoKeyringEntry path.
        if std::env::var("EMBER_VAULT_TEST_KEYRING_PRESENT").is_ok() {
            return Ok(Some(format!("test-passphrase-{service}-{account}")));
        }
        return Ok(None);
    }

    // 3. macOS user-presence gate (security check). When the effective service is the
    //    production default, route the read through `vault_macos` so the
    //    Keychain entry's `kSecAttrAccessControl` triggers the LocalAuthentication
    //    prompt (Touch ID / device passcode). The `keyring` crate cannot do
    //    this. Dev/QA service names (e.g. `ember-daemon-qa`) skip this branch
    //    and fall through to the regular `keyring::Entry` path so qember.sh
    //    demo flows don't fire a biometric prompt.
    #[cfg(target_os = "macos")]
    if crate::vault_macos::apply_user_presence(service, DEFAULT_KEYRING_SERVICE) {
        return crate::vault_macos::get_password_user_presence(service, account)
            .map_err(VaultError::Keyring);
    }

    // 4. System keyring lookup — read-only, no provisioning.
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("init: {e}")))?;
    match entry.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Keyring(format!("read: {e}"))),
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

/// Refuse to open the production keyring service unless the operator has
/// explicitly opted in by creating `<home>/.ember-production`.
///
/// Returns `Ok(())` when the daemon may proceed:
/// - effective service name differs from the production default (any
///   dev/QA service name opts out automatically), OR
/// - effective service matches the production default AND the checkpoint
///   file exists.
///
/// Returns `Err(VaultError::ProductionSentinelMissing)` when the daemon is
/// pointed at the production service but the checkpoint is absent. The error
/// message is the documentation: it tells the operator how to opt in (touch
/// the checkpoint file) or opt out (set `[keyring].service` or
/// `EMBER_KEYRING_SERVICE`). There is deliberately no `--force` or env
/// escape hatch; the checkpoint IS the opt-in.
///
/// The production service name is taken as a parameter (rather than reading
/// `DEFAULT_KEYRING_SERVICE` directly) so the check is unit-testable with
/// synthetic values. Real callers pass `DEFAULT_KEYRING_SERVICE`.
pub fn check_production_sentinel(
    effective_service: &str,
    production_service: &str,
    home_dir: &std::path::Path,
) -> Result<(), VaultError> {
    if effective_service != production_service {
        // Operator has already opted out by picking a non-default service.
        return Ok(());
    }
    let checkpoint = home_dir.join(".ember-production");
    if checkpoint.exists() {
        return Ok(());
    }
    let msg = format!(
        "refusing to open production keychain without opt-in checkpoint\n  \
         reason: no {checkpoint} file exists\n  \
         effective keyring service: {effective_service:?} (production default)\n  \
         to opt in (production users, one-time):   touch ~/.ember-production\n  \
         to opt out (dev/QA, use isolated vault):  set [keyring].service in config,\n  \
                                                   or pass EMBER_KEYRING_SERVICE=ember-daemon-test",
        checkpoint = checkpoint.display(),
    );
    Err(VaultError::ProductionSentinelMissing(msg))
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
    // 1. Environment variable — capture then immediately zeroize from the
    // process environment so it cannot be read from /proc/<pid>/environ
    // by a second party after this point. Done before any background threads
    // are running (called during daemon startup), so the signal/thread race
    // in remove_var is acceptable.
    // Safety: single-threaded startup path; no other threads are reading env.
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
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

    // 2. macOS user-presence gate (security check). For the production keychain service
    //    the vault MEK passphrase entry is wrapped with kSecAttrAccessControl
    //    requiring user presence (Touch ID / device passcode); the `keyring`
    //    crate cannot set that attribute. Read first; if absent, generate +
    //    store via the SE-wrapped writer so the very first daemon start lays
    //    down a SAC-protected entry. Dev/QA services (e.g. `ember-daemon-qa`)
    //    fall through to the keyring path below — biometric on every QA
    //    iteration would break `qember.sh demo up`.
    #[cfg(target_os = "macos")]
    if crate::vault_macos::apply_user_presence(service, DEFAULT_KEYRING_SERVICE) {
        match crate::vault_macos::get_password_user_presence(service, account)
            .map_err(VaultError::Keyring)?
        {
            Some(p) => return Ok(p),
            None => {
                let p = generate_passphrase();
                crate::vault_macos::set_password_user_presence(service, account, &p)
                    .map_err(VaultError::Keyring)?;
                info!(
                    "generated and stored vault passphrase in macOS Keychain with kSecAttrAccessControl=BiometryAny|Or|DevicePasscode"
                );
                return Ok(p);
            }
        }
    }

    // 3. System keyring (non-macOS, or macOS dev/QA service name).
    let entry = keyring::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("init: {e}")))?;

    match entry.get_password() {
        Ok(p) => Ok(p),
        Err(keyring::Error::NoEntry) => {
            // 4. Generate and store a random passphrase, then verify cross-handle read-back
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
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&salt_path)
                .map_err(|e| VaultError::Io(format!("salt open: {e}")))?;
            f.write_all(&salt)
                .map_err(|e| VaultError::Io(format!("salt write: {e}")))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&salt_path, salt)
                .map_err(|e| VaultError::Io(format!("salt write: {e}")))?;
        }
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

        // Re-set the env var: open_from_config removes it after first read
        // (security check). The second vault must be derived from the same passphrase
        // to decrypt what vault1 wrote.
        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

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

    // --- P69K-security check production-checkpoint tests ---
    //
    // The helper is parameterized on home_dir so tests can point at a tempdir
    // and never touch the real `$HOME`. The real production service string is
    // also passed in as a parameter so the test doesn't depend on the global
    // `DEFAULT_KEYRING_SERVICE` constant value.

    #[test]
    fn sentinel_absent_production_service_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        // No checkpoint file created.
        let result =
            check_production_sentinel("ember-daemon", "ember-daemon", tmp.path());
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
        let result =
            check_production_sentinel("ember-daemon", "ember-daemon", tmp.path());
        assert!(
            matches!(result, Err(VaultError::ProductionSentinelMissing(_))),
            "near-miss filenames must not satisfy checkpoint"
        );
    }

    // --- security check: EMBER_VAULT_PASSPHRASE cleared after first read ---

    #[test]
    fn env_var_removed_after_open_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-test-passphrase") };

        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();

        let _vault = Vault::open_from_config(&config).expect("open vault");

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after open_from_config"
        );
    }

    #[test]
    fn env_var_removed_after_resolve_passphrase_no_provision() {
        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-no-provision") };

        let result = resolve_passphrase_no_provision("svc", "acct");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("sec14-no-provision".to_string()));

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent after resolve_passphrase_no_provision"
        );
    }

    // --- security check: macOS user-presence gate routing ---
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
        assert!(crate::vault_macos::apply_user_presence(
            DEFAULT_KEYRING_SERVICE,
            DEFAULT_KEYRING_SERVICE
        ));
        assert!(!crate::vault_macos::apply_user_presence(
            "ember-daemon-qa",
            DEFAULT_KEYRING_SERVICE
        ));
        assert!(!crate::vault_macos::apply_user_presence(
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
            !crate::vault_macos::apply_user_presence(
                "ember-daemon-qa",
                DEFAULT_KEYRING_SERVICE
            ),
            "qember.sh QA service must NOT trigger the user-presence gate \
             (would break demo flows)"
        );
    }

    // --- security check: salt file permissions ---

    #[cfg(unix)]
    #[test]
    fn salt_file_created_with_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: test-only, single-threaded.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec17-perms-test") };

        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();

        // vault_salt is called internally by open_from_config; this triggers the
        // salt-file creation path.
        let _vault = Vault::open_from_config(&config).expect("open vault for sec17");

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
}

#[cfg(test)]
mod name_validation_tests {
    use super::*;

    #[test]
    fn accepts_canonical_names() {
        for name in [
            "gh-token",
            "cloudflare/zone/abc",
            "cloudflare/account-c5/api-token",
            "x",
            "long-name-here",
        ] {
            assert!(
                validate_credential_name(name).is_ok(),
                "rejected canonical: {name}"
            );
        }
    }

    #[test]
    fn rejects_uppercase() {
        assert!(validate_credential_name("GH-Token").is_err());
        assert!(validate_credential_name("github/Foo").is_err());
    }

    #[test]
    fn rejects_underscores_dots_spaces() {
        for bad in ["foo_bar", "foo.bar", "foo bar", "foo@bar"] {
            assert!(
                validate_credential_name(bad).is_err(),
                "accepted bad: {bad}"
            );
        }
    }

    #[test]
    fn rejects_leading_hyphen_or_slash() {
        assert!(validate_credential_name("-foo").is_err());
        assert!(validate_credential_name("/foo").is_err());
    }

    #[test]
    fn rejects_empty_segments() {
        assert!(validate_credential_name("foo//bar").is_err());
        assert!(validate_credential_name("foo/").is_err());
    }

    #[test]
    fn rejects_too_deep() {
        assert!(validate_credential_name("a/b/c/d/e").is_err());
    }

    #[test]
    fn accepts_max_depth() {
        assert!(validate_credential_name("a/b/c/d").is_ok());
    }

    #[test]
    fn rejects_too_long() {
        assert!(validate_credential_name(&"a".repeat(129)).is_err());
    }

    // --- .A VaultKeyStore tests ---

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
        // against accidental rename/removal during .A-SE-WIRE follow-up.
        let key_store = VaultKeyStore::EnvPassphrase;
        match key_store {
            VaultKeyStore::EnvPassphrase => {}
            _ => panic!("expected EnvPassphrase variant"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn vault_key_store_secure_enclave_returns_not_implemented() {
        // The SecureEnclave variant is a stub for .A-SE-WIRE; it must
        // return a clear "not yet implemented" error pointing at the
        // follow-up task so callers know which lane to use today.
        let tmp = tempfile::tempdir().unwrap();
        let mut config = DaemonConfig::default();
        config.data_dir = tmp.path().to_path_buf();

        let key_store = VaultKeyStore::SecureEnclave(SEWrappedKey {
            key_label: "ember-vault-mek-stub".to_string(),
        });

        let result = Vault::open_with_key_store(&config, &key_store);
        match result {
            Err(VaultError::Crypto(msg)) => {
                assert!(
                    msg.contains("not yet implemented"),
                    "expected 'not yet implemented' message, got: {msg}"
                );
                assert!(
                    msg.contains(".A-SE-WIRE"),
                    "expected pointer to follow-up task .A-SE-WIRE, got: {msg}"
                );
            }
            Err(other) => panic!("expected Crypto error from SE stub, got: {other}"),
            Ok(_) => panic!("expected Err from SE stub, got Ok(_)"),
        }
    }

    #[test]
    fn argon2_salt_round_trips_bytes() {
        let bytes: [u8; 16] = [7u8; 16];
        let salt = Argon2Salt::from(bytes);
        assert_eq!(salt.as_bytes(), &bytes);
    }
}
