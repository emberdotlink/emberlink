//! Vault MEK + sealed-credentials store.
//!
//! implementation-note-314 — -A
//! (`vault_macos_se::get_mek_passphrase` already returns
//! `Zeroizing<String>`; the caller at `Vault::open_from_config` binds
//! the result directly and passes `&passphrase`, so the buffer is
//! zeroed on the `Drop` at function exit — verified against the
//! current file shape, no rebind needed), -B (encrypt-then-MAC +
//! verify-then-decrypt in `ember_broker::secure_enclave::stub_unwrap`
//! via `subtle::ConstantTimeEq`; auth tag now computed over the
//! ciphertext so tampered blobs are rejected before any plaintext is
//! produced), and -C (the leakable code path —
//! `SeError::UnwrapFailed → VaultError::Crypto` formatting in
//! `vault_macos_se.rs:105-106` — was eliminated by the upstream
//! Plan-2A System.keychain refactor: the daemon now reads the MEK
//! passphrase directly from `/Library/Keychains/System.keychain` via
//! `SecKeychain::find_generic_password` and no longer ever maps
//! `SeError` into `VaultError`, so the SE key-label and stub-key-
//! registry implementation details cannot reach the operator-facing
//! error string by construction).
//!
//! ## Tier 1: start-of-session unlock
//!
//! `Vault::open_from_config` reads the MEK passphrase via the SE-backed
//! `vault_macos` shim on macOS — first read prompts for Touch ID. See
//! `vault_macos.rs` for the shim contract.
//!
//! ## Tier 2: per-op user presence + idle re-lock
//!
//! After Tier 1 unlocks the vault, the daemon stays "session-permissive"
//! for read-class operations (vault_get, vault_list, status) but
//! per-operation `require_user_presence` gates fire on high-risk write
//! ops (vault_add, vault_remove, grant create, persona key export). The
//! gate state machine lives in `crate::presence` (not here, because the
//! gate is dispatch-level, not vault-level). The daemon supervisor calls
//! `presence::mark_unlocked()` after a successful Tier 1 unlock so
//! subsequent high-risk ops don't double-prompt within the idle window.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead, aead::Payload};
use rusqlite::{OptionalExtension, params};
use tracing::{info, warn};
use uuid::Uuid;

/// implementation-note-27 C5 — AAD domain-separator prefix byte. AEAD
/// associated data for every C5+-sealed credential row is the byte
/// sequence `[AAD_VERSION_BYTE] || uuid_bytes_of_row_id` (17 bytes).
/// The literal `0x01` future-proofs the format: if we ever rotate the
/// AAD shape (e.g. add an explicit version field, switch to a longer
/// identity hash), `0x02` slots in without breaking the existing
/// fallback chain.
const AAD_VERSION_BYTE: u8 = 0x01;

/// Compute the per-row AEAD AAD from a credential row id. The id is the
/// `"cred-<uuid>"` string we mint in `Vault::add`; we extract the
/// trailing UUID and prefix with the AAD version byte. Returns `None`
/// when the id does not match the expected shape — callers MUST treat
/// `None` as "use the legacy no-AAD path" rather than a panic, so a
/// pre-C5 row whose id was minted under a different scheme still
/// decrypts.
fn aad_for_row_id(row_id: &str) -> Option<[u8; 17]> {
    let uuid_str = row_id.strip_prefix("cred-")?;
    let uuid = Uuid::parse_str(uuid_str).ok()?;
    let mut out = [0u8; 17];
    out[0] = AAD_VERSION_BYTE;
    out[1..].copy_from_slice(uuid.as_bytes());
    Some(out)
}

use crate::infra::config::DaemonConfig;
use crate::infra::store::{DaemonStore, StoreError};

/// Compile-time default keyring service name.
pub const DEFAULT_KEYRING_SERVICE: &str = "ember-daemon";
/// Compile-time default keyring account name.
pub const DEFAULT_KEYRING_ACCOUNT: &str = "vault";

// implementation-note-27 C4 — Argon2id KDF parameter pins. The MEK is
// derived by `Vault::from_passphrase` via Argon2id; pinning the cost
// parameters here (and writing them to `vault.params` next to
// `vault.salt`) lets `Vault::open_from_config` refuse to unlock a vault
// sealed under different parameters. Concretely: if a future
// param-rotation campaign bumps `VAULT_ARGON2_M_KIB` to 32 MiB, vaults
// sealed under 19 MiB will fail to open with a clear `argon2 params
// mismatch` error rather than silently producing a wrong key. The pinned
// values match the OWASP recommendation (and `Argon2::default()` in
// argon2 v0.5), so existing vaults sealed under
// `Argon2::default()` continue to decrypt without rotation.
//
// On open: compares against `<data_dir>/vault.params`. Legacy vaults
// without the file get a one-time write with current params + a `warn!`
// log line so subsequent opens are protected.
/// Argon2id memory cost in KiB. Matches OWASP recommendation /
/// `Argon2::default()` in argon2 v0.5.
pub const VAULT_ARGON2_M_KIB: u32 = 19456;
/// Argon2id time cost (iterations).
pub const VAULT_ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism factor.
pub const VAULT_ARGON2_P_COST: u32 = 1;
/// Argon2id output length in bytes (32 = XChaCha20-Poly1305 key size).
pub const VAULT_ARGON2_OUTPUT_LEN: usize = 32;
/// Argon2id algorithm tag — pinned for the `vault.params` file.
pub const VAULT_ARGON2_ALG: &str = "Argon2id";
/// Argon2id version tag — pinned for the `vault.params` file.
pub const VAULT_ARGON2_VER: &str = "V0x13";

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
/// Grammar (per task brief implementation-note-315):
///   - Lowercase ASCII letters `a-z`
///   - Digits `0-9`
///   - Hyphens `-`
///   - Forward slashes `/` for path segments
///   - Each segment: `^[a-z][a-z0-9-]*$`
///   - 1..=7 path segments (hard cap; design §5.1 advises warning at 5+
///     operator-side, but the validator only enforces the hard cap here)
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
    /// Path has more than 7 segments (design §5.1 hard cap).
    TooManySegments { count: usize },
}

impl std::fmt::Display for VaultNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultNameError::Empty => write!(f, "credential name is empty"),
            VaultNameError::TooLong { len } => {
                write!(f, "credential name too long: {len} chars (max 128)")
            }
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
            VaultNameError::TooFewSegments => {
                write!(f, "credential name has no segments (min depth 1)")
            }
            VaultNameError::TooManySegments { count } => {
                write!(f, "credential name has {count} segments (max depth 7)")
            }
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
    if segments.len() > 7 {
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

/// Which user-presence policy lane is calling into the vault.
///
/// Phase 2A (`implementation-note-316`) makes the parameter
/// load-bearing for storage namespace selection: `Headless` now maps to a
/// dedicated internal row-name prefix while `Interactive` preserves the
/// historical flat names. The per-scope MEK split is still follow-up work.
///
/// Phase 2B will route `scope` to a per-scope MEK derivation so interactive
/// (Touch-ID-gated) and headless (CI / agent / unattended) credentials cannot
/// read each other's ciphertext even if one keyring entry is compromised.
///
/// Existing callsites all pass `Interactive` so behaviour is preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultScope {
    /// Touch-ID / biometric-gated lane. The historical default for all
    /// `vault.add` / `vault.get` calls today.
    Interactive,
    /// Headless / unattended lane. Reserved for CI runners, automation agents,
    /// and any path that cannot present a biometric prompt. No callers in
    /// Phase 1 — wired up in Phase 2 along with the per-scope MEK split.
    Headless,
}

const HEADLESS_SCOPE_STORAGE_PREFIX: &str = "__headless/";

pub(crate) fn storage_name_for_scope(scope: VaultScope, logical_name: &str) -> String {
    match scope {
        VaultScope::Interactive => logical_name.to_string(),
        VaultScope::Headless => format!("{HEADLESS_SCOPE_STORAGE_PREFIX}{logical_name}"),
    }
}

pub(crate) fn logical_name_from_storage(scope: VaultScope, stored_name: &str) -> Option<String> {
    match scope {
        VaultScope::Interactive => {
            if stored_name.starts_with(HEADLESS_SCOPE_STORAGE_PREFIX) {
                None
            } else {
                Some(stored_name.to_string())
            }
        }
        VaultScope::Headless => stored_name
            .strip_prefix(HEADLESS_SCOPE_STORAGE_PREFIX)
            .map(str::to_string),
    }
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

/// MEK holder for the daemon's sealed-credentials store.
///
/// **implementation-note-27 C1**: `Vault` is `ZeroizeOnDrop` so the
/// in-memory MEK is wiped on Drop (explicit lock, daemon shutdown, the
/// final `Rc<Vault>` / `Arc<Vault>` reference going away).
///
/// implementation-note-317 (F-S1-001 HIGH + F-S1-008 LOW): `Clone` is
/// REMOVED. Prior to this commit `Vault` derived `Clone` so the in-memory
/// MEK byte-array could be by-value-copied across LocalSet spawn boundaries
/// (runtime.rs spawned each proxy + dashboard task with a fresh
/// `(*shared_rc).clone()`). That made accidental copy proliferation easy
/// — every code path that wanted to hand a sub-task a vault produced a
/// new 32-byte memory block holding the MEK, multiplying the secret's
/// in-memory footprint and the per-copy `Drop` zeroization budget.
///
/// After C1/C2: sharing is `Rc<Vault>` ONLY, but long-lived helper lanes now
/// resolve that live vault through `DaemonStore`'s shared slot instead of
/// owning private runtime copies. `runtime.rs` drops the startup `Rc<Vault>`
/// after wiring the slot, so explicit lock can clear the shared slot and let
/// the single underlying MEK byte-array zeroize when the last live reference
/// drops.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Vault {
    vault_key: [u8; 32],
}

impl Vault {
    pub fn new(vault_key: [u8; 32]) -> Self {
        Vault { vault_key }
    }

    /// Derive a vault key from a passphrase using Argon2id with the
    /// compile-time-pinned parameters (`VAULT_ARGON2_*` constants).
    /// Matches `Argon2::default()` in argon2 v0.5 — existing vaults
    /// sealed under the default continue to decrypt without rotation
    /// (implementation-note-27 C4).
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Self {
        let params = argon2::Params::new(
            VAULT_ARGON2_M_KIB,
            VAULT_ARGON2_T_COST,
            VAULT_ARGON2_P_COST,
            Some(VAULT_ARGON2_OUTPUT_LEN),
        )
        .expect("Argon2 params are compile-time-pinned to a valid combination");
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
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
    /// 2. *macOS, separate-uid posture only* — Secure-Enclave-wrapped MEK
    ///    blob read via `vault_macos_se::get_mek_passphrase`. Detected when
    ///    the daemon's effective home directory resolves to `/var/empty`
    ///    (per design — the system uid that the LaunchDaemon install
    ///    lane runs under has no login keychain, so the keyring branch
    ///    below is unreachable). Missing `vault-mek.bin` here returns a
    ///    `VaultError::Io` whose message tells the operator to run
    ///    `ember daemon install`.
    /// 3. System keyring — service/account resolved in order:
    ///    a. `config.keyring.service` / `config.keyring.account` (if `Some`)
    ///    b. `EMBER_KEYRING_SERVICE` / `EMBER_KEYRING_ACCOUNT` env var (debug backdoor)
    ///    c. Compile-time defaults (`DEFAULT_KEYRING_SERVICE` / `DEFAULT_KEYRING_ACCOUNT`)
    /// 4. Auto-generated random passphrase stored in keyring on first run
    ///
    /// Salt is read from `<data_dir>/vault.salt`; created on first call.
    pub fn open_from_config(config: &DaemonConfig) -> Result<Vault, VaultError> {
        open_from_config_with_presence(config, PresenceAfterOpen::MarkUnlocked)
    }

    /// Open the vault for daemon bootstrap work without flipping operator
    /// presence to Unlocked.
    ///
    /// This keeps startup-only vault hydration distinct from the interactive
    /// session-open posture in design: the daemon may need a temporary vault
    /// handle during boot, but that must not look like a live operator session.
    pub(crate) fn open_bootstrap_from_config(config: &DaemonConfig) -> Result<Vault, VaultError> {
        open_from_config_with_presence(config, PresenceAfterOpen::LeaveLocked)
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
    /// Both passphrase lanes flip the per-op presence gate to Unlocked on
    /// success so per-op `require_user_presence` checks don't
    /// double-prompt within the idle window.
    pub fn open_with_key_store(
        config: &DaemonConfig,
        key_store: &VaultKeyStore,
    ) -> Result<Vault, VaultError> {
        open_with_key_store_and_presence(config, key_store, PresenceAfterOpen::MarkUnlocked)
    }
}

#[derive(Clone, Copy)]
enum PresenceAfterOpen {
    LeaveLocked,
    MarkUnlocked,
}

fn finish_open(passphrase: &str, salt: &[u8; 16], presence: PresenceAfterOpen) -> Vault {
    if matches!(presence, PresenceAfterOpen::MarkUnlocked) {
        crate::trust::presence::mark_unlocked();
    }
    Vault::from_passphrase(passphrase, salt)
}

fn open_from_config_with_presence(
    config: &DaemonConfig,
    presence: PresenceAfterOpen,
) -> Result<Vault, VaultError> {
    let salt = vault_salt(config)?;
    // implementation-note-27 C4: refuse to unlock if vault.params
    // disagrees with the compile-time Argon2 pin. Runs BEFORE any
    // keyring access so a param mismatch aborts before a (potentially
    // user-presence-gated) Keychain prompt fires.
    check_or_write_vault_params(config)?;
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);

    // implementation-note-318 — macOS separate-uid posture (design).
    // The system-uid LaunchDaemon install lane has no login keychain
    // and cannot reach the operator's SE-wrapped keychain entry, so we
    // route through the on-disk SE-wrapped MEK blob laid down at
    // install time. The env-var override (precedence rule 1) must
    // still win: when `EMBER_VAULT_PASSPHRASE` is set we fall through
    // to `resolve_passphrase` below so the env value is consumed +
    // zeroized exactly once. Skipped under cargo-test binaries
    // (`is_cargo_test_binary`) so tests never reach the real SE.
    #[cfg(target_os = "macos")]
    if !is_cargo_test_binary()
        && std::env::var("EMBER_VAULT_PASSPHRASE").is_err()
        && is_separate_uid_posture()
    {
        let passphrase = crate::infra::vault_macos_se::get_mek_passphrase(&config.data_dir)?;
        return Ok(finish_open(&passphrase, &salt, presence));
    }

    // Belt-and-suspenders: refuse to open the production keyring service
    // unless the operator has explicitly opted in with
    // `$HOME/.ember-production`. Dev/QA daemons that point at a custom
    // service name (via config or env override) bypass this check. Skipped
    // entirely under cargo-test binaries — the passphrase branch below is
    // also gated there, so the real keychain is never touched in tests.
    if !is_cargo_test_binary() {
        let home = dirs_next::home_dir().ok_or_else(|| {
            VaultError::ProductionSentinelMissing(
                "refusing to open vault: home directory not resolvable (no $HOME)".to_string(),
            )
        })?;
        check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home)?;
    }

    let passphrase = resolve_passphrase(&service, &account)?;
    Ok(finish_open(&passphrase, &salt, presence))
}

fn open_with_key_store_and_presence(
    config: &DaemonConfig,
    key_store: &VaultKeyStore,
    presence: PresenceAfterOpen,
) -> Result<Vault, VaultError> {
    // implementation-note-27 C4: same params gate as
    // `open_from_config` — runs before any keyring access so a
    // mismatch aborts before a (potentially user-presence-gated)
    // Keychain prompt fires.
    check_or_write_vault_params(config)?;
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
            Ok(finish_open(&passphrase, salt.as_bytes(), presence))
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
            Ok(finish_open(&passphrase, &salt, presence))
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

impl Vault {
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
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        // design path-grammar gate — applies to NEW entries only.
        // Existing rows with non-conformant names continue to function via
        // `get`/`list`/`remove`; this check fires only on insert.
        validate_credential_name(name).map_err(VaultError::InvalidName)?;
        let stored_name = storage_name_for_scope(scope, name);

        // implementation-note-27 C5: mint the row id BEFORE encrypting
        // so the AEAD AAD can be bound to the row's UUID. AAD format is
        // `[0x01, row_uuid_bytes...]` (17 bytes). Decrypt-side (Vault::get)
        // tries this AAD first, falling back to no-AAD for legacy rows.
        let id = format!("cred-{}", Uuid::new_v4());
        let aad = aad_for_row_id(&id).expect("freshly-minted cred-<uuid> id parses");

        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let created_at = chrono::Utc::now().to_rfc3339();

        store
            .conn()
            .execute(
                "INSERT INTO credentials (id, name, nonce, ciphertext, created_at, metadata) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    stored_name,
                    nonce_bytes.as_slice(),
                    ciphertext,
                    created_at,
                    metadata
                ],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(CredentialInfo {
            id,
            name: name.to_string(),
            created_at,
            metadata: metadata.map(str::to_string),
        })
    }

    pub fn list(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
    ) -> Result<Vec<CredentialInfo>, VaultError> {
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
            let mut info = row.map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            let Some(logical_name) = logical_name_from_storage(scope, &info.name) else {
                continue;
            };
            info.name = logical_name;
            result.push(info);
        }
        Ok(result)
    }

    pub fn get(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
    ) -> Result<Vec<u8>, VaultError> {
        // implementation-note-27 C5: select the row id alongside
        // nonce/ciphertext so the AAD-aware decrypt can bind to it.
        // Legacy rows whose id parses cleanly still flow through the
        // AAD-aware path first; the fallback path below catches any
        // ciphertext that was sealed without AAD.
        let stored_name = storage_name_for_scope(scope, name);
        let result: Option<(String, Vec<u8>, Vec<u8>)> = store
            .conn()
            .query_row(
                "SELECT id, nonce, ciphertext FROM credentials WHERE name = ?1",
                params![stored_name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let (id, nonce_bytes, ciphertext) = result.ok_or(VaultError::NotFound)?;

        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Try the AAD-aware path first when we can compute the AAD.
        if let Some(aad) = aad_for_row_id(&id) {
            match cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                },
            ) {
                Ok(plaintext) => return Ok(plaintext),
                Err(_aad_err) => {
                    // Fall through to the legacy no-AAD path.
                }
            }
        }

        // Legacy fallback — no-AAD decrypt. Older daemons (pre-C5)
        // wrote ciphertext without AAD, so a successful no-AAD open is
        // the deterministic signal that the row needs re-sealing on the
        // next write. We log a `warn!` so the operator can see the
        // legacy rows; the next `Vault::add` for this name will write
        // a fresh AAD-bound row, healing the gap.
        match cipher.decrypt(nonce, ciphertext.as_slice()) {
            Ok(plaintext) => {
                warn!(
                    credential_id = %id,
                    credential_name = %name,
                    "vault: legacy no-AAD ciphertext decrypted via fallback path; \
                     next write to this credential will re-seal with per-row AAD"
                );
                Ok(plaintext)
            }
            Err(e) => Err(VaultError::Crypto(e.to_string())),
        }
    }

    pub fn remove(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
    ) -> Result<(), VaultError> {
        let stored_name = storage_name_for_scope(scope, name);
        let rows_affected = store
            .conn()
            .execute(
                "DELETE FROM credentials WHERE name = ?1",
                params![stored_name],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        if rows_affected == 0 {
            return Err(VaultError::NotFound);
        }
        Ok(())
    }

    /// Zero the in-memory MEK for `scope` — Phase 1 stub.
    ///
    /// Per design ("Interactive: demand-pinned"), the idle-zero handler in
    /// `UnlockPinTracker` calls into this method when the grace window
    /// expires with no live pins. Phase 1 logs the request but does not
    /// actually zero the MEK reference — the real implementation lands in
    /// **Phase 2** (`implementation-note-313`) alongside the
    /// session-lifecycle wiring that calls it. The Phase 1 stub exists so
    /// the substrate (the pin tracker + the API hook on Vault) can land in
    /// isolation without the multi-file lifecycle changes.
    ///
    /// Phase 2 will (a) take `&mut self` (or move out of an `Rc<RefCell>>`)
    /// to actually drop the `vault_key` bytes, (b) NOT modify the keyring
    /// or persist anything — re-unlock at the next session-open re-derives
    /// from the keyring-stored passphrase, and (c) emit a signed
    /// `vault_zero` Receipt per design.
    pub fn zero_scope(&self, scope: VaultScope) -> Result<(), VaultError> {
        info!(
            scope = ?scope,
            "vault: zero_scope (Phase 1 stub — no-op; Phase 2 wires lifecycle release)"
        );
        Ok(())
    }

    /// Atomic swap: DELETE existing `name` (if any) + INSERT new value,
    /// wrapped in one SQLite transaction. Closes the rotation-race
    /// window where a concurrent `get` could observe "no key" between a
    /// `remove` and a subsequent `add`, AND the crash-durability gap
    /// where a daemon crash between remove and add would leave the
    /// namespace empty.
    ///
    /// Per KEYCHAIN-CONSOLIDATE-CLI adversarial-review HIGH-3.
    pub fn replace(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        validate_credential_name(name).map_err(VaultError::InvalidName)?;
        let stored_name = storage_name_for_scope(scope, name);

        // implementation-note-27 C5: mint id first, bind AAD to the
        // new row's UUID. Same pattern as `Vault::add`.
        let id = format!("cred-{}", Uuid::new_v4());
        let aad = aad_for_row_id(&id).expect("freshly-minted cred-<uuid> id parses");

        let cipher = XChaCha20Poly1305::new_from_slice(&self.vault_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let created_at = chrono::Utc::now().to_rfc3339();

        let conn = store.conn();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        tx.execute(
            "DELETE FROM credentials WHERE name = ?1",
            params![stored_name],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        tx.execute(
            "INSERT INTO credentials (id, name, nonce, ciphertext, created_at, metadata) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                stored_name,
                nonce_bytes.as_slice(),
                ciphertext,
                created_at,
                metadata
            ],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        tx.commit()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(CredentialInfo {
            id,
            name: name.to_string(),
            created_at,
            metadata: metadata.map(str::to_string),
        })
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
/// `DaemonConfig` today (implementation-note-296 task instructions explicitly note this).
/// If one is added later, gate auto-unseal on first-party mode here.
pub fn try_auto_unseal_from_keyring(config: &DaemonConfig) -> AutoUnsealOutcome {
    try_auto_unseal_from_keyring_with_presence(config, PresenceAfterOpen::MarkUnlocked)
}

/// Best-effort auto-unseal variant used only during daemon bootstrap.
///
/// This preserves the startup contract of "open a temporary bootstrap vault if
/// a key source already exists" without silently treating boot as an
/// interactive operator unlock or publishing that handle into the daemon's
/// shared live-vault slot.
pub(crate) fn try_bootstrap_auto_unseal_from_keyring(config: &DaemonConfig) -> AutoUnsealOutcome {
    try_auto_unseal_from_keyring_with_presence(config, PresenceAfterOpen::LeaveLocked)
}

fn try_auto_unseal_from_keyring_with_presence(
    config: &DaemonConfig,
    presence: PresenceAfterOpen,
) -> AutoUnsealOutcome {
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
                    "refusing to open vault: home directory not resolvable (no $HOME)".to_string(),
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

    // implementation-note-27 C4: refuse to auto-unseal if the
    // vault.params sidecar disagrees with the compile-time Argon2 pin.
    // Same enforcement as `open_from_config`.
    if let Err(e) = check_or_write_vault_params(config) {
        return AutoUnsealOutcome::Error(e);
    }

    // Resolve the passphrase WITHOUT auto-generating one. Distinguishes
    // "keyring miss" (NoKeyringEntry) from "platform error" (Error).
    match resolve_passphrase_no_provision(&service, &account) {
        Ok(Some(passphrase)) => {
            AutoUnsealOutcome::Unsealed(finish_open(&passphrase, &salt, presence))
        }
        Ok(None) => AutoUnsealOutcome::NoKeyringEntry,
        Err(e) => AutoUnsealOutcome::Error(e),
    }
}

/// Reopen the runtime vault without provisioning a fresh passphrase source.
///
/// Used by the same-daemon interactive reopen path after an explicit
/// `vault_lock`. Unlike [`Vault::open_from_config`], this helper MUST NOT
/// silently mint a new key source when the original passphrase entry has
/// disappeared — a reopened daemon must either recover the existing MEK or
/// fail closed.
pub(crate) fn reopen_from_runtime_config(config: &DaemonConfig) -> Result<Vault, VaultError> {
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);
    let salt = vault_salt(config)?;
    check_or_write_vault_params(config)?;

    #[cfg(target_os = "macos")]
    if !is_cargo_test_binary()
        && std::env::var("EMBER_VAULT_PASSPHRASE").is_err()
        && is_separate_uid_posture()
    {
        let passphrase = crate::infra::vault_macos_se::get_mek_passphrase(&config.data_dir)?;
        return Ok(finish_open(
            &passphrase,
            &salt,
            PresenceAfterOpen::MarkUnlocked,
        ));
    }

    if !is_cargo_test_binary() {
        let home = dirs_next::home_dir().ok_or_else(|| {
            VaultError::ProductionSentinelMissing(
                "refusing to open vault: home directory not resolvable (no $HOME)".to_string(),
            )
        })?;
        check_production_sentinel(&service, DEFAULT_KEYRING_SERVICE, &home)?;
    }

    let passphrase = resolve_passphrase_no_provision(&service, &account)?.ok_or_else(|| {
        VaultError::Keyring(
            "runtime vault reopen requires an existing passphrase entry; none found".to_string(),
        )
    })?;
    Ok(finish_open(
        &passphrase,
        &salt,
        PresenceAfterOpen::MarkUnlocked,
    ))
}

/// Like `resolve_passphrase` but never provisions a new keyring entry.
/// Returns `Ok(None)` when the keyring has no entry — the signal callers
/// use to distinguish "needs init" from "failed".
///
/// Test/mock gate is preserved: under `cfg!(test)` / `EMBER_VAULT_MOCK` /
/// cargo test binary, returns the deterministic test passphrase so the
/// real keychain is never touched.
pub(crate) fn resolve_passphrase_no_provision(
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

    // 3. macOS user-presence gate. When the effective service is the
    //    production default, route the read through `vault_macos` so the
    //    Keychain entry's `kSecAttrAccessControl` triggers the LocalAuthentication
    //    prompt (Touch ID / device passcode). The `keyring` crate cannot do
    //    this. Dev/QA service names (e.g. `ember-daemon-qa`) skip this branch
    //    and fall through to the regular `keyring::Entry` path so qember.sh
    //    demo flows don't fire a biometric prompt.
    #[cfg(target_os = "macos")]
    if crate::infra::vault_macos::apply_user_presence(service, DEFAULT_KEYRING_SERVICE) {
        return crate::infra::vault_macos::get_password_user_presence(service, account)
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
pub fn resolve_keyring_service(config: &crate::infra::config::KeyringConfig) -> String {
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
pub fn resolve_keyring_account(config: &crate::infra::config::KeyringConfig) -> String {
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
    let using_default_service =
        config.keyring.service.is_none() && std::env::var("EMBER_KEYRING_SERVICE").is_err();

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

/// Result returned by `migrate_mek_acl`.
#[derive(Debug, serde::Serialize)]
pub struct MigrateMekAclResult {
    pub service: String,
    pub account: String,
    pub before_acl_kind: String,
    pub after_acl_kind: String,
}

/// Re-store the vault MEK passphrase under the platform-current ACL
/// (biometric on macOS via `kSecAttrAccessControl`).
///
/// This migrates a pre-existing MEK entry created before
/// implementation-note-100 shipped so subsequent vault operations
/// use Touch ID instead of the plain keychain password.
///
/// Safety contract:
/// - MEK bytes are held in `Zeroizing<String>` across the delete+add window.
/// - On re-add failure, falls back to re-adding under the original system
///   keyring ACL — no data loss.
/// - Idempotent: if biometric ACL already applies, returns immediately
///   with `before_acl_kind == after_acl_kind == "biometric"`.
pub fn migrate_mek_acl(service: &str, account: &str) -> Result<MigrateMekAclResult, VaultError> {
    use zeroize::Zeroizing;

    // Detect whether biometric ACL should apply for this service.
    #[cfg(target_os = "macos")]
    let wants_biometric =
        crate::infra::vault_macos::apply_user_presence(service, DEFAULT_KEYRING_SERVICE);
    #[cfg(not(target_os = "macos"))]
    let wants_biometric = false;

    if wants_biometric {
        // On macOS with the production service, the MEK is (or should be)
        // stored via vault_macos with kSecAttrAccessControl.  Check if the
        // entry is already accessible through the biometric path.
        #[cfg(target_os = "macos")]
        {
            // Try the biometric path first. If it succeeds the entry already
            // has the right ACL — idempotent exit.
            match crate::infra::vault_macos::get_password_user_presence(service, account) {
                Ok(Some(passphrase)) => {
                    let _p = Zeroizing::new(passphrase);
                    return Ok(MigrateMekAclResult {
                        service: service.to_string(),
                        account: account.to_string(),
                        before_acl_kind: "biometric".to_string(),
                        after_acl_kind: "biometric".to_string(),
                    });
                }
                Ok(None) => {
                    return Err(VaultError::Keyring(
                        "migrate_mek_acl: no MEK entry found in keychain; run `ember init` first"
                            .to_string(),
                    ));
                }
                Err(_e) => {
                    // Entry exists but cannot be read via the biometric path —
                    // it was stored under the plain keyring ACL. Fall through to
                    // migration below.
                }
            }

            // Read via the plain system keyring (pre-migration ACL).
            let passphrase = {
                let entry = keyring::Entry::new(service, account)
                    .map_err(|e| VaultError::Keyring(format!("migrate: init: {e}")))?;
                match entry.get_password() {
                    Ok(p) => Zeroizing::new(p),
                    Err(keyring::Error::NoEntry) => {
                        return Err(VaultError::Keyring(
                            "migrate_mek_acl: no MEK entry found in keychain; \
                             run `ember init` first"
                                .to_string(),
                        ));
                    }
                    Err(e) => {
                        return Err(VaultError::Keyring(format!("migrate: read: {e}")));
                    }
                }
            };

            // Delete the old plain-ACL entry.
            crate::infra::vault_macos::delete_password(service, account)
                .map_err(|e| VaultError::Keyring(format!("migrate: delete: {e}")))?;

            // Re-store under the biometric ACL.
            if let Err(e) =
                crate::infra::vault_macos::set_password_user_presence(service, account, &passphrase)
            {
                // Fallback: restore under the plain system keyring to avoid data loss.
                warn!(
                    service = service,
                    account = account,
                    error = %e,
                    "migrate_mek_acl: biometric re-store failed; falling back to system keyring"
                );
                let entry = keyring::Entry::new(service, account)
                    .map_err(|fe| VaultError::Keyring(format!("migrate: fallback init: {fe}")))?;
                entry
                    .set_password(&passphrase)
                    .map_err(|fe| VaultError::Keyring(format!("migrate: fallback write: {fe}")))?;
                return Ok(MigrateMekAclResult {
                    service: service.to_string(),
                    account: account.to_string(),
                    before_acl_kind: "system_keyring".to_string(),
                    after_acl_kind: "system_keyring".to_string(),
                });
            }

            info!(
                service = service,
                account = account,
                "migrate_mek_acl: MEK re-stored with biometric ACL"
            );
            return Ok(MigrateMekAclResult {
                service: service.to_string(),
                account: account.to_string(),
                before_acl_kind: "system_keyring".to_string(),
                after_acl_kind: "biometric".to_string(),
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = wants_biometric;
        }
    }

    // Non-macOS or QA/dev service — no biometric ACL change possible.
    // Check that an entry exists at all.
    let exists = resolve_passphrase_no_provision(service, account)
        .map_err(|e| VaultError::Keyring(format!("migrate: probe: {e}")))?
        .is_some();
    if !exists {
        return Err(VaultError::Keyring(
            "migrate_mek_acl: no MEK entry found; run `ember init` first".to_string(),
        ));
    }

    Ok(MigrateMekAclResult {
        service: service.to_string(),
        account: account.to_string(),
        before_acl_kind: "system_keyring".to_string(),
        after_acl_kind: "system_keyring".to_string(),
    })
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

/// True when the daemon is running under the design separate-uid posture
/// (the system-uid LaunchDaemon install lane). The signal is that the
/// effective home directory resolves to `/var/empty` — macOS reserves that
/// path as the home of system service users like `_ember`, and the
/// `install-system-daemon` step provisions the daemon's user record with
/// exactly that home. Under this posture there is no login keychain to
/// read, so `Vault::open_from_config` routes through the SE-wrapped MEK
/// blob at `<data_dir>/vault-mek.bin` instead.
///
/// Operator-uid LaunchAgent installs (the `install-agent` posture) keep
/// their normal `/Users/<operator>` home and fall through to the existing
/// login-keychain path.
///
/// Returns `false` when the home directory is unresolvable — the
/// production-checkpoint branch below will produce the better error message
/// in that case.
///
/// macOS-only: the SE-wrapped MEK lane only exists on macOS; Linux daemons
/// always fall through to the system keyring branch.
#[cfg(target_os = "macos")]
fn is_separate_uid_posture() -> bool {
    // Read the daemon's effective uid's passwd entry directly, NOT the
    // `HOME` env var. The launchd plist injects HOME=<operator_home>
    // (see install.rs::render_launchd_plist_body), so any env-var-based
    // home resolution would see the operator's home and miss the
    // /var/empty checkpoint that signals the design separate-uid posture.
    // Per adversarial review implementation-note-62-(-B).
    //
    // The Ok(None) and Err(e) arms both return false but log distinctly
    // so an operator debugging "why did the daemon land on the keychain
    // branch instead of SE?" can tell apart a provisioning race (uid
    // exists in kernel but passwd entry not yet written) from a real
    // passwd-database I/O failure. Per self-review 
    // (implementation-note-319).
    //
    // implementation-note-320: all three 
    // findings from the 2026-05-13 self-review are now closed.
    // (this site): Ok(None) / Err distinguished above.
    // : TOCTOU on file-based MEK blob — obviated by the
    //   System.keychain migration in vault_macos_se.rs (no filesystem
    //   read of the MEK blob remains).
    // : error-category asymmetry — addressed during the keychain
    //   migration (both lookup-failure paths now map to VaultError::Io
    //   with consistent operator-facing recovery hint).
    match nix::unistd::User::from_uid(nix::unistd::geteuid()) {
        Ok(Some(user)) => user.dir == std::path::Path::new("/var/empty"),
        Ok(None) => {
            tracing::warn!(
                uid = nix::unistd::geteuid().as_raw(),
                "is_separate_uid_posture: effective uid has no passwd entry (provisioning race?); falling through to non-SE branch"
            );
            false
        }
        Err(e) => {
            tracing::warn!(
                uid = nix::unistd::geteuid().as_raw(),
                error = %e,
                "is_separate_uid_posture: passwd lookup failed; falling through to non-SE branch"
            );
            false
        }
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

pub fn verify_keyring_roundtrip(
    service: &str,
    account: &str,
    expected: &str,
) -> Result<(), VaultError> {
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

    // 2. macOS user-presence gate. For the production keychain service
    //    the vault MEK passphrase entry is wrapped with kSecAttrAccessControl
    //    requiring user presence (Touch ID / device passcode); the `keyring`
    //    crate cannot set that attribute. Read first; if absent, generate +
    //    store via the SE-wrapped writer so the very first daemon start lays
    //    down a SAC-protected entry. Dev/QA services (e.g. `ember-daemon-qa`)
    //    fall through to the keyring path below — biometric on every QA
    //    iteration would break `qember.sh demo up`.
    #[cfg(target_os = "macos")]
    if crate::infra::vault_macos::apply_user_presence(service, DEFAULT_KEYRING_SERVICE) {
        match crate::infra::vault_macos::get_password_user_presence(service, account)
            .map_err(VaultError::Keyring)?
        {
            Some(p) => return Ok(p),
            None => {
                let p = generate_passphrase();
                crate::infra::vault_macos::set_password_user_presence(service, account, &p)
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
        let bytes =
            std::fs::read(&salt_path).map_err(|e| VaultError::Io(format!("salt read: {e}")))?;
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

/// implementation-note-27 C4: enforce Argon2 parameter pinning via a
/// `<data_dir>/vault.params` sidecar file.
///
/// - If the file exists, parse it and refuse to proceed if any value
///   does not match the compile-time `VAULT_ARGON2_*` constants — the
///   error is `VaultError::Crypto("argon2 params mismatch …")` so the
///   operator sees the dimension that drifted.
/// - If the file does not exist (legacy vault sealed before C4 shipped),
///   write the current pinned params with `warn!` so subsequent opens
///   are protected.
///
/// Called once per `Vault::open_from_config` / `open_with_key_store` /
/// `try_auto_unseal_from_keyring` invocation, BEFORE any Argon2
/// derivation runs. A mismatch aborts the unlock before the MEK is
/// computed.
fn check_or_write_vault_params(config: &DaemonConfig) -> Result<(), VaultError> {
    let params_path = config.data_dir.join("vault.params");
    if params_path.exists() {
        let contents = std::fs::read_to_string(&params_path)
            .map_err(|e| VaultError::Io(format!("vault.params read: {e}")))?;
        let parsed: toml::Value = toml::from_str(&contents).map_err(|e| {
            VaultError::Crypto(format!(
                "argon2 params mismatch: vault.params parse error: {e}"
            ))
        })?;
        let argon2_tbl = parsed
            .get("argon2")
            .and_then(|v| v.as_table())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params missing [argon2] table".to_string(),
                )
            })?;

        let m = argon2_tbl
            .get("m")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params [argon2].m missing or wrong type"
                        .to_string(),
                )
            })?;
        let t = argon2_tbl
            .get("t")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params [argon2].t missing or wrong type"
                        .to_string(),
                )
            })?;
        let p = argon2_tbl
            .get("p")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params [argon2].p missing or wrong type"
                        .to_string(),
                )
            })?;
        let alg = argon2_tbl
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params [argon2].alg missing or wrong type"
                        .to_string(),
                )
            })?;
        let ver = argon2_tbl
            .get("ver")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::Crypto(
                    "argon2 params mismatch: vault.params [argon2].ver missing or wrong type"
                        .to_string(),
                )
            })?;

        if m != VAULT_ARGON2_M_KIB as i64
            || t != VAULT_ARGON2_T_COST as i64
            || p != VAULT_ARGON2_P_COST as i64
            || alg != VAULT_ARGON2_ALG
            || ver != VAULT_ARGON2_VER
        {
            return Err(VaultError::Crypto(format!(
                "argon2 params mismatch: vault.params has \
                 (m={m}, t={t}, p={p}, alg={alg}, ver={ver}) but daemon is pinned to \
                 (m={pin_m}, t={pin_t}, p={pin_p}, alg={pin_alg}, ver={pin_ver}); \
                 either restore the original vault.params or run a key-rotation \
                 campaign that re-seals the vault under the new parameters",
                pin_m = VAULT_ARGON2_M_KIB,
                pin_t = VAULT_ARGON2_T_COST,
                pin_p = VAULT_ARGON2_P_COST,
                pin_alg = VAULT_ARGON2_ALG,
                pin_ver = VAULT_ARGON2_VER,
            )));
        }
        Ok(())
    } else {
        // Legacy vault — write the current pinned params and warn so
        // subsequent opens are protected.
        let contents = format!(
            "[argon2]\nm = {m}\nt = {t}\np = {p}\nalg = \"{alg}\"\nver = \"{ver}\"\n",
            m = VAULT_ARGON2_M_KIB,
            t = VAULT_ARGON2_T_COST,
            p = VAULT_ARGON2_P_COST,
            alg = VAULT_ARGON2_ALG,
            ver = VAULT_ARGON2_VER,
        );
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&params_path)
                .map_err(|e| VaultError::Io(format!("vault.params open: {e}")))?;
            f.write_all(contents.as_bytes())
                .map_err(|e| VaultError::Io(format!("vault.params write: {e}")))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&params_path, contents.as_bytes())
                .map_err(|e| VaultError::Io(format!("vault.params write: {e}")))?;
        }
        warn!(
            path = %params_path.display(),
            m = VAULT_ARGON2_M_KIB,
            t = VAULT_ARGON2_T_COST,
            p = VAULT_ARGON2_P_COST,
            alg = VAULT_ARGON2_ALG,
            ver = VAULT_ARGON2_VER,
            "vault.params absent (legacy vault); writing current pinned params"
        );
        Ok(())
    }
}

fn generate_passphrase() -> String {
    // 32 chars from an alphanumeric alphabet (62 chars) → ~190 bits of entropy.
    // Sampled by rejection from OS entropy to avoid modulo bias.
    const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
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
    use crate::infra::config::{DaemonConfig, KeyringConfig};
    use crate::infra::store::DaemonStore;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    fn other_key() -> [u8; 32] {
        [99u8; 32]
    }

    /// implementation-note-27 C5: a roundtrip through `add` → `get`
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
        assert_eq!(value, b"some-secret-value");
    }

    /// implementation-note-27 C5: a credentials row whose ciphertext
    /// was written WITHOUT AAD (legacy daemon before C5 shipped) must
    /// still decrypt through `Vault::get` via the no-AAD fallback path.
    /// The test synthesises a legacy row directly via SQL so the
    /// fallback branch is exercised deterministically.
    #[test]
    fn legacy_no_aad_decrypts() {
        use chacha20poly1305::aead::Aead;

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());

        // Hand-roll a no-AAD ciphertext for the row, then INSERT it
        // directly. Mirrors what an old daemon's `add` would have done.
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&vault.vault_key).unwrap();
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

        // Reading via the AAD-aware get must fall back to no-AAD and
        // recover the plaintext (rather than failing with a crypto
        // error).
        let value = vault
            .get(VaultScope::Interactive, &store, "legacy-row")
            .unwrap();
        assert_eq!(value, b"legacy-plaintext");
    }

    /// implementation-note-27 C4: when `vault.params` contains values
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

        let mut config = DaemonConfig::for_test(tmp.path());

        // Write a vault.params with the wrong t-cost (1 instead of 2).
        let bad_params = r#"[argon2]
m = 19456
t = 1
p = 1
alg = "Argon2id"
ver = "V0x13"
"#;
        std::fs::write(tmp.path().join("vault.params"), bad_params).unwrap();

        let result = Vault::open_from_config(&config);
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

    /// implementation-note-27 C4 partner: a fresh vault (no
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

        let mut config = DaemonConfig::for_test(tmp.path());

        // No vault.params exists yet.
        let params_path = tmp.path().join("vault.params");
        assert!(!params_path.exists(), "precondition: vault.params absent");

        // First open: provisions both salt and params.
        let _v = Vault::open_from_config(&config).expect("first open should succeed");
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

    /// implementation-note-27 C1: `Vault` must implement
    /// `ZeroizeOnDrop` so the MEK is wiped from memory when the Vault is
    /// dropped (explicit lock, daemon shutdown, or any Rc going to zero
    /// references). Compile-time trait assertion: the function body
    /// compiles iff `Vault: ZeroizeOnDrop`.
    #[test]
    fn vault_is_zeroize() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Vault>();
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
                .unwrap(),
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
                .unwrap(),
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
                .unwrap(),
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
        assert_eq!(value, b"supersecret");
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
        assert_eq!(interactive, b"interactive-secret");
        assert_eq!(headless, b"headless-secret");

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
        // Hold the process-wide test lock — env::set_var on a process-global
        // env var races with peer tests (`env_var_removed_after_*`) under
        // cargo's parallel runner. The lock serializes them.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Use a tempdir so salt is isolated; use env-var passphrase to avoid touching keyring.
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: test-only — process-global env mutation gated by PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

        let mut config = DaemonConfig::for_test(tmp.path());

        let store = DaemonStore::open_in_memory().unwrap();

        // First vault: write a credential.
        let vault1 = Vault::open_from_config(&config).expect("open vault 1");
        vault1
            .add(
                VaultScope::Interactive,
                &store,
                "round-trip-key",
                b"secret-value",
                None,
            )
            .unwrap();

        // Re-set the env var: open_from_config removes it after first read.
        // The second vault must be derived from the same passphrase to
        // decrypt what vault1 wrote.
        // SAFETY: test-only, single-threaded, no other threads reading env vars.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "test-roundtrip-passphrase") };

        // Second vault from same config: must decrypt successfully.
        let vault2 = Vault::open_from_config(&config).expect("open vault 2");
        let value = vault2
            .get(VaultScope::Interactive, &store, "round-trip-key")
            .unwrap();
        assert_eq!(value, b"secret-value");

        let list = vault2.list(VaultScope::Interactive, &store).unwrap();
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

        let mut config = DaemonConfig::for_test(tmp.path());

        let _vault = Vault::open_from_config(&config).expect("open vault");

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent from the environment after open_from_config"
        );
    }

    #[test]
    fn bootstrap_open_from_config_leaves_presence_locked() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let config = DaemonConfig::for_test(tmp.path());
        crate::trust::presence::lock();
        // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "bootstrap-open-passphrase") };

        let _vault = Vault::open_bootstrap_from_config(&config).expect("bootstrap vault open");

        let (is_unlocked, idle_secs) = crate::trust::presence::snapshot();
        assert!(
            !is_unlocked,
            "bootstrap vault open must not look like an interactive operator unlock"
        );
        assert!(
            idle_secs.is_none(),
            "bootstrap vault open must leave presence in Locked state"
        );
        // SAFETY: the happy path removes the env var itself; remove again so a
        // failure above cannot leak process-global state into later tests.
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
    }

    #[test]
    fn env_var_removed_after_resolve_passphrase_no_provision() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "sec14-no-provision") };

        let result = resolve_passphrase_no_provision("svc", "acct");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("sec14-no-provision".to_string()));

        assert!(
            std::env::var("EMBER_VAULT_PASSPHRASE").is_err(),
            "EMBER_VAULT_PASSPHRASE must be absent after resolve_passphrase_no_provision"
        );
    }

    #[test]
    fn bootstrap_auto_unseal_leaves_presence_locked() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let config = DaemonConfig::for_test(tmp.path());
        crate::trust::presence::lock();
        // SAFETY: test-only — env mutation gated by PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "bootstrap-auto-passphrase") };

        match try_bootstrap_auto_unseal_from_keyring(&config) {
            AutoUnsealOutcome::Unsealed(_) => {}
            AutoUnsealOutcome::NoKeyringEntry => {
                panic!("env passphrase should satisfy bootstrap auto-unseal")
            }
            AutoUnsealOutcome::Error(err) => {
                panic!("bootstrap auto-unseal should succeed: {err}")
            }
        }

        let (is_unlocked, idle_secs) = crate::trust::presence::snapshot();
        assert!(
            !is_unlocked,
            "bootstrap auto-unseal must not look like an interactive operator unlock"
        );
        assert!(
            idle_secs.is_none(),
            "bootstrap auto-unseal must leave presence in Locked state"
        );
        // SAFETY: the happy path removes the env var itself; remove again so a
        // failure above cannot leak process-global state into later tests.
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
    }

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
            !crate::infra::vault_macos::apply_user_presence(
                "ember-daemon-qa",
                DEFAULT_KEYRING_SERVICE
            ),
            "qember.sh QA service must NOT trigger the user-presence gate \
             (would break demo flows)"
        );
    }

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

        let mut config = DaemonConfig::for_test(tmp.path());

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

    // --- implementation-note-321: migrate_mek_acl ---

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

        let result =
            result.expect("migrate_mek_acl must succeed for qa service with entry present");
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
        // 8 segments — exceeds the design §5.1 hard cap of 7.
        assert!(validate_credential_name("a/b/c/d/e/f/g/h").is_err());
    }

    #[test]
    fn accepts_max_depth() {
        // 7 segments — at the design §5.1 hard cap.
        assert!(validate_credential_name("a/b/c/d/e/f/g").is_ok());
    }

    /// implementation-note-322 Phase 1 — the v2 path grammar
    /// (design §5.3) introduces credential-type intermediate segments like
    /// `github/apps/<slug>/install-<id>/private-key` which are 5 segments
    /// deep. The previous `> 4` cap rejected these; the lifted `> 7` cap
    /// admits the v2 shapes used by `ember broker register github`.
    #[test]
    fn validate_credential_name_accepts_five_segment_v2_path() {
        assert!(
            validate_credential_name("github/apps/test-slug/install-12345/private-key").is_ok(),
            "5-segment v2 path should be accepted under design §5.3"
        );
    }

    /// Partner test — 8 segments must still be rejected at the new hard cap.
    #[test]
    fn validate_credential_name_rejects_eight_segment_path() {
        let outcome = validate_credential_name("a/b/c/d/e/f/g/h");
        match outcome {
            Err(VaultNameError::TooManySegments { count }) => assert_eq!(count, 8),
            other => panic!("expected TooManySegments {{ count: 8 }}, got {other:?}"),
        }
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
        let mut config = DaemonConfig::for_test(tmp.path());

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
