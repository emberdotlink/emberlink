//! Vault MEK + sealed-credentials store.
//!
//! The vault master-encryption-key (interactive_key) is a random 32-byte
//! key whose at-rest form is a **double-envelope** (ADR 216):
//!
//! - **Outer envelope**: SE ECIES — peeled by the CLI in the Aqua/501
//!   session domain where Secure Enclave operations succeed.
//! - **Inner envelope**: DWK symmetric XChaCha20-Poly1305 — peeled by the
//!   daemon at uid=450 via the `vault.de_unlock_complete` RPC.
//!
//! The former direct-SE unseal functions (`se_unseal_interactive`,
//! `try_se_unseal`, `se_unseal_with_presence`, `AutoUnsealOutcome`,
//! `try_auto_unseal_from_keyring`) were deleted in ADR 216 S4. See
//! `vault_macos_se.rs` for the SE wrap/unwrap primitives still used by
//! the CLI relay's outer-envelope operations.
//!
//! ## Per-op user presence + idle re-lock
//!
//! After the double-envelope unlock, the daemon stays "session-permissive"
//! for ordinary read-class operations (vault_get, vault_list, status), while
//! rows whose [`PresencePolicy`] is `PerAccessFresh` (formerly
//! `requires_biometric=1` before presence-policy unification) require
//! a fresh presence-Device proof on every read. Per-operation
//! `require_user_presence` gates fire on high-risk
//! write ops (vault_add, vault_remove, grant create, persona key export). The
//! gate state machine lives in `crate::presence` (not here, because the
//! gate is dispatch-level, not vault-level). The daemon supervisor calls
//! `presence::mark_unlocked()` after a successful double-envelope unlock
//! so subsequent high-risk ops don't double-prompt within the idle window.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead, aead::Payload};
use chrono::{DateTime, Utc};
use core_crypto::Signer;
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::{SignError, sign_receipt_v2};
use ed25519_dalek::VerifyingKey;
use once_cell::sync::Lazy;
use rusqlite::{OptionalExtension, params};
use std::cell::{Ref, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

/// AAD domain-separator prefix byte. AEAD
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

use crate::auth::presence_gate::PresencePolicy;
use crate::infra::config::DaemonConfig;
use crate::infra::store::{DaemonStore, StoreError};

/// Decrypted vault payload bytes. The heap allocation is scrubbed on drop.
pub type VaultPlaintext = Zeroizing<Vec<u8>>;

/// Compile-time default keyring service name.
pub const DEFAULT_KEYRING_SERVICE: &str = "ember-daemon";
/// Compile-time default keyring account name.
pub const DEFAULT_KEYRING_ACCOUNT: &str = "vault";

#[allow(clippy::type_complexity)]
static RUNTIME_REOPEN_PASSPHRASE_CACHE: Lazy<Mutex<HashMap<PathBuf, Zeroizing<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn remember_runtime_reopen_passphrase(data_dir: &Path, passphrase: &str) {
    let mut cache = RUNTIME_REOPEN_PASSPHRASE_CACHE
        .lock()
        .expect("runtime reopen passphrase cache poisoned");
    cache.insert(
        data_dir.to_path_buf(),
        Zeroizing::new(passphrase.to_string()),
    );
}

/// N6 (pre-release security review, 2026-06): returns the cached reopen
/// passphrase wrapped in [`Zeroizing<String>`] so the heap allocation
/// holding the secret zeroizes on drop. The cache itself stores entries as
/// `Zeroizing<String>`; previously this getter cloned the inner `String`
/// out of the wrapper on the return path, leaving an unzeroized heap copy
/// in the caller's stack frame for the lifetime of the use.
fn runtime_reopen_passphrase(data_dir: &Path) -> Option<Zeroizing<String>> {
    let cache = RUNTIME_REOPEN_PASSPHRASE_CACHE
        .lock()
        .expect("runtime reopen passphrase cache poisoned");
    cache
        .get(data_dir)
        .map(|value| Zeroizing::new((**value).clone()))
}

pub(crate) fn clear_runtime_reopen_passphrase_cache() {
    let mut cache = RUNTIME_REOPEN_PASSPHRASE_CACHE
        .lock()
        .expect("runtime reopen passphrase cache poisoned");
    cache.clear();
}

/// ADR 198 D6 — clear the operator-passphrase caches after a rotation that
/// CHANGED the passphrase (`change_passphrase` mode), so the next vault reopen
/// re-derives the MEK from the freshly-updated keychain rather than a stale
/// cached secret. Clears the runtime-reopen cache (all hosts) and, on macOS,
/// the Touch-ID session cache that short-circuits the keychain read. A `rekey`
/// keeps the same passphrase, so it does NOT need this (the cached passphrase
/// stays correct; only the DB salt changed, which reopen reads fresh).
pub(crate) fn clear_passphrase_caches() {
    clear_runtime_reopen_passphrase_cache();
    #[cfg(target_os = "macos")]
    crate::infra::vault_macos::clear_session_cache();
}

// Argon2id KDF parameter pins. The MEK is
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
    /// The credential row is marked per-entry biometric and this read did not
    /// arrive with a freshly verified presence-Device proof.
    PresenceRequired,
    Keyring(String),
    Io(String),
    /// Daemon was about to open the production keyring service without an
    /// opt-in checkpoint (`$HOME/.ember-production`). Refuses to proceed so that
    /// stray dev/QA daemon starts do not fire real keychain prompts.
    ProductionSentinelMissing(String),
    /// Credential name does not conform to the ADR 097/099 path grammar.
    /// Only fired by `vault_add` for NEW entries; existing non-conformant
    /// entries are grandfathered (per ADR 099 §5.4).
    InvalidName(VaultNameError),
    /// Sealed-blob parse/structural
    /// error: invalid argon2 parameters, malformed length fields, AEAD
    /// key-init failure, etc. `String` carries human-readable detail.
    SealedBlobInvalid(String),
    /// Sealed blob is shorter than the wire format requires. `need` is
    /// the cumulative byte offset the reader tried to advance to; `have`
    /// is the blob length.
    SealedBlobTruncated {
        need: usize,
        have: usize,
    },
    /// First 4 bytes of the sealed blob are not `b"EMVS"`. Returned as
    /// raw bytes so the caller can log the actual value without lossy
    /// UTF-8 conversion.
    SealedBlobBadMagic {
        got: [u8; 4],
    },
    /// Sealed-blob version is not the one this build knows how to read.
    SealedBlobUnknownVersion {
        got: u16,
    },
    /// kdf_id field is not a value this build recognises (currently
    /// only `0x01` = argon2id).
    SealedBlobUnknownKdf {
        got: u8,
    },
    /// aead_id field is not a value this build recognises (currently
    /// only `0x01` = XChaCha20-Poly1305).
    SealedBlobUnknownAead {
        got: u8,
    },
    /// The fingerprint embedded in the sealed blob (or recomputed from
    /// the recovered MEK) does not match the value the caller supplied.
    /// Indicates either operator error (wrong vault) or blob tampering.
    SealedBlobFingerprintMismatch {
        expected: String,
        actual: String,
    },
    /// AEAD authentication tag failed during sealed-blob import.
    /// Surfaces as a single variant rather than a free-form crypto
    /// message so callers can fingerprint the wrong-passphrase /
    /// tampered-ciphertext case explicitly.
    SealedBlobAeadFailure,
    /// Emission
    /// of an `IdentityRotationWitness` Receipt failed. Surfaces signing
    /// failures from `core_events::receipt::sign::sign_receipt_v2`
    /// (canonicalize, serialize, etc.) so callers can distinguish
    /// crypto-layer faults from store-layer faults when persistence
    /// would otherwise mask the underlying signer error.
    WitnessEmit(String),
    /// Scope/MEK split (B1) + adversarial review
    /// CRIT-1 fix (2026-05-22) — a caller invoked an Interactive-lane
    /// operation (`seal`, `open`, or `add`/`get`/`replace`/`list`/
    /// `remove` with `VaultScope::Interactive`) on a Vault that was
    /// constructed via `Vault::new_headless_only`. Production
    /// headless-runtime Vaults (built by `current_headless_vault` and
    /// `headless_enroll`) are headless-only by construction so the
    /// in-memory `interactive_key` is the all-zero checkpoint — any
    /// attempt to seal Interactive-scope ciphertext under it would
    /// produce known-key ciphertext, which is exactly what `can't`
    /// forbids.
    HeadlessOnly,
    /// ADR 206 §4 / ADR 211 — AuthorityBearing values may not be sealed or
    /// opened by a production MEK-backed vault. The live authority path must
    /// install a presence-unwrapped scope KEK (`KEK_s`) first.
    AuthorityBearingRequiresPresence,
    /// ADR 206 §4 / ADR 211 AC-4 — `rotate_mek` is a passphrase/MEK-rotation
    /// primitive: it snapshots the live Interactive key under the passphrase
    /// (`write_pre_rotation_snapshot`) and re-wraps every row onto a freshly
    /// derived MEK. On a presence-backed (`KEK_s`) vault that would leak the
    /// scope KEK into a passphrase-recoverable file AND downgrade AuthorityBearing
    /// custody to a MEK-reachable copy. Refused fail-closed; presence/`KEK_s`
    /// custody is re-keyed through the §4 presence lane, not this primitive.
    AuthorityCustodyRotationUnsupported,
}

/// Reasons a credential name fails the ADR 097/099 path grammar.
///
/// Grammar:
///   - Lowercase ASCII letters `a-z`
///   - Digits `0-9`
///   - Hyphens `-`
///   - Forward slashes `/` for path segments
///   - Each segment: `^[a-z][a-z0-9-]*$`
///   - 1..=7 path segments (hard cap; ADR 099 §5.1 advises warning at 5+
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
    /// Path has more than 7 segments (ADR 099 §5.1 hard cap).
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

/// Validate a credential name against the ADR 097/099 path grammar.
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
            VaultError::PresenceRequired => write!(
                f,
                "credential requires a fresh presence-Device signature before it can be read"
            ),
            VaultError::Keyring(s) => write!(f, "keyring error: {s}"),
            VaultError::Io(s) => write!(f, "io error: {s}"),
            VaultError::HeadlessOnly => write!(
                f,
                "vault is headless-only (constructed via new_headless_only); \
                 Interactive-lane operations refused"
            ),
            VaultError::AuthorityBearingRequiresPresence => write!(
                f,
                "AuthorityBearing values require a presence-unwrapped scope KEK \
                 (ADR 206 §4 / ADR 211); refusing the MEK-backed vault path"
            ),
            VaultError::AuthorityCustodyRotationUnsupported => write!(
                f,
                "MEK rotation is unsupported on a presence-backed (KEK_s) vault \
                 (ADR 206 §4 / ADR 211 AC-4): it would leak the scope KEK under \
                 the passphrase and downgrade AuthorityBearing custody to a MEK"
            ),
            VaultError::ProductionSentinelMissing(s) => write!(f, "{s}"),
            VaultError::InvalidName(e) => write!(f, "invalid credential name: {e}"),
            VaultError::SealedBlobInvalid(s) => write!(f, "sealed blob invalid: {s}"),
            VaultError::SealedBlobTruncated { need, have } => {
                write!(f, "sealed blob truncated: need {need} bytes, have {have}")
            }
            VaultError::SealedBlobBadMagic { got } => write!(
                f,
                "sealed blob bad magic: expected EMVS, got {:02x}{:02x}{:02x}{:02x}",
                got[0], got[1], got[2], got[3]
            ),
            VaultError::SealedBlobUnknownVersion { got } => {
                write!(f, "sealed blob unknown version: {got:#06x}")
            }
            VaultError::SealedBlobUnknownKdf { got } => {
                write!(f, "sealed blob unknown kdf_id: {got:#04x}")
            }
            VaultError::SealedBlobUnknownAead { got } => {
                write!(f, "sealed blob unknown aead_id: {got:#04x}")
            }
            VaultError::SealedBlobFingerprintMismatch { expected, actual } => write!(
                f,
                "sealed blob fingerprint mismatch: expected {expected}, got {actual}"
            ),
            VaultError::SealedBlobAeadFailure => {
                write!(
                    f,
                    "sealed blob AEAD authentication failed (wrong passphrase or tampered ciphertext)"
                )
            }
            VaultError::WitnessEmit(s) => write!(f, "identity rotation witness emit failed: {s}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

impl From<SignError> for VaultError {
    fn from(e: SignError) -> Self {
        VaultError::WitnessEmit(e.to_string())
    }
}

pub struct CredentialInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub metadata: Option<String>,
    /// Per-resource presence policy (ADR 206 vocabulary). `PerAccessFresh`
    /// closes the cached-unlock bypass surfaced by PR #6088. Replaces the
    /// prior `requires_biometric: bool` field per
    /// presence-policy unification.
    pub presence_policy: PresencePolicy,
    /// Custody-class of the row's value. Computed from the storage
    /// namespace at read time (`__headless/` prefix → `DaemonOperational`,
    /// no prefix → `AuthorityBearing`); exposed as a typed field on
    /// `CredentialInfo` so callers do not re-derive the routing from the
    /// raw name string.
    pub value_class: ValueClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultReadGate {
    CachedUnlockOnly,
    FreshPresence,
}

impl VaultReadGate {
    fn satisfies_fresh_presence(self) -> bool {
        matches!(self, VaultReadGate::FreshPresence)
    }
}

/// Which user-presence policy lane is calling into the vault.
///
/// Phase 2A (scope-split namespace) makes the parameter
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

impl VaultScope {
    /// ADR 198 D1 (scope+row-bound DEK-wrap AAD hardening) — the fixed
    /// scope-enum string folded into the DEK-wrap AAD. Binds a wrapped DEK
    /// to its scope cryptographically so an Interactive-wrapped DEK fails
    /// AEAD authentication when unwrapped as Headless EVEN IF the two MEKs
    /// happen to be equal (e.g. the bootstrap single-key Vault). This makes
    /// cross-scope confused-deputy defense rest on the AEAD tag, not solely
    /// on the MEK split. The strings are a stable wire format — never rename
    /// them without an AAD version bump (`.v2` → `.v3`).
    pub(crate) fn label(self) -> &'static [u8] {
        match self {
            VaultScope::Interactive => b"interactive",
            VaultScope::Headless => b"headless",
        }
    }
}

/// Classification of a sealed value's custody, so [`Vault::seal`]/[`Vault::open`]
/// route to the correct key **structurally** rather than by per-call-site
/// judgment (ADR 206 §4 / closure-pass finding #8).
///
/// This is the cross-platform home for the classification the macOS-gated §4
/// engine (`presence_seal`) also speaks — it re-exports this type so there is
/// exactly one vocabulary.
///
/// Routing (ADR 206 §4 sharpened design — the interactive key is re-sourced from
/// the presence-unwrapped scope KEK `KEK_s`):
/// - [`AuthorityBearing`](ValueClass::AuthorityBearing) → the **interactive**
///   key. On the §4 lane that key IS `KEK_s`, so sealing authority material is
///   presence-as-decryption. Refused on a headless-only / idle-zeroed vault
///   (no §4 key present) — there is NO autonomous-key fallback for authority.
/// - [`DaemonOperational`](ValueClass::DaemonOperational) → the **headless**
///   (autonomous) key, so daemon-operational data (the bridge-CA module key,
///   config, …) is never dragged into the presence-gated authority window.
///
/// ADR 211 §3 AC-3 (B1 guard rail): the attested-device / automation unlock
/// path holds only the headless key, so it can reach `DaemonOperational` (infra)
/// but NEVER `AuthorityBearing` (lease-key) material. Do NOT route authority into
/// the headless lane to "make it work without presence" — that is the exact
/// regression the `automation_unlock_decrypts_infra_only_never_lease_key` test
/// fails closed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueClass {
    /// Authority-bearing secret VALUE (persona/grant signing keys, …). MUST be
    /// sealed under the interactive (§4) key; the autonomous key may never be a
    /// recipient.
    AuthorityBearing,
    /// Daemon-operational data (bridge-CA module key, config, …). Sealed under
    /// the autonomous headless key — it is not authority-bearing and must stay
    /// available without a presence gesture. ADR 211 AC-3: automation/headless
    /// unlock may decrypt only this class, never AuthorityBearing lease-key material.
    DaemonOperational,
}

impl ValueClass {
    /// The [`VaultScope`] (and therefore the key) this value class routes to.
    pub(crate) fn scope(self) -> VaultScope {
        match self {
            ValueClass::AuthorityBearing => VaultScope::Interactive,
            ValueClass::DaemonOperational => VaultScope::Headless,
        }
    }

    /// Derive the [`ValueClass`] of an existing row from its on-disk
    /// storage name. Rows under the `__headless/` prefix are
    /// `DaemonOperational`; everything else is `AuthorityBearing`. The
    /// reverse of [`storage_name_for_scope`]. Used by row-shape APIs that
    /// want to expose a typed `value_class: ValueClass` on `CredentialInfo`
    /// rather than re-derive routing at every call site.
    pub(crate) fn from_stored_name(stored_name: &str) -> Self {
        if stored_name.starts_with(HEADLESS_SCOPE_STORAGE_PREFIX) {
            ValueClass::DaemonOperational
        } else {
            ValueClass::AuthorityBearing
        }
    }
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
/// Carries the SE key label and the opaque ECIES-wrapped blob of the
/// 32-byte interactive key. The daemon SE-unwraps the blob at runtime;
/// the raw key never persists.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct SEWrappedKey {
    /// Stable label for the SE-resident wrapping key in the DPK.
    pub key_label: String,
    /// Opaque SE-ECIES-wrapped blob of the 32-byte interactive key.
    pub blob: Vec<u8>,
}

/// Source of the vault MEK at unlock time.
///
/// Three lanes today:
/// - **`Passphrase`** — the established lane. Argon2id over the configured
///   passphrase; salt is carried inside the variant so callers don't have to
///   plumb it separately.
/// - **`SecureEnclave`** *(macOS only, stub)* — placeholder for the SE-wrapped
///   master-key lane. Currently returns `VaultError::Crypto("not yet
///   implemented; use Passphrase variant — see P63.A-SE-WIRE")` from
///   `Vault::open_with_key_store`. Shape is locked here so P63.B (presence
///   attestation) can build on it without the actual SE wiring landing yet.
/// - **`EnvPassphrase`** — the CI / headless escape hatch. The vault MEK is
///   derived from `$EMBER_VAULT_PASSPHRASE`. The salt still has to come from
///   somewhere — `Vault::open_with_key_store` resolves it from disk via
///   `vault_salt(&config)` at the call site.
///
/// A §4 scope KEK (ADR 206) already unwrapped by the operator-session presence
/// gesture (the cross-uid `se_unwrap` tap; the separate-uid daemon never touches
/// the presence-gated SE key itself). The daemon installs these raw bytes as the
/// vault's `interactive_key`, so authority-bearing material is reachable only
/// after a live tap. `Debug` is REDACTED so the KEK can never land in a log line
/// or an error chain.
#[derive(Clone)]
pub struct PresenceUnwrappedKek(pub Zeroizing<[u8; 32]>);

impl std::fmt::Debug for PresenceUnwrappedKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PresenceUnwrappedKek(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub enum VaultKeyStore {
    /// Passphrase-derived key (Argon2id over the env/configured passphrase).
    Passphrase(Argon2Salt),
    /// SE-wrapped master key. macOS only.
    #[cfg(target_os = "macos")]
    SecureEnclave(SEWrappedKey),
    /// ADR 206 §4 presence-as-decryption: the interactive key is the scope KEK
    /// unwrapped by the operator-session presence tap (cross-uid `se_unwrap`),
    /// supplied here already-unwrapped. Platform-agnostic at the vault layer (it
    /// is just a key install); the `se_unwrap` that produces it is macOS-gated in
    /// the operator-session CLI / unlock handoff.
    PresenceScopeKek(PresenceUnwrappedKek),
    /// Env passphrase escape hatch (CI/headless).
    EnvPassphrase,
}

/// MEK holder for the daemon's sealed-credentials store.
///
/// **MEK hardening (C1)**: `Vault` is `ZeroizeOnDrop` so the
/// in-memory MEK is wiped on Drop (explicit lock, daemon shutdown, the
/// final `Rc<Vault>` / `Arc<Vault>` reference going away).
///
/// MEK hardening (C1, F-S1-001 HIGH + F-S1-008 LOW): `Clone` is
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
/// On-disk filename (under `<data_dir>/`) carrying the AEAD-wrapped
/// Headless MEK. The blob is `[24-byte nonce || ciphertext-with-tag]`
/// encrypted under the Interactive MEK with AAD `b"vault.headless-mek.v1"`.
/// Generated lazily on first vault open per the scope/MEK split.
pub(crate) const HEADLESS_MEK_WRAP_FILE: &str = "vault.headless-mek.wrapped";

/// AEAD AAD for the disk-wrapped Headless MEK. Version-prefixed so a
/// future rotation can disambiguate cleanly.
const HEADLESS_MEK_WRAP_AAD: &[u8] = b"vault.headless-mek.v1";

/// ADR 198 D1 — fixed prefix for the per-row DEK-wrap AAD. The
/// credential-row Data Encryption Key is itself AEAD-wrapped under the
/// row's scope MEK using a scope+row-bound AAD. NOTE: this is the wrap of
/// the DEK, not the payload — the payload keeps the existing `[0x01||uuid]`
/// AAD (`aad_for_row_id`), now applied under the DEK rather than the MEK.
///
/// **v2 (scope+row-bound, 2026-05-29 security analysis).** The original
/// v1 used a CONSTANT AAD `b"vault.dek-wrap.v1"`, so cross-scope
/// confused-deputy defense rested entirely on the MEK split: if the two
/// scope MEKs were ever equal (the bootstrap single-key Vault, a future
/// misprovision), an Interactive-wrapped DEK would unwrap cleanly as
/// Headless. v2 folds the scope label AND the identifier into the AAD so the
/// AEAD tag itself rejects a cross-scope or cross-row unwrap. The framing is
/// LENGTH-PREFIXED and therefore canonically injective: a fixed prefix, then a
/// `u8` label-length + the scope label, then a `u32` id-length + the
/// identifier. Because every variable-width field is length-delimited, no two
/// distinct `(scope, id)` inputs can ever produce the same AAD bytes —
/// regardless of the identifier's width or content. (A separator-only framing
/// would be safe only by the accident that no label/id contains the separator
/// byte; the seal-blob ids are variable-width ASCII, not fixed-width, so the
/// length prefixes make injectivity structural rather than accidental — per
/// the S6a.2 adversarial-review hardening.) **There is no v1-accepting
/// fallback** (mirrors the no-no-AAD-fallback discipline on the payload seal):
/// the dev0 host has no enveloped vault yet, so there are no v1 rows to migrate.
const DEK_WRAP_AAD_PREFIX: &[u8] = b"vault.dek-wrap.v2:";

/// ADR 198 D1 — build the scope+row-bound DEK-wrap AAD, length-prefixed so it
/// is canonically injective:
/// `PREFIX || u8(label.len) || label || u32_le(id.len) || id_bytes`.
///
/// For credential rows `id_bytes` is the raw 16-byte UUID of the `cred-<uuid>`
/// row id (`cred_row_uuid_bytes`); for the daemon-internal `seal`/`open` blobs
/// (persona secrets, bridge-CA module key) it is a purpose-bound identifier
/// chosen by the caller (`seal_blob_aad_id`) — variable-width, which is exactly
/// why the length prefix (not a separator) is what guarantees no two distinct
/// `(scope, id)` inputs collide.
fn dek_wrap_aad(scope: VaultScope, id_bytes: &[u8]) -> Vec<u8> {
    let label = scope.label();
    debug_assert!(
        label.len() <= u8::MAX as usize,
        "scope label fits in u8 length prefix"
    );
    let mut aad =
        Vec::with_capacity(DEK_WRAP_AAD_PREFIX.len() + 1 + label.len() + 4 + id_bytes.len());
    aad.extend_from_slice(DEK_WRAP_AAD_PREFIX);
    aad.push(label.len() as u8);
    aad.extend_from_slice(label);
    aad.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    aad.extend_from_slice(id_bytes);
    aad
}

/// ADR 198 D1 — extract the raw 16-byte UUID from a `cred-<uuid>` row id
/// for use as the fixed-width identifier in the DEK-wrap AAD. Returns
/// `None` when the id is not a parseable `cred-<uuid>` (same shape gate as
/// `aad_for_row_id`); callers MUST treat `None` as a hard error rather than
/// silently dropping the row binding (an un-bound wrap would re-open the
/// cross-row splice the v2 AAD closes).
fn cred_row_uuid_bytes(row_id: &str) -> Option<[u8; 16]> {
    let uuid_str = row_id.strip_prefix("cred-")?;
    let uuid = Uuid::parse_str(uuid_str).ok()?;
    Some(*uuid.as_bytes())
}

/// ADR 198 D3 — fixed known plaintext sealed under the Interactive MEK
/// at vault provisioning and AEAD-verified on the fail-loud startup
/// path. A wrong MEK fails the canary's authentication tag, which is
/// the cryptographic key-correctness authority (the `mek_fingerprint`
/// string-compare is demoted to an advisory pre-flight). The canary is
/// stored in `vault_meta` so it works even with zero credential rows.
const VAULT_CANARY_PLAINTEXT: &[u8] = b"ember-vault-canary-v1";

/// ADR 198 D3 — AAD domain-separator for the canary seal.
const VAULT_CANARY_AAD: &[u8] = b"vault.canary.v1";

/// ADR 198 D1 — wrap a freshly-generated Data Encryption Key under a
/// scope MEK. Reuses the exact AEAD the headless-MEK wrap already uses
/// (XChaCha20-Poly1305, 24-byte nonce). The AAD is the scope+row-bound v2
/// AAD (`dek_wrap_aad`) so the wrap is cryptographically pinned to both the
/// `scope` and the per-row/per-blob `id_bytes`. Returns
/// `(dek_nonce, wrapped_dek)`. The nonce is fresh OS entropy per call —
/// never reused across wraps.
fn wrap_dek(
    mek: &[u8; 32],
    dek: &[u8; 32],
    scope: VaultScope,
    id_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(mek)
        .map_err(|e| VaultError::Crypto(format!("dek wrap cipher init: {e}")))?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).expect("OS entropy failure on dek wrap nonce");
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = dek_wrap_aad(scope, id_bytes);
    let wrapped = cipher
        .encrypt(
            nonce,
            Payload {
                msg: dek,
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("dek wrap: {e}")))?;
    Ok((nonce_bytes.to_vec(), wrapped))
}

/// ADR 198 D1 — unwrap a per-row Data Encryption Key under a scope MEK.
/// Pairs with [`wrap_dek`]. The `scope` + `id_bytes` MUST match the values
/// used at wrap time — a mismatch (wrong scope label or wrong row id) fails
/// the AEAD authentication tag, which is the cross-scope / cross-row
/// confused-deputy defense (no longer resting solely on the MEK split).
/// Returns the 32-byte DEK as `Zeroizing` so it is scrubbed on drop. A
/// wrong MEK or tampered wrap likewise fails the AEAD tag.
fn unwrap_dek(
    mek: &[u8; 32],
    dek_nonce: &[u8],
    wrapped_dek: &[u8],
    scope: VaultScope,
    id_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if dek_nonce.len() != 24 {
        return Err(VaultError::Crypto(format!(
            "invalid dek_nonce length: {} (expected 24)",
            dek_nonce.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(mek)
        .map_err(|e| VaultError::Crypto(format!("dek unwrap cipher init: {e}")))?;
    let nonce = XNonce::from_slice(dek_nonce);
    let aad = dek_wrap_aad(scope, id_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: wrapped_dek,
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("dek unwrap failed: {e}")))?;
    if plaintext.len() != 32 {
        return Err(VaultError::Crypto(format!(
            "dek unwrap produced {} bytes (expected 32)",
            plaintext.len()
        )));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&plaintext);
    let mut pt = plaintext;
    use zeroize::Zeroize as _;
    pt.zeroize();
    Ok(dek)
}

/// MEK holder for the daemon's sealed-credentials store.
///
/// **Scope/MEK split (B1, 2026-05-22)** — `Vault`
/// carries TWO 32-byte master keys, one per `VaultScope` lane:
/// - `interactive_key`: passphrase-derived (Argon2id) via the existing
///   keychain → vault.salt → MEK pipeline. Drives Interactive-scope
///   `add` / `get` / `replace` AND the daemon-internal `seal` / `open`
///   path used by persona-secret at-rest encryption (F-05).
/// - `headless_key`: cryptographically-independent 32 bytes drawn from
///   OS entropy at first vault open, AEAD-wrapped under
///   `interactive_key` and persisted to `<data_dir>/vault.headless-mek.wrapped`.
///   Loads at vault-open time; routes ALL Headless-scope `add` / `get` /
///   `replace`. An attacker who recovers the headless attested-device
///   wrap (per `attested_device.rs`) decrypts ONLY the Headless subset.
///
/// Test-only callers via `Vault::new` still get a flat single-key shape
/// (both fields set to the same byte array) — tests don't model the
/// cryptographic split. Production callers reach `Vault::new_split`
/// through `load_or_generate_headless_key` indirectly via `finish_open`.
///
/// MEK hardening (C1): `Vault` is `ZeroizeOnDrop` so both
/// in-memory MEK byte arrays are wiped on Drop (explicit lock, daemon
/// shutdown, the final `Rc<Vault>` / `Arc<Vault>` reference going away).
///
/// MEK hardening (C1, F-S1-001 HIGH + F-S1-008 LOW): `Clone` is
/// REMOVED. Prior to that commit `Vault` derived `Clone`; sharing is
/// `Rc<Vault>` ONLY, but long-lived helper lanes resolve the live vault
/// through `DaemonStore`'s shared slot instead of owning private runtime
/// copies. `runtime.rs` drops the startup `Rc<Vault>` after wiring the
/// slot, so explicit lock can clear the shared slot and let the
/// underlying MEK byte-arrays zeroize when the last live reference drops.
///
/// ADR 198 D6 (amendment 3) — INTERIOR MUTABILITY. The two MEK fields are
/// `RefCell<[u8; 32]>` rather than bare arrays so [`Vault::zero_scope`] can
/// actually wipe one scope's key bytes in place through the shared
/// `&Rc<Vault>` (the ADR 139 demand-pinned idle-zero, and the
/// session-invalidation D6 relies on). NO `Clone` (a `RefCell` is not
/// `Clone` here by design — the C1 no-MEK-copy invariant stands); the keys
/// are never copied out, only borrowed (`Ref`) for the lifetime of one
/// crypto op, so the interior mutability does not widen the in-memory
/// footprint of the secret. `ZeroizeOnDrop` is hand-implemented below (the
/// derive cannot see through `RefCell`) and wipes BOTH cells on Drop — the
/// same guarantee the prior `#[derive(ZeroizeOnDrop)]` gave.
pub struct Vault {
    interactive_key: RefCell<[u8; 32]>,
    headless_key: RefCell<[u8; 32]>,
    authority_key_source: AuthorityKeySource,
    keys_mlocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityKeySource {
    /// Test-only/in-memory constructor. It does not model hardware, but keeps
    /// legacy in-memory unit tests from depending on macOS presence plumbing.
    TestHarness,
    /// Legacy passphrase/keychain MEK. Production AuthorityBearing values must
    /// not route here after ADR 206 §4 / ADR 211.
    Mek,
    /// The interactive key is the operator-session-unwrapped `KEK_s`.
    PresenceScopeKek,
    /// No interactive authority key is installed.
    None,
}

impl Drop for Vault {
    fn drop(&mut self) {
        if self.keys_mlocked {
            unsafe {
                libc::munlock(
                    self.interactive_key.get_mut().as_ptr() as *const libc::c_void,
                    32,
                );
                libc::munlock(
                    self.headless_key.get_mut().as_ptr() as *const libc::c_void,
                    32,
                );
            }
        }
        use zeroize::Zeroize as _;
        self.interactive_key.get_mut().zeroize();
        self.headless_key.get_mut().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Vault {}

/// ADR 198 D5 — the three vault MEK-rotation modes. The wire strings match
/// [`core_events::receipt::VaultMekRotationBody`]'s `mode` field and the
/// `vault_rotate_execute` RPC `mode` param.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationMode {
    /// Same operator passphrase, new salt → new Interactive MEK.
    Rekey,
    /// New operator passphrase + new salt → new Interactive MEK.
    ChangePassphrase,
    /// Fresh random Headless MEK; Interactive MEK unchanged.
    RotateHeadless,
}

impl RotationMode {
    /// Stable wire string (matches the receipt body + RPC param).
    pub fn as_str(self) -> &'static str {
        match self {
            RotationMode::Rekey => "rekey",
            RotationMode::ChangePassphrase => "change_passphrase",
            RotationMode::RotateHeadless => "rotate_headless",
        }
    }

    /// Parse the wire string; `None` for an unknown mode.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rekey" => Some(RotationMode::Rekey),
            "change_passphrase" => Some(RotationMode::ChangePassphrase),
            "rotate_headless" => Some(RotationMode::RotateHeadless),
            _ => None,
        }
    }
}

/// ADR 198 D3/D7 — the result of a committed [`Vault::rotate_mek`]. Carries
/// the freshly-keyed `Vault` (the caller swaps it into the live slot via
/// `set_vault`), the audit facts for the `vault.mek_rotation` Receipt, and
/// the file sidecars to retire post-commit (now shadowed by the DB copies).
pub struct RotationOutcome {
    /// The new live `Vault` to swap into the shared slot (D6).
    pub new_vault: Vault,
    /// The mode that was rotated.
    pub mode: RotationMode,
    /// Count of wrapped DEKs re-wrapped under the new MEK (credentials +
    /// persona secrets in scope).
    pub rewrap_count: u64,
    /// `key_epoch` before / after the rotation (`new == prev + 1`).
    pub prev_key_epoch: i64,
    pub new_key_epoch: i64,
    /// blake3 advisory fingerprint of the rotated scope's MEK before / after.
    pub prev_scope_fingerprint: String,
    pub new_scope_fingerprint: String,
    /// Path to the pre-mutate EMVS snapshot (D4).
    pub snapshot_path: String,
    /// File sidecars now shadowed by the committed DB copies; the caller
    /// best-effort deletes these post-commit (DB-first reads make a lingering
    /// file harmless, so a delete failure is non-fatal).
    pub retired_files: Vec<std::path::PathBuf>,
}

impl Vault {
    /// Test-only / single-key constructor.
    ///
    /// Both `interactive_key` and `headless_key` are set to the same
    /// byte array — the cryptographic Interactive/Headless split is NOT
    /// enforced. Used by unit tests that don't model the split and by
    /// any in-tree caller that pre-dates the B1 cryptographic-split
    /// landing.
    ///
    /// Production paths (passphrase + keychain bootstrap) call
    /// `Vault::new_split` via `load_or_generate_headless_key` so the
    /// Headless MEK is cryptographically independent (32 bytes of fresh
    /// OS entropy, AEAD-wrapped to disk under the Interactive MEK).
    pub fn new(vault_key: [u8; 32]) -> Self {
        Vault {
            interactive_key: RefCell::new(vault_key),
            headless_key: RefCell::new(vault_key),
            authority_key_source: AuthorityKeySource::TestHarness,
            keys_mlocked: false,
        }
    }

    /// Two-key constructor for production callers and tests that DO
    /// model the cryptographic Interactive/Headless split.
    ///
    /// Per the scope/MEK split (B1): the two keys MUST
    /// be cryptographically independent — `interactive_key` is
    /// Argon2id-derived from the operator passphrase; `headless_key` is
    /// fresh OS entropy AEAD-wrapped under `interactive_key` and
    /// persisted to `<data_dir>/vault.headless-mek.wrapped` so it
    /// survives daemon restarts without being re-derivable from the
    /// passphrase.
    pub fn new_split(interactive_key: [u8; 32], headless_key: [u8; 32]) -> Self {
        Self::new_split_with_authority_source(
            interactive_key,
            headless_key,
            AuthorityKeySource::Mek,
        )
    }

    fn new_split_with_authority_source(
        interactive_key: [u8; 32],
        headless_key: [u8; 32],
        authority_key_source: AuthorityKeySource,
    ) -> Self {
        let mut v = Vault {
            interactive_key: RefCell::new(interactive_key),
            headless_key: RefCell::new(headless_key),
            authority_key_source,
            keys_mlocked: false,
        };
        v.keys_mlocked = v.mlock_keys();
        v
    }

    /// Scope/MEK split (B1) + adversarial review
    /// CRIT-1 fix (2026-05-22) — headless-only constructor.
    ///
    /// Sets `interactive_key` to an all-zero checkpoint and
    /// `headless_key` to the supplied MEK. Used by the production
    /// headless-runtime callers — `current_headless_vault` (the
    /// credential-broker read path) and `headless_enroll` (the
    /// re-encryption write path) — so the in-memory `Vault` they hold
    /// is STRUCTURALLY incapable of producing Interactive-lane
    /// ciphertext. Any `add` / `get` / `replace` / `seal` / `open`
    /// call that would route through `interactive_key` refuses with
    /// `VaultError::HeadlessOnly` at runtime; the type-level boundary
    /// the PR docstrings advertised pre-fix was an in-memory single-
    /// key Vault that happened to be used only on Headless scope by
    /// convention. Now it is `can't > won't`.
    ///
    /// The all-zero checkpoint is detected by `is_headless_only()`. A
    /// hypothetical attacker-controlled MEK value of all zeros would
    /// be detected as headless-only and refuse Interactive ops — that
    /// shape is also untrustworthy as a real MEK (Argon2id never
    /// produces zero output under any non-degenerate inputs) so the
    /// false-positive risk is acceptable.
    pub fn new_headless_only(headless_key: [u8; 32]) -> Self {
        let mut v = Vault {
            interactive_key: RefCell::new([0u8; 32]),
            headless_key: RefCell::new(headless_key),
            authority_key_source: AuthorityKeySource::None,
            keys_mlocked: false,
        };
        v.keys_mlocked = v.mlock_keys();
        v
    }

    /// Scope/MEK split (B1) — true iff this Vault
    /// was constructed via [`Vault::new_headless_only`] (or any other
    /// path that left `interactive_key` as the all-zero checkpoint).
    ///
    /// ADR 198 D6 — also true after [`Vault::zero_scope`] wipes the
    /// Interactive key: a zeroed Interactive scope is, by construction, the
    /// all-zero checkpoint, so every Interactive op (`add`/`get`/`replace`/
    /// `seal`/`open`) refuses with `VaultError::HeadlessOnly` exactly as it
    /// would for a headless-only Vault. That is the intended post-idle-zero
    /// posture — the wipe demotes the live vault to headless-only.
    /// Internal-only.
    fn is_headless_only(&self) -> bool {
        self.interactive_key.borrow().iter().all(|b| *b == 0)
    }

    fn ensure_authority_bearing_source(&self) -> Result<(), VaultError> {
        match self.authority_key_source {
            AuthorityKeySource::PresenceScopeKek | AuthorityKeySource::TestHarness => Ok(()),
            AuthorityKeySource::Mek => Err(VaultError::AuthorityBearingRequiresPresence),
            AuthorityKeySource::None => Err(VaultError::HeadlessOnly),
        }
    }

    /// Derive an Interactive vault key from a passphrase using Argon2id
    /// with the compile-time-pinned parameters (`VAULT_ARGON2_*`
    /// constants). Matches `Argon2::default()` in argon2 v0.5 — existing
    /// vaults sealed under the default continue to decrypt without
    /// rotation (MEK hardening C4).
    ///
    /// Returns a single-key Vault (both Interactive and Headless lanes
    /// share the derived bytes). Production callers should instead
    /// derive the Interactive key, then load-or-generate the Headless
    /// key via `load_or_generate_headless_key`, and assemble a real
    /// split via `Vault::new_split`. The single-key shape is preserved
    /// here for backward compatibility with the established test suite.
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Self {
        let interactive = derive_interactive_key(passphrase, salt);
        let mut v = Self {
            interactive_key: RefCell::new(interactive),
            headless_key: RefCell::new(interactive),
            authority_key_source: AuthorityKeySource::Mek,
            keys_mlocked: false,
        };
        v.keys_mlocked = v.mlock_keys();
        v
    }

    fn mlock_keys(&mut self) -> bool {
        let interactive_ptr = self.interactive_key.get_mut().as_ptr();
        let headless_ptr = self.headless_key.get_mut().as_ptr();
        unsafe {
            let rc1 = libc::mlock(interactive_ptr as *const libc::c_void, 32);
            let rc2 = libc::mlock(headless_ptr as *const libc::c_void, 32);
            if rc1 != 0 || rc2 != 0 {
                let err = std::io::Error::last_os_error();
                tracing::warn!(
                    error = %err,
                    "mlock(vault keys) failed — key material may be paged to swap"
                );
                return false;
            }
        }
        tracing::debug!("vault key pages mlock'd (64 bytes pinned)");
        true
    }

    /// AEAD key for the given scope. Internal helper used by every
    /// `add` / `get` / `replace` call path so the scope routing is
    /// concentrated in one method.
    ///
    /// ADR 198 D6 — returns a `Ref` guard into the scope's `RefCell`
    /// rather than `&[u8; 32]` (the keys are now interior-mutable so
    /// `zero_scope` can wipe them). The borrow is held only for the
    /// duration of the caller's crypto op (deref to `&[u8; 32]` /
    /// `&[u8]`); the secret is never copied out.
    fn key_for_scope(&self, scope: VaultScope) -> Ref<'_, [u8; 32]> {
        match scope {
            VaultScope::Interactive => self.interactive_key.borrow(),
            VaultScope::Headless => self.headless_key.borrow(),
        }
    }

    /// Export the live Interactive MEK into the EMVS sealed-blob format.
    ///
    /// `vault_export_sealed_cli_landed`: the daemon keeps the raw MEK inside
    /// the authority space; the CLI receives only the passphrase-sealed blob
    /// and the non-secret advisory fingerprint.
    pub fn export_interactive_mek_sealed(
        &self,
        passphrase: &str,
    ) -> Result<(Vec<u8>, String), VaultError> {
        if self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        let mek = Zeroizing::new(*self.interactive_key.borrow());
        let fingerprint = mek_fingerprint_hex(mek.as_slice());
        let blob = export_mek_sealed(mek.as_slice(), passphrase, &fingerprint)?;
        Ok((blob, fingerprint))
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
    ///    (per ADR 131 — the system uid that the LaunchDaemon install
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
    /// Open the vault via double-envelope unlock.
    ///
    /// ADR 216 S4: direct SE unseal is retired. The vault opens exclusively
    /// through the `vault.de_unlock_complete` RPC (outer SE envelope peeled
    /// by CLI, inner DWK envelope peeled by daemon). This stub preserves
    /// compilation for callers that have not yet migrated to the daemon RPC
    /// path, returning a clear error.
    pub fn open_from_config(
        _config: &DaemonConfig,
        _store: &DaemonStore,
    ) -> Result<Vault, VaultError> {
        Err(VaultError::Crypto(
            "direct vault open retired (ADR 216); vault opens via double-envelope unlock"
                .to_string(),
        ))
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
    ///   Wire-up is tracked under **P63.A-SE-WIRE**.
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

    /// ADR 206 §1 (AC-2) — open a key-store vault WITHOUT flipping the presence
    /// session to Unlocked. The transient-KEK widening path
    /// ([`crate::infra::interactive_unlock::install_presence_scope_kek_vault_leave_locked`])
    /// installs `KEK_s` only for the lifetime of one op and evicts it on return;
    /// it must NOT leave a standing `mark_unlocked` window behind (the widening
    /// path holds no time-window state). The op is authorized on the verified §1
    /// proof + the op-supplied `KEK_s`, not on a presence-unlocked flag, so this
    /// open deliberately leaves the presence session Locked. The returned vault
    /// IS attached to the live slot by the caller; the dispatcher's eviction
    /// guard drops it after the op.
    pub fn open_with_key_store_leave_locked(
        config: &DaemonConfig,
        key_store: &VaultKeyStore,
    ) -> Result<Vault, VaultError> {
        open_with_key_store_and_presence(config, key_store, PresenceAfterOpen::LeaveLocked)
    }
}

#[derive(Clone, Copy)]
enum PresenceAfterOpen {
    LeaveLocked,
    MarkUnlocked,
}

/// Argon2id Interactive-MEK derivation. Extracted from
/// `Vault::from_passphrase` so the production split-key path can derive
/// the Interactive key, then independently load-or-generate the Headless
/// key, and assemble a real `Vault::new_split` without double-deriving
/// or sharing the Argon2 cost.
fn derive_interactive_key(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let params = argon2::Params::new(
        VAULT_ARGON2_M_KIB,
        VAULT_ARGON2_T_COST,
        VAULT_ARGON2_P_COST,
        Some(VAULT_ARGON2_OUTPUT_LEN),
    )
    .expect("Argon2 params are compile-time-pinned to a valid combination");
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");
    key
}

/// ADR 198 D3 amendment — AEAD-wrap a 32-byte Headless MEK under the
/// Interactive MEK with a fresh 24-byte nonce and AAD
/// `b"vault.headless-mek.v1"`. Returns `(nonce, ciphertext-with-tag)`.
/// Shared by the first-run file write, the `provision_envelope_meta` DB
/// write, and the rotation re-wrap so all three produce byte-identical
/// framing. The nonce is fresh OS entropy per call — never reused.
fn wrap_headless_mek(
    interactive_key: &[u8; 32],
    headless_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(interactive_key)
        .map_err(|e| VaultError::Crypto(format!("headless mek cipher init: {e}")))?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::fill(&mut nonce_bytes).expect("OS entropy failure on headless mek nonce");
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: headless_key,
                aad: HEADLESS_MEK_WRAP_AAD,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("headless mek wrap: {e}")))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// ADR 198 D3 amendment — AEAD-unwrap a Headless MEK wrap (DB column or
/// file sidecar) under the Interactive MEK. `source` names the origin for
/// error messages. Returns the 32-byte Headless MEK; the recovered
/// plaintext `Vec` is zeroized before return.
fn unwrap_headless_mek(
    interactive_key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    source: &str,
) -> Result<[u8; 32], VaultError> {
    if nonce_bytes.len() != 24 {
        return Err(VaultError::Crypto(format!(
            "headless mek nonce has invalid length: {} (expected 24, {source})",
            nonce_bytes.len()
        )));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(interactive_key)
        .map_err(|e| VaultError::Crypto(format!("headless mek cipher init: {e}")))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: HEADLESS_MEK_WRAP_AAD,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("headless mek unwrap failed ({source}): {e}")))?;
    if plaintext.len() != 32 {
        return Err(VaultError::Crypto(format!(
            "headless mek unwrap produced {} bytes (expected 32)",
            plaintext.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    let mut pt = plaintext;
    use zeroize::Zeroize as _;
    pt.zeroize();
    Ok(out)
}

/// ADR 198 D3 amendment — read-only probe for the relocated Headless-MEK
/// wrap in `<data_dir>/daemon.db`'s `vault_meta` row. Mirrors
/// [`salt_from_vault_meta`]: opens a read-only connection so it works
/// before the live `DaemonStore` is wired at vault-open time. Returns
/// `None` (→ file-sidecar fallback) on any failure or NULL column.
#[allow(clippy::type_complexity)]
fn headless_mek_from_vault_meta(data_dir: &std::path::Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let db_path = data_dir.join("daemon.db");
    if !db_path.exists() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    use rusqlite::OptionalExtension as _;
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT headless_mek_nonce, headless_mek_wrapped FROM vault_meta WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()?;
    match row {
        Some((Some(n), Some(w))) => Some((n, w)),
        _ => None,
    }
}

/// ADR 198 D4 — snapshot-before-mutate. Seal the OLD Interactive MEK under
/// the current operator passphrase (the EMVS sealed-blob format) to a
/// timestamped `vault-mek-snapshot-<UTC>.emvs` file under `data_dir`, 0600,
/// atomic-written. Returns the snapshot path (recorded in the rotation
/// Receipt). A below-the-DB belt-and-suspenders backstop — the atomic tx
/// already precludes half-rotated state.
fn write_pre_rotation_snapshot(
    data_dir: &std::path::Path,
    old_interactive: &[u8; 32],
    passphrase: &str,
) -> Result<String, VaultError> {
    let fingerprint = mek_fingerprint_hex(old_interactive);
    let blob = export_mek_sealed(old_interactive, passphrase, &fingerprint)?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string();
    let filename = format!("vault-mek-snapshot-{ts}.emvs");
    let path = data_dir.join(&filename);

    std::fs::create_dir_all(data_dir)
        .map_err(|e| VaultError::Io(format!("snapshot: create data dir failed: {e}")))?;
    let mut tmp = tempfile::NamedTempFile::new_in(data_dir)
        .map_err(|e| VaultError::Io(format!("snapshot: tempfile failed: {e}")))?;
    use std::io::Write as _;
    tmp.write_all(&blob)
        .map_err(|e| VaultError::Io(format!("snapshot: write failed: {e}")))?;
    tmp.flush()
        .map_err(|e| VaultError::Io(format!("snapshot: flush failed: {e}")))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| VaultError::Io(format!("snapshot: fsync failed: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| VaultError::Io(format!("snapshot: chmod failed: {e}")))?;
    }
    tmp.persist(&path)
        .map_err(|e| VaultError::Io(format!("snapshot: persist failed: {e}")))?;
    Ok(path.to_string_lossy().into_owned())
}

/// Load the wrapped Headless MEK, or generate a fresh one and persist it.
/// Per the scope/MEK split (B1, ADR 139): the Headless MEK
/// is cryptographically independent of the Interactive MEK — fresh OS
/// entropy at first call, AEAD-wrapped under the Interactive MEK so the
/// daemon can reload it across restarts without re-prompting Touch ID, but
/// an attacker with only the Headless attested-device wrap (per
/// `attested_device.rs`) cannot recover the Interactive subset.
///
/// **ADR 198 D3 amendment — DB-first.** The authoritative store for the
/// wrap is now `vault_meta.headless_mek_nonce`/`headless_mek_wrapped` (so a
/// rotation can re-wrap it atomically with the per-row DEKs in one SQLite
/// transaction). Resolution order: DB column → `vault.headless-mek.wrapped`
/// file sidecar (the only transitional tolerance, for a pre-relocation
/// vault) → first-run generate. First-run still writes the file as a
/// store-independent bootstrap; `provision_envelope_meta` then writes the
/// authoritative DB copy and retires the file.
///
/// First-run file layout: `<data_dir>/vault.headless-mek.wrapped` — a
/// 24-byte XChaCha20 nonce followed by the ciphertext-with-tag of the
/// 32-byte MEK, atomic-written via `tempfile::NamedTempFile::persist`.
fn load_or_generate_headless_key(
    data_dir: &std::path::Path,
    interactive_key: &[u8; 32],
) -> Result<[u8; 32], VaultError> {
    // DB-first (the rotation-atomic substrate).
    if let Some((nonce, wrapped)) = headless_mek_from_vault_meta(data_dir) {
        return unwrap_headless_mek(
            interactive_key,
            &nonce,
            &wrapped,
            "vault_meta.headless_mek_wrapped",
        );
    }

    // File-sidecar fallback (transitional — pre-relocation vault).
    let path = data_dir.join(HEADLESS_MEK_WRAP_FILE);
    if let Ok(blob) = std::fs::read(&path) {
        if blob.len() < 24 + 16 {
            return Err(VaultError::Crypto(format!(
                "headless mek wrap blob at {} is too short ({} bytes; minimum 40)",
                path.display(),
                blob.len()
            )));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(24);
        return unwrap_headless_mek(
            interactive_key,
            nonce_bytes,
            ciphertext,
            &format!("vault.headless-mek.wrapped at {}", path.display()),
        );
    }

    // First-run path: generate fresh entropy, wrap, atomic-write the
    // bootstrap file. `provision_envelope_meta` writes the authoritative DB
    // copy + retires this file.
    let mut headless = [0u8; 32];
    getrandom::fill(&mut headless).expect("OS entropy failure on headless mek generation");
    let (nonce_bytes, ciphertext) = wrap_headless_mek(interactive_key, &headless)?;
    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            VaultError::Crypto(format!(
                "headless mek wrap: create {} failed: {e}",
                parent.display()
            ))
        })?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            VaultError::Crypto(format!(
                "headless mek wrap: tempfile in {} failed: {e}",
                parent.display()
            ))
        })?;
        use std::io::Write as _;
        tmp.write_all(&blob).map_err(|e| {
            VaultError::Crypto(format!("headless mek wrap: write to tempfile failed: {e}"))
        })?;
        tmp.flush().map_err(|e| {
            VaultError::Crypto(format!("headless mek wrap: flush tempfile failed: {e}"))
        })?;
        tmp.as_file().sync_all().map_err(|e| {
            VaultError::Crypto(format!("headless mek wrap: fsync tempfile failed: {e}"))
        })?;
        tmp.persist(&path).map_err(|e| {
            VaultError::Crypto(format!(
                "headless mek wrap: persist to {} failed: {e}",
                path.display()
            ))
        })?;
    } else {
        return Err(VaultError::Crypto(format!(
            "headless mek wrap target {} has no parent directory",
            path.display()
        )));
    }
    Ok(headless)
}

fn finish_open(
    passphrase: &str,
    salt: &[u8; 16],
    data_dir: &std::path::Path,
    presence: PresenceAfterOpen,
) -> Result<Vault, VaultError> {
    let interactive_key = derive_interactive_key(passphrase, salt);
    finish_open_with_interactive_key(interactive_key, data_dir, presence, AuthorityKeySource::Mek)
}

/// Assemble the split-key vault from an already-resolved 32-byte interactive key,
/// loading-or-generating the headless key under it. Shared by the Argon2id
/// passphrase lane ([`finish_open`]) and the ADR 206 §4 presence-as-decryption
/// lane ([`VaultKeyStore::PresenceScopeKek`]), where the interactive key is the
/// scope KEK the operator-session presence tap unwrapped (cross-uid) rather than
/// a passphrase derivation. The daemon never derives or holds a passphrase on the
/// §4 lane — the live tap IS the unlock.
///
/// CLEAN-BREAK NOTE (ADR 206 §4): `load_or_generate_headless_key` AEAD-unwraps an
/// existing headless-MEK blob *under this interactive key*. A vault whose headless
/// blob was wrapped under a PRIOR interactive key (e.g. the retired Argon2id MEK)
/// will fail to unwrap when re-sourced from §4 — the documented clean break
/// (operator pre-users). On a fresh data dir the headless key is generated under
/// the §4 KEK and the lanes are coherent thereafter.
fn finish_open_with_interactive_key(
    interactive_key: [u8; 32],
    data_dir: &std::path::Path,
    presence: PresenceAfterOpen,
    authority_key_source: AuthorityKeySource,
) -> Result<Vault, VaultError> {
    if matches!(presence, PresenceAfterOpen::MarkUnlocked) {
        crate::trust::presence::mark_unlocked();
    }
    let headless_key = load_or_generate_headless_key(data_dir, &interactive_key)?;
    Ok(Vault::new_split_with_authority_source(
        interactive_key,
        headless_key,
        authority_key_source,
    ))
}

/// ADR 216 — open vault with a raw interactive key from the double-envelope
/// unlock flow. Marks presence as Unlocked (the CLI relay IS the presence
/// event). Used by the `vault.de_unlock_complete` and `vault.de_provision_begin`
/// RPC handlers.
pub fn finish_open_with_interactive_key_for_de(
    interactive_key: [u8; 32],
    data_dir: &std::path::Path,
) -> Result<Vault, VaultError> {
    finish_open_with_interactive_key(
        interactive_key,
        data_dir,
        PresenceAfterOpen::LeaveLocked,
        AuthorityKeySource::Mek,
    )
}

// open_from_config_with_presence — retired (SE custody replaces passphrase).

fn open_with_key_store_and_presence(
    config: &DaemonConfig,
    key_store: &VaultKeyStore,
    presence: PresenceAfterOpen,
) -> Result<Vault, VaultError> {
    // MEK hardening (C4): same params gate as
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
            let env_passphrase_active = std::env::var("EMBER_VAULT_PASSPHRASE").is_ok();

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
            if env_passphrase_active {
                remember_runtime_reopen_passphrase(&config.data_dir, &passphrase);
            }
            finish_open(&passphrase, salt.as_bytes(), &config.data_dir, presence)
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
            remember_runtime_reopen_passphrase(&config.data_dir, &passphrase);
            let salt = vault_salt(config)?;
            finish_open(&passphrase, &salt, &config.data_dir, presence)
        }
        VaultKeyStore::PresenceScopeKek(kek) => {
            // ADR 206 §4: the operator-session presence tap already unwrapped the
            // scope KEK (cross-uid `se_unwrap`); install it directly as the
            // interactive key. No passphrase, no keyring, no Argon2 — the live tap
            // is the unlock. The daemon never derives or holds a passphrase here.
            finish_open_with_interactive_key(
                *kek.0,
                &config.data_dir,
                presence,
                AuthorityKeySource::PresenceScopeKek,
            )
        }
        #[cfg(target_os = "macos")]
        VaultKeyStore::SecureEnclave(wrapped) => {
            let label =
                ember_broker::secure_enclave::EciesKeyLabel::from_provisioned(&wrapped.key_label);
            let interactive_key =
                crate::infra::vault_macos_se::unwrap_interactive_key(&label, &wrapped.blob)?;
            finish_open_with_interactive_key(
                interactive_key,
                &config.data_dir,
                presence,
                AuthorityKeySource::Mek,
            )
        }
    }
}

/// ADR 198 D1 / Part B — domain-separator prefix for the PAYLOAD AAD of an
/// enveloped daemon-internal seal (`Vault::seal`/`Vault::open`). Distinct
/// from `DEK_WRAP_AAD_PREFIX` so the wrap AAD and the payload AAD can never
/// alias even though both fold in the same `aad_id`. Same fixed-prefix +
/// purpose-id framing as the wrap AAD.
const SEAL_PAYLOAD_AAD_PREFIX: &[u8] = b"vault.seal-payload.v1:";

/// ADR 198 D1 / Part B — build the payload AAD for an enveloped seal:
/// `SEAL_PAYLOAD_AAD_PREFIX || aad_id`. The `aad_id` is the same
/// purpose-bound identifier folded into the DEK-wrap AAD, so a sealed blob
/// is bound to its purpose+owner on BOTH the payload layer and the DEK-wrap
/// layer.
fn seal_payload_aad(aad_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_PAYLOAD_AAD_PREFIX.len() + aad_id.len());
    aad.extend_from_slice(SEAL_PAYLOAD_AAD_PREFIX);
    aad.extend_from_slice(aad_id);
    aad
}

/// ADR 198 D1 / Part B — the four-component output of an enveloped seal.
/// Carries the payload sealed under a fresh per-blob DEK plus the DEK
/// itself AEAD-wrapped under the (Interactive) MEK. Storage sites persist
/// all four components; the MEK directly encrypts NONE of them — it only
/// wraps the DEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// 24-byte XChaCha20 nonce for the payload seal (under the DEK).
    pub payload_nonce: Vec<u8>,
    /// Payload ciphertext-with-tag, sealed under the per-blob DEK.
    pub ciphertext: Vec<u8>,
    /// 24-byte XChaCha20 nonce for the DEK wrap (under the MEK).
    pub dek_nonce: Vec<u8>,
    /// The per-blob DEK, AEAD-wrapped under the Interactive MEK with the
    /// scope+row-bound v2 wrap AAD.
    pub wrapped_dek: Vec<u8>,
}

/// On-disk magic + version for the [`SealedEnvelope`] concatenated blob
/// format used by file-backed callers (bridge-CA module key). The leading
/// byte disambiguates the enveloped v2 format from the legacy
/// `[24-byte nonce || ciphertext]` direct-MEK blob — a legacy blob would
/// start with a random nonce byte and is overwhelmingly unlikely to begin
/// with this fixed magic, and the parser additionally requires a matching
/// total length so a false match is rejected. There is no legacy-accepting
/// read path (the dev0 host has no enveloped vault yet), but the magic
/// makes a future format bump unambiguous.
const SEALED_ENVELOPE_BLOB_MAGIC: u8 = 0xE2;

impl SealedEnvelope {
    /// ADR 198 Part B — serialize to a single concatenated on-disk blob for
    /// file-backed storage (bridge-CA). Layout (all integers little-endian):
    /// `magic(1) || payload_nonce(24) || dek_nonce(24) ||
    ///  wrapped_dek_len(u32) || wrapped_dek || ciphertext`. The two nonces
    /// are fixed-width; only `wrapped_dek` needs an explicit length so the
    /// trailing `ciphertext` (also variable) is unambiguous.
    pub fn to_blob(&self) -> Vec<u8> {
        debug_assert_eq!(self.payload_nonce.len(), 24);
        debug_assert_eq!(self.dek_nonce.len(), 24);
        let wrapped_len = self.wrapped_dek.len() as u32;
        let mut out =
            Vec::with_capacity(1 + 24 + 24 + 4 + self.wrapped_dek.len() + self.ciphertext.len());
        out.push(SEALED_ENVELOPE_BLOB_MAGIC);
        out.extend_from_slice(&self.payload_nonce);
        out.extend_from_slice(&self.dek_nonce);
        out.extend_from_slice(&wrapped_len.to_le_bytes());
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// ADR 198 Part B — parse a blob produced by [`SealedEnvelope::to_blob`].
    /// Returns `VaultError::Crypto` on any framing violation (bad magic,
    /// truncation, inconsistent length) so a corrupt or legacy blob fails
    /// loud rather than silently mis-parsing.
    pub fn from_blob(blob: &[u8]) -> Result<Self, VaultError> {
        // magic(1) + payload_nonce(24) + dek_nonce(24) + wrapped_len(4)
        const HEADER_LEN: usize = 1 + 24 + 24 + 4;
        if blob.len() < HEADER_LEN {
            return Err(VaultError::Crypto(format!(
                "sealed envelope blob too short: {} bytes (need >= {HEADER_LEN})",
                blob.len()
            )));
        }
        if blob[0] != SEALED_ENVELOPE_BLOB_MAGIC {
            return Err(VaultError::Crypto(format!(
                "sealed envelope blob has unexpected magic 0x{:02x} (expected 0x{:02x})",
                blob[0], SEALED_ENVELOPE_BLOB_MAGIC
            )));
        }
        let payload_nonce = blob[1..25].to_vec();
        let dek_nonce = blob[25..49].to_vec();
        let wrapped_len = u32::from_le_bytes([blob[49], blob[50], blob[51], blob[52]]) as usize;
        let wrapped_end = HEADER_LEN.checked_add(wrapped_len).ok_or_else(|| {
            VaultError::Crypto("sealed envelope wrapped_dek length overflow".into())
        })?;
        if blob.len() < wrapped_end {
            return Err(VaultError::Crypto(format!(
                "sealed envelope blob truncated: wrapped_dek claims {wrapped_len} bytes \
                 but only {} remain",
                blob.len() - HEADER_LEN
            )));
        }
        let wrapped_dek = blob[HEADER_LEN..wrapped_end].to_vec();
        let ciphertext = blob[wrapped_end..].to_vec();
        Ok(SealedEnvelope {
            payload_nonce,
            ciphertext,
            dek_nonce,
            wrapped_dek,
        })
    }
}

impl Vault {
    /// ADR 198 Part B — seal raw bytes under the daemon-internal MEK→DEK
    /// envelope and return a [`SealedEnvelope`] for storage. Used by
    /// persona-secret and bridge-CA module-key at-rest encryption.
    ///
    /// The MEK no longer directly encrypts the payload — a fresh per-blob
    /// 32-byte DEK encrypts the payload (XChaCha20-Poly1305, fresh nonce,
    /// payload AAD bound to `aad_id`), and the DEK is AEAD-wrapped under the
    /// Interactive MEK with the scope+row-bound v2 wrap AAD (scope
    /// Interactive, identifier `aad_id`). `aad_id` is a stable purpose-bound
    /// identifier chosen by the caller (e.g. `b"persona-secret"` + the
    /// persona id) so a sealed blob cannot be spliced across purposes or
    /// owners. Both nonces are fresh OS entropy per call — never reused.
    pub fn seal(
        &self,
        class: ValueClass,
        aad_id: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedEnvelope, VaultError> {
        // ADR 206 §4 — route by value class. AuthorityBearing → the
        // interactive key (which IS the presence-unwrapped KEK_s on the §4
        // lane); DaemonOperational → the autonomous headless key. The scope is
        // folded into the DEK-wrap AAD so a blob sealed in one class fails AEAD
        // authentication when opened in the other.
        let scope = class.scope();

        // Scope/MEK split (B1) + adversarial review
        // CRIT-1 fix: refuse AuthorityBearing on a headless-only / idle-zeroed
        // vault — there is no §4 key to seal authority under, and the
        // autonomous key may NEVER be a fallback recipient for authority.
        // DaemonOperational uses the headless key, which is always present.
        if scope == VaultScope::Interactive && self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        if class == ValueClass::AuthorityBearing {
            self.ensure_authority_bearing_source()?;
        }

        // Fresh per-blob DEK; payload sealed under the DEK (not the MEK).
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek.as_mut_slice()).expect("OS entropy failure on seal dek generation");
        let payload_cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let payload_aad = seal_payload_aad(aad_id);
        let ciphertext = payload_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &payload_aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        // Wrap the DEK under the class-routed scope key with the scope+row-bound
        // v2 AAD; the purpose binding lives in `aad_id`.
        let (dek_nonce, wrapped_dek) = wrap_dek(&self.key_for_scope(scope), &dek, scope, aad_id)?;

        Ok(SealedEnvelope {
            payload_nonce: nonce_bytes.to_vec(),
            ciphertext,
            dek_nonce,
            wrapped_dek,
        })
    }

    /// ADR 198 Part B — open a [`SealedEnvelope`] produced by [`Vault::seal`]
    /// under the SAME `aad_id`. Unwraps the per-blob DEK under the
    /// Interactive MEK (the wrap AAD must match scope+`aad_id`), then
    /// decrypts the payload under the DEK (the payload AAD must match
    /// `aad_id`). Any mismatch — wrong MEK, wrong purpose id, a spliced blob
    /// — fails the AEAD authentication tag. Returns plaintext on success,
    /// `VaultError::Crypto` on AEAD failure. There is NO direct-MEK fallback
    /// (mirrors the credential `get` discipline).
    pub fn open(
        &self,
        class: ValueClass,
        aad_id: &[u8],
        env: &SealedEnvelope,
    ) -> Result<VaultPlaintext, VaultError> {
        // ADR 206 §4 — pair with `seal`: route by the SAME value class. The
        // scope is bound into the DEK-wrap AAD, so opening a blob under the
        // wrong class (e.g. an AuthorityBearing blob as DaemonOperational)
        // fails the AEAD tag even if the two keys happened to be equal.
        let scope = class.scope();

        // Scope/MEK split (B1) + adversarial CRIT-1
        // fix: refuse AuthorityBearing on a headless-only / idle-zeroed vault.
        if scope == VaultScope::Interactive && self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        if class == ValueClass::AuthorityBearing {
            self.ensure_authority_bearing_source()?;
        }
        if env.payload_nonce.len() != 24 {
            return Err(VaultError::Crypto(format!(
                "invalid payload nonce length: {}",
                env.payload_nonce.len()
            )));
        }

        // Unwrap the per-blob DEK under the class-routed scope key.
        let dek = unwrap_dek(
            &self.key_for_scope(scope),
            &env.dek_nonce,
            &env.wrapped_dek,
            scope,
            aad_id,
        )?;

        let payload_cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).unwrap();
        let nonce = XNonce::from_slice(&env.payload_nonce);
        let payload_aad = seal_payload_aad(aad_id);
        payload_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: env.ciphertext.as_slice(),
                    aad: &payload_aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|e| VaultError::Crypto(e.to_string()))
    }

    /// ADR 198 D3 — seal the fixed key-correctness canary plaintext under
    /// the Interactive MEK. Returns `(canary_nonce, canary_ciphertext)`
    /// for storage in `vault_meta`. The seal is a plain XChaCha20-Poly1305
    /// AEAD over `VAULT_CANARY_PLAINTEXT` with AAD `VAULT_CANARY_AAD` and a
    /// fresh 24-byte nonce. Refuses on a headless-only Vault (no
    /// Interactive MEK to seal under).
    pub fn seal_canary(&self) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        if self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.interactive_key.borrow().as_slice())
            .map_err(|e| VaultError::Crypto(format!("canary cipher init: {e}")))?;
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure on canary nonce");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: VAULT_CANARY_PLAINTEXT,
                    aad: VAULT_CANARY_AAD,
                },
            )
            .map_err(|e| VaultError::Crypto(format!("canary seal: {e}")))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// ADR 198 D3 — provision the vault's envelope metadata at first run:
    /// write the KDF `salt`, the pinned Argon2 params TOML, and the
    /// AEAD-sealed canary into `vault_meta`. Called from the open/derive
    /// path exactly once, when the salt is freshly generated, so a wrong
    /// MEK is caught cryptographically on every subsequent open
    /// (`verify_canary`) regardless of credential count.
    pub fn provision_envelope_meta(
        &self,
        store: &DaemonStore,
        salt: &[u8; 16],
    ) -> Result<(), VaultError> {
        if self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        let (canary_nonce, canary) = self.seal_canary()?;
        let params_toml = vault_argon2_params_toml();
        store
            .write_vault_envelope_meta(salt, &params_toml, &canary, &canary_nonce)
            .map_err(VaultError::Store)?;

        // ADR 198 D3 amendment — write the AUTHORITATIVE Headless-MEK wrap
        // into `vault_meta` (re-wrapped under the live Interactive MEK with a
        // fresh nonce) so a future rotation re-wraps it atomically with the
        // per-row DEKs. `load_or_generate_headless_key` wrote a bootstrap
        // file copy at open time; retire it best-effort now that the DB copy
        // is authoritative (DB-first read makes a lingering file harmless, so
        // a delete failure is non-fatal).
        let (h_nonce, h_wrapped) =
            wrap_headless_mek(&self.interactive_key.borrow(), &self.headless_key.borrow())?;
        store
            .write_headless_mek_wrap(&h_nonce, &h_wrapped)
            .map_err(VaultError::Store)?;
        if let Some(dir) = store.data_dir() {
            let file = dir.join(HEADLESS_MEK_WRAP_FILE);
            if file.exists()
                && let Err(e) = std::fs::remove_file(&file)
            {
                warn!(
                    path = %file.display(),
                    error = %e,
                    "vault: failed to retire bootstrap headless-mek file after DB relocation (non-fatal; DB copy is authoritative)"
                );
            }
        }
        Ok(())
    }

    /// Provision canary + headless-MEK wrap under SE-custodied interactive
    /// key. Like [`Self::provision_envelope_meta`] but omits the Argon2
    /// salt/params columns (not needed when the interactive key is
    /// SE-derived rather than passphrase-derived).
    pub fn provision_se_canary_meta(&self, store: &DaemonStore) -> Result<(), VaultError> {
        if self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        let (canary_nonce, canary) = self.seal_canary()?;
        store
            .write_vault_canary(&canary, &canary_nonce)
            .map_err(VaultError::Store)?;

        let (h_nonce, h_wrapped) =
            wrap_headless_mek(&self.interactive_key.borrow(), &self.headless_key.borrow())?;
        store
            .write_headless_mek_wrap(&h_nonce, &h_wrapped)
            .map_err(VaultError::Store)?;
        if let Some(dir) = store.data_dir() {
            let file = dir.join(HEADLESS_MEK_WRAP_FILE);
            if file.exists()
                && let Err(e) = std::fs::remove_file(&file)
            {
                warn!(
                    path = %file.display(),
                    error = %e,
                    "vault: failed to retire bootstrap headless-mek file (non-fatal)"
                );
            }
        }
        Ok(())
    }

    /// ADR 198 D3 — the cryptographic key-correctness authority. AEAD-
    /// unwraps the canary stored in `vault_meta` under the CURRENT
    /// Interactive MEK and checks the recovered plaintext matches the
    /// fixed `VAULT_CANARY_PLAINTEXT`. A wrong MEK fails the AEAD tag →
    /// `VaultError::Crypto` (the fail-loud destination). Works with ZERO
    /// credential rows because the canary lives in `vault_meta`, not on a
    /// credential row.
    ///
    /// Returns `Ok(())` when there is no canary stored yet (pre-migration
    /// vault or a vault provisioned before the canary landed) — the
    /// absence is not a wrong-MEK signal, and the advisory
    /// `mek_fingerprint` still covers that transitional case. Once the
    /// canary is present it is authoritative.
    pub fn verify_canary(&self, store: &DaemonStore) -> Result<(), VaultError> {
        if self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        let Some((canary, canary_nonce)) = store.read_vault_canary().map_err(VaultError::Store)?
        else {
            // No canary stored — nothing to verify (transitional).
            return Ok(());
        };
        if canary_nonce.len() != 24 {
            return Err(VaultError::Crypto(format!(
                "vault canary nonce has invalid length: {} (expected 24)",
                canary_nonce.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.interactive_key.borrow().as_slice())
            .map_err(|e| VaultError::Crypto(format!("canary cipher init: {e}")))?;
        let nonce = XNonce::from_slice(&canary_nonce);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: canary.as_slice(),
                    aad: VAULT_CANARY_AAD,
                },
            )
            .map_err(|_| {
                VaultError::Crypto(
                    "vault canary AEAD verification failed — the in-memory MEK does \
                     NOT match the MEK this vault was sealed under (wrong passphrase, \
                     wrong keychain entry, or silent key divergence); refusing to \
                     proceed (ADR 198 D3 fail-loud)"
                        .to_string(),
                )
            })?;
        if plaintext.as_slice() != VAULT_CANARY_PLAINTEXT {
            return Err(VaultError::Crypto(
                "vault canary unwrapped but plaintext does not match the expected \
                 canary value; refusing to proceed (ADR 198 D3 fail-loud)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn add(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
    ) -> Result<CredentialInfo, VaultError> {
        self.add_with_presence_policy(scope, store, name, value, metadata, PresencePolicy::LaneDefault)
    }

    pub fn add_with_presence_policy(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
        presence_policy: PresencePolicy,
    ) -> Result<CredentialInfo, VaultError> {
        // ADR 097/099 path-grammar gate — applies to NEW entries only.
        // Existing rows with non-conformant names continue to function via
        // `get`/`list`/`remove`; this check fires only on insert.
        validate_credential_name(name).map_err(VaultError::InvalidName)?;
        let stored_name = storage_name_for_scope(scope, name);

        // MEK hardening (C5): mint the row id BEFORE encrypting
        // so the AEAD AAD can be bound to the row's UUID. AAD format is
        // `[0x01, row_uuid_bytes...]` (17 bytes). Decrypt-side (Vault::get)
        // tries this AAD first, falling back to no-AAD for legacy rows.
        let id = format!("cred-{}", Uuid::new_v4());
        let aad = aad_for_row_id(&id).expect("freshly-minted cred-<uuid> id parses");

        // Scope/MEK split (B1): encrypt under the
        // per-scope MEK so an attacker who recovers ONLY the Headless
        // attested-device wrap (per `attested_device.rs`) cannot decrypt
        // Interactive rows.
        //
        // Adversarial CRIT-1 fix (2026-05-22): refuse Interactive ops
        // on a headless-only Vault. Headless ops still proceed.
        if scope == VaultScope::Interactive && self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }

        // ADR 198 D1 — MEK→DEK envelope. Generate a fresh per-row Data
        // Encryption Key, encrypt the payload under the DEK (KEEPING the
        // existing 24-byte payload nonce + `[0x01||uuid]` AAD exactly),
        // then wrap the DEK under the scope MEK with a FRESH dek_nonce.
        // The scope MEK no longer directly encrypts the payload — it only
        // wraps the DEK.
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek.as_mut_slice()).expect("OS entropy failure on dek generation");
        let payload_cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = payload_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        // ADR 198 D1 — scope+row-bound DEK wrap. Bind the wrap AAD to the
        // scope AND the row UUID so the wrapped DEK cannot be unwrapped under
        // a different scope or spliced onto a different row.
        let aad_id =
            cred_row_uuid_bytes(&id).expect("freshly-minted cred-<uuid> id yields a 16-byte uuid");
        let (dek_nonce, wrapped_dek) = wrap_dek(&self.key_for_scope(scope), &dek, scope, &aad_id)?;

        let created_at = chrono::Utc::now().to_rfc3339();

        store
            .conn()
            .execute(
                "INSERT INTO credentials \
                 (id, name, nonce, ciphertext, created_at, metadata, wrapped_dek, dek_nonce, presence_policy) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    stored_name,
                    nonce_bytes.as_slice(),
                    ciphertext,
                    created_at,
                    metadata,
                    wrapped_dek.as_slice(),
                    dek_nonce.as_slice(),
                    presence_policy.as_db_str()
                ],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(CredentialInfo {
            id,
            name: name.to_string(),
            created_at,
            metadata: metadata.map(str::to_string),
            presence_policy,
            value_class: ValueClass::from_stored_name(&stored_name),
        })
    }

    pub fn list(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
    ) -> Result<Vec<CredentialInfo>, VaultError> {
        let mut stmt = store
            .conn()
            .prepare(
                "SELECT id, name, created_at, metadata, presence_policy \
                 FROM credentials ORDER BY created_at",
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let rows = stmt
            .query_map([], |row| {
                let stored_name: String = row.get(1)?;
                let policy_str: String = row.get(4)?;
                Ok(CredentialInfo {
                    id: row.get(0)?,
                    value_class: ValueClass::from_stored_name(&stored_name),
                    name: stored_name,
                    created_at: row.get(2)?,
                    metadata: row.get(3)?,
                    presence_policy: PresencePolicy::from_db_str(&policy_str),
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
    ) -> Result<VaultPlaintext, VaultError> {
        self.get_with_read_gate(scope, store, name, VaultReadGate::CachedUnlockOnly)
    }

    pub fn credential_presence_policy(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
    ) -> Result<PresencePolicy, VaultError> {
        let stored_name = storage_name_for_scope(scope, name);
        let result: Option<String> = store
            .conn()
            .query_row(
                "SELECT presence_policy FROM credentials WHERE name = ?1",
                params![stored_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        result
            .map(|s| PresencePolicy::from_db_str(&s))
            .ok_or(VaultError::NotFound)
    }

    pub fn get_with_read_gate(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        read_gate: VaultReadGate,
    ) -> Result<VaultPlaintext, VaultError> {
        // Adversarial CRIT-1 fix (2026-05-22): refuse Interactive ops
        // on headless-only Vaults BEFORE the SQLite lookup so the gate
        // is visible at the API boundary, not behind a `NotFound`.
        if scope == VaultScope::Interactive && self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }
        // ADR 198 D1 — MEK→DEK envelope read. Select the wrapped DEK +
        // dek_nonce alongside the payload nonce/ciphertext so we can
        // unwrap the per-row DEK under the scope MEK and then decrypt the
        // payload under the DEK. Envelope-only: a row with NULL
        // wrapped_dek pre-dates the S6a migration and is NOT silently
        // decrypted under the MEK — it returns a clear error.
        let stored_name = storage_name_for_scope(scope, name);
        #[allow(clippy::type_complexity)]
        let result: Option<(
            String,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
        )> = store
            .conn()
            .query_row(
                "SELECT id, nonce, ciphertext, wrapped_dek, dek_nonce, presence_policy \
                 FROM credentials WHERE name = ?1",
                params![stored_name],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        let (id, nonce_bytes, ciphertext, wrapped_dek, dek_nonce, policy_str) =
            result.ok_or(VaultError::NotFound)?;
        let presence_policy = PresencePolicy::from_db_str(&policy_str);
        // Presence-policy unification: the read-gate now consults
        // a typed presence policy rather than the prior `requires_biometric`
        // boolean. The semantic is unchanged — `PerAccessFresh` rows demand
        // a fresh presence-Device signature regardless of method lane,
        // closing the cached-unlock bypass surfaced by PR #6088.
        if presence_policy.requires_fresh_presence() && !read_gate.satisfies_fresh_presence() {
            return Err(VaultError::PresenceRequired);
        }

        // ADR 198 D2 — envelope-only. A row missing the wrapped-DEK
        // columns was written by a pre-envelope daemon and must be
        // migrated by the out-of-tree S6a one-shot before it can be read.
        // There is no silent direct-MEK fallback (that would re-introduce
        // the dual-path the ADR explicitly forbids).
        let (wrapped_dek, dek_nonce) = match (wrapped_dek, dek_nonce) {
            (Some(w), Some(n)) => (w, n),
            _ => {
                return Err(VaultError::Crypto(format!(
                    "credential row '{name}' (id {id}) is not enveloped \
                     (wrapped_dek is NULL); run the S6a migration one-shot \
                     to wrap it under the MEK→DEK envelope before reading"
                )));
            }
        };

        // Unwrap the per-row DEK under the scope MEK. The headless-only
        // refusal gate already fired at the top of this fn; this is the
        // cryptographic dispatch for the still-permitted scope.
        //
        // ADR 198 D1 — the unwrap AAD is rebuilt from the SAME scope + the
        // row's OWN UUID. A whole-row cross-scope splice (moving
        // wrapped_dek+dek_nonce+ciphertext into another scope's row) fails
        // here on the scope-label mismatch; a cross-row splice fails on the
        // uuid mismatch. A row id that does not parse as `cred-<uuid>` cannot
        // produce a wrap-bound AAD, so it is a hard error rather than an
        // unbound unwrap.
        let Some(aad_id) = cred_row_uuid_bytes(&id) else {
            return Err(VaultError::Crypto(
                "credential row id is not a parseable cred-<uuid>; cannot bind AAD for dek unwrap"
                    .into(),
            ));
        };
        let dek = unwrap_dek(
            &self.key_for_scope(scope),
            &dek_nonce,
            &wrapped_dek,
            scope,
            &aad_id,
        )?;

        // Decrypt the payload under the DEK. The payload AAD scheme is
        // ONE payload seal format under the DEK: AAD-bound (`[0x01||uuid]`).
        // There is no no-AAD fallback — a committed `add` always binds AAD, and
        // the out-of-tree S6a migration one-shot re-applies AAD when it
        // envelopes legacy rows. (Adversarial review: a surviving no-AAD path
        // would be a second seal format living in the security core.)
        let payload_cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);

        let Some(aad) = aad_for_row_id(&id) else {
            return Err(VaultError::Crypto(
                "credential row id is not a parseable cred-<uuid>; cannot bind AAD for decrypt"
                    .into(),
            ));
        };
        payload_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|e| VaultError::Crypto(e.to_string()))
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

    /// Zero the in-memory MEK for `scope`, wiping the key bytes in place.
    ///
    /// Per ADR 139 ("Interactive: demand-pinned"), the idle-zero handler in
    /// `UnlockPinTracker` calls into this method when the grace window
    /// expires with no live pins. ADR 198 D6 (amendment 3) wired this from a
    /// no-op Phase-1 stub to a real wipe: the per-scope MEK is interior-
    /// mutable (`RefCell<[u8; 32]>`), so we `zeroize()` the scope's bytes in
    /// place through the shared `&Rc<Vault>` — no `&mut self` and no slot
    /// swap required.
    ///
    /// Semantics after a wipe:
    /// - **Interactive** — the key becomes the all-zero checkpoint, so
    ///   `is_headless_only()` flips true and every Interactive op
    ///   (`add`/`get`/`replace`/`seal`/`open`) refuses with
    ///   `VaultError::HeadlessOnly`. The Headless lane (if independent) keeps
    ///   serving — exactly the ADR 139 demand-pinned posture. Re-unlock at
    ///   the next session-open re-derives the Interactive MEK from the
    ///   keyring-stored passphrase.
    /// - **Headless** — wipes the Headless MEK; the next vault open reloads
    ///   it from the (Interactive-MEK-wrapped) `vault_meta` / file sidecar.
    ///
    /// This does NOT touch the keyring, the passphrase caches, or any at-rest
    /// material — it only scrubs the live in-memory key. (Whole-vault teardown
    /// is `DaemonStore::drop_vault`, which drops the `Rc<Vault>` and lets the
    /// `Drop` impl above zeroize both scopes.)
    pub fn zero_scope(&self, scope: VaultScope) -> Result<(), VaultError> {
        use zeroize::Zeroize as _;
        match scope {
            VaultScope::Interactive => self.interactive_key.borrow_mut().zeroize(),
            VaultScope::Headless => self.headless_key.borrow_mut().zeroize(),
        }
        info!(scope = ?scope, "vault: zero_scope wiped in-memory MEK bytes (ADR 198 D6)");
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
        self.replace_with_presence_policy(scope, store, name, value, metadata, PresencePolicy::LaneDefault)
    }

    pub fn replace_with_presence_policy(
        &self,
        scope: VaultScope,
        store: &DaemonStore,
        name: &str,
        value: &[u8],
        metadata: Option<&str>,
        presence_policy: PresencePolicy,
    ) -> Result<CredentialInfo, VaultError> {
        validate_credential_name(name).map_err(VaultError::InvalidName)?;
        let stored_name = storage_name_for_scope(scope, name);

        // MEK hardening (C5): mint id first, bind AAD to the
        // new row's UUID. Same pattern as `Vault::add`.
        let id = format!("cred-{}", Uuid::new_v4());
        let aad = aad_for_row_id(&id).expect("freshly-minted cred-<uuid> id parses");

        // Scope/MEK split (B1): replace also routes
        // per-scope so the rewritten row stays sealed under the scope's
        // key, not whichever MEK happens to be in `self.interactive_key`.
        //
        // Adversarial CRIT-1 fix (2026-05-22): refuse Interactive ops
        // on a headless-only Vault.
        if scope == VaultScope::Interactive && self.is_headless_only() {
            return Err(VaultError::HeadlessOnly);
        }

        // ADR 198 D1 — same MEK→DEK envelope as `add`: fresh per-row DEK,
        // payload encrypted under the DEK, DEK wrapped under the scope MEK
        // with a fresh dek_nonce.
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::fill(dek.as_mut_slice()).expect("OS entropy failure on dek generation");
        let payload_cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice()).unwrap();
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = payload_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        // ADR 198 D1 — scope+row-bound DEK wrap, same as `add`.
        let aad_id =
            cred_row_uuid_bytes(&id).expect("freshly-minted cred-<uuid> id yields a 16-byte uuid");
        let (dek_nonce, wrapped_dek) = wrap_dek(&self.key_for_scope(scope), &dek, scope, &aad_id)?;

        let created_at = chrono::Utc::now().to_rfc3339();

        let conn = store.conn();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        // Sticky escalation: if the existing row was already PerAccessFresh,
        // keep it PerAccessFresh on replace regardless of the caller's
        // ask. Downgrading to LaneDefault requires an explicit delete +
        // re-add, mirroring the pre-consolidation `existing||new` shape.
        let existing_policy_str: Option<String> = tx
            .query_row(
                "SELECT presence_policy FROM credentials WHERE name = ?1",
                params![stored_name.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        let existing_policy = existing_policy_str
            .as_deref()
            .map(PresencePolicy::from_db_str)
            .unwrap_or(PresencePolicy::LaneDefault);
        let presence_policy = if existing_policy.requires_fresh_presence() {
            PresencePolicy::PerAccessFresh
        } else {
            presence_policy
        };
        tx.execute(
            "DELETE FROM credentials WHERE name = ?1",
            params![stored_name.as_str()],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        tx.execute(
            "INSERT INTO credentials \
             (id, name, nonce, ciphertext, created_at, metadata, wrapped_dek, dek_nonce, presence_policy) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                stored_name,
                nonce_bytes.as_slice(),
                ciphertext,
                created_at,
                metadata,
                wrapped_dek.as_slice(),
                dek_nonce.as_slice(),
                presence_policy.as_db_str()
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
            presence_policy,
            value_class: ValueClass::from_stored_name(&stored_name),
        })
    }

    /// ADR 198 D3/D5 — perform an atomic vault MEK rotation.
    ///
    /// Re-protects all at-rest material under a freshly-derived/generated MEK
    /// in ONE SQLite transaction (the single linearization point): re-wraps
    /// every per-row DEK whose scope MEK changes (credentials + persona
    /// secrets), re-seals the canary, re-wraps the relocated headless-MEK and
    /// bridge-CA wraps, and writes the new salt / `mek_fingerprint` /
    /// `key_epoch`. Payload ciphertext + nonces are NEVER touched — only the
    /// wrapped DEKs (and the meta) move to the new MEK.
    ///
    /// Modes (ADR 198 D5):
    /// - `Rekey` — same passphrase, NEW salt → new Interactive MEK. The
    ///   Headless MEK value is unchanged but re-wrapped under the new
    ///   Interactive MEK.
    /// - `ChangePassphrase` — `new_passphrase` + NEW salt → new Interactive
    ///   MEK. The caller updates the keychain entry AFTER this commits.
    /// - `RotateHeadless` — fresh random Headless MEK; Interactive unchanged.
    ///
    /// Crash-safety: a crash before commit rolls back to the intact old vault;
    /// a crash after commit leaves a fully-rotated, openable vault (new salt +
    /// every re-wrapped DEK + both relocated wraps committed together). The
    /// pre-mutate EMVS snapshot (D4) is a below-the-DB backstop.
    ///
    /// This is keychain-free and side-effect-free except the DB transaction
    /// and the snapshot file write; the caller owns `set_vault`, cache
    /// clears, the `change_passphrase` keychain update, the witness Receipt,
    /// and retiring `retired_files` post-commit.
    ///
    /// Honest scope (D6): re-protects AT-REST material only — it does NOT
    /// revoke minted tokens, active grants, or upstream credentials.
    pub fn rotate_mek(
        &self,
        store: &DaemonStore,
        data_dir: &std::path::Path,
        mode: RotationMode,
        current_passphrase: &str,
        new_passphrase: Option<&str>,
    ) -> Result<RotationOutcome, VaultError> {
        if self.is_headless_only() {
            // Rotation always re-wraps under / re-seals the Interactive MEK
            // (the headless-MEK wrap + canary + bridge-CA all live under it),
            // so a headless-only Vault cannot rotate.
            return Err(VaultError::HeadlessOnly);
        }
        // ADR 206 §4 / ADR 211 AC-4 — refuse BEFORE any side effect (the
        // pre-rotation snapshot below seals the live Interactive key under the
        // passphrase). On a presence-backed vault the live Interactive key IS
        // `KEK_s`; snapshotting it under the passphrase would mint a
        // passphrase-recoverable copy of the scope KEK, and the per-row rewrap
        // would downgrade AuthorityBearing custody to a MEK-reachable copy —
        // both silent §4 voids. Presence/`KEK_s` custody is re-keyed through the
        // §4 presence lane, never this MEK-rotation primitive. (`rewrap_personas_in_tx`
        // carries the same invariant as in-tx defense-in-depth.)
        if self.authority_key_source == AuthorityKeySource::PresenceScopeKek {
            return Err(VaultError::AuthorityCustodyRotationUnsupported);
        }

        // Hold every transient plaintext MEK in `Zeroizing` so the stack copies
        // are scrubbed on scope exit / early `?`-return — the
        // MEK hardening (C1) no-residue posture the rest of this file
        // keeps (`unwrap_dek`, `unwrap_headless_mek`, etc.). The only un-tracked
        // copy is the momentary by-value arg to `Vault::new_split` below, which
        // moves straight into the new Vault's `ZeroizeOnDrop` cells — the same
        // constructor pattern every other `new_split` call site uses.
        let old_interactive = Zeroizing::new(*self.interactive_key.borrow());
        let old_headless = Zeroizing::new(*self.headless_key.borrow());

        let interactive_changed =
            matches!(mode, RotationMode::Rekey | RotationMode::ChangePassphrase);
        let headless_changed = matches!(mode, RotationMode::RotateHeadless);

        // Derive/generate the new key material per mode (in-memory only; not
        // touching disk until the tx below).
        let new_salt: Option<[u8; 16]> = if interactive_changed {
            Some(Vault::generate_salt())
        } else {
            None
        };
        let new_interactive: Zeroizing<[u8; 32]> = match mode {
            RotationMode::Rekey => Zeroizing::new(derive_interactive_key(
                current_passphrase,
                &new_salt.expect("rekey always generates a new salt"),
            )),
            RotationMode::ChangePassphrase => {
                let p = new_passphrase.ok_or_else(|| {
                    VaultError::Crypto(
                        "change_passphrase mode requires a new passphrase".to_string(),
                    )
                })?;
                Zeroizing::new(derive_interactive_key(
                    p,
                    &new_salt.expect("change_passphrase always generates a new salt"),
                ))
            }
            RotationMode::RotateHeadless => old_interactive.clone(),
        };
        let new_headless: Zeroizing<[u8; 32]> = match mode {
            RotationMode::RotateHeadless => {
                let mut h = Zeroizing::new([0u8; 32]);
                getrandom::fill(h.as_mut_slice())
                    .expect("OS entropy failure on headless mek rotation");
                h
            }
            _ => old_headless.clone(),
        };

        // Fail loud if a derived Interactive MEK collapsed to the headless-only
        // checkpoint (Argon2id never produces all-zero, but never serve it).
        if interactive_changed && new_interactive.iter().all(|b| *b == 0) {
            return Err(VaultError::Crypto(
                "refusing rotation: newly-derived Interactive MEK is all-zero".to_string(),
            ));
        }

        let new_vault = Vault::new_split(*new_interactive, *new_headless);

        // ADR 198 D4 — snapshot-before-mutate: seal the OLD Interactive MEK
        // under the current passphrase to a timestamped EMVS file.
        let snapshot_path =
            write_pre_rotation_snapshot(data_dir, &old_interactive, current_passphrase)?;

        let prev_key_epoch = store.read_key_epoch().map_err(VaultError::Store)?;
        let new_key_epoch = prev_key_epoch + 1;

        // Rotated-scope fingerprints for the witness Receipt (D7).
        let (prev_scope_fingerprint, new_scope_fingerprint) = if interactive_changed {
            (
                mek_fingerprint_hex(old_interactive.as_slice()),
                mek_fingerprint_hex(new_interactive.as_slice()),
            )
        } else {
            (
                mek_fingerprint_hex(old_headless.as_slice()),
                mek_fingerprint_hex(new_headless.as_slice()),
            )
        };

        let mut retired_files: Vec<std::path::PathBuf> = Vec::new();
        let conn = store.conn();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        // Guarantee the single `vault_meta` row exists so the UPDATEs below
        // land (a pre-migration vault may have salt/canary in file sidecars
        // and no DB row yet). `key_epoch` defaults to 0.
        tx.execute("INSERT OR IGNORE INTO vault_meta (id) VALUES (1)", [])
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        // 1. Re-wrap every per-row credential DEK whose scope MEK changed.
        let mut rewrap_count =
            self.rewrap_credentials_in_tx(&tx, &new_vault, interactive_changed, headless_changed)?;

        // 2. Re-wrap persona-secret DEKs (Interactive MEK) — only when it changed.
        if interactive_changed {
            rewrap_count += self.rewrap_personas_in_tx(&tx, &new_vault)?;
        }

        // 3. Re-seal the canary under the new Interactive MEK — only when it
        //    changed (the canary is sealed directly under the Interactive MEK,
        //    so a rekey/change_passphrase MUST re-seal it or the next open
        //    fails the AEAD canary fail-loud check; RotateHeadless leaves it).
        if interactive_changed {
            let (canary_nonce, canary) = new_vault.seal_canary()?;
            tx.execute(
                "UPDATE vault_meta SET canary = ?1, canary_nonce = ?2 WHERE id = 1",
                params![canary, canary_nonce],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        }

        // 4. Re-wrap the relocated Headless-MEK wrap (ALWAYS): its wrap is
        //    under the Interactive MEK (so a rekey re-wraps it even though the
        //    Headless value is unchanged), and for RotateHeadless the Headless
        //    value itself changed. Committed to vault_meta; retire the file.
        let (h_nonce, h_wrapped) = wrap_headless_mek(&new_interactive, &new_headless)?;
        tx.execute(
            "UPDATE vault_meta SET headless_mek_nonce = ?1, headless_mek_wrapped = ?2 WHERE id = 1",
            params![h_nonce, h_wrapped],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        retired_files.push(data_dir.join(HEADLESS_MEK_WRAP_FILE));

        // 5. Re-wrap the bridge-CA module key — only when its wrapping key
        //    changed and a bridge CA is provisioned. ADR 206 §4: the bridge-CA
        //    module key is DaemonOperational and now wraps under the HEADLESS
        //    key, so a Rekey/ChangePassphrase (which leaves headless unchanged)
        //    no longer disturbs the autonomous bridge CA; only RotateHeadless
        //    re-wraps it.
        if headless_changed {
            self.rewrap_bridge_ca_in_tx(store, &tx, &new_vault, data_dir, &mut retired_files)?;
        }

        // 6. Write the new salt (Rekey/ChangePassphrase) + new advisory
        //    fingerprint + bump key_epoch — all in the same tx as the rewraps.
        if let Some(salt) = new_salt {
            tx.execute(
                "UPDATE vault_meta SET salt = ?1 WHERE id = 1",
                params![salt.as_slice()],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            // The file sidecar (if any) is now shadowed by the DB salt; retire it.
            retired_files.push(data_dir.join("vault.salt"));
        }
        tx.execute(
            "UPDATE vault_meta SET mek_fingerprint = ?1, key_epoch = ?2 WHERE id = 1",
            params![
                mek_fingerprint_hex(new_interactive.as_slice()),
                new_key_epoch
            ],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        // COMMIT — the single linearization point. Everything above either
        // lands together or rolls back together.
        tx.commit()
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;

        Ok(RotationOutcome {
            new_vault,
            mode,
            rewrap_count,
            prev_key_epoch,
            new_key_epoch,
            prev_scope_fingerprint,
            new_scope_fingerprint,
            snapshot_path,
            retired_files,
        })
    }

    /// ADR 198 D3 — re-wrap every credential-row DEK whose scope MEK changed,
    /// inside the rotation transaction. Reads all rows first (single-threaded
    /// daemon → no concurrent writer), then UPDATEs `wrapped_dek`/`dek_nonce`
    /// with a fresh nonce. Payload ciphertext/nonce untouched. Returns the
    /// number of rows re-wrapped.
    fn rewrap_credentials_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        new_vault: &Vault,
        interactive_changed: bool,
        headless_changed: bool,
    ) -> Result<u64, VaultError> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, String, Option<Vec<u8>>, Option<Vec<u8>>)> = {
            let mut stmt = tx
                .prepare("SELECT id, name, wrapped_dek, dek_nonce FROM credentials")
                .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            let mapped = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            let mut v = Vec::new();
            for r in mapped {
                v.push(r.map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?);
            }
            v
        };

        let mut count = 0u64;
        for (id, name, wrapped_dek, dek_nonce) in rows {
            let scope = if name.starts_with(HEADLESS_SCOPE_STORAGE_PREFIX) {
                VaultScope::Headless
            } else {
                VaultScope::Interactive
            };
            let scope_changed = match scope {
                VaultScope::Interactive => interactive_changed,
                VaultScope::Headless => headless_changed,
            };
            if !scope_changed {
                continue;
            }
            // Envelope-only: a NULL-wrapped row predates the envelope and
            // cannot be rotated — fail loud rather than silently skip (a
            // skipped row would be unrotatable and unreadable post-rotation).
            let (wrapped_dek, dek_nonce) = match (wrapped_dek, dek_nonce) {
                (Some(w), Some(n)) => (w, n),
                _ => {
                    return Err(VaultError::Crypto(format!(
                        "cannot rotate: credential row '{name}' (id {id}) is not enveloped \
                         (wrapped_dek is NULL); run the migration one-shot first"
                    )));
                }
            };
            let Some(aad_id) = cred_row_uuid_bytes(&id) else {
                return Err(VaultError::Crypto(format!(
                    "cannot rotate: credential row id '{id}' is not a parseable cred-<uuid>"
                )));
            };
            // Unwrap the DEK under the OLD scope MEK, re-wrap under the NEW
            // scope MEK with the SAME scope+row-bound AAD and a fresh nonce.
            let dek = unwrap_dek(
                &self.key_for_scope(scope),
                &dek_nonce,
                &wrapped_dek,
                scope,
                &aad_id,
            )?;
            let (new_nonce, new_wrapped) =
                wrap_dek(&new_vault.key_for_scope(scope), &dek, scope, &aad_id)?;
            tx.execute(
                "UPDATE credentials SET wrapped_dek = ?1, dek_nonce = ?2 WHERE id = ?3",
                params![new_wrapped.as_slice(), new_nonce.as_slice(), id],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            count += 1;
        }
        Ok(count)
    }

    /// ADR 198 Part B / D5 — re-wrap every enveloped persona-secret DEK under
    /// the new Interactive MEK (only called when the Interactive MEK changed).
    /// A persona row with NULL wrap columns has no at-rest secret under the
    /// MEK and is skipped. Returns the number of persona secrets re-wrapped.
    fn rewrap_personas_in_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        new_vault: &Vault,
    ) -> Result<u64, VaultError> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT id, private_key_dek_nonce, private_key_wrapped_dek FROM personas \
                     WHERE private_key_dek_nonce IS NOT NULL \
                       AND private_key_wrapped_dek IS NOT NULL",
                )
                .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            let mapped = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            let mut v = Vec::new();
            for r in mapped {
                v.push(r.map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?);
            }
            v
        };

        // ADR 206 §4 / ADR 211 AC-4 — persona-secret rows are AuthorityBearing.
        // This rewrap is a SECOND writer of the persona secret columns, one layer
        // below the `seal`/`open` ValueClass gate, so it must carry the same
        // no-MEK-recipient invariant. `rotate_mek` always derives a passphrase
        // MEK destination (`new_vault` is `AuthorityKeySource::Mek`); re-wrapping
        // a presence-custodied (KEK_s) persona DEK onto it would mint a
        // MEK-reachable copy of the persona root and SILENTLY void the §4 flip.
        // Refuse fail-closed when persona rows exist — the whole rotation tx rolls
        // back. AuthorityBearing custody is rotated through the presence/KEK_s
        // lane, never this MEK primitive. (RotateHeadless leaves the Interactive
        // key unchanged and never reaches here.)
        if !rows.is_empty() {
            new_vault.ensure_authority_bearing_source()?;
        }

        let mut count = 0u64;
        for (persona_id, dek_nonce, wrapped_dek) in rows {
            let aad_id = crate::infra::persona::persona_secret_aad_id(&persona_id);
            let dek = unwrap_dek(
                &self.interactive_key.borrow(),
                &dek_nonce,
                &wrapped_dek,
                VaultScope::Interactive,
                &aad_id,
            )?;
            let (new_nonce, new_wrapped) = wrap_dek(
                &new_vault.interactive_key.borrow(),
                &dek,
                VaultScope::Interactive,
                &aad_id,
            )?;
            tx.execute(
                "UPDATE personas SET private_key_dek_nonce = ?1, private_key_wrapped_dek = ?2 \
                 WHERE id = ?3",
                params![new_nonce.as_slice(), new_wrapped.as_slice(), persona_id],
            )
            .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
            count += 1;
        }
        Ok(count)
    }

    /// ADR 198 D1/D3 — re-wrap the bridge-CA module wrapping key under the new
    /// Interactive MEK inside the rotation tx (only when the Interactive MEK
    /// changed). Reads the current wrap DB-first then file-fallback, unwraps
    /// the module key under the OLD MEK, re-seals it under the NEW MEK, and
    /// commits the new `SealedEnvelope` blob to `vault_meta.bridge_ca_wrapped`.
    /// The module-key VALUE is unchanged, so `bridge_ca.sealed` (sealed under
    /// the module key, not the MEK) still opens. No-op when no bridge CA is
    /// provisioned on this host.
    fn rewrap_bridge_ca_in_tx(
        &self,
        store: &DaemonStore,
        tx: &rusqlite::Transaction<'_>,
        new_vault: &Vault,
        data_dir: &std::path::Path,
        retired_files: &mut Vec<std::path::PathBuf>,
    ) -> Result<(), VaultError> {
        let current_blob: Option<Vec<u8>> =
            match store.read_bridge_ca_wrap().map_err(VaultError::Store)? {
                Some(b) => Some(b),
                None => {
                    let file = data_dir.join("bridge_ca.wrap");
                    std::fs::read(&file).ok()
                }
            };
        let Some(blob) = current_blob else {
            // No bridge CA on this host — nothing to re-wrap.
            return Ok(());
        };
        let env = SealedEnvelope::from_blob(&blob).map_err(|e| {
            VaultError::Crypto(format!("bridge-ca wrap blob parse during rotation: {e}"))
        })?;
        // Unwrap under the OLD key (`self`), re-seal under the NEW (`new_vault`).
        // bridge-CA is DaemonOperational (autonomous headless key, ADR 206 §4),
        // so both legs route through that class. Module key held in `Zeroizing`
        // so it is scrubbed.
        let module_key = self.open(
            ValueClass::DaemonOperational,
            crate::trust::bridge_ca::BRIDGE_CA_MODULE_KEY_AAD_ID,
            &env,
        )?;
        let new_env = new_vault.seal(
            ValueClass::DaemonOperational,
            crate::trust::bridge_ca::BRIDGE_CA_MODULE_KEY_AAD_ID,
            &module_key,
        )?;
        tx.execute(
            "UPDATE vault_meta SET bridge_ca_wrapped = ?1 WHERE id = 1",
            params![new_env.to_blob()],
        )
        .map_err(|e| VaultError::Store(StoreError::Sqlite(e)))?;
        retired_files.push(data_dir.join("bridge_ca.wrap"));
        Ok(())
    }
}

// sealed_mek_blob_format_landed
//
// Sealed-blob
// wire format + argon2id-KEK-wrapped MEK. Daemon-side substrate for
// vault export/import (the CLI surface lands in a later slice).
//
// Wire format v2 (little-endian) — ADR 198 (bumped from v1; the at-rest
// vault this MEK unlocks is now an MEK→DEK envelope, so the version
// records the enveloped shape and import is v2-only):
//
//   magic:       4B  = b"EMVS"           ("Ember MEK Vault Sealed")
//   version:     2B  = 0x0002 (LE u16)
//   kdf_id:      1B  = 0x01 (argon2id)
//   aead_id:     1B  = 0x01 (xchacha20-poly1305)
//   salt_len:    1B  = 32
//   salt:        32B
//   argon2_ops:  4B  (LE u32; min 3)
//   argon2_mem:  4B  (LE u32 KiB; min 65536)
//   argon2_par:  1B  (default 1)
//   nonce_len:   1B  = 24
//   nonce:       24B (xchacha20 nonce)
//   fp_len:      1B
//   fingerprint: <fp_len>B (BLAKE3-32 hex string, matches vault_meta.mek_fingerprint)
//   ct_len:      4B  (LE u32)
//   ciphertext:  <ct_len>B (AEAD(KEK, nonce, MEK))
//
// The KEK is derived from the operator passphrase via Argon2id over the
// embedded salt with the embedded cost parameters. Refuses on bad
// magic, unknown version, unknown kdf_id/aead_id, fingerprint mismatch,
// AEAD tag failure, or any length/encoding violation.

/// Sealed-blob format constants — pinned at compile time so the wire
/// format is locked. Bumping the version requires explicit migration
/// logic.
pub(crate) const SEALED_BLOB_MAGIC: [u8; 4] = *b"EMVS";
/// Sealed-blob format version (LE u16). Future format breaks bump this.
///
/// ADR 198 — bumped to v2 (`0x0002`) when the at-rest shape became the
/// MEK→DEK envelope. The sealed blob still carries the MEK bytes (the
/// MEK is what unwraps every per-row DEK); the version bump records that
/// the vault this MEK unlocks is an enveloped vault, so a v2 backup of
/// (sealed-MEK blob + enveloped daemon.db) round-trips coherently. The
/// committed import path is v2-only — the operator re-exports the one
/// dev0 vault as a v2 backup after the out-of-tree S6a migration (D2),
/// so no v1 import path is committed.
pub(crate) const SEALED_BLOB_VERSION: u16 = 0x0002;
/// KDF identifier for argon2id.
pub(crate) const SEALED_BLOB_KDF_ARGON2ID: u8 = 0x01;
/// AEAD identifier for XChaCha20-Poly1305.
pub(crate) const SEALED_BLOB_AEAD_XCHACHA20POLY1305: u8 = 0x01;
/// Fixed salt length for the embedded argon2id salt (bytes).
pub(crate) const SEALED_BLOB_SALT_LEN: u8 = 32;
/// Fixed nonce length for XChaCha20-Poly1305 (bytes).
pub(crate) const SEALED_BLOB_NONCE_LEN: u8 = 24;
/// Default argon2id ops parameter (interactive). Minimum per the format.
pub(crate) const SEALED_BLOB_ARGON2_OPS_DEFAULT: u32 = 3;
/// Default argon2id memory parameter in KiB (interactive, 64 MiB).
pub(crate) const SEALED_BLOB_ARGON2_MEM_KIB_DEFAULT: u32 = 65536;
/// Default argon2id parallelism factor.
pub(crate) const SEALED_BLOB_ARGON2_PAR_DEFAULT: u8 = 1;
/// Minimum permitted argon2id ops (refuse to import below this).
pub(crate) const SEALED_BLOB_ARGON2_OPS_MIN: u32 = 3;
/// Minimum permitted argon2id memory in KiB (refuse to import below this).
pub(crate) const SEALED_BLOB_ARGON2_MEM_KIB_MIN: u32 = 65536;

/// Derive a 32-byte KEK from a passphrase + salt + argon2id cost
/// parameters. Used by both `export_mek_sealed` (to wrap the MEK) and
/// `import_mek_sealed` (to unwrap it). The output is wrapped in
/// `Zeroizing` so the KEK is overwritten on drop — the unwrap path
/// borrows the bytes into the AEAD cipher and then drops the wrapper.
fn derive_sealed_kek(
    passphrase: &str,
    salt: &[u8],
    ops: u32,
    mem_kib: u32,
    par: u8,
) -> Result<zeroize::Zeroizing<[u8; 32]>, VaultError> {
    let params = argon2::Params::new(mem_kib, ops, par as u32, Some(32))
        .map_err(|e| VaultError::SealedBlobInvalid(format!("argon2 params invalid: {e}")))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kek = zeroize::Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| VaultError::SealedBlobInvalid(format!("argon2 derive failed: {e}")))?;
    Ok(kek)
}

/// Compute the canonical MEK fingerprint — `blake3(MEK_bytes).hex()`.
/// Matches `vault_meta.mek_fingerprint` (Slice B). Exposed here so
/// callers building a sealed blob (`ember vault export --sealed`) can
/// pass the same fingerprint they will record on import.
pub fn mek_fingerprint_hex(mek: &[u8]) -> String {
    hex::encode(blake3::hash(mek).as_bytes())
}

/// Sealed export of the live MEK. Wraps `mek` under an argon2id-derived
/// KEK from `passphrase` using XChaCha20-Poly1305 AEAD. The returned
/// blob is the v1 wire format documented above. `plaintext_fingerprint`
/// MUST equal `mek_fingerprint_hex(mek)` — the caller is expected to
/// pass the same fingerprint recorded in `vault_meta.mek_fingerprint`,
/// and this function refuses on mismatch so an inconsistent blob is
/// never produced.
pub fn export_mek_sealed(
    mek: &[u8],
    passphrase: &str,
    plaintext_fingerprint: &str,
) -> Result<Vec<u8>, VaultError> {
    if mek.is_empty() {
        return Err(VaultError::SealedBlobInvalid(
            "MEK bytes are empty".to_string(),
        ));
    }
    let expected_fp = mek_fingerprint_hex(mek);
    if expected_fp != plaintext_fingerprint {
        return Err(VaultError::SealedBlobFingerprintMismatch {
            expected: expected_fp,
            actual: plaintext_fingerprint.to_string(),
        });
    }
    if plaintext_fingerprint.len() > u8::MAX as usize {
        return Err(VaultError::SealedBlobInvalid(format!(
            "fingerprint too long: {} bytes (max {})",
            plaintext_fingerprint.len(),
            u8::MAX
        )));
    }

    // Fresh salt + nonce for every export. Each call produces a distinct
    // ciphertext even for the same (MEK, passphrase).
    let mut salt = [0u8; SEALED_BLOB_SALT_LEN as usize];
    getrandom::fill(&mut salt).expect("OS entropy failure");
    let mut nonce_bytes = [0u8; SEALED_BLOB_NONCE_LEN as usize];
    getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");

    let ops = SEALED_BLOB_ARGON2_OPS_DEFAULT;
    let mem_kib = SEALED_BLOB_ARGON2_MEM_KIB_DEFAULT;
    let par = SEALED_BLOB_ARGON2_PAR_DEFAULT;

    let kek = derive_sealed_kek(passphrase, &salt, ops, mem_kib, par)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_slice())
        .map_err(|e| VaultError::SealedBlobInvalid(format!("AEAD key init failed: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, mek)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    if ciphertext.len() > u32::MAX as usize {
        return Err(VaultError::SealedBlobInvalid(format!(
            "ciphertext too long: {} bytes (max u32)",
            ciphertext.len()
        )));
    }

    // Assemble the wire format. The capacity reserve is tight — every
    // field length is known up front.
    let fp_bytes = plaintext_fingerprint.as_bytes();
    let mut out = Vec::with_capacity(
        4 + 2
            + 1
            + 1
            + 1
            + SEALED_BLOB_SALT_LEN as usize
            + 4
            + 4
            + 1
            + 1
            + SEALED_BLOB_NONCE_LEN as usize
            + 1
            + fp_bytes.len()
            + 4
            + ciphertext.len(),
    );
    out.extend_from_slice(&SEALED_BLOB_MAGIC);
    out.extend_from_slice(&SEALED_BLOB_VERSION.to_le_bytes());
    out.push(SEALED_BLOB_KDF_ARGON2ID);
    out.push(SEALED_BLOB_AEAD_XCHACHA20POLY1305);
    out.push(SEALED_BLOB_SALT_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ops.to_le_bytes());
    out.extend_from_slice(&mem_kib.to_le_bytes());
    out.push(par);
    out.push(SEALED_BLOB_NONCE_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.push(fp_bytes.len() as u8);
    out.extend_from_slice(fp_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Cursor-style reader over a sealed blob. Bounds-checked: every `take`
/// returns `Err(VaultError::SealedBlobTruncated)` rather than panicking
/// when the blob is shorter than expected.
struct SealedBlobReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SealedBlobReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            VaultError::SealedBlobInvalid("length overflow while reading blob".to_string())
        })?;
        if end > self.buf.len() {
            return Err(VaultError::SealedBlobTruncated {
                need: end,
                have: self.buf.len(),
            });
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, VaultError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16_le(&mut self) -> Result<u16, VaultError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn take_u32_le(&mut self) -> Result<u32, VaultError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// Verifies + unwraps a sealed blob. Returns the MEK bytes on success.
/// `expected_fingerprint` MUST equal the fingerprint embedded in the
/// blob; this is a defence-in-depth check so a caller that has a
/// fingerprint commitment (e.g. from `vault_meta`) cannot accept a blob
/// that decrypts to a different MEK than they expect. The recovered
/// MEK is also re-fingerprinted post-decrypt and checked against the
/// same value — so a tampered fingerprint field still cannot smuggle a
/// substituted MEK past the import.
///
/// **Rotation-witness hook (anchor: `rotation_witness_emitted_at_mek_rotation`):**
/// The caller of `import_mek_sealed` is responsible for invoking
/// [`emit_identity_rotation_witness`] BEFORE the prior identity key is
/// zeroized, so the chain-walking
/// `verify_receipt_v2_with_rotation_chain` verifier (Slice E3) can
/// thread a pre-rotation trust anchor forward across the rotation.
/// `import_mek_sealed` itself is a low-level blob-unwrap primitive
/// without access to a `DaemonStore` or the prior `DaemonPersona`, so
/// the actual emission lives at the rotation-aware caller. See
/// [`emit_identity_rotation_witness`] for the canonical emit-side
/// contract and the M3 / explicit-rotation-RPC hook point.
pub fn import_mek_sealed(
    blob: &[u8],
    passphrase: &str,
    expected_fingerprint: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, VaultError> {
    let mut r = SealedBlobReader::new(blob);

    let magic = r.take(4)?;
    if magic != SEALED_BLOB_MAGIC {
        return Err(VaultError::SealedBlobBadMagic {
            got: [magic[0], magic[1], magic[2], magic[3]],
        });
    }

    let version = r.take_u16_le()?;
    if version != SEALED_BLOB_VERSION {
        return Err(VaultError::SealedBlobUnknownVersion { got: version });
    }

    let kdf_id = r.take_u8()?;
    if kdf_id != SEALED_BLOB_KDF_ARGON2ID {
        return Err(VaultError::SealedBlobUnknownKdf { got: kdf_id });
    }

    let aead_id = r.take_u8()?;
    if aead_id != SEALED_BLOB_AEAD_XCHACHA20POLY1305 {
        return Err(VaultError::SealedBlobUnknownAead { got: aead_id });
    }

    let salt_len = r.take_u8()?;
    if salt_len != SEALED_BLOB_SALT_LEN {
        return Err(VaultError::SealedBlobInvalid(format!(
            "unexpected salt_len: {salt_len} (expected {})",
            SEALED_BLOB_SALT_LEN
        )));
    }
    let salt = r.take(salt_len as usize)?.to_vec();

    let ops = r.take_u32_le()?;
    if ops < SEALED_BLOB_ARGON2_OPS_MIN {
        return Err(VaultError::SealedBlobInvalid(format!(
            "argon2 ops below minimum: {ops} (min {})",
            SEALED_BLOB_ARGON2_OPS_MIN
        )));
    }

    let mem_kib = r.take_u32_le()?;
    if mem_kib < SEALED_BLOB_ARGON2_MEM_KIB_MIN {
        return Err(VaultError::SealedBlobInvalid(format!(
            "argon2 mem_kib below minimum: {mem_kib} (min {})",
            SEALED_BLOB_ARGON2_MEM_KIB_MIN
        )));
    }

    let par = r.take_u8()?;
    if par == 0 {
        return Err(VaultError::SealedBlobInvalid(
            "argon2 parallelism is zero".to_string(),
        ));
    }

    let nonce_len = r.take_u8()?;
    if nonce_len != SEALED_BLOB_NONCE_LEN {
        return Err(VaultError::SealedBlobInvalid(format!(
            "unexpected nonce_len: {nonce_len} (expected {})",
            SEALED_BLOB_NONCE_LEN
        )));
    }
    let nonce_bytes = r.take(nonce_len as usize)?.to_vec();

    let fp_len = r.take_u8()? as usize;
    let fp_bytes = r.take(fp_len)?;
    let fingerprint = std::str::from_utf8(fp_bytes)
        .map_err(|e| VaultError::SealedBlobInvalid(format!("fingerprint is not valid UTF-8: {e}")))?
        .to_string();
    if fingerprint != expected_fingerprint {
        return Err(VaultError::SealedBlobFingerprintMismatch {
            expected: expected_fingerprint.to_string(),
            actual: fingerprint,
        });
    }

    let ct_len = r.take_u32_le()? as usize;
    let ciphertext = r.take(ct_len)?.to_vec();
    if r.remaining() != 0 {
        return Err(VaultError::SealedBlobInvalid(format!(
            "trailing bytes after ciphertext: {} byte(s)",
            r.remaining()
        )));
    }

    let kek = derive_sealed_kek(passphrase, &salt, ops, mem_kib, par)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_slice())
        .map_err(|e| VaultError::SealedBlobInvalid(format!("AEAD key init failed: {e}")))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| VaultError::SealedBlobAeadFailure)?;

    // Defence in depth: re-fingerprint the recovered MEK and confirm it
    // still matches `expected_fingerprint`. A tampered fingerprint field
    // that happens to match the caller-supplied value would have passed
    // the embedded check above, but if the AEAD also tampered (or if a
    // future format change accidentally decoupled fingerprint from MEK),
    // this catches it.
    let recovered_fp = mek_fingerprint_hex(&plaintext);
    if recovered_fp != expected_fingerprint {
        return Err(VaultError::SealedBlobFingerprintMismatch {
            expected: expected_fingerprint.to_string(),
            actual: recovered_fp,
        });
    }

    Ok(zeroize::Zeroizing::new(plaintext))
}

// Daemon emit-witness:
// rotation_witness_emitted_at_mek_rotation
//
// At every identity-key rotation point (today: alongside the MEK
// rotation flow that runs through `import_mek_sealed`; tomorrow:
// alongside any explicit `vault.rotate` / `identity.rotate` RPC the
// daemon grows under M3 of the umbrella task), the daemon emits an
// `IdentityRotationWitness` Receipt v2 envelope bridging the prior and
// new identity-key epochs. The witness envelope is signed by the PRIOR
// identity key over the new identity's public key, so a verifier
// holding only the pre-rotation trust anchor can still verify Receipts
// minted by the post-rotation identity via Slice E3's chain-walking
// `verify_receipt_v2_with_rotation_chain`.
//
// Call site discipline:
// - This is the canonical emit-side; the caller MUST invoke this
//   function BEFORE zeroizing or replacing the prior identity key, as
//   the witness signature requires the prior key's live signing
//   material.
// - The signing path routes through `sign_receipt_v2` (the only
//   canonical Receipt v2 signer per `.claude/rules/daemon.md`); no
//   inline blake3 / JCS / signature assembly is permitted.
// - The body matches Slice E1's `IdentityRotationWitnessBody` shape
//   (`prev_epoch_root_id`, `next_epoch_root_id`, `rotated_at_epoch_secs`,
//   `signature_by_prev_root`, `signature_by_next_root`, optional
//   `rotation_reason`).
// - The signed envelope is persisted via
//   `DaemonStore::store_identity_rotation_witness_receipt` so the
//   witness survives a daemon restart and the chain-walk verifier can
//   reassemble it from the local Receipt store.
//
// Where M3's explicit-rotation RPC will hook this: when the umbrella
// grows a dedicated `identity.rotate` / `vault.rotate` RPC, that
// handler MUST call `emit_identity_rotation_witness` immediately
// after deriving the new identity but BEFORE the prior key's Drop
// scrubs the signing material. The MEK-import path
// (`import_mek_sealed` above) is the substrate for today's recovery
// flow; the witness emission belongs at the rotation-aware caller
// (which has both the prior signer and the new identity public key
// in hand), not inside `import_mek_sealed` itself — that function is
// a low-level blob-unwrap primitive without access to a `DaemonStore`
// or the prior `DaemonPersona`. Documented here so future authors of
// `import_mek_sealed` callers know the contract.

/// Emit an `IdentityRotationWitness` Receipt v2 envelope bridging the
/// prior and new identity-key epochs at MEK / identity rotation time.
///
/// **Pre:**
/// - `prior_signer` is the soon-to-be-retired identity key and is
///   still alive (NOT yet zeroized) — its signing material is required
///   to mint the outer envelope signature.
/// - `new_identity_pub` is the new identity's verifying key (the key
///   that will sign Receipts after this rotation).
/// - The prior signer's public key MUST differ from
///   `new_identity_pub` (a "rotation" between equal keys is not a
///   rotation and would defeat the chain-continuity property).
///
/// **Post:**
/// - A signed `ReceiptEnvelope` is returned with
///   `kind == RECEIPT_KIND_IDENTITY_ROTATION_WITNESS`, `receipt_id`
///   populated by `sign_receipt_v2`, and a non-empty
///   `signature` field.
/// - The envelope has been persisted into the daemon's local Receipt
///   store (`receipts` table) via
///   `DaemonStore::store_identity_rotation_witness_receipt`.
/// - The body matches Slice E1's `IdentityRotationWitnessBody` shape;
///   the body's `signature_by_prev_root` is the prior signer's
///   Ed25519 signature over the new identity's raw 32-byte public key
///   bytes (the explicit "prior co-signs over the new identity"
///   attestation the brief calls out), while `signature_by_next_root`
///   is a deterministic non-empty placeholder because the new
///   identity is not yet active and cannot co-sign at rotation time —
///   the chain-walk verifier checks only the outer envelope signature
///   (Slice E3's `verify_receipt_v2_with_rotation_chain` per the
///   algorithm in `core_events::receipt::sign`), so body-level inner
///   signatures are advisory metadata rather than part of the
///   chain-walk trust check.
///
/// **Errors:**
/// - `VaultError::WitnessEmit(_)` when `sign_receipt_v2` fails
///   (canonicalize / serialize), or when the prior signer's
///   `public_key()` is malformed (cannot recover its raw bytes for
///   the `daemon_root_id` field).
/// - `VaultError::Store(_)` when the persistence step fails.
pub fn emit_identity_rotation_witness(
    store: &DaemonStore,
    prior_signer: &dyn Signer,
    new_identity_pub: &VerifyingKey,
    rotation_at: DateTime<Utc>,
) -> Result<ReceiptEnvelope, VaultError> {
    // Epoch root IDs: hex-encoded 32-byte verifying keys. Stable across
    // restarts and recoverable from the public key handle the daemon
    // already publishes via `GET /daemon/identity.json`, so the
    // chain-walk consumer can correlate body epoch IDs back to the
    // `RotationWitnessEntry::prior_identity_pub` /
    // `new_identity_pub` keys it carries alongside the envelope.
    let prior_pub_handle = prior_signer.public_key();
    let prior_epoch_root_id = strip_ed25519_prefix(&prior_pub_handle.0).ok_or_else(|| {
        VaultError::WitnessEmit(format!(
            "prior signer public_key handle '{}' missing expected 'ed25519:' prefix",
            prior_pub_handle.0
        ))
    })?;
    let new_pub_bytes = new_identity_pub.to_bytes();
    let new_epoch_root_id = hex::encode(new_pub_bytes);

    // Defence in depth: refuse to emit a witness when the prior and
    // new epoch roots are identical — that is not a rotation and would
    // also fail Slice E1's `IdentityRotationWitnessBody::validate()`.
    if prior_epoch_root_id == new_epoch_root_id {
        return Err(VaultError::WitnessEmit(
            "prior and new identity public keys are identical — \
             rotation between equal epochs is rejected"
                .to_string(),
        ));
    }

    // The "prior co-signs over the new identity's public key" claim
    // the brief mentions: the prior signer signs the new pub key's
    // raw 32 bytes. The chain-walker does not inspect this field
    // (only the outer envelope signature), but the body carries it so
    // future offline auditors can re-prove the rotation independently.
    let sig_by_prev = prior_signer.sign(&new_pub_bytes);
    let signature_by_prev_root = sig_by_prev.0;

    // The new identity is not yet active and cannot co-sign at
    // rotation time. Slice E1's `validate()` requires this field be
    // non-empty; an explicit placeholder distinguishes "no co-sign
    // yet" from "co-signed by zero" and matches the precedent in the
    // chain-walk tests at
    // `core-events/src/receipt/sign.rs::witness_envelope`.
    let signature_by_next_root = "ed25519sig:pending-next-root-cosign".to_string();

    let rotated_at_epoch_secs: u64 = rotation_at.timestamp().try_into().map_err(|_| {
        VaultError::WitnessEmit(format!(
            "rotation_at timestamp {} is negative — cannot encode as u64 epoch seconds",
            rotation_at.timestamp(),
        ))
    })?;

    let body = serde_json::json!({
        "prev_epoch_root_id": prior_epoch_root_id,
        "next_epoch_root_id": new_epoch_root_id,
        "rotated_at_epoch_secs": rotated_at_epoch_secs,
        "signature_by_prev_root": signature_by_prev_root,
        "signature_by_next_root": signature_by_next_root,
        "rotation_reason": "mek_rotation",
    });

    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: core_events::receipt::RECEIPT_KIND_IDENTITY_ROTATION_WITNESS.to_string(),
        receipt_id: String::new(),
        // daemon_root_id: the prior epoch's root id — mirrors the
        // chain-walk test fixture's convention at
        // `core-events/src/receipt/sign.rs::witness_envelope` and
        // anchors the envelope to the epoch whose signer minted it.
        daemon_root_id: prior_epoch_root_id.clone(),
        traceparent: None,
        // The daemon (acting as Persona) terminates this Receipt — it
        // is a daemon-emitted attestation, not a user-session lifecycle
        // event.
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };

    // Canonical builder — no inline crypto. Populates `receipt_id`
    // and `signature` on `envelope` in place.
    sign_receipt_v2(&mut envelope, prior_signer)?;

    store.store_identity_rotation_witness_receipt(&envelope)?;

    info!(
        receipt_id = %envelope.receipt_id,
        prev_epoch_root_id = %prior_epoch_root_id,
        new_epoch_root_id = %new_epoch_root_id,
        rotated_at = %rotation_at.to_rfc3339(),
        "identity rotation witness emitted"
    );

    Ok(envelope)
}

/// Strip the `ed25519:` wire-form prefix from a `core_crypto::PublicKey`
/// handle, returning the underlying 64-character hex string. Returns
/// `None` when the prefix is absent so the caller can surface a clear
/// error rather than silently propagating a malformed identifier into a
/// signed Receipt body.
fn strip_ed25519_prefix(handle: &str) -> Option<String> {
    handle.strip_prefix("ed25519:").map(|s| s.to_string())
}

// ADR 216 S4 dead-code deletion: the direct-SE unseal functions
// (`try_se_unseal`, `se_unseal_interactive`, `se_unseal_with_presence`,
// `AutoUnsealOutcome`, `try_auto_unseal_from_keyring`) have been removed.
// The daemon's vault MEK and lease-KEK are now unlocked exclusively via
// the double-envelope path (`vault.de_unlock_complete` RPC). The outer SE
// envelope is peeled by the CLI in the Aqua/501 domain; the inner DWK
// envelope is peeled by the daemon at uid=450. See ADR 216 S1/S3.

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
) -> Result<Option<Zeroizing<String>>, VaultError> {
    // N6: returns Zeroizing<String> so the operator passphrase zeroizes
    // on drop. The keychain/vault_macos sub-helpers still hand back bare
    // String — we wrap at receipt so the new heap allocation in this
    // frame zeroizes. (Threading Zeroizing through `keyring_core::Entry`
    // and `vault_macos::get_password_user_presence` is a separate
    // follow-up; the leftover residue is inside those helpers' return
    // paths, not in callers of THIS function.)

    // 1. Environment variable — capture then immediately zeroize from the
    // process environment so it cannot be read from /proc/<pid>/environ
    // by a second party after this point. Done before any background threads
    // are running (called during daemon startup), so the signal/thread race
    // in remove_var is acceptable.
    // Safety: single-threaded startup path; no other threads are reading env.
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
        return Ok(Some(Zeroizing::new(p)));
    }

    // 2. Test gate — same three-axis check as `resolve_passphrase`.
    if cfg!(test) || vault_mock_env_enabled() || is_cargo_test_binary() {
        // In test mode, only return a passphrase if the test has explicitly
        // signaled "keyring entry exists" via `EMBER_VAULT_TEST_KEYRING_PRESENT=1`.
        // Otherwise return None so tests can exercise the NoKeyringEntry path.
        if std::env::var("EMBER_VAULT_TEST_KEYRING_PRESENT").is_ok() {
            return Ok(Some(Zeroizing::new(format!(
                "test-passphrase-{service}-{account}"
            ))));
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
        // `vault_macos::get_password_user_presence` already returns
        // `Zeroizing<String>` (N6-deeper item 3) — no extra wrap needed.
        return crate::infra::vault_macos::get_password_user_presence(service, account)
            .map_err(VaultError::Keyring);
    }

    // 4. System keyring lookup — read-only, no provisioning. Wrap at the
    // `keyring_core::Entry::get_password()` boundary so the bare `String`
    // returned by the third-party crate never escapes into a longer-lived
    // local (N6-deeper item 3).
    let entry = keyring_core::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("init: {e}")))?;
    match entry.get_password().map(Zeroizing::new) {
        Ok(p) => Ok(Some(p)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Keyring(format!("read: {e}"))),
    }
}

/// ADR 198 D5 — resolve the CURRENT operator vault passphrase for a rotation,
/// using the SAME posture order `open_from_config` uses so the rotation
/// resolves the passphrase the daemon actually opened the vault with.
///
/// **CRITICAL (separate-uid posture):** in the ADR 131 separate-uid production
/// posture the passphrase comes from the SE-wrapped `vault-mek.bin` blob, NOT a
/// Touch-ID keychain entry. A keychain-only resolver
/// (`resolve_passphrase_no_provision`) returns `None` there and would break
/// rotation on the real production daemon with "no operator passphrase entry".
/// Order: `EMBER_VAULT_PASSPHRASE` → separate-uid SE blob → runtime-reopen cache
/// → keychain/keyring. Returns `None` only when no source has it (genuine
/// needs-init).
pub(crate) fn resolve_current_vault_passphrase(
    config: &DaemonConfig,
) -> Result<Option<Zeroizing<String>>, VaultError> {
    // N6: returns Zeroizing<String> so the operator passphrase zeroizes
    // on drop. Callers pass &pass (Deref -> &str) into rotate_mek and the
    // keychain helpers, which themselves take &str.
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        return Ok(Some(Zeroizing::new(p)));
    }
    // SE custody: no passphrase concept — the interactive key is SE-wrapped.
    // Rotation under SE custody is a separate flow (not passphrase-based).
    #[cfg(target_os = "macos")]
    if vault_passphrase_is_se_wrapped() {
        return Ok(None);
    }
    if let Some(p) = runtime_reopen_passphrase(&config.data_dir) {
        return Ok(Some(p));
    }
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);
    resolve_passphrase_no_provision(&service, &account)
}

/// ADR 198 D5 — true when the daemon opens its vault via the ADR 131
/// separate-uid SE-wrapped MEK blob (`vault-mek.bin`) rather than a keychain
/// passphrase. `change_passphrase` rotation is NOT supported in this posture
/// (the new passphrase would have to be re-wrapped under the Secure Enclave,
/// not written to the keychain via `set_vault_passphrase`), so the rotation
/// handler refuses `change_passphrase` here rather than silently desyncing the
/// SE blob from the rotated MEK. `rekey` and `rotate_headless` are unaffected —
/// they keep the same operator secret and only change the salt / headless key.
pub(crate) fn vault_passphrase_is_se_wrapped() -> bool {
    // Test-only override so the rotation handler's separate-uid
    // change_passphrase refusal is exercisable (the real detection reads the
    // effective uid's home dir, which is never /var/empty under cargo test).
    if cfg!(test) && std::env::var("EMBER_VAULT_TEST_FORCE_SE_POSTURE").is_ok() {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        !is_cargo_test_binary()
            && std::env::var("EMBER_VAULT_PASSPHRASE").is_err()
            && is_separate_uid_posture()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
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
/// This migrates a pre-existing MEK entry created before the macOS
/// biometric ACL shipped so subsequent vault operations
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
                Ok(Some(_passphrase)) => {
                    // _passphrase is `Zeroizing<String>` (N6-deeper item 3);
                    // it zeroizes on drop at the end of this arm.
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

            // Read via the plain system keyring (pre-migration ACL). Wrap
            // at the `keyring_core` boundary so the bare `String` returned
            // by the third-party crate never escapes the call expression
            // (N6-deeper item 3).
            let passphrase = {
                let entry = keyring_core::Entry::new(service, account)
                    .map_err(|e| VaultError::Keyring(format!("migrate: init: {e}")))?;
                match entry.get_password().map(Zeroizing::new) {
                    Ok(p) => p,
                    Err(keyring_core::Error::NoEntry) => {
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
                let entry = keyring_core::Entry::new(service, account)
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

/// True when the daemon is running under the ADR 131 separate-uid posture
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
pub(crate) fn is_separate_uid_posture() -> bool {
    // Read the daemon's effective uid's passwd entry directly, NOT the
    // `HOME` env var. The launchd plist injects HOME=<operator_home>
    // (see install.rs::render_launchd_plist_body), so any env-var-based
    // home resolution would see the operator's home and miss the
    // /var/empty checkpoint that signals the ADR 131 separate-uid posture.
    // Per adversarial review (P0-B).
    //
    // The Ok(None) and Err(e) arms both return false but log distinctly
    // so an operator debugging "why did the daemon land on the keychain
    // branch instead of SE?" can tell apart a provisioning race (uid
    // exists in kernel but passwd entry not yet written) from a real
    // passwd-database I/O failure. Per self-review P2-1.
    //
    // All three P2
    // findings from the 2026-05-13 self-review are now closed.
    // P2-1 (this site): Ok(None) / Err distinguished above.
    // P2-2: TOCTOU on file-based MEK blob — obviated by the
    //   System.keychain migration in vault_macos_se.rs (no filesystem
    //   read of the MEK blob remains).
    // P2-3: error-category asymmetry — addressed during the keychain
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

#[cfg(not(ember_release))]
pub fn vault_mock_env_enabled() -> bool {
    std::env::var("EMBER_VAULT_MOCK").is_ok()
}

#[cfg(ember_release)]
pub fn vault_mock_env_enabled() -> bool {
    false
}

#[cfg(not(ember_release))]
pub fn vault_dev_mode_env_enabled() -> bool {
    matches!(std::env::var("EMBER_VAULT_DEV_MODE").as_deref(), Ok("1"))
}

#[cfg(ember_release)]
pub fn vault_dev_mode_env_enabled() -> bool {
    false
}

/// True when raw keyring writes must be suppressed: a cargo test binary is
/// running, or the `EMBER_VAULT_MOCK` opt-out is set. Downstream callers
/// (e.g., `ember init` in `emberlink-cli`) must consult this before
/// invoking `keyring_core::Entry::new(...).set_password(...)` directly — the
/// three-axis gate that lives inside `resolve_passphrase` does not cover
/// raw keyring access, and missing it was the leak that fired real
/// keychain popups from the emberlink-cli test suite on 2026-04-22.
pub fn keyring_writes_suppressed() -> bool {
    vault_mock_env_enabled() || is_cargo_test_binary()
}

pub fn verify_keyring_roundtrip(
    service: &str,
    account: &str,
    expected: &str,
) -> Result<(), VaultError> {
    // Test gate — skip the real-keychain verification step under the same
    // conditions that suppress keyring access in resolve_passphrase above.
    if cfg!(test) || vault_mock_env_enabled() || is_cargo_test_binary() {
        return Ok(());
    }
    let verify_entry = keyring_core::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("verify: {e}")))?;
    // Wrap at the `keyring_core::Entry::get_password()` boundary so the
    // round-trip read never lives as a bare `String` (N6-deeper item 3).
    let read_back = Zeroizing::new(
        verify_entry
            .get_password()
            .map_err(|e| VaultError::Keyring(format!("verify read: {e}")))?,
    );
    if *read_back != *expected {
        return Err(VaultError::Keyring(
            "roundtrip mismatch — keyring backend may be mock (missing platform features)"
                .to_string(),
        ));
    }
    Ok(())
}

fn resolve_passphrase(service: &str, account: &str) -> Result<Zeroizing<String>, VaultError> {
    // 1. Environment variable — capture then immediately zeroize from the
    // process environment so it cannot be read from /proc/<pid>/environ
    // by a second party after this point. Done before any background threads
    // are running (called during daemon startup), so the signal/thread race
    // in remove_var is acceptable.
    // Safety: single-threaded startup path; no other threads are reading env.
    if let Ok(p) = std::env::var("EMBER_VAULT_PASSPHRASE") {
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
        return Ok(Zeroizing::new(p));
    }

    // 1b. Test gate — suppress real keychain access. Without this, `cargo test`
    // on macOS triggers a modal "keychain wants access" dialog for every test
    // that opens a Vault. The earlier version only checked `cfg!(test)`, but
    // that's false when ember-daemon is linked as a dep in integration tests
    // (tests/*.rs) or from another crate's tests (emberlink-cli, workers).
    // Now also detects cargo test binaries by their install path: cargo runs
    // tests from `target/<profile>/deps/<name>-<hash>`, so any process whose
    // current_exe contains `/target/` + `/deps/` is a test binary.
    if cfg!(test) || vault_mock_env_enabled() || is_cargo_test_binary() {
        tracing::debug!(
            service = service,
            account = account,
            "vault: returning deterministic test passphrase (cfg!(test) or EMBER_VAULT_MOCK or cargo test binary detected)"
        );
        return Ok(Zeroizing::new(format!(
            "test-passphrase-{service}-{account}"
        )));
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
                let p = Zeroizing::new(generate_passphrase());
                crate::infra::vault_macos::set_password_user_presence(service, account, &p)
                    .map_err(VaultError::Keyring)?;
                info!(
                    "generated and stored vault passphrase in macOS Keychain with kSecAttrAccessControl=BiometryAny|Or|DevicePasscode"
                );
                return Ok(p);
            }
        }
    }

    // 3. System keyring (non-macOS, or macOS dev/QA service name). Wrap at
    // the `keyring_core::Entry::get_password()` boundary so the bare `String`
    // returned by the third-party crate never escapes the call expression.
    let entry = keyring_core::Entry::new(service, account)
        .map_err(|e| VaultError::Keyring(format!("init: {e}")))?;

    match entry.get_password().map(Zeroizing::new) {
        Ok(p) => Ok(p),
        Err(keyring_core::Error::NoEntry) => {
            // 4. Generate and store a random passphrase, then verify cross-handle read-back
            let p = Zeroizing::new(generate_passphrase());
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

/// ADR 198 D5 — overwrite the operator vault passphrase in the platform
/// secret store. This is the `change_passphrase` rotation mode's post-commit
/// step (the caller invokes it AFTER `rotate_mek` commits the new
/// MEK-at-rest, so a rollback can never desync the keychain from the vault).
/// Mirrors the WRITE side of `resolve_passphrase`: macOS user-presence ACL on
/// the production service, system keyring otherwise. Honors the test gate and
/// `keyring_writes_suppressed()` so no real keychain is touched under
/// `cfg!(test)` / `EMBER_VAULT_MOCK` / cargo-test / suppressed-writes.
pub(crate) fn set_vault_passphrase(
    config: &DaemonConfig,
    passphrase: &str,
) -> Result<(), VaultError> {
    if cfg!(test)
        || vault_mock_env_enabled()
        || is_cargo_test_binary()
        || keyring_writes_suppressed()
    {
        // Test-only fault injection so the rotation handler's keychain-desync
        // failure path (adversarial review O/HIGH) is exercisable — the real
        // keychain is never touched under the test gate, so without this hook
        // the failure branch would have zero coverage.
        if cfg!(test) && std::env::var("EMBER_VAULT_TEST_KEYCHAIN_FAIL").is_ok() {
            return Err(VaultError::Keyring(
                "injected keychain failure (EMBER_VAULT_TEST_KEYCHAIN_FAIL)".to_string(),
            ));
        }
        return Ok(());
    }
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);

    #[cfg(target_os = "macos")]
    if crate::infra::vault_macos::apply_user_presence(&service, DEFAULT_KEYRING_SERVICE) {
        crate::infra::vault_macos::set_password_user_presence(&service, &account, passphrase)
            .map_err(VaultError::Keyring)?;
        return Ok(());
    }

    let entry = keyring_core::Entry::new(&service, &account)
        .map_err(|e| VaultError::Keyring(format!("change_passphrase init: {e}")))?;
    entry
        .set_password(passphrase)
        .map_err(|e| VaultError::Keyring(format!("change_passphrase store: {e}")))?;
    verify_keyring_roundtrip(&service, &account, passphrase)?;
    Ok(())
}

/// ADR 198 D3 — best-effort read of the KDF salt from
/// `<data_dir>/daemon.db`'s `vault_meta.salt` column via a read-only
/// probe connection. New vaults write the salt here (committed
/// atomically with the wrapped DEKs in a future rotation tx); a present
/// non-NULL salt is authoritative. Any failure (no DB, no column, NULL,
/// wrong length, lock contention) returns `None` so the caller falls
/// back to the `vault.salt` file sidecar — the only transitional
/// tolerance the committed code carries.
fn salt_from_vault_meta(data_dir: &std::path::Path) -> Option<[u8; 16]> {
    let db_path = data_dir.join("daemon.db");
    if !db_path.exists() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    use rusqlite::OptionalExtension as _;
    let row: Option<Option<Vec<u8>>> = conn
        .query_row("SELECT salt FROM vault_meta WHERE id = 1", [], |r| {
            r.get::<_, Option<Vec<u8>>>(0)
        })
        .optional()
        .ok()?;
    let bytes = row.flatten()?;
    bytes.try_into().ok()
}

fn vault_salt(config: &DaemonConfig) -> Result<[u8; 16], VaultError> {
    // ADR 198 D3 — prefer the DB-resident salt (atomic-rotation
    // substrate). Falls through to the file sidecar only when the DB
    // column is NULL / absent (pre-migration vault).
    if let Some(salt) = salt_from_vault_meta(&config.data_dir) {
        return Ok(salt);
    }
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

/// MEK hardening (C4): enforce Argon2 parameter pinning via a
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
/// ADR 198 D3 — the pinned Argon2 params as the same TOML body
/// `check_or_write_vault_params` writes to the `vault.params` sidecar.
/// Stored in `vault_meta.argon2_params` for new vaults so the params
/// travel in the rotation tx alongside the salt + canary.
fn vault_argon2_params_toml() -> String {
    format!(
        "[argon2]\nm = {m}\nt = {t}\np = {p}\nalg = \"{alg}\"\nver = \"{ver}\"\n",
        m = VAULT_ARGON2_M_KIB,
        t = VAULT_ARGON2_T_COST,
        p = VAULT_ARGON2_P_COST,
        alg = VAULT_ARGON2_ALG,
        ver = VAULT_ARGON2_VER,
    )
}

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
mod tests;

#[cfg(test)]
mod name_validation_tests;

#[cfg(test)]
mod key_store_tests;

#[cfg(test)]
mod sealed_blob_tests;

#[cfg(test)]
mod rotation_witness_tests;
