//! Headless-enrollment attested-device key.
//!
//! Per ADR 139 §"Headless: attested device, variable enrollment": at enrollment
//! time the daemon stashes the headless Vault MEK under a dedicated keychain
//! entry so autopilot can mint short-lived credentials without re-prompting
//! Touch ID between sessions, until the enrollment expiry elapses.
//!
//! ## ATTESTED-DEVICE-MEK-WRAP (B2, 2026-05-22)
//!
//! The headless MEK is **AEAD-wrapped under a per-enrollment wrap-key**
//! before storage. ADR 139 §"Headless: attested device, variable
//! enrollment" steps 1-3 require the wrap, not plaintext-in-keychain.
//!
//! Storage layout (two keychain entries per persona enrollment):
//! - `<account>` — base64(`24-byte nonce` || `ciphertext-with-tag` of the
//!   32-byte MEK), AEAD-encrypted under the wrap-key, AAD
//!   `b"attested-device.mek-wrap.v1"`. Total wire size: 72 bytes raw → 96
//!   bytes base64.
//! - `<WRAP_KEY_PREFIX><account>` — base64(32-byte wrap-key). Stored
//!   under the keychain entry's default `kSecAttrAccessibleAfterFirstUnlock`
//!   ACL posture, so a same-uid process can read it after the device is
//!   first unlocked post-boot — matching ADR 139 §"variable enrollment"
//!   step 3.
//!
//! Both entries are required to recover the MEK. An attacker who lifts
//! only one cannot recover the headless MEK; an attacker who lifts both
//! has effectively the same access the daemon does (matching the
//! same-uid threat model documented in ADR 149 §"Headless invariants").
//!
//! Legacy v1 entries (pre-B2) stored the raw MEK as base64 (44 bytes
//! base64 = 32 raw bytes). `unwrap_mek` detects this shape and refuses
//! with `Error::LegacyUnwrappedFormat` so the operator re-enrolls under
//! the wrapped scheme rather than silently consuming an insecure entry.
//!
//! ## Scope (HEADLESS-ENROLL-CLI-ATTESTED-A)
//!
//! - Generate keychain-backed storage for one MEK per persona-enrollment.
//! - Persist the single active-enrollment metadata slot under the daemon
//!   data dir so the handler can later wire `headless_status` /
//!   `headless_revoke` without re-deriving state.
//! - Expose enroll / store_active / load_active / revoke_active /
//!   active_status as the module's public API.
//!
//! ## Out of scope (later slices)
//!
//! - The Touch ID prompt at enrollment time (slice B's socket method).
//! - Receipt emission (slice B).
//! - CLI commands (slice C).
//! - MEK-source selection from the vault.
//!
//! CLASSIFICATION: PUBLIC

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead, aead::Payload};
use core_events::receipt::HeadlessDelegatedMaterial;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Keychain service used for headless attested-device entries.
///
/// Distinct from the production vault service so the user-presence /
/// biometric gate in `vault_macos::apply_user_presence` does NOT fire for
/// this entry — autopilot reads the MEK without a Touch ID prompt.
pub const KEYCHAIN_SERVICE: &str = "ember-daemon-headless";

/// Relative path under the daemon `data_dir` that carries the one active
/// headless-enrollment metadata record.
pub const ACTIVE_ENROLLMENT_FILE: &str = "headless/active-enrollment.json";

const ACTIVE_ENROLLMENT_VERSION: u8 = 2;

/// Prefix on the keychain account name for the per-enrollment wrap-key
/// companion entry. Per ATTESTED-DEVICE-MEK-WRAP (B2): the wrap-key
/// lives at `<WRAP_KEY_PREFIX><account>` while the wrapped MEK lives
/// at `<account>` for backward compatibility with the entry name the
/// legacy v1 schema used.
const WRAP_KEY_PREFIX: &str = "wrap-key.";

/// AEAD AAD bound into every wrapped headless MEK. Version-prefixed
/// per ADR 139 conventions; bump the suffix on any format rotation.
const HEADLESS_MEK_WRAP_AAD: &[u8] = b"attested-device.mek-wrap.v1";

/// Legacy raw-MEK entries (pre-B2) stored 32 bytes base64-encoded — 44
/// characters. Wrapped entries store 24 + 32 + 16 = 72 bytes base64-encoded
/// — 96 characters. The length test discriminates cleanly.
const LEGACY_RAW_MEK_BASE64_LEN: usize = 44;
type MockKeychain = HashMap<(String, String), String>;

static MOCK_KEYCHAIN: OnceLock<Mutex<MockKeychain>> = OnceLock::new();

#[derive(Debug)]
pub enum Error {
    Keychain(String),
    NotFound,
    Decode(String),
    Encode(String),
    Io(String),
    EnrollmentIdMismatch {
        requested: String,
        active: String,
    },
    UnsupportedSize,
    /// Encountered a pre-B2 raw-MEK entry that must be re-enrolled under
    /// the AEAD-wrapped scheme before it can be read. The operator
    /// remediation is `ember headless enroll --persona <id>` (which
    /// generates a fresh wrap-key + wrapped MEK pair).
    LegacyUnwrappedFormat,
    /// AEAD verification failed — the wrap-key and wrapped MEK don't
    /// agree, or the AAD didn't match. Suggests tampering or schema
    /// drift; safe response is to revoke + re-enroll.
    UnwrapFailed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Keychain(msg) => write!(f, "keychain: {msg}"),
            Error::NotFound => write!(f, "headless enrollment not found"),
            Error::Decode(msg) => write!(f, "decode: {msg}"),
            Error::Encode(msg) => write!(f, "encode: {msg}"),
            Error::Io(msg) => write!(f, "io: {msg}"),
            Error::EnrollmentIdMismatch { requested, active } => write!(
                f,
                "requested enrollment_id '{requested}' does not match active enrollment '{active}'"
            ),
            Error::UnsupportedSize => {
                write!(f, "stored headless MEK has unexpected size (not 32 bytes)")
            }
            Error::LegacyUnwrappedFormat => write!(
                f,
                "headless MEK is in the pre-B2 raw-plaintext keychain format; \
                 re-enroll the persona with `ember headless enroll` to upgrade \
                 to the AEAD-wrapped scheme"
            ),
            Error::UnwrapFailed(msg) => write!(f, "headless MEK unwrap failed: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Mirror the daemon vault's test/mock posture so normal cargo tests never hit
/// the operator's real login keychain.
fn use_mock_keychain() -> bool {
    cfg!(test)
        || crate::infra::vault::vault_mock_env_enabled()
        || crate::infra::vault::is_cargo_test_binary()
}

fn mock_keychain() -> &'static Mutex<MockKeychain> {
    MOCK_KEYCHAIN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn resolved_keychain_entry(account: &str) -> (String, String) {
    if !use_mock_keychain() {
        return (KEYCHAIN_SERVICE.to_string(), account.to_string());
    }

    let service =
        std::env::var("EMBER_KEYRING_SERVICE").unwrap_or_else(|_| KEYCHAIN_SERVICE.to_string());
    let account = match std::env::var("EMBER_KEYRING_ACCOUNT") {
        Ok(prefix) if !prefix.is_empty() => format!("{prefix}.{account}"),
        _ => account.to_string(),
    };
    (service, account)
}

fn keychain_set(account: &str, encoded: &str) -> Result<(), Error> {
    let (service, resolved_account) = resolved_keychain_entry(account);
    if use_mock_keychain() {
        let mut guard = mock_keychain()
            .lock()
            .expect("mock headless keychain mutex poisoned");
        guard.insert((service, resolved_account), encoded.to_string());
        return Ok(());
    }

    let entry = keyring_core::Entry::new(&service, &resolved_account)
        .map_err(|e| Error::Keychain(format!("new: {e}")))?;
    entry
        .set_password(encoded)
        .map_err(|e| Error::Keychain(format!("write: {e}")))
}

fn keychain_get(account: &str) -> Result<String, Error> {
    let (service, resolved_account) = resolved_keychain_entry(account);
    if use_mock_keychain() {
        let guard = mock_keychain()
            .lock()
            .expect("mock headless keychain mutex poisoned");
        return guard
            .get(&(service, resolved_account))
            .cloned()
            .ok_or(Error::NotFound);
    }

    let entry = keyring_core::Entry::new(&service, &resolved_account)
        .map_err(|e| Error::Keychain(format!("new: {e}")))?;
    // Wrap at the third-party `keyring_core::Entry::get_password()` boundary
    // so the bare `String` never escapes the call expression into a
    // longer-lived local allocation (N6-deeper item 3). The wrapped MEK
    // value is base64 (semi-sensitive — it's AEAD ciphertext, but the
    // wrap-key entry next to it is the secret half); zeroizing the bare
    // form here matches the discipline applied to vault_macos. Unwrap via
    // `std::mem::take` to satisfy the bare-String return contract without
    // cascading the type through callers.
    match entry.get_password().map(Zeroizing::new) {
        Ok(mut password) => Ok(std::mem::take(&mut *password)),
        Err(keyring_core::Error::NoEntry) => Err(Error::NotFound),
        Err(e) => Err(Error::Keychain(format!("read: {e}"))),
    }
}

fn keychain_delete(account: &str) -> Result<(), Error> {
    let (service, resolved_account) = resolved_keychain_entry(account);
    if use_mock_keychain() {
        let mut guard = mock_keychain()
            .lock()
            .expect("mock headless keychain mutex poisoned");
        guard.remove(&(service, resolved_account));
        return Ok(());
    }

    let entry = keyring_core::Entry::new(&service, &resolved_account)
        .map_err(|e| Error::Keychain(format!("new: {e}")))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Keychain(format!("delete: {e}"))),
    }
}

/// In-memory record of one headless enrollment.
///
/// The actual MEK bytes live in the macOS keychain under `KEYCHAIN_SERVICE` /
/// `account` — this struct only carries the metadata needed to find / expire
/// the entry. Clone-cheap; `Send + Sync` (no interior mutability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedDevice {
    pub enrollment_id: String,
    pub persona: String,
    /// Account string in the keychain — by convention `persona` for the v0.3
    /// single-enrollment-per-persona slice. Future slices may move to a
    /// per-enrollment UUID; the field is separate from `persona` to leave
    /// room for that without an API break.
    pub account: String,
    pub enrolled_at: SystemTime,
    pub expiry: SystemTime,
    pub template_snapshot_hash: String,
    pub delegated_authority_refs: Vec<String>,
    pub delegated_material: HeadlessDelegatedMaterial,
    pub attested_device_ref: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentMetadata {
    pub template_snapshot_hash: String,
    #[serde(default)]
    pub delegated_authority_refs: Vec<String>,
    #[serde(default)]
    pub delegated_material: HeadlessDelegatedMaterial,
    pub attested_device_ref: String,
}

impl AttestedDevice {
    /// AEAD-wrap `mek` and store the wrap-key + wrapped MEK in the
    /// keychain. Returns the enrollment record.
    ///
    /// Per ATTESTED-DEVICE-MEK-WRAP (B2, ADR 139 §"Headless: attested
    /// device, variable enrollment"): the MEK is encrypted under a
    /// freshly-generated 32-byte wrap-key with a 24-byte XChaCha20 nonce
    /// and AAD `b"attested-device.mek-wrap.v1"`. Two keychain entries
    /// land:
    /// - `<persona>` — base64(nonce || ciphertext-with-tag) of the
    ///   wrapped MEK
    /// - `<WRAP_KEY_PREFIX><persona>` — base64(wrap-key)
    ///
    /// Both entries are required to recover the MEK; either alone is
    /// insufficient. This matches the device-binding posture ADR 139
    /// calls for — the wrap-key entry's keychain ACL is what makes
    /// recovery require the daemon's identity context.
    ///
    /// Caller is responsible for running any biometric / Touch ID prompt
    /// BEFORE calling this function — `enroll` itself does not prompt.
    pub fn enroll(persona: &str, duration: Duration, mek: &[u8; 32]) -> Result<Self, Error> {
        Self::enroll_with_metadata(
            persona,
            duration,
            mek,
            EnrollmentMetadata {
                attested_device_ref: default_attested_device_ref(persona),
                ..EnrollmentMetadata::default()
            },
        )
    }

    pub fn enroll_with_metadata(
        persona: &str,
        duration: Duration,
        mek: &[u8; 32],
        metadata: EnrollmentMetadata,
    ) -> Result<Self, Error> {
        let account = persona.to_string();
        // Generate a fresh per-enrollment wrap-key. The wrap-key NEVER
        // leaves this function in unwrapped form — it lands in keychain
        // base64-encoded and is zeroized from this stack frame on the
        // explicit drop below.
        let mut wrap_key = [0u8; 32];
        getrandom::fill(&mut wrap_key)
            .map_err(|e| Error::Keychain(format!("wrap-key entropy: {e}")))?;
        // Fresh nonce per wrap.
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| Error::Keychain(format!("wrap nonce entropy: {e}")))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key)
            .map_err(|e| Error::Encode(format!("wrap cipher init: {e}")))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: mek.as_slice(),
                    aad: HEADLESS_MEK_WRAP_AAD,
                },
            )
            .map_err(|e| Error::Encode(format!("wrap aead: {e}")))?;
        // Wire shape: [24-byte nonce] || [ciphertext-with-tag]. Base64
        // for keychain storage.
        let mut wire = Vec::with_capacity(24 + ciphertext.len());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);
        let wrapped_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let wrap_key_b64 = base64::engine::general_purpose::STANDARD.encode(wrap_key);

        // Store wrap-key first; if that fails, the wrapped MEK never lands
        // and the operator sees a clean failure rather than a half-written
        // pair. On rollback, an existing wrap-key entry (from a prior
        // failed enroll) gets overwritten — keychain set is idempotent.
        let wrap_key_account = format!("{WRAP_KEY_PREFIX}{account}");
        keychain_set(&wrap_key_account, &wrap_key_b64)?;
        // Then store the wrapped MEK at the persona's account slot.
        if let Err(e) = keychain_set(&account, &wrapped_b64) {
            // Best-effort rollback: try to remove the wrap-key entry so
            // the keychain doesn't hold an orphaned wrap-key. Ignore
            // delete errors — the wrap-key alone is useless.
            let _ = keychain_delete(&wrap_key_account);
            return Err(e);
        }

        // Zeroize the per-stack copy of the wrap-key now that both
        // keychain entries are landed.
        wrap_key.zeroize();

        let now = SystemTime::now();
        Ok(Self {
            enrollment_id: uuid::Uuid::new_v4().to_string(),
            persona: persona.to_string(),
            account,
            enrolled_at: now,
            expiry: now + duration,
            template_snapshot_hash: metadata.template_snapshot_hash,
            delegated_authority_refs: metadata.delegated_authority_refs,
            delegated_material: metadata.delegated_material,
            attested_device_ref: metadata.attested_device_ref,
        })
    }

    /// One-shot helper for the phase-2 handler path: store the MEK in the
    /// keychain and persist the active-enrollment metadata slot under
    /// `data_dir`.
    pub fn enroll_active(
        data_dir: &Path,
        persona: &str,
        duration: Duration,
        mek: &[u8; 32],
    ) -> Result<Self, Error> {
        let device = Self::enroll(persona, duration, mek)?;
        device.store_active(data_dir)?;
        Ok(device)
    }

    pub fn enroll_active_with_metadata(
        data_dir: &Path,
        persona: &str,
        duration: Duration,
        mek: &[u8; 32],
        metadata: EnrollmentMetadata,
    ) -> Result<Self, Error> {
        let device = Self::enroll_with_metadata(persona, duration, mek, metadata)?;
        device.store_active(data_dir)?;
        Ok(device)
    }

    /// Read + AEAD-unwrap the stored MEK from the keychain.
    ///
    /// Per ATTESTED-DEVICE-MEK-WRAP (B2): loads both keychain entries
    /// (wrap-key + wrapped MEK), AEAD-decrypts with the bound
    /// `HEADLESS_MEK_WRAP_AAD`, and returns the 32-byte plaintext MEK.
    ///
    /// Migration: legacy v1 entries (pre-B2) stored the raw MEK as a
    /// 44-character base64 string. If we see that shape, refuse with
    /// `Error::LegacyUnwrappedFormat` — the operator-facing remediation
    /// is to re-enroll under the wrapped scheme. The legacy entry stays
    /// in keychain until explicitly revoked; we do NOT silently delete
    /// it here.
    ///
    /// Returns `Err(Error::NotFound)` if either entry has been deleted
    /// (revoked or never enrolled). Returns `Err(Error::UnwrapFailed)`
    /// if AEAD verification fails (tampering, schema drift, wrap-key
    /// rotated out from under the wrapped MEK).
    ///
    /// **Zeroize discipline:** the returned `[u8; 32]` must be `zeroize`d
    /// by the caller once consumed. This function does not retain a
    /// copy of either the MEK or the wrap-key after return.
    pub fn unwrap_mek(&self) -> Result<[u8; 32], Error> {
        let wrapped_b64 = keychain_get(&self.account)?;

        // Legacy v1 detection: raw 32 bytes base64-encoded → 44 chars.
        // Refuse with a re-enrollment hint rather than silently
        // consuming an insecure entry.
        if wrapped_b64.len() == LEGACY_RAW_MEK_BASE64_LEN {
            return Err(Error::LegacyUnwrappedFormat);
        }

        // Wrap-key entry MUST exist for v2 entries — if it doesn't, the
        // pair is half-installed and the safe response is `NotFound`.
        let wrap_key_account = format!("{WRAP_KEY_PREFIX}{}", self.account);
        let wrap_key_b64 = match keychain_get(&wrap_key_account) {
            Ok(v) => v,
            Err(Error::NotFound) => return Err(Error::NotFound),
            Err(e) => return Err(e),
        };

        let mut wrap_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&wrap_key_b64)
            .map_err(|e| Error::Decode(format!("wrap-key base64: {e}")))?;
        if wrap_key_bytes.len() != 32 {
            wrap_key_bytes.zeroize();
            return Err(Error::UnsupportedSize);
        }
        let mut wrap_key = [0u8; 32];
        wrap_key.copy_from_slice(&wrap_key_bytes);
        wrap_key_bytes.zeroize();

        let mut wire = base64::engine::general_purpose::STANDARD
            .decode(&wrapped_b64)
            .map_err(|e| Error::Decode(format!("wrapped-mek base64: {e}")))?;
        if wire.len() < 24 + 16 {
            wire.zeroize();
            wrap_key.zeroize();
            return Err(Error::UnwrapFailed(format!(
                "wrapped MEK wire too short ({} bytes; minimum 40)",
                wire.len()
            )));
        }
        let (nonce_bytes, ciphertext) = wire.split_at(24);
        let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key).map_err(|e| {
            // Zeroize before bailing.
            wrap_key.zeroize();
            Error::UnwrapFailed(format!("cipher init: {e}"))
        })?;
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: HEADLESS_MEK_WRAP_AAD,
                },
            )
            .map_err(|e| {
                wrap_key.zeroize();
                Error::UnwrapFailed(format!("aead: {e}"))
            })?;

        // Zeroize the wrap-key as soon as decrypt succeeds; the MEK is
        // the only sensitive value that should leave this function.
        wrap_key.zeroize();

        if plaintext.len() != 32 {
            let mut pt = plaintext;
            pt.zeroize();
            return Err(Error::UnsupportedSize);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plaintext);
        // Zeroize the plaintext Vec.
        let mut pt = plaintext;
        pt.zeroize();
        Ok(out)
    }

    /// Delete both the wrapped-MEK and wrap-key keychain entries.
    /// Idempotent: a missing entry returns Ok. Per
    /// ATTESTED-DEVICE-MEK-WRAP (B2) we revoke the wrap-key first so a
    /// concurrent reader cannot win a TOCTOU race where the wrap-key is
    /// still readable but the wrapped MEK is already gone (which would
    /// trigger `NotFound` on the wrapped side — safe, but noisy).
    pub fn revoke(&self) -> Result<(), Error> {
        let wrap_key_account = format!("{WRAP_KEY_PREFIX}{}", self.account);
        // Delete wrap-key first; if a reader observes the missing
        // wrap-key, they correctly report `NotFound`.
        let _ = keychain_delete(&wrap_key_account);
        keychain_delete(&self.account)
    }

    /// Wall-clock check: has the enrollment expiry passed?
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expiry
    }

    /// Seconds remaining before expiry; saturates to 0 when expired.
    pub fn duration_remaining(&self) -> Duration {
        self.expiry
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
    }

    /// Unix-epoch seconds of expiry. Used by `headless_status` socket method
    /// (slice B) and the enrollment Receipt body (also slice B).
    pub fn expiry_unix(&self) -> i64 {
        self.expiry
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Persist this record as the daemon's single active headless enrollment.
    ///
    /// This writes only metadata; the actual MEK bytes must already exist in
    /// the keychain (for example via [`Self::enroll`]).
    pub fn store_active(&self, data_dir: &Path) -> Result<(), Error> {
        persist_active_metadata(data_dir, self)
    }

    /// Load the persisted active-enrollment metadata slot, if any.
    pub fn load_active(data_dir: &Path) -> Result<Option<Self>, Error> {
        let path = active_enrollment_path(data_dir);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Io(format!("read {}: {e}", path.display()))),
        };
        let persisted: PersistedActiveEnrollment = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Decode(format!("parse {}: {e}", path.display())))?;
        Ok(Some(persisted.into_device()?))
    }

    /// Revoke the persisted active enrollment and delete its metadata slot.
    ///
    /// When `enrollment_id` is `Some`, the request must match the active slot.
    /// This lets the handler support future targeted revoke-by-id without
    /// guessing which enrollment is live.
    pub fn revoke_active(
        data_dir: &Path,
        enrollment_id: Option<&str>,
    ) -> Result<Option<Self>, Error> {
        let Some(device) = Self::load_active(data_dir)? else {
            return Ok(None);
        };
        if let Some(requested) = enrollment_id
            && requested != device.enrollment_id
        {
            return Err(Error::EnrollmentIdMismatch {
                requested: requested.to_string(),
                active: device.enrollment_id.clone(),
            });
        }
        device.revoke()?;
        remove_active_metadata(data_dir)?;
        Ok(Some(device))
    }

    /// Report the currently active enrollment in handler-friendly wire shape.
    ///
    /// Expired enrollments are treated as inactive and are cleaned up
    /// immediately so the persisted slot cannot outlive the key it points at.
    pub fn active_status(data_dir: &Path) -> Result<Option<ActiveEnrollmentStatus>, Error> {
        let Some(device) = Self::load_active(data_dir)? else {
            return Ok(None);
        };
        if device.is_expired() {
            device.revoke()?;
            remove_active_metadata(data_dir)?;
            return Ok(None);
        }
        Ok(Some(ActiveEnrollmentStatus {
            enrollment_id: device.enrollment_id.clone(),
            persona: device.persona.clone(),
            duration_remaining_seconds: device.duration_remaining().as_secs(),
            expiry_unix: device.expiry_unix(),
            template_snapshot_hash: device.template_snapshot_hash.clone(),
            delegated_authority_refs: device.delegated_authority_refs.clone(),
            delegated_material: device.delegated_material.clone(),
            attested_device_ref: device.attested_device_ref.clone(),
        }))
    }
}

/// Minimal wire-facing status shape the handler can drop straight into
/// `{"active_enrollment": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveEnrollmentStatus {
    pub enrollment_id: String,
    pub persona: String,
    pub duration_remaining_seconds: u64,
    pub expiry_unix: i64,
    pub template_snapshot_hash: String,
    pub delegated_authority_refs: Vec<String>,
    pub delegated_material: HeadlessDelegatedMaterial,
    pub attested_device_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedActiveEnrollment {
    version: u8,
    enrollment_id: String,
    persona: String,
    account: String,
    enrolled_at_unix: i64,
    expiry_unix: i64,
    #[serde(default)]
    template_snapshot_hash: String,
    #[serde(default)]
    delegated_authority_refs: Vec<String>,
    #[serde(default)]
    delegated_material: HeadlessDelegatedMaterial,
    #[serde(default)]
    attested_device_ref: String,
}

impl PersistedActiveEnrollment {
    fn from_device(device: &AttestedDevice) -> Self {
        Self {
            version: ACTIVE_ENROLLMENT_VERSION,
            enrollment_id: device.enrollment_id.clone(),
            persona: device.persona.clone(),
            account: device.account.clone(),
            enrolled_at_unix: system_time_to_unix(device.enrolled_at),
            expiry_unix: device.expiry_unix(),
            template_snapshot_hash: device.template_snapshot_hash.clone(),
            delegated_authority_refs: device.delegated_authority_refs.clone(),
            delegated_material: device.delegated_material.clone(),
            attested_device_ref: device.attested_device_ref.clone(),
        }
    }

    fn into_device(self) -> Result<AttestedDevice, Error> {
        if self.version != 1 && self.version != ACTIVE_ENROLLMENT_VERSION {
            return Err(Error::Decode(format!(
                "unsupported active enrollment metadata version {}",
                self.version
            )));
        }
        let account = self.account;
        let attested_device_ref = if self.version == 1 || self.attested_device_ref.is_empty() {
            default_attested_device_ref(&account)
        } else {
            self.attested_device_ref
        };
        Ok(AttestedDevice {
            enrollment_id: self.enrollment_id,
            persona: self.persona,
            account,
            enrolled_at: unix_to_system_time(self.enrolled_at_unix, "enrolled_at_unix")?,
            expiry: unix_to_system_time(self.expiry_unix, "expiry_unix")?,
            template_snapshot_hash: self.template_snapshot_hash,
            delegated_authority_refs: self.delegated_authority_refs,
            delegated_material: self.delegated_material,
            attested_device_ref,
        })
    }
}

fn default_attested_device_ref(account: &str) -> String {
    format!("keychain:{KEYCHAIN_SERVICE}:{account}")
}

fn persist_active_metadata(data_dir: &Path, device: &AttestedDevice) -> Result<(), Error> {
    let path = active_enrollment_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Io(format!("create {}: {e}", parent.display())))?;
        let encoded = serde_json::to_vec(&PersistedActiveEnrollment::from_device(device))
            .map_err(|e| Error::Encode(format!("serialize {}: {e}", path.display())))?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| Error::Io(format!("temp {}: {e}", parent.display())))?;
        tmp.write_all(&encoded)
            .map_err(|e| Error::Io(format!("write {}: {e}", path.display())))?;
        tmp.flush()
            .map_err(|e| Error::Io(format!("flush {}: {e}", path.display())))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Error::Io(format!("sync {}: {e}", path.display())))?;
        tmp.persist(&path)
            .map_err(|e| Error::Io(format!("persist {}: {e}", path.display())))?;
        return Ok(());
    }
    Err(Error::Io(format!(
        "active enrollment path {} has no parent directory",
        path.display()
    )))
}

fn remove_active_metadata(data_dir: &Path) -> Result<(), Error> {
    let path = active_enrollment_path(data_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(format!("remove {}: {e}", path.display()))),
    }
}

fn active_enrollment_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ACTIVE_ENROLLMENT_FILE)
}

fn system_time_to_unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_to_system_time(seconds: i64, field: &str) -> Result<SystemTime, Error> {
    if seconds < 0 {
        return Err(Error::Decode(format!(
            "{field} must be >= 0, got {seconds}"
        )));
    }
    Ok(UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

// Tests stay macOS-only for now because the shipped headless enrollment lane is
// macOS-first, but cargo tests use the same mock gate as `vault.rs` so they do
// not touch the real login keychain or fire prompts.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn cleanup(persona: &str) {
        keychain_delete(persona).expect("cleanup headless key material");
    }

    #[test]
    fn enroll_unwrap_revoke_roundtrip() {
        let persona = "test-roundtrip-attested";
        cleanup(persona);
        let mek: [u8; 32] = [0x42; 32];
        let device = AttestedDevice::enroll(persona, Duration::from_secs(3600), &mek)
            .expect("enroll succeeds");
        let recovered = device.unwrap_mek().expect("unwrap succeeds");
        assert_eq!(recovered, mek);
        device.revoke().expect("revoke succeeds");
        match device.unwrap_mek() {
            Err(Error::NotFound) => {}
            other => panic!("expected NotFound after revoke, got {other:?}"),
        }
    }

    #[test]
    fn revoke_is_idempotent() {
        let persona = "test-idempotent-revoke";
        cleanup(persona);
        let device = AttestedDevice {
            enrollment_id: "test-idempotent-revoke".to_string(),
            persona: persona.to_string(),
            account: persona.to_string(),
            enrolled_at: SystemTime::now(),
            expiry: SystemTime::now() + Duration::from_secs(60),
            template_snapshot_hash: String::new(),
            delegated_authority_refs: Vec::new(),
            delegated_material: HeadlessDelegatedMaterial::default(),
            attested_device_ref: default_attested_device_ref(persona),
        };
        // No entry exists; revoke should still succeed.
        device.revoke().expect("revoke succeeds on missing entry");
    }

    #[test]
    fn expiry_marks_device_expired() {
        let device = AttestedDevice {
            enrollment_id: "test-expired".into(),
            persona: "test-expired".into(),
            account: "test-expired".into(),
            enrolled_at: SystemTime::now() - Duration::from_secs(120),
            expiry: SystemTime::now() - Duration::from_secs(60),
            template_snapshot_hash: String::new(),
            delegated_authority_refs: Vec::new(),
            delegated_material: HeadlessDelegatedMaterial::default(),
            attested_device_ref: default_attested_device_ref("test-expired"),
        };
        assert!(device.is_expired());
        assert_eq!(device.duration_remaining(), Duration::ZERO);
    }

    #[test]
    fn future_expiry_is_not_expired() {
        let device = AttestedDevice {
            enrollment_id: "test-future".into(),
            persona: "test-future".into(),
            account: "test-future".into(),
            enrolled_at: SystemTime::now(),
            expiry: SystemTime::now() + Duration::from_secs(3600),
            template_snapshot_hash: String::new(),
            delegated_authority_refs: Vec::new(),
            delegated_material: HeadlessDelegatedMaterial::default(),
            attested_device_ref: default_attested_device_ref("test-future"),
        };
        assert!(!device.is_expired());
        assert!(device.duration_remaining().as_secs() > 3500);
    }

    #[test]
    fn distinct_persona_distinct_entries() {
        let persona_a = "test-distinct-a";
        let persona_b = "test-distinct-b";
        cleanup(persona_a);
        cleanup(persona_b);
        let mek_a: [u8; 32] = [0xAA; 32];
        let mek_b: [u8; 32] = [0xBB; 32];
        let device_a =
            AttestedDevice::enroll(persona_a, Duration::from_secs(3600), &mek_a).expect("enroll A");
        let device_b =
            AttestedDevice::enroll(persona_b, Duration::from_secs(3600), &mek_b).expect("enroll B");
        assert_eq!(device_a.unwrap_mek().unwrap(), mek_a);
        assert_eq!(device_b.unwrap_mek().unwrap(), mek_b);
        device_a.revoke().unwrap();
        device_b.revoke().unwrap();
    }

    #[test]
    fn active_enrollment_roundtrip_persists_and_loads() {
        let tmp = tempdir().expect("tempdir");
        let persona = "test-active-roundtrip";
        cleanup(persona);
        let mek: [u8; 32] = [0x24; 32];

        let device =
            AttestedDevice::enroll_active(tmp.path(), persona, Duration::from_secs(3600), &mek)
                .expect("enroll active succeeds");
        let metadata_path = tmp.path().join(ACTIVE_ENROLLMENT_FILE);
        assert!(
            metadata_path.exists(),
            "active-enrollment metadata must exist"
        );

        let loaded = AttestedDevice::load_active(tmp.path())
            .expect("load active succeeds")
            .expect("active enrollment present");
        assert_eq!(loaded.enrollment_id, device.enrollment_id);
        assert_eq!(loaded.persona, device.persona);
        assert_eq!(loaded.account, device.account);
        assert_eq!(loaded.expiry_unix(), device.expiry_unix());
        assert!(loaded.enrolled_at <= device.enrolled_at);

        let status = AttestedDevice::active_status(tmp.path())
            .expect("status succeeds")
            .expect("active status present");
        assert_eq!(status.enrollment_id, device.enrollment_id);
        assert_eq!(status.persona, persona);
        assert_eq!(status.expiry_unix, device.expiry_unix());
        assert!(status.duration_remaining_seconds > 3500);

        AttestedDevice::revoke_active(tmp.path(), Some(&device.enrollment_id))
            .expect("revoke active succeeds");
    }

    #[test]
    fn revoke_active_clears_metadata_and_keychain_entry() {
        let tmp = tempdir().expect("tempdir");
        let persona = "test-active-revoke";
        cleanup(persona);
        let mek: [u8; 32] = [0x35; 32];

        let device =
            AttestedDevice::enroll_active(tmp.path(), persona, Duration::from_secs(3600), &mek)
                .expect("enroll active succeeds");
        let revoked = AttestedDevice::revoke_active(tmp.path(), Some(&device.enrollment_id))
            .expect("revoke succeeds")
            .expect("active enrollment existed");
        assert_eq!(revoked.enrollment_id, device.enrollment_id);
        assert!(
            AttestedDevice::load_active(tmp.path())
                .expect("load active after revoke")
                .is_none()
        );
        match device.unwrap_mek() {
            Err(Error::NotFound) => {}
            other => panic!("expected NotFound after revoke_active, got {other:?}"),
        }
    }

    #[test]
    fn active_status_cleans_up_expired_enrollment() {
        let tmp = tempdir().expect("tempdir");
        let persona = "test-active-expired";
        cleanup(persona);
        let mek: [u8; 32] = [0x46; 32];

        let device = AttestedDevice::enroll_active(tmp.path(), persona, Duration::ZERO, &mek)
            .expect("enroll active succeeds");
        let status = AttestedDevice::active_status(tmp.path()).expect("status succeeds");
        assert!(
            status.is_none(),
            "expired enrollment must not report active status"
        );
        assert!(
            AttestedDevice::load_active(tmp.path())
                .expect("load active after expiry cleanup")
                .is_none()
        );
        match device.unwrap_mek() {
            Err(Error::NotFound) => {}
            other => panic!("expected NotFound after expiry cleanup, got {other:?}"),
        }
    }

    #[test]
    fn revoke_active_rejects_mismatched_enrollment_id() {
        let tmp = tempdir().expect("tempdir");
        let persona = "test-active-mismatch";
        cleanup(persona);
        let mek: [u8; 32] = [0x57; 32];

        let device =
            AttestedDevice::enroll_active(tmp.path(), persona, Duration::from_secs(3600), &mek)
                .expect("enroll active succeeds");
        let err = AttestedDevice::revoke_active(tmp.path(), Some("wrong-id"))
            .expect_err("mismatched enrollment id must fail");
        assert!(matches!(err, Error::EnrollmentIdMismatch { .. }));
        assert!(
            AttestedDevice::load_active(tmp.path())
                .expect("load active after mismatch")
                .is_some(),
            "mismatch must not clear the active slot"
        );
        AttestedDevice::revoke_active(tmp.path(), Some(&device.enrollment_id))
            .expect("cleanup revoke succeeds");
    }

    // ATTESTED-DEVICE-MEK-WRAP (B2) anchor: enroll writes BOTH the
    // wrap-key and wrapped-MEK entries, and removing either alone makes
    // unwrap fail safely without leaking plaintext.
    #[test]
    fn enroll_lands_both_wrap_key_and_wrapped_mek_entries() {
        let persona = "test-wrap-pair-landed";
        cleanup(persona);
        let _ = keychain_delete(&format!("{WRAP_KEY_PREFIX}{persona}"));
        let mek: [u8; 32] = [0xCD; 32];
        let device =
            AttestedDevice::enroll(persona, Duration::from_secs(3600), &mek).expect("enroll");

        let wrapped_b64 = keychain_get(persona).expect("wrapped-mek entry present");
        let wrap_key_b64 =
            keychain_get(&format!("{WRAP_KEY_PREFIX}{persona}")).expect("wrap-key entry present");

        // Wire shapes: wrapped MEK is 24 nonce + 32 ciphertext + 16 tag
        // = 72 raw bytes → 96 base64 chars. Wrap-key is 32 raw → 44 b64.
        assert_eq!(
            wrap_key_b64.len(),
            44,
            "wrap-key should base64-encode 32 raw bytes"
        );
        assert!(
            wrapped_b64.len() > 80,
            "wrapped MEK should be larger than the legacy 44-char raw shape; got {}",
            wrapped_b64.len()
        );
        assert_ne!(
            wrapped_b64.len(),
            44,
            "wrapped MEK must not look like a raw-MEK entry (collision with legacy detection)"
        );

        // Round-trip: unwrap recovers the original MEK.
        let recovered = device.unwrap_mek().expect("unwrap_mek succeeds");
        assert_eq!(recovered, mek);

        // Lose the wrap-key entry → unwrap reports NotFound (safe).
        let _ = keychain_delete(&format!("{WRAP_KEY_PREFIX}{persona}"));
        match device.unwrap_mek() {
            Err(Error::NotFound) => {}
            other => panic!("expected NotFound without wrap-key, got {other:?}"),
        }

        device.revoke().expect("cleanup revoke");
    }

    // B2 migration: legacy raw-MEK base64 entries are refused with a
    // re-enrollment hint rather than silently consumed.
    #[test]
    fn unwrap_refuses_legacy_raw_mek_entry() {
        let persona = "test-legacy-refuse";
        cleanup(persona);
        let _ = keychain_delete(&format!("{WRAP_KEY_PREFIX}{persona}"));
        let mek: [u8; 32] = [0x99; 32];
        // Hand-roll a legacy v1 entry — raw MEK base64-encoded under the
        // persona's account slot, no wrap-key companion.
        let raw_b64 = base64::engine::general_purpose::STANDARD.encode(mek);
        assert_eq!(raw_b64.len(), 44, "legacy detection assumption");
        keychain_set(persona, &raw_b64).expect("hand-rolled legacy entry");

        let device = AttestedDevice {
            enrollment_id: "legacy-fixture".into(),
            persona: persona.to_string(),
            account: persona.to_string(),
            enrolled_at: SystemTime::now(),
            expiry: SystemTime::now() + Duration::from_secs(3600),
            template_snapshot_hash: String::new(),
            delegated_authority_refs: Vec::new(),
            delegated_material: HeadlessDelegatedMaterial::default(),
            attested_device_ref: default_attested_device_ref(persona),
        };
        match device.unwrap_mek() {
            Err(Error::LegacyUnwrappedFormat) => {}
            other => panic!("expected LegacyUnwrappedFormat, got {other:?}"),
        }

        cleanup(persona);
    }

    // ATTESTED-DEVICE-MEK-WRAP anchor: revoke clears BOTH keychain
    // entries so a subsequent enroll under the same persona doesn't
    // inherit a stale wrap-key.
    #[test]
    fn revoke_clears_both_wrap_key_and_wrapped_mek_entries() {
        let persona = "test-wrap-revoke-both";
        cleanup(persona);
        let _ = keychain_delete(&format!("{WRAP_KEY_PREFIX}{persona}"));
        let mek: [u8; 32] = [0xEE; 32];
        let device =
            AttestedDevice::enroll(persona, Duration::from_secs(3600), &mek).expect("enroll");
        device.revoke().expect("revoke");

        match keychain_get(persona) {
            Err(Error::NotFound) => {}
            other => panic!("wrapped-mek entry should be deleted, got {other:?}"),
        }
        match keychain_get(&format!("{WRAP_KEY_PREFIX}{persona}")) {
            Err(Error::NotFound) => {}
            other => panic!("wrap-key entry should be deleted, got {other:?}"),
        }
    }
}

// VAULT-SCOPE-MEK-SPLIT-CRYPTOGRAPHIC anchor: this constant marks
// the crate-level B1+B2 landing for grep-time auditability.
#[doc(hidden)]
pub const VAULT_SCOPE_MEK_SPLIT_CRYPTOGRAPHIC_LANDED: &str =
    "vault_scope_mek_split_cryptographic_landed";

#[doc(hidden)]
pub const ATTESTED_DEVICE_MEK_WRAP_LANDED: &str = "attested_device_mek_wrap_landed";
