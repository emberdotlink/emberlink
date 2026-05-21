//! Headless-enrollment attested-device key.
//!
//! Per design §"Headless: attested device, variable enrollment": at enrollment
//! time the daemon stashes the headless Vault MEK under a dedicated keychain
//! entry so headless can mint short-lived credentials without re-prompting
//! Touch ID between sessions, until the enrollment expiry elapses.
//!
//! The keychain entry uses the `keyring` crate's default macOS ACL —
//! "this binary can read it when the system is unlocked" — which is the
//! AfterFirstUnlock-equivalent access posture the ADR calls for. Touch ID
//! happens once at enrollment time (slice B's socket handler runs the
//! biometric prompt before calling `enroll()`); after that, headless rides
//! the keychain entry until `is_expired()` returns true.
//!
//! On revoke or expiry, the keychain entry is deleted and the in-memory
//! MEK copy is zeroized.
//!
//! ## Scope (implementation-note-188)
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

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Keychain service used for headless attested-device entries.
///
/// Distinct from the production vault service so the user-presence /
/// biometric gate in `vault_macos::apply_user_presence` does NOT fire for
/// this entry — headless reads the MEK without a Touch ID prompt.
pub const KEYCHAIN_SERVICE: &str = "ember-daemon-headless";

/// Relative path under the daemon `data_dir` that carries the one active
/// headless-enrollment metadata record.
pub const ACTIVE_ENROLLMENT_FILE: &str = "headless/active-enrollment.json";

const ACTIVE_ENROLLMENT_VERSION: u8 = 1;
type MockKeychain = HashMap<(String, String), String>;

static MOCK_KEYCHAIN: OnceLock<Mutex<MockKeychain>> = OnceLock::new();

#[derive(Debug)]
pub enum Error {
    Keychain(String),
    NotFound,
    Decode(String),
    Encode(String),
    Io(String),
    EnrollmentIdMismatch { requested: String, active: String },
    UnsupportedSize,
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
        }
    }
}

impl std::error::Error for Error {}

/// Mirror the daemon vault's test/mock posture so normal cargo tests never hit
/// the operator's real login keychain.
fn use_mock_keychain() -> bool {
    cfg!(test)
        || std::env::var("EMBER_VAULT_MOCK").is_ok()
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
    match entry.get_password() {
        Ok(password) => Ok(password),
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
}

impl AttestedDevice {
    /// Store `mek` under the headless keychain entry for `persona` and return
    /// the enrollment record.
    ///
    /// Caller is responsible for running any biometric / Touch ID prompt
    /// BEFORE calling this function — `enroll` itself does not prompt.
    pub fn enroll(persona: &str, duration: Duration, mek: &[u8; 32]) -> Result<Self, Error> {
        let account = persona.to_string();
        let encoded = base64::engine::general_purpose::STANDARD.encode(mek);
        keychain_set(&account, &encoded)?;
        let now = SystemTime::now();
        Ok(Self {
            enrollment_id: uuid::Uuid::new_v4().to_string(),
            persona: persona.to_string(),
            account,
            enrolled_at: now,
            expiry: now + duration,
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

    /// Read the stored MEK back from the keychain.
    ///
    /// Returns `Err(Error::NotFound)` if the entry has been deleted (revoked
    /// or never enrolled). Returns `Err(Error::UnsupportedSize)` if the
    /// stored value decodes to anything other than 32 bytes — should never
    /// happen for entries written by `enroll`, but the invariant is asserted
    /// so a future migration / hand-edit can't silently widen the MEK type.
    ///
    /// **Zeroize discipline:** the returned `[u8; 32]` must be `zeroize`d by
    /// the caller once consumed. This function does not retain a copy.
    pub fn unwrap_mek(&self) -> Result<[u8; 32], Error> {
        let encoded = keychain_get(&self.account)?;
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|e| Error::Decode(format!("base64: {e}")))?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(Error::UnsupportedSize);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(out)
    }

    /// Delete the keychain entry. Idempotent: a missing entry returns Ok.
    pub fn revoke(&self) -> Result<(), Error> {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedActiveEnrollment {
    version: u8,
    enrollment_id: String,
    persona: String,
    account: String,
    enrolled_at_unix: i64,
    expiry_unix: i64,
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
        }
    }

    fn into_device(self) -> Result<AttestedDevice, Error> {
        if self.version != ACTIVE_ENROLLMENT_VERSION {
            return Err(Error::Decode(format!(
                "unsupported active enrollment metadata version {}",
                self.version
            )));
        }
        Ok(AttestedDevice {
            enrollment_id: self.enrollment_id,
            persona: self.persona,
            account: self.account,
            enrolled_at: unix_to_system_time(self.enrolled_at_unix, "enrolled_at_unix")?,
            expiry: unix_to_system_time(self.expiry_unix, "expiry_unix")?,
        })
    }
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
}
