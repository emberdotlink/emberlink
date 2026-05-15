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
//! ## Scope (implementation-note-117)
//!
//! - Generate keychain-backed storage for one MEK per persona-enrollment.
//! - Track enrollment timestamp / duration / expiry as in-memory metadata.
//! - Expose enroll / unwrap_mek / revoke / is_expired as the module's public API.
//!
//! ## Out of scope (later slices)
//!
//! - The Touch ID prompt at enrollment time (slice B's socket method).
//! - Receipt emission (slice B).
//! - CLI commands (slice C).
//! - Persistence of enrollment metadata across daemon restarts — handled
//!   by slice B alongside the socket-method state.
//!

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use zeroize::Zeroize;

/// Keychain service used for headless attested-device entries.
///
/// Distinct from the production vault service so the user-presence /
/// biometric gate in `vault_macos::apply_user_presence` does NOT fire for
/// this entry — headless reads the MEK without a Touch ID prompt.
pub const KEYCHAIN_SERVICE: &str = "ember-daemon-headless";

#[derive(Debug)]
pub enum Error {
    Keychain(String),
    NotFound,
    Decode(String),
    UnsupportedSize,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Keychain(msg) => write!(f, "keychain: {msg}"),
            Error::NotFound => write!(f, "headless enrollment not found"),
            Error::Decode(msg) => write!(f, "decode: {msg}"),
            Error::UnsupportedSize => {
                write!(f, "stored headless MEK has unexpected size (not 32 bytes)")
            }
        }
    }
}

impl std::error::Error for Error {}

/// In-memory record of one headless enrollment.
///
/// The actual MEK bytes live in the macOS keychain under `KEYCHAIN_SERVICE` /
/// `account` — this struct only carries the metadata needed to find / expire
/// the entry. Clone-cheap; `Send + Sync` (no interior mutability).
#[derive(Debug, Clone)]
pub struct AttestedDevice {
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
    /// the in-memory enrollment record.
    ///
    /// Caller is responsible for running any biometric / Touch ID prompt
    /// BEFORE calling this function — `enroll` itself does not prompt.
    pub fn enroll(persona: &str, duration: Duration, mek: &[u8; 32]) -> Result<Self, Error> {
        let account = persona.to_string();
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &account)
            .map_err(|e| Error::Keychain(format!("new: {e}")))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(mek);
        entry
            .set_password(&encoded)
            .map_err(|e| Error::Keychain(format!("write: {e}")))?;
        let now = SystemTime::now();
        Ok(Self {
            persona: persona.to_string(),
            account,
            enrolled_at: now,
            expiry: now + duration,
        })
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
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &self.account)
            .map_err(|e| Error::Keychain(format!("new: {e}")))?;
        let encoded = match entry.get_password() {
            Ok(p) => p,
            Err(keyring::Error::NoEntry) => return Err(Error::NotFound),
            Err(e) => return Err(Error::Keychain(format!("read: {e}"))),
        };
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
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &self.account)
            .map_err(|e| Error::Keychain(format!("new: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::Keychain(format!("delete: {e}"))),
        }
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
}

// Tests gated on macOS — the keyring crate's `apple-native` backend talks to
// the system keychain. On Linux/CI without `secret-service` running, the
// keyring calls would fail. CI is frozen (project_ci_disabled 2026-05-09);
// these tests run locally on the operator's macOS dev box.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn cleanup(persona: &str) {
        let _ = keyring::Entry::new(KEYCHAIN_SERVICE, persona)
            .and_then(|e| e.delete_credential())
            .ok();
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
        let device_a = AttestedDevice::enroll(persona_a, Duration::from_secs(3600), &mek_a)
            .expect("enroll A");
        let device_b = AttestedDevice::enroll(persona_b, Duration::from_secs(3600), &mek_b)
            .expect("enroll B");
        assert_eq!(device_a.unwrap_mek().unwrap(), mek_a);
        assert_eq!(device_b.unwrap_mek().unwrap(), mek_b);
        device_a.revoke().unwrap();
        device_b.revoke().unwrap();
    }
}
