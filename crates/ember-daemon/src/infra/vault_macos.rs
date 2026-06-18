//! macOS-only Keychain shim with user-presence (Touch ID / device passcode)
//! gating for the vault MEK passphrase.
//!
//! ## Why a separate shim
//!
//! The `keyring` crate (used everywhere else for portable keychain access)
//! does not expose `kSecAttrAccessControl`, the Apple keychain attribute that
//! requires the user to authenticate with Touch ID, Face ID, or the device
//! passcode before a SecItem can be read. Without it, any same-UID process
//! on the box can silently read the vault MEK once macOS' default
//! per-application ACL is satisfied — which it is, for the daemon's own
//! identity. Setting `kSecAccessControlBiometryAny | kSecAccessControlOr |
//! kSecAccessControlDevicePasscode` on the keychain entry forces the
//! LocalAuthentication prompt on every fresh read — biometric primary
//! (Touch ID / Face ID for any enrolled user), passcode fallback. We pick
//! the granular combination over the umbrella `kSecAccessControlUserPresence`
//! so the policy is explicit in code review and so we can later swap
//! `BiometryAny` → `BiometryCurrentSet` if we want re-enrolment to invalidate
//! the entry without further code churn.
//!
//! ## Scope
//!
//! Only the vault-MEK passphrase entry routes through here. All other keyring
//! callers (and non-macOS builds) keep using the `keyring` crate. The
//! `apply_user_presence` predicate decides per-call whether to use this
//! shim — production keychain service ⇒ user-presence; dev/QA service
//! (e.g. `ember-daemon-qa`) ⇒ skip, so `qember.sh demo up` doesn't fire a
//! biometric prompt every iteration.
//!
//! ## Session caching
//!
//! Acceptance requires "exactly ONCE per daemon session" — biometric prompts
//! are user-hostile. We cache the unwrapped passphrase in a process-local
//! `OnceLock`-per-(service,account) map for the daemon's lifetime; any
//! subsequent read in-process returns the cached value with no prompt.
//!
//! ## Fallback chain (P63.A guardrails preserved)
//!
//! `EMBER_VAULT_PASSPHRASE` env → configured passphrase → SE-wrapped key →
//! auto-generated. This file only owns the SE-wrapped-key step; the env-var
//! and auto-generate paths in `vault.rs::resolve_passphrase` run before/after.

use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password, generic_password,
    set_generic_password_options,
};
use zeroize::Zeroizing;

use crate::infra::vault::{
    DEFAULT_KEYRING_SERVICE, VaultError, check_production_sentinel, is_cargo_test_binary,
};

/// Per-process cache: (service, account) → unwrapped passphrase. Populated on
/// first SE-gated read; subsequent reads short-circuit, so the daemon prompts
/// for biometric exactly once per session per credential.
///
/// Mutex (not RwLock) because the read path also writes on first hit and the
/// contention is negligible (a handful of vault opens per daemon lifetime).
/// Per VAULT-MEK-HARDENING-V030-C3: cache values are wrapped in
/// `Zeroizing<String>` so the unwrapped passphrase is overwritten when the
/// cache entry is dropped (test reset, daemon shutdown, lock-then-clear
/// flows). The HashMap key is the (service, account) identity tuple — those
/// are not secret so they don't need to be zeroized.
#[allow(clippy::type_complexity)]
static SESSION_CACHE: Lazy<Mutex<HashMap<(String, String), Zeroizing<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// True when `service` should be wrapped with the biometric+passcode ACL
/// (`kSecAccessControlBiometryAny | kSecAccessControlOr |
/// kSecAccessControlDevicePasscode`).
///
/// Policy: only the *production* keychain service gets the biometric gate.
/// Any dev/QA service (anything that isn't the production default) opts out
/// automatically, matching the production-checkpoint policy in `vault.rs`. This
/// keeps `qember.sh demo up` and integration tests usable without forcing
/// biometric prompts on every cycle.
pub fn apply_user_presence(service: &str, production_default: &str) -> bool {
    service == production_default
}

/// Belt-and-suspenders gate that runs before any SE-backed Keychain operation
/// inside this module. Mirrors the production-checkpoint check enforced at the
/// `vault.rs` entry points so a future caller that bypasses
/// `open_from_config` / `try_auto_unseal_from_keyring` cannot accidentally
/// fire a biometric prompt against the production vault.
///
/// - Refuses under cargo test binaries (tests must never touch the real
///   Keychain — same three-axis guard used in `resolve_passphrase`).
/// - Refuses if the production checkpoint `~/.ember-production` is missing.
fn assert_se_safe(service: &str) -> Result<(), String> {
    if is_cargo_test_binary() {
        return Err(format!(
            "vault_macos: refusing SE-backed Keychain access from cargo test binary \
             (service={service:?}); set EMBER_VAULT_MOCK or run via cargo-env.sh"
        ));
    }
    let home = dirs_next::home_dir().ok_or_else(|| {
        "vault_macos: refusing SE-backed Keychain access: home directory not resolvable".to_string()
    })?;
    match check_production_sentinel(service, DEFAULT_KEYRING_SERVICE, &home) {
        Ok(()) => Ok(()),
        Err(VaultError::ProductionSentinelMissing(msg)) => Err(msg),
        Err(e) => Err(format!("vault_macos: checkpoint check: {e}")),
    }
}

/// Read a generic password under user-presence (biometric / passcode) gating.
///
/// Returns `Ok(Some(p))` if the entry exists and the user authenticated;
/// `Ok(None)` if the entry doesn't exist (caller treats as "needs init");
/// `Err` on any other Security-framework error.
///
/// Cached per (service, account) for the process lifetime — first call may
/// prompt; subsequent calls return immediately.
///
/// **N6-deeper:** the unwrapped passphrase is returned as `Zeroizing<String>`
/// so the heap allocation overwrites itself on drop. Callers MUST consume the
/// returned value via the `Zeroizing` wrapper (Deref to `String`) and not
/// re-bind into a bare `String` local — the bare-String form is reserved for
/// the third-party `security_framework` boundary and the `Zeroizing` wrap is
/// applied in the same expression as the boundary call below.
pub fn get_password_user_presence(
    service: &str,
    account: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    // Session cache fast path — avoids re-prompting for biometric within the
    // same daemon process.
    {
        let cache = SESSION_CACHE
            .lock()
            .expect("vault_macos session cache poisoned");
        if let Some(cached) = cache.get(&(service.to_string(), account.to_string())) {
            // Clone the cached `Zeroizing<String>` directly — both the cached
            // entry and the returned copy will zero their heap allocations on
            // drop, so no bare-String intermediate exists.
            return Ok(Some(cached.clone()));
        }
    }

    // Defense-in-depth: even if a future caller bypasses the entry-point
    // checkpoint, refuse to read the production SE-backed entry from a test
    // binary or without the production opt-in checkpoint.
    assert_se_safe(service)?;

    let opts = PasswordOptions::new_generic_password(service, account);
    match generic_password(opts) {
        Ok(bytes) => {
            // Wrap at the third-party boundary: `String::from_utf8` is the
            // first expression that materializes the unwrapped passphrase on
            // the heap. Wrap it in `Zeroizing` in the same expression so the
            // bare `String` never lives in a longer-lived local.
            let p = Zeroizing::new(
                String::from_utf8(bytes)
                    .map_err(|e| format!("vault_macos: passphrase utf8: {e}"))?,
            );
            let mut cache = SESSION_CACHE
                .lock()
                .expect("vault_macos session cache poisoned");
            cache.insert((service.to_string(), account.to_string()), p.clone());
            Ok(Some(p))
        }
        Err(e) => {
            // errSecItemNotFound (-25300) — entry not present. Map to None so
            // the caller can branch on "needs provisioning" without flattening
            // it into the error path.
            //
            // We match on the formatted error string because security-framework
            // does not expose a stable typed variant for `errSecItemNotFound`
            // in v3.x — `Error::code() -> i32` is stable.
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(format!("vault_macos: read: {e}"))
            }
        }
    }
}

/// Write a generic password with the biometric+passcode ACL
/// (`kSecAccessControlBiometryAny | kSecAccessControlOr |
/// kSecAccessControlDevicePasscode`).
///
/// On first creation this attaches the SAC (`kSecAttrAccessControl`) so future
/// reads require Touch ID / Face ID OR the device passcode. The session
/// cache is also pre-populated so the daemon doesn't prompt on the
/// immediately-following auto-unseal read.
///
/// Note: if an entry already exists with a different SAC (e.g. from a
/// pre-VAULT-MACOS-BIOMETRIC-ACL daemon that used `USER_PRESENCE`), the
/// underlying API replaces it with the new SAC-wrapped version. This is the
/// documented one-shot upgrade path. Existing entries that pre-date this
/// branch are NOT migrated automatically — they continue to function under
/// their original ACL until a write rotates them.
pub fn set_password_user_presence(
    service: &str,
    account: &str,
    passphrase: &str,
) -> Result<(), String> {
    // Defense-in-depth: same SE-safety guard as the read path.
    assert_se_safe(service)?;

    let mut opts = PasswordOptions::new_generic_password(service, account);
    // Biometric primary, passcode fallback. The OR flag is mandatory between
    // the two constraints, otherwise the SAC bitfield is treated as "AND of
    // every flag set" and the keychain rejects entries it considers
    // ambiguous. This combination matches the operator's UX brief: first
    // call of a daemon session prompts Touch ID; subsequent calls in the
    // same process hit the SESSION_CACHE above.
    opts.set_access_control_options(
        AccessControlOptions::BIOMETRY_ANY
            | AccessControlOptions::OR
            | AccessControlOptions::DEVICE_PASSCODE,
    );
    set_generic_password_options(passphrase.as_bytes(), opts)
        .map_err(|e| format!("vault_macos: write: {e}"))?;

    // Pre-populate the session cache so the immediate read-back doesn't
    // double-prompt the user. Wrap the passphrase in `Zeroizing` so the
    // cached copy is overwritten on drop (VAULT-MEK-HARDENING-V030 C3).
    let mut cache = SESSION_CACHE
        .lock()
        .expect("vault_macos session cache poisoned");
    cache.insert(
        (service.to_string(), account.to_string()),
        Zeroizing::new(passphrase.to_string()),
    );
    Ok(())
}

/// Delete a generic password entry. Used by tests to clean up after writes.
/// Errors are swallowed for the not-found case so callers can use this as
/// idempotent cleanup.
#[allow(dead_code)]
pub fn delete_password(service: &str, account: &str) -> Result<(), String> {
    // Drop from the session cache regardless of whether the keychain delete
    // succeeds; otherwise stale entries linger after a manual reset.
    let mut cache = SESSION_CACHE
        .lock()
        .expect("vault_macos session cache poisoned");
    cache.remove(&(service.to_string(), account.to_string()));
    drop(cache);

    match delete_generic_password(service, account) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound — nothing to delete
        Err(e) => Err(format!("vault_macos: delete: {e}")),
    }
}

/// Test-only: clear the in-process session cache. Lets unit AND integration
/// tests assert the "first read prompts, second read doesn't" cache behaviour
/// without needing a fresh process. Per VAULT-MEK-HARDENING-V030-C3 the
/// `_for_tests` suffix has been dropped — production lock paths now also
/// call this fn (hard-lock semantics drop both the in-memory MEK and the
/// SE-wrapped session cache).
///
/// Marked `#[doc(hidden)]` because the integration-tests-without-cfg-test
/// shape requires public-but-not-advertised visibility.
#[doc(hidden)]
pub fn clear_session_cache() {
    let mut cache = SESSION_CACHE
        .lock()
        .expect("vault_macos session cache poisoned");
    cache.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_user_presence_only_for_production_service() {
        // Production default ⇒ gate applied.
        assert!(apply_user_presence("ember-daemon", "ember-daemon"));
        // QA service ⇒ no gate (qember demo flow MUST NOT prompt).
        assert!(!apply_user_presence("ember-daemon-qa", "ember-daemon"));
        // Test/dev services ⇒ no gate.
        assert!(!apply_user_presence("ember-daemon-test", "ember-daemon"));
        assert!(!apply_user_presence("anything-else", "ember-daemon"));
    }

    #[test]
    fn session_cache_clear_is_idempotent() {
        // Smoke: clearing twice in a row must not panic. Real cache-population
        // tests live in the integration suite (they require live Keychain
        // access and are gated behind EMBER_SEC7_LIVE_KEYCHAIN=1).
        clear_session_cache();
        clear_session_cache();
    }
}
