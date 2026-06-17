//! Live macOS Keychain integration test for the user-presence gate.
//!
//! These tests touch the real macOS Keychain and require physical user
//! interaction (Touch ID or device passcode) on the first read of the test
//! entry. They are gated behind `EMBER_SEC7_LIVE_KEYCHAIN=1` so the regular
//! `cargo test -p ember-daemon` suite never:
//!   - prompts the developer for biometric, or
//!   - writes to the operator's real Keychain.
//!
//! To run manually on a macOS workstation:
//!
//!   EMBER_SEC7_LIVE_KEYCHAIN=1 cargo test -p ember-daemon \
//!     --test sec7_user_presence -- --nocapture --test-threads=1
//!
//! Each test uses a uniquely-prefixed temp service name and cleans up after
//! itself. Tests are macOS-only via `#[cfg(target_os = "macos")]`.

#![cfg(target_os = "macos")]

use ember_daemon::infra::vault_macos;

/// One-time per-test guard: skip cleanly when the live-Keychain opt-in is not
/// set. Stdout marker lets `--nocapture` runs confirm the skip happened.
fn live_or_skip(test_name: &str) -> bool {
    if std::env::var("EMBER_SEC7_LIVE_KEYCHAIN").is_ok() {
        true
    } else {
        eprintln!(
            "sec7_user_presence::{test_name}: skipped (set EMBER_SEC7_LIVE_KEYCHAIN=1 to run)"
        );
        false
    }
}

/// Use the production default service name so `assert_se_safe` lets the call
/// through. The live test additionally requires the production checkpoint
/// (`~/.ember-production`) to exist — the same opt-in real operators use.
const PROD_SERVICE: &str = "ember-daemon";

#[test]
fn sec7_set_then_get_round_trips_under_user_presence() {
    if !live_or_skip("sec7_set_then_get_round_trips_under_user_presence") {
        return;
    }

    // Use a uniquely-named test ACCOUNT under the production service so we
    // don't collide with the operator's real vault entry.
    let account = format!("sec7-live-{}", uuid::Uuid::new_v4());
    let passphrase = "sec7-roundtrip-passphrase";

    // First write — attaches kSecAttrAccessControl=BiometryAny|Or|DevicePasscode.
    vault_macos::set_password_user_presence(PROD_SERVICE, &account, passphrase)
        .expect("set_password_user_presence");

    // First read — session cache pre-populated by the writer; should NOT prompt.
    // `get_password_user_presence` returns `Option<Zeroizing<String>>`
    // (N6-deeper item 3); use `.as_deref().map(String::as_str)` to compare to
    // the bare `&str` expected value.
    let got1 = vault_macos::get_password_user_presence(PROD_SERVICE, &account).expect("first get");
    assert_eq!(
        got1.as_deref().map(String::as_str),
        Some(passphrase),
        "first read must match"
    );

    // Clear the in-process cache to simulate a fresh daemon process. The next
    // read will fall through to the real Keychain and (per SAC) prompt the
    // operator. This is the path the daemon takes on every cold start.
    vault_macos::clear_session_cache();
    let got2 = vault_macos::get_password_user_presence(PROD_SERVICE, &account)
        .expect("second get (post-cache-clear)");
    assert_eq!(
        got2.as_deref().map(String::as_str),
        Some(passphrase),
        "post-cache-clear read must still match"
    );

    // Subsequent read — session cache hit, no prompt.
    let got3 = vault_macos::get_password_user_presence(PROD_SERVICE, &account).expect("third get");
    assert_eq!(
        got3.as_deref().map(String::as_str),
        Some(passphrase),
        "cached read must match"
    );

    // Cleanup.
    vault_macos::delete_password(PROD_SERVICE, &account).expect("delete");
}

#[test]
fn sec7_get_missing_entry_returns_none() {
    if !live_or_skip("sec7_get_missing_entry_returns_none") {
        return;
    }

    let account = format!("sec7-missing-{}", uuid::Uuid::new_v4());
    // Make sure no stale entry is present.
    let _ = vault_macos::delete_password(PROD_SERVICE, &account);

    let got = vault_macos::get_password_user_presence(PROD_SERVICE, &account)
        .expect("get on missing entry");
    assert!(
        got.is_none(),
        "missing entry must map errSecItemNotFound to Ok(None), got {got:?}"
    );
}
