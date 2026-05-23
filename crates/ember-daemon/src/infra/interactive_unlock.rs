//! Shared interactive-unlock state for the daemon runtime.
//!
//! This module is the current seam between the daemon's live interactive
//! vault lane and the session lifecycle. It deliberately owns only the
//! shipped substrate:
//!
//! - the shared live-vault slot that explicit lock clears
//! - the session-pin tracker used by `register_session` / session-close paths
//! - the synthetic non-session grace marker used by explicit `vault_unlock`
//!
//! It does NOT yet own ordinary first-op lazy reopen. That remains partial
//! follow-up work for design's accepted target posture.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::infra::config::DaemonConfig;
use crate::infra::store::{DaemonStore, LiveVaultSlot};
use crate::infra::unlock_pin::UnlockPinTracker;
use crate::infra::vault::Vault;

#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveVaultUnavailable;

impl LiveVaultUnavailable {
    pub(crate) fn with_context(self, context: &str) -> String {
        format!("{context}: {self}")
    }
}

impl std::fmt::Display for LiveVaultUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "live vault is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. Supported lanes: managed separate-uid biometric unlock (`vault_unlock_begin/vault_unlock_complete`), a fresh daemon bootstrap via `EMBER_VAULT_PASSPHRASE` for dev probes, or future broker-mediated browser auth"
        )
    }
}

impl std::error::Error for LiveVaultUnavailable {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractiveUnlockSnapshot {
    pub session_pin_count: usize,
    pub grace_window_secs: u64,
    pub grace_remaining_secs: u64,
    pub grace_lock_pending: bool,
    pub grace_zero_due: bool,
}

struct InteractiveUnlockManager {
    live_vault_slot: Option<LiveVaultSlot>,
    config: Option<DaemonConfig>,
    pins: UnlockPinTracker,
}

impl InteractiveUnlockManager {
    fn new() -> Self {
        Self {
            live_vault_slot: None,
            config: None,
            pins: UnlockPinTracker::new(),
        }
    }
}

thread_local! {
    static MANAGER: RefCell<InteractiveUnlockManager> =
        RefCell::new(InteractiveUnlockManager::new());
}

const NON_SESSION_UNLOCK_PIN_ID: &str = "__non_session_unlock__";

/// Register the daemon's shared vault slot so explicit operator lock can
/// cut off the main local runtime lanes in one place.
pub fn register_store(store: Rc<DaemonStore>) {
    register_vault_slot(store.vault_slot());
}

/// Register a shared live-vault slot directly.
pub fn register_vault_slot(slot: LiveVaultSlot) {
    MANAGER.with(|manager| manager.borrow_mut().live_vault_slot = Some(slot));
}

/// Register the daemon runtime config for same-process interactive reopen.
pub fn register_config(config: DaemonConfig) {
    MANAGER.with(|manager| manager.borrow_mut().config = Some(config));
}

/// Read the daemon runtime config from the same-process interactive
/// reopen slot. Consumed only by the macOS-gated `vault_unlock_begin`
/// / `vault_unlock_complete` handler arms in
/// `infra/handler.rs`; suppress the dead-code lint on non-macOS so the
/// Linux build (the headless host) doesn't emit a spurious warning.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn current_config() -> Option<DaemonConfig> {
    MANAGER.with(|manager| manager.borrow().config.clone())
}

/// Configure the shared grace window for this daemon runtime.
///
/// Startup-only today: the runtime applies the tier default before any
/// sessions or explicit unlocks exist.
pub fn configure_grace_window(duration: Duration) {
    MANAGER.with(|manager| {
        manager.borrow_mut().pins = UnlockPinTracker::with_grace_window(duration);
    });
}

/// Return the currently attached live vault from the daemon's shared slot.
///
/// This is the current read seam for the interactive vault lane. Callers that
/// need the vault itself use this helper; callsites that are allowed to reopen
/// intentionally go through the narrower explicit helpers below.
pub(crate) fn current_live_vault(store: &DaemonStore) -> Result<Rc<Vault>, LiveVaultUnavailable> {
    store.vault().ok_or(LiveVaultUnavailable)
}

fn same_daemon_reopen_guidance(op: &str) -> String {
    format!(
        "{op}: live vault is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. Supported lanes: managed separate-uid biometric unlock (`vault_unlock_begin/vault_unlock_complete`), a fresh daemon bootstrap via `EMBER_VAULT_PASSPHRASE` for dev probes, or future broker-mediated browser auth"
    )
}

fn ensure_vault_reopened(store: &DaemonStore, op: &str) -> Result<Rc<Vault>, String> {
    if let Ok(vault) = current_live_vault(store) {
        return Ok(vault);
    }

    let (slot, config) = MANAGER.with(|manager| {
        let manager = manager.borrow();
        (
            manager
                .live_vault_slot
                .clone()
                .unwrap_or_else(|| store.vault_slot()),
            manager.config.clone(),
        )
    });
    let config = config.ok_or_else(|| {
        format!("{op}: interactive unlock config not registered; cannot reopen vault")
    })?;

    if let Some(vault) = slot.get() {
        return Ok(vault);
    }

    let vault = Rc::new(
        crate::infra::vault::reopen_from_runtime_config(&config)
            .map_err(|e| format!("{op}: failed to reopen vault: {e}"))?,
    );
    slot.set(Rc::clone(&vault));
    tracing::info!(operation = op, "interactive unlock: reopened live vault");
    Ok(vault)
}

/// Return the current live vault for session-open. Same-daemon operator-uid
/// reopen is intentionally disabled so this seam fails closed instead of
/// falling back to the legacy login-keychain prompt path.
pub fn ensure_vault_for_session_open(store: &DaemonStore) -> Result<Rc<Vault>, String> {
    current_live_vault(store).map_err(|_| same_daemon_reopen_guidance("register_session"))
}

/// Explicit operator-triggered same-daemon reopen. This is narrower than the
/// accepted lazy first-session unlock posture: the caller must invoke a
/// dedicated unlock operation, and all per-method authority checks still apply
/// before the reopen is attempted.
pub fn ensure_vault_for_explicit_unlock(store: &DaemonStore) -> Result<Rc<Vault>, String> {
    ensure_vault_reopened(store, "vault_unlock")
}

/// Legacy operator-uid `vault_unlock` no longer reopens a hard-locked daemon.
/// Managed separate-uid installs keep using `vault_unlock_begin` /
/// `vault_unlock_complete`, while dev probes should start a fresh daemon with
/// an explicit bootstrap source.
pub fn ensure_live_vault_for_legacy_unlock(store: &DaemonStore) -> Result<Rc<Vault>, String> {
    current_live_vault(store).map_err(|_| same_daemon_reopen_guidance("vault_unlock"))
}

/// Start the shared grace window for a non-session explicit unlock.
///
/// `vault_unlock` has no later close event to release, so it arms the same
/// grace tracker by creating and immediately releasing a synthetic marker.
/// A later `register_session` cancels the pending zero by acquiring a real
/// session pin.
pub fn arm_non_session_grace_window() {
    arm_non_session_grace_window_at(Instant::now());
}

/// Acquire an interactive unlock pin for a newly-opened session.
pub fn acquire_session_pin(session_id: &str) -> bool {
    MANAGER.with(|manager| manager.borrow().pins.acquire_pin(session_id.to_string()))
}

/// Release the interactive unlock pin for a closed session.
pub fn release_session_pin(session_id: &str) -> bool {
    MANAGER.with(|manager| manager.borrow().pins.release_pin(session_id))
}

/// Configured grace window for the shared session-pin tracker.
pub fn grace_window() -> Duration {
    MANAGER.with(|manager| manager.borrow().pins.grace_window())
}

/// True when the last live session pin has been released and the grace
/// window has elapsed.
pub fn grace_zero_due() -> bool {
    MANAGER.with(|manager| manager.borrow().pins.should_zero())
}

pub fn snapshot() -> InteractiveUnlockSnapshot {
    MANAGER.with(|manager| {
        let pins = manager.borrow().pins.snapshot();
        InteractiveUnlockSnapshot {
            session_pin_count: pins.session_pin_count,
            grace_window_secs: pins.grace_window_secs,
            grace_remaining_secs: pins.grace_remaining_secs,
            grace_lock_pending: pins.grace_lock_pending,
            grace_zero_due: pins.grace_zero_due,
        }
    })
}

/// Explicit operator lock: clear the shared live vault and forget all active
/// session pins. Future lazy reopen / grace-zero wiring will rebuild on this
/// seam rather than re-spreading state across callers.
pub fn explicit_lock() {
    MANAGER.with(|manager| {
        let mut manager = manager.borrow_mut();
        if let Some(slot) = manager.live_vault_slot.as_ref() {
            slot.clear();
        }
        let grace_window = manager.pins.grace_window();
        manager.pins = UnlockPinTracker::with_grace_window(grace_window);
    });
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) fn pin_count() -> usize {
    MANAGER.with(|manager| manager.borrow().pins.pin_count())
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) fn set_test_grace_window(duration: Duration) {
    MANAGER.with(|manager| {
        manager.borrow_mut().pins = UnlockPinTracker::with_grace_window(duration);
    });
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) fn acquire_session_pin_at(session_id: &str, acquired_at: Instant) -> bool {
    MANAGER.with(|manager| {
        manager
            .borrow()
            .pins
            .acquire_pin_at(session_id.to_string(), acquired_at)
    })
}

#[doc(hidden)]
#[cfg(test)]
pub(crate) fn release_session_pin_at(session_id: &str, released_at: Instant) -> bool {
    MANAGER.with(|manager| {
        manager
            .borrow()
            .pins
            .release_pin_at(session_id, released_at)
    })
}

#[doc(hidden)]
pub(crate) fn grace_zero_due_at(now: Instant) -> bool {
    MANAGER.with(|manager| manager.borrow().pins.should_zero_at(now))
}

#[doc(hidden)]
pub(crate) fn arm_non_session_grace_window_at(now: Instant) {
    MANAGER.with(|manager| {
        let pins = &manager.borrow().pins;
        let _ = pins.acquire_pin_at(NON_SESSION_UNLOCK_PIN_ID.to_string(), now);
        let _ = pins.release_pin_at(NON_SESSION_UNLOCK_PIN_ID, now);
    });
}

#[doc(hidden)]
pub(crate) fn reset_for_tests() {
    MANAGER.with(|manager| *manager.borrow_mut() = InteractiveUnlockManager::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::vault::Vault;

    #[test]
    fn current_live_vault_surfaces_shared_guidance() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        let store = DaemonStore::open_in_memory_without_vault()
            .expect("open in-memory store without vault");
        let err = match current_live_vault(&store) {
            Ok(_) => panic!("store starts without a live vault"),
            Err(err) => err,
        };
        let rendered = err.with_context("vault_get");
        assert!(
            rendered.contains("vault unavailable"),
            "shared live-vault seam must keep the unavailable reason: {rendered}"
        );
        assert!(
            rendered.contains("ember vault unlock"),
            "shared live-vault seam must keep operator guidance: {rendered}"
        );
    }

    #[test]
    fn current_live_vault_returns_attached_slot() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        store.set_vault(Rc::new(Vault::new([0x31; 32])));
        assert!(
            current_live_vault(&store).is_ok(),
            "shared live-vault seam must surface the attached slot"
        );
    }

    #[test]
    fn explicit_lock_clears_live_vault_and_session_pins() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        store.set_vault(Rc::new(Vault::new([0x41; 32])));
        let store = Rc::new(store);
        register_store(Rc::clone(&store));

        assert!(acquire_session_pin("sess_a"));
        assert_eq!(pin_count(), 1, "register_session pin must be tracked");

        explicit_lock();

        assert!(
            store.vault().is_none(),
            "explicit lock must clear the shared live-vault slot"
        );
        assert_eq!(pin_count(), 0, "explicit lock must forget session pins");
    }

    #[test]
    fn session_pin_lifecycle_is_tracked_centrally() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        assert!(acquire_session_pin("sess_a"));
        assert_eq!(pin_count(), 1);
        assert!(release_session_pin("sess_a"));
        assert_eq!(pin_count(), 0);
        assert!(
            !release_session_pin("sess_missing"),
            "releasing an unknown session must stay a no-op"
        );
    }

    #[test]
    fn grace_zero_due_tracks_last_pin_release() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();
        set_test_grace_window(Duration::from_secs(1));

        let t0 = Instant::now();
        assert!(acquire_session_pin_at("sess_a", t0));
        assert!(!grace_zero_due_at(t0 + Duration::from_millis(500)));

        assert!(release_session_pin_at(
            "sess_a",
            t0 + Duration::from_millis(100)
        ));
        assert!(
            !grace_zero_due_at(t0 + Duration::from_millis(900)),
            "grace zero must wait for the grace window to elapse"
        );
        assert!(
            grace_zero_due_at(t0 + Duration::from_millis(1200)),
            "grace zero must become due after the last pin's grace window"
        );
    }

    #[test]
    fn non_session_unlock_arms_grace_without_leaking_live_pin() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();
        set_test_grace_window(Duration::from_secs(1));

        let t0 = Instant::now();
        arm_non_session_grace_window_at(t0);

        assert_eq!(
            pin_count(),
            0,
            "non-session unlock marker must not remain pinned after arming grace"
        );
        assert!(
            !grace_zero_due_at(t0 + Duration::from_millis(500)),
            "non-session unlock grace must not expire early"
        );
        assert!(
            grace_zero_due_at(t0 + Duration::from_millis(1200)),
            "non-session unlock grace must expire after the configured window"
        );
    }

    #[test]
    fn explicit_lock_preserves_configured_grace_window() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();
        set_test_grace_window(Duration::from_secs(1));

        explicit_lock();

        let t0 = Instant::now();
        arm_non_session_grace_window_at(t0);
        assert!(
            grace_zero_due_at(t0 + Duration::from_millis(1200)),
            "explicit lock must preserve the configured grace window"
        );
    }

    #[test]
    fn configure_grace_window_replaces_default_tracker_window() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        configure_grace_window(Duration::from_secs(2));

        let t0 = Instant::now();
        arm_non_session_grace_window_at(t0);
        assert!(
            !grace_zero_due_at(t0 + Duration::from_secs(1)),
            "configured grace window must replace the default tracker value"
        );
        assert!(
            grace_zero_due_at(t0 + Duration::from_secs(3)),
            "configured grace window must govern non-session unlock expiry"
        );
    }
}
