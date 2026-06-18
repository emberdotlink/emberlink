//! Shared interactive-unlock state for the daemon runtime.
//!
//! This module is the current seam between the daemon's live interactive
//! vault lane and the session lifecycle. It deliberately owns only the
//! shipped substrate:
//!
//! - the shared live-vault slot that explicit lock clears
//! - the session-pin tracker used by `register_session` / session-close paths
//! - the synthetic non-session grace marker used by explicit `vault_unlock`
//! - short request pins used by ordinary first-op lazy reopen

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::infra::config::DaemonConfig;
use crate::infra::store::{DaemonStore, LiveVaultSlot};
use crate::infra::unlock_pin::UnlockPinTracker;
use crate::infra::vault::{PresenceUnwrappedKek, Vault, VaultKeyStore};

pub(crate) const OPERATOR_UNLOCK_LANE_GUIDANCE: &str = "same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. \
     Run `ember vault unlock` to invoke the managed separate-uid biometric unlock flow \
     when available. If you are on a dev probe lane, restart the daemon with \
     `EMBER_VAULT_PASSPHRASE`; future broker-mediated browser auth remains planned";

#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveVaultUnavailable;

impl LiveVaultUnavailable {
    pub(crate) fn with_context(self, context: &str) -> String {
        format!("{context}: {self}")
    }
}

impl std::fmt::Display for LiveVaultUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "live vault is locked; {OPERATOR_UNLOCK_LANE_GUIDANCE}")
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

/// Read the daemon runtime config from the same-process interactive reopen slot.
/// Consumed by the ADR 206 §4 vault unlock/provision handler arms in
/// `infra/handler.rs`; suppress the dead-code lint on non-macOS so the Linux
/// build (the autopilot host) doesn't emit a spurious warning.
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
    format!("{op}: live vault is locked; {OPERATOR_UNLOCK_LANE_GUIDANCE}")
}

fn ensure_vault_reopened(store: &DaemonStore, op: &str) -> Result<Rc<Vault>, String> {
    if let Ok(vault) = current_live_vault(store) {
        return Ok(vault);
    }

    let slot = MANAGER.with(|manager| {
        let manager = manager.borrow();
        manager
            .live_vault_slot
            .clone()
            .unwrap_or_else(|| store.vault_slot())
    });

    if let Some(vault) = slot.get() {
        return Ok(vault);
    }

    // ADR 216: direct SE unseal is removed — the daemon runs as uid=450
    // (System/0 domain) where the SE is unreachable. Vault unlock now
    // happens via the double-envelope CLI relay (vault.de_unlock_complete).
    Err(LiveVaultUnavailable.with_context(op))
}

fn ensure_vault_reopened_from_bootstrap_cache(
    store: &DaemonStore,
    op: &str,
) -> Result<Rc<Vault>, String> {
    if let Ok(vault) = current_live_vault(store) {
        return Ok(vault);
    }

    let slot = MANAGER.with(|manager| {
        let manager = manager.borrow();
        manager
            .live_vault_slot
            .clone()
            .unwrap_or_else(|| store.vault_slot())
    });

    if let Some(vault) = slot.get() {
        return Ok(vault);
    }

    // ADR 216: direct SE unseal is removed (same reason as ensure_vault_reopened).
    Err(LiveVaultUnavailable.with_context(op))
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

/// ADR 206 §4 — install the operator-session-unwrapped scope KEK (KEK_s) as the
/// live interactive vault key (presence-as-decryption unlock). The operator
/// session performed the `se_unwrap` tap and submitted the raw KEK_s; the daemon
/// opens the split-key vault via [`VaultKeyStore::PresenceScopeKek`] and publishes
/// it to the live slot for the unlock window.
///
/// The submitted KEK_s is AUTHORITATIVE: this does NOT short-circuit on an
/// already-attached vault. A daemon that auto-attached a startup MEK vault (or a
/// dev `EMBER_VAULT_PASSPHRASE` vault) is serving a NON-KEK_s key; an idempotent
/// early-return there would silently DROP the submitted KEK_s — the §4 custody
/// re-point would not happen, and (at provision) the canary would be sealed under
/// the wrong key. So we always open a fresh KEK_s vault and REPLACE the slot. The
/// open happens before the slot swap, so a failed open (wrong/corrupt KEK_s)
/// leaves any existing vault untouched rather than leaving the slot empty.
///
/// Canary is NOT verified here: on the §4 lane the interactive key is KEK_s, so a
/// canary sealed under a prior MEK would false-alarm across the clean break. Key
/// correctness is enforced by the per-open AEAD — a wrong KEK_s fails every
/// authority `open`/`unseal` closed. Wiring `verify_canary` onto this path (now
/// that provisioning re-seals the canary under KEK_s) is a follow-up hardening.
pub fn install_presence_scope_kek_vault(
    store: &DaemonStore,
    kek: [u8; 32],
) -> Result<Rc<Vault>, String> {
    install_presence_scope_kek_vault_inner(store, kek, false)
}

/// ADR 206 §1 (AC-2) — install `KEK_s` as the live interactive vault key
/// WITHOUT flipping the presence session to Unlocked (no standing window).
///
/// This is the transient-KEK widening install: the dispatcher installs `KEK_s`
/// from the operator's batched widening gesture for the duration of ONE minting
/// op (which seals under `KEK_s`) and EVICTS it on return. Unlike
/// [`install_presence_scope_kek_vault`] (the `vault.se_unlock_complete` standing
/// unlock, which marks the session unlocked + arms the grace window), this leaves
/// the presence session Locked so the widening path holds no time-window state.
/// The op is authorized on the verified §1 proof + this op-supplied `KEK_s`, not
/// on a presence-unlocked flag.
pub fn install_presence_scope_kek_vault_leave_locked(
    store: &DaemonStore,
    kek: [u8; 32],
) -> Result<Rc<Vault>, String> {
    install_presence_scope_kek_vault_inner(store, kek, true)
}

fn install_presence_scope_kek_vault_inner(
    store: &DaemonStore,
    kek: [u8; 32],
    leave_locked: bool,
) -> Result<Rc<Vault>, String> {
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
        "vault_se_unlock: interactive unlock config not registered; cannot install §4 vault"
            .to_string()
    })?;

    // Open the KEK_s vault FIRST; only swap the live slot on success so a failed
    // open does not detach a vault that was already serving.
    let key_store = VaultKeyStore::PresenceScopeKek(PresenceUnwrappedKek(Zeroizing::new(kek)));
    let opened = if leave_locked {
        Vault::open_with_key_store_leave_locked(&config, &key_store)
    } else {
        Vault::open_with_key_store(&config, &key_store)
    };
    let vault = Rc::new(
        opened.map_err(|e| format!("vault_se_unlock: failed to open §4 scope-KEK vault: {e}"))?,
    );
    slot.set(Rc::clone(&vault));
    if leave_locked {
        tracing::info!(
            "ADR 206 §1: installed transient presence-scope-KEK vault (no standing window)"
        );
    } else {
        tracing::info!("ADR 206 §4: installed presence-scope-KEK vault to the live slot");
    }

    // ADR 206 §4 + ADR 211 — the vault is in the slot but `BoundLeaseRegistry::mint`
    // ALSO needs a live lease-KEK to write a `lease_blobs` row; without one, every
    // grant minted on a §4-unlocked daemon falls through the in-memory-only branch
    // and the per-session proxy's fresh `DaemonStore` 403s `no_live_lease` on the
    // first request. Pair the lease-KEK install with the §4 vault install so the
    // two move together. Loud + non-fatal: vault stays attached even if lease-KEK
    // setup fails (mirrors `rehydrate_persisted_leases` in handler.rs:1952).
    if let Err(e) = ensure_lease_kek_for_session(store) {
        tracing::error!(
            error = %e,
            "ADR 211 lease-KEK: pairing install with §4 vault failed; \
             vault remains attached but grants will mint in-memory only this session"
        );
    }

    Ok(vault)
}

/// ADR 206 §4 + ADR 211 — pair the lease-KEK install with the §4 vault install.
///
/// `BoundLeaseRegistry::mint` only writes a `lease_blobs` row when
/// `store.lease_kek()` is `Some`; without that the per-session proxy's fresh
/// `DaemonStore` cannot rehydrate the lease and the first model-auth request
/// 403s `no_live_lease`. The §4 unlock used to leave the lease-KEK slot empty,
/// which manifested as the V030-NO-LIVE-LEASE-AFTER-FRESH-INIT regression.
///
/// Three branches:
///   (a) `store.lease_kek().is_some()` — already provisioned (prior session DE
///       flow or this session's transient widening); no-op.
///   (b) lease-KEK slot empty but the persisted DE outer blob is on disk — the
///       SE peel requires an interactive CLI relay (Aqua/501 Touch ID) which is
///       NOT callable from inside the daemon-side §4 unlock handler. Emit a
///       clear `tracing::warn!` and return Ok; the operator's recourse today is
///       a follow-up DE-unlock RPC. CLI-side wiring to chain
///       `attempt_de_unlock_purpose("lease_kek")` after `vault.se_unlock_complete`
///       is filed as a follow-up.
///   (c) lease-KEK slot empty and no DE outer blob (the dev0 daily-driver
///       fresh-init shape — pre-ADR-216 disk state, §4 wraps exist but lease-KEK
///       was never set up) — install a fresh in-memory lease-KEK so this
///       session's grants persist their wrapped lease blob to `lease_blobs`
///       (cross-store visible). The lease-KEK itself does NOT survive a daemon
///       restart; the durable DE-provision lane also needs CLI SE-wrap and is
///       the same follow-up wiring as (b). The warn loop closes when DE custody
///       lands.
///
/// Loud + non-fatal: a Sqlite read failure on the DE outer probe surfaces but
/// does NOT block — the caller logs and continues so the §4 vault stays
/// attached. Returning Ok on the warn cases is intentional: the helper is a
/// best-effort pair, not a gate.
fn ensure_lease_kek_for_session(store: &DaemonStore) -> Result<(), String> {
    if store.lease_kek().is_some() {
        // (a) — a prior path (DE-unlock, DE-provision, or this session's
        // earlier widening install) already populated the slot.
        tracing::debug!("ADR 211 lease-KEK already provisioned; §4 install pairs cleanly");
        return Ok(());
    }
    let de_outer = store
        .read_lease_kek_double_envelope_outer()
        .map_err(|e| format!("ADR 211 lease-KEK: reading DE outer blob: {e}"))?;
    if de_outer.is_some() {
        // (b) — durable lease-KEK exists on disk but the slot is empty. The
        // SE peel is a CLI-side operation; we cannot drive it from here.
        tracing::warn!(
            "ADR 211 lease-KEK: persisted DE outer blob is on disk but the slot is \
             empty; the §4 unlock context cannot drive the SE peel. Grants minted \
             in this session will fall through to in-memory-only (no lease_blobs \
             row) and the per-session proxy may 403 closed on first request. \
             Run an explicit lease-KEK DE-unlock to install the persisted key \
             durably; a follow-up wires this into the §4 unlock flow."
        );
        return Ok(());
    }
    // (c) — first-boot for lease-KEK on this host (no DE persistence yet).
    // Install fresh in-memory so this session's mints persist their blobs;
    // lease-KEK durability across restarts requires the CLI SE-wrap relay
    // (follow-up).
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|e| format!("ADR 211 lease-KEK: OS entropy: {e}"))?;
    let lease_kek = crate::trust::lease::LeaseWrapKey::from_raw(*raw);
    store.set_lease_kek(lease_kek);
    tracing::warn!(
        "ADR 211 lease-KEK: first-boot installed IN MEMORY ONLY (no DE persistence). \
         Grants minted this session persist to `lease_blobs` and the per-session \
         proxy can rehydrate them (closes V030-NO-LIVE-LEASE-AFTER-FRESH-INIT), \
         but the lease-KEK is lost on daemon restart and any persisted blobs from \
         this session become unrecoverable. Provision durable lease-KEK custody \
         via the CLI SE-wrap relay (follow-up) to retire this warning."
    );
    Ok(())
}

/// ADR 206 §1 (AC-2) — evict the live-vault slot ONLY, leaving session pins and
/// presence state untouched. Used by the transient-KEK widening eviction guard
/// to drop the `KEK_s` vault installed for one minting op (the `Rc<Vault>` drop
/// triggers `ZeroizeOnDrop`, wiping the in-memory `KEK_s`) without the heavier
/// `explicit_lock` semantics that also forget session pins. The transient path
/// never armed a window or acquired a pin, so there is nothing else to tear down
/// — and clobbering a concurrently-open session's pin would be wrong.
pub fn evict_live_vault_slot(store: &DaemonStore) {
    let slot = MANAGER.with(|manager| {
        manager
            .borrow()
            .live_vault_slot
            .clone()
            .unwrap_or_else(|| store.vault_slot())
    });
    slot.clear();
}

/// Legacy operator-uid `vault_unlock` no longer reopens a hard-locked daemon.
/// Managed separate-uid installs keep using `vault_unlock_begin` /
/// `vault_unlock_complete`, while same-daemon operator-uid reopen is allowed
/// only when the daemon is carrying an explicit env/bootstrap passphrase cache.
pub fn ensure_live_vault_for_legacy_unlock(store: &DaemonStore) -> Result<Rc<Vault>, String> {
    ensure_vault_reopened_from_bootstrap_cache(store, "vault_unlock")
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
            rendered.contains("live vault is locked"),
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
    fn install_presence_scope_kek_replaces_stale_attached_vault() {
        // ADR 206 §4 (adversarial-review HIGH): the submitted KEK_s is
        // authoritative. A daemon serving a stale non-KEK_s vault (e.g. the
        // startup MEK-attached vault) must have it REPLACED — an idempotent
        // early-return would silently drop KEK_s (custody re-point no-op) and,
        // at provision, seal the canary under the wrong key.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_for_tests();

        let tmp = tempfile::tempdir().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let store = DaemonStore::open_in_memory().expect("open in-memory store");

        // A stale (non-KEK_s) vault is already attached.
        let stale = Rc::new(Vault::new([0x55u8; 32]));
        store.set_vault(Rc::clone(&stale));
        register_vault_slot(store.vault_slot());
        register_config(config);

        let kek = [0x42u8; 32];
        let installed =
            install_presence_scope_kek_vault(&store, kek).expect("install §4 scope-KEK vault");

        assert!(
            !Rc::ptr_eq(&installed, &stale),
            "install must REPLACE the stale attached vault, not return it"
        );
        assert!(
            Rc::ptr_eq(&store.vault().expect("vault attached"), &installed),
            "the live slot must hold the freshly-installed §4 vault"
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
