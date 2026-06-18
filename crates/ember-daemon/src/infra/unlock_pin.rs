//! Demand-pinned interactive vault unlock — Phase 1 substrate.
//!
//! Per ADR 139 ("Interactive: demand-pinned"), the interactive Touch-ID-gated
//! vault MEK is **demand-pinned**, not wall-clock-pinned. Sessions acquire a
//! pin on open, release it on close, and the MEK is zeroed after a grace
//! window elapses with no live pins. The grace window covers same-workflow
//! follow-ups (crash recovery, post-merge push 90s later) without re-prompting
//! Touch ID. Outside the window, the next session-open re-prompts — that IS
//! the security signal we want to keep meaningful.
//!
//! ## Phase 1 vs Phase 2
//!
//! This is **Phase 1**: the pure pin-tracking data structure. It exposes
//! `acquire_pin`, `release_pin`, and `should_zero` — no Tokio timers, no
//! Vault coupling, no real-time wall clocks. Tests inject synthetic
//! `Instant`s via `release_pin_at` to exercise grace-window semantics
//! deterministically.
//!
//! **Phase 2** (separate task `VAULT-UNLOCK-INTERACTIVE-PIN-PHASE2`) wires
//! `acquire_pin` / `release_pin` into the session-open / session-close
//! dispatch arms in `handler.rs`, adds the idle-zero handler that calls
//! `Vault::zero_scope(VaultScope::Interactive)` when `should_zero` returns
//! true, and adds the `vault_unlock` / `vault_zero` receipt kinds.
//!
//! ## !Send constraint
//!
//! The daemon runs single-threaded on a `tokio::task::LocalSet`, so the
//! tracker uses `Rc<RefCell<...>>` rather than `Arc<Mutex<...>>`. See
//! `.claude/rules/daemon.md` §"Key constraints".

use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// Session identifier carried by `UnlockPin`. The daemon uses `String`
/// session IDs throughout (see `handler.rs` — `format!("sess_{:032x}", …)`),
/// so we alias `String` here to keep the API readable without dragging in a
/// dedicated newtype.
pub type SessionId = String;

/// Default grace window for the dev0 cohort, per ADR 139.
///
/// Per-tier overrides (team0 = 2 min, ent0 = 0 min) ride through the
/// `UnlockPinTracker::with_grace_window` constructor.
pub const DEFAULT_GRACE_WINDOW: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockPinSnapshot {
    pub session_pin_count: usize,
    pub grace_window_secs: u64,
    pub grace_remaining_secs: u64,
    pub grace_lock_pending: bool,
    pub grace_zero_due: bool,
}

/// A live pin held by an open session against the interactive vault MEK.
///
/// Two pins are equal iff their `session_id` matches — `acquired_at` is
/// metadata for observability only and does NOT participate in `Hash` /
/// `Eq`. This lets `HashSet<UnlockPin>` treat the session as the identity
/// while still tracking per-pin acquisition timestamps.
#[derive(Debug, Clone)]
pub struct UnlockPin {
    pub session_id: SessionId,
    pub acquired_at: Instant,
}

impl PartialEq for UnlockPin {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
    }
}

impl Eq for UnlockPin {}

impl Hash for UnlockPin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.session_id.hash(state);
    }
}

/// Pin-tracking substrate for the interactive vault MEK.
///
/// Holds the live set of session-pin holders plus the `last_released_at`
/// timestamp used to compute grace-window expiry. Phase 1 is pure
/// data-structure logic — no timers, no Vault coupling. Phase 2 wires this
/// into the session lifecycle.
///
/// ## Cloning
///
/// `UnlockPinTracker` is cheap to clone — internally it's an `Rc<RefCell<…>>`
/// so clones share the same pin set. The daemon stashes a single tracker
/// instance and hands clones to the dispatch arms that need it.
#[derive(Clone)]
pub struct UnlockPinTracker {
    inner: Rc<RefCell<TrackerState>>,
    grace_window: Duration,
}

struct TrackerState {
    pins: HashSet<UnlockPin>,
    /// Set when the last pin is released; cleared on next acquire. `None`
    /// means either no pins have ever been released OR a pin is currently
    /// held. `should_zero` only returns true when this is `Some` AND the
    /// grace window has expired.
    last_released_at: Option<Instant>,
}

impl Default for UnlockPinTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UnlockPinTracker {
    /// Construct with the dev0 default grace window (5 minutes).
    pub fn new() -> Self {
        Self::with_grace_window(DEFAULT_GRACE_WINDOW)
    }

    /// Construct with an explicit grace window. Used for per-tier overrides
    /// (team0 = 2 min, ent0 = 0 min) and for deterministic unit tests.
    pub fn with_grace_window(grace_window: Duration) -> Self {
        UnlockPinTracker {
            inner: Rc::new(RefCell::new(TrackerState {
                pins: HashSet::new(),
                last_released_at: None,
            })),
            grace_window,
        }
    }

    /// Configured grace window. Phase 2 reads this when arming the idle-zero
    /// timer.
    pub fn grace_window(&self) -> Duration {
        self.grace_window
    }

    /// Acquire a pin for `session_id`. Idempotent — re-acquiring the same
    /// session_id replaces the previous entry (and refreshes `acquired_at`).
    /// Clears any pending zero schedule because a pin is now live.
    ///
    /// Returns `true` if this was a new acquisition (`session_id` was not
    /// previously pinned) and `false` if it replaced an existing pin.
    pub fn acquire_pin(&self, session_id: SessionId) -> bool {
        self.acquire_pin_at(session_id, Instant::now())
    }

    /// Test-only / deterministic variant of `acquire_pin` taking the
    /// `acquired_at` instant as a parameter. Wall-clock production calls
    /// should use `acquire_pin`.
    pub fn acquire_pin_at(&self, session_id: SessionId, acquired_at: Instant) -> bool {
        let mut state = self.inner.borrow_mut();
        let pin = UnlockPin {
            session_id,
            acquired_at,
        };
        // HashSet::replace returns the previous element if present — None
        // means the insert was a fresh acquisition.
        let was_new = state.pins.replace(pin).is_none();
        // Any live pin cancels a pending zero — invariant: `last_released_at`
        // is `Some` iff `pins` is empty.
        state.last_released_at = None;
        was_new
    }

    /// Release the pin for `session_id`. If this was the last live pin, the
    /// release timestamp is recorded so `should_zero` can later compute
    /// grace-window expiry. Releasing an unknown `session_id` is a no-op.
    ///
    /// Returns `true` if a pin was removed, `false` if `session_id` was not
    /// pinned.
    pub fn release_pin(&self, session_id: &str) -> bool {
        self.release_pin_at(session_id, Instant::now())
    }

    /// Test-only / deterministic variant of `release_pin` taking the
    /// release `Instant` as a parameter.
    pub fn release_pin_at(&self, session_id: &str, released_at: Instant) -> bool {
        let mut state = self.inner.borrow_mut();
        // HashSet::remove uses Hash + Eq — construct a synthetic pin with a
        // throwaway acquired_at so equality keys on session_id only.
        let probe = UnlockPin {
            session_id: session_id.to_string(),
            acquired_at: released_at,
        };
        let removed = state.pins.remove(&probe);
        if removed && state.pins.is_empty() {
            state.last_released_at = Some(released_at);
        }
        removed
    }

    /// Number of live pins. Useful for instrumentation and tests.
    pub fn pin_count(&self) -> usize {
        self.inner.borrow().pins.len()
    }

    /// True iff `session_id` currently holds a pin.
    pub fn is_pinned(&self, session_id: &str) -> bool {
        let probe = UnlockPin {
            session_id: session_id.to_string(),
            acquired_at: Instant::now(),
        };
        self.inner.borrow().pins.contains(&probe)
    }

    /// Returns true iff:
    /// - no pins are currently held, AND
    /// - the last release was at least `grace_window` ago.
    ///
    /// Phase 2's idle-zero handler polls (or schedules a Tokio timer for)
    /// `should_zero` and calls `Vault::zero_scope(VaultScope::Interactive)`
    /// when it flips to true.
    pub fn should_zero(&self) -> bool {
        self.should_zero_at(Instant::now())
    }

    /// Test-only / deterministic variant of `should_zero` taking `now` as a
    /// parameter.
    pub fn should_zero_at(&self, now: Instant) -> bool {
        let state = self.inner.borrow();
        if !state.pins.is_empty() {
            return false;
        }
        match state.last_released_at {
            Some(released_at) => now.saturating_duration_since(released_at) >= self.grace_window,
            None => false,
        }
    }

    pub fn snapshot(&self) -> UnlockPinSnapshot {
        self.snapshot_at(Instant::now())
    }

    pub fn snapshot_at(&self, now: Instant) -> UnlockPinSnapshot {
        let state = self.inner.borrow();
        let session_pin_count = state.pins.len();
        let grace_remaining_secs = if session_pin_count == 0 {
            match state.last_released_at {
                Some(released_at) => self
                    .grace_window
                    .saturating_sub(now.saturating_duration_since(released_at))
                    .as_secs(),
                None => 0,
            }
        } else {
            0
        };
        let grace_zero_due =
            session_pin_count == 0 && state.last_released_at.is_some() && grace_remaining_secs == 0;
        let grace_lock_pending =
            session_pin_count == 0 && state.last_released_at.is_some() && !grace_zero_due;
        UnlockPinSnapshot {
            session_pin_count,
            grace_window_secs: self.grace_window.as_secs(),
            grace_remaining_secs,
            grace_lock_pending,
            grace_zero_due,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_with_short_grace() -> UnlockPinTracker {
        // 1-second grace makes synthetic-Instant arithmetic easy to read.
        UnlockPinTracker::with_grace_window(Duration::from_secs(1))
    }

    #[test]
    fn acquire_then_release_then_grace_expired_should_zero() {
        let tracker = tracker_with_short_grace();
        let t0 = Instant::now();

        assert!(tracker.acquire_pin_at("sess_A".into(), t0));
        assert_eq!(tracker.pin_count(), 1);
        assert!(!tracker.should_zero_at(t0));

        // Release at t0+100ms; grace window is 1s.
        let release_at = t0 + Duration::from_millis(100);
        assert!(tracker.release_pin_at("sess_A", release_at));
        assert_eq!(tracker.pin_count(), 0);

        // Still inside grace — must NOT zero.
        let inside_grace = release_at + Duration::from_millis(500);
        assert!(!tracker.should_zero_at(inside_grace));

        // Past grace — MUST zero.
        let past_grace = release_at + Duration::from_millis(1_100);
        assert!(tracker.should_zero_at(past_grace));
    }

    #[test]
    fn acquire_during_grace_cancels_zero() {
        let tracker = tracker_with_short_grace();
        let t0 = Instant::now();

        tracker.acquire_pin_at("sess_A".into(), t0);
        let release_at = t0 + Duration::from_millis(100);
        tracker.release_pin_at("sess_A", release_at);

        // Mid-grace: should_zero is false.
        let mid_grace = release_at + Duration::from_millis(500);
        assert!(!tracker.should_zero_at(mid_grace));

        // Acquire a fresh pin during the grace window — this MUST cancel
        // the pending zero. After the would-have-expired moment, should_zero
        // is still false because a live pin is held.
        tracker.acquire_pin_at("sess_B".into(), mid_grace);
        let past_original_grace = release_at + Duration::from_millis(1_500);
        assert!(!tracker.should_zero_at(past_original_grace));
        assert_eq!(tracker.pin_count(), 1);
    }

    #[test]
    fn multiple_concurrent_pins_dont_zero_until_all_released() {
        let tracker = tracker_with_short_grace();
        let t0 = Instant::now();

        tracker.acquire_pin_at("sess_A".into(), t0);
        tracker.acquire_pin_at("sess_B".into(), t0 + Duration::from_millis(10));
        tracker.acquire_pin_at("sess_C".into(), t0 + Duration::from_millis(20));
        assert_eq!(tracker.pin_count(), 3);

        // Release two of the three; one pin remains — should_zero is false
        // regardless of how much wall-clock time passes.
        tracker.release_pin_at("sess_A", t0 + Duration::from_millis(100));
        tracker.release_pin_at("sess_B", t0 + Duration::from_millis(200));
        assert_eq!(tracker.pin_count(), 1);

        let way_past_grace = t0 + Duration::from_secs(10);
        assert!(!tracker.should_zero_at(way_past_grace));

        // Release the last pin — grace clock starts now.
        let last_release = t0 + Duration::from_millis(300);
        tracker.release_pin_at("sess_C", last_release);
        assert_eq!(tracker.pin_count(), 0);

        // Inside grace from the LAST release: no zero.
        assert!(!tracker.should_zero_at(last_release + Duration::from_millis(500)));
        // Past grace from the LAST release: zero.
        assert!(tracker.should_zero_at(last_release + Duration::from_millis(1_100)));
    }

    #[test]
    fn snapshot_reports_remaining_grace_time_not_just_configured_window() {
        let tracker = UnlockPinTracker::with_grace_window(Duration::from_secs(5));
        let t0 = Instant::now();
        tracker.acquire_pin_at("sess_A".into(), t0);

        let release_at = t0 + Duration::from_millis(100);
        tracker.release_pin_at("sess_A", release_at);

        let mid_grace = release_at + Duration::from_millis(500);
        let snapshot = tracker.snapshot_at(mid_grace);
        assert_eq!(snapshot.session_pin_count, 0);
        assert_eq!(snapshot.grace_window_secs, 5);
        assert_eq!(snapshot.grace_remaining_secs, 4);
        assert!(snapshot.grace_lock_pending);
        assert!(!snapshot.grace_zero_due);
    }

    #[test]
    fn release_unknown_session_is_noop() {
        let tracker = tracker_with_short_grace();
        let t0 = Instant::now();

        // Release-when-empty: no panic, returns false, no zero scheduled.
        assert!(!tracker.release_pin_at("nobody", t0));
        assert_eq!(tracker.pin_count(), 0);
        assert!(!tracker.should_zero_at(t0 + Duration::from_secs(10)));

        // Acquire one pin, then try to release a different session — must
        // not disturb the held pin and must not schedule a zero.
        tracker.acquire_pin_at("sess_real".into(), t0);
        assert!(!tracker.release_pin_at("sess_other", t0 + Duration::from_millis(10)));
        assert_eq!(tracker.pin_count(), 1);
        assert!(tracker.is_pinned("sess_real"));
        assert!(!tracker.should_zero_at(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn reacquiring_same_session_replaces_pin_and_clears_pending_zero() {
        let tracker = tracker_with_short_grace();
        let t0 = Instant::now();

        // Pin, release, then re-acquire the SAME session during grace.
        tracker.acquire_pin_at("sess_A".into(), t0);
        let release_at = t0 + Duration::from_millis(100);
        tracker.release_pin_at("sess_A", release_at);

        let reacquire_at = release_at + Duration::from_millis(200);
        let was_new = tracker.acquire_pin_at("sess_A".into(), reacquire_at);
        assert!(was_new, "re-acquiring after release counts as new");
        assert_eq!(tracker.pin_count(), 1);

        // Past the original grace — but the pin is held, so no zero.
        assert!(!tracker.should_zero_at(release_at + Duration::from_secs(5)));
    }

    #[test]
    fn default_grace_window_is_five_minutes() {
        let tracker = UnlockPinTracker::new();
        assert_eq!(tracker.grace_window(), DEFAULT_GRACE_WINDOW);
        assert_eq!(tracker.grace_window(), Duration::from_secs(300));
    }
}
