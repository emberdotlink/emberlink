//! presence_cache_invalidation_impl_landed
//!
//! OS-level presence-event watchers that drain the 8h dev0 presence
//! cache (Knob 25) on screen-lock, sleep, and inactivity-timeout signals.
//!
//! This module is the cfg-gated bridge between the OS-native signal
//! transports (NSDistributedNotificationCenter on macOS, logind D-Bus
//! signals on Linux) and the synchronous `PresenceCache::invalidate_for_principal`
//! drain API defined in `ember-memory::cache`. The drain primitive ships
//! in this task; the actual subscriptions ship as stubs (tracing-only)
//! and wire to real OS events in a successor task.
//!
//! Trust-state gating (whether to actually drain on a given event) is
//! NOT this module's concern — it lives in `crate::trust::presence`,
//! which owns the per-session lock state machine. These watchers are
//! the *transport*; the cache drain is the *effect*.

#[cfg(target_os = "linux")]
pub mod invalidation_linux;
#[cfg(target_os = "macos")]
pub mod invalidation_macos;
