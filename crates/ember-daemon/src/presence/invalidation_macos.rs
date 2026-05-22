//! presence_cache_invalidation_impl_landed
//!
//! macOS lock/sleep event subscription via NSDistributedNotificationCenter
//! for `com.apple.screenIsLocked` + IOPowerSources sleep notifications.
//! On either event the watcher drains the dev0 presence cache scoped to
//! the active principal — see `ember_memory::cache::PresenceCache::invalidate_for_principal`.
//!
//! ## Scaffold status
//!
//! This is the stub shipped with implementation-note-387.
//! The real Objective-C runtime bindings (objc2 / cocoa-foundation crate)
//! land in a successor task; the type + signature exist now so call sites
//! in `crate::infra::runtime` can wire the watcher into the daemon's
//! startup tasks behind a `#[cfg(target_os = "macos")]` gate.
//!
//! ## Future work
//!
//! - Subscribe to `com.apple.screenIsLocked` /
//!   `com.apple.screenIsUnlocked` via
//!   `NSDistributedNotificationCenter::default_center().add_observer(...)`.
//! - Subscribe to `IOPowerSources` `kIOPMMessageSystemWillSleep` via
//!   `IORegisterForSystemPower`.
//! - On lock: call `cache.invalidate_for_principal(active_principal,
//!   InvalidationReason::ScreenLock)`.
//! - On sleep: same, with `InvalidationReason::Sleep`.
//! - Active-principal lookup wires through the daemon's session table
//!   once the multi-principal presence model lands.

use std::sync::{Arc, Mutex};

/// macOS presence-event watcher. Currently a no-op stub; logs intent
/// and returns `Ok` so call sites can adopt the API surface now.
///
/// TODO(implementation-note-387 successor): swap the
/// `_cache: Arc<Mutex<()>>` placeholder for
/// `Arc<Mutex<ember_memory::cache::PresenceCache>>` once `ember-memory`
/// is added to `ember-daemon`'s Cargo.toml dep list and the daemon's
/// startup wiring is ready to thread a real cache handle through.
pub struct MacosInvalidationWatcher;

impl MacosInvalidationWatcher {
    /// Start the watcher. In the shipped scaffold this is a no-op that
    /// emits a tracing line so the daemon's startup logs document where
    /// the (future) lock/sleep subscription would attach.
    pub async fn start(_cache: Arc<Mutex<()>>) -> anyhow::Result<()> {
        tracing::info!("MacosInvalidationWatcher::start — TODO: subscribe to lock/sleep events");
        Ok(())
    }
}
