//! presence_cache_invalidation_impl_landed
//! CLASSIFICATION: PUBLIC
//!
//! Linux logind D-Bus subscription for `org.freedesktop.login1` Lock
//! and PrepareForSleep signals. On either signal the watcher drains
//! the dev0 presence cache scoped to the active principal — see
//! `ember_memory::cache::PresenceCache::invalidate_for_principal`.
//!
//! ## Scaffold status
//!
//! Stub shipped with META-PRESENCE-CACHE-INVALIDATION-IMPL. The real
//! `zbus`-based subscription lands in a successor task; this file
//! holds the type + signature so call sites in
//! `crate::infra::runtime` can wire the watcher into the daemon's
//! startup tasks behind a `#[cfg(target_os = "linux")]` gate.
//!
//! ## Future work
//!
//! - Open a system-bus connection (`zbus::Connection::system().await`).
//! - Subscribe to `org.freedesktop.login1.Session.Lock` and
//!   `org.freedesktop.login1.Manager.PrepareForSleep(true)`.
//! - On Lock: call `cache.invalidate_for_principal(active_principal,
//!   InvalidationReason::ScreenLock)`.
//! - On PrepareForSleep(true): same, with `InvalidationReason::Sleep`.
//! - Active-principal lookup wires through the daemon's session table
//!   once the multi-principal presence model lands.

use std::sync::{Arc, Mutex};

/// Linux presence-event watcher. Currently a no-op stub; logs intent
/// and returns `Ok` so call sites can adopt the API surface now.
///
/// TODO(META-PRESENCE-CACHE-INVALIDATION-IMPL successor): swap the
/// `_cache: Arc<Mutex<()>>` placeholder for
/// `Arc<Mutex<ember_memory::cache::PresenceCache>>` once `ember-memory`
/// is added to `ember-daemon`'s Cargo.toml dep list and the daemon's
/// startup wiring is ready to thread a real cache handle through.
pub struct LinuxInvalidationWatcher;

impl LinuxInvalidationWatcher {
    /// Start the watcher. In the shipped scaffold this is a no-op that
    /// emits a tracing line so the daemon's startup logs document where
    /// the (future) logind subscription would attach.
    pub async fn start(_cache: Arc<Mutex<()>>) -> anyhow::Result<()> {
        tracing::info!(
            "LinuxInvalidationWatcher::start — TODO: subscribe to logind Lock/Sleep signals"
        );
        Ok(())
    }
}
