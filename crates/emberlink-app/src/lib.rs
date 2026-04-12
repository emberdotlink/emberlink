//! Shared application runtime for Emberlink product surfaces.
//!
//! All product surfaces (CLI, desktop GUI, browser extension native host)
//! depend on this crate rather than reaching directly into `core_*` crates.
//! The crate owns:
//!
//! - [`AppRuntime`] — the single dispatch entry point, generic over any
//!   [`AppBackend`] so it works with both the SQLite event store (native) and
//!   the in-memory backend (WASM / tests)
//! - [`AppBackend`] — the trait combining [`EventLog`] with app-layer ops
//!   (grants, device-key enrollment)
//! - [`AppSnapshot`] + view types — stable read models for frontends
//! - [`UiAction`] — the structured command enum
//! - [`AppConfig`] — explicit path and env-var configuration
//! - Crypto helpers — encrypt/decrypt/persist `local-state.enc`
//!
//! **No deps on `tauri`, `keyring`, or platform UI** — those stay in the
//! application shells. Callers supply `content_key: String` from their own
//! keychain or env-var layer.

pub mod backend;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod local_state;
pub mod runtime;
pub mod snapshot;

pub use backend::AppBackend;
pub use commands::UiAction;
pub use config::{AppConfig, default_user_dir};
pub use crypto::{atomic_write_bytes, decrypt_state, encrypt_state, load_state, persist_state};
pub use local_state::{EphemeralKeyEntry, LocalKeyEntry, LocalState};
pub use runtime::AppRuntime;
pub use snapshot::{
    AppSnapshot, BadgeGalleryEntry, BadgeView, CredentialView, DeviceView, GrantDetailView,
    GrantHistoryView, GrantSummaryView, PersonaView, RecoveryStatusView, RootView, TrustView,
};
