//! ember-presence — shared client-side presence acquisition.
//!
//! This crate is the single home for the machinery that turns "the operator is
//! physically here" into a daemon-honored authority artifact. It was extracted
//! from `emberlink-cli` so that **both** the CLI and `internal-automation` (the
//! autopilot engine) drive the same audited code instead of each carrying its
//! own copy of the LocalAuthentication FFI and the vault-unlock ceremony.
//!
//! ## Why a base crate (and not a shared dep edge)
//!
//! `ember-daemon` depends on `internal-automation` (it reads internal-automation-owned on-disk
//! formats), and `emberlink-cli` depends on `ember-daemon`. That dependency
//! chain means `internal-automation` cannot reach the CLI's presence code directly
//! without a cycle. `ember-presence` sits at the `core-crypto` layer — below
//! all three — so each can depend on it cleanly.
//!
//! ## What lives here vs. what stays in the caller
//!
//! The genuinely shared, hard-to-duplicate pieces live here:
//!   * [`biometric`] — the macOS `LocalAuthentication.framework` Touch ID FFI,
//!     consumed by the CLI's backup/restore presence prompts.
//!   * [`rpc`] — [`DaemonRpcError`] + a *plain* daemon UDS JSON-RPC client and
//!     [`authority_error_reason`].
//!
//! ADR 206 slice 4 C retired the forgeable daemon-rooted vault-unlock ceremony
//! (`vault_unlock_begin → local-auth → presence_complete → vault_unlock_complete`,
//! plus the managed-unlock authority). Operator presence is now sourced from the
//! §4 presence-as-decryption unlock (`ember vault se-unlock`), so the shared
//! `ceremony` module and its `CeremonyHost` indirection were deleted.
//!
//! CLASSIFICATION: PUBLIC

pub mod biometric;
pub mod rpc;

pub use rpc::{DaemonRpcError, authority_error_reason, daemon_rpc_once};

/// Re-exported so consumers can name the biometric prompt policy without also
/// depending on `core-crypto`.
pub use core_crypto::presence::PresencePromptPolicy;
