//! Shared client-side presence acquisition.
//!
//! The crate turns local operator presence into daemon-verifiable authority
//! evidence and provides the common daemon RPC client used by public callers.

pub mod biometric;
pub mod rpc;

pub use rpc::{DaemonRpcError, authority_error_reason, daemon_rpc_once};

/// Re-exported so consumers can name the biometric prompt policy without also
/// depending on `core-crypto`.
pub use core_crypto::presence::PresencePromptPolicy;
