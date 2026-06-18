//! CLASSIFICATION: PUBLIC
//!
//! proxy-forward-runtime — the generic LLM/HTTP credential-injection
//! forwarding core, linkable WITHOUT emberd's vault/MEK.
//!
//! Extracted out of `ember-daemon/src/infra/proxy.rs` (P22-S2). Every policy,
//! credential, and metering decision routes through the
//! `core_proxy_forward::PolicyBackend` trait, so this crate depends on no
//! daemon types. The daemon keeps its `DaemonPolicyBackend` /
//! `DaemonEventSink` / git-echo lane and depends on this crate for the moved
//! forwarding primitives.

pub mod forward;
pub mod pricing;
pub mod telemetry;

pub use forward::*;
