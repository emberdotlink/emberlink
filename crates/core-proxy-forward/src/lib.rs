//! core-proxy-forward — HTTP CONNECT / forward-proxy primitives.
//!
//! Skeleton substrate landed in implementation-note-41; the
//! actual forward-proxy logic migrates in a follow-up slice (implementation-note-42-
//! CRATE-RENAME-C-MIGRATE, filed separately when needed).

pub mod policy_backend;
pub use policy_backend::{
    ColocatedBackend, GrantRecord, PolicyBackend, PolicyError, PreflightDecision, ProxyState,
    ResolvedGrant,
};

// `match` is a reserved word; the raw identifier `r#match` is the canonical
// module name. Callers spell it `core_proxy_forward::r#match::...`.
pub mod r#match;
