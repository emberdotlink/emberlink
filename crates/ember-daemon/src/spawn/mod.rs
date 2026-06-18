//! Agent-spawn helpers — container mount tables, per-agent socket wiring,
//! and other glue between the daemon's spawn path and the runtime that
//! actually launches the agent container.
//!
//! The `scion` submodule owns the per-agent UDS socket bind-mount story
//! for the SCION-PER-AGENT-UDS-SOCKET hardening (CRIT-1 + CRIT-C).

pub mod checkpoint;
// META-EXEC-DOMAIN-CLONE3-SPAWN-MODULE — modern-Linux clone3 +
// user-namespace spawn primitive that makes ADR 167's per-spawn uid
// pool functional. See `exec_domain.rs` top-of-file for ADR 155
// §Component 2 rationale.
pub mod exec_domain;
pub mod runtime;
pub mod scion;
