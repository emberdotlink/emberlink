//! Agent-spawn helpers — container mount tables, per-agent socket wiring,
//! and other glue between the daemon's spawn path and the runtime that
//! actually launches the agent container.
//!
//! The `scion` submodule owns the per-agent UDS socket bind-mount story
//! for the implementation-note-235 hardening (CRIT-1 + CRIT-C).

pub mod checkpoint;
// implementation-note-349 — modern-Linux clone3 +
// user-namespace spawn primitive that makes design's per-spawn uid
// pool functional. See `exec_domain.rs` top-of-file for design
// §Component 2 rationale.
pub mod exec_domain;
pub mod runtime;
pub mod scion;
