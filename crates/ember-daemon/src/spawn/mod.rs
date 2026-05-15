//! Agent-spawn helpers — container mount tables, per-agent socket wiring,
//! and other glue between the daemon's spawn path and the runtime that
//! actually launches the agent container.
//!
//! The `scion` submodule owns the per-agent UDS socket bind-mount story
//! for the implementation-note-104 hardening (CRIT-1 + CRIT-C).

pub mod checkpoint;
pub mod scion;
