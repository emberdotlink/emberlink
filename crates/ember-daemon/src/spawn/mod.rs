//! Agent-spawn helpers — container mount tables, per-agent socket wiring,
//! and other glue between the daemon's spawn path and the runtime that
//! actually launches the agent container.
//!
//! The `scion` submodule owns the per-agent UDS socket bind-mount story
//! for the implementation-note-150 hardening (CRIT-1 + CRIT-C).

pub mod checkpoint;
// implementation-note-91 — Compose V2 spawn
// lifecycle. Translates a `ComposeManifest` (from ember-construct)
// into a bollard spec via `compose_manifest_to_docker_spec`, asserts
// the daemon's privileged-network-mode invariant, and dispatches via
// `docker_engine_spawn`.
pub mod compose;
// implementation-note-107 — bollard-backed Docker
// engine client + connection helper. Used by the daemon's broker path
// when a Construct invocation needs to talk to the local engine
// (Docker Desktop on macOS, dockerd on Linux, OrbStack, etc.).
pub mod docker;
// implementation-note-388 — modern-Linux clone3 +
// user-namespace spawn primitive that makes design's per-spawn uid
// pool functional. See `exec_domain.rs` top-of-file for design
// §Component 2 rationale.
pub mod exec_domain;
pub mod scion;
