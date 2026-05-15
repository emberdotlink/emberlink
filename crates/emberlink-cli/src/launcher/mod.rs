//! Subprocess launchers for friendly-dev integrations (`ember claude-code`).
//!
//! Per design §2 / implementation-note-272: thin wrappers that register a session with
//! the daemon, inject the appropriate env vars, and `exec` the upstream
//! binary. Today the daemon round-trip is stubbed (real RPC lands in
//! implementation-note-60 / implementation-note-217); the env shape and exit semantics are locked
//! here so the rest of the cohort A flow can call this surface from day
//! one without re-shaping the launcher when the stubs are filled in.

pub mod banner;
pub mod claude_code;
pub mod path_shadow;
