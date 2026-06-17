//! CLASSIFICATION: PUBLIC
//!
//! Shared test-helper module. Per cargo integration-test convention,
//! files under `tests/common/` are loaded into a sibling test crate via
//! `mod common;` (and `tests/common/mod.rs` declares the submodules).
//! Without this `mod.rs` cargo treats `spawn.rs` as a separate
//! integration-test crate, and any sibling integration test that needs
//! `TestDaemonHandle` cannot reach it via the `common::` path.

pub mod spawn;
