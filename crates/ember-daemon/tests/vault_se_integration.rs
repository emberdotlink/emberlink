//! CLASSIFICATION: PUBLIC
//! T2 integration: SE-rooted vault path — RETIRED (ADR 216 S4).
//!
//! The direct SE unseal path (`se_unseal_interactive`, `try_se_unseal`,
//! `se_unseal_with_presence`) was deleted in ADR 216 S4. The vault now
//! opens exclusively via the double-envelope RPC
//! (`vault.de_unlock_complete`). The SE wrap/unwrap primitives survive
//! in `vault_macos_se.rs` for the CLI relay's outer-envelope operations.
//!
//! This file is intentionally empty — the test contract it pinned
//! (SE unseal round-trip) no longer exists as a code path.
