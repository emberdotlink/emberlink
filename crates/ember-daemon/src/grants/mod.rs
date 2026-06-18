//! Grant-level workflow primitives.
//!
//! This module hosts the operator-facing **workflow grant** surface — the
//! authority-side coordinator that fans a single root revoke out across the
//! parent_grant_id delegation chain. Process-lifecycle concerns
//! (SIGTERM/SIGKILL of child agent processes that run under a revoked
//! workflow) are explicitly NOT here; see [`crate::scion::lifecycle`] for the
//! orchestrator-owned seam.
//!
//! Per `feedback_authority_is_our_domain_lifecycle_isnt` (operator 2026-06-10):
//! "don't reach into containers to manage them; revoke authority +
//! cascade-revoke children + broker-fails-closed + emit receipts; orchestrator
//! handles process lifecycle."

pub mod cascade;
