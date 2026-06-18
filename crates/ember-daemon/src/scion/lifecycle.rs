//! SCION descendant lifecycle — orchestrator-owned hand-off seam.
//!
//! When a workflow root is revoked via [`crate::grants::cascade`], the daemon
//! is responsible for:
//!
//! - flipping every descendant grant to `revoked` (eager DOWNWARD cascade),
//! - dropping the descendants' authority leases,
//! - emitting per-grant terminal Receipts + the workflow-level summary,
//! - making the broker boundary fail-closed for every subsequent
//!   `broker.resolve` from any descendant.
//!
//! That is the **authority** half. The **lifecycle** half — graceful wind-
//! down → SIGTERM → SIGKILL on each descendant agent's process group — is
//! NOT the daemon's job. Per operator direction
//! (`feedback_authority_is_our_domain_lifecycle_isnt`, 2026-06-10):
//!
//! > "don't reach into containers to manage them; revoke authority +
//! > cascade-revoke children + broker-fails-closed + emit receipts;
//! > orchestrator handles process lifecycle."
//!
//! ADR 164 §Component 4 lists the SIGTERM/SIGKILL steps as part of the
//! revoke-cascade primitive, but those steps are executed by the
//! orchestrator-side container-lifecycle watcher (ADR 140's "daemon as
//! process supervisor" primitive — implemented as a SEPARATE supervisor
//! plane, not as a credential-injection proxy reaching into SCION).
//!
//! This module exists to make that boundary legible in the source tree:
//!
//! - It re-exports the [`crate::grants::cascade::LifecycleHandoff`] that the
//!   authority cascade produces; the orchestrator consumes that handoff to
//!   drive its own SIGTERM/SIGKILL timing per the cohort defaults.
//! - It documents the bounded-batch + cohort-grace contract so the
//!   orchestrator-side implementer cannot accidentally re-decide the
//!   constants. The numbers MUST stay in sync with ADR 164 §Component 4 and
//!   with [`crate::grants::cascade::Cohort`].
//! - It exposes [`LifecycleConfig`] — the operator-tunable knobs (concurrent
//!   termination cap, cohort) that the orchestrator-side worker reads.
//!
//! # Follow-up: orchestrator-side process-lifecycle cascade
//!
//! A separate task ships the orchestrator-side worker that consumes
//! `LifecycleHandoff` values and drives graceful → SIGTERM → SIGKILL across
//! the descendant process groups. That work belongs in
//! `crates/ember-daemon/src/spawn/` (the daemon-as-process-supervisor seam)
//! or in the workflow-orchestrator crate, NOT here — this module is the
//! authority side of the contract.

pub use crate::grants::cascade::{Cohort, LifecycleHandoff};

/// Bounded-batch + cohort knobs for the orchestrator-side SIGTERM/SIGKILL
/// cascade.
///
/// Per ADR 164 §R2: "Mitigation: cascade is processed in bounded-batch
/// (default 32 concurrent terminations); daemon enforces the cap; remainder
/// serialized."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleConfig {
    /// Maximum concurrent SIGTERM/SIGKILL operations across the descendant
    /// set. Default 32 per ADR 164 §R2.
    pub max_concurrent_terminations: usize,
    /// Cohort whose grace windows govern this cascade.
    pub cohort: Cohort,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            max_concurrent_terminations: 32,
            cohort: Cohort::Dev0,
        }
    }
}

impl LifecycleConfig {
    /// Materialize the cohort grace window the orchestrator MUST observe
    /// before sending SIGTERM. `None` means SIGKILL immediately (only valid
    /// when `LifecycleHandoff::immediate` is true AND the cohort permits it).
    pub fn grace_secs(&self, handoff: &LifecycleHandoff) -> Option<u64> {
        if handoff.immediate && handoff.cohort.immediate_allowed() {
            None
        } else {
            Some(handoff.cohort.grace_secs())
        }
    }

    /// SIGTERM → SIGKILL grace window the orchestrator MUST observe AFTER
    /// sending SIGTERM, before escalating to SIGKILL.
    pub fn sigterm_to_sigkill_secs(&self, handoff: &LifecycleHandoff) -> u64 {
        handoff.cohort.sigterm_to_sigkill_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_dev0_and_32_concurrent() {
        let cfg = LifecycleConfig::default();
        assert_eq!(cfg.max_concurrent_terminations, 32);
        assert_eq!(cfg.cohort, Cohort::Dev0);
    }

    #[test]
    fn immediate_handoff_skips_grace_when_cohort_permits() {
        let cfg = LifecycleConfig::default();
        let handoff = LifecycleHandoff {
            workflow_root_grant_id: "grant-root".to_string(),
            descendant_grant_ids: vec![],
            cohort: Cohort::Team0,
            immediate: true,
        };
        assert_eq!(cfg.grace_secs(&handoff), None);
        assert_eq!(cfg.sigterm_to_sigkill_secs(&handoff), 5);
    }

    #[test]
    fn non_immediate_handoff_observes_cohort_grace() {
        let cfg = LifecycleConfig::default();
        let handoff = LifecycleHandoff {
            workflow_root_grant_id: "grant-root".to_string(),
            descendant_grant_ids: vec![],
            cohort: Cohort::Dev0,
            immediate: false,
        };
        assert_eq!(cfg.grace_secs(&handoff), Some(30));
        assert_eq!(cfg.sigterm_to_sigkill_secs(&handoff), 10);
    }
}
