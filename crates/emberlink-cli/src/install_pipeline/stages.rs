//! Five-stage definition + the `StageHandler` trait the state machine
//! drives (ADR 163 §Component 1).
//!
//! Stages 0-4 themselves are **out of scope for this umbrella PR** —
//! META-ONBOARDING-STAGE-{0,1,2,3,4}-* are `human_only=true` in
//! `tasks.toml` and the operator will execute them by hand on day 2 of the
//! v0.3.0 push. This module wires the umbrella that calls into them and
//! keeps a `NoopStageHandler` test stub so the machine mechanics can run
//! end-to-end without the real stage bodies.
//!
//! CLASSIFICATION: PUBLIC

use std::fmt;

/// The five canonical onboarding stages, in order. The variants are
/// numbered so `Stage::ORDER` and `Stage::from_slug` round-trip cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Stage 0 — preflight (OS / dependencies / FileVault / journey overview).
    Preflight,
    /// Stage 1 — workstation primitives (uid/group, dual-IR generation,
    /// mandatory backup prompt).
    Primitives,
    /// Stage 2 — GitHub auth + GH App installation + repo clone.
    GithubProvisioning,
    /// Stage 3 — daemon install (launchctl / systemd service + first-start).
    DaemonInstall,
    /// Stage 4 — end-to-end smoke test + audit-trail emission.
    SmokeTest,
}

impl Stage {
    /// Canonical execution order. The state machine drives stages in this
    /// order; `--resume` picks up at the first non-`Complete`/`Skipped`
    /// entry.
    pub const ORDER: &'static [Stage] = &[
        Stage::Preflight,
        Stage::Primitives,
        Stage::GithubProvisioning,
        Stage::DaemonInstall,
        Stage::SmokeTest,
    ];

    /// Persistent slug used as the key in `install-state.toml`'s `[stages]`
    /// table. Stable across schema versions; do NOT rename without a
    /// schema_version bump.
    pub fn slug(self) -> &'static str {
        match self {
            Stage::Preflight => "preflight",
            Stage::Primitives => "primitives",
            Stage::GithubProvisioning => "github_provisioning",
            Stage::DaemonInstall => "daemon_install",
            Stage::SmokeTest => "smoke_test",
        }
    }

    /// Inverse of [`Stage::slug`] — parse a slug (case-insensitive,
    /// `-`/`_` normalized) back to a `Stage`. Used by `--redo <slug>`.
    pub fn from_slug(s: &str) -> Option<Stage> {
        let norm = s.trim().to_ascii_lowercase().replace('-', "_");
        match norm.as_str() {
            "preflight" | "stage_0" | "0" => Some(Stage::Preflight),
            "primitives" | "stage_1" | "1" => Some(Stage::Primitives),
            "github_provisioning" | "github" | "stage_2" | "2" => Some(Stage::GithubProvisioning),
            "daemon_install" | "daemon" | "stage_3" | "3" => Some(Stage::DaemonInstall),
            "smoke_test" | "smoke" | "stage_4" | "4" => Some(Stage::SmokeTest),
            _ => None,
        }
    }

    /// One-line label printed when the stage starts running. Operator-facing.
    pub fn label(self) -> &'static str {
        match self {
            Stage::Preflight => "Stage 0 — preflight (OS / dependencies / FileVault)",
            Stage::Primitives => "Stage 1 — workstation primitives (uids, IdentityRoots, backup)",
            Stage::GithubProvisioning => "Stage 2 — GitHub App provisioning",
            Stage::DaemonInstall => "Stage 3 — daemon install + manifest signing",
            Stage::SmokeTest => "Stage 4 — first-session smoke test + Receipt verify",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Result of running a single stage.
#[derive(Debug, Clone)]
pub enum StageOutcome {
    /// Stage finished successfully.
    Complete,
    /// Stage was deliberately skipped by the operator (e.g.
    /// `--skip-github-provisioning`). The pipeline moves on.
    Skipped {
        /// Human-readable reason recorded in the state file.
        reason: String,
    },
}

/// Error type stages return on failure.
///
/// The state machine writes the message into the state file's
/// `StageStatus::Failed { error }` field, so keep it short and
/// operator-actionable.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StageError(pub String);

impl StageError {
    /// Build a stage error from anything that prints.
    pub fn new(msg: impl fmt::Display) -> Self {
        Self(msg.to_string())
    }
}

/// The contract the state machine drives. Each stage is a separate
/// trait impl in a sibling task (`META-ONBOARDING-STAGE-*`).
///
/// Implementations should be idempotent — the umbrella may call `run`
/// again on a stage whose previous run failed, and the operator may
/// invoke `--redo <stage>` to force re-execution after a successful
/// completion. The handler should not assume "first call" semantics.
pub trait StageHandler {
    /// Run the stage. The umbrella records timing + status around this
    /// call; the handler only needs to do the work.
    fn run(&self, stage: Stage) -> Result<StageOutcome, StageError>;
}

/// Production `StageHandler` used until the real ADR 163 stage bodies land.
///
/// This deliberately fails closed: a no-op install handler must not stamp
/// `install-state.toml` as complete or provide ship-gate evidence for
/// Conditions 1/2.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingStageHandler;

impl StageHandler for PendingStageHandler {
    fn run(&self, stage: Stage) -> Result<StageOutcome, StageError> {
        Err(StageError::new(format!(
            "{} is not implemented yet; META-ONBOARDING-PIPELINE-STATE-MACHINE must wire real ADR 163 stage bodies before `ember dev install` can complete",
            stage.label()
        )))
    }
}

/// Test stub `StageHandler`. Returns
/// `StageOutcome::Complete` for every stage without doing any work.
///
/// **Why this exists:** per the META-ONBOARDING-STAGE-{0..4}-* tasks,
/// the real stage bodies are not fully wired. The production entrypoint
/// uses [`PendingStageHandler`] so missing stage bodies fail closed; tests
/// use this stub to exercise resume, state persistence, and `--redo`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStageHandler;

impl StageHandler for NoopStageHandler {
    fn run(&self, _stage: Stage) -> Result<StageOutcome, StageError> {
        Ok(StageOutcome::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_contains_all_five_stages() {
        assert_eq!(Stage::ORDER.len(), 5);
        // each slug is distinct
        let mut slugs: Vec<&str> = Stage::ORDER.iter().map(|s| s.slug()).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), 5);
    }

    #[test]
    fn order_is_preflight_first_smoke_last() {
        assert_eq!(Stage::ORDER.first(), Some(&Stage::Preflight));
        assert_eq!(Stage::ORDER.last(), Some(&Stage::SmokeTest));
    }

    #[test]
    fn slug_round_trips_for_canonical_form() {
        for s in Stage::ORDER {
            assert_eq!(Stage::from_slug(s.slug()), Some(*s));
        }
    }

    #[test]
    fn from_slug_accepts_aliases() {
        assert_eq!(Stage::from_slug("0"), Some(Stage::Preflight));
        assert_eq!(Stage::from_slug("stage-0"), Some(Stage::Preflight));
        assert_eq!(Stage::from_slug("STAGE_0"), Some(Stage::Preflight));
        assert_eq!(Stage::from_slug("github"), Some(Stage::GithubProvisioning));
        assert_eq!(Stage::from_slug("smoke"), Some(Stage::SmokeTest));
    }

    #[test]
    fn from_slug_rejects_garbage() {
        assert_eq!(Stage::from_slug(""), None);
        assert_eq!(Stage::from_slug("stage_5"), None);
        assert_eq!(Stage::from_slug("preflight!"), None);
    }

    #[test]
    fn noop_handler_returns_complete_for_every_stage() {
        let h = NoopStageHandler;
        for s in Stage::ORDER {
            assert!(matches!(h.run(*s).unwrap(), StageOutcome::Complete));
        }
    }

    #[test]
    fn pending_handler_fails_closed_for_every_stage() {
        let h = PendingStageHandler;
        for s in Stage::ORDER {
            let err = h.run(*s).expect_err("pending handler must fail closed");
            assert!(
                err.0.contains("not implemented yet"),
                "unexpected error for {s}: {err}"
            );
        }
    }
}
