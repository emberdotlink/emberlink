//! Five-stage onboarding pipeline state machine (ADR 163 §Component 1+2,
//! META-ONBOARDING-PIPELINE-STATE-MACHINE).
//!
//! The umbrella that drives Stages 0-4 in order, persists progress to
//! `~/.config/emberlink/install-state.toml`, and supports `--resume` /
//! `--redo <stage>` for idempotent re-runs.
//!
//! # Scope of this module
//!
//! - [`state`] — `install-state.toml` schema + atomic read/write.
//! - [`stages`] — `Stage` enum + `StageHandler` trait, a fail-closed
//!   production placeholder, and a test-only `NoopStageHandler`.
//! - [`machine`] — the [`machine::StateMachine`] driver itself.
//! - [`run_install`] / [`run_install_with`] — the CLI entry point for
//!   `ember dev install` / `ember dev install --resume`.
//!
//! # What this module DOES NOT do
//!
//! The five stage bodies (META-ONBOARDING-STAGE-{0..4}-*) are not fully
//! wired yet. Production `ember dev install` therefore fails closed via
//! [`stages::PendingStageHandler`] instead of stamping fake completion
//! into `install-state.toml`. Tests still use [`stages::NoopStageHandler`]
//! to cover the state-machine mechanics.
//!
//! Anchor: `onboarding_pipeline_state_machine_landed`.
//!
//! CLASSIFICATION: PUBLIC

pub mod machine;
pub mod stages;
pub mod state;

use machine::{Plan, StateMachine};
use stages::{PendingStageHandler, Stage, StageHandler};
use state::InstallState;

/// Checkpoint constant required by the autopilot `target_state_anchor` gate.
/// Its presence in the compiled binary confirms the umbrella state
/// machine landed for META-ONBOARDING-PIPELINE-STATE-MACHINE.
#[doc(hidden)]
pub const SENTINEL_ONBOARDING_PIPELINE_STATE_MACHINE_LANDED: &str =
    "onboarding_pipeline_state_machine_landed";

/// Re-export the checkpoint grep used by `/check` and ranker tooling.
/// Living in `mod.rs` keeps a single grep target.
#[doc(hidden)]
pub const SENTINEL_REF: &str = SENTINEL_ONBOARDING_PIPELINE_STATE_MACHINE_LANDED;

/// Returns the checkpoint string. The function is `#[inline(never)]` to
/// prevent the linker from optimizing the constant out — `strings ember`
/// must show the checkpoint so autopilot's `target_state_anchor` matches.
#[doc(hidden)]
#[inline(never)]
pub fn checkpoint() -> &'static str {
    SENTINEL_REF
}

/// CLI flags forwarded from `ember dev install`. Kept narrow on purpose
/// — additional flags (`--skip-github-provisioning`, `--skip-backup`,
/// `--no-backup`) land in the per-stage tasks where they're consumed
/// by the real `StageHandler` impls.
#[derive(Debug, Clone, Default)]
pub struct InstallFlags {
    /// `--resume` — pick up at the first non-`Complete`/`Skipped`
    /// stage. Default when re-running on an existing partial state.
    pub resume: bool,
    /// `--redo <slug>` — force re-execution starting at the named
    /// stage. Mutually exclusive with `--resume`.
    pub redo: Option<Stage>,
}

impl InstallFlags {
    /// Translate CLI flags into a state-machine `Plan`.
    pub fn into_plan(self) -> Plan {
        match (self.redo, self.resume) {
            (Some(start), _) => Plan::Redo { start },
            (None, true) => Plan::Resume,
            // No flags + no existing state == fresh. When state already
            // exists on disk, the state-machine driver treats `Resume`
            // and `Fresh` identically once stages are in a `Pending`
            // bucket; the meaningful distinction is whether to skip
            // existing `Complete`/`Skipped` entries. Default to Resume
            // for safety: re-running `ember dev install` on a partial
            // file should not re-prompt the operator for backup, etc.
            (None, false) => Plan::Resume,
        }
    }
}

/// Drive the pipeline against the real `$HOME`.
///
/// Until real ADR 163 stage bodies land, this uses
/// [`PendingStageHandler`] so `ember dev install` fails closed instead of
/// reporting a completed first-run install without doing the work.
///
/// Errors propagate as `String` to match the existing `dev::install::run`
/// surface; callers in `bin/ember.rs` already format-print.
pub fn run_install(flags: InstallFlags) -> Result<(), String> {
    let state = InstallState::for_real_home().map_err(|e| format!("install-state init: {e}"))?;
    let handler = PendingStageHandler;
    run_install_with(&state, &handler, flags)
}

/// Testable variant of [`run_install`]: caller supplies the state-file
/// handle and the [`StageHandler`].
///
/// Returns `Ok(())` once the pipeline completes (or `--resume` finds
/// nothing to do). Returns `Err(...)` with the failing stage's error
/// embedded.
pub fn run_install_with<H: StageHandler>(
    state: &InstallState,
    handler: &H,
    flags: InstallFlags,
) -> Result<(), String> {
    let plan = flags.into_plan();
    // Touch the checkpoint so the symbol survives dead-code elimination —
    // autopilot greps the compiled binary for it.
    let _ = checkpoint();
    println!("ember dev install — five-stage onboarding pipeline (ADR 163)");
    println!("  state file: {}", state.path().display());
    println!("  plan:       {plan:?}");
    println!();

    // Print the journey overview the first time through (no prior state).
    let prior = state.read().map_err(|e| format!("state read: {e}"))?;
    if prior.first_run_started_at.is_none() {
        print_journey_overview();
    }

    let machine = StateMachine::new(state, handler);
    let report = machine.run(plan).map_err(|e| match e {
        machine::MachineError::Stage { stage, error } => {
            format!("stage {} failed: {}", stage.slug(), error)
        }
        machine::MachineError::State(state_err) => format!("state I/O: {state_err}"),
    })?;

    println!();
    if report.all_complete {
        println!("ember dev install: complete (all 5 stages reached done state).");
    } else {
        println!("ember dev install: partial (re-run with --resume to pick up).");
    }
    Ok(())
}

fn print_journey_overview() {
    println!("We'll spend the next 10-15 minutes setting up emberlink on this workstation.");
    println!("Stages:");
    for s in Stage::ORDER {
        println!("  - {}", s.label());
    }
    println!();
}

#[cfg(test)]
mod tests {
    //! T2: umbrella + flag-to-plan translation tests.
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_flags_translate_to_resume_plan() {
        let plan = InstallFlags::default().into_plan();
        assert_eq!(plan, Plan::Resume);
    }

    #[test]
    fn redo_flag_overrides_resume() {
        let flags = InstallFlags {
            resume: true,
            redo: Some(Stage::DaemonInstall),
        };
        assert_eq!(
            flags.into_plan(),
            Plan::Redo {
                start: Stage::DaemonInstall
            }
        );
    }

    #[test]
    fn explicit_resume_yields_resume_plan() {
        let flags = InstallFlags {
            resume: true,
            redo: None,
        };
        assert_eq!(flags.into_plan(), Plan::Resume);
    }

    #[test]
    fn end_to_end_with_noop_stub_succeeds() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let handler = crate::install_pipeline::stages::NoopStageHandler;
        run_install_with(&state, &handler, InstallFlags::default())
            .expect("noop pipeline must complete");
        let record = state.read().unwrap();
        assert!(record.first_run_completed_at.is_some());
    }

    #[test]
    fn end_to_end_with_partial_fixture_resumes() {
        let home = tempdir().unwrap();
        let dir = home.path().join(".config/emberlink");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-state.toml"),
            r#"
schema_version = 1
first_run_started_at = "2026-05-15T14:23:01Z"

[stages.preflight]
status = "complete"
completed_at = "2026-05-15T14:24:01Z"
duration_seconds = 60
"#,
        )
        .unwrap();
        let state = InstallState::with_home(home.path());
        let handler = crate::install_pipeline::stages::NoopStageHandler;
        run_install_with(&state, &handler, InstallFlags::default()).unwrap();
        let record = state.read().unwrap();
        assert!(record.first_run_completed_at.is_some());
        // preflight kept its existing completed_at, didn't re-run.
        if let state::StageStatus::Complete { completed_at, .. } = record.stage_status("preflight")
        {
            assert_eq!(completed_at, "2026-05-15T14:24:01Z");
        } else {
            panic!("preflight should still be Complete");
        }
    }

    #[test]
    fn sentinel_constant_is_present_in_binary() {
        assert_eq!(SENTINEL_REF, "onboarding_pipeline_state_machine_landed");
    }

    #[test]
    fn production_placeholder_fails_closed() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let handler = PendingStageHandler;
        let err = run_install_with(&state, &handler, InstallFlags::default())
            .expect_err("production placeholder must not complete install");
        assert!(err.contains("META-ONBOARDING-PIPELINE-STATE-MACHINE"));
        let record = state.read().unwrap();
        assert!(record.first_run_completed_at.is_none());
        assert!(matches!(
            record.stage_status(Stage::Preflight.slug()),
            state::StageStatus::Failed { .. }
        ));
    }
}
