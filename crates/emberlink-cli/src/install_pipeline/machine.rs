//! State-machine driver for the five-stage install pipeline
//! (ADR 163 §Component 1+2).
//!
//! The machine reads `install-state.toml`, runs each stage in
//! `Stage::ORDER`, and writes status after every transition.
//! `Plan::Resume` skips stages already `Complete`/`Skipped`;
//! `Plan::Redo(stage)` forces re-execution from a given stage onward.
//!
//! Persistence is per-stage — a crash mid-pipeline leaves a partial
//! state file the next run can resume from. The atomic-rename in
//! [`crate::install_pipeline::state::InstallState::write`] guarantees
//! the file is never left half-serialized.
//!
//! CLASSIFICATION: PUBLIC

use std::time::Instant;

use super::stages::{Stage, StageError, StageHandler, StageOutcome};
use super::state::{InstallState, InstallStateRecord, StageStatus, StateError, now_rfc3339};

/// How the state machine should plan its next run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Fresh start — run every stage in order. Existing state is
    /// overwritten as stages re-run.
    Fresh,
    /// Resume from the first non-`Complete`/`Skipped` stage. This is
    /// the default for `ember dev install --resume` and the implicit
    /// behavior of re-running `ember dev install` on a partial state.
    Resume,
    /// Force re-execution starting at the named stage. Stages before
    /// it keep their existing status; stages from `start` onward are
    /// re-run regardless of prior status. Maps to `--redo <stage>`.
    Redo { start: Stage },
}

/// Errors surfaced by the state machine.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    #[error("install-state error: {0}")]
    State(#[from] StateError),
    #[error("stage {stage} failed: {error}")]
    Stage {
        stage: Stage,
        #[source]
        error: StageError,
    },
}

/// Per-stage transition emitted by the driver. Mostly useful for tests
/// and verbose CLI output; production callers can ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Stage was skipped by the plan (already `Complete` and we're
    /// resuming, OR the operator explicitly chose to bypass it).
    SkippedByPlan { stage: Stage },
    /// Stage entered `Running`.
    Started { stage: Stage },
    /// Stage finished successfully.
    Completed { stage: Stage, duration_seconds: u64 },
    /// Stage was skipped by the handler (e.g. `--skip-github-provisioning`).
    SkippedByHandler { stage: Stage, reason: String },
    /// Stage failed; the pipeline halted.
    Failed { stage: Stage, error: String },
}

/// Outcome of [`StateMachine::run`].
#[derive(Debug, Clone)]
pub struct RunReport {
    /// The transitions the machine drove, in execution order.
    pub transitions: Vec<Transition>,
    /// True when every expected stage is `Complete`/`Skipped` at the
    /// end of the run.
    pub all_complete: bool,
}

/// The pipeline driver. Holds a reference to the on-disk state and a
/// [`StageHandler`] (real or stub).
pub struct StateMachine<'a, H: StageHandler> {
    state: &'a InstallState,
    handler: &'a H,
}

impl<'a, H: StageHandler> StateMachine<'a, H> {
    /// Construct a driver bound to a state-file handle and a stage
    /// handler.
    pub fn new(state: &'a InstallState, handler: &'a H) -> Self {
        Self { state, handler }
    }

    /// Run the pipeline. Persists state after each stage transition,
    /// so a crash leaves the file in a resumable shape.
    pub fn run(&self, plan: Plan) -> Result<RunReport, MachineError> {
        let mut record = self.state.read()?;

        if record.first_run_started_at.is_none() {
            record.first_run_started_at = Some(now_rfc3339());
            self.state.write(&record)?;
        }

        let mut transitions = Vec::new();

        for &stage in Stage::ORDER {
            let should_run = match &plan {
                Plan::Fresh => true,
                Plan::Resume => !record.stage_status(stage.slug()).is_done(),
                Plan::Redo { start } => stage_index(*start) <= stage_index(stage),
            };

            if !should_run {
                transitions.push(Transition::SkippedByPlan { stage });
                continue;
            }

            // Mark Running and persist.
            let started_at = now_rfc3339();
            record.set_stage_status(
                stage.slug(),
                StageStatus::Running {
                    started_at: started_at.clone(),
                },
            );
            self.state.write(&record)?;
            transitions.push(Transition::Started { stage });

            let t0 = Instant::now();
            match self.handler.run(stage) {
                Ok(StageOutcome::Complete) => {
                    let duration = t0.elapsed().as_secs();
                    record.set_stage_status(
                        stage.slug(),
                        StageStatus::Complete {
                            completed_at: now_rfc3339(),
                            duration_seconds: duration,
                        },
                    );
                    self.state.write(&record)?;
                    transitions.push(Transition::Completed {
                        stage,
                        duration_seconds: duration,
                    });
                }
                Ok(StageOutcome::Skipped { reason }) => {
                    record.set_stage_status(
                        stage.slug(),
                        StageStatus::Skipped {
                            skipped_at: now_rfc3339(),
                            reason: reason.clone(),
                        },
                    );
                    self.state.write(&record)?;
                    transitions.push(Transition::SkippedByHandler { stage, reason });
                }
                Err(error) => {
                    record.set_stage_status(
                        stage.slug(),
                        StageStatus::Failed {
                            failed_at: now_rfc3339(),
                            error: error.0.clone(),
                        },
                    );
                    self.state.write(&record)?;
                    transitions.push(Transition::Failed {
                        stage,
                        error: error.0.clone(),
                    });
                    return Err(MachineError::Stage { stage, error });
                }
            }
        }

        // All stages done — if Stage 4 (smoke test) just completed and
        // the first_run_completed_at field isn't set yet, stamp it now.
        let all_done = stage_slugs()
            .iter()
            .all(|s| record.stage_status(s).is_done());
        if all_done && record.first_run_completed_at.is_none() {
            let now = now_rfc3339();
            record.first_run_completed_at = Some(now.clone());
            // Best-effort duration = end - start, rounded to seconds.
            record.first_run_duration_seconds = compute_duration_seconds(
                record.first_run_started_at.as_deref(),
                Some(now.as_str()),
            );
            self.state.write(&record)?;
        }

        Ok(RunReport {
            transitions,
            all_complete: all_done,
        })
    }

    /// Convenience: read the current on-disk state.
    pub fn snapshot(&self) -> Result<InstallStateRecord, MachineError> {
        Ok(self.state.read()?)
    }
}

fn stage_slugs() -> Vec<&'static str> {
    Stage::ORDER.iter().map(|s| s.slug()).collect()
}

fn stage_index(stage: Stage) -> usize {
    Stage::ORDER
        .iter()
        .position(|s| *s == stage)
        .expect("Stage::ORDER must contain every variant")
}

fn compute_duration_seconds(start: Option<&str>, end: Option<&str>) -> Option<u64> {
    use chrono::DateTime;
    let s = DateTime::parse_from_rfc3339(start?).ok()?;
    let e = DateTime::parse_from_rfc3339(end?).ok()?;
    let secs = (e - s).num_seconds();
    if secs < 0 { None } else { Some(secs as u64) }
}

#[cfg(test)]
mod tests {
    //! T2: state-machine tests with fake stage handlers and tempdir
    //! state. Property: each post-run on-disk file is a valid resume
    //! point for the next run.

    use super::*;
    use crate::install_pipeline::stages::{NoopStageHandler, Stage};
    use std::cell::RefCell;
    use tempfile::tempdir;

    /// Recording handler — tracks which stages were called and
    /// optionally fails on one specific stage.
    struct RecordingHandler {
        calls: RefCell<Vec<Stage>>,
        fail_on: Option<Stage>,
        skip_on: Option<(Stage, String)>,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_on: None,
                skip_on: None,
            }
        }

        fn calls(&self) -> Vec<Stage> {
            self.calls.borrow().clone()
        }
    }

    impl StageHandler for RecordingHandler {
        fn run(&self, stage: Stage) -> Result<StageOutcome, StageError> {
            self.calls.borrow_mut().push(stage);
            if self.fail_on == Some(stage) {
                return Err(StageError::new(format!("fault injected at {stage}")));
            }
            if let Some((s, reason)) = &self.skip_on {
                if *s == stage {
                    return Ok(StageOutcome::Skipped {
                        reason: reason.clone(),
                    });
                }
            }
            Ok(StageOutcome::Complete)
        }
    }

    #[test]
    fn fresh_run_executes_every_stage_in_order() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let handler = RecordingHandler::new();
        let machine = StateMachine::new(&state, &handler);

        let report = machine.run(Plan::Fresh).unwrap();

        assert_eq!(handler.calls(), Stage::ORDER.to_vec());
        assert!(report.all_complete, "fresh run should complete");
        // 5 Started + 5 Completed
        let started = report
            .transitions
            .iter()
            .filter(|t| matches!(t, Transition::Started { .. }))
            .count();
        let completed = report
            .transitions
            .iter()
            .filter(|t| matches!(t, Transition::Completed { .. }))
            .count();
        assert_eq!(started, 5);
        assert_eq!(completed, 5);
    }

    #[test]
    fn fresh_run_stamps_first_run_started_and_completed() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let handler = NoopStageHandler;
        StateMachine::new(&state, &handler)
            .run(Plan::Fresh)
            .unwrap();

        let record = state.read().unwrap();
        assert!(record.first_run_started_at.is_some());
        assert!(record.first_run_completed_at.is_some());
        // duration_seconds may be Some(0) on a fast machine — just check it parses.
        assert!(record.first_run_duration_seconds.is_some());
    }

    #[test]
    fn resume_skips_already_completed_stages() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());

        // Pre-populate: stages 0..=2 already complete.
        let mut record = InstallStateRecord::default();
        record.first_run_started_at = Some(now_rfc3339());
        for s in &[
            Stage::Preflight,
            Stage::Primitives,
            Stage::GithubProvisioning,
        ] {
            record.set_stage_status(
                s.slug(),
                StageStatus::Complete {
                    completed_at: now_rfc3339(),
                    duration_seconds: 1,
                },
            );
        }
        state.write(&record).unwrap();

        let handler = RecordingHandler::new();
        let report = StateMachine::new(&state, &handler)
            .run(Plan::Resume)
            .unwrap();

        // Only DaemonInstall + SmokeTest should run.
        assert_eq!(
            handler.calls(),
            vec![Stage::DaemonInstall, Stage::SmokeTest]
        );
        // SkippedByPlan transitions for the 3 already-done stages.
        let skipped_by_plan = report
            .transitions
            .iter()
            .filter(|t| matches!(t, Transition::SkippedByPlan { .. }))
            .count();
        assert_eq!(skipped_by_plan, 3);
        assert!(report.all_complete);
    }

    #[test]
    fn resume_from_fresh_state_runs_every_stage() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let handler = RecordingHandler::new();
        let report = StateMachine::new(&state, &handler)
            .run(Plan::Resume)
            .unwrap();
        assert_eq!(handler.calls(), Stage::ORDER.to_vec());
        assert!(report.all_complete);
    }

    #[test]
    fn redo_reexecutes_from_named_stage_onward() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        // First fresh run.
        StateMachine::new(&state, &NoopStageHandler)
            .run(Plan::Fresh)
            .unwrap();

        // Now redo from GithubProvisioning.
        let handler = RecordingHandler::new();
        let report = StateMachine::new(&state, &handler)
            .run(Plan::Redo {
                start: Stage::GithubProvisioning,
            })
            .unwrap();

        // Stages 0+1 skipped; 2+3+4 re-run.
        assert_eq!(
            handler.calls(),
            vec![
                Stage::GithubProvisioning,
                Stage::DaemonInstall,
                Stage::SmokeTest
            ]
        );
        let skipped = report
            .transitions
            .iter()
            .filter(|t| matches!(t, Transition::SkippedByPlan { .. }))
            .count();
        assert_eq!(skipped, 2);
        assert!(report.all_complete);
    }

    #[test]
    fn failure_halts_pipeline_and_records_failed_status() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let mut handler = RecordingHandler::new();
        handler.fail_on = Some(Stage::DaemonInstall);

        let err = StateMachine::new(&state, &handler)
            .run(Plan::Fresh)
            .unwrap_err();

        match err {
            MachineError::Stage { stage, .. } => assert_eq!(stage, Stage::DaemonInstall),
            other => panic!("expected MachineError::Stage, got {other:?}"),
        }

        let record = state.read().unwrap();
        assert!(matches!(
            record.stage_status(Stage::DaemonInstall.slug()),
            StageStatus::Failed { .. }
        ));
        // SmokeTest never ran.
        assert_eq!(
            record.stage_status(Stage::SmokeTest.slug()),
            StageStatus::Pending
        );
        // first_run_completed_at NOT set (pipeline did not finish).
        assert!(record.first_run_completed_at.is_none());
    }

    #[test]
    fn resume_after_failure_picks_up_at_failed_stage() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());

        // First pass: fail on DaemonInstall.
        let mut bad = RecordingHandler::new();
        bad.fail_on = Some(Stage::DaemonInstall);
        let _ = StateMachine::new(&state, &bad).run(Plan::Fresh);

        // Resume: a clean handler now picks up at DaemonInstall.
        let good = RecordingHandler::new();
        let report = StateMachine::new(&state, &good).run(Plan::Resume).unwrap();

        assert_eq!(good.calls(), vec![Stage::DaemonInstall, Stage::SmokeTest]);
        assert!(report.all_complete);
    }

    #[test]
    fn handler_skip_outcome_records_skipped_and_lets_pipeline_proceed() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let mut handler = RecordingHandler::new();
        handler.skip_on = Some((
            Stage::GithubProvisioning,
            "--skip-github-provisioning".into(),
        ));

        let report = StateMachine::new(&state, &handler)
            .run(Plan::Fresh)
            .unwrap();

        let record = state.read().unwrap();
        assert!(matches!(
            record.stage_status(Stage::GithubProvisioning.slug()),
            StageStatus::Skipped { .. }
        ));
        assert!(report.all_complete);
        assert!(
            report
                .transitions
                .iter()
                .any(|t| matches!(t, Transition::SkippedByHandler { stage, .. } if *stage == Stage::GithubProvisioning))
        );
    }

    #[test]
    fn state_file_after_run_is_valid_input_to_next_run() {
        // Property: every successful run leaves a file the next run can
        // resume from without error.
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        StateMachine::new(&state, &NoopStageHandler)
            .run(Plan::Fresh)
            .unwrap();
        // A second run with Plan::Resume should be a no-op (all done).
        let report = StateMachine::new(&state, &NoopStageHandler)
            .run(Plan::Resume)
            .unwrap();
        assert!(report.all_complete);
        let all_skipped_by_plan = report
            .transitions
            .iter()
            .filter(|t| matches!(t, Transition::SkippedByPlan { .. }))
            .count();
        assert_eq!(all_skipped_by_plan, 5);
    }

    #[test]
    fn partial_state_file_fixture_resumes_at_correct_stage() {
        // Operator hand-crafts a partial install-state.toml that says
        // "Stage 0 and 1 are done, stage 2 failed last time." The
        // machine should pick up at Stage 2.
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

[stages.primitives]
status = "complete"
completed_at = "2026-05-15T14:26:01Z"
duration_seconds = 120

[stages.github_provisioning]
status = "failed"
failed_at = "2026-05-15T14:27:01Z"
error = "PEM read denied"
"#,
        )
        .unwrap();

        let state = InstallState::with_home(home.path());
        let handler = RecordingHandler::new();
        let report = StateMachine::new(&state, &handler)
            .run(Plan::Resume)
            .unwrap();

        assert_eq!(
            handler.calls(),
            vec![
                Stage::GithubProvisioning,
                Stage::DaemonInstall,
                Stage::SmokeTest,
            ]
        );
        assert!(report.all_complete);
    }
}
