//! `install-state.toml` schema + read/write helpers for the five-stage
//! onboarding state machine (ADR 163 §Component 2).
//!
//! This is the WRITER side of the install-state file. The reader for
//! `ember dev status` lives in `internal-automation::status` and is intentionally
//! forward-compatible — it ignores any field it doesn't know. That means we
//! can extend this schema (add per-stage tables, new status fields) without
//! breaking `ember dev status` on older daemons reading newer state files.
//!
//! The path is `~/.config/emberlink/install-state.toml`, per ADR 163. Tests
//! inject an alternate home via [`InstallState::with_home`].
//!
//! CLASSIFICATION: PUBLIC

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema version for `install-state.toml`. Bumped only on incompatible
/// breaks (the reader in `internal-automation::status` is forward-compatible for
/// additive field changes).
pub const SCHEMA_VERSION: u32 = 1;

/// Relative path of the install-state file under `$HOME`.
pub const INSTALL_STATE_REL: &str = ".config/emberlink/install-state.toml";

/// Per-stage status tracked in `install-state.toml`.
///
/// `Pending` is the implicit default for stages that have never been
/// attempted (no entry in the `stages` table). Once a stage starts the
/// machine writes `Running`; on success, `Complete`; on failure, `Failed`
/// with a short error string. `Skipped` records an operator-acknowledged
/// bypass (e.g. `--skip-github-provisioning`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum StageStatus {
    /// Stage has not started yet.
    Pending,
    /// Stage is currently executing.
    Running {
        /// RFC-3339 UTC timestamp when the stage entered `Running`.
        started_at: String,
    },
    /// Stage finished successfully.
    Complete {
        /// RFC-3339 UTC timestamp when the stage finished.
        completed_at: String,
        /// Wall-clock duration in seconds.
        duration_seconds: u64,
    },
    /// Stage failed; operator must address the cause before re-running.
    Failed {
        /// RFC-3339 UTC timestamp when the failure was recorded.
        failed_at: String,
        /// Short human-readable error string.
        error: String,
    },
    /// Stage explicitly skipped by the operator (e.g. `--skip-github-provisioning`).
    Skipped {
        /// RFC-3339 UTC timestamp when the skip was recorded.
        skipped_at: String,
        /// Short reason string.
        reason: String,
    },
}

impl StageStatus {
    /// True when the stage is considered done for resume purposes —
    /// `Complete` and `Skipped` both let the pipeline move on.
    pub fn is_done(&self) -> bool {
        matches!(
            self,
            StageStatus::Complete { .. } | StageStatus::Skipped { .. }
        )
    }
}

/// On-disk record of the install-state file. Fields are public so callers
/// (state-machine driver, future migration code) can manipulate them
/// directly.
///
/// All fields are optional EXCEPT `schema_version` and `stages`; the file
/// is valid in any partial state (the state machine is meant to be
/// interrupted and resumed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallStateRecord {
    /// Schema version of this file. Bumped on incompatible breaks.
    pub schema_version: u32,
    /// RFC-3339 UTC timestamp when the first-run pipeline first started.
    /// Set on the first write; never re-written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_run_started_at: Option<String>,
    /// RFC-3339 UTC timestamp when Stage 4 completed and the operator
    /// reached "done." `None` until the smoke-test passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_run_completed_at: Option<String>,
    /// Wall-clock duration of the full first-run pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_run_duration_seconds: Option<u64>,
    /// Per-stage status keyed by [`Stage::slug`]. Missing entries are
    /// treated as `Pending`.
    #[serde(default)]
    pub stages: toml::value::Table,
}

impl Default for InstallStateRecord {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            first_run_started_at: None,
            first_run_completed_at: None,
            first_run_duration_seconds: None,
            stages: toml::value::Table::new(),
        }
    }
}

impl InstallStateRecord {
    /// Look up a stage's status by slug. Returns `Pending` for unknown
    /// slugs (so the state machine can treat absent-from-disk as
    /// "never started").
    pub fn stage_status(&self, slug: &str) -> StageStatus {
        match self.stages.get(slug) {
            Some(value) => value
                .clone()
                .try_into::<StageStatus>()
                .unwrap_or(StageStatus::Pending),
            None => StageStatus::Pending,
        }
    }

    /// Set a stage's status by slug.
    pub fn set_stage_status(&mut self, slug: &str, status: StageStatus) {
        let value = toml::Value::try_from(status)
            .expect("StageStatus must always serialize to a TOML value");
        self.stages.insert(slug.to_string(), value);
    }

    /// True when every stage in `expected` is `Complete` or `Skipped`.
    pub fn all_done<'a, I: IntoIterator<Item = &'a str>>(&self, expected: I) -> bool {
        expected.into_iter().all(|s| self.stage_status(s).is_done())
    }

    /// Return the slug of the first stage that is NOT done; this is where
    /// `--resume` picks up. Returns `None` if every expected stage is done.
    pub fn first_incomplete<'a, I: IntoIterator<Item = &'a str>>(
        &self,
        expected: I,
    ) -> Option<String> {
        for slug in expected {
            if !self.stage_status(slug).is_done() {
                return Some(slug.to_string());
            }
        }
        None
    }
}

/// Errors from the install-state read/write path.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("install-state I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("install-state.toml parse error: {0}")]
    Parse(String),
    #[error("install-state.toml serialize error: {0}")]
    Serialize(String),
    #[error("install-state.toml schema_version {found} > supported {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
}

/// A handle to the install-state file rooted at a specific home directory.
///
/// Production usage:
///
/// ```ignore
/// let state = InstallState::for_real_home()?;
/// let record = state.read()?;
/// // ... mutate record ...
/// state.write(&record)?;
/// ```
///
/// Tests construct `InstallState::with_home(tempdir.path())` to redirect
/// reads/writes into a fixture.
#[derive(Debug, Clone)]
pub struct InstallState {
    home: PathBuf,
}

impl InstallState {
    /// Construct a handle rooted at the given home directory.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// Construct a handle rooted at the real `$HOME`.
    pub fn for_real_home() -> Result<Self, StateError> {
        let home = dirs_next::home_dir().ok_or_else(|| StateError::Io {
            path: PathBuf::from("$HOME"),
            source: io::Error::new(io::ErrorKind::NotFound, "$HOME not set"),
        })?;
        Ok(Self::with_home(home))
    }

    /// Absolute path of the install-state file.
    pub fn path(&self) -> PathBuf {
        self.home.join(INSTALL_STATE_REL)
    }

    /// Read the install-state file. Returns a default (empty) record if
    /// the file does not exist — this is the "first time installing"
    /// case and is a normal-flow read, not an error.
    pub fn read(&self) -> Result<InstallStateRecord, StateError> {
        let path = self.path();
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(InstallStateRecord::default());
            }
            Err(source) => return Err(StateError::Io { path, source }),
        };
        let record: InstallStateRecord =
            toml::from_str(&raw).map_err(|e| StateError::Parse(e.to_string()))?;
        if record.schema_version > SCHEMA_VERSION {
            return Err(StateError::UnsupportedSchemaVersion {
                found: record.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(record)
    }

    /// Atomically write the install-state file. Creates the parent
    /// directory `~/.config/emberlink/` if it does not yet exist.
    ///
    /// Atomicity: writes to `<path>.tmp` then `rename`s into place. A
    /// crash mid-write leaves the previous version intact.
    pub fn write(&self, record: &InstallStateRecord) -> Result<(), StateError> {
        let path = self.path();
        let dir = path
            .parent()
            .ok_or_else(|| StateError::Io {
                path: path.clone(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "install-state path has no parent",
                ),
            })?
            .to_path_buf();
        fs::create_dir_all(&dir).map_err(|source| StateError::Io {
            path: dir.clone(),
            source,
        })?;

        let body =
            toml::to_string_pretty(record).map_err(|e| StateError::Serialize(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, body).map_err(|source| StateError::Io {
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, &path).map_err(|source| StateError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }
}

/// Format the current UTC time as RFC-3339, the format ADR 163 uses
/// throughout the install-state schema.
pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[doc(hidden)]
#[allow(dead_code)]
pub(crate) fn install_state_path_for(home: &Path) -> PathBuf {
    home.join(INSTALL_STATE_REL)
}

#[cfg(test)]
mod tests {
    //! T1: pure schema round-trip + invariant tests. No I/O.

    use super::*;

    #[test]
    fn default_record_has_schema_version_and_empty_stages() {
        let r = InstallStateRecord::default();
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert!(r.stages.is_empty());
        assert!(r.first_run_started_at.is_none());
        assert!(r.first_run_completed_at.is_none());
    }

    #[test]
    fn stage_status_pending_for_unknown_slug() {
        let r = InstallStateRecord::default();
        assert_eq!(r.stage_status("preflight"), StageStatus::Pending);
    }

    #[test]
    fn set_stage_status_round_trips() {
        let mut r = InstallStateRecord::default();
        let status = StageStatus::Complete {
            completed_at: "2026-05-15T14:36:12Z".to_string(),
            duration_seconds: 42,
        };
        r.set_stage_status("preflight", status.clone());
        assert_eq!(r.stage_status("preflight"), status);
    }

    #[test]
    fn all_done_returns_false_when_any_pending() {
        let mut r = InstallStateRecord::default();
        r.set_stage_status(
            "preflight",
            StageStatus::Complete {
                completed_at: "2026-05-15T14:36:12Z".to_string(),
                duration_seconds: 1,
            },
        );
        // primitives still pending
        assert!(!r.all_done(["preflight", "primitives"]));
    }

    #[test]
    fn all_done_returns_true_when_complete_or_skipped() {
        let mut r = InstallStateRecord::default();
        r.set_stage_status(
            "preflight",
            StageStatus::Complete {
                completed_at: "2026-05-15T14:36:12Z".to_string(),
                duration_seconds: 1,
            },
        );
        r.set_stage_status(
            "github_provisioning",
            StageStatus::Skipped {
                skipped_at: "2026-05-15T14:36:13Z".to_string(),
                reason: "--skip-github-provisioning".to_string(),
            },
        );
        assert!(r.all_done(["preflight", "github_provisioning"]));
    }

    #[test]
    fn first_incomplete_returns_first_pending_in_order() {
        let mut r = InstallStateRecord::default();
        r.set_stage_status(
            "preflight",
            StageStatus::Complete {
                completed_at: "2026-05-15T14:36:12Z".to_string(),
                duration_seconds: 1,
            },
        );
        // primitives pending; github_provisioning skipped further along
        r.set_stage_status(
            "github_provisioning",
            StageStatus::Skipped {
                skipped_at: "2026-05-15T14:36:13Z".to_string(),
                reason: "--skip".to_string(),
            },
        );
        assert_eq!(
            r.first_incomplete(["preflight", "primitives", "github_provisioning"]),
            Some("primitives".to_string()),
        );
    }

    #[test]
    fn first_incomplete_returns_none_when_all_done() {
        let mut r = InstallStateRecord::default();
        for slug in ["preflight", "primitives"] {
            r.set_stage_status(
                slug,
                StageStatus::Complete {
                    completed_at: "2026-05-15T14:36:12Z".to_string(),
                    duration_seconds: 1,
                },
            );
        }
        assert_eq!(r.first_incomplete(["preflight", "primitives"]), None);
    }

    #[test]
    fn failed_stage_is_not_done() {
        let mut r = InstallStateRecord::default();
        r.set_stage_status(
            "preflight",
            StageStatus::Failed {
                failed_at: "2026-05-15T14:36:12Z".to_string(),
                error: "no FileVault".to_string(),
            },
        );
        assert!(!r.all_done(["preflight"]));
        assert_eq!(
            r.first_incomplete(["preflight"]),
            Some("preflight".to_string())
        );
    }

    #[test]
    fn now_rfc3339_parses_back_to_chrono() {
        let s = now_rfc3339();
        let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(&s)
            .expect("now_rfc3339 must emit valid RFC-3339")
            .with_timezone(&Utc);
        // sanity: round-tripped timestamp is within one second of now
        let delta = (Utc::now() - parsed).num_seconds().abs();
        assert!(delta <= 2, "timestamp drift {delta}s exceeds 2s");
    }
}

#[cfg(test)]
mod io_tests {
    //! T2: integration tests against a tempdir home. Real filesystem.

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_missing_file_returns_default() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let record = state.read().expect("read on absent file must succeed");
        assert_eq!(record.schema_version, SCHEMA_VERSION);
        assert!(record.stages.is_empty());
    }

    #[test]
    fn write_then_read_round_trips() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());

        let mut record = InstallStateRecord::default();
        record.first_run_started_at = Some(now_rfc3339());
        record.set_stage_status(
            "preflight",
            StageStatus::Complete {
                completed_at: now_rfc3339(),
                duration_seconds: 7,
            },
        );
        state.write(&record).expect("write succeeds");

        // file is at the expected path
        let path = state.path();
        assert!(
            path.exists(),
            "install-state.toml must be written at {path:?}"
        );
        assert!(
            path.ends_with(".config/emberlink/install-state.toml"),
            "path must be ADR-163-canonical"
        );

        let read = state.read().expect("read succeeds");
        assert_eq!(read.schema_version, SCHEMA_VERSION);
        assert!(read.first_run_started_at.is_some());
        assert!(matches!(
            read.stage_status("preflight"),
            StageStatus::Complete { .. }
        ));
    }

    #[test]
    fn write_is_atomic_no_partial_file_on_serialize_failure() {
        // We can't easily force toml serialize to fail without unsafe;
        // instead, validate the .tmp -> rename path doesn't leave a .tmp
        // sibling on success.
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let record = InstallStateRecord::default();
        state.write(&record).unwrap();

        let dir = home.path().join(".config/emberlink");
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .collect();
        assert!(
            entries.iter().any(|n| n == "install-state.toml"),
            "install-state.toml missing: {entries:?}"
        );
        assert!(
            !entries.iter().any(|n| n.ends_with(".tmp")),
            ".tmp file left behind after successful write: {entries:?}"
        );
    }

    #[test]
    fn unsupported_schema_version_errors() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let dir = home.path().join(".config/emberlink");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-state.toml"),
            format!("schema_version = {}\n", SCHEMA_VERSION + 99),
        )
        .unwrap();

        let err = state.read().unwrap_err();
        assert!(
            matches!(err, StateError::UnsupportedSchemaVersion { .. }),
            "expected UnsupportedSchemaVersion, got {err:?}"
        );
    }

    #[test]
    fn parse_error_surfaces() {
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let dir = home.path().join(".config/emberlink");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("install-state.toml"), "not valid = = toml ===").unwrap();
        let err = state.read().unwrap_err();
        assert!(matches!(err, StateError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn schema_is_forward_compatible_with_unknown_top_level_fields() {
        // The reader in `internal-automation::status` ignores unknown fields; this
        // schema must reciprocate so newer fields on the reader side don't
        // break older writers. (We allow unknown keys via Default + Option.)
        let home = tempdir().unwrap();
        let state = InstallState::with_home(home.path());
        let dir = home.path().join(".config/emberlink");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("install-state.toml"),
            r#"
schema_version = 1
unknown_future_field = "ignored"
[stages]
"#,
        )
        .unwrap();
        // Should NOT error.
        let _read = state
            .read()
            .expect("unknown top-level field must be ignored");
    }
}
