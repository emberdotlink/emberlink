//! Retired v0.3.0 friendly-tester dogfood survey.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Operator correction on 2026-06-17 retired this collector for v0.3.0: the CBOR
//! survey was performative ceremony rather than high-signal evidence. The
//! v0.3.0 gate now uses audit-backed condition 10 plus optional exception notes;
//! any replacement dogfood signal belongs in v0.3.1+ instrumentation work.
//!
//! Anchor: `v030_friendly_tester_dogfood_doc_landed`.
//!
//! The schema in [`Survey`] is the on-wire contract consumed by
//! `META-V030-SHIP-GATE-DASHBOARD`. New fields land with `#[serde(default)]`
//! so older artifacts deserialize cleanly; the schema is versioned via
//! [`Survey::survey_version`] for explicit breaking changes.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// CBOR-serializable survey artifact.
///
/// One tester returns one of these per dogfood week. The shape is small by
/// design: the ship-gate dashboard reads it alongside the live test suite's
/// pass/fail of the 15 conditions from ADR 165 §Component 1; this artifact
/// covers the qualitative half (conditions 8-12 + 13's recovery walk).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Survey {
    pub survey_version: u32,
    pub tester_id: String,
    pub completed_at: DateTime<Utc>,
    /// Wall-clock minutes from signed preview install start to ready state.
    /// Condition 1 target: <20 minutes.
    pub install_wallclock_minutes: u32,
    /// Representative dogfood loops completed during the week.
    /// Condition 8 target: >=5.
    #[serde(default)]
    pub dogfood_loops_completed: u32,
    /// Total operator-facing friction events across the 5-day loop —
    /// Touch IDs + JIT prompts + recovery actions. Condition 9 target: <15.
    pub friction_events_total: u32,
    /// 1-5 perceived-utility rating. 1 = "would not use again",
    /// 5 = "core to my workflow".
    pub perceived_utility: u8,
    /// Number of recovery actions the tester deliberately ran (failure-mode
    /// triggers per ADR 161). Condition 13: >=1 expected.
    pub recovery_actions_run: u32,
    /// Free-text concerns about PR-author identity drift. Condition 11
    /// requires zero instances of "bare claude" drift; this captures any
    /// observed gaps in the bot-identity contract.
    pub pr_author_concerns: String,
    /// Free-text concerns about mock-broker / dev-prod parity behavior.
    /// Condition 12 requires zero mock-broker Receipts on non-allowlisted
    /// providers; this captures any leakage signals.
    pub mock_broker_concerns: String,
}

const SURVEY_VERSION: u32 = 2;

pub const RETIRED_MESSAGE: &str = concat!(
    "retired for v0.3.0 by operator correction 2026-06-17: ",
    "the CBOR survey was performative ceremony, not high-signal evidence. ",
    "Do not submit a survey replacement; use signed audit evidence and ",
    "free-form exception notes only when there is real context to add. ",
    "replacement dogfood signal belongs in v0.3.1+ instrumentation."
);

/// Default on-disk location for completed surveys.
pub fn default_surveys_dir() -> Option<PathBuf> {
    let home = dirs_next::home_dir()?;
    Some(
        home.join(".config")
            .join("emberlink")
            .join("v030-dogfood-surveys"),
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SurveyError {
    #[error("{0}")]
    Retired(&'static str),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("cbor encode: {0}")]
    CborEncode(#[from] ciborium::ser::Error<io::Error>),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("eof on stdin while prompting for: {0}")]
    UnexpectedEof(String),
}

fn read_line<R: BufRead>(input: &mut R, prompt_label: &str) -> Result<String, SurveyError> {
    let mut line = String::new();
    let bytes = input.read_line(&mut line)?;
    if bytes == 0 {
        return Err(SurveyError::UnexpectedEof(prompt_label.to_string()));
    }
    Ok(line.trim().to_string())
}

fn prompt_string<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    help: &str,
) -> Result<String, SurveyError> {
    writeln!(output, "{help}")?;
    write!(output, "{label}: ")?;
    output.flush()?;
    read_line(input, label)
}

fn prompt_u32<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    help: &str,
) -> Result<u32, SurveyError> {
    loop {
        let raw = prompt_string(input, output, label, help)?;
        match raw.parse::<u32>() {
            Ok(n) => return Ok(n),
            Err(_) => writeln!(output, "  not a non-negative integer; try again")?,
        }
    }
}

fn prompt_u8_range<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
    help: &str,
    lo: u8,
    hi: u8,
) -> Result<u8, SurveyError> {
    loop {
        let raw = prompt_string(input, output, label, help)?;
        match raw.parse::<u8>() {
            Ok(n) if n >= lo && n <= hi => return Ok(n),
            _ => writeln!(output, "  expected {lo}-{hi}; try again")?,
        }
    }
}

/// Walk the tester through every survey question. Returns the assembled
/// `Survey`. The caller is responsible for choosing where to write it.
pub fn collect<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    now: DateTime<Utc>,
) -> Result<Survey, SurveyError> {
    writeln!(output, "v0.3.0 friendly-tester dogfood survey")?;
    writeln!(
        output,
        "Each answer is recorded verbatim in the CBOR artifact;"
    )?;
    writeln!(
        output,
        "no answers are uploaded — you submit the artifact yourself."
    )?;
    writeln!(output)?;

    let tester_id = prompt_string(
        input,
        output,
        "tester_id",
        "Tester ID (free text — initials, handle, or whatever the operator agreed with you):",
    )?;
    if tester_id.is_empty() {
        return Err(SurveyError::InvalidInput(
            "tester_id must not be empty".into(),
        ));
    }

    let install_wallclock_minutes = prompt_u32(
        input,
        output,
        "install_wallclock_minutes",
        "Wall-clock minutes from signed preview install start through `ember init --for claude` ready state (target <20):",
    )?;

    let dogfood_loops_completed = prompt_u32(
        input,
        output,
        "dogfood_loops_completed",
        "Representative dogfood loops completed this week (target 5):",
    )?;

    let friction_events_total = prompt_u32(
        input,
        output,
        "friction_events_total",
        "Total Touch IDs + JIT prompts + recovery actions across all 5 days (target <15):",
    )?;

    let perceived_utility = prompt_u8_range(
        input,
        output,
        "perceived_utility",
        "Perceived utility, 1-5 (1=would not use again, 5=core to my workflow):",
        1,
        5,
    )?;

    let recovery_actions_run = prompt_u32(
        input,
        output,
        "recovery_actions_run",
        "Recovery actions deliberately run (failure-mode triggers per ADR 161):",
    )?;

    let pr_author_concerns = prompt_string(
        input,
        output,
        "pr_author_concerns",
        "PR-author concerns — any observed PRs authored by your bare GitHub identity instead of `ember-engine[bot]`? (blank if none):",
    )?;

    let mock_broker_concerns = prompt_string(
        input,
        output,
        "mock_broker_concerns",
        "Mock-broker / dev-prod parity concerns — any Receipts indicating a mock broker fired on a real provider? (blank if none):",
    )?;

    Ok(Survey {
        survey_version: SURVEY_VERSION,
        tester_id,
        completed_at: now,
        install_wallclock_minutes,
        dogfood_loops_completed,
        friction_events_total,
        perceived_utility,
        recovery_actions_run,
        pr_author_concerns,
        mock_broker_concerns,
    })
}

/// Atomically write a CBOR-encoded `Survey` to `<dir>/<tester-id>.cbor`.
/// Returns the final on-disk path.
pub fn write_cbor(survey: &Survey, dir: &Path) -> Result<PathBuf, SurveyError> {
    fs::create_dir_all(dir)?;
    let safe_id = sanitize_tester_id(&survey.tester_id);
    let final_path = dir.join(format!("{safe_id}.cbor"));
    let tmp_path = dir.join(format!(".{safe_id}.cbor.tmp"));

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(survey, &mut bytes)?;

    fs::write(&tmp_path, &bytes)?;
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Sanitize the tester-supplied id for use as a filename: keep alnum, dash,
/// underscore; replace everything else with `_`. Empty results become
/// `unknown`. The full tester id is still recorded inside the CBOR body —
/// this only governs the filename.
fn sanitize_tester_id(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// Driver for the retired `ember admin v030-survey complete` CLI verb.
///
/// Refuses before reading stdin or writing files. The collector implementation
/// remains below for schema compatibility with historical artifacts and tests.
pub fn run_complete_cli(out_dir: Option<PathBuf>) -> Result<PathBuf, SurveyError> {
    let _ = out_dir;
    Err(SurveyError::Retired(RETIRED_MESSAGE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_stdin(lines: &[&str]) -> std::io::Cursor<Vec<u8>> {
        let joined = lines.join("\n") + "\n";
        std::io::Cursor::new(joined.into_bytes())
    }

    #[test]
    fn collect_happy_path_assembles_survey() {
        let mut input = fake_stdin(&[
            "alice", // tester_id
            "12",    // install_wallclock_minutes
            "5",     // dogfood_loops_completed
            "9",     // friction_events_total
            "4",     // perceived_utility
            "2",     // recovery_actions_run
            "",      // pr_author_concerns
            "mock-broker fired on github once",
        ]);
        let mut output = Vec::new();
        let now = Utc::now();
        let survey = collect(&mut input, &mut output, now).expect("collect");
        assert_eq!(survey.survey_version, SURVEY_VERSION);
        assert_eq!(survey.tester_id, "alice");
        assert_eq!(survey.install_wallclock_minutes, 12);
        assert_eq!(survey.dogfood_loops_completed, 5);
        assert_eq!(survey.friction_events_total, 9);
        assert_eq!(survey.perceived_utility, 4);
        assert_eq!(survey.recovery_actions_run, 2);
        assert_eq!(survey.pr_author_concerns, "");
        assert_eq!(
            survey.mock_broker_concerns,
            "mock-broker fired on github once"
        );
        assert_eq!(survey.completed_at, now);
        let printed = String::from_utf8(output).expect("utf8");
        assert!(
            printed.contains("signed preview install"),
            "install prompt should match the production preview/onboarding ship gate"
        );
        assert!(
            !printed.contains("ember dev install"),
            "survey must not ask friendly testers for dev-install timing"
        );
    }

    #[test]
    fn collect_retries_on_bad_numeric() {
        let mut input = fake_stdin(&[
            "bob",
            "not-a-number",
            "5",
            "5",
            "3",
            "6", // out of 1-5
            "5",
            "0",
            "",
            "",
        ]);
        let mut output = Vec::new();
        let survey = collect(&mut input, &mut output, Utc::now()).expect("collect");
        assert_eq!(survey.install_wallclock_minutes, 5);
        assert_eq!(survey.perceived_utility, 5);
        let printed = String::from_utf8(output).expect("utf8");
        assert!(printed.contains("not a non-negative integer"));
        assert!(printed.contains("expected 1-5"));
    }

    #[test]
    fn collect_rejects_empty_tester_id() {
        let mut input = fake_stdin(&[""]);
        let mut output = Vec::new();
        let err = collect(&mut input, &mut output, Utc::now()).unwrap_err();
        assert!(matches!(err, SurveyError::InvalidInput(_)));
    }

    #[test]
    fn write_cbor_roundtrips_and_sanitizes_filename() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let survey = Survey {
            survey_version: SURVEY_VERSION,
            tester_id: "alice/../etc".to_string(),
            completed_at: Utc::now(),
            install_wallclock_minutes: 11,
            dogfood_loops_completed: 5,
            friction_events_total: 8,
            perceived_utility: 4,
            recovery_actions_run: 1,
            pr_author_concerns: String::new(),
            mock_broker_concerns: String::new(),
        };
        let path = write_cbor(&survey, dir.path()).expect("write");
        assert_eq!(path.parent().unwrap(), dir.path());
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert!(!filename.contains('/'));
        assert!(!filename.contains(".."));
        let bytes = std::fs::read(&path).expect("read");
        let decoded: Survey = ciborium::de::from_reader(&bytes[..]).expect("decode");
        assert_eq!(decoded, survey);
    }

    #[test]
    fn sanitize_id_keeps_safe_chars_and_handles_empty() {
        assert_eq!(sanitize_tester_id("alice-1"), "alice-1");
        assert_eq!(sanitize_tester_id("alice/../etc"), "alice____etc");
        assert_eq!(sanitize_tester_id(""), "unknown");
    }
}
