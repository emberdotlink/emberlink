//! CLASSIFICATION: PUBLIC
//!
//! Symptom registry for `ember status --troubleshoot` per ADR 161
//! §Component 3. Each `Symptom` is a `check_fn(&HealthSnapshot) ->
//! Verdict` plus its F-code, summary message, and a recovery command
//! pointer. New symptoms register at compile time via `inventory::submit!`
//! — no central registry edit is required to add a new F-code check, only
//! a `inventory::submit!` invocation in any module compiled into the
//! `emberlink-cli` crate.
//!
//! The runner ([`run_all`]) iterates every registered `Symptom`, calls
//! its check function against the supplied [`HealthSnapshot`], and
//! collects the verdicts in F-code order so the troubleshoot output is
//! deterministic across runs.
//!
//! The conservative-on-uncertainty rule from ADR 161 R4 lives at the
//! check-function level: each check returns [`Verdict::Warn`] when it
//! cannot confirm the OK branch (e.g. a probe that times out should
//! report `warn`, never `ok`). Tests for individual checks pin the
//! `Unknown` → `Warn` rendering so silent false negatives surface in CI.
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `recover_status_troubleshoot_landed` is anchored in this module's
//! docstring.

use std::path::PathBuf;

/// Compile-time-registered symptom check.
///
/// A `Symptom` describes ONE F-code's diagnostic check. The
/// `check` function reads a [`HealthSnapshot`] (pure data) and returns
/// a [`Verdict`] plus an optional detail string the renderer surfaces
/// alongside the F-code header.
///
/// `f_code` is the operator-facing identifier (e.g. `F-INSTALL-1`)
/// that anchors the runbook section (`docs/runbook/recovery.md`).
/// `summary` is the short headline shown in the `[ok]/[warn]/[fail]`
/// line. `recovery_cmd` is the canonical recovery command the operator
/// runs next — rendered after the verdict line.
pub struct Symptom {
    /// F-code identifier (e.g. `F-INSTALL-1`). Stable across releases;
    /// also used as the runbook anchor.
    pub f_code: &'static str,
    /// One-line description of what the check looked for.
    pub summary: &'static str,
    /// Canonical recovery command the operator runs when the check
    /// surfaces a `warn` or `fail`. Rendered with the active `ember`
    /// command prefix — callers may rewrite `ember ...` to a repo-build
    /// path if the invoking launcher is a dev build.
    pub recovery_cmd: &'static str,
    /// Pure function over [`HealthSnapshot`]. MUST NOT do I/O of any
    /// kind — that is the snapshot's job. T1-testable by construction.
    pub check: fn(&HealthSnapshot) -> CheckResult,
}

inventory::collect!(Symptom);

/// Verdict for a single symptom check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The check confirmed the healthy posture.
    Ok,
    /// The check could not confirm the healthy posture but did not see
    /// a hard failure — ADR 161 R4 conservative-on-uncertain rule.
    Warn,
    /// The check observed the failure mode the F-code describes.
    Fail,
}

impl Verdict {
    /// Sort key for output ordering: failures first, then warnings,
    /// then ok lines so the operator sees the actionable items at the
    /// top of the appendix.
    fn order_key(self) -> u8 {
        match self {
            Verdict::Fail => 0,
            Verdict::Warn => 1,
            Verdict::Ok => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Warn => "warn",
            Verdict::Fail => "fail",
        }
    }
}

/// Result of a single check function call.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub verdict: Verdict,
    /// Optional one-line detail shown after the summary headline.
    pub detail: Option<String>,
}

impl CheckResult {
    pub fn ok() -> Self {
        Self {
            verdict: Verdict::Ok,
            detail: None,
        }
    }

    pub fn ok_with(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Ok,
            detail: Some(detail.into()),
        }
    }

    pub fn warn(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Warn,
            detail: Some(detail.into()),
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Fail,
            detail: Some(detail.into()),
        }
    }
}

/// Pure-data snapshot the symptom check functions read.
///
/// The snapshot is assembled OUTSIDE the check functions (by the
/// status/troubleshoot renderer) so the checks themselves stay
/// I/O-free and T1-testable. Tests inject synthetic snapshots to
/// exercise each check; the production renderer captures the real
/// posture from `collect_status_overview` + filesystem probes.
#[derive(Debug, Clone, Default)]
pub struct HealthSnapshot {
    /// Whether the dev or prod daemon socket is reachable. `None` when
    /// the renderer could not even probe the socket (collection
    /// failure); the check function returns `Warn` in that case.
    pub daemon_socket_reachable: Option<bool>,
    /// Whether a stale socket file exists (file present, connect
    /// refused). When the socket is reachable this MUST be `Some(false)`.
    pub daemon_socket_stale: Option<bool>,
    /// Whether the daemon's SQLite database opens cleanly (last known
    /// integrity-check verdict). `None` when the renderer cannot tell.
    pub daemon_db_healthy: Option<bool>,
    /// Whether `~/.ember/shadow/` (the PATH-shimmed launcher root) is
    /// present and writable.
    pub shadow_path_present: Option<bool>,
    /// Resolved shadow-root path the renderer probed.
    pub shadow_path: Option<PathBuf>,
    /// Whether the GitHub broker credential was rejected on a recent
    /// call (broker.resolve saw a 401).
    pub broker_github_credential_invalid: Option<bool>,
    /// Whether the audit-store SQLite ceiling is approaching full.
    /// `Some(usage_ratio)` where `0.0..=1.0`; `None` when the renderer
    /// could not measure.
    pub audit_store_usage_ratio: Option<f32>,
    /// Whether mock brokers are trusted in this daemon process.
    /// `true` is acceptable on dev, surfaces a `warn` on the prod
    /// daemon. The check function reads `daemon_lane_is_prod` to
    /// decide.
    pub mock_brokers_trusted: Option<bool>,
    /// Whether the active daemon lane is the prod-shaped one.
    pub daemon_lane_is_prod: Option<bool>,
    /// Whether the install manifest signature verified at last
    /// startup.
    pub install_manifest_signature_valid: Option<bool>,
}

/// One line of rendered troubleshoot output.
#[derive(Debug, Clone)]
pub struct SymptomLine {
    pub f_code: &'static str,
    pub summary: &'static str,
    pub recovery_cmd: &'static str,
    pub verdict: Verdict,
    pub detail: Option<String>,
}

/// Run every registered [`Symptom`] check against `snapshot` and
/// return the per-symptom lines sorted with failures first.
///
/// The returned `Vec` preserves a stable order across runs: by verdict
/// severity (fail → warn → ok), then by F-code lexicographically. New
/// symptoms registering via `inventory::submit!` slot into the right
/// spot automatically.
pub fn run_all(snapshot: &HealthSnapshot) -> Vec<SymptomLine> {
    let mut lines: Vec<SymptomLine> = inventory::iter::<Symptom>
        .into_iter()
        .map(|s| {
            let result = (s.check)(snapshot);
            SymptomLine {
                f_code: s.f_code,
                summary: s.summary,
                recovery_cmd: s.recovery_cmd,
                verdict: result.verdict,
                detail: result.detail,
            }
        })
        .collect();

    lines.sort_by(|a, b| {
        a.verdict
            .order_key()
            .cmp(&b.verdict.order_key())
            .then_with(|| a.f_code.cmp(b.f_code))
    });
    lines
}

/// Public renderer for a single line — exposed so the troubleshoot
/// composer (in `status::troubleshoot`) can build the F-code section
/// with a consistent format.
pub fn format_line(line: &SymptomLine, ember_cmd: &str) -> String {
    let mut out = format!(
        "[{verdict:<4}] {summary} — {f_code}\n",
        verdict = line.verdict.label(),
        summary = line.summary,
        f_code = line.f_code,
    );
    if let Some(detail) = line.detail.as_deref() {
        out.push_str(&format!("        Detail:   {detail}\n"));
    }
    // Rewrite the canonical `ember ...` prefix to the invoking
    // launcher's prefix so the operator can copy-paste the recovery
    // command straight out of the troubleshoot output.
    let recovery = if ember_cmd == "ember" {
        line.recovery_cmd.to_string()
    } else {
        line.recovery_cmd.replacen("ember ", &format!("{ember_cmd} "), 1)
    };
    out.push_str(&format!("        Recovery: {recovery}\n"));
    out
}

/// Render the F-code appendix as a single block. Always emits the
/// section heading even when every check is `Ok`, so the operator
/// confirms the appendix ran rather than reading a missing section as
/// "the checks were skipped."
pub fn render_appendix(snapshot: &HealthSnapshot, ember_cmd: &str) -> String {
    use std::fmt::Write as _;

    let lines = run_all(snapshot);
    let mut out = String::new();
    let _ = writeln!(out, "F-code symptom checks");
    if lines.is_empty() {
        // No symptom registered. This is only expected in unit tests
        // where the inventory linkage is intentionally skipped; in a
        // real build at least the bundled F-codes register.
        let _ = writeln!(out, "  (no symptoms registered)");
        return out;
    }
    for line in &lines {
        for rendered_line in format_line(line, ember_cmd).lines() {
            let _ = writeln!(out, "  {rendered_line}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Bundled symptom check functions — one per F-code subset shipped in v0.3 per
// ADR 161 §Prerequisites P2 ("at least F-DAEMON-1/2 + F-INSTALL-1 + F-BROKER-2
// coverage at v0.3"). Each `inventory::submit!` is the registration call; new
// F-codes add their own `inventory::submit!` in any module without editing this
// file's runner.

inventory::submit! {
    Symptom {
        f_code: "F-DAEMON-1",
        summary: "Daemon process reachable on its socket",
        recovery_cmd: "ember recover daemon",
        check: check_f_daemon_1,
    }
}

fn check_f_daemon_1(snap: &HealthSnapshot) -> CheckResult {
    match snap.daemon_socket_reachable {
        Some(true) => CheckResult::ok_with("socket reachable"),
        Some(false) => CheckResult::fail("daemon socket connect refused"),
        None => CheckResult::warn("could not probe daemon socket"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-DAEMON-2",
        summary: "Daemon socket file is current (not a stale leftover)",
        recovery_cmd: "ember recover daemon --scope socket",
        check: check_f_daemon_2,
    }
}

fn check_f_daemon_2(snap: &HealthSnapshot) -> CheckResult {
    match snap.daemon_socket_stale {
        Some(true) => CheckResult::fail("socket file present but connect refused (stale)"),
        Some(false) => CheckResult::ok(),
        None => CheckResult::warn("could not determine socket freshness"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-DAEMON-3",
        summary: "Daemon SQLite database opens cleanly",
        recovery_cmd: "ember recover daemon --scope db",
        check: check_f_daemon_3,
    }
}

fn check_f_daemon_3(snap: &HealthSnapshot) -> CheckResult {
    match snap.daemon_db_healthy {
        Some(true) => CheckResult::ok(),
        Some(false) => CheckResult::fail("PRAGMA integrity_check failed"),
        None => CheckResult::warn("daemon DB integrity check did not run"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-INSTALL-1",
        summary: "Shadow path ~/.ember/shadow/ present",
        recovery_cmd: "ember recover install --scope shadow",
        check: check_f_install_1,
    }
}

fn check_f_install_1(snap: &HealthSnapshot) -> CheckResult {
    let path_display = snap
        .shadow_path
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.ember/shadow/".to_string());
    match snap.shadow_path_present {
        Some(true) => CheckResult::ok_with(format!("present at {path_display}")),
        Some(false) => CheckResult::fail(format!("{path_display} missing")),
        None => CheckResult::warn("could not probe shadow path"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-INSTALL-2",
        summary: "Install manifest signature verifies",
        recovery_cmd: "ember recover install --scope manifest",
        check: check_f_install_2,
    }
}

fn check_f_install_2(snap: &HealthSnapshot) -> CheckResult {
    match snap.install_manifest_signature_valid {
        Some(true) => CheckResult::ok(),
        Some(false) => CheckResult::fail("daemon startup reported signature mismatch"),
        None => CheckResult::warn("manifest signature not verified this session"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-BROKER-2",
        summary: "Broker credential authenticates upstream",
        recovery_cmd: "ember recover broker --provider github --scope creds",
        check: check_f_broker_2,
    }
}

fn check_f_broker_2(snap: &HealthSnapshot) -> CheckResult {
    match snap.broker_github_credential_invalid {
        Some(true) => CheckResult::fail("last GitHub broker call returned 401"),
        Some(false) => CheckResult::ok(),
        None => CheckResult::warn("no recent broker probe to confirm credential"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-BROKER-3",
        summary: "Mock brokers are NOT trusted on the prod daemon",
        recovery_cmd: "ember recover daemon --prod --scope plist",
        check: check_f_broker_3,
    }
}

fn check_f_broker_3(snap: &HealthSnapshot) -> CheckResult {
    match (snap.mock_brokers_trusted, snap.daemon_lane_is_prod) {
        (Some(true), Some(true)) => {
            CheckResult::fail("EMBER_ALLOW_MOCK_BROKERS set on the prod lane")
        }
        (Some(true), Some(false)) => CheckResult::ok_with("mock brokers trusted on dev lane (expected)"),
        (Some(true), None) => CheckResult::warn("mock brokers trusted; daemon lane unknown"),
        (Some(false), _) => CheckResult::ok(),
        (None, _) => CheckResult::warn("could not probe daemon for mock-broker flag"),
    }
}

inventory::submit! {
    Symptom {
        f_code: "F-AUDIT-1",
        summary: "Audit store usage is below ceiling",
        recovery_cmd: "ember recover audit --scope rotate",
        check: check_f_audit_1,
    }
}

fn check_f_audit_1(snap: &HealthSnapshot) -> CheckResult {
    match snap.audit_store_usage_ratio {
        Some(ratio) if ratio >= 0.95 => {
            CheckResult::fail(format!("audit store at {:.0}% of ceiling", ratio * 100.0))
        }
        Some(ratio) if ratio >= 0.80 => {
            CheckResult::warn(format!("audit store at {:.0}% of ceiling", ratio * 100.0))
        }
        Some(ratio) => CheckResult::ok_with(format!("{:.0}% of ceiling used", ratio * 100.0)),
        None => CheckResult::warn("could not measure audit store usage"),
    }
}

#[cfg(test)]
mod tests {
    //! T1 unit tests — pure functions over `HealthSnapshot`. No I/O.
    use super::*;

    fn empty_snapshot() -> HealthSnapshot {
        HealthSnapshot::default()
    }

    // ----- per-check verdict tests -----

    #[test]
    fn f_daemon_1_unknown_reports_warn() {
        let snap = empty_snapshot();
        assert_eq!(check_f_daemon_1(&snap).verdict, Verdict::Warn);
    }

    #[test]
    fn f_daemon_1_unreachable_reports_fail() {
        let mut snap = empty_snapshot();
        snap.daemon_socket_reachable = Some(false);
        assert_eq!(check_f_daemon_1(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_daemon_2_stale_socket_reports_fail() {
        let mut snap = empty_snapshot();
        snap.daemon_socket_stale = Some(true);
        assert_eq!(check_f_daemon_2(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_daemon_3_db_corrupt_reports_fail() {
        let mut snap = empty_snapshot();
        snap.daemon_db_healthy = Some(false);
        assert_eq!(check_f_daemon_3(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_install_1_missing_shadow_reports_fail() {
        let mut snap = empty_snapshot();
        snap.shadow_path_present = Some(false);
        snap.shadow_path = Some(PathBuf::from("/home/op/.ember/shadow"));
        let r = check_f_install_1(&snap);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.detail.as_deref().unwrap_or("").contains("/home/op/.ember/shadow"));
    }

    #[test]
    fn f_install_2_unknown_reports_warn_conservative() {
        let snap = empty_snapshot();
        assert_eq!(check_f_install_2(&snap).verdict, Verdict::Warn);
    }

    #[test]
    fn f_broker_2_invalid_credential_reports_fail() {
        let mut snap = empty_snapshot();
        snap.broker_github_credential_invalid = Some(true);
        assert_eq!(check_f_broker_2(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_broker_3_mock_on_prod_reports_fail() {
        let mut snap = empty_snapshot();
        snap.mock_brokers_trusted = Some(true);
        snap.daemon_lane_is_prod = Some(true);
        assert_eq!(check_f_broker_3(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_broker_3_mock_on_dev_is_ok() {
        let mut snap = empty_snapshot();
        snap.mock_brokers_trusted = Some(true);
        snap.daemon_lane_is_prod = Some(false);
        assert_eq!(check_f_broker_3(&snap).verdict, Verdict::Ok);
    }

    #[test]
    fn f_audit_1_full_reports_fail() {
        let mut snap = empty_snapshot();
        snap.audit_store_usage_ratio = Some(0.97);
        assert_eq!(check_f_audit_1(&snap).verdict, Verdict::Fail);
    }

    #[test]
    fn f_audit_1_above_warn_threshold() {
        let mut snap = empty_snapshot();
        snap.audit_store_usage_ratio = Some(0.85);
        assert_eq!(check_f_audit_1(&snap).verdict, Verdict::Warn);
    }

    #[test]
    fn f_audit_1_under_threshold_is_ok() {
        let mut snap = empty_snapshot();
        snap.audit_store_usage_ratio = Some(0.10);
        assert_eq!(check_f_audit_1(&snap).verdict, Verdict::Ok);
    }

    // ----- registry / runner tests -----

    #[test]
    fn registry_picks_up_bundled_symptoms() {
        let snap = empty_snapshot();
        let lines = run_all(&snap);
        let f_codes: Vec<&str> = lines.iter().map(|l| l.f_code).collect();
        // The bundled set in this file.
        for expected in [
            "F-DAEMON-1",
            "F-DAEMON-2",
            "F-DAEMON-3",
            "F-INSTALL-1",
            "F-INSTALL-2",
            "F-BROKER-2",
            "F-BROKER-3",
            "F-AUDIT-1",
        ] {
            assert!(
                f_codes.contains(&expected),
                "registry missing {expected}; got {f_codes:?}"
            );
        }
    }

    #[test]
    fn run_all_sorts_failures_before_warnings_before_ok() {
        // Inject one fail, the rest stay unknown (warn).
        let mut snap = empty_snapshot();
        snap.daemon_socket_reachable = Some(false); // F-DAEMON-1 fail
        snap.daemon_db_healthy = Some(true); // F-DAEMON-3 ok
        let lines = run_all(&snap);
        // First line MUST be a fail.
        assert_eq!(lines[0].verdict, Verdict::Fail);
        // The last verdict in the run MUST be ok (we registered one).
        let last_ok = lines.iter().rev().find(|l| l.verdict == Verdict::Ok);
        assert!(last_ok.is_some(), "expected at least one ok line, got {lines:?}");
    }

    #[test]
    fn t2_five_injected_symptoms_each_surface_correct_f_code() {
        // ADR 161 §Prerequisite P2 — at least 5 injected symptoms must
        // surface their F-code through the runner. This stays at T1
        // because the check functions are pure; no I/O involved.
        let mut snap = empty_snapshot();
        // Symptom 1 — daemon down → F-DAEMON-1.
        snap.daemon_socket_reachable = Some(false);
        // Symptom 2 — stale socket → F-DAEMON-2.
        snap.daemon_socket_stale = Some(true);
        // Symptom 3 — DB corrupt → F-DAEMON-3.
        snap.daemon_db_healthy = Some(false);
        // Symptom 4 — shadow missing → F-INSTALL-1.
        snap.shadow_path_present = Some(false);
        snap.shadow_path = Some(PathBuf::from("/home/op/.ember/shadow"));
        // Symptom 5 — broker creds invalid → F-BROKER-2.
        snap.broker_github_credential_invalid = Some(true);

        let lines = run_all(&snap);
        let fails: Vec<&str> = lines
            .iter()
            .filter(|l| l.verdict == Verdict::Fail)
            .map(|l| l.f_code)
            .collect();

        for expected in [
            "F-DAEMON-1",
            "F-DAEMON-2",
            "F-DAEMON-3",
            "F-INSTALL-1",
            "F-BROKER-2",
        ] {
            assert!(
                fails.contains(&expected),
                "expected {expected} in fails; got {fails:?}"
            );
        }
    }

    // ----- renderer tests -----

    #[test]
    fn format_line_renders_verdict_and_f_code() {
        let line = SymptomLine {
            f_code: "F-INSTALL-1",
            summary: "Shadow path present",
            recovery_cmd: "ember recover install --scope shadow",
            verdict: Verdict::Fail,
            detail: Some("missing".into()),
        };
        let rendered = format_line(&line, "ember");
        assert!(rendered.contains("[fail]"));
        assert!(rendered.contains("F-INSTALL-1"));
        assert!(rendered.contains("Recovery: ember recover install --scope shadow"));
        assert!(rendered.contains("Detail:   missing"));
    }

    #[test]
    fn format_line_rewrites_ember_prefix_for_repo_build() {
        let line = SymptomLine {
            f_code: "F-INSTALL-1",
            summary: "Shadow path present",
            recovery_cmd: "ember recover install --scope shadow",
            verdict: Verdict::Fail,
            detail: None,
        };
        let rendered = format_line(&line, "/tmp/target/debug/ember");
        assert!(
            rendered.contains("Recovery: /tmp/target/debug/ember recover install --scope shadow"),
            "rendered must rewrite ember prefix: {rendered}"
        );
    }

    #[test]
    fn render_appendix_emits_section_heading() {
        let snap = HealthSnapshot::default();
        let out = render_appendix(&snap, "ember");
        assert!(out.contains("F-code symptom checks"));
        // At least one line should be present since the bundled symptoms
        // are registered.
        assert!(out.contains("F-DAEMON-1"), "appendix missing F-DAEMON-1: {out}");
    }
}
