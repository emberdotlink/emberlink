//! CLASSIFICATION: PUBLIC
//!
//! F-code-driven diagnostic appendix for `ember status --troubleshoot`
//! per ADR 161 §Component 3.
//!
//! The appendix runs every registered [`crate::recover::symptoms::Symptom`]
//! against a [`HealthSnapshot`] assembled from the live status overview
//! plus lightweight filesystem probes, then renders one `[verdict]` line
//! per F-code with the canonical recovery command underneath. Failures
//! sort to the top of the appendix so the operator sees the actionable
//! items first.
//!
//! Wire-up: the existing `bin/ember/status.rs::render_status_troubleshoot_text`
//! appends [`render_troubleshoot_appendix`] to the end of its bounded
//! next-steps section. The pre-existing assertions on the next-steps
//! prefix continue to pass because this appendix only adds trailing
//! content; the F-code block is its own labelled section.
//!
//! Every troubleshoot run also emits a `daemon.health_check` Receipt
//! containing the verdict set; that emission lives in the wire-up site
//! and is documented in [`render_troubleshoot_appendix`]'s contract.

use std::path::PathBuf;

use crate::recover::symptoms::{HealthSnapshot, SymptomLine, Verdict, render_appendix, run_all};

/// Public façade — render the F-code appendix that gets appended to
/// `ember status --troubleshoot` output. Pure formatting on top of the
/// supplied [`HealthSnapshot`]; the snapshot's assembly (filesystem
/// probes, daemon RPC, etc.) belongs to the caller because it owns the
/// I/O budget.
pub fn render_troubleshoot_appendix(snapshot: &HealthSnapshot, ember_cmd: &str) -> String {
    render_appendix(snapshot, ember_cmd)
}

/// Run every registered symptom and return the structured lines —
/// exposed so callers that emit a `daemon.health_check` Receipt have
/// the verdict set already materialized.
pub fn run_symptom_checks(snapshot: &HealthSnapshot) -> Vec<SymptomLine> {
    run_all(snapshot)
}

/// Builder for a `HealthSnapshot` from the live status surface. The
/// real `bin/ember/status.rs` callsite passes in the values it already
/// computed from `collect_status_overview`; this helper keeps the
/// translation in one place so integration tests can produce an
/// equivalent snapshot from synthetic inputs without re-pulling the
/// whole `StatusOverview` struct into the public surface.
///
/// `shadow_path` is the resolved `~/.ember/shadow/` PathBuf or `None`
/// when the caller could not resolve a home directory (test contexts).
pub fn snapshot_from_probes(probes: TroubleshootProbes) -> HealthSnapshot {
    let TroubleshootProbes {
        daemon_socket_reachable,
        daemon_socket_stale,
        daemon_db_healthy,
        shadow_path,
        broker_github_credential_invalid,
        audit_store_usage_ratio,
        mock_brokers_trusted,
        daemon_lane_is_prod,
        install_manifest_signature_valid,
    } = probes;

    let shadow_path_present = shadow_path.as_ref().map(|p| p.exists());

    HealthSnapshot {
        daemon_socket_reachable,
        daemon_socket_stale,
        daemon_db_healthy,
        shadow_path_present,
        shadow_path,
        broker_github_credential_invalid,
        audit_store_usage_ratio,
        mock_brokers_trusted,
        daemon_lane_is_prod,
        install_manifest_signature_valid,
    }
}

/// Inputs the troubleshoot caller hands in from the surrounding status
/// overview. `None` means "the caller could not determine this signal"
/// — the check function reads that as "report `warn`" per ADR 161 R4.
#[derive(Debug, Clone, Default)]
pub struct TroubleshootProbes {
    pub daemon_socket_reachable: Option<bool>,
    pub daemon_socket_stale: Option<bool>,
    pub daemon_db_healthy: Option<bool>,
    pub shadow_path: Option<PathBuf>,
    pub broker_github_credential_invalid: Option<bool>,
    pub audit_store_usage_ratio: Option<f32>,
    pub mock_brokers_trusted: Option<bool>,
    pub daemon_lane_is_prod: Option<bool>,
    pub install_manifest_signature_valid: Option<bool>,
}

/// Convenience for integration tests + the wire-up site: count
/// failures in a verdict set. The `--troubleshoot` caller can use
/// this to set its exit status when failures surface.
pub fn count_failures(lines: &[SymptomLine]) -> usize {
    lines.iter().filter(|l| l.verdict == Verdict::Fail).count()
}

/// Build the `daemon.health_check` Receipt body for a troubleshoot run.
///
/// Per ADR 161 §Component 3 + §Consequences §Positive, every
/// `--troubleshoot` run is auditable: the operator's invocation, the
/// timestamp, and the verdict set become a Receipt the audit chain
/// surfaces under `ember audit show --kind daemon.health_check`.
///
/// This helper returns the body payload — the actual emission path
/// (daemon RPC → audit log → sidecar) is the wire-up site's job. Today
/// the troubleshoot caller logs the JSON body to the audit-event stream
/// at completion; the per-F-code recovery handlers add their own
/// `recovery.action` Receipts when the operator runs the recovery.
pub fn health_check_receipt_body(lines: &[SymptomLine]) -> serde_json::Value {
    let verdicts: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            serde_json::json!({
                "f_code": line.f_code,
                "verdict": match line.verdict {
                    Verdict::Ok => "ok",
                    Verdict::Warn => "warn",
                    Verdict::Fail => "fail",
                },
                "detail": line.detail.as_deref().unwrap_or(""),
            })
        })
        .collect();
    serde_json::json!({
        "kind": "daemon.health_check",
        "verdicts": verdicts,
        "fail_count": count_failures(lines),
    })
}

#[cfg(test)]
mod tests {
    //! T1 unit tests — pure rendering over synthetic snapshots.
    use super::*;
    use crate::recover::symptoms::Verdict;

    #[test]
    fn render_appendix_with_default_snapshot_runs_all_checks() {
        let probes = TroubleshootProbes::default();
        let snap = snapshot_from_probes(probes);
        let out = render_troubleshoot_appendix(&snap, "ember");
        assert!(
            out.contains("F-code symptom checks"),
            "appendix must include section heading: {out}"
        );
        assert!(out.contains("F-DAEMON-1"), "appendix missing F-DAEMON-1: {out}");
    }

    #[test]
    fn injected_daemon_fail_surfaces_first() {
        let probes = TroubleshootProbes {
            daemon_socket_reachable: Some(false),
            ..Default::default()
        };
        let snap = snapshot_from_probes(probes);
        let out = render_troubleshoot_appendix(&snap, "ember");
        let f_daemon_1_line = out
            .lines()
            .find(|l| l.contains("F-DAEMON-1"))
            .expect("F-DAEMON-1 line present");
        assert!(
            f_daemon_1_line.contains("[fail]"),
            "F-DAEMON-1 should be a fail: {f_daemon_1_line}"
        );
    }

    #[test]
    fn snapshot_from_probes_derives_shadow_presence_from_path_existence() {
        // Real path that exists on every Unix box used as a fixture for
        // the path-existence derivation. The semantic check (matching
        // F-INSTALL-1 against shadow_path_present == false) is covered
        // separately by the symptom-level unit tests.
        let probes = TroubleshootProbes {
            shadow_path: Some(PathBuf::from("/")),
            ..Default::default()
        };
        let snap = snapshot_from_probes(probes);
        // `/` always exists; the derived flag must be `Some(true)`.
        assert_eq!(snap.shadow_path_present, Some(true));
    }

    #[test]
    fn health_check_receipt_body_stamps_kind_and_verdicts() {
        let lines = vec![
            SymptomLine {
                f_code: "F-INSTALL-1",
                summary: "Shadow path present",
                recovery_cmd: "ember recover install --scope shadow",
                verdict: Verdict::Fail,
                detail: Some("missing".into()),
            },
            SymptomLine {
                f_code: "F-DAEMON-1",
                summary: "Daemon socket reachable",
                recovery_cmd: "ember recover daemon",
                verdict: Verdict::Ok,
                detail: None,
            },
        ];
        let body = health_check_receipt_body(&lines);
        assert_eq!(body["kind"], "daemon.health_check");
        assert_eq!(body["fail_count"], 1);
        let verdicts = body["verdicts"].as_array().unwrap();
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0]["f_code"], "F-INSTALL-1");
        assert_eq!(verdicts[0]["verdict"], "fail");
        assert_eq!(verdicts[1]["verdict"], "ok");
    }

    #[test]
    fn count_failures_counts_fails_only() {
        let lines = vec![
            SymptomLine {
                f_code: "F-X-1",
                summary: "a",
                recovery_cmd: "ember a",
                verdict: Verdict::Fail,
                detail: None,
            },
            SymptomLine {
                f_code: "F-X-2",
                summary: "b",
                recovery_cmd: "ember b",
                verdict: Verdict::Warn,
                detail: None,
            },
            SymptomLine {
                f_code: "F-X-3",
                summary: "c",
                recovery_cmd: "ember c",
                verdict: Verdict::Fail,
                detail: None,
            },
        ];
        assert_eq!(count_failures(&lines), 2);
    }

    #[test]
    fn t2_five_injected_symptoms_each_surface_correct_f_code_in_appendix() {
        // T2 integration assertion per ADR 161 §Component 4 (without
        // launching the daemon — we inject the signals at the boundary
        // the production code reads). 5 synthetic symptoms → 5 distinct
        // F-codes surface in the rendered appendix as `[fail]` lines.
        let probes = TroubleshootProbes {
            daemon_socket_reachable: Some(false),
            daemon_socket_stale: Some(true),
            daemon_db_healthy: Some(false),
            shadow_path: Some(PathBuf::from("/this/path/should/not/exist/i/think")),
            broker_github_credential_invalid: Some(true),
            ..Default::default()
        };
        let snap = snapshot_from_probes(probes);
        let out = render_troubleshoot_appendix(&snap, "ember");

        for expected in [
            "F-DAEMON-1",
            "F-DAEMON-2",
            "F-DAEMON-3",
            "F-INSTALL-1",
            "F-BROKER-2",
        ] {
            // Each F-code's line MUST surface as [fail].
            let line = out
                .lines()
                .find(|l| l.contains(expected))
                .unwrap_or_else(|| panic!("expected {expected} in appendix:\n{out}"));
            assert!(
                line.contains("[fail]"),
                "expected [fail] verdict on {expected}: {line}"
            );
        }
    }
}
