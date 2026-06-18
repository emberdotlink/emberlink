//! `ember recover diagnose` lifecycle umbrella per ADR 195.
//!
//! The command deliberately composes existing daemon RPC primitives instead of
//! opening protected stores directly from the CLI process.

use std::path::Path;

use clap::Args;
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

#[derive(Args, Debug, Clone, Copy, Default)]
pub struct RecoverDiagnoseArgs {}

#[derive(Debug, Clone)]
struct Probe {
    name: &'static str,
    command: &'static str,
    ok: bool,
    detail: String,
    value: Option<Value>,
}

#[derive(Debug, Clone)]
struct NextStep {
    command: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone)]
struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

pub fn handle(_args: RecoverDiagnoseArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover diagnose requires the managed daemon socket path so it can emit a \
             recovery.action receipt; run through the `ember` CLI, then retry",
        )
    })?;

    let probes = collect_probes(&socket_path);
    let next_step = choose_next_step(&probes);
    let state = probe_state_value(&probes);
    let prior_state_digest = digest_value(&state);
    let plan = json!({
        "next_step": next_step.as_ref().map(|step| step.command).unwrap_or("none"),
        "reason": next_step.as_ref().map(|step| step.reason).unwrap_or("all probes green"),
    });
    let dry_run_digest = digest_value(&plan);
    let receipt = emit_recovery_receipt(
        &socket_path,
        &prior_state_digest,
        &dry_run_digest,
        next_step.as_ref(),
    )?;

    println!("{}", render_report(&probes, next_step.as_ref(), &receipt));

    if next_step.is_some() {
        Ok(RecoverOutcome::issue_found())
    } else {
        Ok(RecoverOutcome::ok())
    }
}

fn collect_probes(socket_path: &Path) -> Vec<Probe> {
    vec![
        call_probe(
            socket_path,
            "status",
            json!({}),
            "daemon status",
            "ember status",
            status_detail,
        ),
        call_probe(
            socket_path,
            "vault_status",
            Value::Null,
            "vault status",
            "ember vault unlock",
            vault_detail,
        ),
        call_probe(
            socket_path,
            "list_personas",
            json!({}),
            "persona journal",
            "ember persona list",
            array_count_detail("personas"),
        ),
        call_probe(
            socket_path,
            "list_grants",
            json!({}),
            "grant journal",
            "ember grant list",
            array_count_detail("grants"),
        ),
        call_probe(
            socket_path,
            "audit_verify",
            json!({}),
            "audit verify",
            "ember audit verify",
            audit_detail,
        ),
    ]
}

fn call_probe<F>(
    socket_path: &Path,
    method: &str,
    params: Value,
    name: &'static str,
    command: &'static str,
    detail: F,
) -> Probe
where
    F: Fn(&Value) -> (bool, String),
{
    match crate::call_daemon_rpc(socket_path, method, &params) {
        Ok(value) => {
            let (ok, detail) = detail(&value);
            Probe {
                name,
                command,
                ok,
                detail,
                value: Some(value),
            }
        }
        Err(err) => Probe {
            name,
            command,
            ok: false,
            detail: err.to_string(),
            value: None,
        },
    }
}

fn status_detail(value: &Value) -> (bool, String) {
    let personas = value
        .get("personas")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let grants = value
        .get("grants")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let approvals = value
        .get("approvals")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let quarantined = value
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let authority = value
        .get("quarantine_authority")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let detail = if quarantined {
        format!(
            "quarantined by {authority}; {personas} personas, {grants} active grants, {approvals} pending approvals"
        )
    } else {
        format!("{personas} personas, {grants} active grants, {approvals} pending approvals")
    };
    (!quarantined, detail)
}

fn vault_detail(value: &Value) -> (bool, String) {
    let posture = value
        .get("posture")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let unlocked = value
        .get("unlocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let live_vault_attached = value
        .get("live_vault_attached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    (
        unlocked,
        format!(
            "posture={posture}, unlocked={unlocked}, live_vault_attached={live_vault_attached}"
        ),
    )
}

fn audit_detail(value: &Value) -> (bool, String) {
    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if ok {
        let rows = value
            .get("rows_walked")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let sample = value
            .get("sample_mode")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        (
            true,
            format!("chain ok; rows_walked={rows}, sample_mode={sample}"),
        )
    } else if let Some(breakage) = value.get("break") {
        (
            false,
            format!(
                "chain break: {}",
                breakage
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
        )
    } else {
        (
            false,
            "audit verifier reported a non-ok outcome".to_string(),
        )
    }
}

fn array_count_detail(label: &'static str) -> impl Fn(&Value) -> (bool, String) {
    move |value| {
        let count = value.as_array().map(Vec::len).unwrap_or(0);
        (true, format!("{count} {label} visible through daemon RPC"))
    }
}

fn choose_next_step(probes: &[Probe]) -> Option<NextStep> {
    let status = probes.iter().find(|probe| probe.name == "daemon status")?;
    if status.value.is_none() {
        return Some(NextStep {
            command: "sudo ember daemon install",
            reason: "daemon status RPC was unavailable, so receipt-backed recovery cannot inspect protected state",
        });
    }
    if !status.ok {
        return Some(NextStep {
            command: "ember recover audit-chain --dry-run",
            reason: "daemon status reports audit quarantine",
        });
    }
    if probes
        .iter()
        .any(|probe| probe.name == "audit verify" && !probe.ok)
    {
        return Some(NextStep {
            command: "ember recover audit-chain --dry-run",
            reason: "audit verification is not green",
        });
    }
    if probes
        .iter()
        .any(|probe| probe.name == "vault status" && !probe.ok)
    {
        return Some(NextStep {
            command: "ember recover vault --dry-run",
            reason: "vault posture is not interactive-unlocked",
        });
    }
    if probes
        .iter()
        .any(|probe| probe.name == "persona journal" && !probe.ok)
    {
        return Some(NextStep {
            command: "ember recover --explain F-AUTHORITY-1",
            reason: "persona journal summary could not be read through the daemon",
        });
    }
    if probes
        .iter()
        .any(|probe| probe.name == "grant journal" && !probe.ok)
    {
        return Some(NextStep {
            command: "ember recover --explain F-AUTHORITY-1",
            reason: "grant journal summary could not be read through the daemon",
        });
    }
    None
}

fn emit_recovery_receipt(
    socket_path: &Path,
    prior_state_digest: &str,
    dry_run_digest: &str,
    next_step: Option<&NextStep>,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-diagnose-{}",
        prior_state_digest
            .strip_prefix("blake3:")
            .unwrap_or(prior_state_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    let requested_action = next_step
        .map(|step| step.command)
        .unwrap_or("no-op: all recovery diagnose probes green");
    let params = json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "diagnose",
        "target_kind": "local-machine",
        "target_id": "local-machine",
        "requested_action": requested_action,
        "prior_state_digest": prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": "recovery_action_receipt",
        },
        "outcome": "planned",
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#recovery-lifecycle-plane",
        "adr_refs": ["ADR 195"],
    });

    let value = crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(
        |err| {
            RecoverError::authority(format!(
                "recover diagnose refused: could not emit recovery.action receipt through the daemon broker: {err}. Run `sudo ember daemon install`, then retry `ember recover diagnose`."
            ))
        },
    )?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover diagnose refused: daemon returned no recovery.action receipt_id",
            )
        })?
        .to_string();
    let persisted = value
        .get("persisted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ReceiptSummary {
        receipt_id,
        persisted,
    })
}

fn probe_state_value(probes: &[Probe]) -> Value {
    Value::Array(
        probes
            .iter()
            .map(|probe| {
                json!({
                    "name": probe.name,
                    "ok": probe.ok,
                    "detail": probe.detail,
                    "value": probe.value,
                })
            })
            .collect(),
    )
}

fn digest_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn render_report(
    probes: &[Probe],
    next_step: Option<&NextStep>,
    receipt: &ReceiptSummary,
) -> String {
    let mut out = String::new();
    out.push_str("Recovery diagnose\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    if receipt.persisted {
        out.push_str(" (persisted)\n\n");
    } else {
        out.push_str(" (signed; audit persistence pending)\n\n");
    }
    out.push_str("Probes:\n");
    for probe in probes {
        let state = if probe.ok { "ok" } else { "issue" };
        out.push_str("  ");
        out.push_str(probe.name);
        out.push_str(": ");
        out.push_str(state);
        out.push_str(" - ");
        out.push_str(&probe.detail);
        out.push_str(" [");
        out.push_str(probe.command);
        out.push_str("]\n");
    }
    out.push('\n');
    match next_step {
        Some(step) => {
            out.push_str("Next step:\n  Run `");
            out.push_str(step.command);
            out.push_str("` - ");
            out.push_str(step.reason);
            out.push('\n');
        }
        None => {
            out.push_str("Next step:\n  No recovery action is needed; re-run `ember status` before launching work.\n");
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(name: &'static str, ok: bool, value: Option<Value>) -> Probe {
        Probe {
            name,
            command: "ember test",
            ok,
            detail: "detail".to_string(),
            value,
        }
    }

    #[test]
    fn choose_next_step_routes_quarantine_to_audit_chain() {
        let probes = vec![
            probe("daemon status", false, Some(json!({"quarantined": true}))),
            probe("vault status", true, Some(json!({"unlocked": true}))),
            probe("persona journal", true, Some(json!([]))),
            probe("grant journal", true, Some(json!([]))),
            probe("audit verify", true, Some(json!({"ok": true}))),
        ];

        let step = choose_next_step(&probes).expect("quarantine should route");
        assert_eq!(step.command, "ember recover audit-chain --dry-run");
    }

    #[test]
    fn render_report_names_receipt_and_single_next_step() {
        let probes = vec![
            probe("daemon status", true, Some(json!({"quarantined": false}))),
            probe("vault status", false, Some(json!({"unlocked": false}))),
        ];
        let receipt = ReceiptSummary {
            receipt_id: "rct-123".to_string(),
            persisted: true,
        };
        let step = NextStep {
            command: "ember recover vault --dry-run",
            reason: "vault posture is not interactive-unlocked",
        };

        let rendered = render_report(&probes, Some(&step), &receipt);
        assert!(rendered.contains("Receipt: recovery.action rct-123"));
        assert!(rendered.contains("Run `ember recover vault --dry-run`"));
        assert_eq!(rendered.matches("Next step:").count(), 1);
    }
}
