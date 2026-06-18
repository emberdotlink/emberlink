//! `ember recover audit-chain` lifecycle recovery per ADR 195 + ADR 174.
//!
//! The CLI process does not open daemon-owned audit state directly. It asks the
//! daemon for verifier/status projections, builds a structured plan, emits a
//! daemon-signed `recovery.action` planning receipt, and only routes mutation
//! through the existing `audit_repair_chain` daemon RPC after the operator
//! retypes the confirmation token and supplies operator co-signature material.

use std::path::Path;

use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

#[derive(Args, Debug, Clone, Default)]
pub struct RecoverAuditChainArgs {
    /// Print the recovery plan and confirmation token without executing.
    #[arg(long)]
    pub dry_run: bool,

    /// Retyped confirmation token from a prior dry-run plan.
    #[arg(long, value_name = "TOKEN")]
    pub confirm: Option<String>,

    /// Tail size to pass to the daemon verifier. Omit for full-chain verify.
    #[arg(long)]
    pub tail: Option<usize>,

    /// Row id to preserve when executing truncate-after-row repair.
    #[arg(long)]
    pub from_row_id: Option<i64>,

    /// Enrolled presence-Device public key in `p256:<hex>` wire form (dev0:
    /// YubiKey-PIV ECDSA-P256). The daemon verifies the co-signature against the
    /// presence-Device set under the operator root (ADR 200 §6), so this is the
    /// claimed signer; an `ed25519:<hex>` key is accepted only if so enrolled.
    #[arg(long)]
    pub operator_pubkey: Option<String>,

    /// Raw presence-Device signature hex over the audit repair intent (the
    /// `p256sig:`/`ed25519sig:` payload with the prefix stripped). Produced
    /// out-of-band by the presence Device (ADR 200 OQ-6).
    #[arg(long)]
    pub operator_signature_hex: Option<String>,

    /// Hash of the preserved row at `--from-row-id`.
    #[arg(long)]
    pub current_chain_tip_hash: Option<String>,

    /// Daemon identity-root fingerprint that was included in the signed intent.
    #[arg(long)]
    pub daemon_identity_root_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AuditChainPlan {
    state: AuditChainState,
    failure_class: String,
    adr_174_tier: &'static str,
    requested_action: &'static str,
    target_kind: &'static str,
    target_id: &'static str,
    prior_journal_sha: String,
    proposed_action: Value,
    operator_confirmation_token: String,
    operator_confirmation_token_hash: String,
    requires_operator_cosign: bool,
    executable_via_daemon_rpc: bool,
    refusal_step: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuditChainState {
    Clean,
    QuarantinedBreak,
    CordonedLegacyRows,
    TopologyViolation,
    IncompleteRepair,
    IncompleteRepairReceipt,
    UnknownVerifierOutcome,
}

#[derive(Debug, Clone)]
struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

pub fn handle(args: RecoverAuditChainArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover audit-chain requires the managed daemon socket path; step: broker-unavailable",
        )
    })?;

    let status = call_daemon(&socket_path, "status", json!({}), "daemon status")?;
    let verify = call_daemon(
        &socket_path,
        "audit_verify",
        match args.tail {
            Some(tail) => json!({ "tail": tail }),
            None => json!({}),
        },
        "audit verify",
    )?;

    let plan = build_plan(&status, &verify, args.current_chain_tip_hash.as_deref());
    let plan_digest = digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));
    let receipt_outcome = if args
        .confirm
        .as_deref()
        .is_some_and(|token| token != plan.operator_confirmation_token)
    {
        "refused"
    } else {
        "planned"
    };
    let receipt = emit_recovery_receipt(&socket_path, &plan, &plan_digest, receipt_outcome)?;

    if args.dry_run || plan.state == AuditChainState::Clean {
        println!("{}", render_plan(&plan, &receipt, None));
        return if plan.state == AuditChainState::Clean {
            Ok(RecoverOutcome::ok())
        } else {
            Ok(RecoverOutcome::issue_found())
        };
    }

    let Some(confirm) = args.confirm.as_deref() else {
        println!("{}", render_plan(&plan, &receipt, None));
        return Err(RecoverError::authority(format!(
            "recover audit-chain refused: re-run with --confirm {} after reviewing the dry-run plan",
            plan.operator_confirmation_token
        )));
    };
    if confirm != plan.operator_confirmation_token {
        println!(
            "{}",
            render_plan(
                &plan,
                &receipt,
                Some("operator confirmation token mismatch; no mutation attempted")
            )
        );
        return Err(RecoverError::authority(
            "recover audit-chain refused: confirmation token mismatch",
        ));
    }

    if !plan.executable_via_daemon_rpc {
        println!(
            "{}",
            render_plan(
                &plan,
                &receipt,
                Some(plan.refusal_step.unwrap_or("unsupported-verifier-outcome"))
            )
        );
        return Err(RecoverError::authority(format!(
            "recover audit-chain refused: step: {}",
            plan.refusal_step.unwrap_or("unsupported-verifier-outcome")
        )));
    }

    let repair = repair_params(&args, &plan)?;
    let result = call_daemon(
        &socket_path,
        "audit_repair_chain",
        repair,
        "audit repair-chain",
    )?;
    println!("{}", render_plan(&plan, &receipt, Some("executed")));
    println!("{}", render_repair_result(&result));
    Ok(RecoverOutcome::ok())
}

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &'static str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover audit-chain refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

fn build_plan(status: &Value, verify: &Value, supplied_chain_tip: Option<&str>) -> AuditChainPlan {
    let status_quarantined = status
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let authority = status
        .get("quarantine_authority")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let prior_journal_sha = supplied_chain_tip
        .map(|tip| format!("audit-row:{tip}"))
        .unwrap_or_else(|| digest_value(verify));

    let mut plan = if verify.get("ok").and_then(Value::as_bool).unwrap_or(false)
        && verify.get("legacy_rows_present").is_none()
    {
        AuditChainPlan {
            state: AuditChainState::Clean,
            failure_class: "none".to_string(),
            adr_174_tier: "operator-only",
            requested_action: "no-op",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "no-op",
                "reason": "audit verifier returned ok and daemon is not reporting a repair outcome",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: false,
            executable_via_daemon_rpc: false,
            refusal_step: None,
        }
    } else if let Some(legacy) = verify.get("legacy_rows_present") {
        AuditChainPlan {
            state: AuditChainState::CordonedLegacyRows,
            failure_class: "cordon-migration-attestation-pending".to_string(),
            adr_174_tier: "operator-only",
            requested_action: "acknowledge-cordon-migration",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "acknowledge-cordon-migration",
                "legacy_rows": legacy,
                "route": "ember audit migrate-chain --acknowledge",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: false,
            executable_via_daemon_rpc: false,
            refusal_step: Some("cordon-migration-acknowledge-pending"),
        }
    } else if let Some(breakage) = verify.get("break") {
        let from_row_id = preserve_row_for_break(breakage);
        let executable = from_row_id.is_some();
        AuditChainPlan {
            state: AuditChainState::QuarantinedBreak,
            failure_class: breakage
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("chain-break")
                .to_string(),
            adr_174_tier: if executable {
                "operator-co-signed"
            } else {
                "refused"
            },
            requested_action: if executable {
                "truncate-after-row"
            } else {
                "route-to-manual-audit-forensics"
            },
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": if executable { "truncate-after-row" } else { "route-to-manual-audit-forensics" },
                "daemon_rpc": "audit_repair_chain",
                "repair_kind": "truncate",
                "from_row_id": from_row_id,
                "verifier_break": breakage,
                "quarantine_authority": authority,
                "status_quarantined": status_quarantined,
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: executable,
            executable_via_daemon_rpc: executable,
            refusal_step: if executable {
                None
            } else {
                Some("repair-row-unavailable")
            },
        }
    } else if let Some(topology) = verify.get("topology_violation") {
        AuditChainPlan {
            state: AuditChainState::TopologyViolation,
            failure_class: "chain-topology-invariant-violation".to_string(),
            adr_174_tier: "refused",
            requested_action: "route-to-manual-audit-forensics",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "route-to-manual-audit-forensics",
                "topology_violation": topology,
                "route": "ember audit verify",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: true,
            executable_via_daemon_rpc: false,
            refusal_step: Some("topology-violation-manual-forensics"),
        }
    } else if let Some(incomplete) = verify.get("incomplete_repair") {
        AuditChainPlan {
            state: AuditChainState::IncompleteRepair,
            failure_class: "incomplete-repair-receipt-orphan".to_string(),
            adr_174_tier: "operator-co-signed",
            requested_action: "resume-incomplete-repair",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "resume-incomplete-repair",
                "incomplete_repair": incomplete,
                "route": "audit_repair_chain resume primitive pending",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: true,
            executable_via_daemon_rpc: false,
            refusal_step: Some("incomplete-repair-resume-pending"),
        }
    } else if let Some(incomplete_receipt) = verify.get("incomplete_repair_receipt") {
        AuditChainPlan {
            state: AuditChainState::IncompleteRepairReceipt,
            failure_class: "incomplete-repair-tombstone-orphan".to_string(),
            adr_174_tier: "operator-co-signed",
            requested_action: "chain-repair-finalize",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "chain-repair-finalize",
                "incomplete_repair_receipt": incomplete_receipt,
                "route": "ember audit chain-repair-finalize",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: true,
            executable_via_daemon_rpc: false,
            refusal_step: Some("chain-repair-finalize-pending"),
        }
    } else {
        AuditChainPlan {
            state: AuditChainState::UnknownVerifierOutcome,
            failure_class: "unknown-verifier-outcome".to_string(),
            adr_174_tier: "refused",
            requested_action: "run-audit-verify",
            target_kind: "audit-chain",
            target_id: "local-audit-chain",
            prior_journal_sha,
            proposed_action: json!({
                "action": "run-audit-verify",
                "verifier_response": verify,
                "route": "ember audit verify",
            }),
            operator_confirmation_token: String::new(),
            operator_confirmation_token_hash: String::new(),
            requires_operator_cosign: false,
            executable_via_daemon_rpc: false,
            refusal_step: Some("verifier-outcome-unknown"),
        }
    };

    let token = confirmation_token(&plan);
    plan.operator_confirmation_token_hash = digest_str(&token);
    plan.operator_confirmation_token = token;
    plan
}

fn preserve_row_for_break(breakage: &Value) -> Option<i64> {
    match breakage.get("kind").and_then(Value::as_str) {
        Some("forward_link_mismatch") => breakage.get("predecessor_row_id").and_then(Value::as_i64),
        Some("row_hash_mismatch") => breakage
            .get("at_row_id")
            .and_then(Value::as_i64)
            .and_then(|id| id.checked_sub(1))
            .filter(|id| *id > 0),
        _ => None,
    }
}

fn confirmation_token(plan: &AuditChainPlan) -> String {
    let material = json!({
        "prior_journal_sha": plan.prior_journal_sha,
        "requested_action": plan.requested_action,
        "proposed_action": plan.proposed_action,
    });
    let digest = digest_value(&material);
    format!(
        "audit-chain-{}",
        digest
            .strip_prefix("blake3:")
            .unwrap_or(&digest)
            .chars()
            .take(16)
            .collect::<String>()
    )
}

fn repair_params(
    args: &RecoverAuditChainArgs,
    plan: &AuditChainPlan,
) -> Result<Value, RecoverError> {
    let missing = [
        ("--from-row-id", args.from_row_id.is_none()),
        ("--operator-pubkey", args.operator_pubkey.is_none()),
        (
            "--operator-signature-hex",
            args.operator_signature_hex.is_none(),
        ),
        (
            "--current-chain-tip-hash",
            args.current_chain_tip_hash.is_none(),
        ),
        (
            "--daemon-identity-root-fingerprint",
            args.daemon_identity_root_fingerprint.is_none(),
        ),
    ]
    .iter()
    .filter_map(|(name, missing)| missing.then_some(*name))
    .collect::<Vec<_>>();

    if !missing.is_empty() {
        return Err(RecoverError::authority(format!(
            "recover audit-chain refused: executing truncate-after-row requires {}; run --dry-run first and sign the displayed repair intent",
            missing.join(", ")
        )));
    }

    let planned_from_row_id = plan
        .proposed_action
        .get("from_row_id")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            RecoverError::authority(
                "recover audit-chain refused: current plan does not contain a repair row id",
            )
        })?;
    let supplied_from_row_id = args.from_row_id.expect("validated above");
    if supplied_from_row_id != planned_from_row_id {
        return Err(RecoverError::authority(format!(
            "recover audit-chain refused: --from-row-id {supplied_from_row_id} does not match current dry-run plan row {planned_from_row_id}"
        )));
    }

    Ok(json!({
        "from_row_id": planned_from_row_id,
        "repair_kind": "truncate",
        "operator_signature_hex": args
            .operator_signature_hex
            .as_deref()
            .expect("validated above"),
        "operator_pubkey": args.operator_pubkey.as_deref().expect("validated above"),
        "current_chain_tip_hash": args
            .current_chain_tip_hash
            .as_deref()
            .expect("validated above"),
        "daemon_identity_root_fingerprint": args
            .daemon_identity_root_fingerprint
            .as_deref()
            .expect("validated above"),
    }))
}

fn emit_recovery_receipt(
    socket_path: &Path,
    plan: &AuditChainPlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-audit-chain-{}",
        dry_run_digest
            .strip_prefix("blake3:")
            .unwrap_or(dry_run_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    let params = json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "audit-chain",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_journal_sha,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": plan.operator_confirmation_token_hash,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": "recovery_action_receipt",
            "follow_on_rpc": plan.proposed_action.get("daemon_rpc").cloned().unwrap_or(Value::Null),
        },
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#audit-chain-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 174", "ADR 176"],
    });

    let value =
        crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(|err| {
            RecoverError::authority(format!(
                "recover audit-chain refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover audit-chain refused: daemon returned no recovery.action receipt_id",
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

fn render_plan(plan: &AuditChainPlan, receipt: &ReceiptSummary, note: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("Recovery audit-chain\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    if receipt.persisted {
        out.push_str(" (persisted)\n\n");
    } else {
        out.push_str(" (signed; audit persistence pending)\n\n");
    }
    out.push_str("State: ");
    out.push_str(match plan.state {
        AuditChainState::Clean => "clean",
        AuditChainState::QuarantinedBreak => "quarantined break",
        AuditChainState::CordonedLegacyRows => "cordoned legacy rows",
        AuditChainState::TopologyViolation => "topology violation",
        AuditChainState::IncompleteRepair => "incomplete repair",
        AuditChainState::IncompleteRepairReceipt => "incomplete repair receipt",
        AuditChainState::UnknownVerifierOutcome => "unknown verifier outcome",
    });
    out.push('\n');
    out.push_str("Failure class: ");
    out.push_str(&plan.failure_class);
    out.push('\n');
    out.push_str("ADR 174 tier: ");
    out.push_str(plan.adr_174_tier);
    out.push('\n');
    out.push_str("Prior journal sha: ");
    out.push_str(&plan.prior_journal_sha);
    out.push('\n');
    out.push_str("Requested action: ");
    out.push_str(plan.requested_action);
    out.push('\n');
    out.push_str("Requires operator co-sign: ");
    out.push_str(if plan.requires_operator_cosign {
        "yes"
    } else {
        "no"
    });
    out.push('\n');
    out.push_str("Confirmation token: ");
    out.push_str(&plan.operator_confirmation_token);
    out.push_str("\n\nPlan:\n");
    out.push_str(
        &serde_json::to_string_pretty(&plan.proposed_action).unwrap_or_else(|_| "{}".to_string()),
    );
    out.push('\n');
    if let Some(note) = note {
        out.push_str("\nNote: ");
        out.push_str(note);
        out.push('\n');
    }
    if plan.state != AuditChainState::Clean {
        out.push_str("\nNext step:\n  Re-run with `--confirm ");
        out.push_str(&plan.operator_confirmation_token);
        out.push_str("` after reviewing the plan");
        if plan.requires_operator_cosign {
            out.push_str(" and supplying the operator co-signature arguments");
        }
        out.push_str(".\n");
    }
    out.trim_end().to_string()
}

fn render_repair_result(result: &Value) -> String {
    if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        format!(
            "Repair: ok\n  repair_id: {}\n  tombstone_row_id: {}\n  truncated_row_count: {}\n  new_chain_tip_hash: {}",
            result
                .get("repair_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            result
                .get("tombstone_row_id")
                .and_then(Value::as_i64)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            result
                .get("truncated_row_count")
                .and_then(Value::as_u64)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            result
                .get("new_chain_tip_hash")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )
    } else if let Some(incomplete) = result.get("incomplete_repair") {
        format!("Repair: incomplete\n  {incomplete}")
    } else if let Some(incomplete) = result.get("incomplete_repair_receipt") {
        format!("Repair: incomplete receipt\n  {incomplete}")
    } else {
        format!("Repair: unexpected daemon response\n  {result}")
    }
}

fn digest_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn digest_str(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_clean_chain_as_noop() {
        let plan = build_plan(
            &json!({"quarantined": false, "quarantine_authority": null}),
            &json!({"ok": true, "rows_walked": 4, "sample_mode": "FullWalk"}),
            None,
        );

        assert_eq!(plan.state, AuditChainState::Clean);
        assert_eq!(plan.requested_action, "no-op");
        assert!(!plan.requires_operator_cosign);
    }

    #[test]
    fn plan_forward_link_break_as_cosigned_truncate() {
        let plan = build_plan(
            &json!({"quarantined": true, "quarantine_authority": "startup_audit_chain_break"}),
            &json!({
                "ok": false,
                "break": {
                    "kind": "forward_link_mismatch",
                    "at_row_id": 42,
                    "predecessor_row_id": 41,
                    "expected_prev_hash": "aa",
                    "stored_prev_hash": "bb",
                    "rows_walked_before": 40
                }
            }),
            Some("tip-hash"),
        );

        assert_eq!(plan.state, AuditChainState::QuarantinedBreak);
        assert_eq!(plan.adr_174_tier, "operator-co-signed");
        assert!(plan.requires_operator_cosign);
        assert!(plan.executable_via_daemon_rpc);
        assert_eq!(plan.proposed_action["from_row_id"], json!(41));
        assert!(plan.operator_confirmation_token.starts_with("audit-chain-"));
    }

    #[test]
    fn plan_cordoned_legacy_rows_routes_to_acknowledgement() {
        let plan = build_plan(
            &json!({"quarantined": false, "quarantine_authority": null}),
            &json!({
                "ok": true,
                "legacy_rows_present": {
                    "count": 3,
                    "max_legacy_id": 10,
                    "chain_resumes_at_id": 11
                }
            }),
            None,
        );

        assert_eq!(plan.state, AuditChainState::CordonedLegacyRows);
        assert_eq!(plan.requested_action, "acknowledge-cordon-migration");
        assert_eq!(
            plan.refusal_step,
            Some("cordon-migration-acknowledge-pending")
        );
    }

    #[test]
    fn repair_params_require_cosignature_material() {
        let plan = build_plan(
            &json!({"quarantined": true, "quarantine_authority": "startup_audit_chain_break"}),
            &json!({
                "ok": false,
                "break": {
                    "kind": "forward_link_mismatch",
                    "at_row_id": 42,
                    "predecessor_row_id": 41
                }
            }),
            Some("tip-hash"),
        );
        let err =
            repair_params(&RecoverAuditChainArgs::default(), &plan).expect_err("missing args");
        let msg = err.to_string();
        assert!(msg.contains("--operator-pubkey"));
        assert!(msg.contains("--daemon-identity-root-fingerprint"));
    }

    #[test]
    fn repair_params_reject_row_id_that_differs_from_current_plan() {
        let plan = build_plan(
            &json!({"quarantined": true, "quarantine_authority": "startup_audit_chain_break"}),
            &json!({
                "ok": false,
                "break": {
                    "kind": "forward_link_mismatch",
                    "at_row_id": 42,
                    "predecessor_row_id": 41
                }
            }),
            Some("tip-hash"),
        );
        let err = repair_params(
            &RecoverAuditChainArgs {
                from_row_id: Some(40),
                operator_pubkey: Some("ed25519:aa".to_string()),
                operator_signature_hex: Some("bb".to_string()),
                current_chain_tip_hash: Some("tip-hash".to_string()),
                daemon_identity_root_fingerprint: Some("daemon-root".to_string()),
                ..RecoverAuditChainArgs::default()
            },
            &plan,
        )
        .expect_err("row mismatch");

        assert!(
            err.to_string()
                .contains("does not match current dry-run plan")
        );
    }
}
