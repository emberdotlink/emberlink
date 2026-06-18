//! `ember recover persona` lifecycle recovery per ADR 195.
//!
//! This slice wires explicit persona abandonment plus a fail-closed `restore`
//! eligibility probe. The mutating restore itself remains a separate P14-S4
//! deliverable (blocked on ADR 205 §A.6 step 4 + ADR 206 enrollment) because it
//! must evaluate the ADR 190/195 runtime predicate inside daemon authority
//! space. The CLI never opens daemon-owned persona state directly: it reads the
//! daemon projection or recovery probe, emits planned/refused `recovery.action`
//! receipts through the receipt lane, and executes mutations only through the
//! daemon's operator-presence recovery RPC after the operator retypes the
//! state-bound confirmation token.

use std::path::Path;

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

#[derive(Args, Debug, Clone)]
pub struct RecoverPersonaArgs {
    #[command(subcommand)]
    pub action: RecoverPersonaAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RecoverPersonaAction {
    /// Inspect whether a persona's runtime state can be restored (read-only probe).
    Restore(RestorePersonaArgs),

    /// Mark a persona abandoned with provenance; does not restore identity.
    Abandon(AbandonPersonaArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RestorePersonaArgs {
    /// Persona id whose restore eligibility should be inspected.
    #[arg(value_name = "PERSONA_ID")]
    pub persona_id: String,

    /// Execute the restore once a future daemon mutation RPC can prove the ADR 190/195 predicate.
    #[arg(long)]
    pub execute: bool,

    /// Retyped confirmation token from a future executable restore plan.
    #[arg(long, value_name = "TOKEN")]
    pub confirm: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct AbandonPersonaArgs {
    /// Persona id to abandon.
    #[arg(value_name = "PERSONA_ID")]
    pub persona_id: String,

    /// Human-readable provenance explaining why the persona is abandoned.
    #[arg(long, value_name = "TEXT")]
    pub reason: String,

    /// Execute the abandonment. Omit to print a dry-run plan and token.
    #[arg(long)]
    pub execute: bool,

    /// Retyped confirmation token from the dry-run plan.
    #[arg(long, value_name = "TOKEN")]
    pub confirm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PersonaAbandonPlan {
    target_kind: &'static str,
    target_id: String,
    requested_action: &'static str,
    prior_state_digest: String,
    proposed_action: Value,
    operator_confirmation_token: String,
    operator_confirmation_token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PersonaRestorePlan {
    target_kind: &'static str,
    target_id: String,
    requested_action: &'static str,
    prior_state_digest: String,
    diagnostic_code: String,
    proposed_action: Value,
}

#[derive(Debug, Clone)]
struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

pub fn handle(args: RecoverPersonaArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover persona requires the managed daemon socket path; step: broker-unavailable",
        )
    })?;

    match args.action {
        RecoverPersonaAction::Restore(args) => handle_restore(args, &socket_path),
        RecoverPersonaAction::Abandon(args) => handle_abandon(args, &socket_path),
    }
}

fn handle_restore(args: RestorePersonaArgs, socket_path: &Path) -> RecoverResult {
    let persona_id = args.persona_id.trim().to_string();
    let probe = call_daemon_restore(
        socket_path,
        "recover_persona_restore_status",
        json!({ "id": persona_id }),
        "persona restore status",
    )?;
    let plan = build_restore_plan(&probe)?;
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));
    let receipt_outcome = if plan.diagnostic_code == "eligible_pending_mutation_rpc" {
        "planned"
    } else {
        "refused"
    };
    let receipt = emit_restore_receipt(socket_path, &plan, &plan_digest, receipt_outcome)?;
    println!("{}", render_restore_plan(&plan, &receipt));

    if args.execute {
        return Err(RecoverError::authority(
            "recover persona restore refused: no daemon mutation RPC can restore runtime persona state under the ADR 190/195 predicate yet; no mutation attempted",
        ));
    }

    if plan.diagnostic_code == "eligible_pending_mutation_rpc" {
        Ok(RecoverOutcome::ok())
    } else {
        Ok(RecoverOutcome::issue_found())
    }
}

fn handle_abandon(args: AbandonPersonaArgs, socket_path: &Path) -> RecoverResult {
    let persona_id = args.persona_id.trim().to_string();
    let reason = args.reason.trim().to_string();
    if reason.is_empty() {
        return Err(RecoverError::usage(
            "recover persona abandon requires --reason with non-empty provenance",
        ));
    }

    let personas = call_daemon(socket_path, "list_personas", Value::Null, "list personas")?;
    let persona = find_persona(&personas, &persona_id)?;
    let plan = build_abandon_plan(persona, &reason)?;
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));

    if !args.execute {
        let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "planned", &reason)?;
        println!("{}", render_plan(&plan, &receipt));
        return Ok(RecoverOutcome::ok());
    }

    let Some(confirm) = args.confirm.as_deref() else {
        let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "refused", &reason)?;
        println!("{}", render_plan(&plan, &receipt));
        return Err(RecoverError::authority(format!(
            "recover persona abandon refused: --execute requires --confirm {}; no mutation attempted",
            plan.operator_confirmation_token
        )));
    };

    if confirm != plan.operator_confirmation_token {
        let _ = emit_recovery_receipt(socket_path, &plan, &plan_digest, "refused", &reason);
        return Err(RecoverError::authority(
            "recover persona abandon refused: confirmation token mismatch; no mutation attempted",
        ));
    }

    let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "executed", &reason)?;
    println!("{}", render_executed(&plan, &receipt));
    Ok(RecoverOutcome::ok())
}

fn find_persona<'a>(personas: &'a Value, persona_id: &str) -> Result<&'a Value, RecoverError> {
    let items = personas.as_array().ok_or_else(|| {
        RecoverError::authority(
            "recover persona abandon refused: daemon did not return a persona list",
        )
    })?;
    items
        .iter()
        .find(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id == persona_id)
        })
        .ok_or_else(|| {
            RecoverError::authority(format!(
                "recover persona abandon refused: persona {persona_id} not found"
            ))
        })
}

fn build_restore_plan(status: &Value) -> Result<PersonaRestorePlan, RecoverError> {
    let kind = status
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != "persona_restore_status" {
        return Err(RecoverError::authority(
            "recover persona restore refused: daemon did not return a persona restore status",
        ));
    }
    let persona_id = status
        .get("persona_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            RecoverError::authority("recover persona restore refused: persona id missing")
        })?;
    let diagnostic_code = status
        .get("diagnostic_code")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let can_restore = status
        .get("can_restore")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let restore_eligibility_proven = status
        .get("restore_eligibility_proven")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let durable_persona_terminal = status
        .get("durable_persona_terminal")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let successor_enrollment_required = status
        .get("successor_enrollment_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let decision = if diagnostic_code == "eligible_pending_mutation_rpc" {
        "requires-dedicated-mutation-rpc"
    } else if durable_persona_terminal {
        "refuse-policy-bypass"
    } else {
        "refuse"
    };

    let prior_state = json!({
        "persona_id": persona_id,
        "status": status.get("status").cloned().unwrap_or(Value::Null),
        "name": status.get("name").cloned().unwrap_or(Value::Null),
        "created_at": status.get("created_at").cloned().unwrap_or(Value::Null),
        "durable_persona_terminal": durable_persona_terminal,
        "durable_persona_active": status.get("durable_persona_active").cloned().unwrap_or(Value::Null),
        "restore_eligibility_proven": status.get("restore_eligibility_proven").cloned().unwrap_or(Value::Null),
        "can_restore": can_restore,
        "successor_enrollment_required": successor_enrollment_required,
        "diagnostic_code": diagnostic_code,
        "diagnostics": status.get("diagnostics").cloned().unwrap_or(Value::Null),
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": Value::Null,
        "verb": "persona",
        "requested_action": "restore",
        "persona_id": persona_id,
        "decision": decision,
        "diagnostic_code": diagnostic_code,
        "can_restore": can_restore,
        "restore_eligibility_proven": restore_eligibility_proven,
        "successor_enrollment_required": successor_enrollment_required,
        "successor_enrollment_route": status.get("successor_enrollment_route").cloned().unwrap_or_else(|| {
            json!("ember device enroll (successor per ADR 206/211; a revoked durable persona is not un-revoked)")
        }),
        "floor": "restore proves the ADR 190/195 runtime predicate inside a dedicated daemon mutation RPC; a read-only probe never un-revokes a terminal durable persona",
    });

    Ok(PersonaRestorePlan {
        target_kind: "persona",
        target_id: persona_id.to_string(),
        requested_action: "restore",
        prior_state_digest,
        diagnostic_code,
        proposed_action,
    })
}

fn emit_restore_receipt(
    socket_path: &Path,
    plan: &PersonaRestorePlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let params = restore_receipt_params(plan, dry_run_digest, outcome);

    let value = crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(
        |err| {
            RecoverError::authority(format!(
                "recover persona restore refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        },
    )?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover persona restore refused: daemon returned no recovery.action receipt_id",
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

fn restore_receipt_params(plan: &PersonaRestorePlan, dry_run_digest: &str, outcome: &str) -> Value {
    let recovery_id = format!(
        "recover-persona-restore-{}",
        dry_run_digest
            .strip_prefix("blake3:")
            .unwrap_or(dry_run_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "persona",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "probe_rpc": "recover_persona_restore_status",
            "diagnostic_code": plan.diagnostic_code,
            "decision": plan.proposed_action["decision"].clone(),
            "can_restore": plan.proposed_action["can_restore"].clone(),
            "restore_eligibility_proven": plan.proposed_action["restore_eligibility_proven"].clone(),
            "successor_enrollment_required": plan.proposed_action["successor_enrollment_required"].clone(),
            "evidence_floor": plan.proposed_action["floor"].clone(),
        },
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 190", "ADR 206", "ADR 211"],
    })
}

fn call_daemon_restore(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover persona restore refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

fn render_restore_plan(plan: &PersonaRestorePlan, receipt: &ReceiptSummary) -> String {
    let decision = plan
        .proposed_action
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("refuse");
    let route = plan
        .proposed_action
        .get("successor_enrollment_route")
        .and_then(Value::as_str)
        .unwrap_or("ember device enroll (successor per ADR 206/211)");
    let mut out = String::new();
    out.push_str("recover persona restore (dry-run / no state modified)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Persona: ");
    out.push_str(&plan.target_id);
    out.push('\n');
    out.push_str("Decision: ");
    out.push_str(decision);
    out.push('\n');
    out.push_str("Diagnostic: ");
    out.push_str(&plan.diagnostic_code);
    out.push('\n');
    out.push_str("Prior state digest: ");
    out.push_str(&plan.prior_state_digest);
    out.push_str("\n\nPlan:\n");
    out.push_str(
        &serde_json::to_string_pretty(&plan.proposed_action).unwrap_or_else(|_| "{}".to_string()),
    );
    out.push_str("\n\nNext step:\n  ");
    if plan.diagnostic_code == "eligible_pending_mutation_rpc" {
        out.push_str(
            "Durable persona is active; the authoritative restore predicate runs in the dedicated mutation RPC (not yet built). No state modified.\n",
        );
    } else {
        out.push_str("Do not un-revoke a terminal durable persona. Re-establish authority via `");
        out.push_str(route);
        out.push_str("`.\n");
    }
    out.trim_end().to_string()
}

fn build_abandon_plan(persona: &Value, reason: &str) -> Result<PersonaAbandonPlan, RecoverError> {
    let persona_id = persona
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            RecoverError::authority("recover persona abandon refused: persona id missing")
        })?;
    let current_status = persona
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(current_status, "revoked") {
        return Err(RecoverError::authority(format!(
            "recover persona abandon refused: persona {persona_id} is already terminal ({current_status})"
        )));
    }

    let prior_state = json!({
        "persona_id": persona_id,
        "name": persona.get("name").cloned().unwrap_or(Value::Null),
        "status": current_status,
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": "recover_persona_abandon",
        "verb": "persona",
        "requested_action": "abandon",
        "persona_id": persona_id,
        "reason": reason,
        "new_status": "revoked",
    });

    let mut plan = PersonaAbandonPlan {
        target_kind: "persona",
        target_id: persona_id.to_string(),
        requested_action: "abandon",
        prior_state_digest,
        proposed_action,
        operator_confirmation_token: String::new(),
        operator_confirmation_token_hash: String::new(),
    };
    let token = confirmation_token(&plan);
    plan.operator_confirmation_token_hash = super::vault::digest_str(&token);
    plan.operator_confirmation_token = token;
    Ok(plan)
}

fn confirmation_token(plan: &PersonaAbandonPlan) -> String {
    let material = json!({
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "proposed_action": plan.proposed_action,
    });
    let digest = super::vault::digest_value(&material);
    format!(
        "persona-abandon-{}",
        digest
            .strip_prefix("blake3:")
            .unwrap_or(&digest)
            .chars()
            .take(16)
            .collect::<String>()
    )
}

fn emit_recovery_receipt(
    socket_path: &Path,
    plan: &PersonaAbandonPlan,
    dry_run_digest: &str,
    outcome: &str,
    reason: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-persona-{}",
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
        "verb": "persona",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": plan.operator_confirmation_token_hash,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": if outcome == "executed" {
                "recover_persona_abandon"
            } else {
                "recovery_action_receipt"
            },
            "confirmation_token_hash": plan.operator_confirmation_token_hash,
        },
        "outcome": outcome,
        "abandon_reason": reason,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#persona-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 206", "ADR 211"],
    });

    let method = if outcome == "executed" {
        "recover_persona_abandon"
    } else {
        "recovery_action_receipt"
    };
    let value = crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover persona abandon refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
        ))
    })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover persona abandon refused: daemon returned no recovery.action receipt_id",
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

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover persona abandon refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

fn render_plan(plan: &PersonaAbandonPlan, receipt: &ReceiptSummary) -> String {
    let mut out = String::new();
    out.push_str("recover persona abandon (dry-run / no state modified)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Persona: ");
    out.push_str(&plan.target_id);
    out.push('\n');
    out.push_str("Prior state digest: ");
    out.push_str(&plan.prior_state_digest);
    out.push('\n');
    out.push_str("Confirmation token: ");
    out.push_str(&plan.operator_confirmation_token);
    out.push_str("\n\nPlan:\n");
    out.push_str(
        &serde_json::to_string_pretty(&plan.proposed_action).unwrap_or_else(|_| "{}".to_string()),
    );
    out.push_str("\n\nNext step:\n  Re-run with `--execute --confirm ");
    out.push_str(&plan.operator_confirmation_token);
    out.push_str("` after reviewing the provenance.\n");
    out.trim_end().to_string()
}

fn render_executed(plan: &PersonaAbandonPlan, receipt: &ReceiptSummary) -> String {
    format!(
        "recover persona abandon: executed\nPersona: {}\nReceipt: recovery.action {} (persisted={})",
        plan.target_id, receipt.receipt_id, receipt.persisted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_plan_refuses_terminal_persona() {
        let plan = build_restore_plan(&json!({
            "kind": "persona_restore_status",
            "persona_id": "persona-test",
            "status": "revoked",
            "diagnostic_code": "persona_terminal",
            "can_restore": false,
            "restore_eligibility_proven": false,
            "durable_persona_terminal": true,
            "durable_persona_active": false,
            "successor_enrollment_required": true,
            "diagnostics": ["durable persona is terminal"],
        }))
        .expect("terminal persona builds a refusal plan");

        assert_eq!(plan.target_id, "persona-test");
        assert_eq!(plan.requested_action, "restore");
        assert_eq!(plan.diagnostic_code, "persona_terminal");
        assert_eq!(
            plan.proposed_action["decision"],
            json!("refuse-policy-bypass")
        );
        assert_eq!(plan.proposed_action["can_restore"], json!(false));
    }

    #[test]
    fn restore_plan_reports_active_pending_mutation_rpc() {
        let plan = build_restore_plan(&json!({
            "kind": "persona_restore_status",
            "persona_id": "persona-test",
            "status": "active",
            "diagnostic_code": "eligible_pending_mutation_rpc",
            "can_restore": false,
            "restore_eligibility_proven": false,
            "durable_persona_terminal": false,
            "durable_persona_active": true,
            "successor_enrollment_required": false,
            "diagnostics": ["durable persona is active"],
        }))
        .expect("active persona builds a pending plan");

        assert_eq!(plan.diagnostic_code, "eligible_pending_mutation_rpc");
        assert_eq!(
            plan.proposed_action["decision"],
            json!("requires-dedicated-mutation-rpc")
        );
        // Even for an active persona the read-only probe never proves authority.
        assert_eq!(plan.proposed_action["can_restore"], json!(false));
        assert_eq!(
            plan.proposed_action["restore_eligibility_proven"],
            json!(false)
        );
    }

    #[test]
    fn restore_receipt_params_carry_probe_evidence() {
        let plan = build_restore_plan(&json!({
            "kind": "persona_restore_status",
            "persona_id": "persona-test",
            "status": "active",
            "diagnostic_code": "eligible_pending_mutation_rpc",
            "can_restore": false,
            "restore_eligibility_proven": false,
            "durable_persona_terminal": false,
            "durable_persona_active": true,
            "successor_enrollment_required": false,
            "diagnostics": ["durable persona is active"],
        }))
        .expect("active persona builds a pending plan");

        let params = restore_receipt_params(&plan, "blake3:2222222222222222", "planned");

        assert_eq!(params["verb"], json!("persona"));
        assert_eq!(params["requested_action"], json!("restore"));
        assert_eq!(params["outcome"], json!("planned"));
        assert_eq!(
            params["authority_evidence"]["probe_rpc"],
            json!("recover_persona_restore_status")
        );
        assert_eq!(
            params["authority_evidence"]["diagnostic_code"],
            json!("eligible_pending_mutation_rpc")
        );
        assert_eq!(params["authority_evidence"]["can_restore"], json!(false));
        assert_eq!(
            params["authority_evidence"]["restore_eligibility_proven"],
            json!(false)
        );
        assert_eq!(
            params["authority_evidence"]["successor_enrollment_required"],
            json!(false)
        );
    }

    #[test]
    fn restore_plan_rejects_wrong_kind() {
        let err = build_restore_plan(&json!({
            "kind": "grant_rebuild_chain_status",
            "persona_id": "persona-test",
        }))
        .expect_err("wrong daemon status kind must refuse");

        assert!(
            err.to_string()
                .contains("did not return a persona restore status")
        );
    }

    #[test]
    fn abandon_plan_mints_state_bound_token() {
        let plan = build_abandon_plan(
            &json!({
                "id": "persona-test",
                "name": "runtime-test",
                "status": "active",
            }),
            "operator declared runtime identity unrecoverable",
        )
        .expect("plan");

        assert_eq!(plan.target_id, "persona-test");
        assert_eq!(plan.requested_action, "abandon");
        assert!(
            plan.operator_confirmation_token
                .starts_with("persona-abandon-")
        );
        assert!(!plan.operator_confirmation_token_hash.is_empty());
        assert_eq!(plan.proposed_action["new_status"], json!("revoked"));
    }

    #[test]
    fn abandon_plan_refuses_terminal_persona() {
        let err = build_abandon_plan(
            &json!({
                "id": "persona-test",
                "name": "runtime-test",
                "status": "revoked",
            }),
            "missing evidence",
        )
        .expect_err("terminal personas must refuse");

        assert!(err.to_string().contains("already terminal"));
    }

    #[test]
    fn find_persona_rejects_missing_id() {
        let err = find_persona(
            &json!([
                {"id": "persona-other", "name": "other", "status": "active"}
            ]),
            "persona-test",
        )
        .expect_err("missing persona must refuse");

        assert!(err.to_string().contains("not found"));
    }
}
