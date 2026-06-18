//! `ember recover grant` lifecycle recovery per ADR 195.
//!
//! This slice wires explicit grant abandonment and a fail-closed
//! `rebuild-chain` diagnostic. The CLI never opens the daemon-owned grant
//! store directly: it asks the daemon for the current grant projection or
//! recovery probe, emits a `recovery.action` receipt, and executes mutations
//! only through dedicated operator-presence recovery RPCs after the operator
//! retypes a state-bound confirmation token.

use std::path::Path;

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

#[derive(Args, Debug, Clone)]
pub struct RecoverGrantArgs {
    #[command(subcommand)]
    pub action: RecoverGrantAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RecoverGrantAction {
    /// Inspect whether a grant chain can be rebuilt from signed evidence.
    #[command(name = "rebuild-chain")]
    RebuildChain(RebuildGrantChainArgs),

    /// Mark a grant abandoned with provenance; does not rebuild the chain.
    Abandon(AbandonGrantArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RebuildGrantChainArgs {
    /// Grant id whose materialized chain should be inspected.
    #[arg(value_name = "GRANT_ID")]
    pub grant_id: String,

    /// Execute the rebuild when a future daemon mutation RPC can prove a clean rebuild.
    #[arg(long)]
    pub execute: bool,

    /// Retyped confirmation token from a future executable dry-run plan.
    #[arg(long, value_name = "TOKEN")]
    pub confirm: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct AbandonGrantArgs {
    /// Grant id to mark abandoned.
    #[arg(value_name = "GRANT_ID")]
    pub grant_id: String,

    /// Human-readable provenance explaining why the chain is abandoned.
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
struct GrantAbandonPlan {
    target_kind: &'static str,
    target_id: String,
    requested_action: &'static str,
    prior_state_digest: String,
    proposed_action: Value,
    operator_confirmation_token: String,
    operator_confirmation_token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GrantRebuildChainPlan {
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

pub fn handle(args: RecoverGrantArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover grant requires the managed daemon socket path; step: broker-unavailable",
        )
    })?;

    match args.action {
        RecoverGrantAction::RebuildChain(args) => handle_rebuild_chain(args, &socket_path),
        RecoverGrantAction::Abandon(args) => handle_abandon(args, &socket_path),
    }
}

fn handle_rebuild_chain(args: RebuildGrantChainArgs, socket_path: &Path) -> RecoverResult {
    let grant_id = args.grant_id.trim().to_string();
    let probe = call_daemon_rebuild(
        socket_path,
        "recover_grant_rebuild_chain_status",
        json!({ "id": grant_id }),
        "grant rebuild-chain status",
    )?;
    let plan = build_rebuild_chain_plan(&probe)?;
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));
    let receipt_outcome = if plan.diagnostic_code == "chain_intact" {
        "planned"
    } else {
        "refused"
    };
    let receipt = emit_rebuild_chain_receipt(socket_path, &plan, &plan_digest, receipt_outcome)?;
    println!("{}", render_rebuild_chain_plan(&plan, &receipt));

    if args.execute {
        return Err(RecoverError::authority(
            "recover grant rebuild-chain refused: no daemon mutation RPC can rebuild from signed grant-origin/history evidence yet; no mutation attempted",
        ));
    }

    if plan.diagnostic_code == "chain_intact" {
        Ok(RecoverOutcome::ok())
    } else {
        Ok(RecoverOutcome::issue_found())
    }
}

fn handle_abandon(args: AbandonGrantArgs, socket_path: &Path) -> RecoverResult {
    let grant_id = args.grant_id.trim().to_string();
    let reason = args.reason.trim().to_string();
    if reason.is_empty() {
        return Err(RecoverError::usage(
            "recover grant abandon requires --reason with non-empty provenance",
        ));
    }

    let status = call_daemon(
        socket_path,
        "grant_status",
        json!({ "id": grant_id }),
        "grant status",
    )?;
    let plan = build_abandon_plan(&status, &reason)?;
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));

    if !args.execute {
        let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "planned", &reason)?;
        println!("{}", render_plan(&plan, &receipt));
        return Ok(RecoverOutcome::ok());
    }

    let Some(confirm) = args.confirm.as_deref() else {
        let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "refused", &reason)?;
        println!("{}", render_plan(&plan, &receipt,));
        return Err(RecoverError::authority(format!(
            "recover grant abandon refused: --execute requires --confirm {}; no mutation attempted",
            plan.operator_confirmation_token
        )));
    };

    if confirm != plan.operator_confirmation_token {
        let _ = emit_recovery_receipt(socket_path, &plan, &plan_digest, "refused", &reason);
        return Err(RecoverError::authority(
            "recover grant abandon refused: confirmation token mismatch; no mutation attempted",
        ));
    }

    let receipt = emit_recovery_receipt(socket_path, &plan, &plan_digest, "executed", &reason)?;
    println!("{}", render_executed(&plan, &receipt));
    Ok(RecoverOutcome::ok())
}

fn build_rebuild_chain_plan(status: &Value) -> Result<GrantRebuildChainPlan, RecoverError> {
    let kind = status
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != "grant_rebuild_chain_status" {
        return Err(RecoverError::authority(
            "recover grant rebuild-chain refused: daemon did not return a grant chain recovery status",
        ));
    }
    let grant_id = status
        .get("grant_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            RecoverError::authority("recover grant rebuild-chain refused: grant id missing")
        })?;
    let diagnostic_code = status
        .get("diagnostic_code")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let can_rebuild = status
        .get("can_rebuild")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let signed_origin_journal_available = status
        .get("signed_origin_journal_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let materialized_chain_verifies = status
        .get("materialized_chain_verifies")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let decision = if diagnostic_code == "chain_intact" {
        "no-op"
    } else if can_rebuild {
        "requires-dedicated-mutation-rpc"
    } else {
        "refuse"
    };

    let prior_state = json!({
        "grant_id": grant_id,
        "status": status.get("status").cloned().unwrap_or(Value::Null),
        "persona_id": status.get("persona_id").cloned().unwrap_or(Value::Null),
        "credential_name": status.get("credential_name").cloned().unwrap_or(Value::Null),
        "expires_at": status.get("expires_at").cloned().unwrap_or(Value::Null),
        "blocks_json_present": status.get("blocks_json_present").cloned().unwrap_or(Value::Null),
        "blocks_json_deserializes": status.get("blocks_json_deserializes").cloned().unwrap_or(Value::Null),
        "raw_block_count": status.get("raw_block_count").cloned().unwrap_or(Value::Null),
        "materialized_chain_verifies": materialized_chain_verifies,
        "signed_origin_journal_available": status.get("signed_origin_journal_available").cloned().unwrap_or(Value::Null),
        "can_rebuild": can_rebuild,
        "diagnostic_code": diagnostic_code,
        "diagnostics": status.get("diagnostics").cloned().unwrap_or(Value::Null),
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": Value::Null,
        "verb": "grant",
        "requested_action": "rebuild-chain",
        "grant_id": grant_id,
        "decision": decision,
        "diagnostic_code": diagnostic_code,
        "can_rebuild": can_rebuild,
        "materialized_chain_verifies": materialized_chain_verifies,
        "signed_origin_journal_available": signed_origin_journal_available,
        "audit_chain_route": status.get("audit_chain_route").cloned().unwrap_or_else(|| {
            json!("ember recover audit-chain --dry-run")
        }),
        "floor": "rebuild-chain refuses unless the daemon can prove signed grant-origin/history evidence; scalar grant rows are not rebuild evidence",
    });

    Ok(GrantRebuildChainPlan {
        target_kind: "grant",
        target_id: grant_id.to_string(),
        requested_action: "rebuild-chain",
        prior_state_digest,
        diagnostic_code,
        proposed_action,
    })
}

fn build_abandon_plan(status: &Value, reason: &str) -> Result<GrantAbandonPlan, RecoverError> {
    let kind = status
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != "grant" {
        return Err(RecoverError::authority(
            "recover grant abandon refused: daemon did not return a grant status",
        ));
    }
    let grant_id = status
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            RecoverError::authority("recover grant abandon refused: grant id missing")
        })?;
    let current_status = status
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(
        current_status,
        "revoked"
            | "abandoned"
            | "expired"
            | "exhausted_by_budget"
            | "expired_by_budget"
            | "parent_cascade_revoked"
    ) {
        return Err(RecoverError::authority(format!(
            "recover grant abandon refused: grant {grant_id} is already terminal ({current_status})"
        )));
    }

    let prior_state = json!({
        "grant_id": grant_id,
        "status": current_status,
        "persona_id": status.get("persona_id").cloned().unwrap_or(Value::Null),
        "credential_name": status.get("credential_name").cloned().unwrap_or(Value::Null),
        "expires_at": status.get("expires_at").cloned().unwrap_or(Value::Null),
        "statement_count": status.get("statement_count").cloned().unwrap_or(Value::Null),
        "revoked_sids": status.get("revoked_sids").cloned().unwrap_or(Value::Null),
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": "recover_grant_abandon",
        "verb": "grant",
        "requested_action": "abandon",
        "grant_id": grant_id,
        "reason": reason,
        "new_status": "abandoned",
    });

    let mut plan = GrantAbandonPlan {
        target_kind: "grant",
        target_id: grant_id.to_string(),
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

fn confirmation_token(plan: &GrantAbandonPlan) -> String {
    let material = json!({
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "proposed_action": plan.proposed_action,
    });
    let digest = super::vault::digest_value(&material);
    format!(
        "grant-abandon-{}",
        digest
            .strip_prefix("blake3:")
            .unwrap_or(&digest)
            .chars()
            .take(16)
            .collect::<String>()
    )
}

fn emit_rebuild_chain_receipt(
    socket_path: &Path,
    plan: &GrantRebuildChainPlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let params = rebuild_chain_receipt_params(plan, dry_run_digest, outcome);

    let value = crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(
        |err| {
            RecoverError::authority(format!(
                "recover grant rebuild-chain refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        },
    )?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover grant rebuild-chain refused: daemon returned no recovery.action receipt_id",
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

fn rebuild_chain_receipt_params(
    plan: &GrantRebuildChainPlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Value {
    let recovery_id = format!(
        "recover-grant-rebuild-{}",
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
        "verb": "grant",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "probe_rpc": "recover_grant_rebuild_chain_status",
            "diagnostic_code": plan.diagnostic_code,
            "decision": plan.proposed_action["decision"].clone(),
            "can_rebuild": plan.proposed_action["can_rebuild"].clone(),
            "materialized_chain_verifies": plan.proposed_action["materialized_chain_verifies"].clone(),
            "signed_origin_journal_available": plan.proposed_action["signed_origin_journal_available"].clone(),
            "evidence_floor": plan.proposed_action["floor"].clone(),
        },
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
    })
}

fn emit_recovery_receipt(
    socket_path: &Path,
    plan: &GrantAbandonPlan,
    dry_run_digest: &str,
    outcome: &str,
    reason: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-grant-{}",
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
        "verb": "grant",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": plan.operator_confirmation_token_hash,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": if outcome == "executed" {
                "recover_grant_abandon"
            } else {
                "recovery_action_receipt"
            },
            "confirmation_token_hash": plan.operator_confirmation_token_hash,
        },
        "outcome": outcome,
        "abandon_reason": reason,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#grant-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 205", "ADR 206", "ADR 211"],
    });

    let method = if outcome == "executed" {
        "recover_grant_abandon"
    } else {
        "recovery_action_receipt"
    };
    let value =
        crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
            RecoverError::authority(format!(
                "recover grant abandon refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover grant abandon refused: daemon returned no recovery.action receipt_id",
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

fn call_daemon_rebuild(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover grant rebuild-chain refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
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
            "recover grant abandon refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

fn render_rebuild_chain_plan(plan: &GrantRebuildChainPlan, receipt: &ReceiptSummary) -> String {
    let decision = plan
        .proposed_action
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("refuse");
    let route = plan
        .proposed_action
        .get("audit_chain_route")
        .and_then(Value::as_str)
        .unwrap_or("ember recover audit-chain --dry-run");
    let mut out = String::new();
    out.push_str("recover grant rebuild-chain (dry-run / no state modified)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Grant: ");
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
    if plan.diagnostic_code == "chain_intact" {
        out.push_str("No rebuild action is needed for the current materialized chain.\n");
    } else {
        out.push_str("Do not synthesize grant links from scalar rows. Run `");
        out.push_str(route);
        out.push_str("` or abandon the grant with provenance.\n");
    }
    out.trim_end().to_string()
}

fn render_plan(plan: &GrantAbandonPlan, receipt: &ReceiptSummary) -> String {
    let mut out = String::new();
    out.push_str("recover grant abandon (dry-run / no state modified)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Grant: ");
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

fn render_executed(plan: &GrantAbandonPlan, receipt: &ReceiptSummary) -> String {
    format!(
        "recover grant abandon: executed\nGrant: {}\nReceipt: recovery.action {} (persisted={})",
        plan.target_id, receipt.receipt_id, receipt.persisted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandon_plan_mints_state_bound_token() {
        let plan = build_abandon_plan(
            &json!({
                "kind": "grant",
                "id": "grant-test",
                "status": "active",
                "persona_id": "persona-test",
                "credential_name": "api-key",
                "expires_at": null,
                "statement_count": 1,
                "revoked_sids": [],
            }),
            "missing embed-canonical chain evidence",
        )
        .expect("plan");

        assert_eq!(plan.target_id, "grant-test");
        assert_eq!(plan.requested_action, "abandon");
        assert!(
            plan.operator_confirmation_token
                .starts_with("grant-abandon-")
        );
        assert!(!plan.operator_confirmation_token_hash.is_empty());
        assert_eq!(plan.proposed_action["new_status"], json!("abandoned"));
    }

    #[test]
    fn abandon_plan_refuses_terminal_grant() {
        let err = build_abandon_plan(
            &json!({
                "kind": "grant",
                "id": "grant-test",
                "status": "revoked",
            }),
            "missing evidence",
        )
        .expect_err("terminal grants must refuse");

        assert!(err.to_string().contains("already terminal"));
    }

    #[test]
    fn rebuild_chain_plan_refuses_without_signed_journal_source() {
        let plan = build_rebuild_chain_plan(&json!({
            "kind": "grant_rebuild_chain_status",
            "grant_id": "grant-test",
            "status": "active",
            "persona_id": "persona-test",
            "credential_name": "api-key",
            "expires_at": null,
            "blocks_json_present": true,
            "blocks_json_deserializes": false,
            "raw_block_count": 0,
            "materialized_chain_verifies": false,
            "signed_origin_journal_available": false,
            "can_rebuild": false,
            "diagnostic_code": "signed_origin_journal_unavailable",
            "diagnostics": ["blocks_json_invalid_json"],
            "audit_chain_route": "ember recover audit-chain --dry-run",
        }))
        .expect("plan");

        assert_eq!(plan.target_id, "grant-test");
        assert_eq!(plan.requested_action, "rebuild-chain");
        assert_eq!(plan.proposed_action["decision"], json!("refuse"));
        assert_eq!(
            plan.proposed_action["floor"],
            json!(
                "rebuild-chain refuses unless the daemon can prove signed grant-origin/history evidence; scalar grant rows are not rebuild evidence"
            )
        );
    }

    #[test]
    fn rebuild_chain_receipt_params_carry_probe_evidence() {
        let plan = build_rebuild_chain_plan(&json!({
            "kind": "grant_rebuild_chain_status",
            "grant_id": "grant-test",
            "status": "active",
            "persona_id": "persona-test",
            "credential_name": "api-key",
            "expires_at": null,
            "blocks_json_present": true,
            "blocks_json_deserializes": false,
            "raw_block_count": 0,
            "materialized_chain_verifies": false,
            "signed_origin_journal_available": false,
            "can_rebuild": false,
            "diagnostic_code": "signed_origin_journal_unavailable",
            "diagnostics": ["blocks_json_invalid_json"],
        }))
        .expect("plan");

        let params = rebuild_chain_receipt_params(&plan, "blake3:2222222222222222", "refused");

        assert_eq!(params["verb"], json!("grant"));
        assert_eq!(params["requested_action"], json!("rebuild-chain"));
        assert_eq!(params["outcome"], json!("refused"));
        assert_eq!(
            params["authority_evidence"]["probe_rpc"],
            json!("recover_grant_rebuild_chain_status")
        );
        assert_eq!(
            params["authority_evidence"]["diagnostic_code"],
            json!("signed_origin_journal_unavailable")
        );
        assert_eq!(params["authority_evidence"]["can_rebuild"], json!(false));
        assert_eq!(
            params["authority_evidence"]["materialized_chain_verifies"],
            json!(false)
        );
        assert_eq!(
            params["authority_evidence"]["signed_origin_journal_available"],
            json!(false)
        );
    }
}
