//! CLASSIFICATION: PUBLIC
//!
//! `ember recover authority` — recover authority surfaces per ADR 161
//! §F-AUTHORITY-* and ADR 195 lifecycle recovery.
//!
//! Scope routing:
//! - `delegation` — rotate delegated authority attached to a live lane (scaffold)
//! - `identity-root` — rotate the device's identity-root keypair (deferred to v0.3.1+)
//! - `keychain` — re-pair the macOS Keychain entries / select presence fallback
//!
//! Per-F-code actions (preferred surface):
//! - `--f-code F-AUTHORITY-1 --grant-id <id>` — extend a workflow grant
//!   approaching/past expiry via the daemon's `extend_grant` RPC. Emits a
//!   `recovery.action` receipt (verb=grant, requested_action=extend).
//!   Anchor: `recover_f_authority_1_landed`.
//! - `--f-code F-AUTHORITY-2 [--fallback pam]` — declare the PAM presence
//!   fallback intent for the next authority-widening window when Touch ID
//!   hardware is unavailable. Emits a `recovery.action` receipt
//!   (verb=authority, requested_action=pam-fallback). The actual factor
//!   selection happens at the per-op presence gate (ADR 200/206); this
//!   recovery action never relaxes the §1 presence chokepoint.
//!   Anchor: `recover_f_authority_2_landed`.
//!
//! F-AUTHORITY-3 (regenerate dev IdentityRoot) and F-AUTHORITY-4 (macOS
//! recovery routing) remain scaffold-only at v0.3.0; deferred to v0.3.1+.

use std::path::Path;

use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    RecoverContext, RecoverError, RecoverOutcome, RecoverResult, note_presence_contract,
    note_receipt_contract,
};

#[derive(Args, Debug)]
pub struct RecoverAuthorityArgs {
    /// Per-F-code recovery routing. When set, runs the structured
    /// F-AUTHORITY-N handler instead of the scaffold print.
    #[arg(long, value_enum, value_name = "F_CODE")]
    pub f_code: Option<AuthorityFCode>,

    /// Grant id targeted by F-AUTHORITY-1 (workflow grant extend).
    #[arg(long, value_name = "GRANT_ID")]
    pub grant_id: Option<String>,

    /// Additional TTL (seconds) to add to the grant for F-AUTHORITY-1. Defaults
    /// to 14400 (4h) per ADR 158 §Component 4 recovery posture.
    #[arg(long, value_name = "SECS")]
    pub add_ttl_secs: Option<u64>,

    /// Additional token budget to add to the grant for F-AUTHORITY-1.
    #[arg(long, value_name = "N")]
    pub add_tokens: Option<u64>,

    /// Additional cents budget to add to the grant for F-AUTHORITY-1.
    #[arg(long, value_name = "N")]
    pub add_cents: Option<u64>,

    /// Narrow the recovery to a single sub-component (legacy scope routing).
    /// Prefer `--f-code` for new flows.
    #[arg(long, value_enum)]
    pub scope: Option<AuthorityScope>,

    /// Fallback authentication factor when Touch ID is unavailable.
    /// At v0.3.0 only `pam` is recognized; per ADR 161 §F-AUTHORITY-2.
    #[arg(long, value_enum)]
    pub fallback: Option<AuthorityFallback>,

    /// Human-readable reason for declaring the presence fallback (F-AUTHORITY-2).
    /// Required when `--f-code F-AUTHORITY-2` is set.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuthorityScope {
    /// Rotate delegated authority attached to a live lane.
    Delegation,
    /// Rotate the device's identity-root keypair.
    IdentityRoot,
    /// Re-pair the macOS Keychain entries.
    Keychain,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuthorityFallback {
    /// Fall back to PAM (sudo-style password prompt).
    Pam,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthorityFCode {
    /// F-AUTHORITY-1 — workflow grant expired during a long-running agent call.
    #[value(name = "F-AUTHORITY-1", alias = "f-authority-1")]
    FAuthority1,
    /// F-AUTHORITY-2 — Touch ID hardware failed; declare PAM presence fallback.
    #[value(name = "F-AUTHORITY-2", alias = "f-authority-2")]
    FAuthority2,
}

impl AuthorityFCode {
    /// Human-readable label for diagnostics and tests.
    #[allow(dead_code)]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::FAuthority1 => "F-AUTHORITY-1",
            Self::FAuthority2 => "F-AUTHORITY-2",
        }
    }
}

impl AuthorityScope {
    fn as_str(self) -> &'static str {
        match self {
            AuthorityScope::Delegation => "delegated-authority",
            AuthorityScope::IdentityRoot => "identity-root",
            AuthorityScope::Keychain => "keychain",
        }
    }
}

const DEFAULT_EXTEND_TTL_SECS: u64 = 4 * 60 * 60;
const DEFAULT_PAM_FALLBACK_TTL_SECS: u64 = 24 * 60 * 60;

pub fn handle(args: RecoverAuthorityArgs, context: RecoverContext) -> RecoverResult {
    if let Some(f_code) = args.f_code {
        let socket_path = context.socket_path.clone().ok_or_else(|| {
            RecoverError::authority(
                "recover authority requires the managed daemon socket path; step: broker-unavailable",
            )
        })?;
        return match f_code {
            AuthorityFCode::FAuthority1 => handle_f_authority_1(&args, &socket_path),
            AuthorityFCode::FAuthority2 => handle_f_authority_2(&args, &socket_path),
        };
    }
    legacy_scaffold(args)
}

/// Legacy `--scope` / `--fallback` scaffold path. Preserved so existing
/// muscle memory from the scaffold still prints actionable guidance.
fn legacy_scaffold(args: RecoverAuthorityArgs) -> RecoverResult {
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "delegated-authority".to_string());

    println!(
        "ember recover authority (scope={scope}): scaffold only — pass --f-code F-AUTHORITY-1 \
         (workflow grant extend) or --f-code F-AUTHORITY-2 (PAM fallback) for a structured \
         per-F-code recovery action. See `ember recover --explain F-AUTHORITY-1` (or 2) for \
         the F-code runbook."
    );
    note_presence_contract("authority", &scope);
    note_receipt_contract("authority", &scope);
    if let Some(fallback) = args.fallback {
        eprintln!(
            "  [scaffold] requested fallback: {fallback:?} — re-run with `--f-code F-AUTHORITY-2 \
             --fallback pam --reason <text>` to emit a recovery.action receipt"
        );
    }
    Ok(RecoverOutcome::ok())
}

// ----- F-AUTHORITY-1 — workflow grant extend -----
//
// recover_f_authority_1_landed: surfaces an operator workflow grant
// approaching/past expiry, calls the daemon's `extend_grant` RPC, and emits
// a recovery.action receipt (verb=grant, requested_action=extend).

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GrantExtendPlan {
    target_kind: &'static str,
    target_id: String,
    requested_action: &'static str,
    add_tokens: Option<u64>,
    add_cents: Option<u64>,
    add_ttl_secs: u64,
    prior_state_digest: String,
    proposed_action: Value,
}

fn handle_f_authority_1(args: &RecoverAuthorityArgs, socket_path: &Path) -> RecoverResult {
    let grant_id = args
        .grant_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RecoverError::usage("recover authority --f-code F-AUTHORITY-1 requires --grant-id <id>")
        })?
        .to_string();

    let add_ttl_secs = args.add_ttl_secs.unwrap_or(DEFAULT_EXTEND_TTL_SECS);

    let status = call_daemon(
        socket_path,
        "grant_status",
        json!({ "id": grant_id }),
        "grant status",
        "F-AUTHORITY-1",
    )?;
    let plan = build_grant_extend_plan(&status, args.add_tokens, args.add_cents, add_ttl_secs)?;
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));

    let extend_response = call_daemon(
        socket_path,
        "extend_grant",
        json!({
            "grant_id": grant_id,
            "add_tokens": plan.add_tokens,
            "add_cents": plan.add_cents,
            "add_ttl_secs": plan.add_ttl_secs,
        }),
        "extend_grant",
        "F-AUTHORITY-1",
    )?;

    let new_expires_at = extend_response
        .get("expires_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    let prior_expires_at = status
        .get("expires_at")
        .and_then(Value::as_str)
        .map(str::to_string);

    let receipt = emit_f_authority_1_receipt(
        socket_path,
        &plan,
        &plan_digest,
        "planned",
        prior_expires_at.as_deref(),
        new_expires_at.as_deref(),
    )?;
    println!(
        "{}",
        render_f_authority_1(&plan, &receipt, new_expires_at.as_deref())
    );
    Ok(RecoverOutcome::ok())
}

fn build_grant_extend_plan(
    status: &Value,
    add_tokens: Option<u64>,
    add_cents: Option<u64>,
    add_ttl_secs: u64,
) -> Result<GrantExtendPlan, RecoverError> {
    let kind = status
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != "grant" {
        return Err(RecoverError::authority(
            "recover authority F-AUTHORITY-1 refused: daemon did not return a grant status",
        ));
    }
    let grant_id = status
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            RecoverError::authority("recover authority F-AUTHORITY-1 refused: grant id missing")
        })?;
    let current_status = status
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(
        current_status,
        "revoked"
            | "abandoned"
            | "exhausted_by_budget"
            | "expired_by_budget"
            | "parent_cascade_revoked"
    ) {
        return Err(RecoverError::authority(format!(
            "recover authority F-AUTHORITY-1 refused: grant {grant_id} is terminal ({current_status}); extend cannot revive a terminal grant"
        )));
    }

    let prior_state = json!({
        "grant_id": grant_id,
        "status": current_status,
        "expires_at": status.get("expires_at").cloned().unwrap_or(Value::Null),
        "persona_id": status.get("persona_id").cloned().unwrap_or(Value::Null),
        "credential_name": status.get("credential_name").cloned().unwrap_or(Value::Null),
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": "extend_grant",
        "verb": "grant",
        "requested_action": "extend",
        "grant_id": grant_id,
        "add_tokens": add_tokens,
        "add_cents": add_cents,
        "add_ttl_secs": add_ttl_secs,
    });
    Ok(GrantExtendPlan {
        target_kind: "grant",
        target_id: grant_id.to_string(),
        requested_action: "extend",
        add_tokens,
        add_cents,
        add_ttl_secs,
        prior_state_digest,
        proposed_action,
    })
}

fn emit_f_authority_1_receipt(
    socket_path: &Path,
    plan: &GrantExtendPlan,
    dry_run_digest: &str,
    outcome: &str,
    prior_expires_at: Option<&str>,
    new_expires_at: Option<&str>,
) -> Result<ReceiptSummary, RecoverError> {
    let params = f_authority_1_receipt_params(
        plan,
        dry_run_digest,
        outcome,
        prior_expires_at,
        new_expires_at,
    );
    let value = crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params)
        .map_err(|err| {
            RecoverError::authority(format!(
                "recover authority F-AUTHORITY-1 refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover authority F-AUTHORITY-1 refused: daemon returned no recovery.action receipt_id",
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

fn f_authority_1_receipt_params(
    plan: &GrantExtendPlan,
    dry_run_digest: &str,
    outcome: &str,
    prior_expires_at: Option<&str>,
    new_expires_at: Option<&str>,
) -> Value {
    let recovery_id = format!(
        "recover-authority-f1-{}",
        dry_run_digest
            .strip_prefix("blake3:")
            .unwrap_or(dry_run_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    let mut evidence = serde_json::Map::new();
    evidence.insert("extend_add_ttl_secs".to_string(), json!(plan.add_ttl_secs));
    if let Some(t) = plan.add_tokens {
        evidence.insert("extend_add_tokens".to_string(), json!(t));
    }
    if let Some(c) = plan.add_cents {
        evidence.insert("extend_add_cents".to_string(), json!(c));
    }
    if let Some(prior) = prior_expires_at {
        evidence.insert("extend_prior_expires_at".to_string(), json!(prior));
    }
    if let Some(new) = new_expires_at {
        evidence.insert("extend_new_expires_at".to_string(), json!(new));
    }
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
        "authority_evidence": Value::Object(evidence),
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#f-authority-1--delegated-authority-expired-during-long-running-agent-call",
        "adr_refs": ["ADR 158", "ADR 161", "ADR 195", "ADR 200", "ADR 206"],
    })
}

fn render_f_authority_1(
    plan: &GrantExtendPlan,
    receipt: &ReceiptSummary,
    new_expires_at: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("recover authority F-AUTHORITY-1 (workflow grant extended)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Grant: ");
    out.push_str(&plan.target_id);
    out.push('\n');
    out.push_str("Added TTL: ");
    out.push_str(&plan.add_ttl_secs.to_string());
    out.push_str("s\n");
    if let Some(t) = plan.add_tokens {
        out.push_str("Added tokens: ");
        out.push_str(&t.to_string());
        out.push('\n');
    }
    if let Some(c) = plan.add_cents {
        out.push_str("Added cents: ");
        out.push_str(&c.to_string());
        out.push('\n');
    }
    if let Some(exp) = new_expires_at {
        out.push_str("New expires_at: ");
        out.push_str(exp);
        out.push('\n');
    }
    out.push_str("\nNext step:\n  Resume the agent — `ember claude --resume <session-id>` or re-issue the prompt.\n");
    out.trim_end().to_string()
}

// ----- F-AUTHORITY-2 — PAM presence fallback -----
//
// recover_f_authority_2_landed: emits a recovery.action receipt declaring
// the operator's intent to fall back to PAM for the next presence-widening
// op. The actual factor selection happens at the per-op presence gate
// (ADR 200/206); this receipt records the intent + reason.

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PresenceFallbackPlan {
    target_kind: &'static str,
    target_id: &'static str,
    requested_action: &'static str,
    presence_factor: &'static str,
    reason: String,
    fallback_ttl_secs: u64,
    prior_state_digest: String,
    proposed_action: Value,
}

fn handle_f_authority_2(args: &RecoverAuthorityArgs, socket_path: &Path) -> RecoverResult {
    let fallback = args.fallback.unwrap_or(AuthorityFallback::Pam);
    let factor = match fallback {
        AuthorityFallback::Pam => "pam",
    };
    let reason = args
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RecoverError::usage(
                "recover authority --f-code F-AUTHORITY-2 requires --reason <text> describing why Touch ID is unavailable",
            )
        })?
        .to_string();
    let fallback_ttl_secs = DEFAULT_PAM_FALLBACK_TTL_SECS;

    let plan = build_presence_fallback_plan(factor, &reason, fallback_ttl_secs);
    let plan_digest =
        super::vault::digest_value(&serde_json::to_value(&plan).unwrap_or(Value::Null));

    let receipt = emit_f_authority_2_receipt(socket_path, &plan, &plan_digest, "planned")?;
    println!("{}", render_f_authority_2(&plan, &receipt));
    Ok(RecoverOutcome::ok())
}

fn build_presence_fallback_plan(
    factor: &'static str,
    reason: &str,
    fallback_ttl_secs: u64,
) -> PresenceFallbackPlan {
    let prior_state = json!({
        "presence_floor": "touch-id-or-presence-device",
        "operator_declared_unavailable_at_utc": chrono::Utc::now().to_rfc3339(),
    });
    let prior_state_digest = super::vault::digest_value(&prior_state);
    let proposed_action = json!({
        "daemon_rpc": Value::Null,
        "verb": "authority",
        "requested_action": "pam-fallback",
        "presence_factor": factor,
        "fallback_ttl_secs": fallback_ttl_secs,
        "floor": "the recovery action records intent only; the per-op presence gate (ADR 200/206) still selects the actual factor at widening time and refuses if no factor is available",
    });
    PresenceFallbackPlan {
        target_kind: "presence-fallback",
        target_id: "presence-fallback",
        requested_action: "pam-fallback",
        presence_factor: factor,
        reason: reason.to_string(),
        fallback_ttl_secs,
        prior_state_digest,
        proposed_action,
    }
}

fn emit_f_authority_2_receipt(
    socket_path: &Path,
    plan: &PresenceFallbackPlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let params = f_authority_2_receipt_params(plan, dry_run_digest, outcome);
    let value = crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params)
        .map_err(|err| {
            RecoverError::authority(format!(
                "recover authority F-AUTHORITY-2 refused: could not emit recovery.action receipt through the daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover authority F-AUTHORITY-2 refused: daemon returned no recovery.action receipt_id",
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

fn f_authority_2_receipt_params(
    plan: &PresenceFallbackPlan,
    dry_run_digest: &str,
    outcome: &str,
) -> Value {
    let recovery_id = format!(
        "recover-authority-f2-{}",
        dry_run_digest
            .strip_prefix("blake3:")
            .unwrap_or(dry_run_digest)
            .chars()
            .take(16)
            .collect::<String>()
    );
    let mut evidence = serde_json::Map::new();
    evidence.insert("presence_factor".to_string(), json!(plan.presence_factor));
    evidence.insert(
        "presence_fallback_reason".to_string(),
        json!(plan.reason.clone()),
    );
    evidence.insert(
        "presence_fallback_ttl_secs".to_string(),
        json!(plan.fallback_ttl_secs),
    );
    evidence.insert(
        "evidence_floor".to_string(),
        json!(
            "the recovery action records intent only; the per-op presence gate (ADR 200/206) still selects the actual factor at widening time"
        ),
    );
    json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "authority",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": dry_run_digest,
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": Value::Object(evidence),
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#f-authority-2--touch-id-hardware-failed-sensor-dead-finger-unrecognizable",
        "adr_refs": ["ADR 136", "ADR 161", "ADR 195", "ADR 200", "ADR 206"],
    })
}

fn render_f_authority_2(plan: &PresenceFallbackPlan, receipt: &ReceiptSummary) -> String {
    let mut out = String::new();
    out.push_str("recover authority F-AUTHORITY-2 (PAM presence fallback declared)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    out.push_str(" (persisted=");
    out.push_str(if receipt.persisted { "true" } else { "false" });
    out.push_str(")\n\n");
    out.push_str("Fallback factor: ");
    out.push_str(plan.presence_factor);
    out.push('\n');
    out.push_str("Fallback window: ");
    out.push_str(&plan.fallback_ttl_secs.to_string());
    out.push_str("s\n");
    out.push_str("Reason: ");
    out.push_str(&plan.reason);
    out.push_str("\n\nNext step:\n  The next authority-widening op will prompt for the PAM factor; the per-op presence gate refuses if neither Touch ID nor PAM is available.\n");
    out.push_str("  Schedule Mac hardware service to restore Touch ID; per ADR 161 the PAM fallback is the cohort-A dev0 workaround until then.\n");
    out.trim_end().to_string()
}

// ----- shared helpers -----

#[derive(Debug, Clone)]
struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &str,
    f_code: &str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover authority {f_code} refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_extend_plan_carries_inputs() {
        let plan = build_grant_extend_plan(
            &json!({
                "kind": "grant",
                "id": "grant-test",
                "status": "active",
                "persona_id": "persona-test",
                "credential_name": "api-key",
                "expires_at": "2026-06-12T00:00:00Z",
            }),
            Some(100),
            None,
            7200,
        )
        .expect("plan");

        assert_eq!(plan.target_id, "grant-test");
        assert_eq!(plan.requested_action, "extend");
        assert_eq!(plan.add_ttl_secs, 7200);
        assert_eq!(plan.add_tokens, Some(100));
        assert_eq!(plan.add_cents, None);
        assert_eq!(plan.proposed_action["daemon_rpc"], json!("extend_grant"));
    }

    #[test]
    fn grant_extend_plan_refuses_terminal_grant() {
        let err = build_grant_extend_plan(
            &json!({
                "kind": "grant",
                "id": "grant-test",
                "status": "revoked",
            }),
            None,
            None,
            DEFAULT_EXTEND_TTL_SECS,
        )
        .expect_err("terminal grants must refuse");

        let msg = err.to_string();
        assert!(
            msg.contains("terminal"),
            "error should name terminal status; got {msg}"
        );
    }

    #[test]
    fn grant_extend_plan_refuses_non_grant_status() {
        let err = build_grant_extend_plan(
            &json!({
                "kind": "persona",
                "id": "persona-test",
            }),
            None,
            None,
            DEFAULT_EXTEND_TTL_SECS,
        )
        .expect_err("non-grant status must refuse");

        assert!(err.to_string().contains("grant status"));
    }

    #[test]
    fn f_authority_1_receipt_params_carry_extend_evidence() {
        let plan = build_grant_extend_plan(
            &json!({
                "kind": "grant",
                "id": "grant-test",
                "status": "active",
                "expires_at": "2026-06-12T00:00:00Z",
            }),
            None,
            None,
            14400,
        )
        .expect("plan");

        let params = f_authority_1_receipt_params(
            &plan,
            "blake3:1111111111111111",
            "planned",
            Some("2026-06-12T00:00:00Z"),
            Some("2026-06-12T04:00:00Z"),
        );

        assert_eq!(params["verb"], json!("grant"));
        assert_eq!(params["requested_action"], json!("extend"));
        assert_eq!(params["target_kind"], json!("grant"));
        assert_eq!(params["outcome"], json!("planned"));
        assert_eq!(
            params["authority_evidence"]["extend_add_ttl_secs"],
            json!(14400)
        );
        assert_eq!(
            params["authority_evidence"]["extend_prior_expires_at"],
            json!("2026-06-12T00:00:00Z")
        );
        assert_eq!(
            params["authority_evidence"]["extend_new_expires_at"],
            json!("2026-06-12T04:00:00Z")
        );
    }

    #[test]
    fn presence_fallback_plan_records_intent() {
        let plan = build_presence_fallback_plan("pam", "Touch ID sensor not responding", 86400);

        assert_eq!(plan.target_kind, "presence-fallback");
        assert_eq!(plan.requested_action, "pam-fallback");
        assert_eq!(plan.presence_factor, "pam");
        assert_eq!(plan.fallback_ttl_secs, 86400);
        assert!(
            plan.proposed_action["floor"]
                .as_str()
                .is_some_and(|s| s.contains("per-op presence gate"))
        );
    }

    #[test]
    fn f_authority_2_receipt_params_carry_presence_evidence() {
        let plan = build_presence_fallback_plan("pam", "Touch ID sensor not responding", 86400);
        let params = f_authority_2_receipt_params(&plan, "blake3:2222222222222222", "planned");

        assert_eq!(params["verb"], json!("authority"));
        assert_eq!(params["target_kind"], json!("presence-fallback"));
        assert_eq!(params["requested_action"], json!("pam-fallback"));
        assert_eq!(params["outcome"], json!("planned"));
        assert_eq!(
            params["authority_evidence"]["presence_factor"],
            json!("pam")
        );
        assert_eq!(
            params["authority_evidence"]["presence_fallback_reason"],
            json!("Touch ID sensor not responding")
        );
        assert_eq!(
            params["authority_evidence"]["presence_fallback_ttl_secs"],
            json!(86400)
        );
    }

    #[test]
    fn f_code_label_matches() {
        assert_eq!(AuthorityFCode::FAuthority1.label(), "F-AUTHORITY-1");
        assert_eq!(AuthorityFCode::FAuthority2.label(), "F-AUTHORITY-2");
    }
}
