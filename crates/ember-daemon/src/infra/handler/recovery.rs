use super::*;
use rusqlite::OptionalExtension;

fn required_recovery_action_field<'a>(
    params: &'a Value,
    key: &str,
) -> Result<&'a str, (i32, String)> {
    let value = params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| (-32602, format!("recovery_action_receipt: missing '{key}'")))?;
    Ok(value)
}

fn recovery_action_string_array(params: &Value, key: &str) -> Result<Vec<String>, (i32, String)> {
    let Some(value) = params.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err((
            -32602,
            format!("recovery_action_receipt: '{key}' must be an array"),
        ));
    };
    if items.iter().any(|item| item.as_str().is_none()) {
        return Err((
            -32602,
            format!("recovery_action_receipt: '{key}' must contain only strings"),
        ));
    }
    Ok(items
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::to_string)
        .collect())
}

fn optional_recovery_action_string(
    params: &Value,
    key: &str,
) -> Result<Option<String>, (i32, String)> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                -32602,
                format!("recovery_action_receipt: {key} must be null or a non-empty string"),
            )
        })?;
    Ok(Some(value.to_string()))
}

fn require_recovery_action_literal<'a>(
    params: &'a Value,
    key: &str,
    expected: &str,
) -> Result<&'a str, (i32, String)> {
    let actual = required_recovery_action_field(params, key)?;
    if actual != expected {
        return Err((
            -32602,
            format!("recovery_action_receipt: '{key}' must be '{expected}'"),
        ));
    }
    Ok(actual)
}

/// Optional operator fields (`operator_confirmation_token_hash`,
/// `operator_persona_id`) may be absent or explicitly null, but when present
/// must be a non-empty string. Shared by the lifecycle verbs that admit an
/// operator co-sign (audit-chain, vault).
fn ensure_optional_recovery_operator_fields(params: &Value) -> Result<(), (i32, String)> {
    for key in ["operator_confirmation_token_hash", "operator_persona_id"] {
        if let Some(value) = params.get(key)
            && !value.is_null()
            && value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err((
                -32602,
                format!("recovery_action_receipt: {key} must be null or a non-empty string"),
            ));
        }
    }
    Ok(())
}

fn required_recovery_authority_evidence_field<'a>(
    params: &'a Value,
    key: &str,
) -> Result<&'a str, (i32, String)> {
    let evidence = params
        .get("authority_evidence")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            (
                -32602,
                "recovery_action_receipt: authority_evidence must be an object".to_string(),
            )
        })?;
    evidence
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                -32602,
                format!(
                    "recovery_action_receipt: authority_evidence.{key} must be a non-empty string"
                ),
            )
        })
}

fn recovery_action_authority_evidence(
    params: &Value,
    mode: RecoveryActionMode,
    verb: &str,
) -> Result<Value, (i32, String)> {
    let mut evidence = serde_json::Map::new();
    evidence.insert("daemon_rpc".to_string(), json!(mode.daemon_rpc()));
    evidence.insert("authority_class".to_string(), json!(mode.authority_class()));
    evidence.insert(
        "receipt_scope".to_string(),
        json!(format!("recover-{verb}")),
    );

    let Some(extra) = params.get("authority_evidence") else {
        return Ok(Value::Object(evidence));
    };
    if extra.is_null() {
        return Ok(Value::Object(evidence));
    }
    let extra = extra.as_object().ok_or_else(|| {
        (
            -32602,
            "recovery_action_receipt: authority_evidence must be an object or null".to_string(),
        )
    })?;
    for key in [
        "scope",
        "before_state",
        "after_state",
        "log_excerpt_hash",
        "launchctl_label",
        "launchctl_target",
        "plist_path",
        "socket_path",
        "log_path",
    ] {
        copy_recovery_action_string_evidence(&mut evidence, extra, key)?;
    }
    for key in [
        "confirmation_token_hash",
        "probe_rpc",
        "diagnostic_code",
        "decision",
        "can_rebuild",
        "materialized_chain_verifies",
        "signed_origin_journal_available",
        "can_restore",
        "restore_eligibility_proven",
        "successor_enrollment_required",
        "evidence_floor",
        "launchctl_bootstrap_performed",
        // F-AUTHORITY-1 grant-extend evidence.
        "extend_add_tokens",
        "extend_add_cents",
        "extend_add_ttl_secs",
        "extend_prior_expires_at",
        "extend_new_expires_at",
        // F-AUTHORITY-2 presence-fallback evidence.
        "presence_factor",
        "presence_fallback_reason",
        "presence_fallback_ttl_secs",
    ] {
        copy_recovery_action_scalar_evidence(&mut evidence, extra, key)?;
    }
    Ok(Value::Object(evidence))
}

fn copy_recovery_action_string_evidence(
    evidence: &mut serde_json::Map<String, Value>,
    extra: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), (i32, String)> {
    let Some(value) = extra.get(key) else {
        return Ok(());
    };
    let value = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                -32602,
                format!(
                    "recovery_action_receipt: authority_evidence.{key} must be a non-empty string"
                ),
            )
        })?;
    evidence.insert(key.to_string(), json!(value));
    Ok(())
}

fn copy_recovery_action_scalar_evidence(
    evidence: &mut serde_json::Map<String, Value>,
    extra: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), (i32, String)> {
    let Some(value) = extra.get(key) else {
        return Ok(());
    };
    match value {
        Value::String(text) if !text.trim().is_empty() => {
            evidence.insert(key.to_string(), json!(text.trim()));
            Ok(())
        }
        Value::Bool(_) | Value::Number(_) => {
            evidence.insert(key.to_string(), value.clone());
            Ok(())
        }
        _ => Err((
            -32602,
            format!(
                "recovery_action_receipt: authority_evidence.{key} must be a non-empty string, boolean, or number"
            ),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryActionMode {
    ReceiptOnly,
    GrantAbandonExecute,
    PersonaAbandonExecute,
}

impl RecoveryActionMode {
    fn daemon_rpc(self) -> &'static str {
        match self {
            Self::ReceiptOnly => "recovery_action_receipt",
            Self::GrantAbandonExecute => "recover_grant_abandon",
            Self::PersonaAbandonExecute => "recover_persona_abandon",
        }
    }

    fn authority_class(self) -> &'static str {
        match self {
            Self::ReceiptOnly => "ConnectOnly",
            Self::GrantAbandonExecute | Self::PersonaAbandonExecute => "OperatorPresence",
        }
    }
}

pub(super) fn emit_recovery_action_receipt(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    emit_recovery_action_receipt_with_mode(store, params, RecoveryActionMode::ReceiptOnly)
}

pub(super) fn execute_recover_grant_abandon(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    emit_recovery_action_receipt_with_mode(store, params, RecoveryActionMode::GrantAbandonExecute)
}

pub(super) fn execute_recover_persona_abandon(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    emit_recovery_action_receipt_with_mode(store, params, RecoveryActionMode::PersonaAbandonExecute)
}

pub(super) fn recover_grant_rebuild_chain_status(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let grant_id = required_recovery_action_field(params, "id")?;
    let info = store.get_grant(grant_id).map_err(|e| {
        (
            -32030,
            format!("recover_grant_rebuild_chain_status: load grant {grant_id}: {e}"),
        )
    })?;

    let raw_blocks: Option<String> = store
        .conn()
        .query_row(
            "SELECT blocks_json FROM grants WHERE id = ?1",
            rusqlite::params![grant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            (
                -32030,
                format!("recover_grant_rebuild_chain_status: read blocks_json: {e}"),
            )
        })?
        .flatten();
    let blocks_json_present = raw_blocks
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());

    let mut diagnostics = Vec::new();
    let mut blocks_json_deserializes = false;
    let mut raw_block_count = 0usize;
    let mut materialized_chain_verifies = false;

    if let Some(raw) = raw_blocks
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        match serde_json::from_str::<Vec<core_grant_types::SignedBlock>>(raw) {
            Ok(blocks) => {
                blocks_json_deserializes = true;
                raw_block_count = blocks.len();
                if blocks.is_empty() {
                    diagnostics.push("blocks_json_empty".to_string());
                } else if blocks[0].block.issued_by != info.persona_id {
                    diagnostics.push(format!(
                        "block0_issued_by_mismatch:{}",
                        blocks[0].block.issued_by
                    ));
                } else {
                    let public_key: Option<String> = store
                        .conn()
                        .query_row(
                            "SELECT public_key FROM personas WHERE id = ?1",
                            rusqlite::params![info.persona_id.as_str()],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|e| {
                            (
                                -32030,
                                format!(
                                    "recover_grant_rebuild_chain_status: read persona public key: {e}"
                                ),
                            )
                        })?
                        .flatten();
                    match public_key
                        .as_deref()
                        .ok_or("persona_public_key_missing")
                        .and_then(|key| {
                            core_crypto::grant_chain::root_pubkey_bytes_from_ed25519_hex(key)
                                .map_err(|_| "persona_public_key_invalid")
                        }) {
                        Ok(root_pubkey) => {
                            match core_crypto::grant_chain::verify_chain(&blocks, &root_pubkey) {
                                Ok(()) => {
                                    materialized_chain_verifies = true;
                                }
                                Err(e) => diagnostics.push(format!("chain_verify_failed:{e}")),
                            }
                        }
                        Err(e) => diagnostics.push(e.to_string()),
                    }
                }
            }
            Err(e) => diagnostics.push(format!("blocks_json_invalid_json:{e}")),
        }
    } else {
        diagnostics.push("blocks_json_missing".to_string());
    }

    let status_is_terminal = matches!(
        info.status.as_str(),
        "revoked"
            | "abandoned"
            | "expired"
            | "exhausted_by_budget"
            | "expired_by_budget"
            | "parent_cascade_revoked"
    );
    let diagnostic_code = if status_is_terminal {
        "grant_terminal"
    } else if materialized_chain_verifies {
        "chain_intact"
    } else {
        "signed_origin_journal_unavailable"
    };
    if diagnostic_code == "signed_origin_journal_unavailable" {
        diagnostics.push(
            "daemon grant storage has no signed grant-origin/history source to reconstruct from"
                .to_string(),
        );
    }

    Ok(json!({
        "kind": "grant_rebuild_chain_status",
        "grant_id": info.id,
        "persona_id": info.persona_id,
        "credential_name": info.credential_name,
        "status": info.status,
        "created_at": info.created_at,
        "expires_at": info.expires_at,
        "blocks_json_present": blocks_json_present,
        "blocks_json_deserializes": blocks_json_deserializes,
        "raw_block_count": raw_block_count,
        "materialized_chain_verifies": materialized_chain_verifies,
        "signed_origin_journal_available": false,
        "can_rebuild": false,
        "diagnostic_code": diagnostic_code,
        "diagnostics": diagnostics,
        "audit_chain_route": "ember recover audit-chain --dry-run",
    }))
}

/// Read-only eligibility probe for `ember recover persona restore`.
///
/// Per the P14-S4 design-lock, persona restore "chooses provenance over
/// durable-id resurrection": the authoritative ADR 190/195 runtime-substrate
/// predicate is evaluated only inside the dedicated restore *mutation* RPC,
/// which is not yet built (blocked on ADR 205 §A.6 step 4 + ADR 206
/// enrollment). This probe is explicitly NOT authority — it reports the
/// read-only durable-persona signal for UX and never proves eligibility.
///
/// Conservatism: a revoked durable persona is terminal, and restoring runtime
/// state under it would be a policy bypass, so the probe refuses and routes to
/// successor enrollment (ADR 206/211) rather than un-revocation. `can_restore`
/// and `restore_eligibility_proven` are therefore always `false`.
pub(super) fn recover_persona_restore_status(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = required_recovery_action_field(params, "id")?;
    let persona = store.get_persona(persona_id).map_err(|e| {
        (
            -32030,
            format!("recover_persona_restore_status: load persona {persona_id}: {e}"),
        )
    })?;

    let status = persona.status.as_str();
    let durable_persona_terminal = matches!(status, "revoked");
    let durable_persona_active = matches!(status, "active");
    let durable_persona_enrolling = matches!(status, "enrolling");

    let mut diagnostics = Vec::new();
    let diagnostic_code = if durable_persona_terminal {
        diagnostics.push(
            "durable persona is terminal (revoked); restoring runtime state under a revoked durable persona is a policy bypass — re-establish authority via successor enrollment, not un-revocation"
                .to_string(),
        );
        "persona_terminal"
    } else if durable_persona_enrolling {
        diagnostics.push(
            "durable persona is mid-enrollment (enrolling); it is not a settled durable persona to restore runtime state under"
                .to_string(),
        );
        "persona_enrolling"
    } else if durable_persona_active {
        diagnostics.push(
            "durable persona is active; the necessary precondition holds, but the authoritative ADR 190/195 runtime-substrate predicate is evaluated only inside the dedicated restore mutation RPC, which is not yet built"
                .to_string(),
        );
        "eligible_pending_mutation_rpc"
    } else {
        diagnostics.push(format!(
            "durable persona status '{status}' is not a recognized restore-eligible state; refusing conservatively"
        ));
        "persona_status_unrecognized"
    };

    let successor_enrollment_required = durable_persona_terminal;

    Ok(json!({
        "kind": "persona_restore_status",
        "persona_id": persona.id,
        "name": persona.name,
        "status": persona.status,
        "created_at": persona.created_at,
        "container_id": persona.container_id,
        "parent_grant_id": persona.parent_grant_id,
        "durable_persona_terminal": durable_persona_terminal,
        "durable_persona_active": durable_persona_active,
        "restore_eligibility_proven": false,
        "can_restore": false,
        "successor_enrollment_required": successor_enrollment_required,
        "diagnostic_code": diagnostic_code,
        "diagnostics": diagnostics,
        "successor_enrollment_route": "ember device enroll (successor per ADR 206/211; a revoked durable persona is not un-revoked)",
        "runbook_route": "docs/runbook/recovery.md#persona-lifecycle-recovery",
    }))
}

fn emit_recovery_action_receipt_with_mode(
    store: &DaemonStore,
    params: &Value,
    mode: RecoveryActionMode,
) -> Result<Value, (i32, String)> {
    let recovery_id = required_recovery_action_field(params, "recovery_id")?;
    let surface = require_recovery_action_literal(params, "surface", "lifecycle")?;
    let verb = required_recovery_action_field(params, "verb")?;
    let target_kind = required_recovery_action_field(params, "target_kind")?;
    let target_id = required_recovery_action_field(params, "target_id")?;
    let requested_action = required_recovery_action_field(params, "requested_action")?;
    let prior_state_digest = required_recovery_action_field(params, "prior_state_digest")?;
    let outcome = required_recovery_action_field(params, "outcome")?;
    if mode == RecoveryActionMode::GrantAbandonExecute
        && (verb != "grant"
            || target_kind != "grant"
            || requested_action != "abandon"
            || outcome != "executed")
    {
        return Err((
            -32602,
            "recover_grant_abandon: requires verb='grant', target_kind='grant', requested_action='abandon', outcome='executed'"
                .to_string(),
        ));
    }
    if mode == RecoveryActionMode::PersonaAbandonExecute
        && (verb != "persona"
            || target_kind != "persona"
            || requested_action != "abandon"
            || outcome != "executed")
    {
        return Err((
            -32602,
            "recover_persona_abandon: requires verb='persona', target_kind='persona', requested_action='abandon', outcome='executed'"
                .to_string(),
        ));
    }
    let mut execute_grant_abandon_reason = None;
    let mut execute_persona_abandon_reason = None;

    match verb {
        "diagnose" => {
            if target_kind != "local-machine" {
                return Err((
                    -32602,
                    "recovery_action_receipt: diagnose target_kind must be 'local-machine'"
                        .to_string(),
                ));
            }
            if target_id != "local-machine" {
                return Err((
                    -32602,
                    "recovery_action_receipt: diagnose target_id must be 'local-machine'"
                        .to_string(),
                ));
            }
            if outcome != "planned" {
                return Err((
                    -32602,
                    "recovery_action_receipt: diagnose 'outcome' must be 'planned'".to_string(),
                ));
            }
            if params
                .get("operator_confirmation_token_hash")
                .is_some_and(|value| !value.is_null())
            {
                return Err((
                    -32602,
                    "recovery_action_receipt: diagnose receipts cannot carry operator confirmation"
                        .to_string(),
                ));
            }
            if params
                .get("operator_persona_id")
                .is_some_and(|value| !value.is_null())
            {
                return Err((
                    -32602,
                    "recovery_action_receipt: diagnose receipts cannot carry operator persona"
                        .to_string(),
                ));
            }
        }
        "audit-chain" => {
            if target_kind != "audit-chain" {
                return Err((
                    -32602,
                    "recovery_action_receipt: audit-chain target_kind must be 'audit-chain'"
                        .to_string(),
                ));
            }
            if outcome != "planned" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: audit-chain outcome must be 'planned' or 'refused'; executed repair must route through audit_repair_chain"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        "persona" => {
            if target_kind != "persona" {
                return Err((
                    -32602,
                    "recovery_action_receipt: persona target_kind must be 'persona'".to_string(),
                ));
            }
            if requested_action == "abandon" {
                if outcome != "planned" && outcome != "executed" && outcome != "refused" {
                    return Err((
                        -32602,
                        "recovery_action_receipt: persona abandon outcome must be 'planned', 'executed', or 'refused'"
                            .to_string(),
                    ));
                }
                let reason = required_recovery_action_field(params, "abandon_reason")?;
                if outcome == "executed" {
                    if mode != RecoveryActionMode::PersonaAbandonExecute {
                        return Err((
                            -32602,
                            "recovery_action_receipt: executed persona abandon must route through recover_persona_abandon"
                                .to_string(),
                        ));
                    }
                    let _ =
                        required_recovery_action_field(params, "operator_confirmation_token_hash")?;
                    execute_persona_abandon_reason = Some(reason.to_string());
                }
            } else if outcome != "planned" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: persona outcome must be 'planned' or 'refused'; executed persona recovery must route through a dedicated daemon mutation RPC"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        "vault" => {
            if target_kind != "vault" && target_kind != "vault-backup" {
                return Err((
                    -32602,
                    "recovery_action_receipt: vault target_kind must be 'vault' or 'vault-backup'"
                        .to_string(),
                ));
            }
            if outcome != "planned" && outcome != "executed" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: vault outcome must be 'planned', 'executed', or 'refused'"
                        .to_string(),
                ));
            }
            // The vault-MEK-rotation mutation (target_kind 'vault') has no
            // executed path through the ConnectOnly recovery lane: rotation
            // execution requires the vault-MEK-rotation primitive (ADR 198) and
            // is refused at the CLI. Only the read-only backup verification
            // (target_kind 'vault-backup') may report 'executed'.
            if target_kind == "vault" && outcome == "executed" {
                return Err((
                    -32602,
                    "recovery_action_receipt: vault rotation cannot report 'executed' through the recovery lane; execution requires the vault-MEK-rotation primitive (ADR 198)"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        "trust" => {
            if target_kind != "trust-list" {
                return Err((
                    -32602,
                    "recovery_action_receipt: trust target_kind must be 'trust-list'".to_string(),
                ));
            }
            if outcome != "executed" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: trust outcome must be 'executed' or 'refused'"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        "grant" => {
            if target_kind != "grant" {
                return Err((
                    -32602,
                    "recovery_action_receipt: grant target_kind must be 'grant'".to_string(),
                ));
            }
            if requested_action != "abandon"
                && requested_action != "rebuild-chain"
                && requested_action != "extend"
            {
                return Err((
                    -32602,
                    "recovery_action_receipt: grant requested_action must be 'abandon', 'rebuild-chain', or 'extend'"
                        .to_string(),
                ));
            }
            if outcome != "planned" && outcome != "executed" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: grant outcome must be 'planned', 'executed', or 'refused'"
                    .to_string(),
                ));
            }
            if requested_action == "extend" {
                // F-AUTHORITY-1 — workflow-grant extension. The actual extension
                // mutation runs through the existing OperatorPresence-gated
                // `extend_grant` RPC (audited via grant.extended); this receipt
                // records the recovery-plane intent + outcome but is itself
                // ReceiptOnly mode. Execution must NOT be routed through this
                // path — recover_grant_abandon / recover_persona_abandon are the
                // only mutation-execute modes carried on this lane today.
                if mode != RecoveryActionMode::ReceiptOnly {
                    return Err((
                        -32602,
                        "recovery_action_receipt: grant extend must route as ReceiptOnly; the extend_grant RPC owns the mutation"
                            .to_string(),
                    ));
                }
                ensure_optional_recovery_operator_fields(params)?;
            } else if requested_action == "abandon" {
                let reason = required_recovery_action_field(params, "abandon_reason")?;
                if outcome == "executed" {
                    if mode != RecoveryActionMode::GrantAbandonExecute {
                        return Err((
                            -32602,
                            "recovery_action_receipt: executed grant abandon must route through recover_grant_abandon"
                                .to_string(),
                        ));
                    }
                    let _ =
                        required_recovery_action_field(params, "operator_confirmation_token_hash")?;
                    execute_grant_abandon_reason = Some(reason.to_string());
                }
            } else if outcome == "executed" {
                return Err((
                    -32602,
                    "recovery_action_receipt: executed grant rebuild-chain must route through a dedicated daemon mutation RPC"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        "daemon" => {
            if target_kind != "launchdaemon" {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon target_kind must be 'launchdaemon'"
                        .to_string(),
                ));
            }
            let daemon_kickstart = requested_action.starts_with("launchctl kickstart -k system/");
            let daemon_bootstrap_then_kickstart = requested_action
                .starts_with("launchctl bootstrap system /")
                && requested_action.contains("; launchctl kickstart -k system/");
            if !daemon_kickstart && !daemon_bootstrap_then_kickstart {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon requested_action must be a launchctl kickstart or bootstrap+kickstart"
                        .to_string(),
                ));
            }
            if outcome != "executed" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon outcome must be 'executed' or 'refused'"
                        .to_string(),
                ));
            }
            if required_recovery_authority_evidence_field(params, "scope")? != "daemon_crash" {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon authority_evidence.scope must be 'daemon_crash'"
                        .to_string(),
                ));
            }
            let before_state = required_recovery_authority_evidence_field(params, "before_state")?;
            if before_state != "exited" && before_state != "missing" {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon authority_evidence.before_state must be 'exited' or 'missing'"
                        .to_string(),
                ));
            }
            if required_recovery_authority_evidence_field(params, "after_state")? != "running" {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon authority_evidence.after_state must be 'running'"
                        .to_string(),
                ));
            }
            let log_excerpt_hash =
                required_recovery_authority_evidence_field(params, "log_excerpt_hash")?;
            if !log_excerpt_hash.starts_with("blake3:") {
                return Err((
                    -32602,
                    "recovery_action_receipt: daemon authority_evidence.log_excerpt_hash must be a blake3 digest"
                        .to_string(),
                ));
            }
            let _ = required_recovery_authority_evidence_field(params, "launchctl_label")?;
            let _ = required_recovery_authority_evidence_field(params, "launchctl_target")?;
            let _ = required_recovery_authority_evidence_field(params, "socket_path")?;
            let _ = required_recovery_authority_evidence_field(params, "log_path")?;
            ensure_optional_recovery_operator_fields(params)?;
        }
        "authority" => {
            // F-AUTHORITY-2 — presence-Device fallback when Touch ID hardware
            // is unavailable. The recovery action is declarative: it records
            // the operator's intent to use the PAM fallback presence factor
            // for the next authority-widening window. The actual
            // presence-factor selection happens at the gate (ADR 200 / 206)
            // when the next widening op runs; this lane never wires a
            // standing PAM-acceptance flag, never relaxes the §1 presence
            // chokepoint, and never bypasses the per-op presence-proof
            // requirement. Receipt is ReceiptOnly mode.
            if target_kind != "presence-fallback" {
                return Err((
                    -32602,
                    "recovery_action_receipt: authority target_kind must be 'presence-fallback'"
                        .to_string(),
                ));
            }
            if requested_action != "pam-fallback" {
                return Err((
                    -32602,
                    "recovery_action_receipt: authority requested_action must be 'pam-fallback' at v0.3.0"
                        .to_string(),
                ));
            }
            if outcome != "planned" && outcome != "refused" {
                return Err((
                    -32602,
                    "recovery_action_receipt: authority outcome must be 'planned' or 'refused'; presence-fallback never reports 'executed' through the recovery lane"
                        .to_string(),
                ));
            }
            if mode != RecoveryActionMode::ReceiptOnly {
                return Err((
                    -32602,
                    "recovery_action_receipt: authority pam-fallback must route as ReceiptOnly; presence factor is selected at the per-op gate"
                        .to_string(),
                ));
            }
            ensure_optional_recovery_operator_fields(params)?;
        }
        other => {
            return Err((
                -32602,
                format!(
                    "recovery_action_receipt: unsupported lifecycle verb '{other}' (allowed: diagnose, audit-chain, daemon, persona, grant, vault, trust, authority)"
                ),
            ));
        }
    }

    let dry_run_digest = match params.get("dry_run_digest") {
        Some(value) => value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                (
                    -32602,
                    "recovery_action_receipt: 'dry_run_digest' must be a non-empty string"
                        .to_string(),
                )
            })?,
        None => prior_state_digest,
    };
    let authority_evidence = recovery_action_authority_evidence(params, mode, verb)?;
    let operator_confirmation_token_hash =
        optional_recovery_action_string(params, "operator_confirmation_token_hash")?;
    let operator_persona_id = optional_recovery_action_string(params, "operator_persona_id")?;
    let prior_journal_sha = optional_recovery_action_string(params, "prior_journal_sha")?;
    let related_receipt_ids = recovery_action_string_array(params, "related_receipt_ids")?;
    let adr_refs = recovery_action_string_array(params, "adr_refs")?;
    let runbook_ref = required_recovery_action_field(params, "runbook_ref")?;
    let recorded_at_epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let body = RecoveryActionBody {
        recovery_id: recovery_id.to_string(),
        surface: surface.to_string(),
        verb: verb.to_string(),
        target_kind: target_kind.to_string(),
        target_id: target_id.to_string(),
        requested_action: requested_action.to_string(),
        prior_journal_sha,
        prior_state_digest: prior_state_digest.to_string(),
        dry_run_digest: dry_run_digest.to_string(),
        operator_confirmation_token_hash,
        operator_persona_id,
        authority_evidence,
        outcome: outcome.to_string(),
        related_receipt_ids,
        runbook_ref: runbook_ref.to_string(),
        adr_refs,
        recorded_at_epoch_secs,
    };
    body.validate().map_err(|err| {
        (
            -32602,
            format!("recovery_action_receipt: invalid recovery.action body: {err}"),
        )
    })?;

    let Some(identity) = current_identity() else {
        return Err((
            -32030,
            "recovery_action_receipt: daemon receipt identity is not initialised; \
             refusing to run recovery without a signed recovery.action receipt"
                .to_string(),
        ));
    };
    if let Some(reason) = execute_grant_abandon_reason {
        store.abandon_grant(target_id, &reason).map_err(|e| {
            (
                -32030,
                format!("recover_grant_abandon: abandon grant {target_id}: {e}"),
            )
        })?;
    }
    if let Some(reason) = execute_persona_abandon_reason {
        let persona = store.get_persona(target_id).map_err(|e| {
            (
                -32030,
                format!("recover_persona_abandon: load persona {target_id}: {e}"),
            )
        })?;
        if matches!(persona.status.as_str(), "revoked") {
            return Err((
                -32030,
                format!(
                    "recover_persona_abandon: persona {target_id} is already terminal ({})",
                    persona.status
                ),
            ));
        }
        store.revoke_persona(target_id).map_err(|e| {
            (
                -32030,
                format!("recover_persona_abandon: abandon persona {target_id}: {e}"),
            )
        })?;
        tracing::info!(
            persona_id = %target_id,
            reason = %reason,
            "recover_persona_abandon: persona revoked with recovery provenance"
        );
    }
    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let envelope = issue_atomic_receipt(
        RECEIPT_KIND_RECOVERY_ACTION,
        &body,
        TerminationAuthority::DaemonPersona,
        &identity.pubkey_hex(),
        &signer,
    )
    .map_err(|e| {
        (
            -32030,
            format!("recovery_action_receipt: sign receipt: {e}"),
        )
    })?;
    let envelope_json = serde_json::to_string(&envelope).map_err(|e| {
        (
            -32603,
            format!("recovery_action_receipt: serialize receipt: {e}"),
        )
    })?;
    store
        .store_atomic_receipt_v2(
            &envelope,
            "",
            body.operator_persona_id.as_deref().unwrap_or(""),
            outcome,
        )
        .map_err(|e| {
            (
                -32030,
                format!("recovery_action_receipt: persist receipt artifact: {e}"),
            )
        })?;
    let persisted = match store.log_event(
        None,
        RECEIPT_KIND_RECOVERY_ACTION,
        Some(verb),
        outcome,
        Some(&envelope_json),
    ) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                receipt_id = %envelope.receipt_id,
                "recovery_action_receipt: signed receipt returned but audit persistence failed"
            );
            false
        }
    };

    Ok(json!({
        "kind": RECEIPT_KIND_RECOVERY_ACTION,
        "receipt_id": envelope.receipt_id,
        "persisted": persisted,
        "envelope": envelope,
    }))
}
