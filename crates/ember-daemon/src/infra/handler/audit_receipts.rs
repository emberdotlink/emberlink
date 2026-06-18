use serde_json::{Value, json};

use crate::infra::audit::{
    AuditFilter, BreakKind, RepairError, RepairIntent, RepairKind, RepairOutcome, VerifyOutcome,
    run_audit_verify, truncate_after_row, verify_repair_intent_signature,
};
use crate::infra::receipt::ReceiptFilter;
use crate::infra::rpc_error::RpcError;
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::policy::PolicyEngine;

use super::{RequestContext, current_dispatch_deployment_tier, is_quarantined};

pub(crate) fn handle_verify(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // P13-S3 intentionally-global ConnectOnly diagnostic: verifies chain
    // integrity for the daemon audit log as a whole. Actor filtering would
    // hide the tamper state this method exists to surface.
    let tail = params["tail"].as_u64().map(|n| n as usize);
    audit_verify(store, tail)
}

fn audit_verify(store: &DaemonStore, tail: Option<usize>) -> Result<Value, (i32, String)> {
    let outcome = run_audit_verify(store.conn(), tail, store.data_dir())
        .map_err(|e| RpcError::Internal(format!("audit_verify: {e}")))?;
    Ok(match outcome {
        VerifyOutcome::Ok {
            rows_walked,
            segments_walked,
            sample_mode,
        } => json!({
            "ok": true,
            "rows_walked": rows_walked,
            "segments_walked": segments_walked,
            "sample_mode": format!("{sample_mode:?}"),
            "tail": tail,
        }),
        VerifyOutcome::Break { kind } => match kind {
            BreakKind::RowHashMismatch {
                at_row_id,
                expected_hash,
                stored_hash,
                rows_walked_before,
            } => json!({
                "ok": false,
                "break": {
                    "kind": "row_hash_mismatch",
                    "at_row_id": at_row_id,
                    "expected_hash": expected_hash,
                    "stored_hash": stored_hash,
                    "rows_walked_before": rows_walked_before,
                },
                "tail": tail,
            }),
            BreakKind::ForwardLinkMismatch {
                at_row_id,
                predecessor_row_id,
                expected_prev_hash,
                stored_prev_hash,
                rows_walked_before,
            } => json!({
                "ok": false,
                "break": {
                    "kind": "forward_link_mismatch",
                    "at_row_id": at_row_id,
                    "predecessor_row_id": predecessor_row_id,
                    "expected_prev_hash": expected_prev_hash,
                    "stored_prev_hash": stored_prev_hash,
                    "rows_walked_before": rows_walked_before,
                },
                "tail": tail,
            }),
        },
        VerifyOutcome::LegacyRowsPresent {
            count,
            max_legacy_id,
            chain_resumes_at_id,
        } => json!({
            "ok": true,
            "legacy_rows_present": {
                "count": count,
                "max_legacy_id": max_legacy_id,
                "chain_resumes_at_id": chain_resumes_at_id,
                "remediation_id": "audit.migrate_chain_acknowledge",
            },
            "tail": tail,
        }),
        VerifyOutcome::ChainTopologyInvariantViolation {
            kind,
            at_row_id,
            rows_walked_before,
        } => json!({
            "ok": false,
            "topology_violation": {
                "kind": format!("{kind:?}"),
                "at_row_id": at_row_id,
                "rows_walked_before": rows_walked_before,
            },
            "tail": tail,
        }),
        VerifyOutcome::IncompleteRepair { receipt_id_orphan } => json!({
            "ok": false,
            "incomplete_repair": {
                "receipt_id_orphan": receipt_id_orphan,
                "remediation_id": "audit_repair_chain",
            },
            "tail": tail,
        }),
        VerifyOutcome::IncompleteRepairReceipt { tombstone_row_id } => json!({
            "ok": false,
            "incomplete_repair_receipt": {
                "tombstone_row_id": tombstone_row_id,
                "remediation_id": "audit_repair_chain",
            },
            "tail": tail,
        }),
    })
}

pub(super) fn handle_repair_chain_prepare(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // ADR 174 v2 / P23-S5 follow-up: PREPARE is read-only, but it is still
    // part of the operator unbrick ceremony. Keep it tied to quarantine so
    // operators do not pre-sign repair intents outside a detected break.
    if !is_quarantined() {
        tracing::warn!(
            method = "audit_repair_chain_prepare",
            peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
            "audit_repair_chain_prepare refused: daemon not in quarantine-serve mode"
        );
        return Err(RpcError::InvalidParams(
            "audit_repair_chain_prepare refused: daemon is not in quarantine-serve mode \
             (prepare is only valid after a detected audit-chain break)"
                .to_string(),
        )
        .into());
    }

    let from_row_id = params["from_row_id"].as_i64().ok_or_else(|| {
        RpcError::InvalidParams("missing or non-integer 'from_row_id'".to_string())
    })?;
    let repair_kind_str = params["repair_kind"].as_str().unwrap_or("truncate");
    let repair_kind = match repair_kind_str {
        "truncate" => RepairKind::Truncate,
        "tombstone_segment" => RepairKind::TombstoneSegment,
        other => {
            return Err(RpcError::InvalidParams(format!(
                "unknown repair_kind '{other}' (allowed: 'truncate', 'tombstone_segment')"
            ))
            .into());
        }
    };
    if repair_kind != RepairKind::Truncate {
        return Err(RpcError::InvalidParams(
            "repair_kind tombstone_segment is not supported in v0.3 (only truncate)".to_string(),
        )
        .into());
    }

    let current_chain_tip_hash: Option<String> = store
        .conn()
        .query_row(
            "SELECT row_hash FROM audit_log WHERE id = ?1",
            rusqlite::params![from_row_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    let current_chain_tip_hash = current_chain_tip_hash.ok_or_else(|| {
        RpcError::InvalidParams(format!(
            "from_row_id {from_row_id} does not exist in audit_log or has no row_hash"
        ))
    })?;

    let identity = crate::infra::receipt::current_identity().ok_or_else(|| {
        RpcError::Internal(
            "audit_repair_chain_prepare: daemon identity not initialised".to_string(),
        )
    })?;
    let daemon_identity_root_fingerprint = identity.identity_root_fingerprint();
    let canonical_bytes = crate::infra::audit::canonical_repair_intent_bytes(
        from_row_id,
        &current_chain_tip_hash,
        &daemon_identity_root_fingerprint,
    );
    let canonical_bytes_hex = hex::encode(&canonical_bytes);
    let sha256_hex = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&canonical_bytes))
    };
    let blake3_hex = blake3::hash(&canonical_bytes).to_hex().to_string();

    Ok(json!({
        "ok": true,
        "schema": "emberlink.audit_repair_chain_prepare.v1",
        "from_row_id": from_row_id,
        "repair_kind": "truncate",
        "current_chain_tip_hash": current_chain_tip_hash.clone(),
        "daemon_identity_root_fingerprint": daemon_identity_root_fingerprint.clone(),
        "canonical_bytes_hex": canonical_bytes_hex,
        "canonical_bytes_len": canonical_bytes.len(),
        "sha256_hex": sha256_hex,
        "blake3_hex": blake3_hex,
        "audit_repair_chain_params": {
            "from_row_id": from_row_id,
            "repair_kind": "truncate",
            "operator_signature_hex": null,
            "operator_pubkey": null,
            "current_chain_tip_hash": current_chain_tip_hash,
            "daemon_identity_root_fingerprint": daemon_identity_root_fingerprint,
        },
        "trust_note": "operator_pubkey must come from the operator-held AC-2 card, not this daemon response",
    }))
}

pub(super) fn handle_repair_chain(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // ADR 174 v2: repair is the operator unbrick path from quarantine. Refuse
    // healthy-chain calls before parsing or mutating repair state.
    if !is_quarantined() {
        tracing::warn!(
            method = "audit_repair_chain",
            peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
            "audit_repair_chain refused: daemon not in quarantine-serve mode"
        );
        return Err(RpcError::InvalidParams(
            "audit_repair_chain refused: daemon is not in quarantine-serve mode \
             (repair is only valid as the unbrick path FROM a detected chain \
             break — call `audit_verify` first)"
                .to_string(),
        )
        .into());
    }

    let from_row_id = params["from_row_id"].as_i64().ok_or_else(|| {
        RpcError::InvalidParams("missing or non-integer 'from_row_id'".to_string())
    })?;
    let repair_kind_str = params["repair_kind"].as_str().ok_or_else(|| {
        RpcError::InvalidParams(
            "missing 'repair_kind' (must be 'truncate' or 'tombstone_segment')".to_string(),
        )
    })?;
    let repair_kind = match repair_kind_str {
        "truncate" => RepairKind::Truncate,
        "tombstone_segment" => RepairKind::TombstoneSegment,
        other => {
            return Err(RpcError::InvalidParams(format!(
                "unknown repair_kind '{other}' (allowed: 'truncate', 'tombstone_segment')"
            ))
            .into());
        }
    };
    let operator_signature_hex = params["operator_signature_hex"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'operator_signature_hex'".to_string()))?;
    let operator_signature = hex::decode(operator_signature_hex).map_err(|e| {
        RpcError::InvalidParams(format!("operator_signature_hex is not valid hex: {e}"))
    })?;
    let operator_pubkey = params["operator_pubkey"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'operator_pubkey'".to_string()))?
        .to_string();
    let current_chain_tip_hash = params["current_chain_tip_hash"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'current_chain_tip_hash'".to_string()))?
        .to_string();
    let daemon_identity_root_fingerprint = params["daemon_identity_root_fingerprint"]
        .as_str()
        .ok_or_else(|| {
            RpcError::InvalidParams("missing 'daemon_identity_root_fingerprint'".to_string())
        })?
        .to_string();

    let intent = RepairIntent {
        from_row_id,
        repair_kind,
        operator_signature,
        operator_pubkey: operator_pubkey.clone(),
        current_chain_tip_hash,
        daemon_identity_root_fingerprint,
    };

    // ADR 200 §6 / P23-S5 — close F1: verify the co-signature against the enrolled
    // `presence`-class Device set under the operator root (Model C, 1-of-N), NOT
    // against "any enrolled persona pubkey." The old gate accepted a co-signature
    // from a daemon-vault-sealed agent/runtime persona key — which a compromised
    // daemon can forge. A `presence` Device's private key lives in hardware the
    // daemon does not hold (G1), so only an operator-held co-signature passes here.
    // The enrolled presence-Device set lives in the operator identity substrate
    // (`identity-events.db`), not the main store — reopen it on demand (the daemon
    // idiom for `!Send` rusqlite handles). No data_dir / no operator identity =>
    // empty set => the verify below fails closed (G1: never a forgeable co-sign).
    let presence_devices = match store.data_dir() {
        Some(data_dir) => match crate::infra::identity_substrate::open_identity_store(data_dir) {
            Ok(identity_store) => {
                crate::infra::operator_identity::active_presence_devices_under_operator_root(
                    identity_store.materialized(),
                )
            }
            Err(e) => {
                return Err(RpcError::Internal(format!(
                    "audit_repair_chain: open identity store: {e}"
                ))
                .into());
            }
        },
        None => Vec::new(),
    };
    let cosigner =
        verify_repair_intent_signature(&intent, &presence_devices).map_err(|e| match e {
            RepairError::OperatorSignatureInvalid => {
                tracing::warn!(
                    method = "audit_repair_chain",
                    peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                    presence_device_count = presence_devices.len(),
                    "audit_repair_chain refused: co-signature did not verify against any \
                     enrolled presence Device under the operator root"
                );
                RpcError::OperatorAttestationFailed(
                    "audit_repair_chain: operator co-signature did not verify against an \
                 enrolled presence-class Device under the operator root (ADR 200 §6 — \
                 a daemon-vault-sealed persona key is not accepted)"
                        .to_string(),
                )
            }
            RepairError::OperatorPubkeyInvalid(msg) => RpcError::OperatorAttestationFailed(
                format!("audit_repair_chain: operator_pubkey malformed: {msg}"),
            ),
            other => RpcError::JsonRpcInternal(format!("audit_repair_chain: {other}")),
        })?;

    let outcome = truncate_after_row(store, &intent, &cosigner).map_err(|e| match e {
        RepairError::OperatorSignatureInvalid => RpcError::OperatorAttestationFailed(e.to_string()),
        RepairError::OperatorPubkeyInvalid(_) => RpcError::OperatorAttestationFailed(e.to_string()),
        RepairError::DaemonFingerprintMismatch { .. } => {
            RpcError::OperatorAttestationFailed(e.to_string())
        }
        RepairError::ChainTipMismatch { .. } => RpcError::InvalidParams(e.to_string()),
        RepairError::FromRowIdMissing(_) => RpcError::InvalidParams(e.to_string()),
        RepairError::UnsupportedRepairKind(_) => RpcError::InvalidParams(e.to_string()),
        other => RpcError::JsonRpcInternal(format!("audit_repair_chain: {other}")),
    })?;

    match outcome {
        RepairOutcome::Ok {
            repair_id,
            new_chain_tip_hash,
            tombstone_row_id,
            truncated_row_count,
        } => Ok(json!({
            "ok": true,
            "repair_id": repair_id,
            "new_chain_tip_hash": new_chain_tip_hash,
            "tombstone_row_id": tombstone_row_id,
            "truncated_row_count": truncated_row_count,
        })),
        RepairOutcome::IncompleteRepair { receipt_id_orphan } => Ok(json!({
            "ok": false,
            "incomplete_repair": { "receipt_id_orphan": receipt_id_orphan },
        })),
        RepairOutcome::IncompleteRepairReceipt {
            tombstone_row_id_orphan,
        } => Ok(json!({
            "ok": false,
            "incomplete_repair_receipt": {
                "tombstone_row_id_orphan": tombstone_row_id_orphan,
            },
        })),
    }
}

pub(crate) fn handle_audit_query(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let claimed_persona_id = params["persona_id"].as_str();
    let claimed_agent_id = params["agent_id"].as_str();
    if let (Some(persona_id), Some(agent_id)) = (claimed_persona_id, claimed_agent_id)
        && persona_id != agent_id
    {
        return Err(RpcError::InvalidParams(
            "audit_query: persona_id and agent_id must match when both are provided".to_string(),
        )
        .into());
    }
    let agent_id = match crate::infra::handlers::principal::team0_connect_only_persona_scope(
        ctx,
        "audit_query",
    )? {
        Some(trusted_persona) => {
            if let Some(claimed_persona) = claimed_persona_id.or(claimed_agent_id)
                && claimed_persona != trusted_persona
            {
                tracing::warn!(
                    method = "audit_query",
                    claimed_persona_id = %claimed_persona,
                    trusted_persona_id = %trusted_persona,
                    tier = current_dispatch_deployment_tier().as_str(),
                    "connect-only persona-scoped read refused: claimed persona does not match trusted principal"
                );
                return Err(RpcError::NotFound(
                    "audit_query: claimed actor does not match trusted principal".to_string(),
                )
                .into());
            }
            Some(trusted_persona)
        }
        None => claimed_persona_id.or(claimed_agent_id).map(String::from),
    };
    let limit = params["limit"].as_u64().map(|l| l as usize);
    let filter = AuditFilter {
        persona_id: agent_id,
        limit,
        ..Default::default()
    };
    let entries = store
        .query_audit(&filter)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "action": e.action,
                "credential": e.credential,
                "outcome": e.outcome,
            })
        })
        .collect();
    Ok(json!(list))
}

pub(super) fn handle_audit_log_query(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let filter = AuditFilter {
        id: params["id"].as_i64(),
        agent_id: params["agent_id"].as_str().map(String::from),
        action: params["action"].as_str().map(String::from),
        limit: params["limit"].as_u64().map(|l| l as usize),
        action_prefix: params["action_prefix"].as_str().map(String::from),
        persona_id: params["persona_id"].as_str().map(String::from),
        scope: params["scope"].as_str().map(String::from),
        since_ms: params["since_ms"].as_i64(),
        before_ms: params["before_ms"].as_i64(),
    };
    let entries = store
        .query_audit(&filter)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(list))
}

pub(super) fn handle_audit_explain(
    store: &DaemonStore,
    policy: &PolicyEngine,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_i64()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id'".to_string()))?;
    let explain = crate::infra::audit_explain::build_audit_explain(store, policy, id).map_err(
        |e| match e {
            StoreError::NotFound => RpcError::NotFound(format!("audit event {id} not found")),
            other => RpcError::Internal(other.to_string()),
        },
    )?;
    Ok(serde_json::to_value(explain).unwrap_or(Value::Null))
}

pub(super) fn handle_receipt_tree(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let grant_id = params["grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'grant_id'".to_string()))?;
    let tree = crate::infra::receipt_tree::build_tree(store, grant_id).map_err(|e| match e {
        crate::infra::receipt_tree::ReceiptTreeError::UnknownRoot(id) => {
            RpcError::NotFound(format!("grant '{id}' not found"))
        }
        other => RpcError::Internal(other.to_string()),
    })?;
    Ok(serde_json::to_value(tree).unwrap_or(Value::Null))
}

pub(crate) fn handle_receipt_query(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "receipt_query",
        "actor",
        false,
    )?;
    let filter = ReceiptFilter {
        persona_id,
        kind: params["kind"].as_str().map(String::from),
        grant_id: params["grant_id"].as_str().map(String::from),
        resource: params["resource"].as_str().map(String::from),
        since_iso: params["since"].as_str().map(String::from),
        limit: params["limit"].as_u64(),
        ..Default::default()
    };
    let rows = store
        .query_receipts(&filter)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(list))
}

pub(crate) fn handle_list_receipts(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "list_receipts",
        "persona_id",
        false,
    )?;
    let receipts = store
        .list_receipts(persona_id.as_deref())
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let list: Vec<Value> = receipts
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(list))
}

pub(crate) fn handle_get_receipt(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let id = params["id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'id'".to_string()))?;
    if let Ok(receipt) = store.get_receipt(id) {
        crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal(
            ctx,
            "get_receipt",
            &receipt.summary.persona_id,
        )?;
        return Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null));
    }

    match store.get_grant(id) {
        Ok(grant) => {
            crate::infra::handlers::principal::ensure_connect_only_owner_matches_trusted_principal(
                ctx,
                "get_receipt",
                &grant.persona_id,
            )?;
            let receipt_id = grant.receipt_id.as_deref().ok_or_else(|| {
                RpcError::NotFound(
                format!(
                    "no receipt found for id '{id}' (grant exists but has not reached terminal state)"
                ),
                )
            })?;
            let receipt = store.get_receipt(receipt_id).map_err(|e| match e {
                StoreError::NotFound => RpcError::NotFound(format!(
                    "grant has receipt_id={receipt_id} but receipt body is missing"
                )),
                other => RpcError::Internal(other.to_string()),
            })?;
            Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null))
        }
        Err(StoreError::NotFound) => {
            Err(RpcError::NotFound(format!("no receipt or grant found for id '{id}'")).into())
        }
        Err(e) => Err(RpcError::Internal(e.to_string()).into()),
    }
}
