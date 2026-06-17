//! Ordinary interactive-vault RPC handlers.
//! CLASSIFICATION: PUBLIC

use base64::Engine as _;
use core_grant_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, ReceiptKind, ReceiptOutcome, VaultReceipt,
};
use serde_json::{Value, json};
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::infra::{
    handler::{
        DispatchSource, RequestContext, check_user_presence_gate, current_vault,
        enforce_fresh_presence_proof, enforce_fresh_presence_proof_with_audit,
        handler_must_verify_fresh_presence_proof, mint_operator_presence_token,
    },
    receipt::{current_identity, persist_vault_biometric_receipt, sign_vault_receipt},
    store::DaemonStore,
    vault::{self, VaultError, VaultReadGate, VaultScope},
};
use crate::auth::presence_gate::PresencePolicy;
use crate::trust::presence::{self, HighRiskOp};

fn value_bytes(params: &Value) -> Result<Vec<u8>, (i32, String)> {
    if let Some(bytes) = params["value_bytes"].as_array() {
        let mut out = Vec::with_capacity(bytes.len());
        for item in bytes {
            let byte = item
                .as_u64()
                .ok_or((-32602, "value_bytes entries must be integers".to_string()))?;
            let byte = u8::try_from(byte)
                .map_err(|_| (-32602, "value_bytes entries must fit in u8".to_string()))?;
            out.push(byte);
        }
        Ok(out)
    } else {
        Ok(params["value"]
            .as_str()
            .ok_or((-32602, "missing 'value'".to_string()))?
            .as_bytes()
            .to_vec())
    }
}

pub(crate) fn handle_add(
    store: &DaemonStore,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Per-op user-presence gate. Internal callers (admin CLI / test harness)
    // bypass: same trust model as development milestone force-flag handling.
    if !source.is_internal() {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::VaultAdd, override_qh)?;
    }
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing 'name'".to_string()))?;
    let metadata = params["metadata"].as_str();
    // Wire-compat: accept the historical `require_biometric` / `requires_biometric`
    // booleans on the JSON envelope and lower them to a typed `PresencePolicy`
    // per the presence-policy unification. Callers that pass `true` opt
    // the row into `PerAccessFresh` semantics; `false` and absent fields both
    // remain `LaneDefault` (cached-unlock OK for ordinary reads, widening
    // dispatch fires for writes).
    let requires_fresh = params["require_biometric"].as_bool().unwrap_or(false)
        || params["requires_biometric"].as_bool().unwrap_or(false);
    let presence_policy = PresencePolicy::from_requires_biometric(requires_fresh);
    if requires_fresh && handler_must_verify_fresh_presence_proof(source) {
        enforce_fresh_presence_proof(store, "vault_add", params)?;
    }
    let value = value_bytes(params)?;
    let vault = current_vault(store, "vault_add")?;
    let info = vault
        .add_with_presence_policy(
            VaultScope::Interactive,
            store,
            name,
            &value,
            metadata,
            presence_policy,
        )
        .map_err(|e| (-32000, e.to_string()))?;
    if requires_fresh {
        presence::lock();
    }
    Ok(json!({
        "id": info.id,
        "name": info.name,
        "requires_biometric": info.presence_policy.requires_fresh_presence(),
    }))
}

pub(crate) fn handle_put(
    store: &DaemonStore,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    if !source.is_internal() {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::VaultAdd, override_qh)?;
    }
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing 'name'".to_string()))?;
    let metadata = params["metadata"].as_str();
    let requires_fresh = params["require_biometric"].as_bool().unwrap_or(false)
        || params["requires_biometric"].as_bool().unwrap_or(false);
    let presence_policy = PresencePolicy::from_requires_biometric(requires_fresh);
    if requires_fresh && handler_must_verify_fresh_presence_proof(source) {
        enforce_fresh_presence_proof(store, "vault_put", params)?;
    }
    let value = value_bytes(params)?;
    let vault = current_vault(store, "vault_put")?;
    let info = vault
        .replace_with_presence_policy(
            VaultScope::Interactive,
            store,
            name,
            &value,
            metadata,
            presence_policy,
        )
        .map_err(|e| (-32000, e.to_string()))?;
    if requires_fresh {
        presence::lock();
    }
    Ok(json!({
        "id": info.id,
        "name": info.name,
        "requires_biometric": info.presence_policy.requires_fresh_presence(),
    }))
}

pub(crate) fn handle_remove(
    store: &DaemonStore,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // High-risk write, gated. Emergency-eligible because vault_remove revokes
    // access; let the user shut down a leaked credential mid-quiet-hours.
    if !source.is_internal() {
        let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
        check_user_presence_gate(HighRiskOp::VaultRemove, override_qh)?;
    }
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing 'name'".to_string()))?;
    let vault = current_vault(store, "vault_remove")?;
    vault
        .remove(VaultScope::Interactive, store, name)
        .map_err(|e| (-32000, e.to_string()))?;
    // G6 / OQ-5: removal is a destructive mutation and must leave a
    // tamper-evident audit-chain record.
    let details = json!({ "name": name }).to_string();
    crate::infra::audit::append_audit_event_with_chain(
        store,
        None,
        "vault.remove",
        Some(name),
        "allowed",
        Some(&details),
    )
    .map_err(|e| (-32000, format!("vault_remove: audit chain append: {e}")))?;
    Ok(json!({"removed": true, "name": name}))
}

pub(crate) fn handle_export_sealed(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // vault_export_sealed_cli_landed: socket callers pass the design
    // nonce-bound presence chokepoint in the dispatcher; this handler keeps
    // the raw MEK in daemon space and returns only the EMVS sealed blob.
    presence::record_activity();
    let passphrase = params["passphrase"]
        .as_str()
        .ok_or((-32602, "missing 'passphrase'".to_string()))?;
    if passphrase.is_empty() {
        return Err((-32602, "'passphrase' must not be empty".to_string()));
    }
    let vault = current_vault(store, "vault_export_sealed")?;
    let (blob, fingerprint) = vault
        .export_interactive_mek_sealed(passphrase)
        .map_err(|e| (-32000, e.to_string()))?;
    let details = json!({
        "mek_fingerprint": fingerprint,
        "blob_len": blob.len(),
    })
    .to_string();
    let audit_event_id = crate::infra::audit::append_audit_event_with_chain(
        store,
        None,
        "vault.mek_sealed_exported",
        Some("vault-mek"),
        "allowed",
        Some(&details),
    )
    .map_err(|e| {
        (
            -32000,
            format!("vault_export_sealed: audit chain append: {e}"),
        )
    })?;
    Ok(json!({
        "blob": base64::engine::general_purpose::STANDARD.encode(&blob),
        "mek_fingerprint": fingerprint,
        "audit_event_id": audit_event_id,
    }))
}

pub(crate) fn handle_import_sealed(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // vault_import_sealed_cli_landed: recovery import must work when no live
    // MEK is attached, so it rides the dispatcher presence-chokepoint proof
    // rather than the normal live-vault OperatorPresence window.
    presence::record_activity();
    if store.vault().is_some() {
        return Err((
            -32030,
            "vault_import_sealed refused: live MEK already loaded; run `ember daemon recover-fresh` before importing a sealed MEK backup"
                .to_string(),
        ));
    }
    let blob_b64 = params["blob"]
        .as_str()
        .ok_or((-32602, "missing 'blob'".to_string()))?;
    let passphrase = params["passphrase"]
        .as_str()
        .ok_or((-32602, "missing 'passphrase'".to_string()))?;
    if passphrase.is_empty() {
        return Err((-32602, "'passphrase' must not be empty".to_string()));
    }
    let expected_fingerprint = params["expected_fingerprint"]
        .as_str()
        .ok_or((-32602, "missing 'expected_fingerprint'".to_string()))?;
    if expected_fingerprint.is_empty() {
        return Err((
            -32602,
            "'expected_fingerprint' must not be empty".to_string(),
        ));
    }

    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .map_err(|e| (-32602, format!("'blob' is not valid base64: {e}")))?;
    let recovered = vault::import_mek_sealed(&blob, passphrase, expected_fingerprint)
        .map_err(|e| (-32000, e.to_string()))?;
    if recovered.len() != 32 {
        return Err((
            -32000,
            format!(
                "sealed MEK recovered {} bytes, expected 32",
                recovered.len()
            ),
        ));
    }
    let mut interactive_key = Zeroizing::new([0u8; 32]);
    interactive_key.copy_from_slice(recovered.as_slice());

    let data_dir = store.data_dir().ok_or((
        -32000,
        "vault_import_sealed requires a daemon store with a data_dir".to_string(),
    ))?;
    let imported_vault = vault::finish_open_with_interactive_key_for_de(*interactive_key, data_dir)
        .map_err(|e| (-32000, e.to_string()))?;
    imported_vault
        .verify_canary(store)
        .map_err(|e| (-32000, e.to_string()))?;
    store
        .write_mek_fingerprint(expected_fingerprint)
        .map_err(|e| (-32000, e.to_string()))?;
    store.set_vault(Rc::new(imported_vault));

    let details = json!({
        "mek_fingerprint": expected_fingerprint,
        "blob_len": blob.len(),
    })
    .to_string();
    let audit_event_id = crate::infra::audit::append_audit_event_with_chain(
        store,
        None,
        "vault.mek_sealed_imported",
        Some("vault-mek"),
        "allowed",
        Some(&details),
    )
    .map_err(|e| {
        (
            -32000,
            format!("vault_import_sealed: audit chain append: {e}"),
        )
    })?;
    Ok(json!({
        "imported": true,
        "mek_fingerprint": expected_fingerprint,
        "audit_event_id": audit_event_id,
    }))
}

pub(crate) fn handle_lock() -> Result<Value, (i32, String)> {
    // Explicit re-lock. Always allowed because the user is reducing privilege.
    presence::lock();
    Ok(json!({"locked": true}))
}

pub(crate) fn handle_unlock(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    #[cfg(target_os = "macos")]
    if crate::infra::vault::is_separate_uid_posture() {
        return Err((
            -32030,
            "vault_unlock: separate-uid posture uses the design §4 presence-as-decryption unlock; run `ember vault se-unlock` (one Touch ID tap)".to_string(),
        ));
    }
    crate::infra::interactive_unlock::ensure_live_vault_for_legacy_unlock(store)
        .map_err(|msg| (-32030, msg))?;
    crate::infra::interactive_unlock::arm_non_session_grace_window();
    let requested_method = params
        .get("requested_method")
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("vault_unlock");
    let token = mint_operator_presence_token(ctx.peer.as_ref(), requested_method)?;
    let mut response = json!({"unlocked": true});
    if let Some(token) = token {
        response["presence_token"] = serde_json::to_value(token)
            .map_err(|e| (-32000, format!("vault_unlock: encode presence_token: {e}")))?;
    }
    Ok(response)
}

pub(crate) fn handle_status(store: &DaemonStore) -> Result<Value, (i32, String)> {
    // -S3 intentionally-global ConnectOnly diagnostic: live-vault /
    // interactive-unlock posture has no persona-owned rows to scope.
    presence::record_activity();
    let (unlocked, idle_secs) = presence::snapshot();
    let cfg = presence::current_config();
    let unlock = crate::infra::interactive_unlock::snapshot();
    let live_vault_attached = store.vault().is_some();
    let posture = if unlocked {
        "interactive-unlocked"
    } else if live_vault_attached && unlock.session_pin_count > 0 {
        "presence-locked-vault-pinned"
    } else if live_vault_attached {
        "presence-locked-vault-attached"
    } else {
        "hard-locked"
    };
    // design D1: surface the monotonic MEK-rotation epoch even while locked.
    let key_epoch = store.read_key_epoch().unwrap_or(0);
    Ok(json!({
        "posture": posture,
        "unlocked": unlocked,
        "idle_secs": idle_secs,
        "idle_timeout_secs": cfg.idle_timeout.as_secs(),
        "live_vault_attached": live_vault_attached,
        "session_pin_count": unlock.session_pin_count,
        "grace_window_secs": unlock.grace_window_secs,
        "grace_remaining_secs": unlock.grace_remaining_secs,
        "grace_lock_pending": unlock.grace_lock_pending,
        "grace_zero_due": unlock.grace_zero_due,
        "quiet_hours_start": cfg.quiet_hours_start,
        "quiet_hours_end": cfg.quiet_hours_end,
        "key_epoch": key_epoch,
    }))
}

pub(crate) fn handle_migrate_acl(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    presence::record_activity();
    let service = params["service"]
        .as_str()
        .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_SERVICE);
    let account = params["account"]
        .as_str()
        .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_ACCOUNT);
    let result = crate::infra::vault::migrate_mek_acl(service, account)
        .map_err(|e| (-32000, e.to_string()))?;
    let _ = store.log_event(
        None,
        "vault.mek_acl_migrated",
        None,
        "ok",
        Some(&format!(
            "before={} after={} service={} account={}",
            result.before_acl_kind, result.after_acl_kind, result.service, result.account
        )),
    );
    Ok(json!({
        "before_acl_kind": result.before_acl_kind,
        "after_acl_kind": result.after_acl_kind,
        "service": result.service,
        "account": result.account,
    }))
}

pub(crate) fn handle_list(store: &DaemonStore) -> Result<Value, (i32, String)> {
    // Operator inventory enumeration: bump activity, never prompt.
    presence::record_activity();
    let vault = current_vault(store, "vault_list")?;
    let creds = vault
        .list(VaultScope::Interactive, store)
        .map_err(|e| (-32000, e.to_string()))?;
    let list: Vec<Value> = creds
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "metadata": c.metadata,
                // Wire-compat field name (`requires_biometric`) preserved per
                // Presence-policy unification; populated from the
                // typed PresencePolicy on the row.
                "requires_biometric": c.presence_policy.requires_fresh_presence(),
            })
        })
        .collect();
    Ok(json!(list))
}

pub(crate) fn handle_get(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Read-class: ordinary rows bump activity without prompting. Per-entry
    // biometric rows require a fresh proof before decrypting. Return plaintext
    // only in the response and never log the value.
    presence::record_activity();
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing 'name'".to_string()))?;

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Attempt retrieval; emit a typed VaultReceipt on both success and failure
    // so the audit trail is never silent.
    let vault = current_vault(store, "vault_get")?;
    let mut biometric_audit = None;
    let result = match vault.credential_presence_policy(VaultScope::Interactive, store, name) {
        Ok(policy) if policy.requires_fresh_presence() => {
            enforce_fresh_presence_proof_with_audit(store, "vault_get", params).and_then(|audit| {
                let value = vault
                    .get_with_read_gate(
                        VaultScope::Interactive,
                        store,
                        name,
                        VaultReadGate::FreshPresence,
                    )
                    .map_err(|e| match e {
                        VaultError::PresenceRequired => (
                            -32030,
                            "vault_get requires a fresh presence-Device signature".to_string(),
                        ),
                        other => (-32000, other.to_string()),
                    })?;
                biometric_audit = Some(audit);
                Ok(value)
            })
        }
        Ok(_lane_default) => vault
            .get(VaultScope::Interactive, store, name)
            .map_err(|e| (-32000, e.to_string())),
        Err(VaultError::NotFound) => Err((-32000, "credential not found".to_string())),
        Err(e) => Err((-32000, e.to_string())),
    };
    let (outcome, error) = match &result {
        Ok(_) => (ReceiptOutcome::Success, None),
        Err((_, message)) => (ReceiptOutcome::Failure, Some(message.clone())),
    };

    let mut receipt = VaultReceipt {
        id: format!("rct-vault-{}", uuid::Uuid::new_v4()),
        kind: ReceiptKind::VaultRetrieval,
        key_name: name.to_string(),
        caller_persona: "unknown".to_string(),
        materialized_at_epoch_secs: now_epoch,
        grant_evaluation: GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        },
        outcome,
        evidence: Evidence::default(),
    };
    if let Some(identity) = current_identity() {
        sign_vault_receipt(&mut receipt, identity);
    }
    if let Err(e) = store.store_vault_receipt(&receipt) {
        tracing::warn!(
            error = %e,
            key_name = %name,
            receipt_id = %receipt.id,
            "vault_get: failed to persist typed VaultReceipt"
        );
    }
    if let (Ok(_), Some(audit)) = (&result, biometric_audit.as_ref())
        && let Err(e) = persist_vault_biometric_receipt(
            store,
            name,
            "unknown",
            "vault_get",
            None,
            &audit.presence_authenticator_id,
            &audit.public_key_hash(),
        )
    {
        tracing::warn!(
            error = %e,
            key_name = %name,
            "vault_get: failed to persist biometric vault-read receipt"
        );
    }

    match result {
        Ok(value) => {
            tracing::info!(name = %name, "vault_get: credential fetched");
            let text = String::from_utf8_lossy(&value).into_owned();
            Ok(json!({
                "value": text,
                "value_bytes": value.to_vec(),
            }))
        }
        Err((code, message)) => {
            if let Some(reason) = error {
                tracing::warn!(name = %name, error = %reason, "vault_get: retrieval failed");
            }
            Err((code, message))
        }
    }
}
