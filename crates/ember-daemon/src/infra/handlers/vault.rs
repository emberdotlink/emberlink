//! Ordinary interactive-vault RPC handlers.
//! CLASSIFICATION: PUBLIC

use base64::Engine as _;
use core_grant_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, ReceiptKind, ReceiptOutcome, VaultReceipt,
};
use serde_json::{Value, json};
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::auth::presence_gate::PresencePolicy;
use crate::infra::{
    handler::{
        DispatchSource, RequestContext, check_user_presence_gate, current_vault,
        enforce_fresh_presence_proof, enforce_fresh_presence_proof_with_audit,
        handler_must_verify_fresh_presence_proof, mint_operator_presence_token,
        parse_scope_kek_hex,
    },
    receipt::{current_identity, persist_vault_biometric_receipt, sign_vault_receipt},
    rpc_error::RpcError,
    store::DaemonStore,
    vault::{self, VaultError, VaultReadGate, VaultScope},
};
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
    // bypass: same trust model as C39-HANDLER-C2 force-flag handling.
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
    // vault_export_sealed_cli_landed: socket callers pass the ADR 206
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
            "vault_unlock: separate-uid posture uses the ADR 206 §4 presence-as-decryption unlock; run `ember vault se-unlock` (one Touch ID tap)".to_string(),
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

pub(crate) fn handle_se_provision(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let device_id = params
        .get("device_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.se_provision: 'device_id' required".to_string())
        })?;
    let ecies_key_id = params
        .get("ecies_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.se_provision: 'ecies_key_id' required".to_string())
        })?;
    let wrapped_kek = params
        .get("wrapped_kek")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.se_provision: 'wrapped_kek' (hex) required".to_string())
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| {
                RpcError::InvalidParams(format!("vault.se_provision: 'wrapped_kek' bad hex: {e}"))
            })
        })?;
    let scope_kek = parse_scope_kek_hex(params, "scope_kek")?;

    // ADR 206 §4 — resolve BOTH the AC-7 recipient allowlist (§6 finding
    // M3) and the per-scope binding ("Never one global KEK") from a single
    // identity-substrate open, fail-closed BEFORE any mutation below.
    let (allowed_recipients, provision_scope) = match store.data_dir() {
        Some(data_dir) => match crate::infra::identity_substrate::open_identity_store(data_dir) {
            Ok(identity_store) => {
                let st = identity_store.materialized();
                (
                    crate::infra::operator_identity::active_kek_recipient_ecies_key_ids_under_operator_root(st),
                    crate::infra::operator_identity::operator_authority_scope(st),
                )
            }
            Err(e) => {
                return Err(RpcError::Internal(format!(
                    "vault.se_provision: open identity store: {e}"
                ))
                .into());
            }
        },
        None => (Vec::new(), None),
    };
    if !allowed_recipients.iter().any(|k| k == ecies_key_id) {
        return Err(RpcError::PresenceLocked(format!(
            "vault.se_provision: ecies_key_id '{ecies_key_id}' is not an \
                 enrolled presence-Device or recovery recipient under the \
                 operator root (ADR 206 §4/§6 AC-7 allowlist = enrolled ∪ \
                 recovery); refusing to store a scope-KEK wrap to a \
                 non-enrolled recipient"
        ))
        .into());
    }
    let (scope_kind, scope_id) = provision_scope.ok_or_else(|| {
        RpcError::PresenceLocked(
            "vault.se_provision: no operator-authority scope (no unambiguous \
         operator root); refusing to store a scope-KEK wrap with no scope \
         (ADR 206 §4: never one global KEK)"
                .to_string(),
        )
    })?;

    store
        .write_presence_scope_kek_wrap(
            &scope_kind,
            &scope_id,
            device_id,
            ecies_key_id,
            &wrapped_kek,
        )
        .map_err(|e| RpcError::Internal(format!("vault.se_provision: store wrap: {e}")))?;

    store
        .clear_headless_and_canary_meta()
        .map_err(|e| RpcError::Internal(format!("vault.se_provision: clean-break meta: {e}")))?;
    store.clear_bridge_ca_wrap().map_err(|e| {
        RpcError::Internal(format!("vault.se_provision: clean-break bridge-ca: {e}"))
    })?;
    if let Some(dir) = store.data_dir() {
        for stale in [
            crate::infra::vault::HEADLESS_MEK_WRAP_FILE,
            "bridge_ca.wrap",
            "bridge_ca.sealed",
        ] {
            let path = dir.join(stale);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(RpcError::Internal(format!(
                        "vault.se_provision: clean-break remove {}: {e}",
                        path.display()
                    ))
                    .into());
                }
            }
        }
    }

    let vault =
        crate::infra::interactive_unlock::install_presence_scope_kek_vault(store, *scope_kek)
            .map_err(|e| RpcError::PresenceLocked(format!("vault.se_provision: install: {e}")))?;

    let (canary_nonce, canary) = vault.seal_canary().map_err(|e| {
        RpcError::PresenceLocked(format!("vault.se_provision: re-seal canary: {e}"))
    })?;
    store
        .write_vault_canary(&canary, &canary_nonce)
        .map_err(|e| RpcError::Internal(format!("vault.se_provision: write canary: {e}")))?;

    crate::infra::interactive_unlock::arm_non_session_grace_window();
    Ok(json!({ "status": "provisioned", "device_id": device_id }))
}

pub(crate) fn handle_se_add_recipient_wrap(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let device_id = params
        .get("device_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.se_add_recipient_wrap: 'device_id' required".to_string())
        })?;
    let ecies_key_id = params
        .get("ecies_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams(
                "vault.se_add_recipient_wrap: 'ecies_key_id' required".to_string(),
            )
        })?;
    let wrapped_kek = params
        .get("wrapped_kek")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams(
                "vault.se_add_recipient_wrap: 'wrapped_kek' (hex) required".to_string(),
            )
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| {
                RpcError::InvalidParams(format!(
                    "vault.se_add_recipient_wrap: 'wrapped_kek' bad hex: {e}"
                ))
            })
        })?;

    let (allowed_recipients, add_scope) = match store.data_dir() {
        Some(data_dir) => match crate::infra::identity_substrate::open_identity_store(data_dir) {
            Ok(identity_store) => {
                let st = identity_store.materialized();
                (
                    crate::infra::operator_identity::active_kek_recipient_ecies_key_ids_under_operator_root(st),
                    crate::infra::operator_identity::operator_authority_scope(st),
                )
            }
            Err(e) => {
                return Err(RpcError::Internal(format!(
                    "vault.se_add_recipient_wrap: open identity store: {e}"
                ))
                .into());
            }
        },
        None => (Vec::new(), None),
    };
    if !allowed_recipients.iter().any(|k| k == ecies_key_id) {
        return Err(RpcError::PresenceLocked(format!(
            "vault.se_add_recipient_wrap: ecies_key_id '{ecies_key_id}' is not an \
                 enrolled presence-Device or recovery recipient under the operator root \
                 (ADR 206 §4/§6 AC-7 allowlist = enrolled ∪ recovery); refusing to store \
                 a scope-KEK wrap to a non-enrolled recipient"
        ))
        .into());
    }
    let (scope_kind, scope_id) = add_scope.ok_or_else(|| {
        RpcError::PresenceLocked(
            "vault.se_add_recipient_wrap: no operator-authority scope (no unambiguous \
         operator root); refusing to store a scope-KEK wrap with no scope"
                .to_string(),
        )
    })?;
    store
        .write_presence_scope_kek_wrap(
            &scope_kind,
            &scope_id,
            device_id,
            ecies_key_id,
            &wrapped_kek,
        )
        .map_err(|e| RpcError::Internal(format!("vault.se_add_recipient_wrap: store wrap: {e}")))?;
    Ok(json!({ "status": "recipient_added", "device_id": device_id }))
}

pub(crate) fn handle_se_unlock_begin(store: &DaemonStore) -> Result<Value, (i32, String)> {
    let unlock_scope = match store.data_dir() {
        Some(data_dir) => match crate::infra::identity_substrate::open_identity_store(data_dir) {
            Ok(identity_store) => crate::infra::operator_identity::operator_authority_scope(
                identity_store.materialized(),
            ),
            Err(e) => {
                return Err(RpcError::Internal(format!(
                    "vault.se_unlock_begin: open identity store: {e}"
                ))
                .into());
            }
        },
        None => None,
    };
    let wraps = match unlock_scope {
        Some((scope_kind, scope_id)) => store
            .list_presence_scope_kek_wraps(&scope_kind, &scope_id)
            .map_err(|e| RpcError::Internal(format!("vault.se_unlock_begin: list wraps: {e}")))?,
        None => Vec::new(),
    };
    let wraps_json: Vec<serde_json::Value> = wraps
        .into_iter()
        .map(|(device_id, ecies_key_id, wrapped)| {
            json!({
                "device_id": device_id,
                "ecies_key_id": ecies_key_id,
                "wrapped_kek": hex::encode(&wrapped),
            })
        })
        .collect();
    Ok(json!({ "wraps": wraps_json }))
}

pub(crate) fn handle_se_unlock_complete(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let scope_kek = parse_scope_kek_hex(params, "scope_kek")?;
    crate::infra::interactive_unlock::install_presence_scope_kek_vault(store, *scope_kek)
        .map_err(|e| RpcError::PresenceLocked(format!("vault.se_unlock_complete: install: {e}")))?;
    crate::infra::interactive_unlock::arm_non_session_grace_window();
    crate::trust::presence::mark_unlocked();
    Ok(json!({ "status": "unlocked" }))
}

pub(crate) fn handle_de_provision_begin(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::daemon_wrap_key::DwkPurpose;
    let purpose_str = params
        .get("purpose")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.de_provision_begin: 'purpose' required".to_string())
        })?;
    let purpose = match purpose_str {
        "vault_mek" => DwkPurpose::VaultMek,
        "lease_kek" => DwkPurpose::LeaseKek,
        other => {
            return Err(RpcError::InvalidParams(format!(
                "vault.de_provision_begin: unknown purpose '{other}'"
            ))
            .into());
        }
    };

    let dwk = store.dwk().ok_or_else(|| {
        RpcError::Internal("vault.de_provision_begin: DWK not provisioned".to_string())
    })?;

    let mut raw_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw_key.as_mut()).expect("OS entropy failure");

    let inner_blob = dwk
        .wrap(&*raw_key, purpose)
        .map_err(|e| RpcError::Internal(format!("vault.de_provision_begin: DWK wrap: {e}")))?;

    match purpose {
        DwkPurpose::VaultMek => {
            let vault = crate::infra::vault::finish_open_with_interactive_key_for_de(
                *raw_key,
                store
                    .data_dir()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            );
            match vault {
                Ok(vault) => {
                    store.set_vault(Rc::new(vault));
                    tracing::info!("vault.de_provision_begin: MEK provisioned, vault open");
                }
                Err(e) => {
                    return Err(RpcError::Internal(format!(
                        "vault.de_provision_begin: vault open: {e}"
                    ))
                    .into());
                }
            }
        }
        DwkPurpose::LeaseKek => {
            let lease_kek = crate::trust::lease::LeaseWrapKey::from_raw(*raw_key);
            store.set_lease_kek(lease_kek);
            if let Err(e) = store.rehydrate_persisted_leases(chrono::Utc::now()) {
                tracing::error!(
                    error = %e,
                    "vault.de_provision_begin: lease-KEK installed but \
                     rehydrating persisted leases failed"
                );
            }
            tracing::info!("vault.de_provision_begin: lease-KEK installed (first boot)");
        }
    }

    Ok(json!({
        "inner_blob": hex::encode(&inner_blob),
        "purpose": purpose_str,
    }))
}

pub(crate) fn handle_de_provision_outer(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let outer_blob = params
        .get("outer_blob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams(
                "vault.de_provision_outer: 'outer_blob' (hex) required".to_string(),
            )
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| {
                RpcError::InvalidParams(format!("vault.de_provision_outer: bad hex: {e}"))
            })
        })?;
    let purpose_str = params
        .get("purpose")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams("vault.de_provision_outer: 'purpose' required".to_string())
        })?;

    match purpose_str {
        "vault_mek" => {
            if store.vault().is_some()
                && store.read_double_envelope_outer().ok().flatten().is_some()
            {
                return Err(RpcError::Internal(
                    "vault.de_provision_outer: refusing to overwrite \
                     existing outer blob while vault is open"
                        .to_string(),
                )
                .into());
            }
            store
                .write_double_envelope_outer(&outer_blob)
                .map_err(|e| RpcError::Internal(format!("vault.de_provision_outer: store: {e}")))?;
        }
        "lease_kek" => {
            let outer_present = store
                .read_lease_kek_double_envelope_outer()
                .ok()
                .flatten()
                .is_some();
            if store.lease_kek().is_some() && outer_present {
                return Err(RpcError::Internal(
                    "vault.de_provision_outer: refusing to overwrite \
                     existing lease-KEK outer blob while lease-KEK is active"
                        .to_string(),
                )
                .into());
            }
            store
                .write_lease_kek_double_envelope_outer(&outer_blob)
                .map_err(|e| RpcError::Internal(format!("vault.de_provision_outer: store: {e}")))?;
        }
        other => {
            return Err(RpcError::InvalidParams(format!(
                "vault.de_provision_outer: unknown purpose '{other}'"
            ))
            .into());
        }
    }

    tracing::info!(
        purpose = purpose_str,
        "vault.de_provision_outer: outer blob stored"
    );
    Ok(json!({
        "status": "provisioned",
        "purpose": purpose_str,
    }))
}

pub(crate) fn handle_de_unlock_begin(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let purpose_str = params
        .get("purpose")
        .and_then(|v| v.as_str())
        .unwrap_or("vault_mek");

    let outer_blob = match purpose_str {
        "vault_mek" => store
            .read_double_envelope_outer()
            .map_err(|e| RpcError::Internal(format!("vault.de_unlock_begin: read: {e}")))?,
        "lease_kek" => store.read_lease_kek_double_envelope_outer().map_err(|e| {
            RpcError::Internal(format!("vault.de_unlock_begin: read lease_kek: {e}"))
        })?,
        other => {
            return Err(RpcError::InvalidParams(format!(
                "vault.de_unlock_begin: unknown purpose '{other}'"
            ))
            .into());
        }
    };

    match outer_blob {
        Some(blob) => Ok(json!({
            "outer_blob": hex::encode(&blob),
            "status": "locked",
            "purpose": purpose_str,
        })),
        None => Ok(json!({
            "status": "unprovisioned",
            "purpose": purpose_str,
        })),
    }
}

pub(crate) fn handle_de_unlock_complete(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::daemon_wrap_key::DwkPurpose;
    let inner_blob = params
        .get("inner_blob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RpcError::InvalidParams(
                "vault.de_unlock_complete: 'inner_blob' (hex) required".to_string(),
            )
        })
        .and_then(|h| {
            hex::decode(h).map_err(|e| {
                RpcError::InvalidParams(format!("vault.de_unlock_complete: bad hex: {e}"))
            })
        })?;

    let purpose_str = params
        .get("purpose")
        .and_then(|v| v.as_str())
        .unwrap_or("vault_mek");

    let dwk_purpose = match purpose_str {
        "vault_mek" => DwkPurpose::VaultMek,
        "lease_kek" => DwkPurpose::LeaseKek,
        other => {
            return Err(RpcError::InvalidParams(format!(
                "vault.de_unlock_complete: unknown purpose '{other}'"
            ))
            .into());
        }
    };

    let dwk = store.dwk().ok_or_else(|| {
        RpcError::Internal("vault.de_unlock_complete: DWK not provisioned".to_string())
    })?;

    let raw_key = dwk.unwrap(&inner_blob, dwk_purpose).map_err(|e| {
        RpcError::PresenceLocked(format!("vault.de_unlock_complete: DWK unwrap: {e}"))
    })?;
    if raw_key.len() != 32 {
        return Err(RpcError::PresenceLocked(format!(
            "vault.de_unlock_complete: unwrapped key is {} bytes, expected 32",
            raw_key.len()
        ))
        .into());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&raw_key);

    match dwk_purpose {
        DwkPurpose::VaultMek => {
            let data_dir = store
                .data_dir()
                .unwrap_or_else(|| std::path::Path::new("."));
            let vault =
                crate::infra::vault::finish_open_with_interactive_key_for_de(*key, data_dir)
                    .map_err(|e| {
                        RpcError::PresenceLocked(format!(
                            "vault.de_unlock_complete: vault open: {e}"
                        ))
                    })?;

            let vault = Rc::new(vault);
            vault.verify_canary(store).map_err(|e| {
                RpcError::PresenceLocked(format!(
                    "vault.de_unlock_complete: canary verification failed \
                         (wrong MEK / corrupt double-envelope): {e}"
                ))
            })?;
            store.set_vault(vault);
            crate::trust::presence::mark_unlocked();
            tracing::info!("vault.de_unlock_complete: vault unlocked via double-envelope");

            load_bridge_ca_if_ready(store);
        }
        DwkPurpose::LeaseKek => {
            let lease_kek = crate::trust::lease::LeaseWrapKey::from_raw(*key);
            store.set_lease_kek(lease_kek);
            if let Err(e) = store.rehydrate_persisted_leases(chrono::Utc::now()) {
                tracing::error!(
                    error = %e,
                    "vault.de_unlock_complete: lease-KEK installed but \
                     rehydrating persisted leases failed"
                );
            }
            tracing::info!("vault.de_unlock_complete: lease-KEK installed via double-envelope");

            load_bridge_ca_if_ready(store);
        }
    }

    Ok(json!({
        "status": "unlocked",
        "purpose": purpose_str,
    }))
}

fn load_bridge_ca_if_ready(store: &DaemonStore) {
    if store.bridge_ca().is_some() {
        return;
    }
    if store.lease_kek().is_none() {
        return;
    }
    let Some(vault_ref) = store.vault() else {
        return;
    };
    let data_dir = store
        .data_dir()
        .unwrap_or_else(|| std::path::Path::new("."));
    match crate::infra::runtime::load_or_mint_bridge_ca(data_dir, &vault_ref) {
        Ok(ca) => {
            store.set_bridge_ca_fingerprint(ca.fingerprint());
            store.set_bridge_ca(ca);
            tracing::info!(
                "vault.de_unlock_complete: bridge CA loaded \
                 after vault + lease-KEK unlock"
            );
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "vault.de_unlock_complete: bridge CA load failed"
            );
        }
    }
}

pub(crate) fn handle_status(store: &DaemonStore) -> Result<Value, (i32, String)> {
    // P13-S3 intentionally-global ConnectOnly diagnostic: live-vault /
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
    // ADR 198 D1: surface the monotonic MEK-rotation epoch even while locked.
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
