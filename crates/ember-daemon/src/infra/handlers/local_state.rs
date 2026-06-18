//! Local-state key RPC helpers for the launcher-facing `local_state_key_*`
//! methods.
//! CLASSIFICATION: PUBLIC

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::infra::handlers::support::local_state_vault_name;
use crate::infra::{
    handler::{DispatchSource, PeerCred, RequestContext, current_vault},
    store::DaemonStore,
    vault::VaultScope,
};
use crate::trust::presence;
use core_events::receipt::{
    LocalStateKeyResolveBody, LocalStateKeyRotationBody, RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
    RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
};

pub(crate) fn handle_key_get(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let caller = params["caller"]
        .as_str()
        .ok_or((-32602, "missing 'caller'".to_string()))?;
    let peer = enforce_local_state_gate(
        source,
        ctx.peer,
        caller,
        store,
        ctx.bypass_binary_pin_gate_for_test,
    )?;
    let vault_namespace = local_state_vault_name(caller)?;

    presence::record_activity();
    let vault = current_vault(store, "local_state_key_get")?;

    // N6: key_string is held as Zeroizing<String> so the local-state content
    // key zeroizes on drop. The Ok-arm wraps the bare String produced from
    // vault.get bytes; the Err-arm receives the already-Zeroizing return of
    // generate_content_key. The JSON serialization below moves through
    // serde_json::Value::String which DOES heap-clone the bytes — that ride
    // out of the daemon is unavoidable here; the local heap copy is what
    // this fix zeroizes.
    let (key_string, resolved_or_generated): (Zeroizing<String>, &'static str) =
        match vault.get(VaultScope::Interactive, store, &vault_namespace) {
            Ok(bytes) => {
                let s = String::from_utf8(bytes.to_vec()).map_err(|e| {
                    (
                        -32000,
                        format!("local_state_key_get: stored key is not valid UTF-8: {e}"),
                    )
                })?;
                (Zeroizing::new(s), "resolved")
            }
            Err(crate::infra::vault::VaultError::NotFound) => {
                let key = core_crypto::generate_content_key("local-state");
                vault
                    .add(
                        VaultScope::Interactive,
                        store,
                        &vault_namespace,
                        key.as_bytes(),
                        None,
                    )
                    .map_err(|e| (-32000, format!("local_state_key_get: vault.add: {e}")))?;
                (key, "generated")
            }
            Err(e) => return Err((-32000, e.to_string())),
        };

    // ADR 133 §76-78: local_state.key_resolve is WITHDRAWN from the canonical
    // Receipt lane — these are local daemon/operator plumbing events, not
    // durable signed authority artifacts. Emit an immutable audit row instead
    // of minting a signed v2 receipt. The LocalStateKeyResolveBody is retained
    // as the typed audit-detail shape. (Sweep 3 finding D2.)
    let body = LocalStateKeyResolveBody {
        peer_uid: peer.uid,
        caller: caller.to_string(),
        vault_namespace: vault_namespace.clone(),
        resolved_or_generated: resolved_or_generated.to_string(),
    };
    if let Err(e) = store.log_event(
        None,
        RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
        Some(&vault_namespace),
        resolved_or_generated,
        serde_json::to_string(&body).ok().as_deref(),
    ) {
        tracing::warn!(
            caller = %caller,
            vault_namespace = %vault_namespace,
            error = %e,
            "local_state.key_resolve: audit-row emission failed — work still committed"
        );
    }

    Ok(json!({
        // N6: borrow as &str (via Deref) so we don't move the inner String
        // out of Zeroizing. json! will heap-clone the bytes into a Value;
        // when key_string drops at the end of the scope, the local zeroizes.
        "key": key_string.as_str(),
        "vault_namespace": vault_namespace,
        "resolved_or_generated": resolved_or_generated,
    }))
}

pub(crate) fn handle_key_set(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let caller = params["caller"]
        .as_str()
        .ok_or((-32602, "missing 'caller'".to_string()))?;
    let peer = enforce_local_state_gate(
        source,
        ctx.peer,
        caller,
        store,
        ctx.bypass_binary_pin_gate_for_test,
    )?;
    let key = params["key"]
        .as_str()
        .ok_or((-32602, "missing 'key'".to_string()))?;
    let force = params["force"].as_bool().unwrap_or(false);
    let vault_namespace = local_state_vault_name(caller)?;

    presence::record_activity();
    let vault = current_vault(store, "local_state_key_set")?;

    let already_set = vault
        .get(VaultScope::Interactive, store, &vault_namespace)
        .is_ok();
    let outcome = if already_set {
        if force {
            vault
                .replace(
                    VaultScope::Interactive,
                    store,
                    &vault_namespace,
                    key.as_bytes(),
                    None,
                )
                .map_err(|e| (-32000, format!("local_state_key_set: vault.replace: {e}")))?;
            tracing::info!(
                caller = %caller,
                vault_namespace = %vault_namespace,
                peer_uid = peer.uid,
                "local_state_key_set: force-overwrote existing key"
            );
            "overwritten"
        } else {
            tracing::info!(
                caller = %caller,
                vault_namespace = %vault_namespace,
                peer_uid = peer.uid,
                "local_state_key_set: no-op (already set, force=false)"
            );
            "noop_existing"
        }
    } else {
        vault
            .add(
                VaultScope::Interactive,
                store,
                &vault_namespace,
                key.as_bytes(),
                None,
            )
            .map_err(|e| (-32000, format!("local_state_key_set: vault.add: {e}")))?;
        tracing::info!(
            caller = %caller,
            vault_namespace = %vault_namespace,
            peer_uid = peer.uid,
            "local_state_key_set: stored key in vault"
        );
        "stored"
    };
    Ok(json!({
        "vault_namespace": vault_namespace,
        "already_set": already_set,
        "outcome": outcome,
        "overwritten": outcome == "overwritten",
    }))
}

pub(crate) fn handle_key_rotate_and_reencrypt(
    store: &DaemonStore,
    ctx: &RequestContext,
    source: &DispatchSource,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let caller = params["caller"]
        .as_str()
        .ok_or((-32602, "missing 'caller'".to_string()))?;
    let peer = enforce_local_state_gate(
        source,
        ctx.peer,
        caller,
        store,
        ctx.bypass_binary_pin_gate_for_test,
    )?;
    let ciphertext_value = params["ciphertext"].as_array().ok_or((
        -32602,
        "missing 'ciphertext' (expected JSON array of bytes)".to_string(),
    ))?;
    let ciphertext: Vec<u8> = ciphertext_value
        .iter()
        .map(|v| v.as_u64().map(|n| n as u8).ok_or(()))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| {
            (
                -32602,
                "'ciphertext' must be an array of u8 byte values".to_string(),
            )
        })?;
    let vault_namespace = local_state_vault_name(caller)?;
    presence::record_activity();
    let vault = current_vault(store, "local_state_key_rotate_and_reencrypt")?;

    let old_key_bytes = vault
        .get(VaultScope::Interactive, store, &vault_namespace)
        .map_err(|e| {
            (
                -32000,
                format!("local_state_key_rotate_and_reencrypt: vault.get: {e}"),
            )
        })?;
    // N6: hold old_key as Zeroizing<String> so the local-state content key
    // zeroizes on drop. The bare String produced from utf8-decoded bytes is
    // wrapped at receipt.
    let old_key: Zeroizing<String> =
        Zeroizing::new(String::from_utf8(old_key_bytes.to_vec()).map_err(|e| {
            (
                -32000,
                format!("local_state_key_rotate_and_reencrypt: stored key is not valid UTF-8: {e}"),
            )
        })?);

    if ciphertext.len() < 24 {
        return Err((
            -32602,
            "ciphertext too short (need 24-byte nonce prefix)".to_string(),
        ));
    }
    let (nonce_bytes, ct_and_tag) = ciphertext.split_at(24);
    let encrypted = core_crypto::EncryptedContent {
        nonce_hex: core_types::bytes_to_hex(nonce_bytes),
        ciphertext: ct_and_tag.to_vec(),
    };
    let plaintext = core_crypto::decrypt_content(&old_key, &encrypted, b"emberlink-local-state")
        .map_err(|e| {
            (
                -32000,
                format!("local_state_key_rotate_and_reencrypt: decrypt: {e}"),
            )
        })?;

    let new_key = core_crypto::generate_content_key("local-state");
    let new_encrypted =
        core_crypto::encrypt_content(&new_key, &plaintext, b"emberlink-local-state").map_err(
            |e| {
                (
                    -32000,
                    format!("local_state_key_rotate_and_reencrypt: encrypt: {e}"),
                )
            },
        )?;
    let new_nonce_bytes = core_types::hex_to_bytes(&new_encrypted.nonce_hex).map_err(|e| {
        (
            -32000,
            format!("local_state_key_rotate_and_reencrypt: nonce hex decode: {e}"),
        )
    })?;
    let mut new_ciphertext =
        Vec::with_capacity(new_nonce_bytes.len() + new_encrypted.ciphertext.len());
    new_ciphertext.extend_from_slice(&new_nonce_bytes);
    new_ciphertext.extend_from_slice(&new_encrypted.ciphertext);

    let old_key_hash = blake3::hash(old_key.as_bytes()).to_hex().to_string();
    let new_key_hash = blake3::hash(new_key.as_bytes()).to_hex().to_string();

    vault
        .replace(
            VaultScope::Interactive,
            store,
            &vault_namespace,
            new_key.as_bytes(),
            None,
        )
        .map_err(|e| {
            (
                -32000,
                format!("local_state_key_rotate_and_reencrypt: vault.replace: {e}"),
            )
        })?;

    // ADR 133 §76-78: local_state.key_rotation is WITHDRAWN from the Receipt
    // lane — emit an immutable audit row, not a signed v2 receipt. The
    // LocalStateKeyRotationBody is retained as the typed audit-detail shape.
    // (Sweep 3 finding D2.)
    let body = LocalStateKeyRotationBody {
        peer_uid: peer.uid,
        caller: caller.to_string(),
        vault_namespace: vault_namespace.clone(),
        old_key_hash: format!("blake3:{old_key_hash}"),
        new_key_hash: format!("blake3:{new_key_hash}"),
    };
    if let Err(e) = store.log_event(
        None,
        RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
        Some(&vault_namespace),
        "rotated",
        serde_json::to_string(&body).ok().as_deref(),
    ) {
        tracing::warn!(
            caller = %caller,
            vault_namespace = %vault_namespace,
            error = %e,
            "local_state.key_rotation: audit-row emission failed — work still committed"
        );
    }

    Ok(json!({
        "ciphertext": new_ciphertext,
        "vault_namespace": vault_namespace,
    }))
}

fn enforce_local_state_gate(
    source: &DispatchSource,
    peer: Option<PeerCred>,
    caller: &str,
    store: &DaemonStore,
    bypass_for_test: bool,
) -> Result<PeerCred, (i32, String)> {
    #[cfg(test)]
    {
        let _ = (source, caller, store, bypass_for_test);
        return Ok(peer.unwrap_or(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }));
    }
    #[cfg(not(test))]
    {
        if bypass_for_test {
            return Ok(peer.unwrap_or(PeerCred {
                uid: 501,
                pid: Some(std::process::id() as i32),
            }));
        }
        if source.is_internal() {
            return Err((
                -32401,
                "local_state_key_* is wire-only; refuse Internal dispatch".to_string(),
            ));
        }
        let peer = peer.ok_or((
            -32401,
            "peer credentials unavailable — local_state_key_* requires kernel-attested uid"
                .to_string(),
        ))?;

        let identity = crate::infra::receipt::current_identity().ok_or((
            -32000,
            "daemon identity not initialised — cannot verify binary-pin manifest".to_string(),
        ))?;
        let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());

        let vault = current_vault(store, "local_state_key_*")?;
        let manifest_opt = crate::infra::binary_pin::load_manifest(&vault, store, &pubkey_str)
            .map_err(|e| (-32000, format!("binary-pin manifest load failed: {e}")))?;
        let manifest = manifest_opt.ok_or((
            -32401,
            "binary-pin manifest is not enrolled — run `ember binary-pin generate` to authorize \
         the ember binaries on this machine"
                .to_string(),
        ))?;

        crate::infra::binary_pin::verify_peer_against_manifest(peer.pid, caller, &manifest)
            .map_err(|e| match e {
                crate::infra::binary_pin::BinaryPinError::PeerPidUnavailable => (
                    -32401,
                    "peer pid unavailable — cannot verify binary identity".to_string(),
                ),
                crate::infra::binary_pin::BinaryPinError::PeerBinaryPathUnavailable { pid } => (
                    -32401,
                    format!(
                        "peer binary path unavailable for pid {pid} (platform unsupported or lookup failed)"
                    ),
                ),
                crate::infra::binary_pin::BinaryPinError::NoPinForCaller { caller } => (
                    -32401,
                    format!(
                        "no binary pin enrolled for caller {caller:?} — run `ember binary-pin generate`"
                    ),
                ),
                crate::infra::binary_pin::BinaryPinError::HashMismatch { expected, actual } => (
                    -32401,
                    format!(
                        "peer binary content-hash mismatch: pinned {expected}, peer-actual {actual}"
                    ),
                ),
                other => (-32000, format!("binary-pin verification failed: {other}")),
            })?;

        Ok(peer)
    }
}
