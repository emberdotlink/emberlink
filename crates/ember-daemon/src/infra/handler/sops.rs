use serde_json::{Value, json};

use crate::infra::receipt::persist_vault_biometric_receipt;
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::trust::presence;

#[cfg(feature = "age")]
use crate::infra::vault::{VaultError, VaultReadGate, VaultScope};
#[cfg(feature = "age")]
use core_grants::GrantState as CoreGrantState;

use super::{current_vault, enforce_fresh_presence_proof_with_audit};

// TZ-SOPS-1B-IMPL Phase 2: SOPS DEK unwrap RPC.
//
// Authorisation flow:
//   1. Caller supplies `persona_id`, `grant_id`, and the hex-encoded
//      `encrypted_dek_blob`.
//   2. The grant is looked up; it MUST be active and belong to `persona_id`
//      (mirrors `use_credential`'s guard).
//   3. The grant is rate-limited: one successful unwrap per grant_id per
//      daemon-process lifetime. Second call with the same `grant_id` is
//      rejected loudly. The check happens AFTER successful grant validation but
//      BEFORE invoking the age library, so a stale duplicate request never even
//      causes a decrypt attempt.
//   4. ADR 211 leased authority: the unwrap runs only while the grant has a
//      live lease key in `LeaseRegistry`. An active grant with no live lease is
//      an inert identity and cannot even reach vault crypto.
//   5. The persona's age private key is fetched from the daemon vault at
//      `age/persona/<persona_id>/private-key` (per
//      `crate::age::vault_path_for_persona`). The key bytes live in a
//      `Zeroizing` buffer; they never cross the IPC boundary.
//   6. `sops::unwrap_dek_userspace` decrypts the blob in-process (the function
//      takes `&[u8]` and returns `Zeroizing<Vec<u8>>` — the plaintext DEK). The
//      age private key is dropped at the end of that function call.
//   7. A `sops_dek_unwrapped` audit event is logged with `persona_id` +
//      `dek_fingerprint` + `grant_id` so the operator can reconstruct the
//      unwrap chain.
//   8. The plaintext DEK is hex-encoded into the JSON response, then the
//      `Zeroizing` buffer is dropped (which zeroes the underlying bytes). The
//      hex string in the JSON is sent to the caller; whoever calls this RPC is
//      implicitly trusted with the plaintext DEK by the grant flow.
//
// Phase 3 (TZ-SOPS-1-WRAPPER, orchestrator-only) ships
// `.claude/scripts/sops-as-bot.sh` — the only blessed agent path that calls
// this RPC. Direct callers from the agent harness are out of scope for v0.
#[cfg(feature = "age")]
pub fn handle_unwrap_dek(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Read-class on the user's view but high-trust on the daemon's — bump
    // activity so the vault stays unlocked, but do NOT gate behind biometric
    // (the wrapper script is expected to run unattended in CI/dev loops).
    presence::record_activity();

    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
    let grant_id = params["grant_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'grant_id'".to_string()))?;
    let blob_hex = params["encrypted_dek_blob"].as_str().ok_or_else(|| {
        RpcError::InvalidParams("missing 'encrypted_dek_blob' (hex string)".to_string())
    })?;

    // Decode the hex-encoded ciphertext blob. Reject malformed input loudly so
    // a typo doesn't get smuggled into the age decryptor where the error
    // message is harder to map back.
    let encrypted_dek_blob = hex::decode(blob_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid 'encrypted_dek_blob' hex: {e}")))?;

    // Grant gating: load via DaemonGrantStore to get core_grants::Grant at the
    // state-machine boundary (GRANT-SM-PHASE-C-3A). State and issuer checks use
    // the core type directly.
    let grant = store
        .grant_store()
        .load_grant(grant_id)
        .map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                RpcError::NotFound(format!("grant {grant_id} not found"))
            }
            other => RpcError::Internal(other.to_string()),
        })?;
    if grant.state != CoreGrantState::Active {
        return Err(RpcError::Conflict(format!(
            "grant {grant_id} is not active and cannot be used"
        ))
        .into());
    }
    if grant.issuer.0 != persona_id {
        return Err(RpcError::GrantOwnershipMismatch(
            "grant belongs to a different persona".to_string(),
        )
        .into());
    }

    // Rate-limit: one **successful** unwrap per grant_id per daemon lifetime. We
    // check membership before doing any crypto work so a known-consumed grant is
    // rejected fast, but we don't CLAIM the slot until after the unwrap succeeds
    // — failures along the vault / decrypt path leave the slot open so the
    // caller can retry once they fix the setup. The daemon's single-threaded
    // LocalSet means there's no TOCTOU window between this check and the claim
    // below.
    if store.is_dek_grant_consumed(grant_id) {
        tracing::warn!(
            grant_id = %grant_id,
            persona_id = %persona_id,
            "rejecting duplicate sops_unwrap_dek call for already-consumed grant"
        );
        return Err(RpcError::Conflict(format!(
            "grant {grant_id} has already been used for a SOPS DEK unwrap; \
                 issue a fresh grant"
        ))
        .into());
    }

    // Compute the dek fingerprint BEFORE the unwrap call so the audit row is
    // emitted regardless of decrypt outcome — the failure path also needs the
    // fingerprint for forensics.
    let dek_fingerprint: String = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&encrypted_dek_blob);
        hex::encode(&digest[..16])
    };

    let lease_now = chrono::Utc::now();
    let plaintext_dek = match store
        .leases()
        .with_lease_key(grant_id, lease_now, |lease_key| {
            debug_assert_eq!(lease_key.as_bytes().len(), 32);

            // Load the persona's age private key from the daemon vault. The key
            // bytes live in a `Zeroizing` buffer so they zero on drop — never
            // log them, never serialize them.
            let vault_path = crate::age::vault_path_for_persona(persona_id);
            let vault = current_vault(store, "sops_unwrap_dek")?;
            let mut biometric_audit = None;
            let read_gate = match vault.credential_presence_policy(
                VaultScope::Interactive,
                store,
                &vault_path,
            ) {
                Ok(policy) if policy.requires_fresh_presence() => {
                    biometric_audit = Some(enforce_fresh_presence_proof_with_audit(
                        store,
                        "sops_unwrap_dek",
                        params,
                    )?);
                    VaultReadGate::FreshPresence
                }
                Ok(_lane_default) => VaultReadGate::CachedUnlockOnly,
                Err(e) => {
                    tracing::warn!(
                        persona_id = %persona_id,
                        vault_path = %vault_path,
                        error = %e,
                        "sops_unwrap_dek: persona age key not in vault"
                    );
                    let err: (i32, String) = RpcError::Internal(format!(
                        "persona {persona_id} has no age private key in the vault \
                             (expected at {vault_path})"
                    ))
                    .into();
                    return Err(err);
                }
            };
            let raw_key = vault
                .get_with_read_gate(VaultScope::Interactive, store, &vault_path, read_gate)
                .map_err(|e| {
                    if matches!(e, VaultError::PresenceRequired) {
                        return (
                            -32030,
                            "sops_unwrap_dek requires a fresh presence-Device signature"
                                .to_string(),
                        );
                    }
                    tracing::warn!(
                        persona_id = %persona_id,
                        vault_path = %vault_path,
                        error = %e,
                        "sops_unwrap_dek: persona age key not in vault"
                    );
                    let err: (i32, String) = RpcError::Internal(format!(
                        "persona {persona_id} has no age private key in the vault \
                         (expected at {vault_path})"
                    ))
                    .into();
                    err
                })?;
            if let Some(audit) = biometric_audit.as_ref()
                && let Err(e) = persist_vault_biometric_receipt(
                    store,
                    &vault_path,
                    persona_id,
                    "sops_unwrap_dek",
                    Some(grant_id),
                    &audit.presence_authenticator_id,
                    &audit.public_key_hash(),
                )
            {
                tracing::warn!(
                    error = %e,
                    persona_id = %persona_id,
                    vault_path = %vault_path,
                    grant_id = %grant_id,
                    "sops_unwrap_dek: failed to persist biometric vault-read receipt"
                );
            }
            let age_private_key = raw_key;

            // Invoke the pure unwrap function while the live lease key is
            // borrowed. Plaintext lives in a `Zeroizing<Vec<u8>>`; it will be
            // zeroed when the caller serializes the response and drops it.
            crate::sops::unwrap_dek_userspace(&age_private_key, &encrypted_dek_blob).map_err(|e| {
                // Audit the failure. The grant slot is NOT consumed on failure
                // — the caller can retry once they fix the setup (e.g. wrong age
                // key, truncated blob).
                let _ = store.log_event(
                    Some(persona_id),
                    "sops_dek_unwrapped",
                    None,
                    "denied",
                    Some(
                        &serde_json::json!({
                            "grant_id": grant_id,
                            "dek_fingerprint": dek_fingerprint,
                            "error": e.to_string(),
                        })
                        .to_string(),
                    ),
                );
                RpcError::Internal(format!("dek unwrap failed: {e}")).into()
            })
        }) {
        Some(Ok(dek)) => dek,
        Some(Err(e)) => return Err(e),
        None => {
            tracing::warn!(
                grant_id = %grant_id,
                persona_id = %persona_id,
                "rejecting sops_unwrap_dek for active grant with no live leased authority"
            );
            return Err(RpcError::Conflict(format!(
                "grant {grant_id} has no live leased authority; persona is inert for this grant"
            ))
            .into());
        }
    };

    // Claim the rate-limit slot now that the unwrap succeeded. The pre-check
    // above already guaranteed the slot was open when we entered the handler,
    // and the daemon's single-threaded LocalSet means no other dispatch can have
    // raced in between. `try_consume_dek_grant` returning `false` here is
    // therefore a programmer error.
    let claimed = store.try_consume_dek_grant(grant_id);
    debug_assert!(
        claimed,
        "try_consume_dek_grant returned false after a passing pre-check; \
         this indicates a concurrency invariant violation"
    );

    // Receipt: log_event captures op + persona_id + dek_fingerprint + grant_id
    // + ts (the audit row's own timestamp). Never log the plaintext DEK or the
    // ciphertext blob — only the fingerprint.
    let _ = store.log_event(
        Some(persona_id),
        "sops_dek_unwrapped",
        None,
        "allowed",
        Some(
            &serde_json::json!({
                "grant_id": grant_id,
                "dek_fingerprint": dek_fingerprint,
            })
            .to_string(),
        ),
    );

    // Serialize the plaintext DEK as hex. The `Zeroizing` buffer is dropped
    // immediately after — the hex string we return is the only remaining copy
    // outside the caller's process.
    let dek_hex = hex::encode(plaintext_dek.as_slice());
    drop(plaintext_dek);

    tracing::info!(
        persona_id = %persona_id,
        grant_id = %grant_id,
        dek_fingerprint = %dek_fingerprint,
        "sops_dek_unwrapped"
    );

    Ok(json!({
        "dek_hex": dek_hex,
        "dek_fingerprint": dek_fingerprint,
        "grant_id": grant_id,
        "persona_id": persona_id,
    }))
}

// Stub when the `age` feature is disabled at compile time. Mirror the
// `crate::sops::unwrap_dek_userspace` cfg-not(age) error so the wire surface
// fails loudly instead of silently returning `Method not found` (which would be
// misleading — the method IS configured, just not built).
#[cfg(not(feature = "age"))]
pub fn handle_unwrap_dek(_store: &DaemonStore, _params: &Value) -> Result<Value, (i32, String)> {
    Err(RpcError::Internal(
        "sops_unwrap_dek requires the 'age' feature; build with --features age".to_string(),
    )
    .into())
}

pub fn handle_pubkey(params: &Value) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    let pubkey =
        crate::sops::sops_pubkey(persona_id).map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({"persona_id": persona_id, "pubkey": pubkey}))
}

pub fn handle_wrap(params: &Value) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    let dek_hex = params["dek_hex"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'dek_hex' parameter".to_string()))?;
    let dek = hex::decode(dek_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid 'dek_hex': {e}")))?;
    let encrypted = crate::sops::sops_wrap_dek(persona_id, &dek)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({
        "persona_id": persona_id,
        "encrypted_dek_hex": hex::encode(&encrypted),
    }))
}

pub fn handle_unwrap(params: &Value) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id' parameter".to_string()))?;
    let encrypted_hex = params["encrypted_dek_hex"].as_str().ok_or_else(|| {
        RpcError::InvalidParams("missing 'encrypted_dek_hex' parameter".to_string())
    })?;
    let encrypted = hex::decode(encrypted_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid 'encrypted_dek_hex': {e}")))?;
    let dek = crate::sops::sops_unwrap_in_vault(persona_id, &encrypted)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    Ok(json!({
        "persona_id": persona_id,
        "dek_hex": hex::encode(&dek),
    }))
}
