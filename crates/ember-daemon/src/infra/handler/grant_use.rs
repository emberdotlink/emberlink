use serde_json::{Value, json};

use crate::infra::receipt::persist_vault_biometric_receipt;
use crate::infra::rpc_error::RpcError;
use crate::infra::store::DaemonStore;
use crate::infra::vault::{VaultError, VaultReadGate, VaultScope};
use crate::trust::presence;

use super::{current_vault, enforce_fresh_presence_proof_with_audit};

pub(super) fn handle_use_credential(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // Read-class: bump session activity so an active agent keeps
    // the vault unlocked, but do not prompt for biometric on every
    // credential read.
    presence::record_activity();

    // Two calling conventions:
    //   1. `{persona_id, credential_name}` - classic vault lookup.
    //   2. `{grant_id, persona_id?}` - agent runtime flow. Looks up
    //      the grant by id and derives persona+credential from it.
    //      When the caller also supplies `persona_id`, it MUST match
    //      the grant's persona. This prevents grant-id guessing
    //      cross-persona reads via a leaked id.
    //
    // TODO: GrantInfo retained for use_credential resolved_grant:
    // grant.id, grant.scope, and grant.credential_name are not present
    // in core_grants::Grant. State/issuer checks already use core_grants
    // (migrated in PHASE-C-3A). Full migration requires adding
    // credential_name to core_grants::Grant or a dedicated lookup helper.
    let (persona_id, credential_name, resolved_grant): (
        String,
        String,
        Option<crate::trust::grant::GrantInfo>,
    ) = if let Some(grant_id) = params["grant_id"].as_str() {
        // Load core_grants::Grant for state-machine checks (GRANT-SM-PHASE-C-3A).
        let core_grant = store
            .grant_store()
            .load_grant(grant_id)
            .map_err(|e| match e {
                crate::infra::store::StoreError::NotFound => {
                    RpcError::NotFound(format!("grant {grant_id} not found"))
                }
                other => RpcError::Internal(other.to_string()),
            })?;
        if core_grant.state != core_grants::GrantState::Active {
            return Err(RpcError::Conflict(format!(
                "grant {grant_id} is not active and cannot be used"
            ))
            .into());
        }
        if let Some(caller_persona) = params["persona_id"].as_str()
            && caller_persona != core_grant.issuer.0
        {
            return Err(RpcError::GrantOwnershipMismatch(
                "grant belongs to a different persona".to_string(),
            )
            .into());
        }

        let grant = store.get_grant(grant_id).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => {
                RpcError::NotFound(format!("grant {grant_id} not found"))
            }
            other => RpcError::Internal(other.to_string()),
        })?;

        // DEMO-MAY3-COMPOSITE-MULTI-CRED: when the caller passes
        // both grant_id AND credential_name, honor the caller's
        // value if it's bound to a Credential Statement on the
        // grant's chain. Composite grants carry multiple
        // credential statements (e.g. anthropic-key + github-token);
        // returning grant.credential_name unconditionally would
        // hand back the grant's primary cred regardless of what
        // the caller asked for, breaking per-statement isolation.
        let resolved_cred_name = if let Some(caller_cred) = params["credential_name"].as_str() {
            let chain = store
                .get_access_grant(&grant.id)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            let bound = chain.statements().any(|(_idx, stmt)| {
                stmt.resource_type == core_grant_types::ResourceType::Credential
                    && match &stmt.resource {
                        core_grant_types::ResourceSelector::Exact { value } => value == caller_cred,
                        _ => false,
                    }
            });
            if !bound {
                return Err(RpcError::CredentialNotBound(format!(
                    "credential '{caller_cred}' is not bound to any statement on grant {}",
                    grant.id
                ))
                .into());
            }
            caller_cred.to_string()
        } else {
            grant.credential_name.clone()
        };
        (grant.persona_id.clone(), resolved_cred_name, Some(grant))
    } else {
        let persona_id = params["persona_id"]
            .as_str()
            .ok_or_else(|| RpcError::InvalidParams("missing 'persona_id'".to_string()))?;
        let credential_name = params["credential_name"]
            .as_str()
            .ok_or_else(|| RpcError::InvalidParams("missing 'credential_name'".to_string()))?;
        (persona_id.to_string(), credential_name.to_string(), None)
    };

    // Check grant exists and is active (redundant for the grant_id
    // branch but cheap; preserves single-path-through-evaluate
    // semantics for the classic branch).
    let grant = if let Some(g) = resolved_grant {
        g
    } else {
        store
            .evaluate_grant(&persona_id, &credential_name)
            .map_err(|e| RpcError::Internal(format!("no active grant: {e}")))?
    };

    // DEMO-MAY3-COMPOSITE-PER-STMT-REVOKE: block credential reads
    // when the Credential Statement that authorizes this specific
    // credential_name has been revoked. The previous shape blocked
    // all credential reads if any credential statement was revoked,
    // collapsing per-statement isolation; composite grants need
    // each credential statement to fail independently.
    let revoked_sids = store
        .get_revoked_sids(&grant.id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    if !revoked_sids.is_empty()
        && let Ok(chain) = store.get_access_grant(&grant.id)
    {
        for (_idx, stmt) in chain.statements() {
            let matches_this_credential = stmt.resource_type
                == core_grant_types::ResourceType::Credential
                && match &stmt.resource {
                    core_grant_types::ResourceSelector::Exact { value } => {
                        value == &credential_name
                    }
                    _ => false,
                };
            if matches_this_credential && revoked_sids.contains(&stmt.sid) {
                let _ = store.log_event(
                    Some(&persona_id),
                    "credential.access",
                    Some(&credential_name),
                    "denied_statement_revoked",
                    Some(&format!("grant_id={} sid={}", grant.id, stmt.sid)),
                );
                return Err(RpcError::StatementRevoked.into());
            }
        }
    }

    let vault = current_vault(store, "use_credential")?;
    let mut biometric_audit = None;
    let read_gate =
        match vault.credential_presence_policy(VaultScope::Interactive, store, &credential_name)
        {
            Ok(policy) if policy.requires_fresh_presence() => {
                biometric_audit = Some(enforce_fresh_presence_proof_with_audit(
                    store,
                    "use_credential",
                    params,
                )?);
                VaultReadGate::FreshPresence
            }
            Ok(_lane_default) => VaultReadGate::CachedUnlockOnly,
            Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
        };
    let value = vault
        .get_with_read_gate(VaultScope::Interactive, store, &credential_name, read_gate)
        .map_err(|e| match e {
            VaultError::PresenceRequired => (
                -32030,
                "use_credential requires a fresh presence-Device signature".to_string(),
            ),
            other => RpcError::Internal(other.to_string()).into(),
        })?;
    if let Some(audit) = biometric_audit.as_ref()
        && let Err(e) = persist_vault_biometric_receipt(
            store,
            &credential_name,
            &persona_id,
            "use_credential",
            Some(&grant.id),
            &audit.presence_authenticator_id,
            &audit.public_key_hash(),
        )
    {
        tracing::warn!(
            error = %e,
            key_name = %credential_name,
            grant_id = %grant.id,
            "use_credential: failed to persist biometric vault-read receipt"
        );
    }
    store
        .record_grant_usage(&grant.id)
        .map_err(|e| RpcError::Internal(e.to_string()))?;
    let _ = store.log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        None,
    );
    let text = String::from_utf8_lossy(&value);
    Ok(json!({
        "credential": text,
        "grant_id": grant.id,
        "credential_name": credential_name,
        "scope": grant.scope,
    }))
}
