use core_crypto::{LocalKeyPair, generate_random_identifier};
use core_event_types::VaultObjectClass;
use core_eventlog::{BadgeRecord, EventLog};
use core_grant_types::{AccessGrant, AccessGrantDetail, AccessGrantSummary, RecipientProfile};
use core_types::ValidationError;

use crate::snapshot::{CredentialView, ServiceBindingView};

/// Extension of [`EventLog`] covering the app-layer storage operations that
/// require a concrete backend (grants, credentials, device-key enrollment).
///
/// [`core_state::EventStore`] provides full persistent implementations.
/// [`core_eventlog::MemoryEventLog`] provides no-op stubs used in WASM and
/// test contexts where these operations are delegated to the desktop runtime
/// via native messaging.
pub trait AppBackend: EventLog {
    // --- Persona ↔ device access ---

    fn grant_persona_device_access(
        &mut self,
        persona_id: &str,
        device_id: &str,
    ) -> Result<(), ValidationError>;

    fn upsert_local_device_encryption_key(
        &mut self,
        device_id: &str,
        key_pair: &LocalKeyPair,
    ) -> Result<(), ValidationError>;

    // --- Access grants ---

    fn create_access_grant(&mut self, grant: &AccessGrant) -> Result<(), ValidationError>;

    fn revoke_access_grant(
        &mut self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ValidationError>;

    /// Revoke a grant and emit a Grant Receipt if the daemon identity is
    /// initialised. Mirrors the `DaemonStore::revoke_grant` path used by the
    /// dashboard so all surfaces call the same function.
    ///
    /// Default implementation delegates to `revoke_access_grant`. Backends
    /// with richer receipt infrastructure (e.g. `DaemonStore`) should override.
    fn revoke_grant(&mut self, grant_id: &str) -> Result<(), ValidationError> {
        self.revoke_access_grant(grant_id, None)
    }

    fn access_grant_detail(
        &self,
        grant_id: &str,
    ) -> Result<Option<AccessGrantDetail>, ValidationError>;

    fn list_active_grants(
        &self,
        persona_id: Option<&str>,
        recipient_profile: Option<RecipientProfile>,
    ) -> Result<Vec<AccessGrantSummary>, ValidationError>;

    fn edit_access_grant(
        &mut self,
        grant: &AccessGrant,
        note: Option<&str>,
    ) -> Result<(), ValidationError>;

    /// Create a single persona credential. `claim_type` is a [`core_event_types::ClaimType`]
    /// string (e.g. `"self-asserted"`). `payload_json` must be a JSON object with a
    /// top-level `"schema"` string field. `device_id` is the device creating the record.
    /// Returns the new `object_id`. No-op stub for non-persistent backends.
    fn create_credential(
        &mut self,
        persona_id: &str,
        device_id: &str,
        claim_type: &str,
        payload_json: &str,
    ) -> Result<String, ValidationError>;

    /// Credential summaries for a persona. Returns metadata only — no
    /// payload decryption. Empty for non-persistent backends.
    fn list_credential_summaries(
        &self,
        persona_id: &str,
    ) -> Result<Vec<CredentialView>, ValidationError>;

    /// Service binding metadata for a persona (passkeys, OAuth, password-import, etc.).
    /// Empty for non-persistent backends.
    fn list_service_bindings_for_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<ServiceBindingView>, ValidationError>;

    // --- Badge visibility (local-only, ADR 008) ---

    /// Set badge visibility for a persona's gallery. `visible=true` displays the
    /// badge publicly. No-op for non-persistent backends.
    fn set_badge_visibility(
        &mut self,
        badge_id: &str,
        persona_id: &str,
        visible: bool,
    ) -> Result<(), ValidationError>;

    /// Return the badge gallery for a persona: all active, non-expired recipient
    /// badges with their visibility status. Returns empty for non-persistent backends.
    fn badge_gallery(
        &self,
        persona_id: &str,
        now_secs: u64,
    ) -> Result<Vec<(BadgeRecord, bool)>, ValidationError>;
}

// ---------------------------------------------------------------------------
// EventStore — full persistent implementation
// ---------------------------------------------------------------------------

impl AppBackend for core_state::EventStore {
    fn grant_persona_device_access(
        &mut self,
        persona_id: &str,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        core_state::EventStore::grant_persona_device_access(self, persona_id, device_id)
    }

    fn upsert_local_device_encryption_key(
        &mut self,
        device_id: &str,
        key_pair: &LocalKeyPair,
    ) -> Result<(), ValidationError> {
        core_state::EventStore::upsert_local_device_encryption_key(self, device_id, key_pair)
    }

    fn create_access_grant(&mut self, grant: &AccessGrant) -> Result<(), ValidationError> {
        core_state::EventStore::create_access_grant(self, grant)
    }

    fn revoke_access_grant(
        &mut self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ValidationError> {
        core_state::EventStore::revoke_access_grant(self, grant_id, reason)
    }

    fn access_grant_detail(
        &self,
        grant_id: &str,
    ) -> Result<Option<AccessGrantDetail>, ValidationError> {
        core_state::EventStore::access_grant_detail(self, grant_id)
    }

    fn list_active_grants(
        &self,
        persona_id: Option<&str>,
        recipient_profile: Option<RecipientProfile>,
    ) -> Result<Vec<AccessGrantSummary>, ValidationError> {
        core_state::EventStore::list_active_grants(self, persona_id, recipient_profile)
    }

    fn edit_access_grant(
        &mut self,
        grant: &AccessGrant,
        note: Option<&str>,
    ) -> Result<(), ValidationError> {
        core_state::EventStore::edit_access_grant(self, grant, note)
    }

    fn create_credential(
        &mut self,
        persona_id: &str,
        device_id: &str,
        claim_type: &str,
        payload_json: &str,
    ) -> Result<String, ValidationError> {
        core_state::EventStore::create_persona_credential(
            self,
            persona_id,
            device_id,
            claim_type,
            payload_json,
        )
    }

    fn list_credential_summaries(
        &self,
        persona_id: &str,
    ) -> Result<Vec<CredentialView>, ValidationError> {
        let namespaces = core_state::EventStore::local_vault_namespaces(self)?;
        let mut views = Vec::new();
        for ns in &namespaces {
            if ns.owner_kind != core_event_types::VaultOwnerKind::Persona
                || ns.owner_id != persona_id
            {
                continue;
            }
            let Some(catalog) = core_state::EventStore::local_vault_catalog(self, ns)? else {
                continue;
            };
            for obj in &catalog.objects {
                if obj.class != VaultObjectClass::PersonaCredential || obj.deleted {
                    continue;
                }
                let rev = catalog
                    .revisions
                    .iter()
                    .find(|r| r.id == obj.latest_revision_id);
                let schema = rev
                    .and_then(|r| r.structured_record.as_ref())
                    .map(|s| s.schema_id.clone())
                    .unwrap_or_default();
                let claim_type = rev
                    .and_then(|r| r.claim.as_ref())
                    .map(|c| c.claim_type.as_str().to_string());
                let claim_schema = rev
                    .and_then(|r| r.claim.as_ref())
                    .map(|c| c.claim_schema.clone());
                let display_label = credential_display_label(&schema, claim_schema.as_deref());
                views.push(CredentialView {
                    object_id: obj.id.clone(),
                    persona_id: persona_id.to_string(),
                    schema,
                    display_label,
                    claim_type,
                    claim_schema,
                    created_at: obj.created_at,
                    updated_at: obj.updated_at,
                });
            }
        }
        Ok(views)
    }

    fn list_service_bindings_for_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<ServiceBindingView>, ValidationError> {
        let bindings = core_state::EventStore::service_bindings_for_persona(self, persona_id)?;
        Ok(bindings
            .into_iter()
            .map(|b| {
                let display_account = service_binding_display_account(
                    &b.descriptor.adapter_kind,
                    &b.external_account_id,
                );
                ServiceBindingView {
                    binding_id: b.id,
                    persona_id: persona_id.to_string(),
                    adapter_kind: b.descriptor.adapter_kind,
                    service_label: b.descriptor.service_label,
                    endpoint: b.descriptor.endpoint,
                    display_account,
                    created_at: b.created_at,
                }
            })
            .collect())
    }

    fn set_badge_visibility(
        &mut self,
        badge_id: &str,
        persona_id: &str,
        visible: bool,
    ) -> Result<(), ValidationError> {
        core_state::EventStore::set_badge_visibility(self, badge_id, persona_id, visible)
    }

    fn badge_gallery(
        &self,
        persona_id: &str,
        now_secs: u64,
    ) -> Result<Vec<(BadgeRecord, bool)>, ValidationError> {
        core_state::EventStore::badge_gallery(self, persona_id, now_secs)
    }
}

// ---------------------------------------------------------------------------
// MemoryEventLog — stub implementation for WASM / test contexts
//
// These operations are no-ops or return empty. In practice the extension
// delegates them to the desktop runtime via native messaging.
// ---------------------------------------------------------------------------

impl AppBackend for core_eventlog::MemoryEventLog {
    fn grant_persona_device_access(
        &mut self,
        _persona_id: &str,
        _device_id: &str,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn upsert_local_device_encryption_key(
        &mut self,
        _device_id: &str,
        _key_pair: &LocalKeyPair,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn create_access_grant(&mut self, _grant: &AccessGrant) -> Result<(), ValidationError> {
        Ok(())
    }

    fn revoke_access_grant(
        &mut self,
        _grant_id: &str,
        _reason: Option<&str>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn access_grant_detail(
        &self,
        _grant_id: &str,
    ) -> Result<Option<AccessGrantDetail>, ValidationError> {
        Ok(None)
    }

    fn list_active_grants(
        &self,
        _persona_id: Option<&str>,
        _recipient_profile: Option<RecipientProfile>,
    ) -> Result<Vec<AccessGrantSummary>, ValidationError> {
        Ok(vec![])
    }

    fn edit_access_grant(
        &mut self,
        _grant: &AccessGrant,
        _note: Option<&str>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn create_credential(
        &mut self,
        _persona_id: &str,
        _device_id: &str,
        _claim_type: &str,
        _payload_json: &str,
    ) -> Result<String, ValidationError> {
        Ok(generate_random_identifier("vault-credential"))
    }

    fn list_credential_summaries(
        &self,
        _persona_id: &str,
    ) -> Result<Vec<CredentialView>, ValidationError> {
        Ok(vec![])
    }

    fn list_service_bindings_for_persona(
        &self,
        _persona_id: &str,
    ) -> Result<Vec<ServiceBindingView>, ValidationError> {
        Ok(vec![])
    }

    fn set_badge_visibility(
        &mut self,
        _badge_id: &str,
        _persona_id: &str,
        _visible: bool,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn badge_gallery(
        &self,
        _persona_id: &str,
        _now_secs: u64,
    ) -> Result<Vec<(BadgeRecord, bool)>, ValidationError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Derive a human-readable label from a credential's schema and optional claim schema.
fn credential_display_label(schema: &str, claim_schema: Option<&str>) -> String {
    if let Some(cs) = claim_schema
        && !cs.is_empty()
    {
        // Capitalise the first letter: "employment" → "Employment"
        let mut chars = cs.chars();
        return match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => cs.to_string(),
        };
    }
    // Fall back to last path segment of schema_id: "emberlink:claim:password:1.0" → "password"
    schema
        .rsplit(':')
        .nth(1) // skip version segment
        .or_else(|| schema.rsplit(':').next())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => s.to_string(),
            }
        })
        .unwrap_or_else(|| "Credential".to_string())
}

/// Extract a display account string from a service binding's external_account_id.
/// For passkeys this is JSON-encoded PasskeyBindingMeta; extract rp_id.
/// For other adapters the value is used directly (truncated if long).
fn service_binding_display_account(adapter_kind: &str, external_account_id: &str) -> String {
    if adapter_kind == "passkey" {
        // PasskeyBindingMeta is JSON: {"rp_id":..., "credential_id":..., ...}
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(external_account_id)
            && let Some(rp_id) = val.get("rp_id").and_then(|v| v.as_str())
        {
            return rp_id.to_string();
        }
    }
    // Truncate long values (e.g. raw credential IDs) for display
    if external_account_id.len() > 48 {
        format!("{}…", &external_account_id[..48])
    } else {
        external_account_id.to_string()
    }
}
