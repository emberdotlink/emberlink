//! CLASSIFICATION: PUBLIC
//!
//! KMS caller resolution — loopback and mTLS edge paths (ADR 100 Amendment 1 v3).
//!
//! `ResolvedKmsCaller` is the unified caller context produced at the boundary
//! of the KMS API surface, regardless of whether the caller arrived via the
//! existing loopback bearer-token path or the new mTLS edge listener.

use core_crypto::ca::SpiffeIdentity;
use core_grants::Grant;
use thiserror::Error;

use crate::infra::store::DaemonStore;

/// Errors produced when resolving a KMS caller from either the loopback or
/// edge path.
#[derive(Debug, Error)]
pub enum KmsError {
    #[error("persona not found: {0}")]
    PersonaNotFound(String),
    #[error("no active grants for persona: {0}")]
    NoActiveGrants(String),
    #[error("store error: {0}")]
    Store(#[from] crate::infra::store::StoreError),
}

/// How the caller reached the KMS API surface.
pub enum KmsCallerSource {
    /// Existing loopback path — caller presented a bearer token that identified
    /// a persona via the in-process token registry.
    Loopback { token_persona: String },
    /// New mTLS edge path — caller presented a client certificate whose SPIFFE
    /// URI was verified against the edge CA and parsed into a `SpiffeIdentity`.
    Edge {
        spiffe: SpiffeIdentity,
        cert_serial: u64,
    },
}

/// A fully-resolved KMS caller: persona label, active grants, and the
/// transport path that produced this context.
pub struct ResolvedKmsCaller {
    pub persona: String,
    pub grants: Vec<Grant>,
    pub source: KmsCallerSource,
}

/// Resolve the active grants for `persona` from the daemon store.
///
/// Returns `KmsError::PersonaNotFound` when the persona does not exist in the
/// store.  Returns `KmsError::NoActiveGrants` when the persona exists but has
/// no active grants (the caller should be refused with HTTP 403).
///
/// This function is called by both the loopback and edge code paths immediately
/// after the caller's identity is established so that the grant check happens
/// at a single, auditable point.
pub async fn resolve_persona_grants(
    persona: &str,
    store: &DaemonStore,
) -> Result<Vec<Grant>, KmsError> {
    use crate::trust::grant::GrantStore;

    // Verify the persona exists in the store.
    let personas = store.list_personas().map_err(KmsError::Store)?;
    if !personas.iter().any(|p| p.id == persona) {
        return Err(KmsError::PersonaNotFound(persona.to_owned()));
    }

    // Load active grants for the persona via the grant store adapter.
    let grant_store = store.grant_store();
    let grants = grant_store.list_active(persona).map_err(KmsError::Store)?;

    if grants.is_empty() {
        return Err(KmsError::NoActiveGrants(persona.to_owned()));
    }

    Ok(grants)
}
