//! GrantStore — async CRUD seam for the Grant state machine (ADR 114 step 3).
//!
//! Splits the persistence/lookup surface from the pure transition logic in
//! `state.rs`. Implementations may be SQLite-backed (production daemon),
//! in-memory (tests), or remote (future federation). The trait is
//! intentionally narrow: callers go through `apply_event` / `can_transition`
//! for state changes, and through this trait for storage round-trips.
//!
//! Excluded by design: composite-grant materialization, bulk queries beyond
//! per-persona listing, transactional batch ops. Add via follow-up tasks if
//! production needs surface.

use async_trait::async_trait;
use chrono::Duration;
use thiserror::Error;

use crate::grant::{Grant, GrantState, PrincipalId, Scope};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("grant not found: {0}")]
    NotFound(String),
    #[error("duplicate grant id: {0}")]
    Duplicate(String),
    #[error("invalid transition: {from:?} -> {to:?}")]
    InvalidTransition { from: GrantState, to: GrantState },
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// CRUD-and-lookup interface for grants. Pure trait — no implementation
/// here.
///
/// **Pre/post conditions** are documented per method; the property tests
/// in `crates/core-grants/tests/store_mock.rs` assert each of them against
/// the bundled `MockGrantStore`.
#[async_trait]
pub trait GrantStore: Send + Sync {
    /// Create a new active grant for `persona` with `scope`, expiring after
    /// `ttl`.
    ///
    /// **Pre:** `scope.capability` is non-empty; `ttl` is strictly positive.
    /// **Post:** returned `Grant` has `state == Active`, `issuer == persona`,
    /// and `expires_at == created_at + ttl`. Subsequent `get` returns the
    /// same grant.
    /// **Errors:** `Backend` on storage failure.
    async fn create(
        &self,
        persona: &PrincipalId,
        scope: Scope,
        ttl: Duration,
    ) -> Result<Grant, StoreError>;

    /// Look up a grant by its string ID.
    ///
    /// **Post:** returns `Some(grant)` iff the grant was previously created
    /// and not removed; `None` otherwise. No state machine effects.
    async fn get(&self, grant_id: &str) -> Result<Option<Grant>, StoreError>;

    /// Apply a state transition to an existing grant.
    ///
    /// **Pre:** `grant_id` exists; `target_state` is reachable from the
    /// current state per `core_grants::can_transition`.
    /// **Post:** returns the updated grant with `state == target_state`.
    /// **Errors:** `NotFound` if grant missing; `InvalidTransition` if the
    /// edge is not in the state machine table.
    async fn transition(
        &self,
        grant_id: &str,
        target_state: GrantState,
    ) -> Result<Grant, StoreError>;

    /// Revoke a grant. Terminal — no further transitions are valid.
    ///
    /// **Pre:** `grant_id` exists; `actor` is authorized to revoke (caller's
    /// responsibility — the trait does not gate authority).
    /// **Post:** the grant transitions to `Revoked`; subsequent `get`
    /// returns the grant in `Revoked` state. Idempotent on already-revoked
    /// grants.
    async fn revoke(
        &self,
        grant_id: &str,
        actor: core_grant_types::grant_receipt::RevokeActor,
    ) -> Result<(), StoreError>;

    /// List all grants for a persona, in creation order (oldest first).
    ///
    /// **Post:** returns every grant whose `issuer == persona`, regardless
    /// of state (Active / Paused / Revoked all included). Empty `Vec` if
    /// the persona has no grants.
    async fn list_by_persona(&self, persona: &PrincipalId) -> Result<Vec<Grant>, StoreError>;
}
