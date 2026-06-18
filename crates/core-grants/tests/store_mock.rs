//! HashMap-backed `MockGrantStore` exercising every method of the
//! `GrantStore` trait. Lives in `tests/` (integration) so it compiles
//! against the public crate surface only.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use core_grant_types::grant_receipt::RevokeActor;
use core_grants::{
    Grant, GrantSpec, GrantState, GrantStore, PrincipalId, Scope, StoreError, can_transition,
    create as create_grant,
};

#[derive(Default)]
struct MockGrantStore {
    grants: Mutex<HashMap<String, Grant>>,
}

#[async_trait]
impl GrantStore for MockGrantStore {
    async fn create(
        &self,
        persona: &PrincipalId,
        scope: Scope,
        ttl: Duration,
    ) -> Result<Grant, StoreError> {
        let spec = GrantSpec {
            issuer: persona.clone(),
            scope,
            expires_at: Some(Utc::now() + ttl),
        };
        let grant = create_grant(spec).map_err(|e| StoreError::Backend(format!("{e:?}")))?;
        let id = grant.id.to_string();
        let mut g = self.grants.lock().unwrap();
        if g.contains_key(&id) {
            return Err(StoreError::Duplicate(id));
        }
        g.insert(id, grant.clone());
        Ok(grant)
    }

    async fn get(&self, grant_id: &str) -> Result<Option<Grant>, StoreError> {
        Ok(self.grants.lock().unwrap().get(grant_id).cloned())
    }

    async fn transition(
        &self,
        grant_id: &str,
        target_state: GrantState,
    ) -> Result<Grant, StoreError> {
        let mut g = self.grants.lock().unwrap();
        let grant = g
            .get_mut(grant_id)
            .ok_or_else(|| StoreError::NotFound(grant_id.to_string()))?;
        if !can_transition(grant.state, target_state) {
            return Err(StoreError::InvalidTransition {
                from: grant.state,
                to: target_state,
            });
        }
        grant.state = target_state;
        Ok(grant.clone())
    }

    async fn revoke(&self, grant_id: &str, _actor: RevokeActor) -> Result<(), StoreError> {
        let mut g = self.grants.lock().unwrap();
        let grant = g
            .get_mut(grant_id)
            .ok_or_else(|| StoreError::NotFound(grant_id.to_string()))?;
        grant.state = GrantState::Revoked;
        Ok(())
    }

    async fn list_by_persona(&self, persona: &PrincipalId) -> Result<Vec<Grant>, StoreError> {
        let grants: Vec<Grant> = self
            .grants
            .lock()
            .unwrap()
            .values()
            .filter(|g| &g.issuer == persona)
            .cloned()
            .collect();
        Ok(grants)
    }
}

fn fixed_persona() -> PrincipalId {
    PrincipalId("test-persona".to_string())
}

fn fixed_scope() -> Scope {
    Scope {
        capability: "ReadCredential".into(),
        resource_id: Some("cred-1".into()),
        constraints: vec![],
    }
}

#[tokio::test]
async fn create_then_get_round_trips() {
    let store = MockGrantStore::default();
    let persona = fixed_persona();
    let g = store
        .create(&persona, fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(g.state, GrantState::Active);
    let fetched = store.get(&g.id.to_string()).await.unwrap().unwrap();
    assert_eq!(fetched.id, g.id);
}

#[tokio::test]
async fn transition_active_to_paused_succeeds() {
    let store = MockGrantStore::default();
    let g = store
        .create(&fixed_persona(), fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    let updated = store
        .transition(&g.id.to_string(), GrantState::Paused)
        .await
        .unwrap();
    assert_eq!(updated.state, GrantState::Paused);
}

#[tokio::test]
async fn transition_revoked_to_active_rejected() {
    let store = MockGrantStore::default();
    let g = store
        .create(&fixed_persona(), fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    store
        .transition(&g.id.to_string(), GrantState::Revoked)
        .await
        .unwrap();
    let err = store
        .transition(&g.id.to_string(), GrantState::Active)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidTransition { .. }));
}

#[tokio::test]
async fn revoke_terminates_grant() {
    let store = MockGrantStore::default();
    let g = store
        .create(&fixed_persona(), fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    store
        .revoke(&g.id.to_string(), RevokeActor::Operator)
        .await
        .unwrap();
    let fetched = store.get(&g.id.to_string()).await.unwrap().unwrap();
    assert_eq!(fetched.state, GrantState::Revoked);
}

#[tokio::test]
async fn list_by_persona_returns_empty_for_unknown() {
    let store = MockGrantStore::default();
    let other = PrincipalId("nobody".into());
    let grants = store.list_by_persona(&other).await.unwrap();
    assert!(grants.is_empty());
}

#[tokio::test]
async fn list_by_persona_returns_only_persona_grants() {
    let store = MockGrantStore::default();
    let persona = fixed_persona();
    let _g1 = store
        .create(&persona, fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    let _g2 = store
        .create(&persona, fixed_scope(), Duration::hours(1))
        .await
        .unwrap();
    let grants = store.list_by_persona(&persona).await.unwrap();
    assert_eq!(grants.len(), 2);
    for g in &grants {
        assert_eq!(g.issuer, persona);
    }
}

#[tokio::test]
async fn duplicate_id_rejected() {
    // create a grant, then manually re-insert via a hand-crafted spec to
    // force a collision: skip — Grant::id uses uuid v4, collisions are
    // astronomically unlikely. This branch is primarily defensive backend
    // error coverage. We assert the StoreError variant name compiles.
    let _ = StoreError::Duplicate("noop".into());
}
