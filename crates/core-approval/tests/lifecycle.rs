use core_approval::{
    ApprovalLifecycle, ApprovalOutcome, LifecycleError, RequestId, SubmitMetadata,
};
use core_grant_types::approval::RequestedScope;
use core_grants::Grant;

struct MockLifecycle;

#[async_trait::async_trait]
impl ApprovalLifecycle for MockLifecycle {
    async fn submit_request(
        &self,
        _persona: &str,
        _credential: &str,
        _scope: RequestedScope,
        _metadata: SubmitMetadata,
    ) -> Result<RequestId, LifecycleError> {
        Ok(RequestId("mock".into()))
    }

    async fn decide(
        &self,
        _id: &RequestId,
        _outcome: ApprovalOutcome,
    ) -> Result<Option<Grant>, LifecycleError> {
        Ok(None)
    }

    async fn apply_standing(
        &self,
        _persona: &str,
        _pattern: RequestedScope,
        _ttl: u64,
    ) -> Result<Grant, LifecycleError> {
        Err(LifecycleError::Storage("mock".into()))
    }
}

#[test]
fn trait_shape_compiles() {
    let m = MockLifecycle;
    let id = futures::executor::block_on(m.submit_request(
        "p",
        "c",
        RequestedScope {
            capability: "Read".into(),
            resource_id: None,
            constraints: vec![],
        },
        SubmitMetadata::default(),
    ))
    .unwrap();
    assert_eq!(id, RequestId("mock".into()));
}

#[test]
fn decide_returns_none_on_denied() {
    let m = MockLifecycle;
    let id = RequestId("test-id".into());
    let result = futures::executor::block_on(m.decide(&id, ApprovalOutcome::Denied)).unwrap();
    assert!(result.is_none());
}

#[test]
fn apply_standing_returns_error_from_mock() {
    let m = MockLifecycle;
    let scope = RequestedScope {
        capability: "Read".into(),
        resource_id: None,
        constraints: vec![],
    };
    let result = futures::executor::block_on(m.apply_standing("persona", scope, 3600));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), LifecycleError::Storage(_)));
}
