use super::*;

// --- Access Grant CRUD tests ---

// Test fixture builder kept as documentation of the canonical
// "store with one persona under one root" shape. No current caller
// in this test module (siblings build their own fixtures inline).
#[allow(dead_code)]
fn store_with_persona() -> EventStore {
    let mut store = EventStore::default();
    append_typed(
        &mut store,
        "evt-root-1",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-1",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            label: "Laptop".into(),
            initial_key: test_key("key-device-a-v1"),
            initial_encryption_key: test_encryption_key("key-device-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-1",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            label: "Work".into(),
            disclosure_profile: Some("work-public".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    store
}

// Grant CRUD tests deferred — see ADR 073 follow-up PR for composite grant test port.

fn sample_approval_request(id: &str) -> core_grant_types::approval::ApprovalRequest {
    core_grant_types::approval::ApprovalRequest::new(
        id.into(),
        "agent-claude".into(),
        Some("Claude agent".into()),
        core_grant_types::approval::RequestedScope {
            capability: "ReadCredential".into(),
            resource_id: Some("cred-netflix".into()),
            constraints: vec!["read-only".into()],
        },
        Some(3600),
        Some("Need Netflix password".into()),
        1700000000,
    )
}

#[test]
fn insert_and_retrieve_approval_request() {
    let store = EventStore::default();
    let req = sample_approval_request("req-1");
    store.insert_approval_request(&req).unwrap();

    let loaded = store.get_approval_request("req-1").unwrap().unwrap();
    assert_eq!(loaded.request_id, "req-1");
    assert_eq!(loaded.requester_id, "agent-claude");
    assert_eq!(loaded.requester_label.as_deref(), Some("Claude agent"));
    assert_eq!(loaded.status, "pending");
    assert_eq!(loaded.created_at, 1700000000);
    assert_eq!(loaded.requested_duration_secs, Some(3600));
    assert_eq!(loaded.reason.as_deref(), Some("Need Netflix password"));
    assert!(loaded.resolved_at.is_none());
    assert!(loaded.resolver_id.is_none());

    assert!(store.get_approval_request("nonexistent").unwrap().is_none());
}

#[test]
fn list_pending_approvals_returns_only_pending() {
    let store = EventStore::default();

    let req1 = sample_approval_request("req-1");
    let mut req2 = sample_approval_request("req-2");
    req2.created_at = 1700000060;
    store.insert_approval_request(&req1).unwrap();
    store.insert_approval_request(&req2).unwrap();

    let pending = store.list_pending_approvals().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].request_id, "req-2");
    assert_eq!(pending[1].request_id, "req-1");

    let response = core_grant_types::approval::ApprovalResponse {
        request_id: "req-1".into(),
        status: core_grant_types::approval::ApprovalStatus::Approved,
        resolver_id: "josh".into(),
        resolved_at: 1700000120,
        narrowed_scope: None,
        denial_reason: None,
        granted_duration_secs: Some(3600),
    };
    store.resolve_approval_request("req-1", &response).unwrap();

    let pending = store.list_pending_approvals().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request_id, "req-2");
}

#[test]
fn resolve_approval_request_updates_status() {
    let store = EventStore::default();
    let req = sample_approval_request("req-1");
    store.insert_approval_request(&req).unwrap();

    let response = core_grant_types::approval::ApprovalResponse {
        request_id: "req-1".into(),
        status: core_grant_types::approval::ApprovalStatus::Denied,
        resolver_id: "josh".into(),
        resolved_at: 1700000120,
        narrowed_scope: None,
        denial_reason: Some("Not authorized".into()),
        granted_duration_secs: None,
    };
    store.resolve_approval_request("req-1", &response).unwrap();

    let loaded = store.get_approval_request("req-1").unwrap().unwrap();
    assert_eq!(loaded.status, "denied");
    assert_eq!(loaded.resolved_at, Some(1700000120));
    assert_eq!(loaded.resolver_id.as_deref(), Some("josh"));
    assert_eq!(loaded.denial_reason.as_deref(), Some("Not authorized"));
}

#[test]
fn resolve_already_resolved_request_fails() {
    let store = EventStore::default();
    let req = sample_approval_request("req-1");
    store.insert_approval_request(&req).unwrap();

    let response1 = core_grant_types::approval::ApprovalResponse {
        request_id: "req-1".into(),
        status: core_grant_types::approval::ApprovalStatus::Approved,
        resolver_id: "josh".into(),
        resolved_at: 1700000120,
        narrowed_scope: None,
        denial_reason: None,
        granted_duration_secs: Some(3600),
    };
    store.resolve_approval_request("req-1", &response1).unwrap();

    let response2 = core_grant_types::approval::ApprovalResponse {
        request_id: "req-1".into(),
        status: core_grant_types::approval::ApprovalStatus::Denied,
        resolver_id: "attacker".into(),
        resolved_at: 1700000180,
        narrowed_scope: None,
        denial_reason: Some("forged".into()),
        granted_duration_secs: None,
    };
    let err = store
        .resolve_approval_request("req-1", &response2)
        .unwrap_err();
    assert!(err.message.contains("cannot transition"));
}
