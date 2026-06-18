use super::*;

#[test]
fn append_and_rebuild_materialize_identity_state() {
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

    append_typed(
        &mut store,
        "evt-root-rotate-1",
        EventBody::RootKeyRotated(RootKeyRotatedEvent {
            root_id: "root-a".into(),
            previous_key_id: "key-root-a-v1".into(),
            new_key: test_key("key-root-a-v2"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    append_typed(
        &mut store,
        "evt-device-rotate-1",
        EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            previous_key_id: "key-device-a-v1".into(),
            new_key: test_key("key-device-a-v2"),
        }),
        SignerBinding::device("device-a", "key-device-a-v1"),
    );

    store.rebuild().unwrap();

    let state = store.materialized();
    assert_eq!(store.event_count(), 5);
    assert_eq!(
        state.root("root-a").unwrap().active_key.key_id,
        "key-root-a-v2"
    );
    assert_eq!(
        state.device("device-a").unwrap().active_key.key_id,
        "key-device-a-v2"
    );
    assert_eq!(
        state
            .persona("persona-a")
            .unwrap()
            .disclosure_profile
            .as_deref(),
        Some("work-public")
    );
    assert_eq!(
        state.root_key_history.get("root-a").unwrap(),
        &vec!["key-root-a-v1".to_string(), "key-root-a-v2".to_string()]
    );
}

#[test]
fn device_encryption_rotation_updates_active_encryption_key() {
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
        "evt-device-encryption-rotate-1",
        EventBody::DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            previous_encryption_key_id: "enc-key-device-a-v1".into(),
            new_encryption_key: test_encryption_key("key-device-a-v2"),
        }),
        SignerBinding::device("device-a", "key-device-a-v1"),
    );

    let state = store.materialized();
    assert_eq!(
        state
            .device("device-a")
            .unwrap()
            .active_encryption_key
            .key_id,
        "enc-key-device-a-v2"
    );
    assert_eq!(
        state.device_encryption_key_history.get("device-a").unwrap(),
        &vec![
            "enc-key-device-a-v1".to_string(),
            "enc-key-device-a-v2".to_string()
        ]
    );
}

#[test]
fn endpoint_events_materialize_and_rotate_current_transport_hint() {
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
            label: "Bridge".into(),
            initial_key: test_key("key-device-a-v1"),
            initial_encryption_key: test_encryption_key("key-device-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-endpoint-1",
        EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
            peer_id: "peer-bridge-a".into(),
            device_id: "device-a".into(),
            transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
        }),
        SignerBinding::device("device-a", "key-device-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-endpoint-rotate-1",
        EventBody::EndpointRotated(EndpointRotatedEvent {
            peer_id: "peer-bridge-a".into(),
            device_id: "device-a".into(),
            previous_transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
            new_transport_hint: "relay://127.0.0.1:9200/mailbox/peer-bridge-a".into(),
        }),
        SignerBinding::device("device-a", "key-device-a-v1"),
    );

    store.rebuild().unwrap();

    let endpoint = store.materialized().endpoint("peer-bridge-a").unwrap();
    assert_eq!(endpoint.device_id, "device-a");
    assert_eq!(
        endpoint.transport_hint,
        "relay://127.0.0.1:9200/mailbox/peer-bridge-a"
    );
}

#[test]
fn endpoint_hint_updates_reject_cross_root_peer_claims() {
    let mut store = EventStore::default();

    append_typed(
        &mut store,
        "evt-root-a",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Root A".into(),
            initial_key: test_key("key-root-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-root-b",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-b".into(),
            display_name: "Root B".into(),
            initial_key: test_key("key-root-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-a",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            label: "Bridge A".into(),
            initial_key: test_key("key-device-a-v1"),
            initial_encryption_key: test_encryption_key("key-device-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-endpoint-a",
        EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
            peer_id: "peer-shared".into(),
            device_id: "device-a".into(),
            transport_hint: "relay://127.0.0.1:9100/mailbox/peer-shared".into(),
        }),
        SignerBinding::device("device-a", "key-device-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-b",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-b".into(),
            device_id: "device-b".into(),
            label: "Bridge B".into(),
            initial_key: test_key("key-device-b-v1"),
            initial_encryption_key: test_encryption_key("key-device-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );

    let signer = FixtureSigner::new("key-device-b-v1");
    let event = EventEnvelope::from_body(
        "evt-endpoint-b",
        EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
            peer_id: "peer-shared".into(),
            device_id: "device-b".into(),
            transport_hint: "relay://127.0.0.1:9200/mailbox/peer-shared".into(),
        }),
        Vec::new(),
        SignerBinding::device("device-b", "key-device-b-v1"),
        &signer,
    )
    .unwrap();

    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message
            .contains("endpoint peer id is already claimed by a different root")
    );
}

#[test]
fn recovery_requests_accumulate_approvals_and_execute() {
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
        "evt-recovery-policy-1",
        EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
            root_id: "root-a".into(),
            guardian_threshold: 2,
            cooldown_seconds: 3600,
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    let alex_pub = fixture_guardian_pubkey("guardian-key-alex");
    let riley_pub = fixture_guardian_pubkey("guardian-key-riley");
    append_typed(
        &mut store,
        "evt-guardian-enroll-1",
        EventBody::GuardianEnrolled(GuardianEnrolledEvent {
            root_id: "root-a".into(),
            guardian_id: "guardian-alex".into(),
            guardian_label: "Alex".into(),
            guardian_public_key: alex_pub.clone(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-guardian-enroll-2",
        EventBody::GuardianEnrolled(GuardianEnrolledEvent {
            root_id: "root-a".into(),
            guardian_id: "guardian-riley".into(),
            guardian_label: "Riley".into(),
            guardian_public_key: riley_pub.clone(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-recovery-request-1",
        EventBody::RecoveryRequested(RecoveryRequestedEvent {
            request_id: "recovery-1".into(),
            root_id: "root-a".into(),
            target_device_id: "device-a".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let guardian_one = EventEnvelope::from_body(
        "evt-recovery-approval-1",
        EventBody::RecoveryApproved(RecoveryApprovedEvent {
            request_id: "recovery-1".into(),
            guardian_id: "guardian-alex".into(),
        }),
        vec![EventRef::previous("evt-recovery-request-1", 0)],
        SignerBinding::guardian("guardian-alex", alex_pub.clone()),
        &FixtureSigner::new("guardian-key-alex"),
    )
    .unwrap();
    store
        .append_with_authorizer(guardian_one, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    let guardian_two = EventEnvelope::from_body(
        "evt-recovery-approval-2",
        EventBody::RecoveryApproved(RecoveryApprovedEvent {
            request_id: "recovery-1".into(),
            guardian_id: "guardian-riley".into(),
        }),
        vec![EventRef::previous("evt-recovery-approval-1", 0)],
        SignerBinding::guardian("guardian-riley", riley_pub.clone()),
        &FixtureSigner::new("guardian-key-riley"),
    )
    .unwrap();
    store
        .append_with_authorizer(guardian_two, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    append_typed(
        &mut store,
        "evt-recovery-executed-1",
        EventBody::RecoveryExecuted(RecoveryExecutedEvent {
            request_id: "recovery-1".into(),
            executed_scope: RecoveryScope::FreezeDevice,
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let request = store
        .materialized()
        .recovery_requests_current
        .get("recovery-1")
        .unwrap();
    assert_eq!(request.status, RecoveryRequestStatus::Executed);
    assert_eq!(request.approvals.len(), 2);
    assert_eq!(request.executed_scope, Some(RecoveryScope::FreezeDevice));
}
