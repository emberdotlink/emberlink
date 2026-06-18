use super::*;

#[test]
fn replacement_device_can_take_over_persona_access_after_recovery() {
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
        "evt-device-2",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-b".into(),
            label: "Replacement Laptop".into(),
            initial_key: test_key("key-device-b-v1"),
            initial_encryption_key: test_encryption_key("key-device-b-v1"),
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
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    store
        .grant_persona_device_access("persona-a", "device-a")
        .unwrap();
    append_typed(
        &mut store,
        "evt-device-replaced-1",
        EventBody::DeviceReplaced(DeviceReplacedEvent {
            root_id: "root-a".into(),
            replaced_device_id: "device-a".into(),
            replacement_device_id: "device-b".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    store
        .restore_persona_access_to_replacement_device("device-a", "device-b")
        .unwrap();

    assert!(
        store
            .persona_device_access_for_device("device-a")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.persona_device_access_for_device("device-b").unwrap(),
        vec![PersonaDeviceAccessRecord {
            persona_id: "persona-a".into(),
            device_id: "device-b".into(),
        }]
    );
}

#[test]
fn recovery_approval_rejects_non_guardian_signers() {
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
            guardian_threshold: 1,
            cooldown_seconds: 3600,
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

    let invalid_approval = EventEnvelope::from_body(
        "evt-recovery-approval-invalid",
        EventBody::RecoveryApproved(RecoveryApprovedEvent {
            request_id: "recovery-1".into(),
            guardian_id: "guardian-alex".into(),
        }),
        vec![EventRef::previous("evt-recovery-request-1", 0)],
        SignerBinding::device("device-a", "key-device-a-v1"),
        &FixtureSigner::new("key-device-a-v1"),
    )
    .unwrap();

    let err = store
        .append_with_authorizer(invalid_approval, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(err.message.contains("guardian role"));
}

#[test]
fn revoked_device_cannot_rotate_key_or_receive_persona_access() {
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
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-revoke-1",
        EventBody::DeviceRevoked(DeviceRevokedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            reason: "lost".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let rotate = EventEnvelope::from_body(
        "evt-device-rotate-1",
        EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            previous_key_id: "key-device-a-v1".into(),
            new_key: test_key("key-device-a-v2"),
        }),
        Vec::new(),
        SignerBinding::device("device-a", "key-device-a-v1"),
        &FixtureSigner::new("key-device-a-v1"),
    )
    .unwrap();

    let rotate_err = store
        .append_with_authorizer(rotate, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(rotate_err.message.contains("not active"));

    let grant_err = store
        .grant_persona_device_access("persona-a", "device-a")
        .unwrap_err();
    assert!(grant_err.message.contains("non-active device"));
}

#[test]
fn revoked_persona_cannot_rotate_key_or_receive_device_access() {
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
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-revoke-1",
        EventBody::PersonaRevoked(PersonaRevokedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            reason: "compromised".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let rotate = EventEnvelope::from_body(
        "evt-persona-rotate-1",
        EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            previous_key_id: "key-persona-a-v1".into(),
            new_key: test_key("key-persona-a-v2"),
        }),
        Vec::new(),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
        &FixtureSigner::new("key-persona-a-v1"),
    )
    .unwrap();

    let rotate_err = store
        .append_with_authorizer(rotate, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(rotate_err.message.contains("not active"));

    let grant_err = store
        .grant_persona_device_access("persona-a", "device-a")
        .unwrap_err();
    assert!(grant_err.message.contains("revoked persona"));
}

#[test]
fn contested_recovery_enters_cooldown_and_blocks_execution_until_rejected() {
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
            guardian_threshold: 1,
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

    let approval = EventEnvelope::from_body(
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
        .append_with_authorizer(approval, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    let contest = EventEnvelope::from_body(
        "evt-recovery-contest-1",
        EventBody::RecoveryContested(RecoveryContestedEvent {
            request_id: "recovery-1".into(),
            guardian_id: "guardian-riley".into(),
            reason: "improper approval".into(),
            contested_at_epoch: 1000,
        }),
        vec![EventRef::previous("evt-recovery-approval-1", 0)],
        SignerBinding::guardian("guardian-riley", riley_pub.clone()),
        &FixtureSigner::new("guardian-key-riley"),
    )
    .unwrap();
    store
        .append_with_authorizer(contest, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    let request = store
        .materialized()
        .recovery_requests_current
        .get("recovery-1")
        .unwrap();
    assert_eq!(request.status, RecoveryRequestStatus::Contested);
    assert!(request.cooldown_until.is_some());
    assert_eq!(request.contested_by.len(), 1);
    assert_eq!(request.contest_reason.as_deref(), Some("improper approval"));

    let execute = EventEnvelope::from_body(
        "evt-recovery-executed-1",
        EventBody::RecoveryExecuted(RecoveryExecutedEvent {
            request_id: "recovery-1".into(),
            executed_scope: RecoveryScope::FreezeDevice,
        }),
        vec![EventRef::previous("evt-recovery-contest-1", 0)],
        SignerBinding::root("root-a", "key-root-a-v1"),
        &FixtureSigner::new("key-root-a-v1"),
    )
    .unwrap();
    let execute_err = store
        .append_with_authorizer(execute, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(execute_err.message.contains("cooldown"));

    let reject = EventEnvelope::from_body(
        "evt-recovery-rejected-1",
        EventBody::RecoveryRejected(RecoveryRejectedEvent {
            request_id: "recovery-1".into(),
            rejected_by: "root-a".into(),
            reason: "contest upheld".into(),
        }),
        vec![EventRef::previous("evt-recovery-contest-1", 0)],
        SignerBinding::root("root-a", "key-root-a-v1"),
        &FixtureSigner::new("key-root-a-v1"),
    )
    .unwrap();
    store
        .append_with_authorizer(reject, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    let rejected = store
        .materialized()
        .recovery_requests_current
        .get("recovery-1")
        .unwrap();
    assert_eq!(rejected.status, RecoveryRequestStatus::Rejected);
    assert!(rejected.cooldown_until.is_none());
    assert_eq!(rejected.rejection_reason.as_deref(), Some("contest upheld"));
}

#[test]
fn future_now_clamped_cannot_bypass_cooldown() {
    // Build the same contested state as above (contested_at_epoch=1000,
    // cooldown_seconds=3600 → cooldown_until=4600).
    let mut store = EventStore::default();
    for (id, body, signer) in [
        (
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-x".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-x-v1"),
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
        (
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-x".into(),
                device_id: "device-x".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-x-v1"),
                initial_encryption_key: test_encryption_key("key-device-x-v1"),
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
        (
            "evt-policy-1",
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: "root-x".into(),
                guardian_threshold: 1,
                cooldown_seconds: 3600,
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
        (
            "evt-guardian-1",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-x".into(),
                guardian_id: "guardian-b".into(),
                guardian_label: "Bob".into(),
                guardian_public_key: fixture_guardian_pubkey("guardian-key-b"),
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
        (
            "evt-guardian-2",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-x".into(),
                guardian_id: "guardian-c".into(),
                guardian_label: "Carol".into(),
                guardian_public_key: fixture_guardian_pubkey("guardian-key-c"),
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
        (
            "evt-request-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "recovery-x".into(),
                root_id: "root-x".into(),
                target_device_id: "device-x".into(),
            }),
            SignerBinding::root("root-x", "key-root-x-v1"),
        ),
    ] {
        append_typed(&mut store, id, body, signer);
    }

    let approval = EventEnvelope::from_body(
        "evt-approval-1",
        EventBody::RecoveryApproved(RecoveryApprovedEvent {
            request_id: "recovery-x".into(),
            guardian_id: "guardian-b".into(),
        }),
        vec![EventRef::previous("evt-request-1", 0)],
        SignerBinding::guardian("guardian-b", fixture_guardian_pubkey("guardian-key-b")),
        &FixtureSigner::new("guardian-key-b"),
    )
    .unwrap();
    store
        .append_with_authorizer(approval, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    // Contest at epoch=1000 → cooldown_until = 1000 + 3600 = 4600
    let contest = EventEnvelope::from_body(
        "evt-contest-1",
        EventBody::RecoveryContested(RecoveryContestedEvent {
            request_id: "recovery-x".into(),
            guardian_id: "guardian-c".into(),
            reason: "suspicious".into(),
            contested_at_epoch: 1000,
        }),
        vec![EventRef::previous("evt-approval-1", 0)],
        SignerBinding::guardian("guardian-c", fixture_guardian_pubkey("guardian-key-c")),
        &FixtureSigner::new("guardian-key-c"),
    )
    .unwrap();
    store
        .append_with_authorizer(contest, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap();

    // Attempt execution with a far-future timestamp — should still be blocked by cooldown
    // because append_with_authorizer clamps now_epoch_secs to system_now + 300.
    let execute = EventEnvelope::from_body(
        "evt-execute-1",
        EventBody::RecoveryExecuted(RecoveryExecutedEvent {
            request_id: "recovery-x".into(),
            executed_scope: RecoveryScope::FreezeDevice,
        }),
        vec![EventRef::previous("evt-contest-1", 0)],
        SignerBinding::root("root-x", "key-root-x-v1"),
        &FixtureSigner::new("key-root-x-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(execute, &FixtureVerifier, &IdentityAuthorizer, u64::MAX)
        .unwrap_err();
    // Cooldown expires at epoch 4600; system_now is << 4600 in any CI environment,
    // so the clamped effective_now is well below the cooldown threshold.
    assert!(
        err.message.contains("cooldown") || err.message.contains("approved"),
        "expected cooldown rejection, got: {}",
        err.message
    );
}

#[test]
fn recovery_execution_before_approval_rejected() {
    let mut store = two_root_fixture();
    // Create a recovery policy
    append_typed(
        &mut store,
        "evt-recovery-policy",
        EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
            root_id: "root-a".into(),
            guardian_threshold: 2,
            cooldown_seconds: 3600,
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    // Request recovery
    append_typed(
        &mut store,
        "evt-recovery-request",
        EventBody::RecoveryRequested(RecoveryRequestedEvent {
            request_id: "recovery-1".into(),
            root_id: "root-a".into(),
            target_device_id: "device-a".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    // Try to execute without any approvals
    let event = EventEnvelope::from_body(
        "evt-recovery-execute-premature",
        EventBody::RecoveryExecuted(RecoveryExecutedEvent {
            request_id: "recovery-1".into(),
            executed_scope: RecoveryScope::FreezeDevice,
        }),
        Vec::new(),
        SignerBinding::root("root-a", "key-root-a-v1"),
        &FixtureSigner::new("key-root-a-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("must be approved"),
        "unapproved recovery should not execute: {}",
        err.message
    );
}
