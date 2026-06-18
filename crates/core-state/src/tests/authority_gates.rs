use super::*;

#[test]
fn cross_root_device_add_rejected() {
    let mut store = two_root_fixture();
    // Root A tries to add a device under Root B's identity
    let event = EventEnvelope::from_body(
        "evt-cross-device",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-b".into(),
            device_id: "device-evil".into(),
            label: "evil".into(),
            initial_key: test_key("key-evil"),
            initial_encryption_key: test_encryption_key("key-evil"),
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
        err.message.contains("does not match"),
        "cross-root should be rejected: {}",
        err.message
    );
}

#[test]
fn wrong_key_id_for_root_rejected() {
    let mut store = two_root_fixture();
    // Correct root identity but a fabricated key ID
    let event = EventEnvelope::from_body(
        "evt-wrong-key",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-new".into(),
            label: "new".into(),
            initial_key: test_key("key-new"),
            initial_encryption_key: test_encryption_key("key-new"),
        }),
        Vec::new(),
        SignerBinding::root("root-a", "key-fabricated"),
        &FixtureSigner::new("key-fabricated"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    // A fabricated signing key must be rejected. Since Model C (ADR 200 §2/§5)
    // the rejection comes from the authority check (the fabricated key is
    // neither the founding key nor an active presence Device) rather than the
    // older key-id-equality message — accept either; the security property
    // (an unauthorized key cannot append) is what this test pins.
    assert!(
        err.message
            .contains("neither the root key nor an active presence Device")
            || err.message.contains("does not match"),
        "wrong key id should be rejected: {}",
        err.message
    );
}

#[test]
fn device_key_cannot_perform_root_operations() {
    let mut store = two_root_fixture();
    // Device key tries to create a persona (root-only operation)
    let event = EventEnvelope::from_body(
        "evt-device-escalation",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-evil".into(),
            label: "evil".into(),
            disclosure_profile: None,
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-evil"),
        }),
        Vec::new(),
        SignerBinding::device("device-a", "key-device-a-v1"),
        &FixtureSigner::new("key-device-a-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("does not match"),
        "device key should not perform root operations: {}",
        err.message
    );
}

#[test]
fn persona_key_cannot_add_devices() {
    let mut store = two_root_fixture();
    // Persona key tries to add a device (root-only operation)
    let event = EventEnvelope::from_body(
        "evt-persona-escalation",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-evil".into(),
            label: "evil".into(),
            initial_key: test_key("key-evil"),
            initial_encryption_key: test_encryption_key("key-evil"),
        }),
        Vec::new(),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
        &FixtureSigner::new("key-persona-a-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("does not match"),
        "persona key should not add devices: {}",
        err.message
    );
}

#[test]
fn cross_persona_trust_attestation_rejected() {
    let mut store = two_root_fixture();
    // Persona B's key tries to create a trust attestation claiming to be Persona A
    let event = EventEnvelope::from_body(
        "evt-cross-trust",
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: "trust-fake".into(),
            attester_persona_id: "persona-a".into(), // claims to be A
            subject_persona_id: "persona-b".into(),
            domain: "professional".into(),
            score: 1.0,
            recipient_bound: None,
        }),
        Vec::new(),
        SignerBinding::persona("persona-b", "key-persona-b-v1"), // but signed by B
        &FixtureSigner::new("key-persona-b-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("does not match"),
        "cross-persona attestation should be rejected: {}",
        err.message
    );
}

#[test]
fn trust_revocation_by_non_attester_rejected() {
    let mut store = two_root_fixture();
    // Persona A creates a valid trust attestation
    append_typed(
        &mut store,
        "evt-trust-1",
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: "trust-1".into(),
            attester_persona_id: "persona-a".into(),
            subject_persona_id: "persona-b".into(),
            domain: "professional".into(),
            score: 0.9,
            recipient_bound: None,
        }),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
    );
    // Persona B tries to revoke Persona A's attestation
    let event = EventEnvelope::from_body(
        "evt-trust-revoke-fake",
        EventBody::TrustRevoked(TrustRevokedEvent {
            attestation_id: "trust-1".into(),
            attester_persona_id: "persona-a".into(), // claims to be A
        }),
        Vec::new(),
        SignerBinding::persona("persona-b", "key-persona-b-v1"), // but signed by B
        &FixtureSigner::new("key-persona-b-v1"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("does not match"),
        "non-attester should not revoke trust: {}",
        err.message
    );
}

#[test]
fn frozen_device_cannot_sign_events() {
    let mut store = two_root_fixture();
    // Freeze device-a
    append_typed(
        &mut store,
        "evt-freeze-a",
        EventBody::DeviceFrozen(DeviceFrozenEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            reason: "suspicious activity".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    // Frozen device tries to rotate its own key
    let event = EventEnvelope::from_body(
        "evt-frozen-rotate",
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
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("not active"),
        "frozen device should not sign: {}",
        err.message
    );
}

#[test]
fn unknown_root_id_rejected() {
    let mut store = EventStore::default();
    // Try to add a device to a root that doesn't exist
    let event = EventEnvelope::from_body(
        "evt-phantom",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-phantom".into(),
            device_id: "device-phantom".into(),
            label: "phantom".into(),
            initial_key: test_key("key-phantom"),
            initial_encryption_key: test_encryption_key("key-phantom"),
        }),
        Vec::new(),
        SignerBinding::root("root-phantom", "key-phantom"),
        &FixtureSigner::new("key-phantom"),
    )
    .unwrap();
    let err = store
        .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(
        err.message.contains("unknown root"),
        "non-existent root should be rejected: {}",
        err.message
    );
}
