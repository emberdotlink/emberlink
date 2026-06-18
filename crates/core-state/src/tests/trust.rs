use super::*;

#[test]
fn trust_attestations_materialize_current_and_derived_state_and_can_be_revoked() {
    let mut store = EventStore::default();
    append_typed(
        &mut store,
        "evt-root-a",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-root-b",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-b".into(),
            display_name: "Secondary".into(),
            initial_key: test_key("key-root-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-a",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            label: "Professional".into(),
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-b",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-b".into(),
            persona_id: "persona-b".into(),
            label: "Pseudonymous".into(),
            disclosure_profile: Some("persona.pseudonymous".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-trust-1",
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: "trust-1".into(),
            attester_persona_id: "persona-a".into(),
            subject_persona_id: "persona-b".into(),
            domain: "relay".into(),
            score: 0.8,
            recipient_bound: None,
        }),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
    );

    assert_eq!(store.materialized().trust_edges_current.len(), 1);
    assert_eq!(store.materialized().derived_trust_current.len(), 1);
    assert!(
        (store
            .materialized()
            .derived_trust_current
            .get("derived:persona-b:relay")
            .unwrap()
            .normalized_score
            - 0.8)
            .abs()
            < f32::EPSILON
    );

    append_typed(
        &mut store,
        "evt-trust-revoke-1",
        EventBody::TrustRevoked(TrustRevokedEvent {
            attestation_id: "trust-1".into(),
            attester_persona_id: "persona-a".into(),
        }),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
    );

    assert!(store.materialized().trust_edges_current.is_empty());
    assert!(store.materialized().derived_trust_current.is_empty());
}

#[test]
fn recipient_bound_trust_attestations_do_not_change_public_derived_state() {
    let mut store = EventStore::default();
    append_typed(
        &mut store,
        "evt-root-a",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-root-b",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-b".into(),
            display_name: "Secondary".into(),
            initial_key: test_key("key-root-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-a",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            label: "Professional".into(),
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-persona-b",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-b".into(),
            persona_id: "persona-b".into(),
            label: "Pseudonymous".into(),
            disclosure_profile: Some("persona.pseudonymous".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-trust-public",
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: "trust-public".into(),
            attester_persona_id: "persona-a".into(),
            subject_persona_id: "persona-b".into(),
            domain: "relay".into(),
            score: 0.8,
            recipient_bound: None,
        }),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-trust-recipient",
        EventBody::TrustAttested(TrustAttestedEvent {
            attestation_id: "trust-hidden".into(),
            attester_persona_id: "persona-a".into(),
            subject_persona_id: "persona-b".into(),
            domain: "relay".into(),
            score: 0.2,
            recipient_bound: Some("peer-demo".into()),
        }),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
    );

    assert_eq!(store.materialized().trust_edges_current.len(), 2);
    assert!(
        (store
            .materialized()
            .derived_trust_current
            .get("derived:persona-b:relay")
            .unwrap()
            .normalized_score
            - 0.8)
            .abs()
            < f32::EPSILON
    );
}
