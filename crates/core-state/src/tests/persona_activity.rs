use super::*;

#[test]
fn persona_signed_message_and_content_events_round_trip_through_store() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("emberlink-core-state-message-{unique}.sqlite"));

    {
        let mut store = EventStore::open(&path).unwrap();
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
            "evt-message-1",
            EventBody::MessageSent(MessageSentEvent {
                message_id: "message-1".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "c0ffee".into(),
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-content-1",
            EventBody::ContentPublished(ContentPublishedEvent {
                content_id: "content-1".into(),
                author_persona_id: "persona-a".into(),
                content_type: "post".into(),
                payload_hex: "deadbeef".into(),
                visibility: ContentVisibility::TrustGated,
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );

        assert_eq!(store.event_count(), 4);
        assert_eq!(
            store.current_event_type_for("evt-message-1"),
            Some(EventType::MessageSent)
        );
        assert_eq!(
            store.current_event_type_for("evt-content-1"),
            Some(EventType::ContentPublished)
        );
        assert!(store.materialized().persona("persona-a").is_some());
    }

    let reopened = EventStore::open(&path).unwrap();
    assert_eq!(reopened.event_count(), 4);
    assert_eq!(
        reopened.current_event_type_for("evt-message-1"),
        Some(EventType::MessageSent)
    );
    assert_eq!(
        reopened.current_event_type_for("evt-content-1"),
        Some(EventType::ContentPublished)
    );
    assert!(reopened.materialized().persona("persona-a").is_some());

    let _ = std::fs::remove_file(path);
}

#[test]
fn message_and_content_events_require_active_persona_signer() {
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

    let message = EventEnvelope::from_body(
        "evt-message-1",
        EventBody::MessageSent(MessageSentEvent {
            message_id: "message-1".into(),
            sender_persona_id: "persona-a".into(),
            recipient_persona_id: "persona-b".into(),
            ciphertext_hex: "c0ffee".into(),
        }),
        Vec::new(),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
        &FixtureSigner::new("key-persona-a-v1"),
    )
    .unwrap();
    let content = EventEnvelope::from_body(
        "evt-content-1",
        EventBody::ContentPublished(ContentPublishedEvent {
            content_id: "content-1".into(),
            author_persona_id: "persona-a".into(),
            content_type: "post".into(),
            payload_hex: "deadbeef".into(),
            visibility: ContentVisibility::Public,
        }),
        Vec::new(),
        SignerBinding::persona("persona-a", "key-persona-a-v1"),
        &FixtureSigner::new("key-persona-a-v1"),
    )
    .unwrap();

    let message_err = store
        .append_with_authorizer(message, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(message_err.message.contains("not active"));

    let content_err = store
        .append_with_authorizer(content, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(content_err.message.contains("not active"));
}
