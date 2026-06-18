use super::*;

#[test]
fn service_bindings_round_trip_across_reopen_and_delete_cleanly() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-service-bindings-{unique}.sqlite"
    ));
    let binding = core_event_types::ServiceBinding {
        id: "binding-1".into(),
        persona_id: "persona-a".into(),
        descriptor: core_event_types::ServiceDescriptor {
            adapter_kind: "password".into(),
            service_label: "GitHub".into(),
            endpoint: "https://github.com".into(),
        },
        external_account_id: "alice".into(),
        created_at: 42,
    };

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

        store.upsert_service_binding(&binding).unwrap();
        assert_eq!(
            store.service_bindings_for_persona("persona-a").unwrap(),
            vec![binding.clone()]
        );
        assert_eq!(store.service_bindings().unwrap(), vec![binding.clone()]);
    }

    let mut reopened = EventStore::open(&path).unwrap();
    assert_eq!(
        reopened.service_bindings_for_persona("persona-a").unwrap(),
        vec![binding.clone()]
    );
    assert_eq!(reopened.service_bindings().unwrap(), vec![binding.clone()]);
    assert!(reopened.delete_service_binding("binding-1").unwrap());
    assert!(
        reopened
            .service_bindings_for_persona("persona-a")
            .unwrap()
            .is_empty()
    );
    assert!(reopened.service_bindings().unwrap().is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn service_binding_rejects_unknown_persona() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-service-bindings-invalid-{unique}.sqlite"
    ));

    let mut store = EventStore::open(&path).unwrap();
    let err = store
        .upsert_service_binding(&core_event_types::ServiceBinding {
            id: "binding-1".into(),
            persona_id: "persona-missing".into(),
            descriptor: core_event_types::ServiceDescriptor {
                adapter_kind: "password".into(),
                service_label: "GitHub".into(),
                endpoint: "https://github.com".into(),
            },
            external_account_id: "alice".into(),
            created_at: 42,
        })
        .unwrap_err();

    assert!(err.message.contains("unknown persona: persona-missing"));

    let _ = std::fs::remove_file(path);
}
