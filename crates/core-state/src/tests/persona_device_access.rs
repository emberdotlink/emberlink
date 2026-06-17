use super::*;

#[test]
fn local_persona_device_access_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("emberlink-core-state-access-{unique}.sqlite"));

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

        store
            .grant_persona_device_access("persona-a", "device-a")
            .unwrap();
        assert_eq!(
            store
                .persona_device_access_for_persona("persona-a")
                .unwrap(),
            vec![PersonaDeviceAccessRecord {
                persona_id: "persona-a".into(),
                device_id: "device-a".into(),
            }]
        );
    }

    let reopened = EventStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .persona_device_access_for_persona("persona-a")
            .unwrap(),
        vec![PersonaDeviceAccessRecord {
            persona_id: "persona-a".into(),
            device_id: "device-a".into(),
        }]
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn persona_device_access_requires_same_active_root_membership() {
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
        "evt-root-2",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-b".into(),
            display_name: "Other".into(),
            initial_key: test_key("key-root-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-1",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-b".into(),
            device_id: "device-b".into(),
            label: "Tablet".into(),
            initial_key: test_key("key-device-b-v1"),
            initial_encryption_key: test_encryption_key("key-device-b-v1"),
        }),
        SignerBinding::root("root-b", "key-root-b-v1"),
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

    let err = store
        .grant_persona_device_access("persona-a", "device-b")
        .unwrap_err();
    assert!(err.message.contains("same root"));
}
