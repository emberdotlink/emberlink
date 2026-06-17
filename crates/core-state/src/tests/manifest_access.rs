use super::*;

#[test]
fn replacement_device_can_take_over_local_vault_manifest_access() {
    let mut store = EventStore::default();
    let device_a_encryption = generate_local_encryption_key_pair("device", "device-a");
    let device_b_encryption = generate_local_encryption_key_pair("device", "device-b");
    let namespace = test_namespace();
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
            initial_encryption_key: PublicKeyMaterial {
                key_id: device_a_encryption.key_id.clone(),
                algorithm: device_a_encryption.algorithm,
                public_key: device_a_encryption.public_key.clone(),
            },
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        &mut store,
        "evt-device-2",
        EventBody::DeviceAdded(DeviceAddedEvent {
            root_id: "root-a".into(),
            device_id: "device-b".into(),
            label: "Replacement".into(),
            initial_key: test_key("key-device-b-v1"),
            initial_encryption_key: PublicKeyMaterial {
                key_id: device_b_encryption.key_id.clone(),
                algorithm: device_b_encryption.algorithm,
                public_key: device_b_encryption.public_key.clone(),
            },
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
        .upsert_local_structured_record(
            &namespace,
            "obj-local-1",
            "rev-local-1",
            "manifest-local-record-1",
            "manifest-local-catalog-1",
            1,
            "device-a",
            core_event_types::StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_event_types::StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            },
            br#"{"full_name":"Jordan Hudson"}"#,
            core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_event_types::RetentionPolicy::KeepLatest,
            vec![manifest_key_recipient(
                "device-a",
                device_a_encryption.public_key.clone(),
            )],
        )
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

    let updated = store
        .restore_local_vault_access_to_replacement_device(&namespace, "device-a", "device-b")
        .unwrap();

    assert_eq!(
        updated,
        vec![
            "manifest-local-catalog-1".to_string(),
            "manifest-local-record-1".to_string()
        ]
    );
    let catalog_manifest = store
        .local_file_manifest("manifest-local-catalog-1")
        .unwrap()
        .unwrap();
    let payload_manifest = store
        .local_file_manifest("manifest-local-record-1")
        .unwrap()
        .unwrap();
    assert_eq!(catalog_manifest.authorized_devices.len(), 1);
    assert_eq!(catalog_manifest.authorized_devices[0].device_id, "device-b");
    assert_eq!(payload_manifest.authorized_devices.len(), 1);
    assert_eq!(payload_manifest.authorized_devices[0].device_id, "device-b");
}

#[test]
fn frozen_device_can_be_revoked_from_local_vault_manifest_access() {
    let mut store = EventStore::default();
    let device_a_encryption = generate_local_encryption_key_pair("device", "device-a");
    let namespace = test_namespace();
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
            initial_encryption_key: PublicKeyMaterial {
                key_id: device_a_encryption.key_id.clone(),
                algorithm: device_a_encryption.algorithm,
                public_key: device_a_encryption.public_key.clone(),
            },
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
        .upsert_local_structured_record(
            &namespace,
            "obj-local-1",
            "rev-local-1",
            "manifest-local-record-1",
            "manifest-local-catalog-1",
            1,
            "device-a",
            core_event_types::StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_event_types::StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            },
            br#"{"full_name":"Jordan Hudson"}"#,
            core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_event_types::RetentionPolicy::KeepLatest,
            vec![manifest_key_recipient(
                "device-a",
                device_a_encryption.public_key.clone(),
            )],
        )
        .unwrap();
    append_typed(
        &mut store,
        "evt-device-frozen-1",
        EventBody::DeviceFrozen(DeviceFrozenEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            reason: "lost".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let updated = store
        .revoke_local_vault_access_for_inactive_device(&namespace, "device-a")
        .unwrap();

    assert_eq!(
        updated,
        vec![
            "manifest-local-catalog-1".to_string(),
            "manifest-local-record-1".to_string()
        ]
    );
    let catalog_manifest = store
        .local_file_manifest("manifest-local-catalog-1")
        .unwrap()
        .unwrap();
    let payload_manifest = store
        .local_file_manifest("manifest-local-record-1")
        .unwrap()
        .unwrap();
    assert!(catalog_manifest.authorized_devices.is_empty());
    assert!(payload_manifest.authorized_devices.is_empty());
}

#[test]
fn frozen_device_cannot_restore_manifest_and_access_can_be_revoked() {
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
    store
        .upsert_file_manifest(&test_manifest("manifest-1", "bafy-root-1", "device-a"))
        .unwrap();

    let relationship = create_relationship("storage-1", "peer-a", "peer-b");
    assert!(
        store
            .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
            .is_ok()
    );

    append_typed(
        &mut store,
        "evt-device-freeze-1",
        EventBody::DeviceFrozen(core_event_types::DeviceFrozenEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            reason: "lost".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let err = store
        .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
        .unwrap_err();
    assert!(err.message.contains("active device"));

    store
        .revoke_manifest_access_for_inactive_device("manifest-1", "device-a")
        .unwrap();
    let manifest = store.file_manifest("manifest-1").unwrap();
    assert!(manifest.authorized_devices.is_empty());
}

#[test]
fn replacement_device_can_take_over_manifest_access_after_recovery() {
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
            label: "Replacement".into(),
            initial_key: test_key("key-device-b-v1"),
            initial_encryption_key: test_encryption_key("key-device-b-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    store
        .upsert_file_manifest(&test_manifest("manifest-1", "bafy-root-1", "device-a"))
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
        .restore_manifest_access_to_replacement_device(
            "manifest-1",
            "device-a",
            manifest_device_access("device-b", "wrapped-b"),
        )
        .unwrap();

    let manifest = store.file_manifest("manifest-1").unwrap();
    assert_eq!(manifest.authorized_devices.len(), 1);
    assert_eq!(manifest.authorized_devices[0].device_id, "device-b");

    let relationship = create_relationship("storage-1", "peer-a", "peer-b");
    assert!(
        store
            .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
            .is_err()
    );
    assert_eq!(
        store
            .select_active_restore_device_for_manifest("manifest-1")
            .unwrap(),
        "device-b"
    );
    let (restore_device_id, restore_chunks) = store
        .plan_storage_restore("manifest-1", &relationship)
        .unwrap();
    assert_eq!(restore_device_id, "device-b");
    assert_eq!(restore_chunks.len(), 2);
    assert!(
        store
            .plan_storage_restore_for_device("manifest-1", "device-b", &relationship)
            .is_ok()
    );
}
