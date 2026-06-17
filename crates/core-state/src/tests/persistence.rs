use super::*;

#[test]
fn sqlite_store_round_trips_events_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("emberlink-core-state-{unique}.sqlite"));

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
    }

    let reopened = EventStore::open(&path).unwrap();
    assert_eq!(reopened.event_count(), 2);
    assert_eq!(
        reopened.current_event_type_for("evt-device-1"),
        Some(EventType::DeviceAdded)
    );
    assert_eq!(
        reopened.materialized().device("device-a").unwrap().label,
        "Laptop"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn imported_sync_batches_persist_events_and_peer_cursor_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let local_path =
        std::env::temp_dir().join(format!("emberlink-core-state-sync-local-{unique}.sqlite"));
    let remote_path =
        std::env::temp_dir().join(format!("emberlink-core-state-sync-remote-{unique}.sqlite"));

    {
        let mut remote = EventStore::open(&remote_path).unwrap();
        append_typed(
            &mut remote,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut remote,
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

        let remote_events = remote.events().to_vec();
        let last_remote_event_id = remote.events().last().map(|event| event.event_id.as_str());

        let mut local = EventStore::open(&local_path).unwrap();
        let imported = local
            .import_sync_batch(
                "peer-b",
                "batch-1",
                &remote_events,
                last_remote_event_id,
                &FixtureVerifier,
                &IdentityAuthorizer,
                0,
            )
            .unwrap();

        assert_eq!(imported, 2);
        assert_eq!(local.event_count(), 2);
        assert_eq!(
            local
                .peer_cursor("peer-b")
                .unwrap()
                .last_event_id
                .as_deref(),
            Some("evt-device-1")
        );
        let sync_batches: i64 = local
            .conn
            .query_row("SELECT COUNT(*) FROM sync_batches", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sync_batches, 1);
    }

    let reopened = EventStore::open(&local_path).unwrap();
    assert_eq!(reopened.event_count(), 2);
    assert_eq!(
        reopened
            .peer_cursor("peer-b")
            .unwrap()
            .last_event_id
            .as_deref(),
        Some("evt-device-1")
    );
    assert_eq!(
        reopened.peer_cursors().unwrap(),
        vec![PeerCursor {
            peer_id: "peer-b".into(),
            last_event_id: Some("evt-device-1".into()),
        }]
    );
    assert_eq!(
        reopened.sync_batches().unwrap(),
        vec![SyncBatchRecord {
            batch_id: "batch-1".into(),
            peer_id: "peer-b".into(),
            last_event_id: Some("evt-device-1".into()),
        }]
    );
    assert!(reopened.materialized().root("root-a").is_some());
    assert!(reopened.materialized().device("device-a").is_some());

    let _ = std::fs::remove_file(local_path);
    let _ = std::fs::remove_file(remote_path);
}

#[test]
fn duplicate_event_ids_fail_inside_sqlite_store() {
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

    let duplicate = EventEnvelope::from_body(
        "evt-root-1",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-b".into(),
            display_name: "Other".into(),
            initial_key: test_key("key-root-b-v1"),
        }),
        Vec::new(),
        SignerBinding::root("root-b", "key-root-b-v1"),
        &FixtureSigner::new("key-root-b-v1"),
    )
    .unwrap();

    let err = store
        .append_with_authorizer(duplicate, &FixtureVerifier, &IdentityAuthorizer, 0)
        .unwrap_err();
    assert!(err.message.contains("insert event row"));
}

#[test]
fn current_event_type_uses_reloaded_persistent_events() {
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

    assert_eq!(
        store.current_event_type_for("evt-root-1"),
        Some(EventType::RootCreated)
    );

    let stored_signature: Option<String> = store
        .conn
        .query_row(
            "SELECT signature FROM event_signatures WHERE event_id = ?1",
            params!["evt-root-1"],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert!(stored_signature.is_some());
}

#[test]
fn event_ids_preserve_append_order() {
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
        EventBody::RootRevoked(RootRevokedEvent {
            root_id: "root-a".into(),
            reason: "test".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    assert_eq!(
        store.event_ids(),
        vec!["evt-root-1".to_string(), "evt-root-2".to_string()]
    );
}
