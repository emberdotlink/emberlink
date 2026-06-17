use super::*;

#[test]
fn storage_relationship_and_ledger_events_materialize_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-storage-ledger-{unique}.sqlite"
    ));

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
            "evt-storage-relationship-1",
            storage_relationship_created_event(
                "root-a",
                create_relationship("storage-1", "peer-a", "peer-b"),
            ),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-storage-ledger-1",
            storage_ledger_updated_event("root-a", ledger_delta("storage-1", 524_288)),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
    }

    let reopened = EventStore::open(&path).unwrap();
    let relationship = reopened
        .materialized()
        .storage_relationships_current
        .get("storage-1")
        .unwrap();
    let balance = reopened
        .materialized()
        .storage_balances_current
        .get("storage-1")
        .unwrap();

    assert_eq!(relationship.local_peer_id, "peer-a");
    assert_eq!(relationship.remote_peer_id, "peer-b");
    assert!(relationship.approved);
    assert_eq!(balance.stored_bytes_delta, 524_288);

    let _ = std::fs::remove_file(path);
}
