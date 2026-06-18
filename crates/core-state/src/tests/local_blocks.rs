use super::*;

#[test]
fn storage_manifest_helper_writes_current_rows() {
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

    let manifest = store.file_manifest("manifest-1").unwrap();
    assert_eq!(manifest.encrypted_root_chunk_id, "bafy-root-1");
    assert_eq!(manifest.chunks.len(), 2);
    assert_eq!(manifest.authorized_devices.len(), 1);
    assert_eq!(manifest.authorized_devices[0].device_id, "device-a");
}

#[test]
fn storage_manifest_publish_event_materializes_current_manifest_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-storage-event-{unique}.sqlite"
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
            "evt-storage-1",
            storage_manifest_published_event(
                "root-a",
                "storage-1",
                test_manifest("manifest-1", "bafy-root-1", "device-a"),
            ),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
    }

    let reopened = EventStore::open(&path).unwrap();
    let manifest = reopened.file_manifest("manifest-1").unwrap();
    assert_eq!(manifest.encrypted_root_chunk_id, "bafy-root-1");
    assert_eq!(manifest.chunks.len(), 2);
    assert_eq!(manifest.authorized_devices.len(), 1);
    assert_eq!(manifest.authorized_devices[0].device_id, "device-a");

    let _ = std::fs::remove_file(path);
}

#[test]
fn local_block_coverage_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("emberlink-core-state-local-blocks-{unique}.sqlite"));

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
            "evt-storage-1",
            storage_manifest_published_event(
                "root-a",
                "storage-1",
                test_manifest("manifest-1", "bafy-root-1", "device-a"),
            ),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        let manifest = store.file_manifest("manifest-1").unwrap();
        store
            .upsert_encrypted_block(&EncryptedBlock {
                chunk: manifest.chunks[0].clone(),
                encrypted: EncryptedContent {
                    nonce_hex: "nonce-root".into(),
                    ciphertext: vec![0xaa; 32],
                },
            })
            .unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let coverage = reopened
        .local_block_coverage("manifest-1")
        .unwrap()
        .unwrap();
    assert_eq!(coverage.present_chunks, 1);
    assert_eq!(coverage.total_chunks, 2);
    assert_eq!(coverage.missing_chunks.len(), 1);
    assert_eq!(
        coverage.missing_chunks[0].chunk_id,
        "bafy-root-1-chunk-0001"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn encrypted_local_block_payload_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-encrypted-blocks-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let content_key = generate_content_key("test");
    let block = encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store.upsert_encrypted_block(&block).unwrap();
    }

    let persisted_path = block_dir
        .join(&block.chunk.chunk_id[..block.chunk.chunk_id.len().min(2)])
        .join(format!("{}.blk", block.chunk.chunk_id));
    assert!(persisted_path.exists());
    let conn = rusqlite::Connection::open(&path).unwrap();
    let stored_inline = conn
        .query_row(
            "SELECT nonce_hex, ciphertext FROM local_blocks WHERE chunk_id = ?1",
            rusqlite::params![&block.chunk.chunk_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(stored_inline, (None, None));

    let reopened = EventStore::open(&path).unwrap();
    let encrypted = reopened
        .local_encrypted_content(&block.chunk.chunk_id)
        .unwrap()
        .unwrap();
    let hydrated = EncryptedBlock {
        chunk: block.chunk.clone(),
        encrypted,
    };
    let decrypted = decrypt_block(&hydrated, &content_key).unwrap();

    assert_eq!(decrypted, b"root chunk payload");

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_block_coverage_uses_filesystem_presence_for_file_backed_store() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-file-coverage-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let manifest = publish_manifest(
        "manifest-coverage",
        "chunk-root",
        vec![
            manifest_chunk("manifest-coverage", "chunk-root", 0, 1024),
            manifest_chunk("manifest-coverage", "chunk-leaf", 1, 1024),
        ],
        vec![manifest_device_access("device-a", "wrapped-device-a")],
    );
    let blocks = manifest
        .chunks
        .iter()
        .map(|chunk| EncryptedBlock {
            chunk: chunk.clone(),
            encrypted: EncryptedContent {
                nonce_hex: format!("nonce-{}", chunk.ordinal),
                ciphertext: vec![0xcc; 32],
            },
        })
        .collect::<Vec<_>>();

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
            "evt-storage-1",
            storage_manifest_published_event("root-a", "storage-1", manifest.clone()),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        for block in &blocks {
            store.upsert_encrypted_block(block).unwrap();
        }
    }

    let leaf_chunk_id = blocks[1].chunk.chunk_id.clone();
    let leaf_prefix = &leaf_chunk_id[..leaf_chunk_id.len().min(2)];
    let leaf_path = block_dir
        .join(leaf_prefix)
        .join(format!("{}.blk", leaf_chunk_id));
    std::fs::remove_file(&leaf_path).unwrap();

    let reopened = EventStore::open(&path).unwrap();
    let coverage = reopened
        .local_block_coverage("manifest-coverage")
        .unwrap()
        .unwrap();

    assert_eq!(coverage.present_chunks, 1);
    assert_eq!(coverage.missing_chunks.len(), 1);
    assert_eq!(
        coverage.missing_chunks[0].chunk_id,
        blocks[1].chunk.chunk_id
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_block_audit_reports_missing_orphaned_metadata_and_stray_files() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("emberlink-core-state-block-audit-{unique}.sqlite"));
    let block_dir = local_block_store_root(&path);
    let manifest = publish_manifest(
        "manifest-audit",
        "chunk-root",
        vec![
            manifest_chunk("manifest-audit", "chunk-root", 0, 1024),
            manifest_chunk("manifest-audit", "chunk-leaf", 1, 1024),
        ],
        vec![manifest_device_access("device-a", "wrapped-device-a")],
    );
    let blocks = manifest
        .chunks
        .iter()
        .map(|chunk| EncryptedBlock {
            chunk: chunk.clone(),
            encrypted: EncryptedContent {
                nonce_hex: format!("nonce-{}", chunk.ordinal),
                ciphertext: vec![0xdd; 32],
            },
        })
        .collect::<Vec<_>>();

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
            "evt-storage-1",
            storage_manifest_published_event("root-a", "storage-1", manifest.clone()),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        for block in &blocks {
            store.upsert_encrypted_block(block).unwrap();
        }
        store
            .upsert_local_block(&LocalBlockRecord {
                chunk_id: "orphan-metadata".into(),
                ciphertext_bytes: 64,
            })
            .unwrap();
    }

    let missing_chunk_path = block_dir.join("ch").join("chunk-leaf.blk");
    std::fs::remove_file(&missing_chunk_path).unwrap();
    let stray_chunk_path = block_dir.join("st").join("stray-file.blk");
    std::fs::create_dir_all(stray_chunk_path.parent().unwrap()).unwrap();
    std::fs::write(&stray_chunk_path, b"nonce-stray\nciphertext").unwrap();

    let reopened = EventStore::open(&path).unwrap();
    let audit = reopened.audit_local_blocks().unwrap();

    assert_eq!(
        audit.referenced_chunk_ids,
        BTreeSet::from(["chunk-leaf".to_string(), "chunk-root".to_string()])
    );
    assert_eq!(
        audit.missing_referenced_chunk_ids,
        BTreeSet::from(["chunk-leaf".to_string()])
    );
    assert_eq!(
        audit.orphaned_metadata_chunk_ids,
        BTreeSet::from(["orphan-metadata".to_string()])
    );
    assert_eq!(
        audit.orphaned_file_chunk_ids,
        BTreeSet::from(["stray-file".to_string()])
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn encrypted_local_block_payload_round_trips_in_memory_without_filesystem_store() {
    let content_key = generate_content_key("test");
    let block = encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();
    let mut store = EventStore::open_in_memory().unwrap();

    store.upsert_encrypted_block(&block).unwrap();

    let encrypted = store
        .local_encrypted_content(&block.chunk.chunk_id)
        .unwrap()
        .unwrap();
    let hydrated = EncryptedBlock {
        chunk: block.chunk.clone(),
        encrypted,
    };

    assert_eq!(
        decrypt_block(&hydrated, &content_key).unwrap(),
        b"root chunk payload"
    );
}
