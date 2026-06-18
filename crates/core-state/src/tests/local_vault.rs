use super::*;

#[test]
fn local_encrypted_manifest_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-local-encrypted-manifest-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let content_key = generate_content_key("test");
    let plaintext_chunks = vec![
        br#"{"kind":"structured-record"}"#.to_vec(),
        b"payload tail".to_vec(),
    ];
    let (manifest, blocks) = core_storage::seal_payload_manifest(
        "manifest-local-payload-1",
        &plaintext_chunks,
        &content_key,
        vec![manifest_device_access("device-a", "wrapped-device-a")],
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .upsert_local_encrypted_manifest(&manifest, &blocks)
            .unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded_manifest = reopened
        .local_file_manifest("manifest-local-payload-1")
        .unwrap()
        .unwrap();
    let hydrated_blocks = loaded_manifest
        .chunks
        .iter()
        .map(|chunk| EncryptedBlock {
            chunk: chunk.clone(),
            encrypted: reopened
                .local_encrypted_content(&chunk.chunk_id)
                .unwrap()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    let decrypted =
        core_storage::open_payload_manifest(&loaded_manifest, &hydrated_blocks, &content_key)
            .unwrap();

    assert_eq!(loaded_manifest, manifest);
    assert_eq!(decrypted, plaintext_chunks);

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_vault_catalog_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-vault-catalog-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");
    let content_key = generate_content_key("vault-catalog");
    let catalog = VaultCatalog {
        namespace: test_namespace(),
        objects: vec![core_event_types::VaultObject {
            id: "obj-1".into(),
            namespace: test_namespace(),
            class: core_event_types::VaultObjectClass::StructuredRecord,
            latest_revision_id: "rev-1".into(),
            created_at: 1,
            updated_at: 1,
            durability: core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            retention: core_event_types::RetentionPolicy::KeepLatest,
            deleted: false,
        }],
        revisions: vec![core_event_types::VaultRevision {
            id: "rev-1".into(),
            object_id: "obj-1".into(),
            manifest_id: "manifest-record-1".into(),
            payload_kind: core_event_types::PayloadKind::StructuredRecord,
            content_type: "application/json".into(),
            created_at: 1,
            created_by_device_id: "device-a".into(),
            parent_revision_id: None,
            structured_record: Some(core_event_types::StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_event_types::StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            }),
            claim: None,
        }],
    };

    {
        let mut store = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
        store
            .upsert_local_vault_catalog(
                "manifest-catalog-1",
                &catalog,
                &content_key,
                vec![manifest_device_access("device-a", "wrapped-device-a")],
            )
            .unwrap();
    }

    // Assert the catalog content key is encrypted at rest.
    let ns = test_namespace();
    let raw_conn = rusqlite::Connection::open(&path).unwrap();
    let raw_content_key: String = raw_conn
        .query_row(
            "SELECT content_key FROM local_vault_catalogs WHERE owner_kind = ?1 AND owner_id = ?2",
            rusqlite::params![ns.owner_kind.as_str(), &ns.owner_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        raw_content_key.starts_with("ENC1:"),
        "expected encrypted content_key in SQLite, got: {raw_content_key}"
    );

    // Assert round-trip recovers the original catalog.
    let reopened = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
    let loaded = reopened
        .local_vault_catalog(&test_namespace())
        .unwrap()
        .unwrap();
    assert_eq!(loaded, catalog);

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn upsert_local_structured_record_creates_and_advances_catalog_head() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-structured-record-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let meta = core_event_types::StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    };

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-1",
                "rev-1",
                "manifest-record-1",
                "manifest-catalog-1",
                1,
                "device-a",
                meta.clone(),
                br#"{"full_name":"Jane"}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-1",
                "rev-2",
                "manifest-record-2",
                "manifest-catalog-2",
                2,
                "device-a",
                meta,
                br#"{"full_name":"Jane Doe","skills":["rust"]}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
    let object = catalog
        .objects
        .iter()
        .find(|object| object.id == "obj-1")
        .unwrap();

    assert_eq!(object.latest_revision_id, "rev-2");
    assert_eq!(catalog.revisions.len(), 2);
    assert_eq!(
        String::from_utf8(
            reopened
                .local_manifest_payload_bytes("manifest-record-2")
                .unwrap()
        )
        .unwrap(),
        r#"{"full_name":"Jane Doe","skills":["rust"]}"#
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn upsert_local_structured_record_rejects_non_object_json_payloads() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-structured-record-invalid-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let meta = core_event_types::StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    };

    let err = EventStore::open(&path)
        .unwrap()
        .upsert_local_structured_record(
            &namespace,
            "obj-1",
            "rev-1",
            "manifest-record-1",
            "manifest-catalog-1",
            1,
            "device-a",
            meta,
            br#"["not","an","object"]"#,
            core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_event_types::RetentionPolicy::KeepLatest,
            vec![test_manifest_recipient("device-a")],
        )
        .unwrap_err();

    assert!(err.message.contains("json object"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn upsert_local_persona_credential_round_trips_claim_meta_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-persona-credential-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let meta = core_event_types::StructuredRecordMeta {
        schema_id: "emberlink:claim:password:1.0".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "emberlink".into(),
    };
    let claim = test_claim_meta();

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .upsert_local_persona_credential(
                &namespace,
                "obj-cred-1",
                "rev-cred-1",
                "manifest-cred-1",
                "manifest-catalog-cred-1",
                42,
                "device-a",
                meta,
                claim.clone(),
                br#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
    let object = catalog
        .objects
        .iter()
        .find(|object| object.id == "obj-cred-1")
        .unwrap();
    let revision = catalog
        .revisions
        .iter()
        .find(|revision| revision.id == "rev-cred-1")
        .unwrap();

    assert_eq!(
        object.class,
        core_event_types::VaultObjectClass::PersonaCredential
    );
    assert_eq!(revision.claim.as_ref(), Some(&claim));
    assert_eq!(
        String::from_utf8(
            reopened
                .local_manifest_payload_bytes("manifest-cred-1")
                .unwrap()
        )
        .unwrap(),
        r#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn upsert_local_persona_credential_rejects_non_persona_namespace() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-persona-credential-invalid-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = VaultNamespace {
        owner_kind: core_event_types::VaultOwnerKind::Root,
        owner_id: "root-a".into(),
    };

    let err = EventStore::open(&path)
        .unwrap()
        .upsert_local_persona_credential(
            &namespace,
            "obj-cred-1",
            "rev-cred-1",
            "manifest-cred-1",
            "manifest-catalog-cred-1",
            42,
            "device-a",
            core_event_types::StructuredRecordMeta {
                schema_id: "emberlink:claim:password:1.0".into(),
                schema_version: "v1".into(),
                encoding: core_event_types::StructuredEncoding::Json,
                app_namespace: "emberlink".into(),
            },
            test_claim_meta(),
            br#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#,
            core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_event_types::RetentionPolicy::KeepLatest,
            vec![test_manifest_recipient("device-a")],
        )
        .unwrap_err();

    assert!(err.message.contains("persona-owned namespace"));

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn import_persona_credentials_creates_persona_credential_objects() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-imported-credentials-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();

    let imported_claim = core_event_types::ImportedClaim {
        claim_type: core_event_types::ClaimType::SelfAsserted.as_str().into(),
        payload_json: r#"{"schema":"emberlink:claim:password:1.0","service_name":"GitHub","service_url":"https://github.com","username":"alice","password":"secret","totp_secret":null,"notes":"imported"}"#.into(),
        external_issuer: "bitwarden".into(),
        external_issued_at: Some(42),
        external_expires_at: None,
    };

    {
        let mut store = EventStore::open(&path).unwrap();
        let revisions = store
            .import_persona_credentials(
                &namespace,
                "device-a",
                std::slice::from_ref(&imported_claim),
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(
            revisions[0]
                .claim
                .as_ref()
                .unwrap()
                .external_issuer
                .as_deref(),
            Some("bitwarden")
        );
    }

    let reopened = EventStore::open(&path).unwrap();
    let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
    assert_eq!(catalog.objects.len(), 1);
    assert_eq!(
        catalog.objects[0].class,
        core_event_types::VaultObjectClass::PersonaCredential
    );
    assert_eq!(
        catalog.revisions[0].claim.as_ref().unwrap().claim_schema,
        "emberlink:claim:password:1.0"
    );
    assert_eq!(
        catalog.revisions[0]
            .claim
            .as_ref()
            .unwrap()
            .external_issuer
            .as_deref(),
        Some("bitwarden")
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn tombstoned_local_vault_object_blocks_updates_disclosure_and_becomes_collectable() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("emberlink-core-state-vault-delete-{unique}.sqlite"));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let meta = core_event_types::StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    };
    let template = core_storage::create_presentation_template(
        "template-delete-1",
        namespace.clone(),
        "obj-delete-1",
        "com.example.profile/basic",
        core_event_types::PresentationAudienceKind::Service,
        vec!["full_name".into()],
        Some(3600),
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-delete-1",
                "rev-delete-1",
                "manifest-record-delete-1",
                "manifest-catalog-delete-1",
                1,
                "device-a",
                meta.clone(),
                br#"{"full_name":"Jane Doe","private":{"ssn":"000-00-0000"}}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
        store.upsert_local_presentation_template(&template).unwrap();

        store
            .tombstone_local_vault_object(
                &namespace,
                "obj-delete-1",
                "manifest-catalog-delete-2",
                2,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();

        let err = store
            .upsert_local_structured_record(
                &namespace,
                "obj-delete-1",
                "rev-delete-2",
                "manifest-record-delete-2",
                "manifest-catalog-delete-3",
                3,
                "device-a",
                meta,
                br#"{"full_name":"Jane Updated"}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap_err();
        assert!(err.message.contains("deleted"));

        let err = store
            .issue_local_presentation_artifact(
                &namespace,
                "rev-delete-1",
                "template-delete-1",
                "artifact-delete-1",
                "manifest-artifact-delete-1",
                "svc.example",
                10,
                Some(3700),
                vec![test_manifest_recipient("device-a")],
                None,
            )
            .unwrap_err();
        assert!(err.message.contains("deleted"));

        let plan = store.plan_local_vault_gc(&namespace).unwrap().unwrap();
        assert_eq!(
            plan.collectable_manifest_ids,
            BTreeSet::from([
                "manifest-catalog-delete-1".to_string(),
                "manifest-record-delete-1".to_string(),
            ])
        );
    }

    let reopened = EventStore::open(&path).unwrap();
    let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
    let object = catalog
        .objects
        .iter()
        .find(|object| object.id == "obj-delete-1")
        .unwrap();
    assert!(object.deleted);

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_file_manifest_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-local-manifest-{unique}.sqlite"
    ));
    let manifest = test_manifest("manifest-local-1", "chunk-local-root", "device-a");

    {
        let mut store = EventStore::open(&path).unwrap();
        store.upsert_local_file_manifest(&manifest).unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded = reopened
        .local_file_manifest("manifest-local-1")
        .unwrap()
        .unwrap();

    assert_eq!(loaded, manifest);

    let _ = std::fs::remove_file(path);
}

#[test]
fn local_manifest_key_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-local-manifest-key-{unique}.sqlite"
    ));
    let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");

    {
        let mut store = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
        store
            .upsert_local_manifest_key("manifest-local-1", "content-key-1")
            .unwrap();
    }

    // Assert the value is encrypted at rest (raw SQLite value starts with ENC1:).
    let raw_conn = rusqlite::Connection::open(&path).unwrap();
    let raw_value: String = raw_conn
        .query_row(
            "SELECT content_key FROM local_manifest_keys WHERE manifest_id = 'manifest-local-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        raw_value.starts_with("ENC1:"),
        "expected encrypted value in SQLite, got: {raw_value}"
    );

    // Assert round-trip recovers the original value.
    let reopened = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
    let loaded = reopened.local_manifest_key("manifest-local-1").unwrap();
    // N6-deeper: local_manifest_key returns Option<Zeroizing<String>>.
    assert_eq!(loaded.as_ref().map(|z| z.as_str()), Some("content-key-1"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn local_device_encryption_key_round_trips_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-device-encryption-key-{unique}.sqlite"
    ));
    let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");
    let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");

    {
        let mut store = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
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
                    key_id: encryption_key_pair.key_id.clone(),
                    algorithm: encryption_key_pair.algorithm,
                    public_key: encryption_key_pair.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
            .unwrap();
    }

    // Assert the private key is encrypted at rest (raw SQLite value starts with ENC1:).
    let raw_conn = rusqlite::Connection::open(&path).unwrap();
    let raw_private_key: String = raw_conn
        .query_row(
            "SELECT private_key FROM local_device_encryption_keys WHERE device_id = 'device-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        raw_private_key.starts_with("ENC1:"),
        "expected encrypted private key in SQLite, got: {raw_private_key}"
    );

    // Assert round-trip recovers the original key pair.
    let reopened = EventStore::open_with_key(&path, (*master_key).clone()).unwrap();
    let loaded = reopened
        .local_device_encryption_key_pair("device-a")
        .unwrap()
        .unwrap();
    // PartialEq derive was removed to avoid a timing leak; compare fields explicitly.
    assert_eq!(loaded.algorithm, encryption_key_pair.algorithm);
    assert_eq!(loaded.public_key, encryption_key_pair.public_key);
    assert_eq!(loaded.private_key, encryption_key_pair.private_key);

    let _ = std::fs::remove_file(path);
}

#[test]
fn unwrap_manifest_key_for_device_caches_key_and_opens_payload() {
    let mut store = EventStore::default();
    let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");
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
                key_id: encryption_key_pair.key_id.clone(),
                algorithm: encryption_key_pair.algorithm,
                public_key: encryption_key_pair.public_key.clone(),
            },
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    store
        .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
        .unwrap();

    let content_key = generate_content_key("test");
    let first_block = encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();
    let second_block = encrypt_block("manifest-1", 1, b"leaf chunk payload", &content_key).unwrap();
    let manifest = publish_manifest(
        "manifest-1",
        first_block.chunk.chunk_id.clone(),
        vec![first_block.chunk.clone(), second_block.chunk.clone()],
        vec![
            wrap_manifest_key_access("device-a", &encryption_key_pair.public_key, &content_key)
                .unwrap(),
        ],
    );
    store.upsert_file_manifest(&manifest).unwrap();
    store.upsert_encrypted_block(&first_block).unwrap();
    store.upsert_encrypted_block(&second_block).unwrap();

    assert!(store.local_manifest_key("manifest-1").unwrap().is_none());
    // N6-deeper: unwrap_manifest_key_for_device returns Zeroizing<String>.
    assert_eq!(
        store
            .unwrap_manifest_key_for_device("manifest-1", "device-a")
            .unwrap()
            .as_str(),
        content_key.as_str()
    );
    assert_eq!(
        store
            .local_manifest_key("manifest-1")
            .unwrap()
            .as_ref()
            .map(|z| z.as_str()),
        Some(content_key.as_str())
    );
    assert_eq!(
        store
            .manifest_payload_chunks_for_device("manifest-1", "device-a")
            .unwrap(),
        vec![
            b"root chunk payload".to_vec(),
            b"leaf chunk payload".to_vec()
        ]
    );
    assert_eq!(
        store
            .manifest_payload_bytes_for_device("manifest-1", "device-a")
            .unwrap(),
        b"root chunk payloadleaf chunk payload".to_vec()
    );
    assert_eq!(
        store.open_manifest_payload("manifest-1").unwrap(),
        (
            "device-a".to_string(),
            vec![
                b"root chunk payload".to_vec(),
                b"leaf chunk payload".to_vec()
            ]
        )
    );
    assert_eq!(
        store.prime_manifest_keys_for_device("device-a").unwrap(),
        vec!["manifest-1".to_string()]
    );
}

#[test]
fn manifest_open_requires_active_authorized_device_with_runtime_key() {
    let mut store = EventStore::default();
    let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");
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
                key_id: encryption_key_pair.key_id.clone(),
                algorithm: encryption_key_pair.algorithm,
                public_key: encryption_key_pair.public_key.clone(),
            },
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );

    let content_key = generate_content_key("test");
    let first_block = encrypt_block("manifest-1", 0, b"payload", &content_key).unwrap();
    let manifest = publish_manifest(
        "manifest-1",
        first_block.chunk.chunk_id.clone(),
        vec![first_block.chunk.clone()],
        vec![
            wrap_manifest_key_access("device-a", &encryption_key_pair.public_key, &content_key)
                .unwrap(),
        ],
    );
    store.upsert_file_manifest(&manifest).unwrap();
    store.upsert_encrypted_block(&first_block).unwrap();

    let missing_key_err = store
        .unwrap_manifest_key_for_device("manifest-1", "device-a")
        .unwrap_err();
    assert!(
        missing_key_err
            .message
            .contains("missing local device encryption key")
    );

    let stale_key_pair = generate_local_encryption_key_pair("device", "device-a-stale");
    let stale_key_err = store
        .upsert_local_device_encryption_key(
            "device-a",
            &LocalKeyPair {
                key_id: encryption_key_pair.key_id.clone(),
                algorithm: encryption_key_pair.algorithm,
                public_key: encryption_key_pair.public_key.clone(),
                private_key: stale_key_pair.private_key.clone(),
            },
        )
        .and_then(|_| store.unwrap_manifest_key_for_device("manifest-1", "device-a"))
        .unwrap_err();
    assert!(
        stale_key_err.message.contains("decrypt wrapped secret")
            || stale_key_err.message.contains("read wrapped secret")
            || stale_key_err.message.contains("invalid x25519 identity")
    );
    assert!(store.local_manifest_key("manifest-1").unwrap().is_none());

    store
        .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
        .unwrap();
    append_typed(
        &mut store,
        "evt-device-freeze-1",
        EventBody::DeviceFrozen(DeviceFrozenEvent {
            root_id: "root-a".into(),
            device_id: "device-a".into(),
            reason: "lost".into(),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    let frozen_err = store
        .manifest_payload_bytes_for_device("manifest-1", "device-a")
        .unwrap_err();
    assert!(frozen_err.message.contains("active device"));
}

#[test]
fn local_vault_gc_plan_uses_catalog_retention_and_local_manifests() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("emberlink-core-state-vault-gc-{unique}.sqlite"));
    let block_dir = local_block_store_root(&path);
    {
        let mut store = EventStore::open(&path).unwrap();
        seed_gc_test_catalog(&mut store).unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let plan = reopened
        .plan_local_vault_gc(&test_namespace())
        .unwrap()
        .unwrap();

    assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc");
    assert_eq!(
        plan.retained_revision_ids,
        BTreeSet::from(["rev-2".to_string()])
    );
    assert_eq!(
        plan.retained_manifest_ids,
        BTreeSet::from([
            "manifest-catalog-gc".to_string(),
            "manifest-current".to_string(),
        ])
    );
    assert_eq!(
        plan.collectable_manifest_ids,
        BTreeSet::from(["manifest-old".to_string()])
    );
    assert_eq!(
        plan.collectable_chunk_ids,
        BTreeSet::from(["chunk-old-only".to_string()])
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn apply_local_vault_gc_removes_collectable_manifests_and_block_files() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("emberlink-core-state-gc-apply-{unique}.sqlite"));
    let block_dir = local_block_store_root(&path);

    {
        let mut store = EventStore::open(&path).unwrap();
        seed_gc_test_catalog(&mut store).unwrap();

        let old_manifest = store.local_file_manifest("manifest-old").unwrap().unwrap();
        let old_chunk = old_manifest
            .chunks
            .iter()
            .find(|chunk| chunk.chunk_id == "chunk-old-only")
            .unwrap()
            .chunk_id
            .clone();
        let retained_chunk = "chunk-shared".to_string();
        let old_chunk_path = block_dir.join("ch").join(format!("{old_chunk}.blk"));
        let retained_chunk_path = block_dir.join("ch").join(format!("{retained_chunk}.blk"));
        assert!(old_chunk_path.exists());
        assert!(retained_chunk_path.exists());

        let applied = store
            .apply_local_vault_gc(&test_namespace())
            .unwrap()
            .unwrap();
        assert_eq!(
            applied.collectable_manifest_ids,
            BTreeSet::from(["manifest-old".to_string()])
        );
        assert_eq!(
            applied.collectable_chunk_ids,
            BTreeSet::from(["chunk-old-only".to_string()])
        );

        assert!(store.local_file_manifest("manifest-old").unwrap().is_none());
        assert!(
            store
                .local_file_manifest("manifest-current")
                .unwrap()
                .is_some()
        );
        assert!(!old_chunk_path.exists());
        assert!(retained_chunk_path.exists());
    }

    let reopened = EventStore::open(&path).unwrap();
    assert!(
        reopened
            .local_file_manifest("manifest-old")
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .local_file_manifest("manifest-current")
            .unwrap()
            .is_some()
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_vault_gc_tracks_and_collects_stale_catalog_heads() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-vault-catalog-gc-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let meta = core_event_types::StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    };

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-catalog-gc-1",
                "rev-catalog-gc-1",
                "manifest-record-catalog-gc-1",
                "manifest-catalog-gc-1",
                1,
                "device-a",
                meta.clone(),
                br#"{"full_name":"Jane Doe"}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-catalog-gc-1",
                "rev-catalog-gc-2",
                "manifest-record-catalog-gc-2",
                "manifest-catalog-gc-2",
                2,
                "device-a",
                meta,
                br#"{"full_name":"Jane Updated"}"#,
                core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_event_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();

        let stale_catalog_manifest = store
            .local_file_manifest("manifest-catalog-gc-1")
            .unwrap()
            .unwrap();
        let stale_catalog_chunk = stale_catalog_manifest.chunks[0].chunk_id.clone();
        let stale_catalog_chunk_path = block_dir
            .join(&stale_catalog_chunk[..stale_catalog_chunk.len().min(2)])
            .join(format!("{}.blk", stale_catalog_chunk));
        assert!(stale_catalog_chunk_path.exists());

        let plan = store.plan_local_vault_gc(&namespace).unwrap().unwrap();
        assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc-2");
        assert_eq!(
            plan.retained_manifest_ids,
            BTreeSet::from([
                "manifest-catalog-gc-2".to_string(),
                "manifest-record-catalog-gc-2".to_string(),
            ])
        );
        assert_eq!(
            plan.collectable_manifest_ids,
            BTreeSet::from([
                "manifest-catalog-gc-1".to_string(),
                "manifest-record-catalog-gc-1".to_string(),
            ])
        );
        assert!(
            plan.collectable_chunk_ids
                .contains(&stale_catalog_manifest.chunks[0].chunk_id)
        );

        let applied = store.apply_local_vault_gc(&namespace).unwrap().unwrap();
        assert!(
            applied
                .collectable_manifest_ids
                .contains("manifest-catalog-gc-1")
        );
        assert!(
            store
                .local_file_manifest("manifest-catalog-gc-1")
                .unwrap()
                .is_none()
        );
        assert!(!stale_catalog_chunk_path.exists());
    }

    let reopened = EventStore::open(&path).unwrap();
    let plan = reopened.plan_local_vault_gc(&namespace).unwrap().unwrap();
    assert!(
        !plan
            .collectable_manifest_ids
            .contains("manifest-catalog-gc-1")
    );
    assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc-2");

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn local_vault_catalog_commit_persists_payload_manifests_atomically() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("emberlink-core-state-vault-commit-{unique}.sqlite"));
    let block_dir = local_block_store_root(&path);
    let catalog_key = generate_content_key("vault-catalog");
    let payload_key = generate_content_key("vault-payload");
    let namespace = test_namespace();
    let mut catalog = core_storage::create_vault_catalog(namespace.clone()).unwrap();
    let object = core_storage::create_vault_object(
        "obj-structured-1",
        namespace.clone(),
        core_event_types::VaultObjectClass::StructuredRecord,
        "rev-structured-1",
        1,
        core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
        core_event_types::RetentionPolicy::KeepLatest,
    )
    .unwrap();
    let revision = core_storage::create_vault_revision(
        "rev-structured-1",
        "obj-structured-1",
        "manifest-structured-1",
        core_event_types::PayloadKind::StructuredRecord,
        "application/json",
        1,
        "device-a",
        None,
        Some(core_event_types::StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_event_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        }),
        None,
    )
    .unwrap();
    core_storage::add_vault_object_with_initial_revision(&mut catalog, object, revision).unwrap();
    let payload_chunks = vec![br#"{"name":"primary"}"#.to_vec()];
    let (payload_manifest, payload_blocks) = core_storage::seal_payload_manifest(
        "manifest-structured-1",
        &payload_chunks,
        &payload_key,
        vec![manifest_device_access("device-a", "wrapped-device-a")],
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store
            .commit_local_vault_catalog_with_manifests(
                "manifest-catalog-structured-1",
                &catalog,
                &catalog_key,
                vec![manifest_device_access("device-a", "wrapped-device-a")],
                &[LocalEncryptedManifest {
                    manifest: payload_manifest.clone(),
                    blocks: payload_blocks.clone(),
                }],
            )
            .unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded_catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
    let loaded_manifest = reopened
        .local_file_manifest("manifest-structured-1")
        .unwrap()
        .unwrap();
    let loaded_blocks = loaded_manifest
        .chunks
        .iter()
        .map(|chunk| EncryptedBlock {
            chunk: chunk.clone(),
            encrypted: reopened
                .local_encrypted_content(&chunk.chunk_id)
                .unwrap()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    let decrypted =
        core_storage::open_payload_manifest(&loaded_manifest, &loaded_blocks, &payload_key)
            .unwrap();

    assert_eq!(loaded_catalog, catalog);
    assert_eq!(loaded_manifest, payload_manifest);
    assert_eq!(decrypted, payload_chunks);

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}
