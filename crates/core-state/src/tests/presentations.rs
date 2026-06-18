use super::*;

#[test]
fn local_presentation_templates_round_trip_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-presentation-templates-{unique}.sqlite"
    ));
    let template = core_storage::create_presentation_template(
        "template-1",
        test_namespace(),
        "obj-1",
        "com.example.profile/basic",
        core_event_types::PresentationAudienceKind::Service,
        vec!["full_name".into(), "skills".into()],
        Some(3600),
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store.upsert_local_presentation_template(&template).unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded = reopened.local_presentation_templates().unwrap();

    assert_eq!(loaded, vec![template]);

    let _ = std::fs::remove_file(path);
}

#[test]
fn local_presentation_artifacts_round_trip_across_reopen() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-presentation-artifacts-{unique}.sqlite"
    ));
    let artifact = core_storage::create_presentation_artifact(
        "artifact-1",
        "obj-1",
        "rev-1",
        core_event_types::PresentationAudienceKind::Service,
        "svc.example",
        "com.example.profile/basic",
        "manifest-artifact-1",
        10,
        Some(3700),
    )
    .unwrap();
    let record = LocalPresentationArtifactRecord {
        artifact: artifact.clone(),
        namespace: VaultNamespace {
            owner_kind: VaultOwnerKind::Persona,
            owner_id: "persona-a".into(),
        },
        template_id: "template-1".into(),
        grant_id: None,
    };

    {
        let mut store = EventStore::open(&path).unwrap();
        store.record_local_presentation_artifact(&record).unwrap();
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded = reopened.local_presentation_artifacts().unwrap();

    assert_eq!(loaded, vec![record]);

    let _ = std::fs::remove_file(path);
}

#[test]
fn issue_local_presentation_artifact_builds_audited_encrypted_payload() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-issued-artifact-{unique}.sqlite"
    ));
    let block_dir = local_block_store_root(&path);
    let namespace = test_namespace();
    let catalog_key = generate_content_key("vault-catalog");
    let source_key = generate_content_key("vault-payload");
    let mut catalog = core_storage::create_vault_catalog(namespace.clone()).unwrap();
    let object = core_storage::create_vault_object(
        "obj-1",
        namespace.clone(),
        core_event_types::VaultObjectClass::StructuredRecord,
        "rev-1",
        1,
        core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
        core_event_types::RetentionPolicy::KeepLatest,
    )
    .unwrap();
    let revision = core_storage::create_vault_revision(
        "rev-1",
        "obj-1",
        "manifest-source-1",
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
    let source_chunks = vec![
        br#"{
        "full_name":"Jane Doe",
        "skills":["rust","distributed-systems"],
        "private":{"ssn":"000-00-0000"}
    }"#
        .to_vec(),
    ];
    let (source_manifest, source_blocks) = core_storage::seal_payload_manifest(
        "manifest-source-1",
        &source_chunks,
        &source_key,
        vec![manifest_device_access("device-a", "wrapped-device-a")],
    )
    .unwrap();
    let template = core_storage::create_presentation_template(
        "template-1",
        namespace.clone(),
        "obj-1",
        "com.example.profile/basic",
        core_event_types::PresentationAudienceKind::Service,
        vec!["full_name".into(), "skills".into()],
        Some(3600),
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        store.upsert_local_presentation_template(&template).unwrap();
        store
            .upsert_local_manifest_key("manifest-source-1", &source_key)
            .unwrap();
        store
            .commit_local_vault_catalog_with_manifests(
                "manifest-catalog-1",
                &catalog,
                &catalog_key,
                vec![manifest_device_access("device-a", "wrapped-device-a")],
                &[LocalEncryptedManifest {
                    manifest: source_manifest.clone(),
                    blocks: source_blocks.clone(),
                }],
            )
            .unwrap();

        let artifact = store
            .issue_local_presentation_artifact(
                &namespace,
                "rev-1",
                "template-1",
                "artifact-1",
                "manifest-artifact-1",
                "svc.example",
                10,
                Some(3700),
                vec![test_manifest_recipient("device-a")],
                None,
            )
            .unwrap();

        assert_eq!(artifact.artifact.id, "artifact-1");
        assert_eq!(artifact.artifact.source_revision_id, "rev-1");
        assert_eq!(artifact.artifact.manifest_id, "manifest-artifact-1");
        assert_eq!(artifact.template_id, "template-1");
        assert_eq!(artifact.namespace, namespace);
    }

    let reopened = EventStore::open(&path).unwrap();
    let artifacts = reopened.local_presentation_artifacts().unwrap();
    let artifact_manifest = reopened
        .local_file_manifest("manifest-artifact-1")
        .unwrap()
        .unwrap();
    let artifact_key = reopened
        .local_manifest_key("manifest-artifact-1")
        .unwrap()
        .unwrap();
    let artifact_blocks = artifact_manifest
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
        core_storage::open_payload_manifest(&artifact_manifest, &artifact_blocks, &artifact_key)
            .unwrap();

    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].artifact.recipient_id, "svc.example");
    assert_eq!(artifacts[0].template_id, "template-1");
    assert_eq!(
        String::from_utf8(decrypted[0].clone()).unwrap(),
        r#"{"full_name":"Jane Doe","skills":["rust","distributed-systems"]}"#
    );

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(block_dir);
}

#[test]
fn build_local_presentation_artifact_envelope_requires_namespace_issuer() {
    let mut store = EventStore::default();
    let root_key = generate_local_key_pair("root", "root-a");
    let root_signer = LocalKeySigner::from_local_key_pair(&root_key).unwrap();
    let persona_owner_key = generate_local_key_pair("persona", "persona-a");
    let persona_owner_signer = LocalKeySigner::from_local_key_pair(&persona_owner_key).unwrap();
    let other_persona_key = generate_local_key_pair("persona", "persona-b");
    let other_persona_signer = LocalKeySigner::from_local_key_pair(&other_persona_key).unwrap();

    append_typed_with_signer(
        &mut store,
        "evt-root-runtime-artifact",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Primary".into(),
            initial_key: local_public_key_material(&root_key),
        }),
        SignerBinding::root("root-a", root_key.key_id.clone()),
        &root_signer,
    );
    append_typed_with_signer(
        &mut store,
        "evt-persona-owner-runtime-artifact",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            label: "Owner".into(),
            disclosure_profile: Some("persona.owner".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: local_public_key_material(&persona_owner_key),
        }),
        SignerBinding::root("root-a", root_key.key_id.clone()),
        &root_signer,
    );
    append_typed_with_signer(
        &mut store,
        "evt-persona-other-runtime-artifact",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-b".into(),
            label: "Other".into(),
            disclosure_profile: Some("persona.other".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: local_public_key_material(&other_persona_key),
        }),
        SignerBinding::root("root-a", root_key.key_id.clone()),
        &root_signer,
    );

    let namespace = test_namespace();
    let meta = StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: core_event_types::StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    };
    let template = core_storage::create_presentation_template(
        "template-owner",
        namespace.clone(),
        "obj-owner",
        "com.example.profile/basic",
        core_event_types::PresentationAudienceKind::Service,
        vec!["full_name".into()],
        Some(3600),
    )
    .unwrap();

    store
        .upsert_local_structured_record(
            &namespace,
            "obj-owner",
            "rev-owner",
            "manifest-owner",
            "manifest-catalog-owner",
            1,
            "device-a",
            meta,
            br#"{"full_name":"Jane Doe","private":"secret"}"#,
            core_event_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_event_types::RetentionPolicy::KeepLatest,
            vec![test_manifest_recipient("device-a")],
        )
        .unwrap();
    store.upsert_local_presentation_template(&template).unwrap();
    let record = store
        .issue_local_presentation_artifact(
            &namespace,
            "rev-owner",
            "template-owner",
            "artifact-owner",
            "manifest-artifact-owner",
            "svc.example",
            10,
            Some(3610),
            vec![test_manifest_recipient("device-a")],
            None,
        )
        .unwrap();

    let envelope = store
        .build_local_presentation_artifact_envelope(
            &record.artifact.id,
            "persona-a",
            &persona_owner_signer,
        )
        .unwrap();
    let err = store
        .build_local_presentation_artifact_envelope(
            &record.artifact.id,
            "persona-b",
            &other_persona_signer,
        )
        .unwrap_err();

    assert_eq!(envelope.issuer_persona_id, "persona-a");
    assert!(
        err.message
            .contains("persona-owned disclosure artifacts must be issued by the owning persona")
    );
}

#[test]
fn received_presentation_artifacts_round_trip_and_track_receipts() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emberlink-core-state-received-artifacts-{unique}.sqlite"
    ));
    let artifact = core_storage::create_presentation_artifact(
        "artifact-received-1",
        "obj-1",
        "rev-1",
        core_event_types::PresentationAudienceKind::Peer,
        "persona-target",
        "com.example.profile/basic",
        "manifest-artifact-1",
        10,
        Some(3700),
    )
    .unwrap();
    let key_pair = core_crypto::generate_local_key_pair("persona", "persona-issuer");
    let signer = core_crypto::LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
    let envelope = core_storage::sign_presentation_artifact_envelope(
        &artifact,
        br#"{"full_name":"Jane Doe"}"#.to_vec(),
        "persona-issuer",
        key_pair.key_id.clone(),
        &signer,
    )
    .unwrap();

    {
        let mut store = EventStore::open(&path).unwrap();
        let received = store
            .receive_presentation_artifact(
                &envelope,
                ReceivedDisclosureSourceKind::ExportFile,
                "/tmp/disclosure.artifact",
                10,
            )
            .unwrap();
        assert_eq!(received.envelope.artifact.id, artifact.id);
        assert_eq!(received.envelope.issuer_persona_id, "persona-issuer");
        assert_eq!(received.receipt_count, 1);

        let received = store
            .receive_presentation_artifact(
                &envelope,
                ReceivedDisclosureSourceKind::ExportFile,
                "/tmp/disclosure.artifact",
                20,
            )
            .unwrap();
        assert_eq!(received.receipt_count, 2);
        assert_eq!(received.last_received_at, 20);
    }

    let reopened = EventStore::open(&path).unwrap();
    let loaded = reopened.local_received_presentation_artifacts().unwrap();

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].envelope.artifact.id, artifact.id);
    assert_eq!(loaded[0].first_received_at, 10);
    assert_eq!(loaded[0].last_received_at, 20);
    assert_eq!(loaded[0].receipt_count, 2);
    assert_eq!(
        String::from_utf8(loaded[0].envelope.payload_bytes.clone()).unwrap(),
        r#"{"full_name":"Jane Doe"}"#
    );
    assert_eq!(loaded[0].envelope.issuer_persona_id, "persona-issuer");

    let _ = std::fs::remove_file(path);
}
