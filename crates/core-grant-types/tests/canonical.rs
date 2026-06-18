use core_event_types::*;
use core_principals::{
    AdmissionToken, KeyAlgorithm, Persona, PublicKeyMaterial, RecoveryScope, SurvivalMode,
    TrustThreshold,
};
use core_types::{CanonicalEncode, SCHEMA_VERSION, SchemaVersion, Validate};
use proptest::prelude::*;

fn test_key(key_id: &str) -> PublicKeyMaterial {
    PublicKeyMaterial {
        key_id: key_id.into(),
        algorithm: KeyAlgorithm::DevEd25519Like,
        public_key: format!("devpub:{key_id}"),
    }
}

fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
    PublicKeyMaterial {
        key_id: format!("enc-{key_id}"),
        algorithm: KeyAlgorithm::AgeX25519,
        public_key: format!("age1{key_id}fixture"),
    }
}

fn test_namespace() -> VaultNamespace {
    VaultNamespace {
        owner_kind: VaultOwnerKind::Persona,
        owner_id: "persona-a".into(),
    }
}

fn test_chunk(
    manifest_id: &str,
    chunk_id: &str,
    ordinal: u32,
    ciphertext_bytes: u64,
) -> ChunkReference {
    ChunkReference {
        manifest_id: manifest_id.into(),
        chunk_id: chunk_id.into(),
        ordinal,
        ciphertext_bytes,
    }
}

fn test_structured_record_meta() -> StructuredRecordMeta {
    StructuredRecordMeta {
        schema_id: "com.example.profile/basic".into(),
        schema_version: "v1".into(),
        encoding: StructuredEncoding::Json,
        app_namespace: "com.example.profile".into(),
    }
}

#[test]
fn schema_version_is_frozen_for_bootstrap() {
    assert_eq!(SCHEMA_VERSION, "0.1.0");
    assert_eq!(SchemaVersion::V0_1_0.to_string(), "0.1.0");
}

#[test]
fn persona_requires_parent_root() {
    // Per ADR 200 2026-06-15 amendment: `Persona.root_id` collapsed
    // into `Principal.parent_id`. Validation still rejects the empty
    // parent slot.
    let persona = Persona {
        id: "persona-1".into(),
        parent_id: String::new(),
        label: "friends".into(),
        disclosure_profile: Some("persona.friends".into()),
        survival_mode: SurvivalMode::Strict,
        active_key: test_key("key-1"),
    };

    assert!(persona.validate().is_err());
}

#[test]
fn event_body_reports_subject_and_type() {
    let body = EventBody::DeviceAdded(DeviceAddedEvent {
        root_id: "root-a".into(),
        device_id: "device-a".into(),
        label: "Laptop".into(),
        initial_key: test_key("device-key-1"),
        initial_encryption_key: test_encryption_key("device-key-1"),
    });

    assert_eq!(body.event_type(), EventType::DeviceAdded);
    assert_eq!(body.subject(), EventSubject::device("device-a"));
}

#[test]
fn rotated_keys_must_change_ids() {
    let body = RootKeyRotatedEvent {
        root_id: "root-a".into(),
        previous_key_id: "key-root-a-v1".into(),
        new_key: test_key("key-root-a-v1"),
    };

    assert!(body.validate().is_err());
}

#[test]
fn canonical_encoding_is_stable_for_typed_events() {
    let body = EventBody::PersonaCreated(PersonaCreatedEvent {
        root_id: "root-a".into(),
        persona_id: "persona-work".into(),
        label: "Work".into(),
        disclosure_profile: Some("work-public".into()),
        survival_mode: SurvivalMode::Strict,
        initial_key: test_key("persona-key-1"),
    });

    let encoded = String::from_utf8(body.canonical_encode()).unwrap();

    assert!(encoded.contains("type=persona-created"));
    assert!(encoded.contains("disclosure_profile=work-public"));
    assert!(encoded.contains("survival_mode=strict"));
}

#[test]
fn canonical_event_bodies_round_trip() {
    let body = EventBody::RecoveryExecuted(RecoveryExecutedEvent {
        request_id: "recovery-1".into(),
        executed_scope: RecoveryScope::FreezeDevice,
    });

    let decoded = EventBody::decode_canonical(&body.canonical_encode()).unwrap();

    assert_eq!(decoded, body);
}

#[test]
fn device_encryption_rotation_event_round_trips_canonically() {
    let body = EventBody::DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent {
        root_id: "root-a".into(),
        device_id: "device-a".into(),
        previous_encryption_key_id: "enc-key-device-a-v1".into(),
        new_encryption_key: test_encryption_key("device-a-v2"),
    });

    let decoded = EventBody::decode_canonical(&body.canonical_encode()).unwrap();

    assert_eq!(decoded, body);
}

#[test]
fn structured_record_revision_requires_structured_metadata() {
    let revision = VaultRevision {
        id: "rev-1".into(),
        object_id: "obj-1".into(),
        manifest_id: "manifest-1".into(),
        payload_kind: PayloadKind::StructuredRecord,
        content_type: "application/json".into(),
        created_at: 10,
        created_by_device_id: "device-a".into(),
        parent_revision_id: None,
        structured_record: None,
        claim: None,
    };

    assert!(revision.validate().is_err());
}

#[test]
fn claim_metadata_requires_structured_record_metadata_on_revision() {
    let revision = VaultRevision {
        id: "rev-1".into(),
        object_id: "obj-1".into(),
        manifest_id: "manifest-1".into(),
        payload_kind: PayloadKind::StructuredRecord,
        content_type: "application/json".into(),
        created_at: 10,
        created_by_device_id: "device-a".into(),
        parent_revision_id: None,
        structured_record: None,
        claim: Some(ClaimMeta {
            claim_type: ClaimType::SelfAsserted,
            issuer_persona_id: "persona-a".into(),
            subject_persona_id: "persona-a".into(),
            claim_schema: "employment".into(),
            issued_at: 10,
            expires_at: None,
            external_issuer: None,
            external_credential_id: None,
        }),
    };

    assert!(revision.validate().is_err());
}

#[test]
fn service_issued_claim_requires_external_issuer() {
    let claim = ClaimMeta {
        claim_type: ClaimType::ServiceIssued,
        issuer_persona_id: "persona-a".into(),
        subject_persona_id: "persona-a".into(),
        claim_schema: "password".into(),
        issued_at: 10,
        expires_at: None,
        external_issuer: None,
        external_credential_id: Some("cred-1".into()),
    };

    assert!(claim.validate().is_err());
}

#[test]
fn presentation_artifact_requires_expiry_after_issue_time() {
    let artifact = PresentationArtifact {
        id: "artifact-1".into(),
        source_object_id: "obj-1".into(),
        source_revision_id: "rev-1".into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "svc.example".into(),
        schema_id: "com.example.profile/basic".into(),
        manifest_id: "manifest-1".into(),
        issued_at: 100,
        expires_at: Some(100),
    };

    assert!(artifact.validate().is_err());
}

#[test]
fn presentation_template_canonical_encoding_sorts_field_paths() {
    let template = PresentationTemplate {
        id: "template-1".into(),
        namespace: test_namespace(),
        source_object_id: "obj-1".into(),
        schema_id: "com.example.profile/basic".into(),
        audience_kind: PresentationAudienceKind::Service,
        field_paths: vec!["skills".into(), "full_name".into()],
        expires_after_secs: Some(3600),
    };

    let encoded = String::from_utf8(template.canonical_encode()).unwrap();

    assert!(encoded.contains("field_path_0000=full_name"));
    assert!(encoded.contains("field_path_0001=skills"));
}

#[test]
fn vault_object_rejects_backwards_timestamp_updates() {
    let object = VaultObject {
        id: "obj-1".into(),
        namespace: test_namespace(),
        class: VaultObjectClass::StructuredRecord,
        latest_revision_id: "rev-1".into(),
        created_at: 10,
        updated_at: 9,
        durability: DurabilityPolicy::ReplicatedToApprovedPeers,
        retention: RetentionPolicy::KeepLatest,
        deleted: false,
    };

    assert!(object.validate().is_err());
}

#[test]
fn vault_catalog_requires_latest_revision_membership() {
    let catalog = VaultCatalog {
        namespace: test_namespace(),
        objects: vec![VaultObject {
            id: "obj-1".into(),
            namespace: test_namespace(),
            class: VaultObjectClass::StructuredRecord,
            latest_revision_id: "rev-missing".into(),
            created_at: 1,
            updated_at: 1,
            durability: DurabilityPolicy::ReplicatedToApprovedPeers,
            retention: RetentionPolicy::KeepLatest,
            deleted: false,
        }],
        revisions: vec![VaultRevision {
            id: "rev-1".into(),
            object_id: "obj-1".into(),
            manifest_id: "manifest-1".into(),
            payload_kind: PayloadKind::StructuredRecord,
            content_type: "application/json".into(),
            created_at: 1,
            created_by_device_id: "device-a".into(),
            parent_revision_id: None,
            structured_record: Some(StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            }),
            claim: None,
        }],
    };

    assert!(catalog.validate().is_err());
}

#[test]
fn vault_catalog_canonical_encoding_sorts_objects_and_revisions() {
    let catalog = VaultCatalog {
        namespace: test_namespace(),
        objects: vec![
            VaultObject {
                id: "obj-b".into(),
                namespace: test_namespace(),
                class: VaultObjectClass::StructuredRecord,
                latest_revision_id: "rev-b".into(),
                created_at: 2,
                updated_at: 2,
                durability: DurabilityPolicy::ReplicatedToApprovedPeers,
                retention: RetentionPolicy::KeepLatest,
                deleted: false,
            },
            VaultObject {
                id: "obj-a".into(),
                namespace: test_namespace(),
                class: VaultObjectClass::StructuredRecord,
                latest_revision_id: "rev-a".into(),
                created_at: 1,
                updated_at: 1,
                durability: DurabilityPolicy::ReplicatedToApprovedPeers,
                retention: RetentionPolicy::KeepLatest,
                deleted: false,
            },
        ],
        revisions: vec![
            VaultRevision {
                id: "rev-b".into(),
                object_id: "obj-b".into(),
                manifest_id: "manifest-b".into(),
                payload_kind: PayloadKind::BinaryBlob,
                content_type: "application/octet-stream".into(),
                created_at: 2,
                created_by_device_id: "device-b".into(),
                parent_revision_id: None,
                structured_record: None,
                claim: None,
            },
            VaultRevision {
                id: "rev-a".into(),
                object_id: "obj-a".into(),
                manifest_id: "manifest-a".into(),
                payload_kind: PayloadKind::StructuredRecord,
                content_type: "application/json".into(),
                created_at: 1,
                created_by_device_id: "device-a".into(),
                parent_revision_id: None,
                structured_record: Some(StructuredRecordMeta {
                    schema_id: "com.example.profile/basic".into(),
                    schema_version: "v1".into(),
                    encoding: StructuredEncoding::Json,
                    app_namespace: "com.example.profile".into(),
                }),
                claim: None,
            },
        ],
    };

    let encoded = String::from_utf8(catalog.canonical_encode()).unwrap();

    assert!(encoded.contains("object_count=2"));
    assert!(encoded.contains("revision_count=2"));
    assert!(encoded.contains("object_0000_payload_hex"));
    assert!(encoded.contains("revision_0000_payload_hex"));
}

#[test]
fn vault_catalog_canonical_round_trips() {
    let catalog = VaultCatalog {
        namespace: test_namespace(),
        objects: vec![VaultObject {
            id: "obj-1".into(),
            namespace: test_namespace(),
            class: VaultObjectClass::StructuredRecord,
            latest_revision_id: "rev-1".into(),
            created_at: 1,
            updated_at: 1,
            durability: DurabilityPolicy::ReplicatedToApprovedPeers,
            retention: RetentionPolicy::KeepLatest,
            deleted: false,
        }],
        revisions: vec![VaultRevision {
            id: "rev-1".into(),
            object_id: "obj-1".into(),
            manifest_id: "manifest-1".into(),
            payload_kind: PayloadKind::StructuredRecord,
            content_type: "application/json".into(),
            created_at: 1,
            created_by_device_id: "device-a".into(),
            parent_revision_id: None,
            structured_record: Some(StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            }),
            claim: None,
        }],
    };

    let decoded = VaultCatalog::decode_canonical(&catalog.canonical_encode()).unwrap();

    assert_eq!(decoded, catalog);
}

#[test]
fn vault_revision_claim_canonical_round_trips() {
    let revision = VaultRevision {
        id: "rev-claim-1".into(),
        object_id: "obj-claim-1".into(),
        manifest_id: "manifest-claim-1".into(),
        payload_kind: PayloadKind::StructuredRecord,
        content_type: "application/json".into(),
        created_at: 100,
        created_by_device_id: "device-a".into(),
        parent_revision_id: None,
        structured_record: Some(test_structured_record_meta()),
        claim: Some(ClaimMeta {
            claim_type: ClaimType::PeerAttested,
            issuer_persona_id: "persona-issuer".into(),
            subject_persona_id: "persona-subject".into(),
            claim_schema: "employment".into(),
            issued_at: 90,
            expires_at: Some(1_000),
            external_issuer: None,
            external_credential_id: None,
        }),
    };

    let decoded = VaultRevision::decode_canonical(&revision.canonical_encode()).unwrap();

    assert_eq!(decoded, revision);
}

#[test]
fn presentation_artifact_canonical_round_trips() {
    let artifact = PresentationArtifact {
        id: "artifact-1".into(),
        source_object_id: "obj-1".into(),
        source_revision_id: "rev-1".into(),
        recipient_kind: PresentationAudienceKind::Peer,
        recipient_id: "peer-a".into(),
        schema_id: "com.example.profile/basic".into(),
        manifest_id: "manifest-1".into(),
        issued_at: 1_000,
        expires_at: Some(2_000),
    };

    let decoded = PresentationArtifact::decode_canonical(&artifact.canonical_encode()).unwrap();

    assert_eq!(decoded, artifact);
}

#[test]
fn service_binding_canonical_encoding_contains_descriptor_fields() {
    let binding = ServiceBinding {
        id: "binding-1".into(),
        persona_id: "persona-a".into(),
        descriptor: ServiceDescriptor {
            adapter_kind: "password".into(),
            service_label: "GitHub".into(),
            endpoint: "https://github.com".into(),
        },
        external_account_id: "alice".into(),
        created_at: 100,
    };

    let encoded = String::from_utf8(binding.canonical_encode()).unwrap();

    assert!(encoded.contains("type=service-binding"));
    assert!(encoded.contains("adapter_kind=password"));
    assert!(encoded.contains("service_label=GitHub"));
    assert!(encoded.contains("endpoint=https://github.com"));
}

#[test]
fn imported_claim_requires_json_object_and_external_issuer() {
    let claim = ImportedClaim {
        claim_type: "service-issued".into(),
        payload_json: "{\"username\":\"alice\"}".into(),
        external_issuer: String::new(),
        external_issued_at: Some(10),
        external_expires_at: Some(20),
    };

    assert!(claim.validate().is_err());

    let claim = ImportedClaim {
        claim_type: "service-issued".into(),
        payload_json: "[\"not\",\"an\",\"object\"]".into(),
        external_issuer: "1password".into(),
        external_issued_at: Some(10),
        external_expires_at: Some(20),
    };

    assert!(claim.validate().is_err());
}

#[test]
fn imported_claim_accepts_valid_json_object_payload() {
    let claim = ImportedClaim {
        claim_type: "service-issued".into(),
        payload_json: "{\"username\":\"alice\",\"password\":\"secret\"}".into(),
        external_issuer: "1password".into(),
        external_issued_at: Some(10),
        external_expires_at: Some(20),
    };

    assert!(claim.validate().is_ok());
}

#[test]
fn presentation_result_rejected_requires_reason() {
    let rejected = PresentationResult::Rejected {
        reason: String::new(),
    };
    let accepted = PresentationResult::Accepted {
        response_payload: None,
    };

    assert!(rejected.validate().is_err());
    assert!(accepted.validate().is_ok());
}

#[test]
fn admission_token_signing_payload_is_stable_and_omits_signature() {
    let token = AdmissionToken {
        token_id: "token-1".into(),
        persona_id: "persona-source".into(),
        issuer_persona_id: "persona-issuer".into(),
        issued_at: 100,
        expires_at: 200,
        threshold_met: TrustThreshold::new(0.75).unwrap(),
        issuer_signature_hex: "ed25519sig:deadbeef".into(),
    };

    let encoded = String::from_utf8(token.signing_payload()).unwrap();

    assert!(encoded.contains("type=admission-token"));
    assert!(encoded.contains("persona_id=persona-source"));
    assert!(encoded.contains("issuer_persona_id=persona-issuer"));
    assert!(encoded.contains("threshold_met=0.750000"));
    assert!(!encoded.contains("issuer_signature_hex"));
}

#[test]
fn admission_token_requires_expiry_after_issue_time() {
    let token = AdmissionToken {
        token_id: "token-1".into(),
        persona_id: "persona-source".into(),
        issuer_persona_id: "persona-issuer".into(),
        issued_at: 100,
        expires_at: 100,
        threshold_met: TrustThreshold::new(0.75).unwrap(),
        issuer_signature_hex: "ed25519sig:deadbeef".into(),
    };

    assert!(token.validate().is_err());
}

#[test]
fn trust_event_bodies_round_trip_canonically() {
    let body = EventBody::TrustAttested(TrustAttestedEvent {
        attestation_id: "trust-1".into(),
        attester_persona_id: "persona-professional".into(),
        subject_persona_id: "persona-pseudonymous".into(),
        domain: "professional".into(),
        score: 0.8,
        recipient_bound: Some("peer-demo".into()),
    });

    let decoded = EventBody::decode_canonical(&body.canonical_encode()).unwrap();

    assert_eq!(decoded, body);
}

#[test]
fn endpoint_event_bodies_round_trip_canonically() {
    let updated = EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
        peer_id: "peer-bridge-a".into(),
        device_id: "device-root-a-01".into(),
        transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
    });
    let rotated = EventBody::EndpointRotated(EndpointRotatedEvent {
        peer_id: "peer-bridge-a".into(),
        device_id: "device-root-a-01".into(),
        previous_transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
        new_transport_hint: "relay://127.0.0.1:9200/mailbox/peer-bridge-a".into(),
    });

    let updated_decoded = EventBody::decode_canonical(&updated.canonical_encode()).unwrap();
    let rotated_decoded = EventBody::decode_canonical(&rotated.canonical_encode()).unwrap();

    assert_eq!(updated_decoded, updated);
    assert_eq!(rotated_decoded, rotated);
}

#[test]
fn storage_manifest_event_bodies_round_trip_canonically() {
    let body = EventBody::StorageManifestPublished(StorageManifestPublishedEvent {
        root_id: "root-a".into(),
        relationship_id: "storage-1".into(),
        manifest: FileManifest {
            id: "manifest-1".into(),
            encrypted_root_chunk_id: "bafy-root-1".into(),
            chunks: vec![
                test_chunk("manifest-1", "bafy-root-1", 0, 2048),
                test_chunk("manifest-1", "bafy-root-1-chunk-0001", 1, 1024),
            ],
            authorized_devices: vec![
                ManifestDeviceAccess {
                    device_id: "device-a".into(),
                    wrapped_manifest_key_hex: "deadbeef".into(),
                },
                ManifestDeviceAccess {
                    device_id: "device-b".into(),
                    wrapped_manifest_key_hex: "cafebabe".into(),
                },
            ],
        },
    });

    let decoded = EventBody::decode_canonical(&body.canonical_encode()).unwrap();

    assert_eq!(decoded, body);
}

#[test]
fn storage_relationship_and_ledger_event_bodies_round_trip_canonically() {
    let relationship = EventBody::StorageRelationshipCreated(StorageRelationshipCreatedEvent {
        root_id: "root-a".into(),
        relationship: StorageRelationship {
            id: "storage-1".into(),
            local_peer_id: "peer-a".into(),
            remote_peer_id: "peer-b".into(),
            approved: true,
        },
    });
    let ledger = EventBody::StorageLedgerUpdated(StorageLedgerUpdatedEvent {
        root_id: "root-a".into(),
        entry: StorageLedgerEntry {
            relationship_id: "storage-1".into(),
            stored_bytes_delta: 524_288,
        },
    });

    assert_eq!(
        EventBody::decode_canonical(&relationship.canonical_encode()).unwrap(),
        relationship
    );
    assert_eq!(
        EventBody::decode_canonical(&ledger.canonical_encode()).unwrap(),
        ledger
    );
}

#[test]
fn file_manifest_canonical_encoding_orders_device_access_stably() {
    let manifest = FileManifest {
        id: "manifest-1".into(),
        encrypted_root_chunk_id: "bafyroot".into(),
        chunks: vec![
            test_chunk("manifest-1", "bafyroot-chunk-0001", 1, 512),
            test_chunk("manifest-1", "bafyroot", 0, 1024),
        ],
        authorized_devices: vec![
            ManifestDeviceAccess {
                device_id: "device-b".into(),
                wrapped_manifest_key_hex: "bb".into(),
            },
            ManifestDeviceAccess {
                device_id: "device-a".into(),
                wrapped_manifest_key_hex: "aa".into(),
            },
        ],
    };

    let encoded = String::from_utf8(manifest.canonical_encode()).unwrap();

    assert!(encoded.contains("type=file-manifest"));
    assert!(encoded.contains("encrypted_root_chunk_id=bafyroot"));
    let root_chunk_index = encoded.find("chunk_0000_chunk_id=bafyroot").unwrap();
    let later_chunk_index = encoded
        .find("chunk_0001_chunk_id=bafyroot-chunk-0001")
        .unwrap();
    assert!(root_chunk_index < later_chunk_index);
    let a_index = encoded
        .find("device_access_0000_device_id=device-a")
        .unwrap();
    let b_index = encoded
        .find("device_access_0001_device_id=device-b")
        .unwrap();
    assert!(a_index < b_index);
}

#[test]
fn file_manifest_validation_rejects_duplicate_device_access() {
    let manifest = FileManifest {
        id: "manifest-1".into(),
        encrypted_root_chunk_id: "bafyroot".into(),
        chunks: vec![test_chunk("manifest-1", "bafyroot", 0, 1024)],
        authorized_devices: vec![
            ManifestDeviceAccess {
                device_id: "device-a".into(),
                wrapped_manifest_key_hex: "aa".into(),
            },
            ManifestDeviceAccess {
                device_id: "device-a".into(),
                wrapped_manifest_key_hex: "bb".into(),
            },
        ],
    };

    assert!(manifest.validate().is_err());
}

#[test]
fn file_manifest_validation_rejects_duplicate_chunk_ordinals() {
    let manifest = FileManifest {
        id: "manifest-1".into(),
        encrypted_root_chunk_id: "bafyroot".into(),
        chunks: vec![
            test_chunk("manifest-1", "bafyroot", 0, 1024),
            test_chunk("manifest-1", "bafyroot-chunk-0001", 0, 512),
        ],
        authorized_devices: vec![ManifestDeviceAccess {
            device_id: "device-a".into(),
            wrapped_manifest_key_hex: "aa".into(),
        }],
    };

    assert!(manifest.validate().is_err());
}

#[test]
fn file_manifest_validation_requires_root_chunk_at_ordinal_zero() {
    let manifest = FileManifest {
        id: "manifest-1".into(),
        encrypted_root_chunk_id: "bafyroot".into(),
        chunks: vec![
            test_chunk("manifest-1", "bafyroot-chunk-0001", 0, 512),
            test_chunk("manifest-1", "bafyroot", 1, 1024),
        ],
        authorized_devices: vec![ManifestDeviceAccess {
            device_id: "device-a".into(),
            wrapped_manifest_key_hex: "aa".into(),
        }],
    };

    assert!(manifest.validate().is_err());
}

#[test]
fn golden_root_created_canonical_encoding() {
    let body = EventBody::RootCreated(RootCreatedEvent {
        root_id: "root-alpha".into(),
        display_name: "Alice".into(),
        initial_key: PublicKeyMaterial {
            key_id: "key-root-alpha-v1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: "ed25519pub:abc123".into(),
        },
    });
    let encoded = String::from_utf8(body.canonical_encode()).unwrap();
    let expected = "\
type=root-created\n\
root_id=root-alpha\n\
display_name=Alice\n\
key_id=key-root-alpha-v1\n\
algorithm=ed25519\n\
public_key=ed25519pub:abc123\n";
    assert_eq!(encoded, expected, "RootCreated canonical encoding changed");
}

#[test]
fn golden_device_added_canonical_encoding() {
    let body = EventBody::DeviceAdded(DeviceAddedEvent {
        root_id: "root-alpha".into(),
        device_id: "device-laptop".into(),
        label: "Laptop".into(),
        initial_key: PublicKeyMaterial {
            key_id: "key-device-v1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: "ed25519pub:def456".into(),
        },
        initial_encryption_key: PublicKeyMaterial {
            key_id: "enc-device-v1".into(),
            algorithm: KeyAlgorithm::AgeX25519,
            public_key: "age1laptopfixture".into(),
        },
    });
    let encoded = String::from_utf8(body.canonical_encode()).unwrap();
    let expected = "\
type=device-added\n\
root_id=root-alpha\n\
device_id=device-laptop\n\
label=Laptop\n\
key_id=key-device-v1\n\
algorithm=ed25519\n\
public_key=ed25519pub:def456\n\
encryption_key_id=enc-device-v1\n\
encryption_algorithm=age-x25519\n\
encryption_public_key=age1laptopfixture\n";
    assert_eq!(encoded, expected, "DeviceAdded canonical encoding changed");
}

#[test]
fn golden_trust_attested_canonical_encoding() {
    let body = EventBody::TrustAttested(TrustAttestedEvent {
        attestation_id: "trust-001".into(),
        attester_persona_id: "persona-alice".into(),
        subject_persona_id: "persona-bob".into(),
        domain: "professional".into(),
        score: 0.85,
        recipient_bound: None,
    });
    let encoded = String::from_utf8(body.canonical_encode()).unwrap();
    let expected = "\
type=trust-attested\n\
attestation_id=trust-001\n\
attester_persona_id=persona-alice\n\
subject_persona_id=persona-bob\n\
domain=professional\n\
score=0.850000\n\
recipient_bound=\n";
    assert_eq!(
        encoded, expected,
        "TrustAttested canonical encoding changed"
    );
}

#[test]
fn golden_recovery_executed_canonical_encoding() {
    let body = EventBody::RecoveryExecuted(RecoveryExecutedEvent {
        request_id: "recovery-req-1".into(),
        executed_scope: RecoveryScope::FreezeDevice,
    });
    let encoded = String::from_utf8(body.canonical_encode()).unwrap();
    let expected = "\
type=recovery-executed\n\
request_id=recovery-req-1\n\
executed_scope=freeze-device\n";
    assert_eq!(
        encoded, expected,
        "RecoveryExecuted canonical encoding changed"
    );
}

#[test]
fn golden_storage_manifest_published_canonical_encoding() {
    let body = EventBody::StorageManifestPublished(StorageManifestPublishedEvent {
        root_id: "root-alpha".into(),
        relationship_id: "rel-001".into(),
        manifest: FileManifest {
            id: "manifest-001".into(),
            encrypted_root_chunk_id: "bafy-root".into(),
            chunks: vec![ChunkReference {
                manifest_id: "manifest-001".into(),
                chunk_id: "bafy-root".into(),
                ordinal: 0,
                ciphertext_bytes: 1024,
            }],
            authorized_devices: vec![ManifestDeviceAccess {
                device_id: "device-a".into(),
                wrapped_manifest_key_hex: "deadbeef".into(),
            }],
        },
    });
    let encoded = String::from_utf8(body.canonical_encode()).unwrap();
    // StorageManifestPublished encodes the manifest as a hex blob
    assert!(encoded.starts_with("type=storage-manifest-published\n"));
    assert!(encoded.contains("root_id=root-alpha\n"));
    assert!(encoded.contains("relationship_id=rel-001\n"));
    assert!(encoded.contains("manifest_payload_hex="));
    // Round-trip to verify consistency
    let decoded = EventBody::decode_canonical(&body.canonical_encode()).unwrap();
    assert_eq!(decoded, body);
}

fn arb_key_algorithm() -> impl Strategy<Value = KeyAlgorithm> {
    prop_oneof![
        Just(KeyAlgorithm::DevEd25519Like),
        Just(KeyAlgorithm::Ed25519),
        Just(KeyAlgorithm::AgeX25519),
    ]
}

fn arb_key_full() -> impl Strategy<Value = PublicKeyMaterial> {
    (any::<String>(), arb_key_algorithm(), any::<String>()).prop_map(|(kid, alg, pk)| {
        PublicKeyMaterial {
            key_id: kid,
            algorithm: alg,
            public_key: pk,
        }
    })
}

fn arb_survival_mode() -> impl Strategy<Value = SurvivalMode> {
    prop_oneof![
        Just(SurvivalMode::Strict),
        Just(SurvivalMode::LimitedPersonaContinuity),
    ]
}

fn arb_recovery_scope() -> impl Strategy<Value = RecoveryScope> {
    prop_oneof![
        Just(RecoveryScope::FreezeDevice),
        Just(RecoveryScope::RestorePersonaAccess),
    ]
}

fn arb_content_visibility() -> impl Strategy<Value = ContentVisibility> {
    prop_oneof![
        Just(ContentVisibility::Public),
        Just(ContentVisibility::TrustGated),
        Just(ContentVisibility::Direct),
    ]
}

fn arb_chunk_ref(manifest_id: String) -> impl Strategy<Value = ChunkReference> {
    (any::<String>(), any::<u32>(), any::<u64>()).prop_map(
        move |(chunk_id, ordinal, ciphertext_bytes)| ChunkReference {
            manifest_id: manifest_id.clone(),
            chunk_id,
            ordinal,
            ciphertext_bytes,
        },
    )
}

fn arb_device_access() -> impl Strategy<Value = ManifestDeviceAccess> {
    (any::<String>(), any::<String>()).prop_map(|(device_id, wrapped_key)| ManifestDeviceAccess {
        device_id,
        wrapped_manifest_key_hex: wrapped_key,
    })
}

fn arb_file_manifest() -> impl Strategy<Value = FileManifest> {
    (
        any::<String>(),
        any::<String>(),
        prop::collection::vec(arb_device_access(), 0..3),
    )
        .prop_flat_map(|(id, root_chunk, devices)| {
            let id2 = id.clone();
            prop::collection::vec(arb_chunk_ref(id.clone()), 0..4).prop_map(move |chunks| {
                FileManifest {
                    id: id2.clone(),
                    encrypted_root_chunk_id: root_chunk.clone(),
                    chunks,
                    authorized_devices: devices.clone(),
                }
            })
        })
}

/// Strategy that generates all EventBody variants with arbitrary field values.
fn arb_event_body() -> impl Strategy<Value = EventBody> {
    prop_oneof![
        // Identity events
        (any::<String>(), any::<String>(), arb_key_full()).prop_map(|(rid, name, key)| {
            EventBody::RootCreated(RootCreatedEvent {
                root_id: rid,
                display_name: name,
                initial_key: key,
            })
        }),
        (any::<String>(), any::<String>(), arb_key_full()).prop_map(|(rid, prev, key)| {
            EventBody::RootKeyRotated(RootKeyRotatedEvent {
                root_id: rid,
                previous_key_id: prev,
                new_key: key,
            })
        }),
        (any::<String>(), any::<String>()).prop_map(|(rid, reason)| {
            EventBody::RootRevoked(RootRevokedEvent {
                root_id: rid,
                reason,
            })
        }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            arb_key_full(),
            arb_key_full()
        )
            .prop_map(|(rid, did, label, key, enc_key)| {
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: rid,
                    device_id: did,
                    label,
                    initial_key: key,
                    initial_encryption_key: enc_key,
                })
            }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            arb_key_full()
        )
            .prop_map(|(rid, did, prev, key)| {
                EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
                    root_id: rid,
                    device_id: did,
                    previous_key_id: prev,
                    new_key: key,
                })
            }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            arb_key_full()
        )
            .prop_map(|(rid, did, prev, key)| {
                EventBody::DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent {
                    root_id: rid,
                    device_id: did,
                    previous_encryption_key_id: prev,
                    new_encryption_key: key,
                })
            }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(rid, did, reason)| {
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: rid,
                device_id: did,
                reason,
            })
        }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(rid, did, reason)| {
            EventBody::DeviceFrozen(DeviceFrozenEvent {
                root_id: rid,
                device_id: did,
                reason,
            })
        }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(rid, old_d, new_d)| {
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: rid,
                replaced_device_id: old_d,
                replacement_device_id: new_d,
            })
        }),
        // Persona events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            proptest::option::of(any::<String>()),
            arb_survival_mode(),
            arb_key_full()
        )
            .prop_map(|(rid, pid, label, disc, surv, key)| {
                EventBody::PersonaCreated(PersonaCreatedEvent {
                    root_id: rid,
                    persona_id: pid,
                    label,
                    disclosure_profile: disc,
                    survival_mode: surv,
                    initial_key: key,
                })
            }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            arb_key_full()
        )
            .prop_map(|(rid, pid, prev, key)| {
                EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
                    root_id: rid,
                    persona_id: pid,
                    previous_key_id: prev,
                    new_key: key,
                })
            }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(rid, pid, reason)| {
            EventBody::PersonaRevoked(PersonaRevokedEvent {
                root_id: rid,
                persona_id: pid,
                reason,
            })
        }),
        // Recovery events
        (any::<String>(), any::<u8>(), any::<u32>()).prop_map(|(rid, threshold, cooldown)| {
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: rid,
                guardian_threshold: threshold,
                cooldown_seconds: cooldown,
            })
        }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>()
        )
            .prop_map(|(rid, gid, label, pubkey)| {
                EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                    root_id: rid,
                    guardian_id: gid,
                    guardian_label: label,
                    guardian_public_key: pubkey,
                })
            }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(req, rid, did)| {
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: req,
                root_id: rid,
                target_device_id: did,
            })
        }),
        (any::<String>(), any::<String>()).prop_map(|(req, gid)| {
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: req,
                guardian_id: gid,
            })
        }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<u64>()
        )
            .prop_map(|(req, gid, reason, epoch)| {
                EventBody::RecoveryContested(RecoveryContestedEvent {
                    request_id: req,
                    guardian_id: gid,
                    reason,
                    contested_at_epoch: epoch,
                })
            }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(req, by, reason)| {
            EventBody::RecoveryRejected(RecoveryRejectedEvent {
                request_id: req,
                rejected_by: by,
                reason,
            })
        }),
        (any::<String>(), arb_recovery_scope()).prop_map(|(req, scope)| {
            EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: req,
                executed_scope: scope,
            })
        }),
        // Network events
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(pid, did, hint)| {
            EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
                peer_id: pid,
                device_id: did,
                transport_hint: hint,
            })
        }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>()
        )
            .prop_map(|(pid, did, prev, new_h)| {
                EventBody::EndpointRotated(EndpointRotatedEvent {
                    peer_id: pid,
                    device_id: did,
                    previous_transport_hint: prev,
                    new_transport_hint: new_h,
                })
            }),
        (any::<String>(), any::<String>(), any::<u64>()).prop_map(|(pid, reason, epoch)| {
            EventBody::RelayShutdownNotice(RelayShutdownNoticeEvent {
                relay_peer_id: pid,
                reason,
                deadline_epoch: epoch,
            })
        }),
        // Storage events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<bool>()
        )
            .prop_map(|(rid, sid, local, remote, approved)| {
                EventBody::StorageRelationshipCreated(StorageRelationshipCreatedEvent {
                    root_id: rid,
                    relationship: StorageRelationship {
                        id: sid,
                        local_peer_id: local,
                        remote_peer_id: remote,
                        approved,
                    },
                })
            }),
        (any::<String>(), any::<String>(), any::<i64>()).prop_map(|(rid, rel, delta)| {
            EventBody::StorageLedgerUpdated(StorageLedgerUpdatedEvent {
                root_id: rid,
                entry: StorageLedgerEntry {
                    relationship_id: rel,
                    stored_bytes_delta: delta,
                },
            })
        }),
        // StorageManifestPublished with nested FileManifest
        (any::<String>(), any::<String>(), arb_file_manifest()).prop_map(|(rid, rel, manifest)| {
            EventBody::StorageManifestPublished(StorageManifestPublishedEvent {
                root_id: rid,
                relationship_id: rel,
                manifest,
            })
        }),
        // Trust events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            (0.0f32..=1.0f32),
            proptest::option::of(any::<String>())
        )
            .prop_map(|(aid, attester, subject, domain, score, bound)| {
                EventBody::TrustAttested(TrustAttestedEvent {
                    attestation_id: aid,
                    attester_persona_id: attester,
                    subject_persona_id: subject,
                    domain,
                    score,
                    recipient_bound: bound,
                })
            }),
        (any::<String>(), any::<String>()).prop_map(|(aid, attester)| {
            EventBody::TrustRevoked(TrustRevokedEvent {
                attestation_id: aid,
                attester_persona_id: attester,
            })
        }),
        // Activity events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>()
        )
            .prop_map(|(mid, sender, recipient, ct)| {
                EventBody::MessageSent(MessageSentEvent {
                    message_id: mid,
                    sender_persona_id: sender,
                    recipient_persona_id: recipient,
                    ciphertext_hex: ct,
                })
            }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            arb_content_visibility()
        )
            .prop_map(|(cid, author, ctype, payload, vis)| {
                EventBody::ContentPublished(ContentPublishedEvent {
                    content_id: cid,
                    author_persona_id: author,
                    content_type: ctype,
                    payload_hex: payload,
                    visibility: vis,
                })
            }),
        // Disclosure revocation
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>()
        )
            .prop_map(|(rid, aid, revoker, reason)| {
                EventBody::DisclosureRevoked(DisclosureRevokedEvent {
                    revocation_id: rid,
                    artifact_id: aid,
                    revoker_persona_id: revoker,
                    reason,
                })
            }),
        // Grant exchange events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            proptest::option::of(any::<String>()),
            any::<u64>()
        )
            .prop_map(|(oid, issuer, ek, payload, relay, exp)| {
                EventBody::GrantOfferCreated(GrantOfferCreatedEvent {
                    offer_id: oid,
                    issuer_persona_id: issuer,
                    ephemeral_public_key_hex: ek,
                    sealed_payload_hex: payload,
                    relay_hint: relay,
                    expires_at: exp,
                    conditions_json: String::new(),
                })
            }),
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<u64>()
        )
            .prop_map(|(oid, recipient, response, claimed)| {
                EventBody::GrantOfferClaimed(GrantOfferClaimedEvent {
                    offer_id: oid,
                    recipient_persona_id: recipient,
                    claim_response_hex: response,
                    claimed_at: claimed,
                })
            }),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(oid, issuer, reason)| {
            EventBody::GrantOfferRevoked(GrantOfferRevokedEvent {
                offer_id: oid,
                issuer_persona_id: issuer,
                reason,
            })
        }),
        // Badge events
        (
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            any::<String>(),
            proptest::option::of((any::<String>(), any::<String>())),
            any::<u64>(),
            proptest::option::of(any::<u64>())
        )
            .prop_map(
                |(bid, issuer, recipient, btype, dname, evidence, issued, expires)| {
                    EventBody::BadgeIssued(BadgeIssuedEvent {
                        badge_id: bid,
                        issuer_persona_id: issuer,
                        recipient_persona_id: recipient,
                        badge_type: btype,
                        display_name: dname,
                        evidence: evidence.map(|(et, ph)| BadgeEvidence {
                            evidence_type: et,
                            payload_hex: ph,
                        }),
                        issued_at: issued,
                        expires_at: expires,
                    })
                }
            ),
        (any::<String>(), any::<String>(), any::<String>()).prop_map(|(bid, revoker, reason)| {
            EventBody::BadgeRevoked(BadgeRevokedEvent {
                badge_id: bid,
                revoker_persona_id: revoker,
                reason,
            })
        }),
    ]
}

proptest! {
    #[test]
    fn event_body_canonical_round_trips(body in arb_event_body()) {
        let encoded = body.canonical_encode();
        let decoded = EventBody::decode_canonical(&encoded)
            .unwrap_or_else(|err| panic!(
                "decode failed for {:?}: {err}\nencoded: {}",
                std::mem::discriminant(&body),
                String::from_utf8_lossy(&encoded)
            ));
        // For TrustAttested, f32 roundtrips through "{:.6}" formatting,
        // so compare via re-encoding rather than structural equality.
        let re_encoded = decoded.canonical_encode();
        prop_assert_eq!(
            encoded, re_encoded,
            "canonical encoding is not stable through roundtrip"
        );
    }
}
